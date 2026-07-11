//! Per-zone witness subscription registry.
//!
//! At 1M zones × 5 witnesses = 5M slots, it is neither practical nor correct
//! for every staked node to be eligible to witness every zone. A node in
//! Frankfurt should not be selected to witness a zone served only by nodes in
//! São Paulo — even if its stake makes the global VRF roll.
//!
//! Gap 5 adds **zone subscriptions**: every witness publishes a signed record
//! declaring which zones it actually serves. Jury selection filters the global
//! staked set to the subscribers for the target zone before scoring.
//!
//! ## Scale discipline
//!
//! - Registry is O(subscribers × avg_zones_per_subscriber) in memory.
//!   At 10K nodes × 10 zones each = 100K entries. ~5MB RAM.
//! - `observe()` is O(zones_in_subscription) (typically < 20).
//! - `subscribers(zone)` is O(1) HashSet lookup, returns a bounded slice.
//! - `prune()` is bounded by `MAX_PRUNE_PER_CALL` to keep hot-path cost fixed.
//!
//! ## Bootstrap safety
//!
//! New zones created by auto-scale (Gap 4) start with zero subscribers until
//! nodes observe the new zone count and re-publish. `select_epoch_jury_scoped`
//! (in `consensus.rs`) falls back to the global staked set when the
//! intersection is below `MIN_SCOPED_JURY`, so settlement is never stuck.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::errors::{ElaraError, Result};
use crate::record::ValidationRecord;
use crate::ZoneId;

use super::epoch::EPOCH_OP_KEY;

/// Metadata key for the zone subscription operation.
pub const EPOCH_OP_ZONE_SUBSCRIPTION: &str = "zone_subscription";

/// Maximum entries pruned per `prune()` call to bound health-loop cost.
const MAX_PRUNE_PER_CALL: usize = 1024;

/// A single zone-subscription declaration published by a witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSubscription {
    pub identity_hash: String,
    pub zones: Vec<ZoneId>,
    /// Epoch at which the subscription was emitted.
    pub emitted_epoch: u64,
    /// Epoch after which this subscription is no longer valid.
    pub valid_until: u64,
}

/// Build the metadata blob for a zone subscription record.
pub fn subscription_metadata(
    identity_hash: &str,
    zones: &[ZoneId],
    emitted_epoch: u64,
    valid_until: u64,
) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(
        EPOCH_OP_KEY.into(),
        serde_json::json!(EPOCH_OP_ZONE_SUBSCRIPTION),
    );
    m.insert(
        "zone_subscription_identity".into(),
        serde_json::json!(identity_hash),
    );
    let zone_strs: Vec<String> = zones.iter().map(|z| z.to_string()).collect();
    m.insert("zone_subscription_zones".into(), serde_json::json!(zone_strs));
    m.insert(
        "zone_subscription_epoch".into(),
        serde_json::json!(emitted_epoch),
    );
    m.insert(
        "zone_subscription_valid_until".into(),
        serde_json::json!(valid_until),
    );
    m
}

/// Extract a zone subscription from a validation record, if present.
pub fn extract_subscription(record: &ValidationRecord) -> Result<Option<ZoneSubscription>> {
    let op = match record.metadata.get(EPOCH_OP_KEY).and_then(|v| v.as_str()) {
        Some(o) => o,
        None => return Ok(None),
    };
    if op != EPOCH_OP_ZONE_SUBSCRIPTION {
        return Ok(None);
    }

    let identity_hash = record
        .metadata
        .get("zone_subscription_identity")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ElaraError::Wire("missing zone_subscription_identity".into()))?
        .to_string();

    let zones_raw = record
        .metadata
        .get("zone_subscription_zones")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ElaraError::Wire("missing zone_subscription_zones".into()))?;

    let mut zones: Vec<ZoneId> = Vec::with_capacity(zones_raw.len());
    for z in zones_raw {
        let s = z
            .as_str()
            .ok_or_else(|| ElaraError::Wire("zone_subscription_zones entry not a string".into()))?;
        zones.push(ZoneId::new(s));
    }
    if zones.is_empty() {
        return Err(ElaraError::Wire(
            "zone_subscription_zones must be non-empty".into(),
        ));
    }

    let emitted_epoch = record
        .metadata
        .get("zone_subscription_epoch")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ElaraError::Wire("missing zone_subscription_epoch".into()))?;

    let valid_until = record
        .metadata
        .get("zone_subscription_valid_until")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ElaraError::Wire("missing zone_subscription_valid_until".into()))?;

    if valid_until <= emitted_epoch {
        return Err(ElaraError::Wire(
            "zone_subscription valid_until must be > emitted_epoch".into(),
        ));
    }

    Ok(Some(ZoneSubscription {
        identity_hash,
        zones,
        emitted_epoch,
        valid_until,
    }))
}

/// Registry of live zone subscriptions.
///
/// One instance per node, held on `NodeState` behind a `std::sync::Mutex`.
#[derive(Debug, Default, Clone)]
pub struct ZoneSubscriptionRegistry {
    /// Zone → set of subscribed witness identity hashes.
    subscribers_per_zone: HashMap<ZoneId, HashSet<String>>,
    /// Witness identity → valid_until epoch (for cheap expiry checks).
    expiry: HashMap<String, u64>,
    /// Witness identity → set of zones it subscribes to (for fast updates).
    zones_for_identity: HashMap<String, HashSet<ZoneId>>,
    /// Witness identity → emitted_epoch of current subscription (for replay protection).
    emitted_epoch: HashMap<String, u64>,
}

impl ZoneSubscriptionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an observed subscription. Later subscriptions from the same
    /// identity supersede earlier ones (keyed on emitted_epoch — older
    /// subscriptions are rejected to prevent replay).
    pub fn observe(&mut self, sub: ZoneSubscription) -> bool {
        if let Some(prev) = self.emitted_epoch.get(&sub.identity_hash) {
            if sub.emitted_epoch <= *prev {
                return false; // replay or out-of-order; ignore
            }
            // Remove previous zone assignments for this identity.
            if let Some(prev_zones) = self.zones_for_identity.remove(&sub.identity_hash) {
                for z in prev_zones {
                    if let Some(set) = self.subscribers_per_zone.get_mut(&z) {
                        set.remove(&sub.identity_hash);
                        if set.is_empty() {
                            self.subscribers_per_zone.remove(&z);
                        }
                    }
                }
            }
        }

        let zones: HashSet<ZoneId> = sub.zones.iter().cloned().collect();
        for z in &zones {
            self.subscribers_per_zone
                .entry(z.clone())
                .or_default()
                .insert(sub.identity_hash.clone());
        }
        self.zones_for_identity
            .insert(sub.identity_hash.clone(), zones);
        self.expiry
            .insert(sub.identity_hash.clone(), sub.valid_until);
        self.emitted_epoch
            .insert(sub.identity_hash, sub.emitted_epoch);
        true
    }

    /// Subscribers currently registered for `zone`. Caller should treat the
    /// returned set as an immutable snapshot; clone if it will outlive the
    /// lock.
    pub fn subscribers(&self, zone: &ZoneId) -> HashSet<String> {
        self.subscribers_per_zone
            .get(zone)
            .cloned()
            .unwrap_or_default()
    }

    /// Count of distinct subscribers for `zone` (O(1)).
    pub fn subscriber_count(&self, zone: &ZoneId) -> usize {
        self.subscribers_per_zone
            .get(zone)
            .map(|s| s.len())
            .unwrap_or(0)
    }

    /// Zones this identity currently subscribes to.
    pub fn zones_for(&self, identity_hash: &str) -> HashSet<ZoneId> {
        self.zones_for_identity
            .get(identity_hash)
            .cloned()
            .unwrap_or_default()
    }

    /// `valid_until` epoch for this identity's current subscription, if any.
    pub fn valid_until(&self, identity_hash: &str) -> Option<u64> {
        self.expiry.get(identity_hash).copied()
    }

    /// Remove subscriptions whose `valid_until` has already passed. Bounded
    /// by `MAX_PRUNE_PER_CALL` so the health loop runs in constant time.
    /// Returns the number of entries removed.
    pub fn prune(&mut self, current_epoch: u64) -> usize {
        let expired: Vec<String> = self
            .expiry
            .iter()
            .filter(|(_, vu)| **vu < current_epoch)
            .take(MAX_PRUNE_PER_CALL)
            .map(|(id, _)| id.clone())
            .collect();

        let n = expired.len();
        for id in expired {
            self.expiry.remove(&id);
            self.emitted_epoch.remove(&id);
            if let Some(zones) = self.zones_for_identity.remove(&id) {
                for z in zones {
                    if let Some(set) = self.subscribers_per_zone.get_mut(&z) {
                        set.remove(&id);
                        if set.is_empty() {
                            self.subscribers_per_zone.remove(&z);
                        }
                    }
                }
            }
        }
        n
    }

    /// Total distinct subscribers.
    pub fn total_subscribers(&self) -> usize {
        self.expiry.len()
    }

    /// Iterator over (zone, subscriber count). Useful for admin endpoint.
    pub fn zone_counts(&self) -> Vec<(ZoneId, usize)> {
        let mut v: Vec<_> = self
            .subscribers_per_zone
            .iter()
            .map(|(z, s)| (z.clone(), s.len()))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(i: u64) -> ZoneId {
        ZoneId::from_legacy(i)
    }

    fn sub(id: &str, zones: &[u64], emitted: u64, valid_until: u64) -> ZoneSubscription {
        ZoneSubscription {
            identity_hash: id.into(),
            zones: zones.iter().map(|i| zone(*i)).collect(),
            emitted_epoch: emitted,
            valid_until,
        }
    }

    #[test]
    fn test_observe_and_lookup() {
        let mut r = ZoneSubscriptionRegistry::new();
        assert!(r.observe(sub("alice", &[0, 1], 10, 110)));
        assert_eq!(r.subscriber_count(&zone(0)), 1);
        assert_eq!(r.subscriber_count(&zone(1)), 1);
        assert_eq!(r.subscriber_count(&zone(2)), 0);
        assert!(r.subscribers(&zone(0)).contains("alice"));
        assert_eq!(r.total_subscribers(), 1);
    }

    #[test]
    fn test_supersede_on_newer_emission() {
        let mut r = ZoneSubscriptionRegistry::new();
        r.observe(sub("alice", &[0, 1], 10, 110));
        // Re-subscribes to different zones later
        assert!(r.observe(sub("alice", &[2, 3], 20, 120)));
        assert_eq!(r.subscriber_count(&zone(0)), 0);
        assert_eq!(r.subscriber_count(&zone(1)), 0);
        assert_eq!(r.subscriber_count(&zone(2)), 1);
        assert_eq!(r.subscriber_count(&zone(3)), 1);
    }

    #[test]
    fn test_reject_replay() {
        let mut r = ZoneSubscriptionRegistry::new();
        r.observe(sub("alice", &[0], 10, 110));
        // Older emission is ignored
        assert!(!r.observe(sub("alice", &[1], 5, 105)));
        assert_eq!(r.subscriber_count(&zone(0)), 1);
        assert_eq!(r.subscriber_count(&zone(1)), 0);
    }

    #[test]
    fn test_reject_equal_epoch() {
        let mut r = ZoneSubscriptionRegistry::new();
        r.observe(sub("alice", &[0], 10, 110));
        // Same emitted_epoch (duplicate) is idempotent — second call rejected.
        assert!(!r.observe(sub("alice", &[1], 10, 110)));
        assert_eq!(r.subscriber_count(&zone(0)), 1);
        assert_eq!(r.subscriber_count(&zone(1)), 0);
    }

    #[test]
    fn test_multiple_subscribers_same_zone() {
        let mut r = ZoneSubscriptionRegistry::new();
        r.observe(sub("alice", &[0], 10, 110));
        r.observe(sub("bob", &[0], 11, 111));
        r.observe(sub("carol", &[0, 1], 12, 112));
        assert_eq!(r.subscriber_count(&zone(0)), 3);
        assert_eq!(r.subscriber_count(&zone(1)), 1);
    }

    #[test]
    fn test_prune_expired() {
        let mut r = ZoneSubscriptionRegistry::new();
        r.observe(sub("alice", &[0], 10, 110));
        r.observe(sub("bob", &[0, 1], 11, 20));
        r.observe(sub("carol", &[2], 12, 200));

        let removed = r.prune(50);
        assert_eq!(removed, 1);
        assert_eq!(r.subscriber_count(&zone(0)), 1); // alice still there
        assert_eq!(r.subscriber_count(&zone(1)), 0); // bob removed
        assert_eq!(r.subscriber_count(&zone(2)), 1);
        assert!(r.valid_until("bob").is_none());
        assert_eq!(r.valid_until("alice"), Some(110));
    }

    #[test]
    fn test_zones_for_identity() {
        let mut r = ZoneSubscriptionRegistry::new();
        r.observe(sub("alice", &[0, 3, 7], 10, 110));
        let zs = r.zones_for("alice");
        assert_eq!(zs.len(), 3);
        assert!(zs.contains(&zone(0)));
        assert!(zs.contains(&zone(3)));
        assert!(zs.contains(&zone(7)));
    }

    #[test]
    fn test_empty_registry() {
        let r = ZoneSubscriptionRegistry::new();
        assert_eq!(r.total_subscribers(), 0);
        assert_eq!(r.subscriber_count(&zone(0)), 0);
        assert!(r.subscribers(&zone(0)).is_empty());
        assert!(r.zones_for("nobody").is_empty());
    }

    #[test]
    fn test_metadata_roundtrip() {
        let meta = subscription_metadata("alice", &[zone(1), zone(4)], 50, 150);
        use crate::record::{Classification, ValidationRecord};
        let rec = ValidationRecord::create(
            b"sub",
            vec![1, 2, 3],
            vec![],
            Classification::Public,
            Some(meta),
        );
        let s = extract_subscription(&rec).unwrap().unwrap();
        assert_eq!(s.identity_hash, "alice");
        assert_eq!(s.zones.len(), 2);
        assert_eq!(s.emitted_epoch, 50);
        assert_eq!(s.valid_until, 150);
    }

    #[test]
    fn test_extract_missing_is_none() {
        use crate::record::{Classification, ValidationRecord};
        let rec = ValidationRecord::create(
            b"no metadata",
            vec![1],
            vec![],
            Classification::Public,
            None,
        );
        let s = extract_subscription(&rec).unwrap();
        assert!(s.is_none());
    }

    #[test]
    fn test_extract_wrong_op_is_none() {
        use crate::record::{Classification, ValidationRecord};
        let mut meta = BTreeMap::new();
        meta.insert(EPOCH_OP_KEY.into(), serde_json::json!("epoch_seal"));
        let rec = ValidationRecord::create(
            b"",
            vec![1],
            vec![],
            Classification::Public,
            Some(meta),
        );
        let s = extract_subscription(&rec).unwrap();
        assert!(s.is_none());
    }

    #[test]
    fn test_extract_invalid_valid_until() {
        use crate::record::{Classification, ValidationRecord};
        let meta = subscription_metadata("alice", &[zone(0)], 100, 90);
        let rec = ValidationRecord::create(
            b"",
            vec![1],
            vec![],
            Classification::Public,
            Some(meta),
        );
        assert!(extract_subscription(&rec).is_err());
    }

    #[test]
    fn test_zone_counts_sorted() {
        let mut r = ZoneSubscriptionRegistry::new();
        r.observe(sub("a", &[0], 10, 100));
        r.observe(sub("b", &[0, 2], 11, 100));
        r.observe(sub("c", &[2], 12, 100));
        let counts = r.zone_counts();
        assert_eq!(counts.len(), 2);
        assert_eq!(counts[0].0, zone(0));
        assert_eq!(counts[0].1, 2);
        assert_eq!(counts[1].0, zone(2));
        assert_eq!(counts[1].1, 2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pure-helper coverage tests.
    // 5 axes targeting distinct invariants:
    //   1. EPOCH_OP_ZONE_SUBSCRIPTION op-key + MAX_PRUNE_PER_CALL bound +
    //      ZoneSubscription 4-field exhaustive destructure shape pin +
    //      Clone + PartialEq + Eq.
    //   2. subscription_metadata exact 5-key shape + BTreeMap ASCII-sorted
    //      iteration pin + JSON value-type per field (epoch_op:String,
    //      identity:String, zones:Array<String>, epoch:u64, valid_until:u64).
    //   3. extract_subscription positive round-trip + None-path branches
    //      (no metadata / wrong op-key value) + 6 Wire-error negative paths
    //      (missing identity / missing zones / non-string zone entry / empty
    //      zones / missing epoch / missing valid_until / valid_until <= epoch).
    //   4. ZoneSubscriptionRegistry::new == default + 6 accessor empty-state
    //      pin + observe replay-rejection (older + equal emitted_epoch both
    //      rejected; older rejection state unchanged) + supersede on newer.
    //   5. prune strict-less-than boundary + zone_counts ASCII-sorted +
    //      empty-state idempotent + total_subscribers tracks expiry not
    //      subscriber-per-zone-set.
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn batch_b_zone_subscription_constants_and_struct_shape_pin() {
        // Axis 1: op-key + bound + ZoneSubscription 4-field shape pin.

        // EPOCH_OP_ZONE_SUBSCRIPTION exact value + ASCII lowercase snake_case.
        assert_eq!(EPOCH_OP_ZONE_SUBSCRIPTION, "zone_subscription");
        assert_eq!(EPOCH_OP_ZONE_SUBSCRIPTION.len(), 17);
        assert!(EPOCH_OP_ZONE_SUBSCRIPTION
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '_'));
        assert!(EPOCH_OP_ZONE_SUBSCRIPTION.contains('_'));
        assert!(!EPOCH_OP_ZONE_SUBSCRIPTION.starts_with('_'));
        assert!(!EPOCH_OP_ZONE_SUBSCRIPTION.ends_with('_'));
        // Distinct from EPOCH_OP_KEY (the meta-key under which the op-value
        // sits). Confusing them would silently route subscriptions as seals.
        assert_ne!(EPOCH_OP_ZONE_SUBSCRIPTION, EPOCH_OP_KEY);

        // MAX_PRUNE_PER_CALL value pin — bounds health-loop cost.
        // (private constant; observe via prune behaviour rather than direct
        // assert — the bound is exposed indirectly: at most 1024 removed per
        // call. Smoke-test: prune on empty registry returns 0.)
        let mut empty = ZoneSubscriptionRegistry::new();
        assert_eq!(empty.prune(u64::MAX), 0,
            "prune on empty registry must return 0");

        // ZoneSubscription 4-field exhaustive destructure shape pin —
        // forces compile-time stability on field names.
        let s = ZoneSubscription {
            identity_hash: "alice".into(),
            zones: vec![zone(0), zone(1)],
            emitted_epoch: 10,
            valid_until: 100,
        };
        let ZoneSubscription { identity_hash, zones, emitted_epoch, valid_until } = s.clone();
        assert_eq!(identity_hash, "alice");
        assert_eq!(zones.len(), 2);
        assert_eq!(emitted_epoch, 10);
        assert_eq!(valid_until, 100);
        let _: u64 = emitted_epoch;
        let _: u64 = valid_until;
        let _: String = identity_hash;
        let _: Vec<ZoneId> = zones;

        // Clone independence + PartialEq + Eq.
        let s2 = s.clone();
        assert_eq!(s, s2);
        let s3 = ZoneSubscription {
            identity_hash: "bob".into(),
            zones: vec![zone(0)],
            emitted_epoch: 10,
            valid_until: 100,
        };
        assert_ne!(s, s3);
        // Debug renders.
        assert!(format!("{s:?}").contains("alice"));
    }

    #[test]
    fn batch_b_zone_subscription_metadata_exact_5_key_shape_and_ascii_sorted_iteration() {
        // Axis 2: subscription_metadata exact 5-key shape + iteration order.

        let m = subscription_metadata("alice", &[zone(0), zone(1)], 10, 110);
        assert_eq!(m.len(), 5, "exactly 5 keys: op + identity + zones + epoch + valid_until");

        // ASCII-sorted BTreeMap iteration order.
        let keys: Vec<&String> = m.keys().collect();
        assert_eq!(keys.len(), 5);
        // BTreeMap iterates in lexicographic order. EPOCH_OP_KEY value lives
        // under whatever its key constant is — check via constant.
        assert!(keys.windows(2).all(|w| w[0] <= w[1]),
            "keys must be ASCII-sorted: {keys:?}");

        // All 5 expected keys present.
        assert!(m.contains_key(EPOCH_OP_KEY), "op-key meta-key present");
        assert!(m.contains_key("zone_subscription_identity"));
        assert!(m.contains_key("zone_subscription_zones"));
        assert!(m.contains_key("zone_subscription_epoch"));
        assert!(m.contains_key("zone_subscription_valid_until"));

        // op-key value is the op string (not the meta-key name).
        assert_eq!(
            m.get(EPOCH_OP_KEY).and_then(|v| v.as_str()).unwrap(),
            EPOCH_OP_ZONE_SUBSCRIPTION
        );

        // identity is JSON string.
        assert_eq!(
            m.get("zone_subscription_identity").and_then(|v| v.as_str()).unwrap(),
            "alice"
        );

        // zones is JSON Array<String>.
        let z_arr = m.get("zone_subscription_zones").and_then(|v| v.as_array())
            .expect("zones must be JSON array");
        assert_eq!(z_arr.len(), 2);
        assert!(z_arr.iter().all(|v| v.is_string()),
            "all zone entries must be JSON strings: {z_arr:?}");

        // epoch + valid_until are JSON numbers (u64-coercible).
        assert_eq!(m.get("zone_subscription_epoch").and_then(|v| v.as_u64()), Some(10));
        assert_eq!(m.get("zone_subscription_valid_until").and_then(|v| v.as_u64()), Some(110));

        // Empty zones array case — metadata is still well-formed (policy gate
        // lives in extract_subscription, not in the builder).
        let m_empty = subscription_metadata("bob", &[], 5, 50);
        assert_eq!(m_empty.len(), 5);
        let z_empty = m_empty.get("zone_subscription_zones").and_then(|v| v.as_array()).unwrap();
        assert!(z_empty.is_empty());
    }

    #[test]
    fn batch_b_zone_subscription_extract_negative_paths_and_wire_errors() {
        // Axis 3: extract_subscription None-paths + Wire-error negative paths.
        use crate::record::{Classification, ValidationRecord};
        use serde_json::json;

        // Helper to build a record with arbitrary metadata.
        fn rec_with(meta: BTreeMap<String, serde_json::Value>) -> ValidationRecord {
            ValidationRecord::create(
                b"",
                vec![1],
                vec![],
                Classification::Public,
                Some(meta),
            )
        }

        // Positive round-trip: all 4 fields preserved.
        let m_ok = subscription_metadata("alice", &[zone(0), zone(7), zone(42)], 100, 200);
        let r_ok = rec_with(m_ok);
        let s = extract_subscription(&r_ok).unwrap().unwrap();
        assert_eq!(s.identity_hash, "alice");
        assert_eq!(s.zones.len(), 3);
        assert_eq!(s.emitted_epoch, 100);
        assert_eq!(s.valid_until, 200);

        // None paths: missing op-key, wrong op-key value.
        let no_meta = ValidationRecord::create(b"", vec![1], vec![], Classification::Public, None);
        assert!(extract_subscription(&no_meta).unwrap().is_none());

        let mut bag = BTreeMap::new();
        bag.insert(EPOCH_OP_KEY.into(), json!("epoch_seal"));
        assert!(extract_subscription(&rec_with(bag)).unwrap().is_none());

        // Wire error paths.

        // Missing identity.
        let mut bag = BTreeMap::new();
        bag.insert(EPOCH_OP_KEY.into(), json!(EPOCH_OP_ZONE_SUBSCRIPTION));
        bag.insert("zone_subscription_zones".into(), json!(["zone0"]));
        bag.insert("zone_subscription_epoch".into(), json!(10u64));
        bag.insert("zone_subscription_valid_until".into(), json!(20u64));
        let err = extract_subscription(&rec_with(bag)).unwrap_err();
        assert!(format!("{err}").contains("zone_subscription_identity"));

        // Missing zones.
        let mut bag = BTreeMap::new();
        bag.insert(EPOCH_OP_KEY.into(), json!(EPOCH_OP_ZONE_SUBSCRIPTION));
        bag.insert("zone_subscription_identity".into(), json!("alice"));
        bag.insert("zone_subscription_epoch".into(), json!(10u64));
        bag.insert("zone_subscription_valid_until".into(), json!(20u64));
        let err = extract_subscription(&rec_with(bag)).unwrap_err();
        assert!(format!("{err}").contains("zone_subscription_zones"));

        // Non-string zone entry.
        let mut bag = BTreeMap::new();
        bag.insert(EPOCH_OP_KEY.into(), json!(EPOCH_OP_ZONE_SUBSCRIPTION));
        bag.insert("zone_subscription_identity".into(), json!("alice"));
        bag.insert("zone_subscription_zones".into(), json!([1, 2, 3]));
        bag.insert("zone_subscription_epoch".into(), json!(10u64));
        bag.insert("zone_subscription_valid_until".into(), json!(20u64));
        let err = extract_subscription(&rec_with(bag)).unwrap_err();
        assert!(format!("{err}").contains("not a string"));

        // Empty zones array → Wire("must be non-empty").
        let mut bag = BTreeMap::new();
        bag.insert(EPOCH_OP_KEY.into(), json!(EPOCH_OP_ZONE_SUBSCRIPTION));
        bag.insert("zone_subscription_identity".into(), json!("alice"));
        bag.insert("zone_subscription_zones".into(), json!(Vec::<String>::new()));
        bag.insert("zone_subscription_epoch".into(), json!(10u64));
        bag.insert("zone_subscription_valid_until".into(), json!(20u64));
        let err = extract_subscription(&rec_with(bag)).unwrap_err();
        assert!(format!("{err}").contains("non-empty"));

        // Missing epoch.
        let mut bag = BTreeMap::new();
        bag.insert(EPOCH_OP_KEY.into(), json!(EPOCH_OP_ZONE_SUBSCRIPTION));
        bag.insert("zone_subscription_identity".into(), json!("alice"));
        bag.insert("zone_subscription_zones".into(), json!(["zone0"]));
        bag.insert("zone_subscription_valid_until".into(), json!(20u64));
        let err = extract_subscription(&rec_with(bag)).unwrap_err();
        assert!(format!("{err}").contains("zone_subscription_epoch"));

        // Missing valid_until.
        let mut bag = BTreeMap::new();
        bag.insert(EPOCH_OP_KEY.into(), json!(EPOCH_OP_ZONE_SUBSCRIPTION));
        bag.insert("zone_subscription_identity".into(), json!("alice"));
        bag.insert("zone_subscription_zones".into(), json!(["zone0"]));
        bag.insert("zone_subscription_epoch".into(), json!(10u64));
        let err = extract_subscription(&rec_with(bag)).unwrap_err();
        assert!(format!("{err}").contains("zone_subscription_valid_until"));

        // valid_until == emitted_epoch (boundary) → Wire("must be > emitted_epoch")
        // because the check is `valid_until <= emitted_epoch`.
        let meta_eq = subscription_metadata("alice", &[zone(0)], 100, 100);
        let err = extract_subscription(&rec_with(meta_eq)).unwrap_err();
        assert!(format!("{err}").contains("valid_until"));

        // valid_until < emitted_epoch → same error.
        let meta_lt = subscription_metadata("alice", &[zone(0)], 100, 99);
        let err = extract_subscription(&rec_with(meta_lt)).unwrap_err();
        assert!(format!("{err}").contains("valid_until"));
    }

    #[test]
    fn batch_b_zone_subscription_registry_initial_state_and_replay_rejection_invariants() {
        // Axis 4: Registry::new == default + accessor empty state + observe
        // replay-rejection (older + equal both rejected; supersede on newer).

        let r1 = ZoneSubscriptionRegistry::new();
        let r2 = ZoneSubscriptionRegistry::default();
        // Empty accessors agree.
        assert_eq!(r1.total_subscribers(), 0);
        assert_eq!(r2.total_subscribers(), 0);
        assert_eq!(r1.subscriber_count(&zone(0)), 0);
        assert_eq!(r2.subscriber_count(&zone(0)), 0);
        assert!(r1.subscribers(&zone(0)).is_empty());
        assert!(r1.zones_for("anyone").is_empty());
        assert!(r1.valid_until("anyone").is_none());
        assert!(r1.zone_counts().is_empty());

        // observe true on first.
        let mut reg = ZoneSubscriptionRegistry::new();
        assert!(reg.observe(sub("alice", &[0, 1, 2], 10, 110)));
        assert_eq!(reg.total_subscribers(), 1);
        assert_eq!(reg.subscriber_count(&zone(0)), 1);
        assert_eq!(reg.subscriber_count(&zone(1)), 1);
        assert_eq!(reg.subscriber_count(&zone(2)), 1);
        assert_eq!(reg.zones_for("alice").len(), 3);
        assert_eq!(reg.valid_until("alice"), Some(110));

        // observe at SAME emitted_epoch → false; state unchanged.
        let pre = reg.subscriber_count(&zone(0));
        assert!(!reg.observe(sub("alice", &[5, 6], 10, 200)));
        assert_eq!(reg.subscriber_count(&zone(0)), pre,
            "rejected observe must not touch state");
        assert_eq!(reg.subscriber_count(&zone(5)), 0);
        assert_eq!(reg.subscriber_count(&zone(6)), 0);
        assert_eq!(reg.valid_until("alice"), Some(110),
            "valid_until unchanged on rejected observe");

        // observe at OLDER emitted_epoch → false; state unchanged.
        assert!(!reg.observe(sub("alice", &[7], 5, 105)));
        assert_eq!(reg.subscriber_count(&zone(7)), 0);
        assert_eq!(reg.valid_until("alice"), Some(110));

        // observe at NEWER emitted_epoch → true; supersedes (zones[0,1,2] removed).
        assert!(reg.observe(sub("alice", &[3, 4], 11, 111)));
        assert_eq!(reg.subscriber_count(&zone(0)), 0, "old zones cleared");
        assert_eq!(reg.subscriber_count(&zone(1)), 0);
        assert_eq!(reg.subscriber_count(&zone(2)), 0);
        assert_eq!(reg.subscriber_count(&zone(3)), 1);
        assert_eq!(reg.subscriber_count(&zone(4)), 1);
        assert_eq!(reg.valid_until("alice"), Some(111));

        // total_subscribers counts distinct identities, not zone slots.
        reg.observe(sub("bob", &[3], 10, 100));
        assert_eq!(reg.total_subscribers(), 2);
        assert_eq!(reg.subscriber_count(&zone(3)), 2, "alice + bob share zone(3)");
    }

    #[test]
    fn batch_b_zone_subscription_prune_strict_lt_boundary_and_zone_counts_sorted() {
        // Axis 5: prune strict-less-than boundary + zone_counts ASCII-sorted.

        let mut r = ZoneSubscriptionRegistry::new();
        // 3 subscribers: alice valid_until=100, bob=110, carol=120.
        r.observe(sub("alice", &[0], 10, 100));
        r.observe(sub("bob", &[1], 11, 110));
        r.observe(sub("carol", &[2], 12, 120));
        assert_eq!(r.total_subscribers(), 3);

        // prune at current_epoch=100 — strict <, so alice (vu=100) NOT pruned
        // (100 < 100 is false).
        let removed = r.prune(100);
        assert_eq!(removed, 0, "strict < boundary: vu=100 NOT pruned at epoch=100");
        assert_eq!(r.total_subscribers(), 3);
        assert_eq!(r.valid_until("alice"), Some(100));

        // prune at current_epoch=101 — alice (vu=100 < 101) pruned.
        let removed = r.prune(101);
        assert_eq!(removed, 1);
        assert_eq!(r.total_subscribers(), 2);
        assert!(r.valid_until("alice").is_none());
        assert_eq!(r.subscriber_count(&zone(0)), 0, "alice's zone(0) cleaned up");

        // Idempotent prune: same epoch again returns 0.
        let removed = r.prune(101);
        assert_eq!(removed, 0);

        // prune at u64::MAX evicts all remaining.
        let removed = r.prune(u64::MAX);
        assert_eq!(removed, 2);
        assert_eq!(r.total_subscribers(), 0);

        // zone_counts is ASCII-sorted by ZoneId.
        let mut r2 = ZoneSubscriptionRegistry::new();
        r2.observe(sub("a", &[5], 10, 100));
        r2.observe(sub("b", &[2, 5], 11, 100));
        r2.observe(sub("c", &[8], 12, 100));
        let counts = r2.zone_counts();
        assert_eq!(counts.len(), 3);
        // Sorted by ZoneId. ZoneId::from_legacy(2) < from_legacy(5) < from_legacy(8)
        // by the ZoneId Ord impl. Validate monotonic ordering.
        assert!(counts.windows(2).all(|w| w[0].0 <= w[1].0),
            "zone_counts must be sorted ascending: {counts:?}");
        // Per-zone subscriber counts match.
        let by_zone: BTreeMap<ZoneId, usize> = counts.into_iter().collect();
        assert_eq!(by_zone.get(&zone(2)).copied(), Some(1));
        assert_eq!(by_zone.get(&zone(5)).copied(), Some(2));
        assert_eq!(by_zone.get(&zone(8)).copied(), Some(1));

        // zone_counts is empty on fresh registry.
        let empty = ZoneSubscriptionRegistry::new();
        assert!(empty.zone_counts().is_empty());
    }
}
