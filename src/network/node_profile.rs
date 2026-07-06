//! Node retention profile — orthogonal to `NodeType` (functional role).
//!
//! A node's **role** (Leaf / Relay / Witness / Archive / Anchor / Gateway)
//! says *what it does* in the protocol. A node's **profile** says *how much
//! state it keeps locally*. Both axes combine freely: a Witness with a
//! `Light` profile runs from a phone; a Witness with an `Archive` profile
//! runs on a VPS.
//!
//! Profiles drive three things:
//!   1. **Retention policy** — `records_retention_secs()` tells GC how long
//!      to keep records before pruning them.
//!   2. **Zone scope** — `serves_all_zones()` tells ingest/gossip whether
//!      to accept cross-zone traffic.
//!   3. **Proof strategy** — Light nodes verify balances from
//!      `AccountStateSMT` + latest epoch seal, never replaying the DAG.
//!
//! Spec references:
//!   @spec Protocol §11.12
//!   @spec MESH-BFT Phase 3 Stage 2C

use serde::{Deserialize, Serialize};

/// Storage / retention profile for an Elara node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NodeProfile {
    /// Headers + recent records only (default 72h). Verifies balances via
    /// `/proof/account/{id}` against the last signed epoch root. Phone-tier.
    Light,
    /// Full record store for this node's assigned zone(s). No cross-zone
    /// history. The standard VPS profile. **Default.**
    #[default]
    FullZone,
    /// All records across all zones, never pruned. Historical source of truth.
    Archive,
}

impl NodeProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::FullZone => "full_zone",
            Self::Archive => "archive",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "light" => Self::Light,
            "archive" => Self::Archive,
            // Any unknown string falls back to the safe default.
            _ => Self::FullZone,
        }
    }

    /// How long raw records are kept on this profile, in seconds. `None`
    /// means "never prune" (Archive).
    pub fn records_retention_secs(&self) -> Option<u64> {
        match self {
            Self::Light => Some(72 * 3600),   // 72h — enough to serve recent queries
            Self::FullZone => Some(90 * 86400), // 90 days — typical operator SLA
            Self::Archive => None,
        }
    }

    /// Does this profile store records from every zone?
    pub fn serves_all_zones(&self) -> bool {
        matches!(self, Self::Archive)
    }

    /// Can this node answer `/proof/account/{id}` authoritatively?
    /// Light nodes *ask* for these proofs; they don't generate them.
    pub fn serves_account_proofs(&self) -> bool {
        matches!(self, Self::FullZone | Self::Archive)
    }

    /// Should ingest accept a record arriving over peer-to-peer gossip push?
    ///
    /// Light = phone-tier client. The account running on it asks `/proof/account`
    /// for its own balance and submits its own records via `HttpSubmit`; it
    /// never participates in the DAG firehose. A peer pushing 50 KB records
    /// through a Light node's `/records` POST or `submit_record` PQ verb at
    /// 200 rec/s would fill a phone disk in minutes — pull_loop already
    /// short-circuits on Light (gossip.rs:863) but the inbound push surface
    /// still accepts traffic. This gate closes that asymmetry.
    ///
    /// FullZone / Archive participate in gossip and accept pushes normally.
    /// Local submissions (no `x-elara-sender` header → `HttpSubmit`) are
    /// always accepted regardless of profile — the gate only fires on
    /// peer-relayed traffic.
    pub fn accepts_gossip_push(&self) -> bool {
        match self {
            Self::Light => false,
            Self::FullZone => true,
            Self::Archive => true,
        }
    }

    pub fn all_names() -> &'static [&'static str] {
        &["light", "full_zone", "archive"]
    }
}

/// Effective-retention sentinel for Archive nodes: 1000 years. Long enough
/// that no real record ever ages out; finite so `now - retention` stays
/// representable and GC's iterator-bound arithmetic does not produce NaN.
pub const ARCHIVE_RETENTION_SECS: f64 = 1000.0 * 365.25 * 86400.0;

/// Resolve the effective retention window used by the GC loop.
///
/// Priority:
///   1. Parse `config_profile` (string from `NodeConfig.node_profile`).
///   2. For `Light` / `FullZone`, return `min(profile_retention,
///      fallback_retention_secs)` — the profile defines the *ceiling* but the
///      operator may lower below it to conserve disk on resource-constrained
///      nodes (testnet, phone-tier hardware, small VPS).
///   3. For `Archive`, return `ARCHIVE_RETENTION_SECS` (~1000y) regardless of
///      `fallback_retention_secs`. The Archive profile is the cluster's
///      "historical source of truth" guarantee — operators who want shorter
///      retention must change `node_profile`, not just lower the retention
///      number. This preserves the cluster-wide BFT promise that "if any node
///      is Archive, full history is recoverable."
///   4. An unknown / empty profile string falls back to
///      `fallback_retention_secs`, preserving the pre-Stage-2C behavior.
///
/// Previously, known profiles always overrode the operator-configured
/// retention, which silently inflated testnet retention from the operator's
/// configured 1 day to FullZone's 90-day default. Disk filled, GC pruned 0,
/// and nodes hit `disk_pressure=1` rejecting ingests. The MIN
/// gate at step (2) reconciles operator intent with profile semantics for
/// non-Archive nodes.
pub fn effective_retention_secs(config_profile: &str, fallback_retention_secs: f64) -> f64 {
    // Unknown / empty string → honor the operator-tuned fallback rather than
    // silently coercing to FullZone's 90-day default.
    if config_profile.is_empty() || !NodeProfile::all_names().contains(&config_profile) {
        return fallback_retention_secs;
    }
    match NodeProfile::from_str(config_profile).records_retention_secs() {
        // Light/FullZone: profile is the ceiling; operator can lower under it.
        Some(secs) => (secs as f64).min(fallback_retention_secs),
        // Archive: forever, regardless of operator override. The BFT
        // history-recovery guarantee depends on this — see doc above.
        None => ARCHIVE_RETENTION_SECS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_full_zone() {
        assert_eq!(NodeProfile::default(), NodeProfile::FullZone);
    }

    #[test]
    fn roundtrip_strings() {
        for name in NodeProfile::all_names() {
            let p = NodeProfile::from_str(name);
            assert_eq!(p.as_str(), *name);
        }
    }

    #[test]
    fn unknown_string_falls_back_to_full_zone() {
        assert_eq!(NodeProfile::from_str("bogus"), NodeProfile::FullZone);
        assert_eq!(NodeProfile::from_str(""), NodeProfile::FullZone);
    }

    #[test]
    fn retention_tiers_increase_with_storage_depth() {
        let light = NodeProfile::Light.records_retention_secs().unwrap();
        let full = NodeProfile::FullZone.records_retention_secs().unwrap();
        assert!(light < full, "light must retain less than full_zone");
        assert!(NodeProfile::Archive.records_retention_secs().is_none(),
            "archive never prunes");
    }

    #[test]
    fn proof_serving_policy() {
        assert!(!NodeProfile::Light.serves_account_proofs());
        assert!(NodeProfile::FullZone.serves_account_proofs());
        assert!(NodeProfile::Archive.serves_account_proofs());
    }

    #[test]
    fn zone_scope_policy() {
        assert!(!NodeProfile::Light.serves_all_zones());
        assert!(!NodeProfile::FullZone.serves_all_zones());
        assert!(NodeProfile::Archive.serves_all_zones());
    }

    #[test]
    fn gossip_push_acceptance_policy() {
        // Light is phone-tier client — never accepts firehose pushes.
        assert!(!NodeProfile::Light.accepts_gossip_push(),
            "Light must reject gossip pushes — phone disk would fill in minutes");
        // FullZone + Archive participate in gossip and accept pushes.
        assert!(NodeProfile::FullZone.accepts_gossip_push());
        assert!(NodeProfile::Archive.accepts_gossip_push());
    }

    #[test]
    fn effective_retention_picks_profile_when_operator_does_not_lower() {
        // Operator's value is HIGHER than the profile ceiling — profile wins
        // (operator cannot raise retention above the profile-defined ceiling).
        let high_fallback = 365.0 * 86400.0; // 365 days
        assert_eq!(effective_retention_secs("light", high_fallback), 72.0 * 3600.0);
        assert_eq!(effective_retention_secs("full_zone", high_fallback), 90.0 * 86400.0);
        // Archive ignores operator override entirely — see doc on
        // effective_retention_secs.
        assert_eq!(effective_retention_secs("archive", high_fallback), ARCHIVE_RETENTION_SECS);
    }

    #[test]
    fn effective_retention_lets_operator_lower_below_profile_for_light_and_fullzone() {
        // Testnet operators on FullZone profile (default) configured
        // `record_retention_secs = 1d` to keep disk usage bounded on small VPS
        // (24 GB FS). Previously the profile silently overrode this to 90d,
        // disks filled, GC pruned 0, nodes hit disk_pressure=1. The MIN gate
        // honors the operator's lower value.
        let one_day = 86400.0;
        // FullZone (90d default) → operator lowers to 1d → 1d wins.
        assert_eq!(effective_retention_secs("full_zone", one_day), one_day);
        // Light (72h default) → operator lowers to 1d → 1d wins (1d < 72h).
        assert_eq!(effective_retention_secs("light", one_day), one_day);
        // Light with 1h fallback (operator wants 1h on phone) → 1h wins.
        let one_hour = 3600.0;
        assert_eq!(effective_retention_secs("light", one_hour), one_hour);
    }

    #[test]
    fn effective_retention_archive_ignores_operator_lowering() {
        // Archive's "forever" promise is the cluster's history-recovery
        // backstop. Operators who want shorter retention must change
        // `node_profile`, not just lower `record_retention_secs`. This guards
        // against "I'm Archive but with 1d retention" foot-guns where the
        // cluster loses its source-of-truth silently.
        assert_eq!(effective_retention_secs("archive", 1.0), ARCHIVE_RETENTION_SECS);
        assert_eq!(effective_retention_secs("archive", 86400.0), ARCHIVE_RETENTION_SECS);
        assert_eq!(effective_retention_secs("archive", 1e9), ARCHIVE_RETENTION_SECS);
    }

    #[test]
    fn effective_retention_falls_back_for_unknown_profile() {
        let fallback = 12345.0;
        assert_eq!(effective_retention_secs("", fallback), fallback);
        assert_eq!(effective_retention_secs("bogus", fallback), fallback);
    }

    #[test]
    fn archive_retention_pushes_cutoff_far_into_the_past() {
        // Sanity: with a ~1000y retention, the GC cutoff sits before any
        // reasonable record timestamp but stays finite (no NaN in gc math).
        let now = 2_000_000_000.0_f64; // year ~2033
        let retention = effective_retention_secs("archive", 0.0);
        let cutoff = now - retention;
        assert!(cutoff.is_finite());
        assert!(cutoff < 0.0, "cutoff should be pre-epoch for archive");
    }

    #[test]
    fn serde_roundtrip() {
        for p in [NodeProfile::Light, NodeProfile::FullZone, NodeProfile::Archive] {
            let s = serde_json::to_string(&p).unwrap();
            let back: NodeProfile = serde_json::from_str(&s).unwrap();
            assert_eq!(p, back);
        }
        // Wire format uses snake_case.
        assert_eq!(serde_json::to_string(&NodeProfile::FullZone).unwrap(), "\"full_zone\"");
    }

    #[test]
    fn batch_b_retention_seconds_strict_pin_with_unit_relation_cross_checks() {
        // Existing `retention_tiers_increase_with_storage_depth` only checks
        // light < full. Pin the EXACT second values so a refactor that
        // accidentally swapped Light↔FullZone retention (e.g. typo
        // 72*86400 instead of 72*3600) surfaces here.
        assert_eq!(NodeProfile::Light.records_retention_secs(), Some(72 * 3600),
            "Light retention must be exactly 72h (259_200 secs)");
        assert_eq!(NodeProfile::Light.records_retention_secs().unwrap(), 259_200u64,
            "Light retention 72h = 259_200 secs");

        assert_eq!(NodeProfile::FullZone.records_retention_secs(), Some(90 * 86400),
            "FullZone retention must be exactly 90 days (7_776_000 secs)");
        assert_eq!(NodeProfile::FullZone.records_retention_secs().unwrap(), 7_776_000u64,
            "FullZone retention 90d = 7_776_000 secs");

        assert_eq!(NodeProfile::Archive.records_retention_secs(), None,
            "Archive must return None (never prune)");

        // Cross-relation: FullZone keeps strictly more than Light
        // (the existing tier-test pins this, repeated here as defensive).
        let light = NodeProfile::Light.records_retention_secs().unwrap();
        let full = NodeProfile::FullZone.records_retention_secs().unwrap();
        assert_eq!(full / light, 30, "FullZone:Light retention ratio must be exactly 30:1 (90d/72h)");

        // Unit-relation cross-checks: Light is in HOURS, FullZone in DAYS.
        assert_eq!(light % 3600, 0, "Light retention must be exact-hour multiple");
        assert_eq!(full % 86400, 0, "FullZone retention must be exact-day multiple");
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_archive_retention_secs_strict_pin_thousand_years_with_finite_math_bounds() {
        // Existing `archive_retention_pushes_cutoff_far_into_the_past` checks
        // is_finite + cutoff < 0 — but doesn't pin the exact value.
        // A regression that bumped 1000y to 1e6 years would still pass
        // is_finite (just barely) and cutoff < 0, but would dwarf any
        // operator's expected GC horizon and silently break downstream math.
        let expected = 1000.0 * 365.25 * 86400.0;
        assert_eq!(ARCHIVE_RETENTION_SECS, expected,
            "ARCHIVE_RETENTION_SECS drift: expected {expected}, got {ARCHIVE_RETENTION_SECS}");

        // Numerical sanity: 1000 years in seconds is 31_557_600_000.
        // (1000 * 365.25 * 86400 = 31_557_600_000)
        assert_eq!(ARCHIVE_RETENTION_SECS as u64, 31_557_600_000u64,
            "ARCHIVE_RETENTION_SECS as u64 must be 31_557_600_000 (one thousand Julian years)");

        // Finite-math invariants — used by GC's `now - retention` arithmetic.
        assert!(ARCHIVE_RETENTION_SECS.is_finite(), "must be finite for cutoff math");
        assert!(!ARCHIVE_RETENTION_SECS.is_nan(), "NaN would propagate through GC seek bounds");
        assert!(ARCHIVE_RETENTION_SECS > 0.0, "must be positive");
        // f64 can represent integers up to 2^53 exactly; 31.5B << 2^53 = 9e15.
        assert!(ARCHIVE_RETENTION_SECS < 2f64.powi(53),
            "ARCHIVE_RETENTION_SECS must stay representable as exact f64 integer");

        // Order: ARCHIVE_RETENTION_SECS > all finite profile retentions.
        let light_f64 = NodeProfile::Light.records_retention_secs().unwrap() as f64;
        let full_f64 = NodeProfile::FullZone.records_retention_secs().unwrap() as f64;
        assert!(ARCHIVE_RETENTION_SECS > light_f64);
        assert!(ARCHIVE_RETENTION_SECS > full_f64);
        assert!(ARCHIVE_RETENTION_SECS / full_f64 > 4000.0,
            "Archive retention is >4000× FullZone (90d × 4000 ≈ 985y)");
    }

    #[test]
    fn batch_b_all_names_exact_order_and_length_with_pairwise_distinct_wire_strings() {
        // all_names() defines the canonical wire-string ordering. Pin both
        // order AND length — a regression that added a 4th variant without
        // updating all_names() (or worse, reordered the array) would
        // silently break config-file parsing.
        let names = NodeProfile::all_names();
        assert_eq!(names.len(), 3, "exactly 3 profile names (Light, FullZone, Archive)");
        assert_eq!(names, &["light", "full_zone", "archive"],
            "all_names() order must be [light, full_zone, archive] — used by config parsing");

        // Pairwise distinctness (a regression that emitted duplicate names
        // would silently collapse two profiles to the same wire string).
        let mut sorted = names.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 3, "all 3 wire names must be pairwise distinct");

        // Round-trip every name → enum → name.
        for name in names {
            let p = NodeProfile::from_str(name);
            let back = p.as_str();
            assert_eq!(back, *name,
                "round-trip of '{name}' → {p:?} → '{back}' must preserve identity");
        }

        // The fixed array indices map deterministically — config-file
        // parsers using `all_names()[0]` for Light, [1] for FullZone, etc.
        assert_eq!(NodeProfile::from_str(names[0]), NodeProfile::Light);
        assert_eq!(NodeProfile::from_str(names[1]), NodeProfile::FullZone);
        assert_eq!(NodeProfile::from_str(names[2]), NodeProfile::Archive);
    }

    #[test]
    fn batch_b_node_profile_hash_consistency_and_copy_semantics_under_assignment() {
        use std::collections::{HashSet, HashMap};
        // Hash derive: equal values produce equal hashes (used in
        // HashSet<NodeProfile> and HashMap<NodeProfile, _>).
        let mut set: HashSet<NodeProfile> = HashSet::new();
        set.insert(NodeProfile::Light);
        set.insert(NodeProfile::Light); // duplicate must collapse
        set.insert(NodeProfile::FullZone);
        set.insert(NodeProfile::Archive);
        set.insert(NodeProfile::Light); // 3rd duplicate
        assert_eq!(set.len(), 3, "HashSet must dedup all 3 profiles");

        // HashMap<NodeProfile, _> — used in metrics tagged-by-profile.
        let mut map: HashMap<NodeProfile, u64> = HashMap::new();
        map.insert(NodeProfile::Light, 1);
        map.insert(NodeProfile::FullZone, 2);
        map.insert(NodeProfile::Archive, 3);
        assert_eq!(map.get(&NodeProfile::Light).copied(), Some(1));
        assert_eq!(map.get(&NodeProfile::FullZone).copied(), Some(2));
        assert_eq!(map.get(&NodeProfile::Archive).copied(), Some(3));

        // Copy derive: assignment does NOT move (compile-time check).
        let a = NodeProfile::Light;
        let b = a;  // Copy, not move
        let c = a;  // a still usable after b assignment
        assert_eq!(a, NodeProfile::Light);
        assert_eq!(b, NodeProfile::Light);
        assert_eq!(c, NodeProfile::Light);

        // Default derive returns FullZone (consistent with existing
        // default_is_full_zone but pinned alongside the Copy semantic).
        let d: NodeProfile = Default::default();
        assert_eq!(d, NodeProfile::FullZone);
    }

    #[test]
    fn batch_b_policy_gate_relations_serves_account_proofs_aligns_with_accepts_gossip_push() {
        // The two policy gates serves_account_proofs() and
        // accepts_gossip_push() classify Light as the phone-tier client
        // (neither serves proofs nor accepts pushes) and FullZone/Archive
        // as full-fleet participants (both serve proofs AND accept pushes).
        //
        // A regression that decoupled these (e.g. making FullZone serve
        // proofs but reject pushes) would silently break the operational
        // invariant that "if a profile is a phone-tier client, it does
        // BOTH — clients don't serve proofs OR accept firehose pushes."
        for profile in [NodeProfile::Light, NodeProfile::FullZone, NodeProfile::Archive] {
            let serves_proofs = profile.serves_account_proofs();
            let accepts_push = profile.accepts_gossip_push();
            assert_eq!(serves_proofs, accepts_push,
                "{profile:?}: serves_account_proofs ({serves_proofs}) must align \
                 with accepts_gossip_push ({accepts_push}) — both are phone-tier-client gates");
        }

        // Light is the phone-tier — gates both off.
        assert!(!NodeProfile::Light.serves_account_proofs());
        assert!(!NodeProfile::Light.accepts_gossip_push());

        // FullZone + Archive are full-fleet — both gates on.
        assert!(NodeProfile::FullZone.serves_account_proofs());
        assert!(NodeProfile::FullZone.accepts_gossip_push());
        assert!(NodeProfile::Archive.serves_account_proofs());
        assert!(NodeProfile::Archive.accepts_gossip_push());

        // Cross-relation: only Archive serves ALL zones; FullZone serves a
        // subset (its own zone). serves_all_zones is independent from the
        // other two gates (Archive is the only "true" — FullZone and Light
        // both false).
        assert!(!NodeProfile::Light.serves_all_zones());
        assert!(!NodeProfile::FullZone.serves_all_zones());
        assert!(NodeProfile::Archive.serves_all_zones());

        // FullZone is the unique profile that serves proofs WITHOUT serving
        // all zones (the operational sweet spot).
        let serves_proofs_but_not_all_zones =
            NodeProfile::FullZone.serves_account_proofs()
                && !NodeProfile::FullZone.serves_all_zones();
        assert!(serves_proofs_but_not_all_zones,
            "FullZone uniquely serves proofs without serving all zones");
    }
}
