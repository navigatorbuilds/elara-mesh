//! Zone Manager — hierarchical zone identifiers and subscription management.
//!
//! Replaces the flat `u8` zone assignment (SHA3[0] → 0..255) with
//! hierarchical semantic paths (e.g., "medical/eu/west", "iot/sensors/temp").
//!
//! Zone participation for consensus requires stake-gated admission:
//! - Minimum 100 beat staked
//! - PoW identity (min 20-bit difficulty)
//! - 48-hour identity age
//! - Diversity cap: ≤33% of zone stake from any single entity/subnet

//!
//! Spec references:
//!   @spec Protocol §7.5.1
//!   @spec Protocol §3.3.3
//!   @spec economics §11.1

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::crypto::hash::sha3_256;

// ─── Zone ID ────────────────────────────────────────────────────────────────

/// Hierarchical zone identifier.
///
/// Path format: `"segment/segment/..."` — e.g., `"medical/eu/west/germany"`.
/// The root zone is `"default"`. Legacy numeric zones are `"0"` through `"255"`.
///
/// Zones form a tree: `"medical"` is the parent of `"medical/eu"`,
/// which is the parent of `"medical/eu/west"`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ZoneId(String);

impl ZoneId {
    /// Create a new zone from a path string.
    /// Normalizes: trims whitespace, lowercases, strips trailing slashes.
    pub fn new(path: &str) -> Self {
        let normalized = path
            .trim()
            .to_lowercase()
            .trim_end_matches('/')
            .to_string();
        if normalized.is_empty() {
            Self("default".to_string())
        } else {
            Self(normalized)
        }
    }

    /// The default/root zone.
    pub fn default_zone() -> Self {
        Self("default".to_string())
    }

    /// Create from legacy numeric zone (backward compat with hash-based assignment).
    pub fn from_legacy(n: u64) -> Self {
        Self(n.to_string())
    }

    /// Create from the first byte of a SHA3 hash (backward compat).
    pub fn from_hash_byte(b: u8) -> Self {
        Self::from_legacy(b as u64)
    }

    /// Hash-based zone assignment from a record ID.
    ///
    /// Uses the full SHA3-256 hash modulo `zone_count` to distribute records
    /// across zones. Zone count is dynamic — scales with network size.
    ///
    /// With zone_count=2 (6 nodes): records go to zone "0" or "1".
    /// With zone_count=2000 (10K nodes): records spread across 2000 zones.
    pub fn for_record_dynamic(record_id: &str, zone_count: u64) -> Self {
        let zone_count = zone_count.max(1); // never zero
        let hash = sha3_256(record_id.as_bytes());
        // Use first 8 bytes of hash as u64 for modulo — full entropy, no single-byte limit
        let hash_val = u64::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7],
        ]);
        Self::from_legacy(hash_val % zone_count)
    }

    /// Legacy zone assignment (256 zones from first hash byte).
    /// Only used for backward compatibility with pre-dynamic-zone records.
    pub fn for_record(record_id: &str) -> Self {
        Self::for_record_dynamic(record_id, 256)
    }

    /// The zone path as a string slice.
    pub fn path(&self) -> &str {
        &self.0
    }

    /// Path segments (split by '/').
    pub fn segments(&self) -> Vec<&str> {
        self.0.split('/').collect()
    }

    /// Depth in the hierarchy (0 = root-level zone like "medical" or "42").
    pub fn depth(&self) -> usize {
        self.segments().len() - 1
    }

    /// Parent zone. Returns None for root-level zones.
    /// `"medical/eu/west"` → `Some("medical/eu")`.
    pub fn parent(&self) -> Option<Self> {
        let segs = self.segments();
        if segs.len() <= 1 {
            None
        } else {
            Some(Self(segs[..segs.len() - 1].join("/")))
        }
    }

    /// Check if this zone is an ancestor of `other`.
    /// `"medical"` is an ancestor of `"medical/eu/west"`.
    pub fn is_ancestor_of(&self, other: &Self) -> bool {
        if self.0.len() >= other.0.len() {
            return false;
        }
        other.0.starts_with(&self.0) && other.0.as_bytes().get(self.0.len()) == Some(&b'/')
    }

    /// Check if this zone is a descendant of `other`.
    pub fn is_descendant_of(&self, other: &Self) -> bool {
        other.is_ancestor_of(self)
    }

    /// Create a sandbox zone. Prefixes with "sandbox/" if not already.
    pub fn sandbox(path: &str) -> Self {
        let normalized = path.trim().to_lowercase();
        if normalized.starts_with("sandbox/") {
            Self::new(&normalized)
        } else {
            Self::new(&format!("sandbox/{normalized}"))
        }
    }

    /// Check if this is a sandbox zone (path starts with "sandbox/").
    /// Sandbox zones have special rules:
    /// - Predictions cost nothing (no beat stake required)
    /// - Trust earned doesn't propagate to real zones
    /// - Records expire after one epoch
    pub fn is_sandbox(&self) -> bool {
        self.0.starts_with("sandbox/") || self.0 == "sandbox"
    }

    /// Convert a sandbox zone to its real-zone equivalent by stripping "sandbox/" prefix.
    /// Returns None if this isn't a sandbox zone.
    pub fn promote(&self) -> Option<Self> {
        if !self.is_sandbox() {
            return None;
        }
        let stripped = self.0.strip_prefix("sandbox/").unwrap_or(&self.0);
        if stripped.is_empty() || stripped == "sandbox" {
            None
        } else {
            Some(Self::new(stripped))
        }
    }

    /// Check if this is a legacy numeric zone (0..255).
    pub fn is_legacy(&self) -> bool {
        self.0.parse::<u64>().is_ok()
    }

    /// Get legacy numeric value if this is a legacy zone.
    pub fn legacy_value(&self) -> Option<u64> {
        self.0.parse::<u64>().ok()
    }

    /// Deterministic 8-byte key for RocksDB storage.
    /// Uses SHA3-256 of the path, truncated to 8 bytes.
    /// For legacy zones (numeric strings), uses the number as u64 BE
    /// to maintain backward compatibility with existing RocksDB keys.
    pub fn to_key_bytes(&self) -> [u8; 8] {
        if let Some(n) = self.legacy_value() {
            n.to_be_bytes()
        } else {
            let hash = sha3_256(self.0.as_bytes());
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&hash[..8]);
            bytes
        }
    }

    /// Wire format serialization: length-prefixed UTF-8.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let path_bytes = self.0.as_bytes();
        let len = path_bytes.len() as u16;
        let mut buf = Vec::with_capacity(2 + path_bytes.len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(path_bytes);
        buf
    }

    /// Wire format deserialization: length-prefixed UTF-8.
    pub fn from_wire_bytes(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 2 {
            return None;
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + len {
            return None;
        }
        let path = std::str::from_utf8(&data[2..2 + len]).ok()?;
        Some((Self::new(path), 2 + len))
    }
}

impl fmt::Debug for ZoneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ZoneId(\"{}\")", self.0)
    }
}

impl fmt::Display for ZoneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Allow converting u64 to ZoneId for backward compat.
impl From<u64> for ZoneId {
    fn from(n: u64) -> Self {
        Self::from_legacy(n)
    }
}

/// Allow comparing with u64 for backward compat in tests.
impl PartialEq<u64> for ZoneId {
    fn eq(&self, other: &u64) -> bool {
        self.legacy_value() == Some(*other)
    }
}

// ─── DAM-3D Phase A: same-zone parents gate ────────────────────────────────

/// Decision returned by [`check_cross_zone_parents`].
///
/// Pure helper output — caller decides what to do based on policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossZoneParentsDecision {
    /// Every parent is in the same zone as the record (or in an ancestor zone).
    AllSameOrAncestorZone,
    /// One or more parents are in a zone that is not the record's zone and is
    /// not an ancestor of it. `count` is how many offending parents.
    HasCrossZoneParents { count: usize },
}

/// DAM-3D Phase A — pure check that every parent zone equals the record zone
/// or is an ancestor of it (zone-split soft walk).
///
/// This is the load-bearing structural-zone-axis fix. Without it, any creator
/// can declare cross-zone parents on a record and tie two zones into one DAG,
/// breaking Zone Storage Partitioning. Spec: internal design notes §3 Gap A.
///
/// Pure: no locks, no allocations beyond the offending-count probe — caller
/// decides whether to soft-warn or hard-reject based on
/// `NodeConfig::allow_cross_zone_parents`.
pub fn check_cross_zone_parents(
    record_zone: &ZoneId,
    parent_zones: &[ZoneId],
) -> CrossZoneParentsDecision {
    let count = parent_zones
        .iter()
        .filter(|pz| *pz != record_zone && !pz.is_ancestor_of(record_zone))
        .count();
    if count == 0 {
        CrossZoneParentsDecision::AllSameOrAncestorZone
    } else {
        CrossZoneParentsDecision::HasCrossZoneParents { count }
    }
}

// ─── DAM-3D Phase C: zone_refs cross-zone validation ───────────────────────

/// Decision returned by [`classify_zone_ref`] — DAM-3D Phase C Slice 1.
///
/// Pure helper output. Caller resolves `is_subscribed` (from the local
/// `ZoneManager`) and `seal_exists` (from `CF_EPOCHS` via
/// `seal_exists_at_zone_epoch`) and feeds them in. Slice 1 is observe-only:
/// counters tick but no rejection happens. Slice 2 hard-rejects
/// `GhostSubscribed`; Slice 3 stages `DeferredUnsubscribed` into a
/// `pending_xzone_refs` map with TTL/cap; Slice 4 graduates deferred refs
/// when a subscribing peer's gossip confirms the anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneRefClassification {
    /// Subscribed to ref'd zone AND a seal exists locally at the
    /// referenced epoch — the ref is anchored to a known seal.
    AnchoredSubscribed,
    /// Subscribed to ref'd zone but NO seal exists at the referenced
    /// epoch — ref points at a ghost anchor. Sustained non-zero on a
    /// subscribed zone is the signal that records are claiming
    /// causal links to seals their authoring node fabricated or got
    /// from a partition.
    GhostSubscribed,
    /// Not subscribed to ref'd zone — cannot validate locally. Slice
    /// 1 observes only; the deferred-graduation pipeline (Slice 3+)
    /// is the eventual fix.
    DeferredUnsubscribed,
}

/// DAM-3D Phase C Slice 1 — classify a single zone_ref by anchor
/// availability. Spec: internal design notes §3 Gap C.
///
/// Pure: no locks, no I/O. Caller resolves both inputs (subscription
/// state + seal lookup) and feeds them in. The match is exhaustive
/// across the 2×2 truth table; `(false, *)` collapses to
/// `DeferredUnsubscribed` because a non-subscriber can't tell the
/// difference between ghost and real, and incrementing a "ghost"
/// counter for unsubscribed refs would drown the operator signal.
pub fn classify_zone_ref(
    is_subscribed: bool,
    seal_exists: bool,
) -> ZoneRefClassification {
    match (is_subscribed, seal_exists) {
        (true, true) => ZoneRefClassification::AnchoredSubscribed,
        (true, false) => ZoneRefClassification::GhostSubscribed,
        (false, _) => ZoneRefClassification::DeferredUnsubscribed,
    }
}

/// Borrowed bundle of the four DAM-3D Phase C Slice 1 atomic counters
/// passed into [`classify_and_count_zone_refs`]. Held by reference so
/// the caller (NodeState) keeps ownership and the function does not
/// allocate.
pub struct ZoneRefCounters<'a> {
    pub observed: &'a std::sync::atomic::AtomicU64,
    pub anchored: &'a std::sync::atomic::AtomicU64,
    pub ghost: &'a std::sync::atomic::AtomicU64,
    pub deferred: &'a std::sync::atomic::AtomicU64,
}

/// DAM-3D Phase C Slice 1 — classify every `zone_refs` entry in a
/// record and bump the four observability counters. Spec:
/// internal design notes §3 Gap C.
///
/// Behaviour matches the inline call site this replaces in
/// `network/ingest.rs`:
/// 1. Each `zref_bytes` is decoded via [`crate::itc::ZoneCausalReference::from_bytes`].
///    Decode failure → `continue` *without* bumping any counter
///    (preserves the strict invariant
///    `observed == anchored + ghost + deferred`).
/// 2. On successful decode, `observed` is bumped first.
/// 3. `is_subscribed_fn` resolves whether we host the ref'd zone.
///    `seal_exists_fn` is *only* called when subscribed — non-subscribers
///    can't hold the seal anyway, so the lookup would always return false
///    and waste a CF read.
/// 4. [`classify_zone_ref`] decides the bucket and exactly one of
///    `anchored` / `ghost` / `deferred` is bumped.
///
/// The closure form (vs. taking `&NodeState` directly) keeps this
/// function unit-testable in isolation: tests inject deterministic
/// closures instead of standing up a full `RocksEngine + ZoneManager`
/// fixture, and the production caller passes thin closures that
/// forward to `state.zone_manager` and `state.rocks` so behaviour is
/// byte-identical to the pre-refactor inline loop. Closes the
/// "helper unit-test ≠ live entry-point coverage" gap recorded in
/// internal design notes.
pub fn classify_and_count_zone_refs<F1, F2>(
    zone_refs: &[Vec<u8>],
    counters: ZoneRefCounters<'_>,
    is_subscribed_fn: F1,
    seal_exists_fn: F2,
) where
    F1: Fn(&ZoneId) -> bool,
    F2: Fn(u64, &str) -> bool,
{
    use std::sync::atomic::Ordering::Relaxed;
    for zref_bytes in zone_refs {
        let zref = match crate::itc::ZoneCausalReference::from_bytes(zref_bytes) {
            Ok(z) => z,
            Err(_) => continue,
        };
        counters.observed.fetch_add(1, Relaxed);
        let is_subscribed = is_subscribed_fn(&zref.zone_id);
        let seal_exists = if is_subscribed {
            seal_exists_fn(zref.epoch, zref.zone_id.path())
        } else {
            false
        };
        match classify_zone_ref(is_subscribed, seal_exists) {
            ZoneRefClassification::AnchoredSubscribed => {
                counters.anchored.fetch_add(1, Relaxed);
            }
            ZoneRefClassification::GhostSubscribed => {
                counters.ghost.fetch_add(1, Relaxed);
            }
            ZoneRefClassification::DeferredUnsubscribed => {
                counters.deferred.fetch_add(1, Relaxed);
            }
        }
    }
}

// ─── Admission Requirements ────────────────────────────────────────────────

/// Minimum beat stake required to witness in a zone (100 beat, in base units).
/// Single source of truth is `accounting::types::MIN_WITNESS_STAKE_BASE_UNITS` — the
/// bare `100` literal here was a stale pre-10^9-migration value that resolved
/// to 0.0000001 beat (a 10^9x sybil hole the moment `can_witness` is wired live).
pub const MIN_WITNESS_STAKE: u64 = crate::accounting::types::MIN_WITNESS_STAKE_BASE_UNITS;
/// Minimum identity age in seconds (48 hours).
pub const MIN_IDENTITY_AGE_SECS: u64 = 48 * 3600;
/// Minimum PoW difficulty bits for identity.
pub const MIN_POW_DIFFICULTY: u32 = 20;
/// Maximum fraction of zone stake from any single entity/subnet.
pub const MAX_ENTITY_STAKE_FRACTION: f64 = 0.33;

// ─── Zone Manager ──────────────────────────────────────────────────────────

/// Witness info for admission checking.
#[derive(Debug, Clone)]
pub struct WitnessInfo {
    pub identity_hash: String,
    pub stake: u64,
    pub identity_age_secs: u64,
    pub pow_difficulty: u32,
    pub organization: String,
    pub subnet: String,
}

/// Manages zone subscriptions and witness admission.
///
/// Each node subscribes to a set of zones. Only subscribed zones
/// are stored locally and participated in for consensus.
/// Witnessing a zone requires stake-gated admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneManager {
    /// Zones this node is subscribed to.
    subscriptions: HashSet<ZoneId>,
    /// Per-zone total stake (for admission diversity checking).
    zone_stakes: HashMap<ZoneId, u64>,
    /// Per-zone entity stake breakdown: zone → (entity → stake).
    entity_stakes: HashMap<ZoneId, HashMap<String, u64>>,
    /// Per-zone witness set: zone → set of witness identity hashes.
    zone_witnesses: HashMap<ZoneId, HashSet<String>>,
}

impl Default for ZoneManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ZoneManager {
    pub fn new() -> Self {
        Self {
            subscriptions: HashSet::new(),
            zone_stakes: HashMap::new(),
            entity_stakes: HashMap::new(),
            zone_witnesses: HashMap::new(),
        }
    }

    /// Subscribe to a zone. Also subscribes to all ancestor zones.
    pub fn subscribe(&mut self, zone: &ZoneId) {
        self.subscriptions.insert(zone.clone());
        // Also subscribe to ancestors
        let mut current = zone.parent();
        while let Some(parent) = current {
            self.subscriptions.insert(parent.clone());
            current = parent.parent();
        }
    }

    /// Unsubscribe from a zone.
    pub fn unsubscribe(&mut self, zone: &ZoneId) {
        self.subscriptions.remove(zone);
    }

    /// Check if subscribed to a zone (exact match or ancestor).
    pub fn is_subscribed(&self, zone: &ZoneId) -> bool {
        if self.subscriptions.contains(zone) {
            return true;
        }
        // Check if any subscription is an ancestor of this zone
        self.subscriptions.iter().any(|sub| sub.is_ancestor_of(zone))
    }

    /// Get all subscribed zones.
    pub fn subscribed_zones(&self) -> &HashSet<ZoneId> {
        &self.subscriptions
    }

    /// Register stake for a zone from a specific entity.
    pub fn register_stake(&mut self, zone: &ZoneId, entity: &str, stake: u64) {
        *self.zone_stakes.entry(zone.clone()).or_insert(0) += stake;
        *self
            .entity_stakes
            .entry(zone.clone())
            .or_default()
            .entry(entity.to_string())
            .or_insert(0) += stake;
    }

    /// Register a witness for a zone.
    pub fn register_witness(&mut self, zone: &ZoneId, identity_hash: &str) {
        self.zone_witnesses
            .entry(zone.clone())
            .or_default()
            .insert(identity_hash.to_string());
    }

    /// Total stake in a zone.
    pub fn zone_stake(&self, zone: &ZoneId) -> u64 {
        self.zone_stakes.get(zone).copied().unwrap_or(0)
    }

    /// Witness count for a zone.
    pub fn witness_count(&self, zone: &ZoneId) -> usize {
        self.zone_witnesses.get(zone).map_or(0, |w| w.len())
    }

    /// Check if a witness meets admission requirements for a zone.
    ///
    /// Requirements (Protocol §7.5.1, Audit A1):
    /// 1. Minimum 100 beat staked
    /// 2. PoW identity with min 20-bit difficulty
    /// 3. 48-hour identity age
    /// 4. ≤33% of zone stake from same entity/subnet
    pub fn can_witness(&self, zone: &ZoneId, info: &WitnessInfo) -> AdmissionResult {
        // Check stake
        if info.stake < MIN_WITNESS_STAKE {
            return AdmissionResult::InsufficientStake {
                have: info.stake,
                need: MIN_WITNESS_STAKE,
            };
        }

        // Check PoW difficulty
        if info.pow_difficulty < MIN_POW_DIFFICULTY {
            return AdmissionResult::InsufficientPoW {
                have: info.pow_difficulty,
                need: MIN_POW_DIFFICULTY,
            };
        }

        // Check identity age
        if info.identity_age_secs < MIN_IDENTITY_AGE_SECS {
            return AdmissionResult::TooYoung {
                age_secs: info.identity_age_secs,
                min_secs: MIN_IDENTITY_AGE_SECS,
            };
        }

        // Check diversity — entity stake fraction
        let total_zone_stake = self.zone_stake(zone);
        if total_zone_stake > 0 {
            let entity_stake = self
                .entity_stakes
                .get(zone)
                .and_then(|m| m.get(&info.organization))
                .copied()
                .unwrap_or(0);
            let fraction =
                (entity_stake + info.stake) as f64 / (total_zone_stake + info.stake) as f64;
            if fraction > MAX_ENTITY_STAKE_FRACTION {
                return AdmissionResult::DiversityViolation {
                    entity: info.organization.clone(),
                    fraction,
                    max: MAX_ENTITY_STAKE_FRACTION,
                };
            }
        }

        AdmissionResult::Admitted
    }

    /// Clear all state (for re-initialization).
    pub fn clear(&mut self) {
        self.zone_stakes.clear();
        self.entity_stakes.clear();
        self.zone_witnesses.clear();
    }
}

/// Result of admission check for zone witnessing.
#[derive(Debug, Clone, PartialEq)]
pub enum AdmissionResult {
    Admitted,
    InsufficientStake { have: u64, need: u64 },
    InsufficientPoW { have: u32, need: u32 },
    TooYoung { age_secs: u64, min_secs: u64 },
    DiversityViolation { entity: String, fraction: f64, max: f64 },
}

impl AdmissionResult {
    pub fn is_admitted(&self) -> bool {
        matches!(self, AdmissionResult::Admitted)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ZoneId tests ──

    #[test]
    fn test_zone_id_new() {
        let z = ZoneId::new("Medical/EU/West");
        assert_eq!(z.path(), "medical/eu/west");
    }

    #[test]
    fn test_zone_id_normalize() {
        assert_eq!(ZoneId::new("  FOO/BAR/ ").path(), "foo/bar");
        assert_eq!(ZoneId::new("").path(), "default");
        assert_eq!(ZoneId::new("   ").path(), "default");
    }

    #[test]
    fn test_zone_id_segments() {
        let z = ZoneId::new("medical/eu/west");
        assert_eq!(z.segments(), vec!["medical", "eu", "west"]);
        assert_eq!(z.depth(), 2);
    }

    #[test]
    fn test_zone_id_parent() {
        let z = ZoneId::new("medical/eu/west");
        assert_eq!(z.parent(), Some(ZoneId::new("medical/eu")));
        assert_eq!(z.parent().unwrap().parent(), Some(ZoneId::new("medical")));
        assert_eq!(ZoneId::new("medical").parent(), None);
    }

    #[test]
    fn test_zone_id_ancestry() {
        let parent = ZoneId::new("medical");
        let child = ZoneId::new("medical/eu");
        let grandchild = ZoneId::new("medical/eu/west");
        let unrelated = ZoneId::new("finance");

        assert!(parent.is_ancestor_of(&child));
        assert!(parent.is_ancestor_of(&grandchild));
        assert!(!child.is_ancestor_of(&parent));
        assert!(!parent.is_ancestor_of(&unrelated));
        assert!(!parent.is_ancestor_of(&parent)); // not ancestor of self
    }

    #[test]
    fn test_zone_id_legacy() {
        let z = ZoneId::from_legacy(42);
        assert_eq!(z.path(), "42");
        assert!(z.is_legacy());
        assert_eq!(z.legacy_value(), Some(42));

        let z2 = ZoneId::new("medical");
        assert!(!z2.is_legacy());
        assert_eq!(z2.legacy_value(), None);
    }

    #[test]
    fn test_zone_id_key_bytes_legacy() {
        let z = ZoneId::from_legacy(42);
        assert_eq!(z.to_key_bytes(), 42u64.to_be_bytes());
    }

    #[test]
    fn test_zone_id_key_bytes_hierarchical() {
        let z1 = ZoneId::new("medical/eu");
        let z2 = ZoneId::new("finance/global");
        assert_ne!(z1.to_key_bytes(), z2.to_key_bytes());
        // Deterministic
        assert_eq!(z1.to_key_bytes(), ZoneId::new("medical/eu").to_key_bytes());
    }

    #[test]
    fn test_zone_id_for_record() {
        let z1 = ZoneId::for_record("abc");
        let z2 = ZoneId::for_record("abc");
        assert_eq!(z1, z2); // deterministic
        assert!(z1.is_legacy());
    }

    #[test]
    fn test_zone_id_for_record_dynamic() {
        // With 2 zones, all records land in zone "0" or "1"
        let z = ZoneId::for_record_dynamic("test-record-abc", 2);
        let val = z.legacy_value().unwrap();
        assert!(val < 2, "zone {val} should be < 2");

        // Deterministic
        let z2 = ZoneId::for_record_dynamic("test-record-abc", 2);
        assert_eq!(z, z2);

        // With 1 zone, everything goes to zone "0"
        let z_one = ZoneId::for_record_dynamic("anything", 1);
        assert_eq!(z_one, ZoneId::from_legacy(0));

        // With 0 zones (invalid), clamped to 1
        let z_zero = ZoneId::for_record_dynamic("anything", 0);
        assert_eq!(z_zero, ZoneId::from_legacy(0));

        // Distribution: 1000 records across 4 zones should hit all 4
        let mut zones = std::collections::HashSet::new();
        for i in 0..1000 {
            zones.insert(ZoneId::for_record_dynamic(&format!("rec-{i}"), 4));
        }
        assert_eq!(zones.len(), 4, "1000 records should cover all 4 zones");
    }

    #[test]
    fn test_zone_id_wire_format() {
        let z = ZoneId::new("medical/eu/west");
        let bytes = z.to_wire_bytes();
        let (decoded, consumed) = ZoneId::from_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, z);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn wire_format_legacy_numeric_round_trip() {
        let z = ZoneId::from_legacy(42);
        let bytes = z.to_wire_bytes();
        let (decoded, consumed) = ZoneId::from_wire_bytes(&bytes).unwrap();
        assert_eq!(decoded, z);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn wire_format_from_empty_slice_returns_none() {
        assert!(ZoneId::from_wire_bytes(&[]).is_none());
    }

    #[test]
    fn wire_format_from_one_byte_returns_none() {
        assert!(ZoneId::from_wire_bytes(&[0x00]).is_none());
    }

    #[test]
    fn wire_format_from_truncated_payload_returns_none() {
        // Length prefix says 10 bytes follow, but only 3 are present.
        let mut data = vec![0x00, 0x0A]; // len = 10
        data.extend_from_slice(b"abc");   // only 3 bytes
        assert!(ZoneId::from_wire_bytes(&data).is_none());
    }

    #[test]
    fn wire_format_from_invalid_utf8_returns_none() {
        // Valid length prefix (3), then 3 invalid UTF-8 bytes.
        let data = vec![0x00, 0x03, 0xFF, 0xFE, 0xFD];
        assert!(ZoneId::from_wire_bytes(&data).is_none());
    }

    #[test]
    fn test_zone_id_eq_u64() {
        let z = ZoneId::from_legacy(42);
        assert_eq!(z, 42u64);
    }

    #[test]
    fn test_zone_id_from_u64() {
        let z: ZoneId = 42u64.into();
        assert_eq!(z.path(), "42");
    }

    // ── ZoneManager tests ──

    #[test]
    fn test_subscribe() {
        let mut mgr = ZoneManager::new();
        mgr.subscribe(&ZoneId::new("medical/eu/west"));

        assert!(mgr.is_subscribed(&ZoneId::new("medical/eu/west")));
        // Ancestors auto-subscribed
        assert!(mgr.is_subscribed(&ZoneId::new("medical/eu")));
        assert!(mgr.is_subscribed(&ZoneId::new("medical")));
    }

    #[test]
    fn test_subscribe_descendant_match() {
        let mut mgr = ZoneManager::new();
        mgr.subscribe(&ZoneId::new("medical"));

        // Subscribing to "medical" should match descendant zones
        assert!(mgr.is_subscribed(&ZoneId::new("medical/eu")));
        assert!(mgr.is_subscribed(&ZoneId::new("medical/eu/west")));
        assert!(!mgr.is_subscribed(&ZoneId::new("finance")));
    }

    #[test]
    fn test_admission_accepted() {
        let mgr = ZoneManager::new();
        let zone = ZoneId::new("finance/global");
        let info = WitnessInfo {
            identity_hash: "abc123".to_string(),
            stake: MIN_WITNESS_STAKE * 10, // 1000 beat, well above the floor
            identity_age_secs: 200_000,
            pow_difficulty: 25,
            organization: "acme".to_string(),
            subnet: "10.0.0".to_string(),
        };
        assert!(mgr.can_witness(&zone, &info).is_admitted());
    }

    #[test]
    fn test_admission_insufficient_stake() {
        let mgr = ZoneManager::new();
        let zone = ZoneId::new("finance");
        let info = WitnessInfo {
            identity_hash: "abc".to_string(),
            stake: MIN_WITNESS_STAKE / 2, // 50 beat, half the floor
            identity_age_secs: 200_000,
            pow_difficulty: 25,
            organization: "acme".to_string(),
            subnet: "10.0.0".to_string(),
        };
        assert_eq!(
            mgr.can_witness(&zone, &info),
            AdmissionResult::InsufficientStake {
                have: MIN_WITNESS_STAKE / 2,
                need: MIN_WITNESS_STAKE
            }
        );
    }

    #[test]
    fn test_admission_too_young() {
        let mgr = ZoneManager::new();
        let zone = ZoneId::new("finance");
        let info = WitnessInfo {
            identity_hash: "abc".to_string(),
            stake: MIN_WITNESS_STAKE * 10, // stake passes; age must be the rejection
            identity_age_secs: 3600, // 1 hour, need 48
            pow_difficulty: 25,
            organization: "acme".to_string(),
            subnet: "10.0.0".to_string(),
        };
        match mgr.can_witness(&zone, &info) {
            AdmissionResult::TooYoung { .. } => (),
            other => panic!("Expected TooYoung, got {:?}", other),
        }
    }

    #[test]
    fn test_admission_insufficient_pow() {
        let mgr = ZoneManager::new();
        let zone = ZoneId::new("finance");
        let info = WitnessInfo {
            identity_hash: "abc".to_string(),
            stake: MIN_WITNESS_STAKE * 10, // stake passes; PoW must be the rejection
            identity_age_secs: 200_000,
            pow_difficulty: 16, // need 20
            organization: "acme".to_string(),
            subnet: "10.0.0".to_string(),
        };
        match mgr.can_witness(&zone, &info) {
            AdmissionResult::InsufficientPoW { .. } => (),
            other => panic!("Expected InsufficientPoW, got {:?}", other),
        }
    }

    #[test]
    fn test_admission_diversity_violation() {
        let mut mgr = ZoneManager::new();
        let zone = ZoneId::new("finance");

        // Register existing stake: "acme" has 900 of 1000 beat total
        mgr.register_stake(&zone, "acme", MIN_WITNESS_STAKE * 9);
        mgr.register_stake(&zone, "other", MIN_WITNESS_STAKE);

        let info = WitnessInfo {
            identity_hash: "abc".to_string(),
            stake: MIN_WITNESS_STAKE * 2, // 200 beat — clears the floor, so diversity is the rejection
            identity_age_secs: 200_000,
            pow_difficulty: 25,
            organization: "acme".to_string(), // would push acme to 1100/1200 = 91.7%
            subnet: "10.0.0".to_string(),
        };
        match mgr.can_witness(&zone, &info) {
            AdmissionResult::DiversityViolation { .. } => (),
            other => panic!("Expected DiversityViolation, got {:?}", other),
        }
    }

    #[test]
    fn test_zone_manager_clear() {
        let mut mgr = ZoneManager::new();
        mgr.subscribe(&ZoneId::new("medical"));
        mgr.register_stake(&ZoneId::new("medical"), "acme", 1000);
        mgr.clear();
        assert_eq!(mgr.zone_stake(&ZoneId::new("medical")), 0);
    }

    #[test]
    fn test_unsubscribe() {
        let mut mgr = ZoneManager::new();
        let zone = ZoneId::new("finance");
        mgr.subscribe(&zone);
        assert!(mgr.is_subscribed(&zone));
        mgr.unsubscribe(&zone);
        assert!(!mgr.is_subscribed(&zone));
    }

    // ── Sandbox zone tests ──

    #[test]
    fn test_sandbox_zone_detection() {
        assert!(ZoneId::new("sandbox/experiments").is_sandbox());
        assert!(ZoneId::new("sandbox/weather/predict").is_sandbox());
        assert!(ZoneId::new("sandbox").is_sandbox());
        assert!(!ZoneId::new("medical/eu").is_sandbox());
        assert!(!ZoneId::new("default").is_sandbox());
        assert!(!ZoneId::new("42").is_sandbox());
    }

    #[test]
    fn test_sandbox_factory() {
        let z = ZoneId::sandbox("experiments/weather");
        assert_eq!(z.path(), "sandbox/experiments/weather");
        assert!(z.is_sandbox());

        // Already prefixed — no double prefix
        let z2 = ZoneId::sandbox("sandbox/test");
        assert_eq!(z2.path(), "sandbox/test");
    }

    #[test]
    fn test_sandbox_promote() {
        let z = ZoneId::sandbox("weather/predict");
        let promoted = z.promote().unwrap();
        assert_eq!(promoted.path(), "weather/predict");
        assert!(!promoted.is_sandbox());

        // Non-sandbox returns None
        assert!(ZoneId::new("medical").promote().is_none());

        // Bare "sandbox" can't promote (nothing after prefix)
        assert!(ZoneId::new("sandbox").promote().is_none());
    }

    #[test]
    fn test_sandbox_parent_is_sandbox() {
        let z = ZoneId::sandbox("experiments/deep");
        let parent = z.parent().unwrap();
        assert_eq!(parent.path(), "sandbox/experiments");
        assert!(parent.is_sandbox());
    }

    // ── DAM-3D Phase A: same-zone parents gate ──────────────────────────

    #[test]
    fn dam3d_a_check_cross_zone_parents_empty_is_clean() {
        let z = ZoneId::new("medical/eu");
        assert_eq!(
            check_cross_zone_parents(&z, &[]),
            CrossZoneParentsDecision::AllSameOrAncestorZone
        );
    }

    #[test]
    fn dam3d_a_check_cross_zone_parents_same_zone_passes() {
        let z = ZoneId::new("medical/eu");
        let parents = vec![z.clone(), z.clone(), z.clone()];
        assert_eq!(
            check_cross_zone_parents(&z, &parents),
            CrossZoneParentsDecision::AllSameOrAncestorZone
        );
    }

    #[test]
    fn dam3d_a_check_cross_zone_parents_ancestor_passes() {
        // record in child zone with parent in ancestor zone is the soft-split
        // model — accept.
        let record_zone = ZoneId::new("medical/eu/west");
        let parents = vec![ZoneId::new("medical"), ZoneId::new("medical/eu")];
        assert_eq!(
            check_cross_zone_parents(&record_zone, &parents),
            CrossZoneParentsDecision::AllSameOrAncestorZone
        );
    }

    #[test]
    fn dam3d_a_check_cross_zone_parents_descendant_rejects() {
        // record in ancestor zone with parent in child zone has no causal
        // sense — reject.
        let record_zone = ZoneId::new("medical");
        let parents = vec![ZoneId::new("medical/eu/west")];
        assert_eq!(
            check_cross_zone_parents(&record_zone, &parents),
            CrossZoneParentsDecision::HasCrossZoneParents { count: 1 }
        );
    }

    #[test]
    fn dam3d_a_check_cross_zone_parents_unrelated_rejects() {
        let record_zone = ZoneId::new("medical/eu");
        let parents = vec![ZoneId::new("iot/sensors"), ZoneId::new("finance")];
        assert_eq!(
            check_cross_zone_parents(&record_zone, &parents),
            CrossZoneParentsDecision::HasCrossZoneParents { count: 2 }
        );
    }

    #[test]
    fn dam3d_a_check_cross_zone_parents_mixed_counts_offenders_only() {
        let record_zone = ZoneId::new("medical/eu");
        let parents = vec![
            record_zone.clone(),         // same — pass
            ZoneId::new("medical"),      // ancestor — pass
            ZoneId::new("iot/sensors"),  // offender
            ZoneId::new("finance"),      // offender
        ];
        assert_eq!(
            check_cross_zone_parents(&record_zone, &parents),
            CrossZoneParentsDecision::HasCrossZoneParents { count: 2 }
        );
    }

    #[test]
    fn dam3d_a_check_cross_zone_parents_legacy_numeric_zones() {
        // Legacy hash-derived numeric zones — most testnet records use this
        // shape today. Same numeric zone passes; different numeric zones are
        // cross-zone (no ancestry between flat numeric paths).
        let z42 = ZoneId::from_legacy(42);
        let z99 = ZoneId::from_legacy(99);
        assert_eq!(
            check_cross_zone_parents(&z42, &[z42.clone(), z42.clone()]),
            CrossZoneParentsDecision::AllSameOrAncestorZone
        );
        assert_eq!(
            check_cross_zone_parents(&z42, &[z42.clone(), z99]),
            CrossZoneParentsDecision::HasCrossZoneParents { count: 1 }
        );
    }

    #[test]
    fn dam3d_a_check_cross_zone_parents_self_is_not_ancestor() {
        // Sanity: record_zone == parent_zone is the same-zone branch, not an
        // ancestor branch. (`is_ancestor_of` is strict — never self-ancestral.)
        let z = ZoneId::new("medical/eu");
        assert!(!z.is_ancestor_of(&z));
        assert_eq!(
            check_cross_zone_parents(&z, std::slice::from_ref(&z)),
            CrossZoneParentsDecision::AllSameOrAncestorZone
        );
    }

    #[test]
    fn dam3d_a_check_cross_zone_parents_sibling_zones_reject() {
        // medical/eu and medical/us are siblings — neither ancestor of the
        // other — so a record in one zone with a parent in the other is
        // cross-zone.
        let record_zone = ZoneId::new("medical/eu");
        let parents = vec![ZoneId::new("medical/us")];
        assert_eq!(
            check_cross_zone_parents(&record_zone, &parents),
            CrossZoneParentsDecision::HasCrossZoneParents { count: 1 }
        );
    }

    // ─── DAM-3D Phase C Slice 1: classify_zone_ref ──────────────────────────

    #[test]
    fn dam3d_c_classify_zone_ref_anchored_when_subscribed_and_seal_exists() {
        assert_eq!(
            classify_zone_ref(true, true),
            ZoneRefClassification::AnchoredSubscribed
        );
    }

    #[test]
    fn dam3d_c_classify_zone_ref_ghost_when_subscribed_and_no_seal() {
        // The operator-signal case: we host the zone, so we'd have the
        // seal if it were real — its absence means it's fabricated or
        // the result of a partition.
        assert_eq!(
            classify_zone_ref(true, false),
            ZoneRefClassification::GhostSubscribed
        );
    }

    #[test]
    fn dam3d_c_classify_zone_ref_deferred_when_not_subscribed_no_seal() {
        // Can't validate — not subscribed.
        assert_eq!(
            classify_zone_ref(false, false),
            ZoneRefClassification::DeferredUnsubscribed
        );
    }

    #[test]
    fn dam3d_c_classify_zone_ref_deferred_when_not_subscribed_even_with_seal() {
        // seal_exists is meaningless for unsubscribed zones — the caller
        // should pass `false` always when not subscribed (because we
        // can't have a seal for a zone we don't host), but the classifier
        // must collapse `(false, *)` to Deferred regardless to avoid
        // false-positive ghost counts on the testnet ingress path.
        assert_eq!(
            classify_zone_ref(false, true),
            ZoneRefClassification::DeferredUnsubscribed
        );
    }

    // ─── DAM-3D Phase C Slice 1: classify_and_count_zone_refs (loop body) ────
    // Pair the helper unit-tests above with integration tests that exercise
    // the call-site loop the production ingest path runs. Closes the gap
    // recorded in internal design notes.

    use std::sync::atomic::{AtomicU64, Ordering};

    fn fresh_counters() -> (AtomicU64, AtomicU64, AtomicU64, AtomicU64) {
        (
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
        )
    }

    fn mk_zref_bytes(zone: &ZoneId, seq: u64, epoch: u64) -> Vec<u8> {
        crate::itc::ZoneCausalReference {
            zone_id: zone.clone(),
            zone_sequence: seq,
            epoch,
        }
        .to_bytes()
    }

    #[test]
    fn dam3d_c_count_zone_refs_observed_equals_sum_of_classifications() {
        // The strict invariant: observed == anchored + ghost + deferred.
        // Build a record with one of each classification + a duplicate
        // anchored, run through the loop, assert the equation holds.
        // Uses legacy (numeric) zones so the 24-byte wire format is
        // lossless on round-trip — `to_key_bytes()` SHA3-truncates
        // semantic paths to 8 bytes, which `from_bytes` decodes back
        // as `ZoneId::from_legacy(u64)`. Numeric zones round-trip exactly.
        let (obs, anc, gho, def) = fresh_counters();
        let counters = ZoneRefCounters {
            observed: &obs,
            anchored: &anc,
            ghost: &gho,
            deferred: &def,
        };

        let z_anchor = ZoneId::from_legacy(7);
        let z_ghost = ZoneId::from_legacy(8);
        let z_remote = ZoneId::from_legacy(9);
        let refs = vec![
            mk_zref_bytes(&z_anchor, 0, 1),
            mk_zref_bytes(&z_ghost, 0, 2),
            mk_zref_bytes(&z_remote, 0, 3),
            mk_zref_bytes(&z_anchor, 0, 4), // second anchored
        ];

        // Closures: subscribed to anchor + ghost; seal only exists for anchor.
        classify_and_count_zone_refs(
            &refs,
            counters,
            |z| z == &z_anchor || z == &z_ghost,
            |_, path| path == "7",
        );

        assert_eq!(obs.load(Ordering::Relaxed), 4);
        assert_eq!(anc.load(Ordering::Relaxed), 2);
        assert_eq!(gho.load(Ordering::Relaxed), 1);
        assert_eq!(def.load(Ordering::Relaxed), 1);
        assert_eq!(
            obs.load(Ordering::Relaxed),
            anc.load(Ordering::Relaxed)
                + gho.load(Ordering::Relaxed)
                + def.load(Ordering::Relaxed),
            "observed must equal anchored + ghost + deferred — Slice 1 invariant"
        );
    }

    #[test]
    fn dam3d_c_count_zone_refs_malformed_skipped_doesnt_bump_observed() {
        // Malformed bytes hit the `Err(_) => continue` branch BEFORE
        // observed is bumped, so the strict invariant is preserved
        // even when the wire decoder rejects entries.
        let (obs, anc, gho, def) = fresh_counters();
        let counters = ZoneRefCounters {
            observed: &obs,
            anchored: &anc,
            ghost: &gho,
            deferred: &def,
        };

        let z_good = ZoneId::from_legacy(0);
        let valid = mk_zref_bytes(&z_good, 0, 1);
        let truncated_12: Vec<u8> = vec![0u8; 12]; // decoder needs 24
        let empty: Vec<u8> = vec![];
        let refs = vec![valid, truncated_12, empty];

        classify_and_count_zone_refs(&refs, counters, |_| false, |_, _| false);

        // Only the valid one ticks observed; the two malformed entries
        // are dropped silently (conservative — wire-decoder caught earlier).
        assert_eq!(obs.load(Ordering::Relaxed), 1);
        assert_eq!(def.load(Ordering::Relaxed), 1); // unsubscribed → deferred
        assert_eq!(anc.load(Ordering::Relaxed), 0);
        assert_eq!(gho.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dam3d_c_count_zone_refs_anchored_when_subscribed_and_seal_exists() {
        // Single ref to a zone we host AND have a seal for → AnchoredSubscribed.
        let (obs, anc, gho, def) = fresh_counters();
        let counters = ZoneRefCounters {
            observed: &obs,
            anchored: &anc,
            ghost: &gho,
            deferred: &def,
        };

        let z = ZoneId::from_legacy(11);
        let refs = vec![mk_zref_bytes(&z, 0, 42)];

        classify_and_count_zone_refs(
            &refs,
            counters,
            |zid| zid == &z,
            |epoch, path| epoch == 42 && path == "11",
        );

        assert_eq!(obs.load(Ordering::Relaxed), 1);
        assert_eq!(anc.load(Ordering::Relaxed), 1);
        assert_eq!(gho.load(Ordering::Relaxed), 0);
        assert_eq!(def.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dam3d_c_count_zone_refs_ghost_when_subscribed_no_seal() {
        // Single ref to a zone we host but for which CF_EPOCHS has no
        // seal at the claimed epoch → GhostSubscribed (operator signal).
        let (obs, anc, gho, def) = fresh_counters();
        let counters = ZoneRefCounters {
            observed: &obs,
            anchored: &anc,
            ghost: &gho,
            deferred: &def,
        };

        let z = ZoneId::from_legacy(12);
        let refs = vec![mk_zref_bytes(&z, 0, 42)];

        classify_and_count_zone_refs(
            &refs,
            counters,
            |zid| zid == &z,
            |_, _| false, // host the zone but no seal
        );

        assert_eq!(obs.load(Ordering::Relaxed), 1);
        assert_eq!(anc.load(Ordering::Relaxed), 0);
        assert_eq!(gho.load(Ordering::Relaxed), 1);
        assert_eq!(def.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dam3d_c_count_zone_refs_deferred_when_unsubscribed() {
        // Not subscribed → DeferredUnsubscribed. seal_exists_fn must
        // NOT be consulted (the `is_subscribed` branch short-circuits
        // before seal lookup) — verified by panicking closure.
        let (obs, anc, gho, def) = fresh_counters();
        let counters = ZoneRefCounters {
            observed: &obs,
            anchored: &anc,
            ghost: &gho,
            deferred: &def,
        };

        let z = ZoneId::from_legacy(13);
        let refs = vec![mk_zref_bytes(&z, 0, 7)];

        classify_and_count_zone_refs(
            &refs,
            counters,
            |_| false,
            |_, _| panic!("seal_exists_fn must not be called for unsubscribed zones"),
        );

        assert_eq!(obs.load(Ordering::Relaxed), 1);
        assert_eq!(def.load(Ordering::Relaxed), 1);
        assert_eq!(anc.load(Ordering::Relaxed), 0);
        assert_eq!(gho.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dam3d_c_count_zone_refs_empty_input_is_noop() {
        // Defensive: empty zone_refs slice ticks nothing.
        let (obs, anc, gho, def) = fresh_counters();
        let counters = ZoneRefCounters {
            observed: &obs,
            anchored: &anc,
            ghost: &gho,
            deferred: &def,
        };

        let refs: Vec<Vec<u8>> = vec![];
        classify_and_count_zone_refs(&refs, counters, |_| false, |_, _| false);

        assert_eq!(obs.load(Ordering::Relaxed), 0);
        assert_eq!(anc.load(Ordering::Relaxed), 0);
        assert_eq!(gho.load(Ordering::Relaxed), 0);
        assert_eq!(def.load(Ordering::Relaxed), 0);
    }

    // ─── Pure-helper tests ────────────────────────────────────────────
    //
    // Five fixture-free axes on src/network/zone.rs pure helper surface,
    // chosen orthogonal to the existing 45 tests:
    //  1. Witness-admission constants pin (economics §9.1 / Protocol §11.3).
    //  2. ZoneId::from_wire_bytes failure-mode coverage (short buffer + bad UTF-8).
    //  3. check_cross_zone_parents truth-table — covers empty / same / ancestor /
    //     descendant-as-parent / sibling / mixed-count branches.
    //  4. classify_zone_ref 2×2 truth-table including the (false, _) collapse.
    //  5. AdmissionResult::is_admitted variant disambiguation + field-shape pin.

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_admission_constants_pin_min_witness_stake_age_pow_and_diversity_cap() {
        // Protocol §11.3 witness admission requirements (economics §9.1).
        assert_eq!(
            MIN_WITNESS_STAKE,
            crate::accounting::types::MIN_WITNESS_STAKE_BASE_UNITS,
            "MIN_WITNESS_STAKE MUST be 100 beat in base units (anti-sybil floor)"
        );
        assert_eq!(
            MIN_WITNESS_STAKE,
            100 * crate::accounting::types::BASE_UNITS_PER_BEAT,
            "100 beat = 100 * 10^9 base units (guards against unit-scale regression)"
        );
        assert_eq!(
            MIN_IDENTITY_AGE_SECS, 48 * 3600,
            "MIN_IDENTITY_AGE_SECS MUST be 48 hours (anti-flash-mint witness gate)"
        );
        assert_eq!(MIN_POW_DIFFICULTY, 20, "MIN_POW_DIFFICULTY MUST be 20 (per-record PoW floor)");
        assert_eq!(
            MAX_ENTITY_STAKE_FRACTION, 0.33,
            "MAX_ENTITY_STAKE_FRACTION MUST be 0.33 (1/3 BFT diversity cap)"
        );

        // BFT diversity invariant: MUST be strictly less than 0.5 (single entity
        // controlling majority breaks the consensus safety assumption).
        assert!(MAX_ENTITY_STAKE_FRACTION < 0.5,
            "diversity cap MUST be strictly < 0.5 to preserve BFT safety");
        // AND strictly greater than 0.0 (the cap is enforcement, not exclusion).
        assert!(MAX_ENTITY_STAKE_FRACTION > 0.0,
            "diversity cap MUST be strictly > 0.0 (otherwise no entity could stake)");
    }

    #[test]
    fn batch_b_zone_id_from_wire_bytes_pins_short_buffer_and_bad_utf8_branches() {
        // Empty input → None (need at least 2 bytes for length prefix).
        assert!(
            ZoneId::from_wire_bytes(&[]).is_none(),
            "empty buffer MUST be rejected (need 2 bytes for u16 length prefix)"
        );

        // 1-byte buffer (incomplete length prefix) → None.
        assert!(
            ZoneId::from_wire_bytes(&[0x00]).is_none(),
            "1-byte buffer MUST be rejected (length prefix is 2 bytes)"
        );

        // Length prefix says 5 bytes but only 3 follow → None.
        // Prefix = 0x0005, then "abc" (3 bytes) = total 5 bytes < 2 + 5 needed.
        let truncated = [0x00, 0x05, b'a', b'b', b'c'];
        assert!(
            ZoneId::from_wire_bytes(&truncated).is_none(),
            "length-prefix > available payload MUST be rejected (no panic, no partial read)"
        );

        // Length prefix=4, payload=invalid UTF-8 (0xFF 0xFE is not valid UTF-8) → None.
        let bad_utf8 = [0x00, 0x04, 0xFF, 0xFE, 0xFD, 0xFC];
        assert!(
            ZoneId::from_wire_bytes(&bad_utf8).is_none(),
            "invalid UTF-8 payload MUST be rejected via from_utf8 .ok()? path"
        );

        // Length prefix=0 with empty payload → Some normalized to "default"
        // (Self::new("") falls into the empty branch → "default").
        let zero_len = [0x00, 0x00];
        let (z, consumed) = ZoneId::from_wire_bytes(&zero_len)
            .expect("0-length wire MUST decode (normalized to default)");
        assert_eq!(z.path(), "default", "empty payload normalizes to 'default' zone");
        assert_eq!(consumed, 2, "0-length wire consumes exactly the 2-byte length prefix");

        // Round-trip with trailing bytes: consumed MUST equal 2 + len, not data.len().
        let mut buf = ZoneId::new("medical/eu").to_wire_bytes();
        let buf_len_before_trailer = buf.len();
        buf.extend_from_slice(b"TRAILING_BYTES_IGNORED");
        let (z2, consumed2) = ZoneId::from_wire_bytes(&buf)
            .expect("trailing bytes after a valid wire MUST not break decode");
        assert_eq!(z2.path(), "medical/eu");
        assert_eq!(
            consumed2, buf_len_before_trailer,
            "consumed MUST equal exactly the wire-prefix length, NOT total buffer length"
        );
    }

    #[test]
    fn batch_b_check_cross_zone_parents_truth_table_pins_count_accumulation() {
        let record_zone = ZoneId::new("medical/eu");
        let same = ZoneId::new("medical/eu");
        let ancestor = ZoneId::new("medical");
        let sibling = ZoneId::new("medical/us");      // sibling under "medical"
        let unrelated = ZoneId::new("finance/global"); // entirely different tree
        let descendant = ZoneId::new("medical/eu/west"); // child as parent

        // Empty parents list → AllSameOrAncestorZone (count==0 vacuously).
        assert_eq!(
            check_cross_zone_parents(&record_zone, &[]),
            CrossZoneParentsDecision::AllSameOrAncestorZone,
            "empty parents MUST be AllSameOrAncestorZone (no offending refs to count)"
        );

        // All same → AllSame.
        assert_eq!(
            check_cross_zone_parents(&record_zone, &[same.clone(), same.clone()]),
            CrossZoneParentsDecision::AllSameOrAncestorZone
        );

        // All ancestor → AllSame.
        assert_eq!(
            check_cross_zone_parents(&record_zone, std::slice::from_ref(&ancestor)),
            CrossZoneParentsDecision::AllSameOrAncestorZone,
            "ancestor parent (medical) of record (medical/eu) MUST be allowed"
        );

        // Mix of same + ancestor → AllSame.
        assert_eq!(
            check_cross_zone_parents(&record_zone, &[same.clone(), ancestor.clone()]),
            CrossZoneParentsDecision::AllSameOrAncestorZone
        );

        // Sibling parent → HasCrossZone count=1.
        assert_eq!(
            check_cross_zone_parents(&record_zone, std::slice::from_ref(&sibling)),
            CrossZoneParentsDecision::HasCrossZoneParents { count: 1 },
            "sibling zone (medical/us) as parent of medical/eu MUST be flagged cross-zone"
        );

        // Unrelated zone → HasCrossZone count=1.
        assert_eq!(
            check_cross_zone_parents(&record_zone, std::slice::from_ref(&unrelated)),
            CrossZoneParentsDecision::HasCrossZoneParents { count: 1 }
        );

        // Descendant zone as PARENT (unusual but possible) — record_zone is the
        // ancestor of descendant; descendant is NOT an ancestor of record_zone,
        // and NOT equal to record_zone, so it counts as cross-zone.
        assert_eq!(
            check_cross_zone_parents(&record_zone, std::slice::from_ref(&descendant)),
            CrossZoneParentsDecision::HasCrossZoneParents { count: 1 },
            "descendant zone as PARENT MUST flag — descendant is not ancestor of record"
        );

        // Mixed input — count MUST accumulate exactly the offending entries:
        //   [same, ancestor, sibling, unrelated, sibling] → 3 offending.
        let mixed = vec![
            same.clone(),
            ancestor.clone(),
            sibling.clone(),
            unrelated.clone(),
            sibling.clone(),
        ];
        assert_eq!(
            check_cross_zone_parents(&record_zone, &mixed),
            CrossZoneParentsDecision::HasCrossZoneParents { count: 3 },
            "count MUST accumulate exactly 3 offending parents (2 sibling + 1 unrelated)"
        );
    }

    #[test]
    fn batch_b_classify_zone_ref_pins_full_2x2_truth_table_with_collapse() {
        // The (false, _) collapse means BOTH false-subscribed permutations
        // MUST yield DeferredUnsubscribed — operator signal would drown if
        // unsubscribed refs counted as "ghost".
        assert_eq!(
            classify_zone_ref(true, true),
            ZoneRefClassification::AnchoredSubscribed,
            "(subscribed, seal_exists) MUST be AnchoredSubscribed — happy path"
        );
        assert_eq!(
            classify_zone_ref(true, false),
            ZoneRefClassification::GhostSubscribed,
            "(subscribed, NO seal) MUST be GhostSubscribed — the actionable warning lane"
        );
        assert_eq!(
            classify_zone_ref(false, true),
            ZoneRefClassification::DeferredUnsubscribed,
            "(unsubscribed, seal_exists) MUST collapse to DeferredUnsubscribed — caller didn't get to seal_exists for this row"
        );
        assert_eq!(
            classify_zone_ref(false, false),
            ZoneRefClassification::DeferredUnsubscribed,
            "(unsubscribed, NO seal) MUST collapse to DeferredUnsubscribed — non-subscriber can't tell ghost from real"
        );

        // Variant disambiguation: all 3 ZoneRefClassification variants pairwise distinct.
        let anchored = ZoneRefClassification::AnchoredSubscribed;
        let ghost = ZoneRefClassification::GhostSubscribed;
        let deferred = ZoneRefClassification::DeferredUnsubscribed;
        assert_ne!(anchored, ghost, "AnchoredSubscribed and GhostSubscribed MUST disambiguate");
        assert_ne!(ghost, deferred, "GhostSubscribed and DeferredUnsubscribed MUST disambiguate");
        assert_ne!(anchored, deferred, "AnchoredSubscribed and DeferredUnsubscribed MUST disambiguate");
    }

    #[test]
    fn batch_b_admission_result_is_admitted_pins_variant_disambiguation_and_field_shape() {
        // is_admitted MUST be true ONLY for Admitted.
        assert!(AdmissionResult::Admitted.is_admitted(),
            "Admitted MUST report is_admitted = true");

        // Every other variant MUST report is_admitted = false. Pin field shape
        // simultaneously: each rejection carries the numerics the caller needs
        // to surface to operators.
        let stake = AdmissionResult::InsufficientStake { have: 50, need: 100 };
        assert!(!stake.is_admitted(), "InsufficientStake MUST report is_admitted = false");
        if let AdmissionResult::InsufficientStake { have, need } = stake {
            assert_eq!(have, 50);
            assert_eq!(need, 100);
        } else { panic!("variant moved unexpectedly"); }

        let pow = AdmissionResult::InsufficientPoW { have: 15, need: MIN_POW_DIFFICULTY };
        assert!(!pow.is_admitted(), "InsufficientPoW MUST report is_admitted = false");
        if let AdmissionResult::InsufficientPoW { have, need } = pow {
            assert_eq!(have, 15);
            assert_eq!(need, 20, "need MUST passthrough MIN_POW_DIFFICULTY = 20");
        } else { panic!("variant moved unexpectedly"); }

        let young = AdmissionResult::TooYoung { age_secs: 3600, min_secs: MIN_IDENTITY_AGE_SECS };
        assert!(!young.is_admitted(), "TooYoung MUST report is_admitted = false");
        if let AdmissionResult::TooYoung { age_secs, min_secs } = young {
            assert_eq!(age_secs, 3600);
            assert_eq!(min_secs, 48 * 3600, "min_secs MUST passthrough MIN_IDENTITY_AGE_SECS = 48h");
        } else { panic!("variant moved unexpectedly"); }

        let diversity = AdmissionResult::DiversityViolation {
            entity: "stake_pool_42".to_string(),
            fraction: 0.40,
            max: MAX_ENTITY_STAKE_FRACTION,
        };
        assert!(!diversity.is_admitted(), "DiversityViolation MUST report is_admitted = false");
        if let AdmissionResult::DiversityViolation { entity, fraction, max } = &diversity {
            assert_eq!(entity, "stake_pool_42");
            assert!((fraction - 0.40).abs() < f64::EPSILON);
            assert!((max - 0.33).abs() < f64::EPSILON, "max MUST passthrough MAX_ENTITY_STAKE_FRACTION = 0.33");
        } else { panic!("variant moved unexpectedly"); }

        // Variant disambiguation: PartialEq distinguishes all 5 variants.
        assert_ne!(AdmissionResult::Admitted,
                   AdmissionResult::InsufficientStake { have: 0, need: 0 });
        assert_ne!(AdmissionResult::InsufficientStake { have: 0, need: 0 },
                   AdmissionResult::InsufficientPoW { have: 0, need: 0 });
        // Same-variant equality with same fields:
        assert_eq!(
            AdmissionResult::InsufficientStake { have: 50, need: 100 },
            AdmissionResult::InsufficientStake { have: 50, need: 100 },
            "PartialEq MUST be reflexive for InsufficientStake with same fields"
        );
        // Same-variant inequality with different fields:
        assert_ne!(
            AdmissionResult::InsufficientStake { have: 50, need: 100 },
            AdmissionResult::InsufficientStake { have: 50, need: 101 },
            "PartialEq MUST distinguish field values within a variant"
        );
    }
}
