//! Hierarchical zone identifier — the record's routing key.
//!
//! Moved from the node's `network/zone.rs` at extraction (the audit's
//! MUST-FIX #1): `ValidationRecord.zone` routes records, so the SHARED type
//! must be the real `ZoneId(String)` — the node's old `not(node-core)` u64
//! stub collapsed every hierarchical path to a number and hard-failed
//! deserializing paths like "medical/eu". Pure std + serde + SHA3; the
//! ZoneManager (subscriptions, stake-gated admission) stays node-side.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash::sha3_256;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
