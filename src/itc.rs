//! Interval Tree Clocks — Protocol §11.9 (Almeida et al. 2008).
//!
//! Space-efficient logical clocks for dynamic systems. Provides the same
//! causal ordering guarantees as vector clocks with O(log n) space instead
//! of O(n).
//!
//! # Two-tier temporal ordering
//!
//! - **Intra-zone:** ITC stamps on each record (~40 bytes per spec)
//! - **Inter-zone:** Zone sequence numbers (monotonic per epoch)
//!
//! The pure ITC algebra (`Id`, `Event`, `Stamp`) and its compact, depth-bounded
//! wire codec live in the standalone `elara-itc` crate (MIT/Apache) and are
//! re-exported here so existing `crate::itc::*` paths keep resolving. This
//! module keeps the zone-coupled layer — [`ZoneCausalReference`] and
//! [`ZoneClockManager`] — which binds ITC stamps to the node's [`ZoneId`].
//!
//! Spec references:
//!   @spec Protocol §7.2

use serde::{Deserialize, Serialize};

use crate::errors::{ElaraError, Result};
use crate::ZoneId;

// Pure ITC engine extracted to the standalone `elara-itc` crate (MIT/Apache).
// Re-exported (explicitly, to avoid clashing with `crate::errors::Result`) so
// `crate::itc::{Id, Event, Stamp, MAX_ITC_DEPTH, ItcError}` keep resolving.
pub use elara_itc::{Event, Id, ItcError, Stamp, MAX_ITC_DEPTH};

/// Map the crate's wire-decode error into the node-wide error so a
/// `Stamp::from_bytes(..)?` flows straight into a `crate::errors::Result`.
impl From<ItcError> for ElaraError {
    fn from(e: ItcError) -> Self {
        match e {
            ItcError::Wire(s) => ElaraError::Wire(s),
        }
    }
}

// ─── Zone Causal Reference ──────────────────────────────────────────────────

/// Inter-zone causal reference — Protocol §11.9.
///
/// Used for cross-zone ordering. Each record can reference the latest known
/// state of other zones. A record with `zone_sequence: 45892` for Earth
/// is causally after all Earth records up to that sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneCausalReference {
    /// Zone identifier.
    pub zone_id: ZoneId,
    /// Zone sequence number at time of last sync.
    pub zone_sequence: u64,
    /// Epoch number within the zone.
    pub epoch: u64,
}

impl ZoneCausalReference {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&self.zone_id.to_key_bytes());
        buf.extend_from_slice(&self.zone_sequence.to_be_bytes());
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 24 {
            return Err(ElaraError::Wire(format!(
                "ZoneCausalReference: need 24 bytes, got {}",
                data.len()
            )));
        }
        let zone_id = ZoneId::from_legacy(u64::from_be_bytes(
            [data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]],
        ));
        let zone_sequence = u64::from_be_bytes(
            [data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]],
        );
        let epoch = u64::from_be_bytes(
            [data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23]],
        );
        Ok(Self {
            zone_id,
            zone_sequence,
            epoch,
        })
    }
}

// ─── Zone Clock Manager ─────────────────────────────────────────────────────

/// Manages ITC stamps per zone. Each zone has its own clock tree.
///
/// When a node participates in multiple zones, it maintains separate
/// ITC stamps per zone.
#[derive(Debug, Default)]
pub struct ZoneClockManager {
    /// Per-zone ITC stamp for this node.
    stamps: std::collections::HashMap<ZoneId, Stamp>,
    /// Per-zone sequence numbers (monotonic, incremented per epoch).
    sequences: std::collections::HashMap<ZoneId, u64>,
}

impl ZoneClockManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create the stamp for a zone. New zones start with a seed stamp.
    pub fn get_stamp(&self, zone: &ZoneId) -> Stamp {
        self.stamps.get(zone).cloned().unwrap_or_else(Stamp::seed)
    }

    /// Record an event in a zone (node created a record).
    /// Returns the stamp to embed in the record.
    pub fn record_event(&mut self, zone: ZoneId) -> Stamp {
        let stamp = self.get_stamp(&zone).event();
        self.stamps.insert(zone, stamp.clone());
        stamp
    }

    /// Join with a received stamp (node received a record from another node).
    pub fn receive(&mut self, zone: ZoneId, received: &Stamp) {
        let current = self.get_stamp(&zone);
        // We need to join events but keep our identity
        let merged_event = current.event.join(received.event.clone());
        self.stamps.insert(
            zone,
            Stamp {
                id: current.id,
                event: merged_event,
            },
        );
    }

    /// Fork: create a stamp for a new peer joining a zone.
    /// Returns (our new stamp, peer's stamp).
    pub fn fork_for_peer(&mut self, zone: ZoneId) -> (Stamp, Stamp) {
        let current = self.get_stamp(&zone);
        let (ours, theirs) = current.fork();
        self.stamps.insert(zone, ours.clone());
        (ours, theirs)
    }

    /// Get zone sequence number.
    pub fn zone_sequence(&self, zone: &ZoneId) -> u64 {
        self.sequences.get(zone).copied().unwrap_or(0)
    }

    /// Increment zone sequence number (called at epoch seal).
    pub fn increment_sequence(&mut self, zone: ZoneId) -> u64 {
        let seq = self.sequences.entry(zone).or_insert(0);
        *seq += 1;
        *seq
    }

    /// Build a causal reference for a zone.
    pub fn causal_reference(&self, zone: ZoneId, epoch: u64) -> ZoneCausalReference {
        let seq = self.zone_sequence(&zone);
        ZoneCausalReference {
            zone_id: zone,
            zone_sequence: seq,
            epoch,
        }
    }

    /// Number of zones tracked.
    pub fn zone_count(&self) -> usize {
        self.stamps.len()
    }

    /// Summary for diagnostics.
    pub fn summary(&self) -> serde_json::Value {
        let zones: Vec<serde_json::Value> = self
            .stamps
            .iter()
            .map(|(zone, stamp)| {
                serde_json::json!({
                    "zone": zone.path(),
                    "event_max": stamp.event.max_val(),
                    "sequence": self.zone_sequence(zone),
                    "stamp_bytes": stamp.to_bytes().len(),
                })
            })
            .collect();
        serde_json::json!({
            "zones": self.stamps.len(),
            "details": zones,
        })
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────
//
// The pure-ITC algebra + wire-codec tests live in the `elara-itc` crate. These
// exercise the zone-coupled layer that stays in the node (`ZoneCausalReference`,
// `ZoneClockManager`) and the `Stamp` re-export integration with `ZoneId`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::sha3_256;
    use crate::record::{Classification, ValidationRecord};
    use crate::wire::WIRE_VERSION;
    use crate::ZoneId;
    use std::collections::BTreeMap;

    #[test]
    fn test_wire_roundtrip_with_itc() {
        let stamp = Stamp::seed().event().event();
        let zone_ref = ZoneCausalReference {
            zone_id: ZoneId::from_legacy(42),
            zone_sequence: 100,
            epoch: 5,
        };

        let rec = ValidationRecord {
            id: "019506e0-1234-7000-8000-000000000001".to_string(),
            version: WIRE_VERSION,
            content_hash: sha3_256(b"content").to_vec(),
            creator_public_key: vec![0xAA; 1952],
            timestamp: 1739712345.0,
            parents: vec![],
            classification: Classification::Public,
            metadata: BTreeMap::new(),
            signature: Some(vec![0xBB; 3309]),
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: Some(stamp.to_bytes()),
            zone_refs: vec![zone_ref.to_bytes()],
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };

        let wire = rec.to_bytes();
        let decoded = ValidationRecord::from_bytes(&wire).unwrap();
        assert_eq!(decoded.itc_stamp, rec.itc_stamp);
        assert_eq!(decoded.zone_refs, rec.zone_refs);
        assert_eq!(decoded.version, WIRE_VERSION);

        // Verify the ITC stamp deserializes correctly
        let decoded_stamp = Stamp::from_bytes(decoded.itc_stamp.as_ref().unwrap()).unwrap();
        assert_eq!(decoded_stamp, stamp);

        // Verify the zone ref deserializes correctly
        let decoded_ref = ZoneCausalReference::from_bytes(&decoded.zone_refs[0]).unwrap();
        assert_eq!(decoded_ref, zone_ref);
    }


    // --- ZoneCausalReference tests ---

    #[test]
    fn test_zone_causal_ref_roundtrip() {
        let ref1 = ZoneCausalReference {
            zone_id: ZoneId::from_legacy(42),
            zone_sequence: 45892,
            epoch: 100,
        };
        let bytes = ref1.to_bytes();
        assert_eq!(bytes.len(), 24); // 8 + 8 + 8
        let decoded = ZoneCausalReference::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, ref1);
    }

    #[test]
    fn test_zone_causal_ref_too_short() {
        assert!(ZoneCausalReference::from_bytes(&[0; 10]).is_err());
    }

    #[test]
    fn zone_causal_ref_from_bytes_boundary_and_max_values() {
        // 23 bytes — one short of the 24-byte minimum — must be rejected.
        assert!(
            ZoneCausalReference::from_bytes(&[0xffu8; 23]).is_err(),
            "23-byte input must return Err"
        );
        // u64::MAX in every field must round-trip without truncation.
        let r = ZoneCausalReference {
            zone_id: ZoneId::from_legacy(u64::MAX),
            zone_sequence: u64::MAX,
            epoch: u64::MAX,
        };
        let bytes = r.to_bytes();
        assert_eq!(bytes.len(), 24);
        let decoded = ZoneCausalReference::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, r);
        // Confirm big-endian layout: first 8 bytes encode zone_id BE.
        assert_eq!(&bytes[0..8], &u64::MAX.to_be_bytes());
        assert_eq!(&bytes[8..16], &u64::MAX.to_be_bytes());
        assert_eq!(&bytes[16..24], &u64::MAX.to_be_bytes());
    }

    #[test]
    fn zone_causal_ref_rejects_short_payloads_and_decodes_exact_24() {
        // ZoneCausalReference requires exactly 24 bytes; <24 must error.
        for short_len in 0..24 {
            let short = vec![0u8; short_len];
            assert!(
                ZoneCausalReference::from_bytes(&short).is_err(),
                "ZoneCausalReference must reject {}-byte input",
                short_len,
            );
        }
        // 24-byte zero input must decode (length OK, semantics zero).
        let exact = vec![0u8; 24];
        let r = ZoneCausalReference::from_bytes(&exact).expect("24-byte input must decode");
        assert_eq!(r.zone_sequence, 0);
        assert_eq!(r.epoch, 0);
    }

    // --- ZoneClockManager tests ---

    #[test]
    fn test_zone_clock_basic() {
        let mut mgr = ZoneClockManager::new();

        // First event in zone 0
        let stamp1 = mgr.record_event(ZoneId::from_legacy(0));
        assert_eq!(stamp1.event.max_val(), 1);

        // Second event
        let stamp2 = mgr.record_event(ZoneId::from_legacy(0));
        assert_eq!(stamp2.event.max_val(), 2);

        // Different zone is independent
        let stamp_z1 = mgr.record_event(ZoneId::from_legacy(1));
        assert_eq!(stamp_z1.event.max_val(), 1);
    }

    #[test]
    fn test_zone_clock_receive() {
        let mut mgr_a = ZoneClockManager::new();
        let mut mgr_b = ZoneClockManager::new();

        // A creates events
        let _ = mgr_a.record_event(ZoneId::from_legacy(0));
        let a_stamp = mgr_a.record_event(ZoneId::from_legacy(0));

        // B receives A's stamp
        mgr_b.receive(ZoneId::from_legacy(0), &a_stamp);

        // B's next event should be after A's
        let b_stamp = mgr_b.record_event(ZoneId::from_legacy(0));
        assert!(a_stamp.leq(&b_stamp));
    }

    #[test]
    fn test_zone_clock_fork() {
        let mut mgr = ZoneClockManager::new();
        let _ = mgr.record_event(ZoneId::from_legacy(0));

        let (ours, theirs) = mgr.fork_for_peer(ZoneId::from_legacy(0));
        // Both should have the same event history
        assert_eq!(ours.event, theirs.event);
        // But different identities
        assert_ne!(ours.id, theirs.id);
        // Rejoining gives full identity
        assert!(ours.id.join(theirs.id).is_one());
    }

    #[test]
    fn test_zone_clock_sequence() {
        let mut mgr = ZoneClockManager::new();
        assert_eq!(mgr.zone_sequence(&ZoneId::from_legacy(0)), 0);
        assert_eq!(mgr.increment_sequence(ZoneId::from_legacy(0)), 1);
        assert_eq!(mgr.increment_sequence(ZoneId::from_legacy(0)), 2);
        assert_eq!(mgr.zone_sequence(&ZoneId::from_legacy(0)), 2);
        // Other zone unaffected
        assert_eq!(mgr.zone_sequence(&ZoneId::from_legacy(1)), 0);
    }

    #[test]
    fn test_zone_clock_summary() {
        let mut mgr = ZoneClockManager::new();
        let _ = mgr.record_event(ZoneId::from_legacy(0));
        let _ = mgr.record_event(ZoneId::from_legacy(1));
        let summary = mgr.summary();
        assert_eq!(summary["zones"], 2);
    }
}
