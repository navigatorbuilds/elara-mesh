//! Zone split/merge transition seals — Gap 4 foundation.
//!
//! A **transition seal** is the atomic, anchor-signed record that rehomes
//! accounts when a zone splits (hot zone → two children) or merges (two cold
//! zones → one child). It is the only structure that lets light clients
//! verify a post-transition balance without stalling on "which fork won" —
//! the seal is Merkle-anchored to the last pre-transition epoch and
//! signed by an M-of-N anchor committee.
//!
//! This module defines the types, canonical encoding, and verification logic.
//! It does NOT drive the transition — orchestration lives in a follow-up
//! commit that wires the seal into `auto_scale.rs` and the anchor path.
//!
//! # Invariants (enforced by [`TransitionSeal::validate_structure`])
//!
//! Split:
//! - `parents.len() == 1`, `children.len() == 2`, `split_key.is_some()`
//! - Every account with `account_hash < split_key` lives in `children[0]`,
//!   every other account in `children[1]`.
//!
//! Merge:
//! - `parents.len() == 2`, `children.len() == 1`, `split_key.is_none()`
//! - Both parents' account sets become addressable under the single child.
//!
//! # Signing
//!
//! Proposer anchors sign the SHA3-256 of [`TransitionSeal::canonical_encode_for_sig`],
//! which is the canonical encoding with `proposer_sigs` cleared. This keeps
//! signatures deterministic regardless of sig-collection order.
//!
//! # Thresholds
//!
//! - Split: [`SPLIT_ANCHOR_THRESHOLD`] of N — 4-of-7 today.
//! - Merge: [`MERGE_ANCHOR_THRESHOLD`] of N — 7-of-9, stricter because merges
//!   concentrate state and a bad merge is harder to undo than a bad split.
//!
//! # Dispute window
//!
//! [`TRANSITION_DISPUTE_WINDOW_EPOCHS`] = 3 epochs between
//! `proposed_at_epoch` and `effective_epoch`. Any node can publish a
//! counter-record in this window to veto the transition (bad boundary,
//! unauthorized proposer, committee-diversity violation). The actual dispute
//! resolution ships with the orchestration commit.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::crypto::hash::sha3_256;
use crate::crypto::pqc;
use crate::errors::{ElaraError, Result};
use crate::network::zone::ZoneId;

/// M-of-N anchor threshold for a split transition. Splits *distribute* state,
/// so the cost of a bad split is bounded — a minority of anchors can reverse
/// it by proposing the inverse merge.
pub const SPLIT_ANCHOR_THRESHOLD: usize = 4;

/// M-of-N anchor threshold for a merge transition. Merges *concentrate* state
/// and can't be cleanly undone (you can't know the original split boundary
/// from the merged state), so they require a stricter supermajority.
pub const MERGE_ANCHOR_THRESHOLD: usize = 7;

/// Number of epochs between `proposed_at_epoch` and `effective_epoch` during
/// which any node may publish a counter-record to veto the transition.
pub const TRANSITION_DISPUTE_WINDOW_EPOCHS: u64 = 3;

/// Upper bound on the number of anchor signatures a single seal may carry.
/// `required_threshold()` is 4 for splits and 7 for merges; the real N per
/// committee is a small constant (single-digit anchors per zone). 32 leaves
/// ample headroom for larger committees or redundant sigs while keeping the
/// worst-case Dilithium3 verification cost per `/transitions/propose`
/// bounded: without a cap, a malicious proposer could attach 10K sigs to
/// force ~30s of `dilithium3_verify` work per request.
pub const MAX_PROPOSER_SIGS: usize = 32;

/// Transition kind discriminant. Gives the structure validator a clean
/// anchor for the `parents.len()` / `children.len()` / `split_key` invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionKind {
    Split,
    Merge,
}

/// Read the live state needed to populate a [`ZoneSnapshot`] for a parent
/// zone from a node's storage. Used by Gap 4 orchestration when a node
/// proposes a split/merge and needs to stamp the current state of the
/// zone(s) being closed.
///
/// Data sources:
/// * `state_root` — [`super::merkle::SparseMerkleTree::root`] for the zone.
///   `EMPTY_HASH` for a zone that has never had a record.
/// * `record_count` — [`super::merkle::SparseMerkleTree::leaf_count`] for
///   the zone.
/// * `last_seal_record_id` — newest epoch seal's record id via a 7-day
///   bounded scan ([`super::merkle::find_latest_seal_for_zone`]). Empty
///   string if no seal has ever covered this zone.
/// * `committee_hash` — SHA3-256 commitment to the VRF-selected committee
///   that governs this zone's seal. Computed via
///   [`super::zone_committee::committee_hash_from_members`]. All-zeros means
///   no staked anchors exist (acceptable at bootstrap; the validator will
///   tighten this once Phase 6 enforcement lands).
///
/// Scale: O(zone_tree_root_lookup + 2000 recent records). Bounded by the
/// merkle / recent-record indexes — no O(all_records) scan.
pub fn build_zone_snapshot(
    storage: &crate::storage::rocks::StorageEngine,
    zone: ZoneId,
    committee_hash: [u8; 32],
) -> Result<ZoneSnapshot> {
    let tree = super::merkle::SparseMerkleTree::new(storage, zone.clone());
    let state_root = tree.root()?;
    let record_count = tree.leaf_count()?;

    let last_seal_record_id = match super::merkle::find_latest_seal_for_zone(storage, &zone)? {
        Some((rid, _root, _epoch)) => rid,
        None => String::new(),
    };

    Ok(ZoneSnapshot {
        zone_id: zone,
        state_root,
        last_seal_record_id,
        record_count,
        committee_hash,
    })
}

/// Build a newborn child [`ZoneSnapshot`] — used for the target zones in a
/// transition where no pre-existing state is being inherited. The child's
/// state_root is `EMPTY_HASH` (empty zone tree), record_count is 0, and
/// `last_seal_record_id` is empty.
///
/// The `committee_hash` must be supplied by the caller because children
/// are assigned a fresh committee at transition time; the transition
/// seal is what commits to that assignment.
pub fn newborn_child_snapshot(zone: ZoneId, committee_hash: [u8; 32]) -> ZoneSnapshot {
    ZoneSnapshot {
        zone_id: zone,
        // `SparseMerkleTree::root` returns the module's `EMPTY_HASH` for
        // an empty tree. We replicate the value here rather than re-export
        // a private const — it's the SHA3-256 of the empty string, fixed
        // by the crypto spec, and a mismatch would be caught by the first
        // real leaf insert (different post-root from every honest node).
        state_root: [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
            0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
            0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
        ],
        last_seal_record_id: String::new(),
        record_count: 0,
        committee_hash,
    }
}

/// Zone state at the moment of transition — either a parent zone being
/// closed (Split source, Merge sources) or a child zone being opened
/// (Split children, Merge child).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneSnapshot {
    pub zone_id: ZoneId,
    /// Merkle root over the zone's account/state tree at the transition
    /// boundary. For parents: the final state before closure. For children:
    /// the initial state (subset of parent's for Split, union for Merge).
    pub state_root: [u8; 32],
    /// record_id of the last seal for this zone in the outgoing history
    /// (parents) or all-zero for newborn children (Split) / merged child.
    pub last_seal_record_id: String,
    /// Total records that existed in this zone at the transition.
    pub record_count: u64,
    /// SHA3-256 commitment to the zone's witness committee. Parents carry
    /// the closing committee; children carry the incoming committee.
    pub committee_hash: [u8; 32],
}

/// A single anchor's signature over [`TransitionSeal::seal_hash_for_sig`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorSig {
    /// SHA3-256 of the anchor's Dilithium3 public key (used by the anchor
    /// registry to look up the verifying key).
    pub anchor_identity_hash: [u8; 32],
    /// Dilithium3 detached signature bytes (3309 bytes for ML-DSA-65).
    pub dilithium3_sig: Vec<u8>,
}

/// A zone transition seal — the atomic boundary between pre-transition and
/// post-transition history. See module docs for invariants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionSeal {
    pub kind: TransitionKind,
    /// Epoch at which the transition *takes effect*. All records with
    /// `epoch >= effective_epoch` route against the post-transition zone
    /// layout; records with `epoch < effective_epoch` route against parents.
    pub effective_epoch: u64,
    /// Epoch at which the proposal was published. Must equal
    /// `effective_epoch - TRANSITION_DISPUTE_WINDOW_EPOCHS`.
    pub proposed_at_epoch: u64,
    /// Zone(s) being closed by this transition.
    /// - Split: exactly 1 parent.
    /// - Merge: exactly 2 parents.
    pub parents: Vec<ZoneSnapshot>,
    /// Zone(s) being opened by this transition.
    /// - Split: exactly 2 children, ordered so that accounts with
    ///   `account_hash < split_key` belong to `children[0]`.
    /// - Merge: exactly 1 child.
    pub children: Vec<ZoneSnapshot>,
    /// Account-hash boundary for Split transitions; None for Merges.
    /// Accounts with `account_hash < split_key` go to `children[0]`;
    /// accounts with `account_hash >= split_key` go to `children[1]`.
    pub split_key: Option<[u8; 32]>,
    /// M anchor signatures over [`TransitionSeal::seal_hash_for_sig`].
    /// Ordering is stable across serialisations (sorted by anchor_identity_hash).
    pub proposer_sigs: Vec<AnchorSig>,
}

impl TransitionSeal {
    /// Structural invariants required of *any* well-formed transition seal.
    /// Cheap — O(1) per seal. Must pass before signature verification.
    pub fn validate_structure(&self) -> Result<()> {
        // F2 (2026-07-03 audit): proposed_at_epoch is attacker-controlled on an
        // incoming seal; a value near u64::MAX would overflow the add and panic
        // under release overflow-checks. saturating_add is correct — a saturated
        // sum can never equal a well-formed effective_epoch, so the malformed
        // seal is rejected below rather than crashing the validator.
        if self
            .proposed_at_epoch
            .saturating_add(TRANSITION_DISPUTE_WINDOW_EPOCHS)
            != self.effective_epoch
        {
            return Err(ElaraError::Wire(format!(
                "transition seal: dispute window mismatch (proposed={} effective={} window={})",
                self.proposed_at_epoch, self.effective_epoch, TRANSITION_DISPUTE_WINDOW_EPOCHS
            )));
        }
        // Cap proposer_sigs at MAX_PROPOSER_SIGS so a malicious submitter
        // can't flood a seal with thousands of sigs and force the HTTP
        // path into seconds of Dilithium3 verification per request. Real
        // committees have single-digit anchor counts; 32 is a generous
        // ceiling that catches the DoS shape while leaving operators room.
        if self.proposer_sigs.len() > MAX_PROPOSER_SIGS {
            return Err(ElaraError::Wire(format!(
                "transition seal: proposer_sigs.len() = {} exceeds MAX_PROPOSER_SIGS = {}",
                self.proposer_sigs.len(),
                MAX_PROPOSER_SIGS
            )));
        }
        match self.kind {
            TransitionKind::Split => {
                if self.parents.len() != 1 {
                    return Err(ElaraError::Wire(format!(
                        "split seal must have exactly 1 parent, got {}",
                        self.parents.len()
                    )));
                }
                if self.children.len() != 2 {
                    return Err(ElaraError::Wire(format!(
                        "split seal must have exactly 2 children, got {}",
                        self.children.len()
                    )));
                }
                if self.split_key.is_none() {
                    return Err(ElaraError::Wire(
                        "split seal requires split_key".into(),
                    ));
                }
            }
            TransitionKind::Merge => {
                if self.parents.len() != 2 {
                    return Err(ElaraError::Wire(format!(
                        "merge seal must have exactly 2 parents, got {}",
                        self.parents.len()
                    )));
                }
                if self.children.len() != 1 {
                    return Err(ElaraError::Wire(format!(
                        "merge seal must have exactly 1 child, got {}",
                        self.children.len()
                    )));
                }
                if self.split_key.is_some() {
                    return Err(ElaraError::Wire(
                        "merge seal must not carry split_key".into(),
                    ));
                }
                // Paranoia: a merge where both parents are the same zone is
                // semantically nonsense and trivially detectable.
                if self.parents[0].zone_id == self.parents[1].zone_id {
                    return Err(ElaraError::Wire(
                        "merge seal parents must be distinct zones".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Canonical bytes over which anchors sign. Excludes `proposer_sigs`
    /// so signatures are deterministic regardless of collection order.
    ///
    /// Encoding: `serde_json::to_vec` of a clone with `proposer_sigs` cleared.
    /// The seal has no `HashMap`/`BTreeMap` fields (only `Vec` and primitives),
    /// so serde_json emits fields in struct-declaration order — deterministic.
    /// JSON is already the canonical metadata format for records elsewhere in
    /// the crate (see `epoch::super_seal_metadata`), so this adds no new
    /// serialisation surface for auditors to review.
    pub fn canonical_encode_for_sig(&self) -> Result<Vec<u8>> {
        let mut shallow = self.clone();
        shallow.proposer_sigs.clear();
        serde_json::to_vec(&shallow)
            .map_err(|e| ElaraError::Wire(format!("transition seal encode: {e}")))
    }

    /// SHA3-256 of the canonical-for-sig bytes. This is what anchor
    /// Dilithium3 signatures cover.
    pub fn seal_hash_for_sig(&self) -> Result<[u8; 32]> {
        let bytes = self.canonical_encode_for_sig()?;
        Ok(sha3_256(&bytes))
    }

    /// For Split seals: return the child `ZoneId` an account with
    /// `account_hash` routes to after `effective_epoch`. Returns None if
    /// this is a Merge seal (no routing decision — all accounts go to the
    /// single child).
    pub fn account_belongs_to_child(&self, account_hash: &[u8; 32]) -> Option<&ZoneId> {
        match (self.kind, self.split_key.as_ref()) {
            (TransitionKind::Split, Some(split_key)) => {
                // Lexicographic compare on 32-byte big-endian hashes.
                if account_hash < split_key {
                    self.children.first().map(|c| &c.zone_id)
                } else {
                    self.children.get(1).map(|c| &c.zone_id)
                }
            }
            (TransitionKind::Merge, _) => self.children.first().map(|c| &c.zone_id),
            (TransitionKind::Split, None) => None, // structurally invalid
        }
    }

    /// Verify M-of-N anchor signatures over [`TransitionSeal::seal_hash_for_sig`].
    ///
    /// `anchor_pubkeys` maps each anchor's identity hash (SHA3-256 of its
    /// Dilithium3 public key) to the public-key bytes. The caller is
    /// responsible for populating this from the anchor registry.
    ///
    /// Returns `Ok(())` if at least `threshold` distinct, valid signatures
    /// from registered anchors are present. Duplicate anchor sigs count once.
    pub fn verify_sigs(
        &self,
        anchor_pubkeys: &HashMap<[u8; 32], Vec<u8>>,
        threshold: usize,
    ) -> Result<()> {
        let hash = self.seal_hash_for_sig()?;
        let mut seen: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::new();
        let mut valid = 0usize;

        for sig in &self.proposer_sigs {
            if !seen.insert(sig.anchor_identity_hash) {
                // Same anchor signed twice — only count once.
                continue;
            }
            let Some(pk) = anchor_pubkeys.get(&sig.anchor_identity_hash) else {
                // Anchor not in registry — silently skip. The threshold
                // check below is the real gate.
                continue;
            };
            match pqc::dilithium3_verify(&hash, &sig.dilithium3_sig, pk) {
                Ok(true) => valid += 1,
                _ => continue,
            }
        }

        if valid < threshold {
            return Err(ElaraError::Wire(format!(
                "transition seal: {valid} valid anchor sigs, need {threshold}"
            )));
        }
        Ok(())
    }

    /// Required anchor threshold for this seal's kind.
    pub fn required_threshold(&self) -> usize {
        match self.kind {
            TransitionKind::Split => SPLIT_ANCHOR_THRESHOLD,
            TransitionKind::Merge => MERGE_ANCHOR_THRESHOLD,
        }
    }

    /// Append this anchor's Dilithium3 signature over [`Self::seal_hash_for_sig`]
    /// to `proposer_sigs`. Used by anchor nodes that want to co-sign a
    /// proposed transition (their own proposal, or a gossiped one they've
    /// independently validated) before broadcasting.
    ///
    /// Behaviour:
    /// * Signs the current `seal_hash_for_sig`. If the seal's canonical
    ///   content later changes the signature becomes invalid — this is by
    ///   design; see `canonical_encode_excludes_sigs`.
    /// * Rejects a re-sign by the same anchor (keeps `proposer_sigs` a set
    ///   by `anchor_identity_hash`, same as [`super::transition_store::TransitionStore::add_sig`]).
    /// * Rejects the call once `proposer_sigs.len() == MAX_PROPOSER_SIGS` so
    ///   the caller can't push the seal past the HTTP-path cap by this route.
    /// * Keeps `proposer_sigs` sorted by `anchor_identity_hash` so gossip
    ///   serialisations are byte-stable regardless of collection order.
    ///
    /// Does NOT validate the seal's structure — callers that built the seal
    /// locally are expected to validate before signing. The store's insert
    /// path revalidates regardless.
    pub fn sign_as_anchor(&mut self, identity: &crate::identity::Identity) -> Result<()> {
        if self.proposer_sigs.len() >= MAX_PROPOSER_SIGS {
            return Err(ElaraError::Wire(format!(
                "transition seal: proposer_sigs full ({MAX_PROPOSER_SIGS}), cannot sign"
            )));
        }

        // Derive anchor_identity_hash from the identity's public key. The
        // seal carries the raw SHA3-256 bytes, not the hex string that
        // `Identity::identity_hash` exposes, so we hash the pubkey directly
        // rather than hex-decode (one fewer failure mode).
        let anchor_identity_hash = sha3_256(&identity.public_key);

        if self
            .proposer_sigs
            .iter()
            .any(|s| s.anchor_identity_hash == anchor_identity_hash)
        {
            return Err(ElaraError::Wire(
                "transition seal: this anchor has already signed".into(),
            ));
        }

        let hash = self.seal_hash_for_sig()?;
        let sig_bytes = identity
            .sign(&hash)
            .map_err(|e| ElaraError::Wire(format!("transition seal sign failed: {e}")))?;

        self.proposer_sigs.push(AnchorSig {
            anchor_identity_hash,
            dilithium3_sig: sig_bytes,
        });
        // Keep sig list deterministically ordered for byte-stable gossip.
        self.proposer_sigs
            .sort_by_key(|a| a.anchor_identity_hash);
        Ok(())
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pqc::{dilithium3_keygen, dilithium3_sign_with_pk};

    fn zone_snap(name: &str) -> ZoneSnapshot {
        ZoneSnapshot {
            zone_id: ZoneId::new(name),
            state_root: [1u8; 32],
            last_seal_record_id: format!("seal-{name}"),
            record_count: 100,
            committee_hash: [2u8; 32],
        }
    }

    fn child_snap(name: &str) -> ZoneSnapshot {
        ZoneSnapshot {
            zone_id: ZoneId::new(name),
            state_root: [0u8; 32],
            last_seal_record_id: String::new(),
            record_count: 0,
            committee_hash: [3u8; 32],
        }
    }

    fn make_split_seal() -> TransitionSeal {
        TransitionSeal {
            kind: TransitionKind::Split,
            effective_epoch: 1000,
            proposed_at_epoch: 997,
            parents: vec![zone_snap("medical/eu")],
            children: vec![child_snap("medical/eu/west"), child_snap("medical/eu/east")],
            split_key: Some([0x80u8; 32]),
            proposer_sigs: vec![],
        }
    }

    fn make_merge_seal() -> TransitionSeal {
        TransitionSeal {
            kind: TransitionKind::Merge,
            effective_epoch: 2000,
            proposed_at_epoch: 1997,
            parents: vec![zone_snap("iot/north"), zone_snap("iot/south")],
            children: vec![child_snap("iot")],
            split_key: None,
            proposer_sigs: vec![],
        }
    }

    #[test]
    fn split_structure_ok() {
        make_split_seal().validate_structure().expect("valid split");
    }

    #[test]
    fn merge_structure_ok() {
        make_merge_seal().validate_structure().expect("valid merge");
    }

    #[test]
    fn split_without_split_key_rejected() {
        let mut s = make_split_seal();
        s.split_key = None;
        let err = s.validate_structure().unwrap_err();
        assert!(format!("{err}").contains("split_key"));
    }

    #[test]
    fn merge_with_split_key_rejected() {
        let mut s = make_merge_seal();
        s.split_key = Some([0u8; 32]);
        let err = s.validate_structure().unwrap_err();
        assert!(format!("{err}").contains("split_key"));
    }

    #[test]
    fn split_with_wrong_parent_count_rejected() {
        let mut s = make_split_seal();
        s.parents.push(zone_snap("extra"));
        let err = s.validate_structure().unwrap_err();
        assert!(format!("{err}").contains("1 parent"));
    }

    #[test]
    fn split_with_wrong_child_count_rejected() {
        let mut s = make_split_seal();
        s.children.pop();
        let err = s.validate_structure().unwrap_err();
        assert!(format!("{err}").contains("2 children"));
    }

    #[test]
    fn merge_with_duplicate_parent_zones_rejected() {
        let mut s = make_merge_seal();
        s.parents[1].zone_id = s.parents[0].zone_id.clone();
        let err = s.validate_structure().unwrap_err();
        assert!(format!("{err}").contains("distinct"));
    }

    #[test]
    fn dispute_window_enforced() {
        let mut s = make_split_seal();
        s.proposed_at_epoch = 999; // should be 997 for effective=1000 and window=3
        let err = s.validate_structure().unwrap_err();
        assert!(format!("{err}").contains("dispute window"));
    }

    /// A seal carrying more than MAX_PROPOSER_SIGS must be rejected by
    /// `validate_structure` so the HTTP path doesn't burn Dilithium3
    /// verification cycles on a flood of attacker sigs.
    #[test]
    fn proposer_sigs_over_cap_rejected() {
        let mut s = make_split_seal();
        // Fill with `MAX_PROPOSER_SIGS + 1` distinct anchor sigs — content
        // doesn't matter for the structural cap, only the length.
        for i in 0..=MAX_PROPOSER_SIGS as u32 {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_be_bytes());
            s.proposer_sigs.push(AnchorSig {
                anchor_identity_hash: h,
                dilithium3_sig: vec![0xaa; 32],
            });
        }
        assert!(s.proposer_sigs.len() > MAX_PROPOSER_SIGS);
        let err = s.validate_structure().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("MAX_PROPOSER_SIGS") || msg.contains("proposer_sigs.len()"),
            "expected cap-exceeded error, got: {msg}"
        );
    }

    /// Exactly MAX_PROPOSER_SIGS is still accepted — the cap is inclusive.
    #[test]
    fn proposer_sigs_at_cap_accepted() {
        let mut s = make_split_seal();
        for i in 0..MAX_PROPOSER_SIGS as u32 {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_be_bytes());
            s.proposer_sigs.push(AnchorSig {
                anchor_identity_hash: h,
                dilithium3_sig: vec![0xaa; 32],
            });
        }
        assert_eq!(s.proposer_sigs.len(), MAX_PROPOSER_SIGS);
        s.validate_structure()
            .expect("seal at MAX_PROPOSER_SIGS should pass structural check");
    }

    #[test]
    fn split_account_routing() {
        let s = make_split_seal();
        let low = [0x00u8; 32];
        let high = [0xffu8; 32];
        let exact_boundary = [0x80u8; 32];
        // account < split_key → children[0]
        assert_eq!(s.account_belongs_to_child(&low), Some(&ZoneId::new("medical/eu/west")));
        // account >= split_key → children[1]
        assert_eq!(s.account_belongs_to_child(&high), Some(&ZoneId::new("medical/eu/east")));
        // boundary itself is NOT less-than → children[1]
        assert_eq!(s.account_belongs_to_child(&exact_boundary), Some(&ZoneId::new("medical/eu/east")));
    }

    #[test]
    fn merge_account_routing() {
        let s = make_merge_seal();
        let any_hash = [0x42u8; 32];
        assert_eq!(s.account_belongs_to_child(&any_hash), Some(&ZoneId::new("iot")));
    }

    #[test]
    fn canonical_encode_excludes_sigs() {
        let mut s = make_split_seal();
        let bytes_empty = s.canonical_encode_for_sig().expect("encode empty");
        let hash_empty = s.seal_hash_for_sig().expect("hash empty");

        // Add a fake sig — canonical encode should be byte-identical.
        s.proposer_sigs.push(AnchorSig {
            anchor_identity_hash: [9u8; 32],
            dilithium3_sig: vec![0u8; 3309],
        });
        let bytes_sigged = s.canonical_encode_for_sig().expect("encode sigged");
        let hash_sigged = s.seal_hash_for_sig().expect("hash sigged");

        assert_eq!(bytes_empty, bytes_sigged, "proposer_sigs must not affect canonical bytes");
        assert_eq!(hash_empty, hash_sigged, "proposer_sigs must not affect sig hash");
    }

    #[test]
    fn serde_roundtrip() {
        let s = make_split_seal();
        let json = serde_json::to_string(&s).expect("serialize");
        let back: TransitionSeal = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(s, back);
    }

    #[test]
    fn verify_sigs_requires_threshold() {
        let mut s = make_split_seal();
        let hash = s.seal_hash_for_sig().expect("hash");

        // Mint 5 anchors, sign with 4 of them — should pass SPLIT threshold (4).
        let mut registry: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        let mut sigs: Vec<AnchorSig> = Vec::new();
        for i in 0..5 {
            let kp = dilithium3_keygen().expect("keygen");
            let id = sha3_256(&kp.public_key);
            registry.insert(id, kp.public_key.clone());
            if i < 4 {
                let sig = dilithium3_sign_with_pk(&hash, &kp.secret_key, &kp.public_key)
                    .expect("sign");
                sigs.push(AnchorSig {
                    anchor_identity_hash: id,
                    dilithium3_sig: sig,
                });
            }
        }
        s.proposer_sigs = sigs;
        s.verify_sigs(&registry, SPLIT_ANCHOR_THRESHOLD).expect("4 valid sigs meets split threshold");

        // Drop one sig — must fail.
        s.proposer_sigs.pop();
        let err = s.verify_sigs(&registry, SPLIT_ANCHOR_THRESHOLD).unwrap_err();
        assert!(format!("{err}").contains("3 valid"));
    }

    #[test]
    fn verify_sigs_rejects_forgery() {
        let mut s = make_split_seal();
        let hash = s.seal_hash_for_sig().expect("hash");

        // 4 valid sigs — would pass.
        let mut registry: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        let mut sigs: Vec<AnchorSig> = Vec::new();
        for _ in 0..4 {
            let kp = dilithium3_keygen().expect("keygen");
            let id = sha3_256(&kp.public_key);
            registry.insert(id, kp.public_key.clone());
            let sig = dilithium3_sign_with_pk(&hash, &kp.secret_key, &kp.public_key)
                .expect("sign");
            sigs.push(AnchorSig {
                anchor_identity_hash: id,
                dilithium3_sig: sig,
            });
        }
        s.proposer_sigs = sigs;

        // Now tamper the seal — all sigs become invalid (hash changes).
        s.effective_epoch = 9999;
        s.proposed_at_epoch = 9996;
        let err = s.verify_sigs(&registry, SPLIT_ANCHOR_THRESHOLD).unwrap_err();
        assert!(format!("{err}").contains("0 valid"));
    }

    #[test]
    fn verify_sigs_dedupes_duplicate_anchor() {
        let mut s = make_split_seal();
        let hash = s.seal_hash_for_sig().expect("hash");

        let mut registry: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        // Only 1 real anchor, but append its sig 4 times.
        let kp = dilithium3_keygen().expect("keygen");
        let id = sha3_256(&kp.public_key);
        registry.insert(id, kp.public_key.clone());
        let sig = dilithium3_sign_with_pk(&hash, &kp.secret_key, &kp.public_key)
            .expect("sign");
        for _ in 0..4 {
            s.proposer_sigs.push(AnchorSig {
                anchor_identity_hash: id,
                dilithium3_sig: sig.clone(),
            });
        }
        // Even with 4 copies of the same anchor's sig, we count 1 distinct.
        let err = s.verify_sigs(&registry, SPLIT_ANCHOR_THRESHOLD).unwrap_err();
        assert!(format!("{err}").contains("1 valid"));
    }

    #[test]
    fn merge_uses_stricter_threshold() {
        let split = make_split_seal();
        let merge = make_merge_seal();
        assert_eq!(split.required_threshold(), SPLIT_ANCHOR_THRESHOLD);
        assert_eq!(merge.required_threshold(), MERGE_ANCHOR_THRESHOLD);
        assert!(merge.required_threshold() > split.required_threshold());
    }

    // ─── sign_as_anchor tests ────────────────────────────────────────

    /// Signing an unsigned seal produces a sig that `verify_sigs` accepts
    /// when the anchor is in the registry.
    #[test]
    fn sign_as_anchor_produces_verifiable_sig() {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).expect("gen");

        let mut s = make_split_seal();
        s.sign_as_anchor(&id).expect("sign");

        assert_eq!(s.proposer_sigs.len(), 1);
        let anchor_hash = sha3_256(&id.public_key);
        assert_eq!(s.proposer_sigs[0].anchor_identity_hash, anchor_hash);

        // Seal hash is computed with proposer_sigs cleared, so verify the
        // sig against that hash directly.
        let hash = s.seal_hash_for_sig().expect("hash");
        let ok = pqc::dilithium3_verify(&hash, &s.proposer_sigs[0].dilithium3_sig, &id.public_key)
            .expect("verify");
        assert!(ok, "sig from sign_as_anchor must verify");

        // And through the public verify_sigs API (threshold=1 since only 1 sig).
        let mut registry: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        registry.insert(anchor_hash, id.public_key.clone());
        s.verify_sigs(&registry, 1).expect("verify via registry");
    }

    /// Same anchor signing twice returns an error on the second call; the
    /// first sig is preserved so the caller can recover.
    #[test]
    fn sign_as_anchor_rejects_double_sign() {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).expect("gen");

        let mut s = make_split_seal();
        s.sign_as_anchor(&id).expect("first sign");
        let err = s.sign_as_anchor(&id).unwrap_err();
        assert!(format!("{err}").contains("already signed"));
        assert_eq!(s.proposer_sigs.len(), 1, "first sig must be retained");
    }

    /// Refuses to sign once proposer_sigs is at MAX_PROPOSER_SIGS so the
    /// writer path can't exceed the cap that `validate_structure` enforces.
    #[test]
    fn sign_as_anchor_rejects_when_at_cap() {
        use crate::identity::{CryptoProfile, EntityType, Identity};

        let mut s = make_split_seal();
        // Fill to exactly MAX_PROPOSER_SIGS with cheap fake sigs (distinct
        // anchor hashes so the dup-check doesn't fire first).
        for i in 0..MAX_PROPOSER_SIGS as u32 {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_be_bytes());
            s.proposer_sigs.push(AnchorSig {
                anchor_identity_hash: h,
                dilithium3_sig: vec![0xaa; 32],
            });
        }
        assert_eq!(s.proposer_sigs.len(), MAX_PROPOSER_SIGS);

        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).expect("gen");
        let err = s.sign_as_anchor(&id).unwrap_err();
        assert!(
            format!("{err}").contains("proposer_sigs full"),
            "expected cap error, got {err}"
        );
        assert_eq!(s.proposer_sigs.len(), MAX_PROPOSER_SIGS, "no sig appended at cap");
    }

    /// Multiple anchors signing in arbitrary order produce a proposer_sigs
    /// vector sorted by anchor_identity_hash — byte-stable across peers.
    #[test]
    fn sign_as_anchor_keeps_sigs_sorted() {
        use crate::identity::{CryptoProfile, EntityType, Identity};

        let mut s = make_split_seal();
        // Generate 5 identities, sign in a shuffled order.
        let mut ids: Vec<Identity> = (0..5)
            .map(|_| Identity::generate(EntityType::Device, CryptoProfile::ProfileB).expect("gen"))
            .collect();
        // Arbitrary non-sorted sign order.
        let order = [2usize, 0, 4, 1, 3];
        for i in order {
            s.sign_as_anchor(&ids[i]).expect("sign");
        }

        // Verify sigs are sorted ascending by anchor_identity_hash.
        let hashes: Vec<[u8; 32]> =
            s.proposer_sigs.iter().map(|a| a.anchor_identity_hash).collect();
        let mut sorted = hashes.clone();
        sorted.sort();
        assert_eq!(hashes, sorted, "proposer_sigs must be sorted by anchor_identity_hash");

        // And all 5 sigs verify end-to-end.
        let mut registry: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
        while let Some(id) = ids.pop() {
            registry.insert(sha3_256(&id.public_key), id.public_key.clone());
        }
        s.verify_sigs(&registry, 5).expect("all 5 sigs valid");
    }

    /// Signing does NOT validate structure — intentional (orchestrators
    /// sign after building and may batch validation). The store path
    /// revalidates on insert.
    #[test]
    fn sign_as_anchor_does_not_validate_structure() {
        use crate::identity::{CryptoProfile, EntityType, Identity};

        let mut s = make_split_seal();
        s.split_key = None; // make it structurally invalid
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).expect("gen");
        s.sign_as_anchor(&id)
            .expect("sign_as_anchor should not run structural validation");
        assert_eq!(s.proposer_sigs.len(), 1);
    }

    // ─── build_zone_snapshot / newborn_child_snapshot tests ─────────

    fn tmp_storage() -> (crate::storage::rocks::StorageEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let eng = crate::storage::rocks::StorageEngine::open(dir.path()).expect("open");
        (eng, dir)
    }

    /// Snapshot of an unknown zone carries the empty-tree sentinel and
    /// zero counts — proposers building a seal for a brand-new zone get
    /// a structurally valid snapshot without special-casing in the caller.
    #[test]
    fn build_snapshot_of_empty_zone() {
        let (storage, _dir) = tmp_storage();
        let zone = ZoneId::from_legacy(42);
        let snap = build_zone_snapshot(&storage, zone.clone(), [0u8; 32]).expect("snap");
        assert_eq!(snap.zone_id, zone);
        assert_eq!(snap.record_count, 0);
        assert_eq!(snap.last_seal_record_id, "");
        assert_eq!(snap.committee_hash, [0u8; 32]);
        // state_root should equal the SparseMerkleTree empty sentinel —
        // sanity-check shape, not value (kept internal to merkle.rs).
        let tree = super::super::merkle::SparseMerkleTree::new(&storage, zone);
        assert_eq!(snap.state_root, tree.root().expect("root"));
    }

    /// After inserting leaves into a zone's tree, the snapshot's
    /// state_root and record_count match the tree.
    #[test]
    fn build_snapshot_reflects_zone_tree() {
        use crate::crypto::hash::sha3_256 as hash;
        let (storage, _dir) = tmp_storage();
        let zone = ZoneId::from_legacy(7);

        // Populate the zone's tree with a few leaves.
        {
            let mut tree = super::super::merkle::SparseMerkleTree::new(&storage, zone.clone());
            tree.insert(&hash(b"record_a")).expect("ins a");
            tree.insert(&hash(b"record_b")).expect("ins b");
            tree.insert(&hash(b"record_c")).expect("ins c");
            tree.commit().expect("commit");
        }

        let snap = build_zone_snapshot(&storage, zone.clone(), [0u8; 32]).expect("snap");
        assert_eq!(snap.record_count, 3);

        // Compare against a fresh tree handle (reads from storage).
        let tree = super::super::merkle::SparseMerkleTree::new(&storage, zone);
        assert_eq!(snap.state_root, tree.root().expect("root"));
        assert_ne!(snap.state_root, [0u8; 32]);
    }

    /// A snapshot built from live state is structurally valid when plugged
    /// into a seal — no None-fields, no surprising types.
    #[test]
    fn snapshot_composes_into_valid_split_seal() {
        use crate::crypto::hash::sha3_256 as hash;
        let (storage, _dir) = tmp_storage();
        let parent_zone = ZoneId::from_legacy(1);
        {
            let mut tree = super::super::merkle::SparseMerkleTree::new(&storage, parent_zone.clone());
            tree.insert(&hash(b"r1")).expect("ins");
            tree.commit().expect("commit");
        }

        let parent = build_zone_snapshot(&storage, parent_zone, [0u8; 32]).expect("parent snap");
        let child0 = newborn_child_snapshot(ZoneId::from_legacy(2), [1u8; 32]);
        let child1 = newborn_child_snapshot(ZoneId::from_legacy(3), [2u8; 32]);

        let seal = TransitionSeal {
            kind: TransitionKind::Split,
            effective_epoch: 100,
            proposed_at_epoch: 97,
            parents: vec![parent],
            children: vec![child0, child1],
            split_key: Some([0x80u8; 32]),
            proposer_sigs: vec![],
        };
        seal.validate_structure().expect("seal built from snapshot must validate");
    }

    /// Newborn child's state_root matches the SparseMerkleTree EMPTY_HASH
    /// sentinel. If that constant ever changes, this test catches the drift.
    #[test]
    fn newborn_child_matches_empty_tree_sentinel() {
        let (storage, _dir) = tmp_storage();
        // A fresh tree for a never-touched zone produces EMPTY_HASH.
        let tree = super::super::merkle::SparseMerkleTree::new(&storage, ZoneId::from_legacy(999));
        let live_empty = tree.root().expect("root");
        let child = newborn_child_snapshot(ZoneId::from_legacy(42), [7u8; 32]);
        assert_eq!(
            child.state_root, live_empty,
            "newborn_child_snapshot state_root must match live SparseMerkleTree empty root"
        );
    }

    // ─── constants + threshold relation tests ─────────────────────────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_zts_constants_strict_pin_and_threshold_cross_relations() {
        // Axis 1: Module constants strict-pin + cross-relations.

        // Numeric values + type pins.
        assert_eq!(SPLIT_ANCHOR_THRESHOLD, 4_usize);
        assert_eq!(MERGE_ANCHOR_THRESHOLD, 7_usize);
        assert_eq!(TRANSITION_DISPUTE_WINDOW_EPOCHS, 3_u64);
        assert_eq!(MAX_PROPOSER_SIGS, 32_usize);

        // Type pins (force compile-time type check).
        let _s: usize = SPLIT_ANCHOR_THRESHOLD;
        let _m: usize = MERGE_ANCHOR_THRESHOLD;
        let _d: u64 = TRANSITION_DISPUTE_WINDOW_EPOCHS;
        let _x: usize = MAX_PROPOSER_SIGS;

        // Cross-relation: MERGE > SPLIT (load-bearing — merge concentrates
        // state and can't be cleanly undone, so it demands a stricter
        // supermajority than split, per module docs §38).
        assert!(MERGE_ANCHOR_THRESHOLD > SPLIT_ANCHOR_THRESHOLD,
            "merge must require strictly more sigs than split");

        // MAX_PROPOSER_SIGS > MERGE (cap leaves headroom for full committee
        // + redundant sigs without blowing the dilithium3_verify CPU budget).
        assert!(MAX_PROPOSER_SIGS > MERGE_ANCHOR_THRESHOLD,
            "max sigs cap must leave room above the merge threshold");

        // 4x+ headroom: caps don't bind on any plausible-size committee.
        assert!(MAX_PROPOSER_SIGS as f64 / MERGE_ANCHOR_THRESHOLD as f64 > 4.0,
            "max sigs cap must leave 4x+ headroom over merge threshold");

        // Numerical gap: MERGE − SPLIT == 3 (4 + 3 = 7).
        assert_eq!(MERGE_ANCHOR_THRESHOLD - SPLIT_ANCHOR_THRESHOLD, 3);

        // Dispute window > 0 (a 0-epoch window would let same-epoch disputes
        // race with the seal proposal).
        assert!(TRANSITION_DISPUTE_WINDOW_EPOCHS > 0);

        // Sanity: dispute window is short enough to not stall light clients
        // for hours (at 120 s/epoch this is 6 min).
        assert!(TRANSITION_DISPUTE_WINDOW_EPOCHS < 10);

        // Thresholds themselves > 0 (a 0-sig seal would be unsigned).
        assert!(SPLIT_ANCHOR_THRESHOLD > 0);
        assert!(MERGE_ANCHOR_THRESHOLD > 0);
    }

    #[test]
    fn batch_b_zts_transition_kind_copy_semantics_and_serde_pin() {
        // Axis 2: TransitionKind 2-variant Copy/Eq/serde wire-format pin.

        // Copy semantics — original still usable after by-value moves.
        let k = TransitionKind::Split;
        let _moved = k;        // Copy, not move
        let _again = k;        // still usable
        let _third = k;        // ...and still usable

        // PartialEq + Eq pairwise distinctness across the 2x2 matrix.
        assert_eq!(TransitionKind::Split, TransitionKind::Split);
        assert_eq!(TransitionKind::Merge, TransitionKind::Merge);
        assert_ne!(TransitionKind::Split, TransitionKind::Merge);
        assert_ne!(TransitionKind::Merge, TransitionKind::Split);

        // Debug emits variant names (visible to operators in error messages).
        let dbg_split = format!("{:?}", TransitionKind::Split);
        let dbg_merge = format!("{:?}", TransitionKind::Merge);
        assert!(dbg_split.contains("Split"));
        assert!(dbg_merge.contains("Merge"));
        assert_ne!(dbg_split, dbg_merge);

        // Serde: no rename_all → default PascalCase tags "Split" / "Merge".
        // Wire-format pin (load-bearing — changing this is a chain-breaking
        // gossip-format break).
        let json_split = serde_json::to_string(&TransitionKind::Split).expect("ser split");
        let json_merge = serde_json::to_string(&TransitionKind::Merge).expect("ser merge");
        assert_eq!(json_split, "\"Split\"");
        assert_eq!(json_merge, "\"Merge\"");
        assert_ne!(json_split, json_merge);

        // JSON round-trip per variant.
        let back_split: TransitionKind = serde_json::from_str(&json_split).expect("de split");
        let back_merge: TransitionKind = serde_json::from_str(&json_merge).expect("de merge");
        assert_eq!(back_split, TransitionKind::Split);
        assert_eq!(back_merge, TransitionKind::Merge);

        // Clone is auto-derived but pin behavior.
        #[allow(clippy::clone_on_copy)] // intentional — pin Clone-derive presence on Copy type
        let cloned = TransitionKind::Split.clone();
        assert_eq!(cloned, TransitionKind::Split);
    }

    #[test]
    fn batch_b_zts_zone_snapshot_anchorsig_transition_seal_field_shape_and_serde_roundtrip() {
        // Axis 3: ZoneSnapshot 5-field + AnchorSig 2-field + TransitionSeal
        // 7-field exhaustive destructure + serde round-trip.

        // ZoneSnapshot exhaustive destructure — forces compile-time field
        // stability. Renaming/removing/adding a field fails to compile.
        let snap = ZoneSnapshot {
            zone_id: ZoneId::new("z-a"),
            state_root: [1u8; 32],
            last_seal_record_id: "seal-x".to_string(),
            record_count: 42,
            committee_hash: [2u8; 32],
        };
        let ZoneSnapshot {
            zone_id: _,
            state_root: _,
            last_seal_record_id: _,
            record_count: _,
            committee_hash: _,
        } = &snap;

        // Per-field type pin.
        let _zid: ZoneId = snap.zone_id.clone();
        let _sr: [u8; 32] = snap.state_root;
        let _lsr: String = snap.last_seal_record_id.clone();
        let _rc: u64 = snap.record_count;
        let _ch: [u8; 32] = snap.committee_hash;

        // ZoneSnapshot serde JSON round-trip preserves all 5 fields
        // (PartialEq derived → field-by-field comparison).
        let snap_json = serde_json::to_string(&snap).expect("ser snap");
        let snap_back: ZoneSnapshot = serde_json::from_str(&snap_json).expect("de snap");
        assert_eq!(snap_back, snap);

        // AnchorSig exhaustive destructure (2 fields).
        let sig = AnchorSig {
            anchor_identity_hash: [3u8; 32],
            dilithium3_sig: vec![0xaa; 100],
        };
        let AnchorSig {
            anchor_identity_hash: _,
            dilithium3_sig: _,
        } = &sig;

        let _ah: [u8; 32] = sig.anchor_identity_hash;
        let _ds: Vec<u8> = sig.dilithium3_sig.clone();

        // AnchorSig serde round-trip preserves both fields.
        let sig_json = serde_json::to_string(&sig).expect("ser sig");
        let sig_back: AnchorSig = serde_json::from_str(&sig_json).expect("de sig");
        assert_eq!(sig_back, sig);

        // TransitionSeal exhaustive destructure (7 fields).
        let snap_b = ZoneSnapshot {
            zone_id: ZoneId::new("z-b"),
            state_root: [5u8; 32],
            last_seal_record_id: String::new(),
            record_count: 0,
            committee_hash: [6u8; 32],
        };
        let seal = TransitionSeal {
            kind: TransitionKind::Split,
            effective_epoch: 1000,
            proposed_at_epoch: 997,
            parents: vec![snap.clone()],
            children: vec![snap.clone(), snap_b.clone()],
            split_key: Some([0x80u8; 32]),
            proposer_sigs: vec![sig.clone()],
        };
        let TransitionSeal {
            kind: _,
            effective_epoch: _,
            proposed_at_epoch: _,
            parents: _,
            children: _,
            split_key: _,
            proposer_sigs: _,
        } = &seal;

        // Per-field type pin on TransitionSeal.
        let _k: TransitionKind = seal.kind;
        let _ee: u64 = seal.effective_epoch;
        let _pe: u64 = seal.proposed_at_epoch;
        let _p: Vec<ZoneSnapshot> = seal.parents.clone();
        let _c: Vec<ZoneSnapshot> = seal.children.clone();
        let _sk: Option<[u8; 32]> = seal.split_key;
        let _ps: Vec<AnchorSig> = seal.proposer_sigs.clone();

        // TransitionSeal serde JSON round-trip preserves all 7 fields.
        let seal_json = serde_json::to_string(&seal).expect("ser seal");
        let seal_back: TransitionSeal = serde_json::from_str(&seal_json).expect("de seal");
        assert_eq!(seal_back, seal);

        // split_key=None arm also round-trips cleanly (Merge shape).
        let merge_seal = TransitionSeal {
            kind: TransitionKind::Merge,
            effective_epoch: 2000,
            proposed_at_epoch: 1997,
            parents: vec![snap.clone(), snap_b.clone()],
            children: vec![snap.clone()],
            split_key: None,
            proposer_sigs: vec![],
        };
        let merge_json = serde_json::to_string(&merge_seal).expect("ser merge");
        let merge_back: TransitionSeal = serde_json::from_str(&merge_json).expect("de merge");
        assert_eq!(merge_back.split_key, None);
        assert_eq!(merge_back, merge_seal);

        // Clone independence: mutating clone leaves original untouched.
        let mut seal_clone = seal.clone();
        seal_clone.effective_epoch = 9999;
        assert_eq!(seal.effective_epoch, 1000,
            "original unchanged after clone mutation");
        assert_eq!(seal_clone.effective_epoch, 9999);

        // empty proposer_sigs serializes to an empty array (not absent / null).
        assert!(merge_json.contains("\"proposer_sigs\":[]"),
            "empty proposer_sigs must serialize as []: {merge_json}");
    }

    #[test]
    fn batch_b_zts_validate_structure_exhaustive_error_matrix_and_dispute_window_arithmetic() {
        // Axis 4: validate_structure exhaustive error matrix + dispute-window
        // arithmetic + MAX_PROPOSER_SIGS at-cap vs over-cap boundary.

        let snap_a = ZoneSnapshot {
            zone_id: ZoneId::new("p-a"),
            state_root: [1u8; 32],
            last_seal_record_id: String::new(),
            record_count: 0,
            committee_hash: [0u8; 32],
        };
        let snap_b = ZoneSnapshot {
            zone_id: ZoneId::new("p-b"),
            state_root: [1u8; 32],
            last_seal_record_id: String::new(),
            record_count: 0,
            committee_hash: [0u8; 32],
        };
        let snap_c = ZoneSnapshot {
            zone_id: ZoneId::new("c-c"),
            state_root: [0u8; 32],
            last_seal_record_id: String::new(),
            record_count: 0,
            committee_hash: [0u8; 32],
        };

        let base_split = || TransitionSeal {
            kind: TransitionKind::Split,
            effective_epoch: 1000,
            proposed_at_epoch: 1000 - TRANSITION_DISPUTE_WINDOW_EPOCHS,
            parents: vec![snap_a.clone()],
            children: vec![snap_b.clone(), snap_c.clone()],
            split_key: Some([0x80u8; 32]),
            proposer_sigs: vec![],
        };
        let base_merge = || TransitionSeal {
            kind: TransitionKind::Merge,
            effective_epoch: 1000,
            proposed_at_epoch: 1000 - TRANSITION_DISPUTE_WINDOW_EPOCHS,
            parents: vec![snap_a.clone(), snap_b.clone()],
            children: vec![snap_c.clone()],
            split_key: None,
            proposer_sigs: vec![],
        };

        // SPLIT — valid baseline.
        base_split().validate_structure().expect("split baseline valid");

        // SPLIT — parents.len() == 0.
        let mut s = base_split(); s.parents.clear();
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("1 parent"), "got: {err}");

        // SPLIT — parents.len() == 2.
        let mut s = base_split(); s.parents.push(snap_b.clone());
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("1 parent"), "got: {err}");

        // SPLIT — children.len() == 0.
        let mut s = base_split(); s.children.clear();
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("2 children"), "got: {err}");

        // SPLIT — children.len() == 1.
        let mut s = base_split(); s.children.pop();
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("2 children"), "got: {err}");

        // SPLIT — children.len() == 3.
        let mut s = base_split(); s.children.push(snap_c.clone());
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("2 children"), "got: {err}");

        // SPLIT — split_key=None.
        let mut s = base_split(); s.split_key = None;
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("split_key"), "got: {err}");

        // MERGE — valid baseline.
        base_merge().validate_structure().expect("merge baseline valid");

        // MERGE — parents.len() == 1.
        let mut s = base_merge(); s.parents.pop();
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("2 parents"), "got: {err}");

        // MERGE — parents.len() == 3.
        let mut s = base_merge(); s.parents.push(snap_c.clone());
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("2 parents"), "got: {err}");

        // MERGE — children.len() == 0.
        let mut s = base_merge(); s.children.clear();
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("1 child"), "got: {err}");

        // MERGE — children.len() == 2.
        let mut s = base_merge(); s.children.push(snap_b.clone());
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("1 child"), "got: {err}");

        // MERGE — split_key=Some (forbidden).
        let mut s = base_merge(); s.split_key = Some([0u8; 32]);
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("split_key"), "got: {err}");

        // MERGE — duplicate parent zones.
        let mut s = base_merge(); s.parents[1].zone_id = s.parents[0].zone_id.clone();
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("distinct"), "got: {err}");

        // Dispute window arithmetic — proposed + WINDOW must equal effective.
        // off-by-+1.
        let mut s = base_split();
        s.proposed_at_epoch = s.effective_epoch - TRANSITION_DISPUTE_WINDOW_EPOCHS + 1;
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("dispute window"), "got: {err}");

        // off-by-−1.
        let mut s = base_split();
        s.proposed_at_epoch = s.effective_epoch - TRANSITION_DISPUTE_WINDOW_EPOCHS - 1;
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("dispute window"), "got: {err}");

        // proposed > effective wraps via u64 add overflow check, also rejected.
        let mut s = base_split();
        s.proposed_at_epoch = s.effective_epoch + 1;
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("dispute window"), "got: {err}");

        // proposed == effective (window=0) → rejected.
        let mut s = base_split();
        s.proposed_at_epoch = s.effective_epoch;
        let err = format!("{}", s.validate_structure().unwrap_err());
        assert!(err.contains("dispute window"), "got: {err}");

        // MAX_PROPOSER_SIGS boundary: at-cap (len == MAX) accepted.
        let mut s = base_split();
        for i in 0..MAX_PROPOSER_SIGS as u32 {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_be_bytes());
            s.proposer_sigs.push(AnchorSig {
                anchor_identity_hash: h,
                dilithium3_sig: vec![0xaa; 32],
            });
        }
        assert_eq!(s.proposer_sigs.len(), MAX_PROPOSER_SIGS);
        s.validate_structure().expect("at-cap proposer_sigs accepted");

        // One over cap (len == MAX+1) rejected.
        let mut s_over = s.clone();
        s_over.proposer_sigs.push(AnchorSig {
            anchor_identity_hash: [0xee; 32],
            dilithium3_sig: vec![0xaa; 32],
        });
        assert_eq!(s_over.proposer_sigs.len(), MAX_PROPOSER_SIGS + 1);
        let err = format!("{}", s_over.validate_structure().unwrap_err());
        assert!(err.contains("MAX_PROPOSER_SIGS") || err.contains("exceeds"),
            "got: {err}");

        // Empty proposer_sigs accepted (sig-quorum gate is in verify_sigs,
        // not in validate_structure — separation of concerns).
        let mut s_empty = base_split();
        s_empty.proposer_sigs.clear();
        s_empty.validate_structure().expect("empty proposer_sigs structurally OK");
    }

    #[test]
    fn batch_b_zts_account_routing_required_threshold_canonical_encode_and_newborn_empty_hash_sentinel() {
        // Axis 5: account_belongs_to_child + required_threshold +
        // canonical_encode exclusion + newborn_child_snapshot EMPTY_HASH
        // sentinel byte-exact pin.

        let snap = ZoneSnapshot {
            zone_id: ZoneId::new("p"),
            state_root: [1u8; 32],
            last_seal_record_id: String::new(),
            record_count: 0,
            committee_hash: [0u8; 32],
        };
        let c0 = ZoneSnapshot { zone_id: ZoneId::new("c-low"), ..snap.clone() };
        let c1 = ZoneSnapshot { zone_id: ZoneId::new("c-high"), ..snap.clone() };

        let split_seal = TransitionSeal {
            kind: TransitionKind::Split,
            effective_epoch: 100,
            proposed_at_epoch: 100 - TRANSITION_DISPUTE_WINDOW_EPOCHS,
            parents: vec![snap.clone()],
            children: vec![c0.clone(), c1.clone()],
            split_key: Some([0x80u8; 32]),
            proposer_sigs: vec![],
        };

        // Split routing: account < split_key → children[0].
        let low = [0x00u8; 32];
        assert_eq!(split_seal.account_belongs_to_child(&low),
            Some(&ZoneId::new("c-low")));

        // Just below the boundary → children[0].
        let below = [0x7fu8; 32];  // [0x7f; 32] < [0x80; 32] lexicographically
        assert_eq!(split_seal.account_belongs_to_child(&below),
            Some(&ZoneId::new("c-low")));

        // Exact boundary (account == split_key) → children[1]. Strict < check
        // means boundary value belongs to the "high" side.
        let boundary = [0x80u8; 32];
        assert_eq!(split_seal.account_belongs_to_child(&boundary),
            Some(&ZoneId::new("c-high")));

        // account > split_key → children[1].
        let high = [0xffu8; 32];
        assert_eq!(split_seal.account_belongs_to_child(&high),
            Some(&ZoneId::new("c-high")));

        // Just above the boundary → children[1]. Boundary = [0x80; 32]
        // (every byte 0x80); incrementing the last byte to 0x81 makes the
        // 32-byte BE lexicographic value strictly greater than boundary.
        let mut just_above = [0x80u8; 32]; just_above[31] = 0x81;
        assert_eq!(split_seal.account_belongs_to_child(&just_above),
            Some(&ZoneId::new("c-high")));

        // Split with split_key=None → None (structurally invalid input;
        // routing gracefully returns None rather than panicking).
        let mut bad_split = split_seal.clone();
        bad_split.split_key = None;
        assert_eq!(bad_split.account_belongs_to_child(&low), None);

        // Merge routing: always children[0] regardless of account_hash.
        let snap2 = ZoneSnapshot { zone_id: ZoneId::new("p2"), ..snap.clone() };
        let merge_child = ZoneSnapshot { zone_id: ZoneId::new("merged"), ..snap.clone() };
        let merge_seal = TransitionSeal {
            kind: TransitionKind::Merge,
            effective_epoch: 100,
            proposed_at_epoch: 100 - TRANSITION_DISPUTE_WINDOW_EPOCHS,
            parents: vec![snap.clone(), snap2.clone()],
            children: vec![merge_child.clone()],
            split_key: None,
            proposer_sigs: vec![],
        };
        assert_eq!(merge_seal.account_belongs_to_child(&low),
            Some(&ZoneId::new("merged")));
        assert_eq!(merge_seal.account_belongs_to_child(&high),
            Some(&ZoneId::new("merged")));
        assert_eq!(merge_seal.account_belongs_to_child(&boundary),
            Some(&ZoneId::new("merged")));

        // required_threshold by kind (load-bearing — orchestration paths
        // dispatch quorum gate on this value).
        assert_eq!(split_seal.required_threshold(), SPLIT_ANCHOR_THRESHOLD);
        assert_eq!(merge_seal.required_threshold(), MERGE_ANCHOR_THRESHOLD);
        assert!(merge_seal.required_threshold() > split_seal.required_threshold());

        // canonical_encode_for_sig: adding proposer_sigs MUST NOT affect
        // bytes (load-bearing — sigs are over the canonical form sans sigs,
        // so any bytewise dependence would invalidate every signature on
        // sig-add and the M-of-N gathering would never converge).
        let bytes_empty = split_seal.canonical_encode_for_sig().expect("encode empty");
        let hash_empty = split_seal.seal_hash_for_sig().expect("hash empty");

        // SHA3-256 output is always 32 bytes.
        assert_eq!(hash_empty.len(), 32);

        let mut sealed = split_seal.clone();
        sealed.proposer_sigs.push(AnchorSig {
            anchor_identity_hash: [0x42u8; 32],
            dilithium3_sig: vec![0x99u8; 3309],
        });
        let bytes_sigged = sealed.canonical_encode_for_sig().expect("encode sigged");
        let hash_sigged = sealed.seal_hash_for_sig().expect("hash sigged");
        assert_eq!(bytes_empty, bytes_sigged,
            "canonical_encode_for_sig must clear proposer_sigs (signature-stability)");
        assert_eq!(hash_empty, hash_sigged,
            "seal_hash_for_sig must be invariant under proposer_sigs growth");

        // Determinism: identical seals produce identical canonical bytes + hash.
        let bytes_again = split_seal.canonical_encode_for_sig().expect("re-encode");
        let hash_again = split_seal.seal_hash_for_sig().expect("re-hash");
        assert_eq!(bytes_empty, bytes_again);
        assert_eq!(hash_empty, hash_again);

        // Mutating a non-sig field changes the hash (sanity — sig protects
        // every other field including the dispute-window arithmetic).
        let mut tampered = split_seal.clone();
        tampered.effective_epoch = 9999;
        tampered.proposed_at_epoch = 9999 - TRANSITION_DISPUTE_WINDOW_EPOCHS;
        let hash_tampered = tampered.seal_hash_for_sig().expect("hash tamp");
        assert_ne!(hash_empty, hash_tampered,
            "canonical_encode_for_sig must cover effective_epoch + proposed_at_epoch");

        // Mutating split_key also changes the hash (covers Split-routing).
        let mut tamp_key = split_seal.clone();
        tamp_key.split_key = Some([0x40u8; 32]);
        let hash_tamp_key = tamp_key.seal_hash_for_sig().expect("hash tamp key");
        assert_ne!(hash_empty, hash_tamp_key,
            "split_key must be covered by the canonical sig hash");

        // newborn_child_snapshot byte-exact EMPTY_HASH sentinel pin.
        // FIPS 202 SHA3-256("") is well-known; the module replicates the bytes
        // verbatim (see newborn_child_snapshot:145). If SparseMerkleTree's
        // EMPTY_HASH ever changes, this catches the drift.
        let empty_hash_sentinel: [u8; 32] = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
            0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
            0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
        ];
        let nb = newborn_child_snapshot(ZoneId::new("brand-new"), [0x55u8; 32]);
        assert_eq!(nb.zone_id, ZoneId::new("brand-new"));
        assert_eq!(nb.state_root, empty_hash_sentinel,
            "newborn child's state_root must be the FIPS 202 SHA3-256(\"\") sentinel byte-exact");
        assert_eq!(nb.record_count, 0_u64);
        assert_eq!(nb.last_seal_record_id, String::new());
        assert_eq!(nb.committee_hash, [0x55u8; 32]);

        // Caller-supplied committee_hash + zone_id are preserved exactly;
        // other fields are constant (newborn-zone identity invariants are
        // not parameterized).
        let nb2 = newborn_child_snapshot(ZoneId::new("another"), [0xaau8; 32]);
        assert_eq!(nb2.committee_hash, [0xaau8; 32]);
        assert_ne!(nb2.committee_hash, nb.committee_hash);
        assert_ne!(nb2.zone_id, nb.zone_id);
        assert_eq!(nb2.state_root, empty_hash_sentinel);
        assert_eq!(nb2.record_count, 0);
        assert_eq!(nb2.last_seal_record_id, String::new());

        // Two distinct calls with the same args produce equal snapshots
        // (newborn is a pure function — no clock, no entropy).
        let nb_a = newborn_child_snapshot(ZoneId::new("same"), [0x77u8; 32]);
        let nb_b = newborn_child_snapshot(ZoneId::new("same"), [0x77u8; 32]);
        assert_eq!(nb_a, nb_b);
    }
}
