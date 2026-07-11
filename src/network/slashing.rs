//! Auto-slashing — detect and punish protocol violations.
//!
//! Slashable offenses:
//! 1. **Epoch seal equivocation**: An anchor produces two different epoch seals
//!    for the same (zone, epoch_number). This proves the anchor is trying to
//!    create conflicting views of the epoch — a fundamental BFT violation.
//! 2. **Correlation abuse**: A witness group with high correlation (>0.8)
//!    collectively controlling > 40% zone stake — indicates Sybil collusion.
//!    (Detected via fisherman challenges, not auto-slash.)
//!
//! The fisherman challenge path (challenge → jury → verdict → slash) is
//! separately wired in ingest.rs and handles manual violations.
//!
//! Only the genesis authority node auto-creates slash records.
//! Slash amount: 25% of offender's largest active stake (capped at 50% by ledger).

//!
//! Spec references:
//!   @spec economics §10

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

use tracing::{info, warn};

use crate::ZoneId;
use crate::identity::Identity;
use crate::record::{Classification, ValidationRecord};
use crate::accounting::types::slash_metadata;

use super::geo_fraud::{FraudScanInput, FraudVerdict, scan_witness_set};
use super::liveness_proof::{LivenessFailureProof, LIVENESS_SLASH_PERCENT};
use super::peer_rtt::PeerRttEstimator;
use super::state::NodeState;
use super::LockRecover;

/// Default slash percentage of the offender's largest stake.
const DEFAULT_SLASH_PERCENT: f64 = 0.25;

/// Track epoch seals per anchor for equivocation detection.
///
/// Equivocation = same anchor produces two different seals for the same
/// (zone, epoch_number). This is a BFT safety violation.
pub struct SlashingMonitor {
    /// (creator_hash, zone, epoch_number) → (seal_record_id, content_hash)
    /// If a second seal arrives with different content_hash, it's equivocation.
    seals: HashMap<(String, ZoneId, u64), (String, [u8; 32])>,
    /// Already-slashed keys to avoid repeat slashes.
    slashed: std::collections::HashSet<String>,
    /// Total auto-slashes executed.
    pub slash_count: u64,
}

impl Default for SlashingMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl SlashingMonitor {
    pub fn new() -> Self {
        Self {
            seals: HashMap::new(),
            slashed: std::collections::HashSet::new(),
            slash_count: 0,
        }
    }

    /// Record an epoch seal and check for equivocation.
    ///
    /// Returns `Some((conflicting_seal_id, conflicting_hash))` if this anchor
    /// already produced a different seal for the same (zone, epoch_number).
    pub fn record_seal(
        &mut self,
        creator_hash: &str,
        zone: &ZoneId,
        epoch_number: u64,
        seal_record_id: &str,
        content_hash: [u8; 32],
    ) -> Option<(String, [u8; 32])> {
        let key = (creator_hash.to_string(), zone.clone(), epoch_number);

        if let Some((existing_id, existing_hash)) = self.seals.get(&key) {
            if *existing_hash != content_hash && existing_id != seal_record_id {
                // Different content for same (creator, zone, epoch) = equivocation
                return Some((existing_id.clone(), *existing_hash));
            }
            // Same content or same record ID (duplicate/re-gossip) — not equivocation
            return None;
        }

        self.seals.insert(key, (seal_record_id.to_string(), content_hash));
        None
    }

    /// Check if this anchor was already slashed for this equivocation.
    pub fn already_slashed(&self, creator: &str, seal_a: &str, seal_b: &str) -> bool {
        let key = slash_dedup_key(creator, seal_a, seal_b);
        self.slashed.contains(&key)
    }

    /// Mark a slash as executed.
    pub fn mark_slashed(&mut self, creator: &str, seal_a: &str, seal_b: &str) {
        let key = slash_dedup_key(creator, seal_a, seal_b);
        self.slashed.insert(key);
        self.slash_count += 1;
    }

    /// Number of tracked seal entries.
    pub fn tracked_seals(&self) -> usize {
        self.seals.len()
    }

    /// Size of the already-slashed dedup set. Each entry is one
    /// (creator, seal_a, seal_b) tuple that was already slashed once,
    /// so a re-arrival of the same equivocation pair is short-circuited
    /// in `already_slashed()`. Operator signal — pairs the lifetime
    /// `slash_count` (rate of new slashes) with the resident dedup set
    /// size (how many distinct equivocation pairs we've ever processed).
    pub fn slashed_pair_count(&self) -> usize {
        self.slashed.len()
    }

    /// Prune seal entries older than a given epoch number per zone.
    /// Called periodically to prevent unbounded growth.
    pub fn prune_before_epoch(&mut self, zone: &ZoneId, min_epoch: u64) {
        self.seals.retain(|(_, z, epoch), _| z != zone || *epoch >= min_epoch);
    }
}

/// Deterministic dedup key: sorted record IDs to handle (a,b) == (b,a).
fn slash_dedup_key(creator: &str, seal_a: &str, seal_b: &str) -> String {
    let (first, second) = if seal_a < seal_b {
        (seal_a, seal_b)
    } else {
        (seal_b, seal_a)
    };
    format!("{creator}:{first}:{second}")
}

/// Check an incoming epoch seal for equivocation and auto-slash if detected.
///
/// Called from the ingest pipeline when an epoch seal record is processed.
/// Only the genesis authority creates slash records.
pub async fn check_seal_equivocation(
    state: &Arc<NodeState>,
    creator_hash: &str,
    zone: &ZoneId,
    epoch_number: u64,
    seal_record_id: &str,
    content_hash: [u8; 32],
) {
    // Only genesis authority can auto-slash
    if state.identity.identity_hash != state.config.genesis_authority {
        return;
    }

    // Check for equivocation
    let conflict = {
        let mut monitor = state.slashing.lock_recover();
        let conflict = monitor.record_seal(creator_hash, zone, epoch_number, seal_record_id, content_hash);
        if let Some((ref conflicting_id, _)) = conflict {
            if monitor.already_slashed(creator_hash, seal_record_id, conflicting_id) {
                return; // Already slashed this pair
            }
        }
        conflict
    };

    let Some((conflicting_seal_id, _conflicting_hash)) = conflict else {
        return;
    };

    warn!(
        "EPOCH SEAL EQUIVOCATION: anchor {} produced conflicting seals {} and {} for zone {} epoch {}",
        &creator_hash[..creator_hash.len().min(16)],
        &seal_record_id[..seal_record_id.len().min(16)],
        &conflicting_seal_id[..conflicting_seal_id.len().min(16)],
        zone,
        epoch_number,
    );

    // Find the offender's largest active stake
    let (stake_record_id, slash_amount) = {
        let ledger = state.ledger.read().await;
        let stakes = ledger.stakes_for(creator_hash);
        match stakes.iter().max_by_key(|s| s.amount) {
            Some(stake) => {
                let amount = (stake.amount as f64 * DEFAULT_SLASH_PERCENT) as u64;
                (stake.record_id.clone(), amount.max(1))
            }
            None => {
                warn!("seal equivocation by {} but no active stake — cannot slash",
                    &creator_hash[..creator_hash.len().min(16)]);
                return;
            }
        }
    };

    // Build and execute slash record
    let reason = format!(
        "auto:seal_equivocation:zone={}:epoch={}:seals={}:{}",
        zone, epoch_number,
        &seal_record_id[..seal_record_id.len().min(16)],
        &conflicting_seal_id[..conflicting_seal_id.len().min(16)],
    );

    let genesis_hash = &state.identity.identity_hash;
    match create_slash_record(SlashRecordParams {
        identity: &state.identity,
        amount: slash_amount,
        offender: creator_hash,
        challenger: genesis_hash,
        jury: std::slice::from_ref(genesis_hash),
        stake_record_id: &stake_record_id,
        reason: &reason,
        light_mode: state.config.light_mode,
        slot_nonce: state.next_slot_nonce(),
    }) {
        Ok(slash_record) => {
            // IMPORTANT: Use insert_record_inner_direct instead of gossip::insert_record
            // to avoid deadlock. This function is called from within insert_record_inner_direct
            // (via the state_core), so routing back through the state_core channel would
            // self-deadlock — the core can't process a new message while still processing
            // the current one.
            match super::ingest::insert_record_inner_direct(state, slash_record.clone(), None, false).await {
                Ok(_) => {
                    state.slashing.lock_recover().mark_slashed(
                        creator_hash, seal_record_id, &conflicting_seal_id,
                    );
                    state.auto_slashes_total.fetch_add(1, Relaxed);

                    info!(
                        "AUTO-SLASH: {} slashed {} base units for seal equivocation (zone {} epoch {})",
                        &creator_hash[..creator_hash.len().min(16)],
                        slash_amount,
                        zone,
                        epoch_number,
                    );

                    super::state::NodeState::publish_record_with_fallback(state, &slash_record, None).await;
                }
                Err(e) => warn!("auto-slash insert failed: {e}"),
            }
        }
        Err(e) => warn!("auto-slash record creation failed: {e}"),
    }
}

/// Apply a verified `LivenessFailureProof`: find the offender's largest
/// active stake, build a 1% slash record, and insert it.
///
/// Caller must have already run [`LivenessFailureProof::verify_with_stakers`]
/// — this function trusts the proof and will NOT re-verify. Dedup key is
/// `(offender, zone, epoch)` so one missed deadline can only slash once.
///
/// Only the genesis authority creates slash records (matches the
/// equivocation path in [`check_seal_equivocation`]).
pub async fn apply_liveness_slash(state: &Arc<NodeState>, proof: &LivenessFailureProof) {
    if state.identity.identity_hash != state.config.genesis_authority {
        return;
    }

    // Dedup: one liveness slash per (offender, zone, epoch). We reuse the
    // `slashed` set on SlashingMonitor by encoding the dedup key as a
    // synthetic "seal" pair, so this composes with the existing bookkeeping
    // without adding a second table.
    let dedup = proof.dedup_key();
    {
        let monitor = state.slashing.lock_recover();
        if monitor.already_slashed(&proof.offender_identity_hash, "liveness", &dedup) {
            return;
        }
    }

    let offender = &proof.offender_identity_hash;

    // Find the offender's largest active stake.
    let (stake_record_id, slash_amount) = {
        let ledger = state.ledger.read().await;
        let stakes = ledger.stakes_for(offender);
        match stakes.iter().max_by_key(|s| s.amount) {
            Some(stake) => {
                let amount = (stake.amount as f64 * LIVENESS_SLASH_PERCENT) as u64;
                (stake.record_id.clone(), amount.max(1))
            }
            None => {
                warn!(
                    "liveness failure by {} but no active stake — cannot slash",
                    &offender[..offender.len().min(16)]
                );
                return;
            }
        }
    };

    let reason = format!(
        "auto:liveness_failure:zone={}:epoch={}:base_timeout_ms={}",
        proof.zone, proof.epoch_number, proof.base_timeout_ms,
    );

    let genesis_hash = &state.identity.identity_hash;
    match create_slash_record(SlashRecordParams {
        identity: &state.identity,
        amount: slash_amount,
        offender,
        challenger: genesis_hash,
        jury: std::slice::from_ref(genesis_hash),
        stake_record_id: &stake_record_id,
        reason: &reason,
        light_mode: state.config.light_mode,
        slot_nonce: state.next_slot_nonce(),
    }) {
        Ok(slash_record) => {
            match super::ingest::insert_record_inner_direct(
                state,
                slash_record.clone(),
                None,
                false,
            )
            .await
            {
                Ok(_) => {
                    state.slashing.lock_recover().mark_slashed(
                        offender,
                        "liveness",
                        &dedup,
                    );
                    state.auto_slashes_total.fetch_add(1, Relaxed);

                    info!(
                        "AUTO-SLASH: {} slashed {} base units for liveness failure (zone {} epoch {})",
                        &offender[..offender.len().min(16)],
                        slash_amount,
                        proof.zone,
                        proof.epoch_number,
                    );

                    super::state::NodeState::publish_record_with_fallback(
                        state,
                        &slash_record,
                        None,
                    )
                    .await;
                }
                Err(e) => warn!("liveness-slash insert failed: {e}"),
            }
        }
        Err(e) => warn!("liveness-slash record creation failed: {e}"),
    }
}

/// Compute the base units slash amount for a liveness failure against a
/// given largest-stake value. Pulled out for unit testing without spinning
/// up NodeState / ledger / RocksDB.
pub fn liveness_slash_amount(largest_stake: u64) -> u64 {
    ((largest_stake as f64 * LIVENESS_SLASH_PERCENT) as u64).max(1)
}

/// Inputs to [`create_slash_record`].
///
/// Bundled so callers don't trip the `too_many_arguments` lint and so the
/// named-field construction is self-documenting at every site. All
/// borrowed; no allocation on the slash-emit path.
pub struct SlashRecordParams<'a> {
    pub identity: &'a Identity,
    pub amount: u64,
    pub offender: &'a str,
    pub challenger: &'a str,
    pub jury: &'a [String],
    pub stake_record_id: &'a str,
    pub reason: &'a str,
    pub light_mode: bool,
    /// Fresh nonce allocated from `NodeState::next_slot_nonce()`. Slash
    /// records are signed by the node's own identity and therefore share
    /// the (account, nonce) slot space with every other self-emitted
    /// record — reusing nonce=0 here caused the same SLOT EQUIVOCATION
    /// that was firing on Helsinki.
    pub slot_nonce: u64,
}

/// Create a slash `ValidationRecord`.
pub fn create_slash_record(
    params: SlashRecordParams<'_>,
) -> crate::errors::Result<ValidationRecord> {
    let SlashRecordParams {
        identity,
        amount,
        offender,
        challenger,
        jury,
        stake_record_id,
        reason,
        light_mode,
        slot_nonce,
    } = params;

    let metadata = slash_metadata(amount, offender, challenger, jury, stake_record_id, reason);
    // Canonical v2 ledger preimage (audit 2026-07-06): the old bespoke
    // "auto_slash:{offender}:{stake_record_id}" form was amount- and
    // nonce-blind and would fail the ingest enforcement gate.
    let content_str = crate::accounting::types::canonical_ledger_preimage_v2(
        &metadata,
        &identity.public_key,
        slot_nonce,
    )
    .ok_or_else(|| {
        crate::errors::ElaraError::Ledger("slash metadata missing beat_op".into())
    })?;

    let mut record = ValidationRecord::create(
        content_str.as_bytes(),
        identity.public_key.clone(),
        vec![],
        Classification::Public,
        Some(metadata),
    );
    record.nonce = slot_nonce;

    if light_mode {
        identity.sign_record_light(&mut record)?;
    } else {
        identity.sign_record(&mut record)?;
    }

    Ok(record)
}

/// Slash percentage applied to a proven geographic-fraud verdict.
///
/// Same 25% as equivocation — geo fraud is a direct attack on the
/// diversity assumption that underpins MESH-BFT §5 Theorem 3.1. Treating
/// it lighter than equivocation would encourage sybil farms to lie about
/// geography (cheap) rather than fork epochs (expensive), which is the
/// exact opposite of what the detector is meant to prevent.
pub const GEO_FRAUD_SLASH_PERCENT: f64 = DEFAULT_SLASH_PERCENT;

/// Compute the base units slash amount for a geo-fraud verdict against a
/// given largest-stake value. Pulled out for unit testing.
pub fn geo_fraud_slash_amount(largest_stake: u64) -> u64 {
    ((largest_stake as f64 * GEO_FRAUD_SLASH_PERCENT) as u64).max(1)
}

/// Apply a proven geographic-fraud verdict: find the offender's largest
/// active stake, build a slash record, and insert it.
///
/// Dedup key: `(peer_id, epoch, claimed_zone, reason_tag)` — one slash per
/// (offender, epoch, zone, category) so a single scan cannot double-slash
/// and re-scanning the same epoch is idempotent.
///
/// Caller must have already run [`scan_witness_set`] on verified RTT and witness
/// data — this function trusts the verdict and will NOT re-verify.
///
/// Only the genesis authority creates slash records.
pub async fn apply_geo_fraud_slash(
    state: &Arc<NodeState>,
    verdict: &FraudVerdict,
    epoch_number: u64,
) {
    if state.identity.identity_hash != state.config.genesis_authority {
        return;
    }

    let dedup = verdict.dedup_key(epoch_number);
    {
        let monitor = state.slashing.lock_recover();
        if monitor.already_slashed(&verdict.peer_id, "geo_fraud", &dedup) {
            return;
        }
    }

    let offender = &verdict.peer_id;

    let (stake_record_id, slash_amount) = {
        let ledger = state.ledger.read().await;
        let stakes = ledger.stakes_for(offender);
        match stakes.iter().max_by_key(|s| s.amount) {
            Some(stake) => {
                let amount = geo_fraud_slash_amount(stake.amount);
                (stake.record_id.clone(), amount)
            }
            None => {
                warn!(
                    "geo fraud by {} but no active stake — cannot slash",
                    &offender[..offender.len().min(16)]
                );
                return;
            }
        }
    };

    let reason = format!(
        "auto:geo_fraud:zone={}:epoch={}:samples={}:{}",
        verdict.claimed_zone,
        epoch_number,
        verdict.sample_count,
        verdict.reason.summary(),
    );

    let genesis_hash = &state.identity.identity_hash;
    match create_slash_record(SlashRecordParams {
        identity: &state.identity,
        amount: slash_amount,
        offender,
        challenger: genesis_hash,
        jury: std::slice::from_ref(genesis_hash),
        stake_record_id: &stake_record_id,
        reason: &reason,
        light_mode: state.config.light_mode,
        slot_nonce: state.next_slot_nonce(),
    }) {
        Ok(slash_record) => {
            match super::ingest::insert_record_inner_direct(
                state,
                slash_record.clone(),
                None,
                false,
            )
            .await
            {
                Ok(_) => {
                    state.slashing.lock_recover().mark_slashed(
                        offender,
                        "geo_fraud",
                        &dedup,
                    );
                    state.auto_slashes_total.fetch_add(1, Relaxed);

                    info!(
                        "AUTO-SLASH: {} slashed {} base units for geo fraud (zone {} epoch {} tag {})",
                        &offender[..offender.len().min(16)],
                        slash_amount,
                        verdict.claimed_zone,
                        epoch_number,
                        verdict.reason.tag(),
                    );

                    super::state::NodeState::publish_record_with_fallback(
                        state,
                        &slash_record,
                        None,
                    )
                    .await;
                }
                Err(e) => warn!("geo-fraud insert failed: {e}"),
            }
        }
        Err(e) => warn!("geo-fraud record creation failed: {e}"),
    }
}

/// Run the geographic-fraud detector against the current witness set and
/// apply one slash per fresh verdict. Deterministic order (verdicts are
/// lex-sorted by [`scan_witness_set`]).
///
/// Intended to be invoked at epoch boundaries by the slashing worker —
/// O(n + n²) over the witness set (committee-sized, so trivial even at
/// 1M-zone scale since every committee is bounded per Stage 5 spec).
pub async fn scan_and_slash_geo_fraud(
    state: &Arc<NodeState>,
    witnesses: &[(String, super::consensus::WitnessProfile)],
    rtt: &PeerRttEstimator,
    epoch_number: u64,
) -> usize {
    if state.identity.identity_hash != state.config.genesis_authority {
        return 0;
    }

    let verdicts = scan_witness_set(FraudScanInput { witnesses, rtt });
    let found = verdicts.len();
    for verdict in &verdicts {
        apply_geo_fraud_slash(state, verdict, epoch_number).await;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_no_equivocation_same_seal() {
        let mut monitor = SlashingMonitor::new();
        let zone = ZoneId::from_legacy(0);
        let hash = [0xAA; 32];
        // Same seal re-gossiped — not equivocation
        assert!(monitor.record_seal("anchor1", &zone, 1, "seal_a", hash).is_none());
        assert!(monitor.record_seal("anchor1", &zone, 1, "seal_a", hash).is_none());
    }

    #[test]
    fn test_monitor_no_equivocation_different_anchors() {
        let mut monitor = SlashingMonitor::new();
        let zone = ZoneId::from_legacy(0);
        // Different anchors sealing same zone+epoch — that's multi-anchor, not equivocation
        assert!(monitor.record_seal("anchor1", &zone, 1, "seal_a", [0xAA; 32]).is_none());
        assert!(monitor.record_seal("anchor2", &zone, 1, "seal_b", [0xBB; 32]).is_none());
    }

    #[test]
    fn test_monitor_no_equivocation_different_epochs() {
        let mut monitor = SlashingMonitor::new();
        let zone = ZoneId::from_legacy(0);
        // Same anchor, different epochs — normal progression
        assert!(monitor.record_seal("anchor1", &zone, 1, "seal_a", [0xAA; 32]).is_none());
        assert!(monitor.record_seal("anchor1", &zone, 2, "seal_b", [0xBB; 32]).is_none());
    }

    #[test]
    fn test_monitor_detects_seal_equivocation() {
        let mut monitor = SlashingMonitor::new();
        let zone = ZoneId::from_legacy(0);
        // Same anchor, same zone, same epoch, DIFFERENT content — equivocation!
        assert!(monitor.record_seal("anchor1", &zone, 5, "seal_a", [0xAA; 32]).is_none());
        let conflict = monitor.record_seal("anchor1", &zone, 5, "seal_b", [0xBB; 32]);
        assert!(conflict.is_some());
        let (conflicting_id, conflicting_hash) = conflict.unwrap();
        assert_eq!(conflicting_id, "seal_a");
        assert_eq!(conflicting_hash, [0xAA; 32]);
    }

    #[test]
    fn test_monitor_no_equivocation_different_zones() {
        let mut monitor = SlashingMonitor::new();
        let zone0 = ZoneId::from_legacy(0);
        let zone1 = ZoneId::from_legacy(1);
        // Same anchor, same epoch, different zones — each zone gets its own seal
        assert!(monitor.record_seal("anchor1", &zone0, 1, "seal_a", [0xAA; 32]).is_none());
        assert!(monitor.record_seal("anchor1", &zone1, 1, "seal_b", [0xBB; 32]).is_none());
    }

    #[test]
    fn test_dedup_key_symmetric() {
        let k1 = slash_dedup_key("a1", "seal_a", "seal_b");
        let k2 = slash_dedup_key("a1", "seal_b", "seal_a");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_already_slashed() {
        let mut monitor = SlashingMonitor::new();
        assert!(!monitor.already_slashed("a1", "s1", "s2"));
        monitor.mark_slashed("a1", "s1", "s2");
        assert!(monitor.already_slashed("a1", "s1", "s2"));
        assert!(monitor.already_slashed("a1", "s2", "s1")); // symmetric
        assert!(!monitor.already_slashed("a2", "s1", "s2")); // different anchor
    }

    #[test]
    fn test_prune_old_epochs() {
        let mut monitor = SlashingMonitor::new();
        let zone = ZoneId::from_legacy(0);
        monitor.record_seal("a1", &zone, 1, "s1", [0x01; 32]);
        monitor.record_seal("a1", &zone, 5, "s5", [0x05; 32]);
        monitor.record_seal("a1", &zone, 10, "s10", [0x0A; 32]);
        assert_eq!(monitor.tracked_seals(), 3);

        monitor.prune_before_epoch(&zone, 5);
        assert_eq!(monitor.tracked_seals(), 2); // epochs 5 and 10 remain
    }

    /// Pin the three metric helpers' semantics across the full
    /// slash lifecycle. The /metrics emission relies on:
    ///   I1: empty monitor reports (slash_count=0, tracked_seals=0,
    ///       slashed_pair_count=0).
    ///   I2: `record_seal` (no conflict path) advances `tracked_seals`
    ///       but NOT `slash_count` or `slashed_pair_count` (the slash
    ///       only happens after `mark_slashed`).
    ///   I3: a conflict detected via `record_seal` returning
    ///       `Some(...)` does NOT itself increment `slash_count` —
    ///       slashing is two-phase (detect, then mark). This test
    ///       guards against future-me wiring `slash_count++` into
    ///       `record_seal` and silently double-counting.
    ///   I4: `mark_slashed` advances BOTH `slash_count` and
    ///       `slashed_pair_count` by exactly 1 each call. The two
    ///       gauges must agree in every state — divergence is a bug
    ///       in slash bookkeeping.
    ///   I5: `mark_slashed` is idempotent on the dedup set (same
    ///       (creator, seal_a, seal_b) tuple inserted twice = one
    ///       entry) but the `slash_count` field DOES still increment
    ///       on each call — this is the documented behavior of
    ///       `mark_slashed` (the caller is expected to gate on
    ///       `already_slashed` first). The test pins this so future
    ///       refactors of `mark_slashed` don't silently change
    ///       semantics.
    ///   I6: `prune_before_epoch` reaps `tracked_seals` entries but
    ///       does NOT touch `slash_count` or `slashed_pair_count` —
    ///       the operator must treat the lifetime counter and the
    ///       dedup set as monotonic across prune cycles, the
    ///       resident-set gauge as instantaneous.
    #[test]
    fn ops_49_metric_invariants_pin_slash_lifecycle() {
        let mut monitor = SlashingMonitor::new();
        let zone = ZoneId::from_legacy(0);

        // I1: fresh monitor → all three metrics 0.
        assert_eq!(monitor.slash_count, 0);
        assert_eq!(monitor.tracked_seals(), 0);
        assert_eq!(monitor.slashed_pair_count(), 0);

        // I2: `record_seal` (no conflict) advances tracked_seals only.
        let conflict = monitor.record_seal("a1", &zone, 1, "s1", [0x01; 32]);
        assert!(conflict.is_none(), "first seal cannot conflict");
        assert_eq!(monitor.tracked_seals(), 1);
        assert_eq!(monitor.slash_count, 0, "I2: no slash yet");
        assert_eq!(monitor.slashed_pair_count(), 0, "I2: no dedup yet");

        // I3: a SECOND seal with different content for same (anchor, zone,
        // epoch) returns Some — but slash_count and dedup are unchanged
        // until mark_slashed is called. Slashing is intentionally two-phase.
        let conflict = monitor.record_seal("a1", &zone, 1, "s2", [0x02; 32]);
        assert!(conflict.is_some(), "I3: equivocation detected");
        assert_eq!(
            monitor.slash_count, 0,
            "I3: detection must NOT auto-increment slash_count"
        );
        assert_eq!(
            monitor.slashed_pair_count(),
            0,
            "I3: detection must NOT auto-add dedup entry"
        );
        assert_eq!(
            monitor.tracked_seals(),
            1,
            "I3: conflicting seal does not insert (the original survives)"
        );

        // I4: mark_slashed advances BOTH slash_count and dedup by exactly 1.
        monitor.mark_slashed("a1", "s1", "s2");
        assert_eq!(monitor.slash_count, 1);
        assert_eq!(monitor.slashed_pair_count(), 1);
        assert!(monitor.already_slashed("a1", "s1", "s2"));

        // I5: re-marking the same dedup key DOES increment slash_count
        // (per the documented `mark_slashed` semantics — the caller is
        // expected to gate on `already_slashed`) but the dedup set
        // remains size 1 (HashSet idempotency). This is intentional —
        // the gauge invariant in /metrics is `dedup_pairs ≤ slash_count`,
        // NOT equality. Pin this so the dashboard alarm
        // `executed_total ≠ dedup_pairs` survives a re-mark.
        monitor.mark_slashed("a1", "s1", "s2");
        assert_eq!(
            monitor.slash_count, 2,
            "I5: re-mark increments slash_count (caller gates dedup)"
        );
        assert_eq!(
            monitor.slashed_pair_count(),
            1,
            "I5: HashSet idempotent, dedup unchanged"
        );

        // Also verify symmetric dedup: (a, s2, s1) maps to same key as
        // (a, s1, s2) so a re-mark in flipped order is also idempotent.
        monitor.mark_slashed("a1", "s2", "s1");
        assert_eq!(monitor.slash_count, 3);
        assert_eq!(
            monitor.slashed_pair_count(),
            1,
            "I5: symmetric dedup key (a,s2,s1)==(a,s1,s2)"
        );

        // Add a second distinct equivocation pair to verify the dedup
        // is keyed on the full tuple.
        monitor.mark_slashed("a2", "x", "y");
        assert_eq!(monitor.slash_count, 4);
        assert_eq!(monitor.slashed_pair_count(), 2);

        // I6: prune touches tracked_seals only.
        let prev_count = monitor.slash_count;
        let prev_dedup = monitor.slashed_pair_count();
        monitor.record_seal("a1", &zone, 5, "s5", [0x05; 32]);
        assert_eq!(monitor.tracked_seals(), 2);
        monitor.prune_before_epoch(&zone, 5);
        assert_eq!(
            monitor.tracked_seals(),
            1,
            "epoch 1 reaped, epoch 5 survives"
        );
        assert_eq!(
            monitor.slash_count, prev_count,
            "I6: prune does NOT roll back slash_count"
        );
        assert_eq!(
            monitor.slashed_pair_count(),
            prev_dedup,
            "I6: prune does NOT roll back dedup"
        );
    }

    #[test]
    fn test_liveness_slash_amount_is_one_percent() {
        // 1M base units stake → 10K base units slash (1%).
        assert_eq!(liveness_slash_amount(1_000_000), 10_000);
        // 99 base units → 0 after truncation, bumped to 1 by max(1).
        assert_eq!(liveness_slash_amount(99), 1);
        // Zero stake → still 1 (caller gates on stake presence; this is just math).
        assert_eq!(liveness_slash_amount(0), 1);
    }

    #[test]
    fn test_liveness_slash_record_shape() {
        let identity = crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        )
        .unwrap();

        let amount = liveness_slash_amount(1_000_000);
        let reason = "auto:liveness_failure:zone=0:epoch=42:base_timeout_ms=5000";
        let record = create_slash_record(SlashRecordParams {
            identity: &identity,
            amount,
            offender: "offender_hash_liveness",
            challenger: "challenger_hash",
            jury: &["challenger_hash".to_string()],
            stake_record_id: "stake_liveness_123",
            reason,
            light_mode: false,
            slot_nonce: 1,
        })
        .unwrap();

        assert!(record.signature.is_some());
        assert_eq!(
            record.metadata.get("beat_op").and_then(|v| v.as_str()),
            Some("slash"),
        );
        assert_eq!(
            record
                .metadata
                .get("beat_amount")
                .and_then(crate::accounting::types::parse_beat_amount),
            Some(10_000), // 1% of 1_000_000
        );
        assert_eq!(
            record.metadata.get("beat_reason").and_then(|v| v.as_str()),
            Some(reason),
        );
    }

    #[test]
    fn test_slash_record_creation() {
        let identity = crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        ).unwrap();

        let record = create_slash_record(SlashRecordParams {
            identity: &identity,
            amount: 1_000_000,
            offender: "offender_hash",
            challenger: "challenger_hash",
            jury: &["jury_hash".to_string()],
            stake_record_id: "stake_record_123",
            reason: "auto:seal_equivocation",
            light_mode: false,
            slot_nonce: 2,
        }).unwrap();

        assert!(record.signature.is_some());
        assert_eq!(
            record.metadata.get("beat_op").and_then(|v| v.as_str()),
            Some("slash"),
        );
        assert_eq!(
            record.metadata.get("beat_amount").and_then(crate::accounting::types::parse_beat_amount),
            Some(1_000_000),
        );
        assert_eq!(
            record.metadata.get("beat_offender").and_then(|v| v.as_str()),
            Some("offender_hash"),
        );
    }

    // ── Geo-fraud slashing: pure-function coverage ───────────────────────

    #[test]
    fn geo_fraud_slash_amount_scales_with_stake() {
        assert_eq!(geo_fraud_slash_amount(1_000_000), 250_000);
        assert_eq!(geo_fraud_slash_amount(4), 1);
        // Floor at 1 base unit so a beat-holder always pays something
        // visible — zero-stake attackers are rejected by the caller, not here.
        assert_eq!(geo_fraud_slash_amount(0), 1);
    }

    #[test]
    fn geo_fraud_dedup_key_is_stable_across_runs() {
        use super::super::geo_fraud::{FraudReason, FraudVerdict};
        let v1 = FraudVerdict {
            peer_id: "peer_A".into(),
            claimed_zone: "earth-eu".into(),
            reason: FraudReason::RttOutlierInBucket {
                bucket_median_us: 5_000,
                peer_rtt_us: 80_000,
            },
            sample_count: 50,
        };
        let v2 = FraudVerdict {
            peer_id: "peer_A".into(),
            claimed_zone: "earth-eu".into(),
            reason: FraudReason::RttOutlierInBucket {
                bucket_median_us: 6_000,   // different measurement
                peer_rtt_us: 90_000,       // different measurement
            },
            sample_count: 60,
        };
        // Same (peer, zone, epoch, category) → identical dedup key. The
        // key MUST NOT embed numeric measurements or every re-scan would
        // slash the same offender again.
        assert_eq!(v1.dedup_key(42), v2.dedup_key(42));
        // Different epoch → different key (fraud can re-offend next epoch).
        assert_ne!(v1.dedup_key(42), v1.dedup_key(43));
        // Different category on same epoch → different key (liveness-fraud
        // and outlier-fraud are separate violations).
        let v3 = FraudVerdict {
            peer_id: "peer_A".into(),
            claimed_zone: "earth-eu".into(),
            reason: FraudReason::IntercontinentalFloorViolation {
                our_rtt_us: 5_000,
                floor_us: 30_000,
                paired_peer: "peer_B".into(),
                paired_peer_zone: "earth-us".into(),
            },
            sample_count: 50,
        };
        assert_ne!(v1.dedup_key(42), v3.dedup_key(42));
    }

    #[test]
    fn geo_fraud_reason_tag_is_stable() {
        use super::super::geo_fraud::FraudReason;
        // Tags are part of the slash-record wire format: changing them
        // would invalidate historical dedup keys. Test pins the values.
        let outlier = FraudReason::RttOutlierInBucket {
            bucket_median_us: 1,
            peer_rtt_us: 1,
        };
        let floor = FraudReason::IntercontinentalFloorViolation {
            our_rtt_us: 1,
            floor_us: 1,
            paired_peer: "x".into(),
            paired_peer_zone: "earth-us".into(),
        };
        assert_eq!(outlier.tag(), "rtt_outlier");
        assert_eq!(floor.tag(), "intercontinental_floor");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Fixture-free tests (5 distinct uncovered axes)
    // ─────────────────────────────────────────────────────────────────────

    /// **Axis 1**: pin the three slash-percent constants AND their
    /// coupling.
    ///
    /// `DEFAULT_SLASH_PERCENT` is the 25% equivocation/geo-fraud penalty.
    /// `GEO_FRAUD_SLASH_PERCENT` is defined as a *literal* alias of
    /// `DEFAULT_SLASH_PERCENT` (not an independent 0.25 copy), per the
    /// §10 economics rationale: treating geo fraud lighter than
    /// equivocation would incentivize sybil farms to lie about geography
    /// instead of fork epochs. The literal coupling guards a future-me
    /// refactor that silently decouples them.
    /// `LIVENESS_SLASH_PERCENT` is the 1% rate-limit penalty (cheaper
    /// because liveness failures are recoverable). The 25:1 ratio is a
    /// load-bearing economic property surfaced by /metrics dashboards.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_slash_percent_constants_pin_severity_ordering() {
        assert_eq!(
            DEFAULT_SLASH_PERCENT, 0.25,
            "DEFAULT_SLASH_PERCENT must be 25% (equivocation default)"
        );
        assert_eq!(
            GEO_FRAUD_SLASH_PERCENT, DEFAULT_SLASH_PERCENT,
            "GEO_FRAUD_SLASH_PERCENT must alias DEFAULT_SLASH_PERCENT verbatim"
        );
        assert_eq!(
            LIVENESS_SLASH_PERCENT, 0.01,
            "LIVENESS_SLASH_PERCENT must be 1% (rate-limit tier)"
        );
        assert!(
            GEO_FRAUD_SLASH_PERCENT > LIVENESS_SLASH_PERCENT,
            "geo-fraud severity must exceed liveness severity"
        );
        let ratio = GEO_FRAUD_SLASH_PERCENT / LIVENESS_SLASH_PERCENT;
        assert!(
            (ratio - 25.0).abs() < 1e-9,
            "geo_fraud:liveness ratio must be 25:1, got {ratio}"
        );
    }

    /// **Axis 2**: pin `slash_dedup_key`'s exact wire format and
    /// lex-ordering semantics.
    ///
    /// `test_dedup_key_symmetric` proves (a,b) == (b,a). This axis pins:
    /// (i) the literal format `"{creator}:{first}:{second}"` so a
    /// future-me refactor can't change the delimiter without breaking
    /// every historical dedup entry; (ii) no-swap when seal_a < seal_b;
    /// (iii) swap when seal_a > seal_b; (iv) the creator field is NEVER
    /// folded into the lex-sort even when it'd lex above the seals;
    /// (v) degenerate (seal, seal) doesn't panic.
    #[test]
    fn batch_b_slash_dedup_key_format_and_lex_ordering() {
        assert_eq!(
            slash_dedup_key("anchor1", "seal_a", "seal_b"),
            "anchor1:seal_a:seal_b",
            "format must be {{creator}}:{{first}}:{{second}} with ':' delim"
        );
        assert_eq!(
            slash_dedup_key("anchor1", "seal_z", "seal_a"),
            "anchor1:seal_a:seal_z",
            "(z, a) must swap to (a, z) — lex-sorted second pair"
        );
        // Creator stays in slot 1 even when it'd lex above the seals.
        assert_eq!(
            slash_dedup_key("z_creator", "a_seal", "b_seal"),
            "z_creator:a_seal:b_seal",
        );
        // Different creator → different key (creator partitions the
        // dedup namespace; it is NOT folded into the lex-sort).
        assert_ne!(
            slash_dedup_key("creator_A", "s1", "s2"),
            slash_dedup_key("creator_B", "s1", "s2"),
        );
        // Degenerate input (seal_a == seal_b): function must not panic
        // and the key is deterministic — caller's responsibility to
        // avoid this shape, but the helper survives.
        assert_eq!(
            slash_dedup_key("anchor1", "same", "same"),
            "anchor1:same:same",
        );
    }

    /// **Axis 3**: `SlashingMonitor::default()` must yield the same
    /// observable state as `::new()` — fresh empty state with all three
    /// metric helpers at 0.
    ///
    /// The Default impl is hand-written (forwards to `new()`). A future
    /// derive(Default) refactor could silently switch to a different
    /// init path; this test pins the equivalence so the /metrics
    /// dashboard's "fresh monitor reports 0/0/0" assumption holds
    /// across both construction paths.
    #[test]
    fn batch_b_slashing_monitor_default_matches_new_state() {
        let from_new = SlashingMonitor::new();
        let from_default = SlashingMonitor::default();

        assert_eq!(from_new.slash_count, from_default.slash_count);
        assert_eq!(from_new.tracked_seals(), from_default.tracked_seals());
        assert_eq!(
            from_new.slashed_pair_count(),
            from_default.slashed_pair_count()
        );
        // Pin absolute values, not just equality.
        assert_eq!(from_default.slash_count, 0);
        assert_eq!(from_default.tracked_seals(), 0);
        assert_eq!(from_default.slashed_pair_count(), 0);
        // No-history monitor: `already_slashed` is false for every probe.
        assert!(!from_default.already_slashed("any", "x", "y"));
    }

    /// **Axis 4**: pin the coupling between `liveness_slash_amount`,
    /// `geo_fraud_slash_amount`, and the slash-percent constants —
    /// floor activation AND the above-floor 25:1 ratio.
    ///
    /// Above the floor:
    ///   geo_fraud(N)  ≈ N * 0.25
    ///   liveness(N)   ≈ N * 0.01
    /// so geo / liveness == 25 (within u64-truncation noise).
    /// At/below the floor both helpers clamp via `max(1)` — the "no free
    /// slash" floor that keeps the slash record non-degenerate even when
    /// the offender's largest stake is tiny.
    #[test]
    fn batch_b_geo_fraud_and_liveness_amounts_pin_ratio_and_floor() {
        // Floor: zero stake → both helpers return 1.
        assert_eq!(geo_fraud_slash_amount(0), 1, "floor: zero stake → 1");
        assert_eq!(liveness_slash_amount(0), 1, "floor: zero stake → 1");
        // Floor: 1 base unit stake — 25% truncates to 0, max(1) lifts it.
        assert_eq!(geo_fraud_slash_amount(1), 1);
        // Floor: 99 base units → 0.99 truncates to 0, max(1) lifts it (liveness).
        assert_eq!(liveness_slash_amount(99), 1);

        // Above the floor: ratio holds exactly at well-aligned stakes.
        let stake = 10_000_000_u64;
        let geo = geo_fraud_slash_amount(stake);
        let live = liveness_slash_amount(stake);
        assert_eq!(geo, 2_500_000, "10M * 0.25 = 2.5M");
        assert_eq!(live, 100_000, "10M * 0.01 = 100K");
        assert_eq!(
            geo / live,
            25,
            "above-floor ratio must be 25:1 (geo:liveness)"
        );

        // u64::MAX path: the f64 conversion saturates but `as u64` is
        // defined and `max(1)` keeps the floor intact. Just verify
        // it doesn't panic and stays > 0.
        assert!(geo_fraud_slash_amount(u64::MAX) >= 1);
        assert!(liveness_slash_amount(u64::MAX) >= 1);
    }

    /// **Axis 5**: `prune_before_epoch` must isolate its reap to the
    /// target zone — entries in OTHER zones at the same `min_epoch`
    /// survive.
    ///
    /// `test_prune_old_epochs` covers single-zone retention. This axis
    /// pins cross-zone isolation: in a 1M-zone mainnet a per-zone prune
    /// must never nuke the cross-shard equivocation detector for sibling
    /// zones — that'd be a P0 safety bug. Also pins the `>= min_epoch`
    /// boundary predicate (NOT `> min_epoch`).
    #[test]
    fn batch_b_prune_before_epoch_isolates_to_target_zone() {
        let mut monitor = SlashingMonitor::new();
        let zone_a = ZoneId::from_legacy(0);
        let zone_b = ZoneId::from_legacy(1);
        let zone_c = ZoneId::from_legacy(2);

        // Three zones × three epochs each = 9 seal entries.
        for epoch in [1u64, 5, 10] {
            monitor.record_seal("anchor1", &zone_a, epoch, &format!("a_s{epoch}"), [0x0A; 32]);
            monitor.record_seal("anchor2", &zone_b, epoch, &format!("b_s{epoch}"), [0x0B; 32]);
            monitor.record_seal("anchor3", &zone_c, epoch, &format!("c_s{epoch}"), [0x0C; 32]);
        }
        assert_eq!(monitor.tracked_seals(), 9, "9 entries seeded");

        // Prune zone_A at min_epoch=5: zone_A {5, 10} survives, B+C untouched.
        monitor.prune_before_epoch(&zone_a, 5);
        assert_eq!(
            monitor.tracked_seals(),
            8,
            "cross-zone isolation: only zone_A loses entries"
        );

        // Prune zone_B at min_epoch=10: zone_B drops to {10}; A+C unchanged.
        monitor.prune_before_epoch(&zone_b, 10);
        // zone_A {5, 10} + zone_B {10} + zone_C {1, 5, 10} = 2 + 1 + 3 = 6.
        assert_eq!(monitor.tracked_seals(), 6);

        // Prune zone_C with min_epoch above the highest tracked epoch
        // empties it. Verifies the boundary condition.
        monitor.prune_before_epoch(&zone_c, 999);
        assert_eq!(monitor.tracked_seals(), 3, "zone_C fully reaped");

        // Re-pruning zone_A at min_epoch == lowest surviving epoch is a
        // no-op (predicate is `>= min_epoch`, NOT `> min_epoch`).
        monitor.prune_before_epoch(&zone_a, 5);
        assert_eq!(
            monitor.tracked_seals(),
            3,
            "min_epoch==lowest must keep the boundary entry"
        );

        // Prune empty zone with min_epoch=0 — no-op.
        monitor.prune_before_epoch(&zone_c, 0);
        assert_eq!(monitor.tracked_seals(), 3);
    }
}
