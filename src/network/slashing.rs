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
//! Detection (F2, 2026-09-02 — internal design notes):
//! the durable, creator-keyed witness index in CF_METADATA
//! (`StorageEngine::find_equivocation_witness`), scanned in ingest Phase 2
//! right after the seal's own batch write. There is no RAM seal window any
//! more: detection survives restart, costs one bounded seek per seal, and never
//! walks other creators' seals. Dedup is OFFENSE-keyed (one slash per
//! (creator, zone, epoch)), guarded in RAM by
//! [`SlashingMonitor::reserve_offense`] (single-lock check-and-mark) and on
//! disk by the `slash_offense:` marker written in the slash record's own batch.
//!
//! The fisherman challenge path (challenge → jury → verdict → slash) is
//! separately wired in ingest.rs and handles manual violations.
//!
//! Only the genesis authority node auto-creates slash records.
//! Slash amount: 25% of offender's largest active stake (capped at 50% by ledger).
//!
//! Spec references:
//!   @spec economics §8

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

use tracing::{info, warn};

use crate::ZoneId;
use crate::identity::Identity;
use crate::record::{Classification, ValidationRecord};
use crate::accounting::types::slash_metadata;
use crate::storage::rocks::StorageEngine;

use super::geo_fraud::{FraudScanInput, FraudVerdict, scan_witness_set};
use super::liveness_proof::{LivenessFailureProof, LIVENESS_SLASH_PERCENT};
use super::peer_rtt::PeerRttEstimator;
use super::state::NodeState;
use super::LockRecover;

/// Default slash percentage of the offender's largest stake.
const DEFAULT_SLASH_PERCENT: f64 = 0.25;

/// Metadata key carried by every auto-slash record: the offense digest
/// ([`offense_digest`], 64 lowercase hex chars). Signed and content-hash
/// covered via `canonical_ledger_preimage_v2` (which iterates ALL metadata, so
/// an older binary recomputes the identical preimage — no wire-format change).
/// Registered in `content_safety::ALLOWED_KEYS`; deliberately NOT in
/// `TEXT_LIMITS` (fixed 64 B, under the 256 B default value cap). Ingest
/// Phase 2 derives the durable `slash_offense:` marker from it for any stored
/// slash record (`slash_offense_side_key`).
pub const BEAT_OFFENSE_KEY: &str = "beat_offense";

/// Offense digest: sha3-256 hex of `"{kind}:{creator}:{detail}"`.
///
/// Fixed width on purpose (F2 blocker B3): the raw tuple with a deep zone path
/// could exceed the 256-byte metadata value cap and hard-reject the slash
/// record on every node.
pub fn offense_digest(kind: &str, creator: &str, detail: &str) -> String {
    crate::crypto::hash::sha3_256_hex(format!("{kind}:{creator}:{detail}").as_bytes())
}

/// Offense digest for seal equivocation at one (creator, zone, epoch).
///
/// Keyed by the OFFENSE, not by the seal pair: seals A, B, C by one creator at
/// one (zone, epoch) are ONE offense and slash once. The pre-F2 pair key
/// `creator:A:C` was fresh after `creator:A:B` and slashed the same offense
/// twice.
pub fn seal_equivocation_offense(creator: &str, zone_path: &str, epoch_number: u64) -> String {
    offense_digest("seal_equivocation", creator, &format!("{zone_path}:{epoch_number}"))
}

/// Durable slash-offense marker key for a record about to be stored: `Some`
/// iff the record is a slash carrying a well-formed `beat_offense` digest.
/// Threaded into the record's own Phase-2 `WriteBatch` through
/// `RecordSideWrites::slash_offense_key` (shared crash fate with the record).
/// Two metadata lookups; `None` for every other record.
pub fn slash_offense_side_key(record: &ValidationRecord) -> Option<Vec<u8>> {
    let op = record
        .metadata
        .get(crate::accounting::types::BEAT_OP_KEY)?
        .as_str()?;
    if op != "slash" {
        return None;
    }
    let digest = record.metadata.get(BEAT_OFFENSE_KEY)?.as_str()?;
    // Canonical form only (lowercase hex, as `offense_digest` emits): a
    // mixed-case variant would be a second, distinct marker for one offense.
    if digest.len() != 64 || !digest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    Some(StorageEngine::slash_offense_key(digest))
}

/// In-process dedup of auto-slash offenses.
///
/// F2 (2026-09-02): the per-(creator, zone, epoch) seal map is gone — detection
/// reads the durable witness index instead (`find_equivocation_witness`). What
/// remains is the offense set: digests reserved (in flight) or executed by
/// THIS process, consulted under ONE lock acquisition (`reserve_offense`) so
/// two of the up-to-64 state-core workers cannot both claim the same offense.
/// The durable `slash_offense:` marker is the cross-restart layer behind it.
pub struct SlashingMonitor {
    /// Offense digests reserved or executed ([`offense_digest`]).
    slashed: HashSet<String>,
    /// Total auto-slashes executed by this process (`count_executed`).
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
            slashed: HashSet::new(),
            slash_count: 0,
        }
    }

    /// True iff the offense is reserved or executed in this process.
    pub fn already_slashed(&self, offense: &str) -> bool {
        self.slashed.contains(offense)
    }

    /// Check-and-mark under the caller's single lock acquisition: `true` iff
    /// the offense was absent and is now reserved by the caller. Idempotent
    /// on the set. Never touches `slash_count` — counting is
    /// [`Self::count_executed`] (F2 blocker B6 split the old bundled
    /// `mark_slashed`).
    pub fn reserve_offense(&mut self, offense: &str) -> bool {
        self.slashed.insert(offense.to_string())
    }

    /// Undo a reservation whose slash did not execute (no active stake, record
    /// build or insert failure) so a later detection can retry.
    pub fn release_offense(&mut self, offense: &str) {
        self.slashed.remove(offense);
    }

    /// Count one executed slash. Called only after the slash record was
    /// durably inserted, so `slash_count ≤ slashed_offense_count()` always
    /// (an in-flight reservation or a durable-dedup hit keeps an offense in the
    /// set without a local execution).
    pub fn count_executed(&mut self) {
        self.slash_count += 1;
    }

    /// Size of the offense set (reserved + executed in this process).
    /// `/metrics`: `elara_slashing_dedup_pairs` (series name kept; offense-keyed
    /// since F2).
    pub fn slashed_offense_count(&self) -> usize {
        self.slashed.len()
    }
}

/// Outcome of [`claim_offense`].
pub enum OffenseClaim {
    /// Reserved in RAM and absent on disk — the caller executes the slash and
    /// must `release_offense` on any failure / `count_executed` on success.
    Claimed,
    /// Another in-flight or already-executed claim in this process.
    AlreadyReserved,
    /// The durable marker exists (slashed before a restart, or by the rebuild
    /// path). The RAM reservation is KEPT so later detections short-circuit
    /// without touching disk. Carries the stored slash record's id.
    DurablySlashed(String),
}

/// Reserve an offense for slashing: single-lock RAM check-and-mark first (the
/// in-flight guard across state-core workers), then the durable
/// `slash_offense:` probe off the executor thread.
///
/// Order matters (F2 blocker B4): a RAM check → lock release → durable read →
/// re-lock → mark sequence lets two workers both pass both checks and both
/// insert. Reserving BEFORE the durable read closes that window; the durable
/// layer only has to catch cross-restart repeats.
pub async fn claim_offense(state: &Arc<NodeState>, offense: &str) -> OffenseClaim {
    if !state.slashing.lock_recover().reserve_offense(offense) {
        return OffenseClaim::AlreadyReserved;
    }
    let state2 = state.clone();
    let digest = offense.to_string();
    let hit = match tokio::task::spawn_blocking(move || state2.rocks.slash_offense_record(&digest))
        .await
    {
        Ok(hit) => hit,
        Err(e) => {
            warn!("slash-offense durable probe join failed ({e}); proceeding on the RAM reservation alone");
            None
        }
    };
    match hit {
        Some(record_id) => {
            state.slashing_durable_dedup_hits_total.fetch_add(1, Relaxed);
            OffenseClaim::DurablySlashed(record_id)
        }
        None => OffenseClaim::Claimed,
    }
}

/// Execute the auto-slash for a seal equivocation detected by the Phase-2
/// witness scan (`StorageEngine::find_equivocation_witness`, consumed in
/// ingest Phase 5 and dispatched after all sync locks are released).
///
/// `conflicting_seal_id` is the stored seal by the same creator at the same
/// (zone, epoch) whose content differs from `seal_record_id`. Detection is
/// NOT repeated here — the witness index is the single source of truth.
/// Only the genesis authority creates slash records.
pub async fn check_seal_equivocation(
    state: &Arc<NodeState>,
    creator_hash: &str,
    zone: &ZoneId,
    epoch_number: u64,
    seal_record_id: &str,
    conflicting_seal_id: &str,
) {
    // Only genesis authority can auto-slash
    if state.identity.identity_hash != state.config.genesis_authority {
        return;
    }

    let offense = seal_equivocation_offense(creator_hash, zone.path(), epoch_number);
    match claim_offense(state, &offense).await {
        OffenseClaim::Claimed => {}
        OffenseClaim::AlreadyReserved => return,
        OffenseClaim::DurablySlashed(prior) => {
            warn!(
                "seal equivocation by {} (zone {} epoch {}) already slashed durably by record {} — skipping (restart-safe dedup)",
                &creator_hash[..creator_hash.len().min(16)],
                zone,
                epoch_number,
                &prior[..prior.len().min(16)],
            );
            return;
        }
    }

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
                state.slashing.lock_recover().release_offense(&offense);
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
        offense_key: Some(&offense),
    }) {
        Ok(slash_record) => {
            // IMPORTANT: Use insert_record_inner_direct instead of gossip::insert_record
            // to avoid deadlock. This function is called from within insert_record_inner_direct
            // (via the state_core), so routing back through the state_core channel would
            // self-deadlock — the core can't process a new message while still processing
            // the current one.
            match super::ingest::insert_record_inner_direct(state, slash_record.clone(), None, false).await {
                Ok(_) => {
                    state.slashing.lock_recover().count_executed();
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
                Err(e) => {
                    state.slashing.lock_recover().release_offense(&offense);
                    warn!("auto-slash insert failed: {e}");
                }
            }
        }
        Err(e) => {
            state.slashing.lock_recover().release_offense(&offense);
            warn!("auto-slash record creation failed: {e}");
        }
    }
}

/// Apply a verified `LivenessFailureProof`: find the offender's largest
/// active stake, build a 1% slash record, and insert it.
///
/// Caller must have already run [`LivenessFailureProof::verify_with_stakers`]
/// — this function trusts the proof and will NOT re-verify. Offense key is
/// `liveness:{offender}:{zone}:{epoch}` (digested) so one missed deadline can
/// only slash once — in this process AND across restarts (F2 durable marker).
///
/// Only the genesis authority creates slash records (matches the
/// equivocation path in [`check_seal_equivocation`]).
pub async fn apply_liveness_slash(state: &Arc<NodeState>, proof: &LivenessFailureProof) {
    if state.identity.identity_hash != state.config.genesis_authority {
        return;
    }

    // Dedup: one liveness slash per (offender, zone, epoch) — same offense
    // set + durable marker as the equivocation path (F2).
    let offense = offense_digest("liveness", &proof.offender_identity_hash, &proof.dedup_key());
    match claim_offense(state, &offense).await {
        OffenseClaim::Claimed => {}
        OffenseClaim::AlreadyReserved | OffenseClaim::DurablySlashed(_) => return,
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
                state.slashing.lock_recover().release_offense(&offense);
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
        offense_key: Some(&offense),
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
                    state.slashing.lock_recover().count_executed();
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
                Err(e) => {
                    state.slashing.lock_recover().release_offense(&offense);
                    warn!("liveness-slash insert failed: {e}");
                }
            }
        }
        Err(e) => {
            state.slashing.lock_recover().release_offense(&offense);
            warn!("liveness-slash record creation failed: {e}");
        }
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
    /// F2: offense digest ([`offense_digest`]) for auto-slash records — lands
    /// in metadata as [`BEAT_OFFENSE_KEY`] and drives the durable
    /// `slash_offense:` marker. `None` for fisherman (jury-verdict) slashes,
    /// which are deduped by their challenge record.
    pub offense_key: Option<&'a str>,
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
        offense_key,
    } = params;

    let mut metadata = slash_metadata(amount, offender, challenger, jury, stake_record_id, reason);
    if let Some(digest) = offense_key {
        metadata.insert(BEAT_OFFENSE_KEY.into(), serde_json::json!(digest));
    }
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
/// Offense key: `geo_fraud:{peer_id}:{epoch}:{claimed_zone}:{reason_tag}`
/// (digested) — one slash per (offender, epoch, zone, category) so a single
/// scan cannot double-slash and re-scanning the same epoch is idempotent, in
/// this process and across restarts (F2 durable marker).
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

    let offense = offense_digest("geo_fraud", &verdict.peer_id, &verdict.dedup_key(epoch_number));
    match claim_offense(state, &offense).await {
        OffenseClaim::Claimed => {}
        OffenseClaim::AlreadyReserved | OffenseClaim::DurablySlashed(_) => return,
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
                state.slashing.lock_recover().release_offense(&offense);
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
        offense_key: Some(&offense),
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
                    state.slashing.lock_recover().count_executed();
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
                Err(e) => {
                    state.slashing.lock_recover().release_offense(&offense);
                    warn!("geo-fraud insert failed: {e}");
                }
            }
        }
        Err(e) => {
            state.slashing.lock_recover().release_offense(&offense);
            warn!("geo-fraud record creation failed: {e}");
        }
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
            offense_key: None,
        })
        .unwrap();

        assert!(record.signature.is_some());
        assert!(
            !record.metadata.contains_key(BEAT_OFFENSE_KEY),
            "offense_key: None must not emit beat_offense"
        );
        assert!(
            slash_offense_side_key(&record).is_none(),
            "no beat_offense → no durable marker side-write"
        );
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

        let digest = seal_equivocation_offense("offender_hash", "0", 7);
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
            offense_key: Some(&digest),
        }).unwrap();

        assert!(record.signature.is_some());
        // F2: the offense digest rides in metadata, is allowlisted, and yields
        // exactly the durable marker key ingest Phase 2 threads into the batch.
        assert_eq!(
            record.metadata.get(BEAT_OFFENSE_KEY).and_then(|v| v.as_str()),
            Some(digest.as_str()),
        );
        assert!(crate::content_safety::is_known_key(BEAT_OFFENSE_KEY));
        assert_eq!(
            slash_offense_side_key(&record),
            Some(StorageEngine::slash_offense_key(&digest)),
        );
        // The digest is covered by the signed preimage: mutating it must
        // invalidate the signature (no unsigned dedup channel).
        let mut tampered = record.clone();
        tampered.metadata.insert(
            BEAT_OFFENSE_KEY.into(),
            serde_json::json!(offense_digest("seal_equivocation", "other", "z:1")),
        );
        let sig = tampered.signature.clone().expect("signed");
        assert!(
            !crate::crypto::pqc::dilithium3_verify(
                &tampered.signable_bytes(),
                &sig,
                &tampered.creator_public_key
            )
            .unwrap(),
            "beat_offense must be signature-covered"
        );
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

    // ── F2 (2026-09-02): offense-keyed dedup + durable marker ────────────

    /// Two workers racing on the same offense: exactly one `reserve_offense`
    /// wins, the set is idempotent, and `count_executed` is the only thing
    /// that moves `slash_count` (blocker B6 split) — so
    /// `slash_count ≤ slashed_offense_count()` holds through the lifecycle,
    /// including release-after-failure.
    #[test]
    fn f2_reserve_offense_is_single_lock_check_and_mark() {
        let mut monitor = SlashingMonitor::new();
        let offense = seal_equivocation_offense("anchor1", "0", 5);

        // I1: fresh monitor.
        assert_eq!(monitor.slash_count, 0);
        assert_eq!(monitor.slashed_offense_count(), 0);
        assert!(!monitor.already_slashed(&offense));

        // I2: first reservation wins; second (same offense) loses.
        assert!(monitor.reserve_offense(&offense), "first claim wins");
        assert!(!monitor.reserve_offense(&offense), "second claim loses");
        assert!(monitor.already_slashed(&offense));
        assert_eq!(monitor.slashed_offense_count(), 1);
        assert_eq!(monitor.slash_count, 0, "reservation is not execution");

        // I3: a different seal pair for the SAME (creator, zone, epoch) is the
        // same offense — pre-F2 pair keys would have slashed twice here.
        let same_offense = seal_equivocation_offense("anchor1", "0", 5);
        assert_eq!(same_offense, offense);
        assert!(!monitor.reserve_offense(&same_offense));

        // I4: release re-opens the offense (stake missing / insert failed).
        monitor.release_offense(&offense);
        assert!(!monitor.already_slashed(&offense));
        assert_eq!(monitor.slashed_offense_count(), 0);
        monitor.release_offense(&offense); // no-op on absent
        assert_eq!(monitor.slashed_offense_count(), 0);

        // I5: reserve → execute → counted once; invariant executed ≤ offenses.
        assert!(monitor.reserve_offense(&offense));
        monitor.count_executed();
        assert_eq!(monitor.slash_count, 1);
        assert!(monitor.slash_count as usize <= monitor.slashed_offense_count());

        // I6: a distinct offense (other epoch) is independent.
        let other = seal_equivocation_offense("anchor1", "0", 6);
        assert_ne!(other, offense);
        assert!(monitor.reserve_offense(&other));
        assert_eq!(monitor.slashed_offense_count(), 2);
        assert_eq!(monitor.slash_count, 1);
    }

    /// Digest shape (blocker B3): 64 lowercase hex regardless of input length
    /// (a deep zone path must not blow the 256-B metadata value cap), and the
    /// `kind` prefix partitions the space so a liveness key can never collide
    /// with an equivocation key for the same creator/detail.
    #[test]
    fn f2_offense_digest_is_fixed_width_and_kind_partitioned() {
        let deep_zone = (0..40).map(|i| format!("z{i}")).collect::<Vec<_>>().join("/");
        assert!(deep_zone.len() > 100);
        let d = seal_equivocation_offense("creator", &deep_zone, 999_999);
        assert_eq!(d.len(), 64);
        assert!(d.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert!(d.len() <= 256, "under the default 256-B metadata value cap");

        let a = offense_digest("liveness", "c", "0:5");
        let b = offense_digest("geo_fraud", "c", "0:5");
        let c = offense_digest("seal_equivocation", "c", "0:5");
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
        // Deterministic across calls (restart-stable durable marker).
        assert_eq!(a, offense_digest("liveness", "c", "0:5"));
        // Creator and detail both participate.
        assert_ne!(a, offense_digest("liveness", "d", "0:5"));
        assert_ne!(a, offense_digest("liveness", "c", "0:6"));
    }

    /// Offense key is a function of (creator, zone, epoch) only — the seal
    /// ids do not enter it, so A/B and A/C (and B/C, and C/A) collapse.
    #[test]
    fn f2_seal_equivocation_offense_is_pair_independent() {
        let zone = ZoneId::from_legacy(3);
        let k = seal_equivocation_offense("anchor", zone.path(), 42);
        assert_eq!(k, seal_equivocation_offense("anchor", zone.path(), 42));
        assert_ne!(k, seal_equivocation_offense("anchor", zone.path(), 43));
        assert_ne!(k, seal_equivocation_offense("anchor2", zone.path(), 42));
        assert_ne!(
            k,
            seal_equivocation_offense("anchor", ZoneId::from_legacy(4).path(), 42)
        );
    }

    /// The durable marker side-write is derived only for well-formed slash
    /// records: `beat_op == "slash"` AND a 64-hex `beat_offense`. Anything
    /// else (non-slash op, missing key, malformed digest) → `None`, so a
    /// hostile record cannot plant an arbitrary `slash_offense:` marker.
    #[test]
    fn f2_slash_offense_side_key_requires_slash_op_and_well_formed_digest() {
        use crate::accounting::types::BEAT_OP_KEY;
        let identity = crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        )
        .unwrap();
        let digest = offense_digest("liveness", "off", "0:1");
        let mut record = create_slash_record(SlashRecordParams {
            identity: &identity,
            amount: 5,
            offender: "off",
            challenger: "ch",
            jury: &["ch".to_string()],
            stake_record_id: "stake",
            reason: "auto:liveness_failure",
            light_mode: false,
            slot_nonce: 3,
            offense_key: Some(&digest),
        })
        .unwrap();
        assert_eq!(
            slash_offense_side_key(&record),
            Some(StorageEngine::slash_offense_key(&digest))
        );

        // Non-slash op → None even with a digest present.
        record.metadata.insert(BEAT_OP_KEY.into(), serde_json::json!("stake"));
        assert!(slash_offense_side_key(&record).is_none());
        record.metadata.insert(BEAT_OP_KEY.into(), serde_json::json!("slash"));

        // Malformed digests → None.
        for bad in ["", "abc", &"g".repeat(64), &"A".repeat(64), &"0".repeat(63), &"0".repeat(65)] {
            record.metadata.insert(BEAT_OFFENSE_KEY.into(), serde_json::json!(bad));
            assert!(slash_offense_side_key(&record).is_none(), "accepted {bad:?}");
        }
        // Non-string value → None.
        record.metadata.insert(BEAT_OFFENSE_KEY.into(), serde_json::json!(12));
        assert!(slash_offense_side_key(&record).is_none());
        // Missing key → None.
        record.metadata.remove(BEAT_OFFENSE_KEY);
        assert!(slash_offense_side_key(&record).is_none());
    }

    /// `Default` and `new` agree, and a no-history monitor answers `false`
    /// for every probe (post-F2 shape: offense set only).
    #[test]
    fn batch_b_slashing_monitor_default_matches_new_state() {
        let from_new = SlashingMonitor::new();
        let from_default = SlashingMonitor::default();
        assert_eq!(from_new.slash_count, from_default.slash_count);
        assert_eq!(
            from_new.slashed_offense_count(),
            from_default.slashed_offense_count()
        );
        assert_eq!(from_default.slash_count, 0);
        assert_eq!(from_default.slashed_offense_count(), 0);
        assert!(!from_default.already_slashed("any"));
    }

    /// `claim_offense` end-to-end against a real store: first claim is
    /// `Claimed`; a pre-existing durable `slash_offense:` marker short-circuits
    /// to `DurablySlashed(record_id)` while KEEPING the RAM reservation (so the
    /// next detection never touches disk) and bumps the dedup-hit counter.
    #[cfg(feature = "node-core")]
    #[tokio::test]
    async fn f2_claim_offense_durable_marker_short_circuits() {
        let state = super::super::state::build_test_node_state();
        let fresh = seal_equivocation_offense("anchor-fresh", "0", 1);
        assert!(matches!(claim_offense(&state, &fresh).await, OffenseClaim::Claimed));
        assert!(matches!(
            claim_offense(&state, &fresh).await,
            OffenseClaim::AlreadyReserved
        ));
        assert_eq!(state.slashing_durable_dedup_hits_total.load(Relaxed), 0);

        // Plant the durable marker as a prior (pre-restart) slash would have.
        let durable = seal_equivocation_offense("anchor-durable", "0", 1);
        state
            .rocks
            .put_cf_raw(
                crate::storage::rocks::CF_METADATA,
                &StorageEngine::slash_offense_key(&durable),
                b"slash-rid-1",
            )
            .unwrap();
        match claim_offense(&state, &durable).await {
            OffenseClaim::DurablySlashed(rid) => assert_eq!(rid, "slash-rid-1"),
            _ => panic!("durable marker must short-circuit"),
        }
        assert_eq!(state.slashing_durable_dedup_hits_total.load(Relaxed), 1);
        // Reservation kept: the second probe never reaches the store.
        assert!(matches!(
            claim_offense(&state, &durable).await,
            OffenseClaim::AlreadyReserved
        ));
        assert_eq!(state.slashing_durable_dedup_hits_total.load(Relaxed), 1);
        let m = state.slashing.lock_recover();
        assert_eq!(m.slashed_offense_count(), 2);
        assert_eq!(m.slash_count, 0, "no execution happened");
    }
}
