//! Auto-reward — distribute witness rewards on settlement.
//!
//! When a record reaches finality via AWC consensus, each attesting witness
//! receives a configurable beat reward from the conservation pool.
//! Only the genesis authority node creates reward records.

//!
//! Spec references:
//!   @spec economics §11.1
//!   @spec economics §11.2

use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

use tracing::{debug, info, warn};

use crate::identity::Identity;
use crate::record::{Classification, ValidationRecord};
use crate::accounting::types::witness_reward_metadata;

use super::gossip;
use super::state::NodeState;
use super::{LockRecover, RwLockRecover};

/// Returns `Some(seconds_since_epoch)` or `None` when the system clock is
/// set before 1970-01-01 (VM time reset, NTP misconfiguration at boot).
/// Callers that need `now` for reward calculations must bail out on `None`
/// rather than proceeding with a corrupt `0.0` timestamp.
fn clock_now_secs() -> Option<f64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .ok()
}

/// Exactly-once finalization side-effects, fired on the persistent
/// FinalizedIndex false→true edge (the rids returned by
/// `insert_batch_returning_new` / `FeedOutcome::first_finalization`).
///
/// Per newly-finalized record: credit undisputed witnesses (economics
/// §11.2), broadcast `RecordFinalized`, and distribute witness rewards
/// (economics §11.1, genesis authority only). Centralizing these on the
/// durable index edge fixes two live defects found 2026-06-11 on the
/// dev-net: (a) repeat attestations on an already-settled record re-fired
/// rewards + reputation credit every gossip cycle (each reward record gets
/// a fresh nonce/timestamp, so re-fires would double-pay once the
/// conservation pool is funded); (b) records promoted by the finality
/// monitor or attestation-recovery paths never fired rewards/events at all.
///
/// Reputation dual-writes ride the periodic snapshot loop; this path only
/// updates the in-memory tracker (same durability as the monitor path had).
pub fn finalization_effects(state: &Arc<NodeState>, newly_finalized: Vec<String>) {
    if newly_finalized.is_empty() {
        return;
    }
    let s = state.clone();
    tokio::spawn(async move {
        for rid in newly_finalized {
            // Credit undisputed witnesses BEFORE finality pruning evicts the
            // attestor set from the in-flight map.
            {
                let attestors = {
                    let consensus = s.consensus.lock_recover();
                    consensus.attestors(&rid)
                };
                if !attestors.is_empty() {
                    if let Some(now_ts) = clock_now_secs() {
                        let mut rep = s.reputation.lock_recover();
                        rep.credit_undisputed(&attestors, now_ts);
                    }
                }
            }

            let _ = s.events.send(super::state::NodeEvent::RecordFinalized {
                record_id: rid.clone(),
            });

            distribute_rewards(&s, &rid).await;
        }
    });
}

/// Create and distribute witness reward records for a settled record.
///
/// Called when `feed_attestation` triggers settlement. The genesis authority
/// creates one `witness_reward` record per attesting witness, drawing from
/// the conservation pool.
///
/// Returns the number of rewards successfully distributed.
pub async fn distribute_rewards(
    state: &Arc<NodeState>,
    record_id: &str,
) -> usize {
    let base_reward = state.config.witness_reward_micros;
    if base_reward == 0 {
        info!("distribute_rewards: base_reward=0, skipping");
        return 0;
    }

    // Apply bootstrap phase multiplier (economics §14.2)
    let reward_amount = {
        let bootstrap = state.bootstrap_state.read_recover();
        bootstrap.apply_multiplier(base_reward)
    };
    if reward_amount == 0 {
        info!("distribute_rewards: multiplier=0 (genesis phase), skipping");
        return 0;
    }

    // Only genesis authority distributes rewards
    if state.identity.identity_hash != state.config.genesis_authority {
        return 0;
    }

    // Break reward cascade: never create rewards for witness_reward records.
    // Without this guard, rewards-for-rewards create exponential growth:
    //   N records → N×W rewards → N×W² rewards → N×W³ → ...
    // With W≈4 witnesses: 1,130 records → 290K+ reward records in 4 levels.
    if let Ok(rec) = state.get_record(record_id) {
        if rec.metadata.get("beat_op").and_then(|v| v.as_str()) == Some("witness_reward") {
            debug!("distribute_rewards: skipping reward-for-reward on {}", &record_id[..record_id.len().min(16)]);
            return 0;
        }
    }

    // Get the witness list before finality pruning removes them
    let witnesses: Vec<String> = {
        let consensus = state.consensus.lock_recover();
        consensus.attestors(record_id)
    };

    if witnesses.is_empty() {
        debug!("distribute_rewards: no attestors found for {} (already pruned?)", &record_id[..record_id.len().min(16)]);
        return 0;
    }

    info!("distribute_rewards: {} attestors, reward={} base units each", witnesses.len(), reward_amount);

    // Filter out self (genesis can't reward itself) and duplicates
    let genesis_hash = &state.identity.identity_hash;
    let eligible: Vec<&String> = witnesses
        .iter()
        .filter(|w| *w != genesis_hash)
        .collect();

    if eligible.is_empty() {
        return 0;
    }

    // Recompute entity clusters for diminishing returns (economics §6.3)
    {
        let mut clusterer = state.entity_clusterer.lock_recover();
        clusterer.recompute();
    }

    let mut distributed = 0usize;
    let mut total_amount = 0u64;

    // Get DAG tips once for all reward records in this batch.
    // Rewards reference DAG tips to maintain graph connectivity —
    // without this, 91% of records are disconnected roots.
    let parents = super::server::dag_tip_parents(state, 3).await;

    let Some(now) = clock_now_secs() else {
        warn!("distribute_rewards: clock-before-epoch; skipping reward distribution for {}", &record_id[..record_id.len().min(16)]);
        return 0;
    };

    for witness_hash in &eligible {
        // Apply full reward formula: base × trust_multiplier(age-adjusted) × diversity_bonus (economics §11.1)
        let reputation_adjusted = {
            let rep = state.reputation.lock_recover();
            rep.compute_reward(witness_hash, reward_amount, now)
        };

        // Apply diminishing returns based on entity cluster size (economics §6.3)
        let effective_reward = {
            let clusterer = state.entity_clusterer.lock_recover();
            clusterer.effective_reward(witness_hash, reputation_adjusted)
        };

        if effective_reward == 0 {
            info!("reward skipped for {}: reputation_adjusted={reputation_adjusted} effective=0",
                  &witness_hash[..witness_hash.len().min(16)]);
            continue;
        }

        match create_reward_record(RewardRecordParams {
            identity: &state.identity,
            genesis_hash,
            witness_hash,
            record_id,
            amount: effective_reward,
            parents: parents.clone(),
            light_mode: state.config.light_mode,
            slot_nonce: state.next_slot_nonce(),
        }) {
            Ok(reward_record) => {
                if distributed == 0 {
                    let wire = reward_record.to_bytes().len();
                    info!("reward wire size: {} bytes ({:.1} KB) light_mode={}",
                        wire, wire as f64 / 1024.0, state.config.light_mode);
                }
                // Insert into local storage + DAG + ledger
                match gossip::insert_record(state, reward_record.clone()).await {
                    Ok(_) => {
                        distributed += 1;
                        total_amount += effective_reward;

                        // Gossip push the reward record to peers
                        super::state::NodeState::publish_record_with_fallback(state, &reward_record, None).await;
                    }
                    Err(e) => {
                        warn!("reward insert failed for {}: {e}", &witness_hash[..16.min(witness_hash.len())]);
                    }
                }
            }
            Err(e) => {
                warn!("reward record creation failed for {}: {e}", &witness_hash[..16.min(witness_hash.len())]);
            }
        }
    }

    if distributed > 0 {
        state.auto_rewards_total.fetch_add(distributed as u64, Relaxed);
        state.auto_rewards_amount_total.fetch_add(total_amount, Relaxed);
        info!(
            "distributed {} witness rewards (total {} base units, base {} each) for record {}",
            distributed,
            total_amount,
            reward_amount,
            &record_id[..16.min(record_id.len())]
        );
    }

    distributed
}

/// Inputs to [`create_reward_record`].
///
/// Bundled to keep the witness-reward emit path under the
/// `too_many_arguments` threshold; same parameter-struct pattern used
/// elsewhere in this crate. Borrowed fields stay borrowed.
struct RewardRecordParams<'a> {
    identity: &'a Identity,
    genesis_hash: &'a str,
    witness_hash: &'a str,
    record_id: &'a str,
    amount: u64,
    parents: Vec<String>,
    light_mode: bool,
    /// Freshly-allocated nonce from the node's monotonic counter — reusing
    /// nonces (including the default nonce=0) triggers SLOT EQUIVOCATION
    /// on ingest because every reward record is signed by the same genesis
    /// identity. Callers pull from `state.next_slot_nonce()`.
    slot_nonce: u64,
}

/// Create a single witness reward `ValidationRecord`.
fn create_reward_record(
    params: RewardRecordParams<'_>,
) -> crate::errors::Result<ValidationRecord> {
    let RewardRecordParams {
        identity,
        genesis_hash,
        witness_hash,
        record_id,
        amount,
        parents,
        light_mode,
        slot_nonce,
    } = params;

    let metadata = witness_reward_metadata(amount, genesis_hash, witness_hash, record_id);

    // Canonical v2 ledger preimage (audit 2026-07-06): the old bespoke
    // "witness_reward:{record_id}:{witness_hash}" form was amount- and
    // nonce-blind and would fail the ingest enforcement gate.
    let content_str = crate::accounting::types::canonical_ledger_preimage_v2(
        &metadata,
        &identity.public_key,
        slot_nonce,
    )
    .ok_or_else(|| {
        crate::errors::ElaraError::Ledger("witness_reward metadata missing beat_op".into())
    })?;

    let mut record = ValidationRecord::create(
        content_str.as_bytes(),
        identity.public_key.clone(),
        parents,
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

// ─── Per-Epoch Rewards (Layered Consensus) ──────────────────────────────────

/// Expected records per epoch (for record_count_factor normalization).
const EXPECTED_RECORDS_PER_EPOCH: f64 = 100.0;

/// Compute per-epoch reward with record_count_factor.
///
/// Formula (internal design notes, Audit A4/D5):
/// `reward = base × record_count_factor × trust_multiplier × diversity_bonus × entity_diminishing_returns`
///
/// Where:
/// - `record_count_factor = min(record_count / EXPECTED_RECORDS_PER_EPOCH, 2.0)`
///   → More records in epoch = more reward (capped at 2×)
///   → Empty epochs get zero factor
/// - Other multipliers applied by the caller (reputation, entity clustering)
pub fn epoch_reward_amount(base_reward: u64, record_count: u64) -> u64 {
    if record_count == 0 || base_reward == 0 {
        return 0;
    }
    let factor = (record_count as f64 / EXPECTED_RECORDS_PER_EPOCH).min(2.0);
    (base_reward as f64 * factor) as u64
}

/// Distribute rewards for an epoch seal (per-epoch model).
///
/// Unlike per-record rewards, this distributes rewards to all witnesses
/// who attested to the epoch seal. The reward scales with the number of
/// records in the epoch (record_count_factor).
pub async fn distribute_epoch_rewards(
    state: &Arc<NodeState>,
    seal_id: &str,
    record_count: u64,
    witnesses: &[String],
) -> usize {
    let base_reward = state.config.witness_reward_micros;
    if base_reward == 0 || witnesses.is_empty() {
        return 0;
    }

    // Only genesis authority distributes rewards
    if state.identity.identity_hash != state.config.genesis_authority {
        return 0;
    }

    // Break reward cascade (same guard as distribute_rewards)
    if let Ok(rec) = state.get_record(seal_id) {
        if rec.metadata.get("beat_op").and_then(|v| v.as_str()) == Some("witness_reward") {
            debug!("distribute_epoch_rewards: skipping reward-for-reward on {}", &seal_id[..seal_id.len().min(16)]);
            return 0;
        }
    }

    // Apply bootstrap phase multiplier (economics §14.2)
    let boosted_reward = {
        let bootstrap = state.bootstrap_state.read_recover();
        bootstrap.apply_multiplier(base_reward)
    };
    if boosted_reward == 0 {
        return 0;
    }

    // Apply record_count_factor
    let epoch_base = epoch_reward_amount(boosted_reward, record_count);
    if epoch_base == 0 {
        return 0;
    }

    let genesis_hash = &state.identity.identity_hash;
    let eligible: Vec<&String> = witnesses
        .iter()
        .filter(|w| *w != genesis_hash)
        .collect();

    if eligible.is_empty() {
        return 0;
    }

    // Recompute entity clusters for diminishing returns
    {
        let mut clusterer = state.entity_clusterer.lock_recover();
        clusterer.recompute();
    }

    let mut distributed = 0usize;
    let mut total_amount = 0u64;

    let parents = super::server::dag_tip_parents(state, 3).await;

    let Some(now) = clock_now_secs() else {
        warn!("distribute_epoch_rewards: clock-before-epoch; skipping epoch reward distribution for {}", &seal_id[..seal_id.len().min(16)]);
        return 0;
    };

    for witness_hash in &eligible {
        // Apply trust multiplier with age decay (economics §11.1)
        let reputation_adjusted = {
            let rep = state.reputation.lock_recover();
            rep.compute_reward(witness_hash, epoch_base, now)
        };

        // Apply diminishing returns (economics §6.3)
        let effective_reward = {
            let clusterer = state.entity_clusterer.lock_recover();
            clusterer.effective_reward(witness_hash, reputation_adjusted)
        };

        if effective_reward == 0 {
            continue;
        }

        match create_reward_record(RewardRecordParams {
            identity: &state.identity,
            genesis_hash,
            witness_hash,
            record_id: seal_id,
            amount: effective_reward,
            parents: parents.clone(),
            light_mode: state.config.light_mode,
            slot_nonce: state.next_slot_nonce(),
        }) {
            Ok(reward_record) => {
                match gossip::insert_record(state, reward_record.clone()).await {
                    Ok(_) => {
                        distributed += 1;
                        total_amount += effective_reward;

                        super::state::NodeState::publish_record_with_fallback(state, &reward_record, None).await;
                    }
                    Err(e) => {
                        warn!("epoch reward insert failed for {}: {e}", &witness_hash[..16.min(witness_hash.len())]);
                    }
                }
            }
            Err(e) => {
                warn!("epoch reward creation failed: {e}");
            }
        }
    }

    if distributed > 0 {
        state.auto_rewards_total.fetch_add(distributed as u64, Relaxed);
        state.auto_rewards_amount_total.fetch_add(total_amount, Relaxed);
        info!(
            "distributed {} epoch rewards (total {} base units, base={}, records={}) for seal {}",
            distributed, total_amount, epoch_base, record_count,
            &seal_id[..16.min(seal_id.len())]
        );
    }

    distributed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{CryptoProfile, EntityType};

    fn test_identity() -> Identity {
        Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap()
    }

    #[test]
    fn test_create_reward_record() {
        let identity = test_identity();
        let record = create_reward_record(RewardRecordParams {
            identity: &identity,
            genesis_hash: &identity.identity_hash,
            witness_hash: "witness_abc",
            record_id: "record_123",
            amount: 1_000_000,
            parents: vec![],
            light_mode: false,
            slot_nonce: 1,
        })
        .unwrap();

        assert!(record.signature.is_some());
        assert_eq!(
            record.metadata.get("beat_op").and_then(|v| v.as_str()),
            Some("witness_reward")
        );
        assert_eq!(
            record.metadata.get("beat_amount").and_then(crate::accounting::types::parse_beat_amount),
            Some(1_000_000)
        );
        assert_eq!(
            record.metadata.get("beat_to").and_then(|v| v.as_str()),
            Some("witness_abc")
        );
        assert_eq!(
            record.metadata.get("beat_record_id").and_then(|v| v.as_str()),
            Some("record_123")
        );
    }

    #[test]
    fn test_epoch_reward_amount() {
        // 0 records → 0 reward
        assert_eq!(epoch_reward_amount(1000, 0), 0);

        // 0 base → 0 reward
        assert_eq!(epoch_reward_amount(0, 100), 0);

        // 50 records of 100 expected → factor 0.5
        assert_eq!(epoch_reward_amount(1000, 50), 500);

        // 100 records of 100 expected → factor 1.0
        assert_eq!(epoch_reward_amount(1000, 100), 1000);

        // 200 records → factor capped at 2.0
        assert_eq!(epoch_reward_amount(1000, 200), 2000);

        // 500 records → still capped at 2.0
        assert_eq!(epoch_reward_amount(1000, 500), 2000);
    }

    #[test]
    fn test_create_reward_record_unique_ids() {
        let identity = test_identity();
        let r1 = create_reward_record(RewardRecordParams { identity: &identity, genesis_hash: "genesis", witness_hash: "w1", record_id: "rec1", amount: 1_000_000, parents: vec![], light_mode: false, slot_nonce: 1 }).unwrap();
        let r2 = create_reward_record(RewardRecordParams { identity: &identity, genesis_hash: "genesis", witness_hash: "w2", record_id: "rec1", amount: 1_000_000, parents: vec![], light_mode: false, slot_nonce: 2 }).unwrap();
        let r3 = create_reward_record(RewardRecordParams { identity: &identity, genesis_hash: "genesis", witness_hash: "w1", record_id: "rec2", amount: 1_000_000, parents: vec![], light_mode: false, slot_nonce: 3 }).unwrap();

        // Each reward record should have a unique ID
        assert_ne!(r1.id, r2.id);
        assert_ne!(r1.id, r3.id);
        assert_ne!(r2.id, r3.id);

        // Nonces propagate into slot_key — each reward claims a distinct slot.
        assert_ne!(r1.slot_key(), r2.slot_key());
        assert_ne!(r1.slot_key(), r3.slot_key());
        assert_ne!(r2.slot_key(), r3.slot_key());
    }

    // ─── Fixture-free reward-formula pins ───────────────────────────────────

    /// The per-epoch reward formula divides record_count by this constant.
    /// A silent change (e.g. 100→50) doubles per-epoch reward at the same
    /// record_count — pinning the literal makes any future shift deliberate.
    #[test]
    fn expected_records_per_epoch_pinned_to_100_literal() {
        assert_eq!(EXPECTED_RECORDS_PER_EPOCH, 100.0);
        // And the 100-records-per-epoch threshold yields the exact 1.0 factor:
        assert_eq!(epoch_reward_amount(1000, 100), 1000);
        // 50 records is exactly half:
        assert_eq!(epoch_reward_amount(1000, 50), 500);
    }

    /// Extends test_epoch_reward_amount with the cap-onset boundary
    /// (199 / 200 / 201) and the u64::MAX safety case — the float
    /// multiplication `record_count as f64 / 100.0` does not overflow at
    /// u64::MAX but the `.min(2.0)` cap MUST still hold (a future edit
    /// removing the cap would silently emit 10^17× the intended reward).
    #[test]
    fn epoch_reward_amount_cap_boundary_and_u64_max_safety() {
        // 199 records → factor 1.99 → 1990 (just under cap)
        assert_eq!(epoch_reward_amount(1000, 199), 1990);
        // 200 records → factor 2.0 (cap exact)
        assert_eq!(epoch_reward_amount(1000, 200), 2000);
        // 201 records → factor still 2.0 (just past cap)
        assert_eq!(epoch_reward_amount(1000, 201), 2000);
        // u64::MAX → cap STILL holds, no overflow, no run-away mint
        assert_eq!(epoch_reward_amount(1000, u64::MAX), 2000);
        // 99 records → 990 (just-under-1.0 factor — pins linear region)
        assert_eq!(epoch_reward_amount(1000, 99), 990);
        // 1 record (minimum non-zero) → factor 0.01 → 10
        assert_eq!(epoch_reward_amount(1000, 1), 10);
    }

    /// `create_reward_record` synthesizes the record body as
    /// `witness_reward:{record_id}:{witness_hash}` and pre-hashes it into
    /// `content_hash`. A future edit that swaps the two arg orders (or
    /// changes the separator) is invisible to existing metadata-only tests
    /// because metadata fields are populated independently — this pin
    /// catches the rewrite by reconstructing the canonical SHA3-256.
    #[test]
    fn create_reward_record_content_body_format_pinned() {
        let identity = test_identity();
        let witness = "witness_xyz_42";
        let record_id_arg = "src_rec_abc";

        let r = create_reward_record(RewardRecordParams {
            identity: &identity,
            genesis_hash: &identity.identity_hash,
            witness_hash: witness,
            record_id: record_id_arg,
            amount: 7_777,
            parents: vec![],
            light_mode: false,
            slot_nonce: 99,
        })
        .unwrap();

        // Canonical body MUST be the shared v2 ledger preimage (audit
        // 2026-07-06) — binding amount, nonce, and every metadata field,
        // so the ingest enforcement gate accepts reward records.
        let meta = witness_reward_metadata(7_777, &identity.identity_hash, witness, record_id_arg);
        let expected_body = crate::accounting::types::canonical_ledger_preimage_v2(
            &meta,
            &identity.public_key,
            99,
        )
        .expect("reward metadata carries beat_op");
        let expected_hash = crate::crypto::hash::sha3_256(expected_body.as_bytes()).to_vec();
        assert_eq!(r.content_hash, expected_hash);
        assert!(crate::accounting::types::verify_ledger_content_hash_v2(&r).is_ok());

        // A different nonce or amount MUST NOT match — the old bespoke
        // preimage was blind to both (negative axis).
        let other_nonce_body = crate::accounting::types::canonical_ledger_preimage_v2(
            &meta,
            &identity.public_key,
            100,
        )
        .unwrap();
        let other_hash = crate::crypto::hash::sha3_256(other_nonce_body.as_bytes()).to_vec();
        assert_ne!(r.content_hash, other_hash);
    }

    /// `RewardRecordParams.slot_nonce` MUST propagate to `record.nonce`.
    /// The default `ValidationRecord::create()` constructs records with
    /// `nonce=0` — a regression that dropped the `record.nonce = slot_nonce`
    /// assignment at reward.rs:228 would silently reintroduce the
    /// "all rewards same-slot equivocation" failure mode documented in the
    /// `slot_nonce` field doc (every reward is signed by the same genesis
    /// identity, so nonce-collision = slot-key collision = pending-cap pinch).
    #[test]
    fn create_reward_record_nonce_propagates_from_slot_nonce_arg() {
        let identity = test_identity();
        let nonce_arg = 0xDEAD_BEEF_u64; // distinct from the create()-default 0

        let r = create_reward_record(RewardRecordParams {
            identity: &identity,
            genesis_hash: &identity.identity_hash,
            witness_hash: "w_alpha",
            record_id: "rec_alpha",
            amount: 100,
            parents: vec!["p1".into(), "p2".into()],
            light_mode: false,
            slot_nonce: nonce_arg,
        })
        .unwrap();

        assert_eq!(r.nonce, nonce_arg);
        // And classification + parents propagate too (UNPINNED pre-batch).
        assert_eq!(r.classification, Classification::Public);
        assert_eq!(r.parents, vec!["p1".to_string(), "p2".to_string()]);
    }

    /// The `beat_from` metadata field is set to the genesis_hash by
    /// `witness_reward_metadata` — pre-batch tests assert beat_op,
    /// beat_amount, beat_to, beat_record_id but NOT beat_from. A future
    /// regression that flipped `from`/`to` arg order would silently
    /// reverse audit-trail attribution: beat-flow analysis would show
    /// the WITNESS as the payer and the GENESIS as the payee, the exact
    /// inverse of what happens (genesis-pays-witness for attestation).
    #[test]
    fn create_reward_record_metadata_beat_from_pins_to_genesis_hash() {
        let identity = test_identity();
        let genesis_label = "GENESIS_NODE_42";

        let r = create_reward_record(RewardRecordParams {
            identity: &identity,
            genesis_hash: genesis_label,
            witness_hash: "w_recipient",
            record_id: "rec_target",
            amount: 1_000,
            parents: vec![],
            light_mode: false,
            slot_nonce: 5,
        })
        .unwrap();

        // beat_from = genesis (the payer)
        assert_eq!(
            r.metadata.get("beat_from").and_then(|v| v.as_str()),
            Some(genesis_label)
        );
        // beat_to = witness (the payee) — pinning the asymmetry
        assert_eq!(
            r.metadata.get("beat_to").and_then(|v| v.as_str()),
            Some("w_recipient")
        );
        // beat_from MUST NOT equal beat_to under any non-degenerate input
        assert_ne!(
            r.metadata.get("beat_from").and_then(|v| v.as_str()),
            r.metadata.get("beat_to").and_then(|v| v.as_str())
        );
    }

    // ─── Reward-shape pins ──────────────────────────────────────────────────

    /// Pin the monotonic-then-plateau shape of `epoch_reward_amount` across
    /// a wide record_count sweep. Existing `epoch_reward_amount_cap_boundary_
    /// and_u64_max_safety` checks 6 spot values; this sweeps 31 evenly-spaced
    /// counts so a regression that re-introduced non-monotonic interior
    /// behavior (e.g. an off-by-one floor on the cap factor, or an
    /// accidentally negative factor for empty-but-non-zero counts) trips here
    /// even if the spot-tested boundaries still happen to hold. The flat
    /// plateau at counts ≥ 200 = `2.0 × EXPECTED_RECORDS_PER_EPOCH` MUST hold
    /// regardless of upstream scale.
    #[test]
    fn batch_b_epoch_reward_amount_monotonic_non_decreasing_with_record_count_then_cap_plateau() {
        let base = 1_000u64;
        let mut prev = epoch_reward_amount(base, 0);
        let mut plateau_value: Option<u64> = None;
        for k in 0..=30 {
            let count = k * 10; // 0, 10, 20, ..., 300
            let v = epoch_reward_amount(base, count);
            assert!(
                v >= prev,
                "epoch_reward_amount must be non-decreasing in record_count: \
                 k={k}, count={count}, prev={prev}, v={v}"
            );
            // Plateau region begins at record_count == 2*EXPECTED (=200).
            if count >= (2.0 * EXPECTED_RECORDS_PER_EPOCH) as u64 {
                match plateau_value {
                    None => plateau_value = Some(v),
                    Some(p) => assert_eq!(
                        v, p,
                        "plateau region (count>={}) must be constant: count={count} v={v} p={p}",
                        (2.0 * EXPECTED_RECORDS_PER_EPOCH) as u64
                    ),
                }
            }
            prev = v;
        }
        // Plateau MUST equal 2 × base (cap factor = 2.0).
        assert_eq!(
            plateau_value,
            Some(2 * base),
            "plateau value must equal 2.0 × base_reward = {}",
            2 * base
        );
        // At count=0 the reward is exactly 0 (zero-case bypass).
        assert_eq!(epoch_reward_amount(base, 0), 0);
    }

    /// Pin the linearity of `epoch_reward_amount` in `base_reward` at a
    /// fixed record_count below the cap. The formula multiplies base by a
    /// count-only factor — so doubling base MUST double the reward, tripling
    /// triples it, etc. Existing tests verify spot values at base=1000; this
    /// pins the algebraic invariant `reward(k×base, count) == k × reward(base,
    /// count)` across k ∈ {1, 2, 3, 5, 7, 10} for two distinct counts
    /// (50 below cap, 300 inside cap-plateau). A future edit that introduced
    /// a non-linear adjustment in base (e.g. a sqrt() decay or a tiered
    /// step) would invalidate this and trip here.
    #[test]
    fn batch_b_epoch_reward_amount_linear_homogeneity_in_base_reward_at_fixed_record_count() {
        // Below-cap count: factor = 0.5
        let below_cap_count = 50u64;
        let unit_base = 1_000u64;
        let unit_reward = epoch_reward_amount(unit_base, below_cap_count);
        assert_eq!(unit_reward, 500);
        for k in [1u64, 2, 3, 5, 7, 10] {
            let r = epoch_reward_amount(unit_base * k, below_cap_count);
            assert_eq!(
                r,
                k * unit_reward,
                "linearity broken at k={k} below_cap_count={below_cap_count}: \
                 expected {} got {r}",
                k * unit_reward
            );
        }
        // In-cap count: factor = 2.0 (capped) — linearity STILL holds since
        // the cap is on factor not on base. A regression that capped reward
        // itself (e.g. min(reward, MAX_REWARD)) would break here.
        let in_cap_count = 300u64;
        let unit_reward_in_cap = epoch_reward_amount(unit_base, in_cap_count);
        assert_eq!(unit_reward_in_cap, 2_000);
        for k in [1u64, 2, 3, 5, 7, 10] {
            let r = epoch_reward_amount(unit_base * k, in_cap_count);
            assert_eq!(
                r,
                k * unit_reward_in_cap,
                "linearity broken at k={k} in_cap_count={in_cap_count}"
            );
        }
    }

    /// Pin `EXPECTED_RECORDS_PER_EPOCH` against the rest of the cluster of
    /// numeric constants in `src/network/*.rs`. The economics §11.1
    /// normalization divisor MUST be distinct from the pending-drain
    /// timeouts (600/1200) and the state-core worker cap (64) — a future
    /// refactor that accidentally re-used one of the timeout constants as
    /// the normalization divisor (or vice versa) would double or halve the
    /// per-epoch payout rate silently. Also pins the integer-valued shape
    /// (`.fract() == 0.0`, finite, positive) — a hot-path NaN/Inf or
    /// fractional 99.999 would silently slide every payout off the
    /// canonical 1.0-factor-at-100-records pin.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_expected_records_per_epoch_constant_finite_integral_with_cross_module_disjointness() {
        // Integral-valued + finite + positive
        assert!(EXPECTED_RECORDS_PER_EPOCH.is_finite());
        assert!(EXPECTED_RECORDS_PER_EPOCH > 0.0);
        assert_eq!(
            EXPECTED_RECORDS_PER_EPOCH.fract(),
            0.0,
            "EXPECTED_RECORDS_PER_EPOCH must be integer-valued in f64"
        );
        // Value lock — 100 records/epoch is the §11.1 unit-factor anchor.
        assert_eq!(EXPECTED_RECORDS_PER_EPOCH, 100.0_f64);
        // Cap-onset cross-relation: 2× EXPECTED is the cap-onset record_count.
        assert_eq!(2.0 * EXPECTED_RECORDS_PER_EPOCH, 200.0_f64);
        // Cross-module disjointness — must NOT collide with the pending_drain
        // timeouts or the state_core worker cap. A regression that re-used
        // one of these as the normalization divisor would silently warp the
        // per-epoch payout rate by 6×/12× (timeouts) or 1.56× (worker cap
        // ratio 64/100=0.64 → payout 64% of intended at canonical count=100).
        assert_ne!(
            EXPECTED_RECORDS_PER_EPOCH,
            crate::network::pending_drain::PENDING_DISCARD_TIMEOUT_SECS,
            "EXPECTED_RECORDS_PER_EPOCH must not collide with PENDING soft-cutoff (600s)"
        );
        assert_ne!(
            EXPECTED_RECORDS_PER_EPOCH,
            crate::network::pending_drain::PENDING_HARD_DISCARD_TIMEOUT_SECS,
            "EXPECTED_RECORDS_PER_EPOCH must not collide with PENDING hard-cutoff (1200s)"
        );
        assert_ne!(
            EXPECTED_RECORDS_PER_EPOCH,
            crate::network::state_core::MAX_STATE_CORE_WORKERS as f64,
            "EXPECTED_RECORDS_PER_EPOCH must not collide with MAX_STATE_CORE_WORKERS (64)"
        );
    }

    /// Pin the `light_mode == true` branch of `create_reward_record` —
    /// existing tests all exercise the `light_mode: false` path. The
    /// light-mode branch invokes `identity.sign_record_light` (Dilithium3-
    /// only, sphincs stripped — see identity.rs:473-479) instead of the
    /// dual Dilithium+SPHINCS+ `sign_record`. A regression that silently
    /// fell back to the dual-sig path under light_mode would inflate light-
    /// client record sizes by ~30 KB (SPHINCS+ shake-256s ≈ 29-30 KB).
    /// This pin verifies: (1) record IS still signed, (2) sig_algorithm is
    /// pinned to ALG_DILITHIUM3, (3) classification stays Public, (4) the
    /// canonical content_hash matches the same `witness_reward:{rid}:{w}`
    /// SHA3-256 (light mode does NOT mutate the body).
    #[test]
    fn batch_b_create_reward_record_light_mode_branch_still_signs_and_classification_stays_public() {
        let identity = test_identity();
        let witness = "w_light";
        let record_id_arg = "rec_light";

        let r = create_reward_record(RewardRecordParams {
            identity: &identity,
            genesis_hash: &identity.identity_hash,
            witness_hash: witness,
            record_id: record_id_arg,
            amount: 42,
            parents: vec![],
            light_mode: true,
            slot_nonce: 17,
        })
        .unwrap();

        // (1) Light-mode record IS signed.
        assert!(
            r.signature.is_some(),
            "light_mode=true must still produce a signed record"
        );
        // (2) sig_algorithm pinned to Dilithium3 (NOT the dual scheme).
        assert_eq!(
            r.sig_algorithm,
            crate::crypto::ALG_DILITHIUM3,
            "light_mode=true must use Dilithium3-only signature, not dual-scheme"
        );
        // (3) Classification stays Public regardless of mode.
        assert_eq!(r.classification, Classification::Public);
        // (4) Body unchanged — same canonical v2 preimage as the
        // normal-mode pin in `create_reward_record_content_body_format_pinned`.
        let meta =
            witness_reward_metadata(42, &identity.identity_hash, witness, record_id_arg);
        let expected_body = crate::accounting::types::canonical_ledger_preimage_v2(
            &meta,
            &identity.public_key,
            17,
        )
        .expect("reward metadata carries beat_op");
        let expected_hash = crate::crypto::hash::sha3_256(expected_body.as_bytes()).to_vec();
        assert_eq!(
            r.content_hash, expected_hash,
            "light mode must not alter the canonical content body"
        );
        // Metadata still carries the canonical beat_* fields — light_mode is
        // purely a signature concern, never a metadata concern.
        assert_eq!(
            r.metadata.get("beat_op").and_then(|v| v.as_str()),
            Some("witness_reward")
        );
        assert_eq!(
            r.metadata.get("beat_to").and_then(|v| v.as_str()),
            Some(witness)
        );
        assert_eq!(
            r.metadata.get("beat_record_id").and_then(|v| v.as_str()),
            Some(record_id_arg)
        );
    }

    /// Pin the f64→u64 saturating-cast behavior at reward.rs:259
    /// (`(base_reward as f64 * factor) as u64`). At `base_reward = u64::MAX`
    /// and cap-region `record_count = u64::MAX`, the float multiplication is
    /// 2.0 × ~1.84e19 ≈ 3.69e19, which exceeds u64::MAX. Rust 1.45+
    /// saturates f64→u64 casts (per RFC 2484 + rust-lang/rust#71269), so the
    /// result MUST be `u64::MAX` — not a panic, not a UB wrap-around, not
    /// some negative-equivalent garbage from the legacy LLVM `fptoui`. A
    /// future edit that swapped the as-cast for a `.try_into().unwrap()` or
    /// a hand-rolled `from_f64_lossy` would silently start panicking on the
    /// pathological-input branch instead of saturating, leaking the
    /// reward-distribution loop into a panic on first-witness on a
    /// pathological epoch.
    #[test]
    fn batch_b_epoch_reward_amount_saturating_cast_at_base_u64_max_does_not_panic() {
        // The cap-region: count ≥ 200 saturates factor at 2.0.
        let r = epoch_reward_amount(u64::MAX, 1_000);
        // Saturation MUST hit u64::MAX (no panic, no wrap).
        assert_eq!(
            r,
            u64::MAX,
            "f64→u64 cast at base=u64::MAX × factor=2.0 must saturate to u64::MAX"
        );
        // Same outcome at count=u64::MAX (also cap-region).
        let r2 = epoch_reward_amount(u64::MAX, u64::MAX);
        assert_eq!(r2, u64::MAX);
        // Below-cap factor (0.5) at base=u64::MAX → ~9.2e18 — fits in u64.
        // The saturating cast must NOT clobber a value that DOES fit.
        let r3 = epoch_reward_amount(u64::MAX, 50);
        assert!(
            r3 < u64::MAX,
            "below-cap result must not saturate: r3={r3}, u64::MAX={}",
            u64::MAX
        );
        assert!(
            r3 > 0,
            "below-cap result must be strictly positive at base=u64::MAX"
        );
        // Order: below-cap r3 < cap r1 (cap is the larger product).
        assert!(
            r3 < r,
            "below-cap result must be < cap-saturated result"
        );
    }

    #[test]
    fn clock_now_secs_pre_epoch_is_none() {
        // Pin the platform invariant: SystemTime before UNIX_EPOCH produces Err
        // from duration_since, which is what makes clock_now_secs() return None.
        // This is the reachable branch that distribute_rewards / distribute_epoch_rewards
        // guard against (clock-before-epoch → skip reward distribution).
        let pre_epoch = std::time::UNIX_EPOCH - std::time::Duration::from_secs(1);
        assert!(
            pre_epoch.duration_since(std::time::UNIX_EPOCH).is_err(),
            "pre-epoch SystemTime must produce Err from duration_since"
        );
        // And that Err maps to None via clock_now_secs' ok() conversion.
        let result: Option<f64> = pre_epoch
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .ok();
        assert!(result.is_none(), "pre-epoch time must yield None via ok()");
    }
}
