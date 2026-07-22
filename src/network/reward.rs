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
use crate::crypto::hash::sha3_256_hex;
use crate::storage::rocks::CF_METADATA;

use super::gossip;
use super::state::NodeState;
use super::finalized::{
    pending_effects_key, PENDING_EFFECTS_PREFIX, PENDING_EFFECTS_REPUTATION_CREDITED,
};
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
/// Chunk size for durable FinalizedIndex member inserts. Bounds the
/// `state.finalized` write-lock hold (the per-rid cold-tier probe inside
/// `insert_batch_returning_new` is sized for small batches) against the
/// `MAX_SEAL_RECORDS = 1M` seal-size ceiling — the lock is re-acquired per
/// chunk so readers interleave.
pub const MEMBER_FINALITY_CHUNK: usize = 4096;

/// Durable half of the seal-member finality routing: chunked
/// `insert_batch_returning_new` + lifetime counters + the F5 member counter.
/// Returns every rid that was truly new (the exactly-once effects edge).
/// Takes `&NodeState` (not `Arc`) so `feed_attestation` /
/// `batch_feed_attestations` can call it and defer effects to their callers
/// via the outcome contract.
pub async fn insert_members_durable(state: &NodeState, member_rids: &[String]) -> Vec<String> {
    if member_rids.is_empty() {
        return Vec::new();
    }
    let mut all_new: Vec<String> = Vec::new();
    for chunk in member_rids.chunks(MEMBER_FINALITY_CHUNK) {
        let new_rids = {
            let mut finalized = state.finalized.write().await;
            finalized.insert_batch_returning_new(chunk)
        };
        if new_rids.is_empty() {
            continue;
        }
        state
            .total_ever_settled
            .fetch_add(new_rids.len() as u64, std::sync::atomic::Ordering::Relaxed);
        state
            .total_ever_finalized
            .fetch_add(new_rids.len() as u64, std::sync::atomic::Ordering::Relaxed);
        state
            .seal_member_finalized_durable_total
            .fetch_add(new_rids.len() as u64, std::sync::atomic::Ordering::Relaxed);
        all_new.extend(new_rids);
    }
    all_new
}

/// Full seal-member finality routing for call sites that hold an
/// `Arc<NodeState>`: durable insert (chunked, counted) + exactly-once
/// finalization side-effects for the truly-new rids. This is THE required
/// sink for every `Vec<String>` returned by `add_seal_attestation`,
/// `register_seal_records`, `resolve_late_seal_member`, `promote_anchored`,
/// and the F3 maintenance sweep — dropping those returns re-opens the
/// seal-member durable-write gap.
pub async fn route_member_finality(state: &Arc<NodeState>, member_rids: Vec<String>) {
    if member_rids.is_empty() {
        return;
    }
    let new_rids = insert_members_durable(state, &member_rids).await;
    finalization_effects(state, new_rids);
}

/// Deduplicated witness-hash list for a record from the DURABLE attestation
/// store (CF_ATTESTATIONS, 30-day retention). This is the recovery-safe source:
/// it is written on attestation ingest BEFORE consensus counts the attestation,
/// so at finalization it holds the full settling set — and unlike the volatile
/// `consensus.attestors` (pruned every ~2.5 min, empty after a restart) it is
/// still there minutes/hours later when the recovery sweep re-fires. Empty on
/// error / no attestations.
// NOTE: `get_attestations` prefix-scans CF_ATTESTATIONS, which carries a
// fixed-41-byte prefix extractor (`att:` + 36-char uuid7 + `:` = 41). Every
// finalized record id is a 36-char uuid7 (`ValidationRecord::create`), so the
// lookup key length matches the extractor and the scan returns the full set.
fn durable_attestors(state: &NodeState, record_id: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    if let Ok(rows) = state.witness_mgr.get_attestations(record_id) {
        for a in rows {
            if seen.insert(a.witness_hash.clone()) {
                out.push(a.witness_hash);
            }
        }
    }
    out
}

/// RAII single-flight guard: removes `rid` from the inflight set on `Drop`.
/// Drop is synchronous, so a panic under `panic="unwind"` cannot wedge a rid as
/// permanently in-flight (which would block the recovery sweep forever).
struct InflightGuard<'a> {
    state: &'a Arc<NodeState>,
    rid: String,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.state
            .finalization_effects_inflight
            .lock_recover()
            .remove(&self.rid);
    }
}

/// Claim single-flight ownership of `rid`. Returns a guard if this call won the
/// claim, or `None` if another task already owns it (skip — it will complete or
/// leave the marker for the next sweep).
fn claim_inflight<'a>(state: &'a Arc<NodeState>, rid: &str) -> Option<InflightGuard<'a>> {
    let mut set = state.finalization_effects_inflight.lock_recover();
    if !set.insert(rid.to_string()) {
        return None;
    }
    Some(InflightGuard {
        state,
        rid: rid.to_string(),
    })
}

/// Process the exactly-once finalization side-effects for a single rid,
/// idempotently and recoverably. Safe to call repeatedly and from both the
/// finalize path and the recovery sweep: the durable `pending_effects:` marker,
/// deterministic reward ids, and the reputation marker-bit make every re-run a
/// no-op once the effects have completed.
async fn process_finalization_effect(state: &Arc<NodeState>, rid: &str) {
    // Single-flight: if a live task already owns this rid, skip.
    let Some(_guard) = claim_inflight(state, rid) else {
        return;
    };

    let marker_key = pending_effects_key(rid);
    // Read the durable marker. Absent ⇒ effects already completed + cleared (or
    // this rid never had a marker) ⇒ nothing to do.
    let marker = match state.rocks.get_cf_raw(CF_METADATA, marker_key.as_bytes()) {
        Ok(Some(v)) if !v.is_empty() => v,
        _ => return,
    };
    let mut credited = (marker[0] & PENDING_EFFECTS_REPUTATION_CREDITED) != 0;

    // 1) Reputation credit (non-idempotent) — gated by the marker bit.
    //    apply-then-flip: a crash between the credit and the durable flip
    //    re-credits once on recovery (bounded, non-monetary — accepted).
    if !credited {
        let attestors = durable_attestors(state, rid);
        if attestors.is_empty() {
            // No durable attestors (e.g. a >30-day outage reaped
            // CF_ATTESTATIONS): nothing to credit; mark reputation done so the
            // marker can eventually clear rather than pinning forever.
            credited = true;
        } else if let Some(now_ts) = clock_now_secs() {
            {
                let mut rep = state.reputation.lock_recover();
                rep.credit_undisputed(&attestors, now_ts);
            }
            if state
                .rocks
                .put_cf_raw(
                    CF_METADATA,
                    marker_key.as_bytes(),
                    &[PENDING_EFFECTS_REPUTATION_CREDITED],
                )
                .is_ok()
            {
                credited = true;
            }
        }
        // clock-before-epoch ⇒ leave credited=false ⇒ marker stays ⇒ retry next sweep.
    }

    // 2) RecordFinalized event (lossy broadcast; a duplicate is harmless).
    let _ = state.events.send(super::state::NodeEvent::RecordFinalized {
        record_id: rid.to_string(),
    });

    // 3) Witness rewards (idempotent via deterministic ids + record_exists).
    let (_distributed, _already, failed) = distribute_rewards(state, rid).await;

    // 4) Clear the marker ONLY when reputation is durably credited AND no reward
    //    insert failed. Otherwise leave it — the next sweep retries; already
    //    -distributed witnesses dedup via the deterministic-id pre-check.
    if credited && failed == 0 {
        let _ = state.rocks.delete_cf_raw(CF_METADATA, marker_key.as_bytes());
    }
}

/// Exactly-once finalization side-effects, fired on the persistent
/// FinalizedIndex false→true edge (the rids returned by
/// `insert_batch_returning_new` / `insert_marked` / `FeedOutcome::first_finalization`).
/// Spawns a detached task; the durable `pending_effects:` marker written
/// atomically with `finalized:` makes the effects recoverable if that task
/// panics before completing (`panic="unwind"` kills it silently) — the boot/tick
/// [`reconcile_pending_effects`] sweep re-fires anything left behind.
pub fn finalization_effects(state: &Arc<NodeState>, newly_finalized: Vec<String>) {
    if newly_finalized.is_empty() {
        return;
    }
    let s = state.clone();
    tokio::spawn(async move {
        for rid in newly_finalized {
            process_finalization_effect(&s, &rid).await;
        }
    });
}

/// Boot + per-tick recovery sweep: re-fire the exactly-once effects for any
/// `pending_effects:` marker left behind by a detached effects task that
/// panicked before completing. O(pending) — the prefix scan seeks directly into
/// the marker range (near-free when empty). Idempotent: the single-flight guard
/// skips rids a live task still owns, and completed effects are a no-op.
/// Bounded per sweep so a large post-crash backlog cannot stall the finality
/// loop; the remainder is picked up on the next tick (markers persist).
pub async fn reconcile_pending_effects(state: &Arc<NodeState>) {
    const MAX_PER_SWEEP: usize = 512;
    let prefix = PENDING_EFFECTS_PREFIX.as_bytes();
    // Bound the SCAN itself (not just processing): `prefix_scan_bounded` stops
    // at the store layer after MAX_PER_SWEEP keys, so a large post-crash backlog
    // never materializes the whole range nor pays an O(backlog) scan each tick.
    // The remainder is recovered next tick (markers persist).
    let mut pending: Vec<String> = Vec::new();
    let mut truncated = false;
    let _ = state.rocks.prefix_scan_bounded(CF_METADATA, prefix, |key, _value| {
        if pending.len() >= MAX_PER_SWEEP {
            truncated = true;
            return Ok(false); // stop scanning
        }
        if let Some(rid_bytes) = key.strip_prefix(prefix) {
            if let Ok(rid) = std::str::from_utf8(rid_bytes) {
                pending.push(rid.to_string());
            }
        }
        Ok(true)
    });
    // Publish the observed backlog for operator alerting (OPS gauge).
    state
        .pending_finalization_effects
        .store(pending.len() as u64, std::sync::atomic::Ordering::Relaxed);
    if pending.is_empty() {
        return;
    }
    if truncated {
        warn!(
            "reconcile_pending_effects: ≥{MAX_PER_SWEEP} pending finalization markers; \
             processing {MAX_PER_SWEEP} this sweep, remainder next tick"
        );
    } else {
        debug!(
            "reconcile_pending_effects: recovering {} pending finalization marker(s)",
            pending.len()
        );
    }
    for rid in pending {
        process_finalization_effect(state, &rid).await;
    }
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
) -> (usize, usize, usize) {
    let base_reward = state.config.witness_reward_micros;
    if base_reward == 0 {
        info!("distribute_rewards: base_reward=0, skipping");
        return (0, 0, 0);
    }

    // Apply bootstrap phase multiplier (economics §14.2)
    let reward_amount = {
        let bootstrap = state.bootstrap_state.read_recover();
        bootstrap.apply_multiplier(base_reward)
    };
    if reward_amount == 0 {
        info!("distribute_rewards: multiplier=0 (genesis phase), skipping");
        return (0, 0, 0);
    }

    // Only genesis authority distributes rewards
    if state.identity.identity_hash != state.config.genesis_authority {
        return (0, 0, 0);
    }

    // Break reward cascade: never create rewards for witness_reward records.
    // Without this guard, rewards-for-rewards create exponential growth:
    //   N records → N×W rewards → N×W² rewards → N×W³ → ...
    // With W≈4 witnesses: 1,130 records → 290K+ reward records in 4 levels.
    if let Ok(rec) = state.get_record(record_id) {
        if rec.metadata.get("beat_op").and_then(|v| v.as_str()) == Some("witness_reward") {
            debug!("distribute_rewards: skipping reward-for-reward on {}", &record_id[..record_id.len().min(16)]);
            return (0, 0, 0);
        }
    }

    // Witness list from the DURABLE attestation store (CF_ATTESTATIONS, 30-day
    // retention) — NOT the volatile `consensus.attestors`, which the finality
    // monitor prunes every ~2.5 min and which is empty after a restart. The
    // durable store is written on attestation ingest before consensus counts
    // the attestation, so at finalization it holds the full settling set; this
    // is what lets the recovery sweep re-fire rewards correctly after the fact.
    let witnesses: Vec<String> = durable_attestors(state, record_id);

    if witnesses.is_empty() {
        debug!("distribute_rewards: no durable attestors for {}", &record_id[..record_id.len().min(16)]);
        return (0, 0, 0);
    }

    info!("distribute_rewards: {} attestors, reward={} base units each", witnesses.len(), reward_amount);

    // Filter out self (genesis can't reward itself) and duplicates
    let genesis_hash = &state.identity.identity_hash;
    let eligible: Vec<&String> = witnesses
        .iter()
        .filter(|w| *w != genesis_hash)
        .collect();

    if eligible.is_empty() {
        return (0, 0, 0);
    }

    // Recompute entity clusters for diminishing returns (economics §6.3)
    {
        let mut clusterer = state.entity_clusterer.lock_recover();
        clusterer.recompute();
    }

    let mut distributed = 0usize;
    let mut already = 0usize;
    let mut failed = 0usize;
    let mut total_amount = 0u64;

    // Get DAG tips once for all reward records in this batch.
    // Rewards reference DAG tips to maintain graph connectivity —
    // without this, 91% of records are disconnected roots.
    let parents = super::server::dag_tip_parents(state, 3).await;

    let Some(now) = clock_now_secs() else {
        warn!("distribute_rewards: clock-before-epoch; skipping reward distribution for {}", &record_id[..record_id.len().min(16)]);
        // Transient (bad system clock) — report every eligible witness as
        // "failed" so the caller keeps the pending marker and retries next
        // sweep rather than clearing it and losing the rewards forever.
        return (0, 0, eligible.len());
    };

    // Conservation-pool solvency gate (author-side). Read the pool balance ONCE
    // and drop the read guard immediately — `gossip::insert_record` below takes
    // `ledger.write()`, so holding a read across it would deadlock. Track a
    // running `pool_remaining` as we author. Without this, once the pool is
    // drained a witness_reward is authored + gossiped and then HARD-FAILS at
    // apply (the conservation-pool guard in `apply_op`), and — because the
    // exactly-once marker keeps the rid pending on failure — it is re-authored +
    // re-gossiped every recovery sweep: a doomed-reward storm. Skipping
    // author-side turns that storm into a cheap DEFERRAL (counted as `failed` so
    // the pending_effects marker persists; the reconcile sweep retries once
    // slash/dormancy inflow refills the pool). Genesis-authority-only path, so
    // this is a purely local decision — no cross-node determinism impact.
    // RESIDUAL (pre-existing, out of scope): this closes only the single-call
    // over-commit. A CONCURRENT distribute_rewards/distribute_epoch_rewards call
    // reads the same snapshot and can still collectively over-author; the
    // dominant async commit-drain path (pending_drain) then DROPS the excess op
    // on apply-failure, decoupled from this marker — same ARCH-1 reward-liveness
    // class as the record_exists residual above. Needs a pool reservation.
    // Monthly-disbursement throttle budget, read in the SAME guard as the pool
    // balance (guard dropped before any insert_record ledger.write() — no
    // deadlock). Caps reward outflow at 1%/30-day-window of the pool (economics
    // §2.4 / EARN-IN-ECONOMY.md "bank run") so legitimate traffic alone can't
    // drain it. Over-budget rewards DEFER (counted `failed` → pending_effects
    // marker persists → retried next window), never drop — same marker contract
    // as the pool floor. `now` here is the authority's advisory wall-clock — this
    // budget is read only by this single authority, so it needs no cross-node
    // determinism; the paired consensus-side accounting in apply_op uses the
    // sealed record.timestamp instead (see pool_disbursed_window's struct doc).
    let (mut pool_remaining, mut monthly_remaining): (u64, u64) = {
        let l = state.ledger.read().await;
        (l.conservation_pool, l.pool_monthly_remaining(now))
    };

    for witness_hash in &eligible {
        // Idempotency pre-check BEFORE build/sign/gossip: if the deterministic
        // reward id for this (record_id, witness) already exists locally, the
        // reward was already emitted (a prior fire or a crash-recovery re-run).
        // Skipping here closes the gossip-divergence hazard — a second build
        // would carry a fresh timestamp/nonce/parents and gossip a differently
        // -signed record under the SAME id, forking peers. Rewards are emitted
        // only by the single genesis authority, so this LOCAL check suffices.
        let det_id = witness_reward_det_id(record_id, witness_hash);
        if state.record_exists(&det_id).unwrap_or(false) {
            // RESIDUAL (pre-existing, not introduced here): record_exists proves
            // Phase-2 storage, not that the reward's own ledger delta applied. A
            // witness_reward is tentative-applied and only lands once the reward
            // record ITSELF reaches finality (ARCH-1); if it never self-finalizes
            // within PENDING_DISCARD_TIMEOUT_SECS its delta is discarded, yet the
            // record persists so this pre-check treats it as paid forever. Same
            // lost-outcome as the pre-diff fire-once code (re-creating can't
            // re-apply — ingest dedups the id), so no regression; the true fix
            // is in the ARCH-1 reward-liveness model, out of scope here.
            already += 1;
            continue;
        }

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

        // Author-side solvency gate: never author a reward the conservation pool
        // cannot cover — defer it (count as failed → marker persists → retried
        // by the reconcile sweep on pool recovery) instead of gossiping a record
        // doomed to hard-fail at apply. See the pool_remaining note above.
        if pool_remaining < effective_reward {
            failed += 1;
            warn!("reward deferred for {}: conservation pool {} < reward {} — retry next sweep",
                  &witness_hash[..witness_hash.len().min(16)], pool_remaining, effective_reward);
            continue;
        }

        // Monthly-disbursement throttle: even with a healthy pool balance, cap
        // outflow at the 1%/30-day budget so a sustained-traffic drain degrades
        // gracefully (deferred rewards) instead of emptying the pool. The
        // consensus-side accounting for what actually lands is in apply_op; this
        // is the author-side enforcement point (genesis-authority-only, advisory).
        if monthly_remaining < effective_reward {
            failed += 1;
            warn!("reward deferred for {}: monthly pool budget {} < reward {} — retry next window",
                  &witness_hash[..witness_hash.len().min(16)], monthly_remaining, effective_reward);
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
            det_id: Some(det_id.clone()),
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
                        // Track the running pool balance + monthly budget so the
                        // gates above account for rewards already authored in this
                        // loop (apply_op's accounting is async — after gossip/apply).
                        pool_remaining = pool_remaining.saturating_sub(effective_reward);
                        monthly_remaining = monthly_remaining.saturating_sub(effective_reward);

                        // Gossip push the reward record to peers
                        super::state::NodeState::publish_record_with_fallback(state, &reward_record, None).await;
                    }
                    Err(e) => {
                        // Transient insert failure — count as failed so the
                        // caller keeps the marker and retries this witness next
                        // sweep (already-inserted witnesses dedup via the
                        // record_exists pre-check).
                        failed += 1;
                        warn!("reward insert failed for {}: {e}", &witness_hash[..16.min(witness_hash.len())]);
                    }
                }
            }
            Err(e) => {
                failed += 1;
                warn!("reward record creation failed for {}: {e}", &witness_hash[..16.min(witness_hash.len())]);
            }
        }
    }

    if distributed > 0 {
        state.auto_rewards_total.fetch_add(distributed as u64, Relaxed);
        state.auto_rewards_amount_total.fetch_add(total_amount, Relaxed);
        info!(
            "distributed {} witness rewards (total {} base units, base {} each) for record {} (already={already} failed={failed})",
            distributed,
            total_amount,
            reward_amount,
            &record_id[..16.min(record_id.len())]
        );
    }

    (distributed, already, failed)
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
    /// Deterministic id to assign BEFORE signing, or `None` to keep the random
    /// uuid7 from `create()`. Only the per-record `distribute_rewards` path
    /// passes `Some` (so re-fires dedup); `distribute_epoch_rewards` passes
    /// `None`. CRITICAL: this keeps the per-record and per-epoch reward
    /// categories from colliding on the SAME `wrwd1:sha3(id‖witness)` for a
    /// shared seal `record_id` (which would silently drop one reward while its
    /// caller's metrics count it as paid). Epoch-reward idempotency is a
    /// separate, out-of-scope follow-up.
    det_id: Option<String>,
}

/// Deterministic, collision-resistant id for a witness-reward record, derived
/// ONLY from `(record_id, witness_hash)` — never amount/nonce/timestamp — so
/// every re-fire of the same reward collides on id and dedups at storage
/// (`record_exists`) and ledger (ingest short-circuit) instead of double-paying
/// from the conservation pool. Domain-separated + length-prefixed so distinct
/// pairs can never alias. `"wrwd1:"` + 64 hex = 70 ASCII chars, wire-legal:
/// `validate_wire_id` admits any ASCII id ≤ MAX_RECORD_ID_LEN (128).
fn witness_reward_det_id(record_id: &str, witness_hash: &str) -> String {
    reward_det_id(b"elara.witness_reward.id.v1", record_id, witness_hash)
}

/// Deterministic id for a PER-EPOCH witness reward `(seal_id, witness_hash)`.
/// A DISTINCT domain from the per-record id (`witness_reward_det_id`) so the two
/// reward categories can never collide on a shared seal id — the collision the
/// post-ship rust-reviewer flagged (W1) and verdict finding #4 implies. Closes
/// the epoch double-pay: a re-fire collides on id and dedups instead of minting
/// a second conservation-pool debit. (Crash-recovery under-fire — the epoch path
/// has no outbox marker — remains the separate deferred follow-up.)
fn epoch_reward_det_id(seal_id: &str, witness_hash: &str) -> String {
    reward_det_id(b"elara.epoch_reward.id.v1", seal_id, witness_hash)
}

/// Shared deterministic-id core: `"wrwd1:"` + sha3 of a domain-separated,
/// length-prefixed `(record_id, witness_hash)` preimage. Length-prefixing makes
/// distinct field splits unambiguous; the `domain` tag keeps distinct reward
/// categories apart. Keyed ONLY on the two args — never amount/nonce/timestamp —
/// so every re-fire of the same reward collides.
fn reward_det_id(domain: &[u8], record_id: &str, witness_hash: &str) -> String {
    let mut preimage =
        Vec::with_capacity(12 + domain.len() + record_id.len() + witness_hash.len());
    preimage.extend_from_slice(&(domain.len() as u32).to_be_bytes());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&(record_id.len() as u32).to_be_bytes());
    preimage.extend_from_slice(record_id.as_bytes());
    preimage.extend_from_slice(&(witness_hash.len() as u32).to_be_bytes());
    preimage.extend_from_slice(witness_hash.as_bytes());
    format!("wrwd1:{}", sha3_256_hex(&preimage))
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
        det_id,
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

    // Deterministic id (when supplied) — set AFTER create()/nonce but BEFORE
    // signing (id is field 0 of signable_bytes, so the signature commits to
    // it). Only the per-record reward path passes one; epoch rewards keep the
    // random uuid7 so the two categories never collide on a shared seal id.
    // nonce stays fresh (monotonic) — anti-equivocation is unaffected.
    if let Some(id) = det_id {
        record.id = id;
    }

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
///
/// THROTTLE: the monthly-disbursement cap is enforced author-side only in
/// `distribute_rewards` (the live path). This path is dormant (577b4e48: fires
/// with empty ingest-time attestors ~never) AND economically gated, and it
/// lacks the exactly-once marker, so a defer here would DROP not retry. The
/// consensus-side accounting (`record_pool_disbursement` in apply_op) already
/// counts the rewards this path emits — they are ordinary witness_reward
/// records applied through the same arm. When/if this path is activated per
/// 577b4e48, add the same `monthly_remaining` gate + a marker contract so
/// throttled epoch rewards defer instead of drop.
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

        // Idempotency + divergence guard (verdict finding #4): a deterministic
        // id from (seal_id, witness) — domain-separated from the per-record id —
        // makes a re-fire of this epoch reward collide and dedup at storage +
        // ledger instead of double-paying the conservation pool. Pre-check
        // BEFORE build/sign/gossip so a retry can't gossip a differently-signed
        // variant under the same id (rewards are single-emitter/genesis-only).
        let epoch_det_id = epoch_reward_det_id(seal_id, witness_hash);
        if state.record_exists(&epoch_det_id).unwrap_or(false) {
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
            det_id: Some(epoch_det_id),
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
            det_id: None,
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
        let r1 = create_reward_record(RewardRecordParams { identity: &identity, genesis_hash: "genesis", witness_hash: "w1", record_id: "rec1", amount: 1_000_000, parents: vec![], light_mode: false, slot_nonce: 1, det_id: None }).unwrap();
        let r2 = create_reward_record(RewardRecordParams { identity: &identity, genesis_hash: "genesis", witness_hash: "w2", record_id: "rec1", amount: 1_000_000, parents: vec![], light_mode: false, slot_nonce: 2, det_id: None }).unwrap();
        let r3 = create_reward_record(RewardRecordParams { identity: &identity, genesis_hash: "genesis", witness_hash: "w1", record_id: "rec2", amount: 1_000_000, parents: vec![], light_mode: false, slot_nonce: 3, det_id: None }).unwrap();

        // Each reward record should have a unique ID
        assert_ne!(r1.id, r2.id);
        assert_ne!(r1.id, r3.id);
        assert_ne!(r2.id, r3.id);

        // Nonces propagate into slot_key — each reward claims a distinct slot.
        assert_ne!(r1.slot_key(), r2.slot_key());
        assert_ne!(r1.slot_key(), r3.slot_key());
        assert_ne!(r2.slot_key(), r3.slot_key());
    }

    /// W1 fix: `det_id` is applied only when `Some` — the per-record path opts
    /// into the deterministic id; the epoch path (`None`) keeps the random
    /// uuid7 so the two reward categories never collide on a shared seal id.
    #[test]
    fn create_reward_record_honors_det_id_param() {
        let identity = test_identity();
        let det = witness_reward_det_id("rec-x", "wit-y");
        let mk = |det_id| {
            create_reward_record(RewardRecordParams {
                identity: &identity,
                genesis_hash: &identity.identity_hash,
                witness_hash: "wit-y",
                record_id: "rec-x",
                amount: 100,
                parents: vec![],
                light_mode: false,
                slot_nonce: 7,
                det_id,
            })
            .unwrap()
        };

        // Some(_) → the record carries EXACTLY that id and is signed over it
        // (id is field 0 of signable_bytes; signing happens after assignment).
        let r = mk(Some(det.clone()));
        assert_eq!(r.id, det, "det_id must be applied before signing");
        assert!(r.signature.is_some());

        // None → keeps the random uuid7 (the epoch-reward path), NOT wrwd1:.
        assert!(
            !mk(None).id.starts_with("wrwd1:"),
            "None must keep the random uuid7 id"
        );
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
            det_id: None,
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
            det_id: None,
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
            det_id: None,
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
            det_id: None,
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

    // ── design C: exactly-once finalization effects ──────────────────────────

    #[test]
    fn witness_reward_det_id_is_deterministic_distinct_and_wire_legal() {
        let a = witness_reward_det_id("rec-1", "wit-1");
        // Same (record_id, witness_hash) → same id: the root of idempotency.
        assert_eq!(a, witness_reward_det_id("rec-1", "wit-1"));
        // Distinct inputs → distinct ids.
        assert_ne!(a, witness_reward_det_id("rec-2", "wit-1"));
        assert_ne!(a, witness_reward_det_id("rec-1", "wit-2"));
        // Length-prefixing prevents field-boundary aliasing.
        assert_ne!(
            witness_reward_det_id("ab", "c"),
            witness_reward_det_id("a", "bc")
        );
        // Never keyed on amount/nonce/timestamp — only the two args above.
        // Wire-legal: validate_wire_id admits any ASCII id ≤ 128 bytes.
        assert!(a.starts_with("wrwd1:"));
        assert!(a.is_ascii(), "must be ASCII for validate_wire_id");
        assert_eq!(a.len(), 70, "\"wrwd1:\" (6) + 64 hex");
        assert!(a.len() <= 128, "must fit the wire id length cap");
    }

    /// Per-record and per-epoch reward ids MUST NOT collide for a shared seal id
    /// (domain separation) — else a seal rewarded by both paths silently drops
    /// one reward while metrics count it as paid (verdict finding #4 / W1).
    #[test]
    fn epoch_and_per_record_reward_ids_never_collide() {
        let seal = "0192abcd-1234-7abc-8def-0123456789ab";
        let wh = "wit-1";
        assert_ne!(
            witness_reward_det_id(seal, wh),
            epoch_reward_det_id(seal, wh),
            "per-record and per-epoch ids must differ by domain"
        );
        // epoch id is itself deterministic, distinct, and wire-legal.
        let e = epoch_reward_det_id(seal, wh);
        assert_eq!(e, epoch_reward_det_id(seal, wh));
        assert_ne!(e, epoch_reward_det_id(seal, "wit-2"));
        assert_ne!(e, epoch_reward_det_id("other-seal", wh));
        assert!(e.starts_with("wrwd1:") && e.is_ascii() && e.len() == 70);
    }

    #[test]
    fn claim_inflight_is_single_flight() {
        let state = crate::network::state::build_test_node_state();
        let g1 = claim_inflight(&state, "rid-1");
        assert!(g1.is_some(), "first claim wins");
        assert!(
            claim_inflight(&state, "rid-1").is_none(),
            "second claim on the same rid is blocked while the first guard lives"
        );
        assert!(
            claim_inflight(&state, "rid-2").is_some(),
            "a different rid is independent"
        );
        drop(g1);
        assert!(
            claim_inflight(&state, "rid-1").is_some(),
            "the rid is claimable again once the guard drops (Drop released it)"
        );
    }

    #[tokio::test]
    async fn reconcile_pending_effects_recovers_and_clears_seeded_marker() {
        use crate::network::finalized::PENDING_EFFECTS_FRESH;
        let state = crate::network::state::build_test_node_state();
        // A realistic 36-char uuid7-shaped id: CF_ATTESTATIONS' fixed-41-byte
        // prefix extractor requires `att:`+36+`:` = 41 for the scan to hit.
        let rid = "0192abcd-1234-7abc-8def-0123456789ab";

        // Durable attestation so credit_undisputed has a witness to credit.
        state
            .witness_mgr
            .store_attestation(rid, "wit-x", b"sig", 1.0, None)
            .unwrap();
        // sanity: the durable store round-trips what get_attestations reads
        let att_rows = state.witness_mgr.get_attestations(rid).unwrap();
        assert_eq!(att_rows.len(), 1, "durable attestation must be readable");
        assert_eq!(att_rows[0].witness_hash, "wit-x");
        assert_eq!(durable_attestors(&state, rid), vec!["wit-x".to_string()]);
        // Seed a fresh pending-effects marker, as if the detached effects task
        // died after the durable finalize but before completing effects.
        state
            .rocks
            .put_cf_raw(
                CF_METADATA,
                pending_effects_key(rid).as_bytes(),
                &[PENDING_EFFECTS_FRESH],
            )
            .unwrap();

        reconcile_pending_effects(&state).await;

        // The sweep completed the effects and cleared the marker.
        assert!(
            state
                .rocks
                .get_cf_raw(CF_METADATA, pending_effects_key(rid).as_bytes())
                .unwrap()
                .is_none(),
            "sweep must clear the marker once effects complete"
        );
        // Reputation was credited for the durable attestor (non-idempotent
        // credit_undisputed ran exactly once, gated by the marker bit).
        let credited = {
            let rep = state.reputation.lock_recover();
            rep.summary()
                .into_iter()
                .any(|(wh, _, _, positive, _)| wh == "wit-x" && positive >= 1)
        };
        assert!(credited, "credit_undisputed must have run for the durable attestor");
    }
}
