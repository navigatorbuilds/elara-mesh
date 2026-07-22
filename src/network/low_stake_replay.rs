//! Tier 4.6 — bootstrap-pathology defer/replay buffer.
//!
//! When a node is behind on ledger catch-up, peer attestations whose witness's
//! stake row hasn't synced yet would otherwise be rejected at the sybil-defense
//! gate (`MIN_WITNESS_STAKE = 100 beat`, base units). On a 1-CPU node the
//! self-attestation rate (≤ 0.05/s with the default `auto_witness` cadence) is
//! orders of magnitude below the inbound record rate, so without external
//! attestations nothing finalizes; records age out of `pending_ledger` and the
//! node never catches up.
//!
//! This module buffers low-stake-rejected attestations on a per-witness key
//! and replays them once the witness's stake row reaches the threshold. The
//! sybil defense is preserved end-to-end: the gate still runs at replay time,
//! and entries past `PENDING_HARD_DISCARD_TIMEOUT_SECS` are evicted regardless.
//!
//! See internal design notes §4.6.
use std::sync::Arc;

use tracing::{debug, info};

use super::pending_drain::PENDING_HARD_DISCARD_TIMEOUT_SECS;
use super::state::{DeferredLowStakeAttestation, NodeState};

/// Admin diagnostics: snapshot of the Tier 4.6 buffer for ops debugging.
/// Returns per-witness counts, age range, and a few sample record_ids — enough to
/// identify a stuck-drain witness without needing log scraping. The witness's
/// current `ledger.staked()` value is included so an operator can immediately tell
/// whether the gate is the issue (stake row missing on this node) or the witness
/// is genuinely below threshold.
pub async fn dump_low_stake_buffer(state: &Arc<NodeState>) -> serde_json::Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    // Snapshot the buffer under the lock — clone the small per-witness summaries
    // so we can drop the lock before the per-witness ledger.staked() lookups.
    struct BufSnap {
        witness_hash: String,
        buffered: usize,
        oldest_age_secs: f64,
        newest_age_secs: f64,
        sample_record_ids: Vec<String>,
    }
    let snaps: Vec<BufSnap> = {
        let buf = state
            .low_stake_deferred
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        buf.iter()
            .map(|(witness_hash, entries)| {
                let oldest_received = entries
                    .iter()
                    .map(|e| e.received_at)
                    .fold(f64::INFINITY, f64::min);
                let newest_received = entries
                    .iter()
                    .map(|e| e.received_at)
                    .fold(f64::NEG_INFINITY, f64::max);
                let oldest_age = if oldest_received.is_finite() {
                    (now - oldest_received).max(0.0)
                } else {
                    0.0
                };
                let newest_age = if newest_received.is_finite() {
                    (now - newest_received).max(0.0)
                } else {
                    0.0
                };
                let sample_record_ids = entries
                    .iter()
                    .take(5)
                    .map(|e| e.record_id.clone())
                    .collect();
                BufSnap {
                    witness_hash: witness_hash.clone(),
                    buffered: entries.len(),
                    oldest_age_secs: oldest_age,
                    newest_age_secs: newest_age,
                    sample_record_ids,
                }
            })
            .collect()
    };

    // Per-witness stake lookup runs after the lock drop. Single ledger.read() for
    // all witnesses keeps the read-lock acquisition count to one regardless of
    // buffer size.
    let stakes: std::collections::HashMap<String, u64> = {
        let ledger = state.ledger.read().await;
        snaps
            .iter()
            .map(|s| (s.witness_hash.clone(), ledger.staked(&s.witness_hash)))
            .collect()
    };

    let witnesses: Vec<serde_json::Value> = snaps
        .iter()
        .map(|s| {
            let stake = stakes.get(&s.witness_hash).copied().unwrap_or(0);
            serde_json::json!({
                "witness_hash": s.witness_hash,
                "buffered": s.buffered,
                "oldest_age_secs": s.oldest_age_secs,
                "newest_age_secs": s.newest_age_secs,
                "current_staked_base_units": stake,
                "min_witness_stake_base_units": MIN_WITNESS_STAKE,
                "stake_meets_threshold": stake >= MIN_WITNESS_STAKE,
                "sample_record_ids": s.sample_record_ids,
            })
        })
        .collect();

    serde_json::json!({
        "witnesses": witnesses,
        "total_witnesses": snaps.len(),
        "total_buffered": snaps.iter().map(|s| s.buffered).sum::<usize>(),
        "max_tracked_witnesses": MAX_TRACKED_WITNESSES,
        "hard_discard_timeout_secs": PENDING_HARD_DISCARD_TIMEOUT_SECS,
        "sweep_interval_secs": SWEEP_INTERVAL_SECS,
    })
}

/// Sybil-defense threshold mirrored from the ingest gates. Single source of
/// truth lives in `accounting::types` so this re-check can never drift from the
/// gate (drift would loop the replay sweep). 100 beat in base units.
const MIN_WITNESS_STAKE: u64 = crate::accounting::types::MIN_WITNESS_STAKE_BASE_UNITS;
/// Bound on the number of distinct witnesses tracked. Mirrors the cap on the
/// existing record-not-local `deferred_attestations` buffer.
const MAX_TRACKED_WITNESSES: usize = 5_000;
/// Per-witness FIFO bucket cap. Mirrors the sibling
/// `MAX_DEFERRED_ATTS_PER_RECORD = 128` on the record-not-local buffer, which
/// the low-stake buffer originally omitted — it bounded only the witness-key
/// count, leaving a single witness's bucket unbounded. Without this cap a fresh
/// follower attesting every record it sees pre-stake-sync (the first-external join
/// path), or a hostile peer forging one `witness_hash` over many distinct
/// `record_id`s, grows that bucket without bound (memory) and turns the
/// `already_buffered` linear scan in `buffer_low_stake_attestation` into an
/// O(bucket) insert (CPU). 128 entries × ~5 KB ≈ 640 KB/witness worst case.
const MAX_DEFERRED_ATTS_PER_WITNESS: usize = 128;
/// Sweep cadence. 60 s is faster than the soft pending-discard cutoff (600 s)
/// so most deferred attestations get replayed well before their record's
/// pending entry is at risk of soft-discard.
const SWEEP_INTERVAL_SECS: u64 = 60;

/// Append a deferred attestation to the per-witness buffer, evicting the
/// oldest-witness entry on overflow. Pure synchronous helper — no async or
/// ledger I/O — so it can be called from the ingest hot path without holding
/// any read lock from the caller.
///
/// Maintains `low_stake_deferred_{witnesses,total,oldest_at_bits}`
/// atomics on `state` so the Prometheus scrape path reads in O(1) without
/// touching this buffer's mutex.
pub fn buffer_low_stake_attestation(
    state: &Arc<NodeState>,
    entry: DeferredLowStakeAttestation,
) {
    let mut buf = state
        .low_stake_deferred
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let witness_hash = entry.witness_hash.clone();
    let entry_received_at = entry.received_at;
    let entry_record_id = entry.record_id.clone();

    let bucket_was_new = !buf.contains_key(&witness_hash);
    let bucket = buf.entry(witness_hash).or_default();
    let already_buffered = bucket
        .iter()
        .any(|e| e.record_id == entry_record_id);
    if !already_buffered {
        bucket.push(entry);
        // Per-witness FIFO cap. On overflow drop the front (oldest
        // `received_at`) entry — the hard-discard sweep would evict it first
        // anyway. `bucket_was_new` (len 1) and `overflowed` (len > 128) are
        // mutually exclusive, so the witness-count bump below is unaffected.
        let overflowed = bucket.len() > MAX_DEFERRED_ATTS_PER_WITNESS;
        if overflowed {
            bucket.remove(0);
        }
        // Net total delta cancels on overflow (+1 push, −1 evict), so only
        // bump when nothing was evicted. The oldest gauge self-heals on the
        // next 60 s sweep (`recount_oldest_from_buf`); we deliberately skip an
        // O(total) recount here so the saturated path stays O(bucket).
        if !overflowed {
            state
                .low_stake_deferred_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        if bucket_was_new {
            state
                .low_stake_deferred_witnesses
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        // Oldest is min over all received_at — only relax it on
        // insert (push monotonically grows the candidate set).
        update_oldest_to_min(state, entry_received_at);
    }

    if buf.len() > MAX_TRACKED_WITNESSES {
        let oldest_witness = buf
            .iter()
            .filter_map(|(k, v)| {
                v.iter()
                    .map(|e| e.received_at)
                    .min_by(|a, b| a.total_cmp(b))
                    .map(|ts| (k.clone(), ts))
            })
            .min_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(k, _)| k);
        if let Some(k) = oldest_witness {
            // Subtract evicted bucket from totals before remove.
            if let Some(evicted) = buf.remove(&k) {
                let evicted_len = evicted.len() as u64;
                state
                    .low_stake_deferred_total
                    .fetch_sub(evicted_len, std::sync::atomic::Ordering::Relaxed);
                state
                    .low_stake_deferred_witnesses
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                // The evicted bucket held the oldest entry by construction
                // (it was selected as the LRU witness) — recompute oldest
                // from remaining buckets while we still hold the buffer mutex.
                recount_oldest_from_buf(state, &buf);
            }
        }
    }
}

/// Helper: relax the oldest atomic to `min(current, candidate)` via
/// compare-and-swap. Tolerates concurrent inserts (each tries to lower the
/// stored value; the lowest one wins).
fn update_oldest_to_min(state: &Arc<NodeState>, candidate: f64) {
    let candidate_bits = candidate.to_bits();
    let mut current = state
        .low_stake_deferred_oldest_at_bits
        .load(std::sync::atomic::Ordering::Relaxed);
    loop {
        let current_f = f64::from_bits(current);
        if !candidate.is_finite() || current_f <= candidate {
            return;
        }
        match state.low_stake_deferred_oldest_at_bits.compare_exchange_weak(
            current,
            candidate_bits,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

/// Helper: recompute oldest from the buffer (full iteration).
/// Caller MUST hold the buffer mutex. Stores `f64::INFINITY.to_bits()` when
/// the buffer is empty.
pub(crate) fn recount_oldest_from_buf(
    state: &Arc<NodeState>,
    buf: &std::collections::HashMap<String, Vec<DeferredLowStakeAttestation>>,
) {
    let oldest = buf
        .values()
        .flat_map(|v| v.iter().map(|e| e.received_at))
        .fold(f64::INFINITY, f64::min);
    state
        .low_stake_deferred_oldest_at_bits
        .store(oldest.to_bits(), std::sync::atomic::Ordering::Relaxed);
}

/// Periodic replay sweep. Iterates every tracked witness, re-checks
/// `ledger.staked(witness_hash)`, drains and replays attestations when the
/// stake row has caught up, and evicts entries past
/// `PENDING_HARD_DISCARD_TIMEOUT_SECS` (genuinely-low-stake or sybil entries).
pub async fn low_stake_replay_loop(state: Arc<NodeState>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
        SWEEP_INTERVAL_SECS,
    ));
    interval.tick().await; // immediate first fire after the spawn returns
    loop {
        interval.tick().await;
        // Stage 6 cooperative scheduler (Protocol §11.10): extra backoff
        // when host is saturated. The sweep snapshots witness_hashes under
        // a lock and then re-checks ledger.staked() per-witness — a busy
        // node should not chase a deferred bucket while seal signing waits.
        crate::network::system_load::coop_yield_if_busy(&state.system_load).await;
        run_sweep_once(&state).await;
    }
}

async fn run_sweep_once(state: &Arc<NodeState>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let hard_cutoff = now - PENDING_HARD_DISCARD_TIMEOUT_SECS;

    // Snapshot witness_hashes under the lock, then drop it before any
    // ledger / consensus / RocksDB call. Keeps the ingest path (which also
    // takes this lock to buffer) responsive during a large sweep.
    let witnesses: Vec<String> = {
        let buf = state
            .low_stake_deferred
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        buf.keys().cloned().collect()
    };
    if witnesses.is_empty() {
        return;
    }

    let mut total_drained = 0u64;
    let mut total_expired = 0u64;
    for witness_hash in witnesses {
        let stake = {
            let ledger = state.ledger.read().await;
            ledger.staked(&witness_hash)
        };

        if stake >= MIN_WITNESS_STAKE {
            // Drain bucket atomically — once stake clears the gate every
            // entry can be replayed unconditionally.
            let drained: Vec<DeferredLowStakeAttestation> = {
                let mut buf = state
                    .low_stake_deferred
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let drained = buf.remove(&witness_hash).unwrap_or_default();
                if !drained.is_empty() {
                    // Subtract drained entries + witness count.
                    state.low_stake_deferred_total.fetch_sub(
                        drained.len() as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    state
                        .low_stake_deferred_witnesses
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    // The drained bucket may have held the oldest entry —
                    // recompute oldest under the still-held buffer mutex.
                    recount_oldest_from_buf(state, &buf);
                }
                drained
            };
            for entry in drained {
                if replay_one(state, &entry).await {
                    total_drained += 1;
                }
            }
        } else {
            // Stake still below threshold — only evict entries past the
            // hard-discard ceiling. Keep the rest for the next tick.
            let expired_now = {
                let mut buf = state
                    .low_stake_deferred
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let Some(bucket) = buf.get_mut(&witness_hash) else {
                    continue;
                };
                let before = bucket.len();
                bucket.retain(|e| e.received_at >= hard_cutoff);
                let after = bucket.len();
                let removed = before.saturating_sub(after) as u64;
                let bucket_emptied = bucket.is_empty();
                if bucket_emptied {
                    buf.remove(&witness_hash);
                }
                if removed > 0 {
                    // Subtract expired entries + witness if emptied.
                    state.low_stake_deferred_total.fetch_sub(
                        removed,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    if bucket_emptied {
                        state
                            .low_stake_deferred_witnesses
                            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    // Some retained-out entries had the oldest received_at —
                    // recompute oldest under the still-held buffer mutex.
                    recount_oldest_from_buf(state, &buf);
                }
                removed
            };
            total_expired += expired_now;
        }
    }

    if total_drained > 0 {
        state
            .attestation_receive_low_stake_drained_total
            .fetch_add(total_drained, std::sync::atomic::Ordering::Relaxed);
    }
    if total_expired > 0 {
        state
            .attestation_receive_low_stake_expired_total
            .fetch_add(total_expired, std::sync::atomic::Ordering::Relaxed);
    }
    if total_drained > 0 || total_expired > 0 {
        info!(
            "low_stake_replay sweep: drained={total_drained} expired={total_expired}",
        );
    }
}

/// Replay a single deferred attestation through the same store-and-feed
/// path the ingest handlers use after the gate. The signature was already
/// verified at defer time; we still re-verify here so a buffered entry
/// against a record that has since been re-signed (e.g. forensic eviction
/// + re-emit) cannot smuggle a stale signature into consensus.
async fn replay_one(state: &Arc<NodeState>, entry: &DeferredLowStakeAttestation) -> bool {
    // Record must still be local — if it was evicted (forensic) or never
    // arrived, we cannot reconstruct signable_bytes and must drop the entry.
    let signable = match state.get_record(&entry.record_id) {
        Ok(rec) => rec.signable_bytes(),
        Err(_) => {
            debug!(
                "low_stake_replay: record {} no longer local, dropping att from {}",
                &entry.record_id[..entry.record_id.len().min(16)],
                &entry.witness_hash[..entry.witness_hash.len().min(16)],
            );
            return false;
        }
    };
    if let Some(pk) = entry.witness_public_key.as_deref() {
        match crate::crypto::pqc::dilithium3_verify(&signable, &entry.signature, pk) {
            Ok(true) => {}
            _ => {
                debug!(
                    "low_stake_replay: bad sig on replay from {} for {}",
                    &entry.witness_hash[..entry.witness_hash.len().min(16)],
                    &entry.record_id[..entry.record_id.len().min(16)],
                );
                return false;
            }
        }
    } else {
        return false;
    }

    // Store + feed.
    let stored = {
        let mgr = state.witness_mgr.as_ref();
        match mgr.store_attestation_with_powas(
            &entry.record_id,
            &entry.witness_hash,
            &entry.signature,
            entry.timestamp,
            entry.witness_public_key.as_deref(),
            entry.powas_nonce,
            entry.powas_difficulty,
        ) {
            Ok(s) => s,
            Err(e) => {
                debug!(
                    "low_stake_replay: store_attestation_with_powas failed for {}: {e}",
                    &entry.record_id[..entry.record_id.len().min(16)],
                );
                return false;
            }
        }
    };
    if !stored {
        return false; // duplicate — already counted somewhere else
    }
    let outcome = state
        .feed_attestation(&entry.record_id, &entry.witness_hash, entry.timestamp)
        .await;
    if outcome.first_finalization {
        crate::network::reward::finalization_effects(
            state,
            vec![entry.record_id.clone()],
        );
    }
    crate::network::reward::finalization_effects(state, outcome.seal_members_finalized);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::state::DeferredLowStakeAttestation;

    fn att(record_id: &str, witness: &str, ts: f64) -> DeferredLowStakeAttestation {
        DeferredLowStakeAttestation {
            record_id: record_id.into(),
            witness_hash: witness.into(),
            signature: vec![1, 2, 3],
            timestamp: ts,
            witness_public_key: Some(vec![9; 1952]),
            powas_nonce: None,
            powas_difficulty: None,
            received_at: ts,
        }
    }

    #[test]
    fn buffer_dedupes_per_record_id() {
        let state = crate::network::state::build_test_node_state();

        buffer_low_stake_attestation(&state, att("rec1", "w1", 100.0));
        buffer_low_stake_attestation(&state, att("rec1", "w1", 200.0));
        buffer_low_stake_attestation(&state, att("rec2", "w1", 300.0));

        let buf = state
            .low_stake_deferred
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.get("w1").unwrap().len(), 2);
    }

    #[test]
    fn buffer_caps_distinct_witnesses() {
        let state = crate::network::state::build_test_node_state();

        for i in 0..(MAX_TRACKED_WITNESSES + 50) {
            buffer_low_stake_attestation(
                &state,
                att(&format!("rec{i}"), &format!("w{i}"), i as f64),
            );
        }

        let buf = state
            .low_stake_deferred
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert!(buf.len() <= MAX_TRACKED_WITNESSES);
    }

    #[test]
    fn buffer_caps_per_witness_bucket_fifo() {
        let state = crate::network::state::build_test_node_state();

        // One witness, far more distinct records than the per-bucket cap —
        // the unbounded-bucket / O(n^2)-insert vector a single low-stake
        // witness could otherwise drive.
        let overshoot = MAX_DEFERRED_ATTS_PER_WITNESS + 50;
        for i in 0..overshoot {
            buffer_low_stake_attestation(&state, att(&format!("rec{i}"), "w1", i as f64));
        }

        let buf = state
            .low_stake_deferred
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let bucket = buf.get("w1").unwrap();
        // Bucket is FIFO-capped, not unbounded.
        assert_eq!(bucket.len(), MAX_DEFERRED_ATTS_PER_WITNESS);
        assert_eq!(buf.len(), 1, "single witness key");
        // FIFO: the oldest `overshoot - cap` entries were evicted; the newest
        // cap-worth survive (lowest surviving received_at == evicted count).
        let lowest_surviving = bucket
            .iter()
            .map(|e| e.received_at)
            .fold(f64::INFINITY, f64::min);
        assert_eq!(
            lowest_surviving,
            (overshoot - MAX_DEFERRED_ATTS_PER_WITNESS) as f64,
            "oldest entries must be evicted front-first (FIFO)"
        );
        // The OPS-154 total atomic tracks the capped size, not the overshoot
        // (push +1 / evict −1 cancel on the saturated path).
        assert_eq!(
            state
                .low_stake_deferred_total
                .load(std::sync::atomic::Ordering::Relaxed),
            MAX_DEFERRED_ATTS_PER_WITNESS as u64
        );
    }

    #[tokio::test]
    async fn sweep_expires_stale_entries_when_stake_low() {
        let state = crate::network::state::build_test_node_state();

        // Insert an entry pretending it's older than the hard cutoff.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let mut stale = att("rec_stale", "w_stale", now);
        stale.received_at = now - PENDING_HARD_DISCARD_TIMEOUT_SECS - 100.0;
        buffer_low_stake_attestation(&state, stale);

        // Stake is 0 (test instance has empty ledger) → expired path.
        run_sweep_once(&state).await;

        let buf = state
            .low_stake_deferred
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert!(buf.is_empty(), "stale entry should have been evicted");
        assert_eq!(
            state
                .attestation_receive_low_stake_expired_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
        );
    }

    #[tokio::test]
    async fn dump_buffer_reports_per_witness_age_and_stake() {
        let state = crate::network::state::build_test_node_state();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        // Two witnesses, two entries each with different ages so we can verify
        // the oldest/newest age range is reported per-witness.
        let mut a1 = att("rec_a1", "w_alpha", now);
        a1.received_at = now - 90.0;
        buffer_low_stake_attestation(&state, a1);
        let mut a2 = att("rec_a2", "w_alpha", now);
        a2.received_at = now - 30.0;
        buffer_low_stake_attestation(&state, a2);

        let mut b1 = att("rec_b1", "w_beta", now);
        b1.received_at = now - 10.0;
        buffer_low_stake_attestation(&state, b1);

        let dump = dump_low_stake_buffer(&state).await;

        assert_eq!(dump["total_witnesses"].as_u64().unwrap(), 2);
        assert_eq!(dump["total_buffered"].as_u64().unwrap(), 3);
        assert_eq!(
            dump["min_witness_stake_base_units"]
                .as_u64()
                .or_else(|| dump["witnesses"][0]["min_witness_stake_base_units"].as_u64()),
            Some(MIN_WITNESS_STAKE),
            "MIN_WITNESS_STAKE constant exposed for operator reference",
        );

        let alpha = dump["witnesses"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["witness_hash"] == "w_alpha")
            .expect("w_alpha entry");
        assert_eq!(alpha["buffered"].as_u64().unwrap(), 2);
        assert!(alpha["oldest_age_secs"].as_f64().unwrap() >= 89.0);
        assert!(alpha["newest_age_secs"].as_f64().unwrap() <= 31.0);
        assert_eq!(alpha["current_staked_base_units"].as_u64().unwrap(), 0);
        assert!(!alpha["stake_meets_threshold"].as_bool().unwrap());
        assert_eq!(alpha["sample_record_ids"].as_array().unwrap().len(), 2);

        let beta = dump["witnesses"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["witness_hash"] == "w_beta")
            .expect("w_beta entry");
        assert_eq!(beta["buffered"].as_u64().unwrap(), 1);
    }

    #[tokio::test]
    async fn sweep_keeps_fresh_entries_when_stake_low() {
        let state = crate::network::state::build_test_node_state();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let mut fresh = att("rec_fresh", "w_fresh", now);
        fresh.received_at = now - 30.0; // well within hard cutoff
        buffer_low_stake_attestation(&state, fresh);

        run_sweep_once(&state).await;

        let buf = state
            .low_stake_deferred
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(buf.len(), 1, "fresh entry must survive the sweep");
        assert_eq!(
            state
                .attestation_receive_low_stake_expired_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
    }

    // ── incremental deferred-buffer counters ────────────────

    /// Invariant: counters match the buffer state at every observable
    /// point. Mirrors the incremental-counter pattern of recomputing on a clone
    /// (here via direct buf inspection since the truth is the HashMap).
    fn ops154_assert_invariant(state: &std::sync::Arc<crate::network::state::NodeState>, where_: &str) {
        let buf = state
            .low_stake_deferred
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let expected_witnesses = buf.len() as u64;
        let expected_total: u64 = buf.values().map(|v| v.len() as u64).sum();
        let expected_oldest: f64 = buf
            .values()
            .flat_map(|v| v.iter().map(|e| e.received_at))
            .fold(f64::INFINITY, f64::min);
        let actual_witnesses = state
            .low_stake_deferred_witnesses
            .load(std::sync::atomic::Ordering::Relaxed);
        let actual_total = state
            .low_stake_deferred_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let actual_oldest = f64::from_bits(
            state
                .low_stake_deferred_oldest_at_bits
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        assert_eq!(
            actual_witnesses, expected_witnesses,
            "OPS-154 witness count mismatch at {where_}: actual={actual_witnesses} expected={expected_witnesses}",
        );
        assert_eq!(
            actual_total, expected_total,
            "OPS-154 total mismatch at {where_}: actual={actual_total} expected={expected_total}",
        );
        // Compare oldest by bits since both sides may be NaN/INFINITY in the
        // empty case — bit-equal comparison is the safe form.
        assert_eq!(
            actual_oldest.to_bits(),
            expected_oldest.to_bits(),
            "OPS-154 oldest mismatch at {where_}: actual={actual_oldest} expected={expected_oldest}",
        );
    }

    #[tokio::test]
    async fn ops154_counters_invariant_under_random_ops() {
        let state = crate::network::state::build_test_node_state();
        ops154_assert_invariant(&state, "post-build_test_node_state");
        // Initial state: empty buffer, oldest = +INFINITY.
        assert_eq!(
            state
                .low_stake_deferred_oldest_at_bits
                .load(std::sync::atomic::Ordering::Relaxed),
            f64::INFINITY.to_bits(),
        );

        // Phase 1: insert 3 entries across 2 witnesses, varying received_at.
        let mut e1 = att("rec1", "w1", 0.0); e1.received_at = 100.0;
        buffer_low_stake_attestation(&state, e1);
        ops154_assert_invariant(&state, "post-push w1/rec1@100");

        let mut e2 = att("rec2", "w1", 0.0); e2.received_at = 200.0;
        buffer_low_stake_attestation(&state, e2);
        ops154_assert_invariant(&state, "post-push w1/rec2@200");

        let mut e3 = att("rec3", "w2", 0.0); e3.received_at = 50.0;
        buffer_low_stake_attestation(&state, e3);
        ops154_assert_invariant(&state, "post-push w2/rec3@50 (now oldest)");
        // Oldest should be 50.0 (w2's only entry).
        let oldest_bits = state
            .low_stake_deferred_oldest_at_bits
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(f64::from_bits(oldest_bits), 50.0);
        assert_eq!(
            state.low_stake_deferred_total.load(std::sync::atomic::Ordering::Relaxed),
            3,
        );
        assert_eq!(
            state.low_stake_deferred_witnesses.load(std::sync::atomic::Ordering::Relaxed),
            2,
        );

        // Phase 2: dedupe — re-pushing same record_id is a no-op for counters.
        let total_before_dedupe = state.low_stake_deferred_total.load(std::sync::atomic::Ordering::Relaxed);
        let mut e1_dup = att("rec1", "w1", 0.0); e1_dup.received_at = 999.0;
        buffer_low_stake_attestation(&state, e1_dup);
        ops154_assert_invariant(&state, "post-dedupe push");
        assert_eq!(
            state.low_stake_deferred_total.load(std::sync::atomic::Ordering::Relaxed),
            total_before_dedupe,
            "dedupe must not bump total"
        );

        // Phase 3: drain w2 via sweep (stake=0 + entry received_at older than
        // hard cutoff would expire it; here we use a manual remove since
        // ledger.staked() in test mode is 0 and the expired path requires
        // a stale received_at). Test the drain path by setting up another
        // entry that's beyond hard_cutoff so retain drops it.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let mut stale = att("rec_stale", "w_stale", 0.0);
        stale.received_at = now - PENDING_HARD_DISCARD_TIMEOUT_SECS - 100.0;
        buffer_low_stake_attestation(&state, stale);
        ops154_assert_invariant(&state, "post-push stale");

        run_sweep_once(&state).await;
        ops154_assert_invariant(&state, "post-sweep (w_stale expired)");

        // Phase 4: clear remaining entries via the same expired path —
        // mark all received_at as past the cutoff, run sweep.
        {
            let mut buf = state
                .low_stake_deferred
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for entries in buf.values_mut() {
                for e in entries.iter_mut() {
                    e.received_at = now - PENDING_HARD_DISCARD_TIMEOUT_SECS - 200.0;
                }
            }
            // Buffer mutated by hand — forcibly recount oldest under lock so
            // counters stay coherent for the assert_invariant that follows.
            recount_oldest_from_buf(&state, &buf);
        }
        run_sweep_once(&state).await;
        ops154_assert_invariant(&state, "post-final-sweep (all expired)");
        assert_eq!(
            state.low_stake_deferred_total.load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
        assert_eq!(
            state.low_stake_deferred_witnesses.load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
        assert_eq!(
            state.low_stake_deferred_oldest_at_bits.load(std::sync::atomic::Ordering::Relaxed),
            f64::INFINITY.to_bits(),
            "empty buffer must reset oldest to +INFINITY"
        );
    }

    #[test]
    fn ops154_counters_invariant_under_overflow_eviction() {
        let state = crate::network::state::build_test_node_state();

        // Push MAX_TRACKED_WITNESSES + 50 distinct witnesses with monotonically
        // increasing received_at — the eviction path should drop the oldest
        // witness (the one with the lowest received_at) on each overflow.
        for i in 0..(MAX_TRACKED_WITNESSES + 50) {
            let mut e = att(&format!("rec{i}"), &format!("w{i}"), 0.0);
            e.received_at = (i as f64) + 1.0;
            buffer_low_stake_attestation(&state, e);
            // Assert invariant on a sample (every 1000 pushes — full per-step
            // assert would be O(N²) for the recompute-from-buf check).
            if i % 1000 == 0 {
                ops154_assert_invariant(&state, &format!("post-push#{i}"));
            }
        }
        ops154_assert_invariant(&state, "post-overflow-bulk-push");

        // Buffer is capped at MAX_TRACKED_WITNESSES, total == sum of bucket
        // lens (one per witness) == MAX_TRACKED_WITNESSES, oldest is the
        // surviving lowest received_at.
        let buf = state
            .low_stake_deferred
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(buf.len(), MAX_TRACKED_WITNESSES);
        let total: usize = buf.values().map(|v| v.len()).sum();
        assert_eq!(total, MAX_TRACKED_WITNESSES);
    }

    #[test]
    fn ops154_oldest_starts_at_infinity_and_resets_to_infinity_when_empty() {
        let state = crate::network::state::build_test_node_state();
        // Initial: +INFINITY.
        assert_eq!(
            state.low_stake_deferred_oldest_at_bits.load(std::sync::atomic::Ordering::Relaxed),
            f64::INFINITY.to_bits(),
        );

        let mut e = att("r", "w", 0.0); e.received_at = 42.0;
        buffer_low_stake_attestation(&state, e);
        let bits = state
            .low_stake_deferred_oldest_at_bits
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(f64::from_bits(bits), 42.0);

        // Manually empty the buffer + recount under lock — simulates a
        // future code path that drains via a different route. The recount
        // helper must reset the atomic to +INFINITY.
        {
            let mut buf = state
                .low_stake_deferred
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            buf.clear();
            // Direct mutation bypassed the atomic counters — fix them up.
            state
                .low_stake_deferred_witnesses
                .store(0, std::sync::atomic::Ordering::Relaxed);
            state
                .low_stake_deferred_total
                .store(0, std::sync::atomic::Ordering::Relaxed);
            recount_oldest_from_buf(&state, &buf);
        }
        assert_eq!(
            state.low_stake_deferred_oldest_at_bits.load(std::sync::atomic::Ordering::Relaxed),
            f64::INFINITY.to_bits(),
        );
    }

    // ──────────────────
    //
    // The happy-path tests cover dedupe / overflow / sweep / counter
    // invariants; these 5 pin **constant
    // literals / non-finite tolerance / wire-shape contract / LRU-selection
    // logic / cross-witness recount semantics** — defect surfaces that no
    // prior test reaches and that a sloppy refactor would silently break.
    //
    //   1. Module constants pinned to literal values — MIN_WITNESS_STAKE,
    //      MAX_TRACKED_WITNESSES, SWEEP_INTERVAL_SECS. Sybil-defense
    //      threshold MUST match ingest's gate; a silent 10× change here
    //      would silently widen or narrow the catchup-buffer admission
    //      criterion fleet-wide.
    //   2. buffer_low_stake_attestation tolerates non-finite received_at —
    //      update_oldest_to_min early-returns on NaN / ±INFINITY; pin so a
    //      future "panic on bad received_at" or dropped is_finite() guard
    //      surfaces as a test diff (clock anomalies and NTP steps DO
    //      produce non-finite f64 values in production).
    //   3. dump_low_stake_buffer empty-state wire shape — exposes 6 keys
    //      (witnesses=[], total_witnesses=0, total_buffered=0, plus the
    //      three constant-echo fields max_tracked_witnesses /
    //      hard_discard_timeout_secs / sweep_interval_secs). The constants
    //      flow to operators via this admin JSON; a silent constant change
    //      would change wire shape AND change a non-test consumer.
    //   4. buffer_low_stake_attestation overflow eviction picks the
    //      witness with the smallest min received_at — existing
    //      buffer_caps_distinct_witnesses asserts only the cap, NOT the
    //      LRU-selection logic. A future refactor that picks "any witness"
    //      or "lexicographically smallest" would silently break catch-up
    //      replay budgeting.
    //   5. recount_oldest_from_buf is global-min across witnesses, not
    //      per-bucket — pin so a future refactor that collapses to a
    //      per-bucket min (compile-clean, semantically wrong) surfaces as
    //      a test diff. The oldest_at_bits gauge in the metrics
    //      surface depends on this for non-trivial 2+-witness buffers.

    #[test]
    fn batch_b_module_constants_pinned_to_literal_values() {
        // MIN_WITNESS_STAKE — sybil-defense threshold. MUST match the
        // ingest gate (100 beat in base units) or low-stake replay's gate
        // diverges from ingest's and replays would loop. Single source of
        // truth now lives in accounting::types so the gate sites can't drift.
        assert_eq!(
            MIN_WITNESS_STAKE,
            100 * crate::accounting::types::BASE_UNITS_PER_BEAT,
            "MIN_WITNESS_STAKE = 100 beat sybil threshold (base units, 10^9/beat)"
        );
        // MAX_TRACKED_WITNESSES — bound on distinct witnesses buffered.
        // Mirrors the cap on the record-not-local deferred_attestations
        // buffer. A silent narrowing (e.g. → 500) would aggressively evict
        // under sybil-storm conditions; widening (e.g. → 50_000) would
        // OOM small phone-tier nodes.
        assert_eq!(
            MAX_TRACKED_WITNESSES, 5_000usize,
            "MAX_TRACKED_WITNESSES = 5_000 — matches deferred_attestations cap"
        );
        // SWEEP_INTERVAL_SECS — cadence MUST be faster than
        // PENDING_HARD_DISCARD_TIMEOUT_SECS / 2 so deferred attestations
        // get a replay chance before their record's pending entry soft-
        // discards. 60s vs 1200s leaves ~20 sweep attempts per record.
        assert_eq!(SWEEP_INTERVAL_SECS, 60u64, "sweep cadence = 60s");
        // Inequality invariant: sweep < hard discard, by a big margin.
        assert!(
            (SWEEP_INTERVAL_SECS as f64) * 2.0 < PENDING_HARD_DISCARD_TIMEOUT_SECS,
            "sweep interval must be << hard discard timeout for the buffer to do useful replay work"
        );
    }

    #[test]
    fn batch_b_buffer_tolerates_non_finite_received_at_without_corrupting_oldest_atomic() {
        let state = crate::network::state::build_test_node_state();

        // Push entry with NaN received_at — update_oldest_to_min must
        // early-return on !is_finite() so the atomic stays +INFINITY.
        let mut nan_entry = att("rec_nan", "w_nan", 0.0);
        nan_entry.received_at = f64::NAN;
        buffer_low_stake_attestation(&state, nan_entry);
        let oldest_after_nan = state
            .low_stake_deferred_oldest_at_bits
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            oldest_after_nan,
            f64::INFINITY.to_bits(),
            "NaN received_at must NOT corrupt oldest atomic (early-return guard holds)"
        );

        // Push entry with +INFINITY received_at — same early-return path.
        let mut inf_entry = att("rec_inf", "w_inf", 0.0);
        inf_entry.received_at = f64::INFINITY;
        buffer_low_stake_attestation(&state, inf_entry);
        let oldest_after_inf = state
            .low_stake_deferred_oldest_at_bits
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            oldest_after_inf,
            f64::INFINITY.to_bits(),
            "+INFINITY received_at must NOT corrupt oldest atomic"
        );

        // Now push a finite entry — atomic MUST relax to the finite value
        // even though prior non-finite entries are still in the buffer.
        // Confirms the early-return doesn't poison the atomic for future
        // valid updates.
        let mut finite_entry = att("rec_fin", "w_fin", 0.0);
        finite_entry.received_at = 42.0;
        buffer_low_stake_attestation(&state, finite_entry);
        let oldest_after_finite = state
            .low_stake_deferred_oldest_at_bits
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            f64::from_bits(oldest_after_finite),
            42.0,
            "finite received_at MUST update oldest atomic past prior non-finite pushes"
        );

        // Counter invariant remains coherent — total = 3, witnesses = 3,
        // oldest_atomic via recount-style expected = fold(INFINITY, min,
        // [NaN, INFINITY, 42.0]) = 42.0 (NaN/INFINITY are ignored by min).
        ops154_assert_invariant(&state, "post-mixed-finite/non-finite pushes");
    }

    #[tokio::test]
    async fn batch_b_dump_low_stake_buffer_empty_state_shape_and_constants_echo() {
        let state = crate::network::state::build_test_node_state();

        // Empty buffer — dump must return the 6-key envelope with empty
        // witnesses array and the three constant-echo fields populated to
        // their literal values. Pinning this here means a silent constant
        // change in low_stake_replay.rs ALSO breaks this admin contract.
        let dump = dump_low_stake_buffer(&state).await;

        let obj = dump.as_object().expect("dump must be a JSON object");
        // Six top-level keys, no fewer, no more (catches accidental key
        // additions that change wire compatibility).
        assert_eq!(
            obj.len(),
            6,
            "empty dump must have exactly 6 keys: witnesses, total_witnesses, total_buffered, max_tracked_witnesses, hard_discard_timeout_secs, sweep_interval_secs (got {:?})",
            obj.keys().collect::<Vec<_>>()
        );

        // Empty-state values.
        assert!(
            dump["witnesses"].as_array().unwrap().is_empty(),
            "empty buffer must dump empty witnesses array"
        );
        assert_eq!(dump["total_witnesses"].as_u64().unwrap(), 0);
        assert_eq!(dump["total_buffered"].as_u64().unwrap(), 0);

        // Constant-echo fields — these flow to operators via the admin
        // endpoint, so the constants are *part of the contract*.
        assert_eq!(
            dump["max_tracked_witnesses"].as_u64().unwrap(),
            MAX_TRACKED_WITNESSES as u64,
            "max_tracked_witnesses echoes the constant"
        );
        assert_eq!(
            dump["hard_discard_timeout_secs"].as_f64().unwrap(),
            PENDING_HARD_DISCARD_TIMEOUT_SECS,
            "hard_discard_timeout_secs echoes the pending_drain constant"
        );
        assert_eq!(
            dump["sweep_interval_secs"].as_u64().unwrap(),
            SWEEP_INTERVAL_SECS,
            "sweep_interval_secs echoes the constant"
        );
    }

    #[test]
    fn batch_b_overflow_eviction_picks_witness_with_oldest_min_received_at() {
        let state = crate::network::state::build_test_node_state();

        // Seed three "anchor" witnesses with known received_at ordering.
        // After eviction the witness with the LOWEST min received_at MUST
        // be the one dropped — the LRU-by-receipt-time invariant.
        let mut e_oldest = att("rec_oldest_w", "w_oldest", 0.0);
        e_oldest.received_at = 10.0;
        buffer_low_stake_attestation(&state, e_oldest);
        let mut e_middle = att("rec_middle_w", "w_middle", 0.0);
        e_middle.received_at = 1_000.0;
        buffer_low_stake_attestation(&state, e_middle);
        let mut e_newest = att("rec_newest_w", "w_newest", 0.0);
        e_newest.received_at = 2_000.0;
        buffer_low_stake_attestation(&state, e_newest);

        // Now fill until just under cap. Use received_at FAR newer than
        // the three anchors so the anchors remain candidates for the LRU
        // pick. We've already pushed 3 → need MAX-3 more to hit cap, then
        // one more to trigger eviction.
        for i in 0..(MAX_TRACKED_WITNESSES - 3) {
            let mut filler = att(&format!("rec_fill_{i}"), &format!("w_fill_{i}"), 0.0);
            filler.received_at = 1_000_000.0 + (i as f64);
            buffer_low_stake_attestation(&state, filler);
        }
        // At cap exactly — no eviction yet.
        {
            let buf = state
                .low_stake_deferred
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            assert_eq!(buf.len(), MAX_TRACKED_WITNESSES, "buffer at cap before trigger push");
        }

        // Trigger push — overflow eviction fires.
        let mut trigger = att("rec_trigger", "w_trigger", 0.0);
        trigger.received_at = 2_000_000.0;
        buffer_low_stake_attestation(&state, trigger);

        let buf = state
            .low_stake_deferred
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            buf.len(),
            MAX_TRACKED_WITNESSES,
            "buffer must still be exactly at cap after eviction"
        );
        // LRU contract: w_oldest (received_at=10.0) was evicted, w_middle
        // and w_newest survived.
        assert!(
            !buf.contains_key("w_oldest"),
            "LRU eviction must drop w_oldest (lowest received_at) — got buffer.keys()={:?}",
            buf.keys().take(5).collect::<Vec<_>>()
        );
        assert!(buf.contains_key("w_middle"), "w_middle must survive");
        assert!(buf.contains_key("w_newest"), "w_newest must survive");
        assert!(buf.contains_key("w_trigger"), "trigger push must be retained");
    }

    #[test]
    fn batch_b_recount_oldest_from_buf_picks_global_min_across_witnesses_not_per_bucket() {
        let state = crate::network::state::build_test_node_state();

        // Build a buffer with 3 witnesses × 2 entries each, distinct
        // received_at across the 6 entries. The GLOBAL min must be picked,
        // NOT the min of any one bucket. A future refactor that collapsed
        // to `.values().map(min)` (per-bucket) would compile clean but
        // miss the cross-witness comparison; this test catches that.
        //
        // Layout (witness → [received_at, ...]):
        //   w_a → [500.0, 300.0]   (bucket-min = 300)
        //   w_b → [400.0,  50.0]   (bucket-min = 50) ← GLOBAL min
        //   w_c → [200.0, 100.0]   (bucket-min = 100)
        let pushes: Vec<(&str, &str, f64)> = vec![
            ("rec_a1", "w_a", 500.0),
            ("rec_a2", "w_a", 300.0),
            ("rec_b1", "w_b", 400.0),
            ("rec_b2", "w_b",  50.0),  // global min
            ("rec_c1", "w_c", 200.0),
            ("rec_c2", "w_c", 100.0),
        ];
        for (rec, witness, ts) in &pushes {
            let mut e = att(rec, witness, 0.0);
            e.received_at = *ts;
            buffer_low_stake_attestation(&state, e);
        }

        // Forcibly reset oldest atomic to something WRONG so the recount
        // is the thing being tested (not the buffer-time update_oldest_to_min
        // logic which is exercised elsewhere).
        state
            .low_stake_deferred_oldest_at_bits
            .store(99_999.0f64.to_bits(), std::sync::atomic::Ordering::Relaxed);

        {
            let buf = state
                .low_stake_deferred
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // Sanity: 3 witnesses, 6 entries.
            assert_eq!(buf.len(), 3, "must have 3 witnesses after pushes");
            let total: usize = buf.values().map(|v| v.len()).sum();
            assert_eq!(total, 6, "must have 6 entries across the 3 witnesses");

            recount_oldest_from_buf(&state, &buf);
        }

        let recounted = f64::from_bits(
            state
                .low_stake_deferred_oldest_at_bits
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        // Defect-pin: per-bucket min would return 50, 100, or 300 (any
        // of the bucket-mins) but only 50 is the GLOBAL min. A naive
        // refactor that yielded any of {100, 300} on this layout would
        // silently break the oldest_age gauge in dump_low_stake_buffer.
        assert_eq!(
            recounted, 50.0,
            "recount_oldest_from_buf MUST pick global min (50.0) across witnesses, not a per-bucket min"
        );
    }

    // ─── dump_low_stake_buffer ───
    //
    // The route handler at
    // `routes/admin.rs:967` is a 5-line delegator to `dump_low_stake_buffer`
    // in this module — the testable surface lives here, not in admin.rs.
    //
    // The existing `dump_buffer_reports_per_witness_age_and_stake` test
    // (line 537) covers the multi-witness happy path with two entries each
    // and one constant echoed (MIN_WITNESS_STAKE). It does NOT cover:
    //
    //   (1) Empty-buffer envelope shape — operator dashboards parse the
    //       6 top-level keys (witnesses, total_witnesses, total_buffered,
    //       max_tracked_witnesses, hard_discard_timeout_secs,
    //       sweep_interval_secs); a refactor that swapped one out (or
    //       added a 7th) would surface only on this empty-buffer case
    //       where the witnesses array is `[]` and the totals are 0.
    //   (2) sample_record_ids cap at 5 — the `entries.iter().take(5)`
    //       at line 72 caps a per-witness sample at 5 record_ids
    //       regardless of how many entries the witness has. The existing
    //       test only buffers 2 per witness so the cap is untested. A
    //       refactor that dropped the `take(5)` (or changed the literal)
    //       would silently allow operator dashboards to receive an
    //       unbounded list when a single witness has thousands of
    //       deferred attestations under bootstrap pathology.
    //   (3) stake_meets_threshold true case at the MIN_WITNESS_STAKE
    //       boundary — the existing test only covers stake=0 (default
    //       ledger) which always yields false. The `stake >= MIN_WITNESS_STAKE`
    //       comparison at line 108 needs the true branch pinned with
    //       stake=MIN_WITNESS_STAKE exactly (boundary-equal-to-threshold
    //       must surface as true; the `>=` is load-bearing because the
    //       sybil gate uses the same comparison and a `>` regression
    //       here would silently flag the boundary as still-below for
    //       operators trying to triage which witnesses are below stake).
    //   (4) total_buffered conservation: the top-level `total_buffered`
    //       MUST equal sum(witnesses[].buffered). The existing test
    //       happens to satisfy this (3 == 2+1) but doesn't pin it as
    //       an invariant. A refactor that started counting only fresh
    //       entries or filtered the sum would break this conservation
    //       silently — operator dashboards would show inconsistent
    //       totals.
    //   (5) Single-entry-per-witness edge case for oldest_age/newest_age:
    //       when a witness has exactly ONE deferred entry, oldest_age_secs
    //       MUST equal newest_age_secs (both derive from the same
    //       received_at). A refactor that always offset newest by some
    //       small epsilon, or used `min - 1` for oldest, would not
    //       surface on multi-entry tests but breaks this edge.

    #[tokio::test]
    async fn batch_iii_admin_dump_empty_buffer_envelope_pins_six_top_level_keys_and_constants() {
        // Axis (1): on a fresh state with no deferred attestations, the dump
        // MUST emit all 6 top-level keys with their constant fields set to
        // the in-module constants (MAX_TRACKED_WITNESSES, PENDING_HARD_DISCARD_TIMEOUT_SECS,
        // SWEEP_INTERVAL_SECS). Pins the operator-dashboard contract: the
        // diagnostic payload doesn't degrade to a partial object when the
        // buffer is empty, and the constants are exposed so operators don't
        // need to grep source to learn the cap/cadence.
        use std::collections::BTreeSet;
        let state = crate::network::state::build_test_node_state();
        let dump = dump_low_stake_buffer(&state).await;

        let obj = dump.as_object().expect("dump MUST be a JSON Object");
        let actual_keys: BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let expected_keys: BTreeSet<&str> = [
            "witnesses",
            "total_witnesses",
            "total_buffered",
            "max_tracked_witnesses",
            "hard_discard_timeout_secs",
            "sweep_interval_secs",
        ]
        .iter()
        .copied()
        .collect();
        let added: Vec<&&str> = actual_keys.difference(&expected_keys).collect();
        let dropped: Vec<&&str> = expected_keys.difference(&actual_keys).collect();
        assert!(
            added.is_empty() && dropped.is_empty(),
            "envelope key drift: added={:?} dropped={:?}",
            added,
            dropped
        );

        // Empty-state values.
        assert_eq!(
            dump["witnesses"].as_array().expect("witnesses MUST be array").len(),
            0,
            "witnesses array MUST be empty on fresh state"
        );
        assert_eq!(dump["total_witnesses"].as_u64(), Some(0));
        assert_eq!(dump["total_buffered"].as_u64(), Some(0));

        // Constant echoes — pin the literal module constants so a renumbering
        // refactor (e.g., MAX_TRACKED_WITNESSES 5000 → 10000) surfaces here
        // before operators see the dashboard cap shift silently.
        assert_eq!(
            dump["max_tracked_witnesses"].as_u64(),
            Some(MAX_TRACKED_WITNESSES as u64),
            "max_tracked_witnesses MUST echo the MAX_TRACKED_WITNESSES constant"
        );
        assert_eq!(
            dump["hard_discard_timeout_secs"].as_f64(),
            Some(PENDING_HARD_DISCARD_TIMEOUT_SECS),
            "hard_discard_timeout_secs MUST echo PENDING_HARD_DISCARD_TIMEOUT_SECS"
        );
        assert_eq!(
            dump["sweep_interval_secs"].as_u64(),
            Some(SWEEP_INTERVAL_SECS),
            "sweep_interval_secs MUST echo the SWEEP_INTERVAL_SECS constant"
        );
    }

    #[tokio::test]
    async fn batch_iii_admin_dump_sample_record_ids_capped_at_exactly_five_when_buffered_eight() {
        // Axis (2): buffer 8 deferred attestations for ONE witness. The
        // `sample_record_ids` array MUST have length 5 (the `take(5)` at
        // line 72) NOT 8. The `buffered` count is still 8 — the cap is
        // sample-only. Pins both halves of the contract: the count is
        // unfiltered (operator wants to know the true depth) and the
        // sample is bounded (operator dashboard doesn't OOM on a witness
        // with thousands of pending attestations under bootstrap pathology).
        let state = crate::network::state::build_test_node_state();
        for i in 0..8 {
            buffer_low_stake_attestation(
                &state,
                att(&format!("rec_{i:02}"), "w_solo", i as f64),
            );
        }
        let dump = dump_low_stake_buffer(&state).await;

        assert_eq!(dump["total_witnesses"].as_u64(), Some(1));
        assert_eq!(
            dump["total_buffered"].as_u64(),
            Some(8),
            "total_buffered MUST count all 8 entries (sample cap doesn't apply to the count)"
        );

        let solo = dump["witnesses"]
            .as_array()
            .expect("witnesses array")
            .iter()
            .find(|w| w["witness_hash"] == "w_solo")
            .expect("w_solo entry MUST be present");
        assert_eq!(
            solo["buffered"].as_u64(),
            Some(8),
            "buffered MUST be the unfiltered count (8), not the sample-capped 5"
        );
        let samples = solo["sample_record_ids"].as_array().expect("array");
        assert_eq!(
            samples.len(),
            5,
            "sample_record_ids MUST be capped at 5 — buffered=8 but `take(5)` clamps the sample size"
        );
    }

    #[tokio::test]
    async fn batch_iii_admin_dump_stake_meets_threshold_flips_at_min_witness_stake_boundary() {
        // Axis (3): the existing test only covers stake=0 (false branch);
        // this test pins the true branch AND the `>=` boundary. Two
        // witnesses, one with `staked = MIN_WITNESS_STAKE - 1` (one base unit
        // below the threshold), one with `staked = MIN_WITNESS_STAKE`
        // exactly (boundary-equal). Asserts the first surfaces as
        // `stake_meets_threshold=false` and the second as `true`. The
        // `>=` operator is load-bearing: a refactor to `>` would flip the
        // boundary-equal witness to false and operator triage tools would
        // misclassify an at-threshold witness as still-below.
        use crate::accounting::ledger::AccountState;

        let state = crate::network::state::build_test_node_state();
        // Buffer one entry per witness (just so they show up in the dump).
        buffer_low_stake_attestation(&state, att("rec_low", "w_just_below", 100.0));
        buffer_low_stake_attestation(&state, att("rec_high", "w_at_threshold", 200.0));

        // Manually plant stake balances in the ledger so `ledger.staked(witness)`
        // returns the boundary values. AccountState.staked is pub u64 so
        // direct mutation is safe; we drop the ledger write-guard before
        // calling dump_low_stake_buffer (it acquires its own read-guard).
        {
            let mut ledger = state.ledger.write().await;
            ledger.accounts.insert(
                "w_just_below".to_string(),
                AccountState {
                    staked: MIN_WITNESS_STAKE - 1,
                    ..Default::default()
                },
            );
            ledger.accounts.insert(
                "w_at_threshold".to_string(),
                AccountState {
                    staked: MIN_WITNESS_STAKE,
                    ..Default::default()
                },
            );
        }

        let dump = dump_low_stake_buffer(&state).await;
        let witnesses = dump["witnesses"].as_array().expect("witnesses array");

        let low = witnesses
            .iter()
            .find(|w| w["witness_hash"] == "w_just_below")
            .expect("w_just_below entry");
        assert_eq!(
            low["current_staked_base_units"].as_u64(),
            Some(MIN_WITNESS_STAKE - 1),
            "stake echo MUST match the planted value (boundary-minus-one)"
        );
        assert_eq!(
            low["stake_meets_threshold"].as_bool(),
            Some(false),
            "stake=MIN_WITNESS_STAKE-1 (one base unit below) MUST surface as stake_meets_threshold=false"
        );

        let high = witnesses
            .iter()
            .find(|w| w["witness_hash"] == "w_at_threshold")
            .expect("w_at_threshold entry");
        assert_eq!(
            high["current_staked_base_units"].as_u64(),
            Some(MIN_WITNESS_STAKE),
            "stake echo MUST match the planted value (exactly at threshold)"
        );
        assert_eq!(
            high["stake_meets_threshold"].as_bool(),
            Some(true),
            "stake=MIN_WITNESS_STAKE (exact equality) MUST surface as stake_meets_threshold=true — the `>=` comparison includes the boundary"
        );
    }

    #[tokio::test]
    async fn batch_iii_admin_dump_total_buffered_equals_sum_of_per_witness_buffered_invariant() {
        // Axis (4): conservation invariant. The top-level `total_buffered`
        // MUST equal sum(witnesses[].buffered). Buffer asymmetric counts
        // across 3 witnesses (1, 4, 7) to make the sum 12 — a non-trivial
        // value that a hardcoded constant or off-by-one would surface.
        // Pins that a refactor that started counting only fresh entries,
        // or filtered the sum by stake threshold, would not pass the
        // invariant check.
        let state = crate::network::state::build_test_node_state();
        // 1 entry for w_one
        buffer_low_stake_attestation(&state, att("r_1_0", "w_one", 1.0));
        // 4 entries for w_four
        for i in 0..4 {
            buffer_low_stake_attestation(
                &state,
                att(&format!("r_4_{i}"), "w_four", 10.0 + i as f64),
            );
        }
        // 7 entries for w_seven
        for i in 0..7 {
            buffer_low_stake_attestation(
                &state,
                att(&format!("r_7_{i}"), "w_seven", 100.0 + i as f64),
            );
        }

        let dump = dump_low_stake_buffer(&state).await;

        assert_eq!(dump["total_witnesses"].as_u64(), Some(3));
        let witnesses = dump["witnesses"].as_array().expect("witnesses array");
        assert_eq!(witnesses.len(), 3);

        // Conservation: top-level total_buffered MUST equal sum of per-witness buffered.
        let per_witness_sum: u64 = witnesses
            .iter()
            .map(|w| w["buffered"].as_u64().expect("buffered u64"))
            .sum();
        let top_level = dump["total_buffered"].as_u64().expect("total_buffered u64");
        assert_eq!(
            top_level, per_witness_sum,
            "total_buffered ({top_level}) MUST equal sum of per-witness buffered ({per_witness_sum}) — conservation invariant"
        );
        assert_eq!(
            top_level, 1 + 4 + 7,
            "absolute value: total_buffered MUST be 12 (1+4+7)"
        );
    }

    #[tokio::test]
    async fn batch_iii_admin_dump_single_entry_witness_oldest_equals_newest_age_secs() {
        // Axis (5): when a witness has exactly ONE deferred entry,
        // `oldest_age_secs` MUST equal `newest_age_secs` (both derive from
        // the same `received_at`). The existing multi-entry test (line 537)
        // exercises the case where they differ, but never the boundary
        // where they collapse. A refactor that always offset newest by
        // some small epsilon, or used `min - 1` for oldest, would not
        // surface on multi-entry tests but breaks this edge — operator
        // dashboards rendering "age range: 10s - 11s" for a single entry
        // would mislead triage.
        let state = crate::network::state::build_test_node_state();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let mut solo = att("rec_solo", "w_single", now);
        solo.received_at = now - 42.0;
        buffer_low_stake_attestation(&state, solo);

        let dump = dump_low_stake_buffer(&state).await;
        let witness = dump["witnesses"]
            .as_array()
            .expect("witnesses array")
            .iter()
            .find(|w| w["witness_hash"] == "w_single")
            .expect("w_single entry")
            .clone();

        let oldest = witness["oldest_age_secs"]
            .as_f64()
            .expect("oldest_age_secs f64");
        let newest = witness["newest_age_secs"]
            .as_f64()
            .expect("newest_age_secs f64");

        assert_eq!(
            oldest.to_bits(),
            newest.to_bits(),
            "single-entry witness MUST have oldest_age_secs ({oldest}) bit-equal to newest_age_secs ({newest}) — both derive from the same received_at"
        );
        // Bound the age so we don't depend on wall-clock drift in CI — the
        // entry was planted at now-42, so age should be ≈42s, with a
        // generous +/- 5s envelope for SystemTime jitter between the
        // `now` capture above and the dump call's own `now` capture.
        assert!(
            (oldest - 42.0).abs() < 5.0,
            "age MUST be ≈42s (planted at now-42), got {oldest}"
        );
    }
}
