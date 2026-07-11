//! ARCH-1 commit-on-finality drain.
//!
//! Bridges `AWCConsensus::finalization_queue` → `PendingLedger` → committed
//! `CF_LEDGER`. For every record id drained from the finality queue, the
//! matching delta is pulled from `PendingLedger`, the source record is
//! re-fetched from `CF_RECORDS`, and `apply_single_record` commits the
//! mutation. The delta is then erased from `CF_PENDING_DELTAS` so the
//! commit is crash-consistent (design doc: §3.3, §4.2).
//!
//! Phase 3.3b scope: the helper only. The drain loop is spawned in Phase
//! 3.3c. The peripheral-state fire-sites that today run inline at ingest
//! (xzone counters, velocity, mark_applied, zone_stakes refresh,
//! reincarnation mark_abandoned) are ported to this path in Phase 3.3d.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tracing::{debug, info, warn};

use crate::storage::rocks::CF_PENDING_DELTAS;
use crate::accounting::pending_delta::PendingLedgerDelta;

use super::state::NodeState;
use super::LockRecover;

/// Outcome of a single drain pass. All counts are per-invocation — the
/// long-lived counters live on `NodeState`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitStats {
    /// How many deltas were successfully applied to the committed ledger
    /// and erased from `CF_PENDING_DELTAS`.
    pub committed: u64,
    /// Record id appeared in the finality queue but `CF_RECORDS` had no
    /// entry. Should be impossible in steady state; counted so we notice
    /// if retention or a GC bug eats an in-flight record.
    pub missing_record: u64,
    /// Record id appeared in the finality queue but `PendingLedger` had
    /// no matching delta. Expected for non-ledger records (e.g. epoch
    /// seals) that finalize without ever entering the pending store.
    pub missing_delta: u64,
    /// `apply_single_record` returned an error. Delta is DROPPED (not
    /// re-queued) — the source record is already sealed by consensus,
    /// and re-trying a deterministically-failing op doesn't help.
    pub apply_failed: u64,
    /// §1030 (wall-#5 leg 4): finalized ledger records whose pending delta
    /// was TTL-swept before finalization, recovered by re-deriving the
    /// delta from the stored record.
    pub rederived: u64,
}

/// Drain every newly-finalized record id from the consensus queue and
/// commit its pending delta. Safe to call concurrently with ingest — the
/// per-CF writes race with ingest's `put_cf_raw(CF_PENDING_DELTAS, …)`
/// only in the sense that the drain might delete a key that ingest just
/// wrote, which is the intended ordering.
pub async fn drain_and_commit_pending(state: &Arc<NodeState>) -> CommitStats {
    let mut stats = CommitStats::default();

    let mut finalized_ids: Vec<String> = {
        let mut consensus = state.consensus.lock_recover();
        consensus.drain_newly_finalized()
    };
    // Crash-recovery reconcile: boot_replay_pending_deltas re-armed any
    // finalized-but-unapplied deltas here — the in-memory finalization_queue
    // was wiped by the crash, so without this they would never commit and this
    // node's ledger would silently fork. This list is UNCAPPED (unlike
    // finalization_queue, which drops on overflow) and self-clearing: appended
    // once, empty on every subsequent tick.
    {
        let mut boot = state.boot_reconcile_ids.lock_recover();
        if !boot.is_empty() {
            finalized_ids.append(&mut boot);
        }
    }
    if finalized_ids.is_empty() {
        return stats;
    }

    for rid in finalized_ids {
        // Defensive exactly-once (fusion-audit finding): apply_single_record has
        // no internal CF_APPLIED guard, so "commit once" rests on take() being
        // the sole consumer. A cheap bloom-backed is_applied() check makes the
        // loop idempotent if a rid arrives twice (boot reconcile + a live
        // finality signal for the same id). Drop any stale pending row too.
        if state.rocks.is_applied(&rid) {
            let _ = state.pending_ledger.write().await.take(&rid);
            let _ = state.rocks.delete_cf_raw(CF_PENDING_DELTAS, rid.as_bytes());
            continue;
        }

        // Take the delta first. take() is idempotent — a missing entry
        // means this rid finalized for a non-ledger record (e.g. an epoch
        // seal) that never inserted into pending_ledger. Not an error.
        let delta_opt = {
            let mut pending = state.pending_ledger.write().await;
            pending.take(&rid)
        };
        let delta = match delta_opt {
            Some(d) => d,
            None => {
                stats.missing_delta += 1;
                // Clean any stale CF_PENDING_DELTAS row regardless — belt and
                // braces for the rare case where the in-memory store was
                // reseeded from disk after the in-flight commit started.
                let _ = state
                    .rocks
                    .delete_cf_raw(CF_PENDING_DELTAS, rid.as_bytes());
                // §1030 (wall-#5 leg 4): a missing delta does NOT always mean
                // "non-ledger record". The discard sweep drops Pending-only
                // deltas after the soft TTL — but genesis-window records can
                // take far longer than that to finalize (rehearsal #4: the
                // pool seed's delta was swept at +10 min, the record
                // finalized at +40 min, the apply was silently lost and the
                // authority's ledger forked from both peers'). The RECORD is
                // the source of truth: re-derive the delta and fall through
                // to the normal commit below. `is_applied()` keeps this
                // exactly-once — the commit path marks it, so only
                // never-applied ledger records qualify.
                match rederive_swept_delta(state, &rid) {
                    Some(d) => {
                        info!(
                            "drain_and_commit_pending: re-derived TTL-swept delta for {} (wall-#5 leg 4 recovery)",
                            &rid[..rid.len().min(16)]
                        );
                        stats.rederived += 1;
                        d
                    }
                    None => continue, // genuinely non-ledger-op, or already applied
                }
            }
        };

        // Re-fetch the full record from CF_RECORDS. The delta stores
        // only enough to describe the mutation; the canonical apply path
        // needs the record itself (signatures, metadata, parents). This
        // costs one point lookup per commit — bounded by the drain
        // cadence, so O(drained_per_tick), not O(ledger_size).
        let record = match state.rocks.get_record(&rid) {
            Ok(Some(r)) => r,
            Ok(None) => {
                warn!(
                    "drain_and_commit_pending: CF_RECORDS missing {}",
                    &rid[..rid.len().min(16)]
                );
                stats.missing_record += 1;
                state
                    .pending_drain_missing_record_total
                    .fetch_add(1, Ordering::Relaxed);
                // Drop the pending delta AND erase the on-disk row —
                // the source record is gone; keeping the delta alive
                // would leak effective_available on re-boot.
                let _ = state
                    .rocks
                    .delete_cf_raw(CF_PENDING_DELTAS, rid.as_bytes());
                continue;
            }
            Err(e) => {
                warn!(
                    "drain_and_commit_pending: get_record({}) failed: {e}",
                    &rid[..rid.len().min(16)]
                );
                // Re-insert the delta so the next pass can retry. Ordering
                // is best-effort; a duplicate CF row is harmless because
                // the in-memory store is the source of truth.
                let mut pending = state.pending_ledger.write().await;
                let _ = pending.insert(delta);
                stats.apply_failed += 1;
                continue;
            }
        };

        // Apply + peripheral-state refresh under a single write lock so
        // the consensus zone-stakes refresh sees the fresh ledger.
        let apply_outcome: std::result::Result<(), crate::errors::ElaraError> = {
            let mut ledger = state.ledger.write().await;
            match ledger.apply_single_record(&record, &state.config.genesis_authority) {
                Ok(_) => {
                    fire_peripheral_updates_at_commit(state, &record, &delta, &ledger);
                    Ok(())
                }
                Err(e) => Err(e),
            }
        };

        match apply_outcome {
            Ok(()) => {
                state.rocks.mark_applied(&rid);
                if let Err(e) = state
                    .rocks
                    .delete_cf_raw(CF_PENDING_DELTAS, rid.as_bytes())
                {
                    warn!(
                        "drain_and_commit_pending: delete_cf_raw({}) failed: {e}",
                        &rid[..rid.len().min(16)]
                    );
                }
                state
                    .pending_ledger_commits_total
                    .fetch_add(1, Ordering::Relaxed);
                stats.committed += 1;
                debug!(
                    "ARCH-1 committed delta for {}",
                    &rid[..rid.len().min(16)]
                );
            }
            Err(e) => {
                // apply_single_record failed on a finalized record. The
                // delta is gone from pending_ledger (take() above); we
                // drop it and also erase the on-disk row so the next
                // boot doesn't resurrect it. apply errors here mean the
                // op was deterministically invalid against current
                // ledger state — resurrecting helps no one.
                warn!(
                    "ARCH-1 apply_single_record failed at commit for {}: {e}",
                    &rid[..rid.len().min(16)]
                );
                let _ = state
                    .rocks
                    .delete_cf_raw(CF_PENDING_DELTAS, rid.as_bytes());
                stats.apply_failed += 1;
                state
                    .pending_drain_apply_failed_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    stats
}

/// ARCH-1 stale-pending discard sweep — drop deltas whose source record
/// never reached `Finalized` within the timeout window. Without this,
/// a Transfer whose witnesses never responded would keep `alice`'s
/// locked_by_identity bloated forever, bleeding
/// `effective_available` down until the per-identity quota trips.
///
/// See internal design notes §4.3 for the discard rationale.
pub const PENDING_DISCARD_TIMEOUT_SECS: f64 = 600.0;

/// Hard ceiling for stuck-Sealed entries. Sweep ignores consensus state past
/// this age — Sealed/Anchored entries that never reach Finalized leak the
/// pending bucket forever otherwise (observed in production: oldest
/// entry 36508s old, saturating a single identity's 256-cap and forcing
/// direct-apply on every new record from that identity).
///
/// Sized at 10× `MAX_ADAPTIVE_EPOCH_SECS` (1200s = 10× 120s). The
/// cap-drop brought the upper finality
/// bound to 120s; this hard timeout was previously 3600s (30× finality)
/// which let stuck records linger an entire hour before reaping. 1200s is
/// still 2× the soft cutoff (600s) so the spare-Sealed guard preserves
/// legitimately slow finalizers, and well above any observed
/// finality race in production. Reaping faster reduces per-identity bucket
/// saturation (the observed 256-cap leak) by 3×.
pub const PENDING_HARD_DISCARD_TIMEOUT_SECS: f64 = 1200.0;

// Compile-time non-zero + strict-ordering invariants for the two sweep
// timeouts. Promoted from runtime asserts in
// `batch_ab_pending_discard_timeouts_pin_documented_invariant_hard_is_strict_2x_soft`
// (clippy::assertions_on_constants — both operands are `pub const f64`, so
// each `>` reduced to `true` at const-eval and the runtime assert was
// tautological at every test invocation). A zero or NaN constant landing
// here would make the sweep cutoff math degenerate (`now - 0.0 > t` → every
// record reaped; `now - NaN > t` → every comparison false → sweep silently
// disabled). A future edit that swaps HARD < SOFT would single-stage-
// collapse the §4.3/§4.4 spare-Sealed guard at pending_drain.rs:L266 / L263.
// Continues the §404-§407 closure pattern (`ab6f489c` pow_nonce eq_op,
// `3b5cfe22` profile-capacity, `866d1a5b` bratio cohort, `8614aa71`
// MAX_SNAPSHOT caps).
const _: () = assert!(PENDING_DISCARD_TIMEOUT_SECS > 0.0);
const _: () = assert!(PENDING_HARD_DISCARD_TIMEOUT_SECS > 0.0);
const _: () = assert!(PENDING_HARD_DISCARD_TIMEOUT_SECS > PENDING_DISCARD_TIMEOUT_SECS);

/// Outcome of a sweep pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepStats {
    /// Soft-cutoff drops: `Pending`-state deltas past
    /// `PENDING_DISCARD_TIMEOUT_SECS`.
    pub discarded: u64,
    /// Hard-cutoff drops: any-state deltas past
    /// `PENDING_HARD_DISCARD_TIMEOUT_SECS`. Non-zero in steady state
    /// signals consensus is genuinely stuck on those records — finality
    /// signers aren't accumulating fast enough.
    pub hard_discarded: u64,
}

/// §1030 (wall-#5 leg 4): reconstruct the pending delta for a finalized rid
/// whose delta was TTL-swept before finalization could commit it. Returns
/// None when there is nothing to recover: non-ledger records (the normal
/// missing-delta case), already-applied records (`is_applied` exactly-once
/// guard — the commit path sets it), or storage misses. One point lookup +
/// one parse per missing-delta rid — same bound as the commit path itself.
fn rederive_swept_delta(
    state: &Arc<NodeState>,
    rid: &str,
) -> Option<crate::accounting::pending_delta::PendingLedgerDelta> {
    use crate::accounting::pending_delta::{PendingLedgerDelta, PendingOp};
    if state.rocks.is_applied(rid) {
        return None;
    }
    let record = state.rocks.get_record(rid).ok()??;
    let parsed = crate::accounting::types::extract_ledger_op(&record).ok()??;
    let creator_hash = crate::accounting::types::creator_identity_hash(&record);
    let op = PendingOp::from_parsed(parsed, &creator_hash, &record.id);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(record.timestamp);
    Some(PendingLedgerDelta::new(
        record.id.clone(),
        creator_hash,
        record.timestamp,
        now,
        op,
    ))
}

/// Scan `PendingLedger` for deltas older than
/// `PENDING_DISCARD_TIMEOUT_SECS` and drop them. O(total_pending) in
/// the worst case but bounded by `MAX_TOTAL_PENDING`; in steady state
/// most ticks are O(0). Caller drives the tick cadence.
///
/// Two cutoffs:
///   - **Soft** (`PENDING_DISCARD_TIMEOUT_SECS`, 600s): drop only entries
///     whose record is still `Pending`. Records that reached
///     `Sealed`/`Finalized`/`Anchored` are spared — they are actively
///     progressing through consensus and the drain loop will commit them.
///     Without this guard, a slow-finalizing record (e.g. >600 s on a
///     low-rate testnet) gets its delta discarded just before
///     `drain_newly_finalized` fires, and the apply path then sees
///     `missing_delta` and silently skips. That regressed Slice 4: a
///     12-min finalization on `zone:hil` caused the witness_register
///     apply to never run.
///   - **Hard** (`PENDING_HARD_DISCARD_TIMEOUT_SECS`, 1200s): drop
///     regardless of consensus state. Sealed entries that never reach
///     Finalized otherwise leak the bucket forever (observed: 10-hour-old
///     entries saturating one identity's 256-cap, forcing every new
///     record from that creator into the direct-apply fallback and out
///     of the conservation-invariant safety net). 1200s = 10×
///     `MAX_ADAPTIVE_EPOCH_SECS` and 2× the soft cutoff, so legitimately
///     slow records still complete; only genuinely stuck entries are reaped.
pub async fn sweep_stale_pending(state: &Arc<NodeState>) -> SweepStats {
    use crate::network::consensus::ConfirmationLevel;

    let mut stats = SweepStats::default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let soft_cutoff = now - PENDING_DISCARD_TIMEOUT_SECS;
    let hard_cutoff = now - PENDING_HARD_DISCARD_TIMEOUT_SECS;

    // Collect candidate rids under a read-lock so we hold the write lock
    // only for the actual take() calls. Keeps ingest responsive during
    // sweeps. Each candidate carries its own age + creator identity so we
    // can split soft-vs-hard and group by offender without re-reading the
    // store. Carrying creator inline means a hot-creator finality bottleneck
    // (distinct=1 + max << cap + oldest > timeout) surfaces in the sweep
    // log directly, instead of forcing operators to grep for it.
    let candidates: Vec<(String, f64, String)> = {
        let pending = state.pending_ledger.read().await;
        pending
            .iter()
            .filter(|d| d.applied_at < soft_cutoff)
            .map(|d| (d.record_id.clone(), d.applied_at, d.creator.clone()))
            .collect()
    };
    if candidates.is_empty() {
        return stats;
    }

    // Partition into (rid, hit_hard_ceiling, creator) tuples. Hit-hard
    // takes precedence — we discard regardless of state. Soft-only entries
    // go through the spare-Sealed guard. Single consensus lock acquisition
    // so ingest doesn't see lock churn during a large sweep.
    let to_drop: Vec<(String, bool, String)> = {
        let consensus = state.consensus.lock_recover();
        candidates
            .into_iter()
            .filter_map(|(rid, applied_at, creator)| {
                let hit_hard = applied_at < hard_cutoff;
                if hit_hard {
                    Some((rid, true, creator))
                } else if matches!(
                    consensus.confirmation_level(&rid),
                    ConfirmationLevel::Pending
                ) {
                    Some((rid, false, creator))
                } else {
                    None
                }
            })
            .collect()
    };
    if to_drop.is_empty() {
        return stats;
    }

    // Group hard discards by creator to surface the top offender in the
    // sweep log. Single creator with N hard-discarded entries = finality
    // bottleneck on that account; broad spread = global finality stall.
    let mut hard_by_creator: HashMap<String, u64> = HashMap::new();
    {
        let mut pending = state.pending_ledger.write().await;
        for (rid, hit_hard, creator) in &to_drop {
            if pending.take(rid).is_some() {
                if *hit_hard {
                    stats.hard_discarded += 1;
                    *hard_by_creator.entry(creator.clone()).or_insert(0) += 1;
                } else {
                    stats.discarded += 1;
                }
            }
        }
    }
    for (rid, _, _) in &to_drop {
        if let Err(e) = state
            .rocks
            .delete_cf_raw(CF_PENDING_DELTAS, rid.as_bytes())
        {
            warn!(
                "sweep_stale_pending: delete_cf_raw({}) failed: {e}",
                &rid[..rid.len().min(16)]
            );
        }
    }
    let total = stats.discarded + stats.hard_discarded;
    state
        .pending_ledger_discards_total
        .fetch_add(total, Ordering::Relaxed);
    state
        .pending_ledger_hard_discards_total
        .fetch_add(stats.hard_discarded, Ordering::Relaxed);
    let top_offender = hard_by_creator
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(creator, count)| {
            format!(
                " (top offender: identity={} hard_count={count}/{total_hard})",
                &creator[..creator.len().min(16)],
                total_hard = stats.hard_discarded
            )
        })
        .unwrap_or_default();
    info!(
        "ARCH-1 discard sweep: dropped {} soft (> {}s, Pending-only) + {} hard (> {}s, any state) stale pending deltas{}",
        stats.discarded,
        PENDING_DISCARD_TIMEOUT_SECS as u64,
        stats.hard_discarded,
        PENDING_HARD_DISCARD_TIMEOUT_SECS as u64,
        top_offender
    );
    stats
}

/// Gap 2.1 Phase 2b.3 Slice 4 fix: drain `LedgerState::pending_witness_registrations`
/// to `CF_WITNESS_REGISTRY` on every node.
///
/// `apply_op(WitnessRegister)` queues a (zone, identity, pk, bond, epoch)
/// tuple under the ledger write lock. The tuple has to land in RocksDB
/// before `iter_witnesses_for_zone` can see it (the GET handler at
/// `/admin/witness/registry` and the finality-committee union both read
/// the CF directly). Originally the per-tick flush lived inside
/// `epoch_seal_loop`, but that loop returns early on non-anchor nodes —
/// so on a 5×witness + 1×anchor fleet, only the anchor flushed and every
/// other node's registry stayed empty even though `apply_op` ran on all
/// of them. Moving the flush here makes it part of the always-on
/// pending-drain tick, which runs on every node regardless of role.
///
/// Lock discipline: take the ledger write lock just long enough to
/// `mem::take` the queue, then release it before the (blocking) RocksDB
/// write. Empty queue is the no-op fast path. Errors are logged but do
/// not stall the drain — the queue is already drained from the ledger,
/// so a flush failure means the next apply that ALSO writes to that CF
/// will overwrite/extend; no row is lost permanently because
/// `apply_op(WitnessRegister)` is keyed by `(zone, identity)` and is
/// re-entrant.
pub async fn flush_pending_witness_registrations(state: &Arc<NodeState>) {
    let pending: Vec<(String, String, Vec<u8>, u64, u64)> = {
        let mut ledger = state.ledger.write().await;
        std::mem::take(&mut ledger.pending_witness_registrations)
    };
    if pending.is_empty() {
        return;
    }
    let count = pending.len();
    let rocks = state.rocks.clone();
    let res = tokio::task::spawn_blocking(move || {
        rocks.flush_pending_witness_registrations(&pending)
    })
    .await;
    match res {
        Ok(Ok(written)) => debug!(
            "witness_registry: per-tick flushed {written}/{count} pending entries"
        ),
        Ok(Err(e)) => warn!("witness_registry per-tick flush failed: {e}"),
        Err(e) => warn!("witness_registry per-tick spawn_blocking failed: {e}"),
    }
}

/// ARCH-1 boot replay — rehydrate `PendingLedger` from `CF_PENDING_DELTAS`.
///
/// Must be called BEFORE the drain loop starts so the first tick sees a
/// complete in-memory store. Rows that fail to deserialize are logged
/// and erased so a corrupted entry does not block boot; insert
/// rejections (duplicate / quota) surface through `PendingLedger::boot_replay`
/// as a hard error because they indicate store corruption.
///
/// Cheap: the CF is bounded at `MAX_TOTAL_PENDING` = 1,048,576 entries
/// at ~128 bytes each — <~128 MB worst case, typically sub-megabyte in
/// steady state.
pub async fn boot_replay_pending_deltas(
    state: &Arc<NodeState>,
) -> crate::errors::Result<usize> {
    use crate::accounting::pending_ledger::MAX_TOTAL_PENDING;

    let rows = state
        .rocks
        .list_cf_raw(CF_PENDING_DELTAS, MAX_TOTAL_PENDING.saturating_add(1))?;
    if rows.is_empty() {
        debug!("ARCH-1 boot replay: CF_PENDING_DELTAS empty");
        return Ok(0);
    }

    let mut good = Vec::with_capacity(rows.len());
    let mut corrupt = 0usize;
    let mut already_applied = 0usize;
    // Crash-recovery reconcile (fusion-audited): record ids whose delta is
    // durably FINALIZED but not yet applied. The node crashed inside the
    // finality→drain window; the RAM-only finalization_queue was wiped, the
    // suppressed startup-replay enqueue never re-fires, and the 1200s sweep
    // would reap the orphan → silent ledger fork. Re-arm them through the
    // normal drain via the uncapped one-shot `boot_reconcile_ids`.
    let mut reconcile: Vec<String> = Vec::new();
    for (k, v) in rows {
        match PendingLedgerDelta::from_json(&v) {
            Ok(d) => {
                // If the record is already in CF_APPLIED, the committed
                // ledger has this delta. The CF_PENDING_DELTAS row is
                // stale (commit-time delete did not land, or pre-restart
                // cap-pinch direct-applied while the row remained). Re-
                // inserting would force a stuck pending_ledger entry that
                // never drains because consensus' newly-finalized event
                // already fired pre-restart. Sweep would clear it after
                // PENDING_DISCARD_TIMEOUT_SECS, but until then it would
                // pin elara_pending_ledger_max_identity_depth at cap and
                // generate false alerts. Drop it now.
                if state.rocks.is_applied(&d.record_id) {
                    let _ = state.rocks.delete_cf_raw(CF_PENDING_DELTAS, &k);
                    already_applied += 1;
                } else {
                    // Keyed off the durable FinalizedIndex (the on-disk
                    // `finalized:` authority, restored BEFORE this replay) so it
                    // is robust whether or not startup replay restored
                    // confirmation_levels. Only finalized rows are re-armed;
                    // still-Pending deltas rehydrate normally and finalize later.
                    if state.finalized.read().await.contains(&d.record_id) {
                        reconcile.push(d.record_id.clone());
                    }
                    good.push(d);
                }
            }
            Err(e) => {
                warn!(
                    "ARCH-1 boot replay: corrupt CF_PENDING_DELTAS row (key {} bytes): {e} — erasing",
                    k.len()
                );
                let _ = state.rocks.delete_cf_raw(CF_PENDING_DELTAS, &k);
                corrupt += 1;
            }
        }
    }

    let total = good.len();
    // Genesis/first-boot seeds the supply delta into the in-memory ledger
    // BEFORE this replay runs, so the persisted CF_PENDING_DELTAS copy is a
    // duplicate of a LIVE in-memory entry — not store corruption. Filter those
    // out: re-inserting trips PendingLedger::insert's duplicate canary (a hard
    // error meant to catch genuine CF corruption, not the genesis pre-seed),
    // which used to surface as a scary "ARCH-1 pending-ledger replay failed:
    // ... already exists" WARN on every fresh node's first boot. CF-internal
    // duplicates (two rows, same record_id, neither yet in memory) still trip
    // the canary inside boot_replay below.
    let (count, already_in_memory) = {
        let mut pending = state.pending_ledger.write().await;
        let fresh: Vec<PendingLedgerDelta> = good
            .into_iter()
            .filter(|d| !pending.contains(&d.record_id))
            .collect();
        let fresh_n = fresh.len();
        pending.boot_replay(fresh)?;
        (fresh_n, total - fresh_n)
    };
    if count > 0 || corrupt > 0 || already_applied > 0 || already_in_memory > 0 {
        info!(
            "ARCH-1 boot replay: rehydrated {count} pending deltas ({corrupt} corrupt rows erased, {already_applied} stale rows for already-applied records erased, {already_in_memory} already live in-memory from genesis pre-seed)"
        );
    }
    let reconciled = reconcile.len();
    if reconciled > 0 {
        state.boot_reconcile_ids.lock_recover().append(&mut reconcile);
        state
            .pending_boot_reconciled_total
            .fetch_add(reconciled as u64, Ordering::Relaxed);
        warn!(
            "ARCH-1 boot reconcile: {reconciled} finalized-but-unapplied delta(s) re-armed for \
             commit — node crashed inside the finality→drain window (recovered, not lost)"
        );
    }
    Ok(count)
}

/// Peripheral state updates that the direct-apply ingest branch runs
/// inline at ingest (ingest.rs ~L1509-L1582). Under the ARCH-1 tentative
/// flag these must fire at COMMIT time — after apply_single_record
/// succeeds and the ledger is the authoritative post-op state.
///
/// Called with the ledger write guard still held so the consensus
/// zone-stakes refresh sees fresh stake totals. The function is
/// intentionally self-contained — callers pass ledger by &ref so no
/// internal write-lock reacquires or drops.
fn fire_peripheral_updates_at_commit(
    state: &Arc<NodeState>,
    record: &crate::record::ValidationRecord,
    delta: &PendingLedgerDelta,
    ledger: &crate::accounting::ledger::LedgerState,
) {
    use crate::accounting::pending_delta::PendingOp;
    use std::sync::atomic::Ordering::Relaxed;

    // Gap 2 cross-zone counters. Metadata-driven because the XZONE_OP
    // marker carries "lock" or "claim" regardless of whether the op is
    // XZoneLock or XZoneClaim.
    if let Some(op) = record
        .metadata
        .get(crate::accounting::cross_zone::XZONE_OP_KEY)
        .and_then(|v| v.as_str())
    {
        match op {
            "lock" => {
                state.xzone_locks_total.fetch_add(1, Relaxed);
            }
            "claim" => {
                state.xzone_claims_total.fetch_add(1, Relaxed);
            }
            _ => {}
        }
    }

    // Transfer velocity: transfer count + volume. Pulled from the delta
    // (not the record metadata) because the delta is the
    // already-validated, pre-parsed form.
    if let PendingOp::Transfer { amount, .. } = &delta.op {
        state.beat_transfers_total.fetch_add(1, Relaxed);
        state.beat_volume_micros_total.fetch_add(*amount, Relaxed);
    }

    // Gap 2 sealed-abort + pre-seal refunds: count XZoneAbort/Cancel/Reject
    // applies. Keyed on the parsed PendingOp variant (not metadata) because
    // these ops write `beat_op=xzone_{abort,cancel,reject}`, not `xzone_op=…`,
    // and we want the counter tied to the validated apply-path commit, not
    // gossip-side metadata.
    match &delta.op {
        PendingOp::XZoneAbort { .. } => {
            state.xzone_aborts_total.fetch_add(1, Relaxed);
        }
        PendingOp::XZoneCancel { .. } => {
            state.xzone_cancels_total.fetch_add(1, Relaxed);
        }
        PendingOp::XZoneReject { .. } => {
            state.xzone_rejects_total.fetch_add(1, Relaxed);
        }
        _ => {}
    }

    // Consensus zone-stakes refresh for stake-affecting ops. Keyed on
    // the pending-op variant rather than the beat_op metadata string so
    // we can't drift from the validated op.
    let is_stake_affecting = matches!(
        delta.op,
        PendingOp::Stake { .. } | PendingOp::Unstake { .. } | PendingOp::Slash { .. }
    );
    if is_stake_affecting {
        let mut consensus = state.consensus.lock_recover();
        consensus.register_stakes_from_ledger(ledger);
    }

    // Protocol §6.4: mark a slashed identity's fingerprint as abandoned
    // so a later suspected reincarnation can be flagged. mark_abandoned
    // uses try_lock — if the reincarnation mutex is contended we
    // silently skip, matching the direct-apply branch's behavior.
    if let PendingOp::Slash { offender, .. } = &delta.op {
        if let Ok(mut reinc) = state.reincarnation.try_lock() {
            reinc.mark_abandoned(offender);
            info!(
                "reincarnation: marked {} as abandoned (slashed via commit)",
                &offender[..offender.len().min(16)]
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::{sha3_256, sha3_256_hex};
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::state::NodeState;
    use crate::network::witness::WitnessManager;
    use crate::record::{Classification, ValidationRecord};
    use crate::storage::rocks::{StorageEngine, CF_PENDING_DELTAS};
    use crate::accounting::pending_delta::{PendingLedgerDelta, PendingOp};
    use crate::accounting::types::{
        self, creator_identity_hash, extract_ledger_op, BASE_UNITS_PER_BEAT,
    };
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn pk(byte: u8) -> Vec<u8> {
        vec![byte; 1952]
    }

    fn identity_hash_of(pk: &[u8]) -> String {
        sha3_256_hex(pk)
    }

    fn mk_record(
        id: &str,
        creator_pk: &[u8],
        ts: f64,
        meta: BTreeMap<String, serde_json::Value>,
    ) -> ValidationRecord {
        ValidationRecord {
            id: id.into(),
            version: crate::wire::WIRE_VERSION,
            content_hash: sha3_256(id.as_bytes()).to_vec(),
            creator_public_key: creator_pk.to_vec(),
            timestamp: ts,
            parents: vec![],
            classification: Classification::Public,
            metadata: meta,
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        }
    }

    /// Build a NodeState with ARCH-1 tentative mode enabled and a
    /// genesis_authority matching `genesis_pk`.
    fn state_with_genesis(genesis_pk: &[u8]) -> (Arc<NodeState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "arch1-drain-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            genesis_authority: identity_hash_of(genesis_pk),
            ..Default::default()
        };

        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
        (state, tmp)
    }

    /// End-to-end: a Transfer delta sits unapplied in pending_ledger
    /// until consensus marks the record Finalized; the drain then
    /// commits it.
    #[tokio::test]
    async fn test_arch_1_drain_commits_only_on_finality() {
        let genesis = pk(0x01);
        let alice = pk(0x02);
        let bob = pk(0x03);
        let _genesis_hash = identity_hash_of(&genesis);
        let alice_hash = identity_hash_of(&alice);
        let bob_hash = identity_hash_of(&bob);

        let (state, _tmp) = state_with_genesis(&genesis);

        // 1) Seed Alice with 1_000 beat by applying a mint directly to the
        //    committed ledger. This bypasses ingest — the test targets the
        //    drain helper, not the full pipeline.
        let mint_meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let mint_rec = mk_record("mint-1", &genesis, 1.0, mint_meta);
        {
            let mut ledger = state.ledger.write().await;
            ledger
                .apply_single_record(&mint_rec, &state.config.genesis_authority)
                .expect("seed mint");
        }

        // 2) Build the Transfer record, persist it to CF_RECORDS, and
        //    insert a tentative delta into pending_ledger + CF_PENDING_DELTAS —
        //    exactly as the ingest reroute does under the flag.
        let xfer_meta = types::transfer_metadata(300 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let xfer_rec = mk_record("xfer-1", &alice, 2.0, xfer_meta);
        state
            .rocks
            .put_record(&xfer_rec.id, &xfer_rec)
            .expect("put_record");

        let parsed = extract_ledger_op(&xfer_rec).expect("parse").expect("ledger op");
        let delta = PendingLedgerDelta::new(
            xfer_rec.id.clone(),
            alice_hash.clone(),
            xfer_rec.timestamp,
            2.5,
            PendingOp::from_parsed(parsed, &alice_hash, &xfer_rec.id),
        );
        {
            let mut pending = state.pending_ledger.write().await;
            pending.insert(delta.clone()).expect("insert");
        }
        state
            .rocks
            .put_cf_raw(
                CF_PENDING_DELTAS,
                xfer_rec.id.as_bytes(),
                &delta.to_json().unwrap(),
            )
            .expect("put delta");

        // 3) Ledger MUST still show mint-only balances — the transfer is
        //    tentative, not committed.
        {
            let ledger = state.ledger.read().await;
            assert_eq!(ledger.balance(&alice_hash), 1_000 * BASE_UNITS_PER_BEAT);
            assert_eq!(ledger.balance(&bob_hash), 0);
        }

        // Draining with no finality events in the queue is a no-op.
        let pre = drain_and_commit_pending(&state).await;
        assert_eq!(pre.committed, 0);
        assert_eq!(pre.missing_delta, 0);
        assert_eq!(pre.missing_record, 0);
        assert_eq!(pre.apply_failed, 0);
        assert_eq!(
            state
                .pending_ledger_commits_total
                .load(Ordering::Relaxed),
            0
        );

        // 4) Promote the transfer to Finalized. force_finalized enqueues
        //    the rid on the consensus finality queue (ARCH-1 Phase 3.2).
        {
            let mut consensus = state.consensus.lock_recover();
            consensus.force_finalized(&xfer_rec.id);
        }

        // 5) Drain → the helper pulls the rid off the queue, fetches the
        //    record from CF_RECORDS, applies it, marks applied, erases
        //    the CF_PENDING_DELTAS row.
        let stats = drain_and_commit_pending(&state).await;
        assert_eq!(stats.committed, 1);
        assert_eq!(stats.missing_delta, 0);
        assert_eq!(stats.missing_record, 0);
        assert_eq!(stats.apply_failed, 0);

        // 6) Post-commit: Alice debited, Bob credited, pending store
        //    empty, on-disk delta erased, counter bumped, applied index
        //    set.
        {
            let ledger = state.ledger.read().await;
            assert_eq!(
                ledger.balance(&alice_hash),
                700 * BASE_UNITS_PER_BEAT,
                "alice debited after commit"
            );
            assert_eq!(
                ledger.balance(&bob_hash),
                300 * BASE_UNITS_PER_BEAT,
                "bob credited after commit"
            );
        }
        {
            let pending = state.pending_ledger.read().await;
            assert!(pending.is_empty(), "pending drained");
        }
        assert!(
            state
                .rocks
                .get_cf_raw(CF_PENDING_DELTAS, xfer_rec.id.as_bytes())
                .unwrap()
                .is_none(),
            "CF_PENDING_DELTAS row erased"
        );
        assert!(state.rocks.is_applied(&xfer_rec.id), "CF_APPLIED set");
        assert_eq!(
            state
                .pending_ledger_commits_total
                .load(Ordering::Relaxed),
            1
        );

        // 7) Double-draining is a no-op and does not count a re-commit —
        //    a finalized record is already processed.
        let again = drain_and_commit_pending(&state).await;
        assert_eq!(again.committed, 0);
        assert_eq!(again.missing_delta, 0);
        let _ = creator_identity_hash; // silence unused import warning
    }

    /// Phase 3.3d: a committed Transfer delta must bump the velocity
    /// counters at commit-time so the tentative path produces the same
    /// metrics as the direct-apply path.
    #[tokio::test]
    async fn test_arch_1_transfer_commit_bumps_velocity_counters() {
        let genesis = pk(0x01);
        let alice = pk(0x02);
        let bob = pk(0x03);
        let alice_hash = identity_hash_of(&alice);
        let bob_hash = identity_hash_of(&bob);

        let (state, _tmp) = state_with_genesis(&genesis);

        // Seed alice
        let mint_rec = mk_record(
            "mint-v",
            &genesis,
            1.0,
            types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis"),
        );
        {
            let mut ledger = state.ledger.write().await;
            ledger
                .apply_single_record(&mint_rec, &state.config.genesis_authority)
                .expect("seed mint");
        }

        // Two transfers: 250 + 175
        for (id, amount) in [("xfer-a", 250u64), ("xfer-b", 175u64)] {
            let rec = mk_record(
                id,
                &alice,
                2.0,
                types::transfer_metadata(amount * BASE_UNITS_PER_BEAT, &bob_hash, None),
            );
            state.rocks.put_record(&rec.id, &rec).unwrap();
            let parsed = extract_ledger_op(&rec).unwrap().unwrap();
            let delta = PendingLedgerDelta::new(
                rec.id.clone(),
                alice_hash.clone(),
                rec.timestamp,
                2.5,
                PendingOp::from_parsed(parsed, &alice_hash, &rec.id),
            );
            {
                let mut pending = state.pending_ledger.write().await;
                pending.insert(delta.clone()).unwrap();
            }
            state
                .rocks
                .put_cf_raw(CF_PENDING_DELTAS, rec.id.as_bytes(), &delta.to_json().unwrap())
                .unwrap();
            {
                let mut consensus = state.consensus.lock_recover();
                consensus.force_finalized(&rec.id);
            }
        }

        let stats = drain_and_commit_pending(&state).await;
        assert_eq!(stats.committed, 2);

        assert_eq!(
            state.beat_transfers_total.load(Ordering::Relaxed),
            2,
            "transfer counter bumped at commit"
        );
        assert_eq!(
            state.beat_volume_micros_total.load(Ordering::Relaxed),
            (250 + 175) * BASE_UNITS_PER_BEAT,
            "volume counter summed at commit"
        );
    }

    /// Gap 2 observability: pre-seal `XZoneCancel` and `XZoneReject` ops bump
    /// their dedicated counters when their pending deltas commit. Mirrors the
    /// shape of `test_arch_1_transfer_commit_bumps_velocity_counters` and
    /// keeps `xzone_aborts_total` zero (sealed-abort path is distinct).
    #[tokio::test]
    async fn test_xzone_cancel_reject_counters_bump_at_commit() {
        let genesis = pk(0x01);
        let alice = pk(0x02);
        let bob = pk(0x03);
        let alice_hash = identity_hash_of(&alice);
        let bob_hash = identity_hash_of(&bob);

        let (state, _tmp) = state_with_genesis(&genesis);

        // Seed alice with enough beat to fund two cross-zone locks.
        let mint_rec = mk_record(
            "mint-x",
            &genesis,
            1.0,
            types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis"),
        );
        {
            let mut ledger = state.ledger.write().await;
            ledger
                .apply_single_record(&mint_rec, &state.config.genesis_authority)
                .expect("seed mint");
        }

        // Two unsealed XZoneLocks (zone A → zone B). Direct apply leaves
        // each transfer in `Locked` status with empty `merkle_proof` — the
        // exact pre-seal state cancel/reject require.
        for (id, amount) in [("lock-cancel", 100u64), ("lock-reject", 150u64)] {
            let lock_rec = mk_record(
                id,
                &alice,
                2.0,
                types::xzone_lock_metadata(amount * BASE_UNITS_PER_BEAT, &bob_hash, "A", "B"),
            );
            let mut ledger = state.ledger.write().await;
            ledger
                .apply_single_record(&lock_rec, &state.config.genesis_authority)
                .expect("apply xzone lock");
        }

        // XZoneCancel from alice (sender) targeting lock-cancel.
        let cancel_rec = mk_record(
            "cancel-1",
            &alice,
            3.0,
            types::xzone_cancel_metadata("lock-cancel"),
        );
        state.rocks.put_record(&cancel_rec.id, &cancel_rec).unwrap();
        let cancel_parsed = extract_ledger_op(&cancel_rec).unwrap().unwrap();
        let cancel_delta = PendingLedgerDelta::new(
            cancel_rec.id.clone(),
            alice_hash.clone(),
            cancel_rec.timestamp,
            3.5,
            PendingOp::from_parsed(cancel_parsed, &alice_hash, &cancel_rec.id),
        );
        {
            let mut pending = state.pending_ledger.write().await;
            pending.insert(cancel_delta.clone()).unwrap();
        }
        state
            .rocks
            .put_cf_raw(
                CF_PENDING_DELTAS,
                cancel_rec.id.as_bytes(),
                &cancel_delta.to_json().unwrap(),
            )
            .unwrap();

        // XZoneReject from bob (recipient) targeting lock-reject.
        let reject_rec = mk_record(
            "reject-1",
            &bob,
            4.0,
            types::xzone_reject_metadata("lock-reject"),
        );
        state.rocks.put_record(&reject_rec.id, &reject_rec).unwrap();
        let reject_parsed = extract_ledger_op(&reject_rec).unwrap().unwrap();
        let reject_delta = PendingLedgerDelta::new(
            reject_rec.id.clone(),
            bob_hash.clone(),
            reject_rec.timestamp,
            4.5,
            PendingOp::from_parsed(reject_parsed, &bob_hash, &reject_rec.id),
        );
        {
            let mut pending = state.pending_ledger.write().await;
            pending.insert(reject_delta.clone()).unwrap();
        }
        state
            .rocks
            .put_cf_raw(
                CF_PENDING_DELTAS,
                reject_rec.id.as_bytes(),
                &reject_delta.to_json().unwrap(),
            )
            .unwrap();

        {
            let mut consensus = state.consensus.lock_recover();
            consensus.force_finalized(&cancel_rec.id);
            consensus.force_finalized(&reject_rec.id);
        }

        let stats = drain_and_commit_pending(&state).await;
        assert_eq!(stats.committed, 2, "both refund deltas committed");
        assert_eq!(stats.apply_failed, 0, "no apply failures");

        assert_eq!(
            state.xzone_cancels_total.load(Ordering::Relaxed),
            1,
            "xzone_cancels_total bumps once on XZoneCancel commit",
        );
        assert_eq!(
            state.xzone_rejects_total.load(Ordering::Relaxed),
            1,
            "xzone_rejects_total bumps once on XZoneReject commit",
        );
        assert_eq!(
            state.xzone_aborts_total.load(Ordering::Relaxed),
            0,
            "xzone_aborts_total stays zero — no sealed-abort committed",
        );
    }

    /// ARCH-1 drain canary observability: `apply_failed` and
    /// `missing_record` lifetime counters bump on the matching failure
    /// paths. Each is a separate operator-alert signal:
    ///   - `apply_failed_total` — consensus said yes, ledger said no.
    ///   - `missing_record_total` — finalized id but no CF_RECORDS body.
    /// Per-batch `CommitStats` already track these; this test pins down
    /// that the lifetime counters on `NodeState` follow.
    #[tokio::test]
    async fn test_drain_canary_counters_bump_on_failure() {
        let genesis = pk(0x01);
        let alice = pk(0x02);
        let bob = pk(0x03);
        let alice_hash = identity_hash_of(&alice);
        let bob_hash = identity_hash_of(&bob);

        let (state, _tmp) = state_with_genesis(&genesis);

        // ─── apply_failed path ────────────────────────────────────────
        // Build a Transfer delta from alice → bob for 100 beat without
        // ever minting alice's funds. Pending_ledger insert is unchecked,
        // so the delta sits in the store; on finality the apply path
        // rejects "insufficient balance" and the canary counter bumps.
        let bad_xfer = mk_record(
            "xfer-broke",
            &alice,
            2.0,
            types::transfer_metadata(100 * BASE_UNITS_PER_BEAT, &bob_hash, None),
        );
        state.rocks.put_record(&bad_xfer.id, &bad_xfer).unwrap();
        let bad_parsed = extract_ledger_op(&bad_xfer).unwrap().unwrap();
        let bad_delta = PendingLedgerDelta::new(
            bad_xfer.id.clone(),
            alice_hash.clone(),
            bad_xfer.timestamp,
            2.5,
            PendingOp::from_parsed(bad_parsed, &alice_hash, &bad_xfer.id),
        );
        {
            let mut pending = state.pending_ledger.write().await;
            pending.insert(bad_delta.clone()).unwrap();
        }
        state
            .rocks
            .put_cf_raw(
                CF_PENDING_DELTAS,
                bad_xfer.id.as_bytes(),
                &bad_delta.to_json().unwrap(),
            )
            .unwrap();

        // ─── missing_record path ─────────────────────────────────────
        // Insert a delta whose record body is NEVER written to
        // CF_RECORDS. On finality the drain finds the id, lookups None,
        // and bumps the missing_record canary.
        let ghost_meta = types::transfer_metadata(50 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let ghost_rec = mk_record("xfer-ghost", &alice, 3.0, ghost_meta);
        // NOTE: deliberately NO put_record here.
        let ghost_parsed = extract_ledger_op(&ghost_rec).unwrap().unwrap();
        let ghost_delta = PendingLedgerDelta::new(
            ghost_rec.id.clone(),
            alice_hash.clone(),
            ghost_rec.timestamp,
            3.5,
            PendingOp::from_parsed(ghost_parsed, &alice_hash, &ghost_rec.id),
        );
        {
            let mut pending = state.pending_ledger.write().await;
            pending.insert(ghost_delta.clone()).unwrap();
        }
        state
            .rocks
            .put_cf_raw(
                CF_PENDING_DELTAS,
                ghost_rec.id.as_bytes(),
                &ghost_delta.to_json().unwrap(),
            )
            .unwrap();

        // Finalize both — this is what drives the drain to attempt
        // commit and trip both failure paths.
        {
            let mut consensus = state.consensus.lock_recover();
            consensus.force_finalized(&bad_xfer.id);
            consensus.force_finalized(&ghost_rec.id);
        }

        let stats = drain_and_commit_pending(&state).await;
        assert_eq!(stats.committed, 0, "neither delta committed");
        assert_eq!(stats.apply_failed, 1, "broke transfer hit apply_failed branch");
        assert_eq!(stats.missing_record, 1, "ghost record hit missing_record branch");

        assert_eq!(
            state.pending_drain_apply_failed_total.load(Ordering::Relaxed),
            1,
            "apply_failed lifetime counter bumps once",
        );
        assert_eq!(
            state.pending_drain_missing_record_total.load(Ordering::Relaxed),
            1,
            "missing_record lifetime counter bumps once",
        );
        assert_eq!(
            state.pending_ledger_commits_total.load(Ordering::Relaxed),
            0,
            "no commits — both deltas failed at drain",
        );
        let _ = creator_identity_hash; // silence unused-import warning in test mod
    }

    /// Phase 3.3e sweep: deltas older than PENDING_DISCARD_TIMEOUT_SECS
    /// are discarded, younger ones are preserved.
    #[tokio::test]
    async fn test_arch_1_sweep_drops_stale_preserves_fresh() {
        let genesis = pk(0x01);
        let (state, _tmp) = state_with_genesis(&genesis);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let stale = PendingLedgerDelta::new(
            "rec-stale".to_string(),
            "alice".to_string(),
            0.0,
            now - PENDING_DISCARD_TIMEOUT_SECS - 1.0,
            PendingOp::Transfer {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount: 7,
                memo: None,
            },
        );
        let fresh = PendingLedgerDelta::new(
            "rec-fresh".to_string(),
            "alice".to_string(),
            0.0,
            now,
            PendingOp::Transfer {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount: 11,
                memo: None,
            },
        );
        for d in [&stale, &fresh] {
            {
                let mut pending = state.pending_ledger.write().await;
                pending.insert(d.clone()).unwrap();
            }
            state
                .rocks
                .put_cf_raw(
                    CF_PENDING_DELTAS,
                    d.record_id.as_bytes(),
                    &d.to_json().unwrap(),
                )
                .unwrap();
        }

        let stats = sweep_stale_pending(&state).await;
        assert_eq!(stats.discarded, 1);

        let pending = state.pending_ledger.read().await;
        assert!(!pending.contains("rec-stale"));
        assert!(pending.contains("rec-fresh"));
        drop(pending);

        assert!(
            state
                .rocks
                .get_cf_raw(CF_PENDING_DELTAS, b"rec-stale")
                .unwrap()
                .is_none(),
            "stale CF row erased"
        );
        assert!(
            state
                .rocks
                .get_cf_raw(CF_PENDING_DELTAS, b"rec-fresh")
                .unwrap()
                .is_some(),
            "fresh CF row preserved"
        );
        assert_eq!(
            state
                .pending_ledger_discards_total
                .load(Ordering::Relaxed),
            1
        );
    }

    /// Slice-4 regression: the sweep MUST spare a stale delta whose
    /// record has reached `Sealed` (anchor-proposed) or higher. Without
    /// this guard, slow-finalizing records on a low-rate testnet had
    /// their pending deltas discarded right before
    /// `drain_newly_finalized` fired, leaving the apply path with
    /// `missing_delta` and silently skipping the ledger mutation. This
    /// is exactly how the live witness_register record on `zone:hil`
    /// finalized at att=4 without ever populating `account.witness_bonded`
    /// or `pending_witness_registrations`, leaving every node's
    /// `CF_WITNESS_REGISTRY` empty after Slice 4 deploy.
    #[tokio::test]
    async fn test_arch_1_sweep_spares_progressing_records() {
        use crate::network::consensus::ConfirmationLevel;

        let genesis = pk(0x01);
        let (state, _tmp) = state_with_genesis(&genesis);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let stale_ts = now - PENDING_DISCARD_TIMEOUT_SECS - 1.0;

        // Three deltas, all past the timeout:
        //   - rec-pending  : never sealed → must be discarded
        //   - rec-sealed   : Sealed       → must be preserved (drain pending)
        //   - rec-finalized: Finalized    → must be preserved (drain pending)
        let pending_d = PendingLedgerDelta::new(
            "rec-pending".to_string(),
            "alice".to_string(),
            0.0,
            stale_ts,
            PendingOp::Transfer {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount: 1,
                memo: None,
            },
        );
        let sealed_d = PendingLedgerDelta::new(
            "rec-sealed".to_string(),
            "alice".to_string(),
            0.0,
            stale_ts,
            PendingOp::Transfer {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount: 2,
                memo: None,
            },
        );
        let finalized_d = PendingLedgerDelta::new(
            "rec-finalized".to_string(),
            "alice".to_string(),
            0.0,
            stale_ts,
            PendingOp::Transfer {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount: 3,
                memo: None,
            },
        );
        for d in [&pending_d, &sealed_d, &finalized_d] {
            {
                let mut pending = state.pending_ledger.write().await;
                pending.insert(d.clone()).unwrap();
            }
            state
                .rocks
                .put_cf_raw(
                    CF_PENDING_DELTAS,
                    d.record_id.as_bytes(),
                    &d.to_json().unwrap(),
                )
                .unwrap();
        }

        // Stamp consensus state. Pending is the default — only Sealed
        // and Finalized need to be inserted.
        {
            let mut consensus = state.consensus.lock_recover();
            consensus.set_confirmation_level_for_test(
                "rec-sealed",
                ConfirmationLevel::Sealed,
            );
            consensus.set_confirmation_level_for_test(
                "rec-finalized",
                ConfirmationLevel::Finalized,
            );
        }

        let stats = sweep_stale_pending(&state).await;
        assert_eq!(stats.discarded, 1, "only rec-pending is dropped");

        let pending = state.pending_ledger.read().await;
        assert!(
            !pending.contains("rec-pending"),
            "stale Pending record discarded"
        );
        assert!(
            pending.contains("rec-sealed"),
            "Sealed record spared so the drain can commit it"
        );
        assert!(
            pending.contains("rec-finalized"),
            "Finalized record spared so the drain can commit it"
        );
    }

    /// Hard-ceiling regression: Sealed entries past
    /// `PENDING_HARD_DISCARD_TIMEOUT_SECS` MUST be reaped even though the
    /// soft-cutoff path spares them. Without this, observed
    /// stuck-Sealed entries (10h+) leak the per-identity 256-cap
    /// indefinitely and force every new record from the same creator into
    /// the direct-apply fallback. The test seeds three deltas: one
    /// Pending+stale (soft-discard), one Sealed+slightly-stale (spared),
    /// one Sealed+past-hard-ceiling (hard-discard) — proving the spare-
    /// Sealed guard still protects slow-finalizing records below the
    /// ceiling.
    #[tokio::test]
    async fn test_arch_1_sweep_hard_ceiling_drops_stuck_sealed() {
        use crate::network::consensus::ConfirmationLevel;

        let genesis = pk(0x01);
        let (state, _tmp) = state_with_genesis(&genesis);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let soft_stale_ts = now - PENDING_DISCARD_TIMEOUT_SECS - 1.0;
        let hard_stale_ts = now - PENDING_HARD_DISCARD_TIMEOUT_SECS - 1.0;

        let pending_soft = PendingLedgerDelta::new(
            "rec-pending-soft".to_string(),
            "alice".to_string(),
            0.0,
            soft_stale_ts,
            PendingOp::Transfer {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount: 1,
                memo: None,
            },
        );
        let sealed_below_ceiling = PendingLedgerDelta::new(
            "rec-sealed-slow".to_string(),
            "alice".to_string(),
            0.0,
            soft_stale_ts,
            PendingOp::Transfer {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount: 2,
                memo: None,
            },
        );
        let sealed_past_ceiling = PendingLedgerDelta::new(
            "rec-sealed-stuck".to_string(),
            "alice".to_string(),
            0.0,
            hard_stale_ts,
            PendingOp::Transfer {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount: 3,
                memo: None,
            },
        );

        for d in [&pending_soft, &sealed_below_ceiling, &sealed_past_ceiling] {
            {
                let mut pending = state.pending_ledger.write().await;
                pending.insert(d.clone()).unwrap();
            }
            state
                .rocks
                .put_cf_raw(
                    CF_PENDING_DELTAS,
                    d.record_id.as_bytes(),
                    &d.to_json().unwrap(),
                )
                .unwrap();
        }

        {
            let mut consensus = state.consensus.lock_recover();
            consensus.set_confirmation_level_for_test(
                "rec-sealed-slow",
                ConfirmationLevel::Sealed,
            );
            consensus.set_confirmation_level_for_test(
                "rec-sealed-stuck",
                ConfirmationLevel::Sealed,
            );
        }

        let stats = sweep_stale_pending(&state).await;
        assert_eq!(stats.discarded, 1, "soft-cutoff drops only rec-pending-soft");
        assert_eq!(
            stats.hard_discarded, 1,
            "hard-ceiling drops rec-sealed-stuck regardless of state"
        );

        let pending = state.pending_ledger.read().await;
        assert!(
            !pending.contains("rec-pending-soft"),
            "soft-stale Pending dropped"
        );
        assert!(
            pending.contains("rec-sealed-slow"),
            "Sealed below the hard ceiling is still spared (Slice-4 protection)"
        );
        assert!(
            !pending.contains("rec-sealed-stuck"),
            "Sealed past hard ceiling is reaped — leak prevented"
        );
        drop(pending);

        // Both counters tick: aggregate discards = soft + hard, hard
        // counter exposes the stuck-Sealed subset for alerting.
        assert_eq!(
            state
                .pending_ledger_discards_total
                .load(Ordering::Relaxed),
            2,
            "discards_total = soft + hard"
        );
        assert_eq!(
            state
                .pending_ledger_hard_discards_total
                .load(Ordering::Relaxed),
            1,
            "hard_discards_total counts the consensus-stuck reap"
        );
    }

    /// Multi-creator hard-discard aggregation: confirms the sweep correctly
    /// counts hard discards across distinct creators and doesn't conflate
    /// counts. Exercises the `hard_by_creator` aggregation path that feeds
    /// the top-offender log line operators grep for.
    #[tokio::test]
    async fn test_arch_1_sweep_hard_discards_multi_creator() {
        let genesis = pk(0x01);
        let (state, _tmp) = state_with_genesis(&genesis);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let hard_stale_ts = now - PENDING_HARD_DISCARD_TIMEOUT_SECS - 1.0;

        // alice: 3 hard-stuck entries (top offender)
        // bob:   1 hard-stuck entry
        // carol: 1 hard-stuck entry
        let layout: &[(&str, &str)] = &[
            ("alice", "rec-a-1"),
            ("alice", "rec-a-2"),
            ("alice", "rec-a-3"),
            ("bob", "rec-b-1"),
            ("carol", "rec-c-1"),
        ];

        for (creator, rid) in layout {
            let d = PendingLedgerDelta::new(
                rid.to_string(),
                creator.to_string(),
                0.0,
                hard_stale_ts,
                PendingOp::Transfer {
                    from: creator.to_string(),
                    to: "treasury".to_string(),
                    amount: 1,
                    memo: None,
                },
            );
            {
                let mut pending = state.pending_ledger.write().await;
                pending.insert(d.clone()).unwrap();
            }
            state
                .rocks
                .put_cf_raw(
                    CF_PENDING_DELTAS,
                    d.record_id.as_bytes(),
                    &d.to_json().unwrap(),
                )
                .unwrap();
        }

        let stats = sweep_stale_pending(&state).await;
        assert_eq!(
            stats.hard_discarded, 5,
            "all 5 hard-stuck entries reaped regardless of creator"
        );
        assert_eq!(
            stats.discarded, 0,
            "no soft discards — every entry crossed the hard ceiling"
        );

        let pending = state.pending_ledger.read().await;
        for (_, rid) in layout {
            assert!(
                !pending.contains(rid),
                "{rid} was hard-discarded and must be gone from pending ledger"
            );
        }
        drop(pending);

        assert_eq!(
            state
                .pending_ledger_hard_discards_total
                .load(Ordering::Relaxed),
            5,
            "hard_discards_total counter aggregated across creators"
        );
    }

    /// Phase 3.3f boot replay: persisted CF_PENDING_DELTAS rows rehydrate
    /// into PendingLedger without re-ingesting the source records.
    #[tokio::test]
    async fn test_arch_1_boot_replay_rehydrates_from_cf() {
        let genesis = pk(0x01);
        let (state, _tmp) = state_with_genesis(&genesis);

        // Seed CF_PENDING_DELTAS directly, simulating a node that ingested
        // two tentative deltas and was then restarted before the drain
        // loop could commit them.
        let d1 = PendingLedgerDelta::new(
            "rec-restart-1".to_string(),
            "alice".to_string(),
            100.0,
            100.5,
            PendingOp::Transfer {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount: 50,
                memo: None,
            },
        );
        let d2 = PendingLedgerDelta::new(
            "rec-restart-2".to_string(),
            "alice".to_string(),
            101.0,
            101.5,
            PendingOp::Burn {
                owner: "alice".to_string(),
                amount: 10,
                memo: None,
            },
        );
        for d in [&d1, &d2] {
            state
                .rocks
                .put_cf_raw(
                    CF_PENDING_DELTAS,
                    d.record_id.as_bytes(),
                    &d.to_json().unwrap(),
                )
                .unwrap();
        }

        // Insert a corrupt row — replay must skip it (and erase it) not
        // crash the boot.
        state
            .rocks
            .put_cf_raw(CF_PENDING_DELTAS, b"rec-corrupt", b"not-json")
            .unwrap();

        let n = boot_replay_pending_deltas(&state).await.expect("replay");
        assert_eq!(n, 2);

        let pending = state.pending_ledger.read().await;
        assert_eq!(pending.len(), 2);
        assert!(pending.contains("rec-restart-1"));
        assert!(pending.contains("rec-restart-2"));
        assert_eq!(
            pending.locked_by_identity("alice"),
            60,
            "transfer 50 + burn 10 are both alice debits"
        );
        drop(pending);

        // The corrupt row was erased by replay — list should show 2 rows
        // (the good ones remain because replay does NOT delete them from
        // disk; only the drain-on-commit path does).
        let rows = state.rocks.list_cf_raw(CF_PENDING_DELTAS, 10).unwrap();
        let keys: Vec<String> = rows
            .iter()
            .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
            .collect();
        assert!(!keys.contains(&"rec-corrupt".to_string()));
        assert_eq!(rows.len(), 2);
    }

    /// Boot replay must drop CF_PENDING_DELTAS rows whose record is
    /// already in CF_APPLIED. Re-inserting would create a stuck
    /// pending_ledger entry that never drains because consensus'
    /// newly-finalized event already fired pre-restart, and would pin
    /// elara_pending_ledger_max_identity_depth at cap until sweep timeout.
    #[tokio::test]
    async fn test_arch_1_boot_replay_drops_already_applied_rows() {
        let genesis = pk(0x01);
        let (state, _tmp) = state_with_genesis(&genesis);

        // Stale row: delta whose record is already in CF_APPLIED.
        let stale = PendingLedgerDelta::new(
            "rec-stale-applied".to_string(),
            "alice".to_string(),
            100.0,
            100.5,
            PendingOp::Transfer {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount: 1,
                memo: None,
            },
        );
        // Fresh row: delta whose record is NOT yet in CF_APPLIED — must
        // still be rehydrated.
        let fresh = PendingLedgerDelta::new(
            "rec-fresh-pending".to_string(),
            "alice".to_string(),
            101.0,
            101.5,
            PendingOp::Transfer {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount: 2,
                memo: None,
            },
        );
        for d in [&stale, &fresh] {
            state
                .rocks
                .put_cf_raw(
                    CF_PENDING_DELTAS,
                    d.record_id.as_bytes(),
                    &d.to_json().unwrap(),
                )
                .unwrap();
        }
        state.rocks.mark_applied(&stale.record_id);

        let n = boot_replay_pending_deltas(&state).await.expect("replay");
        assert_eq!(n, 1, "only the fresh delta should rehydrate");

        let pending = state.pending_ledger.read().await;
        assert!(!pending.contains(&stale.record_id), "stale dropped");
        assert!(pending.contains(&fresh.record_id), "fresh kept");
        drop(pending);

        // CF_PENDING_DELTAS: the stale row must be erased; the fresh
        // row remains.
        let rows = state.rocks.list_cf_raw(CF_PENDING_DELTAS, 10).unwrap();
        let keys: Vec<String> = rows
            .iter()
            .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
            .collect();
        assert!(!keys.contains(&stale.record_id), "stale row erased on disk");
        assert!(keys.contains(&fresh.record_id), "fresh row kept on disk");
    }

    /// CRASH-WINDOW RECOVERY (fusion-audited): a ledger delta whose record is
    /// durably FINALIZED but whose apply was lost to a crash inside the
    /// finality→drain window — the RAM-only `finalization_queue` was wiped and
    /// the startup-replay enqueue is suppressed, so nothing re-drives it and
    /// (worse) the 1200s sweep would reap it → silent ledger fork. boot_replay
    /// must DETECT this (durable FinalizedIndex ∧ !is_applied), re-arm it on the
    /// uncapped reconcile list, and the first drain tick must then commit it.
    #[tokio::test]
    async fn test_arch_1_boot_reconcile_commits_finalized_unapplied_delta() {
        let genesis = pk(0x01);
        let alice = pk(0x02);
        let bob = pk(0x03);
        let alice_hash = identity_hash_of(&alice);
        let bob_hash = identity_hash_of(&bob);
        let (state, _tmp) = state_with_genesis(&genesis);

        // Seed alice with 1_000 beat on the committed ledger.
        let mint_meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let mint_rec = mk_record("mint-1", &genesis, 1.0, mint_meta);
        {
            let mut ledger = state.ledger.write().await;
            ledger
                .apply_single_record(&mint_rec, &state.config.genesis_authority)
                .expect("seed mint");
        }

        // Build the Transfer record + delta. Persist the RECORD to CF_RECORDS
        // and the DELTA to CF_PENDING_DELTAS ONLY — this is the post-crash
        // durable state: pending_ledger (RAM) is empty, the finality signal
        // (RAM queue) is gone, but the record is durably finalized.
        let xfer_meta = types::transfer_metadata(300 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let xfer_rec = mk_record("xfer-crash", &alice, 2.0, xfer_meta);
        state.rocks.put_record(&xfer_rec.id, &xfer_rec).expect("put_record");
        let parsed = extract_ledger_op(&xfer_rec).expect("parse").expect("ledger op");
        let delta = PendingLedgerDelta::new(
            xfer_rec.id.clone(),
            alice_hash.clone(),
            xfer_rec.timestamp,
            2.5,
            PendingOp::from_parsed(parsed, &alice_hash, &xfer_rec.id),
        );
        state
            .rocks
            .put_cf_raw(CF_PENDING_DELTAS, xfer_rec.id.as_bytes(), &delta.to_json().unwrap())
            .expect("put delta");

        // Durably finalized (FinalizedIndex) but NEVER enqueued to consensus —
        // exactly the lost-signal crash window.
        state.finalized.write().await.insert(xfer_rec.id.clone());
        assert!(!state.rocks.is_applied(&xfer_rec.id));

        // Boot replay: rehydrates the delta AND re-arms it for commit.
        let n = boot_replay_pending_deltas(&state).await.expect("replay");
        assert_eq!(n, 1, "delta rehydrated");
        assert_eq!(
            state.pending_boot_reconciled_total.load(Ordering::Relaxed),
            1,
            "one finalized-but-unapplied delta re-armed"
        );
        {
            let boot = state.boot_reconcile_ids.lock_recover();
            assert_eq!(boot.len(), 1);
            assert_eq!(boot[0], xfer_rec.id);
        }
        // Not applied yet — only re-armed.
        {
            let ledger = state.ledger.read().await;
            assert_eq!(ledger.balance(&alice_hash), 1_000 * BASE_UNITS_PER_BEAT);
            assert_eq!(ledger.balance(&bob_hash), 0);
        }

        // First drain tick consumes the uncapped reconcile list and commits.
        let stats = drain_and_commit_pending(&state).await;
        assert_eq!(stats.committed, 1, "re-armed delta committed");

        // Recovery complete: balances correct, exactly-once, list drained.
        {
            let ledger = state.ledger.read().await;
            assert_eq!(ledger.balance(&alice_hash), 700 * BASE_UNITS_PER_BEAT, "alice debited");
            assert_eq!(ledger.balance(&bob_hash), 300 * BASE_UNITS_PER_BEAT, "bob credited");
        }
        assert!(state.rocks.is_applied(&xfer_rec.id), "CF_APPLIED set");
        assert!(
            state.rocks.get_cf_raw(CF_PENDING_DELTAS, xfer_rec.id.as_bytes()).unwrap().is_none(),
            "CF_PENDING_DELTAS row erased"
        );
        assert!(state.boot_reconcile_ids.lock_recover().is_empty(), "reconcile list drained");

        // Idempotent: a second drain is a no-op (no double-apply / no double-credit).
        let again = drain_and_commit_pending(&state).await;
        assert_eq!(again.committed, 0, "no double-commit");
        {
            let ledger = state.ledger.read().await;
            assert_eq!(
                ledger.balance(&bob_hash),
                300 * BASE_UNITS_PER_BEAT,
                "bob not double-credited"
            );
        }
    }

    /// Control: a still-PENDING delta (record NOT in FinalizedIndex) must NOT
    /// be re-armed — it rehydrates normally and waits for real finality. Guards
    /// against the reconcile committing a tentative op early.
    #[tokio::test]
    async fn test_arch_1_boot_reconcile_ignores_unfinalized_delta() {
        let genesis = pk(0x01);
        let (state, _tmp) = state_with_genesis(&genesis);

        let delta = PendingLedgerDelta::new(
            "rec-still-pending".to_string(),
            "alice".to_string(),
            100.0,
            100.5,
            PendingOp::Transfer {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount: 5,
                memo: None,
            },
        );
        state
            .rocks
            .put_cf_raw(CF_PENDING_DELTAS, delta.record_id.as_bytes(), &delta.to_json().unwrap())
            .unwrap();
        // Deliberately NOT finalized.

        let n = boot_replay_pending_deltas(&state).await.expect("replay");
        assert_eq!(n, 1, "delta rehydrated");
        assert_eq!(
            state.pending_boot_reconciled_total.load(Ordering::Relaxed),
            0,
            "unfinalized delta must NOT be re-armed"
        );
        assert!(state.boot_reconcile_ids.lock_recover().is_empty());

        // Drain is a no-op: nothing re-armed, nothing on the consensus queue.
        let stats = drain_and_commit_pending(&state).await;
        assert_eq!(stats.committed, 0, "tentative delta not committed early");
        assert!(state.pending_ledger.read().await.contains("rec-still-pending"));
    }

    /// Genesis/first-boot pre-seeds the supply delta into the in-memory
    /// ledger before boot replay runs; the persisted CF copy is then a
    /// duplicate of a LIVE entry, NOT corruption. Replay must skip it
    /// (counting it as already-in-memory) and still return Ok — not the hard
    /// "already exists" error that used to fire as a WARN on every fresh
    /// node's first boot. A genuinely-new row alongside it still rehydrates.
    #[tokio::test]
    async fn test_arch_1_boot_replay_skips_genesis_preseeded_in_memory() {
        let genesis = pk(0x01);
        let (state, _tmp) = state_with_genesis(&genesis);

        // The genesis pre-seed: a delta already LIVE in the in-memory ledger
        // whose record is NOT yet in CF_APPLIED (has not committed).
        let seeded = PendingLedgerDelta::new(
            "rec-genesis-seed".to_string(),
            "alice".to_string(),
            100.0,
            100.5,
            PendingOp::Transfer {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount: 1,
                memo: None,
            },
        );
        // A genuinely-new row: not in memory, not applied — must rehydrate.
        let fresh = PendingLedgerDelta::new(
            "rec-fresh".to_string(),
            "alice".to_string(),
            101.0,
            101.5,
            PendingOp::Transfer {
                from: "alice".to_string(),
                to: "bob".to_string(),
                amount: 2,
                memo: None,
            },
        );
        // Pre-seed `seeded` into the in-memory ledger (what genesis does).
        {
            let mut pending = state.pending_ledger.write().await;
            pending.insert(seeded.clone()).expect("pre-seed");
        }
        // Both are persisted to CF_PENDING_DELTAS (genesis persists its seed;
        // the fresh row is a normal pending op awaiting replay).
        for d in [&seeded, &fresh] {
            state
                .rocks
                .put_cf_raw(
                    CF_PENDING_DELTAS,
                    d.record_id.as_bytes(),
                    &d.to_json().unwrap(),
                )
                .unwrap();
        }

        // Must NOT hard-error: the genesis pre-seed is not corruption.
        let n = boot_replay_pending_deltas(&state)
            .await
            .expect("replay must not hard-error on the genesis pre-seed");
        assert_eq!(n, 1, "only the genuinely-new delta rehydrates");

        let pending = state.pending_ledger.read().await;
        assert_eq!(pending.len(), 2, "pre-seeded + fresh, no duplicate");
        assert!(pending.contains(&seeded.record_id), "pre-seed kept");
        assert!(pending.contains(&fresh.record_id), "fresh rehydrated");
    }

    /// A finalized rid with no matching pending delta (e.g. an epoch
    /// seal that was never a ledger op) must be counted as
    /// `missing_delta`, not fatal.
    #[tokio::test]
    async fn test_arch_1_drain_missing_delta_is_not_fatal() {
        let genesis = pk(0x01);
        let (state, _tmp) = state_with_genesis(&genesis);

        {
            let mut consensus = state.consensus.lock_recover();
            consensus.force_finalized("epoch-seal-without-pending");
        }

        let stats = drain_and_commit_pending(&state).await;
        assert_eq!(stats.committed, 0);
        assert_eq!(stats.missing_delta, 1);
        assert_eq!(stats.missing_record, 0);
        assert_eq!(stats.apply_failed, 0);
    }

    /// §1030 (wall-#5 leg 4): a finalized LEDGER record whose pending delta
    /// was TTL-swept must be recovered by re-deriving the delta from the
    /// stored record — not skipped as `missing_delta`. Rehearsal #4: the
    /// genesis pool seed's delta was swept at +10 min (Pending > soft TTL),
    /// the record finalized at +40 min, the authority's pool stayed 0 while
    /// both peers applied at their commit → ledger fork. The record is the
    /// source of truth.
    #[tokio::test]
    async fn test_arch_1_drain_rederives_ttl_swept_token_delta() {
        let genesis = pk(0x01);
        let alice = pk(0x02);
        let alice_hash = identity_hash_of(&alice);
        let (state, _tmp) = state_with_genesis(&genesis);

        // A mint record present in CF_RECORDS with NO pending delta — the
        // state a TTL discard sweep leaves behind.
        let mint_meta =
            types::mint_metadata(500 * BASE_UNITS_PER_BEAT, &alice_hash, "swept");
        let rec = mk_record("swept-mint-r1", &genesis, 1.0, mint_meta);
        state.rocks.put_record(&rec.id, &rec).expect("put_record");
        {
            let mut consensus = state.consensus.lock_recover();
            consensus.force_finalized("swept-mint-r1");
        }

        let stats = drain_and_commit_pending(&state).await;
        assert_eq!(stats.missing_delta, 1, "delta was missing (swept)");
        assert_eq!(stats.rederived, 1, "swept ledger delta re-derived");
        assert_eq!(stats.committed, 1, "re-derived delta committed");
        {
            let ledger = state.ledger.read().await;
            assert_eq!(
                ledger.balance(&alice_hash),
                500 * BASE_UNITS_PER_BEAT,
                "the recovered apply must land on the committed ledger"
            );
        }
        assert!(
            state.rocks.is_applied("swept-mint-r1"),
            "commit path marks applied"
        );

        // Exactly-once: a second pass over the same rid must NOT re-apply.
        {
            let mut consensus = state.consensus.lock_recover();
            consensus.force_finalized("swept-mint-r1");
        }
        let stats2 = drain_and_commit_pending(&state).await;
        assert_eq!(stats2.rederived, 0, "already-applied rid not re-derived");
        assert_eq!(stats2.committed, 0);
        {
            let ledger = state.ledger.read().await;
            assert_eq!(
                ledger.balance(&alice_hash),
                500 * BASE_UNITS_PER_BEAT,
                "no double-apply"
            );
        }
    }

    /// ARCH-1 cap-pinch (#47): when an identity's `pending_ledger` slot is
    /// at `MAX_PENDING_PER_IDENTITY`, the tentative insert is rejected.
    /// The fix: direct-apply the record to the committed ledger instead
    /// of silently dropping it. Without the fallback the canary's ledger
    /// diverges from peers (peers direct-apply unconditionally on the
    /// !flag branch).
    #[tokio::test]
    async fn test_arch_1_cap_pinch_falls_back_to_direct_apply() {
        use crate::accounting::pending_ledger::MAX_PENDING_PER_IDENTITY;

        let genesis = pk(0x01);
        let alice = pk(0x02);
        let bob = pk(0x03);
        let alice_hash = identity_hash_of(&alice);
        let bob_hash = identity_hash_of(&bob);

        let (state, _tmp) = state_with_genesis(&genesis);

        // Seed alice with 1000 beat through the committed ledger.
        let mint_meta =
            types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let mint_rec = mk_record("mint-cp", &genesis, 1.0, mint_meta);
        {
            let mut ledger = state.ledger.write().await;
            ledger
                .apply_single_record(&mint_rec, &state.config.genesis_authority)
                .expect("seed mint");
        }

        // Fill alice's pending slot to cap with stub deltas. The ops
        // themselves don't need to be applyable — they only need to
        // occupy slots so the next insert is rejected.
        {
            let mut pending = state.pending_ledger.write().await;
            for i in 0..MAX_PENDING_PER_IDENTITY {
                let stub = PendingLedgerDelta::new(
                    format!("stub-{i}"),
                    alice_hash.clone(),
                    i as f64 + 100.0,
                    i as f64 + 100.0,
                    PendingOp::Transfer {
                        from: alice_hash.clone(),
                        to: bob_hash.clone(),
                        amount: 1,
                        memo: None,
                    },
                );
                pending.insert(stub).expect("stub insert");
            }
        }
        assert_eq!(
            state.pending_ledger.read().await.len(),
            MAX_PENDING_PER_IDENTITY,
            "cap is full"
        );

        // The contract under test: a brand-new delta from alice will be
        // rejected from `pending_ledger.insert`, and the rejection branch
        // in ingest must direct-apply the source record to the committed
        // ledger so the canary stays consistent with peers.
        //
        // We exercise the contract directly here (without going through
        // the full ingest pipeline) by reproducing exactly what the
        // ingest fallback branch does:
        //   1) pending_ledger.insert(...) -> Err(InsertRejection::PerIdentityQuotaExceeded)
        //   2) bump rejection + fallback counters
        //   3) apply_single_record on the committed ledger
        //
        // This mirrors src/network/ingest.rs around line 1475 verbatim,
        // so a test failure here means either the rejection contract or
        // the apply contract has drifted.
        let xfer_meta = types::transfer_metadata(300 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let xfer_rec = mk_record("xfer-cp", &alice, 200.0, xfer_meta);
        let parsed = extract_ledger_op(&xfer_rec).expect("parse").expect("ledger op");
        let new_delta = PendingLedgerDelta::new(
            xfer_rec.id.clone(),
            alice_hash.clone(),
            xfer_rec.timestamp,
            201.0,
            PendingOp::from_parsed(parsed, &alice_hash, &xfer_rec.id),
        );

        // Step 1: rejection.
        let insert_res = {
            let mut pending = state.pending_ledger.write().await;
            pending.insert(new_delta)
        };
        assert!(insert_res.is_err(), "cap-full insert must be rejected");

        // Step 2 + 3: bump counters and fall back to direct apply, the
        // exact pair of operations the production rejection branch in
        // ingest.rs runs.
        state
            .pending_ledger_rejections_total
            .fetch_add(1, Ordering::Relaxed);
        state
            .pending_ledger_fallback_direct_apply_total
            .fetch_add(1, Ordering::Relaxed);
        {
            let mut ledger = state.ledger.write().await;
            ledger
                .apply_single_record(&xfer_rec, &state.config.genesis_authority)
                .expect("fallback direct-apply must succeed");
        }

        // Post-fallback: ledger reflects the transfer just like a !flag
        // peer that took the direct-apply branch.
        {
            let ledger = state.ledger.read().await;
            assert_eq!(
                ledger.balance(&alice_hash),
                700 * BASE_UNITS_PER_BEAT,
                "alice debited via fallback"
            );
            assert_eq!(
                ledger.balance(&bob_hash),
                300 * BASE_UNITS_PER_BEAT,
                "bob credited via fallback"
            );
        }
        assert_eq!(
            state
                .pending_ledger_rejections_total
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            state
                .pending_ledger_fallback_direct_apply_total
                .load(Ordering::Relaxed),
            1
        );
    }

    /// Gap 2.1 Phase 2b.3 Slice 4 fix regression: prove
    /// `flush_pending_witness_registrations` drains
    /// `LedgerState::pending_witness_registrations` to
    /// `CF_WITNESS_REGISTRY` regardless of node role.
    ///
    /// Pre-fix the only flush site lived in `epoch_seal_loop`, which
    /// returns early on non-anchor nodes — so a witness-role node would
    /// `apply_op(WitnessRegister)` (queue grew) and never write the
    /// row, leaving `iter_witnesses_for_zone` empty. This test simulates
    /// that exact path: push a tuple onto the queue directly, run the
    /// new helper, assert the CF was written and the queue was emptied.
    #[tokio::test]
    async fn test_witness_registry_flush_writes_to_cf_on_any_node() {
        let genesis = pk(0x01);
        let (state, _tmp) = state_with_genesis(&genesis);

        let zone_path = "zone:hil".to_string();
        let identity = "59fbf75dbf95212de83142d285e9ca3f311cca8fc5136ad107afa092521b8cd1".to_string();
        let dilithium_pk = vec![0xAB; 1952];
        let bond = 100 * BASE_UNITS_PER_BEAT;
        let registered_epoch = 12345_u64;

        // Pre-populate the queue exactly as `apply_op(WitnessRegister)`
        // does. CF starts empty.
        {
            let mut ledger = state.ledger.write().await;
            ledger.pending_witness_registrations.push((
                zone_path.clone(),
                identity.clone(),
                dilithium_pk.clone(),
                bond,
                registered_epoch,
            ));
        }
        assert!(
            state.rocks.iter_witnesses_for_zone(&zone_path).is_empty(),
            "pre-flush registry must be empty"
        );

        flush_pending_witness_registrations(&state).await;

        let entries = state.rocks.iter_witnesses_for_zone(&zone_path);
        assert_eq!(entries.len(), 1, "flush must write the queued tuple");
        let (got_id, got_entry) = &entries[0];
        assert_eq!(got_id, &identity);
        assert_eq!(got_entry.bond, bond);
        assert_eq!(got_entry.registered_epoch, registered_epoch);
        assert_eq!(got_entry.dilithium_pk, dilithium_pk);

        let queue_after = {
            let ledger = state.ledger.read().await;
            ledger.pending_witness_registrations.clone()
        };
        assert!(
            queue_after.is_empty(),
            "queue must be drained after flush, got {} entries",
            queue_after.len()
        );

        // Empty-queue tick is a no-op (no panic, no write).
        flush_pending_witness_registrations(&state).await;
        assert_eq!(
            state.rocks.iter_witnesses_for_zone(&zone_path).len(),
            1,
            "second flush on empty queue must not change the CF"
        );
    }

    /// ARCH-1 named exit-gate test: a
    /// record that is ingested into the tentative ledger but never
    /// reaches finality MUST NOT mutate the committed ledger. The
    /// stale-sweep discards the pending delta on timeout and conservation
    /// (`ledger.total_supply` + per-account balances) is preserved.
    ///
    /// "Fraudulent" here means: the record decoded cleanly enough to enter
    /// `pending_ledger` (modeling the AUDIT-1 era when `witness_public_key`
    /// was optional and a forged sig could survive decode), but consensus
    /// later rejects it — modeled here by withholding `force_finalized`
    /// and letting the `PENDING_DISCARD_TIMEOUT_SECS` sweep expire the
    /// delta. After AUDIT-1 closure the forged-sig path is double-protected
    /// (rejected at decode), but the tentative-ledger discard semantics
    /// remain the load-bearing invariant for any cause of non-finality
    /// (orphaned seal, equivocation, network partition).
    #[tokio::test]
    async fn conservation_holds_under_fraudulent_record() {
        let genesis = pk(0x01);
        let alice = pk(0x02);
        let bob = pk(0x03);
        let alice_hash = identity_hash_of(&alice);
        let bob_hash = identity_hash_of(&bob);

        let (state, _tmp) = state_with_genesis(&genesis);

        // Seed alice with 1_000 beat through the committed ledger.
        let mint_meta =
            types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let mint_rec = mk_record("mint-fraud", &genesis, 1.0, mint_meta);
        {
            let mut ledger = state.ledger.write().await;
            ledger
                .apply_single_record(&mint_rec, &state.config.genesis_authority)
                .expect("seed mint");
        }

        // Conservation snapshot before the fraudulent record lands.
        let (supply_before, alice_before, bob_before) = {
            let ledger = state.ledger.read().await;
            (
                ledger.total_supply,
                ledger.balance(&alice_hash),
                ledger.balance(&bob_hash),
            )
        };
        assert_eq!(supply_before, 1_000 * BASE_UNITS_PER_BEAT);
        assert_eq!(alice_before, 1_000 * BASE_UNITS_PER_BEAT);
        assert_eq!(bob_before, 0);

        // Build the "fraudulent" Transfer record. On the wire this would
        // carry a forged signature; in this test we only need the ledger
        // op to land in pending_ledger. We give it a stale timestamp so
        // the discard sweep treats it as expired without waiting on a
        // real finality vote.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let stale_ts = now - PENDING_DISCARD_TIMEOUT_SECS - 1.0;
        let xfer_rec = mk_record(
            "fraud-1",
            &alice,
            stale_ts,
            types::transfer_metadata(500 * BASE_UNITS_PER_BEAT, &bob_hash, None),
        );
        state.rocks.put_record(&xfer_rec.id, &xfer_rec).unwrap();

        let parsed = extract_ledger_op(&xfer_rec).unwrap().unwrap();
        let delta = PendingLedgerDelta::new(
            xfer_rec.id.clone(),
            alice_hash.clone(),
            xfer_rec.timestamp,
            stale_ts,
            PendingOp::from_parsed(parsed, &alice_hash, &xfer_rec.id),
        );
        {
            let mut pending = state.pending_ledger.write().await;
            pending.insert(delta.clone()).unwrap();
        }
        state
            .rocks
            .put_cf_raw(
                CF_PENDING_DELTAS,
                xfer_rec.id.as_bytes(),
                &delta.to_json().unwrap(),
            )
            .unwrap();

        // Tentative-apply MUST NOT have moved the committed ledger.
        {
            let ledger = state.ledger.read().await;
            assert_eq!(
                ledger.balance(&alice_hash),
                alice_before,
                "tentative-apply must not debit committed ledger"
            );
            assert_eq!(
                ledger.balance(&bob_hash),
                bob_before,
                "tentative-apply must not credit committed ledger"
            );
            assert_eq!(
                ledger.total_supply, supply_before,
                "total_supply is invariant under tentative-apply"
            );
        }

        // No `force_finalized` for fraud-1 — consensus rejects it. The
        // sweep is what closes the discard path.
        let stats = sweep_stale_pending(&state).await;
        assert_eq!(stats.discarded, 1, "stale fraudulent delta must be swept");

        // Pending store is empty and the CF row is gone.
        {
            let pending = state.pending_ledger.read().await;
            assert!(pending.is_empty(), "pending_ledger drained after sweep");
        }
        assert!(
            state
                .rocks
                .get_cf_raw(CF_PENDING_DELTAS, xfer_rec.id.as_bytes())
                .unwrap()
                .is_none(),
            "CF_PENDING_DELTAS row erased on discard"
        );

        // CONSERVATION: balances and supply identical to pre-fraud snapshot.
        {
            let ledger = state.ledger.read().await;
            assert_eq!(
                ledger.balance(&alice_hash),
                alice_before,
                "alice balance unchanged after fraudulent-record sweep"
            );
            assert_eq!(
                ledger.balance(&bob_hash),
                bob_before,
                "bob balance unchanged after fraudulent-record sweep"
            );
            assert_eq!(
                ledger.total_supply, supply_before,
                "conservation invariant: total_supply preserved"
            );
        }

        // Discards counter bumped, commits counter untouched, and the
        // record is NOT in CF_APPLIED (committed-ledger never saw it).
        assert_eq!(
            state.pending_ledger_discards_total.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            state.pending_ledger_commits_total.load(Ordering::Relaxed),
            0
        );
        assert!(
            !state.rocks.is_applied(&xfer_rec.id),
            "fraudulent record must not appear in CF_APPLIED"
        );

        // Re-running the sweeper is a no-op (one-shot discard).
        let again = sweep_stale_pending(&state).await;
        assert_eq!(again.discarded, 0, "sweep must not double-discard");
    }

    // Lock in the pure sync surface — both stats struct defaults and both
    // timeout constants — so the production code's public contract is pinned
    // without spinning up the heavy NodeState fixture every async test in
    // this file uses. CommitStats and SweepStats are returned across the
    // public API boundary (callers in `network/server.rs` consume them for
    // /metrics + telemetry); the timeouts are the two-stage soft/hard cutoff
    // feeding `sweep_stale_pending`'s documented behavior.

    #[test]
    fn batch_ab_commit_stats_default_is_all_zero_and_partial_eq_round_trips() {
        // Pins `CommitStats::default()` at pending_drain.rs:29 — all four
        // u64 counter fields MUST initialize to zero. The struct is the
        // per-invocation outcome of `drain_and_commit_pending`; a non-zero
        // default would silently inflate every commit-cycle metric from
        // the moment a NodeState boots. Also exercises the derived
        // PartialEq/Eq/Clone so a future refactor that touched the derives
        // catches here too.
        let s = CommitStats::default();
        assert_eq!(s.committed, 0, "committed counter must start at 0");
        assert_eq!(s.missing_record, 0, "missing_record counter must start at 0");
        assert_eq!(s.missing_delta, 0, "missing_delta counter must start at 0");
        assert_eq!(s.apply_failed, 0, "apply_failed counter must start at 0");

        // PartialEq self-equality (Default::default produces canonical zero).
        assert_eq!(s, CommitStats::default());
        // Clone is field-equal — no shared interior mutable state.
        let cloned = s.clone();
        assert_eq!(cloned, s);
        // Any non-zero field breaks equality with default — pins the
        // discrimination power of the derive (would catch a `#[derive(Eq)]`
        // implementation that compared by something other than fields).
        let with_committed = CommitStats { committed: 1, ..CommitStats::default() };
        assert_ne!(with_committed, CommitStats::default());
        let with_missing_record = CommitStats { missing_record: 1, ..CommitStats::default() };
        assert_ne!(with_missing_record, CommitStats::default());
        let with_missing_delta = CommitStats { missing_delta: 1, ..CommitStats::default() };
        assert_ne!(with_missing_delta, CommitStats::default());
        let with_apply_failed = CommitStats { apply_failed: 1, ..CommitStats::default() };
        assert_ne!(with_apply_failed, CommitStats::default());
    }

    #[test]
    fn batch_ab_sweep_stats_default_is_all_zero_and_partial_eq_round_trips() {
        // Pins `SweepStats::default()` at pending_drain.rs:207 — both u64
        // counters (discarded = soft-cutoff Pending-only, hard_discarded =
        // hard-cutoff any-state) MUST initialize to zero. A non-zero default
        // would surface as phantom sweep activity on every fresh NodeState,
        // confusing the audit-doc that uses `hard_discarded != 0` as the
        // "consensus genuinely stuck" signal (pending_drain.rs:215-216).
        let s = SweepStats::default();
        assert_eq!(s.discarded, 0, "soft-cutoff counter must start at 0");
        assert_eq!(s.hard_discarded, 0, "hard-cutoff counter must start at 0");

        // PartialEq self-equality + Clone round-trip.
        assert_eq!(s, SweepStats::default());
        assert_eq!(s.clone(), s);
        // Each field is independently discriminated by Eq — a refactor that
        // accidentally aliased the two fields onto the same backing slot
        // would surface here.
        let with_discarded = SweepStats { discarded: 1, ..SweepStats::default() };
        assert_ne!(with_discarded, SweepStats::default());
        let with_hard = SweepStats { hard_discarded: 1, ..SweepStats::default() };
        assert_ne!(with_hard, SweepStats::default());
        assert_ne!(with_discarded, with_hard, "the two counters are not aliased");
    }

    #[test]
    fn batch_ab_pending_discard_timeouts_pin_documented_invariant_hard_is_strict_2x_soft() {
        // Pins both timeout constants at their documented values and the
        // hard ≥ 2× soft invariant from pending_drain.rs:188-204. The
        // two-stage sweep at L251-252 computes `now - SOFT` for the
        // Pending-only cutoff and `now - HARD` for the any-state cutoff;
        // if `HARD < SOFT` the inequality flips and the hard cutoff would
        // exclude records the soft cutoff still includes — single-stage
        // collapse. The 2× headroom is what makes the "spare Sealed records
        // mid-finalization" intent at L201 work (legitimate slow finalizers
        // up to 600s past soft survive; only genuinely stuck records past
        // hard reap).
        assert_eq!(
            PENDING_DISCARD_TIMEOUT_SECS, 600.0_f64,
            "soft cutoff must be 600s (10× MIN_ADAPTIVE_EPOCH_SECS at the old 60s floor)"
        );
        assert_eq!(
            PENDING_HARD_DISCARD_TIMEOUT_SECS, 1200.0_f64,
            "hard cutoff must be 1200s (10× MAX_ADAPTIVE_EPOCH_SECS = 10×120s post 2026-04-29 resize)"
        );
        // Strict-ordering + non-zero invariants are now `const _: () = assert!(..)`
        // static assertions at module scope, immediately after the two const
        // declarations (see pending_drain.rs:L207-L218). They fire at compile
        // time instead of test runtime — a future edit that drops either to
        // zero, swaps HARD < SOFT, or sets NaN fails the build, not a test.
        // Their former runtime-assert versions were clippy::assertions_on_constants
        // tautological since both operands are `pub const f64`.
        //
        // Exact 2× relationship stays as a runtime assert_eq! — clippy does
        // not lint comparisons that go through f64 multiplication (the
        // PENDING_DISCARD_TIMEOUT_SECS * 2.0 RHS is a const expression too,
        // but the lint conservatively only fires on direct comparisons).
        // The 2× pin catches a tuner that drops HARD to e.g. 900 and silently
        // halves the legitimate-slow-finalizer headroom.
        assert_eq!(
            PENDING_HARD_DISCARD_TIMEOUT_SECS,
            PENDING_DISCARD_TIMEOUT_SECS * 2.0,
            "hard cutoff must be exactly 2× soft cutoff per the documented sizing rule"
        );
        // f64::is_finite is still a useful runtime guard against a future
        // NaN/infinity constant — clippy does NOT flag method-call assertions
        // (only direct boolean expressions). Keep both.
        assert!(PENDING_DISCARD_TIMEOUT_SECS.is_finite());
        assert!(PENDING_HARD_DISCARD_TIMEOUT_SECS.is_finite());
    }

    // Lock in the remaining pure-sync surface — Debug formatting of both
    // stats structs (consumed by tracing macros in logs and operator
    // dashboards) and the f64→u64 timeout casts that feed the sweep info!()
    // line at L347. Same fixture-free pattern as the constants tests above so
    // these add coverage without a NodeState setup.

    #[test]
    fn batch_ac_commit_stats_debug_format_lists_all_field_names() {
        // Pins the derived Debug shape of CommitStats. The struct is consumed
        // by tracing fields and by a soon-to-land soak-log line, so the field
        // names appearing in {:?} form part of the observable contract:
        // operators grep for `committed:` to find drain rate, `apply_failed:`
        // to spot canary failures. A rename without updating greppers would
        // surface as missing dashboard rows. Pinning the strings here makes
        // any future rename trip the test rather than silently break
        // downstream alert rules.
        let s = CommitStats {
            committed: 7,
            missing_record: 1,
            missing_delta: 2,
            apply_failed: 3,
            rederived: 4,
        };
        let repr = format!("{s:?}");
        assert!(repr.contains("CommitStats"), "Debug must name the struct");
        assert!(repr.contains("committed: 7"), "committed value must surface");
        assert!(
            repr.contains("missing_record: 1"),
            "missing_record value must surface"
        );
        assert!(
            repr.contains("missing_delta: 2"),
            "missing_delta value must surface"
        );
        assert!(
            repr.contains("apply_failed: 3"),
            "apply_failed value must surface"
        );
        // Field order is the struct declaration order — pinning prevents a
        // refactor that re-ordered fields and accidentally changed the
        // serialized debug shape (which would silently regress any log
        // parser keyed on positional output).
        let pos_committed = repr.find("committed").expect("committed present");
        let pos_missing_record = repr
            .find("missing_record")
            .expect("missing_record present");
        let pos_missing_delta = repr.find("missing_delta").expect("missing_delta present");
        let pos_apply_failed = repr.find("apply_failed").expect("apply_failed present");
        assert!(pos_committed < pos_missing_record);
        assert!(pos_missing_record < pos_missing_delta);
        assert!(pos_missing_delta < pos_apply_failed);
    }

    #[test]
    fn batch_ac_sweep_stats_debug_format_lists_all_field_names() {
        // Same intent as the CommitStats variant: pin SweepStats Debug shape
        // so operator-facing log greps for `hard_discarded:` keep working.
        // The hard_discarded counter is THE alert signal for "consensus is
        // genuinely stuck on these records" (pending_drain.rs:213-216 doc
        // comment) — losing the field name in {:?} output would silently
        // strip the alert from soak-log scrapes.
        let s = SweepStats {
            discarded: 4,
            hard_discarded: 9,
        };
        let repr = format!("{s:?}");
        assert!(repr.contains("SweepStats"), "Debug must name the struct");
        assert!(repr.contains("discarded: 4"), "discarded value must surface");
        assert!(
            repr.contains("hard_discarded: 9"),
            "hard_discarded value must surface"
        );
        // Declaration order: discarded before hard_discarded.
        let pos_soft = repr.find("discarded").expect("discarded present");
        let pos_hard = repr
            .find("hard_discarded")
            .expect("hard_discarded present");
        assert!(
            pos_soft < pos_hard,
            "soft-cutoff field must precede hard-cutoff field in declaration order"
        );
    }

    #[test]
    fn batch_ac_timeout_constants_lossless_u64_cast_pins_log_precision() {
        // Pins the production f64→u64 cast at pending_drain.rs:349 and :351,
        // where the sweep summary info!() line formats both timeouts as
        // unsigned seconds. The cast is lossy in principle (truncates
        // fractional part, saturates outside u64 range). With the current
        // integer constants the cast is round-trip exact — pinning the
        // exactness catches a tuner who flips a constant to e.g. 599.999
        // or 1200.5 and silently regresses the operator-facing summary by
        // a whole second.
        let soft_as_u64 = PENDING_DISCARD_TIMEOUT_SECS as u64;
        let hard_as_u64 = PENDING_HARD_DISCARD_TIMEOUT_SECS as u64;
        assert_eq!(
            soft_as_u64, 600,
            "soft cutoff must cast to 600 exactly (matches info!() summary)"
        );
        assert_eq!(
            hard_as_u64, 1200,
            "hard cutoff must cast to 1200 exactly (matches info!() summary)"
        );
        // Round-trip: cast u64 back to f64 must equal the constant. This
        // confirms the f64 representation has no fractional component that
        // would silently truncate.
        assert_eq!(
            soft_as_u64 as f64, PENDING_DISCARD_TIMEOUT_SECS,
            "f64→u64→f64 round-trip is lossless for the soft cutoff"
        );
        assert_eq!(
            hard_as_u64 as f64, PENDING_HARD_DISCARD_TIMEOUT_SECS,
            "f64→u64→f64 round-trip is lossless for the hard cutoff"
        );
    }

    #[test]
    fn batch_ac_timeout_subtraction_from_unix_now_stays_well_positive() {
        // Pins the subtraction-from-now() arithmetic at
        // pending_drain.rs:251-252 (`soft_cutoff = now - SOFT`,
        // `hard_cutoff = now - HARD`). Both cutoffs MUST stay strictly
        // positive in real-world time math — a negative cutoff would make
        // every applied_at filter at L265 always-true (since applied_at
        // is also a positive f64), reducing the sweep to "drop everything"
        // unconditionally on a single tick.
        //
        // Current epoch (>1.7e9 s since UNIX) minus the largest cutoff
        // (1200 s) is on the order of 1.7e9, well within f64 precision.
        // The pin guards against a hypothetical future where the constants
        // are flipped to huge values (e.g. accidentally typed in
        // milliseconds, 600_000.0 / 1_200_000.0) that would push the
        // cutoff into the negative for nodes booted near genesis.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("post-1970 clock")
            .as_secs_f64();
        let soft_cutoff = now - PENDING_DISCARD_TIMEOUT_SECS;
        let hard_cutoff = now - PENDING_HARD_DISCARD_TIMEOUT_SECS;
        assert!(
            soft_cutoff > 0.0,
            "soft_cutoff must remain positive at current wall-clock now"
        );
        assert!(
            hard_cutoff > 0.0,
            "hard_cutoff must remain positive at current wall-clock now"
        );
        // hard_cutoff is older than soft_cutoff because HARD > SOFT and
        // both are subtracted from the same `now`. The sweep relies on
        // this ordering at L282-291 to split "hit_hard" from "soft-only"
        // — flipping it would route every hard-stuck record through the
        // spare-Sealed guard and never reap them.
        assert!(
            hard_cutoff < soft_cutoff,
            "hard_cutoff (older threshold) must be < soft_cutoff (newer threshold)"
        );
        // Both cutoffs are also finite (no NaN/Inf could survive the
        // f64 subtraction above given the constants are finite, but
        // pinning explicitly catches a future refactor that swaps the
        // constants to f64::INFINITY).
        assert!(soft_cutoff.is_finite());
        assert!(hard_cutoff.is_finite());
    }

    // ─── Timeout-constant literal pins ───────────────────────────────────────

    /// Strict byte-exact literal pin of `PENDING_DISCARD_TIMEOUT_SECS` and
    /// `PENDING_HARD_DISCARD_TIMEOUT_SECS`, their structural 2× ratio, and
    /// their cross-module relationship to `MAX_ADAPTIVE_EPOCH_SECS`. Closes
    /// the gap between the two existing in-module tests (which check
    /// signs/ordering) and the cross-module disjointness pins in
    /// `network/fork`, `network/reward`, and `network/geo_fraud` — none of
    /// those modules anchor the literal values at the module-of-origin. A
    /// future tuner who lifted
    /// `PENDING_DISCARD_TIMEOUT_SECS` to, say, 900s, would silently break
    /// the 10-minute dashboard convention without tripping any sign or
    /// ordering check.
    ///
    /// Cross-module note: `MAX_ADAPTIVE_EPOCH_SECS = 60.0` today (cut from
    /// 120s on 2026-04-29 commit 1cd57b4, then again to 60s) so the actual
    /// ratio is `PENDING_DISCARD = 10× MAX_ADAPTIVE_EPOCH` and
    /// `PENDING_HARD_DISCARD = 20× MAX_ADAPTIVE_EPOCH`. The 1200/60=20
    /// invariant says "spare-Sealed records get 20 epochs of grace before
    /// the hard reaper runs"; if a future cap-drop brings `MAX_ADAPTIVE`
    /// down further, the operator should consciously decide whether to
    /// re-scale the discard timeouts to preserve the 10×/20× ratio or
    /// break it.
    #[test]
    fn batch_b_pending_drain_timeout_consts_byte_exact_with_cross_module_epoch_ratio_and_disjointness() {
        // Strict literal pins.
        assert_eq!(PENDING_DISCARD_TIMEOUT_SECS, 600.0_f64);
        assert_eq!(PENDING_HARD_DISCARD_TIMEOUT_SECS, 1200.0_f64);

        // Finite, strictly positive, integral (.fract()==0) — the values
        // are documented as second-count seconds and any fractional-second
        // drift would suggest accidental division-by-1000 or similar.
        for &v in &[PENDING_DISCARD_TIMEOUT_SECS, PENDING_HARD_DISCARD_TIMEOUT_SECS] {
            assert!(v.is_finite(), "timeout must be finite, got {v}");
            assert!(v > 0.0, "timeout must be strictly positive, got {v}");
            assert_eq!(v.fract(), 0.0, "timeout must be integral seconds, got {v}");
        }

        // Strict 2× ratio (HARD = 2 × SOFT). Pinned in the in-file
        // const_assert (PENDING_HARD_DISCARD_TIMEOUT_SECS >
        // PENDING_DISCARD_TIMEOUT_SECS) but not at the literal 2×.
        let ratio = PENDING_HARD_DISCARD_TIMEOUT_SECS / PENDING_DISCARD_TIMEOUT_SECS;
        assert!(
            (ratio - 2.0).abs() < 1e-9,
            "PENDING_HARD / PENDING_SOFT MUST be exactly 2.0 (got {ratio}); the 2× ratio is the documented spare-Sealed grace factor"
        );

        // 10-minute / 20-minute operator-readable convention pin. Drift to
        // 9 min or 11 min would break the operator-doc convention without
        // tripping any sign check.
        assert_eq!(PENDING_DISCARD_TIMEOUT_SECS, 10.0 * 60.0);
        assert_eq!(PENDING_HARD_DISCARD_TIMEOUT_SECS, 20.0 * 60.0);

        // Cross-module epoch-scaling invariant: the timeouts should be
        // expressible as integer multiples of MAX_ADAPTIVE_EPOCH_SECS so
        // that a single epoch cap drop has a predictable effect on the
        // grace window. With MAX_ADAPTIVE_EPOCH_SECS=60.0 today:
        //   SOFT  = 10 × 60s = 600s
        //   HARD  = 20 × 60s = 1200s
        let max_epoch = crate::network::epoch::MAX_ADAPTIVE_EPOCH_SECS;
        assert!(max_epoch.is_finite() && max_epoch > 0.0);
        assert_eq!(
            PENDING_DISCARD_TIMEOUT_SECS / max_epoch,
            10.0,
            "PENDING_DISCARD MUST be 10 × MAX_ADAPTIVE_EPOCH_SECS (epoch-scaling invariant)"
        );
        assert_eq!(
            PENDING_HARD_DISCARD_TIMEOUT_SECS / max_epoch,
            20.0,
            "PENDING_HARD MUST be 20 × MAX_ADAPTIVE_EPOCH_SECS (epoch-scaling invariant)"
        );

        // Cross-module disjointness — both timeouts must NOT collide with
        // unrelated constants used in the same dashboards / log lines.
        // Distinct from MIN_ADAPTIVE_EPOCH_SECS (5.0), MAX_ADAPTIVE_EPOCH_SECS
        // (60.0), MAX_STATE_CORE_WORKERS cast (64.0). Different physical
        // dimensions (seconds vs counts) — pinning the literal values
        // disjoint reduces dashboard misreadings.
        assert_ne!(PENDING_DISCARD_TIMEOUT_SECS, crate::network::epoch::MIN_ADAPTIVE_EPOCH_SECS);
        assert_ne!(PENDING_DISCARD_TIMEOUT_SECS, crate::network::epoch::MAX_ADAPTIVE_EPOCH_SECS);
        assert_ne!(PENDING_HARD_DISCARD_TIMEOUT_SECS, crate::network::epoch::MAX_ADAPTIVE_EPOCH_SECS);
        let workers_as_f64 = crate::network::state_core::MAX_STATE_CORE_WORKERS as f64;
        assert_ne!(PENDING_DISCARD_TIMEOUT_SECS, workers_as_f64);
        assert_ne!(PENDING_HARD_DISCARD_TIMEOUT_SECS, workers_as_f64);
        // Also disjoint from the beat-amount scaling constant
        // (BASE_UNITS_PER_BEAT=1e9) — wrong-dimension collisions in metric
        // logs would still be misleading.
        assert_ne!(PENDING_DISCARD_TIMEOUT_SECS as u64, BASE_UNITS_PER_BEAT);
        assert_ne!(PENDING_HARD_DISCARD_TIMEOUT_SECS as u64, BASE_UNITS_PER_BEAT);
    }

    /// Pin `CommitStats` default-zero shape, Clone independence, and the
    /// pairwise distinctness of its 4 u64 fields. Default-zero is
    /// load-bearing because `drain_and_commit_pending` returns
    /// `stats.committed += 1` style mutations on a `Default::default()`
    /// — if Default flipped any field to non-zero, every drain pass would
    /// over-report.
    #[test]
    fn batch_b_commit_stats_default_all_zero_clone_independence_and_four_field_pairwise_distinct() {
        // Default must zero ALL FOUR fields.
        let s = CommitStats::default();
        assert_eq!(s.committed, 0);
        assert_eq!(s.missing_record, 0);
        assert_eq!(s.missing_delta, 0);
        assert_eq!(s.apply_failed, 0);
        assert_eq!(s, CommitStats::default(), "Default must be reflexively equal");

        // Clone independence: 4 owned u64 fields — mutating clone must
        // not touch the base.
        let base = CommitStats {
            committed: 11,
            missing_record: 22,
            missing_delta: 33,
            apply_failed: 44,
            rederived: 55,
        };
        let mut cloned = base.clone();
        cloned.committed = 999;
        cloned.missing_record = 999;
        cloned.missing_delta = 999;
        cloned.apply_failed = 999;
        cloned.rederived = 999;
        assert_eq!(base.committed, 11);
        assert_eq!(base.missing_record, 22);
        assert_eq!(base.missing_delta, 33);
        assert_eq!(base.apply_failed, 44);
        assert_ne!(base, cloned);

        // Four-field pairwise distinctness: mutating each field
        // individually must produce a distinct value (i.e. no field is
        // a no-op shadow / no two fields are the SAME field under
        // different names).
        let z = CommitStats::default();
        let mut a = z.clone();
        a.committed = 1;
        let mut b = z.clone();
        b.missing_record = 1;
        let mut c = z.clone();
        c.missing_delta = 1;
        let mut d = z.clone();
        d.apply_failed = 1;
        let all = [&z, &a, &b, &c, &d];
        // All 5 (default + 4 single-bit-set) must be pairwise distinct.
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(
                    all[i], all[j],
                    "CommitStats single-field mutations must be pairwise distinct (i={i}, j={j})"
                );
            }
        }
    }

    /// Pin `SweepStats` default-zero shape, Clone independence, and the
    /// pairwise distinctness of its 2 u64 fields. The hot-loop sweep
    /// re-uses a `SweepStats::default()` per call and would over-report
    /// if Default became non-zero. Two-field distinctness keeps a future
    /// "let me rename hard_discarded for clarity" refactor from
    /// accidentally collapsing both counters into one.
    #[test]
    fn batch_b_sweep_stats_default_all_zero_clone_independence_and_two_field_pairwise_distinct() {
        let s = SweepStats::default();
        assert_eq!(s.discarded, 0);
        assert_eq!(s.hard_discarded, 0);
        assert_eq!(s, SweepStats::default());

        // Clone independence.
        let base = SweepStats {
            discarded: 17,
            hard_discarded: 29,
        };
        let mut cloned = base.clone();
        cloned.discarded = 999;
        cloned.hard_discarded = 999;
        assert_eq!(base.discarded, 17);
        assert_eq!(base.hard_discarded, 29);
        assert_ne!(base, cloned);

        // Two-field pairwise distinctness.
        let z = SweepStats::default();
        let mut a = z.clone();
        a.discarded = 1;
        let mut b = z.clone();
        b.hard_discarded = 1;
        assert_ne!(z, a);
        assert_ne!(z, b);
        assert_ne!(
            a, b,
            "discarded and hard_discarded MUST be distinct fields, not aliases"
        );
    }

    /// Pin `Debug` output for both stats structs to anchor field-name
    /// invariants AND field-name disjointness across the two structs.
    /// Operator dashboards / log lines display the Debug form (or rebuild
    /// from it via `format!("{stats:?}")` in tracing macros); a field
    /// rename in either struct would silently change every grep query
    /// pointed at production logs. Disjointness matters because both
    /// structs feed the same operator surface (one drain tick produces
    /// `CommitStats`; one sweep tick produces `SweepStats`) — a future
    /// PR that gave both structs a `discarded` field would render two
    /// identically-named columns.
    #[test]
    fn batch_b_commit_sweep_stats_debug_shape_field_names_pinned_and_pairwise_disjoint() {
        let cs = CommitStats {
            committed: 1,
            missing_record: 2,
            missing_delta: 3,
            apply_failed: 4,
            rederived: 7,
        };
        let ss = SweepStats {
            discarded: 5,
            hard_discarded: 6,
        };
        let cs_dbg = format!("{cs:?}");
        let ss_dbg = format!("{ss:?}");

        // Struct-name prefix pinned (Debug-derived shape).
        assert!(cs_dbg.starts_with("CommitStats"), "got: {cs_dbg}");
        assert!(ss_dbg.starts_with("SweepStats"), "got: {ss_dbg}");

        // All 5 CommitStats field names appear verbatim.
        for fname in ["committed", "missing_record", "missing_delta", "apply_failed", "rederived"] {
            assert!(
                cs_dbg.contains(fname),
                "CommitStats Debug missing field name `{fname}`: {cs_dbg}"
            );
        }
        // Both SweepStats field names appear verbatim.
        for fname in ["discarded", "hard_discarded"] {
            assert!(
                ss_dbg.contains(fname),
                "SweepStats Debug missing field name `{fname}`: {ss_dbg}"
            );
        }

        // Disjointness: none of CommitStats's 4 field names appear in
        // SweepStats's Debug form, and vice versa (after stripping the
        // struct-name prefix to avoid false-positive on substring
        // "Stats"). A future PR that added e.g. `discarded` to
        // CommitStats would trip this.
        let cs_body = cs_dbg.trim_start_matches("CommitStats");
        let ss_body = ss_dbg.trim_start_matches("SweepStats");
        for fname in ["committed", "missing_record", "missing_delta", "apply_failed"] {
            assert!(
                !ss_body.contains(fname),
                "field-name collision: `{fname}` is a CommitStats field but also appears in SweepStats Debug: {ss_dbg}"
            );
        }
        // Note: "discarded" is a substring of "hard_discarded" so we
        // can't naively test it doesn't appear in cs_body — instead we
        // check the full "hard_discarded" doesn't appear (proper field
        // name), and that "discarded" doesn't appear as a standalone
        // field by checking the SweepStats fields are NOT in CommitStats.
        for fname in ["discarded:", "hard_discarded"] {
            assert!(
                !cs_body.contains(fname),
                "field-name collision: `{fname}` is a SweepStats field but also appears in CommitStats Debug: {cs_dbg}"
            );
        }
    }

    /// Runtime-replicate the file-level `const _: () = assert!(…)`
    /// invariants. The compile-time asserts catch a regression at build
    /// time, but a future PR that deletes BOTH the const_assert AND the
    /// constant invariants (e.g. "let me simplify by deleting these — the
    /// runtime tests pass anyway") would slip through review unless the
    /// runtime suite carries an explicit copy. This belt-and-suspenders
    /// matters because the sweep cutoff math (`now - t > TIMEOUT`)
    /// silently misbehaves if `TIMEOUT` becomes 0 (reaps everything) or
    /// HARD < SOFT (skip the spare-Sealed guard).
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_pending_drain_const_assert_runtime_mirror_for_defence_in_depth() {
        // Mirror const _: () = assert!(PENDING_DISCARD_TIMEOUT_SECS > 0.0);
        assert!(PENDING_DISCARD_TIMEOUT_SECS > 0.0);
        // Mirror const _: () = assert!(PENDING_HARD_DISCARD_TIMEOUT_SECS > 0.0);
        assert!(PENDING_HARD_DISCARD_TIMEOUT_SECS > 0.0);
        // Mirror const _: () = assert!(PENDING_HARD_DISCARD_TIMEOUT_SECS > PENDING_DISCARD_TIMEOUT_SECS);
        assert!(PENDING_HARD_DISCARD_TIMEOUT_SECS > PENDING_DISCARD_TIMEOUT_SECS);

        // Defence-in-depth: also pin NaN/Inf rejection (a regression to
        // `f64::NAN` would slip through `> 0.0` since NaN comparisons
        // all return false, but the compile-time const_assert above
        // would catch it first — this is the runtime double-check).
        assert!(!PENDING_DISCARD_TIMEOUT_SECS.is_nan());
        assert!(!PENDING_HARD_DISCARD_TIMEOUT_SECS.is_nan());
        assert!(PENDING_DISCARD_TIMEOUT_SECS.is_finite());
        assert!(PENDING_HARD_DISCARD_TIMEOUT_SECS.is_finite());
        // Subnormal-rejection (a subnormal f64 close to 0 would pass
        // `> 0.0` but be effectively zero in any arithmetic):
        assert!(PENDING_DISCARD_TIMEOUT_SECS.is_normal());
        assert!(PENDING_HARD_DISCARD_TIMEOUT_SECS.is_normal());
    }
}
