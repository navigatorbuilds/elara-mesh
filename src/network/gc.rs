//! Garbage collection — prune expired and old finalized records.
//!
//! Records with an `expires` metadata field are pruned after their deadline.
//! Additionally, finalized records older than the retention period are pruned.
//! Non-finalized records are never pruned (safety invariant).
//!
//! The GC loop runs periodically when enabled (gc_interval_secs > 0).

//!
//! Spec references:
//!   @spec Protocol §11.8

use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::errors::Result;
use crate::record::ValidationRecord;

#[cfg(feature = "node-core")]
use super::LockRecover;
use crate::storage::Storage;

use super::state::NodeState;

/// Metadata key for record expiration timestamp.
pub const EXPIRES_KEY: &str = "expires";

/// Default retention period for finalized records: 7 days in seconds.
pub const DEFAULT_RETENTION_SECS: f64 = 7.0 * 24.0 * 3600.0;

/// Result of a single GC cycle.
#[derive(Debug, Clone, Default)]
pub struct GcResult {
    /// Records pruned because their `expires` timestamp passed.
    pub expired_pruned: u64,
    /// Records pruned because they were finalized + older than retention.
    pub retention_pruned: u64,
    /// Records pruned because they were sunken (low relevance, EMERGENT-MIND §3).
    pub sunken_pruned: u64,
    /// Records pruned because they were stale (unfinalized + older than 2x retention).
    pub stale_pruned: u64,
    /// Gap 3: per-zone epoch seals pruned because a covering super-seal exists
    /// AND the seal's epoch is below the per-zone safety floor. Super-seals,
    /// zone_transition records, and global seals are NEVER counted here — they
    /// are integrity-critical and never prunable.
    pub seal_pruned: u64,
    /// Tier 3.4 (Protocol §11.8): finalized records pruned because their
    /// per-zone epoch has already been super-sealed (timestamp older than the
    /// zone's `record_pruning_floor_ts` = end-time of the seal at
    /// `latest_super_seal.end_epoch − 2 × SUPER_SEAL_INTERVAL`). The seal's
    /// Merkle root + record hashes preserve verifiability without the body.
    /// Distinct from `retention_pruned` (time-based) and `seal_pruned`
    /// (the seals themselves). Ledger-ops, governance-ops, seals, and
    /// non-finalized records are NEVER counted here.
    pub epoch_pruned: u64,
    /// Records skipped (not finalized, can't prune).
    pub skipped: u64,
    /// IDs of deleted records — used by caller to update in-memory DAG index.
    pub deleted_ids: Vec<String>,
    /// Set when the timestamp-index scan hit `MAX_GC_SCAN_PER_CYCLE` and
    /// broke early. The caller (`gc_loop`) should schedule the next cycle
    /// quickly (drain-mode) rather than wait the full `gc_interval_secs`,
    /// because there is still eligible-but-unscanned old data on disk.
    /// Surfaced as `elara_gc_scan_capped_total` for operator visibility.
    pub scan_capped: bool,
    /// Last `CF_IDX_TIMESTAMP` key the scan consumed before `scan_capped`
    /// fired. When `Some`, the next cycle resumes from this key (instead of
    /// the start of the index), which prevents an unbounded head of
    /// non-prunable records (ledger-ops, governance-ops) from re-blocking the
    /// same first 5_000 slots forever. Cleared (`None`) on a natural
    /// `ts > scan_until` break so the next cycle re-scans from the top to
    /// catch out-of-order inserts.
    pub last_scanned_key: Option<Vec<u8>>,
}

/// Check if a record has expired based on its metadata.
pub fn is_expired(record: &ValidationRecord, now: f64) -> bool {
    record
        .metadata
        .get(EXPIRES_KEY)
        .and_then(|v| v.as_f64())
        .is_some_and(|expires_at| now >= expires_at)
}

/// Run one GC pass: scan storage, identify prunable records, delete them.
///
/// Safety rules:
/// - Records with `expires` < now AND finalized → prune
/// - Finalized records older than `retention_cutoff` → prune
/// - Non-finalized records are NEVER pruned
/// - Epoch seal records are NEVER pruned (protocol integrity)
/// - Ledger op records are NEVER pruned (ledger integrity)
///
/// Protocol §11.8: epoch-based pruning — finalized records can be pruned
/// after their epoch is sealed. The epoch seal's Merkle root preserves
/// verifiability without the full records.
pub fn gc_pass(
    storage: &mut dyn Storage,
    finalized: &std::collections::HashSet<String>,
    dag: &mut crate::dag::DagIndex,
    now: f64,
    retention_secs: f64,
) -> Result<GcResult> {
    let retention_cutoff = now - retention_secs;
    // Scan records older than retention cutoff for retention-based pruning.
    // The timestamp index (CF_IDX_TIMESTAMP) makes this efficient — only
    // iterates old records, not the entire database.
    // Note: we use `until` to limit to old records. Records with explicit
    // `expires` metadata that are newer won't be caught here — they'll be
    // caught by the next scan. For testnet-scale this is fine; at production
    // scale, explicit expiration should be a separate index.
    // Bounded batch: process up to 50K records per GC cycle.
    // At 10M old records, usize::MAX would load all into memory (~20GB).
    // Cursor-based: next cycle picks up where this one left off via timestamp ordering.
    const GC_BATCH: usize = 50_000;
    let all_records = if retention_cutoff > 0.0 {
        storage.query(None, None, None, Some(retention_cutoff), GC_BATCH)?
    } else {
        storage.query(None, None, None, None, GC_BATCH)?
    };

    let mut result = GcResult::default();
    let mut to_delete: Vec<String> = Vec::new();

    for record in &all_records {
        // Never prune epoch seals — they're the integrity backbone
        if record.metadata.contains_key(super::epoch::EPOCH_OP_KEY) {
            continue;
        }

        // Never prune ledger operations — ledger depends on them
        if record.metadata.contains_key(crate::accounting::types::BEAT_OP_KEY) {
            continue;
        }

        // Never prune governance operations
        if record.metadata.contains_key(crate::accounting::governance::GOVERNANCE_OP_KEY) {
            continue;
        }

        // Never prune agent-mandate issuance / revocation carriers (C4 slice 1):
        // the carrier record is the cryptographic proof the principal signed the
        // mandate/revocation. Pruning it at retention would leave the registry
        // entry with no surviving proof of authorization.
        if record.metadata.contains_key(crate::mandate::MANDATE_OP_KEY)
            || record.metadata.contains_key(crate::mandate::MANDATE_REVOCATION_OP_KEY)
        {
            continue;
        }
        // Never prune emergency halt/resume carriers — the carrier is the signed
        // proof of the circuit-breaker action (audit trail + replay re-derivation).
        if record.metadata.contains_key(crate::emergency::EMERGENCY_HALT_OP_KEY)
            || record.metadata.contains_key(crate::emergency::EMERGENCY_RESUME_OP_KEY)
        {
            continue;
        }

        let is_finalized = finalized.contains(&record.id);

        // Check explicit expiration
        if is_expired(record, now) {
            if is_finalized {
                to_delete.push(record.id.clone());
                result.expired_pruned += 1;
            } else {
                result.skipped += 1;
            }
            continue;
        }

        // Check retention period (finalized + old enough)
        if is_finalized && record.timestamp < retention_cutoff {
            to_delete.push(record.id.clone());
            result.retention_pruned += 1;
            continue;
        }
    }

    // Delete identified records
    for id in &to_delete {
        if let Err(e) = storage.delete(id) {
            warn!("gc: failed to delete record {}: {e}", &id[..id.len().min(16)]);
        } else {
            dag.remove(id);
        }
    }

    Ok(result)
}

/// Run one GC pass using a StorageEngine reference directly.
/// Same logic as gc_pass but avoids the &mut dyn Storage requirement.
#[cfg(feature = "node-core")]
pub fn gc_pass_rocks(
    rocks: &crate::storage::rocks::StorageEngine,
    finalized: &std::collections::HashSet<String>,
    dag: &mut crate::dag::DagIndex,
    now: f64,
    retention_secs: f64,
    sunken_ids: &std::collections::HashSet<String>,
) -> Result<GcResult> {
    gc_pass_rocks_with(rocks, |id| finalized.contains(id), dag, now, retention_secs, sunken_ids)
}

/// Run one GC pass with a custom finalized-check function.
/// Used by the GC loop with the disk-backed FinalizedIndex.
#[cfg(feature = "node-core")]
pub fn gc_pass_rocks_with(
    rocks: &crate::storage::rocks::StorageEngine,
    is_finalized: impl Fn(&str) -> bool,
    dag: &mut crate::dag::DagIndex,
    now: f64,
    retention_secs: f64,
    sunken_ids: &std::collections::HashSet<String>,
) -> Result<GcResult> {
    use crate::storage::Storage;
    let retention_cutoff = now - retention_secs;
    // Bounded batch: 50K records per cycle. Multiple cycles drain the backlog.
    const GC_BATCH: usize = 50_000;
    let all_records = if retention_cutoff > 0.0 {
        rocks.query(None, None, None, Some(retention_cutoff), GC_BATCH)?
    } else {
        rocks.query(None, None, None, None, GC_BATCH)?
    };

    let mut result = GcResult::default();
    let mut to_delete: Vec<String> = Vec::new();

    for record in &all_records {
        if record.metadata.contains_key(super::epoch::EPOCH_OP_KEY) {
            continue;
        }
        if record.metadata.contains_key(crate::accounting::types::BEAT_OP_KEY) {
            continue;
        }
        if record.metadata.contains_key(crate::accounting::governance::GOVERNANCE_OP_KEY) {
            continue;
        }
        // Agent-mandate carriers (C4 slice 1) — see the in-memory gc_pass twin.
        if record.metadata.contains_key(crate::mandate::MANDATE_OP_KEY)
            || record.metadata.contains_key(crate::mandate::MANDATE_REVOCATION_OP_KEY)
        {
            continue;
        }
        // Never prune emergency halt/resume carriers — the carrier is the signed
        // proof of the circuit-breaker action (audit trail + replay re-derivation).
        if record.metadata.contains_key(crate::emergency::EMERGENCY_HALT_OP_KEY)
            || record.metadata.contains_key(crate::emergency::EMERGENCY_RESUME_OP_KEY)
        {
            continue;
        }

        let finalized = is_finalized(&record.id);

        if is_expired(record, now) {
            if finalized {
                to_delete.push(record.id.clone());
                result.expired_pruned += 1;
            } else {
                result.skipped += 1;
            }
            continue;
        }

        // Sunken records: low relevance, finalized → eligible for early GC (EMERGENT-MIND §3)
        if finalized && sunken_ids.contains(&record.id) {
            to_delete.push(record.id.clone());
            result.sunken_pruned += 1;
            continue;
        }

        if finalized && record.timestamp < retention_cutoff {
            to_delete.push(record.id.clone());
            result.retention_pruned += 1;
            continue;
        }
    }

    for id in &to_delete {
        // GcPrune (B5): retention GC preserves the mandate-act index so a pruned
        // act still answers an authoritative /mandate/status.
        if let Err(e) = rocks.delete_record(id, crate::storage::rocks::DeleteIntent::GcPrune) {
            warn!("gc: failed to delete record {}: {e}", &id[..id.len().min(16)]);
        } else {
            dag.remove(id);
        }
    }

    Ok(result)
}

/// B5: the compressible disk cap the GC size governor drives against — the raw
/// `disk_cap` minus the GC-EXEMPT mandate mass (`exempt`), saturating, floored at
/// a 1 GiB minimum so exempt mass can never collapse the effective cap to zero
/// and livelock record retention at the 1h floor (MINOR-1). `disk_cap == 0` (size
/// governor disabled) passes through as 0. Pure — unit-tested independently of a
/// live RocksDB.
pub(crate) fn effective_disk_cap(disk_cap: u64, exempt: u64) -> u64 {
    const MIN_COMPRESSIBLE_CAP: u64 = 1024 * 1024 * 1024; // 1 GiB
    if disk_cap == 0 {
        return 0;
    }
    disk_cap.saturating_sub(exempt).max(MIN_COMPRESSIBLE_CAP)
}

/// Background GC loop. Runs periodically when gc_interval_secs > 0.
#[cfg(feature = "node-core")]
pub async fn gc_loop(
    state: Arc<NodeState>,
    mut shutdown: tokio::sync::watch::Receiver<()>,
    hb: Arc<super::supervision::LoopStatus>,
) {
    let interval_secs = state.config.gc_interval_secs;
    if interval_secs == 0 {
        debug!("gc loop disabled (interval=0)");
        return;
    }

    // Stage 2D: retention is profile-driven. Light=72h, FullZone=90d,
    // Archive=∞ (no retention-based pruning). Unknown / empty profile string
    // falls back to the operator-configured `record_retention_secs`.
    let retention_secs = super::node_profile::effective_retention_secs(
        &state.config.node_profile,
        state.config.record_retention_secs,
    );
    let interval = Duration::from_secs(interval_secs);
    let retention_display = if retention_secs >= super::node_profile::ARCHIVE_RETENTION_SECS - 1.0 {
        "~∞ (archive)".to_string()
    } else {
        format!("{}d", retention_secs / 86400.0)
    };
    info!(
        "gc loop started (every {}s, profile={}, retention={})",
        interval_secs, state.config.node_profile, retention_display
    );

    let mut gc_cycle: u64 = 0;
    let mut deletes_since_compact: u64 = 0;
    // SCALE RULE drain interval: when the last cycle hit `MAX_GC_SCAN_PER_CYCLE`
    // we still have eligible records on disk. Sleeping the full
    // `gc_interval_secs` would queue more backlog than we just chewed; sleep
    // 10 s instead until the backlog drains. Calibration: a
    // single capped cycle handles ~5_000 candidates in <3 s, so 10 s of slack
    // is one part work / two parts ingest catch-up.
    const DRAIN_INTERVAL: Duration = Duration::from_secs(10);
    let mut drain_mode = false;
    // Persist the last scanned key across cycles
    // so a scan-cap break resumes from where it stopped instead of re-walking
    // the same head-of-index records (ledger-ops never prune; without this,
    // 5_000 ledger-ops at the front of CF_IDX_TIMESTAMP keep the iterator
    // stuck on slot #1 forever and `gc_pruned_total` stays at 0 even though
    // older non-ledger records exist behind them).
    let mut gc_resume_key: Option<Vec<u8>> = None;

    loop {
        let sleep_for = if drain_mode { DRAIN_INTERVAL } else { interval };
        tokio::select! {
            _ = tokio::time::sleep(sleep_for) => {}
            _ = shutdown.changed() => {
                debug!("gc loop shutting down");
                return;
            }
        }
        hb.heartbeat(); // hang-detection: stamp each cycle (≤300s interval « 1200s stale_after)

        // Stage 6 cooperative scheduler (Protocol §11.10): GC scans CFs +
        // RocksDB compaction; high CPU/IO impact under saturation.
        super::system_load::coop_yield_if_busy(&state.system_load).await;

        // Timestamp the start of this cycle for the duration gauge.
        let cycle_start = std::time::Instant::now();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        // Compute sunken record IDs from relevance tracker (EMERGENT-MIND §3)
        let sunken_ids: std::collections::HashSet<String> = {
            let relevance = state.relevance.lock_recover();
            relevance.sunken_records(now).into_iter().collect()
        };

        // Stage 6.5: size-based retention (Protocol §11.8, MAINNET MANDATE).
        // If total live on-disk bytes exceed `disk_cap_bytes`, shrink the
        // effective retention window proportionally so finalized records
        // drain off before the disk fills. O(1) — no full scan, no per-record
        // accounting. Bounded below at 1 hour so we never collapse retention
        // to zero mid-incident. Cap = 0 disables size-based retention.
        let disk_cap = state.config.disk_cap_bytes;
        // B5: subtract the GC-EXEMPT mandate mass (act index + registry) from the
        // cap. The governor can only compress record retention — never the mandate
        // CFs — so counting them would drive it to livelock retention at the 1h
        // floor chasing bytes it can't reclaim (MINOR-1). Saturating; floored at a
        // 1 GiB minimum compressible allowance so exempt mass can't collapse the
        // effective cap to zero. `total_live_bytes()` already excludes the mandate
        // CFs, so it is exactly the compressible numerator. The acts_budget clamp
        // (≤25% of disk_cap) keeps this subtraction well above the 1 GiB floor.
        let effective_cap = effective_disk_cap(disk_cap, state.rocks.exempt_live_bytes());
        let live_bytes = if effective_cap > 0 { state.rocks.total_live_bytes() } else { 0 };
        let (retention_secs, size_pressure) = if effective_cap > 0 && live_bytes > effective_cap {
            let shrink = (effective_cap as f64) / (live_bytes as f64); // (0, 1)
            let compressed = (retention_secs * shrink).max(3600.0); // floor: 1h
            (compressed, true)
        } else {
            (retention_secs, false)
        };
        if size_pressure {
            info!(
                "gc: disk cap pressure — live_bytes={:.1}GB effective_cap={:.1}GB \
                 (disk_cap={:.1}GB − exempt {:.1}GB) → compressed retention={}h",
                live_bytes as f64 / 1e9,
                effective_cap as f64 / 1e9,
                disk_cap as f64 / 1e9,
                state.rocks.exempt_live_bytes() as f64 / 1e9,
                retention_secs / 3600.0,
            );
        }

        // Streaming GC: iterate timestamp index, check one record at a time,
        // delete eligible records without loading all into a Vec.
        let retention_cutoff = now - retention_secs;
        // Stale cutoff: 2x retention. Unfinalized records older than this are
        // abandoned (never got witnessed) and safe to prune.
        let stale_cutoff = now - (retention_secs * 2.0);

        // Gap 3: per-zone seal pruning floor — derived from the latest
        // super-seal end_epoch minus 2× the super-seal interval. Seals
        // older than this floor have a covering super-seal AND are far
        // enough behind the head that lagging light clients have already
        // had at least one super-seal worth of grace to fetch them.
        // Archive nodes intentionally compute the floor too — but with
        // their effectively-infinite retention, the standard
        // `record.timestamp < retention_cutoff` gate keeps seals on disk
        // forever even when they're prunable by the super-seal rule.
        let seal_pruning_floor: std::collections::HashMap<crate::ZoneId, u64> = {
            use crate::network::RwLockRecover;
            let epoch = state.epoch.read_recover();
            const SAFETY_MARGIN_INTERVALS: u64 = 2;
            let safety_margin =
                SAFETY_MARGIN_INTERVALS.saturating_mul(super::epoch::SUPER_SEAL_INTERVAL);
            epoch
                .latest_super_seal
                .iter()
                .map(|(zone, (end_epoch, _, _, _))| {
                    (zone.clone(), end_epoch.saturating_sub(safety_margin))
                })
                .collect()
        };

        // Tier 3.4 (Protocol §11.8): per-zone record pruning floor — TIMESTAMP
        // (not epoch) below which finalized non-seal records are covered by a
        // super-seal Merkle root. Computed by looking up the seal record at
        // `(zone, floor_epoch)` and reading its timestamp. Records older than
        // this in the same zone are prunable EVEN IF they haven't aged out the
        // time-based retention window — the seal preserves verifiability.
        //
        // Disabled when (a) operator config off, (b) Archive profile (which
        // intentionally keeps all records on disk for historical query), or
        // (c) zone has no super-seal yet. Each branch falls back to the
        // existing time-based retention.
        let epoch_pruning_active = state.config.epoch_pruning_enabled
            && state.config.node_profile != "archive";
        let record_pruning_floor_ts: std::collections::HashMap<crate::ZoneId, f64> = if epoch_pruning_active {
            seal_pruning_floor
                .iter()
                .filter_map(|(zone, floor_epoch)| {
                    state
                        .rocks
                        .seal_timestamp_at_zone_epoch(*floor_epoch, zone.path())
                        .map(|ts| (zone.clone(), ts))
                })
                .collect()
        } else {
            std::collections::HashMap::new()
        };

        let result = {
            let state2 = state.clone();
            let floor = seal_pruning_floor.clone();
            let record_floor = record_pruning_floor_ts.clone();
            let resume = gc_resume_key.clone();
            match tokio::task::spawn_blocking(move || {
                state2.rocks.gc_scan_and_delete(
                    retention_cutoff,
                    stale_cutoff,
                    // Per-candidate bloom-filtered CF_METADATA point read
                    // (~1µs), bounded by the scan cap — replaces the eager
                    // `to_hashset()` snapshot, which walked the ENTIRE
                    // `finalized:*` history under finalized.read() every
                    // cycle and stalled finalization writers for the scan.
                    // Live reads are also strictly safer than a snapshot:
                    // finalization is monotonic, so a record finalized
                    // mid-scan reads as finalized (kept), never as
                    // stale-unfinalized (pruned).
                    &|id| crate::network::finalized::contains_in_rocks(&state2.rocks, id),
                    &|id| sunken_ids.contains(id),
                    &floor,
                    &record_floor,
                    resume.as_deref(),
                )
            })
            .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    warn!("gc pass failed: {e}");
                    continue;
                }
                Err(e) => {
                    warn!("gc spawn_blocking failed: {e}");
                    continue;
                }
            }
        };

        gc_cycle += 1;
        let total = result.expired_pruned
            + result.retention_pruned
            + result.sunken_pruned
            + result.stale_pruned
            + result.seal_pruned
            + result.epoch_pruned;
        deletes_since_compact += total;

        // Remove deleted records from in-memory DAG (batched to avoid starving readers).
        // Use try_write to avoid blocking state_core's dag.write().
        if !result.deleted_ids.is_empty() {
            const DAG_REMOVE_BATCH: usize = 100;
            for chunk in result.deleted_ids.chunks(DAG_REMOVE_BATCH) {
                if let Ok(mut dag_guard) = state.dag.try_write() {
                    let dag = std::sync::Arc::make_mut(&mut *dag_guard);
                    for id in chunk {
                        dag.remove(id);
                    }
                } else {
                    tracing::debug!("gc: DAG contended, deferring batch removal");
                    break; // Will catch up on next GC cycle
                }
                // Lock released between batches — readers can proceed
            }
        }

        // B5: per-cycle act-index budget evictor tick. Trims the OLDEST acts when
        // the act-CF mass exceeds `acts_budget_bytes` (0 = unlimited, e.g. the
        // archive profile). Bounded (≤ACTS_EVICT_PER_TICK via the time index) and
        // NEVER rejects ingest — over-budget nodes still accept sealed act records;
        // this trims the tail and advances the coverage floor. spawn_blocking:
        // bounded iteration + one batch write, off the async executor.
        {
            const ACTS_EVICT_PER_TICK: usize = 5000;
            let budget = state.config.acts_budget_bytes;
            if budget > 0 {
                let state_ev = state.clone();
                match tokio::task::spawn_blocking(move || {
                    state_ev.rocks.evict_acts_over_budget(budget, ACTS_EVICT_PER_TICK)
                })
                .await
                {
                    Ok(Ok(n)) if n > 0 => info!(
                        "gc: B5 act-budget evictor trimmed {n} oldest act entries (budget={:.2}GB)",
                        budget as f64 / 1e9
                    ),
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => warn!("gc: act-budget evictor failed: {e}"),
                    Err(e) => warn!("gc: act-budget evictor spawn_blocking failed: {e}"),
                }
            }
        }

        if total > 0 {
            info!(
                "gc: pruned {} records (expired={}, retention={}, sunken={}, stale={}, seal={}, epoch={}), skipped={}",
                total,
                result.expired_pruned,
                result.retention_pruned,
                result.sunken_pruned,
                result.stale_pruned,
                result.seal_pruned,
                result.epoch_pruned,
                result.skipped
            );
        }

        // Clean up relevance tracking for ALL pruned records, using the
        // pruned-ID set the GC already produced — not a second sunken_records()
        // re-scan. The old re-scan only removed *sunken*-pruned entries, so
        // records pruned for retention/stale/expired/seal/epoch reasons leaked
        // their relevance entries forever (audit 16g). It was also a redundant
        // O(N_tracker) HashMap walk and carried a race (a record re-tracked by
        // concurrent ingest between the prune and the re-scan could be wrongly
        // removed). Iterating deleted_ids is O(pruned) (≤ MAX_GC_SCAN_PER_CYCLE)
        // and race-free: a concurrently re-tracked live entry cannot be in this
        // cycle's deleted_ids. Under scan_capped drain mode this removes only
        // the batch actually pruned this cycle, which is exactly right.
        if !result.deleted_ids.is_empty() {
            let mut relevance = state.relevance.lock_recover();
            for id in &result.deleted_ids {
                relevance.remove(id);
            }
        }

        state.gc_pruned_total.fetch_add(total, Relaxed);

        // Epoch-based-pruning observability: fan out the
        // GcResult breakdown into per-reason counters so dashboards can
        // attribute pressure (retention=baseline, stale=consensus regression,
        // sunken=relevance shedding, expired=explicit-TTL). Existing
        // gc_pruned_total preserved for backward compat.
        state.gc_pruned_expired_total.fetch_add(result.expired_pruned, Relaxed);
        state.gc_pruned_retention_total.fetch_add(result.retention_pruned, Relaxed);
        state.gc_pruned_sunken_total.fetch_add(result.sunken_pruned, Relaxed);
        state.gc_pruned_stale_total.fetch_add(result.stale_pruned, Relaxed);
        state.gc_pruned_seals_total.fetch_add(result.seal_pruned, Relaxed);
        state.gc_pruned_epoch_total.fetch_add(result.epoch_pruned, Relaxed);

        // Cycle counter + duration + completion timestamp gauge for
        // GC liveness ("did GC run? how long did it take?"). Timestamp is
        // integer seconds — Prometheus gauges accept f64 but we want a
        // round Unix ts that aligns with `time()` on dashboards.
        state.gc_cycles_total.fetch_add(1, Relaxed);
        let dur_ms = cycle_start.elapsed().as_millis().min(u64::MAX as u128) as u64;
        state.gc_last_cycle_duration_ms.store(dur_ms, Relaxed);
        state.gc_last_cycle_unix_ts.store(now as u64, Relaxed);

        // Bloat fix: if `gc_scan_and_delete` hit
        // `MAX_GC_SCAN_PER_CYCLE` we have more eligible records on disk than
        // one cycle could chew. Flip to drain mode so the next loop iteration
        // wakes after `DRAIN_INTERVAL` instead of the full `gc_interval_secs`;
        // bump the visibility counter either way so operators can see the
        // backlog clearing in real time.
        //
        // Carry `last_scanned_key` into the next call
        // so the resumed scan begins past the previous stop point. Clearing
        // the resume key on a natural break (`scan_capped == false`) means
        // the next pass starts at the head of the index again — keeps the
        // out-of-order-insert recovery window bounded by one full drain.
        if result.scan_capped {
            state.gc_scan_capped_total.fetch_add(1, Relaxed);
            drain_mode = true;
            gc_resume_key = result.last_scanned_key;
        } else {
            drain_mode = false;
            gc_resume_key = None;
        }

        // Prune orphan edges in the DAG — parents that never arrived
        // will accumulate forever without this cap.
        // Cap scales by RAM: 2GB→2K, 4GB→5K, >4GB→10K.
        // Use try_write to avoid blocking state_core.
        if let Ok(mut dag_guard) = state.dag.try_write() {
            let dag = std::sync::Arc::make_mut(&mut *dag_guard);
            let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();
            let orphan_cap = if ram_gb <= 2 { 2_000 } else if ram_gb <= 4 { 5_000 } else { 10_000 };
            let pruned = dag.prune_orphan_edges(orphan_cap);
            if pruned > 0 {
                info!("gc: pruned {pruned} stale orphan DAG edges (cap={orphan_cap}, {}GB RAM)", ram_gb);
            }
        } else {
            tracing::debug!("gc: DAG contended, deferring orphan prune");
        }

        // Compact RocksDB to reclaim SST file space from tombstones.
        //
        // Three triggers, OR-combined:
        //   (a) Periodic — every 12 cycles (~1h at 5-min interval) if any
        //       deletes accumulated. Steady-state path: GC normally prunes
        //       2-3 records/cycle, batching tombstones an hour at a time
        //       avoids constant compaction I/O.
        //   (b) Burst — whenever `deletes_since_compact` crosses
        //       `COMPACT_BURST_THRESHOLD`. After a retention
        //       tightening, profile change, or initial cleanup, one cycle
        //       can prune tens of thousands of records. Sitting on those
        //       tombstones for 55 more minutes while disk_pressure=1 keeps
        //       rejecting ingests is the wrong tradeoff — once the batch
        //       is big enough to materially move disk, compact NOW.
        //   (c) Disk pressure — whenever `state.disk_pressure` is active,
        //       compact every cycle. Disk pressure means ingest is being
        //       rejected in real time; the node MUST reclaim SST space
        //       even if no fresh deletes happened this cycle (the
        //       tombstones may be from a prior boot's GC pass — counters
        //       reset on restart, so without this the cycle-12 timer has
        //       to elapse anew while the node continues rejecting writes).
        //       Compaction I/O is cheap compared to a non-functional node.
        //
        // Threshold of 5000 chosen empirically: large enough that steady-
        // state never hits it (2-3 records/cycle × 12 cycles = ~36
        // deletes), small enough that any "real" cleanup event compacts
        // within one cycle.
        const COMPACT_BURST_THRESHOLD: u64 = 5000;
        let compact_every = 12; // ~1 hour at 5-min GC interval
        let periodic_due = gc_cycle.is_multiple_of(compact_every) && deletes_since_compact > 0;
        let burst_due = deletes_since_compact >= COMPACT_BURST_THRESHOLD;
        let pressure_due = state.under_disk_pressure();
        if periodic_due || burst_due || pressure_due {
            let rocks = state.rocks.clone();
            let state2 = state.clone();
            let n = deletes_since_compact;
            let trigger = if pressure_due {
                "disk-pressure"
            } else if burst_due {
                "burst"
            } else {
                "periodic"
            };
            deletes_since_compact = 0;
            // 2026-05-17 fleet-bloat fix: compact every CF that delete_record
            // touches, not just records/attestations/dag/idx_timestamp. The
            // delete_touched_cfs() list lives in rocks.rs adjacent to
            // delete_record() so the two stay in sync.
            tokio::task::spawn_blocking(move || {
                info!("gc: {trigger} compaction (deletes_since_compact={n})");
                rocks.compact_post_gc();
                state2.gc_compactions_total.fetch_add(1, Relaxed);
                info!("gc: {trigger} compaction complete");
            });
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashSet};

    use crate::dag::DagIndex;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::record::Classification;
    use crate::storage::rocks::StorageEngine;
    use crate::storage::Storage;

    #[test]
    fn governor_exempt_arithmetic() {
        // B5 MINOR-1: effective_cap = saturating(disk_cap − exempt), floored at
        // 1 GiB, and disk_cap==0 disables the governor.
        const GIB: u64 = 1024 * 1024 * 1024;
        // Normal case: exempt subtracted straight.
        assert_eq!(effective_disk_cap(200 * GIB, 8 * GIB), 192 * GIB);
        // No exempt mass → unchanged.
        assert_eq!(effective_disk_cap(200 * GIB, 0), 200 * GIB);
        // Exempt exceeds cap → saturates, floored at the 1 GiB minimum
        // (never zero, never underflow → no retention livelock at 0).
        assert_eq!(effective_disk_cap(4 * GIB, 100 * GIB), GIB);
        // Subtraction landing below the floor is lifted to the floor.
        assert_eq!(effective_disk_cap(3 * GIB, 2 * GIB + 512 * 1024 * 1024), GIB);
        // Governor disabled passes through as 0 (not floored to 1 GiB).
        assert_eq!(effective_disk_cap(0, 5 * GIB), 0);
    }

    fn test_identity() -> Identity {
        Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap()
    }

    fn test_engine() -> (StorageEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();
        (engine, dir)
    }

    fn insert_record(
        storage: &mut StorageEngine,
        dag: &mut DagIndex,
        identity: &Identity,
        content: &[u8],
        timestamp: f64,
        metadata: Option<BTreeMap<String, serde_json::Value>>,
    ) -> ValidationRecord {
        let mut record = ValidationRecord::create(
            content,
            identity.public_key.clone(),
            vec![],
            Classification::Public,
            metadata,
        );
        record.timestamp = timestamp;
        let signable = record.signable_bytes();
        record.signature = Some(identity.sign(&signable).unwrap());
        use crate::storage::Storage;
        storage.insert(&record).unwrap();
        let _ = dag.insert(record.id.clone(), record.parents.clone(), record.timestamp);
        record
    }

    // ── is_expired ────────────────────────────────────────────────────

    #[test]
    fn test_is_expired_no_field() {
        let id = test_identity();
        let record = ValidationRecord::create(b"data", id.public_key.clone(), vec![], Classification::Public, None);
        assert!(!is_expired(&record, 999999.0));
    }

    #[test]
    fn test_is_expired_future() {
        let id = test_identity();
        let mut meta = BTreeMap::new();
        meta.insert(EXPIRES_KEY.into(), serde_json::json!(2000000.0));
        let record = ValidationRecord::create(b"data", id.public_key.clone(), vec![], Classification::Public, Some(meta));
        assert!(!is_expired(&record, 1000000.0)); // expires in the future
    }

    #[test]
    fn test_is_expired_past() {
        let id = test_identity();
        let mut meta = BTreeMap::new();
        meta.insert(EXPIRES_KEY.into(), serde_json::json!(1000000.0));
        let record = ValidationRecord::create(b"data", id.public_key.clone(), vec![], Classification::Public, Some(meta));
        assert!(is_expired(&record, 2000000.0)); // expired
    }

    // ── gc_pass ────────────────────────────────────────────────────────

    #[test]
    fn test_gc_no_records() {
        let (mut storage, _dir) = test_engine();
        let finalized = HashSet::new();
        let mut dag = DagIndex::new();

        let result = gc_pass(&mut storage, &finalized, &mut dag, 1000000.0, DEFAULT_RETENTION_SECS).unwrap();
        assert_eq!(result.expired_pruned, 0);
        assert_eq!(result.retention_pruned, 0);
        assert_eq!(result.skipped, 0);
    }

    #[test]
    fn test_gc_prunes_expired_finalized() {
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();
        let mut finalized = HashSet::new();

        // Insert record that expires at t=100
        let mut meta = BTreeMap::new();
        meta.insert(EXPIRES_KEY.into(), serde_json::json!(100.0));
        let rec = insert_record(&mut storage, &mut dag, &id, b"temp", 50.0, Some(meta));
        finalized.insert(rec.id.clone());

        assert_eq!(storage.count().unwrap(), 1);

        // GC at t=200 should prune it
        let result = gc_pass(&mut storage, &finalized, &mut dag, 200.0, DEFAULT_RETENTION_SECS).unwrap();
        assert_eq!(result.expired_pruned, 1);
        assert_eq!(storage.count().unwrap(), 0);
    }

    #[test]
    fn gc_deleted_ids_includes_non_sunken_prunes_for_relevance_cleanup() {
        // audit 16g: the gc_loop relevance cleanup now removes tracker entries
        // for EVERY id in result.deleted_ids (not just sunken-pruned ones, which
        // leaked entries for retention/stale/expired/seal/epoch reasons). That
        // fix is only correct if the PRODUCTION scan (gc_scan_and_delete — what
        // gc_loop actually calls; the dyn-Storage gc_pass is test-only and never
        // sets deleted_ids) surfaces non-sunken prunes in deleted_ids. Pin it
        // with a retention prune (finalized + older than retention_cutoff,
        // is_sunken = false) — the exact non-sunken case that used to leak.
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        // Finalized record at ts=100, retention_cutoff=500 → retention-pruned.
        let rec = insert_record(&mut storage, &mut dag, &id, b"old", 100.0, None);
        let mut finalized: HashSet<String> = HashSet::new();
        finalized.insert(rec.id.clone());

        let result = storage
            .gc_scan_and_delete(
                500.0,  // retention_cutoff: ts=100 < 500 → retention prune
                1000.0, // stale_cutoff
                &|rid| finalized.contains(rid),
                &|_| false, // is_sunken: deliberately NOT a sunken prune
                &Default::default(),
                &Default::default(),
                None,
            )
            .expect("gc scan");

        assert_eq!(result.retention_pruned, 1, "old finalized record retention-pruned");
        assert_eq!(result.sunken_pruned, 0, "this is NOT a sunken prune");
        assert!(
            result.deleted_ids.contains(&rec.id),
            "non-sunken (retention) prune must surface the id in deleted_ids so \
             gc_loop can remove its relevance entry (audit 16g leak fix)"
        );
    }

    #[test]
    fn test_gc_skips_expired_non_finalized() {
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();
        let finalized = HashSet::new(); // nothing finalized

        let mut meta = BTreeMap::new();
        meta.insert(EXPIRES_KEY.into(), serde_json::json!(100.0));
        insert_record(&mut storage, &mut dag, &id, b"temp", 50.0, Some(meta));

        // GC at t=200: record expired but NOT finalized → skip
        let result = gc_pass(&mut storage, &finalized, &mut dag, 200.0, DEFAULT_RETENTION_SECS).unwrap();
        assert_eq!(result.expired_pruned, 0);
        assert_eq!(result.skipped, 1);
        assert_eq!(storage.count().unwrap(), 1); // still there
    }

    #[test]
    fn test_gc_prunes_old_finalized() {
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();
        let mut finalized = HashSet::new();

        // Insert record at t=1000 (very old)
        let rec = insert_record(&mut storage, &mut dag, &id, b"old", 1000.0, None);
        finalized.insert(rec.id.clone());

        // GC with now=10000000 and 90-day retention (way past)
        let result = gc_pass(&mut storage, &finalized, &mut dag, 10000000.0, DEFAULT_RETENTION_SECS).unwrap();
        assert_eq!(result.retention_pruned, 1);
        assert_eq!(storage.count().unwrap(), 0);
    }

    #[test]
    fn test_gc_keeps_recent_finalized() {
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();
        let mut finalized = HashSet::new();

        // Insert record at t=1000000
        let rec = insert_record(&mut storage, &mut dag, &id, b"recent", 1000000.0, None);
        finalized.insert(rec.id.clone());

        // GC at t=1000100 with 90-day retention → too recent to prune
        let result = gc_pass(&mut storage, &finalized, &mut dag, 1000100.0, DEFAULT_RETENTION_SECS).unwrap();
        assert_eq!(result.retention_pruned, 0);
        assert_eq!(storage.count().unwrap(), 1);
    }

    #[test]
    fn test_gc_never_prunes_epoch_seals() {
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();
        let mut finalized = HashSet::new();

        // Insert an epoch seal (very old + finalized)
        let mut meta = BTreeMap::new();
        meta.insert(super::super::epoch::EPOCH_OP_KEY.into(), serde_json::json!("seal"));
        let rec = insert_record(&mut storage, &mut dag, &id, b"seal", 1.0, Some(meta));
        finalized.insert(rec.id.clone());

        // GC should never touch it
        let result = gc_pass(&mut storage, &finalized, &mut dag, 999999999.0, 1.0).unwrap();
        assert_eq!(result.retention_pruned, 0);
        assert_eq!(result.expired_pruned, 0);
        assert_eq!(storage.count().unwrap(), 1);
    }

    #[test]
    fn test_gc_never_prunes_mandate_or_revocation_carriers() {
        // C4 slice 1: the carrier record is the only cryptographic proof the
        // principal signed the mandate/revocation — it must survive retention GC,
        // exactly like governance/epoch/ledger carriers.
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();
        let mut finalized = HashSet::new();

        let mut m_meta = BTreeMap::new();
        m_meta.insert(crate::mandate::MANDATE_OP_KEY.into(), serde_json::json!({"v": 1}));
        let m_rec = insert_record(&mut storage, &mut dag, &id, b"mandate", 1.0, Some(m_meta));
        finalized.insert(m_rec.id.clone());

        let mut r_meta = BTreeMap::new();
        r_meta.insert(crate::mandate::MANDATE_REVOCATION_OP_KEY.into(), serde_json::json!({"v": 1}));
        let r_rec = insert_record(&mut storage, &mut dag, &id, b"revocation", 1.0, Some(r_meta));
        finalized.insert(r_rec.id.clone());

        // Very old + finalized: would be retention-pruned without the exemption.
        let result = gc_pass(&mut storage, &finalized, &mut dag, 999999999.0, 1.0).unwrap();
        assert_eq!(result.retention_pruned, 0);
        assert_eq!(result.expired_pruned, 0);
        assert_eq!(storage.count().unwrap(), 2);
    }

    /// Twin coverage: the LIVE node prunes via `gc_pass_rocks_with`, NOT the
    /// in-memory `gc_pass`. A revocation carrier silently pruned on this path
    /// would leave a revoked mandate replayable as valid (its only proof of
    /// revocation is gone). The in-memory twin's test above is not sufficient —
    /// this exercises the path that actually runs in production.
    #[cfg(feature = "node-core")]
    #[test]
    fn test_gc_rocks_never_prunes_mandate_or_revocation_carriers() {
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();
        let mut finalized = HashSet::new();

        let mut m_meta = BTreeMap::new();
        m_meta.insert(crate::mandate::MANDATE_OP_KEY.into(), serde_json::json!({"v": 1}));
        let m_rec = insert_record(&mut storage, &mut dag, &id, b"mandate", 1.0, Some(m_meta));
        finalized.insert(m_rec.id.clone());

        let mut r_meta = BTreeMap::new();
        r_meta.insert(crate::mandate::MANDATE_REVOCATION_OP_KEY.into(), serde_json::json!({"v": 1}));
        let r_rec = insert_record(&mut storage, &mut dag, &id, b"revocation", 1.0, Some(r_meta));
        finalized.insert(r_rec.id.clone());

        // Very old + finalized: retention-pruned WITHOUT the exemption.
        let sunken: HashSet<String> = HashSet::new();
        let result = gc_pass_rocks_with(
            &storage,
            |rid| finalized.contains(rid),
            &mut dag,
            999_999_999.0,
            1.0,
            &sunken,
        )
        .unwrap();
        assert_eq!(result.retention_pruned, 0, "mandate/revocation carriers must survive the live GC path");
        assert_eq!(result.expired_pruned, 0);
        use crate::storage::Storage;
        assert_eq!(storage.count().unwrap(), 2);
    }

    /// The mandate op-keys are protocol WIRE constants — they appear in signed,
    /// sealed records on disk and on the wire between nodes. Changing a value is
    /// a wire-breaking act, not a rename. The GC exemption and the content-safety
    /// allowlist now reference these consts by name (so they can never silently
    /// drift apart), but this pin guards the value itself: if you must change it,
    /// break this test deliberately and migrate sealed history.
    #[test]
    fn test_mandate_op_keys_are_frozen_wire_constants() {
        assert_eq!(crate::mandate::MANDATE_OP_KEY, "mandate_op");
        assert_eq!(crate::mandate::MANDATE_REVOCATION_OP_KEY, "revocation_op");
        assert_eq!(crate::mandate::MANDATE_REF_METADATA_KEY, "mandate_ref");
    }

    /// Live-path (rocks twin) coverage for the OTHER integrity-carrier classes:
    /// epoch seals (chain backbone), ledger-ops (ledger), governance-ops. The
    /// in-memory `gc_pass` tests below exercise these on the non-production path;
    /// this asserts the exemptions also hold on `gc_pass_rocks_with`, the path the
    /// node actually runs. Pruning a ledger-op here would corrupt the ledger;
    /// pruning an epoch seal would break verifiability.
    #[cfg(feature = "node-core")]
    #[test]
    fn test_gc_rocks_never_prunes_integrity_carriers() {
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();
        let mut finalized = HashSet::new();

        let mut e_meta = BTreeMap::new();
        e_meta.insert(super::super::epoch::EPOCH_OP_KEY.into(), serde_json::json!("seal"));
        let e_rec = insert_record(&mut storage, &mut dag, &id, b"seal", 1.0, Some(e_meta));
        finalized.insert(e_rec.id.clone());

        let mut t_meta = BTreeMap::new();
        t_meta.insert(crate::accounting::types::BEAT_OP_KEY.into(), serde_json::json!("mint"));
        let t_rec = insert_record(&mut storage, &mut dag, &id, b"mint", 1.0, Some(t_meta));
        finalized.insert(t_rec.id.clone());

        let mut g_meta = BTreeMap::new();
        g_meta.insert(crate::accounting::governance::GOVERNANCE_OP_KEY.into(), serde_json::json!("propose"));
        let g_rec = insert_record(&mut storage, &mut dag, &id, b"propose", 1.0, Some(g_meta));
        finalized.insert(g_rec.id.clone());

        // All very old + finalized: retention-pruned WITHOUT the exemptions.
        let sunken: HashSet<String> = HashSet::new();
        let result = gc_pass_rocks_with(
            &storage,
            |rid| finalized.contains(rid),
            &mut dag,
            999_999_999.0,
            1.0,
            &sunken,
        )
        .unwrap();
        assert_eq!(result.retention_pruned, 0, "integrity carriers must survive the live GC path");
        assert_eq!(result.epoch_pruned, 0);
        use crate::storage::Storage;
        assert_eq!(storage.count().unwrap(), 3);
    }

    #[test]
    fn test_gc_never_prunes_ledger_ops() {
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();
        let mut finalized = HashSet::new();

        // Insert a ledger operation (very old + finalized)
        let mut meta = BTreeMap::new();
        meta.insert(crate::accounting::types::BEAT_OP_KEY.into(), serde_json::json!("mint"));
        let rec = insert_record(&mut storage, &mut dag, &id, b"mint", 1.0, Some(meta));
        finalized.insert(rec.id.clone());

        let result = gc_pass(&mut storage, &finalized, &mut dag, 999999999.0, 1.0).unwrap();
        assert_eq!(result.retention_pruned, 0);
        assert_eq!(storage.count().unwrap(), 1);
    }

    #[test]
    fn test_gc_never_prunes_governance_ops() {
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();
        let mut finalized = HashSet::new();

        let mut meta = BTreeMap::new();
        meta.insert(crate::accounting::governance::GOVERNANCE_OP_KEY.into(), serde_json::json!("propose"));
        let rec = insert_record(&mut storage, &mut dag, &id, b"proposal", 1.0, Some(meta));
        finalized.insert(rec.id.clone());

        let result = gc_pass(&mut storage, &finalized, &mut dag, 999999999.0, 1.0).unwrap();
        assert_eq!(result.retention_pruned, 0);
        assert_eq!(storage.count().unwrap(), 1);
    }

    #[test]
    fn test_gc_dag_updated_after_prune() {
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();
        let mut finalized = HashSet::new();

        let rec = insert_record(&mut storage, &mut dag, &id, b"prunable", 1.0, None);
        finalized.insert(rec.id.clone());

        // Verify DAG has the record
        assert!(dag.contains(&rec.id));

        // Prune it
        gc_pass(&mut storage, &finalized, &mut dag, 999999999.0, 1.0).unwrap();

        // DAG should no longer have it
        assert!(!dag.contains(&rec.id));
    }

    // ── Stage 2D: profile-driven retention ───────────────────────────────

    #[test]
    fn light_profile_prunes_records_older_than_72h() {
        use crate::network::node_profile::effective_retention_secs;
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();
        let mut finalized = HashSet::new();

        // A record that's 100 hours old — beyond Light's 72h window.
        let now = 1_000_000.0_f64;
        let old = insert_record(&mut storage, &mut dag, &id, b"old", now - 100.0 * 3600.0, None);
        finalized.insert(old.id.clone());
        // And one that's 10 hours old — well within the window.
        let fresh = insert_record(&mut storage, &mut dag, &id, b"fresh", now - 10.0 * 3600.0, None);
        finalized.insert(fresh.id.clone());
        assert_eq!(storage.count().unwrap(), 2);

        // Pass a fallback well above Light's 72h ceiling so the retention MIN
        // gate selects the profile value — this test exercises Light's 72h
        // retention semantics, not the operator-can-lower path (covered in
        // node_profile.rs tests).
        let retention = effective_retention_secs("light", 365.0 * 86400.0);
        let result = gc_pass(&mut storage, &finalized, &mut dag, now, retention).unwrap();

        assert_eq!(result.retention_pruned, 1, "only the 100h-old record should go");
        assert!(storage.get(&old.id).is_err(), "old record gone");
        assert!(storage.get(&fresh.id).is_ok(), "fresh record kept");
    }

    #[test]
    fn archive_profile_keeps_ancient_records() {
        use crate::network::node_profile::effective_retention_secs;
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();
        let mut finalized = HashSet::new();

        // A record from 1970 — pre-epoch by any reasonable clock.
        let now = 2_000_000_000.0_f64; // year ~2033
        let ancient = insert_record(&mut storage, &mut dag, &id, b"ancient", 100.0, None);
        finalized.insert(ancient.id.clone());

        let retention = effective_retention_secs("archive", 1.0);
        let result = gc_pass(&mut storage, &finalized, &mut dag, now, retention).unwrap();

        assert_eq!(result.retention_pruned, 0,
            "archive profile must keep ancient records");
        assert!(storage.get(&ancient.id).is_ok());
    }

    #[test]
    fn full_zone_profile_uses_90d_retention() {
        use crate::network::node_profile::effective_retention_secs;
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();
        let mut finalized = HashSet::new();

        let now = 1_000_000_000.0_f64;
        let day = 86400.0;
        // 120 days old → should be pruned.
        let very_old = insert_record(&mut storage, &mut dag, &id, b"very_old", now - 120.0 * day, None);
        finalized.insert(very_old.id.clone());
        // 30 days old → kept.
        let recent = insert_record(&mut storage, &mut dag, &id, b"recent", now - 30.0 * day, None);
        finalized.insert(recent.id.clone());

        // Pass a fallback well above FullZone's 90d ceiling so the retention
        // MIN gate selects the profile value — this test exercises FullZone's
        // 90d retention semantics, not the operator-can-lower path.
        let retention = effective_retention_secs("full_zone", 365.0 * 86400.0);
        let result = gc_pass(&mut storage, &finalized, &mut dag, now, retention).unwrap();

        assert_eq!(result.retention_pruned, 1);
        assert!(storage.get(&very_old.id).is_err());
        assert!(storage.get(&recent.id).is_ok());
    }

    // ── Gap 3: seal pruning post super-seal consolidation ─────────────────

    /// Build a record with arbitrary metadata, set it finalized in the
    /// returned set, and persist it at `timestamp`.
    fn insert_seal_like(
        storage: &mut StorageEngine,
        dag: &mut DagIndex,
        id: &Identity,
        timestamp: f64,
        meta: BTreeMap<String, serde_json::Value>,
    ) -> ValidationRecord {
        insert_record(storage, dag, id, &timestamp.to_le_bytes(), timestamp, Some(meta))
    }

    fn seal_meta(zone: &str, epoch: u64) -> BTreeMap<String, serde_json::Value> {
        let mut m = BTreeMap::new();
        m.insert("epoch_op".into(), serde_json::json!("seal"));
        m.insert("epoch_zone".into(), serde_json::json!(zone));
        m.insert("epoch_number".into(), serde_json::json!(epoch));
        m
    }

    #[test]
    fn gc_seal_pruning_below_floor_is_pruned() {
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        // Two seals in zone "z1": epoch 5 (below floor) and epoch 50 (above).
        let old_seal = insert_seal_like(&mut storage, &mut dag, &id, 100.0, seal_meta("z1", 5));
        let young_seal = insert_seal_like(&mut storage, &mut dag, &id, 100.0, seal_meta("z1", 50));

        let mut finalized: HashSet<String> = HashSet::new();
        finalized.insert(old_seal.id.clone());
        finalized.insert(young_seal.id.clone());

        let mut floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();
        floor.insert(crate::ZoneId::new("z1"), 30);

        let result = storage
            .gc_scan_and_delete(
                500.0, // retention_cutoff: both records are older
                1000.0, // stale_cutoff: irrelevant since both finalized
                &|rid| finalized.contains(rid),
                &|_| false,
                &floor,
                &Default::default(),
                None,
            )
            .expect("gc scan");

        assert_eq!(result.seal_pruned, 1, "seal at epoch 5 should be pruned");
        assert_eq!(
            result.retention_pruned, 0,
            "seals must be counted as seal_pruned, not retention_pruned"
        );
        assert!(
            storage.get(&old_seal.id).is_err(),
            "epoch=5 seal removed from storage"
        );
        assert!(
            storage.get(&young_seal.id).is_ok(),
            "epoch=50 seal kept (above floor)"
        );
    }

    #[test]
    fn gc_seal_pruning_skips_zone_without_floor() {
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        let seal = insert_seal_like(&mut storage, &mut dag, &id, 100.0, seal_meta("zNoSuper", 5));

        let mut finalized: HashSet<String> = HashSet::new();
        finalized.insert(seal.id.clone());

        // Zone "z1" has a floor — but the seal is in "zNoSuper".
        let mut floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();
        floor.insert(crate::ZoneId::new("z1"), 30);

        let result = storage
            .gc_scan_and_delete(500.0, 1000.0, &|rid| finalized.contains(rid), &|_| false, &floor, &Default::default(), None)
            .expect("gc scan");

        assert_eq!(result.seal_pruned, 0);
        assert!(storage.get(&seal.id).is_ok(), "no super-seal for this zone — keep");
    }

    #[test]
    fn gc_seal_pruning_keeps_super_seal_records() {
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        // A super-seal record itself — even with a low "covering epoch", it
        // must NEVER be pruned (it IS the consolidation primitive).
        let mut meta = BTreeMap::new();
        meta.insert("epoch_op".into(), serde_json::json!("super_seal"));
        meta.insert("super_seal_zone".into(), serde_json::json!("z1"));
        meta.insert("super_seal_start_epoch".into(), serde_json::json!(0));
        meta.insert("super_seal_end_epoch".into(), serde_json::json!(63));
        let ss_rec = insert_seal_like(&mut storage, &mut dag, &id, 100.0, meta);

        let mut finalized: HashSet<String> = HashSet::new();
        finalized.insert(ss_rec.id.clone());

        // Even with a high floor, super-seals are integrity-critical.
        let mut floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();
        floor.insert(crate::ZoneId::new("z1"), 10_000);

        let result = storage
            .gc_scan_and_delete(500.0, 1000.0, &|rid| finalized.contains(rid), &|_| false, &floor, &Default::default(), None)
            .expect("gc scan");

        assert_eq!(result.seal_pruned, 0);
        assert!(storage.get(&ss_rec.id).is_ok(), "super-seal must never be pruned");
    }

    #[test]
    fn gc_seal_pruning_keeps_zone_transition_records() {
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        // A zone_transition record — never pruned regardless of epoch.
        let mut meta = BTreeMap::new();
        meta.insert("epoch_op".into(), serde_json::json!("zone_transition"));
        meta.insert("epoch_zone".into(), serde_json::json!("z1"));
        meta.insert("epoch_number".into(), serde_json::json!(5));
        let zt_rec = insert_seal_like(&mut storage, &mut dag, &id, 100.0, meta);

        let mut finalized: HashSet<String> = HashSet::new();
        finalized.insert(zt_rec.id.clone());

        let mut floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();
        floor.insert(crate::ZoneId::new("z1"), 1_000);

        let result = storage
            .gc_scan_and_delete(500.0, 1000.0, &|rid| finalized.contains(rid), &|_| false, &floor, &Default::default(), None)
            .expect("gc scan");

        assert_eq!(result.seal_pruned, 0);
        assert!(storage.get(&zt_rec.id).is_ok(), "zone_transition must never be pruned");
    }

    #[test]
    fn gc_scan_and_delete_keeps_signed_proof_carriers() {
        // Regression: the PRODUCTION GC path (gc_scan_and_delete — what gc_loop
        // actually runs via spawn_blocking) must exempt mandate + emergency
        // carriers exactly like its twins (gc_pass / gc_pass_rocks_with) do.
        // The exemption originally lived only in the twins; the scale-refactored
        // production scan dropped it, so finalized signed-proof carriers past
        // retention were pruned on the live box. The plain record is the control:
        // it MUST prune, proving the window actually triggers retention GC (else
        // the survival asserts would pass vacuously).
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        let carrier = |key: &str| {
            let mut m = BTreeMap::new();
            m.insert(key.to_string(), serde_json::json!("x"));
            m
        };

        // ts 100..=104 are all below retention_cutoff=500 → retention-eligible.
        let mandate = insert_record(&mut storage, &mut dag, &id, b"m", 100.0, Some(carrier(crate::mandate::MANDATE_OP_KEY)));
        let revoke = insert_record(&mut storage, &mut dag, &id, b"r", 101.0, Some(carrier(crate::mandate::MANDATE_REVOCATION_OP_KEY)));
        let halt = insert_record(&mut storage, &mut dag, &id, b"h", 102.0, Some(carrier(crate::emergency::EMERGENCY_HALT_OP_KEY)));
        let resume = insert_record(&mut storage, &mut dag, &id, b"s", 103.0, Some(carrier(crate::emergency::EMERGENCY_RESUME_OP_KEY)));
        let plain = insert_record(&mut storage, &mut dag, &id, b"p", 104.0, None);

        let mut finalized: HashSet<String> = HashSet::new();
        for r in [&mandate, &revoke, &halt, &resume, &plain] {
            finalized.insert(r.id.clone());
        }

        let result = storage
            .gc_scan_and_delete(500.0, 1000.0, &|rid| finalized.contains(rid), &|_| false, &Default::default(), &Default::default(), None)
            .expect("gc scan");

        // Signed-proof carriers survive the retention sweep…
        assert!(storage.get(&mandate.id).is_ok(), "mandate carrier must never be pruned");
        assert!(storage.get(&revoke.id).is_ok(), "mandate-revocation carrier must never be pruned");
        assert!(storage.get(&halt.id).is_ok(), "emergency-halt carrier must never be pruned");
        assert!(storage.get(&resume.id).is_ok(), "emergency-resume carrier must never be pruned");
        // …and the control proves the window actually prunes (non-vacuous test).
        assert!(storage.get(&plain.id).is_err(), "plain finalized record past retention must prune (control)");
        assert_eq!(result.retention_pruned, 1, "only the plain control record should retention-prune");
    }

    #[test]
    fn gc_seal_pruning_does_not_double_count_with_retention() {
        // A non-seal record alongside a prunable seal — both finalized + old.
        // Counters must split: 1 seal_pruned, 1 retention_pruned.
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        let plain = insert_record(&mut storage, &mut dag, &id, b"plain", 100.0, None);
        let seal = insert_seal_like(&mut storage, &mut dag, &id, 100.0, seal_meta("z1", 5));

        let mut finalized: HashSet<String> = HashSet::new();
        finalized.insert(plain.id.clone());
        finalized.insert(seal.id.clone());

        let mut floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();
        floor.insert(crate::ZoneId::new("z1"), 30);

        let result = storage
            .gc_scan_and_delete(500.0, 1000.0, &|rid| finalized.contains(rid), &|_| false, &floor, &Default::default(), None)
            .expect("gc scan");

        assert_eq!(result.seal_pruned, 1);
        assert_eq!(result.retention_pruned, 1);
        assert!(storage.get(&plain.id).is_err());
        assert!(storage.get(&seal.id).is_err());
    }

    #[test]
    fn gc_seal_pruning_clears_cf_epochs_disc5_index() {
        // Gap 3: pruning a seal must also clear the CF_EPOCHS DISC-5
        // index entry. Without this, the index leaks ~50 bytes/seal
        // forever — same scale problem the seal pruning solves.
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        let seal = insert_seal_like(&mut storage, &mut dag, &id, 100.0, seal_meta("z1", 5));

        // Write the DISC-5 index entry that ingest.rs:2090-2110 would have
        // written for a seal arriving via the live path.
        let disc5_key = crate::network::epoch::disc5_index_key(5, "z1", &seal.id);
        storage
            .put_cf_raw(crate::storage::rocks::CF_EPOCHS, &disc5_key, &[])
            .unwrap();
        assert!(
            storage
                .get_cf_raw(crate::storage::rocks::CF_EPOCHS, &disc5_key)
                .unwrap()
                .is_some(),
            "DISC-5 index should be present pre-prune"
        );

        let mut finalized: HashSet<String> = HashSet::new();
        finalized.insert(seal.id.clone());
        let mut floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();
        floor.insert(crate::ZoneId::new("z1"), 30);

        let result = storage
            .gc_scan_and_delete(500.0, 1000.0, &|rid| finalized.contains(rid), &|_| false, &floor, &Default::default(), None)
            .expect("gc scan");

        assert_eq!(result.seal_pruned, 1);
        assert!(storage.get(&seal.id).is_err(), "seal removed");
        assert!(
            storage
                .get_cf_raw(crate::storage::rocks::CF_EPOCHS, &disc5_key)
                .unwrap()
                .is_none(),
            "DISC-5 index entry must be cleared on seal prune"
        );
    }

    #[test]
    fn gc_seal_pruning_beat_op_never_pruned_even_below_floor() {
        // beat_op records are integrity-critical (ledger replay) — never prune.
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        let mut meta = BTreeMap::new();
        meta.insert("beat_op".into(), serde_json::json!("transfer"));
        let tx = insert_seal_like(&mut storage, &mut dag, &id, 100.0, meta);

        let mut finalized: HashSet<String> = HashSet::new();
        finalized.insert(tx.id.clone());

        let floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();

        let result = storage
            .gc_scan_and_delete(500.0, 1000.0, &|rid| finalized.contains(rid), &|_| false, &floor, &Default::default(), None)
            .expect("gc scan");

        assert_eq!(result.seal_pruned, 0);
        assert_eq!(result.retention_pruned, 0);
        assert!(storage.get(&tx.id).is_ok(), "ledger op must never be pruned");
    }

    // ── Tier 3.4 (Protocol §11.8) epoch-based record pruning ──────────────

    /// Helper: build a per-zone floor_ts map keyed on the same zone as `rec`.
    fn floor_for_record_zone(rec: &ValidationRecord, ts: f64)
        -> std::collections::HashMap<crate::ZoneId, f64>
    {
        let mut m = std::collections::HashMap::new();
        m.insert(rec.record_zone(), ts);
        m
    }

    #[test]
    fn gc_epoch_pruning_below_floor_is_pruned() {
        // A finalized non-seal record whose timestamp is below the zone's
        // record_pruning_floor_ts MUST be pruned via the epoch path even
        // though it has not aged out the time-based retention window.
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        let rec = insert_record(&mut storage, &mut dag, &id, b"old-and-sealed", 100.0, None);
        let mut finalized: HashSet<String> = HashSet::new();
        finalized.insert(rec.id.clone());

        let floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();
        let record_floor = floor_for_record_zone(&rec, 200.0);

        let result = storage
            .gc_scan_and_delete(
                50.0, // retention_cutoff older than rec.ts (NOT prunable by retention)
                10.0,
                &|rid| finalized.contains(rid),
                &|_| false,
                &floor,
                &record_floor,
                None,
            )
            .expect("gc scan");

        assert_eq!(result.epoch_pruned, 1, "record at ts=100 < floor=200 must prune via epoch path");
        assert_eq!(result.retention_pruned, 0, "must NOT count as retention prune");
        assert!(storage.get(&rec.id).is_err(), "record removed from storage");
    }

    #[test]
    fn gc_epoch_pruning_above_floor_is_kept() {
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        let rec = insert_record(&mut storage, &mut dag, &id, b"too-recent", 300.0, None);
        let mut finalized: HashSet<String> = HashSet::new();
        finalized.insert(rec.id.clone());

        let floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();
        // floor_ts = 200; record ts = 300 → above floor, must be kept.
        let record_floor = floor_for_record_zone(&rec, 200.0);

        let result = storage
            .gc_scan_and_delete(
                50.0,  // retention cutoff older than ts → NOT prunable by retention
                10.0,
                &|rid| finalized.contains(rid),
                &|_| false,
                &floor,
                &record_floor,
                None,
            )
            .expect("gc scan");

        assert_eq!(result.epoch_pruned, 0);
        assert_eq!(result.retention_pruned, 0);
        assert!(storage.get(&rec.id).is_ok(), "record above floor must be kept");
    }

    #[test]
    fn gc_epoch_pruning_disabled_falls_back_to_retention() {
        // With an empty record_pruning_floor_ts map the epoch gate is OFF.
        // Record older than retention_cutoff still gets pruned via retention.
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        let rec = insert_record(&mut storage, &mut dag, &id, b"plain", 100.0, None);
        let mut finalized: HashSet<String> = HashSet::new();
        finalized.insert(rec.id.clone());

        let floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();
        let empty_record_floor: std::collections::HashMap<crate::ZoneId, f64> = Default::default();

        let result = storage
            .gc_scan_and_delete(
                500.0,  // retention cutoff: rec ts=100 < 500 → retention prune
                1000.0,
                &|rid| finalized.contains(rid),
                &|_| false,
                &floor,
                &empty_record_floor,
                None,
            )
            .expect("gc scan");

        assert_eq!(result.epoch_pruned, 0, "no epoch path when floor map empty");
        assert_eq!(result.retention_pruned, 1, "retention path still works");
        assert!(storage.get(&rec.id).is_err());
    }

    #[test]
    fn gc_epoch_pruning_beat_op_never_pruned_below_floor() {
        // Tier 3.4 must respect the same integrity exclusion as Gap 3:
        // beat_op records are ledger-critical → never prune.
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        let mut meta = BTreeMap::new();
        meta.insert("beat_op".into(), serde_json::json!("transfer"));
        let tx = insert_record(&mut storage, &mut dag, &id, b"transfer", 100.0, Some(meta));
        let mut finalized: HashSet<String> = HashSet::new();
        finalized.insert(tx.id.clone());

        let floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();
        let record_floor = floor_for_record_zone(&tx, 1_000_000.0);

        let result = storage
            .gc_scan_and_delete(
                50.0,
                10.0,
                &|rid| finalized.contains(rid),
                &|_| false,
                &floor,
                &record_floor,
                None,
            )
            .expect("gc scan");

        assert_eq!(result.epoch_pruned, 0);
        assert_eq!(result.retention_pruned, 0);
        assert!(storage.get(&tx.id).is_ok(), "ledger op must never be pruned even below floor");
    }

    #[test]
    fn gc_epoch_pruning_unfinalized_record_below_floor_is_kept() {
        // Even with a covering super-seal floor, an unfinalized record
        // must NOT be pruned via the epoch path — that would silently
        // discard records still seeking finality.
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        let rec = insert_record(&mut storage, &mut dag, &id, b"unfinalized", 100.0, None);
        let finalized: HashSet<String> = HashSet::new();  // empty → record not finalized

        let floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();
        let record_floor = floor_for_record_zone(&rec, 1_000_000.0);

        let result = storage
            .gc_scan_and_delete(
                500.0,  // retention_cutoff > rec.ts but record is unfinalized
                1500.0, // stale_cutoff > rec.ts → STALE branch fires
                &|rid| finalized.contains(rid),
                &|_| false,
                &floor,
                &record_floor,
                None,
            )
            .expect("gc scan");

        assert_eq!(result.epoch_pruned, 0, "unfinalized record cannot be epoch-pruned");
        // Stale path will still claim it because ts < stale_cutoff. That's
        // the existing safety net for abandoned records — separate from
        // the new epoch path.
        assert_eq!(result.stale_pruned, 1);
    }

    #[test]
    fn gc_epoch_pruning_zone_without_floor_falls_through() {
        // A record in zone Z with no entry in record_pruning_floor_ts must
        // fall through to retention. Zones without an active super-seal
        // (e.g., very young zones, archive nodes) are NOT epoch-prunable.
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        let rec = insert_record(&mut storage, &mut dag, &id, b"plain", 100.0, None);
        let mut finalized: HashSet<String> = HashSet::new();
        finalized.insert(rec.id.clone());

        // Floor map populated for a DIFFERENT zone — record's zone has no entry.
        let mut record_floor: std::collections::HashMap<crate::ZoneId, f64> = Default::default();
        record_floor.insert(crate::ZoneId::new("some-other-zone"), 1_000_000.0);
        let floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();

        let result = storage
            .gc_scan_and_delete(
                50.0,  // retention cutoff older than ts → not retention-prunable
                10.0,
                &|rid| finalized.contains(rid),
                &|_| false,
                &floor,
                &record_floor,
                None,
            )
            .expect("gc scan");

        assert_eq!(result.epoch_pruned, 0, "zone without floor entry is not epoch-prunable");
        assert!(storage.get(&rec.id).is_ok(), "record kept");
    }

    // ── Bloat fix: gc_scan_and_delete cap (MAX_GC_SCAN_PER_CYCLE = 5000) ──

    #[test]
    fn gc_scan_cap_not_set_when_records_under_limit() {
        // Sanity: small datasets must not flip the scan_capped signal,
        // otherwise the drain-mode interval would hijack idle clusters.
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        // 50 finalized records — well under the 5000 cap.
        let mut finalized: HashSet<String> = HashSet::new();
        for i in 0..50 {
            let rec = insert_record(&mut storage, &mut dag, &id, b"x", 10.0 + (i as f64), None);
            finalized.insert(rec.id.clone());
        }

        let floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();
        let result = storage
            .gc_scan_and_delete(
                500.0, // retention_cutoff: all 50 are older
                10_000.0,
                &|rid| finalized.contains(rid),
                &|_| false,
                &floor,
                &Default::default(),
                None,
            )
            .expect("gc scan");

        assert!(!result.scan_capped, "50 records must not trip the 5000 cap");
        assert_eq!(result.retention_pruned, 50, "all 50 must prune in one cycle");
    }

    #[test]
    fn gc_scan_cap_set_when_records_exceed_limit_and_resumes_next_cycle() {
        // The real-world scenario: a node with ~10K eligible records ran
        // one unbounded cycle that ate 616 s. With the cap, each cycle chews
        // 5000 and signals `scan_capped`; the gc_loop then schedules the
        // next cycle at DRAIN_INTERVAL (10 s) instead of gc_interval_secs.
        //
        // This test verifies both halves of the contract:
        //   (a) first cycle: hits the cap, signals scan_capped, prunes 5000
        //   (b) second cycle: drains the rest, no longer capped
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        // 6000 finalized records → first cycle should hit the 5000 cap.
        // 6000 keeps the test fast (~5-10 s) while still over the boundary.
        let mut finalized: HashSet<String> = HashSet::new();
        for i in 0..6_000u64 {
            // Distinct timestamps so the index keys are unique and sort.
            let ts = 10.0 + (i as f64) * 0.001;
            let rec = insert_record(&mut storage, &mut dag, &id, b"x", ts, None);
            finalized.insert(rec.id.clone());
        }

        let floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();

        // First cycle — must hit the cap.
        let first = storage
            .gc_scan_and_delete(
                10_000.0, // retention_cutoff: all 6000 are older
                100_000.0,
                &|rid| finalized.contains(rid),
                &|_| false,
                &floor,
                &Default::default(),
                None,
            )
            .expect("gc scan 1");

        assert!(first.scan_capped, "6000 records must trip the 5000 cap");
        assert_eq!(
            first.retention_pruned, 5_000,
            "first cycle prunes exactly 5000 (the cap)"
        );

        // Second cycle — drains the remaining 1000, no longer capped.
        let second = storage
            .gc_scan_and_delete(
                10_000.0,
                100_000.0,
                &|rid| finalized.contains(rid),
                &|_| false,
                &floor,
                &Default::default(),
                None,
            )
            .expect("gc scan 2");

        assert!(!second.scan_capped, "second cycle drains the rest, not capped");
        assert_eq!(
            second.retention_pruned, 1_000,
            "second cycle prunes the remaining 1000"
        );
    }

    #[test]
    fn gc_scan_resume_skips_past_non_prunable_head() {
        // Follow-up scenario: a node whose first 5000 CF_IDX_TIMESTAMP
        // entries are ledger-ops that NEVER prune. Without `resume_from`, every
        // cycle re-scans those same 5000 slots and never reaches the prunable
        // records behind them — `scan_capped` keeps firing while
        // `gc_pruned_total` stays at 0 (observed on several nodes after the
        // first fix).
        //
        // This test plants a wall of 5000 ledger-ops (never prunable) followed
        // by a single prunable retention record, then exercises both halves
        // of the contract:
        //   (a) resume_from=None: first cycle caps inside the ledger-op wall,
        //       returns last_scanned_key, prunes 0
        //   (b) resume_from=Some(last_scanned_key): second cycle resumes past
        //       the wall and prunes the trailing record
        let id = test_identity();
        let (mut storage, _dir) = test_engine();
        let mut dag = DagIndex::new();

        let mut finalized: HashSet<String> = HashSet::new();
        // 5000 ledger-ops at the head — finalized but `beat_op` metadata
        // permanently exempts them from pruning.
        for i in 0..5_000u64 {
            let mut meta = BTreeMap::new();
            meta.insert("beat_op".into(), serde_json::json!("noop"));
            let ts = 10.0 + (i as f64) * 0.001;
            let rec = insert_record(&mut storage, &mut dag, &id, b"tok", ts, Some(meta));
            finalized.insert(rec.id.clone());
        }
        // One ordinary retention-eligible record AFTER the wall.
        let tail = insert_record(&mut storage, &mut dag, &id, b"tail", 20.0, None);
        finalized.insert(tail.id.clone());

        let floor: std::collections::HashMap<crate::ZoneId, u64> = Default::default();

        // (a) First cycle with resume_from=None — scans 5000 ledger-ops, caps,
        // prunes 0, returns the last key it touched.
        let first = storage
            .gc_scan_and_delete(
                10_000.0,
                100_000.0,
                &|rid| finalized.contains(rid),
                &|_| false,
                &floor,
                &Default::default(),
                None,
            )
            .expect("gc scan 1");

        assert!(first.scan_capped, "5000 ledger-ops must trip the 5000 cap");
        assert_eq!(
            first.retention_pruned, 0,
            "ledger-ops are never prunable — head-wall hides the tail record"
        );
        assert!(
            first.last_scanned_key.is_some(),
            "scan_capped path must surface last_scanned_key for the loop to resume"
        );
        assert!(
            storage.get(&tail.id).is_ok(),
            "tail record still untouched after capped pass"
        );

        // (b) Second cycle with resume_from=last_scanned_key — must skip past
        // the wall and reach the prunable tail.
        let second = storage
            .gc_scan_and_delete(
                10_000.0,
                100_000.0,
                &|rid| finalized.contains(rid),
                &|_| false,
                &floor,
                &Default::default(),
                first.last_scanned_key.as_deref(),
            )
            .expect("gc scan 2");

        assert!(
            !second.scan_capped,
            "resumed cycle finds only one record — must not cap"
        );
        assert_eq!(
            second.retention_pruned, 1,
            "resumed cycle prunes the previously-hidden tail record"
        );
        assert!(
            storage.get(&tail.id).is_err(),
            "tail record removed after resumed pass"
        );
    }

    // ── constants + GcResult defaults + is_expired boundary tests ─
    //
    // Density target for gc.rs (L/T=51.0 pre-batch, 0 batch_* tests). Pins:
    //
    //   1. `EXPIRES_KEY` (gc.rs:29) — metadata field literal "expires". Used
    //      by `is_expired` and by every record producer; a typo would
    //      silently disable expiration of new records on the cutover.
    //
    //   2. `DEFAULT_RETENTION_SECS` (gc.rs:32) — 7-day default for finalized
    //      record retention. Strict numeric expansion 7.0 * 24.0 * 3600.0
    //      = 604_800.0; any drift here changes prune-window semantics
    //      cluster-wide.
    //
    //   3. `GcResult::default()` (derive Default at gc.rs:35) — every counter
    //      starts at zero, deleted_ids empty, scan_capped false,
    //      last_scanned_key None. Production hot loop at gc.rs:125/212
    //      relies on a clean Default start each cycle.
    //
    //   4. `GcResult::clone()` — preserves counters AND deeply clones the
    //      deleted_ids Vec, so a downstream metric consumer mutating its
    //      copy cannot corrupt the upstream cycle's tally.
    //
    //   5. `is_expired` boundary semantics — pins `now >= expires_at`
    //      (inclusive equality), non-numeric metadata branch returns false,
    //      and negative-expires defensive branch. Existing tests
    //      (gc.rs:672/679/688) cover no-field / future / past; this batch
    //      adds the three uncovered edge axes.

    #[test]
    fn batch_b_expires_key_metadata_field_pin_documented_literal_for_protocol_compat() {
        // EXPIRES_KEY is the public protocol contract — every record
        // producer must use this exact string to mark records as expiring.
        // A typo (e.g. "expire" or "expires_at") would silently disable
        // expiration on those records — they'd pass through GC forever.
        assert_eq!(
            EXPIRES_KEY, "expires",
            "EXPIRES_KEY must be the literal \"expires\" for cross-version compatibility"
        );

        // Round-trip: a record with this exact metadata key gets picked
        // up by is_expired; a record with a near-miss key does NOT.
        let id = test_identity();
        let mut meta_correct = BTreeMap::new();
        meta_correct.insert(EXPIRES_KEY.into(), serde_json::json!(100.0));
        let rec_with = ValidationRecord::create(
            b"data",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta_correct),
        );
        assert!(is_expired(&rec_with, 200.0), "EXPIRES_KEY metadata is honored");

        let mut meta_wrong = BTreeMap::new();
        meta_wrong.insert("expires_at".into(), serde_json::json!(100.0)); // off-by-key
        let rec_off = ValidationRecord::create(
            b"data2",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta_wrong),
        );
        assert!(
            !is_expired(&rec_off, 200.0),
            "off-by-one key (`expires_at`) must not be treated as the expiry field"
        );
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_default_retention_secs_pin_seven_days_in_seconds_strict_value() {
        // DEFAULT_RETENTION_SECS = 7 * 24 * 3600 = 604_800 (one week).
        // Strict equality on the numeric expansion — any change here is
        // a change to mainnet retention semantics and must be a
        // deliberate protocol decision.
        assert_eq!(
            DEFAULT_RETENTION_SECS, 604_800.0,
            "7-day retention in seconds is 7 * 24 * 3600 = 604,800"
        );
        // Derived sanity bounds — guard against suspect-zero or
        // wraparound on f64.
        assert!(DEFAULT_RETENTION_SECS > 0.0, "retention must be positive");
        assert!(
            DEFAULT_RETENTION_SECS.is_finite(),
            "retention must be finite (no NaN/Inf)"
        );
        assert!(
            (DEFAULT_RETENTION_SECS - 7.0 * 24.0 * 3600.0).abs() < 1e-9,
            "literal must match its 7 * 24 * 3600 expansion"
        );
    }

    #[test]
    fn batch_b_gc_result_default_initializes_all_zero_counters_empty_deleted_ids_no_scan_cap() {
        // Production hot loop calls `GcResult::default()` at gc.rs:125
        // and gc.rs:212 (gc_pass + gc_pass_rocks_with). Every cycle MUST
        // start from a clean baseline — a leaked counter would over-count
        // operator metrics (`elara_gc_*_total`), and a leaked deleted_ids
        // Vec would double-delete records on the next cycle.
        let r = GcResult::default();
        assert_eq!(r.expired_pruned, 0);
        assert_eq!(r.retention_pruned, 0);
        assert_eq!(r.sunken_pruned, 0);
        assert_eq!(r.stale_pruned, 0);
        assert_eq!(r.seal_pruned, 0);
        assert_eq!(r.epoch_pruned, 0);
        assert_eq!(r.skipped, 0);
        assert!(r.deleted_ids.is_empty(), "no deleted IDs at default");
        assert!(!r.scan_capped, "scan_capped starts false");
        assert!(r.last_scanned_key.is_none(), "last_scanned_key starts None");
    }

    #[test]
    fn batch_b_gc_result_clone_preserves_counters_and_deeply_clones_deleted_ids_vec() {
        // GcResult is shared by reference (or cloned) through the
        // gc_loop's metric-recording layer. A shallow Clone of
        // deleted_ids would let a metric consumer mutating its copy
        // corrupt the upstream cycle's tally. Pins the standard
        // `derive(Clone)` semantics — disjoint Vecs after clone.
        let mut original = GcResult {
            expired_pruned: 1,
            retention_pruned: 2,
            sunken_pruned: 3,
            stale_pruned: 4,
            seal_pruned: 5,
            epoch_pruned: 6,
            skipped: 7,
            deleted_ids: vec!["r1".into(), "r2".into()],
            scan_capped: true,
            last_scanned_key: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        };
        let cloned = original.clone();

        // Counter parity.
        assert_eq!(cloned.expired_pruned, 1);
        assert_eq!(cloned.retention_pruned, 2);
        assert_eq!(cloned.sunken_pruned, 3);
        assert_eq!(cloned.stale_pruned, 4);
        assert_eq!(cloned.seal_pruned, 5);
        assert_eq!(cloned.epoch_pruned, 6);
        assert_eq!(cloned.skipped, 7);
        assert!(cloned.scan_capped);
        assert_eq!(
            cloned.last_scanned_key.as_deref(),
            Some([0xDE, 0xAD, 0xBE, 0xEF].as_ref())
        );
        assert_eq!(cloned.deleted_ids, vec!["r1".to_string(), "r2".to_string()]);

        // Deep-clone proof: mutate original, clone must be unaffected.
        original.deleted_ids.push("r3".into());
        original.expired_pruned = 99;
        assert_eq!(
            cloned.deleted_ids.len(),
            2,
            "clone's Vec untouched by source push"
        );
        assert_eq!(
            cloned.expired_pruned, 1,
            "clone's counter untouched by source mutation"
        );
    }

    #[test]
    fn batch_b_is_expired_boundary_inclusive_equality_non_numeric_metadata_and_negative_expiry() {
        // Extends gc.rs:672/679/688 (no-field / future / past) with three
        // axes not yet pinned:
        //   - `now == expires_at` (boundary equality, predicate `now >= expires_at`)
        //   - non-f64 metadata value (string / null) → `.as_f64()` is None
        //   - negative expiry → defensive branch, any `now >= -1.0` is expired
        let id = test_identity();

        // Boundary: now == expires_at → expired (inclusive on equality).
        let mut meta_boundary = BTreeMap::new();
        meta_boundary.insert(EXPIRES_KEY.into(), serde_json::json!(1_000.0));
        let rec_boundary = ValidationRecord::create(
            b"data_b",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta_boundary),
        );
        assert!(
            is_expired(&rec_boundary, 1_000.0),
            "now == expires_at is expired (inclusive predicate `now >= expires_at`)"
        );

        // Non-numeric metadata: string value — `.as_f64()` returns None.
        let mut meta_str = BTreeMap::new();
        meta_str.insert(EXPIRES_KEY.into(), serde_json::json!("not-a-number"));
        let rec_str = ValidationRecord::create(
            b"data_s",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta_str),
        );
        assert!(
            !is_expired(&rec_str, f64::MAX),
            "string metadata fails `.as_f64()` → predicate returns false"
        );

        // Non-numeric metadata: null value.
        let mut meta_null = BTreeMap::new();
        meta_null.insert(EXPIRES_KEY.into(), serde_json::Value::Null);
        let rec_null = ValidationRecord::create(
            b"data_n",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta_null),
        );
        assert!(
            !is_expired(&rec_null, f64::MAX),
            "null metadata fails `.as_f64()` → predicate returns false"
        );

        // Negative expiry: a record with `expires_at = -1.0` is expired
        // at any `now >= -1.0`. Defensive — protocol producers should
        // never emit negative timestamps, but the predicate must not
        // panic or wrap.
        let mut meta_neg = BTreeMap::new();
        meta_neg.insert(EXPIRES_KEY.into(), serde_json::json!(-1.0));
        let rec_neg = ValidationRecord::create(
            b"data_neg",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta_neg),
        );
        assert!(
            is_expired(&rec_neg, 0.0),
            "negative expires_at + now=0 is expired"
        );
    }
}
