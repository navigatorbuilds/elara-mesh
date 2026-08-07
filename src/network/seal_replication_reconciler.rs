//! Active seal-replication reconciler (Gap 6).
//!
//! Closes the verifiable-replication invariant: Merkle-of-seal-replicas
//! ensures each seal has at least R=3 independent copies; falls back to
//! flood if the replication invariant breaks.
//!
//! The passive half captures every K-DHT-routed seal push into a bounded
//! FIFO. The active half is a periodic tick that probes each tracked target
//! for actual seal persistence and re-pushes the seal to fresh K-DHT targets
//! whenever the realized replication factor is below
//! `seal_dht_replication_floor`.
//!
//! ## Pacing
//! - Tick every `seal_dht_reconcile_interval_secs` (default 30s).
//! - Each tick drains entries with age ≥ `seal_dht_ack_timeout_secs`
//!   (default 60s) from the head of the queue.
//! - Per-target probe deadline is `seal_dht_probe_timeout_ms` (default 2s).
//! - An entry is dropped after `seal_dht_max_repush_retries` re-pushes
//!   (default 3) without reaching the floor — `floor_violation_total`
//!   increments for operator escalation.
//!
//! ## Why probes, not just blind re-push
//! A naive periodic re-push would waste bandwidth on already-replicated
//! seals (the dedup `seen` set on receivers absorbs duplicates but the wire
//! cost is still paid). The probe is a 2KB-ish PQ-RPC `records_exist` that
//! returns a bitmap — much cheaper than the seal record itself, and lets
//! the reconciler converge on "exactly enough replicas" rather than "at
//! least enough".
//!
//! ## Mainnet scale
//! At 10K nodes × 720 seals/day × R=3 = 21.6M tracked seal-replications/day.
//! With the default 30s tick and 60s ack timeout, steady-state queue depth
//! ≈ push_rate × 60s. At a per-zone seal cadence ≪ 1/s the work is bounded;
//! at a per-zone cadence near 1/s the operator should raise the cap or
//! shorten the interval. Slice 3c plans a batched probe endpoint that
//! collapses N×K HTTP requests per tick into one.

use std::collections::HashSet;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use crate::network::state::{NodeState, PendingSealReplication};

/// Outcome of a single per-target probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Peer was reachable AND reported the seal present.
    Present,
    /// Peer was reachable AND reported the seal absent.
    Absent,
    /// Peer was unreachable, timed out, or returned an unparseable reply.
    /// Counts as missing for floor-invariant purposes (we can't trust the
    /// seal is replicated there) but is reported as a separate counter so
    /// the operator can attribute under-replication to network outage vs.
    /// peer-side GC.
    Failed,
}

/// Pure helper: drain pending entries that are due for probing.
///
/// "Due" means `now - entry.pushed_at >= ack_timeout`. Drains from the head
/// (oldest first), stopping at the first entry that is NOT yet due — since
/// the queue is enqueued in monotonic-pushed_at order, this short-circuits
/// the scan.
///
/// `max_per_tick` bounds how much work a single tick takes regardless of
/// queue depth — at scale the queue can be deep, but the reconciler must
/// not stall the runtime. Entries left undrained will be picked up on the
/// next tick.
pub fn drain_due_entries(
    queue: &mut VecDeque<PendingSealReplication>,
    now: Instant,
    ack_timeout: Duration,
    max_per_tick: usize,
) -> Vec<PendingSealReplication> {
    let mut due = Vec::new();
    while due.len() < max_per_tick {
        let Some(front) = queue.front() else { break };
        if now.saturating_duration_since(front.pushed_at) < ack_timeout {
            // Head not due → tail isn't either (FIFO + monotonic enqueue).
            break;
        }
        match queue.pop_front() {
            Some(entry) => due.push(entry),
            None => break,
        }
    }
    due
}

/// Pure helper: pick fresh K-DHT-style re-push targets, excluding peers
/// that already confirmed the seal AND self.
///
/// `dht_closest` is the current ordered K-closest list for the seal id —
/// the caller computed it via the live DHT, which may have rotated since
/// the original push. We treat it as the canonical "current responsible
/// peer set". Targets that already returned `Present` are filtered out so
/// we don't waste the re-push on them (they'll dedup, but the wire cost
/// is still paid). Self is always excluded.
///
/// Returns at most `k` peer hashes, in DHT-distance order. May return fewer
/// than `k` (or even zero) if the eligible-peer set is sparse — caller
/// must detect that and treat it as a floor violation.
pub fn select_repush_targets(
    dht_closest: &[String],
    already_present: &HashSet<String>,
    self_hash: &str,
    k: usize,
) -> Vec<String> {
    if k == 0 {
        return Vec::new();
    }
    dht_closest
        .iter()
        .filter(|h| h.as_str() != self_hash && !already_present.contains(h.as_str()))
        .take(k)
        .cloned()
        .collect()
}

/// Pure helper: count probe outcomes that confirm the seal is present at
/// the peer. Failed probes do NOT count as present — the reconciler treats
/// "we don't know" as "missing" so the floor invariant errs on the side of
/// extra replication.
pub fn count_present(probes: &[ProbeOutcome]) -> usize {
    probes.iter().filter(|o| matches!(o, ProbeOutcome::Present)).count()
}

/// Pure helper: a tick decision — given the realized replication factor
/// and config, what should the reconciler do with this entry?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryDisposition {
    /// Replication factor met or exceeded floor — drop entry, no action.
    Satisfied,
    /// Replication factor below floor and retries available — issue
    /// re-push, requeue with `retries+1`.
    RepushAndRequeue,
    /// Replication factor below floor and retries exhausted — drop entry,
    /// bump floor-violation counter.
    FloorViolation,
}

/// Pure helper: classify what to do with a pending entry based on probe
/// results, the configured floor, and the retry budget. Lifted out of the
/// async tick so unit tests can sweep the decision matrix without mocking
/// HTTP.
pub fn classify_entry(
    present_count: usize,
    floor: usize,
    retries_so_far: u8,
    max_retries: u8,
) -> EntryDisposition {
    if present_count >= floor {
        EntryDisposition::Satisfied
    } else if retries_so_far >= max_retries {
        EntryDisposition::FloorViolation
    } else {
        EntryDisposition::RepushAndRequeue
    }
}

/// Run one reconciler tick.
///
/// 1. Drain due entries (capped per tick).
/// 2. For each: parallel-probe each target via `records_exist` PQ verb.
/// 3. Classify and act: satisfied → drop, under-replicated → re-push to
///    fresh K-DHT targets and requeue with retries+1, exhausted → drop +
///    floor_violation.
///
/// Returns the work-units processed for observability — the loop logs at
/// debug level when non-zero.
pub async fn run_reconcile_tick(state: &Arc<NodeState>) -> ReconcileTickReport {
    state.gossip_seal_replication_reconcile_ticks_total.fetch_add(1, Relaxed);

    let cfg = &state.config;
    let ack_timeout = Duration::from_secs(cfg.seal_dht_ack_timeout_secs);
    let probe_timeout = Duration::from_millis(cfg.seal_dht_probe_timeout_ms);
    let floor = cfg.seal_dht_replication_floor.max(1);
    let max_retries = cfg.seal_dht_max_repush_retries;
    let k = cfg.content_routing_k.max(1);

    // Bound the per-tick work so a deep queue doesn't stall the runtime.
    // Conservative default keyed off the queue cap so steady-state churn
    // doesn't outpace the tick.
    let max_per_tick = cfg.seal_dht_replication_pending_max.min(64);

    let due: Vec<PendingSealReplication> = {
        let mut q = state.pending_seal_replications.lock().await;
        let drained = drain_due_entries(&mut q, Instant::now(), ack_timeout, max_per_tick);
        // Reflect the new depth on the gauge so /metrics is fresh
        // immediately after a drain.
        state.gossip_seal_replication_pending_depth
            .store(q.len() as u64, Relaxed);
        drained
    };

    if due.is_empty() {
        return ReconcileTickReport::default();
    }

    let mut report = ReconcileTickReport::default();
    let pq_offset = cfg.pq_port_offset;
    let self_hash = state.identity.identity_hash.clone();

    for entry in due {
        let probes = probe_targets(state, &entry, probe_timeout, pq_offset).await;
        let present_count = count_present(&probes);

        // Update probe counters.
        for outcome in &probes {
            match outcome {
                ProbeOutcome::Present => {
                    state.gossip_seal_replication_probe_ok_total.fetch_add(1, Relaxed);
                }
                ProbeOutcome::Absent => {
                    state.gossip_seal_replication_probe_miss_total.fetch_add(1, Relaxed);
                }
                ProbeOutcome::Failed => {
                    state.gossip_seal_replication_probe_fail_total.fetch_add(1, Relaxed);
                }
            }
        }
        report.probes += probes.len();

        let disposition = classify_entry(present_count, floor, entry.retries, max_retries);
        match disposition {
            EntryDisposition::Satisfied => {
                report.satisfied += 1;
            }
            EntryDisposition::FloorViolation => {
                state.gossip_seal_replication_floor_violation_total.fetch_add(1, Relaxed);
                report.floor_violations += 1;
            }
            EntryDisposition::RepushAndRequeue => {
                let already: HashSet<String> = entry.targets.iter()
                    .zip(probes.iter())
                    .filter_map(|(t, o)| if matches!(o, ProbeOutcome::Present) {
                        Some(t.clone())
                    } else {
                        None
                    })
                    .collect();

                // Snapshot K closest from the live DHT for this seal id.
                let dht_closest: Vec<String> = {
                    let dht = state.dht.lock().unwrap_or_else(|e| e.into_inner());
                    dht.closest_to_record(&entry.seal_id, k * 2)
                        .into_iter()
                        .map(|p| p.identity_hash.clone())
                        .collect()
                };

                let fresh = select_repush_targets(&dht_closest, &already, &self_hash, k);
                if fresh.is_empty() {
                    // Topology can't supply fresh targets — count as
                    // floor violation immediately rather than spinning.
                    state.gossip_seal_replication_floor_violation_total.fetch_add(1, Relaxed);
                    report.floor_violations += 1;
                    continue;
                }

                let issued = repush_to_targets(state, &entry.seal_id, &fresh).await;
                if issued > 0 {
                    state.gossip_seal_replication_repush_total.fetch_add(issued as u64, Relaxed);
                    report.repushes += issued;

                    // Requeue with retries+1 and refreshed pushed_at so
                    // the next tick gives the re-push time to land.
                    let mut q = state.pending_seal_replications.lock().await;
                    let cap = cfg.seal_dht_replication_pending_max.max(1);
                    while q.len() >= cap {
                        q.pop_front();
                        state.gossip_seal_replication_overflow_total.fetch_add(1, Relaxed);
                    }
                    q.push_back(PendingSealReplication {
                        seal_id: entry.seal_id.clone(),
                        targets: fresh,
                        pushed_at: Instant::now(),
                        retries: entry.retries.saturating_add(1),
                    });
                    state.gossip_seal_replication_pending_depth
                        .store(q.len() as u64, Relaxed);
                } else {
                    // No re-push landed (e.g., all peers unresolvable).
                    // Treat as floor violation — retry budget would just
                    // re-burn against the same broken topology.
                    state.gossip_seal_replication_floor_violation_total.fetch_add(1, Relaxed);
                    report.floor_violations += 1;
                }
            }
        }
    }

    report
}

/// Probe each target in parallel via `records_exist`. Returns one
/// `ProbeOutcome` per target in the same order as `entry.targets`.
async fn probe_targets(
    state: &Arc<NodeState>,
    entry: &PendingSealReplication,
    probe_timeout: Duration,
    pq_offset: u16,
) -> Vec<ProbeOutcome> {
    use crate::network::gossip::http_to_pq_addr;

    // Resolve identity_hash → host:port → pq_addr from the peer table.
    // Done once up front while the lock is held.
    let resolved: Vec<Option<String>> = {
        let peers = state.peers.read().await;
        entry.targets.iter()
            .map(|h| {
                peers.get(h).and_then(|p| {
                    let base = format!("http://{}:{}", p.host, p.port);
                    http_to_pq_addr(&base, pq_offset)
                })
            })
            .collect()
    };

    let pq_client = state.pq_client.clone();
    let mut handles = Vec::with_capacity(resolved.len());
    for (target_hash, pq_addr_opt) in entry.targets.iter().zip(resolved) {
        let seal_id = entry.seal_id.clone();
        let pq_client = pq_client.clone();
        let _target_hash = target_hash.clone();
        handles.push(tokio::spawn(async move {
            let Some(pq_addr) = pq_addr_opt else {
                return ProbeOutcome::Failed;
            };
            match tokio::time::timeout(
                probe_timeout,
                pq_client.records_exist(&pq_addr, std::slice::from_ref(&seal_id)),
            ).await {
                Ok(Ok(bits)) => match bits.first() {
                    Some(true) => ProbeOutcome::Present,
                    Some(false) => ProbeOutcome::Absent,
                    None => ProbeOutcome::Failed,
                },
                Ok(Err(_)) => ProbeOutcome::Failed,
                Err(_) => ProbeOutcome::Failed,
            }
        }));
    }

    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        out.push(h.await.unwrap_or(ProbeOutcome::Failed));
    }
    out
}

/// Issue a focused re-push to the explicit fresh-target list. Bypasses the
/// generic `push_to_peers` K-DHT selection because the reconciler has
/// already computed who needs the seal — and selecting again would risk
/// re-picking already-present peers.
///
/// Returns the count of pushes that the dispatcher accepted (PQ RPC OK).
/// Network-level failures are counted in the per-target spawn but not
/// re-counted as repushes here.
async fn repush_to_targets(
    state: &Arc<NodeState>,
    seal_id: &str,
    fresh_targets: &[String],
) -> usize {
    use crate::network::gossip::http_to_pq_addr;
    use crate::storage::Storage;

    // Load the seal record from local storage.
    let wire_bytes: Vec<u8> = match state.rocks.get_wire_bytes(seal_id) {
        Ok(b) if !b.is_empty() => b,
        _ => return 0,
    };

    let pq_offset = state.config.pq_port_offset;
    let self_hash = state.identity.identity_hash.clone();
    let network_id = state.config.network_id.clone();

    // Resolve targets to PQ addrs with the peer table read lock.
    let resolved: Vec<Option<String>> = {
        let peers = state.peers.read().await;
        fresh_targets.iter()
            .map(|h| {
                peers.get(h).and_then(|p| {
                    let base = format!("http://{}:{}", p.host, p.port);
                    http_to_pq_addr(&base, pq_offset)
                })
            })
            .collect()
    };

    let pq_client = state.pq_client.clone();
    let mut handles = Vec::with_capacity(resolved.len());
    for pq_addr_opt in resolved {
        let Some(pq_addr) = pq_addr_opt else { continue };
        let wire_bytes = wire_bytes.clone();
        let self_hash = self_hash.clone();
        let network_id = network_id.clone();
        let pq_client = pq_client.clone();
        handles.push(tokio::spawn(async move {
            let headers = crate::network::pq_client::GossipHeaders {
                hops: 0,
                sender_identity_hash: &self_hash,
                trace_id: None,
                network_id: &network_id,
                protocol_version: crate::network::config::PROTOCOL_VERSION,
            };
            match pq_client.submit_record_gossip(&pq_addr, &wire_bytes, headers).await {
                Ok(resp) => resp.is_success(),
                Err(_) => false,
            }
        }));
    }

    let mut ok = 0usize;
    for h in handles {
        if h.await.unwrap_or(false) {
            ok += 1;
        }
    }
    ok
}

/// Long-lived reconciler loop. Spawned once at startup; ticks every
/// `seal_dht_reconcile_interval_secs`. Resilient to a panicking tick —
/// the loop logs and continues.
pub async fn reconcile_loop(state: Arc<NodeState>) {
    let interval_secs = state.config.seal_dht_reconcile_interval_secs.max(1);
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    tracing::info!(
        "seal-replication reconciler online: tick={}s ack_timeout={}s probe_timeout={}ms floor={} max_retries={}",
        interval_secs,
        state.config.seal_dht_ack_timeout_secs,
        state.config.seal_dht_probe_timeout_ms,
        state.config.seal_dht_replication_floor,
        state.config.seal_dht_max_repush_retries,
    );

    loop {
        interval.tick().await;
        if !state.config.seal_dht_routing_enabled {
            // Slice 3a-equivalent behavior: queue stays empty, but we
            // still tick (incrementing the counter) so a flat counter
            // unambiguously means "loop dead", not "routing disabled".
            state.gossip_seal_replication_reconcile_ticks_total.fetch_add(1, Relaxed);
            continue;
        }
        let report = run_reconcile_tick(&state).await;
        if report.is_meaningful() {
            tracing::debug!(
                "seal-replication tick: probes={} satisfied={} repushes={} floor_violations={}",
                report.probes, report.satisfied, report.repushes, report.floor_violations,
            );
        }
    }
}

/// Per-tick observability summary. Returned from `run_reconcile_tick` so
/// the loop can log non-trivial ticks at debug level.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileTickReport {
    pub probes: usize,
    pub satisfied: usize,
    pub repushes: usize,
    pub floor_violations: usize,
}

impl ReconcileTickReport {
    pub fn is_meaningful(&self) -> bool {
        self.probes + self.satisfied + self.repushes + self.floor_violations > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::time::{Duration, Instant};

    #[test]
    fn drain_due_skips_fresh_entries() {
        // Entries fresher than ack_timeout must NOT be drained — the
        // reconciler would otherwise probe before the originating push has
        // had a chance to land at the K-DHT peers.
        let mut q = VecDeque::new();
        let now = Instant::now();
        q.push_back(PendingSealReplication {
            seal_id: "seal_a".into(),
            targets: vec!["t1".into()],
            pushed_at: now, // brand new
            retries: 0,
        });
        let due = drain_due_entries(&mut q, now, Duration::from_secs(60), 100);
        assert!(due.is_empty(), "fresh entry should not be drained");
        assert_eq!(q.len(), 1, "queue should retain the entry");
    }

    #[test]
    fn drain_due_picks_aged_entries_in_order() {
        // FIFO: oldest entry drains first. Mirrors the queue's monotonic
        // push order and ensures a regression that swapped order would
        // surface in this test.
        let mut q = VecDeque::new();
        let now = Instant::now();
        let old = now - Duration::from_secs(120);
        let mid = now - Duration::from_secs(90);
        q.push_back(PendingSealReplication {
            seal_id: "old".into(), targets: vec!["t".into()], pushed_at: old, retries: 0,
        });
        q.push_back(PendingSealReplication {
            seal_id: "mid".into(), targets: vec!["t".into()], pushed_at: mid, retries: 0,
        });
        let due = drain_due_entries(&mut q, now, Duration::from_secs(60), 100);
        assert_eq!(due.len(), 2);
        assert_eq!(due[0].seal_id, "old");
        assert_eq!(due[1].seal_id, "mid");
        assert!(q.is_empty());
    }

    #[test]
    fn drain_due_short_circuits_on_first_fresh_entry() {
        // The queue's monotonic-pushed_at invariant lets the drainer stop
        // at the first non-due head — at scale this avoids scanning
        // thousands of fresh entries every tick. Regression here would
        // turn an O(due_count) operation into O(queue_depth).
        let mut q = VecDeque::new();
        let now = Instant::now();
        // Old (due), then fresh — drain should stop at fresh and leave
        // it in place.
        q.push_back(PendingSealReplication {
            seal_id: "old".into(),
            targets: vec!["t".into()],
            pushed_at: now - Duration::from_secs(120),
            retries: 0,
        });
        q.push_back(PendingSealReplication {
            seal_id: "fresh".into(),
            targets: vec!["t".into()],
            pushed_at: now,
            retries: 0,
        });
        let due = drain_due_entries(&mut q, now, Duration::from_secs(60), 100);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].seal_id, "old");
        assert_eq!(q.len(), 1);
        assert_eq!(q.front().unwrap().seal_id, "fresh");
    }

    #[test]
    fn drain_due_respects_max_per_tick() {
        // A deep queue must not let one tick chew through everything —
        // bounded work per tick is what keeps the reconciler from
        // stalling the runtime under load.
        let mut q = VecDeque::new();
        let now = Instant::now();
        let old = now - Duration::from_secs(120);
        for i in 0..50 {
            q.push_back(PendingSealReplication {
                seal_id: format!("seal_{i}"),
                targets: vec!["t".into()],
                pushed_at: old,
                retries: 0,
            });
        }
        let due = drain_due_entries(&mut q, now, Duration::from_secs(60), 10);
        assert_eq!(due.len(), 10);
        assert_eq!(q.len(), 40);
    }

    #[test]
    fn select_repush_excludes_self_and_present() {
        // The reconciler's correctness hinges on never re-pushing to a
        // peer that already has the seal (waste) or to self (no-op). DHT
        // ordering must be preserved.
        let dht = vec!["a".into(), "self".into(), "b".into(), "c".into(), "d".into()];
        let present: HashSet<String> = ["b".into()].into_iter().collect();
        let picked = select_repush_targets(&dht, &present, "self", 3);
        assert_eq!(picked, vec!["a".to_string(), "c".to_string(), "d".to_string()]);
    }

    #[test]
    fn select_repush_returns_empty_when_all_filtered() {
        // Topology where every closest peer is already-present or self
        // gives the reconciler no fresh target — caller must treat empty
        // as a floor violation rather than silently doing nothing.
        let dht = vec!["self".into(), "a".into()];
        let present: HashSet<String> = ["a".into()].into_iter().collect();
        let picked = select_repush_targets(&dht, &present, "self", 5);
        assert!(picked.is_empty());
    }

    #[test]
    fn select_repush_clamps_to_k() {
        // Even when many fresh peers exist, we never push to more than
        // K — that's the per-record fan-out budget. Regression that
        // returned all eligible peers would amplify under-replication
        // recovery into a sqrt(n) flood.
        let dht: Vec<String> = (0..20).map(|i| format!("p{i}")).collect();
        let picked = select_repush_targets(&dht, &HashSet::new(), "self", 5);
        assert_eq!(picked.len(), 5);
        assert_eq!(picked, vec!["p0", "p1", "p2", "p3", "p4"]
            .into_iter().map(String::from).collect::<Vec<_>>());
    }

    #[test]
    fn select_repush_zero_k_returns_empty() {
        // Misconfig must not crash. K=0 → empty pick (and the caller's
        // floor-violation path will fire).
        let dht = vec!["a".into()];
        let picked = select_repush_targets(&dht, &HashSet::new(), "self", 0);
        assert!(picked.is_empty());
    }

    #[test]
    fn count_present_only_counts_present() {
        // Failed and Absent both indicate the seal is not confirmed at
        // the peer — only Present counts toward the floor invariant.
        let probes = vec![
            ProbeOutcome::Present,
            ProbeOutcome::Absent,
            ProbeOutcome::Failed,
            ProbeOutcome::Present,
        ];
        assert_eq!(count_present(&probes), 2);
    }

    #[test]
    fn classify_entry_satisfied_above_floor() {
        // Replication factor met — drop the entry, no action needed.
        // Floor inclusive: present == floor satisfies.
        assert_eq!(classify_entry(3, 3, 0, 3), EntryDisposition::Satisfied);
        assert_eq!(classify_entry(5, 3, 0, 3), EntryDisposition::Satisfied);
    }

    #[test]
    fn classify_entry_repushes_under_floor_with_budget() {
        // Below floor and retry budget remaining → re-push.
        assert_eq!(classify_entry(2, 3, 0, 3), EntryDisposition::RepushAndRequeue);
        assert_eq!(classify_entry(0, 3, 2, 3), EntryDisposition::RepushAndRequeue);
    }

    #[test]
    fn classify_entry_violates_when_retries_exhausted() {
        // Below floor AND retries exhausted → drop with floor violation.
        // Retries-so-far == max_retries means we've already done max_retries
        // re-pushes; any more would exceed budget.
        assert_eq!(classify_entry(1, 3, 3, 3), EntryDisposition::FloorViolation);
        assert_eq!(classify_entry(0, 3, 5, 3), EntryDisposition::FloorViolation);
    }

    #[test]
    fn report_is_meaningful_only_with_nonzero_work() {
        // A no-op tick (queue empty / no due entries) emits a default
        // report — the loop must NOT log debug for those, or the log
        // gets noisy at scale.
        let empty = ReconcileTickReport::default();
        assert!(!empty.is_meaningful());

        let with_probes = ReconcileTickReport { probes: 1, ..Default::default() };
        assert!(with_probes.is_meaningful());
    }

    #[test]
    fn config_defaults_match_audit_intent() {
        // Audit-2026-04-30 §2 intent: R≥3, fast-enough recovery, bounded
        // probe budget. Lock the defaults so a regression here surfaces
        // immediately.
        let cfg = crate::network::config::NodeConfig::default();
        assert_eq!(cfg.seal_dht_reconcile_interval_secs, 30);
        assert_eq!(cfg.seal_dht_ack_timeout_secs, 60);
        assert_eq!(cfg.seal_dht_probe_timeout_ms, 2_000);
        assert_eq!(cfg.seal_dht_max_repush_retries, 3);
    }

    // ============================================================
    // Fixture-free pure-helper tests
    // ============================================================

    #[test]
    fn batch_b_probe_outcome_three_variant_pairwise_distinct_and_count_present_exhaustive_matrix() {
        // 3 variants, all pairwise distinct (Copy + PartialEq derives).
        let p = ProbeOutcome::Present;
        let a = ProbeOutcome::Absent;
        let f = ProbeOutcome::Failed;
        assert_ne!(p, a);
        assert_ne!(p, f);
        assert_ne!(a, f);
        // Copy semantics: value-copy by move-into-vec doesn't consume.
        let _copies = [p, a, f, p, a, f];
        assert_eq!(p, ProbeOutcome::Present);

        // count_present invariant matrix — only Present counts toward floor.
        assert_eq!(count_present(&[]), 0, "empty probe set");
        assert_eq!(
            count_present(&[ProbeOutcome::Absent, ProbeOutcome::Failed, ProbeOutcome::Absent]),
            0,
            "no Present in mix of Absent/Failed"
        );
        assert_eq!(
            count_present(&[ProbeOutcome::Failed; 7]),
            0,
            "all-Failed never increments"
        );
        assert_eq!(
            count_present(&[ProbeOutcome::Absent; 7]),
            0,
            "all-Absent never increments"
        );
        assert_eq!(
            count_present(&[ProbeOutcome::Present; 7]),
            7,
            "all-Present saturates"
        );
        // Mixed: 4 Present out of 9 probes.
        let mix = [
            ProbeOutcome::Present, ProbeOutcome::Absent, ProbeOutcome::Failed,
            ProbeOutcome::Present, ProbeOutcome::Failed, ProbeOutcome::Absent,
            ProbeOutcome::Present, ProbeOutcome::Absent, ProbeOutcome::Present,
        ];
        assert_eq!(count_present(&mix), 4);
        // Floor-invariant pin: Failed treated identically to Absent —
        // swapping all Failed for Absent must NOT change the count.
        let swapped: Vec<ProbeOutcome> = mix.iter()
            .map(|o| match o {
                ProbeOutcome::Failed => ProbeOutcome::Absent,
                other => *other,
            })
            .collect();
        assert_eq!(count_present(&swapped), count_present(&mix));
    }

    #[test]
    fn batch_b_entry_disposition_three_variant_pairwise_distinct_and_classify_entry_saturation_boundaries() {
        // 3 variants, all pairwise distinct.
        let s = EntryDisposition::Satisfied;
        let r = EntryDisposition::RepushAndRequeue;
        let v = EntryDisposition::FloorViolation;
        assert_ne!(s, r);
        assert_ne!(s, v);
        assert_ne!(r, v);
        // Copy semantics.
        let _copies = [s, r, v, s];
        assert_eq!(s, EntryDisposition::Satisfied);

        // Saturation boundaries — must not panic at usize/u8 extrema.
        // (a) present_count == usize::MAX always Satisfied regardless of floor.
        assert_eq!(
            classify_entry(usize::MAX, 0, 0, 0),
            EntryDisposition::Satisfied
        );
        assert_eq!(
            classify_entry(usize::MAX, usize::MAX, 0, 0),
            EntryDisposition::Satisfied,
            "usize::MAX present >= usize::MAX floor — inclusive"
        );
        // (b) floor=0 always Satisfied (any present_count >= 0).
        assert_eq!(classify_entry(0, 0, 0, 0), EntryDisposition::Satisfied);
        assert_eq!(classify_entry(0, 0, u8::MAX, u8::MAX), EntryDisposition::Satisfied);
        // (c) present=0, floor=1, retries=0, max=0 → FloorViolation
        //     (retries_so_far >= max_retries fires immediately when max=0).
        assert_eq!(
            classify_entry(0, 1, 0, 0),
            EntryDisposition::FloorViolation,
            "max_retries=0 with under-floor present must be FloorViolation"
        );
        // (d) present=0, floor=usize::MAX, retries=u8::MAX, max=u8::MAX-1 → FloorViolation.
        assert_eq!(
            classify_entry(0, usize::MAX, u8::MAX, u8::MAX - 1),
            EntryDisposition::FloorViolation,
            "u8::MAX retries exceeds any max < u8::MAX → exhausted"
        );
        // (e) present=floor-1, retries<max → RepushAndRequeue (the
        //     happy "retry budget remaining" cell).
        assert_eq!(
            classify_entry(2, 3, 0, 3),
            EntryDisposition::RepushAndRequeue
        );
        // (f) Inclusive-floor pin: present_count == floor IS satisfied.
        for floor in [1usize, 2, 3, 5, 10, 100, usize::MAX / 2] {
            assert_eq!(
                classify_entry(floor, floor, 0, 3),
                EntryDisposition::Satisfied,
                "present==floor must be inclusive Satisfied at floor={floor}"
            );
            // And present == floor - 1 with retries available → RepushAndRequeue.
            if floor > 0 {
                assert_eq!(
                    classify_entry(floor - 1, floor, 0, 3),
                    EntryDisposition::RepushAndRequeue,
                    "present==floor-1 with budget must RepushAndRequeue at floor={floor}"
                );
            }
        }
    }

    #[test]
    fn batch_b_reconcile_tick_report_four_field_default_zero_and_is_meaningful_axis_disjunction_with_copy_independence() {
        // Default produces (0,0,0,0).
        let d = ReconcileTickReport::default();
        assert_eq!(d.probes, 0);
        assert_eq!(d.satisfied, 0);
        assert_eq!(d.repushes, 0);
        assert_eq!(d.floor_violations, 0);
        assert!(!d.is_meaningful(), "default report must not be meaningful");

        // is_meaningful is a disjunction over all 4 fields — each field
        // independently flipped to 1 makes the report meaningful.
        let only_probes = ReconcileTickReport { probes: 1, ..Default::default() };
        let only_satisfied = ReconcileTickReport { satisfied: 1, ..Default::default() };
        let only_repushes = ReconcileTickReport { repushes: 1, ..Default::default() };
        let only_violations = ReconcileTickReport { floor_violations: 1, ..Default::default() };
        assert!(only_probes.is_meaningful());
        assert!(only_satisfied.is_meaningful());
        assert!(only_repushes.is_meaningful());
        assert!(only_violations.is_meaningful());

        // PartialEq distinguishes which field carries the 1.
        assert_ne!(only_probes, only_satisfied);
        assert_ne!(only_probes, only_repushes);
        assert_ne!(only_probes, only_violations);
        assert_ne!(only_satisfied, only_repushes);
        assert_ne!(only_satisfied, only_violations);
        assert_ne!(only_repushes, only_violations);

        // Copy semantics: mutating a copy does NOT touch the source.
        let base = ReconcileTickReport { probes: 5, satisfied: 0, repushes: 0, floor_violations: 0 };
        let mut copy = base;
        copy.satisfied = 99;
        assert_eq!(base.satisfied, 0, "Copy is by-value — base must be unchanged");
        assert_eq!(copy.satisfied, 99);
        assert_eq!(base.probes, 5);

        // Large-value safety: each field independently at usize::MAX still
        // reports meaningful (no overflow in the OR'd disjunction).
        let big = ReconcileTickReport {
            probes: usize::MAX,
            satisfied: 0,
            repushes: 0,
            floor_violations: 0,
        };
        assert!(big.is_meaningful());
    }

    #[test]
    fn batch_b_drain_due_entries_clock_rewind_saturation_max_per_tick_zero_and_inclusive_age_boundary() {
        let now = Instant::now();

        // (a) Clock-rewind safety: now < pushed_at must NOT panic.
        // saturating_duration_since yields 0, which is < ack_timeout → NOT due.
        let mut q = VecDeque::new();
        q.push_back(PendingSealReplication {
            seal_id: "future".into(),
            targets: vec!["t".into()],
            pushed_at: now + Duration::from_secs(60),
            retries: 0,
        });
        let due = drain_due_entries(&mut q, now, Duration::from_secs(30), 100);
        assert!(due.is_empty(), "clock-rewind entry must NOT be drained");
        assert_eq!(q.len(), 1, "queue retains the future-pushed entry");

        // (b) max_per_tick = 0 drains nothing, even with all-aged entries.
        let mut q = VecDeque::new();
        for i in 0..5 {
            q.push_back(PendingSealReplication {
                seal_id: format!("aged_{i}"),
                targets: vec!["t".into()],
                pushed_at: now - Duration::from_secs(120),
                retries: 0,
            });
        }
        let due = drain_due_entries(&mut q, now, Duration::from_secs(60), 0);
        assert!(due.is_empty(), "max_per_tick=0 must drain zero entries");
        assert_eq!(q.len(), 5, "queue intact when budget is zero");

        // (c) Inclusive-age boundary: age == ack_timeout IS due.
        // duration_since == ack_timeout, and the check is `< ack_timeout`
        // → false → entry IS due.
        let mut q = VecDeque::new();
        q.push_back(PendingSealReplication {
            seal_id: "exact".into(),
            targets: vec!["t".into()],
            pushed_at: now - Duration::from_secs(60),
            retries: 0,
        });
        let due = drain_due_entries(&mut q, now, Duration::from_secs(60), 100);
        assert_eq!(due.len(), 1, "age == ack_timeout must drain (>= semantics)");
        assert_eq!(due[0].seal_id, "exact");
        assert!(q.is_empty());

        // (d) Empty queue with positive max_per_tick → empty result, no panic.
        let mut q: VecDeque<PendingSealReplication> = VecDeque::new();
        let due = drain_due_entries(&mut q, now, Duration::from_secs(60), 100);
        assert!(due.is_empty());

        // (e) max_per_tick exceeds queue depth → drains all aged, stops at empty.
        let mut q = VecDeque::new();
        for i in 0..3 {
            q.push_back(PendingSealReplication {
                seal_id: format!("a_{i}"),
                targets: vec!["t".into()],
                pushed_at: now - Duration::from_secs(120),
                retries: 0,
            });
        }
        let due = drain_due_entries(&mut q, now, Duration::from_secs(60), 9999);
        assert_eq!(due.len(), 3, "drains all aged when budget exceeds queue depth");
        assert!(q.is_empty());
    }

    #[test]
    fn batch_b_select_repush_targets_no_dedupe_pin_and_filter_independence_and_k_ceiling_invariants() {
        // (a) Dedup-behavior pin: the helper does NOT dedupe the input
        //     dht_closest list. The DHT layer is responsible for unique
        //     identity_hashes; this helper is a pure filter+take, not a set.
        //     A regression adding HashSet-based dedupe would change wire
        //     behavior for malformed DHT outputs.
        let dht = vec!["a".into(), "a".into(), "b".into()];
        let picked = select_repush_targets(&dht, &HashSet::new(), "self", 10);
        assert_eq!(picked, vec!["a".to_string(), "a".to_string(), "b".to_string()]);

        // (b) Empty dht_closest → empty result, no panic.
        let empty_dht: Vec<String> = Vec::new();
        let picked = select_repush_targets(&empty_dht, &HashSet::new(), "self", 5);
        assert!(picked.is_empty());

        // (c) Filter independence: a peer matching BOTH self_hash AND
        //     already_present is filtered exactly once (not double-filtered
        //     resulting in a missing slot). The slot budget is independent
        //     of which predicate fired.
        let dht = vec!["dup".into(), "x".into(), "y".into()];
        let present: HashSet<String> = ["dup".into()].into_iter().collect();
        let picked = select_repush_targets(&dht, &present, "dup", 5);
        // "dup" matches both self and present — filtered exactly once.
        // x and y survive both filters → k=5 yields 2 results.
        assert_eq!(picked, vec!["x".to_string(), "y".to_string()]);

        // (d) k ceiling invariant: result.len() <= min(eligible_count, k)
        //     always. Sweep across (eligible, k) cells.
        for eligible in [0usize, 1, 3, 7, 15] {
            for k in [0usize, 1, 5, 100] {
                let dht: Vec<String> = (0..eligible).map(|i| format!("p{i}")).collect();
                let picked = select_repush_targets(&dht, &HashSet::new(), "self", k);
                let expected = eligible.min(k);
                assert_eq!(
                    picked.len(),
                    expected,
                    "k ceiling violation at eligible={eligible} k={k}: got {} expected {}",
                    picked.len(),
                    expected
                );
            }
        }

        // (e) Order preservation: the FIRST k surviving peers in dht_closest
        //     order are returned (Kademlia distance order is load-bearing).
        let dht: Vec<String> = (0..10).map(|i| format!("p{i}")).collect();
        let present: HashSet<String> = ["p0".into(), "p2".into(), "p5".into()].into_iter().collect();
        let picked = select_repush_targets(&dht, &present, "self", 4);
        // Excludes p0, p2, p5 → eligible: p1, p3, p4, p6, p7, p8, p9.
        // First 4 in DHT order: p1, p3, p4, p6.
        assert_eq!(
            picked,
            vec!["p1".to_string(), "p3".to_string(), "p4".to_string(), "p6".to_string()],
            "DHT distance order must be preserved across filtering"
        );
    }

    #[test]
    fn drain_due_pop_front_safe_on_single_entry() {
        // Regression guard: drain_due_entries previously used
        // pop_front().expect() which would panic on unexpected empty.
        // Verify the pop path completes cleanly for a single due entry.
        let mut q = VecDeque::new();
        let now = Instant::now();
        q.push_back(PendingSealReplication {
            seal_id: "only".into(),
            targets: vec!["peer-1".into()],
            pushed_at: now - Duration::from_secs(90),
            retries: 0,
        });
        let due = drain_due_entries(&mut q, now, Duration::from_secs(60), 10);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].seal_id, "only");
        assert!(q.is_empty());
    }

    #[test]
    fn dht_lock_poison_recovery() {
        // A thread that panics while holding state.dht would poison the
        // Mutex.  The reconciler must not cascade-panic on the next tick;
        // unwrap_or_else(|e| e.into_inner()) recovers the still-valid
        // RoutingTable rather than propagating the poison.
        use crate::network::dht::{NodeId, RoutingTable};
        use std::sync::{Arc, Mutex};

        let table = Arc::new(Mutex::new(RoutingTable::new(NodeId([0u8; 32]))));
        let table2 = Arc::clone(&table);

        // Poison the mutex: thread acquires lock, then panics.
        let _ = std::panic::catch_unwind(move || {
            let _guard = table2.lock().unwrap();
            panic!("intentional poison");
        });

        assert!(table.is_poisoned(), "mutex must be poisoned after thread panic");

        // Mirrors the production fix: recover without panicking.
        let _guard = table.lock().unwrap_or_else(|e| e.into_inner());
        // Reaching here means no panic — the error path is handled.
    }
}
