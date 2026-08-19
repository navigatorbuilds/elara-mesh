//! Fork detection and partition healing.
//!
//! Detects when this node's DAG has diverged from peers after a network
//! partition. Compares Merkle roots and tip sets with connected peers to
//! identify missing records on either side.
//!
//! Healing: when divergence is detected, triggers a delta sync to pull
//! missing records from the peer with the most records. Does NOT discard
//! local records — the DAM is append-only, so both sides' records are valid.

//!
//! Spec references:
//!   @spec Protocol §7.3

use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use super::state::NodeState;
use super::RwLockRecover;

/// A peer must remain diverged for this long before the monitor emits a
/// "persistent divergence" alert. 600s = 10 minutes wall-clock = 5–20 epochs
/// at production-target epoch lengths (30–120s) — well past any transient
/// gossip propagation lag, so the alert means a real partition or a stuck
/// peer, not a momentary lag.
///
/// NETWORK-HARDENING-ROADMAP Tier 1.2 sub-bullet #2.
pub const PERSISTENT_DIVERGENCE_ALERT_THRESHOLD_SECS: u64 = 600;
// MerkleTree no longer needed — using merkle::global_merkle_root() (O(zone_count)) instead

/// Result of comparing our DAG with a peer's.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ForkCheckResult {
    /// Our finalized record count (from `state_core` snapshot's
    /// `finalized_count`). Compares like-for-like with `peer_count` —
    /// see Tier 1.2 fix 2026-04-28.
    pub our_count: usize,
    /// Peer's finalized record count (from /status `finalized_count`).
    pub peer_count: usize,
    /// Our Merkle root (hex).
    pub our_root: String,
    /// Peer's Merkle root (hex).
    pub peer_root: String,
    /// Whether roots match.
    pub in_sync: bool,
    /// Records we have that peer doesn't (from Bloom diff, if run).
    pub we_have_extra: usize,
    /// Records peer has that we don't.
    pub peer_has_extra: usize,
    /// Peer address checked.
    pub peer_addr: String,
    /// PARTITION-MERGE Phase A: peer's `total_attestation_weight` from
    /// /status — sum of `attestation_weight_for_seal` across the peer's
    /// `latest_seal_id` per zone. Used by `pick_heal_target` to rank
    /// candidates by chain weight before raw record count, so a partition
    /// stuffed with 1M garbage records cannot outrank a partition with
    /// fewer-but-finalized records (Protocol §3.3.3 partition-merge
    /// operator π — heavier chain wins).
    /// Falls back to 0 if /status response lacks the field (peer running
    /// pre-Phase-A binary) — that peer effectively drops to lex-min /
    /// record-count tiebreak only, which matches today's behaviour.
    #[serde(default)]
    pub peer_attestation_weight: u64,
}

/// Check for fork divergence against all connected peers.
///
/// Returns a `ForkCheckResult` per peer that responded. Slot locks are
/// unbounded — callers (heal_partition, fork_monitor_loop) must tolerate
/// queueing behind in-flight RPCs. For ops endpoints that must not hang,
/// use [`check_forks_with_lock_timeout`].
pub async fn check_forks(state: &Arc<NodeState>) -> Vec<ForkCheckResult> {
    check_forks_inner(state, None).await
}

/// Lock-bounded variant: fails fast (skips that peer) when the per-peer PQ
/// slot is held by another caller longer than `lock_timeout`. Use this from
/// `/convergence` and other ops surfaces — a heal cycle that holds a slot
/// for minutes will simply produce a "skipped" peer in the report instead
/// of hanging the operator's curl.
pub async fn check_forks_with_lock_timeout(
    state: &Arc<NodeState>,
    lock_timeout: Duration,
) -> Vec<ForkCheckResult> {
    check_forks_inner(state, Some(lock_timeout)).await
}

async fn check_forks_inner(
    state: &Arc<NodeState>,
    lock_timeout: Option<Duration>,
) -> Vec<ForkCheckResult> {
    let peers = state.peers.read().await;
    let connected = peers.connected();
    if connected.is_empty() {
        return Vec::new();
    }

    let peer_urls: Vec<String> = connected.iter().map(|p| p.base_url()).collect();
    drop(peers);

    // Tier 1.2 fork-monitor fix 2026-05-13: pick our highest-epoch seal
    // anchor instead of `global_merkle_root`. The old signal was a
    // sparse-tree commitment over locally-ingested records — any gossip-
    // window difference, plus the ≤2GB-RAM ingest gate that skips merkle
    // inserts, made `peer_persistent_divergence_total` saturate cluster-
    // wide as a constant false positive. The seal anchor is anchor-signed
    // and identical on every peer that finalized the same (zone, epoch),
    // so disagreement at a matching epoch is a REAL fork.
    let our_anchor: Option<(String, u64, String)> = state
        .epoch
        .read_recover()
        .highest_seal_anchor()
        .map(|(z, ep, h)| (z.to_string(), ep, hex::encode(h)));

    // Tier 1.2 fix 2026-04-28: use finalized_count, NOT record_count(). The peer
    // side reads `finalized_count` from /status (settled+finalized chain head), so
    // comparing our `state.rocks.count()` (= finalized + in-flight pending +
    // snapshots/metadata) against peer's finalized_count would always show us
    // "ahead" by ~135K records on a busy node and route every heal toward us.
    // Both sides must read the same field — finalized_count is the comparable
    // one because it's the chain head, not the in-memory bounded DAG view.
    let our_count = if let Some(core) = state.state_core.get() {
        core.read_snapshot().finalized_count
    } else {
        state.finalized.read().await.len()
    };

    let pq_offset = state.config.pq_port_offset;
    let mut results = Vec::new();

    for peer_url in &peer_urls {
        match check_single_peer(state, peer_url, pq_offset, our_anchor.as_ref(), our_count, lock_timeout)
            .await
        {
            Some(result) => results.push(result),
            None => {
                debug!("fork check: failed to reach {peer_url}");
            }
        }
    }

    results
}

/// Check fork status against a single peer.
///
/// `lock_timeout` bounds how long the per-peer slot mutex is waited on.
/// `None` = unbounded (the historical fork-monitor / heal path). `Some(d)` =
/// fail fast if another caller already holds the slot — used by ops surfaces
/// like `/convergence` that must not hang during heal cycles.
async fn check_single_peer(
    state: &Arc<NodeState>,
    peer_url: &str,
    pq_offset: u16,
    our_anchor: Option<&(String, u64, String)>,
    our_count: usize,
    lock_timeout: Option<Duration>,
) -> Option<ForkCheckResult> {
    // AUDIT-10: PQ-only. No HTTPS fallback. If PQ addr can't be derived, skip peer.
    let pq_addr = super::gossip::http_to_pq_addr(peer_url, pq_offset)?;

    // Single /status RPC carries everything: finalized_count,
    // total_attestation_weight, and latest_seal_anchor. Replaces the
    // separate `get_merkle_root` RPC (Tier 1.2 fix 2026-05-13).
    //
    // Tier 1.2 fix 2026-04-28: use finalized_count, NOT dag_size. The
    // peer side reads `finalized_count` from /status (settled+finalized
    // chain head), so comparing our `state.rocks.count()` against peer's
    // finalized_count would always show us "ahead" by ~135K records on a
    // busy node and route every heal toward us. Both sides must read the
    // same field — finalized_count is the comparable one because it's
    // the chain head, not the in-memory bounded DAG view.
    //
    // PARTITION-MERGE Phase A: pull `total_attestation_weight` in the
    // same RPC. Missing on pre-Phase-A peers → defaults to 0.
    let status = match lock_timeout {
        Some(d) => state
            .pq_client
            .get_status_with_lock_timeout(&pq_addr, d)
            .await
            .ok()?,
        None => state.pq_client.get_status(&pq_addr).await.ok()?,
    };

    let peer_count = status["finalized_count"].as_u64().unwrap_or(0) as usize;
    let peer_attestation_weight = status["total_attestation_weight"].as_u64().unwrap_or(0);

    // Tier 1.2 fix 2026-05-13: parse peer's `latest_seal_anchor` block.
    // Missing/null on pre-Phase-B peers → `None` → comparison is skipped
    // (in_sync stays true). When present, both peers' anchors at the
    // same (zone, epoch) MUST hash-match — disagreement at a finalized
    // epoch is a REAL fork (anchor-signed, not gossip-window noise).
    let peer_anchor: Option<(String, u64, String)> = status
        .get("latest_seal_anchor")
        .and_then(|v| {
            if v.is_null() {
                return None;
            }
            let zone = v.get("zone")?.as_str()?.to_string();
            let epoch = v.get("epoch")?.as_u64()?;
            let hash = v.get("hash")?.as_str()?.to_string();
            Some((zone, epoch, hash))
        });

    // New in_sync semantics (replaces `our_root == peer_root` on
    // global_merkle_root, which was a gossip-window-noisy false signal):
    //   - Either side lacks an anchor (cold-start, or pre-Phase-B peer)
    //     → in_sync = true (we can't tell; don't alert).
    //   - Different anchor zones → in_sync = true (can't compare across
    //     zones without a cross-zone RPC; deferred to a follow-up).
    //   - Same zone, different epochs → in_sync = true (gossip-lag, not
    //     a fork — peers will converge as the lagger catches up).
    //   - Same zone, same epoch, hash matches → in_sync = true (real
    //     agreement at a finalized, anchor-signed epoch).
    //   - Same zone, same epoch, hash differs → in_sync = false (REAL
    //     fork — never a gossip artifact).
    let (our_root_str, peer_root_str, in_sync) = match (our_anchor, &peer_anchor) {
        (Some((our_z, our_ep, our_h)), Some((peer_z, peer_ep, peer_h)))
            if our_z == peer_z && our_ep == peer_ep =>
        {
            (our_h.clone(), peer_h.clone(), our_h == peer_h)
        }
        (Some((_, _, our_h)), Some((_, _, peer_h))) => {
            // Different zones or different epochs — can't compare yet.
            (our_h.clone(), peer_h.clone(), true)
        }
        (Some((_, _, our_h)), None) => (our_h.clone(), String::new(), true),
        (None, Some((_, _, peer_h))) => (String::new(), peer_h.clone(), true),
        (None, None) => (String::new(), String::new(), true),
    };

    // Estimate divergence from count difference
    let (we_have_extra, peer_has_extra) = if in_sync {
        (0, 0)
    } else {
        (
            our_count.saturating_sub(peer_count),
            peer_count.saturating_sub(our_count),
        )
    };

    Some(ForkCheckResult {
        our_count,
        peer_count,
        our_root: our_root_str,
        peer_root: peer_root_str,
        in_sync,
        we_have_extra,
        peer_has_extra,
        peer_addr: peer_url.to_string(),
        peer_attestation_weight,
    })
}

/// Pick the best peer to heal from.
///
/// PARTITION-MERGE Phase A: rank by `(peer_attestation_weight, peer_has_extra)`
/// in lex order — heavier chain wins first, falling back to record excess as
/// the legacy tiebreak. This is the load-bearing fix for the §3.3.3 partition-
/// merge operator π: previously a partition with 1M garbage records out-ranked
/// a partition with 1K finalized records purely on count. With weight first,
/// a peer that has accumulated more attestation weight (i.e. was on the
/// canonical chain side) is selected even when the raw record count is lower.
///
/// Pre-Phase-A peers report weight=0 → they downrank to count-only behaviour,
/// preserving compatibility. Returns `None` if no diverged peer has any extra
/// records (equal-count or smaller peers can't resolve the fork by pulling).
fn pick_heal_target<'a>(diverged: &[&'a ForkCheckResult]) -> Option<&'a ForkCheckResult> {
    diverged
        .iter()
        .filter(|c| c.peer_has_extra > 0)
        .max_by_key(|c| (c.peer_attestation_weight, c.peer_has_extra))
        .copied()
}

/// Attempt partition healing: delta sync from the peer with the most records.
///
/// Protocol §3.3.3: partition-merge operator π — partitions grow independently,
/// merge preserves all records with no data loss. Both sides' records and
/// epoch seals are accepted. The partition with more attestation weight
/// determines the canonical epoch chain; the other partition's records are
/// preserved in the DAG but not in the winning epoch's Merkle root.
///
/// Only runs if fork divergence was detected. Uses the existing delta sync
/// mechanism (Bloom filter exchange) to pull missing records.
pub async fn heal_partition(state: &Arc<NodeState>) -> usize {
    let checks = check_forks(state).await;

    let diverged: Vec<&ForkCheckResult> = checks.iter().filter(|c| !c.in_sync).collect();
    if diverged.is_empty() {
        debug!("fork heal: no divergence detected");
        return 0;
    }

    // Pick the peer with the greatest record excess over us. Pulling from a peer
    // that has fewer or equal records to ours would be pointless (and in the
    // equal-count case we can't decide direction from counts alone).
    let Some(target) = pick_heal_target(&diverged) else {
        debug!(
            "fork heal: {} peer(s) diverged but none have extra records — skipping",
            diverged.len()
        );
        return 0;
    };

    info!(
        "fork heal: divergence with {} (our={}, theirs={}), triggering delta sync",
        target.peer_addr, target.our_count, target.peer_count,
    );

    // Sync directly from the diverged peer (not initial_sync which picks connected[0])
    super::sync::initial_sync_from(state, &target.peer_addr).await;

    // Count newly synced records (approximate — compare counts before/after)
    let new_count = state.record_count().unwrap_or(0);

    let healed = new_count.saturating_sub(target.our_count);
    if healed > 0 {
        state.fork_heals_total.fetch_add(healed as u64, Relaxed);
        info!("fork heal: synced {healed} missing records from {}", target.peer_addr);
    }

    healed
}

/// Update the per-peer "first observed diverged" tracker on `state` and emit
/// alerts for streaks that have crossed `PERSISTENT_DIVERGENCE_ALERT_THRESHOLD_SECS`.
///
/// Returns the number of NEW alerts emitted on this call (peers that crossed
/// the threshold for the first time during their current streak). Returning a
/// count makes the helper unit-testable — the integration with the monitor
/// loop just discards the value.
///
/// Per NETWORK-HARDENING-ROADMAP Tier 1.2 #2.
///
/// SEAL-ANCHORED COMMITMENT (Tier 1.2 fix landed 2026-05-13): `in_sync`
/// is now computed in `check_single_peer` from the `latest_seal_anchor`
/// block in /status (`{zone, epoch, hash}`) — the highest-epoch finalized
/// seal record's content hash, picked via `EpochState::highest_seal_anchor`.
/// Two peers on the same canonical chain MUST share the same seal record
/// for the same `(zone, epoch)` (the record is anchor-signed and bit-
/// identical on every peer that finalized that epoch), so hash mismatch
/// at a matching epoch is a REAL fork. Replaced the old
/// `global_merkle_root` comparison, a sparse-tree commitment over locally-
/// ingested records that saturated `peer_persistent_divergence_total`
/// fleet-wide on every healthy mesh because (a) any gossip-window difference
/// registered as divergence, and (b) the ≤2GB-RAM ingest gate skipped
/// merkle inserts entirely so phone-tier peers were always "diverged"
/// from any non-2GB peer. New behaviour: cold-start nodes (no anchor yet),
/// peers anchored on different zones, and peers at different epochs all
/// resolve to `in_sync = true` — gossip lag never alerts; only a real
/// fork at an anchor-signed finalized epoch does.
pub async fn update_divergence_alerts(
    state: &Arc<NodeState>,
    checks: &[ForkCheckResult],
    threshold_secs: u64,
) -> u32 {
    update_divergence_alerts_at(state, checks, threshold_secs, Instant::now()).await
}

/// Same as `update_divergence_alerts` but takes the "now" instant explicitly
/// so tests can simulate elapsed time without sleeping.
pub async fn update_divergence_alerts_at(
    state: &Arc<NodeState>,
    checks: &[ForkCheckResult],
    threshold_secs: u64,
    now: Instant,
) -> u32 {
    let mut tracker = state.peer_divergence_first_seen.lock().await;
    let mut new_alerts: u32 = 0;
    let mut resolved_alerts: u32 = 0;
    let threshold = Duration::from_secs(threshold_secs);

    // (1) Apply this tick's observations: insert/clear per-peer.
    //     Resolutions of *alerted* streaks tick `_resolved_total` so the
    //     operator-facing delta `persistent_total - resolved_total` reports
    //     currently-firing alerts. Sub-threshold churn (insert + clear before
    //     the streak crossed the threshold) does NOT count — the bool gate
    //     keeps the ratio interpretable.
    for c in checks {
        if c.in_sync {
            if let Some((_first_seen, alerted)) = tracker.remove(&c.peer_addr) {
                if alerted {
                    resolved_alerts += 1;
                }
            }
        } else {
            tracker.entry(c.peer_addr.clone()).or_insert((now, false));
        }
    }

    // (2) Cross-the-threshold check on every tracked peer (entries the
    //     current `checks` may have skipped — e.g. transient timeout — stay
    //     in the map and continue ageing toward the alert).
    for (peer_addr, (first_seen, alerted)) in tracker.iter_mut() {
        if !*alerted && now.saturating_duration_since(*first_seen) >= threshold {
            warn!(
                "persistent peer divergence: {peer_addr} diverged for ≥{}s — \
                 partition or stuck peer (Tier 1.2 #2 alert)",
                threshold_secs
            );
            *alerted = true;
            new_alerts += 1;
        }
    }

    if new_alerts > 0 {
        state
            .peer_persistent_divergence_total
            .fetch_add(new_alerts as u64, Relaxed);
    }
    if resolved_alerts > 0 {
        state
            .peer_persistent_divergence_resolved_total
            .fetch_add(resolved_alerts as u64, Relaxed);
    }
    new_alerts
}

/// Periodic fork check loop. Runs on a slow interval (every 5 minutes).
/// If divergence is detected, triggers healing automatically.
pub async fn fork_monitor_loop(
    state: Arc<NodeState>,
    mut shutdown: tokio::sync::watch::Receiver<()>,
    hb: Arc<super::supervision::LoopStatus>,
) {
    let interval_secs = 300u64; // 5 minutes
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    interval.tick().await; // skip first immediate tick

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Hang-detection: a deadlocked fork_monitor would leave forks
                // undetected (a safety gap) with no other direct signal.
                hb.heartbeat();
                // Stage 6 cooperative scheduler (Protocol §11.10): extra
                // backoff when host is saturated. check_forks fans out to
                // every connected peer over PQ + heal_partition is heavier
                // still — we don't want a 5-min tick competing with seal
                // signing on a phone-tier box.
                super::system_load::coop_yield_if_busy(&state.system_load).await;
                let checks = check_forks(&state).await;
                let diverged_count = checks.iter().filter(|c| !c.in_sync).count();

                // Tier 1.2 #2 — age the per-peer divergence tracker on
                // every tick and emit alerts for streaks that crossed the
                // 10-min threshold. Decoupled from healing: a peer can be
                // diverged-and-healing or diverged-and-stuck; this surfaces
                // either via /metrics so an operator notices.
                let _ = update_divergence_alerts(
                    &state,
                    &checks,
                    PERSISTENT_DIVERGENCE_ALERT_THRESHOLD_SECS,
                ).await;

                if diverged_count > 0 {
                    warn!("fork monitor: {diverged_count} peers diverged, attempting heal");
                    heal_partition(&state).await;
                } else if !checks.is_empty() {
                    debug!("fork monitor: all {} peers in sync", checks.len());
                }
            }
            _ = shutdown.changed() => {
                info!("fork monitor: shutting down");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering::Relaxed;

    /// Build a fresh `NodeState` for the divergence-tracker tests. Mirrors
    /// the helper in `routes/sync.rs::tests::test_state()` so the assertion
    /// surface is identical — the test only touches the two new
    /// divergence fields, but Rust still needs a full constructor call.
    fn test_state_for_divergence() -> (Arc<NodeState>, tempfile::TempDir) {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "audit1-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };

        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        (Arc::new(NodeState::new(config, identity, rocks, wmgr)), tmp)
    }

    fn aligned(addr: &str) -> ForkCheckResult {
        ForkCheckResult {
            our_count: 100,
            peer_count: 100,
            our_root: "ours".into(),
            peer_root: "ours".into(),
            in_sync: true,
            we_have_extra: 0,
            peer_has_extra: 0,
            peer_addr: addr.into(),
            peer_attestation_weight: 0,
        }
    }

    /// Tier 1.2 #2 — single peer crosses threshold once, no spam.
    /// On the first observation we record a (now, alerted=false) entry.
    /// On a tick where elapsed ≥ threshold we increment the counter ONCE
    /// and flip the alerted flag; every tick after that returns 0 new
    /// alerts so the counter doesn't drift while the partition persists.
    #[tokio::test]
    async fn divergence_alert_fires_once_per_streak() {
        let (state, _tmp) = test_state_for_divergence();
        let t0 = Instant::now();
        let threshold = 10u64;

        let n1 = update_divergence_alerts_at(&state, &[diverged(120, 100, "p1")], threshold, t0).await;
        assert_eq!(n1, 0, "first observation must not alert immediately");
        assert_eq!(state.peer_persistent_divergence_total.load(Relaxed), 0);

        let t_late = t0 + Duration::from_secs(threshold + 1);
        let n2 = update_divergence_alerts_at(&state, &[diverged(120, 100, "p1")], threshold, t_late).await;
        assert_eq!(n2, 1, "crossing threshold must alert exactly once");
        assert_eq!(state.peer_persistent_divergence_total.load(Relaxed), 1);

        let t_later = t_late + Duration::from_secs(60);
        let n3 = update_divergence_alerts_at(&state, &[diverged(120, 100, "p1")], threshold, t_later).await;
        assert_eq!(n3, 0, "still-diverged streak must not re-alert");
        assert_eq!(state.peer_persistent_divergence_total.load(Relaxed), 1);
    }

    /// When a peer rejoins consensus the streak entry is cleared. A later
    /// divergence is a fresh streak that can alert again — this is what
    /// makes the counter usable as "number of partition events", not just
    /// "ever diverged once".
    #[tokio::test]
    async fn divergence_resolves_then_realerts_on_new_streak() {
        let (state, _tmp) = test_state_for_divergence();
        let t0 = Instant::now();
        let threshold = 10u64;

        // Streak 1: cross threshold, alert.
        update_divergence_alerts_at(&state, &[diverged(120, 100, "p1")], threshold, t0).await;
        update_divergence_alerts_at(
            &state,
            &[diverged(120, 100, "p1")],
            threshold,
            t0 + Duration::from_secs(threshold + 1),
        ).await;
        assert_eq!(state.peer_persistent_divergence_total.load(Relaxed), 1);

        // Resolution: peer reports in_sync — tracker entry must clear.
        update_divergence_alerts_at(
            &state,
            &[aligned("p1")],
            threshold,
            t0 + Duration::from_secs(threshold + 2),
        ).await;
        assert_eq!(state.peer_divergence_first_seen.lock().await.len(), 0);

        // Streak 2: same peer diverges again — must alert again on cross.
        let t_streak2 = t0 + Duration::from_secs(threshold + 100);
        update_divergence_alerts_at(&state, &[diverged(120, 100, "p1")], threshold, t_streak2).await;
        let n = update_divergence_alerts_at(
            &state,
            &[diverged(120, 100, "p1")],
            threshold,
            t_streak2 + Duration::from_secs(threshold + 1),
        ).await;
        assert_eq!(n, 1, "post-resolution divergence must be a fresh streak");
        assert_eq!(state.peer_persistent_divergence_total.load(Relaxed), 2);
    }

    /// L26 (2026-05-12) — `_resolved_total` ticks only when an ALERTED streak
    /// clears. Sub-threshold churn (insert then clear without crossing the
    /// alert window) must NOT bump the counter, so the operator-facing delta
    /// `persistent_total - resolved_total = currently-firing alerts` stays
    /// monotonic and interpretable.
    #[tokio::test]
    async fn resolved_counter_ticks_only_for_alerted_streaks() {
        let (state, _tmp) = test_state_for_divergence();
        let t0 = Instant::now();
        let threshold = 10u64;

        // Sub-threshold blip on p1: insert then clear before crossing
        // threshold. Resolved counter must stay at 0.
        update_divergence_alerts_at(&state, &[diverged(120, 100, "p1")], threshold, t0).await;
        update_divergence_alerts_at(
            &state,
            &[aligned("p1")],
            threshold,
            t0 + Duration::from_secs(threshold - 1),
        ).await;
        assert_eq!(
            state.peer_persistent_divergence_resolved_total.load(Relaxed),
            0,
            "sub-threshold churn must not tick resolved_total"
        );
        assert_eq!(state.peer_persistent_divergence_total.load(Relaxed), 0);

        // Alerted streak on p2: cross threshold then resolve. Resolved must
        // increment by exactly 1.
        update_divergence_alerts_at(&state, &[diverged(120, 100, "p2")], threshold, t0).await;
        update_divergence_alerts_at(
            &state,
            &[diverged(120, 100, "p2")],
            threshold,
            t0 + Duration::from_secs(threshold + 1),
        ).await;
        assert_eq!(state.peer_persistent_divergence_total.load(Relaxed), 1);
        assert_eq!(
            state.peer_persistent_divergence_resolved_total.load(Relaxed),
            0,
            "no resolutions yet"
        );
        update_divergence_alerts_at(
            &state,
            &[aligned("p2")],
            threshold,
            t0 + Duration::from_secs(threshold + 2),
        ).await;
        assert_eq!(
            state.peer_persistent_divergence_resolved_total.load(Relaxed),
            1,
            "alerted streak resolved must tick exactly once"
        );

        // Currently-firing-alerts delta interpretation: total - resolved == 0
        // when all alerted streaks have resolved.
        assert_eq!(
            state.peer_persistent_divergence_total.load(Relaxed)
                - state.peer_persistent_divergence_resolved_total.load(Relaxed),
            0,
            "delta must read as zero currently-firing alerts post-resolution"
        );
    }

    #[test]
    fn test_fork_check_result_in_sync() {
        let result = ForkCheckResult {
            our_count: 100,
            peer_count: 100,
            our_root: "abc123".to_string(),
            peer_root: "abc123".to_string(),
            in_sync: true,
            we_have_extra: 0,
            peer_has_extra: 0,
            peer_addr: "http://localhost:9473".to_string(),
            peer_attestation_weight: 0,
        };
        assert!(result.in_sync);
        assert_eq!(result.we_have_extra, 0);
    }

    #[test]
    fn test_fork_check_result_diverged() {
        let result = ForkCheckResult {
            our_count: 100,
            peer_count: 120,
            our_root: "abc123".to_string(),
            peer_root: "def456".to_string(),
            in_sync: false,
            we_have_extra: 0,
            peer_has_extra: 20,
            peer_addr: "http://localhost:9473".to_string(),
            peer_attestation_weight: 0,
        };
        assert!(!result.in_sync);
        assert_eq!(result.peer_has_extra, 20);
    }

    #[test]
    fn test_fork_check_result_we_ahead() {
        let result = ForkCheckResult {
            our_count: 150,
            peer_count: 100,
            our_root: "aaa".to_string(),
            peer_root: "bbb".to_string(),
            in_sync: false,
            we_have_extra: 50,
            peer_has_extra: 0,
            peer_addr: "http://peer:9473".to_string(),
            peer_attestation_weight: 0,
        };
        assert!(!result.in_sync);
        assert_eq!(result.we_have_extra, 50);
        assert_eq!(result.peer_has_extra, 0);
    }

    fn diverged(peer_count: usize, our_count: usize, addr: &str) -> ForkCheckResult {
        diverged_w(peer_count, our_count, addr, 0)
    }

    fn diverged_w(
        peer_count: usize,
        our_count: usize,
        addr: &str,
        peer_attestation_weight: u64,
    ) -> ForkCheckResult {
        ForkCheckResult {
            our_count,
            peer_count,
            our_root: "ours".to_string(),
            peer_root: "theirs".to_string(),
            in_sync: false,
            we_have_extra: our_count.saturating_sub(peer_count),
            peer_has_extra: peer_count.saturating_sub(our_count),
            peer_addr: addr.to_string(),
            peer_attestation_weight,
        }
    }

    #[test]
    fn test_pick_heal_target_all_peers_smaller() {
        // The original bug: 3 peers all with less data. Old code picked the
        // "tallest dwarf" and synced from a peer with fewer records.
        let a = diverged(5093, 324715, "http://a");
        let b = diverged(3000, 324715, "http://b");
        let c = diverged(1500, 324715, "http://c");
        let diverged = vec![&a, &b, &c];
        assert!(
            pick_heal_target(&diverged).is_none(),
            "must not heal from peers that all have less data than us"
        );
    }

    #[test]
    fn test_pick_heal_target_picks_peer_with_extra() {
        let a = diverged(90, 100, "http://a");  // peer has less
        let b = diverged(150, 100, "http://b"); // peer has more — pick this
        let c = diverged(95, 100, "http://c");  // peer has less
        let diverged = vec![&a, &b, &c];
        let target = pick_heal_target(&diverged).expect("should pick a target");
        assert_eq!(target.peer_addr, "http://b");
        assert_eq!(target.peer_has_extra, 50);
    }

    #[test]
    fn test_pick_heal_target_picks_greatest_excess() {
        // Two peers with more data — pick the one with the biggest gap.
        let a = diverged(110, 100, "http://a"); // +10
        let b = diverged(200, 100, "http://b"); // +100 — pick this
        let c = diverged(150, 100, "http://c"); // +50
        let diverged = vec![&a, &b, &c];
        let target = pick_heal_target(&diverged).expect("should pick a target");
        assert_eq!(target.peer_addr, "http://b");
        assert_eq!(target.peer_has_extra, 100);
    }

    #[test]
    fn test_pick_heal_target_equal_counts_skipped() {
        // Diverged but same count — can't resolve direction from counts alone.
        let a = diverged(100, 100, "http://a");
        let diverged = vec![&a];
        assert!(pick_heal_target(&diverged).is_none());
    }

    #[test]
    fn test_pick_heal_target_empty() {
        let diverged: Vec<&ForkCheckResult> = vec![];
        assert!(pick_heal_target(&diverged).is_none());
    }

    /// PARTITION-MERGE Phase A — heavier attestation weight beats higher
    /// raw record count. Without this rule, a partition stuffed with 1M
    /// garbage records could outrank a partition with fewer-but-finalized
    /// records (Protocol §3.3.3 partition-merge operator π).
    #[test]
    fn test_pick_heal_target_higher_weight_beats_higher_count() {
        // a: peer is way ahead in count but has zero attestation weight
        //    (e.g. partition full of unattested junk).
        // b: peer has fewer extra records but the seals are heavily
        //    attested — this is the canonical chain post-heal.
        let a = diverged_w(10_000, 100, "http://garbage", 0);
        let b = diverged_w(200, 100, "http://canonical", 1_000_000);
        let diverged = vec![&a, &b];
        let target = pick_heal_target(&diverged).expect("must pick a target");
        assert_eq!(
            target.peer_addr, "http://canonical",
            "weight must outrank raw count"
        );
    }

    /// Equal weight (e.g. both peers reported 0 because pre-Phase-A binary)
    /// falls through to peer_has_extra ordering — same behaviour as before.
    #[test]
    fn test_pick_heal_target_equal_weight_falls_back_to_count() {
        let a = diverged_w(110, 100, "http://a", 500);
        let b = diverged_w(200, 100, "http://b", 500);
        let c = diverged_w(150, 100, "http://c", 500);
        let diverged = vec![&a, &b, &c];
        let target = pick_heal_target(&diverged).expect("must pick a target");
        assert_eq!(target.peer_addr, "http://b");
        assert_eq!(target.peer_has_extra, 100);
    }

    #[test]
    fn test_fork_check_serializes() {
        let result = ForkCheckResult {
            our_count: 50,
            peer_count: 50,
            our_root: "root_hash".to_string(),
            peer_root: "root_hash".to_string(),
            in_sync: true,
            we_have_extra: 0,
            peer_has_extra: 0,
            peer_addr: "http://peer:9473".to_string(),
            peer_attestation_weight: 0,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["in_sync"], true);
        assert_eq!(json["our_count"], 50);
    }

    // ─── additional axes ────────────────────────────────────────────────

    /// Pin `PERSISTENT_DIVERGENCE_ALERT_THRESHOLD_SECS` and its cross-module
    /// numeric cohabitation with `pending_drain::PENDING_DISCARD_TIMEOUT_SECS`.
    /// Both constants are independently motivated ("600s = 10 min wall-clock")
    /// but currently share the value — the equality is a load-bearing
    /// coincidence: a `/status` response that stops arriving for a peer
    /// triggers BOTH the pending-soft-discard sweep AND the persistent-
    /// divergence alert at the same 10-minute mark, so operator dashboards
    /// see a single coherent "this peer is stuck" signal instead of two
    /// staggered alerts. A future tuner who shifts only one of the two
    /// breaks the simultaneity. Test pins the coincidence so the drift is
    /// deliberate.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_persistent_divergence_alert_threshold_strict_pin_with_pending_soft_cutoff_cross_equivalence() {
        // Strict literal pin — 600s = 10 minutes wall-clock per the §11.12
        // hardening roadmap Tier 1.2 #2 doc.
        assert_eq!(PERSISTENT_DIVERGENCE_ALERT_THRESHOLD_SECS, 600u64);
        // Positive non-zero (a 0 would alert every check tick, drowning the
        // dashboard).
        assert!(PERSISTENT_DIVERGENCE_ALERT_THRESHOLD_SECS > 0);
        // Cross-module coincidence pin: both 10-minute timers share this
        // value. The cast goes u64→f64; both are integer-valued at 600 so
        // the cast is lossless.
        assert_eq!(
            PERSISTENT_DIVERGENCE_ALERT_THRESHOLD_SECS as f64,
            crate::network::pending_drain::PENDING_DISCARD_TIMEOUT_SECS,
            "persistent-divergence alert and pending soft-discard must coincide at 600s — operators see a single coherent stuck-peer signal"
        );
        // And NOT at the hard-discard 1200s ceiling — the alert fires at the
        // soft sweep, not the hard reap.
        assert_ne!(
            PERSISTENT_DIVERGENCE_ALERT_THRESHOLD_SECS as f64,
            crate::network::pending_drain::PENDING_HARD_DISCARD_TIMEOUT_SECS,
            "alert threshold must NOT coincide with hard-discard ceiling (1200s)"
        );
        // 1-hour conversion sanity — 600s = 10 min = 0.1666… h.
        assert_eq!(PERSISTENT_DIVERGENCE_ALERT_THRESHOLD_SECS, 10 * 60);
    }

    /// Pin the full serde shape of `ForkCheckResult`. The struct rides the
    /// `/convergence` ops endpoint and any field rename silently breaks
    /// operator dashboards keyed on the snake_case JSON keys. Existing
    /// `test_fork_check_serializes` spot-checks 2 of 9 fields; this pins
    /// all 9 + verifies each field's JSON type matches the Rust type
    /// (a refactor that swapped `peer_attestation_weight: u64` for an
    /// `Option<u64>` would emit JSON `null` instead of `0` and break
    /// downstream `weight > 0` filters).
    #[test]
    fn batch_b_fork_check_result_serde_shape_pins_all_nine_snake_case_field_keys() {
        let r = ForkCheckResult {
            our_count: 100,
            peer_count: 200,
            our_root: "our_hash".to_string(),
            peer_root: "peer_hash".to_string(),
            in_sync: false,
            we_have_extra: 5,
            peer_has_extra: 105,
            peer_addr: "http://peer:9473".to_string(),
            peer_attestation_weight: 12_345,
        };
        let json = serde_json::to_value(&r).unwrap();
        // All 9 fields must be present as snake_case keys.
        for key in [
            "our_count",
            "peer_count",
            "our_root",
            "peer_root",
            "in_sync",
            "we_have_extra",
            "peer_has_extra",
            "peer_addr",
            "peer_attestation_weight",
        ] {
            assert!(
                json.get(key).is_some(),
                "JSON shape must carry key {key:?} — operator dashboard keys on it"
            );
        }
        // Value + type pins.
        assert_eq!(json["our_count"], 100);
        assert_eq!(json["peer_count"], 200);
        assert_eq!(json["our_root"], "our_hash");
        assert_eq!(json["peer_root"], "peer_hash");
        assert_eq!(json["in_sync"], false);
        assert_eq!(json["we_have_extra"], 5);
        assert_eq!(json["peer_has_extra"], 105);
        assert_eq!(json["peer_addr"], "http://peer:9473");
        assert_eq!(json["peer_attestation_weight"], 12_345);
        // peer_attestation_weight MUST serialize as a JSON number, not null
        // (a refactor that swapped to Option<u64> would emit null and break
        // dashboards that filter on `weight > 0`).
        assert!(
            json["peer_attestation_weight"].is_number(),
            "peer_attestation_weight must serialize as a JSON number, not null"
        );
        // Exactly 9 top-level keys — no shadow/extra fields.
        let obj = json.as_object().expect("must serialize as object");
        assert_eq!(
            obj.len(),
            9,
            "ForkCheckResult must serialize exactly 9 keys; got {} ({:?})",
            obj.len(),
            obj.keys().collect::<Vec<_>>()
        );
    }

    /// Pin `pick_heal_target` lex-ordering invariant: rank is
    /// `(peer_attestation_weight, peer_has_extra)` — heavier chain
    /// dominates first, count is the secondary tiebreak. Existing tests
    /// cover individual cases; this pins the FULL lex-precedence: a peer
    /// with weight=N+1 wins over a peer with weight=N regardless of how
    /// much further behind in raw count, AND when weights tie, the highest
    /// peer_has_extra wins. This is the load-bearing §3.3.3 partition-merge
    /// operator π invariant — flipping the order silently re-introduces
    /// the "1M garbage records outranks 1K finalized" failure mode.
    #[test]
    fn batch_b_pick_heal_target_lex_ordering_weight_dominates_count_tiebreak() {
        // 1) Higher weight wins even with much lower count excess.
        let huge_count_zero_weight = diverged_w(1_000_000, 100, "http://garbage", 0);
        let small_count_high_weight = diverged_w(105, 100, "http://canonical", 1);
        let pool = vec![&huge_count_zero_weight, &small_count_high_weight];
        let pick = pick_heal_target(&pool).expect("must pick a target");
        assert_eq!(
            pick.peer_addr, "http://canonical",
            "weight=1 must beat weight=0 even with 200_000× larger count excess"
        );
        // 2) When weights tie, peer_has_extra is the tiebreak (canonical
        // count-ordering on the same weight tier).
        let same_weight_small = diverged_w(110, 100, "http://small", 999);
        let same_weight_big = diverged_w(500, 100, "http://big", 999);
        let pool2 = vec![&same_weight_small, &same_weight_big];
        let pick2 = pick_heal_target(&pool2).expect("must pick a target");
        assert_eq!(
            pick2.peer_addr, "http://big",
            "with equal weights, larger peer_has_extra wins"
        );
        // 3) Weight=N+1 wins over weight=N even when the higher-weight peer
        // has fewer-but-still-positive excess.
        let np1 = diverged_w(105, 100, "http://np1", 100);
        let n_higher_count = diverged_w(10_000, 100, "http://n", 99);
        let pool3 = vec![&np1, &n_higher_count];
        let pick3 = pick_heal_target(&pool3).expect("must pick a target");
        assert_eq!(
            pick3.peer_addr, "http://np1",
            "weight=100 must beat weight=99 even with smaller count excess"
        );
    }

    /// Pin the defensive filter at `pick_heal_target` — peers with
    /// `peer_has_extra == 0` are filtered out BEFORE the lex ordering runs,
    /// even when their attestation weight is enormous. A regression that
    /// dropped the filter would silently sync from a peer that has exactly
    /// the same record count as us (no records to gain) but a high weight,
    /// wasting bandwidth on a no-op delta sync every monitor tick.
    /// Distinct from `test_pick_heal_target_equal_counts_skipped` which uses
    /// weight=0; this verifies weight=u64::MAX cannot bypass the filter.
    #[test]
    fn batch_b_pick_heal_target_zero_extra_filtered_out_even_at_u64_max_weight() {
        // peer_has_extra=0 AND weight=u64::MAX → must be filtered out.
        let same_count_max_weight = diverged_w(100, 100, "http://no-extra-max-weight", u64::MAX);
        let pool = vec![&same_count_max_weight];
        assert!(
            pick_heal_target(&pool).is_none(),
            "peer_has_extra=0 must be filtered regardless of weight (max u64 doesn't bypass)"
        );
        // Mixed pool: max-weight peer with zero extras + lower-weight peer
        // with a small but non-zero excess → the lower-weight peer is picked
        // because the max-weight one was filtered out first.
        let small_with_extra = diverged_w(105, 100, "http://small-extra-low-weight", 1);
        let pool_mixed = vec![&same_count_max_weight, &small_with_extra];
        let pick = pick_heal_target(&pool_mixed).expect("must pick the only non-filtered peer");
        assert_eq!(
            pick.peer_addr, "http://small-extra-low-weight",
            "the only peer past the peer_has_extra>0 filter must win regardless of opponent's weight"
        );
        // Empty pool stays None.
        let empty: Vec<&ForkCheckResult> = vec![];
        assert!(pick_heal_target(&empty).is_none());
    }

    /// Pin `ForkCheckResult::clone()` produces fully independent String
    /// allocations — Clone semantics on a struct holding 4 owned Strings
    /// (`our_root`, `peer_root`, `peer_addr` × 2 hashes + URL) are NOT
    /// derived for free; a refactor that swapped any String for an `&str`
    /// or `Cow<'a, str>` would break the lifetime contract Clone implies.
    /// Test: mutate the clone's strings, original must be unchanged.
    #[test]
    fn batch_b_fork_check_result_clone_produces_independent_owned_string_fields() {
        let base = ForkCheckResult {
            our_count: 100,
            peer_count: 100,
            our_root: "original_our_root".to_string(),
            peer_root: "original_peer_root".to_string(),
            in_sync: true,
            we_have_extra: 0,
            peer_has_extra: 0,
            peer_addr: "http://original:9473".to_string(),
            peer_attestation_weight: 42,
        };
        let mut cloned = base.clone();
        // Mutate the clone's owned Strings.
        cloned.our_root = "MUTATED_our_root".to_string();
        cloned.peer_root = "MUTATED_peer_root".to_string();
        cloned.peer_addr = "http://MUTATED:9473".to_string();
        cloned.peer_attestation_weight = 99_999;
        // Original MUST be untouched — no shared interior mutability.
        assert_eq!(base.our_root, "original_our_root");
        assert_eq!(base.peer_root, "original_peer_root");
        assert_eq!(base.peer_addr, "http://original:9473");
        assert_eq!(base.peer_attestation_weight, 42);
        // And the clone has the new values.
        assert_eq!(cloned.our_root, "MUTATED_our_root");
        assert_eq!(cloned.peer_root, "MUTATED_peer_root");
        assert_eq!(cloned.peer_addr, "http://MUTATED:9473");
        assert_eq!(cloned.peer_attestation_weight, 99_999);
        // Numeric Copy fields propagate by value too.
        let cloned2 = base.clone();
        assert_eq!(cloned2.our_count, base.our_count);
        assert_eq!(cloned2.peer_count, base.peer_count);
        assert_eq!(cloned2.in_sync, base.in_sync);
        assert_eq!(cloned2.we_have_extra, base.we_have_extra);
        assert_eq!(cloned2.peer_has_extra, base.peer_has_extra);
    }
}
