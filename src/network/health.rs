//! Node health monitor — periodic checks with configurable thresholds.

//!
//! Spec references:
//!   @spec Protocol §11.14

use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::state::NodeState;
use super::LockRecover;

/// Emergency readiness level per Protocol Section 12.3.
///
/// - `Green` — Normal operation. All systems nominal.
/// - `Yellow` — Degraded. Some peers lost or gossip failures elevated.
/// - `Orange` — Partitioned. No peers or majority of gossip failing. Autonomous mode.
/// - `Red` — Critical. Storage failure or consensus stalled. Sovereign mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReadinessLevel {
    Green,
    Yellow,
    Orange,
    Red,
}

impl ReadinessLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Yellow => "yellow",
            Self::Orange => "orange",
            Self::Red => "red",
        }
    }

    /// Numeric level for metrics (0=green, 1=yellow, 2=orange, 3=red).
    pub fn level(&self) -> u8 {
        match self {
            Self::Green => 0,
            Self::Yellow => 1,
            Self::Orange => 2,
            Self::Red => 3,
        }
    }
}

/// Individual health check result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: CheckStatus,
    pub message: String,
}

/// Status of a single health check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Warn,
    Critical,
}

/// Aggregated health report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthReport {
    /// Overall status (worst of all checks).
    pub status: CheckStatus,
    /// Emergency readiness level.
    pub readiness: ReadinessLevel,
    /// Individual check results.
    pub checks: Vec<Check>,
    /// Timestamp when this report was generated.
    pub timestamp: f64,
}

impl HealthReport {
    pub fn status_str(&self) -> &'static str {
        match self.status {
            CheckStatus::Ok => "healthy",
            CheckStatus::Warn => "degraded",
            CheckStatus::Critical => "critical",
        }
    }
}

/// Run all health checks against the current node state.
pub async fn evaluate(state: &Arc<NodeState>) -> HealthReport {
    let mut checks = Vec::new();

    // Use lock-free snapshot when available (updated every 10 state_core mutations).
    // Previously took dag.read().await + peers.read().await + finalized.read().await
    // which all blocked when state_core held write locks during heavy sync —
    // causing /health to hang for minutes on every restart.
    let snapshot = state.state_core.get().map(|core| core.read_snapshot());

    // ── 1. Peer connectivity ────────────────────────────────────────
    let connected = if let Some(snap) = &snapshot {
        snap.peers_connected
    } else {
        // Fallback before state_core is initialized
        state.peers.read().await.connected().len()
    };
    let min_peers = state.config.health_min_peers as usize;

    // Read gossip-push history early: peers_check uses it to tell a genuine
    // partition (had an active mesh, lost every peer) apart from a solo/genesis
    // authority that seals alone and never pushes. Reused by the gossip-health
    // check below.
    let push_total = state.gossip_push_total.load(Relaxed);

    checks.push(peers_check(
        connected,
        min_peers,
        push_total,
        inbound_sync_age_secs(state),
    ));

    // ── 2. Sync freshness ───────────────────────────────────────────
    let (dag_size, newest_ts) = if let Some(snap) = &snapshot {
        // last_updated = when state_core last processed a mutation
        (snap.dag_size, snap.last_updated)
    } else {
        let dag = state.dag.read().await;
        let tips = dag.tips();
        let newest = if tips.is_empty() {
            0.0
        } else {
            let tip = tips[0].clone();
            state.get_record(&tip).map(|r| r.timestamp).unwrap_or(0.0)
        };
        (dag.len(), newest)
    };

    let now = now_ts();
    let lag = if newest_ts > 0.0 { now - newest_ts } else { 0.0 };
    let max_lag = state.config.health_max_sync_lag_secs as f64;

    checks.push(if dag_size == 0 {
        Check {
            name: "sync",
            status: CheckStatus::Warn,
            message: "empty DAG".into(),
        }
    } else if max_lag > 0.0 && lag > max_lag {
        Check {
            name: "sync",
            status: CheckStatus::Warn,
            message: format!("last record {:.0}s ago (max: {max_lag:.0}s)", lag),
        }
    } else {
        Check {
            name: "sync",
            status: CheckStatus::Ok,
            message: format!("{dag_size} records, last {:.0}s ago", lag),
        }
    });

    // ── 2b. Pull-sync staleness ─────────────────────────────────────
    // Catches a follower that can't sync from its seed (unreachable seed,
    // wire-incompatible peer, partition). Distinct from the record-age check
    // above — which ships disabled because a quiet testnet legitimately has old
    // records: a caught-up idle follower STILL records a successful 0-record
    // pull every cycle, so this fires only when pulls actually stop succeeding.
    // Pure seeds (no pull attempts) are auto-exempt. Logic in `pull_sync_check`.
    if let Some(c) = pull_sync_check(
        state.config.health_max_pull_staleness_secs as f64,
        state.delta_sync_attempts_total.load(Relaxed),
        state.last_successful_pull_unix.load(Relaxed),
        now,
        state.uptime(),
    ) {
        checks.push(c);
    }

    // ── 3. Gossip push health (rolling 5-minute window) ────────────
    //
    // Uses a snapshot to compute failure rate over recent activity only,
    // so startup transients don't permanently inflate the rate.
    // push_total is read once near the peers check above and reused here.
    let push_failed = state.gossip_push_failed_total.load(Relaxed);

    let (recent_push, recent_failed) = {
        static SNAPSHOT: std::sync::Mutex<Option<(f64, u64, u64)>> = std::sync::Mutex::new(None);
        let mut snap = SNAPSHOT.lock_recover();
        match *snap {
            Some((ts, snap_push, snap_failed)) if now - ts < 300.0 => {
                // Within window — compute delta from snapshot
                (push_total.saturating_sub(snap_push), push_failed.saturating_sub(snap_failed))
            }
            _ => {
                // Window expired or first run — take new snapshot, use cumulative for this cycle
                *snap = Some((now, push_total, push_failed));
                (push_total, push_failed)
            }
        }
    };

    let fail_rate = if recent_push > 0 {
        recent_failed as f64 / recent_push as f64
    } else {
        0.0
    };

    checks.push(if push_total == 0 {
        Check {
            name: "gossip",
            status: CheckStatus::Ok,
            message: "no pushes yet".into(),
        }
    } else if recent_push == 0 {
        Check {
            name: "gossip",
            status: CheckStatus::Ok,
            message: format!("{push_total} pushes (none recent)"),
        }
    } else if fail_rate > 0.5 {
        Check {
            name: "gossip",
            status: CheckStatus::Critical,
            message: format!("{:.0}% push failure rate ({recent_failed}/{recent_push} recent)", fail_rate * 100.0),
        }
    } else if fail_rate > 0.2 {
        Check {
            name: "gossip",
            status: CheckStatus::Warn,
            message: format!("{:.0}% push failure rate ({recent_failed}/{recent_push} recent)", fail_rate * 100.0),
        }
    } else {
        Check {
            name: "gossip",
            status: CheckStatus::Ok,
            message: format!("{push_total} pushes, {:.0}% failure rate", fail_rate * 100.0),
        }
    });

    // ── 4. Auto-witness health ──────────────────────────────────────
    let aw_cycles = state.auto_witness_cycles_total.load(Relaxed);
    let aw_failures = state.auto_witness_failures_total.load(Relaxed);
    let aw_fail_rate = if aw_cycles > 0 {
        aw_failures as f64 / aw_cycles as f64
    } else {
        0.0
    };

    checks.push(if !state.config.auto_witness {
        Check {
            name: "witness",
            status: CheckStatus::Ok,
            message: "auto-witness disabled".into(),
        }
    } else if aw_cycles == 0 {
        Check {
            name: "witness",
            status: CheckStatus::Ok,
            message: "no witness cycles yet".into(),
        }
    } else if aw_fail_rate > 0.5 {
        Check {
            name: "witness",
            status: CheckStatus::Warn,
            message: format!("{:.0}% cycle failure rate ({aw_failures}/{aw_cycles})", aw_fail_rate * 100.0),
        }
    } else {
        Check {
            name: "witness",
            status: CheckStatus::Ok,
            message: format!("{aw_cycles} cycles, {:.0}% failure rate", aw_fail_rate * 100.0),
        }
    });

    // ── 5. Consensus progress ───────────────────────────────────────
    // Use atomic counters — no lock needed. Previously took consensus.lock()
    // and finalized.read().await which blocked during heavy sync.
    let tracked = state.total_attestations_processed.load(Relaxed) as usize;
    let finalized_count = state.total_ever_finalized.load(Relaxed) as usize;

    // Unstaked nodes can attest/forward but never self-finalize — that's by
    // design, not a degradation signal. Without this gate the consensus
    // check warns forever on unstaked anchors (e.g. an unstaked anchor at the testnet),
    // tripping the /health rollup to "degraded" for what is expected steady
    // state.
    let unstaked = {
        let our_hash = state.identity.identity_hash.clone();
        let ledger = state.ledger.read().await;
        ledger.staked(&our_hash) == 0
    };

    checks.push(if dag_size == 0 {
        Check {
            name: "consensus",
            status: CheckStatus::Ok,
            message: "no records to settle".into(),
        }
    } else if finalized_count > 0 {
        Check {
            name: "consensus",
            status: CheckStatus::Ok,
            message: format!("{finalized_count} finalized, {tracked} attestations"),
        }
    } else if tracked > 0 && unstaked {
        Check {
            name: "consensus",
            status: CheckStatus::Ok,
            message: format!("{tracked} attestations forwarded (unstaked, no self-settlement)"),
        }
    } else if tracked > 0 {
        Check {
            name: "consensus",
            status: CheckStatus::Warn,
            message: format!("{tracked} attestations but 0 settlements"),
        }
    } else {
        Check {
            name: "consensus",
            status: CheckStatus::Ok,
            message: "awaiting attestations".into(),
        }
    });

    // ── 6. DAG index consistency ────────────────────────────────────
    // The in-memory DAG is an active window (eviction keeps only recent records).
    // Comparing DAG size vs total storage is meaningless — DAG is intentionally
    // much smaller. Instead, just report the DAG size as healthy if non-zero.
    let storage_count = state.record_count().unwrap_or(0);
    checks.push(Check {
        name: "dag_index",
        status: if dag_size == 0 && storage_count > 0 {
            CheckStatus::Critical
        } else {
            CheckStatus::Ok
        },
        message: format!("{dag_size} active ({storage_count} total in storage)"),
    });

    // ── 7b. Gap 4 TransitionSeal health ─────────────────────────────
    checks.push(transitions_check(
        state.transitions_expired_total.load(Relaxed),
        state.transitions_mirror_write_failures_total.load(Relaxed),
        state.transitions_proposed_by_orchestrator_total.load(Relaxed),
        state.transitions_finalized_total.load(Relaxed),
    ));

    // ── 7. DAG orphans & tip health ─────────────────────────────────
    // Uses lock-free snapshot. Previously took dag.read().await which blocked
    // on 1-core nodes when state_core held the write lock during sync.
    {
        let (tips, orphans) = if let Some(snap) = &snapshot {
            (snap.dag_tips, snap.dag_orphan_edges)
        } else {
            let dag = state.dag.read().await;
            (dag.tip_count(), dag.orphan_count())
        };
        checks.push(Check {
            name: "dag_orphans",
            status: if orphans > 5000 {
                CheckStatus::Critical
            } else if orphans > 1000 {
                CheckStatus::Warn
            } else {
                CheckStatus::Ok
            },
            message: format!("{tips} tips, {orphans} orphan edges"),
        });
    }

    // ── 7b. DAG completeness (R2-6b honest surface) ─────────────────
    // Orphan count is a WEAK proxy for the silent-gap mode: a node missing
    // whole regions of history receives nothing, so it accumulates few
    // orphans (observed live 2026-07-02: 14 orphans while 2,800 records
    // missing). The real signal is the peer-reported total_missing that the
    // delta puller persists after every cycle. Non-zero = the bounded 24h
    // window will not close the gap on its own; /health must say so instead
    // of reporting GREEN (the 2.3-day invisible-stall failure class).
    {
        let peer_missing = state
            .delta_peer_total_missing
            .load(std::sync::atomic::Ordering::Relaxed);
        // Tier-1 (contract §4): sealed-epoch deficits are the second gap
        // axis — epochs whose seal PROVES records this node doesn't have.
        // The zero-progress streak upgrades "gap exists" to "gap is not
        // healing": full_pull sweeps keep coming back empty while deficits
        // stay open, which is when the manual recovery recipe is warranted.
        let open_deficits = state
            .dag_deficit_open
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len() as u64;
        let no_progress_streak = state
            .full_pull_zero_progress_streak
            .load(std::sync::atomic::Ordering::Relaxed);
        checks.push(Check {
            name: "dag_gap",
            status: if peer_missing > 0 || open_deficits > 0 {
                CheckStatus::Warn
            } else {
                CheckStatus::Ok
            },
            message: if peer_missing > 0 || open_deficits > 0 {
                let mut msg = String::new();
                if peer_missing > 0 {
                    msg.push_str(&format!(
                        "peer reports {peer_missing} records missing beyond the delta window"
                    ));
                }
                if open_deficits > 0 {
                    if !msg.is_empty() {
                        msg.push_str("; ");
                    }
                    msg.push_str(&format!(
                        "{open_deficits} sealed epochs with locally-missing records \
                         (full_pull escalation active"
                    ));
                    if no_progress_streak > 0 {
                        msg.push_str(&format!(
                            ", {no_progress_streak} consecutive sweeps without progress"
                        ));
                    }
                    msg.push(')');
                }
                msg.push_str(
                    " — manual recovery: POST /admin/snapshot_rebootstrap_from \
                     (docs/KNOWN-LIMITATIONS.md)",
                );
                msg
            } else {
                "no peer-reported gap".to_string()
            },
        });
    }

    // ── 8. Storage integrity (F-6/F-8) ──────────────────────────────
    // RocksDB background-error state: the HARD-failure signal a background
    // flush/compaction failed (mid-compaction ENOSPC, I/O fault, lost mount,
    // corruption) and the DB may have halted writes. Distinct from the
    // recoverable throttle/back-pressure gauges and from the proactive
    // `disk_pressure` free-space gate — none of which see an error that has
    // already fired. Critical so a wedged DB fails /health (and the /alive
    // AND-gate) for an operator — including the first external operator's node —
    // instead of silently dropping every write. Inert (Ok) at 0, so it never
    // perturbs a healthy node's status. O(1) DB property read.
    let bg_errors = state.rocks.background_errors();
    checks.push(Check {
        name: "storage",
        status: if bg_errors > 0 {
            CheckStatus::Critical
        } else {
            CheckStatus::Ok
        },
        message: if bg_errors > 0 {
            format!(
                "rocksdb background-errors={bg_errors} — writes may be halted (I/O fault / mid-compaction ENOSPC / corruption)"
            )
        } else {
            "rocksdb healthy (0 background-errors)".into()
        },
    });

    // ── Aggregate ───────────────────────────────────────────────────
    let worst = checks
        .iter()
        .map(|c| c.status)
        .max_by_key(|s| match s {
            CheckStatus::Ok => 0,
            CheckStatus::Warn => 1,
            CheckStatus::Critical => 2,
        })
        .unwrap_or(CheckStatus::Ok);

    // ── Readiness level determination ────────────────────────────
    let readiness = determine_readiness(connected, fail_rate, push_total, &worst);

    HealthReport {
        status: worst,
        readiness,
        checks,
        timestamp: now,
    }
}

/// Gap 4 TransitionSeal health check (extracted for unit test coverage).
///
/// Two production signals:
///   - `transitions_expired_total > 0` means at least one TransitionSeal
///     reached `effective_epoch` in `AwaitingSigs` without crossing the
///     Dilithium3 sig threshold. Root cause is always one of: anchor set
///     too small to reach M-of-N, cosign path broken on this fleet, or
///     gossip not reaching anchors inside the window. The auto-scaler is
///     effectively off while this is non-zero.
///   - `transitions_mirror_write_failures_total > 0` means the
///     CF_TRANSITIONS_PENDING durability mirror is failing. Pending
///     proposals will be lost across restart; cosigns collected before a
///     crash won't replay.
///
/// Counters are in-memory, reset on restart → no false positives from
/// stale state. Mirror failures take priority because they imply all
/// pending state is being silently dropped, which is worse than individual
/// proposals expiring.
pub fn transitions_check(
    expired: u64,
    mirror_fail: u64,
    proposed: u64,
    finalized: u64,
) -> Check {
    if mirror_fail > 0 {
        Check {
            name: "transitions",
            status: CheckStatus::Warn,
            message: format!(
                "{mirror_fail} pending-mirror write failures (durability degraded)"
            ),
        }
    } else if expired > 0 {
        Check {
            name: "transitions",
            status: CheckStatus::Warn,
            message: format!(
                "{expired} proposals expired without threshold \
                 (proposed={proposed}, finalized={finalized}) — check anchor set + cosign"
            ),
        }
    } else {
        Check {
            name: "transitions",
            status: CheckStatus::Ok,
            message: format!("proposed={proposed}, finalized={finalized}"),
        }
    }
}

/// Peer-connectivity health check.
///
/// `push_total` (cumulative successful gossip pushes) doubles as a "did this
/// node ever have a working mesh?" signal:
///
/// - **Ok**: `>= min_peers` connected.
/// - **Warn**: `1..min_peers` connected (below the redundancy floor).
/// - **Critical**: `0` connected *after* the node had an active gossip mesh
///   (`push_total > 10`) — a genuine partition: it lost every peer it once
///   reached.
/// - **Warn**: `0` connected having never pushed gossip — a solo/genesis
///   authority (seals alone by design) or a still-bootstrapping node. 0 peers
///   is its design posture, so this is degraded redundancy, not total failure.
///
/// The last carve-out mirrors the unstaked-consensus carve-out in `evaluate`
/// and keeps the `/health` readiness rollup consistent with the
/// `elara_readiness_level` gauge (which already treats 0-peers-no-gossip as
/// Warn, not Critical). Without it a healthy solo authority self-reports RED:
/// `peers==0` forced the check Critical, and `determine_readiness` rolls
/// `Critical && peers==0` up to RED — a false "total system failure" signal.
///
/// `inbound_sync_age_secs` (None = never served) is the inbound-liveness
/// carve-out: `connected` counts only peers this node DIALED, so a
/// pull-gossip seed — which dials nobody and is dialed BY followers — reads
/// 0 forever while actively feeding a live mesh (authority seed observed
/// serving 6,400 records while `/health` said "running solo", 2026-07-02).
/// A record-level sync request served within `INBOUND_SYNC_LIVENESS_SECS`
/// is direct evidence the mesh reaches this node, so it beats both the
/// solo-Warn and the mesh-lost-Critical (a node that peers still pull from
/// is not partitioned). Header/checkpoint verbs deliberately don't stamp
/// the signal — light clients ride those and aren't mesh-peer evidence.
pub fn peers_check(
    connected: usize,
    min_peers: usize,
    push_total: u64,
    inbound_sync_age_secs: Option<u64>,
) -> Check {
    let inbound_live = inbound_sync_age_secs
        .map(|age| age <= INBOUND_SYNC_LIVENESS_SECS)
        .unwrap_or(false);
    if connected >= min_peers && connected > 0 {
        Check {
            name: "peers",
            status: CheckStatus::Ok,
            message: format!("{connected} connected"),
        }
    } else if connected > 0 {
        Check {
            name: "peers",
            status: CheckStatus::Warn,
            message: format!("{connected} connected (min: {min_peers})"),
        }
    } else if inbound_live {
        Check {
            name: "peers",
            status: CheckStatus::Ok,
            message: format!(
                "0 dialed; serving inbound sync (last {}s ago)",
                inbound_sync_age_secs.unwrap_or(0)
            ),
        }
    } else if push_total > 10 {
        Check {
            name: "peers",
            status: CheckStatus::Critical,
            message: "no connected peers (mesh lost)".into(),
        }
    } else {
        Check {
            name: "peers",
            status: CheckStatus::Warn,
            message: "no connected peers (running solo)".into(),
        }
    }
}

/// How recently a served record-level sync request still counts as
/// mesh-liveness evidence for `peers_check`. Generous vs the follower pull
/// cadence (seconds-to-minutes) so jitter can't flap the check, small vs a
/// real outage: after a partition the carve-out expires in ≤10 min and the
/// pre-existing mesh-lost/solo semantics take back over.
pub const INBOUND_SYNC_LIVENESS_SECS: u64 = 600;

/// Age in seconds of the most recent served record-level sync request
/// (`NodeState::stamp_inbound_sync`), `None` if never served. Feeds
/// `peers_check`'s inbound-liveness carve-out. Process-monotonic on both
/// sides (stamp stores `mono_secs()+1`), so an NTP backward step can't
/// shrink the age and mask a partition for up to `INBOUND_SYNC_LIVENESS_SECS`.
pub fn inbound_sync_age_secs(state: &Arc<NodeState>) -> Option<u64> {
    let stamped = state.last_inbound_sync_mono.load(Relaxed);
    if stamped == 0 {
        return None;
    }
    Some(crate::network::state::mono_secs().saturating_sub(stamped - 1))
}

/// Pure pull-sync staleness verdict (the `pull-sync` health check).
///
/// Catches a follower whose pulls have stopped succeeding (unreachable seed,
/// wire-incompatible peer, partition) — a class the record-age `sync` check
/// misses, because that check must ship lax/disabled (an idle testnet has old
/// records by design) while a caught-up follower still records a successful
/// 0-record pull every cycle. So `last_pull_unix` going stale is an unambiguous
/// "can't reach my seed" signal even when record-age looks fine.
///
/// - `staleness_max <= 0` → disabled → `None`.
/// - `attempts == 0` → this node never pulls (a pure seed/authority) → exempt → `None`.
/// - `last_pull_unix == 0` (tried, never once succeeded) → `Warn` only past the
///   boot grace (`uptime > staleness_max`), else `None` (don't flag a node that
///   hasn't had time for its first pull cycle).
/// - else → `Ok`/`Warn` by `now_unix - last_pull_unix` vs `staleness_max`.
pub fn pull_sync_check(
    staleness_max: f64,
    attempts: u64,
    last_pull_unix: u64,
    now_unix: f64,
    uptime: f64,
) -> Option<Check> {
    if staleness_max <= 0.0 || attempts == 0 {
        return None;
    }
    if last_pull_unix == 0 {
        if uptime > staleness_max {
            return Some(Check {
                name: "pull-sync",
                status: CheckStatus::Warn,
                message: format!(
                    "no successful pull in {uptime:.0}s since boot ({attempts} attempts) — seed unreachable or wire-incompatible"
                ),
            });
        }
        return None;
    }
    let staleness = now_unix - last_pull_unix as f64;
    Some(if staleness > staleness_max {
        Check {
            name: "pull-sync",
            status: CheckStatus::Warn,
            message: format!(
                "last successful pull {staleness:.0}s ago (max: {staleness_max:.0}s) — seed unreachable or wire-incompatible"
            ),
        }
    } else {
        Check {
            name: "pull-sync",
            status: CheckStatus::Ok,
            message: format!("last successful pull {staleness:.0}s ago"),
        }
    })
}

/// Determine emergency readiness level from health signals.
///
/// - **Green**: >= 1 peer, gossip failure < 20%, no critical checks.
/// - **Yellow**: < min_peers (but > 0), or gossip 20-50% failure, or any warn check.
/// - **Orange**: 0 connected peers, or gossip > 50% failure. Node is partitioned.
/// - **Red**: All checks critical + no peers.
pub fn determine_readiness(
    connected_peers: usize,
    gossip_fail_rate: f64,
    gossip_push_total: u64,
    worst_check: &CheckStatus,
) -> ReadinessLevel {
    // RED: total system failure (all checks critical + no peers)
    if *worst_check == CheckStatus::Critical && connected_peers == 0 {
        return ReadinessLevel::Red;
    }

    // ORANGE: partitioned — no peers or majority gossip failing
    if connected_peers == 0 && gossip_push_total > 10 {
        return ReadinessLevel::Orange;
    }
    if gossip_push_total > 10 && gossip_fail_rate > 0.5 {
        return ReadinessLevel::Orange;
    }

    // YELLOW: degraded
    if *worst_check == CheckStatus::Warn || *worst_check == CheckStatus::Critical {
        return ReadinessLevel::Yellow;
    }
    if gossip_push_total > 10 && gossip_fail_rate > 0.2 {
        return ReadinessLevel::Yellow;
    }

    ReadinessLevel::Green
}

/// Background health monitor loop. Periodically evaluates health and logs warnings.
pub async fn health_check_loop(state: Arc<NodeState>, mut shutdown: mpsc::Receiver<()>) {
    let interval = Duration::from_secs(state.config.health_check_interval_secs);
    if interval.is_zero() {
        debug!("health monitor disabled (interval = 0)");
        return;
    }

    debug!("health monitor started (interval = {}s)", interval.as_secs());

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = shutdown.recv() => {
                debug!("health monitor shutting down");
                return;
            }
        }

        // Stage 6 cooperative scheduler (Protocol §11.10).
        super::system_load::coop_yield_if_busy(&state.system_load).await;

        let report = evaluate(&state).await;

        // Audit-2026-05-07 §8 line 2339: cache the report so `/health`
        // serves O(1) lock-free. The handler used to call `evaluate()`
        // synchronously; on the 4 GB / 2 GB RAM tier during boot replay
        // the handler hung for 3-6 min on RocksDB + lock contention,
        // surfacing as `/health=000` to curl at 15 s timeout. The
        // background loop still pays that cost, but only once per
        // `health_check_interval_secs` and asynchronously — the
        // operator-facing /health response is always immediate.
        state
            .cached_health
            .store(Some(std::sync::Arc::new(report.clone())));

        // LIVENESS-3: Apply pending zone_transition if our observed max epoch
        // has crossed target_epoch. Runs on every node (witnesses included) so
        // a scheduled transition doesn't rot when the node boots with
        // current_max_epoch < target_epoch and is not seal-eligible.
        super::epoch::apply_pending_zone_transition_if_due(&state);

        // zone_count is consensus-critical and MUST be identical fleet-wide
        // (routing is `sha3(record_id)[0..8] % zone_count` — disagreement routes
        // the same record to different zones → divergent sealing/settlement =
        // fork). It is mutated ONLY via the signed, epoch-gated ZoneTransition
        // channel: Gap-4 autoscaler below emits it (authority-only), and
        // apply_pending_zone_transition_if_due / LIVENESS-2 boot replay apply it
        // deterministically on every node.
        //
        // A former peer-count heuristic lived here: it set
        // `zone_count = (connected_peers + 1) / zone_min_witnesses` on any
        // auto-mode node. With the default `zone_min_witnesses = 1` it computed
        // `zone_count = node_count`, diverging every follower from the authority
        // (observed live: a 2-node fleet drove a witness to zone_count=2 vs the
        // authority's 1 — a permanent, replay-unrecoverable desync, since the
        // later canonical 1→2 transition is rejected on `old_count` mismatch).
        // It also conflated node count with throughput (10k idle nodes need 1
        // zone, not 10k). Removed 2026-06-19 (zone_count fusion audit). Do NOT
        // reintroduce a local zone_count derivation — joiners acquire the
        // canonical count by replaying the authority's signed transition chain.

        // Gap 4: Activity-driven zone auto-scaling. Every node runs the
        // calculator for telemetry, but only the genesis authority emits
        // the `zone_transition` record that actually moves the network.
        if state.config.auto_zone_scale {
            if let Err(e) = run_auto_scale_tick(&state).await {
                warn!("auto_zone_scale tick failed: {e}");
            }
        }

        // Gap 5: Maintain our own zone subscription record so scoped jury
        // selection knows which zones we serve. Also prune expired entries
        // from the registry so it doesn't grow unbounded.
        if let Err(e) = run_zone_subscription_tick(&state).await {
            debug!("zone_subscription tick: {e}");
        }

        // Gap 4: Advance pending TransitionSeal lifecycle and prune
        // terminal entries. Pure bookkeeping — actual application of
        // finalized transitions (rewriting zone routing tables) lives with
        // the orchestrator and ships in a follow-up commit.
        // Transitions-F1: the staked-anchor trust set is fetched here (one
        // memoized read per health tick) because the tick itself is sync.
        let transition_trust = state.transition_trust_view().await;
        if let Err(e) = run_transition_tick(&state, &transition_trust) {
            debug!("transition tick: {e}");
        }

        // PARTITION-MERGE conservation trip-wire: scan recently-demoted seals
        // for cross-zone claim coverage (xzone_demotion_probe). Cheap when no
        // same-epoch demotions occurred (the common case). Runs on every node.
        super::xzone_demotion_probe::run_demoted_seal_xzone_scan_tick(&state).await;

        // Gap 4 pull backstop: anchors that missed a seal via gossip
        // pull one random peer's `/transitions?status=awaitingsigs`
        // and fold unknown ids into their local store. Keeps M-of-N
        // collection alive across transient partitions / peer backoff.
        // Non-anchors early-return inside the fn.
        super::routes::transitions::run_transition_pull_tick(&state).await;

        let level = report.readiness.as_str().to_uppercase();
        match report.status {
            CheckStatus::Ok => {
                debug!("health: OK [{level}]");
            }
            CheckStatus::Warn => {
                let warnings: Vec<_> = report.checks.iter()
                    .filter(|c| c.status != CheckStatus::Ok)
                    .map(|c| format!("{}={}", c.name, c.message))
                    .collect();
                warn!("health: DEGRADED [{level}] — {}", warnings.join(", "));
            }
            CheckStatus::Critical => {
                let crits: Vec<_> = report.checks.iter()
                    .filter(|c| c.status == CheckStatus::Critical)
                    .map(|c| format!("{}={}", c.name, c.message))
                    .collect();
                warn!("health: CRITICAL [{level}] — {}", crits.join(", "));
            }
        }
    }
}

fn now_ts() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Gap 4: One tick of activity-driven zone scaling.
///
/// 1. Snapshot per-zone activity from `EpochState.zone_activity_rate`
/// 2. Feed to `AutoScaler.observe()` which applies hysteresis
/// 3. If the result is Split/Merge AND this node is the genesis authority,
///    emit a signed `zone_transition` record scheduled for the next
///    epoch boundary (+ small safety margin).
///
/// Scale: O(active_zones) per tick. Zones with no activity contribute nothing.
async fn run_auto_scale_tick(state: &Arc<NodeState>) -> crate::errors::Result<()> {
    use crate::errors::ElaraError;

    // Snapshot activity and current max epoch (for target_epoch selection).
    let (per_zone_activity, current_max_epoch) = {
        let epoch = state.epoch.read().map_err(|e| ElaraError::Storage(e.to_string()))?;
        let activity = epoch.zone_activity_rate.clone();
        let max_epoch = epoch.latest_epoch.values().copied().max().unwrap_or(0);
        (activity, max_epoch)
    };

    let current_zone_count = super::consensus::get_zone_count();

    // Run the scaler (hysteresis included).
    let decision = {
        let mut scaler = state.auto_scaler.lock_recover();
        scaler.observe(&per_zone_activity, current_zone_count)
    };

    let Some(decision) = decision else {
        debug!("auto_scale: no hysteresis fire this tick (current_zones={current_zone_count})");
        return Ok(());
    };

    // Telemetry: every node logs the decision, even if it won't emit.
    let (direction, new_count, avg_rate) = match &decision {
        super::auto_scale::ScalingDecision::Split { new_count, avg_rate } => {
            ("split", *new_count, *avg_rate)
        }
        super::auto_scale::ScalingDecision::Merge { new_count, avg_rate } => {
            ("merge", *new_count, *avg_rate)
        }
        super::auto_scale::ScalingDecision::NoChange { .. } => return Ok(()),
    };
    info!(
        "auto_scale: {direction} recommended (zones {current_zone_count} → {new_count}, avg rate {:.3} rec/s)",
        avg_rate,
    );

    // Only the genesis authority emits the zone_transition record.
    if state.identity.identity_hash != state.config.genesis_authority {
        debug!("auto_scale: not genesis authority — decision is advisory only");
        return Ok(());
    }

    // Choose target_epoch a few epochs in the future so every node has time
    // to receive the transition record before it fires.
    let target_epoch = current_max_epoch + 3;
    let meta = super::epoch::zone_transition_metadata(target_epoch, current_zone_count, new_count);
    let parents = super::server::dag_tip_parents(state, 3).await;
    let content_str =
        format!("zone_transition:{current_zone_count}:{new_count}:epoch{target_epoch}");
    let mut record = crate::record::ValidationRecord::create(
        content_str.as_bytes(),
        state.identity.public_key.clone(),
        parents,
        crate::record::Classification::Public,
        Some(meta),
    );
    record.nonce = state.next_slot_nonce();
    if state.config.light_mode {
        state.identity.sign_record_light(&mut record)
    } else {
        state.identity.sign_record(&mut record)
    }
    .map_err(|e| ElaraError::Wire(format!("auto_scale sign failed: {e}")))?;

    match super::gossip::insert_record_synced(state, record.clone()).await {
        Ok(_) => info!(
            "auto_scale: zone_transition emitted — {current_zone_count} → {new_count} at epoch {target_epoch} (id {})",
            record.id,
        ),
        Err(e) => warn!("auto_scale: zone_transition insert failed: {e}"),
    }

    // Gap 4 orchestrator: in parallel with the legacy zone_transition
    // record (kept for backward compat with existing nodes), emit a
    // TransitionSeal into the TransitionStore. This is the path that
    // will eventually replace the legacy record once light clients
    // consume seals directly; today it populates `/transitions/*`
    // and seeds M-of-N sig collection.
    //
    // Only one anchor actually inserts; other anchors would duplicate
    // the seal hash and their insert would merge via add_sig. Today
    // only the genesis authority runs this path (gated above), so the
    // seal is 1-of-N and won't reach threshold until anchor rotation
    // lands. That's fine — the pipeline is live, and the counters tell
    // operators the orchestrator is working.
    // Use state_core's lock-free snapshot for current_epoch — same path
    // TransitionStore tick loop uses (see `run_transition_store_tick`).
    // If state_core isn't warm yet, fall back to `current_max_epoch`
    // from the EpochState read we already have.
    let current_epoch = state
        .state_core
        .get()
        .map(|c| c.read_snapshot().current_epoch)
        .unwrap_or(current_max_epoch);

    // Assemble VRF-registered anchor candidates for committee_hash computation.
    // Reads under both locks sequentially — vrf_registry (std::sync) first,
    // then ledger (tokio::sync). Both reads are fast (no disk I/O).
    let candidates = {
        use super::zone_committee::assemble_candidates;
        use super::RwLockRecover;
        let registered: Vec<String> = state
            .vrf_registry
            .read_recover()
            .registered_identities()
            .iter()
            .map(|s| s.to_string())
            .collect();
        let ledger = state.ledger.read().await;
        assemble_candidates(registered, |id| ledger.staked(id))
    };

    // Gap 4 orchestrator silent-no-op fix: `pick_transition_target` requires
    // `per_zone_activity.len() >= 2` for a Merge target. The activity map
    // only tracks zones that produced records during the last sample window,
    // so a fleet with a cold zone never appears there and the merge picker
    // returns None — leading to an infinite "merge recommended" log loop
    // with `transitions_orchestrator_proposed_total` stuck at zero.
    // Enrich the map with rate=0 entries for any active zones the registry
    // knows about. observe() has already run on the original (correct)
    // map, so this enrichment is downstream-only and doesn't perturb the
    // hysteresis decision.
    let per_zone_activity_for_picker = {
        use super::RwLockRecover;
        let mut map = per_zone_activity.clone();
        let reg = state.zone_registry.read_recover();
        for zone in reg.active_zones() {
            map.entry(zone.clone()).or_insert(0.0);
        }
        map
    };

    // ARCH-2 (c) cooldown gate: on a low-traffic network, hysteresis fires
    // every tick because avg_rate stays below MERGE threshold. Without this
    // gate, the orchestrator emits a fresh seal every 2 minutes for the same
    // parent zones, racing `transitions_expired_total` upward without ever
    // collecting M-of-N sigs. Skip if an active proposal already targets the
    // same parents — the next tick will re-evaluate after the previous one
    // finalizes/expires/is vetoed.
    if let Some(target) =
        super::auto_scale::pick_transition_target(&decision, &per_zone_activity_for_picker)
    {
        // Pre-flight: refuse to propose what can't possibly finalize. Sigs
        // come from registered+staked anchors (the same `candidates` pool
        // assembled above), so if that pool is below the kind's M-of-N
        // threshold the seal would expire after the dispute window without
        // ever being countersigned. Without this gate, low-anchor fleets
        // (e.g. testnet with 2 anchors vs MERGE_ANCHOR_THRESHOLD=7) emit a
        // dead-on-arrival proposal every tick, racing `expired_total` while
        // `finalized_total` stays at zero forever.
        let required = match &target {
            super::auto_scale::TransitionTarget::Split { .. } => {
                super::zone_transition_seal::SPLIT_ANCHOR_THRESHOLD
            }
            super::auto_scale::TransitionTarget::Merge { .. } => {
                super::zone_transition_seal::MERGE_ANCHOR_THRESHOLD
            }
        };
        if candidates.len() < required {
            state
                .transitions_orchestrator_skipped_undersized_pool_total
                .fetch_add(1, Relaxed);
            debug!(
                "auto_scale: anchor pool size {} < kind threshold {} — skipping propose (would expire dead-on-arrival)",
                candidates.len(),
                required,
            );
            return Ok(());
        }

        let parents: Vec<crate::network::zone::ZoneId> = match &target {
            super::auto_scale::TransitionTarget::Split { parent } => vec![parent.clone()],
            super::auto_scale::TransitionTarget::Merge { a, b } => vec![a.clone(), b.clone()],
        };
        let already_pending = {
            use super::RwLockRecover;
            state
                .transitions
                .read_recover()
                .has_active_with_parents(&parents)
        };
        if already_pending {
            state
                .transitions_orchestrator_skipped_pending_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!(
                "auto_scale: active proposal for parents={:?} already pending — skipping orchestrator propose",
                parents
            );
            return Ok(());
        }
    }

    let seal_opt = super::auto_scale::propose_transition_from_decision(
        &state.rocks,
        &state.identity,
        &decision,
        &per_zone_activity_for_picker,
        current_epoch,
        &candidates,
        super::zone_committee::DEFAULT_COMMITTEE_SIZE,
    );
    match seal_opt {
        Ok(Some(seal)) => {
            // Hold the write lock only for the insert itself. Gossip
            // broadcast goes through the HTTP client which must not
            // run under a sync lock (would block the tokio worker),
            // and conceptually broadcast is a peer-facing concern
            // separate from store bookkeeping.
            let inserted_id: Option<[u8; 32]> = {
                let mut store = state
                    .transitions
                    .write()
                    .map_err(|e| ElaraError::Storage(format!("transitions rwlock poisoned: {e}")))?;
                match store.insert(seal.clone()) {
                    Ok(id) => {
                        state
                            .transitions_proposed_by_orchestrator_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        info!(
                            "auto_scale: TransitionSeal proposed — kind={:?} parents={} effective_epoch={} seal_id={}",
                            seal.kind,
                            seal.parents.len(),
                            seal.effective_epoch,
                            hex::encode(id),
                        );
                        Some(id)
                    }
                    Err(e) => {
                        state
                            .transitions_orchestrator_insert_rejected_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        warn!("auto_scale: TransitionSeal insert rejected: {e}");
                        None
                    }
                }
            };
            // Gossip the seal to peers so other anchors can sign it and the
            // dispute window covers the whole anchor set — not just this
            // node. Fires only on successful insert so a duplicate/full
            // rejection doesn't amplify. Internal sqrt(n) fan-out +
            // SeenSet dedup mean a broadcast storm can't happen even if
            // this tick fires every health cycle.
            if inserted_id.is_some() {
                super::gossip::push_transition_seal_to_peers(state, &seal).await;
            }
        }
        Ok(None) => {
            // pick_transition_target returned None — decision was
            // NoChange or activity snapshot was unusable. Already
            // logged at the decision level above.
        }
        Err(e) => {
            warn!("auto_scale: propose_transition_from_decision failed: {e}");
        }
    }

    Ok(())
}

/// Gap 4: Advance pending TransitionSeal lifecycle each health cycle.
///
/// Runs `TransitionStore::tick(current_epoch)` which flips AwaitingSigs →
/// Expired and DisputeWindow → Finalized once `effective_epoch` has
/// passed, then prunes terminal entries older than the retention window.
///
/// Finalized seals are then (1) persisted durably to `CF_TRANSITIONS_FINAL`
/// via [`persist_finalized_transitions`] and (2) applied to the live
/// [`ZoneRegistry`] via [`apply_finalized_to_zone_registry`] in the same
/// tick — so a fresh `Finalized` flip both survives restart and updates
/// routing + committee iteration without operator intervention. Per-seal
/// M-of-N anchor-sig verify runs before either step so a forged seal that
/// gossiped past per-message verify cannot mutate state.
///
/// Scale: O(pending) per tick, hard-capped by `MAX_PENDING_TRANSITIONS`
/// (= 1024) — well under a millisecond at that size.
pub(crate) fn run_transition_tick(
    state: &Arc<NodeState>,
    trust: &std::collections::HashSet<[u8; 32]>,
) -> crate::errors::Result<()> {
    use crate::errors::ElaraError;

    // Best-effort current epoch — same fallback as the HTTP handlers. If the
    // state_core isn't warm yet (cold boot), skip the tick rather than
    // drive everything to Expired on epoch 0.
    let Some(core) = state.state_core.get() else {
        return Ok(());
    };
    let current_epoch = core.read_snapshot().current_epoch;
    if current_epoch == 0 {
        return Ok(());
    }

    // Retention: keep terminal entries for a few epochs so HTTP clients
    // that poll after the transition fires can still observe the final
    // status. Short retention because the store is memory-only.
    const RETENTION_EPOCHS: u64 = 10;

    // Collect (id, seal) for newly-finalized entries while the write lock
    // is held so we can persist them durably outside the lock. Serializing
    // to JSON inside the lock is cheap (sub-millisecond even for the full
    // seal), but the RocksDB write is not — keep the lock as tight as
    // possible.
    let (finalized_with_seals, finalized_kinds, expired_ids, sig_rejected_ids, pruned) = {
        let mut store = state
            .transitions
            .write()
            .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;
        let outcome = store.tick(current_epoch);
        let mut with_seals: Vec<([u8; 32], Vec<u8>)> =
            Vec::with_capacity(outcome.newly_finalized.len());
        // Gap 4 close-out: seals whose M-of-N anchor sigs fail verify
        // against the local `CF_IDENTITIES` registry. Tracked separately
        // so `clear_pending_mirror` still wipes the stale pending row
        // (nothing else will now) without us persisting or applying the
        // seal itself. See `zone_registry_tick_sig_verify_failures_total`.
        let mut sig_rejected: Vec<[u8; 32]> = Vec::new();
        // Observability: track Split/Merge breakdown at the finalize
        // edge. Captured under the write lock so the kind counters
        // stay in sync with the pending store view. Released below.
        let mut split_finalized: u64 = 0;
        let mut merge_finalized: u64 = 0;
        for id in &outcome.newly_finalized {
            if let Some(pending) = store.get(id) {
                // Gap 4 close-out: verify M-of-N Dilithium3 anchor sigs
                // against the locally-registered pubkey set BEFORE we
                // persist to CF_TRANSITIONS_FINAL or mutate the
                // zone_registry. The store reached threshold on sig
                // *count* (distinct anchor_identity_hash entries), but
                // only the HTTP `add_sig` handler runs crypto verify
                // on each incoming sig — gossip-ingest and direct
                // inserts bypass that, so without this gate a forged
                // seal that gossiped past verification would still
                // flip routing on every node and persist to disk
                // (replayed at boot forever).
                let mut anchor_pubkeys: std::collections::HashMap<[u8; 32], Vec<u8>> =
                    std::collections::HashMap::with_capacity(pending.seal.proposer_sigs.len());
                for sig in &pending.seal.proposer_sigs {
                    // Transitions-F1: stake pre-filter. `verify_sigs`
                    // silently skips identities absent from this map, so
                    // leaving an unstaked signer OUT is what keeps its sig
                    // from counting toward the M-of-N threshold. This
                    // apply-site gate is independent of the ingest-side
                    // `verify_anchor_sig` gate — gossip races and direct
                    // store inserts can land sigs that never crossed an
                    // ingest handler, and this tick is the ONLY writer of
                    // CF_TRANSITIONS_FINAL (boot replay trusts CF
                    // presence), so the filter here is load-bearing.
                    if !trust.contains(&sig.anchor_identity_hash) {
                        state
                            .transition_sig_stake_rejected_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        continue;
                    }
                    let hex_key = hex::encode(sig.anchor_identity_hash);
                    if let Some(pk) = state.rocks.get_public_key(&hex_key) {
                        anchor_pubkeys.insert(sig.anchor_identity_hash, pk);
                    }
                }
                if let Err(e) = pending
                    .seal
                    .verify_sigs(&anchor_pubkeys, pending.seal.required_threshold())
                {
                    warn!(
                        "transition tick: rejecting finalized seal {} — verify_sigs failed (threshold={}): {e}",
                        hex::encode(id),
                        pending.seal.required_threshold(),
                    );
                    state
                        .zone_registry_tick_sig_verify_failures_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    sig_rejected.push(*id);
                    continue;
                }
                match pending.seal.kind {
                    crate::network::zone_transition_seal::TransitionKind::Split => {
                        split_finalized += 1;
                    }
                    crate::network::zone_transition_seal::TransitionKind::Merge => {
                        merge_finalized += 1;
                    }
                }
                match serde_json::to_vec(&pending.seal) {
                    Ok(bytes) => with_seals.push((*id, bytes)),
                    Err(e) => warn!(
                        "transition tick: failed to serialize finalized seal {}: {e}",
                        hex::encode(id),
                    ),
                }
            }
        }
        let expired = outcome.newly_expired.clone();
        let pruned = store.prune(current_epoch, RETENTION_EPOCHS);
        (
            with_seals,
            (split_finalized, merge_finalized),
            expired,
            sig_rejected,
            pruned,
        )
    };

    // Persist each finalized seal to CF_TRANSITIONS_FINAL so a restart
    // doesn't forget them before the orchestrator apply path runs.
    persist_finalized_transitions(&state.rocks, &finalized_with_seals);

    // Gap 5: mirror each durable seal into the live ZoneRegistry so
    // routing + committee iteration reflect the post-transition tree
    // without waiting for a restart. Apply errors are logged per-id
    // and counted — a coherent fleet never fires the failure path.
    apply_finalized_to_zone_registry(state, &finalized_with_seals);

    // Now that finalized seals are durable in FINAL, clear their pending
    // mirror. Also clear any freshly-expired entries — they never reached
    // threshold so there's nothing to persist; they just need to stop
    // replaying on restart. Sig-rejected ids (Gap 4 close-out) are
    // included too: the seal never made it to FINAL, but the pending
    // mirror row is stale (store has moved past AwaitingSigs) and would
    // otherwise re-hydrate on restart.
    let terminal_ids: Vec<[u8; 32]> = finalized_with_seals
        .iter()
        .map(|(id, _)| *id)
        .chain(expired_ids.iter().copied())
        .chain(sig_rejected_ids.iter().copied())
        .collect();
    clear_pending_mirror(&state.rocks, &terminal_ids);

    // Observability: bump finalized/expired counters AFTER the durable
    // persist so a crash between tick() and put_cf_raw doesn't inflate
    // the finalized total without a matching CF row. Split/merge
    // subtotals invariant: split + merge == total, enforced below by
    // construction (single counted increment per newly_finalized id).
    let (split_finalized, merge_finalized) = finalized_kinds;
    let total_finalized = split_finalized + merge_finalized;
    if total_finalized > 0 {
        state
            .transitions_finalized_total
            .fetch_add(total_finalized, std::sync::atomic::Ordering::Relaxed);
        if split_finalized > 0 {
            state
                .transitions_finalized_split_total
                .fetch_add(split_finalized, std::sync::atomic::Ordering::Relaxed);
        }
        if merge_finalized > 0 {
            state
                .transitions_finalized_merge_total
                .fetch_add(merge_finalized, std::sync::atomic::Ordering::Relaxed);
        }
    }
    if !expired_ids.is_empty() {
        state
            .transitions_expired_total
            .fetch_add(expired_ids.len() as u64, std::sync::atomic::Ordering::Relaxed);
    }

    if !finalized_with_seals.is_empty() {
        info!(
            "transition tick: {} proposal(s) finalized + persisted at epoch {} (split={}, merge={}, ids: {})",
            finalized_with_seals.len(),
            current_epoch,
            split_finalized,
            merge_finalized,
            finalized_with_seals
                .iter()
                .map(|(id, _)| hex::encode(id))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    if pruned > 0 {
        debug!(
            "transition tick: pruned {pruned} terminal entries (retention={RETENTION_EPOCHS} epochs)"
        );
    }
    Ok(())
}

/// Gap 4: delete each terminal TransitionSeal id from `CF_TRANSITIONS_PENDING`.
///
/// Called from `run_transition_tick` once an entry has either been
/// persisted to `CF_TRANSITIONS_FINAL` (for finalized) or is guaranteed
/// not to be replayed (for expired / vetoed). Errors logged and swallowed
/// — a failed delete means the pending CF retains a stale entry which
/// boot-replay can detect via in-memory store status.
fn clear_pending_mirror(
    rocks: &crate::storage::rocks::StorageEngine,
    ids: &[[u8; 32]],
) {
    for id in ids {
        if let Err(e) = rocks.delete_cf_raw(
            crate::storage::rocks::CF_TRANSITIONS_PENDING,
            id,
        ) {
            warn!(
                "transition tick: failed to clear pending mirror {}: {e}",
                hex::encode(id),
            );
        }
    }
}

/// Gap 4: write each freshly-finalized TransitionSeal to `CF_TRANSITIONS_FINAL`.
///
/// Idempotent — re-writing the same (id, seal_bytes) on a subsequent tick
/// is a no-op in RocksDB semantics. Errors are logged and swallowed: losing
/// one durable write is recoverable (the next tick will re-observe the
/// Finalized entry and retry), but propagating would abort the whole
/// health cycle.
///
/// Pulled out of `run_transition_tick` so the persistence contract is
/// directly unit-testable without spinning up a full state_core.
fn persist_finalized_transitions(
    rocks: &crate::storage::rocks::StorageEngine,
    finalized_with_seals: &[([u8; 32], Vec<u8>)],
) {
    for (id, seal_bytes) in finalized_with_seals {
        if let Err(e) = rocks.put_cf_raw(
            crate::storage::rocks::CF_TRANSITIONS_FINAL,
            id,
            seal_bytes,
        ) {
            warn!(
                "transition tick: failed to persist finalized seal {}: {e}",
                hex::encode(id),
            );
        }
    }
}

/// Gap 5: apply freshly-persisted finalized seals to the live
/// `ZoneRegistry`.
///
/// Called from `run_transition_tick` immediately after
/// [`persist_finalized_transitions`] has made each seal durable. Decodes
/// each `(id, seal_bytes)` pair — decoding from the just-serialized
/// bytes is trivially safe, but we re-decode instead of threading a
/// second copy through the call site — and applies it under the
/// registry write lock.
///
/// Apply-time failures (consistency violations) are logged per-id and
/// counted on `state.zone_registry_tick_apply_failures_total`; the rest
/// of the batch still goes through so one anomalous seal doesn't stall
/// the whole tick. In a coherent fleet the failure path is dead code —
/// any seal that reached `CF_TRANSITIONS_FINAL` has already cleared
/// dispute + M-of-N cosign.
fn apply_finalized_to_zone_registry(
    state: &Arc<NodeState>,
    finalized_with_seals: &[([u8; 32], Vec<u8>)],
) {
    if finalized_with_seals.is_empty() {
        return;
    }
    let mut registry = match state.zone_registry.write() {
        Ok(r) => r,
        Err(e) => {
            warn!("zone_registry lock poisoned at tick apply: {e}");
            return;
        }
    };
    for (id, seal_bytes) in finalized_with_seals {
        let seal: crate::network::zone_transition_seal::TransitionSeal =
            match serde_json::from_slice(seal_bytes) {
                Ok(s) => s,
                Err(e) => {
                    // Should be impossible — we just serialized this seal
                    // in the same tick. Log and move on.
                    warn!(
                        "zone_registry tick: failed to decode just-persisted seal {}: {e}",
                        hex::encode(id),
                    );
                    continue;
                }
            };
        match registry.apply_transition(&seal) {
            Ok(()) => {
                state
                    .zone_registry_tick_applied_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => {
                warn!(
                    "zone_registry tick: apply_transition rejected seal {}: {e}",
                    hex::encode(id),
                );
                state
                    .zone_registry_tick_apply_failures_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

/// Gap 5: rebuild the live [`ZoneRegistry`] from `CF_TRANSITIONS_FINAL`
/// at boot. Seeds with the current flat-modulo zone set as the genesis
/// layout, then replays every finalized seal in `(effective_epoch,
/// seal_id)` order.
///
/// Counts applied / decode-failed / apply-failed seals on the
/// corresponding `state.zone_registry_boot_*_total` atomics so
/// operators can confirm via `/transitions/stats` that a restart
/// rebuilt the registry cleanly. On a healthy node:
/// `applied == total_finalized_in_cf`, both failure counters are zero.
///
/// Safe to call multiple times — each call swaps the registry wholesale
/// so there's no partial-state risk if boot re-runs after a retry.
pub fn boot_rehydrate_zone_registry(state: &Arc<NodeState>) -> usize {
    // Genesis layout: the flat-modulo zones currently in use. At the
    // first boot on a fresh network this is the pre-transition tree
    // the naive routing assumes; any subsequent splits/merges walk
    // from these starting zones.
    let zone_count = crate::network::consensus::get_zone_count();
    let genesis: Vec<crate::network::zone::ZoneId> = (0..zone_count)
        .map(crate::network::zone::ZoneId::from_legacy)
        .collect();

    let (registry, stats) = match crate::network::zone_registry::rebuild_from_finalized(
        &state.rocks,
        genesis,
    ) {
        Ok(pair) => pair,
        Err(e) => {
            warn!("boot_rehydrate_zone_registry: rebuild failed: {e}");
            return 0;
        }
    };

    let applied = stats.seals_applied;

    state
        .zone_registry_boot_applied_total
        .store(stats.seals_applied as u64, std::sync::atomic::Ordering::Relaxed);
    state
        .zone_registry_boot_decode_failures_total
        .store(stats.seals_skipped_decode as u64, std::sync::atomic::Ordering::Relaxed);
    state
        .zone_registry_boot_apply_failures_total
        .store(
            stats.seals_skipped_apply.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

    for (id_hex, err) in &stats.seals_skipped_apply {
        warn!("boot_rehydrate_zone_registry: apply rejected seal {id_hex}: {err}");
    }
    if stats.truncated {
        warn!(
            "boot_rehydrate_zone_registry: CF_TRANSITIONS_FINAL exceeded MAX_REPLAY_SEALS — \
             registry partial"
        );
    }

    match state.zone_registry.write() {
        Ok(mut guard) => *guard = registry,
        Err(e) => {
            warn!("boot_rehydrate_zone_registry: zone_registry lock poisoned: {e}");
            return 0;
        }
    }

    if applied > 0
        || stats.seals_skipped_decode > 0
        || !stats.seals_skipped_apply.is_empty()
    {
        info!(
            "boot_rehydrate_zone_registry: read={} applied={} decode_failed={} apply_failed={} \
             highest_effective_epoch={}",
            stats.seals_read,
            applied,
            stats.seals_skipped_decode,
            stats.seals_skipped_apply.len(),
            state
                .zone_registry
                .read()
                .map(|r| r.highest_effective_epoch())
                .unwrap_or(0),
        );
    }

    applied
}

/// Gap 4: read a previously-finalized TransitionSeal from `CF_TRANSITIONS_FINAL`.
///
/// Returns `None` if the id isn't persisted or the stored bytes fail to
/// deserialize (indicates on-disk corruption — caller should treat as
/// unknown and log separately if recovery matters).
pub fn load_finalized_transition(
    rocks: &crate::storage::rocks::StorageEngine,
    id: &[u8; 32],
) -> Option<crate::network::zone_transition_seal::TransitionSeal> {
    let bytes = rocks
        .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, id)
        .ok()
        .flatten()?;
    serde_json::from_slice(&bytes).ok()
}

/// Gap 4: on boot, re-hydrate the in-memory TransitionStore from
/// `CF_TRANSITIONS_PENDING` so proposals survive a node restart.
///
/// CF_TRANSITIONS_PENDING is populated by the HTTP handlers (propose /
/// sig / veto) and pruned by `run_transition_tick` when entries reach a
/// terminal state. On cold start, the in-memory store is empty — this
/// function walks the CF, deserializes each entry, and re-inserts it
/// into the store via a direct map insert (bypassing `insert`'s
/// validation because the entry already passed validation on the
/// original write).
///
/// Returns the number of entries replayed. Logs (never fails) so boot
/// is robust against on-disk corruption: a malformed row is skipped
/// rather than blocking node startup.
///
/// Scale: bounded by `MAX_PENDING_TRANSITIONS` (1024) so worst-case
/// deserialization cost is a few ms at boot — negligible vs. the rest
/// of node startup.
pub fn boot_replay_pending_transitions(state: &Arc<NodeState>) -> usize {
    let mut store = match state.transitions.write() {
        Ok(s) => s,
        Err(e) => {
            warn!("boot_replay_pending: transitions lock poisoned: {e}");
            return 0;
        }
    };
    let replayed = replay_pending_transitions_from_rocks(&state.rocks, &mut store);
    // Record under Relaxed — this is a boot-time single-write counter that's
    // later only read by the stats handler; no other writer races.
    state
        .transitions_boot_replayed_total
        .store(replayed as u64, std::sync::atomic::Ordering::Relaxed);
    replayed
}

/// Pure core of [`boot_replay_pending_transitions`]. Takes a storage
/// engine + a write-locked store so it's directly unit-testable without
/// constructing a full `NodeState`.
///
/// Corrupt rows are skipped (logged). Terminal-status rows (a crash
/// between status flip and CF delete could leave one) are also skipped
/// so we don't rehydrate a dead proposal.
pub(crate) fn replay_pending_transitions_from_rocks(
    rocks: &crate::storage::rocks::StorageEngine,
    store: &mut crate::network::transition_store::TransitionStore,
) -> usize {
    use crate::network::transition_store::{PendingStatus, PendingTransition};

    let rows = match rocks.list_cf_raw(
        crate::storage::rocks::CF_TRANSITIONS_PENDING,
        crate::network::transition_store::MAX_PENDING_TRANSITIONS,
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!("boot_replay_pending: list_cf_raw failed: {e}");
            return 0;
        }
    };

    if rows.is_empty() {
        return 0;
    }

    let mut replayed = 0;
    let mut skipped_corrupt = 0;
    let mut skipped_terminal = 0;
    for (_key, value) in rows {
        let pending: PendingTransition = match serde_json::from_slice(&value) {
            Ok(p) => p,
            Err(e) => {
                warn!("boot_replay_pending: skipping corrupt row: {e}");
                skipped_corrupt += 1;
                continue;
            }
        };

        if matches!(
            pending.status,
            PendingStatus::Vetoed | PendingStatus::Finalized | PendingStatus::Expired
        ) {
            skipped_terminal += 1;
            continue;
        }

        store.replay_insert(pending);
        replayed += 1;
    }

    if replayed > 0 || skipped_corrupt > 0 || skipped_terminal > 0 {
        info!(
            "boot_replay_pending_transitions: replayed={replayed} \
             skipped_corrupt={skipped_corrupt} skipped_terminal={skipped_terminal}"
        );
    }
    replayed
}

/// Gap 5: maintain this node's own zone subscription and prune expired entries.
///
/// A node is "subscribed" to a zone when it has published a signed
/// `zone_subscription` record indicating it serves that zone. Scoped jury
/// selection (`consensus::select_epoch_jury_scoped`) filters the global
/// staked set against the subscription registry before VRF scoring.
///
/// This tick runs every health cycle and does two things:
///   1. Prunes expired subscription entries from the local registry
///      (bounded by `MAX_PRUNE_PER_CALL` so cost is constant).
///   2. If our current subscription is expiring soon, or we've never
///      published one, emits a new signed `zone_subscription` record that
///      covers every zone this node currently serves.
///
/// **Which zones do we serve?** Until we add sharding (Gap 6 territory),
/// full-profile nodes serve every zone; light nodes serve none. Sharding
/// will tighten this to a per-node subset.
///
/// Scale: O(active_zones) per emission (bounded by zone_count config).
async fn run_zone_subscription_tick(state: &Arc<NodeState>) -> crate::errors::Result<()> {
    use crate::errors::ElaraError;

    let our_hash = state.identity.identity_hash.clone();
    let current_epoch = {
        let epoch = state.epoch.read().map_err(|e| ElaraError::Storage(e.to_string()))?;
        epoch.latest_epoch.values().copied().max().unwrap_or(0)
    };

    // Prune expired entries regardless of whether we emit. Cheap, bounded.
    {
        let mut reg = state.zone_subscriptions.lock_recover();
        let pruned = reg.prune(current_epoch);
        if pruned > 0 {
            debug!("zone_subscriptions: pruned {pruned} expired entries");
        }
    }

    // Light nodes do not witness, so they do not subscribe.
    if state.config.light_mode {
        return Ok(());
    }

    // Are we staked? Unstaked nodes can't witness, so no subscription needed.
    let staked_amount = {
        let ledger = state.ledger.read().await;
        ledger.staked(&our_hash)
    };
    if staked_amount == 0 {
        return Ok(());
    }

    // Decide whether we need to (re)publish: only emit if we have no current
    // subscription OR ours is within the refresh margin of expiring.
    let validity_epochs = state.config.zone_subscription_validity_epochs.max(10);
    let refresh_margin = state
        .config
        .zone_subscription_refresh_margin
        .max(1)
        .min(validity_epochs.saturating_sub(1));

    let needs_emit = {
        let reg = state.zone_subscriptions.lock_recover();
        match reg.valid_until(&our_hash) {
            None => true,
            Some(vu) => vu.saturating_sub(current_epoch) <= refresh_margin,
        }
    };
    if !needs_emit {
        return Ok(());
    }

    // Build the zone list. For now, full nodes serve every zone.
    let zone_count = super::consensus::get_zone_count();
    let zones: Vec<crate::ZoneId> = (0..zone_count)
        .map(crate::ZoneId::from_legacy)
        .collect();
    if zones.is_empty() {
        return Ok(());
    }

    let valid_until = current_epoch + validity_epochs;
    let meta = super::zone_subscription::subscription_metadata(
        &our_hash,
        &zones,
        current_epoch,
        valid_until,
    );
    let parents = super::server::dag_tip_parents(state, 3).await;
    let content = format!(
        "zone_subscription:{}:{}:{}",
        our_hash,
        zones.len(),
        current_epoch,
    );
    let mut record = crate::record::ValidationRecord::create(
        content.as_bytes(),
        state.identity.public_key.clone(),
        parents,
        crate::record::Classification::Public,
        Some(meta),
    );
    record.nonce = state.next_slot_nonce();
    state
        .identity
        .sign_record(&mut record)
        .map_err(|e| ElaraError::Wire(format!("zone_subscription sign failed: {e}")))?;

    match super::gossip::insert_record_synced(state, record.clone()).await {
        Ok(_) => info!(
            "zone_subscription emitted: zones={} valid_until_epoch={} id={}",
            zones.len(),
            valid_until,
            record.id,
        ),
        Err(e) => warn!("zone_subscription insert failed: {e}"),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_status_ordering() {
        assert!(matches!(CheckStatus::Ok, CheckStatus::Ok));
        assert!(matches!(CheckStatus::Warn, CheckStatus::Warn));
        assert!(matches!(CheckStatus::Critical, CheckStatus::Critical));
    }

    #[test]
    fn test_health_report_status_str() {
        let report = HealthReport {
            status: CheckStatus::Ok,
            readiness: ReadinessLevel::Green,
            checks: vec![],
            timestamp: 0.0,
        };
        assert_eq!(report.status_str(), "healthy");

        let report = HealthReport {
            status: CheckStatus::Warn,
            readiness: ReadinessLevel::Yellow,
            checks: vec![],
            timestamp: 0.0,
        };
        assert_eq!(report.status_str(), "degraded");

        let report = HealthReport {
            status: CheckStatus::Critical,
            readiness: ReadinessLevel::Red,
            checks: vec![],
            timestamp: 0.0,
        };
        assert_eq!(report.status_str(), "critical");
    }

    #[test]
    fn test_check_serialization() {
        let check = Check {
            name: "peers",
            status: CheckStatus::Ok,
            message: "3 connected".into(),
        };
        let json = serde_json::to_value(&check).unwrap();
        assert_eq!(json["name"], "peers");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["message"], "3 connected");
    }

    #[test]
    fn test_report_serialization() {
        let report = HealthReport {
            status: CheckStatus::Warn,
            readiness: ReadinessLevel::Yellow,
            checks: vec![
                Check {
                    name: "peers",
                    status: CheckStatus::Warn,
                    message: "1 connected (min: 2)".into(),
                },
                Check {
                    name: "sync",
                    status: CheckStatus::Ok,
                    message: "50 records".into(),
                },
            ],
            timestamp: 1234.5,
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["status"], "warn");
        assert_eq!(json["checks"].as_array().unwrap().len(), 2);
        assert_eq!(json["timestamp"], 1234.5);
        assert_eq!(json["readiness"], "yellow");
    }

    #[test]
    fn test_readiness_level_ordering() {
        assert!(ReadinessLevel::Green < ReadinessLevel::Yellow);
        assert!(ReadinessLevel::Yellow < ReadinessLevel::Orange);
        assert!(ReadinessLevel::Orange < ReadinessLevel::Red);
    }

    #[test]
    fn test_readiness_level_values() {
        assert_eq!(ReadinessLevel::Green.level(), 0);
        assert_eq!(ReadinessLevel::Yellow.level(), 1);
        assert_eq!(ReadinessLevel::Orange.level(), 2);
        assert_eq!(ReadinessLevel::Red.level(), 3);
    }

    #[test]
    fn test_determine_readiness_green() {
        let level = determine_readiness(3, 0.05, 100, &CheckStatus::Ok);
        assert_eq!(level, ReadinessLevel::Green);
    }

    #[test]
    fn test_determine_readiness_yellow_warn() {
        let level = determine_readiness(1, 0.1, 100, &CheckStatus::Warn);
        assert_eq!(level, ReadinessLevel::Yellow);
    }

    #[test]
    fn test_determine_readiness_yellow_high_fail_rate() {
        let level = determine_readiness(3, 0.3, 100, &CheckStatus::Ok);
        assert_eq!(level, ReadinessLevel::Yellow);
    }

    #[test]
    fn test_determine_readiness_orange_no_peers() {
        let level = determine_readiness(0, 0.0, 50, &CheckStatus::Warn);
        assert_eq!(level, ReadinessLevel::Orange);
    }

    #[test]
    fn test_determine_readiness_orange_majority_fail() {
        let level = determine_readiness(2, 0.6, 100, &CheckStatus::Ok);
        assert_eq!(level, ReadinessLevel::Orange);
    }

    #[test]
    fn test_determine_readiness_green_evicted_dag() {
        // DAG has way fewer records than storage — normal with eviction
        let level = determine_readiness(3, 0.0, 100, &CheckStatus::Ok);
        assert_eq!(level, ReadinessLevel::Green);
    }

    #[test]
    fn test_determine_readiness_red_critical_no_peers() {
        let level = determine_readiness(0, 0.9, 100, &CheckStatus::Critical);
        assert_eq!(level, ReadinessLevel::Red);
    }

    #[test]
    fn test_determine_readiness_green_no_pushes() {
        // No gossip activity yet — should be green, not orange
        let level = determine_readiness(0, 0.0, 0, &CheckStatus::Ok);
        assert_eq!(level, ReadinessLevel::Green);
    }

    #[test]
    fn test_readiness_serialization() {
        let json = serde_json::to_value(ReadinessLevel::Orange).unwrap();
        assert_eq!(json, "orange");
        let deser: ReadinessLevel = serde_json::from_value(json).unwrap();
        assert_eq!(deser, ReadinessLevel::Orange);
    }

    // ── peers_check (solo-authority vs partition distinction) ────────

    #[test]
    fn peers_check_ok_at_or_above_min() {
        let c = peers_check(3, 1, 100, None);
        assert_eq!(c.name, "peers");
        assert!(matches!(c.status, CheckStatus::Ok));
        assert!(c.message.contains("3 connected"));
    }

    #[test]
    fn peers_check_warn_below_min() {
        // 0 < connected < min_peers: degraded redundancy, not down.
        let c = peers_check(2, 5, 100, None);
        assert!(matches!(c.status, CheckStatus::Warn));
        assert!(c.message.contains("min: 5"));
    }

    #[test]
    fn peers_check_critical_when_mesh_lost() {
        // Had an active gossip mesh (push_total > 10) and dropped to 0 peers:
        // a genuine partition — must stay Critical.
        let c = peers_check(0, 1, 47, None);
        assert!(matches!(c.status, CheckStatus::Critical));
        assert!(c.message.contains("mesh lost"));
    }

    #[test]
    fn peers_check_warn_when_solo_never_pushed() {
        // 0 peers, never pushed gossip: solo/genesis authority or bootstrapping.
        // The core fix — must be Warn, not Critical.
        let c = peers_check(0, 1, 0, None);
        assert!(matches!(c.status, CheckStatus::Warn));
        assert!(c.message.contains("running solo"));
    }

    #[test]
    fn solo_authority_does_not_roll_up_to_red() {
        // Regression: a solo authority (0 peers, never pushed, every other check
        // Ok) used to self-report RED because peers==0 was hardcoded Critical and
        // determine_readiness rolls `Critical && peers==0` up to RED. With the
        // push-aware peers_check it must roll up to Yellow (degraded redundancy).
        let peers = peers_check(0, 1, 0, None).status;
        assert!(matches!(peers, CheckStatus::Warn));
        let level = determine_readiness(0, 0.0, 0, &peers);
        assert_eq!(level, ReadinessLevel::Yellow);
        assert_ne!(level, ReadinessLevel::Red);
    }

    #[test]
    fn partitioned_node_still_rolls_up_to_red() {
        // The real-emergency signal must survive: a node that had a mesh and lost
        // every peer still surfaces RED.
        let peers = peers_check(0, 1, 50, None).status;
        assert!(matches!(peers, CheckStatus::Critical));
        let level = determine_readiness(0, 0.9, 50, &peers);
        assert_eq!(level, ReadinessLevel::Red);
    }

    // ── peers_check inbound-liveness carve-out (pull-gossip seed) ─────

    #[test]
    fn peers_check_ok_when_zero_dialed_but_serving_inbound_sync() {
        // The 2026-07-02 authority-seed case: dials nobody (connected=0),
        // low push_total, but served a follower's delta_sync seconds ago.
        // Must be Ok — the mesh demonstrably reaches this node.
        let c = peers_check(0, 1, 0, Some(30));
        assert!(matches!(c.status, CheckStatus::Ok), "got: {:?}", c.message);
        assert!(c.message.contains("serving inbound sync"));
    }

    #[test]
    fn peers_check_inbound_liveness_beats_mesh_lost_critical() {
        // Even with push history (push_total > 10), recent inbound sync means
        // peers still reach us — not a partition. Ok, not Critical.
        let c = peers_check(0, 1, 47, Some(INBOUND_SYNC_LIVENESS_SECS));
        assert!(matches!(c.status, CheckStatus::Ok), "got: {:?}", c.message);
    }

    #[test]
    fn peers_check_stale_inbound_restores_prior_semantics() {
        // Inbound evidence older than the window is no evidence: the solo-Warn
        // and mesh-lost-Critical branches must behave exactly as pre-carve-out.
        let solo = peers_check(0, 1, 0, Some(INBOUND_SYNC_LIVENESS_SECS + 1));
        assert!(matches!(solo.status, CheckStatus::Warn));
        assert!(solo.message.contains("running solo"));
        let lost = peers_check(0, 1, 47, Some(INBOUND_SYNC_LIVENESS_SECS + 1));
        assert!(matches!(lost.status, CheckStatus::Critical));
        assert!(lost.message.contains("mesh lost"));
    }

    #[test]
    fn peers_check_inbound_liveness_does_not_mask_below_min_warn() {
        // The carve-out only rescues the connected==0 branches: a node with
        // 1 dialed peer below min_peers=5 stays Warn regardless of inbound
        // traffic — dialed-redundancy shortfall is real and actionable.
        let c = peers_check(1, 5, 100, Some(1));
        assert!(matches!(c.status, CheckStatus::Warn));
        assert!(c.message.contains("min: 5"));
    }

    // ── pull_sync_check (silent-desync detector) ─────────────────────

    #[test]
    fn pull_sync_ok_when_recently_pulled_even_if_zero_records() {
        // Core discriminator: an idle-but-syncing follower keeps stamping a
        // successful (0-record) pull, so a small staleness stays Ok — this is
        // why record-age can't replace it (record-age would look stale here too).
        let c = pull_sync_check(600.0, 5000, 1_000_000_000, 1_000_000_010.0, 50_000.0)
            .expect("a pulling follower yields a verdict");
        assert_eq!(c.name, "pull-sync");
        assert!(matches!(c.status, CheckStatus::Ok));
        assert!(c.message.contains("10s ago"));
    }

    #[test]
    fn pull_sync_warns_when_pulls_have_gone_stale() {
        // Live incident shape: last successful pull 16h ago because every pull
        // since fails AEAD against a wire-incompatible seed.
        let sixteen_h = 16.0 * 3600.0;
        let c = pull_sync_check(600.0, 6645, 1_000_000_000, 1_000_000_000.0 + sixteen_h, 200_000.0)
            .expect("a pulling follower yields a verdict");
        assert!(matches!(c.status, CheckStatus::Warn));
        assert!(c.message.contains("wire-incompatible"));
    }

    #[test]
    fn pull_sync_exempts_pure_seed_with_no_pull_attempts() {
        // Pure authority seed: seed_peers=[], never pulls → attempts==0 → no verdict, even
        // though last_pull==0 would otherwise read as "never synced".
        assert!(pull_sync_check(600.0, 0, 0, 1_000_000_000.0, 999_999.0).is_none());
    }

    #[test]
    fn pull_sync_disabled_when_threshold_zero() {
        assert!(pull_sync_check(0.0, 5000, 1_000_000_000, 1_000_100_000.0, 100.0).is_none());
    }

    #[test]
    fn pull_sync_silent_during_boot_grace_before_first_pull() {
        // attempts>0 but never succeeded yet, still within boot grace → silent.
        assert!(pull_sync_check(600.0, 3, 0, 1_000_000_000.0, 120.0).is_none());
    }

    #[test]
    fn pull_sync_warns_when_never_synced_past_boot_grace() {
        // A fresh node (e.g. an external joiner with a down seed / bad config)
        // that has tried past the grace and never once succeeded.
        let c = pull_sync_check(600.0, 40, 0, 1_000_000_000.0, 1200.0)
            .expect("past boot grace yields a verdict");
        assert!(matches!(c.status, CheckStatus::Warn));
        assert!(c.message.contains("since boot"));
    }

    // ── transitions_check (Gap 4 /health surface) ────────────────────

    #[test]
    fn transitions_check_ok_when_no_activity() {
        let c = transitions_check(0, 0, 0, 0);
        assert_eq!(c.name, "transitions");
        assert!(matches!(c.status, CheckStatus::Ok));
        assert!(c.message.contains("proposed=0"));
        assert!(c.message.contains("finalized=0"));
    }

    #[test]
    fn transitions_check_ok_when_only_finalized() {
        // Healthy anchor fleet: proposals fire and finalize with zero
        // expired. Sanity check that finalized activity keeps status Ok.
        let c = transitions_check(0, 0, 7, 7);
        assert!(matches!(c.status, CheckStatus::Ok));
        assert!(c.message.contains("proposed=7"));
        assert!(c.message.contains("finalized=7"));
    }

    #[test]
    fn transitions_check_warns_on_expired() {
        // Proposals are firing but not crossing threshold — anchor set
        // too small or cosign broken. Must warn with actionable hint.
        let c = transitions_check(3, 0, 5, 2);
        assert!(matches!(c.status, CheckStatus::Warn));
        assert!(c.message.contains("3 proposals expired"));
        assert!(c.message.contains("proposed=5"));
        assert!(c.message.contains("finalized=2"));
        assert!(c.message.contains("anchor set"));
    }

    #[test]
    fn transitions_check_warns_on_mirror_failures() {
        // Durability mirror breaking is worse than individual expiries;
        // must take priority even when expired also > 0.
        let c = transitions_check(1, 2, 10, 7);
        assert!(matches!(c.status, CheckStatus::Warn));
        assert!(c.message.contains("2 pending-mirror write failures"));
        assert!(c.message.contains("durability degraded"));
        // Expired message should NOT leak when mirror_fail dominates
        assert!(!c.message.contains("expired"));
    }

    /// Gap 4: `persist_finalized_transitions` writes each (id, seal_bytes)
    /// pair into `CF_TRANSITIONS_FINAL`, and `load_finalized_transition`
    /// round-trips it back as the original `TransitionSeal`. Proves the
    /// durability contract the orchestrator will depend on after a
    /// node restart.
    #[test]
    fn persist_and_reload_finalized_transition() {
        use crate::network::zone::ZoneId;
        use crate::network::zone_transition_seal::{
            TransitionKind, TransitionSeal, ZoneSnapshot, TRANSITION_DISPUTE_WINDOW_EPOCHS,
        };
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let rocks = StorageEngine::open(tmp.path()).expect("open rocks");

        let seal = TransitionSeal {
            kind: TransitionKind::Split,
            proposed_at_epoch: 500,
            effective_epoch: 500 + TRANSITION_DISPUTE_WINDOW_EPOCHS,
            parents: vec![ZoneSnapshot {
                zone_id: ZoneId::new("medical/eu"),
                state_root: [0x11; 32],
                last_seal_record_id: "p".into(),
                record_count: 42,
                committee_hash: [0x22; 32],
            }],
            children: vec![
                ZoneSnapshot {
                    zone_id: ZoneId::new("medical/eu/west"),
                    state_root: [0; 32],
                    last_seal_record_id: String::new(),
                    record_count: 0,
                    committee_hash: [0x33; 32],
                },
                ZoneSnapshot {
                    zone_id: ZoneId::new("medical/eu/east"),
                    state_root: [0; 32],
                    last_seal_record_id: String::new(),
                    record_count: 0,
                    committee_hash: [0x44; 32],
                },
            ],
            split_key: Some([0x80; 32]),
            proposer_sigs: vec![],
        };
        let id = seal.seal_hash_for_sig().expect("hash");
        let bytes = serde_json::to_vec(&seal).expect("serialize");

        persist_finalized_transitions(&rocks, &[(id, bytes)]);

        let back = load_finalized_transition(&rocks, &id)
            .expect("persisted seal should reload");
        assert_eq!(back, seal);

        // Unknown id returns None (not a panic, not an error).
        let missing = load_finalized_transition(&rocks, &[0xff; 32]);
        assert!(missing.is_none());
    }

    /// Gap 4: boot-replay pulls persisted `PendingTransition` rows from
    /// CF_TRANSITIONS_PENDING and re-admits them to the store, skipping
    /// corrupt rows and rows that crashed with a terminal status.
    #[test]
    fn boot_replay_restores_pending_and_skips_terminal() {
        use crate::network::transition_store::{
            PendingStatus, PendingTransition, TransitionStore,
        };
        use crate::network::zone::ZoneId;
        use crate::network::zone_transition_seal::{
            TransitionKind, TransitionSeal, ZoneSnapshot, TRANSITION_DISPUTE_WINDOW_EPOCHS,
        };
        use crate::storage::rocks::{StorageEngine, CF_TRANSITIONS_PENDING};

        let tmp = tempfile::tempdir().expect("tempdir");
        let rocks = StorageEngine::open(tmp.path()).expect("open rocks");

        fn mk_seal(proposed_at: u64) -> TransitionSeal {
            TransitionSeal {
                kind: TransitionKind::Split,
                proposed_at_epoch: proposed_at,
                effective_epoch: proposed_at + TRANSITION_DISPUTE_WINDOW_EPOCHS,
                parents: vec![ZoneSnapshot {
                    zone_id: ZoneId::new("replay/parent"),
                    state_root: [1; 32],
                    last_seal_record_id: "p".into(),
                    record_count: 1,
                    committee_hash: [2; 32],
                }],
                children: vec![
                    ZoneSnapshot {
                        zone_id: ZoneId::new("replay/a"),
                        state_root: [0; 32],
                        last_seal_record_id: String::new(),
                        record_count: 0,
                        committee_hash: [3; 32],
                    },
                    ZoneSnapshot {
                        zone_id: ZoneId::new("replay/b"),
                        state_root: [0; 32],
                        last_seal_record_id: String::new(),
                        record_count: 0,
                        committee_hash: [4; 32],
                    },
                ],
                split_key: Some([0x80; 32]),
                proposer_sigs: vec![],
            }
        }

        // Live pending — should replay.
        let live = PendingTransition {
            seal: mk_seal(100),
            vetoes: Vec::new(),
            status: PendingStatus::AwaitingSigs,
            id: mk_seal(100).seal_hash_for_sig().unwrap(),
        };
        rocks
            .put_cf_raw(
                CF_TRANSITIONS_PENDING,
                &live.id,
                &serde_json::to_vec(&live).unwrap(),
            )
            .unwrap();

        // Terminal stale row (crash between status flip and CF delete) —
        // must be skipped.
        let stale = PendingTransition {
            seal: mk_seal(200),
            vetoes: Vec::new(),
            status: PendingStatus::Vetoed,
            id: mk_seal(200).seal_hash_for_sig().unwrap(),
        };
        rocks
            .put_cf_raw(
                CF_TRANSITIONS_PENDING,
                &stale.id,
                &serde_json::to_vec(&stale).unwrap(),
            )
            .unwrap();

        // Corrupt row — must be skipped, not panic.
        rocks
            .put_cf_raw(CF_TRANSITIONS_PENDING, &[0xaa; 32], b"{not-json")
            .unwrap();

        let mut store = TransitionStore::new();
        let replayed = replay_pending_transitions_from_rocks(&rocks, &mut store);
        assert_eq!(replayed, 1, "only the AwaitingSigs row should replay");
        assert!(store.get(&live.id).is_some());
        assert!(store.get(&stale.id).is_none());
    }

    // ── Gap 5 Phase 3: live ZoneRegistry wiring ──────────────────────

    /// Build a fully-constructed `NodeState` for integration tests. The
    /// background tasks never start because none of the timers are
    /// polled — we only exercise fns that take `&Arc<NodeState>` and
    /// touch registry / rocks.
    fn build_test_state() -> (std::sync::Arc<crate::network::state::NodeState>, tempfile::TempDir) {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::state::NodeState;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "gap5-phase3-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };

        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = std::sync::Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocks"),
        );
        let wmgr = std::sync::Arc::new(WitnessManager::new(rocks.clone()));
        let state = std::sync::Arc::new(NodeState::new(config, identity, rocks, wmgr));
        (state, tmp)
    }

    /// Build a canonical Split seal from `parent` → two children at
    /// `effective_epoch`, mirroring what `run_transition_tick` would
    /// produce.
    fn mk_split_seal(
        parent: &str,
        child_a: &str,
        child_b: &str,
        proposed_at: u64,
    ) -> crate::network::zone_transition_seal::TransitionSeal {
        use crate::network::zone::ZoneId;
        use crate::network::zone_transition_seal::{
            TransitionKind, TransitionSeal, ZoneSnapshot, TRANSITION_DISPUTE_WINDOW_EPOCHS,
        };
        TransitionSeal {
            kind: TransitionKind::Split,
            proposed_at_epoch: proposed_at,
            effective_epoch: proposed_at + TRANSITION_DISPUTE_WINDOW_EPOCHS,
            parents: vec![ZoneSnapshot {
                zone_id: ZoneId::new(parent),
                state_root: [0x11; 32],
                last_seal_record_id: "p".into(),
                record_count: 100,
                committee_hash: [0x22; 32],
            }],
            children: vec![
                ZoneSnapshot {
                    zone_id: ZoneId::new(child_a),
                    state_root: [0; 32],
                    last_seal_record_id: String::new(),
                    record_count: 0,
                    committee_hash: [0x33; 32],
                },
                ZoneSnapshot {
                    zone_id: ZoneId::new(child_b),
                    state_root: [0; 32],
                    last_seal_record_id: String::new(),
                    record_count: 0,
                    committee_hash: [0x44; 32],
                },
            ],
            split_key: Some([0x80; 32]),
            proposer_sigs: vec![],
        }
    }

    /// Gap 4 close-out: attach `SPLIT_ANCHOR_THRESHOLD` valid Dilithium3
    /// sigs to a seal AND register each signing anchor's pubkey in
    /// `state.rocks.CF_IDENTITIES` — so `apply_finalized_to_zone_registry`
    /// will let the seal through its `verify_sigs` gate.
    ///
    /// Without this, seals built by `mk_split_seal` have `proposer_sigs: []`
    /// and the sig-verify gate (added 2026-04-21 to close Gap 4) rejects
    /// them, dumping the apply. Tests that exercise the apply path must
    /// call this helper.
    fn sign_seal_for_test(
        state: &std::sync::Arc<crate::network::state::NodeState>,
        seal: &mut crate::network::zone_transition_seal::TransitionSeal,
    ) {
        use crate::crypto::hash::sha3_256;
        use crate::crypto::pqc::{dilithium3_keygen, dilithium3_sign_with_pk};
        use crate::network::zone_transition_seal::AnchorSig;

        let hash = seal.seal_hash_for_sig().expect("seal hash");
        let threshold = seal.required_threshold();
        let mut sigs: Vec<AnchorSig> = Vec::with_capacity(threshold);
        for _ in 0..threshold {
            let kp = dilithium3_keygen().expect("keygen");
            let id = sha3_256(&kp.public_key);
            // Register under the hex form — same keying convention the
            // production resolve path uses (routes/transitions.rs:66).
            state
                .rocks
                .store_public_key_anchor(&hex::encode(id), &kp.public_key)
                .expect("register anchor pubkey");
            let sig = dilithium3_sign_with_pk(&hash, &kp.secret_key, &kp.public_key)
                .expect("sign");
            sigs.push(AnchorSig {
                anchor_identity_hash: id,
                dilithium3_sig: sig,
            });
        }
        // Keep sigs sorted by anchor_identity_hash — same invariant the
        // production propose path maintains so `verify_sigs` dedup is
        // deterministic.
        sigs.sort_by_key(|s| s.anchor_identity_hash);
        seal.proposer_sigs = sigs;
    }

    /// Phase 3: `apply_finalized_to_zone_registry` decodes each freshly
    /// persisted seal and mirrors it into `state.zone_registry`. A
    /// successful apply bumps `zone_registry_tick_applied_total` and
    /// retires the parent zone from `active_zones()`.
    #[test]
    fn tick_apply_mirrors_seal_into_live_registry() {
        use crate::network::zone::ZoneId;

        let (state, _tmp) = build_test_state();

        // Seed the live registry with the parent zone so the split has
        // somewhere to land. Without this, apply would reject ("unknown
        // parent").
        {
            let mut reg = state.zone_registry.write().unwrap();
            *reg = crate::network::zone_registry::ZoneRegistry::with_genesis(vec![
                ZoneId::new("medical/eu"),
            ]);
        }

        let mut seal = mk_split_seal("medical/eu", "medical/eu/west", "medical/eu/east", 10);
        sign_seal_for_test(&state, &mut seal);
        let id = seal.seal_hash_for_sig().expect("hash");
        let bytes = serde_json::to_vec(&seal).expect("serialize");

        // Counters start at zero.
        assert_eq!(
            state
                .zone_registry_tick_applied_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        apply_finalized_to_zone_registry(&state, &[(id, bytes)]);

        assert_eq!(
            state
                .zone_registry_tick_applied_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "tick apply counter must reflect the one applied seal"
        );
        assert_eq!(
            state
                .zone_registry_tick_apply_failures_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "no failures on a valid seal"
        );

        let reg = state.zone_registry.read().unwrap();
        let actives: Vec<_> = reg.active_zones().cloned().collect();
        assert!(
            actives.contains(&ZoneId::new("medical/eu/west")),
            "west child must be active"
        );
        assert!(
            actives.contains(&ZoneId::new("medical/eu/east")),
            "east child must be active"
        );
        assert!(
            !actives.contains(&ZoneId::new("medical/eu")),
            "parent must no longer be active"
        );
    }

    /// Phase 3: apply against an unseeded registry (unknown parent) must
    /// bump the failure counter without panicking, so one anomalous
    /// seal can't take down the tick.
    #[test]
    fn tick_apply_counts_failure_on_unknown_parent() {
        let (state, _tmp) = build_test_state();

        // Registry is empty (default `new()` has no genesis zones), so
        // a Split referencing "orphan" parent must be rejected.
        let mut seal = mk_split_seal("orphan", "orphan/a", "orphan/b", 5);
        sign_seal_for_test(&state, &mut seal);
        let id = seal.seal_hash_for_sig().expect("hash");
        let bytes = serde_json::to_vec(&seal).expect("serialize");

        apply_finalized_to_zone_registry(&state, &[(id, bytes)]);

        assert_eq!(
            state
                .zone_registry_tick_applied_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            state
                .zone_registry_tick_apply_failures_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "unknown-parent apply must count as a failure"
        );
        assert_eq!(
            state
                .zone_registry_tick_sig_verify_failures_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "sig-verify counter must NOT fire — this test passes sig gate and fails apply"
        );
    }

    /// Gap 4 close-out: `apply_finalized_to_zone_registry` is internal
    /// and trusts its caller (`run_transition_tick`) to have already
    /// verified sigs. The actual sig-verify gate lives in the tick's
    /// collection loop — tested via `tick_rejects_seal_below_sig_threshold`
    /// below.
    ///
    /// Phase 3: `boot_rehydrate_zone_registry` reads every seal from
    /// CF_TRANSITIONS_FINAL and replays them in effective-epoch order.
    /// The post-boot registry reflects the full split history (both
    /// first-level and nested children are active), and the boot
    /// counters match what was persisted.
    #[test]
    fn boot_rehydrate_replays_finalized_cf_and_sets_counters() {
        use crate::network::zone::ZoneId;

        let (state, _tmp) = build_test_state();

        // Seed two seals into CF_TRANSITIONS_FINAL in reverse
        // chronological order to prove the boot path sorts by
        // effective_epoch — the nested split must apply AFTER its
        // parent even though its key sorts first.
        let mut first_split =
            mk_split_seal("medical/eu", "medical/eu/west", "medical/eu/east", 10);
        sign_seal_for_test(&state, &mut first_split);
        let mut nested_split = mk_split_seal(
            "medical/eu/east",
            "medical/eu/east/north",
            "medical/eu/east/south",
            20,
        );
        sign_seal_for_test(&state, &mut nested_split);

        // Pre-seed the flat-modulo genesis layout with a zone that
        // `boot_rehydrate_zone_registry` expects — we override ZONE_COUNT
        // via direct inject by making the registry contain our parent.
        //
        // The real code path calls `get_zone_count()` and seeds
        // ZoneId::from_legacy(i) for i in 0..N. That's not the tree we
        // want. So we persist our seals and verify the boot path
        // APPLIES them — parents won't match genesis zones, so every
        // seal goes into the apply-failure bucket.
        //
        // To actually exercise the "registry was rebuilt" branch, we
        // test the lower-level `rebuild_from_finalized` with a matching
        // genesis, then separately assert the state-level helper
        // surfaces boot counters and swaps the registry wholesale.

        for seal in [&nested_split, &first_split] {
            let id = seal.seal_hash_for_sig().expect("hash");
            let bytes = serde_json::to_vec(seal).expect("serialize");
            state
                .rocks
                .put_cf_raw(
                    crate::storage::rocks::CF_TRANSITIONS_FINAL,
                    &id,
                    &bytes,
                )
                .expect("persist seal");
        }

        // Exercise rebuild directly with the matching genesis so we
        // can check the happy path — what the boot helper would do if
        // the genesis zones matched the persisted seals.
        let genesis = vec![ZoneId::new("medical/eu")];
        let (registry, stats) =
            crate::network::zone_registry::rebuild_from_finalized(&state.rocks, genesis)
                .expect("rebuild");
        assert_eq!(stats.seals_read, 2);
        assert_eq!(stats.seals_applied, 2, "both seals must apply in epoch order");
        assert_eq!(stats.seals_skipped_decode, 0);
        assert!(stats.seals_skipped_apply.is_empty());
        assert!(!stats.truncated);

        let actives: Vec<_> = registry.active_zones().cloned().collect();
        assert!(actives.contains(&ZoneId::new("medical/eu/west")));
        assert!(actives.contains(&ZoneId::new("medical/eu/east/north")));
        assert!(actives.contains(&ZoneId::new("medical/eu/east/south")));
        assert!(
            !actives.contains(&ZoneId::new("medical/eu/east")),
            "east was split into north/south — must no longer be active"
        );

        // Now exercise the state-level helper. It seeds from flat-modulo
        // genesis, so our persisted seals WILL miss their parents and
        // land in the apply-failure bucket. The test verifies the
        // helper surfaces those counts and doesn't panic — the registry
        // comes up valid, just reflecting only the genesis zones.
        let applied = boot_rehydrate_zone_registry(&state);
        // applied = seals whose parent matched a genesis zone. None of
        // our seeded seals have parents in the flat-modulo tree, so
        // applied == 0.
        assert_eq!(applied, 0);
        assert_eq!(
            state
                .zone_registry_boot_applied_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            state
                .zone_registry_boot_decode_failures_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "all seals decoded cleanly"
        );
        assert_eq!(
            state
                .zone_registry_boot_apply_failures_total
                .load(std::sync::atomic::Ordering::Relaxed),
            2,
            "both seals had unknown parents under flat-modulo genesis"
        );
    }

    /// Phase 3: a corrupt row under CF_TRANSITIONS_FINAL must bump the
    /// decode-failure counter at boot without panicking. Registry
    /// comes up with only the valid seals applied.
    #[test]
    fn boot_rehydrate_counts_corrupt_row() {
        let (state, _tmp) = build_test_state();

        // One corrupt row, nothing else.
        state
            .rocks
            .put_cf_raw(
                crate::storage::rocks::CF_TRANSITIONS_FINAL,
                &[0xbb; 32],
                b"not-a-seal",
            )
            .expect("persist corrupt");

        let applied = boot_rehydrate_zone_registry(&state);
        assert_eq!(applied, 0);
        assert_eq!(
            state
                .zone_registry_boot_decode_failures_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "corrupt row must be counted, not fatal"
        );
    }

    /// Build a NodeState whose `genesis_authority` matches the local identity
    /// hash so `run_auto_scale_tick` doesn't bail out at the authority gate.
    /// This is the only test path that exercises the orchestrator-propose
    /// branch, so the helper stays scoped to this module.
    fn build_test_state_as_genesis_authority()
        -> (std::sync::Arc<crate::network::state::NodeState>, tempfile::TempDir)
    {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::state::NodeState;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "auto-scale-undersized-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            genesis_authority: identity.identity_hash.clone(),
            ..Default::default()
        };

        let rocks = std::sync::Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocks"),
        );
        let wmgr = std::sync::Arc::new(WitnessManager::new(rocks.clone()));
        let state = std::sync::Arc::new(NodeState::new(config, identity, rocks, wmgr));
        (state, tmp)
    }

    /// Gap 4 close-out: when the registered+staked anchor pool is too small
    /// for the kind's M-of-N threshold, the orchestrator must skip the
    /// proposal and bump `transitions_orchestrator_skipped_undersized_pool_total`
    /// rather than emit a dead-on-arrival seal that would expire after the
    /// dispute window.
    ///
    /// On testnet this exact shape happens daily: 2 anchors vs
    /// `MERGE_ANCHOR_THRESHOLD = 7` means every merge proposal expires;
    /// without this gate `transitions_expired_total` races up while
    /// `finalized_total` stays at zero forever.
    #[tokio::test]
    async fn auto_scale_skips_propose_when_anchor_pool_under_threshold() {
        use crate::network::zone::ZoneId;

        let (state, _tmp) = build_test_state_as_genesis_authority();

        // Two cold zones → average rate 0 → triggers Merge once hysteresis
        // is satisfied. Seed `latest_epoch` too so `current_max_epoch` is
        // non-zero (orchestrator computes target_epoch off it).
        {
            let mut epoch = state.epoch.write().expect("epoch lock");
            epoch.zone_activity_rate.insert(ZoneId::new("z0"), 0.0);
            epoch.zone_activity_rate.insert(ZoneId::new("z1"), 0.0);
            epoch.latest_epoch.insert(ZoneId::new("z0"), 100);
            epoch.latest_epoch.insert(ZoneId::new("z1"), 100);
        }
        crate::network::consensus::set_zone_count(2);

        // Pre-drive the auto_scaler past hysteresis-1 so the next observe
        // (inside run_auto_scale_tick) returns Some(Merge). VRF registry
        // stays empty, so `candidates.len() == 0 < MERGE_ANCHOR_THRESHOLD`.
        {
            let activity = state
                .epoch
                .read()
                .expect("epoch lock")
                .zone_activity_rate
                .clone();
            let mut scaler = state.auto_scaler.lock_recover();
            for _ in 0..(crate::network::auto_scale::HYSTERESIS_TICKS - 1) {
                let _ = scaler.observe(&activity, 2);
            }
        }

        run_auto_scale_tick(&state)
            .await
            .expect("auto_scale tick must not error");

        let skipped = state
            .transitions_orchestrator_skipped_undersized_pool_total
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            skipped, 1,
            "expected one skipped-undersized increment, got {skipped}"
        );

        let proposed = state
            .transitions_proposed_by_orchestrator_total
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            proposed, 0,
            "no TransitionSeal must be inserted when the anchor pool is undersized"
        );

        let pending_count = {
            use crate::network::RwLockRecover;
            state.transitions.read_recover().status_counts().total()
        };
        assert_eq!(
            pending_count, 0,
            "TransitionStore must remain empty — proposal was gated pre-insert"
        );
    }

    // ─── ReadinessLevel sync pins ─────────────────────────────────────────
    //
    // Three sync pins on previously-uncovered surfaces:
    //   1. ReadinessLevel::as_str() — all 4 variants → lowercase strings
    //   2. CheckStatus + ReadinessLevel serde lowercase rename for all variants
    //   3. now_ts() returns positive UNIX timestamp above the 2026 baseline

    #[test]
    fn batch_ai_readiness_level_as_str_pins_lowercase_string_for_all_four_variants() {
        // `level()` numeric values are pinned by test_readiness_level_values;
        // the lowercase string representation is the operator-facing label
        // (rendered in `/health` JSON and dashboards) and was uncovered.
        assert_eq!(ReadinessLevel::Green.as_str(), "green");
        assert_eq!(ReadinessLevel::Yellow.as_str(), "yellow");
        assert_eq!(ReadinessLevel::Orange.as_str(), "orange");
        assert_eq!(ReadinessLevel::Red.as_str(), "red");
    }

    #[test]
    fn batch_ai_check_status_and_readiness_level_serde_round_trip_pins_lowercase_for_all_variants() {
        // The `#[serde(rename_all = "lowercase")]` attribute on both enums is
        // load-bearing — dashboards/SDKs expect lowercase. test_check_serialization
        // covers Ok only; test_report_serialization covers (Warn, Yellow) only.
        // Pin all variants here so a future bump (e.g. adding `Unknown`)
        // doesn't silently break the wire shape.

        // CheckStatus — all three variants.
        assert_eq!(serde_json::to_value(CheckStatus::Ok).unwrap(), "ok");
        assert_eq!(serde_json::to_value(CheckStatus::Warn).unwrap(), "warn");
        assert_eq!(
            serde_json::to_value(CheckStatus::Critical).unwrap(),
            "critical"
        );

        // ReadinessLevel — embedded in HealthReport via #[serde(rename_all)]
        // on the enum at definition site. Pin all four to lowercase.
        let mk_report = |readiness| HealthReport {
            status: CheckStatus::Ok,
            readiness,
            checks: vec![],
            timestamp: 0.0,
        };
        assert_eq!(
            serde_json::to_value(mk_report(ReadinessLevel::Green)).unwrap()["readiness"],
            "green",
        );
        assert_eq!(
            serde_json::to_value(mk_report(ReadinessLevel::Yellow)).unwrap()["readiness"],
            "yellow",
        );
        assert_eq!(
            serde_json::to_value(mk_report(ReadinessLevel::Orange)).unwrap()["readiness"],
            "orange",
        );
        assert_eq!(
            serde_json::to_value(mk_report(ReadinessLevel::Red)).unwrap()["readiness"],
            "red",
        );
    }

    #[test]
    fn batch_ai_now_ts_returns_positive_above_2026_baseline() {
        // `now_ts()` is the wall-clock helper used for HealthReport.timestamp
        // and for transition-store pending/finalized timestamps. A regression
        // returning 0 (e.g. swapping to a monotonic clock that resets) would
        // break correlation with operator dashboards expecting UNIX seconds.
        // 2026-01-01 00:00:00 UTC = 1_735_689_600. We're past that.
        let ts = now_ts();
        assert!(
            ts > 1_735_689_600.0,
            "now_ts() must return UNIX seconds past 2026-01-01; got {ts}",
        );
        // Sanity: nowhere near far-future overflow (year-2100 sanity).
        assert!(
            ts < 4_102_444_800.0,
            "now_ts() must be reasonable wall clock, not stamp-overflow; got {ts}",
        );
    }

    // ─── ReadinessLevel boundary-semantics tests ──────────────────────────
    //
    // Earlier tests pinned the lowercase serde rename + as_str surface;
    // existing test_determine_readiness_* pin the happy paths for each
    // ReadinessLevel.
    // These five fixture-free tests pin the BOUNDARY semantics the existing
    // suite leaves open: the strict-greater-than gates at 0.2 / 0.5 fail rate,
    // the gossip_push_total>10 noise floor, the Red-requires-both-conditions
    // precedence, the transitions_check mirror_fail-vs-expired precedence
    // (priority over expired per L382-385 doc), and the HealthReport JSON
    // top-level key contract that operator dashboards depend on.

    #[test]
    fn batch_b_determine_readiness_fail_rate_strict_greater_than_at_yellow_0_2_and_orange_0_5_boundaries() {
        // L439: orange gate is `gossip_fail_rate > 0.5` (strict). At exactly
        // 0.5 with push>10 + Ok worst-check the fall-through hits the
        // Yellow gate (`> 0.2`) which IS strictly greater than 0.2 at 0.5,
        // so the call returns Yellow — pinning the 0.5 boundary belongs to
        // YELLOW, not Orange. A future relax to `>= 0.5` would silently
        // flip every 50%-failing fleet to Orange and trigger sovereign-mode
        // playbooks.
        assert_eq!(
            determine_readiness(3, 0.5, 100, &CheckStatus::Ok),
            ReadinessLevel::Yellow,
            "fail_rate=0.5 exact must be Yellow (orange gate is strict >0.5)"
        );
        // Just-above 0.5 IS Orange — pin the strict-greater-than direction.
        assert_eq!(
            determine_readiness(3, 0.5000001, 100, &CheckStatus::Ok),
            ReadinessLevel::Orange,
            "fail_rate just-above 0.5 must be Orange"
        );

        // L447: yellow gate is `gossip_fail_rate > 0.2` (strict). At exactly
        // 0.2 with push>10 + Ok worst-check the fall-through hits Green.
        // A future relax to `>= 0.2` would silently flip every 20%-failing
        // fleet to Yellow.
        assert_eq!(
            determine_readiness(3, 0.2, 100, &CheckStatus::Ok),
            ReadinessLevel::Green,
            "fail_rate=0.2 exact must be Green (yellow gate is strict >0.2)"
        );
        // Just-above 0.2 IS Yellow.
        assert_eq!(
            determine_readiness(3, 0.2000001, 100, &CheckStatus::Ok),
            ReadinessLevel::Yellow,
            "fail_rate just-above 0.2 must be Yellow"
        );
    }

    #[test]
    fn batch_b_determine_readiness_gossip_push_noise_floor_pins_strict_greater_than_10() {
        // All three fail-rate gates (orange + yellow) condition on
        // `gossip_push_total > 10` (L436, L439, L447). At push <= 10 the
        // fail_rate value is IRRELEVANT — the function returns Green
        // regardless. This is the noise-floor that prevents a fresh node's
        // first 10 retries from triggering false-positive escalation.
        // Pin so a refactor changing the floor (e.g. to >=10 or >100)
        // surfaces here.

        // push=10 exact: even 100% failure rate must be Green.
        assert_eq!(
            determine_readiness(3, 1.0, 10, &CheckStatus::Ok),
            ReadinessLevel::Green,
            "push=10 exact + 100% fail must stay Green (gate is strict >10)"
        );

        // push=11 (just above the floor): same 100% rate now triggers Orange.
        assert_eq!(
            determine_readiness(3, 1.0, 11, &CheckStatus::Ok),
            ReadinessLevel::Orange,
            "push=11 + 100% fail must be Orange (above noise floor)"
        );

        // push=0: even worse fail context (would-be NaN if computed) must be
        // benign Green when no traffic has flowed.
        assert_eq!(
            determine_readiness(3, 0.99, 0, &CheckStatus::Ok),
            ReadinessLevel::Green,
            "no traffic (push=0) must be Green regardless of fail_rate"
        );

        // Floor applies to the YELLOW gate too — push=10 + 50% fail + Ok = Green
        // (NOT Yellow). The yellow gate L447 also requires push>10.
        assert_eq!(
            determine_readiness(3, 0.5, 10, &CheckStatus::Ok),
            ReadinessLevel::Green,
            "push=10 + 50% fail + Ok worst-check must be Green (no yellow without >10 push)"
        );
    }

    #[test]
    fn batch_b_determine_readiness_red_requires_both_critical_and_zero_peers_with_peers_falls_to_yellow() {
        // L430-433: RED only fires when BOTH `worst_check == Critical` AND
        // `connected_peers == 0`. Either alone falls through:
        //   - Critical + 1+ peer → falls to Yellow (via the Warn-or-Critical
        //     gate at L444).
        //   - 0 peers + Ok check → falls to Orange (no-peers gate at L436)
        //     IF push>10, else Green.
        // The test_determine_readiness_red_critical_no_peers covers the
        // happy "both true → Red" path. Pin the "either alone" non-escalation
        // here so a regression that loosened to OR-instead-of-AND would
        // surface — that would silently put every node briefly hitting a
        // Critical check (even with peers) into sovereign-mode.
        assert_eq!(
            determine_readiness(1, 0.0, 0, &CheckStatus::Critical),
            ReadinessLevel::Yellow,
            "Critical + 1 peer must be Yellow (Red requires zero peers AND critical)"
        );
        assert_eq!(
            determine_readiness(5, 0.0, 0, &CheckStatus::Critical),
            ReadinessLevel::Yellow,
            "Critical + 5 peers must be Yellow"
        );

        // 0 peers + Ok worst-check + push>10 → Orange (NOT Red) — the
        // partitioned branch fires before the Red branch could even be
        // considered (which it can't, since worst_check is not Critical).
        assert_eq!(
            determine_readiness(0, 0.0, 50, &CheckStatus::Ok),
            ReadinessLevel::Orange,
            "0 peers + Ok + push>10 must be Orange, not Red"
        );

        // The both-true happy path (regression guard for the existing test).
        assert_eq!(
            determine_readiness(0, 0.0, 0, &CheckStatus::Critical),
            ReadinessLevel::Red,
            "Critical + 0 peers must be Red"
        );
    }

    #[test]
    fn batch_b_transitions_check_mirror_fail_takes_priority_over_expired_when_both_positive() {
        // L382-385 doc: "Mirror failures take priority because they imply
        // all pending state is being silently dropped, which is worse than
        // individual proposals expiring."
        //
        // Existing tests (transitions_check_warns_on_expired,
        // transitions_check_warns_on_mirror_failures) cover each
        // SEPARATELY but never together — a regression that flipped the
        // `if mirror_fail > 0 { ... } else if expired > 0 { ... }`
        // precedence to evaluate expired first would still pass both
        // existing tests (each has the OTHER variable at 0). Pin the
        // precedence with both at non-zero so the regression surfaces.

        let chk = transitions_check(
            /* expired */ 10,
            /* mirror_fail */ 5,
            /* proposed */ 100,
            /* finalized */ 80,
        );
        assert_eq!(chk.status, CheckStatus::Warn);
        assert!(
            chk.message.contains("mirror"),
            "mirror_fail must dominate the message when both positive — got: {}",
            chk.message
        );
        assert!(
            !chk.message.contains("expired"),
            "expired count must NOT appear in mirror-priority message — got: {}",
            chk.message
        );
        // Name pin: the check identifier must be the literal "transitions"
        // regardless of which sub-branch fires.
        assert_eq!(chk.name, "transitions");

        // Sanity boundary: mirror_fail=0 + expired>0 falls into the expired
        // branch (existing test covers this, but pin alongside for clarity).
        let chk2 = transitions_check(10, 0, 100, 80);
        assert!(chk2.message.contains("expired"));
        assert!(!chk2.message.contains("mirror"));
    }

    #[test]
    fn batch_b_health_report_serialization_pins_all_four_top_level_keys_with_checks_array_inner_shape() {
        // The HealthReport JSON wire is the public /health endpoint payload.
        // Operator dashboards key on these four top-level fields. test_report_
        // serialization only spot-checks `status` / `checks.len()` /
        // `timestamp` / `readiness` — it does NOT pin that NO OTHER top-level
        // keys exist (a future #[serde] rename or added field would not be
        // caught). Pin the exact 4-key contract.
        let report = HealthReport {
            status: CheckStatus::Critical,
            readiness: ReadinessLevel::Red,
            checks: vec![
                Check {
                    name: "peers",
                    status: CheckStatus::Critical,
                    message: "0 connected".into(),
                },
            ],
            timestamp: 1_777_000_000.5,
        };
        let json = serde_json::to_value(&report).expect("serialize");
        let obj = json.as_object().expect("top-level must be JSON object");

        // Exactly 4 top-level keys.
        assert_eq!(
            obj.len(),
            4,
            "HealthReport JSON must have exactly 4 top-level keys, got {}: {:?}",
            obj.len(),
            obj.keys().collect::<Vec<_>>()
        );
        assert!(obj.contains_key("status"));
        assert!(obj.contains_key("readiness"));
        assert!(obj.contains_key("checks"));
        assert!(obj.contains_key("timestamp"));

        // status / readiness lowercase per batch_ai pin.
        assert_eq!(obj["status"], "critical");
        assert_eq!(obj["readiness"], "red");

        // timestamp must serialize as a JSON number (not string), and
        // round-trip preserves the f64 value.
        assert!(obj["timestamp"].is_number(), "timestamp must be a JSON number");
        assert_eq!(
            obj["timestamp"].as_f64().expect("timestamp f64"),
            1_777_000_000.5
        );

        // checks must be an array, and each element must be a JSON object
        // with EXACTLY 3 keys: name / status / message (Check has 3 fields).
        let checks_arr = obj["checks"].as_array().expect("checks must be array");
        assert_eq!(checks_arr.len(), 1);
        let inner = checks_arr[0].as_object().expect("each check must be object");
        assert_eq!(
            inner.len(),
            3,
            "Check JSON must have exactly 3 keys, got {}: {:?}",
            inner.len(),
            inner.keys().collect::<Vec<_>>()
        );
        assert!(inner.contains_key("name"));
        assert!(inner.contains_key("status"));
        assert!(inner.contains_key("message"));
        assert_eq!(inner["name"], "peers");
        assert_eq!(inner["status"], "critical");
        assert_eq!(inner["message"], "0 connected");
    }
}
