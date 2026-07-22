//! Core protocol route handlers: /ping, /status, /health, /records, /validate, /metrics, etc.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::Json;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tracing::debug;

use crate::crypto::pqc::dilithium3_verify;
use crate::errors::ElaraError;
use crate::storage::Storage;
use crate::record::ValidationRecord;
use crate::accounting::types::{
    creator_identity_hash, extract_ledger_op,
};
use crate::accounting::validate;

use crate::network::gossip;
use crate::network::state::NodeState;
use crate::network::LockRecover;
use crate::network::RwLockRecover;

use super::super::server::{AppError, format_op};

// ─── /ping ───────────────────────────────────────────────────────────────────

pub async fn ping() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "pong": true,
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": crate::network::config::PROTOCOL_VERSION,
    }))
}

// ─── /version ────────────────────────────────────────────────────────────────
//
// Build-identity surface for deploy verification. Returns the git SHA + ref +
// dirty flag captured at `cargo build` time (via `build.rs`) plus the UTC
// build timestamp. Two binaries built from different commits, or the same
// commit with uncommitted changes, return distinct (sha, dirty, build_ts)
// tuples — sufficient to confirm fleet uniformity without ssh+sha256sum
// round-trips. Also consumed by ops scripts (`scripts/claude-heartbeat.sh`
// all-up gate) which curl `/version` against each node — those run on loopback.
// The git tuple is LOOPBACK-ONLY: for non-loopback callers on the public
// listener it is nulled (the live git sha is a private-repo commit absent from
// the curated public mirror, and a precise build fingerprint); public callers
// still get version + protocol_version.

pub async fn version(
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Json<serde_json::Value> {
    // Build identity (git sha/ref/dirty + build timestamp) is a precise build
    // fingerprint, and the live node's git sha is a PRIVATE-repo commit that does
    // not exist in the curated public-mirror history — exposing it leaks a private
    // identifier AND aids vuln targeting. Withhold for non-loopback callers; the
    // public surface keeps only version + protocol_version (already on /ping).
    // Loopback (deploy verification, scripts/claude-heartbeat.sh) keeps the tuple.
    let is_loopback = super::super::server::ip_is_loopback_canonical(connect_info.0.ip());
    let mut body = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": crate::network::config::PROTOCOL_VERSION,
        // PQ-transport handshake wire version (elara_pq_transport::frame::WIRE_VERSION,
        // NOT the unrelated crate::wire::WIRE_VERSION record-format constant). Exposed
        // UNCONDITIONALLY — never withheld off-loopback — because the caller that needs
        // it most is a remote joiner checking PQ-wire compatibility over plain HTTP
        // BEFORE the PQ dial: a mismatch here is the deterministic cause of the #1
        // first-join failure (the silent "looks like the network is dead" handshake
        // reject, attributed seed-side by elara_pq_handshake_wire_mismatch_total). It is
        // a public protocol contract like protocol_version, not a build fingerprint.
        "pq_wire_version": crate::network::pq_transport::WIRE_VERSION,
        "git_sha": option_env!("BUILD_GIT_SHA").unwrap_or("unknown"),
        "git_ref": option_env!("BUILD_GIT_REF").unwrap_or("unknown"),
        "git_dirty": option_env!("BUILD_GIT_DIRTY") == Some("1"),
        "build_ts_secs": option_env!("BUILD_TS_SECS")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0),
    });
    if !is_loopback {
        if let Some(obj) = body.as_object_mut() {
            for k in ["git_sha", "git_ref", "git_dirty", "build_ts_secs"] {
                if let Some(v) = obj.get_mut(k) {
                    *v = serde_json::Value::Null;
                }
            }
        }
    }
    Json(body)
}

// ─── /probe ──────────────────────────────────────────────────────────────────

pub async fn handle_probe_endpoint(
    State(state): State<Arc<NodeState>>,
    Json(request): Json<crate::network::probe::ProbeRequest>,
) -> Json<crate::network::probe::ProbeResponse> {
    Json(crate::network::probe::handle_probe(&state, &request).await)
}

// ─── /status ─────────────────────────────────────────────────────────────────

/// Fields on `/status` withheld (nulled) for non-loopback callers on the public
/// listener. Every entry is node-local state — host resources (`listen_addr`,
/// `system_load`, `rss_mb`, `memory_pressure`, `disk_usage`), this node's
/// operational counters (`gc_pruned_total`, `auto_slashes_total`), optional
/// higher-layer counters (`continuity_identities`, `reincarnation_*`),
/// real-time per-zone timing (`zone_timing`), committee composition
/// (`committees`), peer-bandwidth/mesh-density (`peer_bandwidth`,
/// `pq_read_limiter`), and this
/// node's zone subscription set (`subscribed_zones`). A synced peer derives NONE
/// of these from the shared chain; they fingerprint THIS deployment. Loopback
/// (operator dashboard / admin listener) keeps the full set.
///
/// Deliberately NOT here: discovery identity/PoW fields (`public_key_hex`,
/// `pow_nonce`, `pow_difficulty`) are load-bearing — `discovery::bootstrap`
/// parses them to build `PeerInfo`; and `genesis_authority` is the
/// inherently-public trust anchor every light client pins. Single source of
/// truth for the gate — keep in sync with the strip loop in `status` and the
/// `status_*` gate tests.
const STATUS_LOOPBACK_ONLY_FIELDS: &[&str] = &[
    "listen_addr",
    "system_load",
    "rss_mb",
    "memory_pressure",
    "disk_usage",
    "peer_bandwidth",
    "pq_read_limiter",
    "subscribed_zones",
    "committees",
    "zone_timing",
    "gc_pruned_total",
    "auto_slashes_total",
    "continuity_identities",
    "reincarnation_fingerprints",
    "reincarnation_abandoned",
    "reincarnation_candidates",
    // Build identity — loopback-only, matching the `/version` gate (86d9bc32).
    // The live `git_sha` is the PRIVATE-repo HEAD (absent from the curated public
    // mirror, so it reveals the private upstream + exact binary for targeting);
    // `build_ts_secs` is a deploy-time fingerprint. Added to /status (71d3959d)
    // for operator binary-drift detection — a loopback concern — but mis-filed as
    // public, which defeated the /version gate for any non-loopback caller.
    "git_sha",
    "build_ts_secs",
];

/// Companion allowlist to [`STATUS_LOOPBACK_ONLY_FIELDS`]: every `/status`
/// field SAFE to surface to a non-loopback (public-listener) caller. All of it
/// is chain-derived or inherently-public state — none fingerprints THIS host.
/// Kept as an explicit allowlist (not "everything not in the denylist") so a
/// newly-added status field can't silently leak: `status_field_set_is_fully_classified`
/// fails until the new key is consciously placed in EITHER this list (public) or
/// `STATUS_LOOPBACK_ONLY_FIELDS` (node-local). Default-deny, matching the curated
/// PQ `handle_status` peer surface (router.rs). Keep in sync with the `status` body.
/// Test-only — consumed solely by `status_field_set_is_fully_classified` (the runtime
/// gate uses the `STATUS_LOOPBACK_ONLY_FIELDS` denylist). `#[cfg(test)]` keeps it out
/// of the non-test lib target, where it would trip `dead_code` under `-D warnings`.
#[cfg(test)]
const STATUS_PUBLIC_FIELDS: &[&str] = &[
    "identity_hash",
    "genesis_authority",
    "node_type",
    "protocol_version",
    "network_id",
    "dag_size",
    "dag_tips",
    "dag_roots",
    "dag_edges",
    "ledger_supply",
    "ledger_supply_beat",
    "ledger_staked",
    "ledger_staked_beat",
    "ledger_accounts",
    "conservation_pool",
    "conservation_pool_beat",
    "peers_connected",
    "peers_total",
    "finalized_count",
    "current_epoch",
    "consensus_attestations",
    "consensus_settled",
    "pending_anchors",
    "total_attestation_weight",
    "total_ever_settled",
    "total_ever_finalized",
    "total_attestations_processed",
    "uptime_secs",
    "version",
    "delta_peer_total_missing",
    "pow_nonce",
    "pow_difficulty",
    "public_key_hex",
    "min_pow_difficulty",
    "legacy_vrf_proof_count",
    "latest_seal_anchor",
    "zone_count",
    "zone_transition",
];

pub async fn status(
    State(state): State<Arc<NodeState>>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
) -> Json<serde_json::Value> {
    // Node-local fingerprint gate (single source of truth — see the
    // STATUS_LOOPBACK_ONLY_FIELDS doc). Hoisted to the top so the per-zone
    // loopback-only fields (zone_timing, subscribed_zones) can SKIP their
    // O(subscribed-zones) materialization entirely for a non-loopback caller —
    // those fields are nulled for the public listener anyway, so building them
    // just to discard the bytes is anonymous-triggerable wasted work. The cheaper
    // scalar fingerprint fields are still built unconditionally and stripped below.
    let is_loopback = super::super::server::ip_is_loopback_canonical(connect_info.0.ip());

    // Temporal proprioception: per-zone adaptive intervals (EMERGENT-MIND §4).
    // Loopback-only (operator dashboard) — null for the public listener, and the
    // per-zone walk is skipped there rather than built-then-stripped.
    let zone_timing = if is_loopback {
        let epoch = state.epoch.read_recover();
        let mut timing = serde_json::Map::new();
        for (zone, interval) in &epoch.zone_adaptive_interval {
            let rate = epoch.zone_activity_rate.get(zone).copied().unwrap_or(0.0);
            let recurrence = epoch.prediction_recurrence.get(zone);
            timing.insert(zone.to_string(), serde_json::json!({
                "adaptive_interval_secs": interval,
                "activity_rate_rps": rate,
                "last_prediction_accuracy": recurrence.map(|r| r.1),
                "last_prediction_epoch": recurrence.map(|r| r.0),
            }));
        }
        serde_json::Value::Object(timing)
    } else {
        serde_json::Value::Null
    };

    // Use lock-free ArcSwap snapshot when available (avoids timeouts on VPS under load).
    // Falls back to direct lock reads if state core isn't initialized yet.
    // `_current_epoch_snap` (the state_core snapshot's cached epoch) is read
    // but intentionally discarded: current_epoch is reported LIVE below so the
    // public liveness tip doesn't freeze on an idle node (the snapshot only
    // refreshes on record ingest). Everything else here is snapshot-sourced.
    let (dag_size, dag_tips, dag_roots, dag_edges, ledger_supply, ledger_staked, ledger_accounts,
         peers_connected, peers_total, finalized_count, _current_epoch_snap, conservation_pool) = if let Some(core) = state.state_core.get() {
        let snap = core.read_snapshot();
        (snap.dag_size, snap.dag_tips, snap.dag_roots, snap.dag_edges,
         snap.ledger_supply, snap.ledger_staked, snap.ledger_accounts,
         snap.peers_connected, snap.peers_total, snap.finalized_count, snap.current_epoch,
         snap.conservation_pool)
    } else {
        let dag = state.dag.read().await;
        let ledger = state.ledger.read().await;
        let peers = state.peers.read().await;
        let finalized = state.finalized.read().await;
        let epoch = dag.current_epoch();
        (dag.len(), dag.tips().len(), dag.roots().len(), dag.edge_count(),
         ledger.total_supply, ledger.total_staked, ledger.accounts.len(),
         peers.connected().len(), peers.len(), finalized.len(), epoch,
         ledger.conservation_pool)
    };

    let (consensus_attestations, finalized_settled, pending_anchors) = {
        let c = state.consensus.lock_recover();
        (c.total_attestation_count(), c.settled_count(), c.pending_anchor_count())
    };

    // PARTITION-MERGE Phase A: total accumulated attestation weight across
    // every zone's latest seal. Read by `pick_heal_target` over /status to
    // rank candidate heal-from peers by chain weight rather than raw record
    // count, so a partition with 1M garbage records can no longer outrank
    // a partition with fewer-but-finalized records. Cost is O(active zones
    // on this node × committee size); on a 1M-zone fleet this is still
    // bounded by the witness committee cap (≤100) per zone, and /status is
    // polled at minute cadence, not request-path.
    let total_attestation_weight: u64 = {
        let epoch = state.epoch.read_recover();
        let consensus = state.consensus.lock_recover();
        epoch
            .latest_seal_id
            .values()
            .map(|id| consensus.attestation_weight_for_seal(id))
            .sum()
    };

    // Tier-1.2 fork-monitor anchor: the (zone, epoch, seal_hash) tuple
    // peers compare against in `fork::check_single_peer` to replace the
    // gossip-window-noisy `global_merkle_root` signal. `null` until the
    // first seal lands locally.
    //
    // current_epoch is read from the SAME live epoch guard (not the state_core
    // snapshot): the snapshot only refreshes on record ingest, so on an idle
    // node its cached epoch freezes while empty seals keep advancing the real
    // tip — a frozen-looking /status is a launch-week footgun. Same active-zone
    // max the snapshot caches (EpochState::active_zone_max_epoch), so the value
    // is identical under traffic and merely fresher when idle. One guard serves
    // both, so this adds no lock cost over the prior single anchor read.
    let (current_epoch, latest_seal_anchor) = {
        let ep = state.epoch.read_recover();
        let cur = ep.active_zone_max_epoch(crate::network::consensus::get_zone_count());
        let anchor = ep.highest_seal_anchor().map(|(zone, epoch, hash)| serde_json::json!({
            "zone": zone.to_string(),
            "epoch": epoch,
            "hash": hex::encode(hash),
        }));
        (cur, anchor)
    };

    // MAINNET gap #5: committee snapshot for /status (computed outside the
    // JSON macro since it can't host arbitrary expressions).
    let committees_json = {
        let c = state.consensus.lock_recover();
        // SCALE RULE: cap the per-zone committee sample so the public,
        // frequently-polled /status can't enumerate + serialize every committee
        // (up to 1M zones at the mainnet target) on each call. `active_zones` is
        // the TRUE count (O(1)); the full per-zone list lives behind the
        // paginated /committees endpoint. Truncation detectable as
        // `per_zone.len() < active_zones`.
        const STATUS_PER_ZONE_SAMPLE: usize = 100;
        let (active_zones, sample) = c.committee_summary_capped(STATUS_PER_ZONE_SAMPLE);
        let per_zone: Vec<serde_json::Value> = sample.into_iter()
            .map(|(z, n, s)| serde_json::json!({
                "zone": z,
                "members": n,
                "stake": s,
            }))
            .collect();
        serde_json::json!({
            "size_cap": crate::network::consensus::MAINNET_COMMITTEE_SIZE,
            "active_zones": active_zones,
            "rotations_total": c.committee_rotations_total,
            "per_zone": per_zone,
        })
    };

    // Loopback-only zone subscription set (node-local fingerprint — see the const
    // doc). Skip the O(subscribed-zones) string materialization for a non-loopback
    // caller; the field is null on the public listener regardless, so the same
    // host-fingerprint class the /metrics tier system keeps off the public plane
    // (server::clamp_public_metric_tier) and the PQ `handle_status` peer surface
    // already omits is here built-only-for-loopback rather than built-then-stripped.
    let subscribed_zones_json = if is_loopback {
        serde_json::Value::Array(
            state
                .zone_manager
                .lock_recover()
                .subscribed_zones()
                .iter()
                .map(|z| serde_json::Value::String(z.to_string()))
                .collect(),
        )
    } else {
        serde_json::Value::Null
    };

    let mut body = serde_json::json!({
        "identity_hash": state.identity.identity_hash,
        "genesis_authority": state.config.genesis_authority,
        "node_type": state.config.node_type,
        "protocol_version": crate::network::config::PROTOCOL_VERSION,
        "network_id": state.config.network_id,
        "listen_addr": state.config.listen_addr,
        "dag_size": dag_size,
        "dag_tips": dag_tips,
        "dag_roots": dag_roots,
        "dag_edges": dag_edges,
        "ledger_supply": ledger_supply,
        "ledger_supply_beat": validate::format_beat_precise(ledger_supply),
        "ledger_staked": ledger_staked,
        "ledger_staked_beat": validate::format_beat_precise(ledger_staked),
        "ledger_accounts": ledger_accounts,
        "conservation_pool": conservation_pool,
        "conservation_pool_beat": validate::format_beat_precise(conservation_pool),
        "peers_connected": peers_connected,
        "peers_total": peers_total,
        "subscribed_zones": subscribed_zones_json,
        "finalized_count": finalized_count,
        "current_epoch": current_epoch,
        "consensus_attestations": consensus_attestations,
        "consensus_settled": finalized_settled,
        "pending_anchors": pending_anchors,
        "total_attestation_weight": total_attestation_weight,
        "total_ever_settled": state.total_ever_settled.load(std::sync::atomic::Ordering::Relaxed),
        "total_ever_finalized": state.total_ever_finalized.load(std::sync::atomic::Ordering::Relaxed),
        "total_attestations_processed": state.total_attestations_processed.load(std::sync::atomic::Ordering::Relaxed),
        "uptime_secs": state.uptime(),
        "version": env!("CARGO_PKG_VERSION"),
        // Build identity on the operator's daily endpoint: the Jun-28-vs-Jul-1
        // binary drift was remotely invisible (both sides said v0.2.0) and cost
        // a day of mesh-split diagnosis. /version and /metrics already carry
        // these; /status is what operators actually curl.
        "git_sha": option_env!("BUILD_GIT_SHA").unwrap_or("unknown"),
        "build_ts_secs": option_env!("BUILD_TS_SECS").unwrap_or("0"),
        "delta_peer_total_missing": state.delta_peer_total_missing.load(std::sync::atomic::Ordering::Relaxed),
        "pow_nonce": state.identity.pow_nonce,
        "pow_difficulty": state.identity.pow_difficulty,
        "public_key_hex": hex::encode(&state.identity.public_key),
        "min_pow_difficulty": state.config.min_pow_difficulty,
        "gc_pruned_total": state.gc_pruned_total.load(std::sync::atomic::Ordering::Relaxed),
        "auto_slashes_total": state.auto_slashes_total.load(std::sync::atomic::Ordering::Relaxed),
        "rss_mb": crate::network::state::NodeState::current_rss_mb(),
        "memory_pressure": state.under_memory_pressure(),
        "legacy_vrf_proof_count": crate::crypto::vrf::legacy_vrf_proof_total(),
        // Stage 6 cooperative-scheduler sensor (Protocol §11.10) — host
        // fingerprint, stripped to null for non-loopback below.
        "system_load": serde_json::json!({
            "cores": state.system_load.cores(),
            "load_1m": state.system_load.load_1m(),
            "normalized_load": state.system_load.normalized_load(),
            "cpu_fraction": state.system_load.cpu_fraction(),
            "samples_total": state.system_load.samples_total(),
            "is_busy": state.system_load.is_busy(),
        }),
        // Stage 6 per-peer token-bucket limiter (Protocol §11.10)
        "peer_bandwidth": {
            "tracked_peers": state.peer_bandwidth.tracked_peers(),
            "skipped_total": state.peer_bandwidth.skipped_total.load(std::sync::atomic::Ordering::Relaxed),
        },
        // PQ inbound read-admission gate (parity with the HTTP rate limiter).
        // `skipped_total` here = PQ read requests rejected with 429.
        "pq_read_limiter": {
            "tracked_peers": state.pq_read_limiter.tracked_peers(),
            "skipped_total": state.pq_read_limiter.skipped_total.load(std::sync::atomic::Ordering::Relaxed),
        },
        // Stage 6.5 size-based retention (Protocol §11.8)
        "disk_usage": {
            "live_bytes": state.rocks.total_live_bytes(),
            "cap_bytes": state.config.disk_cap_bytes,
        },
        // MAINNET gap #5: per-zone VRF committee snapshot. Settlement
        // denominator for the zone is `committee_stake` when ≥ 1 member.
        "committees": committees_json,
        "latest_seal_anchor": latest_seal_anchor,
        "continuity_identities": state.continuity.try_lock().map(|c| c.identity_count()).unwrap_or(0),
        "reincarnation_fingerprints": state.reincarnation.try_lock().map(|r| r.fingerprint_count()).unwrap_or(0),
        "reincarnation_abandoned": state.reincarnation.try_lock().map(|r| r.abandoned_count()).unwrap_or(0),
        "reincarnation_candidates": state.reincarnation.try_lock().map(|r| r.candidate_count()).unwrap_or(0),
        // Temporal proprioception: per-zone adaptive intervals (EMERGENT-MIND §4)
        "zone_timing": zone_timing,
        // Zone count + pending transition
        "zone_count": crate::network::consensus::get_zone_count(),
        "zone_transition": state.zone_transition.lock_recover().as_ref().map(|t| serde_json::json!({
            "target_epoch": t.target_epoch,
            "new_count": t.new_count,
            "old_count": t.old_count,
            "announced_by": t.announced_by,
            "record_id": t.record_id,
        })),
    });

    // Strip node-local fingerprint fields for non-loopback callers on the public
    // listener. Loopback keeps the full dashboard.
    if !is_loopback {
        if let Some(obj) = body.as_object_mut() {
            for k in STATUS_LOOPBACK_ONLY_FIELDS {
                if let Some(v) = obj.get_mut(*k) {
                    *v = serde_json::Value::Null;
                }
            }
        }
    }

    Json(body)
}

// ─── /health ─────────────────────────────────────────────────────────────────

pub async fn compute_health(state: &Arc<NodeState>) -> serde_json::Value {
    // Serve the cached report written by
    // `health_check_loop`. The handler is O(1) lock-free via ArcSwap —
    // never calls `evaluate()` directly. Boot replay + heavy ingest on
    // the 4 GB / 2 GB RAM tier used to block the synchronous call for
    // 3-6 min, surfacing as `/health=000` to monitoring. With the
    // cache, the worst case is a stale-but-immediate payload —
    // monitoring can detect staleness via `cache_age_secs`.
    if let Some(report) = state.cached_health.load_full() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let cache_age = (now - report.timestamp).max(0.0);
        return serde_json::json!({
            "status": report.status_str(),
            "readiness": report.readiness.as_str(),
            "readiness_level": report.readiness.level(),
            "checks": report.checks,
            "uptime_secs": state.uptime(),
            "version": env!("CARGO_PKG_VERSION"),
            "cached": true,
            "cache_age_secs": cache_age,
            // Loop-supervision (verdict 2026-07-19): live per-loop liveness read
            // straight from the registry (NOT the cached report) so a subsystem
            // that silently died/hung shows here even while the rest of /health is
            // green. Empty on nodes that wire no supervised loops.
            "supervised_loops": state.loop_registry.render_health_json(),
        });
    }
    // Cache not yet populated — first health tick hasn't completed.
    // Return a minimal "warming" payload immediately. The handler MUST
    // stay lock-free here; the symptom this fix closes is exactly the
    // case where the handler tried to compute a fresh report and hung.
    serde_json::json!({
        "status": "warming",
        "readiness": "orange",
        "readiness_level": 2u8,
        "checks": [],
        "uptime_secs": state.uptime(),
        "version": env!("CARGO_PKG_VERSION"),
        "cached": false,
        "supervised_loops": state.loop_registry.render_health_json(),
    })
}

pub async fn health(State(state): State<Arc<NodeState>>) -> axum::response::Response {
    // Always return 200 — health status is conveyed via the JSON body (readiness field).
    // Returning 503 for critical state confuses monitoring tools and load balancers
    // into thinking the node has crashed when it's actually running but degraded.
    let body = compute_health(&state).await;
    (axum::http::StatusCode::OK, Json(body)).into_response()
}

// ─── /alive ──────────────────────────────────────────────────────────────────
// Lightweight liveness probe. Distinct from /health (which inspects locks,
// caches, and emits a multi-field JSON body): /alive touches no NodeState
// internals, takes no locks, performs no I/O. A 200 from /alive means the
// axum runtime is scheduling tasks and the listener socket is accepting —
// nothing more. Load balancers and orchestrators (k8s livenessProbe,
// haproxy, systemd watchdog) want this fast-path semantic, not the
// readiness mix that /health conveys. Body is JSON `{"alive":true}` so
// curl-based probes can assert on it without parsing headers.
pub async fn alive() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "alive": true }))
}

// ─── /records (POST) ─────────────────────────────────────────────────────────

pub async fn submit_record(
    State(state): State<Arc<NodeState>>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    // Hard resource backpressure — reject new submissions when the node is critically
    // resource-constrained. Clients should retry with exponential backoff on 429.
    // Only avail-based disk pressure (real disk-full safety) gates
    // ingest. Cap-based pressure is operator policy and is enforced via GC
    // compaction + retention compression, not by rejecting client writes.
    if state.under_critical_memory_pressure() || state.under_avail_pressure() {
        return Err(ElaraError::RateLimited.into());
    }

    // Cross-transport parity with PQ `guard_record_body` (pq_transport/router.rs):
    // reject an oversized body BEFORE `from_bytes` + the `to_bytes` re-serialize
    // in insert_record_inner. A real record is hard-capped at MAX_RECORD_BYTES
    // (64 KiB); without this the HTTP path parsed up to axum's 2 MiB default
    // before the downstream cap fired — wasted parse work a handshaked peer drives.
    if body.len() > crate::network::ingest::MAX_RECORD_BYTES {
        return Err(ElaraError::Wire(format!(
            "record too large: {} bytes (max {})",
            body.len(),
            crate::network::ingest::MAX_RECORD_BYTES
        ))
        .into());
    }

    let record = ValidationRecord::from_bytes(&body)?;
    // Signature verification is handled by gossip::insert_record

    // Protocol version check — reject records from incompatible peers
    let peer_version: u32 = headers
        .get("x-elara-protocol-version")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0); // missing header -> version 0 (pre-versioning)

    let min_version = state.config.min_protocol_version;
    if min_version > 0 && peer_version < min_version {
        return Ok(Json(serde_json::json!({
            "accepted": false,
            "reason": "protocol_version_too_low",
            "peer_version": peer_version,
            "min_version": min_version,
        })));
    }

    // Network isolation — reject records from a different network
    let peer_network: &str = headers
        .get("x-elara-network-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("testnet"); // missing header = testnet (backward compat)
    if peer_network != state.config.network_id {
        return Ok(Json(serde_json::json!({
            "accepted": false,
            "reason": "network_mismatch",
            "peer_network": peer_network,
            "our_network": state.config.network_id,
        })));
    }

    // MAINNET gap #8 (floor-push): ingress byte meter. Counted after
    // protocol-version + network-id gating so foreign-network spam and
    // incompatible peers don't inflate the figure. Includes bytes that later
    // dedup (that's legitimate inbound traffic the node still paid for on the
    // wire). HTTP headers + TLS framing are excluded — those are amortized
    // noise at record-level granularity.
    state
        .gossip_bytes_in_total
        .fetch_add(body.len() as u64, std::sync::atomic::Ordering::Relaxed);

    // Profile-scoped push acceptance: Light (phone-tier) nodes reject
    // peer-relayed pushes to keep their disk bounded — account running on
    // them pulls headers + own-account proofs only. Local account submission
    // has no `x-elara-sender` header and bypasses this gate. FullZone /
    // Archive accept pushes normally.
    if headers.contains_key("x-elara-sender") {
        let profile = crate::network::node_profile::NodeProfile::from_str(
            &state.config.node_profile,
        );
        if !profile.accepts_gossip_push() {
            state
                .gossip_push_rejected_profile_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(Json(serde_json::json!({
                "accepted": false,
                "reason": "profile_rejects_push",
                "profile": profile.as_str(),
            })));
        }
    }

    let record_id = record.id.clone();

    // Check dedup — only check membership, don't insert yet.
    // Insert happens after successful validation to prevent failed records
    // from permanently poisoning the seen set.
    {
        let already_seen = state.seen.lock_recover().contains(&record_id);
        if already_seen {
            state.gossip_seen_dedup_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(Json(
                serde_json::json!({"accepted": false, "reason": "duplicate", "id": record_id}),
            ));
        }
    }
    // Check gossip rejection cache — skip records we already tried and rejected.
    // This prevents infinite push/pull retry of permanently invalid records.
    {
        let already_rejected = state.gossip_rejected.lock_recover().contains(&record_id);
        if already_rejected {
            state.gossip_rejected_dedup_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(Json(
                serde_json::json!({"accepted": false, "reason": "previously_rejected", "id": record_id}),
            ));
        }
    }

    // Extract gossip flow-control headers
    let incoming_hops: Option<u8> = headers
        .get("x-elara-hops")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());
    let sender: Option<String> = headers
        .get("x-elara-sender")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let sender_port: Option<u16> = headers
        .get("x-elara-port")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());
    // NAT traversal: sender can advertise a reachable host (e.g., Tailscale IP)
    // instead of relying on the TCP source IP which may be an unreachable NAT IP.
    let sender_advertised_host: Option<String> = headers
        .get("x-elara-host")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= 253) // basic validation
        .map(|s| s.to_string());
    let sender_pow_nonce: u64 = headers
        .get("x-elara-pow-nonce")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let sender_pow_difficulty: u8 = headers
        .get("x-elara-pow-difficulty")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // NAT self-report: peer tells us if it's directly reachable.
    // "0" = behind NAT (don't push to or pull from this peer).
    let sender_reachable: bool = headers
        .get("x-elara-reachable")
        .and_then(|v| v.to_str().ok())
        .map(|s| s != "0")
        .unwrap_or(true); // default reachable for old peers without the header
    // Implicit peer discovery: register the sender as a peer if not already known.
    if let (Some(sender_hash), Some(port)) = (&sender, sender_port) {
        // Prefer advertised host (NAT traversal) over TCP source IP.
        let host = sender_advertised_host.clone()
            .unwrap_or_else(|| connect_info.0.ip().to_string());
        // Don't auto-register an implicit peer whose advertised host is unreachable
        // (port 0), not a routable IP literal, a reserved/non-routable address, or
        // CGNAT. `is_dialable_wire_host` requires a routable IP **literal**: the
        // `x-elara-host` header is attacker-controllable, and a bare hostname would
        // slip past the reserved-IP filter (no DNS) only to be resolved+dialed raw →
        // blind SSRF. (This handler is loopback-only today — `/records` lives on the
        // 127.0.0.1 data plane — so this is defense-in-depth, not the primary vector;
        // the remote vectors are the PEX / FIND_NODE response parsers.) The literal
        // gate folds in the shared reserved-IP filter (loopback, RFC1918, 169.254
        // cloud-metadata, broadcast, unspecified, IPv4-mapped/NAT64). It deliberately
        // does NOT cover 100.64/10 (Tailscale CGNAT is a valid dial target), so the
        // CGNAT-skip is kept here as a separate, implicit-discovery-only clause.
        let is_nat = port == 0
            || !crate::network::discovery::is_dialable_wire_host(&host)
            || super::super::server::parse_ipv4_octets(&host)
                .is_some_and(|octets| octets[0] == 100 && (64..=127).contains(&octets[1]));
        if is_nat {
            tracing::debug!(
                "implicit peer discovery: skipping {} — NAT detected (host={host}, port={port})",
                &sender_hash[..sender_hash.len().min(16)]
            );
        } else if *sender_hash != state.identity.identity_hash {
            // Verify PoW BEFORE taking the lock — CPU work, no contention.
            let sender_pk_hex = headers
                .get("x-elara-public-key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let min_pow = state.config.min_pow_difficulty;
            let pow_verified = if !sender_pk_hex.is_empty() && sender_pow_difficulty >= min_pow {
                if let Ok(pk_bytes) = hex::decode(&sender_pk_hex) {
                    crate::identity::Identity::verify_pow_static(&pk_bytes, sender_pow_nonce, sender_pow_difficulty)
                } else {
                    false
                }
            } else {
                false
            };

            // Single write lock: check if known (update last_seen) OR register.
            // This prevents the TOCTOU race where concurrent pushes all see the
            // peer as unknown and all proceed to register+log.
            {
                let mut peers = state.peers.write().await;
                if peers.get(sender_hash).is_some() {
                    // Already known — mark connected to reset failures + backoff.
                    // Critical for NAT'd peers: VPS can't ping them, so heartbeat
                    // accumulates failures. But if they're pushing records to us,
                    // they're alive. Reset liveness on every successful push.
                    // PQ-R6: we never serve TLS in-process, so don't advertise it.
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs_f64();
                    peers.mark_connected(sender_hash, now);
                    // Tier 1.1 NAT detection: trust the peer's self-reported
                    // reachability so the heartbeat dial loop skips NAT'd
                    // peers (preventing failures-driven ban) and recovered
                    // peers re-enter normal heartbeat. See discovery.rs.
                    peers.update_reachability(sender_hash, sender_reachable);
                } else if pow_verified && peer_version >= min_version {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs_f64();
                    let peer = crate::network::peer::PeerInfo {
                        identity_hash: sender_hash.clone(),
                        host,
                        port,
                        node_type: crate::network::peer::NodeType::Witness,
                        last_seen: now,
                        state: crate::network::peer::PeerState::Connected,
                        failures: 0,
                        successes: 1,
                        valid_records: 1,
                        invalid_records: 0,
                        backoff_until: 0.0,
                        pow_nonce: sender_pow_nonce,
                        pow_difficulty: sender_pow_difficulty,
                        public_key_hex: sender_pk_hex,
                        provenance: crate::network::peer::PeerProvenance::Inbound,
                        subscribed_zones: Vec::new(),
                        att_watermark: 0.0,
                        pull_failures: 0,
                        pull_backoff_until: 0.0,
                        reachable: sender_reachable,
                        protocol_version: peer_version,
                        att_pull_invalid_sig: 0,
                        att_pull_invalid_powas: 0,
                        att_push_low_stake_deferred: 0,
recent_bad_sig_record_ids: std::collections::VecDeque::new(),
                    };
                    if peers.insert(peer) {
                        tracing::info!("implicit peer discovery: registered {} via gossip push (PoW: {}, verified, reachable: {})", &sender_hash[..sender_hash.len().min(16)], sender_pow_difficulty, sender_reachable);
                    }
                } else {
                    tracing::debug!("implicit peer discovery: rejected {} — PoW not verified (need x-elara-public-key header)", &sender_hash[..sender_hash.len().min(16)]);
                }
            }
        }
    }
    let trace_id: String = headers
        .get("x-elara-trace-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());

    // Insert into storage + DAG — via state core channel (no lock contention)
    // Gossip pushes use GossipPush source (priority channel) to avoid starvation
    // behind bulk delta-pull backlog. Also skips per-identity rate limits —
    // peers with >100 records/hr from one identity can catch up via push relay.
    let is_gossip_push = sender.is_some();
    let record_clone = record.clone();
    if let Some(core) = state.state_core.get() {
        // B6: the HTTP path has no PQ handshake identity to authenticate the
        // relayer, so it cannot mint a *remotely-vouched* trusted push. `/records`
        // is loopback-only (not in PUBLIC_ROUTE_PREFIXES → off-host 404s), so the
        // only legitimate push here is the node's own local relay re-entry: trust
        // == loopback. Defense-in-depth — keeps the variant safe-by-construction
        // even if a future routing change exposed `/records`.
        let push_trusted = super::super::server::ip_is_loopback_canonical(connect_info.0.ip());
        let source = if is_gossip_push {
            let peer_hash = sender.clone().unwrap_or_default();
            crate::network::state_core::RecordSource::GossipPush { peer_hash, trusted: push_trusted }
        } else {
            let peer_ip = Some(connect_info.0.ip().to_string());
            crate::network::state_core::RecordSource::HttpSubmit { peer_ip }
        };

        if is_gossip_push {
            // ── Async gossip push: return 202 immediately ──────────────────
            // Records take 18-1200ms to process (avg 229ms). State core is
            // single-threaded. A queue of 40 records × 229ms = 10s, exceeding
            // the 10s push timeout. By returning immediately, we eliminate
            // queue-depth-induced push failures (was 52-66% failure rate).
            //
            // The sender only checks HTTP status — response body is unused.
            // Dedup is handled by the seen set (inserted before background task).
            // Relay happens only after successful insertion (no invalid relay).
            state.seen.lock_recover().insert(record_id.clone());
            let state_bg = state.clone();
            let rid = record_id.clone();
            let rc = record_clone;
            let node_type = crate::network::peer::NodeType::from_str(&state.config.node_type);
            let exclude_sender = sender;
            let tid = trace_id;
            let core = core.clone();
            tokio::spawn(async move {
                let result = core.insert_record(record, source).await;
                match result {
                    crate::network::state_core::InsertResult::Accepted { .. } => {
                        // Relay after successful validation
                        match incoming_hops {
                            Some(hops) if hops > 0 && node_type.can_relay() => {
                                crate::network::gossip::push_to_peers(
                                    &state_bg, &rc, hops - 1,
                                    exclude_sender.as_deref(), Some(tid.as_str()),
                                ).await;
                            }
                            Some(_) => {
                                state_bg.gossip_push_skipped_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            None => {
                                // Gossip pushes always have hops — this shouldn't happen
                                NodeState::publish_record_with_fallback(&state_bg, &rc, exclude_sender.as_deref()).await;
                            }
                        }
                    }
                    crate::network::state_core::InsertResult::Rejected { reason } => {
                        let creator_hash = crate::accounting::types::creator_identity_hash(&rc);
                        tracing::warn!(
                            "gossip push REJECTED: id={} creator={} reason={}",
                            &rid[..rid.len().min(16)],
                            &creator_hash[..creator_hash.len().min(16)],
                            reason,
                        );
                        // B6 (fork-safety linchpin): never permanently-cache an
                        // untrusted push's rejection — a permanent gossip_rejected
                        // entry is consulted+skipped by every pull driver, so a
                        // forged push could censor a canonical record out of sync.
                        // Park it instead (not consulted by pull skips).
                        // 8b invariant: seal-class disposes first — a TRUSTED
                        // push's seal reject was still an embargo leak here.
                        if crate::network::gossip::dispose_seal_ingest_failure(&state_bg, &rc, 0) {
                            // seal-class disposed (declined or bounded park)
                        } else if crate::network::gossip::should_permanent_reject(!push_trusted, &reason) {
                            state_bg.gossip_rejected.lock_recover().insert(rid);
                        } else {
                            crate::network::gossip::park_retryable(&state_bg, &rid);
                        }
                    }
                    crate::network::state_core::InsertResult::Error { message } => {
                        tracing::warn!("gossip push ERROR: id={} error={}", &rid[..rid.len().min(16)], message);
                        // P0: InsertResult::Error is a TRANSIENT state-core infra
                        // failure (worker down/restarting), never a content
                        // rejection — park for retry, NEVER permanent-cache. A
                        // gossip_rejected entry is consult-and-skip on every pull
                        // driver, so embargoing an infra failure makes the record
                        // un-repullable on this node (P0 silent-loss).
                        if !crate::network::gossip::dispose_seal_ingest_failure(&state_bg, &rc, 0) {
                            crate::network::gossip::park_retryable(&state_bg, &rid);
                        }
                    }
                }
            });
            return Ok(Json(serde_json::json!({"accepted": true, "id": record_id})));
        }

        // ── Sync path: direct HTTP submissions await result ──────────────
        let result = core.insert_record(record, source).await;
        match result {
            crate::network::state_core::InsertResult::Accepted { .. } => {}
            crate::network::state_core::InsertResult::Rejected { reason } => {
                let creator_hash = crate::accounting::types::creator_identity_hash(&record_clone);
                tracing::warn!(
                    "POST /records REJECTED: id={} creator={} ts={:.3} reason={}",
                    &record_id[..record_id.len().min(16)],
                    &creator_hash[..creator_hash.len().min(16)],
                    record_clone.timestamp,
                    reason,
                );
                // 8b invariant: seal-class never enters gossip_rejected.
                if crate::network::gossip::dispose_seal_ingest_failure(&state, &record_clone, 0) {
                    // seal-class disposed (declined or bounded park)
                } else if !crate::network::gossip::is_retryable_ingest_rejection(&reason) {
                    state.gossip_rejected.lock_recover().insert(record_id.clone());
                } else {
                    crate::network::gossip::park_retryable(&state, &record_id);
                }
                return Ok(Json(serde_json::json!({"accepted": false, "reason": reason, "id": record_id})));
            }
            crate::network::state_core::InsertResult::Error { message } => {
                let creator_hash = crate::accounting::types::creator_identity_hash(&record_clone);
                tracing::warn!(
                    "POST /records ERROR: id={} creator={} ts={:.3} error={}",
                    &record_id[..record_id.len().min(16)],
                    &creator_hash[..creator_hash.len().min(16)],
                    record_clone.timestamp,
                    message,
                );
                // P0: transient state-core infra failure → park for retry, never
                // permanent-cache (gossip_rejected is consult-and-skip on pull).
                if !crate::network::gossip::dispose_seal_ingest_failure(&state, &record_clone, 0) {
                    crate::network::gossip::park_retryable(&state, &record_id);
                }
                // P0 parity: transient state-core failure is retryable infra,
                // not a content fault — TransientReject → 503, not Storage → 500.
                return Err(AppError(crate::errors::ElaraError::TransientReject(message)));
            }
        }
    } else {
        // Fallback: direct insert (core not initialized yet, e.g. during startup)
        gossip::insert_record(&state, record).await?;
    }

    // Mark as seen AFTER successful insertion — not before.
    state.seen.lock_recover().insert(record_id.clone());

    debug!(trace_id = %trace_id, "accepted record {record_id}");

    // Gossip relay for direct submissions (gossip push relay handled in async block above)
    let node_type = crate::network::peer::NodeType::from_str(&state.config.node_type);
    let state2 = state.clone();
    let exclude_sender = sender.clone();
    let tid = trace_id.clone();
    debug!(trace_id = %trace_id, "gossip propagation starting");
    tokio::spawn(async move {
        match incoming_hops {
            None => {
                // Originator record (no hops header) — full push with max hops
                NodeState::publish_record_with_fallback(&state2, &record_clone, exclude_sender.as_deref()).await;
            }
            Some(hops) if hops > 0 && node_type.can_relay() => {
                crate::network::gossip::push_to_peers(
                    &state2, &record_clone, hops - 1,
                    exclude_sender.as_deref(), Some(tid.as_str()),
                ).await;
            }
            Some(_) => {
                state2.gossip_push_skipped_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    });

    Ok(Json(
        serde_json::json!({"accepted": true, "id": record_id}),
    ))
}

// ─── /records (GET) ──────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct RecordQuery {
    pub since: Option<f64>,
    pub limit: Option<usize>,
    pub creator: Option<String>,
    /// ZSP-C: optional zone scope. When set, the responder iterates
    /// `CF_RECORD_BY_ZONE` (O(records_in_zone)) instead of the global
    /// timestamp/creator scan, so a light client subscribed to two zones
    /// out of 1M doesn't pay for the other 999,998. Accepts a hierarchical
    /// path (`medical/eu`) or a legacy numeric id.
    pub zone: Option<String>,
}

impl RecordQuery {
    /// Build a `RecordQuery` programmatically (used by `/records/from/{epoch}`
    /// to dispatch into the canonical `query_records` handler with a
    /// pre-computed `since` timestamp). Kept tiny on purpose — the struct
    /// otherwise reads its values from axum's `Query` extractor.
    pub fn __from_parts(
        since: Option<f64>,
        limit: Option<usize>,
        creator: Option<String>,
        zone: Option<String>,
    ) -> Self {
        Self { since, limit, creator, zone }
    }
}

pub async fn query_records(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<RecordQuery>,
) -> Result<Json<Vec<String>>, AppError> {
    state.stamp_inbound_sync();
    let since = params.since.unwrap_or(0.0);
    let limit = params.limit.unwrap_or(100).min(1000);
    let creator_key = params.creator.as_ref().and_then(|h| hex::decode(h).ok());
    let zone_filter: Option<crate::ZoneId> = params.zone.as_deref().map(crate::ZoneId::new);

    let state2 = state.clone();
    let wire_bytes = tokio::task::spawn_blocking(move || -> Result<Vec<Vec<u8>>, ElaraError> {
        let storage = state2.rocks.as_ref();

        // Zone-scoped path (ZSP-C): iterate CF_RECORD_BY_ZONE, fetch records
        // by id, apply optional creator filter post-read. Bytes-on-wire is
        // bounded by zone size, not global record count.
        if let Some(zone) = zone_filter {
            let zone_key = zone.to_key_bytes();
            // Over-fetch slightly when a creator filter is active, since the
            // zone iter doesn't pre-filter by creator. Cap at 4× to bound
            // worst-case iteration on zones with few matching records.
            let scan_cap = if creator_key.is_some() { limit.saturating_mul(4) } else { limit };
            let ids = storage.iter_zone(&zone_key, Some(since), None, scan_cap);
            let mut out = Vec::with_capacity(ids.len().min(limit));
            for id in &ids {
                if out.len() >= limit { break; }
                if let Ok(Some(rec)) = storage.get_record(id) {
                    if let Some(ref c) = creator_key {
                        if &rec.creator_public_key != c { continue; }
                    }
                    out.push(rec.to_bytes());
                }
            }
            return Ok(out);
        }

        // Zone-blind path: legacy global query (existing semantics preserved).
        let records = storage.query(
            None,
            creator_key.as_deref(),
            Some(since),
            None,
            limit,
        )?;
        Ok(records.iter().map(|r| r.to_bytes()).collect::<Vec<_>>())
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    let hex_records: Vec<String> = wire_bytes.iter().map(hex::encode).collect();
    Ok(Json(hex_records))
}

// ─── /announce ───────────────────────────────────────────────────────────────

pub async fn receive_announcements(
    State(state): State<Arc<NodeState>>,
    Json(announcements): Json<Vec<gossip::RecordAnnouncement>>,
) -> Json<serde_json::Value> {
    let announcements: Vec<_> = announcements.into_iter().take(1000).collect();
    let mut want = Vec::new();
    let mut have = Vec::new();

    for ann in &announcements {
        let already_seen = state.seen.lock_recover().contains(&ann.record_id);
        if already_seen {
            have.push(ann.record_id.clone());
            continue;
        }
        // Check gossip rejection cache — don't request records we already rejected
        let already_rejected = state.gossip_rejected.lock_recover().contains(&ann.record_id);
        if already_rejected {
            state.gossip_rejected_dedup_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            have.push(ann.record_id.clone());
            continue;
        }
        let in_storage = state.rocks.record_exists(&ann.record_id).unwrap_or(false);
        if in_storage {
            have.push(ann.record_id.clone());
        } else {
            want.push(ann.record_id.clone());
        }
    }

    Json(serde_json::json!({
        "want": want,
        "have": have,
    }))
}

// ─── /records/fetch ──────────────────────────────────────────────────────────

pub async fn fetch_records_wire(
    State(state): State<Arc<NodeState>>,
    Json(ids): Json<Vec<String>>,
) -> Result<Json<Vec<String>>, AppError> {
    let max_fetch = 100usize;
    let state2 = state.clone();
    let ids_capped: Vec<String> = ids.into_iter().take(max_fetch).collect();

    let (hex_records, wire_bytes_served) = tokio::task::spawn_blocking(move || {
        let mut results = Vec::new();
        let mut bytes = 0u64;
        for id in &ids_capped {
            if let Ok(b) = state2.rocks.get_wire_bytes(id) {
                bytes = bytes.saturating_add(b.len() as u64);
                results.push(hex::encode(&b));
            }
        }
        (results, bytes)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;

    // MAINNET gap #8 (floor-push): account for pull-responder egress. The
    // hex-encoded payload doubles on the wire (2 bytes of JSON per record
    // byte), but we count the raw record bytes to stay consistent with the
    // push path. Framing overhead is uniformly excluded across both paths.
    state
        .gossip_bytes_out_total
        .fetch_add(wire_bytes_served, std::sync::atomic::Ordering::Relaxed);

    Ok(Json(hex_records))
}

// ─── /records/search ─────────────────────────────────────────────────────────

pub async fn search_records(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    use std::sync::atomic::Ordering::Relaxed;

    let query = crate::storage::SearchQuery {
        text: params.get("q").cloned(),
        creator_hash: params.get("creator").cloned(),
        metadata_key: params.get("key").cloned(),
        metadata_value: params.get("value").cloned(),
        since: params.get("from").and_then(|s| s.parse().ok()),
        until: params.get("to").and_then(|s| s.parse().ok()),
        classification: params.get("class").and_then(|s| match s.as_str() {
            "0" | "public" | "Public" => Some(crate::record::Classification::Public),
            "1" | "private" | "Private" => Some(crate::record::Classification::Private),
            "2" | "restricted" | "Restricted" => Some(crate::record::Classification::Restricted),
            "3" | "sovereign" | "Sovereign" => Some(crate::record::Classification::Sovereign),
            _ => None,
        }),
        limit: params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(100).min(1000),
        offset: params.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0),
    };

    state.search_queries_total.fetch_add(1, Relaxed);

    let results = state.search_records(&query)?;

    let records: Vec<serde_json::Value> = results.iter().map(|r| {
        let hash = hex::encode(r.record_hash());
        serde_json::json!({
            "id": r.id,
            "hash": hash,
            "creator_hash": creator_identity_hash(r),
            "timestamp": r.timestamp,
            "classification": format!("{:?}", r.classification),
            "metadata": r.metadata,
        })
    }).collect();

    Ok(Json(serde_json::json!({
        "count": records.len(),
        "results": records,
    })))
}

// ─── /validate ───────────────────────────────────────────────────────────────

pub async fn validate_record(
    State(state): State<Arc<NodeState>>,
    body: axum::body::Bytes,
) -> Json<serde_json::Value> {
    Json(compute_validate_record(&state, &body).await)
}

/// Shared validate-record service-fn.
/// Always returns a JSON envelope (never errors) — wire/parse failures surface
/// as `{"valid": false, "checks": [...]}` so axum and PQ render identical
/// bodies without needing different status codes.
pub async fn compute_validate_record(
    state: &Arc<NodeState>,
    body: &[u8],
) -> serde_json::Value {
    // Oversized bodies can't be valid records (MAX_RECORD_BYTES hard cap) —
    // reject before deserializing up to axum's 2 MiB default. Same shape as the
    // wire_format failure arm below so HTTP renders a consistent envelope.
    if body.len() > crate::network::ingest::MAX_RECORD_BYTES {
        return serde_json::json!({
            "valid": false,
            "checks": [{"check": "wire_format", "passed": false,
                "error": format!("record too large: {} bytes (max {})",
                    body.len(), crate::network::ingest::MAX_RECORD_BYTES)}],
        });
    }

    let mut checks = Vec::new();
    let mut valid = true;

    // 1. Wire deserialization
    let record = match ValidationRecord::from_bytes(body) {
        Ok(r) => {
            checks.push(serde_json::json!({"check": "wire_format", "passed": true}));
            r
        }
        Err(e) => {
            return serde_json::json!({
                "valid": false,
                "checks": [{"check": "wire_format", "passed": false, "error": e.to_string()}],
            });
        }
    };

    let record_id = record.id.clone();
    let creator_hash = creator_identity_hash(&record);

    // 2. Bounds validation
    let bounds_ok = record.metadata.len() <= gossip::MAX_METADATA_ENTRIES
        && record.parents.len() <= gossip::MAX_PARENTS
        && record.metadata.values().all(|v| v.to_string().len() <= gossip::MAX_METADATA_VALUE_LEN);
    if !bounds_ok {
        valid = false;
    }
    checks.push(serde_json::json!({"check": "bounds", "passed": bounds_ok,
        "metadata_entries": record.metadata.len(), "parents": record.parents.len()}));

    // 3. Timestamp drift
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let ts_ok = record.timestamp <= now_ts + gossip::MAX_FUTURE_DRIFT_SECS;
    if !ts_ok {
        valid = false;
    }
    checks.push(serde_json::json!({"check": "timestamp", "passed": ts_ok,
        "record_ts": record.timestamp, "drift_secs": record.timestamp - now_ts}));

    // 4. Signature verification — Dilithium3 on caller-supplied bytes, off the
    // async worker (spawn_blocking; 2026-07-12 sweep A7). JoinError ⇒ false:
    // this fn is infallible-by-design (result envelope, never Err).
    let sig_ok = match record.signature.clone() {
        Some(sig) => {
            let msg = record.signable_bytes();
            let pk = record.creator_public_key.clone();
            tokio::task::spawn_blocking(move || {
                matches!(dilithium3_verify(&msg, &sig, &pk), Ok(true))
            })
            .await
            .unwrap_or(false)
        }
        None => false,
    };
    if !sig_ok {
        valid = false;
    }
    checks.push(serde_json::json!({"check": "signature", "passed": sig_ok}));

    // 5. Ledger operation validation (if applicable)
    match extract_ledger_op(&record) {
        Ok(Some(parsed_op)) => {
            let ledger = state.ledger.read().await;
            let result = validate::validate_op(
                &ledger,
                &creator_hash,
                &state.config.genesis_authority,
                &parsed_op,
                record.timestamp,
                // /validate is a fresh-record pre-submission dry-run (mempool
                // admission), so enforce the rate-limiters here.
                true,
            );
            if !result.valid {
                valid = false;
            }
            checks.push(serde_json::json!({
                "check": "beat_op",
                "passed": result.valid,
                "op": format_op(&parsed_op),
                "error": result.error,
            }));
        }
        Ok(None) => {
            checks.push(serde_json::json!({"check": "beat_op", "passed": true, "op": null}));
        }
        Err(e) => {
            valid = false;
            checks.push(serde_json::json!({"check": "beat_op", "passed": false, "error": e.to_string()}));
        }
    }

    // 6. DAG parent existence check (advisory, not blocking): a record with
    // parents not-yet-local is still valid/submittable (they arrive via gossip),
    // so `passed` is always true BY DESIGN. `advisory: true` flags that to callers
    // so always-true is not mistaken for "all parents present" — read
    // `missing_locally` for the real local-resolution state.
    let parents_found = {
        let dag = state.dag.read().await;
        record.parents.iter().filter(|p| dag.contains(p)).count()
    };
    checks.push(serde_json::json!({
        "check": "parents",
        "passed": true,
        "advisory": true,
        "total": record.parents.len(),
        "found_locally": parents_found,
        "missing_locally": record.parents.len() - parents_found,
    }));

    // 7. Duplicate check
    let is_dup = state.seen.lock_recover().contains(&record_id);
    checks.push(serde_json::json!({"check": "duplicate", "passed": !is_dup, "is_duplicate": is_dup}));
    if is_dup {
        valid = false;
    }

    serde_json::json!({
        "valid": valid,
        "record_id": record_id,
        "creator_hash": creator_hash,
        "classification": record.classification.name(),
        "timestamp": record.timestamp,
        "checks": checks,
    })
}

// ─── /records/stream ─────────────────────────────────────────────────────────

/// Per-IP bound within the global 50-slot SSE cap. The global cap alone lets
/// ONE address hold every slot and starve all other subscribers (2026-07-12
/// sweep A9). Loopback is exempt — the node's own UI/daemon must never queue
/// behind external subscribers.
const SSE_PER_IP_MAX: usize = 5;

fn sse_per_ip_slots(
) -> &'static std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>> {
    static SLOTS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>,
    > = std::sync::OnceLock::new();
    SLOTS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// RAII slot: decrements the holder's per-IP count when the SSE stream drops.
/// `None` = exempt connection (loopback), no bookkeeping.
struct SsePerIpSlot(Option<std::net::IpAddr>);

impl Drop for SsePerIpSlot {
    fn drop(&mut self) {
        if let Some(ip) = self.0 {
            if let Ok(mut m) = sse_per_ip_slots().lock() {
                if let Some(n) = m.get_mut(&ip) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        m.remove(&ip);
                    }
                }
            }
        }
    }
}

pub async fn records_stream(
    State(state): State<Arc<NodeState>>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, AppError> {
    if state.events.receiver_count() > 50 {
        return Err(ElaraError::RateLimited.into());
    }

    // Claim a per-IP slot before subscribing; released when the stream drops
    // (the guard moves into the stream closure below).
    let ip = connect_info.0.ip();
    let slot = if ip.is_loopback() {
        SsePerIpSlot(None)
    } else {
        {
            let mut m = sse_per_ip_slots()
                .lock()
                .map_err(|_| ElaraError::Network("sse per-ip slot lock poisoned".into()))?;
            let n = m.entry(ip).or_insert(0);
            if *n >= SSE_PER_IP_MAX {
                return Err(ElaraError::RateLimited.into());
            }
            *n += 1;
        }
        SsePerIpSlot(Some(ip))
    };

    let identity_filter = params.get("identity").cloned();

    let rx = state.events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |result| {
        // Holds the per-IP slot for the stream's whole lifetime; its Drop
        // releases the count when the subscriber disconnects.
        let _hold_slot = &slot;
        match result {
            Ok(event) => {
                let (event_type, data, creator) = match &event {
                    crate::network::state::NodeEvent::RecordInserted {
                        record_id,
                        creator_hash,
                        beat_op,
                        beat_amount,
                        timestamp,
                    } => (
                        "record_inserted",
                        serde_json::json!({
                            "record_id": record_id,
                            "creator_hash": creator_hash,
                            "beat_op": beat_op,
                            "beat_amount": beat_amount,
                            "timestamp": timestamp,
                        }),
                        Some(creator_hash.clone()),
                    ),
                    crate::network::state::NodeEvent::RecordSealed { record_id, witness_count } => (
                        "record_sealed",
                        serde_json::json!({
                            "record_id": record_id,
                            "witness_count": witness_count,
                        }),
                        None,
                    ),
                    crate::network::state::NodeEvent::RecordFinalized { record_id } => (
                        "record_finalized",
                        serde_json::json!({ "record_id": record_id }),
                        None,
                    ),
                };

                if let Some(ref filter) = identity_filter {
                    if let Some(ref c) = creator {
                        if c != filter {
                            return None;
                        }
                    }
                }

                Some(Ok(Event::default()
                    .event(event_type)
                    .data(data.to_string())))
            }
            Err(_) => None,
        }
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

// ─── /witness ────────────────────────────────────────────────────────────────

pub async fn witness_record(
    State(state): State<Arc<NodeState>>,
    body: axum::body::Bytes,
) -> Result<axum::body::Bytes, AppError> {
    // Cross-transport parity with PQ `guard_record_body` — reject oversized
    // bodies before the parse (see submit_record). MAX_RECORD_BYTES = 64 KiB.
    if body.len() > crate::network::ingest::MAX_RECORD_BYTES {
        return Err(ElaraError::Wire(format!(
            "record too large: {} bytes (max {})",
            body.len(),
            crate::network::ingest::MAX_RECORD_BYTES
        ))
        .into());
    }
    let record = ValidationRecord::from_bytes(&body)?;

    let signable = record.signable_bytes();
    if let Some(sig) = &record.signature {
        if !dilithium3_verify(&signable, sig, &record.creator_public_key)? {
            return Err(ElaraError::InvalidSignature.into());
        }
    } else {
        return Err(ElaraError::InvalidSignature.into());
    }

    let signable = record.signable_bytes();
    let attestation_sig = state
        .identity
        .sign(&signable)
        .map_err(|e| ElaraError::Network(format!("witness sign failed: {e}")))?;

    let mut response = Vec::with_capacity(64 + attestation_sig.len());
    response.extend_from_slice(state.identity.identity_hash.as_bytes());
    response.extend_from_slice(&attestation_sig);

    Ok(axum::body::Bytes::from(response))
}

// ─── /peers ──────────────────────────────────────────────────────────────────

/// Default / hard cap on the number of peers `/peers` returns in one response.
/// `total` reports the TRUE known-peer count (after the self-filter); only the
/// returned `peers` array is bounded. The peer table is reachable over the PQ
/// `list_peers` verb by any handshaked peer and grows with the node population
/// (up to the 10K+-node design target), so a single call must not dump the
/// whole table as one JSON payload — SCALE RULE: bounded, always. Truncation is
/// detectable as `peers.len() < total`. The default (1000) sits far above the
/// discovery consumer's `MAX_NEW_PEERS_PER_SOURCE = 32` per-round admission cap
/// (discovery.rs), so the bound never starves PEX. Mirrors the `/epochs` bound.
const PEERS_DEFAULT_LIMIT: usize = 1000;
const PEERS_MAX_LIMIT: usize = 10_000;

#[derive(serde::Deserialize)]
pub struct PeersQuery {
    pub limit: Option<usize>,
}

pub async fn compute_list_peers(
    state: &Arc<NodeState>,
    limit: Option<usize>,
) -> serde_json::Value {
    let limit = limit.unwrap_or(PEERS_DEFAULT_LIMIT).min(PEERS_MAX_LIMIT);
    let peers = state.peers.read().await;
    let self_hash = &state.identity.identity_hash;
    let mut peer_list: Vec<serde_json::Value> = peers
        .all()
        .iter()
        .filter(|p| p.identity_hash != *self_hash)
        .map(|p| {
            serde_json::json!({
                "identity_hash": p.identity_hash,
                "host": p.host,
                "port": p.port,
                "node_type": p.node_type,
                "last_seen": p.last_seen,
                "state": format!("{:?}", p.state),
                "reachable": p.reachable,
                "failures": p.failures,
                "successes": p.successes,
                "pow_nonce": p.pow_nonce,
                "pow_difficulty": p.pow_difficulty,
                "public_key_hex": p.public_key_hex,
                "protocol_version": p.protocol_version,
                // Per-peer attestation pull-side rejections, so
                // operators can attribute a bad-sig storm to a specific
                // neighbour. `top(rate(...))` over /peers identifies the source.
                "att_pull_invalid_sig": p.att_pull_invalid_sig,
                "att_pull_invalid_powas": p.att_pull_invalid_powas,
                // Per-peer push-side low-stake-deferred count. When one
                // peer dominates this counter and global low_stake_drained_total
                // stays at 0, that peer is forwarding for a witness whose stake
                // gossip is stuck on this node — pick a different peer for
                // snapshot rebootstrap.
                "att_push_low_stake_deferred": p.att_push_low_stake_deferred,
                // Ring buffer of recent record_ids that failed sig
                // verification from this peer. Lets operators distinguish a
                // Byzantine forwarder (consistent record_ids across nodes)
                // from a verification mismatch (different record_ids per node).
                "recent_bad_sig_record_ids": p.recent_bad_sig_record_ids.iter().collect::<Vec<_>>(),
            })
        })
        .collect();
    // Deterministic order so the bounded page is a stable lowest-hash-first
    // slice across calls, not an arbitrary peer-table sample.
    peer_list.sort_by(|a, b| {
        a.get("identity_hash")
            .and_then(|v| v.as_str())
            .cmp(&b.get("identity_hash").and_then(|v| v.as_str()))
    });
    // True known-peer total captured BEFORE the page bound so `total` stays
    // honest even when the returned array is capped. `Vec::len` is O(1).
    let total = peer_list.len();
    peer_list.truncate(limit);
    serde_json::json!({"peers": peer_list, "total": total})
}

pub async fn list_peers(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<PeersQuery>,
) -> Json<serde_json::Value> {
    Json(compute_list_peers(&state, params.limit).await)
}

// ─── /metrics ────────────────────────────────────────────────────────────────

/// `?tier=p0|p1|debug` overrides the node-level default for this one
/// request. Lets an operator spot-check a debug-tier metric on a P1-defaulted
/// node without a restart. Garbage values silently fall back to the node default.
///
/// The override is loopback-scoped: a non-loopback caller (the public
/// `0.0.0.0` listener) may only *downgrade* the surface, never escalate above
/// the node's configured tier — otherwise any anonymous internet client could
/// force `?tier=debug` and scrape the full per-device hardware fingerprint
/// (per-core CPU freq, hwmon/thermal temps, per-disk IO, per-NIC counters).
pub async fn metrics(
    State(state): State<Arc<NodeState>>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let requested = params
        .get("tier")
        .and_then(|s| super::super::server::MetricTier::parse(s));
    let tier_override = super::super::server::clamp_public_metric_tier(
        super::super::server::ip_is_loopback_canonical(connect_info.0.ip()),
        requested,
        super::super::server::current_metric_tier(),
    );
    super::super::server::metrics_handler_tiered(state, tier_override).await
}

// ─── /node/identity ──────────────────────────────────────────────────────────

pub(crate) fn compute_node_identity_payload(state: &NodeState) -> serde_json::Value {
    let is_genesis = state.identity.identity_hash == state.config.genesis_authority;

    serde_json::json!({
        "identity_hash": state.identity.identity_hash,
        "entity_type": format!("{:?}", state.identity.entity_type),
        "crypto_profile": format!("{:?}", state.identity.profile),
        "algorithm": state.identity.algorithm,
        "has_pow": state.identity.pow_difficulty > 0,
        "pow_difficulty": state.identity.pow_difficulty,
        "node_type": state.config.node_type,
        "is_genesis_authority": is_genesis,
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": crate::network::config::PROTOCOL_VERSION,
    })
}

pub async fn node_identity(
    State(state): State<Arc<NodeState>>,
) -> Json<serde_json::Value> {
    Json(compute_node_identity_payload(&state))
}

// ─── /node/config ────────────────────────────────────────────────────────────

pub async fn node_config(
    State(state): State<Arc<NodeState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "listen_addr": state.config.listen_addr,
        "node_type": state.config.node_type,
        "genesis_authority": &state.config.genesis_authority[..state.config.genesis_authority.len().min(16)],
        "seed_peers_count": state.config.seed_peers.len(),
        "dns_seeds": state.config.dns_seeds,
        "gossip_pull_interval_secs": state.config.gossip_pull_interval_secs,
        "gossip_max_hops": state.config.gossip_max_hops,
        "auto_witness": state.config.auto_witness,
        "auto_witness_interval_secs": state.config.auto_witness_interval_secs,
        "auto_witness_batch_size": state.config.auto_witness_batch_size,
        "epoch_seal_interval_secs": state.config.epoch_seal_interval_secs,
        "snapshot_interval_secs": state.config.snapshot_interval_secs,
        "max_peer_failures": state.config.max_peer_failures,
        "pex_interval_secs": state.config.pex_interval_secs,
        "rate_limit_read": state.config.rate_limit_read,
        "rate_limit_write": state.config.rate_limit_write,
        "witness_reward_micros": state.config.witness_reward_micros,
        "light_mode": state.config.light_mode,
    }))
}

// ─── /gossip ─────────────────────────────────────────────────────────────────

pub async fn gossip_health(
    State(state): State<Arc<NodeState>>,
) -> Json<serde_json::Value> {
    use std::sync::atomic::Ordering::Relaxed;

    let push_total = state.gossip_push_total.load(Relaxed);
    let push_content_routed = state.gossip_push_content_routed_total.load(Relaxed);
    let relay_total = state.gossip_relay_total.load(Relaxed);
    let relay_content_routed = state.gossip_relay_content_routed_total.load(Relaxed);
    let relay_committee_routed = state.gossip_relay_committee_routed_total.load(Relaxed);
    let snapshot_bootstrap_epoch_indexed = state.snapshot_bootstrap_epoch_indexed_total.load(Relaxed);
    let pull_total = state.gossip_pull_total.load(Relaxed);
    let bytes_out = state.gossip_bytes_out_total.load(Relaxed);
    let bytes_in = state.gossip_bytes_in_total.load(Relaxed);
    let push_skipped = state.gossip_push_skipped_total.load(Relaxed);
    let seen_dedup = state.gossip_seen_dedup_total.load(Relaxed);
    let push_failed = state.gossip_push_failed_total.load(Relaxed);
    let retry_total = state.gossip_retry_total.load(Relaxed);
    let retry_success = state.gossip_retry_success_total.load(Relaxed);
    let att_dedup = state.attestation_dedup_total.load(Relaxed);
    let uptime = state.uptime();

    let minutes = (uptime / 60.0).max(1.0);
    let push_rate = push_total as f64 / minutes;
    let pull_rate = pull_total as f64 / minutes;
    // MAINNET gap #8 (floor-push): average egress/ingress bytes per second,
    // computed over node uptime. Gives a quick curl+jq answer to "what's the
    // seal-traffic cost right now?" without pulling + diffing /metrics.
    let seconds = uptime.max(1.0);
    let bytes_out_per_sec = (bytes_out as f64 / seconds).round() as u64;
    let bytes_in_per_sec = (bytes_in as f64 / seconds).round() as u64;

    let seen_count = state.seen.lock_recover().len();
    let att_seen_count = state.attestation_seen.lock_recover().len();
    let att_bad_sig_count = state.attestation_bad_sigs.lock_recover().len();
    let rejected_count = state.gossip_rejected.lock_recover().len();
    let rejected_dedup = state.gossip_rejected_dedup_total.load(Relaxed);

    Json(serde_json::json!({
        "push_total": push_total,
        "push_content_routed_total": push_content_routed,
        "relay_total": relay_total,
        "relay_content_routed_total": relay_content_routed,
        "relay_committee_routed_total": relay_committee_routed,
        "snapshot_bootstrap_epoch_indexed_total": snapshot_bootstrap_epoch_indexed,
        "pull_total": pull_total,
        "bytes_out_total": bytes_out,
        "bytes_in_total": bytes_in,
        "bytes_out_per_sec_avg": bytes_out_per_sec,
        "bytes_in_per_sec_avg": bytes_in_per_sec,
        "push_skipped_total": push_skipped,
        "seen_dedup_total": seen_dedup,
        "push_failed_total": push_failed,
        "retry_total": retry_total,
        "retry_success_total": retry_success,
        "attestation_dedup_total": att_dedup,
        "push_rate_per_min": (push_rate * 100.0).round() / 100.0,
        "pull_rate_per_min": (pull_rate * 100.0).round() / 100.0,
        "effective_hops": state.effective_max_hops(),
        "config_max_hops": state.config.gossip_max_hops,
        "pull_interval_secs": state.config.gossip_pull_interval_secs,
        "seen_set_size": seen_count,
        "attestation_seen_set_size": att_seen_count,
        "attestation_bad_sig_cache_size": att_bad_sig_count,
        "gossip_rejected_cache_size": rejected_count,
        "gossip_rejected_dedup_total": rejected_dedup,
        "uptime_seconds": (uptime * 100.0).round() / 100.0,
    }))
}

// ─── /limits ─────────────────────────────────────────────────────────────────

pub async fn protocol_limits() -> Json<serde_json::Value> {
    Json(crate::accounting::limits::all_limits())
}

// ─── /dht/find_node ──────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct DhtQuery {
    target: Option<String>,
    count: Option<usize>,
}

pub async fn dht_find_node(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<DhtQuery>,
) -> Json<serde_json::Value> {
    use crate::network::dht::NodeId;

    let count = params.count.unwrap_or(8).min(20);
    let dht = state.dht.lock_recover();

    let target = params
        .target
        .as_deref()
        .and_then(NodeId::from_hex)
        .unwrap_or(*dht.local_id());

    let closest: Vec<serde_json::Value> = dht
        .closest(&target, count)
        .iter()
        .map(|p| {
            serde_json::json!({
                "identity_hash": p.identity_hash,
                "host": p.host,
                "port": p.port,
                "last_seen": p.last_seen,
            })
        })
        .collect();

    Json(serde_json::json!({
        "target": target.to_hex(),
        "peers": closest,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Loopback `ConnectInfo` for `status()` handler tests — exercises the
    /// full (un-gated) node dashboard, so the field-existence pins below see
    /// the host-fingerprint block. Non-loopback gating is pinned separately by
    /// `status_withholds_host_fingerprint_from_non_loopback`.
    fn lo_ci() -> axum::extract::ConnectInfo<std::net::SocketAddr> {
        axum::extract::ConnectInfo("127.0.0.1:0".parse().unwrap())
    }

    #[tokio::test]
    async fn version_handler_returns_required_fields() {
        let resp = version(lo_ci()).await;
        let v = &resp.0;
        assert!(v.get("version").and_then(|x| x.as_str()).is_some(), "version field missing");
        assert!(v.get("protocol_version").is_some(), "protocol_version missing");
        assert!(v.get("git_sha").and_then(|x| x.as_str()).is_some(), "git_sha missing");
        assert!(v.get("git_ref").and_then(|x| x.as_str()).is_some(), "git_ref missing");
        assert!(v.get("git_dirty").and_then(|x| x.as_bool()).is_some(), "git_dirty missing");
        assert!(v.get("build_ts_secs").and_then(|x| x.as_u64()).is_some(), "build_ts_secs missing");
    }

    #[tokio::test]
    async fn version_matches_cargo_pkg_version() {
        let resp = version(lo_ci()).await;
        let v = &resp.0;
        assert_eq!(
            v.get("version").and_then(|x| x.as_str()),
            Some(env!("CARGO_PKG_VERSION")),
        );
    }

    #[tokio::test]
    async fn version_git_sha_is_either_unknown_or_full_40_hex() {
        let resp = version(lo_ci()).await;
        let sha = resp.0.get("git_sha").and_then(|x| x.as_str()).unwrap();
        assert!(
            sha == "unknown" || (sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit())),
            "git_sha not 'unknown' nor 40-char hex: {sha:?}",
        );
    }

    #[tokio::test]
    async fn version_build_ts_is_non_zero_when_built_via_build_rs() {
        // build.rs always sets BUILD_TS_SECS; if it's 0 either build.rs failed
        // to register the env var or the package was built without re-running.
        let resp = version(lo_ci()).await;
        let ts = resp.0.get("build_ts_secs").and_then(|x| x.as_u64()).unwrap();
        assert!(ts > 0, "build_ts_secs is 0 — build.rs did not run");
    }

    #[tokio::test]
    async fn ping_handler_returns_pong_true_and_versions() {
        let resp = ping().await;
        let v = &resp.0;
        assert_eq!(
            v.get("pong").and_then(|x| x.as_bool()),
            Some(true),
            "pong field must be true",
        );
        assert_eq!(
            v.get("version").and_then(|x| x.as_str()),
            Some(env!("CARGO_PKG_VERSION")),
            "version must match Cargo.toml",
        );
        assert_eq!(
            v.get("protocol_version").and_then(|x| x.as_u64()),
            Some(crate::network::config::PROTOCOL_VERSION as u64),
            "protocol_version must match the const",
        );
    }

    #[tokio::test]
    async fn protocol_limits_returns_required_keys() {
        // All limit keys consumed by account, explorer, and operator-tooling
        // must be present — account velocity caps and governance threshold
        // probes break silently if any of these go missing.
        let resp = protocol_limits().await;
        let v = &resp.0;
        for key in [
            "max_supply",
            "min_free_tier_per_day",
            "max_witness_fee",
            "max_slash_fraction",
            "max_unstake_cooldown_secs",
            "min_supermajority_threshold",
            "max_supermajority_threshold",
            "min_participation_fraction_floor",
            "identity_algorithm",
            "allowed_sig_algorithms",
            "max_pow_difficulty",
            "min_velocity_window_secs",
            "max_propagation_rate_per_hour",
            "min_record_retention_secs",
            "max_dormancy_threshold_secs",
            "conservation_pool_min_fraction",
            "max_epoch_seal_interval_secs",
            "min_witness_reward_micros",
            "max_witness_reward_micros",
        ] {
            assert!(v.get(key).is_some(), "protocol_limits missing key {key}");
        }
    }

    #[tokio::test]
    async fn protocol_limits_values_match_token_constants() {
        // Pin the wire shape: handler returns the same values that
        // crate::accounting::limits exposes. Drift here means a constant changed
        // in code without the wire surface tracking — account caches go stale.
        let resp = protocol_limits().await;
        let v = &resp.0;
        assert_eq!(
            v.get("max_supply").and_then(|x| x.as_u64()),
            Some(crate::accounting::limits::MAX_SUPPLY),
            "max_supply must equal accounting::limits::MAX_SUPPLY",
        );
        assert_eq!(
            v.get("identity_algorithm").and_then(|x| x.as_str()),
            Some(crate::accounting::limits::IDENTITY_ALGORITHM),
            "identity_algorithm must equal accounting::limits::IDENTITY_ALGORITHM",
        );
    }

    // `/health` must be O(1)
    // lock-free even when the node is booting (state_core not initialized,
    // RocksDB busy with replay). The cached-report path is what closes
    // the post-deploy `/health=000` saturation symptom; these tests pin
    // the warming-vs-cached contract so the handler can't regress back to
    // calling `evaluate()` synchronously.

    #[tokio::test]
    async fn compute_health_warming_when_cache_empty() {
        let state = crate::network::state::build_test_node_state();
        // Fresh NodeState has `cached_health = ArcSwapOption::empty()`.
        let v = compute_health(&state).await;
        assert_eq!(
            v.get("status").and_then(|x| x.as_str()),
            Some("warming"),
            "empty cache must return status=warming",
        );
        assert_eq!(
            v.get("readiness").and_then(|x| x.as_str()),
            Some("orange"),
            "empty cache must return readiness=orange",
        );
        assert_eq!(
            v.get("cached").and_then(|x| x.as_bool()),
            Some(false),
            "empty cache must surface cached=false",
        );
        assert!(
            v.get("checks").and_then(|x| x.as_array()).map(|a| a.is_empty()).unwrap_or(false),
            "warming response must carry empty checks (no lock-touching probes)",
        );
        assert!(
            v.get("version").and_then(|x| x.as_str()).is_some(),
            "version must always be present so deploy verification can pin build SHA",
        );
    }

    #[tokio::test]
    async fn validate_record_rejects_oversized_body_before_parse() {
        // Cross-transport parity with PQ `record_body_guard_caps_submit_and_witness_before_decode`:
        // the HTTP record-parse path must reject a body past MAX_RECORD_BYTES with a
        // `wire_format` failure BEFORE deserializing up to axum's 2 MiB default.
        let state = crate::network::state::build_test_node_state();
        let max = crate::network::ingest::MAX_RECORD_BYTES;

        // Over the cap → rejected as "too large", not a generic parse error.
        let over = compute_validate_record(&state, &vec![0u8; max + 1]).await;
        assert_eq!(over.get("valid").and_then(|v| v.as_bool()), Some(false));
        let over_err = over["checks"][0]["error"].as_str().unwrap_or("");
        assert!(
            over_err.contains("too large"),
            "over-cap body must be rejected with 'too large', got: {over_err}",
        );

        // Exactly at the cap → NOT short-circuited for size (proves `>` not `>=`,
        // matching insert_record_inner's `wire_len > MAX_RECORD_BYTES`). An all-zero
        // body still fails downstream, but never with the size-reject message.
        let at = compute_validate_record(&state, &vec![0u8; max]).await;
        assert_eq!(at.get("valid").and_then(|v| v.as_bool()), Some(false));
        let at_err = at["checks"][0]["error"].as_str().unwrap_or("");
        assert!(
            !at_err.contains("too large"),
            "at-cap body must reach the parser (not size-rejected), got: {at_err}",
        );
    }

    #[tokio::test]
    async fn compute_health_serves_cached_report_lock_free() {
        let state = crate::network::state::build_test_node_state();
        let report = crate::network::health::HealthReport {
            status: crate::network::health::CheckStatus::Warn,
            readiness: crate::network::health::ReadinessLevel::Yellow,
            checks: vec![crate::network::health::Check {
                name: "peers",
                status: crate::network::health::CheckStatus::Warn,
                message: "1 connected (min: 2)".into(),
            }],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
        };
        state.cached_health.store(Some(std::sync::Arc::new(report)));

        let v = compute_health(&state).await;
        assert_eq!(
            v.get("status").and_then(|x| x.as_str()),
            Some("degraded"),
            "cached Warn-level report must serialize status as 'degraded'",
        );
        assert_eq!(
            v.get("readiness").and_then(|x| x.as_str()),
            Some("yellow"),
            "cached readiness level must round-trip via cached path",
        );
        assert_eq!(
            v.get("cached").and_then(|x| x.as_bool()),
            Some(true),
            "populated cache must surface cached=true so monitoring can distinguish",
        );
        let checks = v.get("checks").and_then(|x| x.as_array()).expect("checks array");
        assert_eq!(checks.len(), 1, "cached checks must survive the JSON round-trip");
        assert_eq!(
            checks[0].get("name").and_then(|x| x.as_str()),
            Some("peers"),
            "cached check name must round-trip",
        );
        let age = v.get("cache_age_secs").and_then(|x| x.as_f64()).expect("cache_age_secs");
        assert!(
            (0.0..5.0).contains(&age),
            "fresh cache age must be near-zero (got {age}s) — drift here means the handler is recomputing instead of serving cache",
        );
    }

    #[tokio::test]
    async fn compute_health_cache_age_grows_with_stale_report() {
        // Pin staleness detection: a 60s-old cache must surface cache_age_secs > 50.
        // Monitoring tools rely on this field to fail-over to a fresh node when
        // the current node's health-tick has frozen.
        let state = crate::network::state::build_test_node_state();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let stale_report = crate::network::health::HealthReport {
            status: crate::network::health::CheckStatus::Ok,
            readiness: crate::network::health::ReadinessLevel::Green,
            checks: vec![],
            timestamp: now - 60.0,
        };
        state.cached_health.store(Some(std::sync::Arc::new(stale_report)));

        let v = compute_health(&state).await;
        let age = v.get("cache_age_secs").and_then(|x| x.as_f64()).expect("cache_age_secs");
        assert!(
            (55.0..75.0).contains(&age),
            "60s-old cache must surface cache_age_secs ~60 (got {age}) — staleness signal is the operator's lifeline when the background tick stalls",
        );
    }

    // Lock in the two construction paths for
    // `RecordQuery` so the programmatic (`__from_parts`) and HTTP-query-string
    // (`#[derive(serde::Deserialize)]`) routes stay interchangeable. The
    // `/records/from/{epoch}` handler converts its epoch path-param into a
    // `since` timestamp and dispatches into `query_records` via __from_parts;
    // axum's `Query<RecordQuery>` extractor feeds the same struct from the
    // wire. If those paths drift, the epoch-anchored sync endpoint silently
    // queries a different slice than the bare `/records?since=…` route.

    #[test]
    fn batch_z_record_query_from_parts_constructs_with_all_some_values() {
        // Happy path: every field carries an explicit Some(...). The
        // `/records/from/{epoch}` dispatcher uses this shape after resolving
        // the epoch → timestamp + propagating any creator/zone scope from the
        // request. The constructor must not mutate or swap fields.
        let q = RecordQuery::__from_parts(
            Some(1234.5),
            Some(50),
            Some("deadbeef".to_string()),
            Some("medical/eu".to_string()),
        );
        assert_eq!(q.since, Some(1234.5));
        assert_eq!(q.limit, Some(50));
        assert_eq!(q.creator.as_deref(), Some("deadbeef"));
        assert_eq!(q.zone.as_deref(), Some("medical/eu"));
    }

    #[test]
    fn batch_z_record_query_from_parts_preserves_none_inputs() {
        // None pass-through. `query_records` treats None as "no filter":
        // since=None → 0.0, limit=None → 100 (capped at 1000), creator=None
        // → zone-blind, zone=None → global scan. If __from_parts silently
        // substituted defaults here, `/records/from/{epoch}` would dispatch
        // with a different effective query than the user intended.
        let q = RecordQuery::__from_parts(None, None, None, None);
        assert!(q.since.is_none(), "since must round-trip None");
        assert!(q.limit.is_none(), "limit must round-trip None");
        assert!(q.creator.is_none(), "creator must round-trip None");
        assert!(q.zone.is_none(), "zone must round-trip None");
    }

    #[test]
    fn batch_z_record_query_deserialize_via_json_matches_from_parts() {
        // Pin the contract: the `#[derive(serde::Deserialize)]` derive and
        // the programmatic `__from_parts` constructor produce field-equal
        // structs given the same logical input. This is what makes the two
        // entry points (HTTP `Query<RecordQuery>` and `/records/from/{epoch}`
        // internal dispatch) interchangeable on the responder side. The
        // zone field accepts both hierarchical paths and legacy numeric ids;
        // both shapes go through the same deserializer.
        let from_json: RecordQuery = serde_json::from_value(serde_json::json!({
            "since": 99.0,
            "limit": 7,
            "creator": "abc123",
            "zone": "medical/eu",
        }))
        .expect("RecordQuery must deserialize from JSON object with all fields");
        let from_parts = RecordQuery::__from_parts(
            Some(99.0),
            Some(7),
            Some("abc123".to_string()),
            Some("medical/eu".to_string()),
        );
        assert_eq!(from_json.since, from_parts.since);
        assert_eq!(from_json.limit, from_parts.limit);
        assert_eq!(from_json.creator, from_parts.creator);
        assert_eq!(from_json.zone, from_parts.zone);

        // Empty object → all None (Option<T> defaults to None for missing
        // keys under serde). This is the path axum takes when the client
        // calls `/records` with no query string at all.
        let empty: RecordQuery = serde_json::from_value(serde_json::json!({}))
            .expect("RecordQuery must deserialize from empty object");
        assert!(empty.since.is_none());
        assert!(empty.limit.is_none());
        assert!(empty.creator.is_none());
        assert!(empty.zone.is_none());
    }

    // ─── Lock in the read-only state-introspection
    // endpoints. `/node/identity`, `/node/config`, `/peers`, `/gossip` and
    // `/dht/find_node` are operator surface — account bootstrap, ops scripts,
    // canary monitoring and the explorer SPA all key on field shapes here.
    // A silent drop or rename in the JSON response (e.g. removing
    // `protocol_version` from `/node/identity`) breaks deploy verification
    // and cluster-axis monitoring without surfacing in the type-checker.
    // These tests pin the JSON contracts so a future cleanup pass can't
    // delete a field without flipping a test red.

    #[tokio::test]
    async fn node_identity_returns_required_fields_on_test_state() {
        let state = crate::network::state::build_test_node_state();
        let resp = node_identity(State(state.clone())).await;
        let v = &resp.0;
        // Every field the ops dashboard + deploy verification script consumes.
        for key in [
            "identity_hash",
            "entity_type",
            "crypto_profile",
            "algorithm",
            "has_pow",
            "pow_difficulty",
            "node_type",
            "is_genesis_authority",
            "version",
            "protocol_version",
        ] {
            assert!(
                v.get(key).is_some(),
                "/node/identity must surface `{key}` — operators script against this field",
            );
        }
        // identity_hash from Identity::generate is SHA3-256-hex over the
        // Dilithium3 public key → 64 hex chars. A silent change to a shorter
        // hash here breaks every peer-pinning script in ops/.
        let h = v.get("identity_hash").and_then(|x| x.as_str()).unwrap();
        assert_eq!(h.len(), 64, "identity_hash must be 64-hex SHA3-256");
        // Test state uses CryptoProfile::ProfileB → algorithm "dilithium3"
        // (SPHINCS+ only attached on ProfileA). Pinning this prevents an
        // accidental swap of the test fixture's profile.
        assert_eq!(v.get("algorithm").and_then(|x| x.as_str()), Some("dilithium3"));
        assert_eq!(v.get("crypto_profile").and_then(|x| x.as_str()), Some("ProfileB"));
        assert_eq!(v.get("entity_type").and_then(|x| x.as_str()), Some("Device"));
        // Test fixture sets `min_pow_difficulty: 0` and Identity::generate
        // (non-PoW variant) starts at difficulty 0 → has_pow=false.
        assert_eq!(v.get("has_pow").and_then(|x| x.as_bool()), Some(false));
        assert_eq!(v.get("pow_difficulty").and_then(|x| x.as_u64()), Some(0));
        // Protocol version pin — bump deliberately, not by accident.
        assert_eq!(
            v.get("protocol_version").and_then(|x| x.as_u64()),
            Some(crate::network::config::PROTOCOL_VERSION as u64),
        );
        assert_eq!(
            v.get("version").and_then(|x| x.as_str()),
            Some(env!("CARGO_PKG_VERSION")),
        );
    }

    #[tokio::test]
    async fn node_identity_is_genesis_authority_false_when_identity_differs() {
        // A freshly-generated test identity has a random hash that will not
        // match TESTNET_GENESIS_AUTHORITY. The `is_genesis_authority` flag
        // gates downstream behavior (single-anchor cap, committee bias under
        // Phase 6b — only the genesis authority signs canonical seals). False-positive
        // here would let a non-authority node sign canonical seals.
        let state = crate::network::state::build_test_node_state();
        assert_ne!(
            state.identity.identity_hash,
            state.config.genesis_authority,
            "test fixture must not accidentally generate the genesis hash",
        );
        let v = node_identity(State(state.clone())).await.0;
        assert_eq!(
            v.get("is_genesis_authority").and_then(|x| x.as_bool()),
            Some(false),
            "non-authority identity must surface is_genesis_authority=false",
        );
    }

    #[tokio::test]
    async fn node_config_returns_required_fields_on_test_state() {
        let state = crate::network::state::build_test_node_state();
        let v = node_config(State(state.clone())).await.0;
        // Pin every field the internal design notes operator-onramp + cluster-monitor
        // tooling key on. Drop one here and the docker-compose snippet drifts
        // from the actual node-config shape silently.
        for key in [
            "listen_addr",
            "node_type",
            "genesis_authority",
            "seed_peers_count",
            "dns_seeds",
            "gossip_pull_interval_secs",
            "gossip_max_hops",
            "auto_witness",
            "auto_witness_interval_secs",
            "auto_witness_batch_size",
            "epoch_seal_interval_secs",
            "snapshot_interval_secs",
            "max_peer_failures",
            "pex_interval_secs",
            "rate_limit_read",
            "rate_limit_write",
            "witness_reward_micros",
            "light_mode",
        ] {
            assert!(
                v.get(key).is_some(),
                "/node/config must surface `{key}` — operator-onramp keys on it",
            );
        }
        // genesis_authority is truncated to the first 16 chars in the response
        // (privacy + UI brevity); the full hash lives in the config but never
        // hits the wire. Pin the truncation contract.
        let ga = v.get("genesis_authority").and_then(|x| x.as_str()).unwrap();
        assert_eq!(
            ga.len(),
            16,
            "genesis_authority must be truncated to 16 hex chars in /node/config — full hash stays internal",
        );
        // Defaults from NodeConfig::default that downstream tooling assumes:
        // node_type="witness", auto_witness=true, gossip_max_hops=6,
        // epoch_seal_interval_secs=60. A silent change to any of these is a
        // protocol-level behavior change that must be deliberate.
        assert_eq!(v.get("node_type").and_then(|x| x.as_str()), Some("witness"));
        assert_eq!(v.get("auto_witness").and_then(|x| x.as_bool()), Some(true));
        assert_eq!(v.get("gossip_max_hops").and_then(|x| x.as_u64()), Some(6));
        assert_eq!(v.get("epoch_seal_interval_secs").and_then(|x| x.as_u64()), Some(60));
        assert_eq!(v.get("light_mode").and_then(|x| x.as_bool()), Some(false));
    }

    #[tokio::test]
    async fn compute_list_peers_returns_empty_for_fresh_state() {
        // Fresh NodeState has no peers in the PeerTable. The "peers" array
        // in the response must round-trip as an empty JSON array (NOT null,
        // NOT a missing field, NOT absent) so the explorer SPA and
        // `curl /peers | jq '.peers | length'` ops scripts work identically
        // for a brand-new node and a stuck-with-zero-peers node.
        let state = crate::network::state::build_test_node_state();
        let v = compute_list_peers(&state, None).await;
        let arr = v
            .get("peers")
            .and_then(|x| x.as_array())
            .expect("/peers must surface `peers` as a JSON array, never null");
        assert!(
            arr.is_empty(),
            "fresh NodeState must list zero peers (PeerTable starts empty)",
        );
        // Self-filter pin: the handler explicitly excludes the local identity
        // from the peer list. If the filter is dropped, the local node would
        // appear in its own /peers output and confuse peer-count health checks.
        // The test reaches
        // through the same code path with an empty table to ensure the filter
        // doesn't accidentally panic on the no-self-known branch.
        assert_eq!(arr.len(), 0);
    }

    #[tokio::test]
    async fn gossip_health_returns_zero_counters_on_fresh_state() {
        // Every counter exposed by `/gossip` lives behind an AtomicU64 and
        // initializes to 0. The handler is read-only; a fresh NodeState must
        // return all zeros without panicking on the SeenSet locks or the
        // uptime calculation. Pin this so a future refactor that adds a new
        // metric forgets neither the JSON shape nor the zero-init invariant.
        let state = crate::network::state::build_test_node_state();
        let v = gossip_health(State(state.clone())).await.0;
        for counter_key in [
            "push_total",
            "push_content_routed_total",
            "relay_total",
            "relay_content_routed_total",
            "relay_committee_routed_total",
            "snapshot_bootstrap_epoch_indexed_total",
            "pull_total",
            "bytes_out_total",
            "bytes_in_total",
            "push_skipped_total",
            "seen_dedup_total",
            "push_failed_total",
            "retry_total",
            "retry_success_total",
            "attestation_dedup_total",
            "gossip_rejected_dedup_total",
        ] {
            assert_eq!(
                v.get(counter_key).and_then(|x| x.as_u64()),
                Some(0),
                "/gossip `{counter_key}` must initialize to 0 on fresh NodeState",
            );
        }
        // Config-derived passthroughs must surface their NodeConfig::default
        // values exactly. A silent default-shift here is a behavior change
        // even if no counter ticks.
        assert_eq!(
            v.get("config_max_hops").and_then(|x| x.as_u64()),
            Some(6),
            "config_max_hops must match NodeConfig::default.gossip_max_hops",
        );
        assert_eq!(
            v.get("pull_interval_secs").and_then(|x| x.as_u64()),
            Some(30),
            "pull_interval_secs must match NodeConfig::default.gossip_pull_interval_secs",
        );
        // SeenSet sizes must round-trip as 0 even though the field is gated
        // behind a Mutex. Locks held during /gossip serve must remain quick
        // enough to scrape on every cluster tick.
        for set_key in [
            "seen_set_size",
            "attestation_seen_set_size",
            "attestation_bad_sig_cache_size",
            "gossip_rejected_cache_size",
        ] {
            assert_eq!(
                v.get(set_key).and_then(|x| x.as_u64()),
                Some(0),
                "/gossip `{set_key}` must surface 0 on fresh NodeState (SeenSet empty)",
            );
        }
    }

    #[tokio::test]
    async fn dht_find_node_returns_empty_peers_on_fresh_state() {
        // RoutingTable on a fresh NodeState has zero peers inserted (only
        // local_id is recorded). `closest()` returns an empty Vec; the
        // handler must surface `peers: []` and a `target` echoed back from
        // either the explicit query-string `target` or the local_id when
        // no target is provided. Pin both branches so a regression in
        // NodeId::from_hex or the local_id fallback can't go undetected.
        let state = crate::network::state::build_test_node_state();

        // Branch 1: no target → handler defaults to local_id.
        let q = DhtQuery { target: None, count: Some(5) };
        let v = dht_find_node(State(state.clone()), Query(q)).await.0;
        let target_hex = v.get("target").and_then(|x| x.as_str()).unwrap();
        assert_eq!(
            target_hex.len(),
            64,
            "NodeId hex is 32 bytes / 64 chars; default-target path must echo local_id of that shape",
        );
        let arr = v
            .get("peers")
            .and_then(|x| x.as_array())
            .expect("/dht/find_node must surface `peers` as a JSON array");
        assert!(
            arr.is_empty(),
            "fresh RoutingTable must return zero peers from closest()",
        );

        // Branch 2: explicit target hex. NodeId::from_hex must round-trip;
        // an invalid target also falls back to local_id (covered by the
        // `unwrap_or(*dht.local_id())` line) so the handler is panic-free
        // on arbitrary input from the wire.
        let q2 = DhtQuery {
            target: Some("00".repeat(32)),
            count: Some(3),
        };
        let v2 = dht_find_node(State(state.clone()), Query(q2)).await.0;
        assert_eq!(
            v2.get("target").and_then(|x| x.as_str()),
            Some("00".repeat(32).as_str()),
            "explicit valid target hex must echo back unchanged",
        );
        assert_eq!(
            v2.get("peers").and_then(|x| x.as_array()).unwrap().len(),
            0,
            "empty RoutingTable returns no closest peers regardless of target",
        );

        // Branch 3: count cap. The handler clamps `count` at 20; a request
        // for 9999 must not allocate a 9999-sized vec, and must still
        // return successfully with an empty payload on an empty table.
        let q3 = DhtQuery {
            target: None,
            count: Some(9999),
        };
        let v3 = dht_find_node(State(state.clone()), Query(q3)).await.0;
        assert_eq!(
            v3.get("peers").and_then(|x| x.as_array()).unwrap().len(),
            0,
            "count-clamp branch must remain panic-free + return empty for empty table",
        );
    }

    // ─── /gossip orthogonal axes beyond the
    // existing fresh-state-zero-counters pin (`gossip_health_returns_zero_…`).
    // Fresh-state has ONE test, but the three load-bearing axes
    // it does NOT pin are (1) atomic-counter-tick propagation to JSON, (2)
    // rate-calc uptime-clamp when uptime < 60s (the `.max(1.0)` clamp in both
    // the per-minute and per-second branches), and (3) effective_hops surfacing
    // the live `effective_max_hops()` result rather than the raw config value.
    // A refactor that swaps `as_u64`/`as_f64` reads, drops the clamp, or
    // accidentally surfaces `config.gossip_max_hops` in the `effective_hops`
    // field would slip past the fresh-state-zero pin (because zero divided by
    // anything is still zero). Pin all three here.

    #[tokio::test]
    async fn batch_ccccc_gossip_health_atomic_counter_tick_surfaces_in_json() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = crate::network::state::build_test_node_state();

        // Tick three orthogonal counters: a content-routing counter
        // (push_content_routed_total — gap-6 observability),
        // a bytes-counter (gossip_bytes_in_total — gap-8 floor-push), and
        // a dedup-counter (seen_dedup_total — sybil-suppression efficiency).
        // Three different categories defend against a refactor that, e.g.,
        // moves only one family of counters off the JSON envelope while
        // leaving the rest visible.
        state.gossip_push_content_routed_total.store(7, Relaxed);
        state.gossip_bytes_in_total.store(123_456, Relaxed);
        state.gossip_seen_dedup_total.store(42, Relaxed);

        let v = gossip_health(State(state.clone())).await.0;
        assert_eq!(
            v.get("push_content_routed_total").and_then(|x| x.as_u64()),
            Some(7),
            "push_content_routed_total tick must surface unchanged (OPS-118 gate)",
        );
        assert_eq!(
            v.get("bytes_in_total").and_then(|x| x.as_u64()),
            Some(123_456),
            "bytes_in_total tick must surface unchanged (gap-8 egress audit)",
        );
        assert_eq!(
            v.get("seen_dedup_total").and_then(|x| x.as_u64()),
            Some(42),
            "seen_dedup_total tick must surface unchanged (sybil-suppression gauge)",
        );
    }

    #[tokio::test]
    async fn batch_ccccc_gossip_health_rate_calcs_clamp_uptime_minute_floor_at_one() {
        use std::sync::atomic::Ordering::Relaxed;
        // build_test_node_state() creates a NodeState whose `start_time` is
        // `SystemTime::now()` at construction. Within the same tokio test
        // tick, `uptime()` returns a value well below 60s — without the
        // `(uptime / 60.0).max(1.0)` clamp the per-minute rate would either
        // explode (divide-by-tiny) or stay zero (integer-divide truncation).
        // Pre-tick push_total to a non-trivial value and assert the rate
        // surfaced is EXACTLY push_total (= rate / 1.0 minute floor).
        // Symmetrically pin bytes_out_per_sec_avg against `seconds.max(1.0)`.
        let state = crate::network::state::build_test_node_state();
        state.gossip_push_total.store(60, Relaxed);
        state.gossip_pull_total.store(30, Relaxed);
        state.gossip_bytes_out_total.store(1_000, Relaxed);

        let v = gossip_health(State(state.clone())).await.0;

        // Per-minute rates: the clamp forces `minutes >= 1.0`, so on a
        // sub-second-old NodeState the rate equals the raw count.
        assert_eq!(
            v.get("push_rate_per_min").and_then(|x| x.as_f64()),
            Some(60.0),
            "push_rate_per_min must equal push_total when uptime < 60s (minute-floor clamp)",
        );
        assert_eq!(
            v.get("pull_rate_per_min").and_then(|x| x.as_f64()),
            Some(30.0),
            "pull_rate_per_min must equal pull_total when uptime < 60s (minute-floor clamp)",
        );

        // Per-second bytes average: `seconds.max(1.0)` floors the divisor,
        // so for a fresh node `bytes_out_per_sec_avg == bytes_out_total` as
        // a u64 round. Without the clamp this would be inf or NaN.
        assert_eq!(
            v.get("bytes_out_per_sec_avg").and_then(|x| x.as_u64()),
            Some(1_000),
            "bytes_out_per_sec_avg must equal bytes_out_total when uptime < 1s (seconds-floor clamp)",
        );
    }

    #[tokio::test]
    async fn batch_ccccc_gossip_health_effective_hops_reflects_adaptive_floor_not_config_max() {
        // Pin: `effective_hops` in the JSON envelope is the LIVE result of
        // `state.effective_max_hops()`, NOT a passthrough of
        // `config.gossip_max_hops`. On an empty DHT (no peers inserted)
        // the adaptive formula floors at 2 (peer_count=1 → log2(1)=0 → +2 = 2)
        // while `config_max_hops` stays at the default 6. A refactor that
        // accidentally surfaces the config value in the effective field
        // would silently disable the small-network bandwidth optimization
        // and over-flood at 6-hop horizon on a 6-node testnet. Both keys
        // are present so we explicitly assert they DIFFER.
        let state = crate::network::state::build_test_node_state();
        let v = gossip_health(State(state.clone())).await.0;

        assert_eq!(
            v.get("effective_hops").and_then(|x| x.as_u64()),
            Some(2),
            "effective_hops must floor at 2 on empty DHT (adaptive formula, NOT config_max_hops passthrough)",
        );
        assert_eq!(
            v.get("config_max_hops").and_then(|x| x.as_u64()),
            Some(6),
            "config_max_hops must surface NodeConfig::default.gossip_max_hops (=6) unchanged",
        );
        // Belt-and-braces: explicit inequality between the two fields. If
        // a refactor reduces both fields to the same source the inequality
        // breaks; that's the load-bearing distinction this test guards.
        assert_ne!(
            v.get("effective_hops").and_then(|x| x.as_u64()),
            v.get("config_max_hops").and_then(|x| x.as_u64()),
            "effective_hops MUST diverge from config_max_hops on empty DHT (adaptive ≠ ceiling)",
        );
    }

    // Pin the /status JSON contract that the operator audit tooling
    // depends on. The audit rule
    // grep-greps four specific keys (`node_type`, `identity_hash`,
    // `genesis_authority`, `ledger_accounts`) on /status to differentiate
    // anchor-vs-witness configurations and detect the genesis-authority node
    // via `identity_hash == genesis_authority`. A future refactor that drops,
    // renames, or reshapes any of these keys would silently break the audit
    // tooling — and the jq-null-on-missing-key trap (memory addendum) means
    // the breakage wouldn't surface as a runtime error, just as a permanent
    // wrong-classification. These tests catch the regression at CI gate.

    #[tokio::test]
    async fn batch_481_status_surfaces_required_audit_rule_keys() {
        // PIN: the four keys the audit rule grep-greps on /status
        // MUST be present on every node. A refactor that drops or renames
        // any of them silently breaks the operator audit tooling embedded
        // in scripts/fleet-probe.sh v5 (commit `6bf359b8`). Pin the
        // entire required-key set with explicit existence assertions.
        let state = crate::network::state::build_test_node_state();
        let v = status(State(state.clone()), lo_ci()).await.0;
        for required in [
            // Audit-rule grep targets (the four-key triad + accts).
            "node_type",
            "identity_hash",
            "genesis_authority",
            "ledger_accounts",
            // Chain-tip lockstep indicators (fleet-probe v4 columns).
            "latest_seal_anchor",
            "current_epoch",
            "total_ever_finalized",
            // Auto-witness skip-path differentiator.
            "ledger_staked",
            // Network-presence indicators consumed by the v5 probe.
            "peers_connected",
            "peers_total",
            "uptime_secs",
        ] {
            assert!(
                v.get(required).is_some(),
                "/status must surface `{required}` — §439-§481 audit-rule tooling greps on it; a missing key would silently break the audit-tick classification"
            );
        }
    }

    #[tokio::test]
    async fn batch_481_status_identity_hash_is_64_hex_chars_full_not_truncated() {
        // PIN: the audit rule does `identity_hash[:8]` truncation FOR
        // DISPLAY but the underlying field MUST be the full 64-hex SHA3-256
        // hash (matches `/node/identity` contract). A truncation regression
        // (e.g. /status returning 16-hex like /node/config does for
        // `genesis_authority`) would make the audit rule's `identity_hash ==
        // genesis_authority` comparison FALSE-NEGATIVE permanently — every
        // genesis-authority node would appear as a non-authority, silently
        // resurrecting the genesis-authority misidentification pathology.
        let state = crate::network::state::build_test_node_state();
        let v = status(State(state.clone()), lo_ci()).await.0;
        let id_hash = v.get("identity_hash").and_then(|x| x.as_str()).unwrap();
        assert_eq!(
            id_hash.len(),
            64,
            "identity_hash on /status MUST be full 64-hex SHA3-256 (NOT truncated like /node/config's genesis_authority); audit-rule compares against genesis_authority"
        );
        assert!(
            id_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "identity_hash MUST be pure lowercase hex"
        );
    }

    #[tokio::test]
    async fn batch_481_status_genesis_authority_full_hash_matches_identity_hash_format() {
        // PIN: the audit rule's load-bearing comparison is
        // `identity_hash == genesis_authority` (string-equality on the
        // two top-level /status fields). For this comparison to work BOTH
        // fields MUST be the same format (both full-hex, not one full and
        // one truncated). /node/config's `genesis_authority` is truncated
        // to 16 chars (line 1808-1812 above pins that); /status's
        // `genesis_authority` MUST NOT be truncated.
        let state = crate::network::state::build_test_node_state();
        let v = status(State(state.clone()), lo_ci()).await.0;
        let id_hash = v.get("identity_hash").and_then(|x| x.as_str()).unwrap();
        let gauth = v.get("genesis_authority").and_then(|x| x.as_str()).unwrap();
        assert_eq!(
            gauth.len(),
            id_hash.len(),
            "/status genesis_authority MUST be same length as identity_hash (both full 64-hex); a length mismatch would silently break the §439 audit-rule comparison"
        );
        assert_eq!(
            gauth.len(),
            64,
            "/status genesis_authority MUST be full 64-hex (NOT 16-hex truncation)"
        );
        assert!(
            gauth.chars().all(|c| c.is_ascii_hexdigit()),
            "/status genesis_authority MUST be pure lowercase hex"
        );
    }

    #[tokio::test]
    async fn batch_481_status_node_type_is_one_of_four_class_taxonomy_values() {
        // PIN: the four-class taxonomy (anchor / witness / leaf) keys
        // off `node_type`. A regression that introduces a new variant (or
        // renames an existing one) would break the audit-rule's class
        // assignment. Test fixture uses NodeConfig::default → "witness"
        // (verified at line 1818 above). Pin that /status surfaces it
        // verbatim AND it's in the recognized class-set.
        let state = crate::network::state::build_test_node_state();
        let v = status(State(state.clone()), lo_ci()).await.0;
        let node_type = v.get("node_type").and_then(|x| x.as_str()).unwrap();
        // Default test fixture: witness.
        assert_eq!(
            node_type, "witness",
            "test fixture node_type must be 'witness' (default in NodeConfig::default)"
        );
        // Wire contract: node_type must be one of the recognized variants
        // the four-class taxonomy maps over.
        assert!(
            ["anchor", "witness", "leaf"].contains(&node_type),
            "/status node_type must be one of {{anchor, witness, leaf}}; got '{node_type}'"
        );
    }

    #[tokio::test]
    async fn batch_481_status_latest_seal_anchor_null_on_fresh_state_pins_optional_shape() {
        // PIN: `latest_seal_anchor` on /status is the load-bearing
        // chain-tip lockstep field (all fleet nodes must converge on the
        // same `{zone, epoch, hash}` triple). On fresh test state with no
        // seal ever observed, the field MUST surface as JSON null — NOT be
        // absent (would break the field-existence audit-rule pin above)
        // and NOT default to an empty Object (would false-positive
        // "received a seal" via cluster-comparison). Pin the null-when-
        // empty shape so a refactor that swaps the `Option<JSON>` to
        // `JSON_or_default(empty_obj)` breaks loudly at CI gate.
        let state = crate::network::state::build_test_node_state();
        let v = status(State(state.clone()), lo_ci()).await.0;
        let anchor = v.get("latest_seal_anchor").expect("key must exist");
        assert!(
            anchor.is_null(),
            "/status latest_seal_anchor MUST be JSON null on fresh state (no seal observed yet); got {anchor:?}"
        );
        // Cross-check: the key IS present (audit-rule pin above caught it),
        // its VALUE is null. This is what `jq '.latest_seal_anchor'` would
        // return identically — the jq-null-on-missing-key trap (memory
        // addendum 2026-05-21) does NOT apply here because the key IS
        // surfaced; just its value is null. Pinning this distinction
        // prevents a future refactor from making the field key-absent.
        let map = v.as_object().expect("/status response is an object");
        assert!(
            map.contains_key("latest_seal_anchor"),
            "/status response object MUST contain the `latest_seal_anchor` key explicitly (even when null) — jq cannot distinguish missing-key from null-value, so the key MUST be physically present"
        );
    }

    #[tokio::test]
    async fn status_latest_seal_anchor_exposes_hash_field_when_seal_present() {
        // PIN: bench-week-offline-rejoin.sh phase-4 reads
        // `.latest_seal_anchor.hash` via jq from /status. Pin the non-null
        // shape so a refactor that drops or renames the `hash` sub-key
        // silently breaks the bench harness's state_root_match comparison.
        let state = crate::network::state::build_test_node_state();
        let zone = crate::ZoneId::new("z0");
        let hash = [0xABu8; 32];
        {
            let mut epoch = state.epoch.write().expect("epoch write");
            epoch.latest_epoch.insert(zone.clone(), 7);
            epoch.latest_seal_hash.insert(zone.clone(), hash);
        }
        let v = status(State(state), lo_ci()).await.0;
        let anchor = v.get("latest_seal_anchor").expect("latest_seal_anchor key missing");
        assert!(!anchor.is_null(), "latest_seal_anchor must be non-null after seal inserted");
        let hash_hex = anchor.get("hash").and_then(|h| h.as_str())
            .expect("latest_seal_anchor.hash must be a string");
        assert_eq!(hash_hex, "ab".repeat(32), "hash must be hex-encoded [0xAB;32]");
        assert_eq!(anchor.get("epoch").and_then(|e| e.as_u64()), Some(7));
        assert_eq!(anchor.get("zone").and_then(|z| z.as_str()), Some("z0"));
    }

    #[tokio::test]
    async fn status_current_epoch_reads_live_tip_not_stale_snapshot() {
        // REGRESSION PIN (idle-node liveness): current_epoch on /status must
        // reflect the LIVE epoch tip, not the state_core snapshot's cached copy.
        // The snapshot only refreshes on record ingest, so on an idle node its
        // current_epoch freezes while empty seals keep advancing the real tip —
        // reading it stale made /status look stalled (the field an operator or a
        // launch-week reviewer curls to check the chain is alive). Here we
        // advance the live epoch with NO ingest, so the snapshot stays at its
        // fresh-state 0, and assert /status reports the live value. Pre-fix this
        // returned 0 (stale snapshot / dag fallback).
        let state = crate::network::state::build_test_node_state();
        {
            let mut epoch = state.epoch.write().expect("epoch write");
            // zone "0" is an active zone under the default zone_count (4);
            // insert a tip far above the fresh snapshot's 0.
            epoch.latest_epoch.insert(crate::ZoneId::new("0"), 50_128);
        }
        let v = status(State(state), lo_ci()).await.0;
        assert_eq!(
            v.get("current_epoch").and_then(|e| e.as_u64()),
            Some(50_128),
            "/status current_epoch MUST read the live active-zone tip (50128), not the stale snapshot (0)"
        );
    }

    #[tokio::test]
    async fn status_withholds_host_fingerprint_from_non_loopback() {
        // The public listener serves /status to anonymous internet callers.
        // Everything in STATUS_LOOPBACK_ONLY_FIELDS is node-local state — host
        // resources (listen_addr/system_load/rss_mb/memory_pressure/disk_usage),
        // this node's operational counters (gc_pruned_total/auto_slashes_total),
        // optional higher-layer counters (continuity_identities/
        // reincarnation_*), real-time per-zone timing (zone_timing), committee
        // composition (committees), peer-bandwidth/mesh-density (peer_bandwidth),
        // and the zone subscription set (subscribed_zones) — none derivable from
        // the shared chain. A non-loopback caller MUST see every one of these keys
        // present-but-null (shape-stable for explorer clients); a regression that
        // re-exposes any of them silently leaks a deployment fingerprint. This
        // asserts over the const itself so adding a field to the gate auto-covers.
        let state = crate::network::state::build_test_node_state();
        let public_ci = axum::extract::ConnectInfo(
            "203.0.113.7:54321".parse::<std::net::SocketAddr>().unwrap(),
        );
        let v = status(State(state.clone()), public_ci).await.0;
        for withheld in STATUS_LOOPBACK_ONLY_FIELDS {
            let val = v.get(withheld).unwrap_or_else(|| {
                panic!("/status MUST keep `{withheld}` key present (null) for shape stability")
            });
            assert!(
                val.is_null(),
                "/status MUST withhold `{withheld}` (null) from a non-loopback caller — got {val:?}; node-local fingerprint leak on the public listener"
            );
        }
        // Public / shared-chain data stays surfaced to the public caller. NOTE:
        // genesis_authority stays public (inherently-public trust anchor light
        // clients pin); public_key_hex/pow_nonce stay public (discovery::bootstrap
        // parses them to build PeerInfo — gating them breaks peer discovery).
        for public_field in ["identity_hash", "genesis_authority", "public_key_hex", "pow_nonce", "current_epoch", "ledger_accounts"] {
            assert!(
                v.get(public_field).is_some_and(|x| !x.is_null()),
                "/status public field `{public_field}` must remain surfaced to non-loopback callers"
            );
        }
        // The loopback path still serves the full operator dashboard — every gated
        // field present and non-null.
        let lo = status(State(state), lo_ci()).await.0;
        for shown in STATUS_LOOPBACK_ONLY_FIELDS {
            assert!(
                lo.get(shown).is_some_and(|x| !x.is_null()),
                "loopback /status MUST still expose `{shown}` (full operator dashboard) — got {:?}",
                lo.get(shown)
            );
        }
        assert!(
            lo.get("system_load").is_some_and(|x| x.is_object()),
            "loopback /status MUST still expose the full system_load object"
        );
    }

    #[tokio::test]
    async fn status_field_set_is_fully_classified() {
        // Default-deny drift guard for the public /status surface. The non-loopback
        // gate test above only proves the KNOWN node-local fields are stripped — it
        // cannot catch a NEWLY-added field that is a host fingerprint but was never
        // added to STATUS_LOOPBACK_ONLY_FIELDS (the strip loop is a denylist). This
        // closes that drift: every key the handler emits MUST be classified as either
        // public (STATUS_PUBLIC_FIELDS) or node-local (STATUS_LOOPBACK_ONLY_FIELDS),
        // and the two sets MUST be disjoint. A new /status field fails this test until
        // it is consciously placed in one. First external-peer surface — a silent
        // fingerprint leak here is exactly the class hardened before the public join.

        // The two classification sets must be disjoint — a field can't be both
        // public and node-local-gated.
        for f in STATUS_LOOPBACK_ONLY_FIELDS {
            assert!(
                !STATUS_PUBLIC_FIELDS.contains(f),
                "`{f}` is in BOTH STATUS_PUBLIC_FIELDS and STATUS_LOOPBACK_ONLY_FIELDS — classify it once"
            );
        }

        let state = crate::network::state::build_test_node_state();
        let public_ci = axum::extract::ConnectInfo(
            "203.0.113.7:54321".parse::<std::net::SocketAddr>().unwrap(),
        );
        let v = status(State(state), public_ci).await.0;
        let obj = v.as_object().expect("/status must be a JSON object");

        for key in obj.keys() {
            let is_public = STATUS_PUBLIC_FIELDS.contains(&key.as_str());
            let is_gated = STATUS_LOOPBACK_ONLY_FIELDS.contains(&key.as_str());
            assert!(
                is_public || is_gated,
                "/status field `{key}` is UNCLASSIFIED — add it to STATUS_PUBLIC_FIELDS \
                 (safe for anonymous public callers) or STATUS_LOOPBACK_ONLY_FIELDS \
                 (node-local host fingerprint, stripped on the public listener). \
                 Default-deny: an unclassified field is a potential deployment-fingerprint leak."
            );
        }

        // Every classification-list entry must correspond to a real emitted key —
        // catches stale entries left behind when a field is renamed or removed.
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        for f in STATUS_PUBLIC_FIELDS.iter().chain(STATUS_LOOPBACK_ONLY_FIELDS.iter()) {
            assert!(
                keys.contains(f),
                "classification list names `{f}` but /status no longer emits it — remove the stale entry"
            );
        }
    }

    #[tokio::test]
    async fn version_withholds_git_identity_from_non_loopback() {
        // The live node's git sha is a private-repo commit absent from the curated
        // public mirror, and a precise build fingerprint. Non-loopback callers on
        // the public listener get version + protocol_version only; the git tuple is
        // present-but-null. Loopback keeps the full tuple (deploy verification).
        let public_ci = axum::extract::ConnectInfo(
            "203.0.113.7:54321".parse::<std::net::SocketAddr>().unwrap(),
        );
        let pub_v = version(public_ci).await.0;
        for withheld in ["git_sha", "git_ref", "git_dirty", "build_ts_secs"] {
            assert!(
                pub_v.get(withheld).is_some_and(|x| x.is_null()),
                "/version MUST withhold `{withheld}` (present-but-null) from a non-loopback caller — got {:?}",
                pub_v.get(withheld)
            );
        }
        // version + protocol_version stay public.
        assert_eq!(pub_v.get("version").and_then(|x| x.as_str()), Some(env!("CARGO_PKG_VERSION")));
        assert!(pub_v.get("protocol_version").is_some_and(|x| !x.is_null()));
        // pq_wire_version is a public protocol contract — it MUST survive the
        // non-loopback withhold (a remote joiner reads it over HTTP to check PQ-wire
        // compatibility before dialing), and it MUST be the PQ-transport handshake
        // constant, NOT the unrelated crate::wire record-format WIRE_VERSION. This
        // second assertion is the guard against the two-constants trap.
        assert!(
            pub_v.get("pq_wire_version").is_some_and(|x| !x.is_null()),
            "/version MUST expose pq_wire_version to non-loopback callers (the joiner needs it pre-dial)",
        );
        assert_eq!(
            pub_v.get("pq_wire_version").and_then(|x| x.as_u64()),
            Some(crate::network::pq_transport::WIRE_VERSION as u64),
            "pq_wire_version MUST be the PQ-transport handshake constant, not crate::wire::WIRE_VERSION",
        );
        // Loopback keeps the full build identity.
        let lo_v = version(lo_ci()).await.0;
        assert!(lo_v.get("git_sha").and_then(|x| x.as_str()).is_some(), "loopback /version MUST expose git_sha");
    }

    // ─── Pin the residual pure-handler surface that
    // the existing `ping_handler_returns_pong_true_and_versions` +
    // `protocol_limits_returns_required_keys` + `dht_find_node_returns_empty_peers_on_fresh_state`
    // tests leave uncovered. These are the cross-endpoint isolation
    // guarantees (each handler returns its own envelope without leaking
    // the others' fields) plus the wire-deserialization path on `DhtQuery`
    // (the existing test uses direct struct construction, NOT serde via JSON
    // — which is the actual axum `Query<DhtQuery>` extractor path).
    // ────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn batch_b_alive_handler_returns_only_alive_true_no_version_leak() {
        // PIN: /alive is the load-balancer fast-path probe — handler at
        // routes/core.rs:311 has the explicit doc-comment "touches no
        // NodeState internals, takes no locks, performs no I/O". Body MUST
        // be exactly `{"alive":true}` — a single key. If a future refactor
        // attaches `version` / `protocol_version` (the way /ping does), the
        // k8s livenessProbe still passes BUT the build.rs env-var read on
        // every probe tick becomes a hot path the doc explicitly forbids.
        // Pin the single-field shape against accidental cross-endpoint
        // field bleeding from /ping.
        let resp = alive().await;
        let v = &resp.0;
        assert_eq!(
            v.get("alive").and_then(|x| x.as_bool()),
            Some(true),
            "/alive must surface `alive: true` (boolean, not string)",
        );
        let map = v.as_object().expect("/alive must return a JSON object");
        assert_eq!(
            map.len(),
            1,
            "/alive envelope MUST be a single-key object — got {} keys ({:?}). Drift here means the handler grew lock-touching probes that violate the fast-path contract.",
            map.len(),
            map.keys().collect::<Vec<_>>(),
        );
        // Cross-endpoint isolation: /alive must NOT carry the fields /ping
        // and /version do — those are deployment-identity surfaces, /alive
        // is liveness only.
        for forbidden in ["pong", "version", "protocol_version", "git_sha", "git_ref"] {
            assert!(
                v.get(forbidden).is_none(),
                "/alive must NOT surface `{forbidden}` — that's /ping or /version territory; field bleeding here means the handler started touching state",
            );
        }
    }

    #[test]
    fn batch_b_dht_query_deserialize_empty_object_defaults_both_fields_to_none() {
        // PIN: the existing `dht_find_node_returns_empty_peers_on_fresh_state`
        // test constructs `DhtQuery` via the struct-literal path
        // (`DhtQuery { target: None, count: Some(5) }`) — that bypasses
        // serde entirely. The actual wire path is
        // `Query<DhtQuery>` from axum, which calls
        // `serde_urlencoded::from_str → DhtQuery`. If the derive on either
        // field changes (e.g. adding `#[serde(default)]` becomes load-bearing
        // when struct-construction tests still pass), the handler's "no
        // query string" path would silently fail at axum's extractor.
        // Pin the serde-deserialize path explicitly.
        let q: DhtQuery = serde_json::from_value(serde_json::json!({}))
            .expect("DhtQuery must deserialize from an empty object");
        assert!(q.target.is_none(), "missing `target` key must deserialize to None");
        assert!(q.count.is_none(), "missing `count` key must deserialize to None");

        // Round-trip with all-Some via JSON to pin the field NAMES (not just
        // the types). A silent rename to `peer` / `k` would fail this.
        let q2: DhtQuery = serde_json::from_value(serde_json::json!({
            "target": "00".repeat(32),
            "count": 7,
        }))
        .expect("DhtQuery must deserialize with both target and count present");
        assert_eq!(q2.target.as_deref(), Some("00".repeat(32).as_str()));
        assert_eq!(q2.count, Some(7));

        // Wrong-type rejection: `count` is `Option<usize>`, NOT `Option<String>`.
        // A wire-format relaxation that accepted `"7"` (stringified usize)
        // would change the extractor's contract. Pin the strict-typed shape.
        // (DhtQuery lacks `Debug`, so `expect_err` won't compile — match on the
        // Result directly.)
        let err = match serde_json::from_value::<DhtQuery>(serde_json::json!({
            "count": "7",
        })) {
            Ok(_) => panic!("string-typed count must reject — count is Option<usize>"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("integer") || msg.contains("usize") || msg.contains("number"),
            "DhtQuery error must call out the integer-typed expectation; got: {msg}",
        );
    }

    #[tokio::test]
    async fn batch_b_dht_find_node_invalid_target_hex_falls_back_to_local_id() {
        // PIN: routes/core.rs:1361-1365 wires
        // `params.target.as_deref().and_then(NodeId::from_hex).unwrap_or(*dht.local_id())`.
        // The existing test covers (None → local_id) and (valid hex →
        // echo back). The third branch — `Some("garbage")` where
        // `NodeId::from_hex` returns None — would silently fall back to
        // local_id via `unwrap_or`. A regression that swaps `unwrap_or`
        // for `unwrap()` on a wrong-shape input panics the handler and
        // converts a client-side typo into a 500. Pin the fallback branch.
        let state = crate::network::state::build_test_node_state();
        let local_hex = {
            let dht = state.dht.lock_recover();
            dht.local_id().to_hex()
        };

        // Branch: target is present but NOT 64-hex (NodeId::from_hex returns
        // None). The handler must NOT echo the garbage back — it must echo
        // local_id (the fallback). This is the panic-free invariant.
        let q = DhtQuery {
            target: Some("not_hex_at_all".to_string()),
            count: Some(5),
        };
        let v = dht_find_node(State(state.clone()), Query(q)).await.0;
        let target_echo = v.get("target").and_then(|x| x.as_str()).unwrap();
        assert_eq!(
            target_echo, local_hex,
            "invalid-hex target MUST fall back to local_id via unwrap_or — got {target_echo:?}, expected {local_hex:?}",
        );

        // Branch: target is a hex string of wrong length (16 chars, half a
        // node id). `NodeId::from_hex` enforces 32-byte / 64-char. Same
        // fallback applies.
        let q2 = DhtQuery {
            target: Some("deadbeef".repeat(2)),  // 16 chars — wrong length
            count: Some(3),
        };
        let v2 = dht_find_node(State(state.clone()), Query(q2)).await.0;
        assert_eq!(
            v2.get("target").and_then(|x| x.as_str()).unwrap(),
            local_hex,
            "wrong-length hex MUST also trigger the local_id fallback",
        );
    }

    #[tokio::test]
    async fn batch_b_protocol_limits_envelope_pins_governance_cap_formula_and_exact_key_count() {
        // PIN: the existing `protocol_limits_returns_required_keys` test
        // (routes/core.rs:1453) loops over 19 keys but OMITS
        // `governance_cap_formula`. That field exists at
        // accounting/limits.rs:239 — `"governance_cap_formula": GOVERNANCE_CAP_FORMULA`
        // — and is consumed by the account governance UI when computing
        // the staking-to-voting-cap ratio. A silent drop of this key
        // wouldn't trip the existing required-key loop. Pin it explicitly,
        // and pin the exact total key count so an addition or removal
        // tips a test red.
        let resp = protocol_limits().await;
        let v = &resp.0;
        // Specific key pin: governance_cap_formula is the OMITTED key in
        // the existing test's required-keys loop. Pin its presence + that
        // its value type is a string (per `GOVERNANCE_CAP_FORMULA` being
        // a const &str at accounting::limits).
        assert!(
            v.get("governance_cap_formula").and_then(|x| x.as_str()).is_some(),
            "/protocol/limits MUST surface `governance_cap_formula` as a string — the existing required-keys loop OMITS it, so this is the test that catches a silent drop",
        );

        // Exact-count pin: 20 keys per `all_limits()` at accounting/limits.rs:233.
        // Catches both accidental additions (account gets a field it doesn't
        // know about and breaks parsing in strict mode) and accidental
        // removals (consumer assumes default and ships wrong constant).
        let map = v.as_object().expect("/protocol/limits must be a JSON object");
        assert_eq!(
            map.len(),
            20,
            "/protocol/limits envelope MUST have exactly 20 keys (per accounting::limits::all_limits) — got {} ({:?}). Drift means the account's wire contract changed without coordination.",
            map.len(),
            map.keys().collect::<Vec<_>>(),
        );
    }

    #[tokio::test]
    async fn batch_b_ping_and_version_cross_endpoint_isolation_pins_field_disjointness() {
        // PIN: /ping and /version overlap on (version, protocol_version) —
        // both are deploy-identity surfaces. They DIVERGE on:
        //   - /ping is the lightweight liveness-with-versions probe and
        //     MUST NOT carry git_sha / git_ref / git_dirty / build_ts_secs
        //     (those are build-identity, not protocol-identity)
        //   - /version is the build-identity surface and MUST carry all
        //     four build fields
        //   - /ping carries `pong: true` which /version MUST NOT echo
        // Cross-endpoint field bleeding (a refactor that consolidates the
        // two handlers) would defeat the deploy-verification choreography
        // in scripts/claude-heartbeat.sh which calls both endpoints.
        let p = ping().await.0;
        let vsn = version(lo_ci()).await.0;

        // Overlap: both carry (version, protocol_version).
        assert_eq!(
            p.get("version").and_then(|x| x.as_str()),
            vsn.get("version").and_then(|x| x.as_str()),
            "/ping and /version MUST report the same `version` (CARGO_PKG_VERSION)",
        );
        assert_eq!(
            p.get("protocol_version").and_then(|x| x.as_u64()),
            vsn.get("protocol_version").and_then(|x| x.as_u64()),
            "/ping and /version MUST report the same `protocol_version`",
        );

        // Divergence direction 1: /ping carries `pong`, /version does NOT.
        assert_eq!(
            p.get("pong").and_then(|x| x.as_bool()),
            Some(true),
            "/ping MUST carry pong:true",
        );
        assert!(
            vsn.get("pong").is_none(),
            "/version MUST NOT carry pong (build-identity surface, not liveness)",
        );

        // Divergence direction 2: /version carries build-identity fields,
        // /ping does NOT. A refactor that merges the two would leak
        // build SHAs onto every health-probe tick.
        for build_field in ["git_sha", "git_ref", "git_dirty", "build_ts_secs"] {
            assert!(
                vsn.get(build_field).is_some(),
                "/version MUST carry `{build_field}`",
            );
            assert!(
                p.get(build_field).is_none(),
                "/ping MUST NOT carry `{build_field}` — that's /version territory; field bleeding here means the lightweight probe started reading build.rs env vars",
            );
        }

        // Exact-count pin on both envelopes: /ping=3, /version=7.
        let pmap = p.as_object().expect("/ping is an object");
        let vmap = vsn.as_object().expect("/version is an object");
        assert_eq!(
            pmap.len(),
            3,
            "/ping envelope MUST be exactly 3 keys (pong, version, protocol_version) — got {} ({:?})",
            pmap.len(),
            pmap.keys().collect::<Vec<_>>(),
        );
        assert_eq!(
            vmap.len(),
            7,
            "/version envelope MUST be exactly 7 keys (version, protocol_version, pq_wire_version + the 4 build fields) — got {} ({:?})",
            vmap.len(),
            vmap.keys().collect::<Vec<_>>(),
        );
        // pq_wire_version is protocol-identity (kept for all callers), NOT a /ping field.
        assert!(
            vsn.get("pq_wire_version").is_some(),
            "/version MUST carry pq_wire_version (PQ-wire compatibility contract)",
        );
        assert!(
            p.get("pq_wire_version").is_none(),
            "/ping MUST NOT carry pq_wire_version — keep the liveness probe at 3 keys",
        );
    }

    // ─── compute_validate_record orthogonal pins ─────────
    // `compute_validate_record` (the pure helper
    // at routes/core.rs:934 behind `/validate`) was the LARGEST un-pinned
    // `compute_*` helper in this file after the explorer
    // + token sweeps. It emits a structured JSON envelope
    // of validation checks and is documented as NEVER erroring — wire/parse
    // failures surface as `{valid:false, checks:[...]}` so axum and PQ
    // render identical bodies without needing different status codes.
    // Five orthogonal axes here:
    //   1. Wire-format failure short-circuits to a single-check envelope.
    //   2. Valid wire but unsigned record exercises ALL 7 checks (sig
    //      fails, bounds/timestamp/beat_op/parents/duplicate pass).
    //   3. Properly signed record passes signature → `valid=true`
    //      round-trip with all 7 checks passing.
    //   4. Duplicate detection via pre-populated SeenSet →
    //      `duplicate.passed=false` & `is_duplicate=true`.
    //   5. Bounds failure (>MAX_METADATA_ENTRIES) → `bounds.passed=false`
    //      but check-list continues (NOT a short-circuit like wire).

    #[tokio::test]
    async fn batch_xxx_compute_validate_record_wire_format_failure_returns_envelope_with_single_check() {
        // PIN: garbage bytes that aren't a valid wire ValidationRecord must
        // return an envelope with `valid=false`, a single `wire_format`
        // check (passed=false, with an error string), and NO record_id /
        // creator_hash / classification / timestamp fields (the helper
        // early-returns before computing those). A regression that ran
        // subsequent checks on a half-deserialized record would crash on
        // the empty creator_public_key, AND would leak null record_id
        // strings to the wire (breaking the `/validate` UI's "show me the
        // record_id you parsed" affordance, which currently relies on
        // record_id being absent for parse failures vs present for
        // post-parse validation failures).
        let state = crate::network::state::build_test_node_state();
        let garbage: &[u8] = b"this is not a wire ValidationRecord";
        let v = compute_validate_record(&state, garbage).await;

        // Envelope: `valid` is exactly false (NOT null, NOT missing).
        assert_eq!(
            v.get("valid").and_then(|x| x.as_bool()),
            Some(false),
            "wire_format failure MUST surface valid=false",
        );

        // `checks` is a single-element array.
        let checks = v
            .get("checks")
            .and_then(|x| x.as_array())
            .expect("checks must be an array even on wire failure");
        assert_eq!(
            checks.len(),
            1,
            "wire_format failure MUST short-circuit to exactly 1 check (no bounds/sig/etc. on undeserializable bytes); got {} ({:?})",
            checks.len(),
            checks,
        );
        assert_eq!(
            checks[0].get("check").and_then(|x| x.as_str()),
            Some("wire_format"),
        );
        assert_eq!(
            checks[0].get("passed").and_then(|x| x.as_bool()),
            Some(false),
        );
        assert!(
            checks[0].get("error").and_then(|x| x.as_str()).is_some(),
            "wire_format failure MUST attach an `error` string for operator debugging",
        );

        // Early-return invariant: post-parse fields MUST NOT appear in
        // the envelope when wire-format fails. A regression that
        // populated `record_id: null` or `creator_hash: ""` would break
        // the dashboard's parse-vs-validation distinction.
        for absent_key in ["record_id", "creator_hash", "classification", "timestamp"] {
            assert!(
                v.get(absent_key).is_none(),
                "wire_format failure MUST NOT carry `{absent_key}` (early-return branch); leak would break the parse-vs-validate UI distinction",
            );
        }
    }

    #[tokio::test]
    async fn batch_xxx_compute_validate_record_unsigned_valid_wire_runs_all_seven_checks() {
        // PIN: a wire-valid but UNSIGNED record (record.signature=None)
        // must NOT short-circuit — every one of the 7 check categories
        // (wire_format, bounds, timestamp, signature, beat_op, parents,
        // duplicate) MUST appear in `checks`, in order, with `signature`
        // being the failing one (since no sig) and all others passing.
        // Pin both the exact check-name set AND `valid=false` (signature
        // failure is fatal). A regression that returned early on the
        // first failed check (e.g., a misplaced `return` after the sig
        // branch) would surface as missing tail-checks.
        let state = crate::network::state::build_test_node_state();
        let record = crate::record::ValidationRecord::create(
            b"unsigned-valid-wire",
            state.identity.public_key.clone(),
            Vec::new(),
            crate::record::Classification::Public,
            None,
        );
        let body = record.to_bytes();
        let v = compute_validate_record(&state, &body).await;

        // `valid` is false because signature is None.
        assert_eq!(
            v.get("valid").and_then(|x| x.as_bool()),
            Some(false),
            "unsigned record MUST surface valid=false",
        );

        // Envelope carries post-parse fields (record_id, creator_hash,
        // classification, timestamp) — distinct from the wire-fail branch.
        assert_eq!(
            v.get("record_id").and_then(|x| x.as_str()),
            Some(record.id.as_str()),
            "post-parse branch MUST echo record_id",
        );
        assert!(
            v.get("creator_hash").and_then(|x| x.as_str()).is_some(),
            "post-parse branch MUST surface creator_hash",
        );
        assert_eq!(
            v.get("classification").and_then(|x| x.as_str()),
            Some("PUBLIC"),
            "post-parse branch MUST surface Classification::name() uppercase value",
        );

        let checks = v
            .get("checks")
            .and_then(|x| x.as_array())
            .expect("checks must be a JSON array");
        // Exact-7-check pin. Order matters because /validate UIs and PQ
        // diagnostic tooling iterate in order; a reorder would silently
        // change the "first failure" message.
        let expected_checks = [
            "wire_format",
            "bounds",
            "timestamp",
            "signature",
            "beat_op",
            "parents",
            "duplicate",
        ];
        assert_eq!(
            checks.len(),
            expected_checks.len(),
            "post-parse branch MUST run all {} checks; got {} ({:?})",
            expected_checks.len(),
            checks.len(),
            checks.iter().map(|c| c.get("check").and_then(|x| x.as_str())).collect::<Vec<_>>(),
        );
        for (i, expected_name) in expected_checks.iter().enumerate() {
            assert_eq!(
                checks[i].get("check").and_then(|x| x.as_str()),
                Some(*expected_name),
                "checks[{i}] MUST be `{expected_name}` (in-order pin); got {:?}",
                checks[i].get("check"),
            );
        }

        // signature is the ONLY failed check on this branch.
        let sig_check = &checks[3];
        assert_eq!(
            sig_check.get("passed").and_then(|x| x.as_bool()),
            Some(false),
            "signature MUST fail on unsigned record",
        );
        // All other checks pass: bounds (empty meta), timestamp (now),
        // beat_op (no metadata → None branch), parents (empty), duplicate
        // (fresh SeenSet).
        for ok_idx in [0usize, 1, 2, 4, 5, 6] {
            assert_eq!(
                checks[ok_idx].get("passed").and_then(|x| x.as_bool()),
                Some(true),
                "checks[{ok_idx}] (`{}`) MUST pass on unsigned-valid-wire record (only signature fails)",
                expected_checks[ok_idx],
            );
        }
    }

    #[tokio::test]
    async fn batch_xxx_compute_validate_record_properly_signed_record_round_trips_to_valid_true() {
        // PIN: when the record is properly signed by the same Dilithium3
        // keypair whose public key is embedded as `creator_public_key`,
        // ALL 7 checks pass and the envelope surfaces `valid=true`. This
        // exercises the signature-verify round-trip wired through
        // `dilithium3_verify(&record.signable_bytes(), sig, pk)` at
        // routes/core.rs:983. A regression that fed `to_bytes()` instead
        // of `signable_bytes()` to the verifier (the most likely "fix"
        // for an unrelated wire-version bump) would break every
        // /validate call on properly signed records — silently downgrading
        // the explorer's "valid: true" badge to "valid: false" cluster-wide.
        let state = crate::network::state::build_test_node_state();
        let mut record = crate::record::ValidationRecord::create(
            b"properly-signed-record",
            state.identity.public_key.clone(),
            Vec::new(),
            crate::record::Classification::Public,
            None,
        );
        // sign_record_light is Dilithium3-only (Profile B); state.identity
        // is generated as ProfileB in build_test_node_state so this is the
        // correct sign call. Sets record.signature and sig_algorithm.
        state
            .identity
            .sign_record_light(&mut record)
            .expect("sign_record_light");
        assert!(record.signature.is_some(), "sign_record_light MUST populate signature");

        let body = record.to_bytes();
        let v = compute_validate_record(&state, &body).await;

        assert_eq!(
            v.get("valid").and_then(|x| x.as_bool()),
            Some(true),
            "properly-signed-no-ledger-op record MUST surface valid=true; got: {v:?}",
        );

        let checks = v
            .get("checks")
            .and_then(|x| x.as_array())
            .expect("checks array");
        for check in checks.iter() {
            let name = check.get("check").and_then(|x| x.as_str()).unwrap_or("?");
            let passed = check.get("passed").and_then(|x| x.as_bool()).unwrap_or(false);
            assert!(
                passed,
                "check `{name}` MUST pass on properly-signed record; got {check:?}",
            );
        }

        // beat_op check explicitly surfaces `op: null` for records
        // without a LedgerOp metadata key. Pin this so a regression that
        // changed the "no op" sentinel to `"none"` or `""` doesn't
        // silently break the explorer's "this record carries no ledger op"
        // affordance.
        let beat_op_check = checks
            .iter()
            .find(|c| c.get("check").and_then(|x| x.as_str()) == Some("beat_op"))
            .expect("beat_op check must be present");
        assert!(
            beat_op_check.get("op").map(|v| v.is_null()).unwrap_or(false),
            "beat_op `op` MUST be JSON null for records without a LedgerOp; got {beat_op_check:?}",
        );
    }

    #[tokio::test]
    async fn batch_xxx_compute_validate_record_duplicate_detection_via_pre_populated_seen_set() {
        // PIN: when a record's `id` is already present in `state.seen`
        // (the SeenSet at routes/core.rs:1040), the duplicate check MUST
        // fire `passed=false` & `is_duplicate=true` and the envelope
        // surfaces `valid=false`. This pins the SeenSet wiring through
        // the helper; a regression that read from a different cache
        // (e.g., gossip_rejected instead of seen) would silently allow
        // duplicate `/validate` reports to flap between valid and
        // invalid depending on which cache happens to be populated.
        // Setup: sign a valid record, THEN insert record.id into seen
        // BEFORE calling compute_validate_record on the wire bytes.
        let state = crate::network::state::build_test_node_state();
        let mut record = crate::record::ValidationRecord::create(
            b"duplicate-detect-record",
            state.identity.public_key.clone(),
            Vec::new(),
            crate::record::Classification::Public,
            None,
        );
        state
            .identity
            .sign_record_light(&mut record)
            .expect("sign_record_light");
        let record_id = record.id.clone();
        let body = record.to_bytes();

        // Pre-populate the SeenSet with this record's id.
        {
            let mut seen = state.seen.lock_recover();
            let newly_inserted = seen.insert(record_id.clone());
            assert!(newly_inserted, "pre-populate insert MUST return true on fresh SeenSet");
        }

        let v = compute_validate_record(&state, &body).await;

        // Envelope: valid=false because the duplicate fail makes it fatal.
        assert_eq!(
            v.get("valid").and_then(|x| x.as_bool()),
            Some(false),
            "duplicate-detect MUST surface valid=false even though sig is good; got {v:?}",
        );

        let checks = v
            .get("checks")
            .and_then(|x| x.as_array())
            .expect("checks array");
        let dup_check = checks
            .iter()
            .find(|c| c.get("check").and_then(|x| x.as_str()) == Some("duplicate"))
            .expect("duplicate check must be present in checks array");
        assert_eq!(
            dup_check.get("passed").and_then(|x| x.as_bool()),
            Some(false),
            "duplicate.passed MUST be false when record_id is in SeenSet; got {dup_check:?}",
        );
        assert_eq!(
            dup_check.get("is_duplicate").and_then(|x| x.as_bool()),
            Some(true),
            "duplicate.is_duplicate MUST be true on SeenSet hit",
        );

        // Cross-axis pin: signature MUST still pass (the sig is valid;
        // only the duplicate check fires). A regression that conflated
        // dup-failure with sig-failure (e.g., setting valid=false and
        // failing sig in a single branch) would surface here.
        let sig_check = checks
            .iter()
            .find(|c| c.get("check").and_then(|x| x.as_str()) == Some("signature"))
            .expect("signature check present");
        assert_eq!(
            sig_check.get("passed").and_then(|x| x.as_bool()),
            Some(true),
            "signature MUST still pass on duplicate-but-properly-signed record; got {sig_check:?}",
        );
    }

    #[tokio::test]
    async fn batch_xxx_compute_validate_record_bounds_failure_does_not_short_circuit_check_list() {
        // PIN: a record with >MAX_METADATA_ENTRIES metadata keys must
        // surface `bounds.passed=false` AND continue running ALL
        // subsequent checks (signature, beat_op, parents, duplicate).
        // This is distinct from the wire_format branch (which DOES
        // short-circuit to 1 check). The bounds-fail-but-keep-going
        // contract lets operators see a single envelope listing every
        // structural problem with a record — not "first failure wins".
        // A regression that added `return` after the bounds failure
        // would surface as missing tail-checks (4 missing: signature,
        // beat_op, parents, duplicate).
        let state = crate::network::state::build_test_node_state();
        let mut record = crate::record::ValidationRecord::create(
            b"bounds-failure-record",
            state.identity.public_key.clone(),
            Vec::new(),
            crate::record::Classification::Public,
            None,
        );
        // Stuff cap+1 metadata entries (one over
        // crate::network::ingest::MAX_METADATA_ENTRIES) so the test tracks
        // the constant instead of pinning a stale literal.
        let over_cap = crate::network::ingest::MAX_METADATA_ENTRIES as u32 + 1;
        for i in 0..over_cap {
            record.metadata.insert(format!("k{i:02}"), serde_json::json!(i));
        }
        let body = record.to_bytes();
        let v = compute_validate_record(&state, &body).await;

        // valid=false because bounds is fatal.
        assert_eq!(
            v.get("valid").and_then(|x| x.as_bool()),
            Some(false),
            "bounds failure MUST surface valid=false",
        );

        let checks = v
            .get("checks")
            .and_then(|x| x.as_array())
            .expect("checks array");
        // All 7 checks STILL run (NOT a short-circuit).
        assert_eq!(
            checks.len(),
            7,
            "bounds failure MUST NOT short-circuit; expected 7 checks, got {} ({:?})",
            checks.len(),
            checks.iter().map(|c| c.get("check").and_then(|x| x.as_str())).collect::<Vec<_>>(),
        );

        // bounds.passed=false with metadata_entries echoed back.
        let bounds_check = &checks[1];
        assert_eq!(
            bounds_check.get("check").and_then(|x| x.as_str()),
            Some("bounds"),
            "bounds is the 2nd check (after wire_format)",
        );
        assert_eq!(
            bounds_check.get("passed").and_then(|x| x.as_bool()),
            Some(false),
            "bounds MUST fail when metadata.len() > MAX_METADATA_ENTRIES",
        );
        assert_eq!(
            bounds_check.get("metadata_entries").and_then(|x| x.as_u64()),
            Some(over_cap as u64),
            "bounds_check MUST echo the offending metadata_entries count for operator triage; got {bounds_check:?}",
        );
        // wire_format still passed (record deserialized fine — the bounds
        // failure is a domain check, not a wire check).
        assert_eq!(
            checks[0].get("check").and_then(|x| x.as_str()),
            Some("wire_format"),
        );
        assert_eq!(
            checks[0].get("passed").and_then(|x| x.as_bool()),
            Some(true),
            "wire_format MUST still pass — bounds failure is post-parse, not wire-level",
        );
    }

    // ─── compute_list_peers orthogonal-axis pins ─────────
    // Previously the routes/core.rs `compute_list_peers` surface had ONE
    // positive test (`compute_list_peers_returns_empty_for_fresh_state` at
    // ~L1826) covering only the empty-table branch. The handler at
    // `routes/core.rs:1155` is the wire-shape contract for `/peers`
    // (consumed by the explorer SPA + every operator `curl /peers | jq …`
    // script + the per-peer forensic triage flows). The
    // empty-state pin would survive every regression class listed below.
    //
    // Axes pinned:
    //  1. Defense-in-depth self-filter — the handler-side `!= self_hash`
    //     filter at `routes/core.rs:1161` must stay live even if a peer
    //     leaks into the table via a path that bypasses `PeerTable::insert`'s
    //     self-rejection (e.g., peers.json serde-load, or `set_local_identity`
    //     called AFTER insert).
    //  2. Top-level JSON envelope is strictly 1-key `{"peers": [...]}`.
    //     Catches a regression that appends `total_count` / `as_of` and
    //     breaks consumer scripts doing `jq '.peers | length'`.
    //  3. Per-peer entry has a strict 17-key shape covering identity_hash,
    //     host, port, node_type, last_seen, state, reachable, failures,
    //     successes, pow_nonce, pow_difficulty, public_key_hex,
    //     protocol_version, att_pull_invalid_sig, att_pull_invalid_powas,
    //     att_push_low_stake_deferred, recent_bad_sig_record_ids. Drop or
    //     add of any field is a wire break — particularly silent removal
    //     of the forensic counters that triage bootstrap
    //     pathologies.
    //  4. `state` is rendered via `format!("{:?}", PeerState)` (Debug) NOT
    //     via PeerState::as_str / Display. A refactor to derive Display
    //     would silently flip the wire from `"Stale"` to whatever Display
    //     emits (e.g., `"stale"`), corrupting every `/peers | jq
    //     '.peers[].state == "Connected"'` check.
    //  5. `recent_bad_sig_record_ids` round-trips VecDeque FIFO
    //     order as a JSON string-array. Catches (a) serde-skip-when-empty
    //     making the field a `null`, (b) order corruption from a refactor
    //     to `BTreeSet` or `HashSet`, and (c) type mismatch (e.g., dropping
    //     to a count instead of the IDs themselves).
    fn batch_iiii_make_peer(identity_hash: &str) -> crate::network::peer::PeerInfo {
        crate::network::peer::PeerInfo {
            identity_hash: identity_hash.to_string(),
            host: "10.0.0.1".to_string(),
            port: 9473,
            node_type: crate::network::peer::NodeType::Leaf,
            last_seen: 1000.0,
            state: crate::network::peer::PeerState::Connected,
            failures: 0,
            successes: 0,
            valid_records: 0,
            invalid_records: 0,
            backoff_until: 0.0,
            pow_nonce: 0,
            pow_difficulty: 0,
            public_key_hex: String::new(),
            provenance: crate::network::peer::PeerProvenance::Outbound,
            subscribed_zones: Vec::new(),
            att_watermark: 0.0,
            pull_failures: 0,
            pull_backoff_until: 0.0,
            reachable: true,
            protocol_version: 0,
            att_pull_invalid_sig: 0,
            att_pull_invalid_powas: 0,
            att_push_low_stake_deferred: 0,
            recent_bad_sig_record_ids: std::collections::VecDeque::new(),
        }
    }

    #[tokio::test]
    async fn batch_iiii_axis1_handler_filters_self_even_when_table_contains_self() {
        // Axis 1: defense-in-depth self-filter. `PeerTable::insert` already
        // rejects self (peer.rs:390 short-circuits on `local_identity_hash`
        // match), but the handler at `routes/core.rs:1161` ALSO filters via
        // `p.identity_hash != *self_hash`. This redundancy is load-bearing:
        // if a peer ever enters via a path that bypasses `insert()` — e.g.,
        // peers.json serde load, or `set_local_identity()` called AFTER
        // insertion — the handler-side filter is the LAST line of defense
        // against `/peers` listing the local node in its own peer set
        // (which would corrupt every peer-count health check + the explorer
        // SPA's "connected to N peers" badge).
        //
        // Construction: clear the table's `local_identity_hash` to bypass
        // `PeerTable::insert`'s self-rejection, insert a peer whose
        // `identity_hash` matches the handler's `state.identity.identity_hash`,
        // then ask the handler to render. Only the handler's `!= self_hash`
        // filter prevents leakage.
        let state = crate::network::state::build_test_node_state();
        let self_hash = state.identity.identity_hash.clone();
        {
            let mut peers = state.peers.write().await;
            peers.set_local_identity(""); // disable PeerTable's insert-time self-reject
            let inserted = peers.insert(batch_iiii_make_peer(&self_hash));
            assert!(
                inserted,
                "test setup: insert(self) MUST succeed once local_identity is empty",
            );
        }
        let v = compute_list_peers(&state, None).await;
        let arr = v
            .get("peers")
            .and_then(|x| x.as_array())
            .expect("`peers` array must surface even when the table contains self");
        assert!(
            arr.is_empty(),
            "handler-side self-filter dropped — got {} peer(s) when only entry matches self_hash; \
             `routes/core.rs:1161` filter regression: {:?}",
            arr.len(),
            arr,
        );
    }

    #[tokio::test]
    async fn batch_iiii_axis2_top_level_envelope_is_strict_two_key_with_total() {
        // Axis 2: the top-level JSON envelope MUST be exactly
        // `{"peers": [...], "total": N}` — these two keys, no more. Consumer
        // scripts do `jq '.peers | length'` and the explorer SPA does
        // `response.peers.map(...)`; both still work. `total` was added with
        // the public-surface response bound so a caller can detect truncation
        // (`peers.len() < total`) — pinned here so a later edit can't silently
        // drop it or append a third key. Any further top-level addition must
        // land as a deliberate test edit.
        let state = crate::network::state::build_test_node_state();
        {
            let mut peers = state.peers.write().await;
            assert!(
                peers.insert(batch_iiii_make_peer("aaaaaaaaaaaaaaaa")),
                "test setup: insert(distinct-from-self) must succeed",
            );
        }
        let v = compute_list_peers(&state, None).await;
        let obj = v
            .as_object()
            .expect("compute_list_peers MUST return a JSON object at the top level");
        let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["peers", "total"],
            "top-level envelope MUST emit EXACTLY 2 keys {{peers, total}}; got: {:?}",
            obj.keys().collect::<Vec<_>>(),
        );
        // `total` mirrors the returned peer count when below the page cap (one
        // peer here, far under PEERS_DEFAULT_LIMIT).
        assert_eq!(
            obj.get("total").and_then(|x| x.as_u64()),
            Some(1),
            "`total` MUST report the true known-peer count",
        );
    }

    #[tokio::test]
    async fn batch_iiii_compute_list_peers_bounds_returned_rows_while_total_reports_true_count() {
        // Public-surface response bound: `/peers` is reachable over the PQ
        // `list_peers` verb by any handshaked peer and grows with the node
        // population, so a single call must not dump the whole table. `limit`
        // bounds the returned `peers` array while `total` reports the TRUE
        // known-peer count so a caller detects truncation as `peers.len() <
        // total`. Rows are ordered by identity_hash for a deterministic page.
        let state = crate::network::state::build_test_node_state();
        {
            let mut peers = state.peers.write().await;
            for i in 0..5u8 {
                assert!(
                    peers.insert(batch_iiii_make_peer(&format!("peer-{i:02}"))),
                    "test setup: insert distinct peer must succeed",
                );
            }
        }
        // Request a page smaller than the peer table.
        let v = compute_list_peers(&state, Some(2)).await;
        let obj = v.as_object().expect("top-level MUST be JSON Object");
        let arr = obj["peers"].as_array().expect("`peers` MUST be a JSON Array");
        assert_eq!(
            arr.len(),
            2,
            "returned peers MUST be bounded by the requested limit",
        );
        assert_eq!(
            obj.get("total").and_then(|x| x.as_u64()),
            Some(5),
            "`total` MUST report the TRUE known-peer count regardless of the page cap",
        );
        // Deterministic ordering — lowest identity_hash first ("peer-00","peer-01").
        assert_eq!(
            arr[0]["identity_hash"].as_str(),
            Some("peer-00"),
            "page MUST be ordered by identity_hash — first row is the lowest",
        );
        assert_eq!(
            arr[1]["identity_hash"].as_str(),
            Some("peer-01"),
            "page MUST be ordered by identity_hash — second row is the next lowest",
        );
    }

    #[tokio::test]
    async fn batch_iiii_axis3_per_peer_entry_has_strict_17_key_shape() {
        // Axis 3: every per-peer object MUST carry exactly these 17 fields
        // and nothing else. Drop = wire break for consumers; add = silent
        // wire bloat that goes uncaught until the same field name lands
        // with a different meaning later. The
        // forensic counters (`att_pull_invalid_sig`, `att_pull_invalid_powas`,
        // `att_push_low_stake_deferred`, `recent_bad_sig_record_ids`) are
        // particularly load-bearing: dropping any of them silently breaks
        // the bootstrap-pathology triage workflow documented at
        // `routes/core.rs:1177-1192`.
        let state = crate::network::state::build_test_node_state();
        {
            let mut peers = state.peers.write().await;
            assert!(peers.insert(batch_iiii_make_peer("bbbbbbbbbbbbbbbb")));
        }
        let v = compute_list_peers(&state, None).await;
        let arr = v.get("peers").and_then(|x| x.as_array()).expect("peers array");
        assert_eq!(arr.len(), 1, "test setup: expected exactly 1 peer; got {arr:?}");
        let entry = arr[0]
            .as_object()
            .expect("each peer entry MUST be a JSON object");
        let expected: std::collections::BTreeSet<&str> = [
            "identity_hash",
            "host",
            "port",
            "node_type",
            "last_seen",
            "state",
            "reachable",
            "failures",
            "successes",
            "pow_nonce",
            "pow_difficulty",
            "public_key_hex",
            "protocol_version",
            "att_pull_invalid_sig",
            "att_pull_invalid_powas",
            "att_push_low_stake_deferred",
            "recent_bad_sig_record_ids",
        ]
        .into_iter()
        .collect();
        let actual: std::collections::BTreeSet<&str> =
            entry.keys().map(|k| k.as_str()).collect();
        assert_eq!(
            actual, expected,
            "per-peer entry shape drifted; \
             missing keys: {:?}; extra keys: {:?}",
            expected.difference(&actual).collect::<Vec<_>>(),
            actual.difference(&expected).collect::<Vec<_>>(),
        );
    }

    #[tokio::test]
    async fn batch_iiii_axis4_state_field_is_debug_formatted_not_display() {
        // Axis 4: the `state` field is rendered via `format!("{:?}",
        // PeerState)` (Debug-derived → variant name as written). A future
        // refactor that switches to PeerState::as_str (which doesn't exist
        // today but is the natural sibling to NodeType::as_str) OR derives
        // a Display impl with snake_case rendering would silently flip the
        // wire value from `"Stale"` to e.g. `"stale"`. Both the explorer
        // SPA and operator scripts compare with the Debug-cased strings
        // (`p.state === "Connected"`); a case flip would silently render
        // every health gauge zero with no error log.
        //
        // We exercise PeerState::Stale specifically (not the Connected
        // default) so the test catches both (a) the refactor described
        // above AND (b) an accidental hard-coded `format!("Connected")`
        // that would survive a default-state test.
        let state = crate::network::state::build_test_node_state();
        {
            let mut peers = state.peers.write().await;
            let mut p = batch_iiii_make_peer("cccccccccccccccc");
            p.state = crate::network::peer::PeerState::Stale;
            assert!(peers.insert(p));
        }
        let v = compute_list_peers(&state, None).await;
        let arr = v.get("peers").and_then(|x| x.as_array()).unwrap();
        assert_eq!(arr.len(), 1);
        let state_field = arr[0].get("state").and_then(|x| x.as_str()).unwrap_or("");
        assert_eq!(
            state_field, "Stale",
            "`state` field MUST be Debug-formatted (`format!(\"{{:?}}\", PeerState)`); \
             got `{state_field}` — a Display/as_str refactor would silently break \
             wire compatibility with the explorer SPA + operator scripts",
        );
    }

    #[tokio::test]
    async fn batch_iiii_axis5_recent_bad_sig_record_ids_preserves_vec_deque_fifo_order() {
        // Axis 5: `recent_bad_sig_record_ids` contract. It is a
        // bounded VecDeque (cap = `BAD_SIG_SAMPLE_CAP = 16`) used by
        // forensic triage to triangulate Byzantine-forwarder vs
        // verification-mismatch (peer.rs:240-251). The wire surface MUST:
        //   (a) ALWAYS be a JSON array — never null, never missing
        //       (catches a `#[serde(skip_serializing_if = "VecDeque::is_empty")]`
        //       regression that would break the empty-state path);
        //   (b) preserve insertion order via VecDeque's `iter()` —
        //       catches a refactor to BTreeSet (alphabetical) or
        //       HashSet (random) which would corrupt the
        //       "most-recent-failure first" forensic ordering;
        //   (c) carry string elements (not the count-only summary that
        //       a future "lossy /peers light mode" might emit).
        let state = crate::network::state::build_test_node_state();
        {
            let mut peers = state.peers.write().await;
            let mut p = batch_iiii_make_peer("dddddddddddddddd");
            // VecDeque FIFO: push_back("alpha") then "beta" then "gamma"
            // → iter() yields alpha, beta, gamma in that order. A switch
            // to BTreeSet would yield alphabetical (also alpha/beta/gamma
            // by coincidence here), so we deliberately push out-of-alpha
            // order to differentiate.
            p.recent_bad_sig_record_ids.push_back("rec_zulu".to_string());
            p.recent_bad_sig_record_ids.push_back("rec_alpha".to_string());
            p.recent_bad_sig_record_ids.push_back("rec_mike".to_string());
            assert!(peers.insert(p));
        }
        let v = compute_list_peers(&state, None).await;
        let arr = v.get("peers").and_then(|x| x.as_array()).unwrap();
        assert_eq!(arr.len(), 1);
        let bad_sig = arr[0]
            .get("recent_bad_sig_record_ids")
            .expect("OPS-32 field `recent_bad_sig_record_ids` MUST be present (never null/absent)");
        let bad_sig_arr = bad_sig
            .as_array()
            .expect("`recent_bad_sig_record_ids` MUST be a JSON array, not null/object/string");
        let actual: Vec<&str> = bad_sig_arr
            .iter()
            .map(|x| {
                x.as_str()
                    .expect("each entry MUST be a JSON string (record_id)")
            })
            .collect();
        assert_eq!(
            actual,
            vec!["rec_zulu", "rec_alpha", "rec_mike"],
            "VecDeque FIFO order corrupted; got {actual:?} — a refactor to BTreeSet \
             would yield alphabetical (`rec_alpha, rec_mike, rec_zulu`) and break \
             the OPS-32 most-recent-first forensic ordering",
        );
    }

    // ─── compute_node_identity_payload orthogonal pins ───
    //
    // `node_identity` is a 0-coverage handler: a 16-line pure-state
    // 10-key envelope describing this node's identity + crypto + protocol
    // version, consumed by operator dashboards + account boot probes to
    // distinguish genesis-authority nodes from leaf nodes. It previously had
    // ZERO direct route-layer tests (existing core.rs tests cover version() /
    // ping() / protocol_limits() / compute_health / compute_list_peers /
    // node_config / gossip_health — node_identity sits in the gap between
    // node_config and gossip_health).
    //
    // 5 axes natively orthogonal to each other AND to the previously-zero coverage
    // surface:
    //   (1) Empty/fresh state yields exactly the 10-key envelope — BTreeSet
    //       symmetric-difference catches add/drop/rename on any of
    //       {identity_hash, entity_type, crypto_profile, algorithm, has_pow,
    //       pow_difficulty, node_type, is_genesis_authority, version,
    //       protocol_version} + wire-type pins on each key (3 strings,
    //       1 bool, 2 u64s, 4 strings — matches the json!() shape exactly).
    //   (2) Fresh non-genesis identity yields is_genesis_authority=false —
    //       build_test_node_state() generates a random identity whose hash
    //       is overwhelmingly unlikely to collide with the default
    //       TESTNET_GENESIS_AUTHORITY constant. Asserts identity_hash !=
    //       genesis_authority precondition AND is_genesis_authority == false.
    //       Defends a refactor flipping the equality direction (e.g.
    //       `identity_hash != genesis_authority` typo) which would surface
    //       every non-genesis node as genesis on the operator dashboard.
    //   (3) Genesis-authority case yields is_genesis_authority=true — THE
    //       CRITICAL ORTHOGONALITY AXIS. Builds a custom NodeState where
    //       config.genesis_authority is set to the just-generated identity's
    //       identity_hash. Asserts is_genesis_authority == true AND
    //       identity_hash == genesis_authority byte-faithful. This is the
    //       only test in the file that exercises the true branch of the
    //       is_genesis comparison; without it, a refactor that hardcoded
    //       is_genesis = false would pass all other tests + ship.
    //   (4) Entity_type and crypto_profile use Debug-formatted enum strings
    //       NOT serde rename — both EntityType and CryptoProfile are tagged
    //       `#[serde(rename = "...")]` so serde would produce "DEVICE" and
    //       "B" respectively, but the route uses `format!("{:?}", ...)`
    //       producing "Device" and "ProfileB" (Debug form). Asserts the
    //       exact Debug-formatted strings + includes a negative assertion
    //       that the serde rename forms are NOT present. Defends both
    //       `entity_type.as_str()` and `serde_json::to_value` swap
    //       regressions — same orthogonality class as the admin_sunset
    //       Debug-vs-serde axis.
    //   (5) has_pow boolean derived from pow_difficulty > 0 — Identity::
    //       generate creates an identity with pow_difficulty == 0 (no PoW
    //       challenge solved at generation time), so has_pow must be false
    //       AND pow_difficulty must be 0. Then mutate the identity's
    //       pow_difficulty to a positive value (constructing a second state
    //       with a synthesized PoW-bearing identity) and re-call helper —
    //       asserts has_pow becomes true. This axis defends a refactor
    //       swapping `> 0` for `>= 0` (always true) or `!= 0` (works for
    //       u8 but breaks if pow_difficulty becomes signed) which would
    //       hide PoW-on/PoW-off distinction from operator tooling.

    /// Custom NodeState builder where config.genesis_authority is overwritten
    /// to match the just-generated identity's identity_hash, so
    /// is_genesis_authority surfaces as true. Mirrors build_test_node_state
    /// pattern (std::mem::forget(tmp), Identity::generate Device ProfileB,
    /// open RocksDB tempdir, wrap in Arc) and DOES NOT touch any persisted
    /// state — purely an in-memory config override.
    fn build_genesis_authority_state() -> Arc<NodeState> {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        // KEY: override genesis_authority to match the generated identity_hash.
        // This is the only way to flip is_genesis_authority to true without
        // physically planting the genesis authority's full identity material.
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "batch-aaaaa-admin".into(),
            network_id: "batch-aaaaa-genesis".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            genesis_authority: identity.identity_hash.clone(),
            ..Default::default()
        };
        let rocks = Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = NodeState::new(config, identity, rocks, wmgr);
        std::mem::forget(tmp);
        Arc::new(state)
    }

    #[test]
    fn batch_aaaaa_compute_node_identity_envelope_is_ten_keys() {
        // Axis 1: top-level envelope shape. node_identity emits EXACTLY 10
        // keys. BTreeSet symmetric-difference catches any add/drop/rename;
        // wire-type pins lock the JSON shape so a refactor flipping a
        // string to int (or vice versa) breaks here, not at the operator
        // dashboard parse step.
        use std::collections::BTreeSet;
        let state = crate::network::state::build_test_node_state();
        let v = compute_node_identity_payload(&state);

        let obj = v.as_object().expect("top-level must be JSON Object");
        let actual_keys: BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let expected_keys: BTreeSet<&str> = [
            "identity_hash",
            "entity_type",
            "crypto_profile",
            "algorithm",
            "has_pow",
            "pow_difficulty",
            "node_type",
            "is_genesis_authority",
            "version",
            "protocol_version",
        ].iter().copied().collect();
        let added: Vec<&&str> = actual_keys.difference(&expected_keys).collect();
        let dropped: Vec<&&str> = expected_keys.difference(&actual_keys).collect();
        assert!(
            added.is_empty() && dropped.is_empty(),
            "node_identity envelope key drift: added={:?} dropped={:?}",
            added, dropped
        );

        // Wire-type pins on every key. A refactor flipping a string to int
        // (or vice versa) silently breaks account/operator dashboards
        // parsing the structured payload.
        assert!(v["identity_hash"].is_string(),       "identity_hash must be string");
        assert!(v["entity_type"].is_string(),         "entity_type must be string");
        assert!(v["crypto_profile"].is_string(),      "crypto_profile must be string");
        assert!(v["algorithm"].is_string(),           "algorithm must be string");
        assert!(v["has_pow"].is_boolean(),            "has_pow must be boolean");
        assert!(v["pow_difficulty"].is_u64(),         "pow_difficulty must be u64");
        assert!(v["node_type"].is_string(),           "node_type must be string");
        assert!(v["is_genesis_authority"].is_boolean(),
                "is_genesis_authority must be boolean");
        assert!(v["version"].is_string(),             "version must be string");
        assert!(v["protocol_version"].is_u64(),       "protocol_version must be u64");
    }

    #[test]
    fn batch_aaaaa_fresh_non_genesis_identity_is_not_authority() {
        // Axis 2: fresh non-genesis identity → is_genesis_authority == false.
        // build_test_node_state() generates a random identity whose hash
        // is overwhelmingly unlikely to match the default
        // TESTNET_GENESIS_AUTHORITY constant. This pin defends a refactor
        // flipping the equality direction (e.g. `!=` instead of `==`) or
        // hardcoding `is_genesis = true` which would surface every non-
        // genesis node as genesis on operator dashboards.
        let state = crate::network::state::build_test_node_state();

        // Precondition: identity_hash MUST NOT match the default genesis
        // authority. If this ever flakes (cryptographically impossible —
        // SHA3-256 collision probability), the test result is meaningless.
        assert_ne!(
            state.identity.identity_hash, state.config.genesis_authority,
            "PRECONDITION: fresh random identity_hash must differ from \
             TESTNET_GENESIS_AUTHORITY constant (collision impossible \
             under SHA3-256)",
        );

        let v = compute_node_identity_payload(&state);
        assert_eq!(
            v["is_genesis_authority"].as_bool(),
            Some(false),
            "fresh non-matching identity must surface is_genesis_authority \
             == false — defends a refactor flipping the comparison or \
             hardcoding the field to true",
        );
        // Cross-check: identity_hash + genesis_authority surfaced in the
        // payload don't equal each other (operators can grep both fields
        // in /node/identity output to verify the assignment).
        assert_eq!(
            v["identity_hash"].as_str(),
            Some(state.identity.identity_hash.as_str()),
        );
    }

    #[test]
    fn batch_aaaaa_genesis_authority_identity_surfaces_true() {
        // Axis 3: THE CRITICAL ORTHOGONALITY AXIS. Constructs a NodeState
        // where config.genesis_authority is overwritten to match the
        // generated identity's identity_hash, so is_genesis_authority must
        // surface as true. This is the ONLY test in core.rs that exercises
        // the true branch of the is_genesis comparison; without it, a
        // refactor hardcoding is_genesis = false would pass every other
        // test and ship.
        let state = build_genesis_authority_state();

        // Precondition: identity_hash MUST equal genesis_authority by
        // construction (build_genesis_authority_state forces this).
        assert_eq!(
            state.identity.identity_hash, state.config.genesis_authority,
            "PRECONDITION: builder must force identity_hash == \
             genesis_authority",
        );

        let v = compute_node_identity_payload(&state);
        assert_eq!(
            v["is_genesis_authority"].as_bool(),
            Some(true),
            "matching identity must surface is_genesis_authority == true — \
             without this pin a refactor hardcoding the field to false \
             would silently mask the genesis authority on operator \
             dashboards",
        );
        // Byte-faithful echo: identity_hash must appear exactly as the
        // String stored in state.identity.identity_hash (NOT truncated,
        // NOT lowercased, NOT re-hashed).
        assert_eq!(
            v["identity_hash"].as_str(),
            Some(state.identity.identity_hash.as_str()),
        );
    }

    #[test]
    fn batch_aaaaa_entity_type_and_crypto_profile_use_debug_format_not_serde() {
        // Axis 4: status fields use Debug-formatted enum strings, NOT
        // serde rename. EntityType::Device is `#[serde(rename = "DEVICE")]`
        // and CryptoProfile::ProfileB is `#[serde(rename = "B")]`, but
        // the route uses `format!("{:?}", ...)` producing the Rust Debug
        // form "Device" / "ProfileB" (mixed case, full variant name).
        //
        // A refactor swapping `format!("{:?}", state.identity.entity_type)`
        // for either of:
        //   - `state.identity.entity_type.as_str()`          → "DEVICE" / "B"
        //   - `serde_json::to_value(&state.identity.entity_type)` → "DEVICE" / "B"
        // would change the wire string and break any operator dashboard
        // OR test fixture parsing the status field. This is the same
        // orthogonality class as the admin_sunset axis but on a
        // different enum pair, so a future "DRY the format strings"
        // refactor that touches both files would be caught by either test.
        let state = crate::network::state::build_test_node_state();
        let v = compute_node_identity_payload(&state);

        // build_test_node_state generates Device + ProfileB, so the Debug
        // form must surface as "Device" / "ProfileB".
        assert_eq!(
            v["entity_type"].as_str(),
            Some("Device"),
            "entity_type must be Debug-formatted 'Device' NOT serde 'DEVICE' — \
             refactor swapping format!(\"{{:?}}\", entity_type) for serde \
             would surface 'DEVICE' here",
        );
        assert_eq!(
            v["crypto_profile"].as_str(),
            Some("ProfileB"),
            "crypto_profile must be Debug-formatted 'ProfileB' NOT serde 'B' — \
             refactor swapping format!(\"{{:?}}\", profile) for serde \
             would surface 'B' here",
        );
        // Negative assertions: explicitly confirm the serde forms do NOT
        // appear. If a refactor switches to serde-based serialization,
        // these assertions fire even before the equality checks above.
        assert_ne!(
            v["entity_type"].as_str(), Some("DEVICE"),
            "entity_type must NOT be SCREAMING_SNAKE_CASE 'DEVICE' (serde \
             rename form) — Debug form 'Device' is the contract",
        );
        assert_ne!(
            v["crypto_profile"].as_str(), Some("B"),
            "crypto_profile must NOT be single-char 'B' (serde rename form) \
             — Debug form 'ProfileB' is the contract",
        );
        // Algorithm string is hard-coded "dilithium3" for ProfileB at
        // Identity::generate-time, NOT computed from CryptoProfile via
        // Debug or serde — pin it to defend against a refactor that
        // routes algorithm through CryptoProfile::Debug (would surface
        // as "ProfileB" instead of "dilithium3").
        assert_eq!(
            v["algorithm"].as_str(),
            Some("dilithium3"),
            "algorithm must be the literal 'dilithium3' string set by \
             Identity::generate for ProfileB, NOT derived from CryptoProfile",
        );
    }

    #[test]
    fn batch_aaaaa_has_pow_boolean_derives_from_pow_difficulty() {
        // Axis 5: has_pow boolean derives from pow_difficulty > 0.
        // Identity::generate creates an identity with pow_difficulty == 0
        // by default (no PoW challenge solved at generation time), so
        // has_pow must be false on a fresh identity. This pin defends a
        // refactor swapping `> 0` for `>= 0` (always true) or `!= 0`
        // (works for u8 but breaks if pow_difficulty ever becomes signed).
        //
        // To exercise the true branch we synthesize a second NodeState
        // and reach into its identity to set pow_difficulty to a positive
        // value — Identity is owned by NodeState (Arc<Identity> is not the
        // shape; NodeState owns Identity by value). We use a custom
        // builder that injects pow_difficulty before NodeState construction.
        let fresh_state = crate::network::state::build_test_node_state();
        let v_fresh = compute_node_identity_payload(&fresh_state);

        // pow_difficulty == 0 → has_pow == false on a freshly-generated
        // identity (no PoW solved).
        assert_eq!(
            v_fresh["pow_difficulty"].as_u64(),
            Some(0),
            "fresh Identity::generate must have pow_difficulty == 0",
        );
        assert_eq!(
            v_fresh["has_pow"].as_bool(),
            Some(false),
            "has_pow must be false when pow_difficulty == 0 — defends \
             refactor swapping `> 0` for `>= 0` (would always return true)",
        );

        // Synthesize a PoW-bearing identity via a custom NodeState build.
        // Identity::generate doesn't expose pow_difficulty injection, so
        // we construct a manual builder that overrides the field
        // post-generation (Identity is owned by value inside NodeState).
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let mut identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        identity.pow_difficulty = 24; // synthesized PoW level
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "batch-aaaaa-pow".into(),
            network_id: "batch-aaaaa-pow-net".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let rocks = Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let pow_state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
        std::mem::forget(tmp);
        let v_pow = compute_node_identity_payload(&pow_state);

        // pow_difficulty == 24 → has_pow == true. The exact integer
        // round-trips into u64.
        assert_eq!(
            v_pow["pow_difficulty"].as_u64(),
            Some(24),
            "pow_difficulty must round-trip the injected value 24 as u64",
        );
        assert_eq!(
            v_pow["has_pow"].as_bool(),
            Some(true),
            "has_pow must be true when pow_difficulty > 0 — defends \
             refactor hardcoding has_pow = false or swapping `> 0` for `< 0`",
        );
    }
}
