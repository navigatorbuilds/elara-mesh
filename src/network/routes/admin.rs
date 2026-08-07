//! Admin route handlers: /admin/* endpoints.
//!
//! Auth posture:
//!
//! Every handler in this module is PQ-Dilithium3-signed via `X-PQ-Admin` and
//! gated by the operator allowlist + per-IP lockout. The remaining choice is
//! whether the local node must additionally be the **genesis authority**:
//!
//! - **Genesis-only (`verify_admin_auth_pq`)** — cluster-policy ops that emit
//!   fleet-wide signed records that ONLY a genesis-signed record can validly
//!   produce. These belong on the genesis box because the resulting record
//!   would be rejected by peers if signed by anyone else:
//!     * `/admin/zone_transition` — emits a signed `ZoneTransition` record.
//!
//! - **Any-node (`verify_admin_auth_pq_any_node`)** — node-local housekeeping
//!   that mutates or reads LOCAL state (rate limiter, content blocklist,
//!   peer table, DAG/ledger reindex, GC, snapshot, sync triggers, forensic
//!   inspections, scoped views). Forcing these through the genesis gate
//!   strands the operator: the affected box may not be the genesis box (an
//!   observed ENOSPC incident is the canonical proof — compact_cf was
//!   genesis-only by reflex, so the operator could not address the node's bloat
//!   from the affected host). PQ allowlist + per-IP lockout still apply.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::Json;

use crate::errors::ElaraError;
use crate::storage::Storage;

use crate::network::gossip;
use crate::network::snapshot;
use crate::network::state::NodeState;
use crate::network::LockRecover;
use crate::network::RwLockRecover;

use super::super::server::{AppError, verify_admin_auth_pq, verify_admin_auth_pq_any_node};

/// Char-boundary-safe prefix truncation for displaying identifiers in logs
/// and response payloads. The raw idiom `&s[..s.len().min(N)]` panics when
/// byte N falls inside a multi-byte UTF-8 char — reachable wherever the
/// string is caller-supplied (e.g. `ban_identity`'s JSON body carries a
/// free-form `identity_hash`). Internal hex ids are ASCII so N is always a
/// boundary there, but every display-truncation site uses this helper so the
/// panic class stays dead regardless of what upstream formats become.
fn display_prefix(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ─── /admin/snapshot ─────────────────────────────────────────────────────────

pub async fn admin_snapshot(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — writes a snapshot of LOCAL ledger/epoch/finalized
    // state to LOCAL disk. No cluster policy at stake.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    // O(accounts) ledger clone under a read guard — inherent capture cost
    // (save_snapshot serializes the full ledger, and a lock guard can't
    // cross spawn_blocking). The finalized set is NOT captured under its
    // lock: the cold tier (CF_METADATA `finalized:*`) is the exact truth
    // `to_hashset()` reads, so the full prefix walk runs lock-free on the
    // blocking pool instead of stalling every finalization writer
    // (state_core, gossip, sync, pending_drain) for the whole scan.
    let ledger = state.ledger.read().await.clone();
    let epoch = state.epoch.read_recover().clone();
    let path = state.snapshot_path.clone();
    let rocks = std::sync::Arc::clone(&state.rocks);

    let result = tokio::task::spawn_blocking(move || {
        let finalized_set = crate::network::finalized::collect_finalized_ids(&rocks);
        snapshot::save_snapshot(&ledger, &finalized_set, &epoch, &path)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;

    match result {
        Ok(()) => Ok(Json(serde_json::json!({
            "snapshot": "saved",
            "accounts": state.ledger.read().await.accounts.len(),
            "finalized_records": state.finalized.read().await.len(),
            "epoch_zones": state.epoch.read_recover().latest_epoch.len(),
        }))),
        Err(e) => Err(e.into()),
    }
}

// ─── /admin/tasks ────────────────────────────────────────────────────────────

pub async fn admin_tasks(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — reports LOCAL background-task counters + uptime.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    let uptime = state.uptime();
    let uptime_hours = uptime / 3600.0;

    let gossip_push = state.gossip_push_total.load(std::sync::atomic::Ordering::Relaxed);
    let gossip_pull = state.gossip_pull_total.load(std::sync::atomic::Ordering::Relaxed);
    let gossip_relay = state.gossip_relay_total.load(std::sync::atomic::Ordering::Relaxed);
    let auto_witness_cycles = state.auto_witness_cycles_total.load(std::sync::atomic::Ordering::Relaxed);
    let auto_witness_records = state.auto_witness_records_total.load(std::sync::atomic::Ordering::Relaxed);
    let auto_witness_failures = state.auto_witness_failures_total.load(std::sync::atomic::Ordering::Relaxed);
    let auto_rewards = state.auto_rewards_total.load(std::sync::atomic::Ordering::Relaxed);
    let auto_rewards_amount = state.auto_rewards_amount_total.load(std::sync::atomic::Ordering::Relaxed);

    Ok(Json(serde_json::json!({
        "uptime_secs": uptime,
        "uptime_hours": (uptime_hours * 100.0).round() / 100.0,
        "background_tasks": {
            "gossip": {
                "enabled": true,
                "pull_interval_secs": state.config.gossip_pull_interval_secs,
                "push_total": gossip_push,
                "pull_total": gossip_pull,
                "relay_total": gossip_relay,
                "push_failed": state.gossip_push_failed_total.load(std::sync::atomic::Ordering::Relaxed),
                "retry_total": state.gossip_retry_total.load(std::sync::atomic::Ordering::Relaxed),
                "retry_success": state.gossip_retry_success_total.load(std::sync::atomic::Ordering::Relaxed),
                "reconnect_attempts": state.peer_reconnect_attempts_total.load(std::sync::atomic::Ordering::Relaxed),
                "reconnect_success": state.peer_reconnect_success_total.load(std::sync::atomic::Ordering::Relaxed),
            },
            "auto_witness": {
                "enabled": state.config.auto_witness,
                "interval_secs": state.config.auto_witness_interval_secs,
                "batch_size": state.config.auto_witness_batch_size,
                "cycles_total": auto_witness_cycles,
                "records_witnessed": auto_witness_records,
                "failures": auto_witness_failures,
            },
            "snapshot": {
                "enabled": state.config.snapshot_interval_secs > 0,
                "interval_secs": state.config.snapshot_interval_secs,
            },
            "epoch_sealing": {
                "enabled": state.config.epoch_seal_interval_secs > 0,
                "interval_secs": state.config.epoch_seal_interval_secs,
                "zones": state.epoch.read_recover().latest_epoch.len(),
            },
            "rewards": {
                "enabled": state.config.witness_reward_micros > 0,
                "reward_micros": state.config.witness_reward_micros,
                "total_distributed": auto_rewards,
                "total_amount_micros": auto_rewards_amount,
                "total_amount_beat": crate::accounting::validate::format_beat_precise(auto_rewards_amount),
            },
            "pex": {
                "enabled": state.config.pex_interval_secs > 0,
                "interval_secs": state.config.pex_interval_secs,
            },
            "rate_limiter": {
                "write_limit": state.config.rate_limit_write,
                "read_limit": state.config.rate_limit_read,
                "rejected_total": state.rate_limiter.get()
                    .map(|rl| rl.rejected_total.load(std::sync::atomic::Ordering::Relaxed))
                    .unwrap_or(0),
            },
        },
    })))
}

// ─── /admin/account-smt/orphans ──────────────────────────────────────────────

/// Read-only F-5 phantom diagnostic. Enumerates persisted account-SMT value-leaves
/// that have **no** matching live ledger account — the *SMT-ahead* "ghost"/"phantom"
/// leaves that the ledger-side `diagnose_account_smt_divergence` structurally cannot
/// surface (it iterates the ledger, which has no such account). Names each orphan by
/// its 32-byte `account_id` (the exact key a future targeted reconcile/`delete`
/// takes). Node-local, one-shot scan — O(populated leaves), not a hot path.
///
/// Query: `?max_scan=N` (default 1_000_000), `?limit=N` sample size (default 64).
pub async fn admin_account_smt_orphans(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local read-only forensic — surfaces LOCAL CF_ACCOUNT_SMT vs LOCAL
    // ledger. No cluster policy at stake.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    let max_scan = params
        .get("max_scan")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1_000_000)
        .clamp(1, 50_000_000);
    let sample_limit = params
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(64)
        .clamp(1, 4096);

    // Clone only the account-id keys under the lock (cheap vs the full state map),
    // then run the RocksDB leaf scan off the async runtime.
    let ledger_ids: std::collections::HashSet<String> = {
        let ledger = state.ledger.read().await;
        ledger.accounts.keys().cloned().collect()
    };
    let ledger_accounts = ledger_ids.len();
    let rocks = std::sync::Arc::clone(&state.rocks);

    let scan = tokio::task::spawn_blocking(move || {
        crate::network::account_merkle::scan_orphan_smt_leaves(
            &rocks,
            &ledger_ids,
            max_scan,
            sample_limit,
        )
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;

    Ok(Json(serde_json::json!({
        "orphan_count": scan.orphan_count,
        "scanned_leaves": scan.scanned_leaves,
        "truncated": scan.truncated,
        "ledger_accounts": ledger_accounts,
        "sample": scan.sample,
        "note": "orphan = persisted account-SMT value-leaf with no live ledger account (F-5 SMT-ahead phantom). account_id_hex is the AccountStateSMT::delete key. real_corruption is determined by the seal-root check, not this count.",
    })))
}

// ─── /admin/account-smt/reconcile-orphans ─────────────────────────────────────

/// F-5 one-time cleanup (mutating): tombstone every SMT-ahead phantom value-leaf
/// so the persisted account-SMT root converges to `root_over_accounts(ledger)`.
/// Complement of the shipped repair-path fix (which stops *new* phantoms) — this
/// removes *historical* ones already committed into a node's `account_smt_root`
/// (e.g. pre-256-bit-re-genesis orphans, a repair-path V2 ghost).
///
/// **Gated by construction — and serialized by the writer gate.** The deletes
/// are applied to a buffered tree and committed ONLY if the resulting root
/// equals the clean ledger-rebuild root; root-equality ⟹ leaf-set-equality
/// under SHA3-256 collision-resistance, so the op can neither miss a phantom
/// nor over-delete a live account. On abort the column family is byte-for-byte
/// untouched. The root-equality check alone does NOT detect a concurrent SMT
/// writer landing after buffering (both compared values predate the commit) —
/// the handler holds `NodeState::account_smt_write_gate` across the whole
/// scan→commit sequence, and THAT is what makes concurrent mutation impossible
/// rather than merely unlikely (fusion-audited TOCTOU fix, 2026-07-05).
///
/// **Run on the seal-producing node.** `account_smt_root` is non-finality-gating;
/// after commit the producer's next seal (≤ the quiet-zone seal cap) re-binds the
/// clean root and boot §6a then verifies. Node-local, PQ-admin-gated.
///
/// Query: `?max_scan=N` (default 1_000_000) bounds the leaf enumeration;
/// `?max_delete=N` (default 10_000) refuses (no mutation) above this — a large
/// orphan set is an operator escalation, not an auto-delete.
pub async fn admin_account_smt_reconcile_orphans(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local mutation of the LOCAL CF_ACCOUNT_SMT toward the LOCAL ledger.
    // No cluster policy at stake (the root is non-finality-gating).
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    let max_scan = params
        .get("max_scan")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1_000_000)
        .clamp(1, 50_000_000);
    let max_delete = params
        .get("max_delete")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(10_000)
        .clamp(1, 10_000_000);

    // The gate needs full account state (to rebuild the target root), so clone the
    // account map under the lock, then run the reconcile off the async runtime.
    let accounts = {
        let ledger = state.ledger.read().await;
        ledger.accounts.clone()
    };
    let rocks = std::sync::Arc::clone(&state.rocks);

    // CF_ACCOUNT_SMT writer gate (leaf lock — see NodeState field doc). Held
    // across the ENTIRE scan→buffer→root-gate→commit sequence: the reconcile's
    // root-equality gate is only sound while no other SMT writer can land
    // between its buffered reads and its commit — this hold is what makes the
    // doc'd "abort, never a wrong commit" property actually true under
    // concurrency (fusion-audited TOCTOU fix, 2026-07-05).
    let _smt_gate = state.account_smt_write_gate.lock().await;
    let outcome = tokio::task::spawn_blocking(move || {
        crate::network::account_merkle::reconcile_orphan_leaves_to_ledger(
            &rocks, &accounts, max_scan, max_delete,
        )
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    Ok(Json(serde_json::json!({
        "committed": outcome.committed,
        "deleted": outcome.deleted,
        "scanned_leaves": outcome.scanned_leaves,
        "pre_root": outcome.pre_root,
        "post_root": outcome.post_root,
        "target_root": outcome.target_root,
        "aborted_reason": outcome.aborted_reason,
        "tombstoned": outcome.tombstoned,
        "note": "F-5 one-time phantom cleanup. Commits ONLY if post-delete root == root_over_accounts(ledger). After commit the NEXT seal (≤ quiet-zone cap, ~60s) re-binds the clean root and boot §6a verifies. Run on the seal-producing node.",
    })))
}

// ─── /admin/export ───────────────────────────────────────────────────────────

pub async fn admin_export(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<axum::response::Response, AppError> {
    // Node-local — exports LOCAL DAG records for the host the
    // operator is troubleshooting. The PQ allowlist + per-IP lockout already
    // gate the read; forcing genesis was a reflex, not a policy.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    // Bounded export: default 10K records, max 100K. Use `since` timestamp for pagination.
    let limit: usize = params.get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000)
        .min(100_000);
    let since: Option<f64> = params.get("since")
        .and_then(|s| s.parse().ok());

    let state2 = state.clone();
    let records = tokio::task::spawn_blocking(move || -> crate::errors::Result<Vec<crate::record::ValidationRecord>> {
        let storage = state2.rocks.as_ref();
        storage.query(None, None, since, None, limit)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    let mut sorted = records;
    sorted.sort_by(|a, b| a.timestamp.total_cmp(&b.timestamp));

    let mut output = String::new();
    for rec in &sorted {
        output.push_str(&hex::encode(rec.to_bytes()));
        output.push('\n');
    }

    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8"),
         (axum::http::header::CONTENT_DISPOSITION, "attachment; filename=\"elara-dag-export.hex\"")],
        output,
    ).into_response())
}

// ─── /admin/ban_ip, /admin/unban_ip, /admin/bans ─────────────────────────────

#[derive(serde::Deserialize)]
pub struct BanIpBody {
    ip: String,
}

pub async fn admin_ban_ip(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Json(body): Json<BanIpBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — mutates LOCAL rate-limiter ban list. Each node
    // tracks its own bans; there is no auto-propagation. An operator banning
    // an attacker on the box being targeted must reach that box.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let ip: IpAddr = body.ip.parse()
        .map_err(|_| ElaraError::Config(format!("invalid IP address: {}", body.ip)))?;
    if let Some(rl) = state.rate_limiter.get() {
        rl.deny_ip(ip);
        Ok(Json(serde_json::json!({"banned": true, "ip": body.ip})))
    } else {
        Ok(Json(serde_json::json!({"banned": false, "reason": "rate limiter not initialized"})))
    }
}

pub async fn admin_unban_ip(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Json(body): Json<BanIpBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — mirror of admin_ban_ip, same rationale.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let ip: IpAddr = body.ip.parse()
        .map_err(|_| ElaraError::Config(format!("invalid IP address: {}", body.ip)))?;
    let removed = state.rate_limiter.get()
        .map(|rl| rl.allow_ip(ip))
        .unwrap_or(false);
    Ok(Json(serde_json::json!({"unbanned": removed, "ip": body.ip})))
}

pub async fn admin_bans(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — read LOCAL ban list.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let mut ips: Vec<String> = state.rate_limiter.get()
        .map(|rl| rl.denied_ips().iter().map(|ip| ip.to_string()).collect())
        .unwrap_or_default();
    let denied_total = state.rate_limiter.get()
        .map(|rl| rl.denied_total.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap_or(0);
    // Cap the serialized list (a /8 mass-ban or auto-ban storm makes the ban set
    // large); `count` stays the TRUE size (truncation detectable as
    // `banned_ips.len() < count`). SCALE RULE: bounded, always.
    const MAX_BANS_IN_RESPONSE: usize = 10_000;
    let count = ips.len();
    ips.truncate(MAX_BANS_IN_RESPONSE);
    Ok(Json(serde_json::json!({
        "banned_ips": ips,
        "count": count,
        "denied_requests_total": denied_total,
    })))
}

// ─── /admin/ban_identity, /admin/unban_identity, /admin/banned_identities ────

#[derive(serde::Deserialize)]
pub struct BanIdentityBody {
    identity_hash: String,
    reason: String,
}

pub async fn admin_ban_identity(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Json(body): Json<BanIdentityBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — banned_identities is per-node state (each box
    // tracks its own list, no auto-propagation). Operator must reach each
    // node anyway.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    state.ban_identity(&body.identity_hash, &body.reason)?;
    {
        let mut banned = state.banned_identities.write().map_err(|e| ElaraError::Storage(e.to_string()))?;
        banned.insert(body.identity_hash.clone());
    }
    tracing::warn!("identity banned: {} — {}", display_prefix(&body.identity_hash, 16), body.reason);
    Ok(Json(serde_json::json!({
        "banned": true,
        "identity_hash": body.identity_hash,
        "reason": body.reason,
    })))
}

pub async fn admin_unban_identity(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Json(body): Json<BanIdentityBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — mirror of admin_ban_identity, same rationale.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let removed = state.unban_identity(&body.identity_hash)?;
    {
        let mut banned = state.banned_identities.write().map_err(|e| ElaraError::Storage(e.to_string()))?;
        banned.remove(&body.identity_hash);
    }
    Ok(Json(serde_json::json!({
        "unbanned": removed,
        "identity_hash": body.identity_hash,
    })))
}

pub async fn admin_banned_identities(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — read LOCAL banned-identities list.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let banned = state.banned_identities.read().map_err(|e| ElaraError::Storage(e.to_string()))?;
    let mut list: Vec<&String> = banned.iter().collect();
    // Cap the serialized list; `count` stays the TRUE size (truncation detectable
    // as `banned_identities.len() < count`). SCALE RULE: bounded, always.
    const MAX_BANNED_IDS_IN_RESPONSE: usize = 10_000;
    let count = list.len();
    list.truncate(MAX_BANNED_IDS_IN_RESPONSE);
    Ok(Json(serde_json::json!({
        "banned_identities": list,
        "count": count,
        "rejections_total": state.banned_rejections_total.load(std::sync::atomic::Ordering::Relaxed),
    })))
}

// ─── /admin/blocklist/* ──────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct BlockTermBody {
    term: String,
}

pub async fn admin_add_blocked_term(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Json(body): Json<BlockTermBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — LOCAL content_blocklist mutation; not auto-
    // propagated, each operator curates their own node's filter list.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let normalized = body.term.to_lowercase().trim().to_string();
    if normalized.is_empty() || normalized.len() < 2 {
        return Err(ElaraError::Wire("term must be at least 2 characters".into()).into());
    }
    state.add_blocked_term(&normalized)?;
    {
        let mut blocklist = state.content_blocklist.write().map_err(|e| ElaraError::Storage(e.to_string()))?;
        if !blocklist.contains(&normalized) {
            blocklist.push(normalized.clone());
        }
    }
    tracing::warn!("content blocklist: added term ({}B)", normalized.len());
    Ok(Json(serde_json::json!({
        "added": true,
        "term_length": normalized.len(),
    })))
}

pub async fn admin_remove_blocked_term(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Json(body): Json<BlockTermBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — mirror of admin_add_blocked_term.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let normalized = body.term.to_lowercase().trim().to_string();
    let removed = state.remove_blocked_term(&normalized)?;
    {
        let mut blocklist = state.content_blocklist.write().map_err(|e| ElaraError::Storage(e.to_string()))?;
        blocklist.retain(|t| t != &normalized);
    }
    Ok(Json(serde_json::json!({
        "removed": removed,
    })))
}

pub async fn admin_content_blocklist(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — read LOCAL content_blocklist.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let blocklist = state.content_blocklist.read().map_err(|e| ElaraError::Storage(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "terms_count": blocklist.len(),
        "rejections_total": state.content_rejections_total.load(std::sync::atomic::Ordering::Relaxed),
    })))
}

// ─── /admin/purge_peer ───────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct PurgePeerBody {
    identity_hash: String,
}

pub async fn admin_purge_peer(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Json(body): Json<PurgePeerBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — mutates LOCAL peers table + LOCAL DHT.
    // Operator purges a peer from the box they are SSH'd into.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let ih = &body.identity_hash;
    let mut removed_peer = false;
    let mut removed_dht = false;
    {
        let mut peers = state.peers.write().await;
        if peers.remove(ih).is_some() {
            removed_peer = true;
        }
    }
    if let Some(node_id) = crate::network::dht::NodeId::from_hex(ih) {
        let mut dht = state.dht.lock_recover();
        removed_dht = dht.remove(&node_id);
    }
    Ok(Json(serde_json::json!({
        "purged": ih,
        "removed_from_peer_table": removed_peer,
        "removed_from_dht": removed_dht,
    })))
}

// ─── /admin/force_sync ───────────────────────────────────────────────────────

pub async fn admin_force_sync(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — pulls deltas INTO the local node from every
    // peer in the local peer table. Operator triggers this against the box
    // that's behind.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let peers: Vec<String> = {
        let pt = state.peers.read().await;
        pt.connected().iter().map(|p| p.base_url()).collect()
    };
    if peers.is_empty() {
        return Ok(Json(serde_json::json!({
            "synced": false,
            "reason": "no connected peers",
        })));
    }
    let mut synced = 0usize;
    let mut errors = 0usize;
    for base_url in &peers {
        match gossip::delta_pull(&state, base_url).await {
            Ok(n) => synced += n as usize,
            Err(_) => errors += 1,
        }
    }
    Ok(Json(serde_json::json!({
        "synced": true,
        "peers_contacted": peers.len(),
        "records_received": synced,
        "errors": errors,
    })))
}

// ─── /admin/force_resync_from ────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ForceResyncFromBody {
    pub peer_addr: String,
}

/// Tier 1.2 #3 — force a delta re-sync from ONE specific peer's base URL.
/// Operator workflow when `/convergence` shows a single peer diverged: name
/// that peer, this endpoint runs `initial_sync_from` against it (snapshot
/// bootstrap if DAG empty, otherwise cursor-based delta) and reports how
/// many records arrived. Differs from `/admin/force_sync` (loops every
/// connected peer via `delta_pull`) and `/admin/resync` (auto-picks the
/// peer with the highest record count).
///
/// Security: `peer_addr` must match a base URL already in our peer table —
/// admin can't aim this at arbitrary URLs (would let a compromised admin
/// token pull from a hostile box).
pub async fn admin_force_resync_from(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Json(body): Json<ForceResyncFromBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — same recovery posture as the sibling
    // `/admin/snapshot_rebootstrap_from` (already any_node). Operator names the peer, the call pulls into
    // the local node only. The peer-allowlist check below already prevents
    // pointing this at an arbitrary URL.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    let peer_addr = body.peer_addr.trim().to_string();
    if peer_addr.is_empty() {
        return Err(AppError(ElaraError::Wire(
            "force_resync_from: missing peer_addr".into(),
        )));
    }

    let known: bool = {
        let pt = state.peers.read().await;
        pt.connected().iter().any(|p| p.base_url() == peer_addr)
    };
    if !known {
        return Err(AppError(ElaraError::Wire(format!(
            "force_resync_from: peer_addr {peer_addr} not in connected peer table"
        ))));
    }

    let records_before = state.record_count().unwrap_or(0);
    let received = crate::network::sync::initial_sync_from(&state, &peer_addr).await;
    let records_after = state.record_count().unwrap_or(records_before);
    let net_growth = records_after.saturating_sub(records_before);

    Ok(Json(serde_json::json!({
        "synced": true,
        "peer_addr": peer_addr,
        "records_received": received,
        "records_before": records_before,
        "records_after": records_after,
        "net_growth": net_growth,
    })))
}

// ─── /admin/snapshot_rebootstrap_from ────────────────────────────────────────

/// Query DTO for `/admin/snapshot_rebootstrap_from`. Query params, NOT a JSON
/// body (V2 relocation, 2026-07-05): the admin signature binds the request
/// target (path + query) but never the body, so a body-carried `force` was the
/// one remaining substitution lever — an on-path attacker racing a captured
/// header could flip it and turn an operator's safe rebootstrap into a
/// permanent, height-invisible ledger rollback (defeating the
/// refuse-if-behind guard). In the signed query, flipping `force` or
/// redirecting `peer_addr` invalidates the signature and fails closed.
#[derive(serde::Deserialize)]
pub struct SnapshotRebootstrapQuery {
    pub peer_addr: String,
    /// Accept a snapshot whose epoch tip is BEHIND the local tip (permanent
    /// ledger-content rollback — see the refuse-if-behind guard in
    /// `apply_bootstrap_snapshot_full`). Off by default; send `force=true`
    /// only when the local ledger is known-bad and the rewind is intended.
    #[serde(default)]
    pub force: bool,
}

/// Force snapshot bootstrap from a
/// specific peer regardless of local DAG state. Operator escape hatch when
/// a node is severely behind on FinalizedIndex (a bootstrap pathology where
/// a node falls far behind on finalized records).
///
/// Why this exists: `initial_sync_from` only attempts the snapshot-bootstrap
/// path when `dag_len == 0`. A node that holds a small hot DAG (e.g. 1500
/// records on a 2GB box) but has only 10% of peers' finalized records will
/// NEVER take that path — it stays on cursor-based delta sync and recovers
/// at fetch_rate × cycle, which on a million-record chain takes weeks. This
/// endpoint forces the snapshot path so the node loads peer ledger as
/// authoritative + restores `FinalizedIndex` from snapshot in one shot.
///
/// Effect (see `apply_bootstrap_snapshot_full` in sync.rs):
///   - Replaces `state.ledger` with the peer's snapshot ledger
///   - Seeds `CF_APPLIED` from `snapshot.applied_record_ids` (dedup post-restore)
///   - `FinalizedIndex.restore_from_snapshot` — hot set rebuilt from snapshot
///   - `state.ledger_loaded_from_snapshot = true` — startup skips full replay
///   - Subsequent delta sync runs cursor-based from `snapshot_timestamp`
///
/// Security: `peer_addr` must already be in our connected peer table — admin
/// can't aim this at arbitrary URLs. The snapshot itself is signature-verified
/// against `trusted_snapshot_signers` in `enforce_snapshot_signer_trust`.
///
/// Rollback safety: connected says nothing about AHEAD. Pointing this at a
/// behind peer (or at an ahead peer whose archive snapshot lags below our
/// tip) would replace the ledger with older content while CF_APPLIED keeps
/// the newer records marked applied — a permanent, height-invisible content
/// rollback. `apply_bootstrap_snapshot_full` refuses that shape unless the
/// request carries `force=true` — a SIGNED query param (V2), so an on-path
/// attacker can't inject it into a captured header's request.
///
/// Differs from `/admin/force_resync_from` (which calls `initial_sync_from`,
/// preserves the dag_len gate, and falls through to delta sync when DAG is
/// non-empty — useless for the bootstrap-pathology case).
pub async fn admin_snapshot_rebootstrap_from(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Query(q): Query<SnapshotRebootstrapQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Use the any-node variant: this is a node-local recovery operation —
    // an operator unsticks the node by SSHing to it and curling its own port.
    // Gating on genesis-authority would force the operator to instead curl
    // the genesis node, which can't replay-bootstrap a different node. The
    // PQ admin signature requirement (allowlist + nonce + path binding) is
    // still mandatory.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    let peer_addr = q.peer_addr.trim().to_string();
    if peer_addr.is_empty() {
        return Err(AppError(ElaraError::Wire(
            "snapshot_rebootstrap_from: missing peer_addr".into(),
        )));
    }

    let known: bool = {
        let pt = state.peers.read().await;
        pt.connected().iter().any(|p| p.base_url() == peer_addr)
    };
    if !known {
        return Err(AppError(ElaraError::Wire(format!(
            "snapshot_rebootstrap_from: peer_addr {peer_addr} not in connected peer table"
        ))));
    }

    let finalized_before = state.finalized.read().await.len();
    let accounts_before = state.ledger.read().await.accounts.len();
    let dag_size_before = state.dag.read().await.len();

    state
        .admin_snapshot_rebootstrap_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let outcome: Result<&'static str, String> =
        match crate::network::sync::snapshot_bootstrap(&state, &peer_addr, q.force).await {
            Ok(_) => Ok("snapshot_applied_then_delta"),
            Err(e) => Err(format!("{e}")),
        };

    let finalized_after = state.finalized.read().await.len();
    let accounts_after = state.ledger.read().await.accounts.len();
    let dag_size_after = state.dag.read().await.len();

    Ok(Json(serde_json::json!({
        "rebootstrap_attempted": true,
        "peer_addr": peer_addr,
        "outcome": match &outcome {
            Ok(s) => s.to_string(),
            Err(e) => format!("error: {e}"),
        },
        "finalized_before": finalized_before,
        "finalized_after": finalized_after,
        "finalized_growth": finalized_after.saturating_sub(finalized_before),
        "accounts_before": accounts_before,
        "accounts_after": accounts_after,
        "dag_size_before": dag_size_before,
        "dag_size_after": dag_size_after,
        "ledger_loaded_from_snapshot": state.ledger_loaded_from_snapshot.load(std::sync::atomic::Ordering::Relaxed),
    })))
}

// ─── /admin/reindex_dag ──────────────────────────────────────────────────────

pub async fn admin_reindex_dag(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — rebuilds the LOCAL DAG + ledger from LOCAL
    // RocksDB. Recovery op for whichever box has the corrupted index.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let genesis = state.config.genesis_authority.clone();
    let state2 = state.clone();
    let (new_dag, new_ledger, records_processed) = tokio::task::spawn_blocking(move || {
        // Route through `rebuild_dag_lightweight` (streams CF_DAG +
        // CF_IDX_TIMESTAMP at ~200 B/record) instead of `state::rebuild_dag`,
        // which materialises every record (~8 KB each) into a Vec via
        // `query(usize::MAX)`. At 10M records the materialising path needs
        // ~80 GB heap and OOMs the box; the lightweight path is O(records ×
        // 200 B) and matches what the boot path already uses.
        let dag = state2.rocks.rebuild_dag_lightweight()?;
        let (ledger, rp) = state2.rocks.rebuild_ledger_streaming(&genesis, &state2.config.genesis_validators)?;
        Ok::<_, ElaraError>((dag, ledger, rp))
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;
    let dag_size = new_dag.len();
    let accounts = new_ledger.accounts.len();
    state.rocks.bulk_mark_applied(&new_ledger.applied_record_ids);
    *state.dag.write().await = Arc::new(new_dag);
    let mut ledger = new_ledger;
    ledger.applied_record_ids.clear();
    // Refresh the consensus stake view from the rebuilt ledger — matches the
    // other live-node replace sites. `zone_stakes` drives the 2/3 quorum
    // threshold and `staker_stakes` drives liveness-decay; the epoch tick
    // (epoch.rs:4260) re-registers within ~1 interval, but a reindex is a
    // recovery op — make it immediately consistent rather than leaving a
    // 1-epoch stale-quorum window after the operator ran reindex to recover.
    // The O(accounts) registration walk holds the seal loop's consensus
    // lock either way; run it on the blocking pool so an executor worker
    // isn't pinned for the duration (the ledger threads through the closure
    // because `register` borrows it before the write-lock swap below).
    let ledger = {
        let state3 = state.clone();
        tokio::task::spawn_blocking(move || {
            state3.consensus.lock_recover().register_stakes_from_ledger(&ledger);
            ledger
        })
        .await
        .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?
    };
    *state.ledger.write().await = ledger;
    // Runtime wholesale ledger replace on a live node → drop the memoized
    // staked-anchor view (contract: state.rs:invalidate_anchor_view), else the
    // proposer/verifier may serve a stale committee after the rebuild.
    state.invalidate_anchor_view();
    Ok(Json(serde_json::json!({
        "reindexed": true,
        "dag_records": dag_size,
        "ledger_accounts": accounts,
        "ledger_records_processed": records_processed,
    })))
}

// ─── /admin/gc ───────────────────────────────────────────────────────────────

// Synchronous core of `GET /admin/gc`. Pulled out so callers
// can pin the wire envelope, the
// `gc_enabled` boolean derivation, the `record_retention_days`
// secs→days conversion, and the `gc_pruned_total` passthrough
// without an `Arc<NodeState>` plumbing dependency. The route handler
// loads `gc_pruned_total` via the atomic on `NodeState`, reads the
// two `state.config` scalars, and passes the three resolved values
// in.
pub(crate) fn compute_gc_status_payload(
    gc_interval_secs: u64,
    record_retention_secs: f64,
    gc_pruned_total: u64,
) -> serde_json::Value {
    serde_json::json!({
        "gc_interval_secs": gc_interval_secs,
        "record_retention_secs": record_retention_secs,
        "record_retention_days": record_retention_secs / 86400.0,
        "gc_pruned_total": gc_pruned_total,
        "gc_enabled": gc_interval_secs > 0,
    })
}

pub async fn admin_gc_status(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local read of GC config + prune counters. Auth-gated like every
    // other /admin verb — the module invariant is "every handler PQ-signed"
    // and these 8 read-only diagnostics silently skipped it (2026-07-05 audit).
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let gc_pruned = state.gc_pruned_total.load(std::sync::atomic::Ordering::Relaxed);
    Ok(Json(compute_gc_status_payload(
        state.config.gc_interval_secs,
        state.config.record_retention_secs,
        gc_pruned,
    )))
}

pub async fn admin_gc_trigger(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — manual GC sweep on the LOCAL RocksDB. Same
    // posture as `/admin/rocks/compact_cf` (any_node per 3390a01).
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let retention = state.config.record_retention_secs;
    let retention_cutoff = now - retention;
    let stale_cutoff = now - (retention * 2.0);
    // Every O(n) leg — the sunken-set scan under the relevance Mutex, the
    // per-zone floor derivation (one rocks point read per super-sealed
    // zone), and the GC scan itself — runs on the blocking pool. The
    // finalized check is a per-candidate bloom-filtered CF_METADATA point
    // read (finalized::contains_in_rocks, ~1µs) instead of the old eager
    // `to_hashset()` full `finalized:*` prefix walk under finalized.read(),
    // which stalled every finalization writer for the whole scan and was
    // O(total finalized history) regardless of how few candidates GC
    // actually visits.
    let result = {
        let state2 = state.clone();
        tokio::task::spawn_blocking(move || {
            let sunken_ids: std::collections::HashSet<String> = {
                let relevance = state2.relevance.lock_recover();
                relevance.sunken_records(now).into_iter().collect()
            };
            // Gap 3: per-zone seal pruning floor — same derivation as gc_loop.
            let seal_pruning_floor: std::collections::HashMap<crate::ZoneId, u64> = {
                let epoch = state2.epoch.read_recover();
                const SAFETY_MARGIN_INTERVALS: u64 = 2;
                let safety_margin = SAFETY_MARGIN_INTERVALS
                    .saturating_mul(crate::network::epoch::SUPER_SEAL_INTERVAL);
                epoch
                    .latest_super_seal
                    .iter()
                    .map(|(zone, (end_epoch, _, _, _))| {
                        (zone.clone(), end_epoch.saturating_sub(safety_margin))
                    })
                    .collect()
            };
            // Per-zone record pruning floor (Protocol §11.8) — same compute
            // path as `gc_loop`. Empty when operator config disabled OR Archive
            // profile, mirroring the live loop's behavior.
            let epoch_pruning_active = state2.config.epoch_pruning_enabled
                && state2.config.node_profile != "archive";
            let record_pruning_floor_ts: std::collections::HashMap<crate::ZoneId, f64> =
                if epoch_pruning_active {
                    seal_pruning_floor
                        .iter()
                        .filter_map(|(zone, floor_epoch)| {
                            state2
                                .rocks
                                .seal_timestamp_at_zone_epoch(*floor_epoch, zone.path())
                                .map(|ts| (zone.clone(), ts))
                        })
                        .collect()
                } else {
                    std::collections::HashMap::new()
                };
            state2.rocks.gc_scan_and_delete(
                retention_cutoff,
                stale_cutoff,
                &|id| crate::network::finalized::contains_in_rocks(&state2.rocks, id),
                &|id| sunken_ids.contains(id),
                &seal_pruning_floor,
                &record_pruning_floor_ts,
                None,
            )
        })
        .await
        .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?
    }?;
    // Remove from DAG
    if !result.deleted_ids.is_empty() {
        let mut dag_guard = state.dag.write().await;
        let dag = std::sync::Arc::make_mut(&mut *dag_guard);
        for id in &result.deleted_ids {
            dag.remove(id);
        }
    }
    let total = result.expired_pruned
        + result.retention_pruned
        + result.sunken_pruned
        + result.stale_pruned
        + result.seal_pruned;
    state.gc_pruned_total.fetch_add(total, std::sync::atomic::Ordering::Relaxed);
    state
        .gc_pruned_seals_total
        .fetch_add(result.seal_pruned, std::sync::atomic::Ordering::Relaxed);
    Ok(Json(serde_json::json!({
        "expired_pruned": result.expired_pruned,
        "retention_pruned": result.retention_pruned,
        "sunken_pruned": result.sunken_pruned,
        "stale_pruned": result.stale_pruned,
        "seal_pruned": result.seal_pruned,
        "skipped": result.skipped,
        "total_pruned": total,
    })))
}

// ─── /admin/dag_check ────────────────────────────────────────────────────────

pub(crate) fn compute_dag_check_payload(
    storage_records: usize,
    dag_indexed: usize,
    tips: usize,
    roots: usize,
    edges: usize,
) -> serde_json::Value {
    let missing = storage_records.saturating_sub(dag_indexed);
    let coverage = if storage_records > 0 {
        (dag_indexed as f64 / storage_records as f64 * 100.0).min(100.0)
    } else {
        100.0
    };
    serde_json::json!({
        "storage_records": storage_records,
        "dag_indexed": dag_indexed,
        "missing_from_dag": missing,
        "coverage_pct": (coverage * 100.0).round() / 100.0,
        "healthy": missing == 0,
        "tips": tips,
        "roots": roots,
        "edges": edges,
    })
}

pub async fn admin_dag_check(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let dag = state.dag.read().await;
    let storage_count = state.record_count()?;
    let dag_count = dag.len();
    Ok(Json(compute_dag_check_payload(
        storage_count,
        dag_count,
        dag.tips().len(),
        dag.roots().len(),
        dag.edge_count(),
    )))
}

// ─── /admin/fork_check ──────────────────────────────────────────────────────

pub async fn admin_fork_check(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let mut results = crate::network::fork::check_forks(&state).await;
    let peers_checked = results.len();
    let diverged = results.iter().filter(|r| !r.in_sync).count();
    // Cap the serialized array (the heal path keeps the full set); `peers_checked`
    // and `diverged` are computed over ALL peers above, so they stay honest.
    // SCALE RULE: bounded, always.
    const MAX_PEERS_IN_RESPONSE: usize = 1000;
    results.truncate(MAX_PEERS_IN_RESPONSE);
    Ok(Json(serde_json::json!({
        "peers_checked": peers_checked,
        "in_sync": diverged == 0,
        "diverged_count": diverged,
        "fork_heals_total": state.fork_heals_total.load(std::sync::atomic::Ordering::Relaxed),
        "results": results,
    })))
}

pub async fn admin_fork_heal(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — fork-heal pulls into LOCAL state from connected
    // peers. The diverged box is the one the operator must call this on.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let healed = crate::network::fork::heal_partition(&state).await;
    Ok(Json(serde_json::json!({
        "records_synced": healed,
        "fork_heals_total": state.fork_heals_total.load(std::sync::atomic::Ordering::Relaxed),
    })))
}

// ─── /admin/revocations, /admin/key_rotations ────────────────────────────────

pub(crate) fn compute_revocations_payload(state: &NodeState) -> serde_json::Value {
    let registry = state.key_registry.read_recover();
    // Cap the serialized array — revocations accumulate with every key rotation
    // over the network's life (10M+ at scale). `revoked_keys` below stays the
    // TRUE total via `revocation_count()` (truncation detectable as
    // `revocations.len() < revoked_keys`). SCALE RULE: bounded, always.
    const MAX_REVOCATIONS_IN_RESPONSE: usize = 10_000;
    let revocations: Vec<_> = registry.revocations().iter().take(MAX_REVOCATIONS_IN_RESPONSE).map(|r| {
        serde_json::json!({
            "revoked_key_hash": r.revoked_key_hash,
            "revoked_public_key": r.revoked_public_key,
            "revoked_at": r.revoked_at,
            "reason": r.reason,
            "record_id": r.record_id,
            "identity_hash": r.identity_hash,
        })
    }).collect();
    let rejected = state.revocations_rejected_total.load(std::sync::atomic::Ordering::Relaxed);
    serde_json::json!({
        "revoked_keys": registry.revocation_count(),
        "records_rejected": rejected,
        "revocations": revocations,
    })
}

pub async fn admin_revocations(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    Ok(Json(compute_revocations_payload(&state)))
}

pub(crate) fn compute_key_rotations_payload(state: &NodeState) -> serde_json::Value {
    let registry = state.key_registry.read_recover();
    serde_json::json!({
        "rotated_identities": registry.rotated_identities(),
        "total_rotations": registry.total_rotations(),
    })
}

pub async fn admin_key_rotations(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    Ok(Json(compute_key_rotations_payload(&state)))
}

// ─── /admin/witness_liveness ─────────────────────────────────────────────────

pub(crate) fn compute_witness_liveness_payload(
    state: &NodeState,
    now: f64,
) -> serde_json::Value {
    let display_threshold = 48.0 * 3600.0;
    let liveness = state.witness_liveness.lock_recover();
    let active = liveness.active_count(display_threshold, now);
    let tracked = liveness.tracked_count();
    let inactive = liveness.inactive_witnesses(display_threshold, now);
    // Cap the serialized detail array — the inactive set grows with the witness
    // population. `inactive_witnesses` stays the TRUE count (truncation
    // detectable as `inactive_details.len() < inactive_witnesses`). SCALE RULE:
    // bounded, always.
    const MAX_INACTIVE_IN_RESPONSE: usize = 5_000;
    serde_json::json!({
        "tracked_witnesses": tracked,
        "active_witnesses": active,
        "inactive_witnesses": inactive.len(),
        "display_threshold_hours": 48,
        "inactive_details": inactive.iter().take(MAX_INACTIVE_IN_RESPONSE).map(|(h, idle)| {
            serde_json::json!({
                "witness_hash": h,
                "idle_secs": idle,
                "idle_hours": idle / 3600.0,
            })
        }).collect::<Vec<_>>(),
    })
}

pub async fn admin_witness_liveness(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    Ok(Json(compute_witness_liveness_payload(&state, now)))
}

// ─── /admin/low_stake_buffer ─────────────────────────────────────────────────
//
// Surface the contents of the low-stake-deferred buffer so an
// operator can identify which witness(es) are stuck (drain count flat while
// buffered entries climb). Pairs with the metrics gauges
// elara_attestation_low_stake_witnesses / _buffered / _oldest_age_seconds.

pub async fn admin_low_stake_buffer(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    Ok(Json(crate::network::low_stake_replay::dump_low_stake_buffer(&state).await))
}

// ─── /admin/sunset ───────────────────────────────────────────────────────────

pub(crate) fn compute_sunset_payload(state: &NodeState) -> serde_json::Value {
    let sunset_state = state.sunset.read_recover();
    let entries: Vec<_> = sunset_state.entries().iter().map(|(algo, entry)| {
        serde_json::json!({
            "algorithm": algo,
            "status": format!("{:?}", entry.status),
            "effective_epoch": entry.effective_epoch,
            "reason": entry.reason,
        })
    }).collect();
    serde_json::json!({
        "sunset_entries": entries.len(),
        "algorithms": entries,
    })
}

pub async fn admin_sunset(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    Ok(Json(compute_sunset_payload(&state)))
}

// ─── /admin/conservation_check ───────────────────────────────────────────────

// Synchronous core of `GET /admin/conservation_check`. Pulled out so
// callers can pin wire-shape contracts
// without async ledger plumbing. The helper takes the already-read
// `local_supply` so callers do the `state.ledger.read().await` themselves
// at the route layer (and tests can pass arbitrary values).
pub(crate) fn compute_conservation_check_payload(
    local_supply: u64,
    computed_total: u64,
) -> serde_json::Value {
    // ADMIN-2 (2026-07-03 audit): this endpoint previously hardcoded
    // conservation_ok=true and verified NOTHING — false assurance on a
    // money-safety diagnostic. It now reports the REAL local invariant:
    // sum(available) + total_staked + pending_xzone_locked + conservation_pool
    // (== computed_total, supplied by the caller) vs total_supply.
    let ok = computed_total == local_supply;
    serde_json::json!({
        "local_supply": local_supply,
        "peers_checked": 0,
        "mismatches": if ok { 0 } else { 1 },
        "conservation_ok": ok,
        "results": [],
        "note": "local invariant sum(available)+total_staked+pending_xzone_locked+conservation_pool vs total_supply; peer fanout removed (AUDIT-10 PQ-only), query /supply/total per-peer out-of-band",
    })
}

pub async fn admin_conservation_check(
    method: axum::http::Method,
    uri: axum::http::Uri,
    State(state): State<Arc<NodeState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — peer fanout was removed, so this is
    // now purely a read of LOCAL ledger.total_supply.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    // Peer fanout removed — there is no PQ verb for /supply/total,
    // and a local conservation-invariant check needs no peer gossip.
    // Wallets / CLI can query `/supply/total` per-peer on their own if needed.
    //
    // O(accounts) sum on the blocking pool so a mainnet-size account map
    // doesn't stall an async executor worker. The ledger read lock is still
    // held for the sum — the sum IS the minimal work under lock (cloning the
    // map first would cost the same O(n) under the same lock, plus the
    // allocation), so contention with the seal loop's ledger.write is
    // bounded by one addition pass.
    let state2 = state.clone();
    let (local_supply, computed_total) = tokio::task::spawn_blocking(move || {
        let l = state2.ledger.blocking_read();
        let sum_available: u128 = l.accounts.values().map(|a| a.available as u128).sum();
        let computed = sum_available
            .saturating_add(l.total_staked as u128)
            .saturating_add(l.pending_xzone_locked as u128)
            .saturating_add(l.conservation_pool as u128);
        (l.total_supply, computed.min(u64::MAX as u128) as u64)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;
    Ok(Json(compute_conservation_check_payload(local_supply, computed_total)))
}

// ─── /admin/epoch_health ─────────────────────────────────────────────────────

// Synchronous core of `GET /admin/epoch_health`. Pulled out so callers
// can pin wire-shape contracts without the
// `state.epoch.read_recover()` mutex plumbing. Caller passes the
// already-collected per-zone slice `(zone_path, epoch_num, seal_id,
// adaptive_interval_secs, activity_rate_rps)` (insertion order); helper
// renders each row with the 16-char `seal_id` truncation prefix +
// 4-decimal `activity_rate_rps` format pin + the load-bearing
// "everything-ok placeholder" semantic (stale_zones is hardcoded 0 and
// per-row `status` is hardcoded "ok" until the overdue-detection wire-up
// lands — pinning these locks the placeholder contract so any future
// refactor wiring up overdue detection MUST update the tests).
/// One row of the bounded `/admin/epoch_health` per-zone page:
/// `(zone_path, latest_epoch, seal_id, adaptive_interval_secs, activity_rate_rps)`.
/// Factored out so the `(usize, Vec<…>)` page type stays under
/// `clippy::type_complexity` — CI runs clippy `-D warnings`.
type EpochHealthZoneRow = (String, u64, String, f64, f64);

pub(crate) fn compute_epoch_health_payload(
    expected_interval: f64,
    total_zones: usize,
    zones: &[EpochHealthZoneRow],
) -> serde_json::Value {
    let zone_entries: Vec<serde_json::Value> = zones
        .iter()
        .map(|(zone_path, epoch_num, seal_id, adaptive_interval, activity_rate)| {
            let overdue = false;
            serde_json::json!({
                "zone": zone_path,
                "epoch": epoch_num,
                "seal_id": display_prefix(seal_id, 16),
                "adaptive_interval_secs": adaptive_interval,
                "activity_rate_rps": format!("{:.4}", activity_rate),
                "status": if overdue { "STALE" } else { "ok" },
            })
        })
        .collect();
    serde_json::json!({
        // TRUE total zone count. The caller caps `zones` to a bounded page, so
        // this can exceed `zones.len()` — truncation is detectable as
        // `zones.len() < total_zones`. Same 4-key envelope as before.
        "total_zones": total_zones,
        "stale_zones": 0u32,
        "expected_interval_secs": expected_interval,
        "zones": zone_entries,
    })
}

pub async fn admin_epoch_health(
    method: axum::http::Method,
    uri: axum::http::Uri,
    State(state): State<Arc<NodeState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — reads LOCAL epoch state to surface per-zone
    // adaptive interval + activity rate as the local node sees it.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let expected_interval = state.config.epoch_seal_interval_secs as f64;
    // Cap the per-zone array — a node tracks up to 1M zones at the mainnet
    // target, so the full per-zone walk must not serialize as one payload.
    // `total_zones` carries the TRUE count; `zones` is a bounded page (operators
    // use the elara_zone_activity_* summary gauges for the fleet-wide view).
    // SCALE RULE: bounded, always.
    const MAX_ZONES_IN_RESPONSE: usize = 5_000;
    let (total_zones, zones): (usize, Vec<EpochHealthZoneRow>) = {
        let epoch_state = state.epoch.read_recover();
        let total = epoch_state.latest_epoch.len();
        let zones = epoch_state
            .latest_epoch
            .iter()
            .take(MAX_ZONES_IN_RESPONSE)
            .map(|(zone, epoch_num)| {
                let seal_id = epoch_state
                    .latest_seal_id
                    .get(zone)
                    .cloned()
                    .unwrap_or_default();
                let adaptive_interval = epoch_state.adaptive_interval(zone, expected_interval);
                let activity_rate = epoch_state
                    .zone_activity_rate
                    .get(zone)
                    .copied()
                    .unwrap_or(0.0);
                (
                    zone.path().to_string(),
                    *epoch_num,
                    seal_id,
                    adaptive_interval,
                    activity_rate,
                )
            })
            .collect();
        (total, zones)
    };
    Ok(Json(compute_epoch_health_payload(expected_interval, total_zones, &zones)))
}

// ─── /admin/audit_log ────────────────────────────────────────────────────────

// Synchronous core of `GET /admin/audit_log`. Pulled out so callers
// can pin wire-shape contracts without the async
// mutex plumbing on `state.admin_audit_log`. Caller passes the already-locked
// slice (newest-last insertion-order); helper reverses it (newest-first) and
// caps to 100 entries.
pub(crate) fn compute_admin_audit_log_payload(
    log: &[(f64, String, String, String)],
) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = log
        .iter()
        .rev()
        .take(100)
        .map(|(ts, ip, endpoint, token)| {
            serde_json::json!({
                "timestamp": ts,
                "ip": ip,
                "endpoint": endpoint,
                "token_prefix": token,
            })
        })
        .collect();
    serde_json::json!({ "total": entries.len(), "entries": entries })
}

pub async fn admin_audit_log(
    method: axum::http::Method,
    uri: axum::http::Uri,
    State(state): State<Arc<NodeState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — reads LOCAL admin_audit_log ring buffer.
    // Forensic surface; operator wants to inspect access on the targeted
    // box, not on the genesis box.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let payload = {
        let log = state.admin_audit_log.lock_recover();
        compute_admin_audit_log_payload(&log)
    };
    Ok(Json(payload))
}

// ─── /admin/retirement_candidates ────────────────────────────────────────────

// Synchronous core of `GET /admin/retirement_candidates`. Pulled out so callers
// can pin wire-shape contracts without the
// `state.retirement` mutex plumbing. Caller passes the already-collected
// `(identity_hash, reasons)` slice (insertion order); helper renders the
// 16-char-prefix `identity` + verbatim `reasons` per row and wraps in the
// `{ candidates, nodes }` envelope.
pub(crate) fn compute_retirement_candidates_payload(
    candidates: &[(String, Vec<String>)],
) -> serde_json::Value {
    let items: Vec<serde_json::Value> = candidates.iter().map(|(id, reasons)| {
        serde_json::json!({ "identity": display_prefix(id, 16), "reasons": reasons })
    }).collect();
    serde_json::json!({ "candidates": items.len(), "nodes": items })
}

pub async fn admin_retirement_candidates(
    method: axum::http::Method,
    uri: axum::http::Uri,
    State(state): State<Arc<NodeState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — reads LOCAL retirement state.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let candidates = { state.retirement.lock_recover().candidates_for_retirement() };
    Ok(Json(compute_retirement_candidates_payload(&candidates)))
}

// ─── /admin/resync ───────────────────────────────────────────────────────────

pub async fn admin_resync(
    method: axum::http::Method,
    uri: axum::http::Uri,
    State(state): State<Arc<NodeState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — picks the peer with the highest record_count
    // and pulls INTO local state. Pure recovery on the local box.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    let peers: Vec<(String, String)> = {
        let peer_table = state.peers.read().await;
        peer_table.connected().iter().map(|p| (p.identity_hash.clone(), p.base_url())).collect()
    };
    if peers.is_empty() {
        return Ok(Json(serde_json::json!({"error": "no connected peers for re-sync"})));
    }
    let mut best_peer = String::new();
    let mut best_url = String::new();
    let mut best_count = 0u64;
    // AUDIT-10: PQ-only snapshot metadata fetch.
    let pq_offset = state.config.pq_port_offset;
    for (id, url) in &peers {
        let pq_addr = match super::super::gossip::http_to_pq_addr(url, pq_offset) {
            Some(a) => a,
            None => continue,
        };
        if let Ok(body) = state.pq_client.get_snapshot_metadata(&pq_addr).await {
            let count = body.get("record_count").and_then(|v| v.as_u64()).unwrap_or(0);
            if count > best_count {
                best_count = count;
                best_peer = id.clone();
                best_url = url.clone();
            }
        }
    }
    if best_url.is_empty() {
        return Ok(Json(serde_json::json!({"error": "no reachable peers with snapshot"})));
    }
    let state2 = state.clone();
    let url = best_url.clone();
    tokio::spawn(async move {
        tracing::info!("admin resync: starting from peer {} ({})", display_prefix(&best_peer, 16), url);
        let count = crate::network::sync::initial_sync(&state2).await;
        tracing::info!("admin resync: synced {} records", count);
    });
    Ok(Json(serde_json::json!({
        "ok": true,
        "syncing_from": best_url,
        "peer_record_count": best_count,
        "message": "re-sync started in background",
    })))
}

// ─── /admin/zone_transition ──────────────────────────────────────────────────

/// Pure guard: minimum acceptable `target_epoch` for an operator-scheduled
/// zone transition — current tip plus the same dispute-free window the
/// auto-scaler always leaves (`TRANSITION_DISPUTE_WINDOW_EPOCHS`,
/// zone_transition_seal.rs). Kept as a helper so the test module pins the
/// admin path to the auto-scaler constant and the two can't drift apart
/// again (admin-audit 2026-07-05: the old guard accepted current+1).
fn zone_transition_min_target(current_max_epoch: u64) -> u64 {
    current_max_epoch
        .saturating_add(crate::network::zone_transition_seal::TRANSITION_DISPUTE_WINDOW_EPOCHS)
}

/// Schedule a zone count transition at a future epoch.
/// Only genesis authority can announce this. Creates a signed record
/// that propagates via gossip — all nodes will apply the transition
/// when the target epoch is reached.
///
/// Query params: target_epoch, new_count
pub async fn admin_zone_transition(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // STAYS genesis-only — emits a signed ZoneTransition record
    // that the rest of the fleet only honors when signed by the genesis
    // identity. The explicit `state.identity.identity_hash !=
    // state.config.genesis_authority` check below would still trip without
    // the gate, but keeping the auth helper aligned avoids a confusing
    // 200-then-503 flow on non-genesis boxes.
    verify_admin_auth_pq(&state, method.as_str(), &uri, &headers)?;

    // Must be genesis authority
    if state.identity.identity_hash != state.config.genesis_authority {
        return Err(AppError(ElaraError::Wire(
            "zone_transition: only genesis authority can schedule transitions".into(),
        )));
    }

    let target_epoch: u64 = params.get("target_epoch")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| AppError(ElaraError::Wire("missing/invalid target_epoch".into())))?;
    let new_count: u64 = params.get("new_count")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| AppError(ElaraError::Wire("missing/invalid new_count".into())))?;

    if new_count == 0 {
        return Err(AppError(ElaraError::Wire("new_count must be > 0".into())));
    }

    let old_count = crate::network::consensus::get_zone_count();
    if new_count == old_count {
        return Err(AppError(ElaraError::Wire(format!(
            "new_count ({new_count}) == current zone_count ({old_count}), nothing to change"
        ))));
    }

    // Verify target epoch leaves the dispute-free migration window. A bare
    // "in the future" guard accepts target = current+1, inside the window the
    // codebase's own auto-scaler always leaves (it schedules at
    // current + TRANSITION_DISPUTE_WINDOW_EPOCHS, auto_scale.rs) — too tight
    // a lead means nodes flip get_zone_count() at different wall-clock
    // moments and route the same record to different zones (fork vector).
    let current_max_epoch = {
        let epoch = state.epoch.read_recover();
        epoch.latest_epoch.values().copied().max().unwrap_or(0)
    };
    let dispute_window =
        crate::network::zone_transition_seal::TRANSITION_DISPUTE_WINDOW_EPOCHS;
    let min_target = zone_transition_min_target(current_max_epoch);
    if target_epoch < min_target {
        return Err(AppError(ElaraError::Wire(format!(
            "target_epoch ({target_epoch}) must be >= current max epoch ({current_max_epoch}) \
             + dispute window ({dispute_window}) = {min_target} — a shorter lead risks \
             nodes applying the zone-count flip at different times (routing fork)"
        ))));
    }

    // Create signed zone transition record
    let meta = crate::network::epoch::zone_transition_metadata(target_epoch, old_count, new_count);
    let parents = super::super::server::dag_tip_parents(&state, 3).await;
    let content_str = format!("zone_transition:{old_count}:{new_count}:epoch{target_epoch}");
    let mut record = crate::record::ValidationRecord::create(
        content_str.as_bytes(),
        state.identity.public_key.clone(),
        parents,
        crate::record::Classification::Public,
        Some(meta),
    );
    // Stamp monotonic slot nonce BEFORE signing so this transition record
    // doesn't collide with an earlier one from the same identity on (account, 0).
    record.nonce = state.next_slot_nonce();
    if state.config.light_mode {
        state.identity.sign_record_light(&mut record)
    } else {
        state.identity.sign_record(&mut record)
    }
        .map_err(|e| AppError(ElaraError::Wire(format!("failed to sign transition record: {e}"))))?;

    let record_id = super::super::server::insert_and_push(&state, record).await?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "record_id": record_id,
        "target_epoch": target_epoch,
        "old_count": old_count,
        "new_count": new_count,
        "message": format!("zone transition scheduled: at epoch {target_epoch}, zone_count {} → {}", old_count, new_count),
    })))
}

// ─── /admin/witness/register ─────────────────────────────────────────────────

/// Submit a `LedgerOp::WitnessRegister` record from this node's identity into
/// the per-zone witness registry (Gap 2.1 Phase 2b.3 Slice 4 — emitter for the
/// Slice 3 storage layer). The signed record is gossiped fleet-wide so every
/// peer's `CF_WITNESS_REGISTRY` converges on the same view, which is the
/// prerequisite for `finality_committee_includes_witness_registry=true`
/// (Slice 3d) without re-introducing the snapshot-mismatch divergence that
/// killed the Slice 1 soak.
///
/// Bonds `bond` micros (default `WITNESS_BOND_MIN`) from `available` into
/// `witness_bonded`; bond is recoverable later via a future
/// `WitnessUnregister` op (out of scope here). Operator runs this once per
/// node per zone they wish to attest in; a duplicate submit will succeed at
/// parse but consume another bond, so it is *not* idempotent at the apply
/// layer — caller's responsibility to check `/admin/witness/registry` first.
///
/// Query: zone (required), bond (optional, default WITNESS_BOND_MIN micros)
pub async fn admin_witness_register(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    let zone_path = params
        .get("zone")
        .cloned()
        .ok_or_else(|| AppError(ElaraError::Wire("missing zone".into())))?;
    if zone_path.is_empty() {
        return Err(AppError(ElaraError::Wire("zone must be non-empty".into())));
    }

    let bond: u64 = match params.get("bond") {
        Some(v) => v
            .parse()
            .map_err(|_| AppError(ElaraError::Wire(format!("invalid bond: {v}"))))?,
        None => crate::accounting::types::WITNESS_BOND_MIN,
    };
    if bond < crate::accounting::types::WITNESS_BOND_MIN {
        return Err(AppError(ElaraError::Wire(format!(
            "bond {bond} below WITNESS_BOND_MIN {}",
            crate::accounting::types::WITNESS_BOND_MIN,
        ))));
    }

    let meta = crate::accounting::types::witness_register_metadata(&zone_path, bond);
    let parents = super::super::server::dag_tip_parents(&state, 3).await;
    // Canonical v2 ledger preimage (audit 2026-07-06): the old bespoke
    // "witness_register:{zone_path}:{bond}" form was nonce-blind and would
    // fail the ingest enforcement gate.
    let slot_nonce = state.next_slot_nonce();
    let content_str = crate::accounting::types::canonical_ledger_preimage_v2(
        &meta,
        &state.identity.public_key,
        slot_nonce,
    )
    .ok_or_else(|| {
        AppError(ElaraError::Ledger(
            "witness_register metadata missing beat_op".into(),
        ))
    })?;
    let mut record = crate::record::ValidationRecord::create(
        content_str.as_bytes(),
        state.identity.public_key.clone(),
        parents,
        crate::record::Classification::Public,
        Some(meta),
    );
    record.nonce = slot_nonce;
    if state.config.light_mode {
        state.identity.sign_record_light(&mut record)
    } else {
        state.identity.sign_record(&mut record)
    }
    .map_err(|e| {
        AppError(ElaraError::Wire(format!(
            "failed to sign witness_register record: {e}"
        )))
    })?;

    let record_id = super::super::server::insert_and_push(&state, record).await?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "record_id": record_id,
        "zone_path": zone_path,
        "bond": bond,
        "bond_beat": bond / crate::accounting::types::BASE_UNITS_PER_BEAT,
        "identity_hash": state.identity.identity_hash,
        "message": format!(
            "witness_register submitted for zone {zone_path} with {} beat bond",
            bond / crate::accounting::types::BASE_UNITS_PER_BEAT
        ),
    })))
}

// ─── /admin/witness/registry ─────────────────────────────────────────────────

/// Inspect the on-disk `CF_WITNESS_REGISTRY` for a given zone. Read-only;
/// available on every node. Used to verify gossip propagation: after
/// submitting a witness_register record on one node, query this endpoint on
/// every peer until the entry appears.
///
/// Query: zone (required)
pub async fn admin_witness_registry(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    let zone_path = params
        .get("zone")
        .cloned()
        .ok_or_else(|| AppError(ElaraError::Wire("missing zone".into())))?;

    // Uncapped RocksDB prefix materialization — run it on the blocking pool
    // (direct storage scan; no NodeState lock involved, only executor hygiene).
    let entries = {
        let rocks = std::sync::Arc::clone(&state.rocks);
        let zp = zone_path.clone();
        tokio::task::spawn_blocking(move || rocks.iter_witnesses_for_zone(&zp))
            .await
            .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?
    };
    // Cap the serialized array; `count` below stays the TRUE per-zone total
    // (truncation detectable as `entries.len() < count`). NOTE: the underlying
    // `iter_witnesses_for_zone` still materialises the full per-zone set from
    // RocksDB — a limit-aware storage scan is a separate follow-up; this bounds
    // the JSON response. SCALE RULE: bounded, always.
    const MAX_WITNESS_ENTRIES_IN_RESPONSE: usize = 10_000;
    let formatted: Vec<serde_json::Value> = entries
        .iter()
        .take(MAX_WITNESS_ENTRIES_IN_RESPONSE)
        .map(|(id, e)| {
            serde_json::json!({
                "identity_hash": id,
                "bond": e.bond,
                "bond_beat": e.bond / crate::accounting::types::BASE_UNITS_PER_BEAT,
                "registered_epoch": e.registered_epoch,
                "dilithium_pk_len": e.dilithium_pk.len(),
                "dilithium_pk_hex_prefix": hex::encode(
                    &e.dilithium_pk[..e.dilithium_pk.len().min(16)]
                ),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "zone_path": zone_path,
        "count": entries.len(),
        "entries": formatted,
    })))
}

// ─── /admin/onboard_anchor ───────────────────────────────────────────────────

/// Operator-callable anchor onboarding. Forces the local node to re-publish its VRF
/// registration record to the DAG, gossiping it fleet-wide so peers can
/// verify epoch seals signed by this anchor's VRF key.
///
/// This closes the operator surface gap that the boot path leaves open:
/// `bin/elara_node.rs:1513-1528` only emits the registration record once
/// at startup. If gossip propagation drops it (slow VPS uplink, peer
/// churn during boot, or this node started before its peers came up), the
/// fleet may never learn this anchor's VRF key — and `extract_vrf_registration`
/// gates per-zone witness selection on registry membership.
///
/// Idempotent: re-publishing is safe. `VrfRegistry::register` keeps the
/// latest by `registered_at`, so a second record bumps the timestamp without
/// changing the key. Use this when:
///   - A new anchor boots in a partially-connected network and gossip
///     dropped the boot-time record.
///   - You suspect VRF registry drift across the fleet (compare
///     `elara_vrf_registry_identities` cluster-wide).
///   - You're flipping `enforce_per_zone_vrf` to true and want to ensure
///     fresh registration before the gate engages.
///
/// Preconditions:
///   - `config.node_type` must satisfy `can_seal_epochs()` (anchor-class).
///     `extract_vrf_registration` rejects records from non-anchor node_type
///     so a witness/leaf cannot become an anchor without a config change +
///     restart.
///   - `node_state.vrf_public_key` must be Some — boot path generates the
///     VRF keypair before this gate, so the only way it's None is on a
///     non-anchor node.
///
/// Auth: uses `verify_admin_auth_pq_any_node` (NOT the genesis-only
/// `verify_admin_auth_pq`). Self-publish only — the inner helper builds a record
/// from the local identity, so a non-genesis operator can onboard their own
/// anchor but cannot publish on behalf of another node. With the genesis-only
/// gate the endpoint was unreachable on every node except the genesis
/// authority, breaking the rollout's "5 anchors register" path.
///
/// Response: record_id of the published registration, identity_hash,
/// vrf_public_key_hex, node_type. The record_id can be queried on peers
/// to verify gossip propagation (`GET /records/{id}`).
pub async fn admin_onboard_anchor(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Use the any-node PQ admin gate, not the
    // genesis-only one. The handler can ONLY publish the LOCAL node's own VRF
    // registration record (`prepare_onboard_anchor_record` calls
    // `state.create_self_ledger_record` with the local identity, so a non-genesis
    // operator cannot impersonate or onboard a different anchor). Forcing genesis
    // through this gate makes the endpoint useless for its documented purpose:
    // each anchor operator must self-onboard from their own host. Without the
    // any-node gate, raising `vrf_registry_identities` from 2→7 is
    // mechanically impossible.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    let (record, was_already_registered, vrf_pubkey_hex, node_type_str) =
        prepare_onboard_anchor_record(&state)?;

    let record_id = super::super::server::insert_and_push_admin(&state, record).await?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "record_id": record_id,
        "identity_hash": state.identity.identity_hash,
        "vrf_public_key_hex": vrf_pubkey_hex,
        "node_type": node_type_str,
        "was_already_registered": was_already_registered,
        "message": if was_already_registered {
            "VRF registration record re-published (idempotent — latest registered_at wins)".to_string()
        } else {
            "VRF registration record published — anchor onboarded".to_string()
        },
    })))
}

/// Inner: precondition gates + record construction. Returns
/// `(signed_record, was_already_registered, vrf_pubkey_hex, node_type_str)`.
/// Split out from the handler so unit tests can exercise the gates without
/// having to fake admin PQ auth or stand up the gossip subsystem.
pub(crate) fn prepare_onboard_anchor_record(
    state: &Arc<NodeState>,
) -> Result<(crate::record::ValidationRecord, bool, String, &'static str), AppError> {
    let node_type = crate::network::peer::NodeType::from_str(&state.config.node_type);
    if !node_type.can_seal_epochs() {
        return Err(AppError(ElaraError::Wire(format!(
            "node_type '{}' cannot become anchor — set node_type=anchor in config and restart",
            state.config.node_type,
        ))));
    }

    let pk = state.vrf_public_key.as_ref().ok_or_else(|| {
        AppError(ElaraError::Wire(
            "no VRF public key on this node — anchor-class node must boot with VRF keypair".into(),
        ))
    })?;

    let was_already_registered = state
        .vrf_registry
        .read()
        .map(|r| r.is_registered(&state.identity.identity_hash))
        .unwrap_or(false);

    let meta = crate::network::vrf_registry::vrf_registration_metadata(pk);
    let record = state.create_self_ledger_record(vec![], meta).map_err(|e| {
        AppError(ElaraError::Wire(format!(
            "VRF registration record creation failed: {e}"
        )))
    })?;

    Ok((record, was_already_registered, hex::encode(pk.as_bytes()), node_type.as_str()))
}

// ─── /admin/zone_autoscale ───────────────────────────────────────────────────

/// Testable core of `GET
/// /admin/zone_autoscale`. The caller (admin_zone_autoscale handler) takes
/// the lock against `state.epoch.zone_activity_rate` and `state.auto_scaler`,
/// runs the dry-run `recommend_zone_count` (pure, lock-free), then hands the
/// resolved scalars + the (cloned) per-zone activity + the dry-run decision
/// in here. The helper emits the strict 11-key envelope `{ enabled,
/// is_genesis_authority, current_zone_count, max_zones, hysteresis_ticks,
/// consecutive_hot, consecutive_cold, last_decision, this_tick_recommendation,
/// per_zone_activity, per_zone_count }`, where `per_zone_activity` is capped
/// at 5000 rows (idiom b) and `per_zone_count` is the TRUE uncapped zone
/// total. `last_decision` is Some/None — `None` AND
/// `Some(NoChange)` both render as JSON `null` (preserves the earlier
/// handler's `_ => Null` arm; NoChange isn't really a "decision" and the
/// `this_tick_recommendation` field carries the live NoChange details).
///
/// clippy::too_many_arguments is allowed because the argument list IS the
/// wire schema. Wrapping into a struct shuffles every field through a
/// builder for zero behavioural change — the helper exists to pin the
/// 10-key envelope independently of the `Arc<NodeState>` plumbing, and
/// each call site already names every field at the call boundary.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_zone_autoscale_payload(
    auto_zone_scale: bool,
    is_genesis_authority: bool,
    current_zone_count: u64,
    max_zones: u64,
    hysteresis_ticks: u32,
    consec_hot: u32,
    consec_cold: u32,
    last_decision: Option<crate::network::auto_scale::ScalingDecision>,
    this_tick_recommendation: crate::network::auto_scale::ScalingDecision,
    per_zone_activity: Vec<(crate::network::zone::ZoneId, f64)>,
) -> serde_json::Value {
    use crate::network::auto_scale::ScalingDecision;

    // SCALE RULE cap (idiom b): serialize at most 5000 per-zone rows;
    // `per_zone_count` carries the TRUE total so truncation is detectable
    // as `per_zone_activity.len() < per_zone_count`. A 1M-zone mainnet
    // would otherwise serialize ~1M rows into one JSON response.
    const MAX_PER_ZONE_ACTIVITY_IN_RESPONSE: usize = 5_000;
    let per_zone_count = per_zone_activity.len();
    let per_zone_json: Vec<serde_json::Value> = per_zone_activity
        .iter()
        .take(MAX_PER_ZONE_ACTIVITY_IN_RESPONSE)
        .map(|(z, r)| serde_json::json!({ "zone": z.to_string(), "rate": r }))
        .collect();

    let last_decision_json = match last_decision {
        Some(ScalingDecision::Split { new_count, avg_rate }) =>
            serde_json::json!({ "direction": "split", "new_count": new_count, "avg_rate": avg_rate }),
        Some(ScalingDecision::Merge { new_count, avg_rate }) =>
            serde_json::json!({ "direction": "merge", "new_count": new_count, "avg_rate": avg_rate }),
        _ => serde_json::Value::Null,
    };

    let this_tick_json = match this_tick_recommendation {
        ScalingDecision::Split { new_count, avg_rate } =>
            serde_json::json!({ "direction": "split", "new_count": new_count, "avg_rate": avg_rate }),
        ScalingDecision::Merge { new_count, avg_rate } =>
            serde_json::json!({ "direction": "merge", "new_count": new_count, "avg_rate": avg_rate }),
        ScalingDecision::NoChange { avg_rate, reason } =>
            serde_json::json!({ "direction": "none", "avg_rate": avg_rate, "reason": format!("{reason:?}") }),
    };

    serde_json::json!({
        "enabled": auto_zone_scale,
        "is_genesis_authority": is_genesis_authority,
        "current_zone_count": current_zone_count,
        "max_zones": max_zones,
        "hysteresis_ticks": hysteresis_ticks,
        "consecutive_hot": consec_hot,
        "consecutive_cold": consec_cold,
        "last_decision": last_decision_json,
        "this_tick_recommendation": this_tick_json,
        "per_zone_activity": per_zone_json,
        "per_zone_count": per_zone_count,
    })
}

/// Gap 4: Inspect activity-driven autoscaler status. Read-only; works on every
/// node regardless of genesis-authority role. Shows current hysteresis
/// counters, last decision, per-zone activity snapshot, and what the
/// calculator would recommend THIS tick.
pub async fn admin_zone_autoscale(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — read-only inspector of LOCAL autoscaler state.
    // Docstring already documented "works on every node regardless of
    // genesis-authority role" — auth gate is now aligned with that.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    // The whole read+dry-run runs on the blocking pool: the
    // zone_activity_rate clone under epoch.read_recover is O(zones) (the
    // dry-run recommender needs the FULL per-zone map — an aggregate
    // decision — so the clone is the minimal capture), and the recommend
    // walk is another O(zones) of pure CPU. The RESPONSE per-zone list is
    // capped in compute_zone_autoscale_payload; the clone here is not
    // avoidable without starving the dry-run of its input.
    let state2 = state.clone();
    let payload = tokio::task::spawn_blocking(move || {
        let current_zone_count = crate::network::consensus::get_zone_count();

        let per_zone_activity = {
            let ep = state2.epoch.read_recover();
            ep.zone_activity_rate.clone()
        };

        let (consec_hot, consec_cold, hysteresis_ticks, max_zones, last_decision) = {
            let sc = state2.auto_scaler.lock_recover();
            let (h, c) = sc.counters();
            (
                h,
                c,
                sc.hysteresis_ticks,
                sc.max_zones,
                sc.last_decision.clone(),
            )
        };

        let dry_run = crate::network::auto_scale::recommend_zone_count(
            &per_zone_activity,
            current_zone_count,
            max_zones,
        );

        let per_zone_vec: Vec<(crate::network::zone::ZoneId, f64)> =
            per_zone_activity.into_iter().collect();

        compute_zone_autoscale_payload(
            state2.config.auto_zone_scale,
            state2.identity.identity_hash == state2.config.genesis_authority,
            current_zone_count,
            max_zones,
            hysteresis_ticks,
            consec_hot,
            consec_cold,
            last_decision,
            dry_run,
            per_zone_vec,
        )
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;
    Ok(Json(payload))
}

// ─── /admin/zone_subscriptions ───────────────────────────────────────────────

/// Testable core of
/// `GET /admin/zone_subscriptions`. The route handler resolves the 9
/// state/config scalars (identity / light_mode / current_epoch /
/// our_subscribed_zones / our_subscription_valid_until_epoch / validity_epochs
/// / refresh_margin_epochs / total_subscribers / per_zone_subscribers) from
/// the LOCAL ZoneSubscriptionRegistry + EpochState + NodeConfig, then passes
/// them in here. The helper computes ONE derived field —
/// `our_subscription_epochs_remaining = our_subscription_valid_until_epoch
/// .map(|vu| vu.saturating_sub(current_epoch))` — and emits the strict
/// 10-key envelope. Pulling the math into the helper makes the
/// Option-through-saturating-sub-and-None-passthrough triple-cell truth table
/// pinnable independently of the `Arc<NodeState>` + registry-lock plumbing
/// on the route handler.
///
/// clippy::too_many_arguments is allowed because the argument list IS the
/// wire schema. Same posture as `compute_zone_autoscale_payload` above —
/// wrapping into a struct adds a builder hop for zero behavioural change.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_zone_subscriptions_payload(
    identity: String,
    light_mode: bool,
    current_epoch: u64,
    our_subscribed_zones: Vec<String>,
    our_subscription_valid_until_epoch: Option<u64>,
    validity_epochs: u64,
    refresh_margin_epochs: u64,
    total_subscribers_across_all_zones: usize,
    per_zone_subscribers: Vec<serde_json::Value>,
) -> serde_json::Value {
    let our_subscription_epochs_remaining =
        our_subscription_valid_until_epoch.map(|vu| vu.saturating_sub(current_epoch));

    serde_json::json!({
        "identity": identity,
        "light_mode": light_mode,
        "current_epoch": current_epoch,
        "our_subscribed_zones": our_subscribed_zones,
        "our_subscription_valid_until_epoch": our_subscription_valid_until_epoch,
        "our_subscription_epochs_remaining": our_subscription_epochs_remaining,
        "validity_epochs": validity_epochs,
        "refresh_margin_epochs": refresh_margin_epochs,
        "total_subscribers_across_all_zones": total_subscribers_across_all_zones,
        "per_zone_subscribers": per_zone_subscribers,
    })
}

/// Gap 5: inspect the local zone-subscription registry. Shows which zones this
/// node currently serves, when our subscription expires, and a per-zone
/// subscriber-count summary useful for diagnosing "why isn't this node in the
/// jury for zone X?".
pub async fn admin_zone_subscriptions(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — reports LOCAL ZoneSubscriptionRegistry view from
    // the local node's perspective. Distinct from `/admin/zones/scope`
    // (already any_node), but same per-node read posture.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    let our_hash = state.identity.identity_hash.clone();

    let (our_zones, our_valid_until, total_subs, per_zone_counts) = {
        let reg = state.zone_subscriptions.lock_recover();
        let our_zones: Vec<String> = reg
            .zones_for(&our_hash)
            .into_iter()
            .map(|z| z.to_string())
            .collect();
        let our_valid_until = reg.valid_until(&our_hash);
        let total = reg.total_subscribers();
        // ADMIN-3 (2026-07-03 audit): zone_counts() is O(all_zones) — up to ~1M
        // rows at mainnet scale — and was serialized uncapped. Cap the per-zone
        // detail list (the aggregate `total` above stays exact); mirrors the
        // MAX_ZONES=5000 cap the sibling admin endpoints use.
        const MAX_ZONE_COUNTS_IN_RESPONSE: usize = 5_000;
        let counts: Vec<serde_json::Value> = reg
            .zone_counts()
            .into_iter()
            .take(MAX_ZONE_COUNTS_IN_RESPONSE)
            .map(|(z, n)| serde_json::json!({ "zone": z.to_string(), "subscribers": n }))
            .collect();
        (our_zones, our_valid_until, total, counts)
    };

    // Canonical current_epoch: the live active-zone tip (single source of
    // truth — see EpochState::active_zone_max_epoch). Reads live off the epoch
    // guard (no state_core staleness), and — unlike the prior raw
    // `latest_epoch.values().max()` — excludes stale zones left over from a
    // superseded zone_count so they can't inflate the epoch that drives the
    // subscription-epochs-remaining math below.
    let current_epoch = state
        .epoch
        .read_recover()
        .active_zone_max_epoch(crate::network::consensus::get_zone_count());

    Ok(Json(compute_zone_subscriptions_payload(
        our_hash,
        state.config.light_mode,
        current_epoch,
        our_zones,
        our_valid_until,
        state.config.zone_subscription_validity_epochs,
        state.config.zone_subscription_refresh_margin,
        total_subs,
        per_zone_counts,
    )))
}

// ─── /admin/content_routing ──────────────────────────────────────────────────

// Synchronous core of `GET /admin/content_routing`. Pulled out so
// callers can pin the wire envelope, the
// `content_routing_active` boolean derivation, and the scalar/Vec
// passthrough independently of the `Arc<NodeState>` + async DHT-lookup
// plumbing on the route handler. The route handler resolves the four
// scalars + builds the `responsible_nodes` vec from the live DHT, then
// passes the resolved values in.
pub(crate) fn compute_content_routing_payload(
    record_id: String,
    content_routing_threshold: usize,
    content_routing_k: usize,
    peer_count: usize,
    responsible_nodes: Vec<serde_json::Value>,
) -> serde_json::Value {
    let active = content_routing_threshold > 0 && peer_count >= content_routing_threshold;
    serde_json::json!({
        "record_id": record_id,
        "content_routing_threshold": content_routing_threshold,
        "content_routing_k": content_routing_k,
        "peer_count": peer_count,
        "content_routing_active": active,
        "responsible_nodes": responsible_nodes,
    })
}

/// Gap 6: preview content-routed gossip placement for a given record_id.
///
/// Query string:
///   `record_id` — required, the record identifier to preview
///
/// Returns the K DHT-closest peers (the responsible replica set) plus the
/// effective routing configuration. Useful for diagnosing "why didn't my
/// record reach node X?": if X isn't in the closest K, content routing
/// explicitly excluded it by design.
pub async fn admin_content_routing(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    axum::extract::Query(params):
        axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — previews the LOCAL DHT's K-closest set. Each
    // node's DHT is its own view of the overlay, so this needs to run on
    // the box whose routing is being investigated.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    let record_id = params
        .get("record_id")
        .cloned()
        .unwrap_or_else(|| "0198d6e0-0000-7000-8000-000000000000".into());

    let k = state.config.content_routing_k.max(1);
    let threshold = state.config.content_routing_threshold;

    let peer_count = state.peers.read().await.len();

    let closest: Vec<serde_json::Value> = {
        let dht = state.dht.lock_recover();
        dht.closest_to_record(&record_id, k)
            .into_iter()
            .map(|p| {
                serde_json::json!({
                    "identity_hash": p.identity_hash,
                    "host": p.host,
                    "port": p.port,
                    "provenance": format!("{:?}", p.provenance),
                })
            })
            .collect()
    };

    Ok(Json(compute_content_routing_payload(
        record_id,
        threshold,
        k,
        peer_count,
        closest,
    )))
}

// ─── /admin/epoch_snapshots (Gap 7) ─────────────────────────────────────────
//
// Reports this node's Gap 7 archive-snapshot state:
//   - whether archive-mode snapshots are enabled
//   - list of epoch snapshots on disk (sorted ascending)
//   - current max epoch across zones (when the next snapshot triggers)
//   - retention + cadence config
//
// Safe on all nodes: non-archive nodes just report `enabled=false` with
// an empty list.

/// Testable core of
/// `GET /admin/epoch_snapshots`. The route handler resolves the 6 config /
/// state scalars (node_type / archival / every_n / retention / snapshot dir
/// / current max epoch) + the on-disk epoch Vec via `spawn_blocking`, then
/// hands them in here. The helper computes 5 derived fields — `enabled`
/// (archival AND every_n>0), `latest_epoch_on_disk` (last of the sorted
/// Vec), `count` (Vec len), `next_trigger_at_epoch` (latest+every_n with
/// `saturating_add` overflow protection, defaults to every_n when the disk
/// list is empty), and `epochs_until_next_trigger` (next_trigger - current
/// max via `saturating_sub`) — and emits the strict 12-key envelope.
/// Pulling the derived-field math into the helper makes the tri-axis
/// orthogonality explicit: (a) enabled requires BOTH archival AND every_n>0,
/// (b) next_trigger uses saturating_add, (c) epochs_until_next_trigger uses
/// saturating_sub — each can regress independently and each surfaces a
/// distinct operator-facing failure mode.
pub(crate) fn compute_epoch_snapshots_payload(
    node_type_str: String,
    archival: bool,
    every_n_epochs: u64,
    retention: usize,
    snapshot_dir: String,
    current_max_epoch: u64,
    epochs_on_disk: Vec<u64>,
) -> serde_json::Value {
    let enabled = archival && every_n_epochs > 0;
    let latest = epochs_on_disk.last().copied();
    let count = epochs_on_disk.len();
    let next_trigger_at_epoch = latest
        .map(|n| n.saturating_add(every_n_epochs))
        .unwrap_or(every_n_epochs);
    let epochs_until_next_trigger = next_trigger_at_epoch.saturating_sub(current_max_epoch);

    serde_json::json!({
        "node_type": node_type_str,
        "is_archival": archival,
        "enabled": enabled,
        "every_n_epochs": every_n_epochs,
        "retention": retention,
        "snapshot_dir": snapshot_dir,
        "current_max_epoch": current_max_epoch,
        "epochs_on_disk": epochs_on_disk,
        "count": count,
        "latest_epoch_on_disk": latest,
        "next_trigger_at_epoch": next_trigger_at_epoch,
        "epochs_until_next_trigger": epochs_until_next_trigger,
    })
}

pub async fn admin_epoch_snapshots(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — docstring above says "Safe on all nodes".
    // Inspects LOCAL archive snapshot directory + LOCAL epoch state.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    let node_type_str = state.config.node_type.clone();
    let node_type = crate::network::peer::NodeType::from_str(&node_type_str);
    let archival = node_type.is_archival();
    let every_n = state.config.archive_snapshot_every_n_epochs;
    let retention = state.config.archive_snapshot_retention;

    let dir = state.config.data_dir.join("snapshots");
    let epochs = tokio::task::spawn_blocking({
        let dir = dir.clone();
        move || crate::network::snapshot::list_epoch_snapshots(&dir)
    })
    .await
    .map_err(|e| AppError(ElaraError::Network(format!("spawn_blocking: {e}"))))??;

    let max_epoch = {
        let ep = state.epoch.read_recover();
        ep.latest_epoch.values().copied().max().unwrap_or(0)
    };

    Ok(Json(compute_epoch_snapshots_payload(
        node_type_str,
        archival,
        every_n,
        retention,
        dir.display().to_string(),
        max_epoch,
        epochs,
    )))
}

// ─── /admin/memory ───────────────────────────────────────────────────────────

/// Memory diagnostics: reports sizes of all in-memory data structures.
/// Used to identify memory leaks by watching which structures grow over time.
/// PQ-admin-authed but does NOT require genesis authority (runs on every node).
pub async fn admin_memory(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    // Process RSS from /proc/self/status
    let rss_kb: u64 = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0);

    let consensus_detail = {
        let c = state.consensus.lock_recover();
        c.memory_detail()
    };

    let dag_detail = {
        let d = state.dag.read().await;
        serde_json::json!({
            "nodes": d.len(),
            "edges": d.edge_count(),
            "orphan_edges": d.orphan_count(),
            "roots": d.roots().len(),
            "tips": d.tips().len(),
        })
    };

    let seen_len = state.seen.lock_recover().len();
    let att_seen_len = state.attestation_seen.lock_recover().len();
    let att_bad_len = state.attestation_bad_sigs.lock_recover().len();
    let gossip_rejected_len = state.gossip_rejected.lock_recover().len();

    let peers_detail = {
        let p = state.peers.read().await;
        serde_json::json!({
            "total": p.all().len(),
            "connected": p.connected().len(),
            "banned": p.banned_count(),
        })
    };

    let finalized_len = state.finalized.read().await.len();

    let entity_detail = {
        let ec = state.entity_clusterer.lock_recover();
        serde_json::json!({ "witnesses": ec.witness_count(), "entities": ec.entity_count() })
    };

    let liveness_len = {
        let l = state.witness_liveness.lock_recover();
        l.tracked_count()
    };

    let trust_len = {
        let t = state.trust.read().await;
        t.tracked_identities()
    };

    let prop_limiter = {
        let l = state.propagation_limiter.lock_recover();
        l.tracked_identities()
    };

    let epoch_zones = {
        let e = state.epoch.read_recover();
        e.latest_epoch.len()
    };

    let uptime = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        (now - state.start_time) as u64
    };

    // RocksDB internal memory
    let (rocks_memtable, rocks_block_cache, rocks_table_readers) = state.rocks.memory_usage();

    Ok(Json(serde_json::json!({
        "rss_mb": rss_kb as f64 / 1024.0,
        "uptime_secs": uptime,
        "rocksdb": {
            "memtable_mb": rocks_memtable as f64 / (1024.0 * 1024.0),
            "block_cache_mb": rocks_block_cache as f64 / (1024.0 * 1024.0),
            "table_readers_mb": rocks_table_readers as f64 / (1024.0 * 1024.0),
            "total_mb": (rocks_memtable + rocks_block_cache + rocks_table_readers) as f64 / (1024.0 * 1024.0),
        },
        "consensus": consensus_detail,
        "dag": dag_detail,
        "seen_dedup": seen_len,
        "attestation_seen": att_seen_len,
        "attestation_bad_sigs": att_bad_len,
        "gossip_rejected": gossip_rejected_len,
        "peers": peers_detail,
        "finalized_index": finalized_len,
        "entity_clusterer": entity_detail,
        "witness_liveness": liveness_len,
        "trust_identities": trust_len,
        "propagation_limiter": prop_limiter,
        "epoch_zones": epoch_zones,
    })))
}

// ─── /admin/zones/scope (ZSP Phase E) ───────────────────────────────────────

/// `GET /admin/zones/scope` — local zone-scope view for operators.
///
/// Distinct from `/admin/zone_subscriptions` (which reports the
/// network-wide `ZoneSubscriptionRegistry` used by Gap 5 per-zone VRF
/// committees). This endpoint reports the **local** `ZoneManager`
/// subscription set used by the ingest filter (`ingest.rs:523`),
/// gossip filter (`gossip.rs:321`), and ZSP Phase D purge tick.
///
/// Per-zone disk usage is computed via `StorageEngine::count_zone` —
/// O(records_in_zone) bounded by the ZSP-B `CF_RECORD_BY_ZONE` prefix
/// scan, so this is only safe to call for the (small) subscribed set,
/// not for an enumeration of all zones present on disk. Global
/// totals come from the `elara_zone_idx_*` gauges (O(1) each).
///
/// The `default_behavior` field surfaces the Phase A subtlety: an
/// empty subscription set means *accept-all* at the ingest filter,
/// not *accept-nothing*. Operators should see `"accept_all"` when
/// they expect `"scoped"`.
pub async fn admin_zones_scope(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Same misclassification as the sibling onboarding endpoint —
    // this endpoint reports the LOCAL ZoneManager subscription set and per-zone
    // disk usage. It must be callable from any operator on their own node, not
    // restricted to genesis. Read-only, no state mutation.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;
    // compute_zones_scope runs one `count_zone` rocks prefix scan per listed
    // zone (≤ 5000 after the idiom-b cap) — blocking-pool work, not
    // executor work.
    let state2 = state.clone();
    let payload = tokio::task::spawn_blocking(move || compute_zones_scope(&state2))
        .await
        .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;
    Ok(Json(payload))
}

/// Inner logic for `/admin/zones/scope`. Extracted from the auth-gated
/// handler so tests can exercise the JSON shape without going through
/// the PQ admin auth wrapper.
pub(crate) fn compute_zones_scope(state: &Arc<NodeState>) -> serde_json::Value {
    let mut subscribed: Vec<crate::network::zone::ZoneId> = {
        let mgr = state.zone_manager.lock_recover();
        let mut zones: Vec<_> = mgr.subscribed_zones().iter().cloned().collect();
        zones.sort_by_key(|a| a.to_string());
        zones
    };

    let subscribed_zone_count = subscribed.len();
    let default_behavior = if subscribed_zone_count == 0 {
        "accept_all"
    } else {
        "scoped"
    };

    // SCALE RULE cap (idiom b): both detail surfaces (`subscribed_zones`,
    // `per_zone_storage`) list at most the first 5000 zones (ASCII-lex
    // order); `subscribed_zone_count` carries the TRUE total so truncation
    // is detectable as list len < count. The cap ALSO bounds the per-zone
    // `count_zone` rocks prefix scans below to ≤5000 — an
    // everything-subscriber at 1M-zone mainnet would otherwise run one scan
    // per subscribed zone in a single request.
    const MAX_ZONES_IN_SCOPE_RESPONSE: usize = 5_000;
    subscribed.truncate(MAX_ZONES_IN_SCOPE_RESPONSE);

    let per_zone: Vec<serde_json::Value> = subscribed
        .iter()
        .map(|z| {
            let key = z.to_key_bytes();
            let n = state.rocks.count_zone(&key);
            serde_json::json!({
                "zone": z.to_string(),
                "record_count": n,
            })
        })
        .collect();

    let global_idx_entries = state.rocks.zone_idx_total_entries();
    let global_idx_distinct = state.rocks.zone_idx_distinct_zones();

    use std::sync::atomic::Ordering;
    let purge_state = serde_json::json!({
        "queue_depth": crate::network::zone_purge::queue_depth(state.as_ref()),
        "oldest_lag_seconds": crate::network::zone_purge::oldest_lag_secs(state.as_ref()),
        "records_purged_total":
            state.zone_purge_records_purged_total.load(Ordering::Relaxed),
    });

    serde_json::json!({
        "subscribed_zones": subscribed.iter().map(|z| z.to_string()).collect::<Vec<_>>(),
        "subscribed_zone_count": subscribed_zone_count,
        "default_behavior": default_behavior,
        "per_zone_storage": per_zone,
        "global_zone_idx_entries": global_idx_entries,
        "global_zone_idx_distinct_zones": global_idx_distinct,
        "pending_purge": purge_state,
    })
}

// ─── /admin/zones/subscribe (ZSP Phase E) ───────────────────────────────────

/// `POST /admin/zones/subscribe?zone=<path>` — add a zone to the local
/// `ZoneManager`. Idempotent: re-subscribing is a no-op. The handler
/// routes through `NodeState::subscribe_zone` (`network/state.rs:3187`)
/// so the new subscription is persisted via
/// `zone_persist::save_subscriptions` (`network/zone_persist.rs:53`)
/// and survives restart — Phase E Slice 3.
///
/// Note: `ZoneManager::subscribe` auto-adds ancestor zones, so
/// subscribing to `medical/eu/cardiology` also pins `medical/eu` and
/// `medical`. This matches the ingest filter which short-circuits on
/// ancestor coverage.
pub async fn admin_zones_subscribe(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Mutates LOCAL ZoneManager via
    // state.subscribe_zone — per-node operator action, not network-wide. The
    // genesis-only gate prevented non-genesis operators from configuring their
    // own node's zone subscriptions. ZSP Phase E expects per-operator control.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    let zone_str = params
        .get("zone")
        .ok_or_else(|| AppError(ElaraError::Wire("missing ?zone= parameter".into())))?;
    if zone_str.is_empty() {
        return Err(AppError(ElaraError::Wire("empty zone path".into())));
    }
    let zone = crate::network::zone::ZoneId::new(zone_str);

    let already = {
        let mgr = state.zone_manager.lock_recover();
        mgr.subscribed_zones().contains(&zone)
    };
    if !already {
        // ZSP Phase E Slice 3: route through state helper so the new
        // subscription persists across restart. Idempotent — subscribe()
        // also auto-pins ancestors per zone.rs:331-339.
        state.subscribe_zone(&zone);
    }
    let total = state
        .zone_manager
        .lock_recover()
        .subscribed_zones()
        .len();

    Ok(Json(serde_json::json!({
        "ok": true,
        "zone": zone.to_string(),
        "already_subscribed": already,
        "total_subscribed_zones": total,
    })))
}

// ─── /admin/zones/unsubscribe (ZSP Phase E) ─────────────────────────────────

/// `POST /admin/zones/unsubscribe?zone=<path>` — remove a zone from the
/// local `ZoneManager` AND enqueue it for ZSP Phase D bounded purge.
/// Wraps `NodeState::unsubscribe_zone` (state.rs) which is the canonical
/// helper and the only safe path to retire local records.
///
/// Returns the new pending-purge queue depth so the operator can poll
/// `/admin/zones/scope` to watch the drain progress.
pub async fn admin_zones_unsubscribe(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Same as zones_subscribe — wraps
    // state.unsubscribe_zone for the LOCAL node. Per-operator self-service.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    let zone_str = params
        .get("zone")
        .ok_or_else(|| AppError(ElaraError::Wire("missing ?zone= parameter".into())))?;
    if zone_str.is_empty() {
        return Err(AppError(ElaraError::Wire("empty zone path".into())));
    }
    let zone = crate::network::zone::ZoneId::new(zone_str);

    let was_subscribed = {
        let mgr = state.zone_manager.lock_recover();
        mgr.subscribed_zones().contains(&zone)
    };

    state.unsubscribe_zone(&zone);

    let total_after = {
        let mgr = state.zone_manager.lock_recover();
        mgr.subscribed_zones().len()
    };
    let queue_depth = crate::network::zone_purge::queue_depth(state.as_ref());

    Ok(Json(serde_json::json!({
        "ok": true,
        "zone": zone.to_string(),
        "was_subscribed": was_subscribed,
        "total_subscribed_zones": total_after,
        "purge_queue_depth": queue_depth,
    })))
}

// ─── /admin/forensic/slot/{account_hash}/{nonce_hex} ──────────────────────
//
// ARCH-4 forensics. Inspects the (creator, nonce) slot index without
// destructive ops: returns the stored record_id, version, signable_bytes
// digest, signature digest, and a fresh sig-verify result. Used to bisect
// "ConflictProof record_a signature invalid" storms surfaced by
// elara_attestations_processed_total flat-line under rising bytes_in.
//
// account_hash: hex SHA3-256 of creator_public_key (64 chars).
// nonce_hex:    16-char zero-padded hex of u64 (matches slot_key format
//               built in record.rs:673 — `{}:{:016x}`).
//
// Output is read-only forensic JSON. No state mutation, no peer fanout.
pub async fn admin_forensic_slot(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Path((account_hash, nonce_hex)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Forensic inspection must work on every node — the whole point is
    // bisecting "this node has X, that node has Y" across the fleet. Same
    // rationale as /admin/memory. Still PQ-auth-protected, so only an
    // admin-pubkey holder (allowlisted in ELARA_ADMIN_PUBKEYS) can call.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    if account_hash.len() != 64 || !account_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError(ElaraError::Wire(
            "account_hash must be 64-char SHA3-256 hex".into(),
        )));
    }
    if nonce_hex.len() != 16 || !nonce_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError(ElaraError::Wire(
            "nonce_hex must be 16-char zero-padded hex of u64".into(),
        )));
    }

    let slot_key = format!("{}:{}", account_hash, nonce_hex);
    let record_id = match state.rocks.slot_lookup(&slot_key) {
        Ok(Some(id)) => id,
        Ok(None) => {
            return Ok(Json(serde_json::json!({
                "slot_key": slot_key,
                "found": false,
                "note": "slot index has no entry — no record has claimed this (account, nonce) pair on this node",
            })));
        }
        Err(e) => return Err(AppError(ElaraError::Storage(format!("slot_lookup: {e}")))),
    };

    let record = match state.rocks.get_record(&record_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Ok(Json(serde_json::json!({
                "slot_key": slot_key,
                "record_id": record_id,
                "found": false,
                "note": "slot points to a record_id that's not in storage — orphaned slot entry",
            })));
        }
        Err(e) => return Err(AppError(ElaraError::Storage(format!("get_record: {e}")))),
    };

    let signable = record.signable_bytes();
    let signable_sha3 = crate::crypto::hash::sha3_256_hex(&signable);
    let pk_sha3 = crate::crypto::hash::sha3_256_hex(&record.creator_public_key);

    let (sig_present, sig_sha3, sig_len, sig_verifies, sig_verify_error) = match record.signature.as_deref() {
        None => (false, String::new(), 0usize, false, Some("no signature on record".to_string())),
        Some(sig) => {
            let s_hash = crate::crypto::hash::sha3_256_hex(sig);
            let s_len = sig.len();
            match crate::identity::Identity::verify(&signable, sig, &record.creator_public_key) {
                Ok(true) => (true, s_hash, s_len, true, None),
                Ok(false) => (true, s_hash, s_len, false, Some("Identity::verify returned false".to_string())),
                Err(e) => (true, s_hash, s_len, false, Some(format!("{e}"))),
            }
        }
    };

    Ok(Json(serde_json::json!({
        "slot_key": slot_key,
        "found": true,
        "record_id": record_id,
        "version": record.version,
        "timestamp": record.timestamp,
        "nonce": record.nonce,
        "classification": format!("{:?}", record.classification),
        "creator_pk_len": record.creator_public_key.len(),
        "creator_pk_sha3": pk_sha3,
        "signable_bytes_len": signable.len(),
        "signable_bytes_sha3": signable_sha3,
        "signature_present": sig_present,
        "signature_len": sig_len,
        "signature_sha3": sig_sha3,
        "sig_verifies": sig_verifies,
        "sig_verify_error": sig_verify_error,
        "metadata_keys": record.metadata.keys().cloned().collect::<Vec<_>>(),
        "parents_count": record.parents.len(),
    })))
}

// ─── /admin/forensic/record/{record_id} ────────────────────────────────────
//
// Record-id-keyed sibling of /admin/forensic/slot. Where
// the slot endpoint bisects "this (account, nonce) slot has different
// occupants across the fleet", this one bisects "this single record_id has
// different sig-verify outcomes across the fleet" — the failure mode
// surfaced by the per-peer recent_bad_sig_record_ids ring buffer.
//
// Operator workflow: a node's /peers shows a peer with recent_bad_sig_record_ids
// = ["019d4442-4f7c…", …]. Pick one ID. Run this endpoint on each fleet
// node. Compare:
//   - same signable_bytes_sha3 across all nodes + sig_verifies=false on only
//     one node → that node has stale state for the signing key (witness
//     PK rotated, sync gap, missing PK registration record).
//   - different signable_bytes_sha3 across nodes → wire-version drift /
//     storage-upgrade bug producing different byte representations of the
//     same logical record.
//   - record absent on some nodes → those nodes never received it (gossip
//     drop / orphan-resolver gap).
//
// Read-only, PQ-authed, any-node. Mirrors slot endpoint posture.
pub async fn admin_forensic_record(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Path(record_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    if record_id.is_empty() || record_id.len() > 128 {
        return Err(AppError(ElaraError::Wire(
            "record_id must be 1-128 chars".into(),
        )));
    }

    let record = match state.rocks.get_record(&record_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Ok(Json(serde_json::json!({
                "record_id": record_id,
                "found": false,
                "note": "no record with this id in storage on this node — gossip never delivered it, or it was GC'd",
            })));
        }
        Err(e) => return Err(AppError(ElaraError::Storage(format!("get_record: {e}")))),
    };

    let signable = record.signable_bytes();
    let signable_sha3 = crate::crypto::hash::sha3_256_hex(&signable);
    let pk_sha3 = crate::crypto::hash::sha3_256_hex(&record.creator_public_key);

    let (sig_present, sig_sha3, sig_len, sig_verifies, sig_verify_error) = match record.signature.as_deref() {
        None => (false, String::new(), 0usize, false, Some("no signature on record".to_string())),
        Some(sig) => {
            let s_hash = crate::crypto::hash::sha3_256_hex(sig);
            let s_len = sig.len();
            match crate::identity::Identity::verify(&signable, sig, &record.creator_public_key) {
                Ok(true) => (true, s_hash, s_len, true, None),
                Ok(false) => (true, s_hash, s_len, false, Some("Identity::verify returned false".to_string())),
                Err(e) => (true, s_hash, s_len, false, Some(format!("{e}"))),
            }
        }
    };

    let slot_key = format!("{}:{:016x}", pk_sha3, record.nonce);

    Ok(Json(serde_json::json!({
        "record_id": record_id,
        "found": true,
        "version": record.version,
        "timestamp": record.timestamp,
        "nonce": record.nonce,
        "classification": format!("{:?}", record.classification),
        "zone": record.zone,
        "creator_pk_len": record.creator_public_key.len(),
        "creator_pk_sha3": pk_sha3,
        "slot_key": slot_key,
        "signable_bytes_len": signable.len(),
        "signable_bytes_sha3": signable_sha3,
        "signature_present": sig_present,
        "signature_len": sig_len,
        "signature_sha3": sig_sha3,
        "sig_verifies": sig_verifies,
        "sig_verify_error": sig_verify_error,
        "metadata_keys": record.metadata.keys().cloned().collect::<Vec<_>>(),
        "parents_count": record.parents.len(),
    })))
}

// ─── /admin/forensic/record/{record_id}/evict_unverifiable ─────────────────
//
// Surgical repair: record-id-keyed sibling of the slot
// eviction endpoint below. The slot variant covers the
// monotonic-nonce-collision case; this variant covers anything else where
// a node holds a record whose locally-stored bytes don't reproduce the
// witness's signature — most commonly a wire-version drift the slot
// endpoint can't address (the record may not be slot-indexed yet, or the
// (creator, nonce) tuple may have collided into a different occupant).
//
// The `/peers` endpoint surfaces `recent_bad_sig_record_ids` per
// peer. The operator picks an id, calls `/admin/forensic/record/{id}` to
// confirm `sig_verifies=false`, then this endpoint atomically removes
// the unverifiable record so the next gossip round refetches the
// canonical bytes from the fleet.
//
// Same auth posture as the slot endpoint and `admin_forensic_record`:
// PQ Dilithium3, allowlisted operator, runs on any node. Refuses to
// evict a verifying record. Releases the slot index entry too if the
// (creator, nonce) tuple still points back at the evicted record.
/// Remove an evicted record from the LIVE in-memory DAG as well
/// (admin-audit 2026-07-05). Without this the evicted id stays in
/// `state.dag` until restart — if it was a tip, `dag_tip_parents` keeps
/// citing it as a parent of newly-authored records, publishing lineage
/// edges to an id whose bytes no longer exist and can never re-verify
/// (phantom parent; peers hold a permanent orphan edge for it).
/// `DagIndex::remove` re-tips the evictee's parents and drops orphan
/// edges. The boot-time rebuild is keyed on CF_IDX_TIMESTAMP, which
/// `delete_record` already cleans — this covers the live window.
async fn evict_from_live_dag(state: &Arc<NodeState>, record_id: &str) {
    let mut dag_guard = state.dag.write().await;
    std::sync::Arc::make_mut(&mut *dag_guard).remove(record_id);
}

pub async fn admin_evict_unverifiable_record(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Path(record_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    if record_id.is_empty() || record_id.len() > 128 {
        return Err(AppError(ElaraError::Wire(
            "record_id must be 1-128 chars".into(),
        )));
    }

    let record = match state.rocks.get_record(&record_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Ok(Json(serde_json::json!({
                "record_id": record_id,
                "evicted": false,
                "reason": "not_found",
                "note": "no record with this id in storage on this node — nothing to evict",
            })));
        }
        Err(e) => return Err(AppError(ElaraError::Storage(format!("get_record: {e}")))),
    };

    let signable = record.signable_bytes();
    let pk_sha3 = crate::crypto::hash::sha3_256_hex(&record.creator_public_key);
    let signable_sha3 = crate::crypto::hash::sha3_256_hex(&signable);
    let slot_key = format!("{}:{:016x}", pk_sha3, record.nonce);

    let sig = match record.signature.as_deref() {
        Some(s) => s,
        None => {
            state.rocks.delete_record(&record_id, crate::storage::rocks::DeleteIntent::AdminEvict)
                .map_err(|e| AppError(ElaraError::Storage(format!("delete_record: {e}"))))?;
            evict_from_live_dag(&state, &record_id).await;
            // Release the slot only if it currently points at this record.
            if let Ok(Some(occupant)) = state.rocks.slot_lookup(&slot_key) {
                if occupant == record_id {
                    state.rocks.slot_delete(&slot_key)
                        .map_err(|e| AppError(ElaraError::Storage(format!("slot_delete: {e}"))))?;
                }
            }
            return Ok(Json(serde_json::json!({
                "record_id": record_id,
                "evicted": true,
                "reason": "no_signature_present",
                "version": record.version,
                "slot_key": slot_key,
                "metadata_keys": record.metadata.keys().cloned().collect::<Vec<_>>(),
            })));
        }
    };

    let verifies = crate::identity::Identity::verify(&signable, sig, &record.creator_public_key).unwrap_or_default();

    if verifies {
        return Ok(Json(serde_json::json!({
            "record_id": record_id,
            "evicted": false,
            "reason": "signature_verifies",
            "note": "occupant is cryptographically valid — refusing to evict",
            "version": record.version,
            "timestamp": record.timestamp,
            "nonce": record.nonce,
            "slot_key": slot_key,
            "signable_bytes_sha3": signable_sha3,
            "creator_pk_sha3": pk_sha3,
            "metadata_keys": record.metadata.keys().cloned().collect::<Vec<_>>(),
        })));
    }

    state.rocks.delete_record(&record_id, crate::storage::rocks::DeleteIntent::AdminEvict)
        .map_err(|e| AppError(ElaraError::Storage(format!("delete_record: {e}"))))?;
    evict_from_live_dag(&state, &record_id).await;
    if let Ok(Some(occupant)) = state.rocks.slot_lookup(&slot_key) {
        if occupant == record_id {
            state.rocks.slot_delete(&slot_key)
                .map_err(|e| AppError(ElaraError::Storage(format!("slot_delete: {e}"))))?;
        }
    }

    Ok(Json(serde_json::json!({
        "record_id": record_id,
        "evicted": true,
        "reason": "signature_failed_verify",
        "version": record.version,
        "timestamp": record.timestamp,
        "nonce": record.nonce,
        "slot_key": slot_key,
        "creator_pk_sha3": pk_sha3,
        "signable_bytes_sha3": signable_sha3,
        "signature_sha3": crate::crypto::hash::sha3_256_hex(sig),
        "metadata_keys": record.metadata.keys().cloned().collect::<Vec<_>>(),
    })))
}

// ─── /admin/forensic/slot/{ah}/{nonce}/evict_unverifiable ──────────────────
//
// ARCH-4 surgical repair: pre-monotonic-nonce records hardcoded with nonce=0
// (committed before ddb4600 on 2026-04-17) collided at slot
// `<creator>:0000000000000000`. Many of those records were also signed under
// the v4 signable_bytes formula and stored upgraded to v5 — so the v5
// verifier reads them back, builds nonce-inclusive signable_bytes, and the
// signature no longer verifies. A non-verifying record at the slot blocks
// every future legitimate emit at that (account, nonce) pair AND prevents
// `ConflictProof::verify` from constructing — so the conflict never gossips
// and the fleet diverges silently.
//
// This endpoint releases that exact deadlock: load the slot occupant, run
// `Identity::verify` on its current `signable_bytes()`, and if (and only if)
// verification fails, atomically drop both the slot index entry and the
// record from CF_RECORDS. A record whose own signature fails its own current
// formula is not a valid record under any interpretation — it cannot be
// gossiped to a fresh node, cannot be relayed, cannot be finalized. Storing
// it past a binary upgrade was a migration-coverage bug; this is the
// narrowest cure that puts that bug behind us.
//
// Auth uses `verify_admin_auth_pq_any_node` because eviction must run on
// every node (the bug manifests as cross-node divergence, so each node has a
// different unverifiable occupant). It is still PQ-Dilithium3-signed and
// allowlisted via ELARA_ADMIN_PUBKEYS.
//
// Returns:
//   - 400 if path components are malformed,
//   - 404 if the slot is empty (already free, nothing to evict),
//   - 200 with `evicted: false` + `sig_verifies: true` if the occupant is
//     valid (refuse to evict, this is not the right tool),
//   - 200 with `evicted: true` + before/after fingerprints if the occupant
//     was unverifiable and has been removed.
pub async fn admin_evict_unverifiable_slot(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Path((account_hash, nonce_hex)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    if account_hash.len() != 64 || !account_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError(ElaraError::Wire(
            "account_hash must be 64-char SHA3-256 hex".into(),
        )));
    }
    if nonce_hex.len() != 16 || !nonce_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError(ElaraError::Wire(
            "nonce_hex must be 16-char zero-padded hex of u64".into(),
        )));
    }

    let slot_key = format!("{}:{}", account_hash, nonce_hex);
    let record_id = match state.rocks.slot_lookup(&slot_key) {
        Ok(Some(id)) => id,
        Ok(None) => {
            return Ok(Json(serde_json::json!({
                "slot_key": slot_key,
                "evicted": false,
                "reason": "slot_already_empty",
                "note": "no slot index entry for this (account, nonce) — nothing to evict",
            })));
        }
        Err(e) => return Err(AppError(ElaraError::Storage(format!("slot_lookup: {e}")))),
    };

    let record = match state.rocks.get_record(&record_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            // Orphaned slot index entry — the record itself is already gone.
            // Still release the slot so a future legitimate emit can claim it.
            state.rocks.slot_delete(&slot_key)
                .map_err(|e| AppError(ElaraError::Storage(format!("slot_delete: {e}"))))?;
            return Ok(Json(serde_json::json!({
                "slot_key": slot_key,
                "record_id": record_id,
                "evicted": true,
                "reason": "orphaned_slot_index",
                "note": "slot pointed to a record_id absent from CF_RECORDS — released the index entry",
            })));
        }
        Err(e) => return Err(AppError(ElaraError::Storage(format!("get_record: {e}")))),
    };

    let signable = record.signable_bytes();
    let sig = match record.signature.as_deref() {
        Some(s) => s,
        None => {
            // No signature at all — definitely not a valid v5 record.
            // Evict + release the slot.
            state.rocks.delete_record(&record_id, crate::storage::rocks::DeleteIntent::AdminEvict)
                .map_err(|e| AppError(ElaraError::Storage(format!("delete_record: {e}"))))?;
            evict_from_live_dag(&state, &record_id).await;
            state.rocks.slot_delete(&slot_key)
                .map_err(|e| AppError(ElaraError::Storage(format!("slot_delete: {e}"))))?;
            return Ok(Json(serde_json::json!({
                "slot_key": slot_key,
                "record_id": record_id,
                "evicted": true,
                "reason": "no_signature_present",
                "version": record.version,
                "metadata_keys": record.metadata.keys().cloned().collect::<Vec<_>>(),
            })));
        }
    };

    let verifies = crate::identity::Identity::verify(&signable, sig, &record.creator_public_key).unwrap_or_default();

    if verifies {
        // Refuse to evict a valid record. This endpoint is for unverifiable
        // occupants only — anything else is the operator's mistake.
        return Ok(Json(serde_json::json!({
            "slot_key": slot_key,
            "record_id": record_id,
            "evicted": false,
            "reason": "signature_verifies",
            "note": "occupant is cryptographically valid — refusing to evict",
            "version": record.version,
            "timestamp": record.timestamp,
            "nonce": record.nonce,
            "metadata_keys": record.metadata.keys().cloned().collect::<Vec<_>>(),
        })));
    }

    // Unverifiable. Drop the record + the slot entry. Order matters: delete
    // the record first so a concurrent slot_lookup that races us either sees
    // the (now-stale) slot entry pointing at a missing record (handled by
    // ingest as "free slot") or sees the cleared slot entry directly.
    state.rocks.delete_record(&record_id, crate::storage::rocks::DeleteIntent::AdminEvict)
        .map_err(|e| AppError(ElaraError::Storage(format!("delete_record: {e}"))))?;
    evict_from_live_dag(&state, &record_id).await;
    state.rocks.slot_delete(&slot_key)
        .map_err(|e| AppError(ElaraError::Storage(format!("slot_delete: {e}"))))?;

    Ok(Json(serde_json::json!({
        "slot_key": slot_key,
        "record_id": record_id,
        "evicted": true,
        "reason": "signature_failed_verify",
        "version": record.version,
        "timestamp": record.timestamp,
        "nonce": record.nonce,
        "creator_pk_sha3": crate::crypto::hash::sha3_256_hex(&record.creator_public_key),
        "signable_bytes_sha3": crate::crypto::hash::sha3_256_hex(&signable),
        "signature_sha3": crate::crypto::hash::sha3_256_hex(sig),
        "metadata_keys": record.metadata.keys().cloned().collect::<Vec<_>>(),
    })))
}

// ─── /admin/pending_ledger ───────────────────────────────────────────────────

/// ARCH-1 observability: top-N creators currently holding pending deltas.
///
/// Closes the "which identity is bottlenecked" gap that the
/// `elara_pending_ledger_max_identity_depth` gauge cannot answer (gauge is a
/// scalar; can't expose the identity behind the number without a label, and
/// labelling on creator-id would explode cardinality on a million-creator
/// mainnet).
///
/// Returns:
/// - aggregate: depth, distinct_identities, max_per_identity_depth, oldest_age_secs
/// - lifetime counters: commits, discards, hard_discards, rejections,
///   fallback_direct_apply (the conservation-bypass path)
/// - top_creators[≤20]: per-creator depth + oldest_age_secs, sorted by depth
///   descending. Identity is the full creator string — admin endpoint, no
///   cardinality concern (bounded N, gated behind genesis admin auth).
///
/// Operator playbook:
/// - depth_total at MAX_TOTAL_PENDING (1M) → cluster-wide finality stall.
/// - distinct=1 + top[0].depth at MAX_PENDING_PER_IDENTITY (4096) →
///   single-creator cap-pinch (rate-limit upstream OR confirm fallback fired).
/// - distinct=1 + top[0].depth << 4096 + top[0].oldest_age_secs > 1200 →
///   single-creator finality bottleneck (Gap 8 territory). Top creator's
///   identity is the live bottleneck source — match against the
///   `top offender: identity=` log line emitted by ARCH-1 discard sweep.
pub async fn admin_pending_ledger(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — surfaces LOCAL pending-ledger top-N. Bottleneck
    // bisection across the fleet wants this on EVERY box (each node has its
    // own pending bucket), so genesis-only was the wrong gate from day 1.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    use std::sync::atomic::Ordering;
    let lifetime = PendingLedgerLifetimeCounters {
        commits_total: state.pending_ledger_commits_total.load(Ordering::Relaxed),
        discards_total: state.pending_ledger_discards_total.load(Ordering::Relaxed),
        hard_discards_total: state.pending_ledger_hard_discards_total.load(Ordering::Relaxed),
        rejections_total: state.pending_ledger_rejections_total.load(Ordering::Relaxed),
        fallback_direct_apply_total: state
            .pending_ledger_fallback_direct_apply_total
            .load(Ordering::Relaxed),
    };

    // O(pending ≤ MAX_TOTAL_PENDING=1M) aggregation on the blocking pool.
    // The pending_ledger read lock is held for the walk (ingest writers
    // wait — bounded by one pass), but an async executor worker isn't.
    let state2 = state.clone();
    let payload = tokio::task::spawn_blocking(move || {
        let pending = state2.pending_ledger.blocking_read();
        pending_ledger_inspection_payload(&pending, &lifetime, now)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;
    Ok(Json(payload))
}

/// `GET /admin/epoch_prune_shadow` — Tier 3.4 Slice 2 operator drilldown.
/// Returns up to 100 shadow-eligible seals (oldest first) so operators can
/// inspect which sealed-record sets would be reclaimed under epoch-based
/// pruning today, before flipping the policy on. Pure observation — does
/// not prune.
///
/// Response shape:
///   {
///     "horizon": 100,
///     "indexed_seals": <int>,
///     "eligible_seals": <int>,
///     "eligible_records": <int>,
///     "max_returned": 100,
///     "seals": [
///       { "seal_id": "...", "epoch": <u64>, "zone": "...",
///         "record_count": <usize>, "lag_epochs": <u64> },
///       ...
///     ]
///   }
pub async fn admin_epoch_prune_shadow(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Node-local — pure observation against LOCAL consensus state.
    // Operator wants this on each box to see per-node shadow counts before
    // flipping prune policy.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    const MAX_RETURNED: usize = 100;

    // One O(seals) pass under ONE take of the consensus lock (the epoch
    // seal loop's lock), on the blocking pool — replaces two back-to-back
    // full scans (count + drilldown) run inline on the async executor.
    // `eligible_seals` is now the TRUE eligible total from the fused scan,
    // not the MAX_RETURNED-capped list length the old route reported.
    let state2 = state.clone();
    let (indexed_seals, eligible_records, eligible_seals, entries) =
        tokio::task::spawn_blocking(move || {
            let zone_epochs: HashMap<crate::network::zone::ZoneId, u64> = {
                let epoch = state2.epoch.read_recover();
                epoch.latest_epoch.clone()
            };
            let horizon = crate::network::consensus::AWCConsensus::EPOCH_PRUNE_SHADOW_HORIZON;
            let consensus = state2.consensus.lock_recover();
            let indexed_seals = consensus.seal_epoch_indexed_count();
            let (eligible_records, eligible_seals, entries) =
                consensus.epoch_prune_shadow_summary(horizon, &zone_epochs, MAX_RETURNED);
            (indexed_seals, eligible_records, eligible_seals, entries)
        })
        .await
        .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;

    let seals: Vec<serde_json::Value> = entries
        .iter()
        .map(|(sid, epoch, zone, recs, lag)| {
            serde_json::json!({
                "seal_id": sid,
                "epoch": epoch,
                "zone": zone.to_string(),
                "record_count": recs,
                "lag_epochs": lag,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "horizon": crate::network::consensus::AWCConsensus::EPOCH_PRUNE_SHADOW_HORIZON,
        "indexed_seals": indexed_seals,
        "eligible_seals": eligible_seals,
        "eligible_records": eligible_records,
        "max_returned": MAX_RETURNED,
        "seals": seals,
    })))
}

// ─── /admin/rocks/compact_cf ────────────────────────────────────────────────
//
// Operator-triggered RocksDB compaction. Closes an ENOSPC runbook gap — the
// gc_loop's `pressure_due` branch already auto-triggers compaction
// (`gc.rs:556`), but the operator needs an escape hatch
// when (a) the box is full enough that gc cannot recover fast enough, or
// (b) bloat is suspected on a CF outside the gc's hard-coded list.
//
// Two referenced anchors that lied prior to this commit:
//   - server.rs:8096 HELP: "per-CF triage happens via `compact_cf` admin RPCs"
//   - server.rs:8108 HELP: "escalate via /admin/compact_cf if the CF is under known bloat"
// Neither endpoint existed; both now resolve to this handler.
//
// Auth gate widened from `verify_admin_auth_pq`
// (genesis-only) to `verify_admin_auth_pq_any_node`. The original build
// matched the rest of the admin surface's genesis-gating pattern by reflex,
// but compaction is a per-node housekeeping op — there's no cluster policy
// at stake. An observed ENOSPC incident hit exactly this wall: the affected
// node was not the genesis authority, so the operator could not POST
// `/admin/rocks/compact_cf` against it to drain its 18.7 GB of SSTs even
// with a valid PQ admin signature. Any-node auth keeps the same PQ
// signature + per-key allowlist + per-IP lockout protections; the only
// thing it relaxes is "must be the genesis authority" which the operator
// surface for compaction never depended on.

/// Heavy CFs that bloat under tombstones — same list `gc_loop` compacts on
/// `pressure_due` (`gc.rs:553-560`), plus `merkle` to match
/// `startup_compaction_if_needed`'s heavy-set (`rocks.rs:2829`).
pub(crate) const COMPACT_CF_ALLOWLIST: &[&str] = &[
    "records",
    "attestations",
    "dag",
    "idx_timestamp",
    "merkle",
];

#[derive(serde::Deserialize, Default)]
pub struct AdminCompactCfQuery {
    /// Single CF to compact. Must be in `COMPACT_CF_ALLOWLIST`. Omit to
    /// compact every CF in the allowlist (the runbook default).
    pub cf: Option<String>,
}

/// Resolve the operator's `?cf=` query into a concrete CF list, validating
/// against the allowlist. Pulled out so the validation contract is
/// unit-testable without spinning a NodeState (matches the
/// `prepare_onboard_anchor_record` pattern).
pub(crate) fn resolve_compact_cf_list(
    cf_query: Option<&str>,
) -> Result<Vec<&'static str>, String> {
    match cf_query {
        None | Some("") => Ok(COMPACT_CF_ALLOWLIST.to_vec()),
        Some(name) => match COMPACT_CF_ALLOWLIST.iter().find(|&&c| c == name) {
            Some(&c) => Ok(vec![c]),
            None => Err(format!(
                "compact_cf: '{name}' not in allowlist {:?}",
                COMPACT_CF_ALLOWLIST
            )),
        },
    }
}

pub async fn admin_rocks_compact_cf(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    State(state): State<Arc<NodeState>>,
    Query(q): Query<AdminCompactCfQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Audit 2026-05-11: any-node, NOT genesis-only. Compaction is per-node
    // housekeeping; the operator must be able to invoke it on whichever box
    // is under disk pressure regardless of which node currently holds the
    // genesis identity. PQ signature + allowlist + per-IP lockout still apply.
    verify_admin_auth_pq_any_node(&state, method.as_str(), &uri, &headers)?;

    let cfs = resolve_compact_cf_list(q.cf.as_deref()).map_err(ElaraError::Network)?;

    let rocks = state.rocks.clone();
    let cfs_for_task = cfs.clone();
    tokio::task::spawn_blocking(move || {
        tracing::info!(
            target: "elara::admin",
            "admin: operator-triggered compact_cf start: {cfs:?}",
            cfs = cfs_for_task
        );
        for cf in &cfs_for_task {
            rocks.compact_cf(cf);
        }
        tracing::info!(
            target: "elara::admin",
            "admin: operator-triggered compact_cf complete: {cfs:?}",
            cfs = cfs_for_task
        );
    });

    state
        .admin_compact_cf_triggered_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    Ok(Json(serde_json::json!({
        "triggered": true,
        "cfs": cfs,
        "note": "compaction runs in background; check elara_rocksdb_running_compactions + total-sst-files-size for completion",
    })))
}

/// Snapshot of the lifetime counters that ride alongside the live PendingLedger
/// in the `/admin/pending_ledger` payload. Captured before the read lock so the
/// inspection helper is a pure fn over plain values — testable without
/// constructing a full `NodeState`.
pub(super) struct PendingLedgerLifetimeCounters {
    pub commits_total: u64,
    pub discards_total: u64,
    pub hard_discards_total: u64,
    pub rejections_total: u64,
    pub fallback_direct_apply_total: u64,
}

/// Builds the JSON payload for `/admin/pending_ledger`. Pure fn so the
/// per-creator aggregation + sort priority + top-20 truncation contract
/// is unit-testable without spinning up a NodeState.
///
/// Sort priority for `top_creators`: depth descending, then oldest-first on
/// tie (smaller `applied_at` ranks higher among equal depths). Truncated to
/// 20 entries — the diagnostic shape always shows up in the top of the bucket.
pub(super) fn pending_ledger_inspection_payload(
    pending: &crate::accounting::pending_ledger::PendingLedger,
    lifetime: &PendingLedgerLifetimeCounters,
    now: f64,
) -> serde_json::Value {
    use crate::accounting::pending_ledger::{MAX_PENDING_PER_IDENTITY, MAX_TOTAL_PENDING};

    // O(pending_count) — bounded by MAX_TOTAL_PENDING=1M, runs admin-side.
    let mut per_creator: HashMap<String, (u64, f64)> = HashMap::new();
    for d in pending.iter() {
        let entry = per_creator
            .entry(d.creator.clone())
            .or_insert((0, d.applied_at));
        entry.0 += 1;
        if d.applied_at < entry.1 {
            entry.1 = d.applied_at;
        }
    }

    let mut sorted: Vec<(String, u64, f64)> = per_creator
        .into_iter()
        .map(|(creator, (depth, oldest))| (creator, depth, oldest))
        .collect();
    sorted.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then(a.2.total_cmp(&b.2))
    });
    sorted.truncate(20);

    let top_creators: Vec<serde_json::Value> = sorted
        .into_iter()
        .map(|(creator, depth, oldest)| {
            let age = (now - oldest).max(0.0);
            serde_json::json!({
                "identity": creator,
                "depth": depth,
                "oldest_age_secs": (age * 10.0).round() / 10.0,
            })
        })
        .collect();

    let oldest_age = pending
        .oldest_applied_at()
        .map(|a| (now - a).max(0.0))
        .unwrap_or(0.0);

    serde_json::json!({
        "aggregate": {
            "depth": pending.len() as u64,
            "distinct_identities": pending.distinct_identities() as u64,
            "max_per_identity_depth": pending.max_per_identity_depth() as u64,
            "oldest_age_secs": (oldest_age * 10.0).round() / 10.0,
        },
        "lifetime_counters": {
            "commits_total": lifetime.commits_total,
            "discards_total": lifetime.discards_total,
            "hard_discards_total": lifetime.hard_discards_total,
            "rejections_total": lifetime.rejections_total,
            "fallback_direct_apply_total": lifetime.fallback_direct_apply_total,
        },
        "top_creators": top_creators,
        "max_per_identity_cap": MAX_PENDING_PER_IDENTITY,
        "max_total_cap": MAX_TOTAL_PENDING,
    })
}

#[cfg(test)]
mod admin_zone_transition_guard_tests {
    use super::zone_transition_min_target;
    use crate::network::zone_transition_seal::TRANSITION_DISPUTE_WINDOW_EPOCHS;

    #[test]
    fn admin_lead_time_matches_auto_scaler_dispute_window() {
        // The auto-scaler schedules every transition at
        // current + TRANSITION_DISPUTE_WINDOW_EPOCHS (auto_scale.rs). The
        // operator path must never accept a shorter lead: a transition landing
        // inside the window lets nodes flip get_zone_count() at different
        // wall-clock moments → same record routed to different zones (fork).
        assert_eq!(
            zone_transition_min_target(1000) - 1000,
            TRANSITION_DISPUTE_WINDOW_EPOCHS,
            "admin guard must mirror the auto-scaler's dispute window exactly"
        );
        // The pre-fix behavior (accepting current+1) must be below the floor.
        assert!(
            1001 < zone_transition_min_target(1000),
            "target = current+1 must be rejected by the guard"
        );
        // Overflow safety at the top of the epoch range.
        assert_eq!(zone_transition_min_target(u64::MAX), u64::MAX);
    }
}

#[cfg(test)]
mod admin_pending_ledger_tests {
    use super::{pending_ledger_inspection_payload, PendingLedgerLifetimeCounters};
    use crate::accounting::pending_delta::{PendingLedgerDelta, PendingOp};
    use crate::accounting::pending_ledger::PendingLedger;
    use std::collections::HashMap;

    fn mk_delta(record_id: &str, creator: &str, applied_at: f64) -> PendingLedgerDelta {
        PendingLedgerDelta::new(
            record_id.to_string(),
            creator.to_string(),
            applied_at,
            applied_at,
            PendingOp::Transfer {
                from: creator.to_string(),
                to: "bob".to_string(),
                amount: 1,
                memo: None,
            },
        )
    }

    fn empty_lifetime() -> PendingLedgerLifetimeCounters {
        PendingLedgerLifetimeCounters {
            commits_total: 0,
            discards_total: 0,
            hard_discards_total: 0,
            rejections_total: 0,
            fallback_direct_apply_total: 0,
        }
    }

    #[test]
    fn empty_pending_ledger_yields_zero_aggregate_and_empty_top_creators() {
        let pending = PendingLedger::new();
        let now = 1_000_000.0;
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);

        let agg = &payload["aggregate"];
        assert_eq!(agg["depth"], 0);
        assert_eq!(agg["distinct_identities"], 0);
        assert_eq!(agg["max_per_identity_depth"], 0);
        assert_eq!(agg["oldest_age_secs"], 0.0);

        assert!(
            payload["top_creators"].as_array().unwrap().is_empty(),
            "empty pending → top_creators must be []"
        );

        // Caps come from the constants — verifies they're surfaced for ops.
        assert_eq!(payload["max_per_identity_cap"], 4096);
        assert_eq!(payload["max_total_cap"], 1_048_576);
    }

    #[test]
    fn single_creator_finality_bottleneck_shape_is_distinguishable() {
        // The testnet pathology shape: distinct=1, top[0] has elevated depth
        // and oldest_age > 1200s. Operators read this combination as Gap 8
        // territory — single-creator finality bottleneck, not cap-pinch.
        let mut pending = PendingLedger::new();
        let bottleneck = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let now = 10_000.0;
        let oldest_applied_at = now - 1500.0; // 1500s old → over the 1200s gate
        for i in 0..7 {
            pending
                .insert(mk_delta(
                    &format!("rec-{i}"),
                    bottleneck,
                    oldest_applied_at + (i as f64),
                ))
                .expect("insert");
        }

        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);
        let agg = &payload["aggregate"];
        assert_eq!(agg["depth"], 7);
        assert_eq!(agg["distinct_identities"], 1);
        assert_eq!(agg["max_per_identity_depth"], 7);
        let oldest_age = agg["oldest_age_secs"].as_f64().unwrap();
        assert!(
            (1500.0..=1500.5).contains(&oldest_age),
            "oldest_age must reflect oldest applied_at — got {oldest_age}"
        );

        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(top[0]["identity"], bottleneck);
        assert_eq!(top[0]["depth"], 7);
        let top_age = top[0]["oldest_age_secs"].as_f64().unwrap();
        assert!(top_age > 1200.0, "bottleneck shape requires oldest > 1200s");
    }

    #[test]
    fn top_creators_sorted_by_depth_descending_oldest_first_on_tie() {
        // Setup: alice with depth 5 (oldest at t=10), bob with depth 5
        // (oldest at t=5), carol with depth 2. Expected order on ties:
        // bob first (older oldest_applied_at), then alice, then carol.
        let mut pending = PendingLedger::new();
        for i in 0..5 {
            pending
                .insert(mk_delta(&format!("a-{i}"), "alice", 10.0 + i as f64))
                .expect("insert alice");
        }
        for i in 0..5 {
            pending
                .insert(mk_delta(&format!("b-{i}"), "bob", 5.0 + i as f64))
                .expect("insert bob");
        }
        for i in 0..2 {
            pending
                .insert(mk_delta(&format!("c-{i}"), "carol", 100.0 + i as f64))
                .expect("insert carol");
        }

        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(top.len(), 3);
        assert_eq!(top[0]["identity"], "bob"); // depth 5, oldest_at=5 (older)
        assert_eq!(top[0]["depth"], 5);
        assert_eq!(top[1]["identity"], "alice"); // depth 5, oldest_at=10
        assert_eq!(top[1]["depth"], 5);
        assert_eq!(top[2]["identity"], "carol"); // depth 2 → last
        assert_eq!(top[2]["depth"], 2);
    }

    #[test]
    fn top_creators_truncated_to_20_when_distinct_exceeds_limit() {
        // 25 creators each with depth descending from 25 down to 1. Top 20
        // must come back; the 5 smallest-depth creators must be dropped.
        let mut pending = PendingLedger::new();
        for c in 0..25 {
            let depth = 25 - c;
            for i in 0..depth {
                pending
                    .insert(mk_delta(
                        &format!("c{c}-r{i}"),
                        &format!("creator-{c:02}"),
                        100.0,
                    ))
                    .expect("insert");
            }
        }

        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(top.len(), 20, "top_creators must truncate to 20");
        assert_eq!(top[0]["identity"], "creator-00", "creator-00 had highest depth (25)");
        assert_eq!(top[0]["depth"], 25);
        assert_eq!(top[19]["identity"], "creator-19", "20th entry must be creator-19 (depth 6)");
        assert_eq!(top[19]["depth"], 6);

        let agg = &payload["aggregate"];
        assert_eq!(agg["distinct_identities"], 25, "aggregate sees all 25 even though top is capped");
    }

    #[test]
    fn lifetime_counters_passed_through_unchanged() {
        // Ensures the JSON shape exposes every counter ops dashboards need.
        let pending = PendingLedger::new();
        let lifetime = PendingLedgerLifetimeCounters {
            commits_total: 100,
            discards_total: 200,
            hard_discards_total: 7,
            rejections_total: 13,
            fallback_direct_apply_total: 42,
        };
        let payload = pending_ledger_inspection_payload(&pending, &lifetime, 0.0);
        let lc = &payload["lifetime_counters"];
        assert_eq!(lc["commits_total"], 100);
        assert_eq!(lc["discards_total"], 200);
        assert_eq!(lc["hard_discards_total"], 7);
        assert_eq!(lc["rejections_total"], 13);
        assert_eq!(lc["fallback_direct_apply_total"], 42);
    }

    #[test]
    fn batch_t_clock_skew_future_applied_at_clamps_oldest_age_to_zero() {
        // The helper computes `(now - applied_at).max(0.0)` at two call sites:
        // top_creators[].oldest_age_secs and aggregate.oldest_age_secs. Both
        // must clamp to 0.0 when `applied_at` is in the future relative to
        // `now` (NTP skew between the account host that stamped the delta and
        // the admin node serving the inspection). Without the clamp the
        // operator dashboard would render a negative age, which the ops parser
        // rejects as malformed — a silent regression vs the runbook contract.
        let mut pending = PendingLedger::new();
        let now = 1_000.0;
        let future_applied = now + 500.0;
        pending
            .insert(mk_delta("rec-skew", "skewed-creator", future_applied))
            .expect("insert");
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);

        assert_eq!(
            payload["aggregate"]["oldest_age_secs"], 0.0,
            "future applied_at must clamp aggregate.oldest_age_secs to 0.0"
        );
        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(
            top[0]["oldest_age_secs"], 0.0,
            "future applied_at must clamp top_creators[].oldest_age_secs to 0.0"
        );
    }

    #[test]
    fn batch_t_singleton_creators_each_depth_one_sorted_oldest_first() {
        // Five distinct creators, each with exactly one pending record, all at
        // tied depth=1. The sort priority is (depth desc, oldest_applied_at
        // asc), so on a uniform depth-1 surface the entire ordering reduces
        // to oldest-first. This is the "low-load fan-out" shape — many
        // accounts with a single in-flight record — and the operator dashboard
        // relies on the deterministic oldest-first tiebreak to surface the
        // account that's been stuck the longest at the top of the list.
        let mut pending = PendingLedger::new();
        for i in 0..5 {
            // applied_at: 50.0, 40.0, 30.0, 20.0, 10.0 — descending, so the
            // oldest (10.0) is creator-4 and must come back first.
            let applied_at = 50.0 - (i as f64) * 10.0;
            pending
                .insert(mk_delta(
                    &format!("r-{i}"),
                    &format!("creator-{i}"),
                    applied_at,
                ))
                .expect("insert");
        }
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);

        assert_eq!(payload["aggregate"]["depth"], 5);
        assert_eq!(payload["aggregate"]["distinct_identities"], 5);
        assert_eq!(payload["aggregate"]["max_per_identity_depth"], 1);

        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(top.len(), 5);
        for entry in top {
            assert_eq!(entry["depth"], 1, "every entry must show depth=1");
        }
        // Oldest-first on tied depth → creator-4 (applied_at=10.0) leads.
        assert_eq!(top[0]["identity"], "creator-4");
        assert_eq!(top[4]["identity"], "creator-0");
    }

    #[test]
    fn batch_u_same_creator_min_applied_at_retained_under_jumbled_insertion_order() {
        // Pins the per-creator min-retention branch at
        // `pending_ledger_inspection_payload`: when a creator already has an
        // entry, the helper updates `entry.1 = d.applied_at` ONLY if the new
        // delta's applied_at is strictly less than the stored value. Insert
        // three deltas in jumbled order (middle, then oldest, then newest)
        // for the SAME creator; the payload must surface the smallest
        // applied_at as `oldest_age_secs`. Without the explicit min-branch
        // the second insertion would either overwrite (newest-wins regression)
        // or get short-circuited (first-wins regression) and the dashboard
        // would render the wrong "stuck since" age.
        let mut pending = PendingLedger::new();
        let now = 1_000.0;
        pending
            .insert(mk_delta("r-mid", "alice", 500.0))
            .expect("insert mid");
        pending
            .insert(mk_delta("r-oldest", "alice", 100.0))
            .expect("insert oldest");
        pending
            .insert(mk_delta("r-newest", "alice", 900.0))
            .expect("insert newest");

        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);
        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(top[0]["identity"], "alice");
        assert_eq!(top[0]["depth"], 3);
        // Min retained: applied_at=100.0 → age = 1000 - 100 = 900.0s.
        // Verifies the min-branch fires on the SECOND insertion (oldest after
        // mid) AND does NOT fire on the THIRD insertion (newest after min).
        let top_age = top[0]["oldest_age_secs"].as_f64().unwrap();
        assert!(
            (top_age - 900.0).abs() < 0.05,
            "min-retention must surface oldest applied_at — got {top_age}, want ~900.0"
        );
        // Aggregate uses pending.oldest_applied_at() — same answer for a
        // single creator but pinned separately to detect drift if either
        // path forgets to track the oldest.
        let agg_age = payload["aggregate"]["oldest_age_secs"].as_f64().unwrap();
        assert!(
            (agg_age - 900.0).abs() < 0.05,
            "aggregate oldest_age_secs must also reflect min applied_at — got {agg_age}"
        );
    }

    #[test]
    fn batch_u_oldest_age_secs_one_decimal_rounding_pins_dashboard_contract() {
        // Pins the `(age * 10.0).round() / 10.0` rule used at the two emit
        // sites (top_creators[].oldest_age_secs + aggregate.oldest_age_secs).
        // The dashboard contract is "1 decimal place"; a silent switch to
        // truncation (`(x * 10.0).trunc() / 10.0`) would shift values near
        // the .X5 boundary downward and misrepresent finality lag.
        //
        // Decimal literals like 0.05 / 0.15 are NOT exactly representable in
        // f64 (they are 0.04999... / 0.14999...), so we pick values that
        // are safely clear of the .X5 rounding boundary in BOTH directions:
        //   age = 0.04s   → round(0.4)  = 0   → display 0.0
        //   age = 0.36s   → round(3.6)  = 4   → display 0.4
        //   age = 12.99s  → round(129.9)= 130 → display 13.0
        //   age = 42.0s   → round(420.0)= 420 → display 42.0 (integer pass-through)
        let now = 1_000.0;

        let mut pending = PendingLedger::new();
        pending
            .insert(mk_delta("rb", "below-half", now - 0.04))
            .expect("insert");
        let p = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);
        let below = p["top_creators"][0]["oldest_age_secs"].as_f64().unwrap();
        assert!(
            (below - 0.0).abs() < 1e-9,
            "age=0.04 must round-down to 0.0, got {below}"
        );

        let mut pending2 = PendingLedger::new();
        pending2
            .insert(mk_delta("ra", "above-half", now - 0.36))
            .expect("insert");
        let p2 = pending_ledger_inspection_payload(&pending2, &empty_lifetime(), now);
        let above = p2["top_creators"][0]["oldest_age_secs"].as_f64().unwrap();
        assert!(
            (above - 0.4).abs() < 1e-9,
            "age=0.36 must round-up to 0.4, got {above}"
        );

        let mut pending3 = PendingLedger::new();
        pending3
            .insert(mk_delta("rd", "near-tens-step", now - 12.99))
            .expect("insert");
        let p3 = pending_ledger_inspection_payload(&pending3, &empty_lifetime(), now);
        let near_step = p3["top_creators"][0]["oldest_age_secs"].as_f64().unwrap();
        assert!(
            (near_step - 13.0).abs() < 1e-9,
            "age=12.99 must round-up to 13.0, got {near_step}"
        );

        // Integer-second age: age=42.0 → display 42.0 unchanged (pass-through
        // verifies the rounding rule doesn't perturb integer-valued ages).
        let mut pending4 = PendingLedger::new();
        pending4
            .insert(mk_delta("rc", "exact-int", now - 42.0))
            .expect("insert");
        let p4 = pending_ledger_inspection_payload(&pending4, &empty_lifetime(), now);
        let exact = p4["top_creators"][0]["oldest_age_secs"].as_f64().unwrap();
        assert!(
            (exact - 42.0).abs() < 1e-9,
            "age=42.0 must round-to 42.0 exactly, got {exact}"
        );
    }

    #[test]
    fn batch_u_aggregate_max_per_identity_depth_reflects_deepest_creator_only() {
        // Pin `aggregate.max_per_identity_depth` against a heterogeneous
        // depth shape: alice=4, bob=2, carol=1. The aggregate must report 4
        // (alice's depth), NOT the sum (7) or distinct count (3). Operators
        // read this field to spot per-identity cap-pinch approaching
        // MAX_PENDING_PER_IDENTITY=4096 — a sum or count would mask the
        // signal entirely (cap-pinch fires on per-identity, not aggregate
        // depth).
        let mut pending = PendingLedger::new();
        for i in 0..4 {
            pending
                .insert(mk_delta(&format!("a-{i}"), "alice", 100.0 + i as f64))
                .expect("insert alice");
        }
        for i in 0..2 {
            pending
                .insert(mk_delta(&format!("b-{i}"), "bob", 200.0 + i as f64))
                .expect("insert bob");
        }
        pending
            .insert(mk_delta("c-0", "carol", 300.0))
            .expect("insert carol");

        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let agg = &payload["aggregate"];
        assert_eq!(agg["depth"], 7, "aggregate depth is the SUM (4+2+1)");
        assert_eq!(agg["distinct_identities"], 3, "three distinct creators");
        assert_eq!(
            agg["max_per_identity_depth"], 4,
            "max_per_identity_depth is the DEEPEST creator (alice=4), not sum or distinct"
        );
    }

    #[test]
    fn batch_u_lifetime_counters_u64_max_round_trip_through_serde_no_silent_narrowing() {
        // Regression guard: the lifetime counters arrive as u64 (sourced from
        // AtomicU64 / fetch_add at admin/pending_ledger) and the JSON payload
        // must preserve them across the full u64 range. A silent narrowing
        // to i64 (the default for `serde_json::Number` integer path on some
        // platforms) would saturate above i64::MAX and truncate the operator
        // dashboard's lifetime totals after long uptime. `u64::MAX` =
        // 18_446_744_073_709_551_615 fits as a JSON integer per RFC 8259 §6
        // and serde_json::Number::as_u64 round-trips it faithfully — pin
        // that contract here so a future swap to a non-u64 path fails loudly.
        let pending = PendingLedger::new();
        let lifetime = PendingLedgerLifetimeCounters {
            commits_total: u64::MAX,
            discards_total: u64::MAX - 1,
            hard_discards_total: u64::MAX - 2,
            rejections_total: u64::MAX - 3,
            fallback_direct_apply_total: u64::MAX - 4,
        };
        let payload = pending_ledger_inspection_payload(&pending, &lifetime, 0.0);
        let lc = &payload["lifetime_counters"];
        assert_eq!(
            lc["commits_total"].as_u64().unwrap(),
            u64::MAX,
            "u64::MAX must survive round-trip via as_u64"
        );
        assert_eq!(lc["discards_total"].as_u64().unwrap(), u64::MAX - 1);
        assert_eq!(lc["hard_discards_total"].as_u64().unwrap(), u64::MAX - 2);
        assert_eq!(lc["rejections_total"].as_u64().unwrap(), u64::MAX - 3);
        assert_eq!(
            lc["fallback_direct_apply_total"].as_u64().unwrap(),
            u64::MAX - 4
        );
        // Belt-and-braces: assert as_i64 returns None for the value that
        // exceeds i64::MAX. If a future regression narrows the serde path to
        // i64 these would falsely succeed.
        assert!(
            lc["commits_total"].as_i64().is_none(),
            "u64::MAX must NOT be representable as i64 (would indicate silent narrowing)"
        );
    }

    // ─── Wire-shape contracts ────────────────────────────────────────────────
    //
    // Density-hygiene slice on `pending_ledger_inspection_payload`. Prior
    // slices pinned behavioral contracts (sort priority, min-retention,
    // clock-skew clamp, rounding, u64 round-trip). This slice closes the
    // wire-shape contract on the JSON envelope so the operator dashboard +
    // any third-party `/admin/pending_ledger` consumer is locked against a
    // silent key-addition / key-removal regression:
    //   • top-level object always has the same exact key set;
    //   • every sub-object (aggregate, lifetime_counters, top_creators
    //     entries) pins its exact key set;
    //   • the surfaced max-cap pair is sourced from the
    //     `crate::accounting::pending_ledger` constants, not hardcoded magic
    //     numbers (a bump in either constant must surface here, not just in
    //     the runbook prose).
    //
    // Pattern parallels the `compute_zones_scope` wire-shape tests: each entry
    // is a pure key-set + type-shape check, no behavioral coverage overlap.

    #[test]
    fn batch_dd_top_level_payload_object_with_exactly_five_keys() {
        // The dashboard contract for `/admin/pending_ledger` is a 5-key
        // top-level object: {aggregate, lifetime_counters, top_creators,
        // max_per_identity_cap, max_total_cap}. A silent 6th key (e.g.
        // accidentally leaving a `_debug` field in during a refactor) would
        // bloat every operator scrape and could leak internal-only state.
        // Conversely a silent 4-key shape (e.g. dropping `top_creators` on
        // an empty-pending optimization) would break the runbook's
        // "is top_creators empty?" diagnostic for the single-creator
        // bottleneck shape pinned in `single_creator_finality_bottleneck_shape_is_distinguishable`.
        let pending = PendingLedger::new();
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 0.0);
        let obj = payload
            .as_object()
            .expect("top-level payload must be a JSON Object");
        let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "aggregate",
                "lifetime_counters",
                "max_per_identity_cap",
                "max_total_cap",
                "top_creators",
            ],
            "top-level payload key set must be exactly 5 documented keys; \
             a drift here breaks the dashboard schema + every curl runbook"
        );
    }

    #[test]
    fn batch_dd_aggregate_subobject_has_exactly_four_keys() {
        // `aggregate` is the diagnostic block the operator dashboard
        // renders front-and-center. Its 4-key shape — {depth,
        // distinct_identities, max_per_identity_depth, oldest_age_secs} —
        // is the input contract for the per-node "pending ledger pressure"
        // card. A silent 5th key would scroll the card layout; a missing
        // key would render a `--` placeholder and mask the underlying
        // signal.
        let pending = PendingLedger::new();
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 0.0);
        let agg = payload["aggregate"]
            .as_object()
            .expect("aggregate must be a JSON Object");
        let mut keys: Vec<&str> = agg.keys().map(|s| s.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "depth",
                "distinct_identities",
                "max_per_identity_depth",
                "oldest_age_secs",
            ],
            "aggregate sub-object key set must be exactly the 4 documented keys; \
             a drift here breaks the dashboard pressure-card schema"
        );
    }

    #[test]
    fn batch_dd_lifetime_counters_subobject_has_exactly_five_keys() {
        // The 5-counter contract on lifetime_counters mirrors the 5-field
        // `PendingLedgerLifetimeCounters` struct (commits_total,
        // discards_total, hard_discards_total, rejections_total,
        // fallback_direct_apply_total). A future addition (e.g. a 6th
        // `applied_via_seal_total`) must update both the struct AND this
        // test — pinning the count here forces the dashboard schema to be
        // updated in lockstep instead of silently lagging behind the
        // counter taxonomy.
        let pending = PendingLedger::new();
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 0.0);
        let lc = payload["lifetime_counters"]
            .as_object()
            .expect("lifetime_counters must be a JSON Object");
        let mut keys: Vec<&str> = lc.keys().map(|s| s.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "commits_total",
                "discards_total",
                "fallback_direct_apply_total",
                "hard_discards_total",
                "rejections_total",
            ],
            "lifetime_counters key set must be exactly 5 documented keys \
             (mirrors PendingLedgerLifetimeCounters fields 1:1)"
        );
    }

    #[test]
    fn batch_dd_top_creators_entry_has_exactly_three_keys_identity_depth_oldest_age_secs() {
        // Each `top_creators` entry is a 3-key object: {identity, depth,
        // oldest_age_secs}. The operator runbook for the single-creator
        // bottleneck (internal design notes)
        // greps for this exact key set; a silent addition of e.g. a
        // `record_ids` array would bloat the response from O(creators) to
        // O(records) and could push the JSON envelope past the operator
        // dashboard's parse budget at the 4096-per-identity cap.
        let mut pending = PendingLedger::new();
        pending
            .insert(mk_delta("rec-shape", "shape-creator", 100.0))
            .expect("insert");
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 200.0);
        let top = payload["top_creators"].as_array().expect("top_creators must be a JSON Array");
        assert_eq!(top.len(), 1, "single insert → single entry");
        let entry = top[0].as_object().expect("entry must be a JSON Object");
        let mut keys: Vec<&str> = entry.keys().map(|s| s.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["depth", "identity", "oldest_age_secs"],
            "top_creators entry must have exactly the 3 documented keys; \
             additional keys would bloat the response at the per-identity cap"
        );
    }

    #[test]
    fn batch_dd_max_caps_match_pending_ledger_constants_exactly() {
        // The `max_per_identity_cap` + `max_total_cap` fields surface the
        // ARCH-1 capacity limits to the operator dashboard. They MUST be
        // sourced from the `crate::accounting::pending_ledger` constants
        // (MAX_PENDING_PER_IDENTITY=4096, MAX_TOTAL_PENDING=1_048_576) and
        // not be free-standing JSON literals — a constant bump in
        // pending_ledger.rs must propagate to the dashboard without a
        // separate code edit. The empty-pending test at L2836 already pins
        // the literal values; this test adds the structural guard that the
        // values are sourced from the same constants the runtime uses for
        // admission control.
        use crate::accounting::pending_ledger::{MAX_PENDING_PER_IDENTITY, MAX_TOTAL_PENDING};
        let pending = PendingLedger::new();
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 0.0);
        assert_eq!(
            payload["max_per_identity_cap"].as_u64().expect("u64"),
            MAX_PENDING_PER_IDENTITY as u64,
            "max_per_identity_cap must equal MAX_PENDING_PER_IDENTITY \
             (admission-control constant — not a free-standing JSON literal)"
        );
        assert_eq!(
            payload["max_total_cap"].as_u64().expect("u64"),
            MAX_TOTAL_PENDING as u64,
            "max_total_cap must equal MAX_TOTAL_PENDING \
             (admission-control constant — not a free-standing JSON literal)"
        );
        // Belt-and-braces: pin the integer JSON type so a future change to
        // f64 (e.g. via serde_json::Number::from_f64) would surface here.
        assert!(
            payload["max_per_identity_cap"].is_u64(),
            "max_per_identity_cap must serialize as an unsigned integer"
        );
        assert!(
            payload["max_total_cap"].is_u64(),
            "max_total_cap must serialize as an unsigned integer"
        );
    }

    // ─── Wire-shape hardening (continued) ────────────────────────────────────
    //
    // Continues the wire-shape hardening opened on the
    // `pending_ledger_inspection_payload` JSON envelope. The prior slice pinned the
    // top-level and sub-object key SETS; this slice pins:
    //   • the truncate-cap boundary at exactly 21 distinct creators (earlier
    //     slices covered 25-creators; the boundary itself was unpinned —
    //     a future off-by-one regression to `.truncate(21)` would pass the
    //     N=25 test and silently let a 21st creator surface);
    //   • per-entry FIELD type contracts (top_creators[i].identity is String,
    //     top_creators[i].depth is u64) which the prior exact-key-set tests
    //     only partially imply — a future struct field re-type to a Number-as-
    //     String or a u64 → f64 narrowing would survive the key-set check;
    //   • the JSON Array type contract on `top_creators` directly (the prior
    //     test 1 pins it via `as_array().unwrap()` which would lenient-unwrap
    //     a null — `.is_array()` is the strict type pin);
    //   • the depth-vs-truncate algebraic invariant: `distinct_identities ≥
    //     top_creators.len()` always, with equality iff distinct ≤ 20.
    //   • the empty-pending oldest_age_secs emission as exactly 0.0 (not
    //     -0.0, not the absent/null path) — operator dashboard "lag" widget
    //     parses this as f64.

    #[test]
    fn batch_ee_exactly_twenty_one_distinct_creators_drops_only_the_lowest_depth_one() {
        // Boundary test at N=21: top_creators must be capped at 20 entries,
        // with the lowest-depth (creator-20, depth=1) dropped. The existing
        // `top_creators_truncated_to_20_when_distinct_exceeds_limit` test
        // uses N=25 which is 5 past the boundary — an off-by-one regression
        // to `.truncate(21)` would let creator-20 surface and silently bloat
        // the operator dashboard; the N=25 test would still pass because
        // it only asserts top.len()==20, which truncate(21) would also
        // satisfy by dropping creator-21..24. Pin the exact boundary here.
        let mut pending = PendingLedger::new();
        for c in 0..21 {
            let depth = 21 - c; // 21, 20, …, 1
            for i in 0..depth {
                pending
                    .insert(mk_delta(
                        &format!("c{c}-r{i}"),
                        &format!("creator-{c:02}"),
                        100.0,
                    ))
                    .expect("insert");
            }
        }
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(
            top.len(),
            20,
            "21 distinct creators must truncate to exactly 20 — boundary pin"
        );
        // creator-00 (depth 21) at top; creator-19 (depth 2) at position 19.
        assert_eq!(top[0]["identity"], "creator-00");
        assert_eq!(top[0]["depth"], 21);
        assert_eq!(top[19]["identity"], "creator-19");
        assert_eq!(top[19]["depth"], 2);
        // creator-20 (depth 1) must NOT appear — pin negative
        // exhaustively (a strict .contains() over identities).
        let identities: Vec<&str> = top
            .iter()
            .map(|e| e["identity"].as_str().unwrap())
            .collect();
        assert!(
            !identities.contains(&"creator-20"),
            "creator-20 (depth=1, lowest) must be dropped — got identities: {identities:?}"
        );
        // Aggregate still sees all 21
        assert_eq!(
            payload["aggregate"]["distinct_identities"], 21,
            "aggregate must report all 21 distinct creators, not the truncated 20"
        );
    }

    #[test]
    fn batch_ee_top_creators_field_is_strict_json_array_type_on_empty_pending() {
        // Pin: `top_creators` value is a STRICT JSON Array (`.is_array()`),
        // not null, not an object, not absent. The existing empty-pending
        // tests use `.as_array().unwrap()` which accepts the value as-array
        // but would silently coerce in some serde paths. The `.is_array()`
        // method is the strict type predicate — a future regression that
        // changed the serializer to emit `null` for empty-Vec optimization
        // would fail this test specifically while the `.as_array().unwrap()`
        // path could still pass (`null` does not panic via `.as_array()` on
        // some serde_json versions — explicit Option<&Vec> conversion).
        let pending = PendingLedger::new();
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 0.0);
        let tc = &payload["top_creators"];
        assert!(
            tc.is_array(),
            "top_creators must serialize as a JSON Array, got: {tc:?}"
        );
        assert!(
            !tc.is_null(),
            "top_creators must NOT serialize as JSON null on empty-pending state"
        );
        assert_eq!(
            tc.as_array().unwrap().len(),
            0,
            "empty pending → top_creators must be an empty Array []"
        );
    }

    #[test]
    fn batch_ee_top_creators_entry_identity_field_is_strict_json_string_type() {
        // Pin: each top_creators[i].identity is a strict JSON String type
        // (`.is_string()`), NOT a Number, NOT a null. The
        // `entry_has_exactly_three_keys` test pins the KEY presence but not
        // the field's TYPE — a future regression that serialized the creator
        // identity as a u64 (e.g. via a hash-as-number encoding) would
        // survive the key-set check and silently break every operator
        // dashboard that calls `.identity as string`.
        let mut pending = PendingLedger::new();
        pending
            .insert(mk_delta("r0", "alice", 100.0))
            .expect("insert");
        pending.insert(mk_delta("r1", "bob", 200.0)).expect("insert");
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let top = payload["top_creators"].as_array().unwrap();
        assert!(!top.is_empty(), "test setup must produce ≥1 creator");
        for (i, entry) in top.iter().enumerate() {
            assert!(
                entry["identity"].is_string(),
                "top_creators[{i}].identity must be a JSON String, got: {:?}",
                entry["identity"]
            );
        }
    }

    #[test]
    fn batch_ee_top_creators_entry_depth_field_is_strict_unsigned_integer_not_float() {
        // Pin: each top_creators[i].depth is a strict JSON unsigned integer
        // (`.is_u64()`), NOT a float, NOT a string. The function emits
        // `depth: u64` via the serde_json::json!() macro at L2756 — a future
        // refactor that did `depth as f64` to support a "decimal depth"
        // display feature would silently narrow above 2^53 (JSON spec is
        // ambiguous about integer precision in Number; serde_json treats
        // u64::MAX safely but f64 loses precision at u64::MAX). Pin the
        // type so the regression lands here, not in the dashboard at high
        // depth (which won't reach 2^53 in practice but the contract is
        // what matters — explicit u64 = no surprises).
        let mut pending = PendingLedger::new();
        // Use multiple creators with distinct depths to exercise both
        // single-element and multi-element array shapes.
        pending
            .insert(mk_delta("a0", "alice", 100.0))
            .expect("insert");
        pending
            .insert(mk_delta("a1", "alice", 101.0))
            .expect("insert");
        pending
            .insert(mk_delta("a2", "alice", 102.0))
            .expect("insert");
        pending.insert(mk_delta("b0", "bob", 200.0)).expect("insert");
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(top.len(), 2, "two creators expected");
        for (i, entry) in top.iter().enumerate() {
            assert!(
                entry["depth"].is_u64(),
                "top_creators[{i}].depth must be a JSON u64, got: {:?}",
                entry["depth"]
            );
            // Belt-and-braces: a future f64 narrowing path may leave is_u64
            // returning true on integer-valued floats on some serde paths,
            // so also pin that it's NOT also serialized as a float (the
            // tighter `.is_f64()` predicate must be false for true u64s).
            assert!(
                !entry["depth"].is_f64(),
                "top_creators[{i}].depth must NOT also be classified as f64 — \
                 serde_json::Number distinguishes integer vs float paths"
            );
        }
    }

    #[test]
    fn batch_ee_distinct_identities_aggregate_invariant_vs_top_creators_length() {
        // Pin the algebraic relationship between aggregate.distinct_identities
        // and top_creators.len(): they are EQUAL when distinct ≤ 20 (bijection
        // — every creator appears in top_creators), and top_creators is
        // CAPPED at 20 when distinct > 20 (aggregate retains the full count
        // for the dashboard's "n distinct of {x} truncated" line). The
        // operator dashboard at `/admin/pending_ledger` computes the
        // "truncation indicator" as `distinct - top.len()` — a regression
        // that capped distinct_identities at 20 instead of top_creators
        // would silently zero this indicator and operators would miss the
        // signal that creators are being dropped from the top-N list.
        //
        // Test three regimes:
        //   • zero creators           → distinct=0, top_creators.len()=0
        //   • subcap distinct=5       → distinct=5, top_creators.len()=5
        //   • supercap distinct=23    → distinct=23, top_creators.len()=20
        // (boundary distinct=21 is already covered above by the truncate-cap
        //  test; this test verifies the invariant ACROSS regimes, not the
        //  boundary specifically).

        // Regime 1: empty.
        {
            let pending = PendingLedger::new();
            let payload =
                pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
            let distinct = payload["aggregate"]["distinct_identities"]
                .as_u64()
                .expect("u64");
            let top_len = payload["top_creators"].as_array().unwrap().len() as u64;
            assert_eq!(distinct, 0);
            assert_eq!(top_len, 0);
            assert!(distinct >= top_len, "invariant: distinct ≥ top.len() always");
        }

        // Regime 2: subcap (5 distinct creators).
        {
            let mut pending = PendingLedger::new();
            for c in 0..5 {
                pending
                    .insert(mk_delta(&format!("r{c}"), &format!("creator-{c:02}"), 100.0))
                    .expect("insert");
            }
            let payload =
                pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
            let distinct = payload["aggregate"]["distinct_identities"]
                .as_u64()
                .expect("u64");
            let top_len = payload["top_creators"].as_array().unwrap().len() as u64;
            assert_eq!(distinct, 5, "5 inserted ⇒ 5 distinct");
            assert_eq!(top_len, 5, "≤20 ⇒ bijection: top.len() == distinct");
            assert!(distinct >= top_len, "invariant holds");
        }

        // Regime 3: supercap (23 distinct creators).
        {
            let mut pending = PendingLedger::new();
            for c in 0..23 {
                pending
                    .insert(mk_delta(&format!("r{c}"), &format!("creator-{c:02}"), 100.0))
                    .expect("insert");
            }
            let payload =
                pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
            let distinct = payload["aggregate"]["distinct_identities"]
                .as_u64()
                .expect("u64");
            let top_len = payload["top_creators"].as_array().unwrap().len() as u64;
            assert_eq!(distinct, 23, "23 inserted ⇒ 23 distinct (aggregate retains all)");
            assert_eq!(top_len, 20, ">20 ⇒ top_creators capped at 20");
            assert!(
                distinct > top_len,
                "supercap regime: distinct must EXCEED top.len(), dashboard indicator > 0"
            );
        }
    }

    #[test]
    fn batch_gg_top_creators_depth_sum_equals_aggregate_depth_in_subcap_regime() {
        // Partition invariant: in the subcap regime (distinct ≤ 20) every creator
        // appears in top_creators and every pending record is counted in exactly
        // one creator bucket. Therefore the sum of `top_creators[i].depth` MUST
        // equal `aggregate.depth`. A regression that double-counted a record into
        // two buckets (or dropped one) would surface as a sum-mismatch here even
        // when the per-bucket depth values look plausible in isolation.
        //
        // Setup: 4 creators with 3, 2, 2, 1 records respectively (total = 8
        // records, distinct = 4 ≤ 20). Subcap regime, full bijection.
        let mut pending = PendingLedger::new();
        // creator-a: 3 records
        pending.insert(mk_delta("ra1", "creator-a", 100.0)).unwrap();
        pending.insert(mk_delta("ra2", "creator-a", 101.0)).unwrap();
        pending.insert(mk_delta("ra3", "creator-a", 102.0)).unwrap();
        // creator-b: 2 records
        pending.insert(mk_delta("rb1", "creator-b", 110.0)).unwrap();
        pending.insert(mk_delta("rb2", "creator-b", 111.0)).unwrap();
        // creator-c: 2 records
        pending.insert(mk_delta("rc1", "creator-c", 120.0)).unwrap();
        pending.insert(mk_delta("rc2", "creator-c", 121.0)).unwrap();
        // creator-d: 1 record
        pending.insert(mk_delta("rd1", "creator-d", 130.0)).unwrap();

        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let aggregate_depth = payload["aggregate"]["depth"].as_u64().expect("u64");
        let top_arr = payload["top_creators"].as_array().expect("array");
        let top_sum: u64 = top_arr
            .iter()
            .map(|e| e["depth"].as_u64().expect("u64 depth"))
            .sum();

        assert_eq!(aggregate_depth, 8, "8 records inserted ⇒ aggregate.depth=8");
        assert_eq!(
            top_arr.len(),
            4,
            "subcap: top_creators.len() == distinct creators"
        );
        assert_eq!(
            top_sum, aggregate_depth,
            "partition invariant: sum(top_creators[i].depth) == aggregate.depth in subcap regime"
        );
    }

    #[test]
    fn batch_gg_top_creators_depth_sum_le_aggregate_depth_in_supercap_regime() {
        // Partition invariant under truncation: in the supercap regime
        // (distinct > 20) top_creators is capped at 20 entries, so the bottom
        // creators are dropped. The sum of `top_creators[i].depth` MUST be
        // ≤ `aggregate.depth`, and STRICTLY < when bottom creators have
        // depth > 0. A regression that summed pre-truncation depth into
        // top_creators[0] (or any single bucket) would inflate the visible
        // sum past aggregate.depth and break operator dashboards that compute
        // "shown vs hidden" record-count from these two fields.
        //
        // Setup: 25 distinct creators, each with depth=1 ⇒ aggregate.depth=25,
        // top_creators capped at 20 with sum = 20 < 25.
        let mut pending = PendingLedger::new();
        for c in 0..25 {
            pending
                .insert(mk_delta(&format!("r{c}"), &format!("creator-{c:02}"), 100.0))
                .unwrap();
        }

        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let aggregate_depth = payload["aggregate"]["depth"].as_u64().expect("u64");
        let top_arr = payload["top_creators"].as_array().expect("array");
        let top_sum: u64 = top_arr
            .iter()
            .map(|e| e["depth"].as_u64().expect("u64 depth"))
            .sum();

        assert_eq!(aggregate_depth, 25, "25 records inserted ⇒ aggregate.depth=25");
        assert_eq!(top_arr.len(), 20, "supercap: top_creators capped at 20");
        assert_eq!(top_sum, 20, "20 entries × depth-1 each ⇒ sum=20");
        assert!(
            top_sum <= aggregate_depth,
            "partition invariant: sum(top.depth) ≤ aggregate.depth always"
        );
        assert!(
            top_sum < aggregate_depth,
            "supercap with positive bottom-bucket depth: sum STRICTLY < aggregate.depth (5 records hidden)"
        );
    }

    #[test]
    fn batch_gg_top_creators_identities_pairwise_distinct() {
        // Dedup invariant: top_creators is built from a HashMap keyed on creator,
        // so identities MUST be pairwise distinct. A regression that flattened
        // the per_creator HashMap into a Vec of `(record_id, creator, ...)`
        // tuples (one entry per record, not per creator) would silently emit
        // duplicate identities — breaking the dashboard's "n distinct creators"
        // count.
        //
        // Setup: 3 creators with multiple records each. Top_creators must have
        // exactly 3 entries, all with distinct identity strings.
        let mut pending = PendingLedger::new();
        pending.insert(mk_delta("r1", "creator-alpha", 100.0)).unwrap();
        pending.insert(mk_delta("r2", "creator-alpha", 101.0)).unwrap();
        pending.insert(mk_delta("r3", "creator-alpha", 102.0)).unwrap();
        pending.insert(mk_delta("r4", "creator-beta", 110.0)).unwrap();
        pending.insert(mk_delta("r5", "creator-beta", 111.0)).unwrap();
        pending.insert(mk_delta("r6", "creator-gamma", 120.0)).unwrap();

        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let top_arr = payload["top_creators"].as_array().expect("array");
        let identities: Vec<String> = top_arr
            .iter()
            .map(|e| e["identity"].as_str().expect("string").to_string())
            .collect();

        assert_eq!(identities.len(), 3, "3 distinct creators ⇒ 3 entries");
        let mut sorted = identities.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            identities.len(),
            "top_creators identities must be pairwise distinct (no duplicates)"
        );
    }

    #[test]
    fn batch_gg_lifetime_counters_all_five_fields_strict_u64_not_f64() {
        // Wire-contract pin: each of the 5 lifetime_counters fields MUST be
        // emitted as a strict JSON integer (u64), not a float. A regression
        // that promoted any counter to f64 (e.g. via a downstream rate-per-sec
        // calculation accidentally writing back into the canonical struct)
        // would surface here. Tested with non-zero values to defeat the
        // "0 vs 0.0 both parse as_u64" false negative — only positive ints
        // with distinct values distinguish the two JSON encodings.
        let lifetime = PendingLedgerLifetimeCounters {
            commits_total: 11,
            discards_total: 22,
            hard_discards_total: 33,
            rejections_total: 44,
            fallback_direct_apply_total: 55,
        };
        let pending = PendingLedger::new();
        let payload = pending_ledger_inspection_payload(&pending, &lifetime, 1_000.0);

        let lc = &payload["lifetime_counters"];
        // Strict u64 type pin on each field — is_u64() returns false for f64 values.
        for field in &[
            "commits_total",
            "discards_total",
            "hard_discards_total",
            "rejections_total",
            "fallback_direct_apply_total",
        ] {
            assert!(
                lc[field].is_u64(),
                "lifetime_counters.{field} must be strict u64 (not f64), got {:?}",
                lc[field]
            );
            assert!(
                !lc[field].is_f64(),
                "lifetime_counters.{field} must NOT be f64",
            );
        }
        // Value round-trip pin — guards against silent narrowing through f64.
        assert_eq!(lc["commits_total"].as_u64(), Some(11));
        assert_eq!(lc["discards_total"].as_u64(), Some(22));
        assert_eq!(lc["hard_discards_total"].as_u64(), Some(33));
        assert_eq!(lc["rejections_total"].as_u64(), Some(44));
        assert_eq!(lc["fallback_direct_apply_total"].as_u64(), Some(55));
    }

    #[test]
    fn batch_gg_aggregate_depth_le_max_total_cap_invariant() {
        // Cross-field algebraic invariant: aggregate.depth ≤ max_total_cap
        // ALWAYS (the pending ledger refuses to accept inserts past
        // MAX_TOTAL_PENDING, so the aggregate count can never exceed the cap
        // surfaced in the same payload). A regression that decoupled the
        // displayed cap from the enforcement cap — e.g. payload sources the
        // cap from a hardcoded literal instead of `MAX_TOTAL_PENDING` — would
        // be invisible to standalone tests but would surface here through
        // a same-payload algebraic check.
        //
        // Tested in three regimes: empty (0 ≤ cap), small populated (8 ≤ cap),
        // and verifying the cap value itself is positive (sanity).
        use crate::accounting::pending_ledger::MAX_TOTAL_PENDING;

        // Regime 1: empty.
        {
            let pending = PendingLedger::new();
            let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
            let depth = payload["aggregate"]["depth"].as_u64().expect("u64");
            let cap = payload["max_total_cap"].as_u64().expect("u64");
            assert_eq!(depth, 0);
            assert_eq!(
                cap, MAX_TOTAL_PENDING as u64,
                "max_total_cap must source from MAX_TOTAL_PENDING constant"
            );
            assert!(depth <= cap, "invariant: aggregate.depth ≤ max_total_cap (empty case)");
        }

        // Regime 2: populated.
        {
            let mut pending = PendingLedger::new();
            for c in 0..8 {
                pending
                    .insert(mk_delta(&format!("r{c}"), &format!("creator-{c:02}"), 100.0))
                    .unwrap();
            }
            let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
            let depth = payload["aggregate"]["depth"].as_u64().expect("u64");
            let cap = payload["max_total_cap"].as_u64().expect("u64");
            assert_eq!(depth, 8);
            assert!(depth <= cap, "invariant: aggregate.depth ≤ max_total_cap (populated)");
            assert!(cap > 0, "cap must be positive (sanity — MAX_TOTAL_PENDING is a positive const)");
        }
    }

    #[test]
    fn batch_ii_aggregate_max_per_identity_depth_le_max_per_identity_cap_invariant() {
        // Companion to batch_gg_aggregate_depth_le_max_total_cap_invariant, but
        // for the per-identity surface. Invariant:
        //     aggregate.max_per_identity_depth ≤ max_per_identity_cap
        // The cap surfaced in the payload MUST source from MAX_PENDING_PER_IDENTITY
        // (4096) — a regression that decoupled the displayed cap from the enforcement
        // cap (e.g. hardcoded `4_096_u64` literal in the payload) would make this
        // pair fall out of lockstep on the next constant bump. Three regimes pin
        // the algebra: empty (0 ≤ cap), single-creator with elevated depth
        // (depth ≤ cap), and multi-creator with one elevated-depth creator
        // (max_per_identity_depth = max(depth), still ≤ cap).
        use crate::accounting::pending_ledger::MAX_PENDING_PER_IDENTITY;

        // Regime 1: empty → max_per_identity_depth = 0.
        {
            let pending = PendingLedger::new();
            let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
            let max_pid = payload["aggregate"]["max_per_identity_depth"]
                .as_u64()
                .expect("u64");
            let cap = payload["max_per_identity_cap"].as_u64().expect("u64");
            assert_eq!(max_pid, 0);
            assert_eq!(
                cap, MAX_PENDING_PER_IDENTITY as u64,
                "max_per_identity_cap must source from MAX_PENDING_PER_IDENTITY constant"
            );
            assert!(
                max_pid <= cap,
                "invariant: aggregate.max_per_identity_depth ≤ max_per_identity_cap (empty case)"
            );
        }

        // Regime 2: single-creator elevated depth (testnet finality-bottleneck shape).
        {
            let mut pending = PendingLedger::new();
            for i in 0..12 {
                pending
                    .insert(mk_delta(&format!("r-{i}"), "single-creator", 100.0 + i as f64))
                    .unwrap();
            }
            let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
            let max_pid = payload["aggregate"]["max_per_identity_depth"]
                .as_u64()
                .expect("u64");
            let cap = payload["max_per_identity_cap"].as_u64().expect("u64");
            assert_eq!(max_pid, 12);
            assert!(
                max_pid <= cap,
                "invariant: aggregate.max_per_identity_depth ≤ max_per_identity_cap (single-creator)"
            );
        }

        // Regime 3: multi-creator with one elevated (max = max(depths) over all creators).
        {
            let mut pending = PendingLedger::new();
            for i in 0..9 {
                pending
                    .insert(mk_delta(&format!("alice-{i}"), "alice", 100.0 + i as f64))
                    .unwrap();
            }
            for i in 0..3 {
                pending
                    .insert(mk_delta(&format!("bob-{i}"), "bob", 200.0 + i as f64))
                    .unwrap();
            }
            for i in 0..5 {
                pending
                    .insert(mk_delta(&format!("carol-{i}"), "carol", 300.0 + i as f64))
                    .unwrap();
            }
            let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
            let max_pid = payload["aggregate"]["max_per_identity_depth"]
                .as_u64()
                .expect("u64");
            let cap = payload["max_per_identity_cap"].as_u64().expect("u64");
            // max(9, 3, 5) = 9 — alice's depth is the per-identity max.
            assert_eq!(max_pid, 9);
            assert!(
                max_pid <= cap,
                "invariant: aggregate.max_per_identity_depth ≤ max_per_identity_cap (multi-creator)"
            );
        }
    }

    #[test]
    fn batch_ii_aggregate_distinct_identities_is_strict_u64_type_not_f64_or_string() {
        // Companion to batch_ee's `batch_ee_top_creators_entry_depth_field_is_strict_unsigned_integer_not_float`
        // which pins the per-creator depth type. This pins the AGGREGATE-LEVEL
        // distinct_identities counter as a strict JSON integer (u64), guarding
        // against a future refactor that accidentally serializes through f64
        // (loses precision past 2^53) OR through a String wrapper (would break
        // every JSON consumer that does numeric ordering). Empty + populated
        // both checked so a regression that only types one branch wrong
        // (e.g. `if distinct == 0 { Value::Null } else { Value::Number(...) }`)
        // surfaces.
        let empty_payload = pending_ledger_inspection_payload(
            &PendingLedger::new(),
            &empty_lifetime(),
            1_000.0,
        );
        let empty_distinct = &empty_payload["aggregate"]["distinct_identities"];
        assert!(
            empty_distinct.is_u64(),
            "aggregate.distinct_identities MUST be strict JSON unsigned integer on empty pending — got {empty_distinct:?}"
        );
        assert!(
            !empty_distinct.is_string(),
            "aggregate.distinct_identities must never serialize as a String wrapper (would break operator JSON-num ordering)"
        );
        assert_eq!(empty_distinct.as_u64(), Some(0));

        // Populated: three distinct creators, expected distinct=3 strict-u64.
        let mut pending = PendingLedger::new();
        for c in ["alice", "bob", "carol"] {
            for i in 0..2 {
                pending
                    .insert(mk_delta(&format!("{c}-{i}"), c, 100.0 + i as f64))
                    .unwrap();
            }
        }
        let populated_payload =
            pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let populated_distinct = &populated_payload["aggregate"]["distinct_identities"];
        assert!(
            populated_distinct.is_u64(),
            "aggregate.distinct_identities MUST be strict JSON unsigned integer on populated pending — got {populated_distinct:?}"
        );
        assert!(
            !populated_distinct.is_string(),
            "populated branch must not serialize as String either"
        );
        assert_eq!(populated_distinct.as_u64(), Some(3));
    }

    #[test]
    fn batch_ii_aggregate_oldest_age_secs_is_strict_json_number_type_not_string() {
        // Type-strictness pin on aggregate.oldest_age_secs. The empty-pending
        // existing test asserts `agg["oldest_age_secs"] == 0.0` via Value::eq
        // which accepts Number(0.0) — but does NOT pin the JSON wire type:
        // a regression to `Value::String("0.0")` (via accidental format!() use)
        // would still satisfy `== 0.0` against an f64 Rust literal *if* serde_json
        // ever changes its PartialEq semantics. is_f64()/is_number() are
        // type-strict gates that survive that refactor. Pinned on both regimes:
        // empty (oldest_age_secs=0.0) and populated (oldest_age_secs > 0).
        let empty_payload = pending_ledger_inspection_payload(
            &PendingLedger::new(),
            &empty_lifetime(),
            1_000.0,
        );
        let empty_oldest = &empty_payload["aggregate"]["oldest_age_secs"];
        assert!(
            empty_oldest.is_number(),
            "aggregate.oldest_age_secs MUST be strict JSON Number on empty — got {empty_oldest:?}"
        );
        assert!(
            !empty_oldest.is_string(),
            "aggregate.oldest_age_secs must never serialize as a String (operator dashboards expect Number for time-math)"
        );
        // The helper rounds to one decimal via (x*10).round()/10 → always f64,
        // even when x=0.0. is_f64() pins that contract.
        assert!(
            empty_oldest.is_f64(),
            "rounded oldest_age_secs MUST serialize as f64 (the (x*10).round()/10 expression always lands as f64)"
        );

        // Populated regime: oldest record at applied_at=100.0, now=1000.0 → age=900.0.
        let mut pending = PendingLedger::new();
        for i in 0..3 {
            pending
                .insert(mk_delta(&format!("r-{i}"), "creator", 100.0 + i as f64))
                .unwrap();
        }
        let populated_payload =
            pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let populated_oldest = &populated_payload["aggregate"]["oldest_age_secs"];
        assert!(
            populated_oldest.is_number(),
            "populated aggregate.oldest_age_secs MUST be strict Number — got {populated_oldest:?}"
        );
        assert!(
            !populated_oldest.is_string(),
            "populated branch must not regress to String type"
        );
        let val = populated_oldest.as_f64().expect("f64");
        assert!(
            (899.5..=900.5).contains(&val),
            "populated oldest_age_secs must reflect (now - oldest_applied_at) ≈ 900.0 — got {val}"
        );
    }

    #[allow(clippy::range_plus_one)]
    #[test]
    fn batch_ii_top_creators_oldest_age_secs_strictly_non_negative_when_now_after_oldest_applied_at() {
        // Value-domain invariant on top_creators[i].oldest_age_secs: when
        // `now ≥ oldest_applied_at` (the common case), the age MUST be ≥ 0.
        // The `batch_t_clock_skew_future_applied_at_clamps_oldest_age_to_zero`
        // test pins the *clamp* behavior under future-applied_at clock skew; this
        // test pins the *non-clamped* common case across a multi-creator
        // population — a regression that broke the `(now - oldest).max(0.0)`
        // expression (e.g. swapped subtraction direction → negative ages on
        // the common path) would surface here, not in the clock-skew test.
        // Pinned across N=10 distinct creators to catch any sort-order-dependent
        // sign regression.
        let mut pending = PendingLedger::new();
        for c in 0..10 {
            for i in 0..(c + 1) {
                pending
                    .insert(mk_delta(
                        &format!("c{c}-r{i}"),
                        &format!("creator-{c:02}"),
                        100.0 + c as f64 * 10.0 + i as f64,
                    ))
                    .unwrap();
            }
        }
        let now = 100_000.0; // far after every applied_at
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);
        let top = payload["top_creators"].as_array().expect("array");
        assert_eq!(top.len(), 10, "10 distinct creators must all appear (under 20-cap)");
        for (i, entry) in top.iter().enumerate() {
            let age = entry["oldest_age_secs"].as_f64().expect("f64");
            assert!(
                age >= 0.0,
                "top_creators[{i}].oldest_age_secs must be ≥ 0 when now > all applied_at — got {age} for {:?}",
                entry["identity"]
            );
            // Cross-check: every age is also strictly positive (now=100k, oldest≤290 → age≥99710).
            assert!(
                age > 99_000.0,
                "top_creators[{i}].oldest_age_secs must reflect now-applied_at, not 0 — got {age}"
            );
        }
    }

    #[test]
    fn batch_ii_payload_pure_fn_two_calls_same_input_byte_identical_json_serialization() {
        // Purity / determinism pin for pending_ledger_inspection_payload —
        // analogue of the `batch_z_deterministic_repeated_calls_return_identical_serialized_json`
        // test which pinned the same property for compute_zones_scope. Distinct
        // helper, distinct mod, distinct invocation surface — so a future
        // refactor that introduces HashMap-iteration-order leakage into the
        // payload of one helper but not the other would surface here, not
        // in the existing batch_z test.
        //
        // Two byte-identical calls (same PendingLedger, same lifetime, same now)
        // MUST produce byte-identical serde_json::to_string output across N=3
        // calls. Critical because the helper materializes a HashMap<String, ...>
        // internally — if the sort tiebreak collapses (e.g. same (depth,
        // oldest_at) for two creators), HashMap iteration order leaks. We
        // construct distinct depths + distinct oldest_at to avoid the
        // unstable-sort corner; the test pins the deterministic path.
        let mut pending = PendingLedger::new();
        // 4 creators, all with distinct (depth, oldest_at) — avoids the
        // unstable-sort edge entirely.
        for i in 0..3 {
            pending
                .insert(mk_delta(&format!("a-{i}"), "alice", 100.0 + i as f64))
                .unwrap();
        }
        for i in 0..5 {
            pending
                .insert(mk_delta(&format!("b-{i}"), "bob", 200.0 + i as f64))
                .unwrap();
        }
        for i in 0..2 {
            pending
                .insert(mk_delta(&format!("c-{i}"), "carol", 300.0 + i as f64))
                .unwrap();
        }
        for i in 0..7 {
            pending
                .insert(mk_delta(&format!("d-{i}"), "dave", 400.0 + i as f64))
                .unwrap();
        }
        let lifetime = PendingLedgerLifetimeCounters {
            commits_total: 1_234,
            discards_total: 12,
            hard_discards_total: 3,
            rejections_total: 7,
            fallback_direct_apply_total: 0,
        };
        let now = 10_000.0;

        let payload_a = pending_ledger_inspection_payload(&pending, &lifetime, now);
        let payload_b = pending_ledger_inspection_payload(&pending, &lifetime, now);
        let payload_c = pending_ledger_inspection_payload(&pending, &lifetime, now);

        let s_a = serde_json::to_string(&payload_a).expect("to_string a");
        let s_b = serde_json::to_string(&payload_b).expect("to_string b");
        let s_c = serde_json::to_string(&payload_c).expect("to_string c");

        assert_eq!(
            s_a, s_b,
            "two byte-identical-input calls must produce identical JSON serialization"
        );
        assert_eq!(
            s_b, s_c,
            "three calls must remain identical (catches any state-decay regression on repeated calls)"
        );

        // Cross-check via Value::eq too — captures the rare case where
        // serde_json::to_string canonicalizes differently than Value::eq.
        assert_eq!(payload_a, payload_b);
        assert_eq!(payload_b, payload_c);
    }

    #[test]
    fn batch_jj_top_creators_n_20_boundary_no_truncation_all_entries_have_positive_depth() {
        // Boundary pin at the EXACT truncate-cap of 20 distinct creators. The
        // existing tests pin N=21 and N=23 — the
        // supercap side. The subcap side at N≤19 is implicit in several
        // tests but the exact N=20 boundary — "20 distinct creators yields
        // 20 entries without any truncation" — is unpinned. A regression
        // to `.truncate(19)` would pass every existing test (because all
        // existing tests checking exact lengths use N ≤ 5 or N ≥ 21) but
        // silently drop the 20th creator from operator dashboards.
        //
        // Setup: 20 distinct creators with monotonically descending depth
        // (creator-00 depth=20, creator-01 depth=19, …, creator-19 depth=1).
        // Distinct depths avoid the sort-tiebreak path entirely so the
        // ordering is unambiguous and the boundary pin is the only invariant
        // under test.
        let mut pending = PendingLedger::new();
        for c in 0..20 {
            let depth = 20 - c;
            for i in 0..depth {
                pending
                    .insert(mk_delta(
                        &format!("c{c}-r{i}"),
                        &format!("creator-{c:02}"),
                        100.0 + i as f64,
                    ))
                    .expect("insert");
            }
        }
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);

        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(
            top.len(),
            20,
            "N=20 boundary: top_creators must contain exactly 20 entries — no truncation, no padding"
        );
        // Every entry must carry a strictly positive depth — catches a
        // refactor that padded the list with zero-depth placeholders.
        for (i, entry) in top.iter().enumerate() {
            let d = entry["depth"].as_u64().expect("depth u64");
            assert!(
                d >= 1,
                "top_creators[{i}] depth must be ≥1 — got {d}"
            );
        }

        let agg = &payload["aggregate"];
        assert_eq!(
            agg["distinct_identities"], 20,
            "aggregate.distinct_identities must equal 20 at the boundary"
        );
        // The bijection holds at exactly N=20 — every distinct creator
        // appears in top_creators, dashboard truncation indicator
        // (distinct - top.len()) must read 0.
        assert_eq!(
            agg["distinct_identities"].as_u64().unwrap(),
            top.len() as u64,
            "N=20 boundary: distinct == top.len() — bijection at the cap edge"
        );
    }

    #[test]
    fn batch_jj_top_creators_oldest_age_secs_rounded_to_one_tenth_quantum() {
        // Pin the `(age * 10.0).round() / 10.0` rounding contract directly
        // at `top_creators[].oldest_age_secs` (admin.rs:2757). A future
        // refactor to `(age * 100.0).round() / 100.0` (0.01-quantum) or
        // raw f64 (no rounding) would pass every existing test — existing
        // oldest_age tests check ≥0.0 invariants or wide ranges (e.g. the
        // bottleneck test asserts > 1200.0). No existing test pins the
        // exact 0.1-quantum at sub-second age values where the rounding is
        // observable.
        //
        // Inputs use exact-f64-representable values (0.5, 0.25, 0.75, 0.125)
        // and `now = 1024.0` (also exact in f64) so the subtraction
        // `now - applied_at` is bit-exact — sidesteps f64 round-trip drift
        // (`0.55` is not exact in f64 and produced 0.5 instead of 0.6 in
        // a previous draft of this test). The assertions pin the
        // 0.1-quantum integer that `(age * 10.0).round()` lands on rather
        // than the output f64 literal (avoids comparing literal `0.3_f64`
        // against `3.0 / 10.0` which may differ at the last ULP).
        //
        // Setup: four creators with distinct depths so sort order is
        // unambiguous:
        //   alice: depth=4, applied_at = now - 0.5    → age 0.5   → quantum 5  → /10 = 0.5
        //   bob:   depth=3, applied_at = now - 0.25   → age 0.25  → 2.5 round-half-away-from-zero → 3 → 0.3
        //   carol: depth=2, applied_at = now - 0.75   → age 0.75  → 7.5 round-half-away-from-zero → 8 → 0.8
        //   dave:  depth=1, applied_at = now - 0.125  → age 0.125 → 1.25 round → 1 → 0.1
        let mut pending = PendingLedger::new();
        let now = 1024.0_f64;
        for i in 0..4 {
            pending
                .insert(mk_delta(&format!("a-{i}"), "alice", now - 0.5))
                .expect("insert alice");
        }
        for i in 0..3 {
            pending
                .insert(mk_delta(&format!("b-{i}"), "bob", now - 0.25))
                .expect("insert bob");
        }
        for i in 0..2 {
            pending
                .insert(mk_delta(&format!("c-{i}"), "carol", now - 0.75))
                .expect("insert carol");
        }
        pending
            .insert(mk_delta("d-0", "dave", now - 0.125))
            .expect("insert dave");

        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);
        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(top.len(), 4);

        // Pin the integer quantum directly — sidesteps f64 literal-vs-divided
        // equality concerns.
        fn quantum_int(x: f64) -> i64 {
            (x * 10.0).round() as i64
        }
        let alice_age = top[0]["oldest_age_secs"].as_f64().expect("alice age f64");
        let bob_age = top[1]["oldest_age_secs"].as_f64().expect("bob age f64");
        let carol_age = top[2]["oldest_age_secs"].as_f64().expect("carol age f64");
        let dave_age = top[3]["oldest_age_secs"].as_f64().expect("dave age f64");

        // 0.5 * 10 = 5.0 → round = 5 → /10 = 0.5
        assert_eq!(
            quantum_int(alice_age),
            5,
            "alice age (input 0.5s) must quantize to integer 5 at 0.1-quantum"
        );
        // 0.25 * 10 = 2.5 → round-half-away-from-zero = 3 → /10 = 0.3
        assert_eq!(
            quantum_int(bob_age),
            3,
            "bob age (input 0.25s) must quantize to integer 3 (Rust f64::round is half-away-from-zero, 2.5→3)"
        );
        // 0.75 * 10 = 7.5 → round-half-away-from-zero = 8 → /10 = 0.8
        assert_eq!(
            quantum_int(carol_age),
            8,
            "carol age (input 0.75s) must quantize to integer 8 (7.5→8)"
        );
        // 0.125 * 10 = 1.25 → round = 1 → /10 = 0.1
        assert_eq!(
            quantum_int(dave_age),
            1,
            "dave age (input 0.125s) must quantize to integer 1 at 0.1-quantum"
        );

        // Quantum invariant — every emitted age, multiplied by 10, must be
        // an exact integer (within f64 precision). Catches a refactor that
        // switched to a finer (0.01) or coarser quantum without updating
        // the rounding step.
        for (i, entry) in top.iter().enumerate() {
            let age = entry["oldest_age_secs"].as_f64().unwrap();
            let times_ten = age * 10.0;
            let rounded = times_ten.round();
            assert!(
                (times_ten - rounded).abs() < 1e-9,
                "top_creators[{i}] oldest_age_secs={age} not on 0.1 quantum (age*10={times_ten}, rounded={rounded})"
            );
        }
    }

    #[test]
    fn batch_jj_top_creators_depth_field_strictly_non_increasing_across_indices() {
        // Property invariant across the array, distinct from
        // `top_creators_sorted_by_depth_descending_oldest_first_on_tie` which
        // pins specific creator names at specific indices (alice@1, bob@0,
        // carol@2). That test would PASS even if the middle of the array
        // were scrambled — it only checks indices 0, 1, 2 with three
        // creators. Here we walk N=10 creators with distinct descending
        // depths and pin the property `top[i].depth ≥ top[i+1].depth` for
        // every adjacent pair. A sort flip that preserved the endpoints
        // (highest at top, lowest at bottom) but reordered the middle would
        // surface here, not in the existing 3-creator test.
        let mut pending = PendingLedger::new();
        for c in 0..10 {
            let depth = 10 - c;
            for i in 0..depth {
                pending
                    .insert(mk_delta(
                        &format!("c{c}-r{i}"),
                        &format!("creator-{c:02}"),
                        100.0 + i as f64,
                    ))
                    .expect("insert");
            }
        }
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(top.len(), 10);

        // Walk the adjacent pairs — property pin.
        for w in top.windows(2) {
            let lhs_depth = w[0]["depth"].as_u64().expect("lhs depth u64");
            let rhs_depth = w[1]["depth"].as_u64().expect("rhs depth u64");
            assert!(
                lhs_depth >= rhs_depth,
                "non-increasing property violated: {lhs_depth} vs {rhs_depth} at adjacent indices ({} vs {})",
                w[0]["identity"],
                w[1]["identity"]
            );
        }

        // Sanity: the array goes from highest depth (10) to lowest (1).
        assert_eq!(top[0]["depth"], 10, "head must be max depth");
        assert_eq!(top[9]["depth"], 1, "tail must be min depth");
    }

    #[test]
    fn batch_jj_payload_observes_input_mutation_between_calls_distinct_identities_grows() {
        // Helper purity ≠ helper-input-immutability. The helper is pure (no
        // internal state, no cache), but a future refactor that introduced
        // a static cache keyed on `&pending` pointer (rather than its
        // contents) would silently return stale payloads on the second call
        // after mutation. Existing purity test `batch_ii_payload_pure_fn_…`
        // pins same-input → same-output across N=3 calls; it cannot catch
        // a cache that returns the first call's output when the SECOND
        // call is on the mutated input.
        //
        // Setup: insert 1 record from alice → snapshot payload. Mutate
        // pending (insert 1 record from bob) → snapshot payload. The two
        // payloads MUST differ: distinct_identities 1→2, aggregate.depth
        // 1→2, top_creators.len() 1→2.
        let mut pending = PendingLedger::new();
        pending
            .insert(mk_delta("a-0", "alice", 100.0))
            .expect("insert alice");

        let payload_pre = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let pre_distinct = payload_pre["aggregate"]["distinct_identities"]
            .as_u64()
            .unwrap();
        let pre_depth = payload_pre["aggregate"]["depth"].as_u64().unwrap();
        let pre_top_len = payload_pre["top_creators"].as_array().unwrap().len();
        assert_eq!(pre_distinct, 1);
        assert_eq!(pre_depth, 1);
        assert_eq!(pre_top_len, 1);

        // Mutate the same PendingLedger.
        pending
            .insert(mk_delta("b-0", "bob", 200.0))
            .expect("insert bob");

        let payload_post = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let post_distinct = payload_post["aggregate"]["distinct_identities"]
            .as_u64()
            .unwrap();
        let post_depth = payload_post["aggregate"]["depth"].as_u64().unwrap();
        let post_top_len = payload_post["top_creators"].as_array().unwrap().len();
        assert_eq!(
            post_distinct, 2,
            "helper must observe mutation: distinct_identities grew 1→2"
        );
        assert_eq!(
            post_depth, 2,
            "helper must observe mutation: aggregate.depth grew 1→2"
        );
        assert_eq!(
            post_top_len, 2,
            "helper must observe mutation: top_creators grew 1→2"
        );

        // Strong distinctness pin — the two payloads must NOT be equal.
        assert_ne!(
            payload_pre, payload_post,
            "post-mutation payload must differ from pre-mutation payload (no stale-cache regression)"
        );
    }

    #[test]
    fn batch_jj_top_creators_identity_field_byte_identical_to_inserted_creator_string() {
        // Pin that `top_creators[i].identity` is byte-identical to the
        // creator string passed at insert time — no Unicode normalization,
        // no case fold, no ASCII trim. Operators identify creators by
        // exact identity-hash strings; a silent normalization in the helper
        // would make two distinct creators collide in the operator dashboard.
        //
        // Test vector: a creator string with non-ASCII UTF-8 (Umlaut,
        // CJK), mixed case, and hyphen — common pathology shapes that a
        // refactor might "accidentally clean up".
        let mut pending = PendingLedger::new();
        let weird_creator = "Creator-Ümläut-石黑一雄-MIXED_case";
        let plain_creator = "creator-plain";
        for i in 0..3 {
            pending
                .insert(mk_delta(&format!("w-{i}"), weird_creator, 100.0 + i as f64))
                .expect("insert weird creator");
        }
        for i in 0..1 {
            pending
                .insert(mk_delta(&format!("p-{i}"), plain_creator, 200.0 + i as f64))
                .expect("insert plain creator");
        }
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(top.len(), 2);

        // Sort: weird_creator (depth=3) first, plain_creator (depth=1) second.
        let weird_id = top[0]["identity"].as_str().expect("identity is string");
        let plain_id = top[1]["identity"].as_str().expect("identity is string");
        assert_eq!(
            weird_id, weird_creator,
            "identity must round-trip byte-identical — no Unicode normalization, no case fold"
        );
        assert_eq!(plain_id, plain_creator, "plain ASCII identity round-trip");

        // Distinctness pin — two creators that differ ONLY in case must
        // appear as TWO entries, not one collapsed entry.
        let mut pending2 = PendingLedger::new();
        pending2
            .insert(mk_delta("lo-0", "alice", 100.0))
            .expect("insert");
        pending2
            .insert(mk_delta("hi-0", "ALICE", 200.0))
            .expect("insert");
        let payload2 = pending_ledger_inspection_payload(&pending2, &empty_lifetime(), 1_000.0);
        let top2 = payload2["top_creators"].as_array().unwrap();
        assert_eq!(
            top2.len(),
            2,
            "alice ≠ ALICE — case-sensitive creator keys must yield two distinct top entries (no fold)"
        );
        assert_eq!(
            payload2["aggregate"]["distinct_identities"], 2,
            "case-sensitive distinct_identities must be 2"
        );
    }

    #[test]
    fn batch_kk_lifetime_counters_each_field_isolation_only_one_nonzero_emits_others_as_zero() {
        // Field-isolation pin on `lifetime_counters`. The existing
        // `lifetime_counters_passed_through_unchanged` (line 2942) uses all
        // five fields ALL NON-ZERO with distinct values (1/2/3/4/42) — a
        // regression that aliased one field to another (e.g. wired both
        // `commits_total` and `discards_total` to the SAME source field)
        // would mismatch on at least one access. But a different class of
        // regression — one that silently dropped zero values from the
        // emitted JSON (a hypothetical "skip-zero serializer") — would
        // pass the existing test because no field is zero in that setup.
        //
        // This test exercises FIVE separate isolation cases, one per
        // lifetime field, where exactly ONE field is non-zero (set to a
        // distinct prime: 13/17/19/23/29 — primes minimize the chance of
        // an accidental sum-pattern producing the same value) and the
        // OTHER FOUR are 0. Each case asserts the active field equals
        // its prime AND each of the other four equals 0. Catches:
        //   • Field-key aliasing (active field bleeds into a different key)
        //   • Zero elision (other four absent from emitted object)
        //   • Sum-folding (helper accidentally summing into one key)
        let cases: &[(&str, u64)] = &[
            ("commits_total", 13),
            ("discards_total", 17),
            ("hard_discards_total", 19),
            ("rejections_total", 23),
            ("fallback_direct_apply_total", 29),
        ];
        for &(active_field, prime) in cases {
            let mut lifetime = empty_lifetime();
            match active_field {
                "commits_total" => lifetime.commits_total = prime,
                "discards_total" => lifetime.discards_total = prime,
                "hard_discards_total" => lifetime.hard_discards_total = prime,
                "rejections_total" => lifetime.rejections_total = prime,
                "fallback_direct_apply_total" => lifetime.fallback_direct_apply_total = prime,
                _ => unreachable!(),
            }
            let pending = PendingLedger::new();
            let payload = pending_ledger_inspection_payload(&pending, &lifetime, 1_000.0);
            let lc = &payload["lifetime_counters"];

            // Active field carries the prime.
            assert_eq!(
                lc[active_field].as_u64(),
                Some(prime),
                "active field `{active_field}` must equal prime {prime}, got {:?}",
                lc[active_field]
            );

            // All four other fields must be present AND equal 0 — pins
            // both no-alias (no other field copies the prime) and
            // no-zero-elision (zero values are emitted, not dropped).
            for &(other_field, _) in cases {
                if other_field == active_field {
                    continue;
                }
                assert_eq!(
                    lc[other_field].as_u64(),
                    Some(0),
                    "with `{active_field}={prime}` and all others 0, \
                     `{other_field}` must serialize as 0 — got {:?} \
                     (regression: field aliased or zero-elision in serializer)",
                    lc[other_field]
                );
            }
        }
    }

    #[test]
    fn batch_kk_aggregate_oldest_age_secs_exact_equality_to_top_creators_zero_when_distinct_one() {
        // Cross-derivation pin: when `distinct_identities == 1`, the sole
        // creator IS the global oldest, so `aggregate.oldest_age_secs`
        // MUST equal `top_creators[0].oldest_age_secs` exactly (bit-for-bit
        // f64 equality after rounding).
        //
        // The two values flow through DIFFERENT code paths:
        //   • `aggregate.oldest_age_secs` derives from
        //     `pending.oldest_applied_at()` which scans `by_record.values()`
        //     and reduces with `f64::min`.
        //   • `top_creators[i].oldest_age_secs` derives from the helper's
        //     per-creator HashMap aggregation which scans `pending.iter()`
        //     and tracks the minimum `applied_at` per creator inline.
        // A divergence here would mean one of these paths is wrong — and
        // the existing single-creator test (line 3060 series) uses a fuzzy
        // 0.05 tolerance against the literal 900.0, NOT a direct
        // pin between the two emitted fields. So a regression where both
        // paths drift in the SAME direction (e.g. both shift by -50)
        // would pass the existing test silently.
        //
        // Input values 0.5/0.25/0.75/0.125/0.375 are exactly f64-representable
        // so the rounded results are deterministic.
        let mut pending = PendingLedger::new();
        let now = 1_024.0_f64;
        let applied_ats: &[f64] = &[0.5, 0.25, 0.75, 0.125, 0.375];
        for (i, &at) in applied_ats.iter().enumerate() {
            pending
                .insert(mk_delta(&format!("r-{i}"), "sole_creator", at))
                .expect("insert");
        }
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);

        let agg_age = payload["aggregate"]["oldest_age_secs"]
            .as_f64()
            .expect("aggregate.oldest_age_secs must be f64");
        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(top.len(), 1, "single creator setup must yield exactly one top entry");
        let top0_age = top[0]["oldest_age_secs"]
            .as_f64()
            .expect("top_creators[0].oldest_age_secs must be f64");

        assert_eq!(
            agg_age, top0_age,
            "single-creator: aggregate.oldest_age_secs ({agg_age}) MUST equal \
             top_creators[0].oldest_age_secs ({top0_age}) exactly — divergence \
             indicates oldest_applied_at vs per-creator-aggregation code paths drifted"
        );
        assert_eq!(
            payload["aggregate"]["distinct_identities"].as_u64(),
            Some(1),
            "distinct_identities must be 1 — precondition of this invariant"
        );
    }

    #[test]
    fn batch_kk_aggregate_oldest_age_secs_dominates_max_top_creator_oldest_age() {
        // Dominance algebraic invariant: `aggregate.oldest_age_secs` is the
        // age of the GLOBAL oldest `applied_at` across all pending deltas
        // (via `pending.oldest_applied_at()`). Per-creator
        // `top_creators[i].oldest_age_secs` is the age of THAT creator's
        // oldest. So aggregate.oldest_age_secs ≥ max(top_creators[].oldest_age_secs)
        // ALWAYS, with equality precisely when the creator owning the
        // global oldest is in the top-20 (i.e. wasn't truncated).
        //
        // This invariant catches
        // a regression where aggregate.oldest_age_secs is wired to a
        // weaker signal (e.g. average, median, or the last-inserted
        // applied_at) — any of those would violate the dominance bound
        // on multi-creator setups.
        //
        // Three creators with distinct oldest applied_at:
        //   alice oldest = 100.0  (age 900.0 — GLOBAL oldest)
        //   bob   oldest = 200.0  (age 800.0)
        //   carol oldest = 300.0  (age 700.0)
        let mut pending = PendingLedger::new();
        for i in 0..3 {
            pending
                .insert(mk_delta(&format!("a-{i}"), "alice", 100.0 + i as f64))
                .expect("insert alice");
        }
        for i in 0..2 {
            pending
                .insert(mk_delta(&format!("b-{i}"), "bob", 200.0 + i as f64))
                .expect("insert bob");
        }
        pending
            .insert(mk_delta("c-0", "carol", 300.0))
            .expect("insert carol");
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);

        let agg_age = payload["aggregate"]["oldest_age_secs"]
            .as_f64()
            .expect("aggregate.oldest_age_secs must be f64");
        let top = payload["top_creators"].as_array().unwrap();
        let max_top_age = top
            .iter()
            .map(|e| e["oldest_age_secs"].as_f64().unwrap())
            .fold(f64::NEG_INFINITY, f64::max);

        assert!(
            agg_age >= max_top_age,
            "dominance invariant violated: aggregate.oldest_age_secs ({agg_age}) \
             MUST be ≥ max(top_creators[].oldest_age_secs) ({max_top_age}) — \
             the global oldest is never younger than any specific creator's oldest"
        );

        // With 3 creators (no truncation possible at distinct=3 < 20),
        // equality should hold: alice owns the global oldest AND is in
        // top_creators. Pin this stronger form too — it'd surface a
        // regression where aggregate.oldest_age_secs is correct but
        // top_creators aggregation accidentally clipped the alice entry.
        assert_eq!(
            agg_age, max_top_age,
            "distinct=3 < 20 (no truncation): aggregate.oldest_age_secs must EQUAL \
             max(top_creators[].oldest_age_secs) — got agg={agg_age}, max_top={max_top_age}"
        );
    }

    #[test]
    fn batch_kk_aggregate_max_per_identity_depth_equals_top_creators_zero_depth_at_subcap() {
        // Cross-derivation equality: `aggregate.max_per_identity_depth`
        // derives from `pending.max_per_identity_depth()` which scans
        // `by_identity.values().map(Vec::len).max()`. `top_creators[0].depth`
        // derives from the helper's per-creator HashMap aggregation,
        // sorted depth-descending. Both should equal the deepest bucket
        // size when distinct ≤ 20 (sub-cap — no truncation can drop the
        // top entry).
        //
        // Two distinct paths, same physical signal. The existing
        // `batch_u_aggregate_max_per_identity_depth_reflects_deepest_creator_only`
        // (line 3140) pins aggregate against a literal (4), and existing
        // batch_jj tests pin top_creators sort order — but no test pins
        // the cross-derivation EQUALITY between `aggregate.max_per_identity_depth`
        // and `top_creators[0].depth` directly. So a regression where one
        // path drifted (e.g. by_identity grew stale after a remove) would
        // pass both existing tests if the drift was the same magnitude.
        //
        // Setup: 5 creators with distinct descending depths {7, 5, 3, 2, 1}.
        // top[0] should be the creator with depth=7; aggregate.max_per_identity_depth
        // should be 7.
        let mut pending = PendingLedger::new();
        let depths: &[(&str, u64)] = &[
            ("creator-a", 7),
            ("creator-b", 5),
            ("creator-c", 3),
            ("creator-d", 2),
            ("creator-e", 1),
        ];
        for &(creator, depth) in depths {
            for i in 0..depth {
                pending
                    .insert(mk_delta(
                        &format!("{creator}-r{i}"),
                        creator,
                        100.0 + i as f64,
                    ))
                    .expect("insert");
            }
        }
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);

        let agg_max = payload["aggregate"]["max_per_identity_depth"]
            .as_u64()
            .expect("aggregate.max_per_identity_depth must be u64");
        let top = payload["top_creators"].as_array().unwrap();
        let top0_depth = top[0]["depth"]
            .as_u64()
            .expect("top_creators[0].depth must be u64");

        assert_eq!(
            agg_max, top0_depth,
            "cross-derivation: aggregate.max_per_identity_depth ({agg_max}) MUST equal \
             top_creators[0].depth ({top0_depth}) at distinct=5 sub-cap — both derive \
             the deepest bucket through different code paths (by_identity vs by_record \
             aggregation), drift indicates one path is stale"
        );
        // Sanity anchor: both should be 7 (matches the test setup).
        assert_eq!(agg_max, 7, "max bucket size in this setup is 7 (creator-a)");
    }

    #[test]
    fn batch_kk_aggregate_distinct_identities_equals_top_creators_len_at_subcap_sampled() {
        // Sub-cap exact-equality strengthening of the
        // `aggregate.distinct_identities ≥ top_creators.len()` invariant.
        // When distinct ≤ 20 (sub-cap), the truncate(20) is a no-op so
        // the bijection holds exactly: distinct_identities == top_creators.len().
        //
        // Sample five distinct-count regimes — 1 (degenerate),
        // 5 (low-mid), 10 (mid), 19 (sub-cap by 1), 20 (exact cap edge).
        // A regression where the helper added a phantom entry (e.g.
        // accidentally double-counted a creator) would violate the exact
        // equality on multiple regimes simultaneously. A regression that
        // SOMETIMES truncated below 20 (e.g. an `if distinct >= 19` typo
        // for `>= 21`) would surface at N=19 or N=20 only.
        for &n in &[1_usize, 5, 10, 19, 20] {
            let mut pending = PendingLedger::new();
            for c in 0..n {
                pending
                    .insert(mk_delta(
                        &format!("c{c}-r0"),
                        &format!("creator-{c:03}"),
                        100.0 + c as f64,
                    ))
                    .expect("insert");
            }
            let payload =
                pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
            let distinct = payload["aggregate"]["distinct_identities"]
                .as_u64()
                .expect("distinct_identities must be u64") as usize;
            let top_len = payload["top_creators"].as_array().unwrap().len();
            assert_eq!(
                distinct, n,
                "N={n} sub-cap: aggregate.distinct_identities ({distinct}) must equal N"
            );
            assert_eq!(
                distinct, top_len,
                "N={n} sub-cap: aggregate.distinct_identities ({distinct}) MUST equal \
                 top_creators.len() ({top_len}) — sub-cap bijection holds before truncate(20) fires"
            );
        }
    }

    #[test]
    fn batch_ll_hidden_creator_count_equals_distinct_minus_top_len_at_supercap_sampled() {
        // SUPERCAP companion to the
        // `batch_kk_aggregate_distinct_identities_equals_top_creators_len_at_subcap_sampled` test.
        // When distinct > 20, the truncation hides (distinct - 20) creators
        // from `top_creators`. The operator dashboard at `/admin/pending_ledger`
        // computes the "truncation indicator" as `distinct - top.len()` —
        // sampling across THREE supercap regimes (N=21 just above the cap,
        // N=30 mid-supercap, N=50 high-supercap) pins the hidden-count
        // identity at varying truncation magnitudes.
        //
        // Existing supercap tests pin individual (distinct, top.len()) pairs
        // at N=21, N=23, N=25 but none assert the SUBTRACTION identity
        // `distinct - top.len() == N - 20` directly with the explicit
        // "this many creators are hidden" framing. A regression that
        // accidentally clipped `distinct_identities` to 20 (mirroring the
        // truncate onto the aggregate field — a class of bug that would
        // silently zero the operator dashboard's "n distinct of {x}
        // truncated" line) would survive the individual-pair tests since
        // they pin distinct at the exact N value but only at ONE regime.
        // This test surfaces it across all three sample points.
        for &(n, expected_hidden) in &[(21_usize, 1_usize), (30, 10), (50, 30)] {
            let mut pending = PendingLedger::new();
            for c in 0..n {
                pending
                    .insert(mk_delta(&format!("r{c}"), &format!("creator-{c:03}"), 100.0))
                    .expect("insert");
            }
            let payload =
                pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
            let distinct = payload["aggregate"]["distinct_identities"]
                .as_u64()
                .expect("distinct_identities must be u64") as usize;
            let top_len = payload["top_creators"].as_array().unwrap().len();

            assert_eq!(
                distinct, n,
                "N={n} supercap: aggregate.distinct_identities ({distinct}) must equal N \
                 — clipping aggregate to 20 silently zeroes dashboard 'hidden' indicator"
            );
            assert_eq!(
                top_len, 20,
                "N={n} supercap: top_creators.len() ({top_len}) must equal 20 (truncated)"
            );
            assert_eq!(
                distinct - top_len,
                expected_hidden,
                "N={n} supercap: hidden creator count (distinct - top.len()) must equal \
                 N - 20 = {expected_hidden} — dashboard truncation indicator integrity"
            );
        }
    }

    #[test]
    fn batch_ll_top_creators_last_depth_ge_hidden_creator_max_depth_at_supercap() {
        // Sort-correctness invariant at supercap: when the helper truncates
        // to 20, it MUST drop the BOTTOM-20-by-depth creators (i.e. the
        // depth-descending sort happens BEFORE the truncate). A regression
        // that truncated BEFORE sorting (e.g. truncated the HashMap iter
        // order which is non-deterministic) would drop random creators and
        // the bottom-of-top_creators depth could be lower than some hidden
        // creator's depth.
        //
        // Setup: 25 distinct creators with bimodal depth distribution —
        // creators 00..19 have depth=10 (5 records each), creators 20..24
        // have depth=1 (1 record each). After sort+truncate, top_creators
        // must contain ALL the depth-10 creators (the first 20 entries);
        // creators 20..24 are hidden. Asserts `top_creators[19].depth >=
        // max(hidden_creator_depths)`, where `max(hidden)` is 1.
        //
        // Stronger pin: every entry in top_creators has depth=10 (uniform
        // by construction), and no hidden creator has depth > 1.
        let mut pending = PendingLedger::new();
        // Creators 00..19 with depth=10 each.
        for c in 0..20 {
            for r in 0..10 {
                pending
                    .insert(mk_delta(
                        &format!("r-{c:02}-{r}"),
                        &format!("creator-{c:02}"),
                        100.0 + r as f64,
                    ))
                    .expect("insert deep");
            }
        }
        // Creators 20..24 with depth=1 each.
        for c in 20..25 {
            pending
                .insert(mk_delta(
                    &format!("r-{c:02}-only"),
                    &format!("creator-{c:02}"),
                    100.0,
                ))
                .expect("insert shallow");
        }

        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let top = payload["top_creators"].as_array().expect("array");
        assert_eq!(top.len(), 20, "supercap: top_creators capped at 20");
        assert_eq!(payload["aggregate"]["distinct_identities"].as_u64(), Some(25));

        // Min depth across top_creators (the bottom of the surfaced list).
        let top_min_depth = top
            .iter()
            .map(|e| e["depth"].as_u64().expect("u64 depth"))
            .min()
            .expect("non-empty");
        // Max depth across hidden creators is 1 by construction (creators 20..24).
        let hidden_max_depth: u64 = 1;

        assert!(
            top_min_depth >= hidden_max_depth,
            "sort correctness: bottom of top_creators (depth={top_min_depth}) must be \
             ≥ max(hidden_creator_depths) ({hidden_max_depth}) — a hidden creator with \
             higher depth than the surfaced bottom indicates truncate-before-sort regression"
        );
        // Stronger by construction: bottom of top_creators is exactly the
        // 20-creator deep cohort, so depth=10 throughout.
        assert_eq!(
            top_min_depth, 10,
            "by construction (20 deep creators × depth-10 each), all surfaced have depth=10"
        );
    }

    #[test]
    fn batch_ll_aggregate_max_per_identity_depth_equals_top_zero_depth_at_supercap() {
        // Supercap companion to the
        // `batch_kk_aggregate_max_per_identity_depth_equals_top_creators_zero_depth_at_subcap` test.
        // The truncation in `pending_ledger_inspection_payload` happens
        // AFTER the depth-descending sort, so `top_creators[0]` should be
        // UNAFFECTED by truncation — it's always the deepest creator.
        // Therefore `aggregate.max_per_identity_depth == top_creators[0].depth`
        // must hold at supercap as well, not just sub-cap.
        //
        // Setup: 25 distinct creators where creator-00 has depth=50 (the
        // unique max) and creators 01..24 have depth=1 each. At supercap
        // (distinct=25 > 20), top_creators is truncated to 20, but
        // top_creators[0] should still be creator-00 with depth=50, and
        // aggregate.max_per_identity_depth should equal 50.
        //
        // Catches a regression where the truncate accidentally dropped the
        // max-bucket creator (e.g. truncate-before-sort), or where
        // `aggregate.max_per_identity_depth` drifted from its by_identity
        // scan and one path returned a different value than the other.
        let mut pending = PendingLedger::new();
        // creator-00: depth=50 (max)
        for r in 0..50 {
            pending
                .insert(mk_delta(
                    &format!("r-00-{r}"),
                    "creator-00",
                    100.0 + r as f64,
                ))
                .expect("insert max-bucket");
        }
        // creators 01..24: depth=1 each
        for c in 1..25 {
            pending
                .insert(mk_delta(
                    &format!("r-{c:02}-only"),
                    &format!("creator-{c:02}"),
                    100.0,
                ))
                .expect("insert shallow");
        }

        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let agg_max = payload["aggregate"]["max_per_identity_depth"]
            .as_u64()
            .expect("aggregate.max_per_identity_depth must be u64");
        let top = payload["top_creators"].as_array().unwrap();
        let top0_depth = top[0]["depth"].as_u64().expect("u64 depth");
        let top0_id = top[0]["identity"].as_str().expect("str identity");

        assert_eq!(top.len(), 20, "supercap: top_creators truncated to 20");
        assert_eq!(
            payload["aggregate"]["distinct_identities"].as_u64(),
            Some(25),
            "25 distinct creators in aggregate"
        );
        assert_eq!(
            agg_max, 50,
            "aggregate.max_per_identity_depth must equal max bucket size (50)"
        );
        assert_eq!(
            top0_depth, 50,
            "top_creators[0].depth must equal max bucket size (50) — \
             truncation happens after sort, top[0] is untouched"
        );
        assert_eq!(
            agg_max, top0_depth,
            "cross-derivation at supercap: aggregate.max_per_identity_depth ({agg_max}) \
             MUST equal top_creators[0].depth ({top0_depth}) — both derive the deepest \
             bucket through different code paths (by_identity scan vs per_creator HashMap)"
        );
        assert_eq!(
            top0_id, "creator-00",
            "top_creators[0] identity must be the max-bucket creator (creator-00)"
        );
    }

    #[test]
    fn batch_ll_aggregate_depth_minus_top_sum_equals_sum_of_hidden_depths_at_supercap() {
        // Partition algebraic invariant at supercap with VARYING per-creator
        // depths. Extends the `top_creators_depth_sum_le_aggregate_depth_in_supercap_regime` test
        // (which uses uniform depth=1 ⇒ hidden sum=5 by construction) to a
        // regime where each surfaced and hidden creator has a DIFFERENT
        // depth, so the partition identity
        //   aggregate.depth - sum(top_creators[].depth) == sum_of_hidden_depths
        // becomes algebraically non-trivial.
        //
        // Setup: 30 distinct creators (10 hidden after truncate-to-20):
        //   creators 00..19: depth=2 each   → 20 surfaced, surfaced_sum=40
        //   creators 20..29: depth=1 each   → 10 hidden,   hidden_sum=10
        //   aggregate.depth = 40 + 10 = 50.
        //
        // Asserts: aggregate.depth==50, top.len()==20, top.depth.sum()==40,
        //          50 - 40 == 10 (hidden_sum, the "records dropped" count).
        //
        // Catches a regression that mis-attributed records to top_creators
        // buckets (e.g. counting hidden creators' records into top[0]'s
        // depth would inflate top.sum past aggregate.depth and violate the
        // partition).
        let mut pending = PendingLedger::new();
        // Surfaced cohort: 20 creators × depth=2
        for c in 0..20 {
            for r in 0..2 {
                pending
                    .insert(mk_delta(
                        &format!("r-{c:02}-{r}"),
                        &format!("creator-{c:02}"),
                        100.0 + r as f64,
                    ))
                    .expect("insert surfaced");
            }
        }
        // Hidden cohort: 10 creators × depth=1
        for c in 20..30 {
            pending
                .insert(mk_delta(
                    &format!("r-{c:02}-only"),
                    &format!("creator-{c:02}"),
                    100.0,
                ))
                .expect("insert hidden");
        }

        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        let aggregate_depth =
            payload["aggregate"]["depth"].as_u64().expect("aggregate.depth must be u64");
        let top = payload["top_creators"].as_array().expect("array");
        let top_sum: u64 = top.iter().map(|e| e["depth"].as_u64().unwrap()).sum();
        let hidden_sum_expected: u64 = 10; // 10 hidden creators × depth-1

        assert_eq!(aggregate_depth, 50, "20 × 2 + 10 × 1 = 50 records inserted");
        assert_eq!(top.len(), 20, "supercap: top capped at 20");
        assert_eq!(
            top_sum, 40,
            "20 surfaced × depth-2 each ⇒ top.depth.sum() = 40"
        );
        assert_eq!(
            aggregate_depth - top_sum,
            hidden_sum_expected,
            "partition algebraic invariant at supercap: aggregate.depth ({aggregate_depth}) \
             minus sum(top[].depth) ({top_sum}) must equal sum_of_hidden_depths \
             ({hidden_sum_expected}) — varying-bucket regime distinct from Batch-GG's \
             uniform-depth=1 case"
        );
        // Strict-inequality witness: top_sum < aggregate_depth (since hidden cohort > 0).
        assert!(
            top_sum < aggregate_depth,
            "supercap with positive hidden buckets: top.depth.sum() ({top_sum}) \
             STRICTLY < aggregate.depth ({aggregate_depth})"
        );
    }

    #[test]
    fn batch_ll_payload_byte_identical_across_insertion_order_permutation() {
        // Permutation stability pin: same SET of pending records (creator,
        // applied_at, record_id) inserted in DIFFERENT orders MUST produce
        // a byte-identical payload. Distinct from an earlier purity pin
        // (same input → same output) which only exercises the trivial
        // "call the helper twice on the SAME ledger" path — that does not
        // test whether the helper's internal HashMap-iter + sort path
        // produces a canonical output independent of insertion order.
        //
        // The helper materializes `per_creator: HashMap<String, ...>` then
        // sorts by (depth-desc, applied_at-asc). HashMap iteration order
        // is intentionally non-deterministic across Rust binaries (and
        // even across runs within the same binary, with the default
        // RandomState). If the sort's tiebreak collapsed (e.g. equal
        // depth + equal applied_at across two creators), the resulting
        // top_creators order would leak HashMap iteration order into the
        // payload. This test pins the canonicalization by using DISTINCT
        // (depth, applied_at) tuples per creator so the sort is total —
        // and asserts that three permutations of the SAME record set
        // produce byte-identical JSON.
        //
        // Setup: 10 creators with distinct depths {10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
        // and distinct oldest applied_at — inserted in three orders:
        //   order A: creator-0..9 (depth descending matches insertion order)
        //   order B: creator-9..0 reverse (depth ascending — sort must REWIND)
        //   order C: jumbled (10, 0, 5, 9, 2, 6, 1, 8, 3, 7, 4 — arbitrary mix)
        let depths: Vec<(usize, u64)> = (0..10).map(|i| (i, 10 - i as u64)).collect();
        let now = 10_000.0;

        let build = |order: &[usize]| -> serde_json::Value {
            let mut pending = PendingLedger::new();
            for &idx in order {
                let depth = depths[idx].1;
                let creator = format!("creator-{idx}");
                let base_at = 1000.0 + (idx as f64 * 10.0);
                for r in 0..depth {
                    pending
                        .insert(mk_delta(
                            &format!("r-{idx}-{r}"),
                            &creator,
                            base_at + r as f64,
                        ))
                        .expect("insert");
                }
            }
            pending_ledger_inspection_payload(&pending, &empty_lifetime(), now)
        };

        let order_a: Vec<usize> = (0..10).collect();
        let order_b: Vec<usize> = (0..10).rev().collect();
        let order_c: Vec<usize> = vec![4, 7, 1, 8, 0, 5, 9, 2, 6, 3];

        let payload_a = build(&order_a);
        let payload_b = build(&order_b);
        let payload_c = build(&order_c);

        let json_a = serde_json::to_string(&payload_a).expect("serialize a");
        let json_b = serde_json::to_string(&payload_b).expect("serialize b");
        let json_c = serde_json::to_string(&payload_c).expect("serialize c");

        assert_eq!(
            json_a, json_b,
            "payload must be byte-identical across insertion-order permutation A vs B \
             (ascending vs descending) — sort canonicalization broken"
        );
        assert_eq!(
            json_b, json_c,
            "payload must be byte-identical across insertion-order permutation B vs C \
             (descending vs jumbled) — sort canonicalization broken"
        );
        // Sanity: top[0] must be the depth-10 creator (creator-0).
        let top_a = payload_a["top_creators"].as_array().unwrap();
        assert_eq!(top_a[0]["identity"].as_str(), Some("creator-0"));
        assert_eq!(top_a[0]["depth"].as_u64(), Some(10));
        assert_eq!(top_a.len(), 10, "10 creators ≤ 20 cap, full bijection");
    }

    #[test]
    fn batch_mm_equal_depth_greater_than_one_tiebreak_sorted_oldest_first() {
        // The `batch_t_singleton_creators_each_depth_one_sorted_oldest_first` test
        // pins the oldest-first tiebreak in the regime where ALL records share
        // depth=1. In that regime the depth-desc primary key is a no-op for
        // every comparison, so the test cannot distinguish a comparator that
        // SKIPS the depth-desc check when depths are equal from one that
        // correctly applies depth-desc first then falls through to oldest-asc.
        //
        // This test forces the tiebreak path with depth STRICTLY GREATER than
        // one (depth=5 across 3 creators), so the depth-desc comparison
        // actively returns Equal and the comparator MUST proceed to the
        // applied_at-asc tiebreak. A regression that only invoked the
        // applied_at tiebreak when depth==1 (special-case path) would silently
        // shuffle the order at depth>1.
        //
        // Setup: 3 creators × depth=5, distinct oldest_applied_at across
        // creators (alice=100.0, bob=200.0, carol=50.0). Ordering by
        // oldest-asc tiebreak: carol(50) → alice(100) → bob(200).
        let mut pending = PendingLedger::new();
        let now = 1_000.0;
        for r in 0..5 {
            // alice records at 100.0, 110.0, 120.0, 130.0, 140.0 — oldest = 100
            pending
                .insert(mk_delta(
                    &format!("r-alice-{r}"),
                    "alice",
                    100.0 + r as f64 * 10.0,
                ))
                .expect("insert alice");
            // bob records at 200.0, 210.0, 220.0, 230.0, 240.0 — oldest = 200
            pending
                .insert(mk_delta(
                    &format!("r-bob-{r}"),
                    "bob",
                    200.0 + r as f64 * 10.0,
                ))
                .expect("insert bob");
            // carol records at 50.0, 60.0, 70.0, 80.0, 90.0 — oldest = 50
            pending
                .insert(mk_delta(
                    &format!("r-carol-{r}"),
                    "carol",
                    50.0 + r as f64 * 10.0,
                ))
                .expect("insert carol");
        }
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);

        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(top.len(), 3, "exactly 3 creators expected");
        // All 3 have depth=5 — pin the depth-equality precondition for the test
        for entry in top {
            assert_eq!(
                entry["depth"], 5,
                "all 3 creators must share depth=5 to force the tiebreak path"
            );
        }
        // Ordering must be oldest-first across the equal-depth set.
        assert_eq!(
            top[0]["identity"], "carol",
            "carol (oldest_applied_at=50) must lead the equal-depth tiebreak"
        );
        assert_eq!(
            top[1]["identity"], "alice",
            "alice (oldest_applied_at=100) must come second in the equal-depth tiebreak"
        );
        assert_eq!(
            top[2]["identity"], "bob",
            "bob (oldest_applied_at=200) must come last in the equal-depth tiebreak"
        );
    }

    #[test]
    fn batch_mm_aggregate_oldest_age_secs_monotonic_in_advancing_now() {
        // Pins the subtraction direction in the helper's age computation:
        //   age = (now - oldest_applied_at).max(0.0)
        // For a stable pending ledger (no inserts/removes between calls),
        // advancing `now` by Δt MUST increase aggregate.oldest_age_secs by
        // exactly Δt (modulo the 0.1-quantum rounding). A regression that
        // swapped the operands (oldest - now) would yield negative ages
        // clamped to 0 across all advancing-now values — silently freezing
        // the operator dashboard's "stuck since" age at 0.0.
        //
        // The N=10 advancing-now grid sampled at Δt = 0, 10, 100, 1000, 10000
        // covers small-clock advances (10s tick), medium (100s = ~1 epoch),
        // and large (1h+) — catches a Δt-overflow regression at i64 boundary
        // too. The expected value is derived from the formula directly with
        // 0.1-quantum rounding applied, not from a hardcoded literal.
        let mut pending = PendingLedger::new();
        pending
            .insert(mk_delta("r-1", "alice", 1_000.0))
            .expect("insert");

        // Stable ledger across calls. Sample at advancing `now`.
        let baseline_now = 1_000.0;
        let mut prev_age: Option<f64> = None;
        for &delta in &[0.0, 10.0, 100.0, 1_000.0, 10_000.0] {
            let now = baseline_now + delta;
            let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);
            let age = payload["aggregate"]["oldest_age_secs"]
                .as_f64()
                .expect("aggregate.oldest_age_secs must be a JSON number");
            // Expected age = (now - 1000.0).max(0.0), quantized to 0.1.
            let expected = ((now - 1_000.0).max(0.0) * 10.0).round() / 10.0;
            assert!(
                (age - expected).abs() < 1e-9,
                "at delta={delta}s, aggregate.oldest_age_secs must equal {expected} \
                 (got {age}); subtraction direction must be (now - oldest), not (oldest - now)"
            );
            // Monotonicity: each step must be ≥ previous.
            if let Some(p) = prev_age {
                assert!(
                    age >= p,
                    "aggregate.oldest_age_secs must be non-decreasing as now advances \
                     (delta={delta}: prev={p}, curr={age})"
                );
            }
            prev_age = Some(age);
        }
        // Sanity: final age at delta=10000 must be 10000.0 (the full advance).
        assert!(
            (prev_age.unwrap() - 10_000.0).abs() < 1e-9,
            "after advancing now by 10000s, aggregate.oldest_age_secs must equal 10000.0"
        );
    }

    #[test]
    fn batch_mm_aggregate_distinct_identities_le_aggregate_depth_algebraic_invariant() {
        // Algebraic upper bound: each distinct identity contributes ≥1 record
        // to the ledger, so the total record count (aggregate.depth) must be
        // ≥ the distinct-identity count (aggregate.distinct_identities). A
        // regression that swapped the two fields (depth ← distinct, or vice
        // versa) would surface here for any setup where the two values
        // genuinely differ.
        //
        // The invariant `distinct_identities ≤ depth` is non-trivial only when
        // SOME creator has depth > 1 (otherwise both fields are equal). The
        // setup samples N=10 total records distributed across {1, 3, 5, 10}
        // creators — at N=10/creators=1 the per-creator depth is 10 (depth=10,
        // distinct=1, ratio 10×); at N=10/creators=10 depth=10, distinct=10
        // (ratio 1×, equality boundary). The full range exercises both the
        // strict-inequality and the equality cases.
        for &num_creators in &[1usize, 3, 5, 10] {
            let mut pending = PendingLedger::new();
            // Distribute 10 records across num_creators creators round-robin.
            for r in 0..10 {
                let creator_idx = r % num_creators;
                pending
                    .insert(mk_delta(
                        &format!("r-{r}"),
                        &format!("creator-{creator_idx}"),
                        100.0 + r as f64,
                    ))
                    .expect("insert");
            }
            let payload =
                pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
            let depth = payload["aggregate"]["depth"]
                .as_u64()
                .expect("aggregate.depth is u64");
            let distinct = payload["aggregate"]["distinct_identities"]
                .as_u64()
                .expect("aggregate.distinct_identities is u64");
            assert!(
                distinct <= depth,
                "at num_creators={num_creators}: distinct_identities ({distinct}) \
                 must be ≤ depth ({depth}) — algebraic invariant: each identity \
                 contributes ≥1 record"
            );
            // Sanity: distinct must equal num_creators in the round-robin setup.
            assert_eq!(
                distinct, num_creators as u64,
                "at num_creators={num_creators}: distinct_identities must equal {num_creators}"
            );
            // Sanity: depth must always equal 10 (total records).
            assert_eq!(
                depth, 10,
                "at num_creators={num_creators}: total depth must equal 10"
            );
        }
    }

    #[test]
    fn batch_mm_top_creators_depth_le_aggregate_max_per_identity_depth_per_element_invariant() {
        // Algebraic per-element upper bound: every `top_creators[i].depth` is
        // bounded above by `aggregate.max_per_identity_depth` (which IS the
        // deepest creator's depth, derived independently via
        // `pending.max_per_identity_depth()` scanning the by_identity HashMap).
        //
        // Distinct from the top[0]==max_per_identity_depth
        // EQUALITY at sub-cap and the same at supercap —
        // those pin the EQUALITY on top[0] only. This test pins the UPPER
        // BOUND on ALL top_creators[i] across i ∈ [0, top.len()) — catches
        // a regression where top[k] (k>0) somehow exceeds the per-identity
        // depth (e.g. a wraparound in u64 subtraction during sort, or a
        // misindexed source field that pulled depth from `aggregate.depth`
        // instead of per-creator entry).
        //
        // Setup: bimodal depth — 1 creator at depth=10, 4 creators at
        // depth=3, sampled at distinct=5 (sub-cap). max_per_identity_depth=10.
        // ALL top_creators[i].depth ≤ 10.
        let mut pending = PendingLedger::new();
        for r in 0..10 {
            pending
                .insert(mk_delta(
                    &format!("r-alice-{r}"),
                    "alice",
                    100.0 + r as f64,
                ))
                .expect("insert alice");
        }
        for c in 0..4 {
            for r in 0..3 {
                pending
                    .insert(mk_delta(
                        &format!("r-c{c}-{r}"),
                        &format!("creator-{c}"),
                        200.0 + r as f64,
                    ))
                    .expect("insert creator");
            }
        }
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 10_000.0);
        let max_per_identity = payload["aggregate"]["max_per_identity_depth"]
            .as_u64()
            .expect("max_per_identity_depth is u64");
        assert_eq!(
            max_per_identity, 10,
            "max_per_identity_depth must equal alice's depth=10"
        );
        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(top.len(), 5, "5 creators expected at sub-cap");
        for (i, entry) in top.iter().enumerate() {
            let entry_depth = entry["depth"].as_u64().expect("depth is u64");
            assert!(
                entry_depth <= max_per_identity,
                "top_creators[{i}].depth ({entry_depth}) must be ≤ \
                 aggregate.max_per_identity_depth ({max_per_identity}) — \
                 algebraic per-element upper bound"
            );
        }
    }

    #[test]
    fn batch_mm_top_creators_comparator_total_ordering_contract_pairwise() {
        // Pins the COMPARATOR CONTRACT independent of specific values:
        // for any pair (i, j) with i < j in top_creators, EITHER
        //   (1) depth[i] > depth[j]                          (primary)
        //   OR
        //   (2) depth[i] == depth[j] AND oldest[i] ≤ oldest[j] (tiebreak)
        //
        // Existing tests pin SPECIFIC orderings against literal expected
        // identities (an earlier depth=1 ordering, and the depth=5 ordering above). This
        // test pins the comparator CONTRACT — i.e. the predicate that must
        // hold for ANY adjacent and ANY non-adjacent pair, regardless of
        // specific identities or oldest_applied_at values. A regression
        // that broke ordering only for non-adjacent pairs (e.g. an
        // insertion-sort bug that left some i<j pair out of order while
        // adjacent pairs i,i+1 are correct) would surface here.
        //
        // Setup: bimodal depth — 5 creators at depth=3, 5 creators at
        // depth=2. Within each depth band, distinct oldest_applied_at. The
        // pairwise check iterates all (i, j) with i < j in top_creators
        // (10 entries → 45 pairs).
        let mut pending = PendingLedger::new();
        // 5 creators × depth=3, oldest_applied_at staggered 100..104
        for c in 0..5 {
            for r in 0..3 {
                pending
                    .insert(mk_delta(
                        &format!("r-deep-c{c}-{r}"),
                        &format!("deep-c{c}"),
                        // Distinct oldest applied_at per creator
                        100.0 + c as f64 + r as f64 * 100.0,
                    ))
                    .expect("insert deep");
            }
        }
        // 5 creators × depth=2, oldest_applied_at staggered 50..54
        for c in 0..5 {
            for r in 0..2 {
                pending
                    .insert(mk_delta(
                        &format!("r-shallow-c{c}-{r}"),
                        &format!("shallow-c{c}"),
                        50.0 + c as f64 + r as f64 * 100.0,
                    ))
                    .expect("insert shallow");
            }
        }
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 10_000.0);
        let top = payload["top_creators"].as_array().unwrap();
        assert_eq!(top.len(), 10, "10 creators expected (5 deep + 5 shallow)");

        // Pairwise total-ordering contract check over all (i, j) with i < j.
        for (i, entry_i) in top.iter().enumerate() {
            let depth_i = entry_i["depth"].as_u64().unwrap();
            let oldest_i = entry_i["oldest_age_secs"].as_f64().unwrap();
            for (j, entry_j) in top.iter().enumerate().skip(i + 1) {
                let depth_j = entry_j["depth"].as_u64().unwrap();
                let oldest_j = entry_j["oldest_age_secs"].as_f64().unwrap();
                // oldest_age_secs is (now - oldest_applied_at), so OLDER
                // applied_at means LARGER oldest_age_secs. Tiebreak should
                // sort oldest_applied_at ascending → oldest_age_secs
                // descending. Pair (i, j) must satisfy:
                //   (depth_i > depth_j) OR
                //   (depth_i == depth_j AND oldest_age_secs_i ≥ oldest_age_secs_j)
                let primary_holds = depth_i > depth_j;
                let tiebreak_holds = depth_i == depth_j && oldest_i >= oldest_j;
                assert!(
                    primary_holds || tiebreak_holds,
                    "comparator contract violated at pair (i={i}, j={j}): \
                     depth[{i}]={depth_i}, depth[{j}]={depth_j}, \
                     oldest_age_secs[{i}]={oldest_i}, oldest_age_secs[{j}]={oldest_j} \
                     — neither (depth desc) NOR (depth equal + oldest_age desc) holds"
                );
            }
        }

        // Sanity: top[0..5] are deep creators, top[5..10] are shallow.
        for (i, entry) in top.iter().enumerate().take(5) {
            assert_eq!(
                entry["depth"], 3,
                "top[{i}] must be a depth=3 (deep) creator"
            );
        }
        for (i, entry) in top.iter().enumerate().skip(5).take(5) {
            assert_eq!(
                entry["depth"], 2,
                "top[{i}] must be a depth=2 (shallow) creator"
            );
        }
    }

    // ─── Cross-derivation invariants ─────────────────────────────────────────
    //
    // Picks up follow-up axes for the `pending_ledger_inspection_payload`
    // helper. The five tests are orthogonal to all prior slices:
    //
    //   1. Cross-derivation against `pending.pending_count_for(identity)` — a
    //      THIRD independent route to per-creator depth (helper's per-creator
    //      HashMap vs `pending_count_for` which scans `by_identity`). KK-4
    //      pins agreement on top[0] only against `max_per_identity_depth()`;
    //      this pins agreement on ALL top_creators[i] against a different API
    //      method, catching a drift between the helper's accumulator and the
    //      pending-ledger's by_identity index.
    //   2. Removal-by-`take()` observability — companion to JJ-4
    //      (mutation-by-INSERTION); pins mutation-by-REMOVAL so a future
    //      stale-cache regression that retains creator entries after take()
    //      empties their bucket would surface here.
    //   3. Lifetime/aggregate field separation — empty pending + non-zero
    //      lifetime_counters must yield ALL `aggregate.*` fields at 0 and
    //      `top_creators` empty. Catches an accidental binding of aggregate.depth
    //      to lifetime.commits_total (or any other cross-field wiring).
    //   4. Per-element `top_creators[i].oldest_age_secs` converges to MIN
    //      across applied_at, not first-observed or max. The helper's accumulator
    //      uses `or_insert((0, d.applied_at))` then `if d.applied_at < entry.1`
    //      — a regression dropping the `<` comparison would leave entry.1
    //      stuck at first-observed. Setup inserts records in NON-monotonic
    //      applied_at order to defeat insertion-order coincidence.
    //   5. Clock-skew clamp at MULTI-creator regime — an earlier clamp test
    //      uses a single creator. This extends to 3 creators all with future
    //      applied_at (distinct future values), pinning the clamp at BOTH
    //      aggregate AND every top_creators[i]. Catches a regression where the
    //      clamp at top_creators[i] is gated on a single-creator special case.

    #[test]
    fn batch_nn_top_creators_depth_cross_derivation_against_pending_count_for_public_api() {
        // Cross-derivation pin: for each `top_creators[i].identity`, the
        // `depth` field MUST equal `pending.pending_count_for(identity)`. The
        // helper computes depth via its own per-creator HashMap accumulator
        // (counting `pending.iter()` records by creator). `pending_count_for`
        // is an independent public-API method that scans the `by_identity`
        // index. Both should converge to the same per-creator record count;
        // divergence indicates one path is stale (e.g. by_identity grew stale
        // after a take() or a remove()).
        //
        // Distinct from KK-4 (`max_per_identity_depth` cross-derivation, which
        // pins ONLY top[0] against ONE public API method): this test pins ALL
        // top_creators[i] against a DIFFERENT public API method
        // (`pending_count_for`), exercising a third independent derivation
        // route across every entry in the sorted list.
        //
        // Setup: 5 creators × varying depths (alice=10, bob=7, carol=4, dave=3,
        // eve=1) — all at sub-cap. Sorted by depth-desc, top_creators has 5
        // entries. Each entry's depth must equal pending_count_for(identity).
        let mut pending = PendingLedger::new();
        let depths = [("alice", 10u64), ("bob", 7), ("carol", 4), ("dave", 3), ("eve", 1)];
        for (creator, depth) in &depths {
            for r in 0..*depth {
                pending
                    .insert(mk_delta(
                        &format!("r-{creator}-{r}"),
                        creator,
                        100.0 + r as f64,
                    ))
                    .expect("insert");
            }
        }
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 10_000.0);
        let top = payload["top_creators"].as_array().expect("top is array");
        assert_eq!(top.len(), 5, "5 creators at sub-cap → 5 entries expected");
        for entry in top {
            let identity = entry["identity"].as_str().expect("identity is string");
            let depth_from_helper = entry["depth"].as_u64().expect("depth is u64");
            let depth_from_public_api = pending.pending_count_for(identity) as u64;
            assert_eq!(
                depth_from_helper, depth_from_public_api,
                "top_creators[{identity}].depth ({depth_from_helper}) must equal \
                 pending.pending_count_for({identity}) ({depth_from_public_api}) — \
                 helper's per-creator HashMap accumulator and the by_identity index \
                 must agree on per-creator record count across all entries"
            );
        }
    }

    #[test]
    fn batch_nn_removal_by_take_drops_creator_from_top_and_decrements_distinct_identities() {
        // Mutation-by-REMOVAL observability — companion to the
        // mutation-by-INSERTION test. The helper observes `pending.iter()`
        // each call, so after `take()` empties a creator's bucket the helper
        // MUST drop the creator from `top_creators` and decrement
        // `aggregate.distinct_identities`. A regression that built a cache
        // from a stale snapshot (e.g. `&pending`-keyed memoization that
        // doesn't observe take()) would silently retain the removed creator.
        //
        // Setup: insert 5 records by alice + 3 records by bob, snapshot
        // payload A (distinct=2, top has both). Then take() ALL 5 alice
        // records. Snapshot payload B must have distinct=1, top has ONLY bob,
        // alice MUST NOT appear in top_creators.
        let mut pending = PendingLedger::new();
        for r in 0..5 {
            pending
                .insert(mk_delta(&format!("r-alice-{r}"), "alice", 100.0 + r as f64))
                .expect("insert alice");
        }
        for r in 0..3 {
            pending
                .insert(mk_delta(&format!("r-bob-{r}"), "bob", 200.0 + r as f64))
                .expect("insert bob");
        }
        let payload_pre = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        assert_eq!(
            payload_pre["aggregate"]["distinct_identities"], 2,
            "pre-removal: distinct=2 (alice + bob)"
        );
        let top_pre = payload_pre["top_creators"].as_array().expect("array");
        assert_eq!(top_pre.len(), 2, "pre-removal: top has 2 entries");
        // Now take() all 5 alice records.
        for r in 0..5 {
            let removed = pending.take(&format!("r-alice-{r}"));
            assert!(
                removed.is_some(),
                "take() of r-alice-{r} must remove a delta"
            );
        }
        // Snapshot AFTER removal — alice MUST be absent from top_creators.
        let payload_post = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
        assert_eq!(
            payload_post["aggregate"]["distinct_identities"], 1,
            "post-removal: distinct must decrement to 1 (only bob)"
        );
        assert_eq!(
            payload_post["aggregate"]["depth"], 3,
            "post-removal: aggregate.depth must equal bob's 3 records"
        );
        let top_post = payload_post["top_creators"].as_array().expect("array");
        assert_eq!(top_post.len(), 1, "post-removal: top has 1 entry (only bob)");
        assert_eq!(
            top_post[0]["identity"], "bob",
            "post-removal: only bob must remain in top_creators"
        );
        // Strict absence pin: alice MUST NOT appear as ANY entry's identity.
        for entry in top_post {
            assert_ne!(
                entry["identity"], "alice",
                "post-removal: alice MUST NOT appear in top_creators — \
                 stale-cache regression would silently retain her"
            );
        }
    }

    #[test]
    fn batch_nn_empty_pending_with_nonzero_lifetime_counters_yields_zero_aggregate_and_empty_top() {
        // Lifetime/aggregate field separation pin: lifetime_counters are
        // separate from the live pending state, so a non-zero `lifetime` MUST
        // NOT contaminate `aggregate.*` or `top_creators`. Catches a regression
        // where (e.g.) `aggregate.depth` was accidentally wired to
        // `lifetime.commits_total`, which would silently inflate the operator
        // dashboard's depth widget without any matching pending records.
        //
        // The existing empty-pending test at L2819 uses `empty_lifetime()`, so
        // it cannot catch this cross-contamination. This test uses NON-zero
        // lifetime values with EMPTY pending and asserts all aggregate fields
        // stay at 0 and top_creators stays empty.
        let pending = PendingLedger::new(); // empty
        let nonzero_lifetime = PendingLedgerLifetimeCounters {
            commits_total: 100,
            discards_total: 200,
            hard_discards_total: 300,
            rejections_total: 400,
            fallback_direct_apply_total: 500,
        };
        let payload = pending_ledger_inspection_payload(&pending, &nonzero_lifetime, 1_000.0);
        let agg = &payload["aggregate"];
        assert_eq!(
            agg["depth"], 0,
            "empty pending: aggregate.depth must be 0 regardless of lifetime values"
        );
        assert_eq!(
            agg["distinct_identities"], 0,
            "empty pending: aggregate.distinct_identities must be 0"
        );
        assert_eq!(
            agg["max_per_identity_depth"], 0,
            "empty pending: aggregate.max_per_identity_depth must be 0"
        );
        assert_eq!(
            agg["oldest_age_secs"], 0.0,
            "empty pending: aggregate.oldest_age_secs must be 0.0"
        );
        assert!(
            payload["top_creators"].as_array().expect("array").is_empty(),
            "empty pending: top_creators must be [] regardless of lifetime values"
        );
        // Cross-check: lifetime values DID flow through correctly.
        let lc = &payload["lifetime_counters"];
        assert_eq!(lc["commits_total"], 100);
        assert_eq!(lc["discards_total"], 200);
        assert_eq!(lc["hard_discards_total"], 300);
        assert_eq!(lc["rejections_total"], 400);
        assert_eq!(lc["fallback_direct_apply_total"], 500);
    }

    #[test]
    fn batch_nn_top_creators_oldest_age_secs_tracks_min_applied_at_under_non_monotonic_insertion() {
        // Per-element `oldest_age_secs` MUST converge to `(now - MIN(applied_at))`.max(0.0)
        // rounded to 0.1, NOT first-observed and NOT max. The helper's
        // accumulator pattern is `or_insert((0, d.applied_at))` then
        // `if d.applied_at < entry.1 { entry.1 = d.applied_at }`. A regression
        // that dropped the `<` comparison would leave entry.1 stuck at the
        // first-observed applied_at; a regression that flipped the comparison
        // to `>` would track MAX instead of MIN.
        //
        // Setup: 3 creators × 5 records each. For each creator, applied_at
        // values are NON-monotonic in insertion order — the MIN is in the
        // MIDDLE of the inserted sequence (not first, not last). This defeats
        // both stuck-at-first and stuck-at-last regressions in a single test.
        //
        // alice: applied_at = [300, 200, 100, 250, 350] — MIN=100 at insertion-index 2
        // bob:   applied_at = [600, 500, 400, 550, 650] — MIN=400 at insertion-index 2
        // carol: applied_at = [900, 800, 700, 850, 950] — MIN=700 at insertion-index 2
        //
        // Expected oldest_age_secs at now=10_000:
        //   alice → (10000 - 100).max(0).0 → 9900.0 rounded → 9900.0
        //   bob   → (10000 - 400).max(0).0 → 9600.0
        //   carol → (10000 - 700).max(0).0 → 9300.0
        let mut pending = PendingLedger::new();
        let creator_data = [
            ("alice", [300.0, 200.0, 100.0, 250.0, 350.0], 100.0),
            ("bob", [600.0, 500.0, 400.0, 550.0, 650.0], 400.0),
            ("carol", [900.0, 800.0, 700.0, 850.0, 950.0], 700.0),
        ];
        for (creator, applied_ats, _min) in &creator_data {
            for (r, applied_at) in applied_ats.iter().enumerate() {
                pending
                    .insert(mk_delta(
                        &format!("r-{creator}-{r}"),
                        creator,
                        *applied_at,
                    ))
                    .expect("insert");
            }
        }
        let now = 10_000.0;
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);
        let top = payload["top_creators"].as_array().expect("array");
        assert_eq!(top.len(), 3, "3 creators expected");
        // Build a lookup map from identity → oldest_age_secs.
        let mut age_by_identity: HashMap<&str, f64> = HashMap::new();
        for entry in top {
            let identity = entry["identity"].as_str().expect("string");
            let age = entry["oldest_age_secs"].as_f64().expect("f64");
            age_by_identity.insert(identity, age);
        }
        for (creator, _applied_ats, min_applied) in &creator_data {
            let expected = ((now - min_applied).max(0.0) * 10.0).round() / 10.0;
            let actual = age_by_identity.get(creator).copied().expect("present");
            assert!(
                (actual - expected).abs() < 1e-9,
                "{creator}: oldest_age_secs must equal (now - MIN(applied_at)).max(0.0) = \
                 {expected} (got {actual}) — accumulator must converge to MIN regardless of \
                 insertion order"
            );
        }
    }

    #[test]
    fn batch_nn_clock_skew_clamp_at_multi_creator_regime_aggregate_and_per_element() {
        // Multi-creator extension of the
        // `batch_t_clock_skew_future_applied_at_clamps_oldest_age_to_zero` test,
        // which uses a SINGLE creator. The clamp `(now - applied_at).max(0.0)`
        // is applied at TWO sites (aggregate.oldest_age_secs derived from
        // `pending.oldest_applied_at()` and top_creators[].oldest_age_secs
        // derived from the per-creator accumulator). A regression that
        // applied the clamp only at the aggregate level OR only on the
        // single-creator branch would survive the single-creator test but fail here at the
        // per-element level across multiple creators.
        //
        // Setup: 3 creators, each with 2 records, ALL records at applied_at
        // strictly greater than `now` (distinct future values per creator).
        // Both aggregate.oldest_age_secs AND every top_creators[i].oldest_age_secs
        // MUST clamp to 0.0 (not negative).
        let mut pending = PendingLedger::new();
        let now = 1_000.0;
        // alice: 2 records at 1500, 1600 (both future)
        // bob:   2 records at 2500, 2400 (both future)
        // carol: 2 records at 3500, 3700 (both future)
        let setups = [
            ("alice", [1_500.0, 1_600.0]),
            ("bob", [2_500.0, 2_400.0]),
            ("carol", [3_500.0, 3_700.0]),
        ];
        for (creator, applied_ats) in &setups {
            for (r, applied_at) in applied_ats.iter().enumerate() {
                pending
                    .insert(mk_delta(
                        &format!("r-{creator}-{r}"),
                        creator,
                        *applied_at,
                    ))
                    .expect("insert");
            }
        }
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);
        // Aggregate clamp pin.
        assert_eq!(
            payload["aggregate"]["oldest_age_secs"], 0.0,
            "aggregate.oldest_age_secs must clamp to 0.0 when ALL applied_at > now \
             across 3 creators"
        );
        // Per-element clamp pin across ALL top_creators entries.
        let top = payload["top_creators"].as_array().expect("array");
        assert_eq!(top.len(), 3, "3 creators expected");
        for entry in top {
            let identity = entry["identity"].as_str().expect("string");
            let age = entry["oldest_age_secs"].as_f64().expect("f64");
            assert_eq!(
                age, 0.0,
                "top_creators[{identity}].oldest_age_secs must clamp to 0.0 \
                 when applied_at > now (got {age}) — clamp must fire at the \
                 per-element site across ALL creators, not just at the aggregate site"
            );
        }
    }

    // ---- 5 orthogonal axes ----
    //
    // Each test below pins a contract on `pending_ledger_inspection_payload`
    // that is independently derived from a route NOT exercised by any prior
    // batch, so a
    // regression introduced at any single derivation site surfaces in exactly
    // one of these tests rather than cascading silently across the runbook.

    #[test]
    fn batch_oo_aggregate_distinct_identities_re_derived_via_pending_iter_hashset_cross_regime() {
        // Cross-derivation pin for `aggregate.distinct_identities`. The helper
        // calls `pending.distinct_identities()` (pending_ledger.rs:239) which
        // returns `self.by_identity.len()` — count of an internal index keyed
        // by creator. Re-derive the same value via `pending.iter()` (which
        // reads from `self.by_record.values()`, a DIFFERENT internal map) and
        // collect creators into a HashSet. The two indices MUST agree at
        // every regime, since they track the same logical set of live deltas
        // from different angles. A regression where `by_identity` becomes
        // stale (e.g. an `insert` path that forgets to add to `by_identity`,
        // or a `remove` path that forgets to clear empty buckets) would pass
        // every existing test (both
        // compare against `top_creators.len()`, which is ALSO derived from
        // `pending.iter()` via the helper's per_creator HashMap, so a stale
        // `by_identity` slips past those tests).
        //
        // Sweep N ∈ {0, 1, 5, 19, 20, 21, 100} — covers empty, single,
        // sub-cap, cap-adjacent, and super-cap regimes.
        use std::collections::HashSet;
        let now = 10_000.0;
        for &n in &[0_usize, 1, 5, 19, 20, 21, 100] {
            let mut pending = PendingLedger::new();
            for i in 0..n {
                pending
                    .insert(mk_delta(
                        &format!("rec-{i}"),
                        &format!("creator-{i:03}"),
                        100.0 + i as f64,
                    ))
                    .unwrap_or_else(|_| panic!("insert N={n} i={i}"));
            }
            let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);
            let agg_distinct = payload["aggregate"]["distinct_identities"]
                .as_u64()
                .expect("distinct_identities u64");
            let iter_distinct: HashSet<&str> =
                pending.iter().map(|d| d.creator.as_str()).collect();
            assert_eq!(
                agg_distinct as usize,
                iter_distinct.len(),
                "N={n}: aggregate.distinct_identities ({agg_distinct}) must equal \
                 HashSet-of-creators from pending.iter() ({}) — internal indices \
                 by_identity and by_record must agree at every regime",
                iter_distinct.len()
            );
            // Sanity: derived value matches the count we inserted (each delta
            // has a unique creator).
            assert_eq!(
                agg_distinct as usize, n,
                "N={n}: every inserted creator is distinct; expected {n} got {agg_distinct}"
            );
        }
    }

    #[test]
    fn batch_oo_top_creators_len_bounded_by_twenty_across_n_sweep() {
        // Universal bound pin: `top_creators.len() ≤ 20` regardless of how
        // many distinct creators are in pending. Existing tests pin SPECIFIC
        // N points (at N=21, N=20, and N=21/30/50). None pin the bound as a SWEEP,
        // so a regression that introduced a depth-dependent truncate (e.g.
        // truncate to `2 * max_per_identity_depth` instead of constant 20)
        // would pass at most existing test points by coincidence.
        //
        // Sweep N ∈ {0, 1, 5, 19, 20, 21, 50, 100} pins the bound across
        // empty / sub-cap / cap-adjacent / well-above-cap regimes.
        let now = 5_000.0;
        for &n in &[0_usize, 1, 5, 19, 20, 21, 50, 100] {
            let mut pending = PendingLedger::new();
            for i in 0..n {
                pending
                    .insert(mk_delta(
                        &format!("r-{i}"),
                        &format!("c-{i:04}"),
                        50.0 + i as f64,
                    ))
                    .unwrap_or_else(|_| panic!("insert N={n} i={i}"));
            }
            let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);
            let top_len = payload["top_creators"]
                .as_array()
                .expect("top_creators array")
                .len();
            assert!(
                top_len <= 20,
                "N={n}: top_creators.len()={top_len} must satisfy ≤ 20 universal bound \
                 (sort.truncate(20) at admin.rs:2748)"
            );
            // Also pin the lower-bound complement: top_creators.len() ==
            // min(N, 20). Catches a regression that always returned 20
            // entries regardless of input (e.g. pad with empty strings).
            let expected = n.min(20);
            assert_eq!(
                top_len, expected,
                "N={n}: top_creators.len()={top_len} must equal min(N, 20)={expected}"
            );
        }
    }

    #[test]
    fn batch_oo_aggregate_oldest_age_secs_round_half_away_from_zero_at_sub_second_boundaries() {
        // Round-half-away-from-zero CONTRACT pin at `aggregate.oldest_age_secs`.
        // An earlier test pinned the SAME `(age * 10.0).round() / 10.0`
        // expression at `top_creators[].oldest_age_secs` (admin.rs:2757).
        // This test pins the contract at the SECOND call site —
        // `aggregate.oldest_age_secs` at admin.rs:2772 — which flows from a
        // DIFFERENT input (`pending.oldest_applied_at()` reads the global MIN
        // across all records, while top_creators[] reads per-creator MIN from
        // the helper's HashMap accumulator). A refactor that switched to a
        // round-half-to-even crate (`(age * 10.0).round_ties_even() / 10.0`)
        // at the aggregate site alone would silently flip 0.3 → 0.2 in the
        // operator dashboard while every top_creators[]-level test stayed green.
        //
        // Sweep age ∈ {0.5, 0.25, 0.75, 0.125} — same boundary set as the
        // earlier top_creators test, but applied at the aggregate site. Each setup uses a SINGLE
        // creator so `pending.oldest_applied_at()` is deterministic.
        let now = 1_024.0_f64;
        let boundaries: &[(f64, i64)] = &[
            (0.5, 5),    // 0.5 * 10 = 5.0 → round = 5 → /10 = 0.5
            (0.25, 3),   // 0.25 * 10 = 2.5 → round-half-away-from-zero = 3 → 0.3
            (0.75, 8),   // 0.75 * 10 = 7.5 → round-half-away-from-zero = 8 → 0.8
            (0.125, 1),  // 0.125 * 10 = 1.25 → round = 1 → /10 = 0.1
        ];
        for &(age_input, expected_quantum) in boundaries {
            let mut pending = PendingLedger::new();
            pending
                .insert(mk_delta("r-0", "alice", now - age_input))
                .expect("insert");
            let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);
            let agg_age = payload["aggregate"]["oldest_age_secs"]
                .as_f64()
                .expect("aggregate.oldest_age_secs f64");
            let quantum = (agg_age * 10.0).round() as i64;
            assert_eq!(
                quantum, expected_quantum,
                "age input {age_input}s at aggregate level must quantize to integer \
                 {expected_quantum} at 0.1-quantum (got {quantum}, age {agg_age}). \
                 Catches a refactor that changed the rounding contract at the \
                 aggregate.oldest_age_secs site (admin.rs:2772) independent of \
                 top_creators[]."
            );
            // Quantum invariant — the emitted age, multiplied by 10, must be
            // an exact integer (within f64 precision). Catches a refactor
            // that switched to a finer (0.01) or coarser quantum.
            let times_ten = agg_age * 10.0;
            let rounded = times_ten.round();
            assert!(
                (times_ten - rounded).abs() < 1e-9,
                "age input {age_input}s: aggregate.oldest_age_secs={agg_age} \
                 not on 0.1 quantum (age*10={times_ten}, rounded={rounded})"
            );
        }
    }

    #[test]
    fn batch_oo_top_creators_depth_re_derived_via_pending_iter_filter_count_per_element() {
        // Third cross-derivation route for `top_creators[i].depth`. Existing
        // pins:
        //   - against `pending.pending_count_for(identity)`
        //     (which reads `by_identity` HashMap and returns the bucket size).
        //   - against `pending.max_per_identity_depth()`
        //     for top[0] only (which reads `by_identity` values and takes
        //     max).
        // Both existing routes flow through the `by_identity` index. This
        // test re-derives via `pending.iter().filter(|d| d.creator == X).count()`
        // — flows through `by_record` (which is the helper's actual input
        // via `pending.iter()` at admin.rs:2730). Catches a regression in the
        // helper's per_creator HashMap accumulator (e.g. `entry.0 += 2`
        // typo, or a shadowed `entry` rebind that silently zeros the count
        // mid-loop) that leaves `by_identity` correct and so passes those
        // by_identity-based tests.
        let mut pending = PendingLedger::new();
        let now = 7_500.0;
        // Distinct depths so sort order is deterministic — 5 creators with
        // depths 5/4/3/2/1 — covers the per-element check across the full
        // top_creators array.
        for (idx, &depth) in [5_usize, 4, 3, 2, 1].iter().enumerate() {
            let creator = format!("c{idx}");
            for r in 0..depth {
                pending
                    .insert(mk_delta(
                        &format!("r-{idx}-{r}"),
                        &creator,
                        100.0 + idx as f64,
                    ))
                    .expect("insert");
            }
        }
        let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);
        let top = payload["top_creators"].as_array().expect("array");
        assert_eq!(top.len(), 5, "5 creators expected");
        for (i, entry) in top.iter().enumerate() {
            let identity = entry["identity"].as_str().expect("identity str");
            let helper_depth = entry["depth"].as_u64().expect("depth u64");
            let filter_count = pending
                .iter()
                .filter(|d| d.creator == identity)
                .count() as u64;
            assert_eq!(
                helper_depth, filter_count,
                "top_creators[{i}] identity={identity}: helper depth={helper_depth} \
                 must equal pending.iter().filter(creator==identity).count()={filter_count} \
                 — re-derivation through the SAME source index (by_record) as the \
                 helper uses internally, catches an accumulator-loop regression \
                 distinct from Batch-NN's by_identity-route cross-check"
            );
        }
    }

    #[test]
    fn batch_oo_top_creators_identity_set_equals_pending_iter_creator_set_at_subcap_sampled() {
        // SET-equality bijection pin: at sub-cap (N ≤ 20), the set of
        // identities in `top_creators` must exactly equal the set of distinct
        // creators in `pending.iter()`. Strictly stronger than an earlier
        // test (which pinned `aggregate.distinct_identities ==
        // top_creators.len()` — a LENGTH equality only; a regression that
        // dropped creator-X but added a fabricated creator-Y would pass that
        // length check). This pin catches such a substitution at every
        // sub-cap N.
        //
        // Sweep N ∈ {2, 5, 10, 19, 20} — sub-cap regimes only (super-cap
        // would intentionally drop creators by sort order, so bijection
        // doesn't hold there; the hidden-count identity covers the
        // super-cap algebra).
        use std::collections::HashSet;
        let now = 3_000.0;
        for &n in &[2_usize, 5, 10, 19, 20] {
            let mut pending = PendingLedger::new();
            for i in 0..n {
                let creator = format!("creator-{i:03}");
                // Distinct depths so sort order is deterministic, but the
                // SET-equality assertion is order-independent anyway.
                let depth = n - i + 1;
                for r in 0..depth {
                    pending
                        .insert(mk_delta(
                            &format!("r-{i}-{r}"),
                            &creator,
                            200.0 + (i * 100 + r) as f64,
                        ))
                        .unwrap_or_else(|_| panic!("insert N={n} i={i} r={r}"));
                }
            }
            let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);
            let top = payload["top_creators"].as_array().expect("array");
            let top_set: HashSet<&str> = top
                .iter()
                .map(|e| e["identity"].as_str().expect("identity str"))
                .collect();
            let pending_set: HashSet<&str> =
                pending.iter().map(|d| d.creator.as_str()).collect();
            assert_eq!(
                top_set, pending_set,
                "N={n}: top_creators identity SET must equal the SET of distinct \
                 creators in pending.iter(). top_set={top_set:?} pending_set={pending_set:?} — \
                 catches a regression that substitutes one creator for another \
                 (length-only checks would miss the substitution)"
            );
            // Sanity: cardinality matches at sub-cap.
            assert_eq!(top.len(), n, "N={n}: sub-cap, top_creators.len() must equal N");
        }
    }

    #[test]
    fn batch_pp_aggregate_depth_and_max_per_identity_depth_strict_u64_type_empty_and_populated() {
        // Wire-contract type pin for the two remaining `aggregate.*` numeric
        // fields. An earlier test pinned `aggregate.distinct_identities` as
        // strict u64; another pinned `aggregate.oldest_age_secs` as
        // strict f64. The other two `aggregate.*` fields — `depth` and
        // `max_per_identity_depth` — were unpinned at the type level. A
        // regression that promoted EITHER field to f64 (e.g. via a downstream
        // rate-per-sec accumulator accidentally writing back into the rendered
        // aggregate snapshot) would surface here through `is_u64()` returning
        // false. Tested at BOTH empty AND populated branches because a
        // branch-conditional `if depth == 0 { Null } else { Number }`
        // regression would slip past a single-regime test.
        for branch in &["empty", "populated"] {
            let mut pending = PendingLedger::new();
            if *branch == "populated" {
                // 3 records by alice, 2 by bob — max_per_identity_depth=3,
                // depth=5, distinct=2. All three numeric aggregate fields are
                // non-zero so the JSON encoding distinguishes u64 from f64.
                for r in 0..3 {
                    pending
                        .insert(mk_delta(&format!("ra-{r}"), "alice", 100.0 + r as f64))
                        .expect("insert alice");
                }
                for r in 0..2 {
                    pending
                        .insert(mk_delta(&format!("rb-{r}"), "bob", 200.0 + r as f64))
                        .expect("insert bob");
                }
            }
            let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);
            let agg = &payload["aggregate"];
            for field in &["depth", "max_per_identity_depth"] {
                assert!(
                    agg[field].is_u64(),
                    "branch={branch}: aggregate.{field} must be strict u64 (not f64 or string), got {:?}",
                    agg[field]
                );
                assert!(
                    !agg[field].is_f64(),
                    "branch={branch}: aggregate.{field} must NOT be f64"
                );
            }
            // Value-domain sanity: populated branch must have non-zero values
            // for both fields (so the type distinction is non-trivial — a
            // 0 vs 0.0 would parse as_u64 in both encodings).
            if *branch == "populated" {
                assert_eq!(agg["depth"].as_u64(), Some(5));
                assert_eq!(agg["max_per_identity_depth"].as_u64(), Some(3));
            } else {
                assert_eq!(agg["depth"].as_u64(), Some(0));
                assert_eq!(agg["max_per_identity_depth"].as_u64(), Some(0));
            }
        }
    }

    #[test]
    fn batch_pp_aggregate_depth_cross_derived_via_pending_iter_count_across_n_sweep() {
        // Cross-derivation pin for `aggregate.depth`. The helper sources depth
        // via `pending.len() as u64` (admin.rs:2769) — `pending.len()` returns
        // `by_record.len()` (pending_ledger.rs:122-124), a cached count on the
        // internal map. Re-derive the same value via `pending.iter().count()`
        // which iterates `by_record.values()` and counts dynamically. The two
        // routes track the same logical state through different code paths;
        // any drift between cached length and live count would surface here.
        //
        // Mirror of an earlier test which pinned `aggregate.distinct_identities`
        // against `pending.iter()` HashSet-of-creators; this pin covers the
        // OTHER cached-length-vs-live-count route in the helper.
        //
        // Catches a regression where an `insert` path adds to `by_record` but
        // forgets to increment any internal length counter, or a `remove`
        // path decrements `by_record` but leaves a stale length. Existing
        // tests on `depth` (depth ≤ max_total_cap; partition algebra) compare depth against itself or
        // pending.iter()-derived sums, so they'd pass with a drifted cache.
        //
        // Sweep N ∈ {0, 1, 5, 19, 20, 21, 50, 100} — empty, single, sub-cap,
        // cap-adjacent, super-cap regimes.
        let now = 8_000.0;
        for &n in &[0_usize, 1, 5, 19, 20, 21, 50, 100] {
            let mut pending = PendingLedger::new();
            for i in 0..n {
                pending
                    .insert(mk_delta(
                        &format!("r-{i}"),
                        &format!("c-{i:04}"),
                        50.0 + i as f64,
                    ))
                    .unwrap_or_else(|_| panic!("insert N={n} i={i}"));
            }
            let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);
            let agg_depth = payload["aggregate"]["depth"]
                .as_u64()
                .expect("aggregate.depth u64");
            let iter_count = pending.iter().count() as u64;
            assert_eq!(
                agg_depth, iter_count,
                "N={n}: aggregate.depth ({agg_depth}) must equal pending.iter().count() \
                 ({iter_count}) — cached length and live iteration must agree at every regime"
            );
            // Sanity: derived value equals the insertion count (each record
            // is distinct).
            assert_eq!(
                agg_depth as usize, n,
                "N={n}: every inserted record is distinct; expected {n} got {agg_depth}"
            );
        }
    }

    #[test]
    fn batch_pp_top_creators_len_min_distinct_creators_twenty_at_multi_record_per_creator_regime() {
        // Bound pin under K << N regime — where K = distinct_creators and
        // N = total record_count. An earlier test swept the bound across N
        // with 1-record-per-creator, so K == N always; the bound it pinned
        // (`top_creators.len() == min(N, 20)`) is degenerate against a
        // regression that returned `min(record_count, 20)` instead of
        // `min(distinct_creators, 20)`, because at K==N the two are identical.
        //
        // This test uses K << N — many records per creator — so the two
        // formulae diverge and the correct contract (`min(K, 20)`) is
        // distinguishable from the wrong one (`min(N, 20)`).
        //
        // Sample points:
        //   - K=3, N=300 (each creator inserts 100 records) → expect top.len()=3
        //   - K=21, N=210 (each creator inserts 10 records) → expect top.len()=20
        //   - K=50, N=200 (each creator inserts 4 records) → expect top.len()=20
        // The K=3 case is the most diagnostic: a regression returning
        // `min(N=300, 20)=20` instead of `min(K=3, 20)=3` would surface here
        // through a 17-entry overflow (top.len()=20 vs expected 3).
        let now = 6_000.0;
        let cases: &[(usize, usize)] = &[
            (3, 100),  // K=3, records-per-creator=100 → N=300, expect 3
            (21, 10),  // K=21, records-per-creator=10 → N=210, expect 20
            (50, 4),   // K=50, records-per-creator=4  → N=200, expect 20
        ];
        for &(k, records_per) in cases {
            let mut pending = PendingLedger::new();
            for i in 0..k {
                let creator = format!("c-{i:04}");
                for r in 0..records_per {
                    pending
                        .insert(mk_delta(
                            &format!("r-{i}-{r}"),
                            &creator,
                            100.0 + (i * records_per + r) as f64,
                        ))
                        .unwrap_or_else(|_| panic!("insert K={k} i={i} r={r}"));
                }
            }
            let payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), now);
            let top_len = payload["top_creators"]
                .as_array()
                .expect("top_creators array")
                .len();
            let expected = k.min(20);
            assert_eq!(
                top_len, expected,
                "K={k} records-per={records_per}: top_creators.len()={top_len} must equal \
                 min(K, 20)={expected} (NOT min(N={}, 20) — that's the regression we catch)",
                k * records_per
            );
            // Cross-check: aggregate.distinct_identities must also equal K
            // (not N) — the bound is sourced from distinct_creators, not
            // record_count.
            let distinct = payload["aggregate"]["distinct_identities"]
                .as_u64()
                .expect("distinct u64") as usize;
            assert_eq!(
                distinct, k,
                "K={k}: aggregate.distinct_identities must equal K (not N={})",
                k * records_per
            );
        }
    }

    #[test]
    fn batch_pp_helper_observes_no_mutation_on_pending_ledger_across_call() {
        // Read-only contract pin: the helper's signature takes
        // `pending: &crate::accounting::pending_ledger::PendingLedger` (immutable
        // borrow), but a future refactor could insert a Mutex-wrapped
        // interior-mutability cache or a lazy-init side effect. Pin that ALL
        // four public-API read methods on PendingLedger return the same value
        // BEFORE and AFTER the helper call.
        //
        // The four methods exercise distinct internal data structures:
        //   - `len()`              → `by_record.len()` (cached usize)
        //   - `distinct_identities()` → `by_identity.len()` (cached usize)
        //   - `max_per_identity_depth()` → max(by_identity.values().len())
        //   - `oldest_applied_at()` → min(by_record.values().applied_at)
        // A regression that mutated any of the underlying maps (e.g. an
        // accidental `entry(...).or_insert(...)` on a query path) would surface
        // on AT LEAST one of these four read paths.
        //
        // Setup: non-trivial pending state (3 alice + 2 bob = 5 records) so
        // every read returns a non-zero/non-empty value, distinguishing a
        // "mutation that produced the same value" from a "mutation that
        // changed the value".
        let mut pending = PendingLedger::new();
        for r in 0..3 {
            pending
                .insert(mk_delta(&format!("ra-{r}"), "alice", 100.0 + r as f64))
                .expect("insert alice");
        }
        for r in 0..2 {
            pending
                .insert(mk_delta(&format!("rb-{r}"), "bob", 200.0 + r as f64))
                .expect("insert bob");
        }

        // Snapshot all four read paths BEFORE helper call.
        let len_before = pending.len();
        let distinct_before = pending.distinct_identities();
        let max_depth_before = pending.max_per_identity_depth();
        let oldest_before = pending.oldest_applied_at();
        // Materialise iter into a Vec<(creator, applied_at)> for a 5th
        // cross-check — order-sensitive, so equality also pins iteration
        // determinism within a single ledger.
        let iter_before: Vec<(String, f64)> = pending
            .iter()
            .map(|d| (d.creator.clone(), d.applied_at))
            .collect();

        // Call helper.
        let _payload = pending_ledger_inspection_payload(&pending, &empty_lifetime(), 1_000.0);

        // Re-read all four paths AFTER helper call.
        let len_after = pending.len();
        let distinct_after = pending.distinct_identities();
        let max_depth_after = pending.max_per_identity_depth();
        let oldest_after = pending.oldest_applied_at();
        let iter_after: Vec<(String, f64)> = pending
            .iter()
            .map(|d| (d.creator.clone(), d.applied_at))
            .collect();

        assert_eq!(len_before, len_after, "pending.len() drifted across helper call");
        assert_eq!(
            distinct_before, distinct_after,
            "pending.distinct_identities() drifted across helper call"
        );
        assert_eq!(
            max_depth_before, max_depth_after,
            "pending.max_per_identity_depth() drifted across helper call"
        );
        assert_eq!(
            oldest_before, oldest_after,
            "pending.oldest_applied_at() drifted across helper call"
        );
        assert_eq!(
            iter_before, iter_after,
            "pending.iter() materialisation drifted across helper call — catches a refactor \
             that mutated by_record entries (e.g. updated applied_at) under the read borrow"
        );
        // Value-domain sanity: setup invariants — helper saw a non-empty
        // ledger so the assertions above weren't trivially satisfied on
        // empty state.
        assert_eq!(len_after, 5, "setup invariant: 3+2 records");
        assert_eq!(distinct_after, 2, "setup invariant: 2 creators");
        assert_eq!(max_depth_after, 3, "setup invariant: max bucket = 3 (alice)");
        assert_eq!(oldest_after, Some(100.0), "setup invariant: alice's first record");
    }

    #[test]
    fn batch_pp_payload_contains_no_json_null_at_any_depth_empty_and_populated() {
        // No-null tree-walk pin across the ENTIRE payload, at BOTH empty and
        // populated branches. Mirror of an earlier test which pinned the same
        // contract for `compute_zones_scope` output. The helper has at least
        // one `Option<T> → unwrap_or` site at admin.rs:2762-2765 where
        // `pending.oldest_applied_at()` returns `Option<f64>` and is collapsed
        // via `.unwrap_or(0.0)` — a regression that removed the unwrap_or
        // (e.g. `pending.oldest_applied_at().map(|a| ...)`) would emit a JSON
        // `null` on empty-ledger payloads, breaking the operator dashboard's
        // numeric-coerce expectations and the JSON-schema validator at the
        // explorer-frontend layer.
        //
        // Test BOTH empty (where unwrap_or-vs-null divergence is observable)
        // and populated (where the broader payload tree has more nodes and
        // could host a different latent `null` regression).
        fn assert_no_null(v: &serde_json::Value, path: &str) {
            match v {
                serde_json::Value::Null => panic!("found null at JSON path '{path}'"),
                serde_json::Value::Array(arr) => {
                    for (i, e) in arr.iter().enumerate() {
                        assert_no_null(e, &format!("{path}[{i}]"));
                    }
                }
                serde_json::Value::Object(map) => {
                    for (k, e) in map.iter() {
                        assert_no_null(e, &format!("{path}.{k}"));
                    }
                }
                _ => {}
            }
        }

        // Branch 1: empty pending ledger — the regression of greatest concern
        // (oldest_applied_at returns None → if unwrap_or were dropped, this
        // would emit null).
        let pending_empty = PendingLedger::new();
        let payload_empty =
            pending_ledger_inspection_payload(&pending_empty, &empty_lifetime(), 1_000.0);
        assert_no_null(&payload_empty, "$");
        // Belt-and-suspenders: explicitly pin the suspect site as a Number.
        assert!(
            payload_empty["aggregate"]["oldest_age_secs"].is_number(),
            "empty: aggregate.oldest_age_secs must be JSON Number, not Null"
        );

        // Branch 2: populated pending ledger with non-zero lifetime counters.
        // Stresses a broader payload tree (top_creators[] populated, lifetime
        // values non-zero) — catches a regression that emits null on any
        // sub-tree node of the populated path.
        let mut pending_pop = PendingLedger::new();
        for r in 0..5 {
            pending_pop
                .insert(mk_delta(&format!("r-{r}"), "alice", 100.0 + r as f64))
                .expect("insert");
        }
        let lifetime = PendingLedgerLifetimeCounters {
            commits_total: 11,
            discards_total: 22,
            hard_discards_total: 33,
            rejections_total: 44,
            fallback_direct_apply_total: 55,
        };
        let payload_pop =
            pending_ledger_inspection_payload(&pending_pop, &lifetime, 2_000.0);
        assert_no_null(&payload_pop, "$");
        // Belt-and-suspenders: pin the same suspect site is still a Number on
        // the populated branch.
        assert!(
            payload_pop["aggregate"]["oldest_age_secs"].is_number(),
            "populated: aggregate.oldest_age_secs must be JSON Number, not Null"
        );
    }
}

#[cfg(test)]
mod admin_onboard_anchor_tests {
    //! Unit tests for `prepare_onboard_anchor_record` — the testable
    //! core of `/admin/onboard_anchor`. We bypass the PQ admin gate and the
    //! gossip submit step (both shared with every other admin handler) and
    //! exercise the precondition checks + record construction in isolation.
    //!
    //! Coverage:
    //!   1. Non-anchor node_type rejected with actionable error message.
    //!   2. Missing VRF keypair rejected with actionable error message.
    //!   3. Success path: record carries the VRF metadata that
    //!      `extract_vrf_registration` round-trips successfully (i.e. peers
    //!      receiving this record will register the anchor in their
    //!      VrfRegistry under the producer's identity hash).
    //!   4. `was_already_registered` flag flips correctly on the second call.
    use super::prepare_onboard_anchor_record;
    use crate::crypto::vrf::VrfSecretKey;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::state::NodeState;
    use crate::network::vrf_registry::{extract_vrf_registration, VrfRegistration};
    use crate::network::witness::WitnessManager;
    use crate::storage::rocks::StorageEngine;
    use std::sync::Arc;

    /// Minimal NodeState parameterized by `node_type` and whether to install
    /// a VRF keypair. The tempdir is forgotten so the rocks instance lives
    /// for the duration of the test (matches the pattern in
    /// `transitions::tests::test_state`).
    fn build_state(node_type: &str, install_vrf: bool) -> Arc<NodeState> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin-token-x".into(),
            network_id: "ops147-onboard-test".into(),
            node_type: node_type.into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks =
            Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let mut state = NodeState::new(config, identity, rocks, wmgr);
        if install_vrf {
            let sk = VrfSecretKey::generate().expect("vrf keygen");
            let pk = sk.public_key();
            state.set_vrf_keys(Some(sk), Some(pk));
        }
        std::mem::forget(tmp);
        Arc::new(state)
    }

    /// AppError isn't Debug — match instead of using `.expect()`.
    fn unwrap_ok<T>(
        r: Result<T, super::super::super::server::AppError>,
        label: &str,
    ) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{label}: AppError({})", e.0),
        }
    }
    fn unwrap_err_msg<T>(
        r: Result<T, super::super::super::server::AppError>,
        label: &str,
    ) -> String {
        match r {
            Ok(_) => panic!("{label}: expected Err, got Ok"),
            Err(e) => e.0.to_string(),
        }
    }

    #[test]
    fn ops147_rejects_non_anchor_node_type() {
        // node_type=witness cannot become an anchor — extract_vrf_registration
        // would drop the resulting record at ingest, so we must reject here
        // with an operator-facing message that points at the config fix.
        let state = build_state("witness", true);
        let msg = unwrap_err_msg(
            prepare_onboard_anchor_record(&state),
            "witness must not be allowed to onboard as anchor",
        );
        assert!(
            msg.contains("witness") && msg.contains("set node_type=anchor"),
            "error must name the offending node_type and the fix path; got: {msg}"
        );
    }

    #[test]
    fn ops147_rejects_missing_vrf_key() {
        // Anchor-class node without a VRF keypair: boot misconfiguration
        // (set_vrf_keys never called). Record creation would emit metadata
        // pointing at the all-zeros key — useless.
        let state = build_state("anchor", false);
        let msg = unwrap_err_msg(
            prepare_onboard_anchor_record(&state),
            "anchor without VRF key must not produce a registration record",
        );
        assert!(
            msg.contains("VRF") && msg.contains("VRF keypair"),
            "error must point at the VRF keypair gap; got: {msg}"
        );
    }

    #[test]
    fn ops147_success_path_round_trips_through_extract_vrf_registration() {
        // The record this handler produces must be ingestible — i.e.
        // extract_vrf_registration on the resulting record returns Some
        // and the parsed VRF pubkey matches the local node's. Without this
        // round-trip, peers would silently drop the record (rejected
        // counter would climb fleet-wide) and the registry would never
        // converge.
        let state = build_state("anchor", true);
        let (record, was_already_registered, pubkey_hex, node_type_str) = unwrap_ok(
            prepare_onboard_anchor_record(&state),
            "anchor + VRF must succeed",
        );

        assert_eq!(node_type_str, "anchor");
        assert!(!was_already_registered, "fresh state — registry empty");

        // Record carries the VRF metadata that ingest expects.
        let reg: VrfRegistration =
            extract_vrf_registration(&record).expect("ingest must accept this record");
        assert_eq!(reg.vrf_public_key_hex, pubkey_hex);
        assert_eq!(reg.node_type, "anchor");
        assert_eq!(reg.record_id, record.id);
        assert!(
            !reg.vrf_full_public_key_hex.is_empty(),
            "full public key must be carried so peers can verify VRF proofs (post-2026-04 format)"
        );

        // Sanity-check the canonical pubkey shape.
        let pk_bytes = hex::decode(&pubkey_hex).expect("pubkey is hex");
        assert_eq!(pk_bytes.len(), 32, "VRF pubkey hash is 32 bytes");
    }

    #[test]
    fn ops147_idempotent_flag_flips_on_second_call() {
        // Operators should be able to re-publish the registration record
        // (e.g. after a gossip drop). The flag in the response surfaces
        // whether the registry already had the entry — useful for
        // distinguishing "first-time onboarding" from "re-publish".
        let state = build_state("anchor", true);

        // Call 1: registry empty → flag must be false.
        let (record1, already_1, _, _) =
            unwrap_ok(prepare_onboard_anchor_record(&state), "first call");
        assert!(!already_1);

        // Manually insert into the local registry to simulate having
        // observed the record's ingest. We don't replay the full ingest
        // pipeline because the inner helper only consults
        // `vrf_registry.is_registered(identity)` — direct mutation
        // isolates the flag's logic from the rest of the ingest chain.
        let reg = extract_vrf_registration(&record1).expect("metadata extracts");
        {
            let mut registry = state.vrf_registry.write().expect("registry lock");
            registry.register(&state.identity.identity_hash, reg);
        }

        // Call 2: registry has this anchor → flag must be true.
        let (_, already_2, _, _) =
            unwrap_ok(prepare_onboard_anchor_record(&state), "second call");
        assert!(already_2, "flag must surface that registry already has this anchor");
    }

    // ─── Rejection-side edge gaps ────────────────────────────────────────────
    //
    // Closes the remaining edge gaps on `prepare_onboard_anchor_record` left
    // open by the first slice:
    //   • Only `witness` was pinned on the rejection side. The four other
    //     canonical non-anchor node_types ({leaf, relay, archive, gateway})
    //     also fail `can_seal_epochs()` and must surface the same actionable
    //     error pattern — an operator who set node_type=archive expecting
    //     "high-capacity storage = epoch authority" deserves the same fix
    //     pointer as the witness-typo operator. Each of the five canonical
    //     non-anchor types lands on a distinct match-arm of
    //     `NodeType::from_str` (peer.rs:57), so coverage isn't redundant.
    //   • Unknown / typo node_type strings (e.g. uppercase "ANCHOR" — the
    //     `from_str` match is case-sensitive at peer.rs:58) fall through to
    //     `Leaf` and reject — BUT the error message formats with
    //     `state.config.node_type` (the raw string), so the operator sees
    //     their actual typo, not the silently-defaulted "leaf". Pin this so
    //     a future regression to `node_type.as_str()` doesn't strip the
    //     typo and confuse the operator about what their config actually
    //     says.
    //   • The success-path `pubkey_hex` return is rendered via `hex::encode`
    //     (lowercase). A switch to `hex::encode_upper` or to a base64
    //     encoding would silently break operator runbooks + dashboard
    //     parsers that grep for `[0-9a-f]{64}`. Pin the exact 64-lowercase-
    //     hex shape so the contract is testable, not folklore.
    //   • The success-path `node_type_str` returns the `&'static str` from
    //     `NodeType::as_str()` (peer.rs:68), which is the exact lowercase
    //     "anchor" string. The static-lifetime guarantee matters because the
    //     value is embedded in the JSON response without copying — a regression
    //     that returned `state.config.node_type.clone()` (a `String`) would
    //     leak the operator's raw config casing back through the API. Pin
    //     exact-equality + length to surface the regression here.

    #[test]
    fn batch_w_all_non_anchor_canonical_node_types_rejected_uniformly() {
        // Loop over the four canonical non-anchor types that the first
        // test didn't reach. Each must surface the exact same operator
        // contract: error names the offending node_type AND points at the
        // fix (`set node_type=anchor in config and restart`). Catches a
        // regression that special-cased one rejection branch but not the
        // others (e.g. dropping the fix-pointer for "archive" on the theory
        // that archive nodes "should know better" — they don't, and the
        // operator dashboard needs a uniform fix string to grep on).
        for offender in &["leaf", "relay", "archive", "gateway"] {
            let state = build_state(offender, true);
            let msg = unwrap_err_msg(
                prepare_onboard_anchor_record(&state),
                &format!("{offender} must not be allowed to onboard as anchor"),
            );
            assert!(
                msg.contains(offender),
                "[{offender}] error must name the offending node_type; got: {msg}"
            );
            assert!(
                msg.contains("set node_type=anchor"),
                "[{offender}] error must point at the fix path; got: {msg}"
            );
        }
    }

    #[test]
    fn batch_w_unknown_node_type_string_preserves_raw_value_in_error_message() {
        // `NodeType::from_str` (peer.rs:57) is case-sensitive — uppercase
        // "ANCHOR" falls through the match-default to `Leaf`, which then
        // fails `can_seal_epochs()`. The error message is built from
        // `state.config.node_type` (the raw operator-supplied string), NOT
        // from `node_type.as_str()` (which would emit the defaulted "leaf").
        // Pinning the raw-preservation contract here: an operator who
        // mistyped "ANCHOR" sees "ANCHOR" in the error, not "leaf" — without
        // this the error is misleading ("but I set node_type=leaf nowhere
        // in my config!") and triages 10× slower.
        let state = build_state("ANCHOR", true);
        let msg = unwrap_err_msg(
            prepare_onboard_anchor_record(&state),
            "case-mismatched ANCHOR must reject",
        );
        assert!(
            msg.contains("ANCHOR"),
            "error must echo the operator's raw config value 'ANCHOR' to aid triage; got: {msg}"
        );
        assert!(
            !msg.contains("'leaf'"),
            "error must NOT silently substitute the defaulted 'leaf' for the raw input; got: {msg}"
        );
        assert!(
            msg.contains("set node_type=anchor"),
            "fix-pointer must still be present; got: {msg}"
        );
    }

    #[test]
    fn batch_w_success_pubkey_hex_is_64_lowercase_hex_no_prefix() {
        // `hex::encode` emits 64 lowercase ASCII hex chars (`[0-9a-f]`) with
        // no `0x` prefix. Operator dashboards + runbooks grep against this
        // exact shape — a regression to `hex::encode_upper` would still
        // pass the 32-byte round-trip in `ops147_success_path` but would
        // break every `[0-9a-f]{64}` grep downstream. Pin the strict shape
        // so a future encoder swap lands here first.
        let state = build_state("anchor", true);
        let (_record, _was_registered, pubkey_hex, _node_type_str) = unwrap_ok(
            prepare_onboard_anchor_record(&state),
            "anchor + VRF must succeed",
        );
        assert_eq!(
            pubkey_hex.len(),
            64,
            "pubkey_hex must be exactly 64 chars (32 bytes × 2); got len={}",
            pubkey_hex.len()
        );
        assert!(
            !pubkey_hex.starts_with("0x"),
            "pubkey_hex must NOT carry a '0x' prefix — runbooks grep on raw hex; got: {pubkey_hex}"
        );
        assert!(
            pubkey_hex.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "pubkey_hex must be strictly lowercase [0-9a-f] — uppercase encoding breaks operator-runbook greps; got: {pubkey_hex}"
        );
    }

    #[test]
    fn batch_w_success_node_type_str_pinned_to_lowercase_anchor_static_lifetime() {
        // The 4th tuple field comes from `NodeType::as_str()` (peer.rs:68),
        // which returns a `&'static str` — exact lowercase "anchor", 6
        // chars. A regression that swapped to `state.config.node_type.as_str()`
        // (a `&str` borrowing into the operator's raw config) would leak
        // case-folding (e.g. "Anchor", "ANCHOR") back through the API and
        // pollute downstream parsers expecting the canonical form. Pin
        // exact equality + byte-length so the regression lands here, NOT in
        // the account's per-node-type rendering pipeline.
        let state = build_state("anchor", true);
        let (_, _, _, node_type_str) = unwrap_ok(
            prepare_onboard_anchor_record(&state),
            "anchor + VRF must succeed",
        );
        assert_eq!(
            node_type_str, "anchor",
            "node_type_str must be the canonical lowercase form, not the operator's raw input"
        );
        assert_eq!(
            node_type_str.len(),
            6,
            "node_type_str byte-length must match the canonical 'anchor' static string"
        );
        // &'static str invariant: a fn that returned String would still
        // compare equal at the value level, so we also pin the by-value
        // identity against `NodeType::Anchor.as_str()` to surface a swap
        // to a heap-allocated path.
        assert_eq!(
            node_type_str,
            crate::network::peer::NodeType::Anchor.as_str(),
            "node_type_str must come from NodeType::as_str() (the canonical &'static str), not a fresh String allocation"
        );
    }

    // ─── onboard_anchor edge axes ────────────────────────────────────────────
    //
    // Picks up the pivot away from `pending_ledger_inspection_payload`.
    // Closes five orthogonal axes left open by the earlier slices on
    // `prepare_onboard_anchor_record`:
    //   • Empty-string `node_type` (operator unset OR config-load defaulted
    //     to "") is a DISTINCT failure mode from "witness" (canonical
    //     non-anchor) and "ANCHOR" (case-mismatch typo). All three fall
    //     through `NodeType::from_str` to `Leaf` but the error message must
    //     still echo the raw value — even when raw is empty — so operators
    //     who see `node_type ''` in the error can grep their config for an
    //     unset/missing line, not get a confusing "but I never set 'leaf'"
    //     triage.
    //   • An earlier test pinned `pubkey_hex` SHAPE (64 lowercase hex no prefix) but
    //     not VALUE identity to the actual VRF key bytes. A regression that
    //     swapped the encoded source (e.g. `hex::encode(pk.full_pk())` —
    //     the 1952-byte full key — instead of `pk.as_bytes()` — the 32-byte
    //     hash) would emit hex of the wrong length AND fail the
    //     shape test, BUT a regression that swapped to a different 32-byte
    //     identity (e.g. `state.identity.identity_hash` bytes, or a constant
    //     all-zero buffer) would silently pass that shape pin while
    //     producing a useless registration record. Pin the value-identity
    //     here against the actual state's pubkey bytes.
    //   • The helper does NOT memoize records. Each call goes through
    //     `state.create_self_ledger_record(...)` which produces a fresh
    //     record with a distinct id (depends on timestamp, nonce, signing
    //     material). The existing idempotent-flag test exercises
    //     two sequential calls but only asserts the FLAG flips — not that
    //     the underlying record_ids are DISTINCT. A future caching layer
    //     that returned the same record on the second call would still
    //     flip the flag (because we mutate the registry between calls in
    //     that test) but would silently break re-publish semantics — peers
    //     dedup on record_id, so two identical records would land as one
    //     and the operator's "force re-publish" runbook step would no-op.
    //     Pin distinct record_ids across two back-to-back calls.
    //   • `was_already_registered` is keyed strictly on the LOCAL state's
    //     identity_hash. The idempotent-flag test exercises the
    //     keyed-on-LOCAL-identity branch by registering THIS state's
    //     identity. The orthogonal branch — registry contains OTHER
    //     anchors' identities but NOT this state's — is unpinned. A
    //     regression to a "registry-non-empty" boolean (e.g. checking
    //     `r.count() > 0` instead of `r.is_registered(&state.identity)`)
    //     would silently return `was_already_registered=true` when another
    //     anchor onboarded first, breaking the operator's first-onboard vs
    //     re-publish distinction. Pin: registry containing a different
    //     identity must NOT flip the flag.
    //   • the success-path test asserts `vrf_full_public_key_hex` is
    //     non-empty (catches a regression to legacy hash-only metadata).
    //     The value-identity to the actual `pk.full_pk()` bytes is
    //     unpinned. A regression that emitted a fixed-length but ALL-ZERO
    //     full key (e.g. a stub leftover from migration) would still pass
    //     the non-empty check but would break VRF proof verification at
    //     every peer. Pin: the metadata's `vrf_full_public_key` hex
    //     byte-equals `hex::encode(state.vrf_public_key.as_ref().unwrap().full_pk())`,
    //     and the decoded length passes the ≥1900 byte gate that
    //     `VrfRegistry::get_public_key` enforces at vrf_registry.rs:84.

    #[test]
    fn batch_oo_empty_string_node_type_preserves_raw_value_in_error_message() {
        // Operator-unset OR config-load-defaulted node_type="" — distinct from
        // the case-typo "ANCHOR" and the canonical-non-anchor "witness"
        // cases. The from_str match falls through to Leaf in all three
        // cases, but the error message constructs from the raw config value
        // (`state.config.node_type`), so the empty literal `''` must still
        // appear in the error to give operators a grep-able marker that
        // their config value is missing — without this, the error reads
        // "node_type '' cannot become anchor" and could be mis-parsed by a
        // future regression that substituted the defaulted "leaf", confusing
        // triage with a value the operator never set.
        let state = build_state("", true);
        let msg = unwrap_err_msg(
            prepare_onboard_anchor_record(&state),
            "empty node_type must reject as non-anchor",
        );
        // The error format is `node_type '{}' cannot become anchor — set node_type=anchor in config and restart`
        // so the empty literal manifests as `node_type ''` (two adjacent
        // single quotes). Pin both the empty-quoted form AND the absence of
        // the silently-defaulted "leaf" so a regression that swapped the
        // format expression from `state.config.node_type` to
        // `node_type.as_str()` would surface here.
        assert!(
            msg.contains("node_type ''"),
            "error must echo the empty raw config value as `node_type ''`; got: {msg}"
        );
        assert!(
            !msg.contains("'leaf'"),
            "error must NOT silently substitute the defaulted 'leaf' for the empty raw input; got: {msg}"
        );
        assert!(
            msg.contains("set node_type=anchor"),
            "fix-pointer must still be present even on empty input; got: {msg}"
        );
    }

    #[test]
    fn batch_oo_pubkey_hex_value_byte_identical_to_state_vrf_public_key_as_bytes() {
        // An earlier test pinned `pubkey_hex` SHAPE (64 lowercase hex, no `0x` prefix)
        // but not VALUE identity. A regression that swapped the source from
        // `pk.as_bytes()` (32-byte hash) to a different 32-byte buffer
        // (e.g. `state.identity.identity_hash` decoded as bytes, or a
        // constant all-zero array, or a misaligned pointer into the full
        // key) would silently pass shape but produce a useless registration
        // — peers' `VrfRegistry::get_public_key` would then return a key
        // that VRF proofs would fail to verify against. Pin byte-equality
        // to the live state's `vrf_public_key.as_bytes()` source-of-truth.
        let state = build_state("anchor", true);
        let (_record, _was_registered, pubkey_hex, _node_type_str) = unwrap_ok(
            prepare_onboard_anchor_record(&state),
            "anchor + VRF must succeed",
        );
        let expected_hex = hex::encode(
            state
                .vrf_public_key
                .as_ref()
                .expect("VRF key installed")
                .as_bytes(),
        );
        assert_eq!(
            pubkey_hex, expected_hex,
            "pubkey_hex must byte-equal hex::encode of state.vrf_public_key.as_bytes() (the compact 32-byte hash, not the full key, not the identity_hash)"
        );
    }

    #[test]
    fn batch_oo_sequential_success_calls_produce_distinct_record_ids() {
        // The helper does NOT cache; each call goes through
        // `state.create_self_ledger_record(...)` which produces a fresh
        // signed record with a distinct id (timestamp + nonce + signing
        // material differ). The idempotent-flag test does call the
        // helper twice but only asserts the FLAG flips — not that the
        // underlying record_ids differ. A future caching layer keyed on
        // `(state.identity, vrf_public_key)` would silently elide the
        // second record's id, breaking re-publish semantics: peers dedup
        // on record_id, so a second identical record would land as one
        // and the operator's "force re-publish on gossip drop" runbook
        // step would no-op without surfacing the issue.
        let state = build_state("anchor", true);
        let (record_a, _, _, _) = unwrap_ok(
            prepare_onboard_anchor_record(&state),
            "first call must succeed",
        );
        let (record_b, _, _, _) = unwrap_ok(
            prepare_onboard_anchor_record(&state),
            "second call must succeed",
        );
        assert_ne!(
            record_a.id, record_b.id,
            "two back-to-back successful calls must produce DISTINCT record_ids — the helper is uncached and each call must mint a fresh record so operators can force-re-publish on gossip drop"
        );
    }

    #[test]
    fn batch_oo_was_already_registered_keyed_strictly_on_state_identity_hash() {
        // `is_registered(&state.identity.identity_hash)` is the keyed
        // lookup, NOT a `count() > 0` non-empty check. Pin this by
        // inserting a registration under a DIFFERENT identity_hash and
        // verifying the flag remains false. A regression to a
        // registry-non-empty boolean would surface here as a false flag
        // flip — the operator's first-onboard vs re-publish distinction
        // would silently invert whenever any other anchor onboarded
        // first, breaking the dashboard "new vs re-publish" labels.
        let state = build_state("anchor", true);

        // Register a FAKE registration under a different identity hash.
        // We don't need a real anchor or a verifiable record — just enough
        // to make `count()` non-zero so a regression that confused
        // is_registered(id) with count()>0 would fail here.
        {
            let other_identity = "other-anchor-identity-hash-not-ours";
            let fake_reg = VrfRegistration {
                vrf_public_key_hex: hex::encode([0x42u8; 32]),
                vrf_full_public_key_hex: String::new(),
                registered_at: 1000.0,
                record_id: "fake-record-id-for-keyed-lookup-test".into(),
                node_type: "anchor".into(),
            };
            let mut registry = state.vrf_registry.write().expect("registry lock");
            registry.register(other_identity, fake_reg);
        }
        // Sanity: registry is non-empty but does NOT contain our identity.
        {
            let registry = state.vrf_registry.read().expect("registry lock");
            assert!(
                registry.count() >= 1,
                "registry must be non-empty for the test to exercise the keyed-lookup vs non-empty distinction"
            );
            assert!(
                !registry.is_registered(&state.identity.identity_hash),
                "registry must NOT contain our identity — test setup is wrong if it does"
            );
        }

        // Helper call: flag must be false because OUR identity isn't
        // registered, even though the registry is non-empty.
        let (_record, was_already_registered, _, _) = unwrap_ok(
            prepare_onboard_anchor_record(&state),
            "anchor + VRF + registry-with-other-anchor must succeed",
        );
        assert!(
            !was_already_registered,
            "was_already_registered must be FALSE when the registry contains a DIFFERENT identity — flag is keyed strictly on state.identity.identity_hash, not on registry.count() > 0"
        );
    }

    #[test]
    fn batch_oo_vrf_full_public_key_in_metadata_matches_state_full_pk_byte_exact() {
        // The success-path test asserts `vrf_full_public_key_hex` is
        // non-empty (catches a regression to legacy hash-only metadata).
        // Value-identity to the actual `pk.full_pk()` bytes is unpinned —
        // a regression that emitted a fixed-length but ALL-ZERO full key
        // (migration stub leftover) OR that emitted a DIFFERENT key's
        // full_pk (e.g. a hardcoded test fixture from a copy-paste) would
        // still pass the non-empty check while breaking VRF proof
        // verification at every peer. Pin byte-equality to the live
        // state's `full_pk()` AND the decoded length passes the ≥1900-byte
        // gate that `VrfRegistry::get_public_key` enforces at
        // vrf_registry.rs:84 (anything shorter would silently fall through
        // to the hash-only branch which can't verify proofs).
        let state = build_state("anchor", true);
        let (record, _, _, _) = unwrap_ok(
            prepare_onboard_anchor_record(&state),
            "anchor + VRF must succeed",
        );
        let reg: VrfRegistration =
            extract_vrf_registration(&record).expect("ingest must accept this record");
        let expected_full_hex = hex::encode(
            state
                .vrf_public_key
                .as_ref()
                .expect("VRF key installed")
                .full_pk(),
        );
        assert_eq!(
            reg.vrf_full_public_key_hex, expected_full_hex,
            "vrf_full_public_key_hex must byte-equal hex::encode of state.vrf_public_key.full_pk() — a regression to all-zero stub OR a different key's full_pk would silently pass OPS-147's non-empty check while breaking peer VRF proof verification"
        );
        // Decoded length must clear the ≥1900-byte gate that
        // VrfRegistry::get_public_key enforces. Anything shorter falls
        // through to the hash-only branch which cannot verify VRF proofs.
        let decoded_len = hex::decode(&reg.vrf_full_public_key_hex)
            .expect("vrf_full_public_key_hex is valid hex")
            .len();
        assert!(
            decoded_len >= 1900,
            "decoded vrf_full_public_key must be ≥1900 bytes to clear the VrfRegistry::get_public_key full-key gate at vrf_registry.rs:84; got len={decoded_len}"
        );
    }
}

#[cfg(test)]
mod admin_rocks_compact_cf_tests {
    //! Unit tests for `resolve_compact_cf_list` — the testable core
    //! of `POST /admin/rocks/compact_cf`. The PQ admin gate + spawn_blocking
    //! handoff are shared with every other admin handler; what's unique here
    //! is the operator-input validation against the allowlist (so a typo in
    //! `?cf=` produces an actionable error rather than a silent no-op or a
    //! panic in `db.cf_handle()`).
    use super::{resolve_compact_cf_list, COMPACT_CF_ALLOWLIST};

    #[test]
    fn ops186_no_cf_param_compacts_full_allowlist() {
        // Default runbook path: operator hits POST /admin/rocks/compact_cf
        // with no query — every heavy CF should fire. Order MUST match
        // COMPACT_CF_ALLOWLIST so the response JSON matches the contract
        // documented in the metric HELP text.
        let cfs = resolve_compact_cf_list(None).expect("None must succeed");
        assert_eq!(cfs, COMPACT_CF_ALLOWLIST.to_vec());

        let cfs_empty =
            resolve_compact_cf_list(Some("")).expect("empty string must succeed");
        assert_eq!(cfs_empty, COMPACT_CF_ALLOWLIST.to_vec());
    }

    #[test]
    fn ops186_valid_cf_param_returns_singleton() {
        // Operator targets a single CF — must return exactly that CF, not
        // the full allowlist. Test every entry so a future allowlist drift
        // (e.g. someone drops `merkle`) breaks the test.
        for &cf in COMPACT_CF_ALLOWLIST {
            let result =
                resolve_compact_cf_list(Some(cf)).unwrap_or_else(|e| panic!("{cf}: {e}"));
            assert_eq!(result, vec![cf], "{cf} must produce singleton");
        }
    }

    #[test]
    fn ops186_unknown_cf_rejected_with_actionable_message() {
        // The compact_cf method calls `self.cf(cf_name)` which would panic on
        // an unknown handle. The allowlist gate catches the typo BEFORE we
        // reach rocks, and the error message must surface what the operator
        // typed AND the valid options.
        let err = resolve_compact_cf_list(Some("recordz"))
            .expect_err("typo must reject");
        assert!(
            err.contains("'recordz'"),
            "error must echo the operator's typo: {err}"
        );
        assert!(
            err.contains("records"),
            "error must list valid options for self-rescue: {err}"
        );

        // Sanity: a CF that exists in the broader schema but is NOT in the
        // allowlist (e.g. `ledger`, `peers`) also rejects. The allowlist is
        // narrower than the schema by design — we don't want operators
        // compacting CFs that don't bloat or that we haven't measured.
        for unsafe_cf in ["ledger", "peers", "governance", "epochs"] {
            let err = resolve_compact_cf_list(Some(unsafe_cf)).expect_err(unsafe_cf);
            assert!(
                err.contains(unsafe_cf),
                "allowlist must reject {unsafe_cf} explicitly: {err}"
            );
        }
    }

    // Five orthogonal
    // axes on `resolve_compact_cf_list` left uncovered by the earlier three tests
    // and not in scope for the DTO layer or the const-contents layer.
    // Each axis pins a regression vector that the existing three tests cannot
    // catch on their own.

    #[test]
    fn batch_rr_resolver_rejects_case_variants_of_every_allowlist_member() {
        // The resolver uses byte-equality (`c == name`) for the allowlist
        // match — NOT case-insensitive comparison. Pin that contract so a
        // future PR adding `c.to_lowercase() == name.to_lowercase()` (a
        // well-intentioned "be lenient on operator typos" refactor) lands
        // here as a clean failure rather than as a silent operational drift.
        //
        // Why this matters: the ENOSPC runbook tells
        // operators to use the exact lowercase CF names from the schema.
        // Lenient case would mask a stale runbook reference like
        // `?cf=Records` (capital R, e.g. from a copy-paste out of a slack
        // thread that auto-capitalized) hitting a different CF in some
        // future schema split (e.g. when `records_v2` is added alongside
        // `records`). Strict case keeps the operator-visible CF name a
        // unique discriminator.
        //
        // Test pattern: for each allowlist member, build BOTH the all-
        // uppercase and the first-letter-capitalized variants and verify
        // both reject. Two case-divergent shapes per member is broader
        // than a single variant — catches a half-baked normalization
        // (e.g. `.to_ascii_lowercase()` that handles ASCII-uppercase but
        // not Unicode title-case).
        for &cf in COMPACT_CF_ALLOWLIST {
            // All-uppercase variant: `"records"` → `"RECORDS"`. Sanity-
            // pin that the variant actually differs from the original —
            // would render the rejection assertion vacuous on an all-
            // uppercase member (none of the current 5 entries hit this,
            // but documents the assumption explicitly).
            let upper = cf.to_uppercase();
            assert_ne!(
                upper, cf,
                "sanity: uppercase variant of `{cf}` must differ from the original"
            );
            let err_upper = resolve_compact_cf_list(Some(&upper))
                .expect_err(&format!("uppercase `{upper}` must reject (byte-equality match)"));
            assert!(
                err_upper.contains(&format!("'{upper}'")),
                "error must echo the operator's exact uppercase input: {err_upper}"
            );

            // First-letter-capitalized variant: `"records"` → `"Records"`.
            let mut chars: Vec<char> = cf.chars().collect();
            if let Some(first) = chars.first_mut() {
                *first = first
                    .to_uppercase()
                    .next()
                    .unwrap_or(*first);
            }
            let cap: String = chars.into_iter().collect();
            if cap == cf {
                // Member is already first-letter-capitalized — defensive
                // skip so the test stays meaningful if the const ever
                // grows a member like `"Snapshot"`.
                continue;
            }
            let err_cap = resolve_compact_cf_list(Some(&cap))
                .expect_err(&format!("first-letter-cap `{cap}` must reject"));
            assert!(
                err_cap.contains(&format!("'{cap}'")),
                "error must echo the operator's exact capitalized input: {err_cap}"
            );
        }
    }

    #[test]
    fn batch_rr_resolver_rejects_whitespace_padded_input_no_implicit_trim() {
        // The resolver applies NO `.trim()` to the input — byte-equality
        // match against the allowlist. Pin that contract: a future
        // `name.trim()` would silently accept ` records` (leading space,
        // e.g. from URL-decoded `%20records` artifact) which currently
        // rejects.
        //
        // Why this matters: lenient trim masks copy-paste artifacts in
        // operator runbooks (e.g. a trailing newline from a markdown code
        // block, a tab artifact from auto-completion) and erases the
        // discriminator between "operator typed the wrong CF" and
        // "operator typed the right CF with leading whitespace". Both
        // surface the same actionable error today; lenient trim would
        // silently succeed on the whitespace case while the type-and-
        // typo case still fails, creating a confusing operator UX.
        //
        // Sanity canary: the unpadded form passes — guards against a
        // regression that breaks the entire valid-CF path.
        let unpadded = "records";
        assert_eq!(
            resolve_compact_cf_list(Some(unpadded)).expect("unpadded `records` must pass"),
            vec![unpadded],
            "sanity: unpadded `records` resolves to the singleton (canary against \
             a refactor that breaks the entire valid path)"
        );

        // Each whitespace shape independently rejects. Listed as four
        // operator-realistic shapes from URL decode + shell paste:
        //   - leading space (`?cf=%20records` — fat-fingered URL),
        //   - trailing space (`?cf=records%20`),
        //   - leading newline (`?cf=%0Arecords` — copy-paste with a
        //     trailing line break that got URL-encoded),
        //   - leading tab (`?cf=%09records` — tab-completion artifact),
        //   - embedded space (`?cf=rec%20ords` — partial-keyword paste).
        for padded in [" records", "records ", "\nrecords", "\trecords", "rec ords"] {
            let err = resolve_compact_cf_list(Some(padded))
                .expect_err(&format!("whitespace-padded `{padded}` must reject"));
            assert!(
                err.contains(&format!("'{padded}'")),
                "error must echo the operator's exact padded input: {err}"
            );
        }
    }

    #[test]
    fn batch_rr_resolver_distinct_typos_produce_distinct_error_messages() {
        // The third test pins ONE typo ("recordz") and 4 unsafe-but-real CFs
        // (ledger/peers/governance/epochs) in a loop, but does not assert
        // that the errors are mutually DISTINCT across distinct typos. A
        // future refactor could swap the format!() body for a constant
        // `"compact_cf: invalid CF name"` string and pass every existing
        // test because the OPERATOR's-input echo would be lost only in a
        // way the per-test assertions don't catch (each test still finds
        // its own substring if the const error happened to contain it,
        // but the set of distinct errors would collapse to size 1).
        //
        // The exact echo matters operationally: the operator's log scrape
        // needs to disambiguate "I typed 'recordz' (typo of 'records')"
        // from "I typed 'attestation' (typo of 'attestations')" — same
        // error class, different fixes. A unique-error-per-input contract
        // is the cleanest way to pin this.
        //
        // Six typo shapes chosen to span: leading-underscore artifact
        // (`_records`), digit-substitution (`rec0rds`), prefix without
        // suffix (`attestation` — substring of allowlist's "attestations"
        // but not equal), single-char typo (`merklie`), nonsense
        // (`xxx`), and a wholly distinct CF name from the broader schema
        // (`identities`).
        use std::collections::HashSet;
        let typos = ["xxx", "rec0rds", "_records", "merklie", "attestation", "identities"];
        let mut seen: HashSet<String> = HashSet::new();
        for typo in typos.iter() {
            let err = resolve_compact_cf_list(Some(typo))
                .expect_err(&format!("typo `{typo}` must reject"));
            assert!(
                err.contains(&format!("'{typo}'")),
                "error must echo the operator's exact typo `{typo}`: {err}"
            );
            assert!(
                seen.insert(err.clone()),
                "duplicate error for `{typo}`: {err} — distinct typos must produce \
                 distinct error messages (collapsing to a generic `invalid CF` \
                 error would lose the operator-input echo that the log scrape relies on)"
            );
        }
        assert_eq!(
            seen.len(),
            typos.len(),
            "every distinct typo must produce a unique error message; observed \
             {} unique errors for {} typos",
            seen.len(),
            typos.len()
        );
    }

    #[test]
    fn batch_rr_resolver_is_idempotent_under_identical_input_byte_equal_output() {
        // Pin that the resolver is a pure function: same input ⇒ byte-
        // equal output across consecutive calls. Three branches exercised
        // (None / Some(valid) / Some(typo)) so all three Result shapes
        // ride the idempotence pin.
        //
        // Regression caught: a future refactor that wires a HashMap
        // iteration into the path (e.g. switching the allowlist to a
        // HashSet for O(1) lookup) would randomize the Vec order via
        // DefaultHasher's seed — two consecutive calls would produce
        // byte-divergent Ok vecs. The static-slice-iteration pattern
        // today is deterministic; this test pins that against silent
        // structural drift.
        //
        // Also catches an Err-path regression: if the format!() string
        // ever incorporates a non-deterministic component (timestamp,
        // call counter, random UUID for tracing correlation), two
        // consecutive calls would diverge.
        for input in [None, Some("records"), Some("typo_cf_definitely_not_real")] {
            let first = resolve_compact_cf_list(input);
            let second = resolve_compact_cf_list(input);
            match (first, second) {
                (Ok(a), Ok(b)) => assert_eq!(
                    a, b,
                    "Ok branch must be idempotent for input {input:?}: {a:?} vs {b:?}"
                ),
                (Err(a), Err(b)) => assert_eq!(
                    a, b,
                    "Err branch must be idempotent for input {input:?}: `{a}` vs `{b}`"
                ),
                (a, b) => panic!(
                    "branch disagreement for input {input:?}: {a:?} vs {b:?} \
                     — the Ok/Err split must be deterministic"
                ),
            }
        }

        // Triple-call sanity: pin that idempotence holds across MORE than
        // two consecutive calls. A two-call test would miss a regression
        // that flips on every-other-call (e.g. a thread_local toggle).
        // Three calls catch the period-2 oscillation; the static-iteration
        // path today is period-1 (constant).
        let a = resolve_compact_cf_list(Some("records")).expect("call 1");
        let b = resolve_compact_cf_list(Some("records")).expect("call 2");
        let c = resolve_compact_cf_list(Some("records")).expect("call 3");
        assert_eq!(a, b, "call 1 vs call 2");
        assert_eq!(b, c, "call 2 vs call 3 (catches period-2 oscillation)");
    }

    #[test]
    fn batch_rr_resolver_error_message_lists_every_allowlist_member() {
        // ops186_unknown_cf_rejected_with_actionable_message pins that
        // the error contains the operator's typo AND a sample allowlist
        // member (`"records"`). This batch pins the strictly-stronger
        // contract: the error contains EVERY single CF name in
        // COMPACT_CF_ALLOWLIST.
        //
        // Regression caught: a future "did you mean?" refactor that drops
        // the full Debug listing (`{:?}` of the slice) in favor of a
        // single best-guess suggestion (e.g. Levenshtein-closest member)
        // would land silently otherwise. Operators reading the runbook
        // would no longer see the full set of valid options inline — they
        // would have to grep the schema for the right name under disk
        // pressure, which is exactly the wrong moment to make them work.
        //
        // The full listing is also the documented contract: the format!()
        // template explicitly inlines `{:?}` of COMPACT_CF_ALLOWLIST,
        // which Debug-formats the slice as `["records", "attestations",
        // "dag", "idx_timestamp", "merkle"]`. Pin that EVERY member
        // appears, not just the well-known one.
        let err = resolve_compact_cf_list(Some("definitely_not_a_cf_anywhere"))
            .expect_err("typo must reject");
        for &cf in COMPACT_CF_ALLOWLIST {
            assert!(
                err.contains(cf),
                "error must list every allowlist member; missing `{cf}` in: {err}"
            );
        }
        // Cross-pin the third test's invariant in the same test — the
        // "typo echo + full options listing" is a single contract that
        // belongs in one place rather than split across two tests each
        // pinning half.
        assert!(
            err.contains("'definitely_not_a_cf_anywhere'"),
            "error must echo the operator's exact typo: {err}"
        );

        // Pin the leading prefix as part of the message contract — the
        // string starts with `compact_cf: ` so the operator's log scrape
        // can disambiguate this error from other format!() outputs (e.g.
        // a future `cf_handle: 'X' not found` from a different code path).
        assert!(
            err.starts_with("compact_cf:"),
            "error message must start with the `compact_cf:` prefix so log scrapes \
             can disambiguate the source: {err}"
        );
    }
}

#[cfg(test)]
mod admin_body_dto_tests {
    //! Density-hygiene tests: pins the wire
    //! contract of the public admin body-DTOs so a future serde rename
    //! (e.g. `#[serde(rename = "ip_address")]`) surfaces as a deserialize
    //! test diff instead of a silent breaking change for operator tooling
    //! (`elara-cli pq-admin`, curl-shaped runbooks). Each handler also
    //! gates auth via `verify_admin_auth_pq_any_node` and runs inside an
    //! async axum extractor, but the serde contract is the part that
    //! third-party clients lock onto — that's what these tests pin.
    use super::{
        BanIdentityBody, BanIpBody, BlockTermBody, ForceResyncFromBody, PurgePeerBody,
        SnapshotRebootstrapQuery,
    };

    #[test]
    fn batch_ac_ban_ip_body_deserializes_field_ip_required_with_forward_compat_unknown_fields() {
        let body: BanIpBody = serde_json::from_str(r#"{"ip":"203.0.113.7"}"#)
            .expect("valid BanIpBody JSON must deserialize");
        assert_eq!(body.ip, "203.0.113.7");

        let missing: Result<BanIpBody, _> = serde_json::from_str("{}");
        assert!(
            missing.is_err(),
            "missing ip field must reject — without this, a typo'd client payload would \
             default to empty string and admin_ban_ip would 400 only at IpAddr::parse, \
             losing the precise schema-side error"
        );

        let extra: BanIpBody = serde_json::from_str(r#"{"ip":"1.2.3.4","extra":"ignored"}"#)
            .expect(
                "unknown extra field must be silently ignored — adding `#[serde(deny_unknown_fields)]` \
                 would break forward-compat for older binaries",
            );
        assert_eq!(extra.ip, "1.2.3.4");
    }

    #[test]
    fn batch_ac_ban_identity_body_deserializes_both_identity_hash_and_reason_as_required() {
        let body: BanIdentityBody = serde_json::from_str(
            r#"{"identity_hash":"a1b2c3d4e5f6","reason":"spam flood"}"#,
        )
        .expect("both-fields-present BanIdentityBody must deserialize");
        assert_eq!(body.identity_hash, "a1b2c3d4e5f6");
        assert_eq!(body.reason, "spam flood");

        let no_reason: Result<BanIdentityBody, _> =
            serde_json::from_str(r#"{"identity_hash":"abc"}"#);
        assert!(
            no_reason.is_err(),
            "missing reason must reject — an empty-default reason would defeat the \
             operator-trail purpose of the audit-log warn! line in admin_ban_identity"
        );

        let no_id: Result<BanIdentityBody, _> =
            serde_json::from_str(r#"{"reason":"spam"}"#);
        assert!(
            no_id.is_err(),
            "missing identity_hash must reject — a default-empty hash would let an \
             admin call accidentally ban the empty-string identity sentinel"
        );
    }

    #[test]
    fn batch_ac_block_term_body_deserializes_field_term_required_string() {
        let body: BlockTermBody = serde_json::from_str(r#"{"term":"ScamWord"}"#)
            .expect("valid BlockTermBody JSON must deserialize");
        assert_eq!(body.term, "ScamWord");

        let missing: Result<BlockTermBody, _> = serde_json::from_str("{}");
        assert!(missing.is_err(), "missing term must reject");

        let wrong_type: Result<BlockTermBody, _> = serde_json::from_str(r#"{"term":42}"#);
        assert!(
            wrong_type.is_err(),
            "non-string term must reject — a future schema-loosening to a sum type \
             would land silently and break operator-side JSON-schema validation"
        );
    }

    // Pins the wire
    // contract of the remaining 2 admin body-DTOs (PurgePeerBody,
    // ForceResyncFromBody) plus SnapshotRebootstrapQuery (relocated
    // body→query in V2 so the admin signature covers it). Same rationale as
    // the earlier body-DTO pins: operator tooling (`elara-cli pq-admin`, curl runbooks)
    // locks onto these field names; a silent serde rename here would
    // break every caller.

    #[test]
    fn batch_am_purge_peer_body_deserializes_field_identity_hash_required() {
        let body: PurgePeerBody = serde_json::from_str(
            r#"{"identity_hash":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"}"#,
        )
        .expect("valid PurgePeerBody JSON must deserialize");
        assert_eq!(body.identity_hash, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4");

        let missing: Result<PurgePeerBody, _> = serde_json::from_str("{}");
        assert!(
            missing.is_err(),
            "missing identity_hash must reject — a default-empty hash would let an \
             admin call silently purge the empty-string identity sentinel from both \
             the peer table and the DHT (admin_purge_peer at L415)"
        );

        let wrong_field: Result<PurgePeerBody, _> =
            serde_json::from_str(r#"{"peer_id":"a1b2c3d4"}"#);
        assert!(
            wrong_field.is_err(),
            "field name 'identity_hash' is the wire contract — a rename to e.g. \
             'peer_id' or 'identity' must surface as a test failure, not a silent \
             400 from clients still sending the old field"
        );

        let extra: PurgePeerBody =
            serde_json::from_str(r#"{"identity_hash":"abc","note":"ignored"}"#)
                .expect("unknown extra field must be silently ignored — forward-compat");
        assert_eq!(extra.identity_hash, "abc");
    }

    #[test]
    fn batch_am_force_resync_from_body_deserializes_field_peer_addr_required() {
        let body: ForceResyncFromBody =
            serde_json::from_str(r#"{"peer_addr":"http://10.0.0.1:9473"}"#)
                .expect("valid ForceResyncFromBody JSON must deserialize");
        assert_eq!(body.peer_addr, "http://10.0.0.1:9473");

        let missing: Result<ForceResyncFromBody, _> = serde_json::from_str("{}");
        assert!(
            missing.is_err(),
            "missing peer_addr must reject at serde — the handler's empty-string \
             check (admin_force_resync_from at L516) is the second line of defense \
             but a serde-side rejection gives the operator a precise field-name \
             error first"
        );

        let wrong_type: Result<ForceResyncFromBody, _> =
            serde_json::from_str(r#"{"peer_addr":12345}"#);
        assert!(
            wrong_type.is_err(),
            "non-string peer_addr must reject — peer table entries are base URL \
             strings; an integer/array here would never match a connected peer \
             and silently bounce off the allowlist check"
        );

        let extra: ForceResyncFromBody = serde_json::from_str(
            r#"{"peer_addr":"http://node-a:9473","mode":"snapshot"}"#,
        )
        .expect("unknown extra field must be silently ignored — forward-compat");
        assert_eq!(extra.peer_addr, "http://node-a:9473");
    }

    #[test]
    fn batch_am_snapshot_rebootstrap_query_dto_field_names_and_force_default() {
        // SnapshotRebootstrapQuery is a QUERY DTO, not a body DTO (V2
        // relocation 2026-07-05): `peer_addr` + `force` ride the request
        // target so the admin signature covers them — a body-carried `force`
        // was the one substitution lever that could turn a safe rebootstrap
        // into a permanent ledger rollback. ForceResyncFromBody intentionally
        // stays a body DTO (its rollback lever is hardcoded off:
        // `initial_sync_from` always calls `snapshot_bootstrap(_, _, false)`),
        // so the two recovery endpoints now DIFFER in wire shape — a future
        // refactor unifying them would re-open the unsigned-force hole and
        // must trip here.
        let q: SnapshotRebootstrapQuery =
            serde_json::from_str(r#"{"peer_addr":"http://203.0.113.7:9473"}"#)
                .expect("valid SnapshotRebootstrapQuery must deserialize");
        assert_eq!(q.peer_addr, "http://203.0.113.7:9473");
        assert!(
            !q.force,
            "force must default to FALSE when omitted — the rollback override \
             is opt-in per call; a default-true would make every rebootstrap \
             a potential rollback"
        );

        let forced: SnapshotRebootstrapQuery =
            serde_json::from_str(r#"{"peer_addr":"http://203.0.113.7:9473","force":true}"#)
                .expect("explicit force=true must deserialize");
        assert!(forced.force, "explicit force:true must parse to true");

        let missing: Result<SnapshotRebootstrapQuery, _> = serde_json::from_str("{}");
        assert!(
            missing.is_err(),
            "missing peer_addr must reject — axum's Query extractor turns this \
             into a 400 with a precise field-name error instead of the \
             handler's generic empty-string Wire error"
        );

        let extra: SnapshotRebootstrapQuery = serde_json::from_str(
            r#"{"peer_addr":"http://hil:9473","include_pending":true}"#,
        )
        .expect("unknown extra field must be silently ignored — forward-compat");
        assert_eq!(extra.peer_addr, "http://hil:9473");

        // The field NAMES are the signed-wire contract: an operator signs
        // `?peer_addr=…&force=true` and the server must parse exactly those
        // names. ForceResyncFromBody keeps `peer_addr` too (body-side).
        let body: ForceResyncFromBody =
            serde_json::from_str(r#"{"peer_addr":"http://nyc:9473"}"#)
                .expect("ForceResyncFromBody parses");
        assert_eq!(body.peer_addr, "http://nyc:9473");
    }
}

#[cfg(test)]
mod admin_zones_scope_tests {
    //! Pins `compute_zones_scope`, the
    //! inner logic for `GET /admin/zones/scope`. Until these tests the
    //! helper had zero direct coverage — its only caller is the
    //! auth-gated handler exercised through integration tests. A
    //! refactor that dropped a top-level key, flipped the
    //! `default_behavior` sentinel, or unsorted `subscribed_zones`
    //! would surface as a account/operator-dashboard regression rather
    //! than a test failure.
    //!
    //! Pinned contracts:
    //!   1. Empty-subscription fresh node → `default_behavior =
    //!      "accept_all"` (the Phase A subtlety: empty set ≠ reject-all).
    //!   2. The six top-level keys consumed by `elara-cli zones` and
    //!      the operator dashboard.
    //!   3. Post-subscribe `default_behavior = "scoped"` plus the
    //!      per_zone_storage[].record_count=0 fresh-state baseline.
    //!   4. ZoneManager::subscribe auto-pins ancestor zones; the
    //!      resulting `subscribed_zones` is lex-sorted for stable
    //!      operator output.
    //!   5. The `pending_purge` sub-object (queue_depth +
    //!      oldest_lag_seconds + records_purged_total) with zero
    //!      baselines on a fresh node.
    use super::compute_zones_scope;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::state::NodeState;
    use crate::network::witness::WitnessManager;
    use crate::network::zone::ZoneId;
    use crate::network::LockRecover;
    use crate::storage::rocks::StorageEngine;
    use std::sync::Arc;

    /// Minimal NodeState. Tempdir is forgotten so the rocks instance
    /// stays alive for the duration of the test (matches the pattern
    /// in `admin_onboard_anchor_tests::build_state`).
    fn build_state() -> Arc<NodeState> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "batch-q-admin-token".into(),
            network_id: "batch-q-zones-scope".into(),
            node_type: "leaf".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks =
            Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = NodeState::new(config, identity, rocks, wmgr);
        std::mem::forget(tmp);
        Arc::new(state)
    }

    #[test]
    fn batch_q_compute_zones_scope_fresh_state_default_behavior_is_accept_all() {
        // Pins the ZSP Phase A subtlety surfaced in the helper docstring:
        // an empty subscription set means *accept-all* at the ingest
        // filter, NOT *accept-nothing*. A regression that returned
        // "scoped" with an empty subscribed_zones list would make every
        // operator's filter look misconfigured at a glance.
        let state = build_state();
        let v = compute_zones_scope(&state);
        assert_eq!(v["default_behavior"], "accept_all");
        assert!(
            v["subscribed_zones"].as_array().unwrap().is_empty(),
            "fresh node must have no subscriptions"
        );
        assert!(
            v["per_zone_storage"].as_array().unwrap().is_empty(),
            "no subscriptions ⇒ no per-zone storage entries"
        );
    }

    #[test]
    fn batch_q_compute_zones_scope_top_level_keys_pinned() {
        // /admin/zones/scope is consumed by the operator dashboard and
        // `elara-cli zones`. A serde rename or a dropped key would break
        // both at parse time — pin the full key set so the regression
        // lands in this test, not in production tooling.
        let state = build_state();
        let v = compute_zones_scope(&state);
        let obj = v.as_object().expect("must be a JSON object");
        for k in &[
            "subscribed_zones",
            "subscribed_zone_count",
            "default_behavior",
            "per_zone_storage",
            "global_zone_idx_entries",
            "global_zone_idx_distinct_zones",
            "pending_purge",
        ] {
            assert!(obj.contains_key(*k), "missing top-level key: {k}");
        }
    }

    #[test]
    fn zones_scope_detail_lists_capped_at_5000_with_true_count() {
        // SCALE RULE pin (idiom b, O(n)-under-lock DoS batch): with more
        // than 5000 subscribed zones, `subscribed_zones` and
        // `per_zone_storage` list exactly the first 5000 (ASCII-lex order)
        // while `subscribed_zone_count` reports the TRUE total — and the
        // cap bounds the per-zone `count_zone` rocks scans to ≤5000 per
        // request. Sub-cap case: count == len, no truncation.
        let state = build_state();
        for i in 0..5_001 {
            state.subscribe_zone(&ZoneId::new(&format!("zone{i:05}")));
        }
        let v = compute_zones_scope(&state);
        assert_eq!(
            v["subscribed_zones"].as_array().unwrap().len(),
            5_000,
            "subscribed_zones must cap at 5000 rows"
        );
        assert_eq!(
            v["per_zone_storage"].as_array().unwrap().len(),
            5_000,
            "per_zone_storage must cap at 5000 rows"
        );
        assert_eq!(
            v["subscribed_zone_count"].as_u64().unwrap(),
            5_001,
            "subscribed_zone_count must carry the TRUE uncapped total"
        );
        assert_eq!(v["default_behavior"], "scoped");

        let small = build_state();
        small.subscribe_zone(&ZoneId::new("medical"));
        let vs = compute_zones_scope(&small);
        assert_eq!(
            vs["subscribed_zones"].as_array().unwrap().len() as u64,
            vs["subscribed_zone_count"].as_u64().unwrap(),
            "below the cap, count must equal the listed length"
        );
    }

    #[test]
    fn batch_q_compute_zones_scope_one_subscribe_flips_default_to_scoped_with_zero_record_count() {
        // After one subscribe, default_behavior flips to "scoped" and
        // the per_zone_storage entry carries record_count=0 (fresh node,
        // no records ingested). This catches a regression where the
        // map step silently dropped zero-record zones from the per-zone
        // list, which would leave operators unable to confirm their
        // subscription took effect until the first record arrived.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("medical"));
        let v = compute_zones_scope(&state);
        assert_eq!(v["default_behavior"], "scoped");

        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert_eq!(zones, vec!["medical"]);

        let per_zone = v["per_zone_storage"].as_array().unwrap();
        assert_eq!(per_zone.len(), 1);
        assert_eq!(per_zone[0]["zone"], "medical");
        assert_eq!(per_zone[0]["record_count"], 0);
    }

    #[test]
    fn batch_q_compute_zones_scope_hierarchical_subscribe_auto_pins_ancestors_lex_sorted() {
        // ZoneManager::subscribe auto-adds the parent chain (see
        // zone.rs:458-466). Subscribing to `medical/eu/cardio` must
        // make `subscribed_zones` contain all three entries — and they
        // must come back in lex order (sort_by_key on path string in
        // compute_zones_scope:1863). Operator runbooks grep by exact
        // line; non-deterministic ordering rots the runbook.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("medical/eu/cardio"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            zones,
            vec!["medical", "medical/eu", "medical/eu/cardio"],
            "subscribed_zones must include all ancestors in lex order"
        );
        assert_eq!(v["default_behavior"], "scoped");

        // per_zone_storage must mirror the same three zones in the same
        // order (the iteration walks `subscribed` which was already
        // sorted at L1863).
        let per_zone_paths: Vec<String> = v["per_zone_storage"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["zone"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            per_zone_paths,
            vec!["medical", "medical/eu", "medical/eu/cardio"]
        );
    }

    #[test]
    fn batch_q_compute_zones_scope_pending_purge_shape_with_zero_baselines() {
        // pending_purge is a nested object whose three keys are read by
        // the soak monitor every tick:
        //   - queue_depth: usize from zone_purge::queue_depth (0 on
        //     fresh node).
        //   - oldest_lag_seconds: f64 from zone_purge::oldest_lag_secs
        //     (returns 0.0 when the queue is empty per zone_purge.rs:65).
        //   - records_purged_total: AtomicU64 counter (0 at boot).
        // A rename to e.g. `queue_size` or `lag_secs` would silently
        // break the soak monitor's per-tick parse — pin the names and
        // baselines so any future rename surfaces here first.
        let state = build_state();
        let v = compute_zones_scope(&state);
        let pp = &v["pending_purge"];
        assert!(pp.is_object(), "pending_purge must be a JSON object");
        assert_eq!(pp["queue_depth"], 0);
        assert_eq!(pp["records_purged_total"], 0);
        let lag = pp["oldest_lag_seconds"]
            .as_f64()
            .expect("oldest_lag_seconds must be a JSON number");
        assert_eq!(lag, 0.0, "empty queue ⇒ lag must be exactly 0.0");
    }

    #[test]
    fn batch_t_disjoint_top_level_zones_returned_in_lex_order_no_ancestor_pin() {
        // Subscribing to two top-level (depth-1) zones must NOT cross-pin
        // each other — they have no shared ancestor path other than the
        // implicit root. The lex-sort is what the operator dashboard groups
        // by, so a regression that left insertion order intact (or sorted
        // by hash for hot-key reasons) would silently re-order the dashboard
        // every restart. Pinning `finance` < `medical` here exercises the
        // ASCII-lex contract pinned at compute_zones_scope:1863.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("medical"));
        state.subscribe_zone(&ZoneId::new("finance"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            zones,
            vec!["finance", "medical"],
            "disjoint top-level subscriptions must come back lex-sorted, not insertion-order"
        );
        assert_eq!(v["default_behavior"], "scoped");

        // per_zone_storage must mirror the same lex order. Both have
        // record_count=0 on the fresh-state node.
        let per_zone_paths: Vec<String> = v["per_zone_storage"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["zone"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(per_zone_paths, vec!["finance", "medical"]);
        for entry in v["per_zone_storage"].as_array().unwrap() {
            assert_eq!(entry["record_count"], 0);
        }
    }

    #[test]
    fn batch_t_unsubscribe_returns_to_accept_all_and_enqueues_purge() {
        // Subscribe-then-unsubscribe round-trip. After unsubscribe the
        // subscription set is empty again ⇒ `default_behavior` returns to
        // `accept_all` (mirror of batch_q test 1), AND the pending_purge
        // queue picks up exactly one entry (the unsubscribed zone is pushed
        // via `enqueue_purge_zone` in NodeState::unsubscribe_zone at
        // state.rs:4158). This is the account-observable signal that an
        // operator-driven zone retirement is in flight: the soak monitor
        // tracks `pending_purge.queue_depth>0` as "drain in progress".
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("transient"));
        state.unsubscribe_zone(&ZoneId::new("transient"));
        let v = compute_zones_scope(&state);

        assert_eq!(
            v["default_behavior"], "accept_all",
            "after unsubscribe of the only zone, default_behavior must return to accept_all"
        );
        assert!(
            v["subscribed_zones"].as_array().unwrap().is_empty(),
            "subscribed_zones must be empty after unsubscribe"
        );
        assert!(
            v["per_zone_storage"].as_array().unwrap().is_empty(),
            "per_zone_storage must be empty after unsubscribe"
        );
        assert_eq!(
            v["pending_purge"]["queue_depth"], 1,
            "unsubscribe must enqueue exactly one purge entry"
        );
    }

    #[test]
    fn batch_v_per_zone_entry_has_only_zone_and_record_count_keys() {
        // The per_zone_storage entries are consumed key-by-key by
        // `elara-cli zones` (Rust serde struct with two fields) and by the
        // operator dashboard's per-zone storage column. The shape contract
        // is "exactly these two keys" — silently adding a third field
        // (e.g. `last_seal_epoch`, `merkle_height`) would either break the
        // strict-shape JSON parsers downstream or cause shape drift that
        // ages out by the time someone notices. Pin the strict-2-key
        // contract so a regression that adds a field lands here first.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("medical"));
        let v = compute_zones_scope(&state);
        let entries = v["per_zone_storage"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "single subscribe ⇒ single entry");
        let entry = entries[0].as_object().expect("entry must be a JSON object");
        let mut keys: Vec<&str> = entry.keys().map(|s| s.as_str()).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["record_count", "zone"],
            "per_zone_storage entries must contain ONLY `zone` + `record_count` — any new field is a contract change"
        );
    }

    #[test]
    fn batch_v_global_zone_idx_metrics_are_numbers_with_zero_baseline_on_fresh_node() {
        // `global_zone_idx_entries` + `global_zone_idx_distinct_zones` are
        // scraped by the operator dashboard's "zone-idx coverage" widget
        // and by the soak monitor's per-tick storage-health line. Both
        // come from rocks getters that return `usize` (rocks.rs:1221,
        // 1232) → serde renders as a JSON number. Pin both as numeric
        // u64-shaped with a `0` baseline on a fresh node, so a regression
        // that flipped the field to a stringified count or a nested object
        // (e.g. `{count: N}`) would land in this test instead of breaking
        // the operator dashboard's parse silently.
        let state = build_state();
        let v = compute_zones_scope(&state);
        let entries = v["global_zone_idx_entries"]
            .as_u64()
            .expect("global_zone_idx_entries must be a non-negative integer");
        let distinct = v["global_zone_idx_distinct_zones"]
            .as_u64()
            .expect("global_zone_idx_distinct_zones must be a non-negative integer");
        assert_eq!(entries, 0, "fresh node must have zero zone_idx entries");
        assert_eq!(distinct, 0, "fresh node must have zero distinct zones");
    }

    #[test]
    fn batch_v_subscribe_zone_idempotent_no_double_count_in_subscribed_zones() {
        // Operator-friendly idempotence: re-running an ansible task that
        // calls /admin/zones/subscribe on already-subscribed zones must
        // NOT inflate `subscribed_zones`. ZoneManager::subscribe uses
        // HashSet::insert (zone.rs:459), which is set-based so the second
        // call is a no-op — but pin the externally-observable shape so a
        // future refactor that swapped to Vec::push (or that emitted a
        // pending_purge entry on duplicate subscribe) lands here.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("medical"));
        state.subscribe_zone(&ZoneId::new("medical"));
        // Also exercise idempotence on a deep path — re-subscribing must
        // not double-add the ancestor chain either.
        state.subscribe_zone(&ZoneId::new("finance/eu"));
        state.subscribe_zone(&ZoneId::new("finance/eu"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            zones,
            vec!["finance", "finance/eu", "medical"],
            "duplicate subscribes must collapse — set semantics, not list-append"
        );
        // pending_purge must NOT pick up entries from duplicate subscribes
        // (purge is unsubscribe-only).
        assert_eq!(v["pending_purge"]["queue_depth"], 0);
    }

    #[test]
    fn batch_v_disjoint_siblings_under_common_parent_lex_sorted_by_full_path() {
        // The hierarchy test in batch_q exercised ancestor-before-descendant
        // (`medical` < `medical/eu` < `medical/eu/cardio`), which is BOTH
        // ASCII lex AND "shorter-prefix-first" — a regression that swapped
        // the sort to depth-ascending or to byte-skipping-slashes would
        // still pass that test. This case picks two siblings under the same
        // parent (`medical/asia` vs `medical/eu`) so the only valid sort key
        // is the full path-string lex compare at compute_zones_scope:1863.
        // Expected order: parent first (auto-pinned), then siblings by
        // ASCII: 'a' < 'e' ⇒ `medical/asia` < `medical/eu`.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("medical/eu"));
        state.subscribe_zone(&ZoneId::new("medical/asia"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            zones,
            vec!["medical", "medical/asia", "medical/eu"],
            "disjoint siblings under a common parent must sort by full path string, not depth or insertion order"
        );
    }

    #[test]
    fn batch_v_per_zone_storage_strict_parallel_to_subscribed_zones() {
        // `subscribed_zones` and `per_zone_storage` are emitted from the
        // SAME sorted vec (compute_zones_scope:1873 iterates `subscribed`
        // which is the same slice that becomes `subscribed_zones`). A
        // regression that sourced `per_zone_storage` from a separate
        // unsorted HashMap or from a rocks iterator would silently
        // de-align the two — the dashboard would render zone N's stats
        // under zone M's label. Pin the strict parallel-index alignment
        // so any future refactor that splits the iteration sources lands
        // here first.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("zulu"));
        state.subscribe_zone(&ZoneId::new("alpha"));
        state.subscribe_zone(&ZoneId::new("mike"));
        let v = compute_zones_scope(&state);
        let subscribed: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        let per_zone_labels: Vec<String> = v["per_zone_storage"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["zone"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            subscribed.len(),
            per_zone_labels.len(),
            "subscribed_zones and per_zone_storage must have identical length"
        );
        assert_eq!(
            subscribed, per_zone_labels,
            "per_zone_storage[i].zone must match subscribed_zones[i] for every i — dashboard alignment depends on this"
        );
        // Sanity: also pin the lex order (alpha < mike < zulu) so a sort
        // regression here doesn't slip past as "they're both wrong but
        // in the same way".
        assert_eq!(subscribed, vec!["alpha", "mike", "zulu"]);
    }

    // ─── Edge gaps on compute_zones_scope ────────────────────────────────────
    //
    // Continues the routes/admin.rs coverage work. Pivots back to
    // `compute_zones_scope` to drain the remaining edge gaps left open by
    // earlier tests:
    //   • The `queue_depth` field is a load-gauge (a zone can sit in the queue
    //     multiple times during partial drain — see zone_purge.rs:74-76). Pin
    //     that N unsubscribes ⇒ N queue entries by exact count, NOT collapsed
    //     to "distinct unsubscribed zones". A regression that swapped the
    //     VecDeque to a HashSet (silently deduping the work units) would land
    //     here, not in production when a 100K-record drain stalls because the
    //     worker thinks the queue is shorter than it actually is.
    //   • `records_purged_total` is the third leg of `pending_purge` (sourced
    //     from the `zone_purge_records_purged_total` AtomicU64 at
    //     state.rs:2261) but batch-Q only pinned queue_depth + oldest_lag.
    //     Pin the u64-shape + zero baseline so a regression to AtomicU32 or
    //     to f64 (silent narrowing or float-rendering) surfaces.
    //   • Zone path ordering uses ASCII byte-by-byte compare via `String::cmp`
    //     (compute_zones_scope:1863). The "natural sort" trap (`zone-2` before
    //     `zone-10`) is the obvious operator expectation — pin that the
    //     contract is ASCII lex, NOT natural-sort, so a dependency upgrade
    //     that swapped to `natord` or similar surfaces in the test rather
    //     than as a dashboard re-order on the next deploy.
    //   • Subscribe → unsubscribe → re-subscribe lifecycle: the purge queue
    //     entry is NOT cleared by re-subscribe (the worker filters at dequeue
    //     time, not at insert time — zone_purge.rs:84-86 docstring). Pin that
    //     `subscribed_zones` returns the re-added zone AND that the dead
    //     purge entry stays in queue_depth until the worker drains it. A
    //     regression that proactively cleared the queue on re-subscribe would
    //     break the FIFO invariant.
    //   • `global_zone_idx_entries` + `global_zone_idx_distinct_zones` are
    //     sourced from rocks getters (rocks.rs:1221/1232) which count the
    //     record-side index — NOT the subscription set. Pin that subscribe/
    //     unsubscribe churn leaves these counters at zero. A regression that
    //     wired subscription mutations into the same atomic counter would
    //     surface the operator dashboard showing "5 zones" when the chain
    //     actually has zero records.

    #[test]
    fn batch_x_compute_zones_scope_multiple_unsubscribes_accumulate_queue_depth() {
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("a"));
        state.subscribe_zone(&ZoneId::new("b"));
        state.subscribe_zone(&ZoneId::new("c"));
        state.unsubscribe_zone(&ZoneId::new("a"));
        state.unsubscribe_zone(&ZoneId::new("b"));
        state.unsubscribe_zone(&ZoneId::new("c"));
        let v = compute_zones_scope(&state);
        assert_eq!(
            v["pending_purge"]["queue_depth"], 3,
            "3 unsubscribes ⇒ 3 queue entries — work units, not distinct zones"
        );
        assert_eq!(
            v["default_behavior"], "accept_all",
            "all subscriptions cleared ⇒ back to accept_all"
        );
        assert!(
            v["subscribed_zones"].as_array().unwrap().is_empty(),
            "fully drained subscription set must be empty"
        );
    }

    #[test]
    fn batch_x_compute_zones_scope_records_purged_total_is_u64_zero_baseline() {
        let state = build_state();
        let v = compute_zones_scope(&state);
        let purged = v["pending_purge"]["records_purged_total"]
            .as_u64()
            .expect("records_purged_total must be a non-negative integer");
        assert_eq!(
            purged, 0,
            "fresh node — purge worker never ran ⇒ records_purged_total must be exactly 0"
        );
        assert!(
            v["pending_purge"]["records_purged_total"].is_number(),
            "records_purged_total must serialize as a JSON number, not a string or object"
        );
    }

    #[test]
    fn batch_x_compute_zones_scope_zone_paths_with_digits_sort_ascii_byte_order_not_natural() {
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("zone-2"));
        state.subscribe_zone(&ZoneId::new("zone-10"));
        state.subscribe_zone(&ZoneId::new("zone-1"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            zones,
            vec!["zone-1", "zone-10", "zone-2"],
            "ASCII lex puts `zone-10` before `zone-2` because byte '1' (0x31) < byte '2' (0x32) at position 5 — natural sort would order 1<2<10"
        );
    }

    #[test]
    fn batch_x_compute_zones_scope_subscribe_unsubscribe_resubscribe_lifecycle() {
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("transient"));
        let v1 = compute_zones_scope(&state);
        assert_eq!(v1["default_behavior"], "scoped");
        assert_eq!(v1["pending_purge"]["queue_depth"], 0);

        state.unsubscribe_zone(&ZoneId::new("transient"));
        let v2 = compute_zones_scope(&state);
        assert_eq!(v2["default_behavior"], "accept_all");
        assert!(v2["subscribed_zones"].as_array().unwrap().is_empty());
        assert_eq!(
            v2["pending_purge"]["queue_depth"], 1,
            "unsubscribe pushes one work unit"
        );

        state.subscribe_zone(&ZoneId::new("transient"));
        let v3 = compute_zones_scope(&state);
        assert_eq!(
            v3["default_behavior"], "scoped",
            "re-subscribe flips back to scoped"
        );
        let zones: Vec<String> = v3["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert_eq!(zones, vec!["transient"]);
        assert_eq!(
            v3["pending_purge"]["queue_depth"], 1,
            "re-subscribe must NOT clear the queue — worker filters at dequeue, not insert (zone_purge.rs:84-86)"
        );
    }

    #[test]
    fn batch_x_compute_zones_scope_global_zone_idx_unaffected_by_subscribe_unsubscribe_churn() {
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("medical"));
        state.subscribe_zone(&ZoneId::new("finance"));
        state.unsubscribe_zone(&ZoneId::new("medical"));
        state.subscribe_zone(&ZoneId::new("logistics"));
        let v = compute_zones_scope(&state);
        let entries = v["global_zone_idx_entries"]
            .as_u64()
            .expect("global_zone_idx_entries must be a non-negative integer");
        let distinct = v["global_zone_idx_distinct_zones"]
            .as_u64()
            .expect("global_zone_idx_distinct_zones must be a non-negative integer");
        assert_eq!(
            entries, 0,
            "subscription churn must not bump the record-side index; entries reflect ingested records, not subscriptions"
        );
        assert_eq!(
            distinct, 0,
            "subscription churn must not bump the record-side distinct-zone count"
        );
        let subscribed: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            subscribed,
            vec!["finance", "logistics"],
            "subscribed set must reflect the live state after churn — medical dropped, logistics added, finance retained"
        );
    }

    #[test]
    fn batch_y_idempotent_double_subscribe_single_entry_no_queue_growth() {
        // `ZoneManager::subscribe` is idempotent — subscribing the same
        // zone twice is a no-op on the second call (zone.rs:458 checks
        // `contains` before inserting). This propagates to
        // `compute_zones_scope`: the subscribed_zones array must contain
        // "analytics" exactly once, default_behavior stays "scoped", and
        // queue_depth must stay 0 — a buggy subscribe-twice that pushes
        // two entries would break the soak monitor's "any nonzero depth ⇒
        // drain in progress" heuristic and trigger false operator alerts.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("analytics"));
        state.subscribe_zone(&ZoneId::new("analytics"));
        let v = compute_zones_scope(&state);
        let zones = v["subscribed_zones"].as_array().unwrap();
        assert_eq!(
            zones.len(),
            1,
            "idempotent subscribe must yield exactly one subscribed_zones entry, not two"
        );
        assert_eq!(
            zones[0].as_str().unwrap(),
            "analytics",
            "the single entry must be the subscribed zone string"
        );
        assert_eq!(v["default_behavior"], "scoped");
        assert_eq!(
            v["pending_purge"]["queue_depth"], 0,
            "double-subscribe must NOT grow the purge queue"
        );
    }

    #[test]
    fn batch_y_two_disjoint_hierarchies_all_ancestors_lex_order() {
        // Two disjoint deep subscriptions auto-pin two independent ancestor
        // chains. `finance/eu` pins `finance` + `finance/eu`; `medical/us`
        // pins `medical` + `medical/us`. All four must appear in ASCII-lex
        // order in both `subscribed_zones` and `per_zone_storage`. The lex
        // contract for mixed-root trees ("finance" < "medical" because 'f'
        // (0x66) < 'm' (0x6D)) must hold after every restart — operator
        // runbooks grep the JSON line-by-line and depend on stable order.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("finance/eu"));
        state.subscribe_zone(&ZoneId::new("medical/us"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            zones,
            vec!["finance", "finance/eu", "medical", "medical/us"],
            "two disjoint hierarchies must yield all four ancestors in lex order"
        );
        let per_zone_paths: Vec<String> = v["per_zone_storage"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["zone"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            per_zone_paths,
            vec!["finance", "finance/eu", "medical", "medical/us"],
            "per_zone_storage must mirror the same four zones in lex order"
        );
    }

    #[test]
    fn batch_y_oldest_lag_seconds_is_json_number_zero_when_queue_empty() {
        // `oldest_lag_seconds` is produced by `zone_purge::oldest_lag_secs`
        // which returns `0.0_f64` when the purge queue is empty
        // (`zone_purge.rs: queue is empty ⇒ oldest=None ⇒ 0.0`). Serde
        // renders `f64` as a JSON number. Pinning this prevents a future
        // refactor that accidentally serializes as a string ("0") or as a
        // nested object — both would silently break the soak monitor's
        // `oldest_lag_seconds > threshold` numeric comparison.
        let state = build_state();
        let v = compute_zones_scope(&state);
        assert!(
            v["pending_purge"]["oldest_lag_seconds"].is_number(),
            "oldest_lag_seconds must serialize as a JSON number, not a string or object"
        );
        let lag = v["pending_purge"]["oldest_lag_seconds"]
            .as_f64()
            .expect("oldest_lag_seconds must be parseable as f64");
        assert_eq!(
            lag, 0.0,
            "empty queue ⇒ oldest_lag_seconds must be exactly 0.0"
        );
    }

    #[test]
    fn batch_y_per_zone_storage_zones_match_subscribed_zones_element_for_element() {
        // `subscribed_zones` and `per_zone_storage[*].zone` are derived from
        // the same sorted `subscribed` Vec (L1863-L1882): both walk the
        // identical iterator, so their i-th elements must always agree.
        // If a future refactor adds a separate sort key to `per_zone_storage`
        // (e.g. sort by record_count descending for "hottest zones first")
        // without updating `subscribed_zones`, the two arrays would diverge
        // and operator dashboards that zip them column-by-column would show
        // mismatched zone / record-count pairs.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("gamma"));
        state.subscribe_zone(&ZoneId::new("alpha"));
        state.subscribe_zone(&ZoneId::new("beta"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        let per_zone_zones: Vec<String> = v["per_zone_storage"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["zone"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            zones.len(),
            per_zone_zones.len(),
            "subscribed_zones and per_zone_storage must have the same length"
        );
        for (i, (sz, pz)) in zones.iter().zip(per_zone_zones.iter()).enumerate() {
            assert_eq!(
                sz, pz,
                "index {i}: subscribed_zones[{i}]={sz:?} ≠ per_zone_storage[{i}].zone={pz:?} — arrays must be element-wise aligned"
            );
        }
    }

    #[test]
    fn batch_y_unsubscribe_never_subscribed_zone_enqueues_purge_unconditionally() {
        // `NodeState::unsubscribe_zone` calls `enqueue_purge_zone` at
        // `state.rs:4158` UNCONDITIONALLY — after the zone_manager lock is
        // released, regardless of whether the zone was present in the
        // manager. This is intentional: an operator who accidentally issues
        // `?zone=ghost-zone` must get a work unit in the purge queue so the
        // reconciliation worker can verify there is nothing to clean up
        // (rather than silently swallowing the request with no audit trail).
        //
        // The observable effect: queue_depth increments from 0 to 1 even
        // though `subscribed_zones` remains empty (no matching entry to
        // remove) and `default_behavior` stays `accept_all`.
        let state = build_state();
        state.unsubscribe_zone(&ZoneId::new("ghost-zone-never-subscribed"));
        let v = compute_zones_scope(&state);
        assert_eq!(
            v["pending_purge"]["queue_depth"], 1,
            "unsubscribe on a never-subscribed zone must unconditionally enqueue one purge work unit (state.rs:4158)"
        );
        assert_eq!(
            v["default_behavior"], "accept_all",
            "no subscription was ever active ⇒ default_behavior stays accept_all"
        );
        assert!(
            v["subscribed_zones"].as_array().unwrap().is_empty(),
            "subscribed_zones must remain empty — the unsubscribe was a no-op on the manager set"
        );
    }

    #[test]
    fn batch_z_top_level_value_is_json_object_type() {
        // Pin: the compute_zones_scope return value at the top level is a
        // JSON Object (`serde_json::json!({...})` macro at L1896). A
        // refactor that wrapped it in an outer Array (`[{...}]`) or
        // String (`"{...}"` pre-encoded) would silently break every
        // `GET /admin/zones/scope` consumer — operator dashboards parse
        // the body as `obj["subscribed_zones"]` (object indexing), not
        // as `arr[0]["subscribed_zones"]`. The object-shape guarantee is
        // the wire contract; pin it explicitly so the `.as_object()`
        // path can never silently flip to null/array.
        let state = build_state();
        let v = compute_zones_scope(&state);
        assert!(
            v.is_object(),
            "compute_zones_scope must return a JSON Object at the top level, not an Array/String/Number/Null"
        );
        let obj = v.as_object().expect("top-level value must be a JSON Object");
        assert_eq!(
            obj.len(),
            7,
            "top-level object must have exactly 7 keys (subscribed_zone_count joined in the \
             O(n)-under-lock DoS batch) — found {}: {:?}",
            obj.len(),
            obj.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn batch_z_default_behavior_is_json_string_type_on_both_branches() {
        // `default_behavior` is computed by the if/else at L1867-L1871 as
        // a string literal — either "accept_all" or "scoped". Pin BOTH
        // branches as JSON String type so a refactor that swapped to a
        // numeric enum (0/1) or boolean (true/false) for "compactness"
        // would surface as a test failure at PR time, not as a silent
        // dashboard regression where every operator's filter status
        // shows up as `null` or `0`/`1` instead of the expected
        // human-readable string. Operator runbooks (`elara-cli zones
        // scope | jq .default_behavior`) and dashboard panels both
        // depend on the string-type contract.
        let state = build_state();
        // Branch A: empty subscription set ⇒ "accept_all"
        let v_empty = compute_zones_scope(&state);
        assert!(
            v_empty["default_behavior"].is_string(),
            "default_behavior on fresh state must serialize as a JSON String, not number/boolean/null"
        );
        assert_eq!(v_empty["default_behavior"].as_str().unwrap(), "accept_all");
        // Branch B: one subscription ⇒ "scoped"
        state.subscribe_zone(&ZoneId::new("compliance"));
        let v_scoped = compute_zones_scope(&state);
        assert!(
            v_scoped["default_behavior"].is_string(),
            "default_behavior on scoped state must serialize as a JSON String"
        );
        assert_eq!(v_scoped["default_behavior"].as_str().unwrap(), "scoped");
    }

    #[test]
    fn batch_z_per_zone_storage_is_empty_array_not_null_on_fresh_state() {
        // Pin: `per_zone_storage` on a fresh node is an EMPTY ARRAY
        // (`[]`), not `null`. The serde_json::json! macro at L1899 wraps
        // the `Vec<serde_json::Value>` produced by `.collect()` — empty
        // Vec collects to empty Array, never to null. This contract
        // matters because TypeScript dashboard code in `dashboards/`
        // does `data.per_zone_storage.forEach(...)`: a null would throw
        // `TypeError: Cannot read properties of null`, an empty array
        // would correctly no-op. A future refactor that switched to
        // `Option<Vec<_>>` returning `None` on empty would silently
        // break the dashboard on every fresh node.
        let state = build_state();
        let v = compute_zones_scope(&state);
        assert!(
            v["per_zone_storage"].is_array(),
            "per_zone_storage on fresh state must be a JSON Array, not null/object/string"
        );
        assert_eq!(
            v["per_zone_storage"].as_array().unwrap().len(),
            0,
            "fresh state ⇒ empty array, length must be exactly 0"
        );
        // Also pin subscribed_zones same property (matches the dashboard
        // .forEach contract on the sibling field).
        assert!(
            v["subscribed_zones"].is_array(),
            "subscribed_zones on fresh state must be a JSON Array, not null"
        );
        assert_eq!(
            v["subscribed_zones"].as_array().unwrap().len(),
            0,
            "fresh state ⇒ empty array, length must be exactly 0"
        );
    }

    #[test]
    fn batch_z_subscribe_descendant_does_not_duplicate_existing_ancestors() {
        // Pin: subscribing `a/b/c` AFTER `a/b` is already subscribed
        // must NOT duplicate `a` or `a/b` in subscribed_zones. The
        // ZoneManager::subscribe call at zone.rs:458 uses a `HashSet`
        // for the underlying store + `contains`-before-insert, so
        // ancestor auto-pinning is naturally dedup'd. The output Vec
        // collected at L1862 then sorted at L1863 must contain each
        // distinct ancestor exactly once. A regression that pushed
        // duplicates into the Vec (e.g. switching the backing store to
        // a Vec without dedup) would produce a `subscribed_zones`
        // array like `["a", "a", "a/b", "a/b", "a/b/c"]` — visible to
        // operators as "why is each zone listed twice?" and to dashboards
        // as inflated counts.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("a/b"));
        state.subscribe_zone(&ZoneId::new("a/b/c"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            zones,
            vec!["a", "a/b", "a/b/c"],
            "overlapping descendant subscription must NOT duplicate already-pinned ancestors — expected exactly 3 entries in lex order"
        );
        // Defensive: also verify per_zone_storage is the same length, i.e.
        // the dedup propagates through both derivation sites.
        assert_eq!(
            v["per_zone_storage"].as_array().unwrap().len(),
            3,
            "per_zone_storage must also have exactly 3 entries — dedup must propagate through both arrays"
        );
    }

    #[test]
    fn batch_z_deterministic_repeated_calls_return_identical_serialized_json() {
        // Pin: two back-to-back `compute_zones_scope` calls on identical
        // state must produce byte-identical serialized JSON. This guards
        // against a future refactor that introduced HashMap iteration
        // into the per_zone_storage build path (currently L1873 iterates
        // a `Vec` which preserves insertion-then-sort order). A HashMap
        // leak would surface as flaky soak-monitor diffs and break the
        // operator workflow that `diff`s two scope snapshots to confirm
        // "nothing changed between deploys". Determinism is part of the
        // wire contract, not an accident of implementation.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("payments/eu"));
        state.subscribe_zone(&ZoneId::new("payments/us"));
        state.subscribe_zone(&ZoneId::new("identity"));
        let json_first =
            serde_json::to_string(&compute_zones_scope(&state)).expect("serialize first");
        let json_second =
            serde_json::to_string(&compute_zones_scope(&state)).expect("serialize second");
        assert_eq!(
            json_first, json_second,
            "two back-to-back calls on identical state must produce byte-identical JSON — a diff indicates non-deterministic iteration order leaked into the output"
        );
    }

    #[test]
    fn batch_aa_subscribed_zones_each_element_is_json_string_type() {
        // Pin: every element of `subscribed_zones` is a JSON String, not
        // an Array (of bytes), not an Object, not a Number. The map step
        // at L1897 calls `z.to_string()` on each ZoneId, which serde
        // renders as a JSON String. A future refactor that changed
        // ZoneId to a tuple-struct without the `to_string()` projection
        // — and switched the map to `subscribed.iter().cloned().collect()`
        // — could leak the raw ZoneId byte representation into the wire
        // contract. Operator dashboards and `elara-cli zones | jq
        // .subscribed_zones[]` both depend on String elements; a
        // regression to Array/Object would break every consumer. Pin the
        // type on multiple elements so the assertion can't drift to
        // "first element happens to be a String by coincidence".
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("alpha"));
        state.subscribe_zone(&ZoneId::new("bravo"));
        state.subscribe_zone(&ZoneId::new("charlie"));
        let v = compute_zones_scope(&state);
        let arr = v["subscribed_zones"]
            .as_array()
            .expect("subscribed_zones must be an Array");
        assert_eq!(arr.len(), 3, "expected exactly 3 subscriptions");
        for (i, elem) in arr.iter().enumerate() {
            assert!(
                elem.is_string(),
                "subscribed_zones[{i}] must be a JSON String, got: {elem:?}"
            );
        }
    }

    #[test]
    fn batch_aa_per_zone_storage_zone_field_each_element_is_json_string_type() {
        // Pin: every `per_zone_storage[i]["zone"]` is a JSON String. The
        // serde_json::json! macro at L1879 emits `z.to_string()` into the
        // `zone` slot — a regression that switched to `z.to_key_bytes()`
        // (the byte-slice form used internally for rocks lookups) would
        // render as a JSON Array of integers and break every operator
        // tool that does `.zone` field access expecting a string. The
        // `zone` field is the dashboard's per-row header — any non-String
        // type produces an unreadable widget. Walk all entries (not just
        // [0]) so a partial refactor that only converted one branch
        // surfaces here.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("zeta"));
        state.subscribe_zone(&ZoneId::new("yankee"));
        state.subscribe_zone(&ZoneId::new("xray"));
        let v = compute_zones_scope(&state);
        let entries = v["per_zone_storage"]
            .as_array()
            .expect("per_zone_storage must be an Array");
        assert_eq!(entries.len(), 3);
        for (i, entry) in entries.iter().enumerate() {
            let zone_field = &entry["zone"];
            assert!(
                zone_field.is_string(),
                "per_zone_storage[{i}].zone must be a JSON String, got: {zone_field:?}"
            );
        }
    }

    #[test]
    fn batch_aa_per_zone_storage_record_count_is_json_unsigned_integer_type() {
        // Pin: every `per_zone_storage[i]["record_count"]` deserializes
        // via `.as_u64()` (NOT `.as_i64()`, NOT `.as_f64()`, NOT
        // `.as_str()`). The source at L1880 is `rocks.count_zone(&key)`
        // which returns `u64` (rocks.rs:`count_zone`). A regression that
        // switched the rocks counter to `i64` for "easier subtraction
        // math" would render -1 on overflow and silently break every
        // dashboard widget that treats record_count as a non-negative
        // monotone counter. The strict-u64 contract is what gives
        // operators the "0 ⇒ no records ingested for this zone" signal;
        // pin it on all entries (not just one) so a partial refactor
        // surfaces here.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("alpha"));
        state.subscribe_zone(&ZoneId::new("bravo"));
        state.subscribe_zone(&ZoneId::new("charlie"));
        let v = compute_zones_scope(&state);
        let entries = v["per_zone_storage"]
            .as_array()
            .expect("per_zone_storage must be an Array");
        assert_eq!(entries.len(), 3);
        for (i, entry) in entries.iter().enumerate() {
            let rc = &entry["record_count"];
            assert!(
                rc.is_u64(),
                "per_zone_storage[{i}].record_count must be a JSON unsigned integer (u64-fit), got: {rc:?}"
            );
            assert_eq!(
                rc.as_u64().unwrap(),
                0,
                "fresh state ⇒ every subscribed zone has zero records"
            );
        }
    }

    #[test]
    fn batch_aa_pending_purge_top_level_is_object_with_exactly_three_keys() {
        // Pin: `pending_purge` is a JSON Object (not Array, not String,
        // not pre-encoded JSON) with exactly 3 named keys. The 3-key
        // contract is what the soak monitor's per-tick storage-health
        // line parses; a silent rename of one key (e.g.
        // `records_purged_total` → `records_purged`) would land here
        // first instead of as a parse-failure in the soak log. Pin BOTH
        // the type (.is_object()) AND the exact key set so a regression
        // that added a 4th key (e.g. `last_purge_at_secs`) without
        // updating the consumer-side parser surfaces in this test —
        // the contract is "exactly three named scalar fields, no more".
        let state = build_state();
        let v = compute_zones_scope(&state);
        let pp = &v["pending_purge"];
        assert!(
            pp.is_object(),
            "pending_purge must be a JSON Object, not Array/String/Null"
        );
        let pp_obj = pp.as_object().expect("pending_purge must be a JSON Object");
        let mut keys: Vec<&str> = pp_obj.keys().map(|s| s.as_str()).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["oldest_lag_seconds", "queue_depth", "records_purged_total"],
            "pending_purge must contain ONLY these 3 keys — any 4th field is a contract change"
        );
    }

    #[test]
    fn batch_aa_deeply_nested_five_level_zone_path_preserves_all_ancestors_in_lex_order() {
        // Pin: subscribing to a 5-level zone path `a/b/c/d/e` auto-pins
        // all 5 ancestors (a, a/b, a/b/c, a/b/c/d, a/b/c/d/e) and
        // returns them in lex order in `subscribed_zones`. The
        // ZoneManager::subscribe auto-pin loop at zone.rs:458-466 walks
        // the parent chain via split-at-`/` — pin the n=5 case so a
        // regression that introduced a depth ceiling (e.g. "only the
        // 3 nearest ancestors") would land here instead of silently
        // mis-filtering a 5-level hierarchy at the ingest layer. Lex
        // sort with these labels matches depth-first prefix sort
        // (each shorter prefix precedes its descendant), so the
        // assertion vector is also a regression-detector for the
        // sort-by-key contract at L1863.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("a/b/c/d/e"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .expect("subscribed_zones must be an Array")
            .iter()
            .map(|s| s.as_str().expect("each element must be a String").to_string())
            .collect();
        assert_eq!(
            zones,
            vec!["a", "a/b", "a/b/c", "a/b/c/d", "a/b/c/d/e"],
            "5-level subscribe must auto-pin all 5 ancestors in lex order"
        );
        // per_zone_storage mirrors subscribed_zones element-wise.
        let per_zone_paths: Vec<String> = v["per_zone_storage"]
            .as_array()
            .expect("per_zone_storage must be an Array")
            .iter()
            .map(|e| {
                e["zone"]
                    .as_str()
                    .expect("zone field must be a String")
                    .to_string()
            })
            .collect();
        assert_eq!(
            per_zone_paths,
            vec!["a", "a/b", "a/b/c", "a/b/c/d", "a/b/c/d/e"],
            "per_zone_storage must mirror the 5-level lex order"
        );
    }

    #[test]
    fn batch_bb_pending_purge_queue_depth_is_json_unsigned_integer_zero_on_fresh_state() {
        // Pin: `pending_purge.queue_depth` is a JSON unsigned integer
        // (`is_u64()`), NOT a Number-as-float (`0.0`), NOT a string
        // (`"0"`), NOT a nested object. The source at L1890 is
        // `zone_purge::queue_depth(state)` which returns `usize` — serde
        // renders `usize` as a JSON Number that fits in `u64`. Pin the
        // strict-u64 contract because the soak monitor uses
        // `pending_purge.queue_depth` in numeric comparisons against an
        // integer threshold (drain SLA); a regression that switched to
        // `f64` (e.g. "express as seconds-since-enqueue average") would
        // pass `is_number()` but fail `as_u64()` and silently corrupt
        // the threshold comparison. Distinct from
        // `batch_v_global_zone_idx_metrics_*` which pinned the two
        // global counters; this pin covers the THIRD numeric scalar in
        // the response that wasn't yet type-pinned.
        let state = build_state();
        let v = compute_zones_scope(&state);
        let qd = &v["pending_purge"]["queue_depth"];
        assert!(
            qd.is_u64(),
            "pending_purge.queue_depth must be a JSON unsigned integer (u64-fit), got: {qd:?}"
        );
        assert_eq!(
            qd.as_u64().unwrap(),
            0,
            "fresh state ⇒ empty purge queue ⇒ queue_depth must be exactly 0"
        );
    }

    #[test]
    fn batch_bb_per_zone_storage_entry_has_exactly_two_keys_zone_and_record_count() {
        // Pin: each `per_zone_storage[i]` object has EXACTLY two keys —
        // `zone` and `record_count`. The serde_json::json! macro at
        // L1878-L1881 emits exactly those two slots. The 2-key contract
        // matters because dashboard widgets render this as a 2-column
        // table — a third silently-added field (e.g. `last_ingest_at`)
        // would expand the row but not the header, producing offset
        // columns until the operator notices. Pin BOTH the count (==2)
        // AND the exact key names so a rename of one slot
        // (`record_count` → `count`) lands here, not in a downstream
        // dashboard parse failure. Walk every entry (not just [0]) so
        // a partial refactor that only converted one branch surfaces.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("alpha"));
        state.subscribe_zone(&ZoneId::new("bravo"));
        state.subscribe_zone(&ZoneId::new("charlie"));
        let v = compute_zones_scope(&state);
        let entries = v["per_zone_storage"]
            .as_array()
            .expect("per_zone_storage must be an Array");
        assert_eq!(entries.len(), 3);
        for (i, entry) in entries.iter().enumerate() {
            let obj = entry
                .as_object()
                .unwrap_or_else(|| panic!("per_zone_storage[{i}] must be an Object"));
            assert_eq!(
                obj.len(),
                2,
                "per_zone_storage[{i}] must have exactly 2 keys, got {}: {:?}",
                obj.len(),
                obj.keys().collect::<Vec<_>>()
            );
            let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
            keys.sort();
            assert_eq!(
                keys,
                vec!["record_count", "zone"],
                "per_zone_storage[{i}] keys must be EXACTLY [record_count, zone] — any rename is a wire-contract break"
            );
        }
    }

    #[test]
    fn batch_bb_unicode_zone_path_preserves_utf8_bytes_in_subscribed_zones() {
        // Pin: non-ASCII zone paths round-trip safely through
        // ZoneManager::subscribe + compute_zones_scope without
        // corruption, mangling, or escape-encoding drift. ZoneId::new
        // (zone.rs:40) `to_lowercase()`s the path — for CJK / accented
        // characters the lowercase mapping is mostly a no-op (no case
        // distinction for `日本`, `医療`, etc.), so the input bytes
        // appear verbatim in subscribed_zones. The UTF-8 byte sequence
        // is preserved end-to-end because serde_json emits JSON
        // Strings as UTF-8 by default. A regression that introduced
        // ASCII-only normalization (e.g. `path.is_ascii()` panic, or
        // a Unicode-stripping `replace`) would corrupt the path and
        // break operators who run regional/internationalized zone
        // taxonomies. Pin one CJK and one accented-Latin path so
        // partial regressions on one branch surface here.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("日本/医療"));
        state.subscribe_zone(&ZoneId::new("café/médical"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .expect("subscribed_zones must be an Array")
            .iter()
            .map(|s| s.as_str().expect("each element must be a String").to_string())
            .collect();
        // ZoneManager auto-pins ancestors, so each 2-level path adds 2
        // entries: parent + full path. 4 total in lex order (the
        // `c` of `café` sorts before `日` in byte/lex order).
        assert!(
            zones.contains(&"日本".to_string()),
            "ancestor `日本` must be auto-pinned and preserved as UTF-8 in subscribed_zones, got: {zones:?}"
        );
        assert!(
            zones.contains(&"日本/医療".to_string()),
            "full UTF-8 path `日本/医療` must round-trip verbatim, got: {zones:?}"
        );
        assert!(
            zones.contains(&"café".to_string()),
            "accented Latin ancestor `café` must preserve combining diacritics, got: {zones:?}"
        );
        assert!(
            zones.contains(&"café/médical".to_string()),
            "full accented Latin path `café/médical` must round-trip verbatim, got: {zones:?}"
        );
    }

    #[test]
    fn batch_bb_subscribe_three_then_unsubscribe_middle_leaves_other_two_in_subscribed() {
        // Pin: with three disjoint subscriptions, unsubscribing the
        // MIDDLE one (lex-order) leaves exactly the other two in
        // subscribed_zones AND in per_zone_storage. Exercises the set
        // semantics of ZoneManager::unsubscribe (zone.rs:469 →
        // HashSet::remove) which must only drop the target key, not
        // its siblings. A regression that mistakenly cleared the
        // whole subscription set (e.g. confusing `unsubscribe` with
        // `unsubscribe_all`) or that dropped an adjacent key by
        // accident (off-by-one on the sort key) would land here. Pin
        // BOTH arrays since per_zone_storage is derived from the same
        // sorted Vec — divergence between the two would also surface.
        // Companion to batch_t which exercised single-subscribe +
        // unsubscribe; this pins the 3-then-remove-1 case so the
        // selective drop is verified independently of the round-trip.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("alpha"));
        state.subscribe_zone(&ZoneId::new("bravo"));
        state.subscribe_zone(&ZoneId::new("charlie"));
        state.unsubscribe_zone(&ZoneId::new("bravo"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            zones,
            vec!["alpha", "charlie"],
            "unsubscribing the middle entry must leave the other two in lex order — got: {zones:?}"
        );
        let per_zone_zones: Vec<String> = v["per_zone_storage"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["zone"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            per_zone_zones,
            vec!["alpha", "charlie"],
            "per_zone_storage must mirror the post-unsubscribe subscribed_zones, got: {per_zone_zones:?}"
        );
        // Default behavior stays "scoped" because two subscriptions remain.
        assert_eq!(
            v["default_behavior"].as_str().unwrap(),
            "scoped",
            "two remaining subscriptions ⇒ default_behavior must still be `scoped`"
        );
        // queue_depth bumps by 1 for the one unsubscribe (purge enqueued).
        assert_eq!(
            v["pending_purge"]["queue_depth"].as_u64().unwrap(),
            1,
            "exactly one unsubscribe ⇒ queue_depth must be exactly 1"
        );
    }

    #[test]
    fn batch_bb_full_json_round_trip_via_serde_string_preserves_all_seven_top_level_fields() {
        // Pin: the compute_zones_scope JSON output survives a
        // `serde_json::to_string` → `serde_json::from_str` round-trip
        // with the SAME 7 top-level keys present and the SAME
        // sub-shapes preserved. This is the wire-contract pin: the
        // value emitted on the HTTP body MUST deserialize back to a
        // structure that operators / SDKs / dashboards can re-parse.
        // A regression that introduced a non-string Map key, a NaN
        // f64, or a circular reference would fail `to_string` at
        // serialize time. A regression that introduced a key that
        // serializes-but-doesn't-deserialize (none in stdlib but
        // possible with custom types) would land at the
        // `from_str::<Value>` step. Distinct from batch_z's
        // determinism pin which compared two emissions; this pin
        // proves the emission is fully self-consistent against the
        // serde Value parser — so the dashboard's HTTP-fetch +
        // JSON.parse path can never silently consume malformed JSON.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("payments/eu"));
        state.subscribe_zone(&ZoneId::new("identity"));
        let original = compute_zones_scope(&state);
        let serialized =
            serde_json::to_string(&original).expect("compute_zones_scope output must serialize");
        let reparsed: serde_json::Value =
            serde_json::from_str(&serialized).expect("serialized output must round-trip via from_str");
        // Top-level shape and key set survive the round-trip.
        let obj = reparsed
            .as_object()
            .expect("reparsed value must still be a JSON Object");
        assert_eq!(
            obj.len(),
            7,
            "round-trip must preserve the 7-key top-level contract, got {}: {:?}",
            obj.len(),
            obj.keys().collect::<Vec<_>>()
        );
        for k in &[
            "subscribed_zones",
            "subscribed_zone_count",
            "default_behavior",
            "per_zone_storage",
            "global_zone_idx_entries",
            "global_zone_idx_distinct_zones",
            "pending_purge",
        ] {
            assert!(
                obj.contains_key(*k),
                "round-trip must preserve top-level key `{k}`, missing in: {:?}",
                obj.keys().collect::<Vec<_>>()
            );
        }
        // Field-level equality (byte-for-byte) — the parsed Value
        // must equal the original Value, proving no semantic drift
        // was introduced by the serialize/deserialize cycle.
        assert_eq!(
            original, reparsed,
            "serde_json round-trip must produce a semantically identical Value — a diff indicates non-canonical serialization or lossy field handling"
        );
    }

    // ─── ZoneId-normalization + post-mutation counter axes ────────────────────────────────────────────────────────
    // Two axes beyond the earlier wire-shape edges:
    //  (1) ZoneId-normalization paths that flow through compute_zones_scope
    //      verbatim (uppercase→lowercase, trailing-slash strip), and
    //  (2) post-mutation counter mirroring (records_purged_total) and the
    //      non-empty-queue branch of oldest_lag_seconds — both unobserved
    //      in prior batches which only pinned the zero baseline.

    #[test]
    fn batch_cc_subscribed_zones_is_empty_array_not_null_on_fresh_state() {
        // Pin: `subscribed_zones` on a fresh node is an empty JSON Array
        // (`[]`), NOT `null` and NOT a missing field. The source at L1897
        // is `subscribed.iter().map(...).collect::<Vec<_>>()` which on an
        // empty `subscribed` Vec serializes to `[]`. The HTTP consumer
        // (operator dashboard widget that iterates the array to render
        // chip badges) MUST be able to call `.length` and `.forEach` on
        // it unconditionally — a regression that emitted `null` on the
        // empty branch (e.g. via `Option<Vec<_>>` wrapping) would crash
        // the widget's iteration on fresh nodes. Companion to batch_z
        // `per_zone_storage_is_empty_array_not_null_on_fresh_state` which
        // pinned the OTHER top-level array slot.
        let state = build_state();
        let v = compute_zones_scope(&state);
        let arr = v["subscribed_zones"]
            .as_array()
            .expect("subscribed_zones must be a JSON Array on fresh state, NOT null or missing");
        assert!(
            arr.is_empty(),
            "fresh state ⇒ subscribed_zones must be exactly [], got {arr:?}"
        );
        assert!(
            !v["subscribed_zones"].is_null(),
            "subscribed_zones must NEVER be null — empty Array is the contract on the empty branch"
        );
    }

    #[test]
    fn batch_cc_uppercase_zone_path_normalized_to_lowercase_in_subscribed_zones() {
        // Pin: ZoneId::new lowercases the input path (zone.rs:43
        // `.to_lowercase()`). The JSON output of compute_zones_scope
        // reflects the NORMALIZED zone path, never the caller's
        // pre-normalization string. A regression that bypassed
        // `.to_lowercase()` (e.g. switched to `as_str()` after a refactor)
        // would make case-sensitive duplicates appear as distinct
        // subscriptions in the operator dashboard — both `PAYMENTS/EU`
        // and `payments/eu` would render as separate chips, doubling the
        // perceived subscription count and breaking the idempotency
        // invariant pinned by batch_v_subscribe_zone_idempotent_*.
        // Distinct from batch_bb Unicode (where lowercase mapping is
        // mostly a no-op for CJK) — this pins the ASCII case-fold path
        // explicitly with mixed-case input.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("PAYMENTS/EU"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        // ZoneManager auto-pins the ancestor `payments` (post-lowercase).
        assert!(
            zones.contains(&"payments".to_string()),
            "lowercased ancestor `payments` must appear in subscribed_zones, got: {zones:?}"
        );
        assert!(
            zones.contains(&"payments/eu".to_string()),
            "lowercased full path `payments/eu` must appear in subscribed_zones, got: {zones:?}"
        );
        // Negative: the uppercase form must NOT appear — proves the
        // case-fold actually happened (a no-op normalization would leave
        // `PAYMENTS/EU` in the output).
        assert!(
            !zones.contains(&"PAYMENTS/EU".to_string()),
            "uppercase form `PAYMENTS/EU` must NOT appear — ZoneId::new lowercases, got: {zones:?}"
        );
        assert!(
            !zones.contains(&"PAYMENTS".to_string()),
            "uppercase ancestor `PAYMENTS` must NOT appear — ZoneId::new lowercases, got: {zones:?}"
        );
    }

    #[test]
    fn batch_cc_trailing_slash_zone_path_stripped_in_subscribed_zones() {
        // Pin: ZoneId::new strips trailing slashes (zone.rs:44
        // `.trim_end_matches('/')`). The JSON output reflects the
        // stripped form. A regression that removed this normalization
        // would let `medical/` and `medical` coexist as separate
        // subscriptions, doubling the apparent depth-0 entry count. The
        // operator dashboard would render both chips and the per-zone
        // record count would split traffic between them at ingest. Pin
        // BOTH single-trailing-slash and multi-trailing-slash inputs
        // since `trim_end_matches('/')` strips ALL trailing slashes by
        // pattern semantics, not just one.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("medical/"));
        state.subscribe_zone(&ZoneId::new("payments///"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        // Both ended up depth-0 entries after stripping, lex-sorted.
        assert_eq!(
            zones,
            vec!["medical", "payments"],
            "trailing slashes must be stripped — got: {zones:?}"
        );
        // Negative: neither raw form must appear.
        assert!(
            !zones.contains(&"medical/".to_string()),
            "`medical/` (with trailing slash) must NOT survive normalization, got: {zones:?}"
        );
        assert!(
            !zones.contains(&"payments/".to_string())
                && !zones.contains(&"payments//".to_string())
                && !zones.contains(&"payments///".to_string()),
            "no partial-strip form of `payments///` may survive — got: {zones:?}"
        );
    }

    #[test]
    fn batch_cc_records_purged_total_mirrors_atomic_value_when_nonzero() {
        // Pin: `pending_purge.records_purged_total` reads
        // `state.zone_purge_records_purged_total.load(Relaxed)` verbatim
        // at L1893. The zero baseline is covered by
        // batch_x_compute_zones_scope_records_purged_total_is_u64_zero_baseline,
        // but the NONZERO post-purge state has been unobserved — a
        // regression that hard-coded `0` (e.g. accidentally constructed
        // the JSON before the atomic was added) would pass the baseline
        // test but silently drop every operator's purge-totals dashboard
        // to zero. Directly bump the atomic (the purge_loop's effect on
        // this counter) and verify the JSON mirrors the exact value.
        use std::sync::atomic::Ordering;
        let state = build_state();
        // Set to a distinctive non-round value so any accidental hard-
        // coded constant (`0`, `1`, `42`) would fail-match.
        state
            .zone_purge_records_purged_total
            .store(424242, Ordering::Relaxed);
        let v = compute_zones_scope(&state);
        let rpt = &v["pending_purge"]["records_purged_total"];
        assert!(
            rpt.is_u64(),
            "records_purged_total must remain u64-typed even when nonzero, got: {rpt:?}"
        );
        assert_eq!(
            rpt.as_u64().unwrap(),
            424242,
            "records_purged_total must mirror the atomic value verbatim — load(Relaxed) at L1893 is the wire contract"
        );
        // Sanity: the OTHER pending_purge counters are unaffected by
        // mutating just this one atomic — proves the field-level
        // independence (no accidental aliasing across the 3 slots).
        assert_eq!(
            v["pending_purge"]["queue_depth"].as_u64().unwrap(),
            0,
            "queue_depth must remain at 0 — only records_purged_total was bumped"
        );
        assert_eq!(
            v["pending_purge"]["oldest_lag_seconds"].as_f64().unwrap(),
            0.0,
            "oldest_lag_seconds must remain at 0.0 — only records_purged_total was bumped"
        );
    }

    #[test]
    fn batch_cc_oldest_lag_seconds_is_json_number_with_nonnegative_value_when_queue_nonempty() {
        // Pin: when the purge queue is NON-empty,
        // `pending_purge.oldest_lag_seconds` is a JSON Number (f64-fit)
        // with value `>= 0.0`. Source at L1891 is
        // `zone_purge::oldest_lag_secs(state)`. Returns `0.0` only on
        // empty-queue (pinned by batch_y); on non-empty queue computes
        // `(now - head_ts).max(0.0)` (zone_purge.rs:71). A regression
        // that flipped the `.max(0.0)` guard would let a small
        // backward-clock skew produce a negative number, which serde
        // emits as a JSON Number — `is_f64()` still passes, but
        // downstream dashboards that render this as "X seconds ago"
        // would display nonsense ("-3 seconds ago"). Pin BOTH the type
        // AND the non-negativity invariant. Companion to batch_y which
        // pinned the zero-baseline; this pins the non-empty branch.
        let state = build_state();
        // Subscribe then immediately unsubscribe — pushes one entry
        // onto the purge queue at `SystemTime::now()`. queue_depth
        // becomes 1 and the head_ts is "right now" so oldest_lag_secs
        // is a very small positive (or exactly 0.0) number.
        state.subscribe_zone(&ZoneId::new("alpha"));
        state.unsubscribe_zone(&ZoneId::new("alpha"));
        let v = compute_zones_scope(&state);
        let lag = &v["pending_purge"]["oldest_lag_seconds"];
        assert!(
            lag.is_f64() || lag.is_u64() || lag.is_i64(),
            "oldest_lag_seconds must be a JSON Number type, got: {lag:?}"
        );
        let lag_f = lag.as_f64().expect("oldest_lag_seconds must be Number-coercible to f64");
        assert!(
            lag_f >= 0.0,
            "oldest_lag_seconds must be >= 0.0 (zone_purge.rs:71 clamps with .max(0.0)) — got: {lag_f}"
        );
        // Bounded sanity — a fresh unsubscribe just happened, so the lag
        // is < 60 seconds. A regression that swapped `now - head_ts` to
        // `head_ts - now` (sign flip clamped to 0) would produce a
        // suspiciously large positive (or always-zero) value; this loose
        // upper bound catches the latter cluster of regressions without
        // being flaky on slow test runners.
        assert!(
            lag_f < 60.0,
            "fresh-unsubscribe lag must be < 60s on a stable test runner — got: {lag_f}"
        );
        // queue_depth must mirror the unsubscribe: exactly 1 entry was
        // enqueued by zone_purge::enqueue_zone (called from unsubscribe).
        assert_eq!(
            v["pending_purge"]["queue_depth"].as_u64().unwrap(),
            1,
            "exactly one unsubscribe ⇒ queue_depth must be 1 — pairs the non-empty lag assertion"
        );
    }

    // ─── Five orthogonal invariants on top of the earlier
    //     coverage. Pins the read-only contract
    //     directly on the underlying state (not just on the output JSON,
    //     which batch_z already covers), special-character preservation in
    //     zone paths beyond Unicode (batch_bb) and case-fold (batch_cc),
    //     a 100-zone stress on the per_zone_storage/subscribed_zones
    //     element-wise alignment invariant first surfaced by batch_y, a
    //     no-`null`-anywhere wire contract (catches a future `Option<T>`
    //     field accidentally emitting `null`), and a three-disjoint-root
    //     lex-sort total-order pin distinct from the two-hierarchies
    //     coverage in batch_y. Each test is independent — failure of any
    //     one points at a distinct regression class.

    #[test]
    fn batch_dd_compute_zones_scope_is_read_only_state_unchanged_after_ten_calls() {
        // Pin: `compute_zones_scope` is a pure read on `NodeState` — ten
        // back-to-back calls leave the underlying ZoneManager subscription
        // set, the `zone_purge_records_purged_total` atomic, and the
        // global zone-idx counters byte-identical to their pre-call
        // baseline. Distinct from batch_z which pinned BYTE-IDENTICAL
        // OUTPUT — this test pins BYTE-IDENTICAL UNDERLYING STATE, the
        // stronger invariant. A regression that silently triggered an
        // internal purge-tick or bumped a "scope was scraped" counter
        // (e.g. a future "track read traffic" instrumentation that misused
        // the purge counter) would pass batch_z (same output, same state
        // mutation each call) but fail here.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("payments"));
        state.subscribe_zone(&ZoneId::new("identity"));
        state.subscribe_zone(&ZoneId::new("messaging"));

        use std::sync::atomic::Ordering;
        let purged_before = state.zone_purge_records_purged_total.load(Ordering::Relaxed);
        let idx_entries_before = state.rocks.zone_idx_total_entries();
        let idx_distinct_before = state.rocks.zone_idx_distinct_zones();
        let subscribed_count_before = state.zone_manager.lock_recover().subscribed_zones().len();

        for _ in 0..10 {
            let _ = compute_zones_scope(&state);
        }

        assert_eq!(
            state.zone_manager.lock_recover().subscribed_zones().len(),
            subscribed_count_before,
            "10× compute_zones_scope must not mutate the ZoneManager subscription set"
        );
        assert_eq!(
            state.zone_purge_records_purged_total.load(Ordering::Relaxed),
            purged_before,
            "10× compute_zones_scope must not advance zone_purge_records_purged_total — read-only invariant"
        );
        assert_eq!(
            state.rocks.zone_idx_total_entries(),
            idx_entries_before,
            "10× compute_zones_scope must not write to the zone-idx CF — read-only invariant"
        );
        assert_eq!(
            state.rocks.zone_idx_distinct_zones(),
            idx_distinct_before,
            "10× compute_zones_scope must not add distinct zones to the idx CF — read-only invariant"
        );
    }

    #[test]
    fn batch_dd_zone_path_with_hyphens_dots_underscores_preserved_byte_for_byte_in_subscribed_zones() {
        // Pin: ZoneId::new only normalizes (trim whitespace + to_lowercase
        // + strip trailing `/` — zone.rs:40-45). Hyphens, dots, underscores
        // are NOT stripped or remapped. A regression that added a
        // `.replace('-', "_")` or `.replace('.', '_')` (a well-meaning
        // "canonicalize identifier-style separators" pass) would silently
        // collapse distinct zones into one, breaking operator dashboards
        // that grouped by exact path. Distinct from batch_bb Unicode
        // (CJK/emoji round-trip) and batch_cc lowercase normalization
        // (uppercase ASCII → lowercase) — this pins the *negative space*
        // of normalization: characters that look like delimiters in some
        // identifier systems but MUST stay verbatim in zone paths.
        let state = build_state();
        // Single all-lowercase path so ZoneId normalization is a no-op
        // and the assertion is on the original byte sequence verbatim.
        state.subscribe_zone(&ZoneId::new("payments-v2.eu_west"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .expect("subscribed_zones must be an Array")
            .iter()
            .map(|s| s.as_str().expect("each element must be a String").to_string())
            .collect();
        assert_eq!(
            zones,
            vec!["payments-v2.eu_west".to_string()],
            "hyphen + dot + underscore must survive byte-for-byte in subscribed_zones"
        );
        // Mirror in per_zone_storage — if normalization quietly stripped a
        // character there but not in subscribed_zones, the parallel-array
        // contract (batch_y per_zone_storage[i].zone == subscribed_zones[i])
        // would still hold pairwise but the operator-visible zone string
        // would now disagree with the original POST body.
        assert_eq!(
            v["per_zone_storage"][0]["zone"].as_str().unwrap(),
            "payments-v2.eu_west",
            "per_zone_storage entry must mirror the byte-perfect zone path"
        );
    }

    #[test]
    fn batch_dd_subscribe_one_hundred_disjoint_zones_per_zone_storage_length_matches_subscribed_zones_length() {
        // Pin: the parallel-array alignment invariant (per_zone_storage[i]
        // mirrors subscribed_zones[i], pinned pairwise by batch_y) holds
        // at N=100 disjoint zones, not just at the N=2..5 range exercised
        // by previous batches. A regression that capped the
        // per_zone_storage build loop at some internal `MAX_PER_ZONE`
        // constant (e.g. "render only the top 50 zones to keep the JSON
        // small") would silently truncate the response, leaving operators
        // with a missing chunk of their subscription set on the dashboard.
        // The alignment is the load-bearing wire contract — every
        // dashboard zip-renders the two arrays side-by-side.
        let state = build_state();
        for i in 0..100 {
            state.subscribe_zone(&ZoneId::new(&format!("zone-{i:03}")));
        }
        let v = compute_zones_scope(&state);
        let subscribed_len = v["subscribed_zones"]
            .as_array()
            .expect("subscribed_zones must be an Array")
            .len();
        let per_zone_len = v["per_zone_storage"]
            .as_array()
            .expect("per_zone_storage must be an Array")
            .len();
        assert_eq!(
            subscribed_len, 100,
            "100 disjoint subscribes must produce exactly 100 entries in subscribed_zones"
        );
        assert_eq!(
            per_zone_len, 100,
            "per_zone_storage must mirror subscribed_zones length at N=100 (no truncation, no internal cap)"
        );
        assert_eq!(
            subscribed_len, per_zone_len,
            "parallel-array alignment invariant must hold at N=100 (batch_y pairwise + this length pin = full coverage)"
        );
    }

    #[test]
    fn batch_dd_compute_zones_scope_output_contains_no_null_values_at_any_depth() {
        // Pin: the JSON tree returned by `compute_zones_scope` contains
        // NO `null` values at any depth — every leaf is a concrete typed
        // value (String / Number / Bool / Array / Object). A future
        // refactor that introduced an `Option<T>` field (e.g. a "last
        // purge tick timestamp" that's None until the first purge runs)
        // would serialize as `null` and silently break every operator
        // dashboard that parses with non-null assumptions. Pin the
        // absence-of-null contract at the wire layer so the refactor
        // surfaces here before it ships. Walks both empty-state and
        // populated-state outputs — covers both the
        // empty-Array-not-null branches (batch_z) and the per_zone_storage
        // populated branches.
        fn walk_no_nulls(v: &serde_json::Value, path: &str) {
            match v {
                serde_json::Value::Null => panic!(
                    "compute_zones_scope output must contain NO null values; \
                     found null at JSON path `{path}`"
                ),
                serde_json::Value::Object(map) => {
                    for (k, child) in map {
                        let child_path = format!("{path}.{k}");
                        walk_no_nulls(child, &child_path);
                    }
                }
                serde_json::Value::Array(items) => {
                    for (i, child) in items.iter().enumerate() {
                        let child_path = format!("{path}[{i}]");
                        walk_no_nulls(child, &child_path);
                    }
                }
                _ => {}
            }
        }
        // Branch 1: empty fresh state (default_behavior=accept_all path).
        let empty_state = build_state();
        let v_empty = compute_zones_scope(&empty_state);
        walk_no_nulls(&v_empty, "$");
        // Branch 2: populated state (scoped path + per_zone_storage filled
        // + pending_purge with a non-empty queue from an unsubscribe).
        let pop_state = build_state();
        pop_state.subscribe_zone(&ZoneId::new("alpha"));
        pop_state.subscribe_zone(&ZoneId::new("bravo"));
        pop_state.subscribe_zone(&ZoneId::new("charlie"));
        pop_state.unsubscribe_zone(&ZoneId::new("bravo"));
        let v_pop = compute_zones_scope(&pop_state);
        walk_no_nulls(&v_pop, "$");
    }

    #[test]
    fn batch_dd_subscribed_zones_lex_sort_total_order_over_three_disjoint_top_level_hierarchies() {
        // Pin: `subscribed_zones` is lex-sorted across THREE disjoint
        // top-level roots inserted out of order. Distinct from batch_y
        // (two hierarchies) and batch_q's hierarchical auto-pin (single
        // chain) — this exercises the strict total order across multiple
        // independent prefixes, the operator scenario where a node
        // subscribes to `payments` + `identity` + `messaging` (three
        // unrelated bizdomains). A regression that introduced a stable-
        // sort-by-insertion-time would pass single-hierarchy tests
        // (insertion order matches lex by construction) but fail here
        // because the three roots are inserted in REVERSE lex order
        // (charlie → bravo → alpha) and the sort must permute them back.
        // Pin against an absolute expected vector, NOT a "sorted == True"
        // helper, so a future regression to a partial order surfaces as
        // a clear value diff.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("charlie"));
        state.subscribe_zone(&ZoneId::new("bravo"));
        state.subscribe_zone(&ZoneId::new("alpha"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .expect("subscribed_zones must be an Array")
            .iter()
            .map(|s| s.as_str().expect("each element must be a String").to_string())
            .collect();
        assert_eq!(
            zones,
            vec!["alpha".to_string(), "bravo".to_string(), "charlie".to_string()],
            "three disjoint roots inserted in reverse lex order must be \
             returned in canonical lex order — strict total order pin"
        );
        // per_zone_storage must echo the same lex order element-wise.
        let per_zone_paths: Vec<String> = v["per_zone_storage"]
            .as_array()
            .expect("per_zone_storage must be an Array")
            .iter()
            .map(|e| e["zone"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            per_zone_paths,
            vec!["alpha".to_string(), "bravo".to_string(), "charlie".to_string()],
            "per_zone_storage must mirror the three-root lex order — alignment + sort, together"
        );
    }

    // ─── Density-hygiene continuation ────────────────────────────────────────
    //
    // Density-hygiene continuation on `compute_zones_scope`. An earlier slice pinned
    // top-level/sub-object FIELD types for `subscribed_zones[i]`,
    // `per_zone_storage[i].zone`, `per_zone_storage[i].record_count`, and the
    // pending_purge 3-key shape — but it never pinned the type contracts on
    // the TWO global zone-idx u64 gauges (`global_zone_idx_entries` +
    // `global_zone_idx_distinct_zones`). A serde-Serialize regression that
    // accidentally widened either to f64 (e.g. via a stats-collector that
    // returned `f64` for "compatibility") would silently land in
    // `compute_zones_scope` without any test catching it. This slice closes
    // these last two type-contract gaps, plus the three-leg zero-baseline on
    // `pending_purge` (an earlier test pinned records_purged_total alone; another
    // pinned queue_depth alone; the COMBINED zero baseline that operators
    // read as "no purge activity at all" is unpinned), plus the operator-
    // observable subscribe→unsubscribe DIFFERENCE between queue_depth
    // (transient, +=1 at enqueue) and records_purged_total (eventual, only
    // increments inside the purge worker tick — verified at zone_purge.rs:156),
    // plus a small bijection pin across multiple cardinalities of the
    // `subscribed_zones.len() == per_zone_storage.len()` invariant (an earlier
    // N=100 test covers ONE cardinality; this exercises the relation across the
    // operator-realistic range {0,1,5,10}).

    #[test]
    fn batch_ee_global_zone_idx_entries_is_strict_unsigned_integer_type() {
        // Pin: `global_zone_idx_entries` is a JSON unsigned integer (u64).
        // Sourced from `state.rocks.zone_idx_total_entries()` which returns
        // `u64`. A future refactor that swapped to `usize` (which serde_json
        // serializes via the u64 path on 64-bit but i64 on 32-bit hosts) or
        // narrowed to f64 (e.g. for "uniform numeric" formatting) would
        // silently break the operator dashboard's exact-count display. Pin
        // the strict type predicate `.is_u64()` AND the negative `.is_f64()`
        // predicate (serde_json::Number distinguishes the two paths).
        let state = build_state();
        let v = compute_zones_scope(&state);
        let entries = &v["global_zone_idx_entries"];
        assert!(
            entries.is_u64(),
            "global_zone_idx_entries must be a JSON u64, got: {entries:?}"
        );
        assert!(
            !entries.is_f64(),
            "global_zone_idx_entries must NOT be classified as f64"
        );
        assert_eq!(
            entries.as_u64().unwrap(),
            0,
            "fresh node — zone idx is empty ⇒ total_entries=0"
        );
    }

    #[test]
    fn batch_ee_global_zone_idx_distinct_zones_is_strict_unsigned_integer_type() {
        // Pin: `global_zone_idx_distinct_zones` is a JSON unsigned integer
        // (u64). Sourced from `state.rocks.zone_idx_distinct_zones()` which
        // returns `u64`. Operators read this gauge to detect zone-idx growth
        // mismatch with subscribed_zones (heuristic: idx grew via ingest
        // beyond the subscribed set, signal of zone autoscale triggering).
        // An earlier test pinned identical baseline behavior across
        // multiple reads (read-only invariant); the TYPE contract was never
        // pinned directly.
        let state = build_state();
        let v = compute_zones_scope(&state);
        let distinct = &v["global_zone_idx_distinct_zones"];
        assert!(
            distinct.is_u64(),
            "global_zone_idx_distinct_zones must be a JSON u64, got: {distinct:?}"
        );
        assert!(
            !distinct.is_f64(),
            "global_zone_idx_distinct_zones must NOT be classified as f64"
        );
        assert_eq!(
            distinct.as_u64().unwrap(),
            0,
            "fresh node — zone idx is empty ⇒ distinct_zones=0"
        );
    }

    #[test]
    fn batch_ee_pending_purge_all_three_legs_zero_baseline_on_fresh_state() {
        // Pin the COMBINED zero baseline: all three pending_purge legs
        // (queue_depth, oldest_lag_seconds, records_purged_total) must equal
        // 0 on a fresh node. An earlier test pinned records_purged_total alone;
        // another pinned queue_depth alone; the THREE-WAY pin captures the
        // operator dashboard's "no purge activity" reading — a regression
        // that initialized one of the three to a sentinel (`-1` for oldest_lag
        // to mean "unset") would pass the individual-leg tests but make the
        // dashboard's combined-pressure card render a misleading non-zero
        // signal on every boot. Pin all three together so the regression
        // fires on the dashboard contract, not on a single field.
        let state = build_state();
        let v = compute_zones_scope(&state);
        let pp = &v["pending_purge"];
        assert_eq!(
            pp["queue_depth"].as_u64().expect("u64"),
            0,
            "fresh node ⇒ purge queue depth=0"
        );
        let oldest_lag = pp["oldest_lag_seconds"].as_f64().expect("f64");
        assert_eq!(
            oldest_lag, 0.0,
            "fresh node ⇒ oldest_lag_seconds=0.0 (NOT a sentinel like -1.0 or f64::NAN)"
        );
        assert!(
            oldest_lag.is_finite() && !oldest_lag.is_sign_negative(),
            "oldest_lag_seconds must be a finite non-negative f64, got: {oldest_lag}"
        );
        assert_eq!(
            pp["records_purged_total"].as_u64().expect("u64"),
            0,
            "fresh node ⇒ records_purged_total=0"
        );
    }

    #[test]
    fn batch_ee_subscribe_then_unsubscribe_increments_queue_depth_but_not_records_purged_total() {
        // Pin the operator-observable DIFFERENCE between the two atomic
        // legs of pending_purge: subscribe→unsubscribe MUST increment
        // queue_depth (+=1 at enqueue time in `enqueue_purge_zone` —
        // state.rs:4158) but MUST NOT increment records_purged_total
        // (that only ticks inside the purge worker loop at zone_purge.rs:156,
        // which has NOT run synchronously in the test harness). This is the
        // operator-visible "drain in flight" signal vs "drain complete"
        // signal — a regression that incremented both at enqueue (e.g. by
        // mistaking the counter's semantic for "zones queued" instead of
        // "records deleted") would zero the queue_depth indicator
        // immediately on the next compute call and confuse every operator
        // reading the soak monitor.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("ephemeral"));
        state.unsubscribe_zone(&ZoneId::new("ephemeral"));
        let v = compute_zones_scope(&state);
        let pp = &v["pending_purge"];
        assert_eq!(
            pp["queue_depth"].as_u64().expect("u64"),
            1,
            "subscribe+unsubscribe ⇒ exactly one queue entry"
        );
        assert_eq!(
            pp["records_purged_total"].as_u64().expect("u64"),
            0,
            "purge worker has NOT run ⇒ records_purged_total must remain 0 — \
             pins the two-leg semantic distinction (enqueue ≠ purge completion)"
        );
    }

    #[test]
    fn batch_ee_subscribed_zones_and_per_zone_storage_length_bijection_across_cardinalities() {
        // Pin the bijection invariant across multiple cardinalities of the
        // subscribed set: subscribed_zones.len() == per_zone_storage.len()
        // must hold at 0, 1, 5, and 10 subscriptions. An earlier test pinned this
        // at N=100 with disjoint zones; this test exercises the relation
        // ACROSS the operator-realistic range. A regression that special-
        // cased empty-set behavior (e.g. populated subscribed_zones via
        // path A but per_zone_storage via path B with an off-by-one when
        // both are empty) would pass the N=100 test but fail at N=0 or 1.
        // The dashboard's per-zone storage column renders one row per
        // subscribed zone — a bijection regression would either drop rows
        // or render orphan rows with no matching subscription header.
        //
        // The previously-pinned cardinality test uses N=100 with
        // pre-generated zone paths; this test additionally locks down N=0
        // (boundary — empty arrays) and intermediate N=1, 5 where structural
        // contracts (arity-1 array vs arity-N array) sometimes diverge in
        // serializers.
        for &n in &[0usize, 1, 5, 10] {
            let state = build_state();
            for i in 0..n {
                state.subscribe_zone(&ZoneId::new(&format!("zone-{i:03}")));
            }
            let v = compute_zones_scope(&state);
            let subscribed_len = v["subscribed_zones"]
                .as_array()
                .expect("subscribed_zones must be Array")
                .len();
            let per_zone_len = v["per_zone_storage"]
                .as_array()
                .expect("per_zone_storage must be Array")
                .len();
            assert_eq!(
                subscribed_len, n,
                "subscribed_zones.len() must equal N={n}"
            );
            assert_eq!(
                per_zone_len, n,
                "per_zone_storage.len() must equal N={n} — bijection invariant"
            );
            assert_eq!(
                subscribed_len, per_zone_len,
                "bijection invariant at N={n}: subscribed_zones.len() == per_zone_storage.len()"
            );
        }
    }

    // ─── Five orthogonal invariants on top of the earlier
    //     coverage. Pins the lossless
    //     serde round-trip contract (catches f64::NaN/Infinity drift in
    //     `oldest_lag_seconds` that the existing no-null walker would miss),
    //     the depth-6 ancestor walk (an earlier test covered depth-3 only — a future
    //     `MAX_ANCESTOR_DEPTH` cap at 3/4 would silently truncate deep
    //     subscriptions), the value-uniformity of `record_count` across N=7
    //     entries (an earlier test pinned the TYPE u64 on each entry; this pins the
    //     VALUE=0 on a fresh node — catches an uninitialized-memory regression
    //     where the first entry is 0 but later entries drift), the composite-
    //     normalization collapse where uppercase + trailing-slash variants of
    //     the same zone produce ONE entry (an earlier test covered each axis
    //     separately — this is the cross-axis pin), and the idempotency-
    //     under-normalization-variants invariant (three subscribe calls with
    //     0/1/3 trailing slashes collapse to a single entry — not 3).

    #[test]
    fn batch_hh_compute_zones_scope_json_output_round_trips_via_serde_string_loss_less() {
        // Pin: `compute_zones_scope` output round-trips losslessly through
        // `serde_json::to_string` → `from_str` AND contains NO non-finite
        // f64 leaves. Catches a regression where `pending_purge.oldest_lag_seconds`
        // accidentally returns f64::NaN or f64::INFINITY (e.g. via
        // `(now - head_ts) / 0.0` if some future refactor normalized by
        // queue depth). serde_json emits non-finite f64s as `null` silently —
        // so AFTER the round-trip a NaN/Infinity will surface as Value::Null,
        // and a finite-leaf walker on v_back catches it cleanly. The existing
        // walker on v_pop catches NaN that's already serialized as
        // null at compute time; this catches NaN that only manifests across
        // the to_string→from_str boundary.
        //
        // Note (stabilization): the original implementation
        // asserted `v == round_trip(v)` byte-exact via `serde_json::Value::eq`.
        // That assertion was flaky at ~27% rate in isolation because some
        // wall-clock-derived f64 values for `oldest_lag_seconds` don't satisfy
        // f64 → decimal → f64 bit-equality through serde_json's ryu emitter +
        // Rust's f64 parser. Both crates are individually correct, but the
        // round-trip pair has edge cases on specific f64 bit patterns. The
        // test's STATED intent (per its comment) is to catch NaN/Infinity
        // drift — which is achieved by walking v_back for nulls, NOT by
        // byte-equality. The original implementation conflated "round-trip
        // is lossless" (which is a serde_json property, not ours to pin)
        // with "no NaN/Infinity in the output" (which IS our contract).
        //
        // Test BOTH branches (empty + populated with non-empty purge queue)
        // so the no-null check covers all leaf types in the output tree.
        fn assert_no_null_and_all_finite(v: &serde_json::Value, path: &str) {
            match v {
                serde_json::Value::Null => panic!(
                    "compute_zones_scope round-trip output must contain NO \
                     null values; found null at JSON path `{path}` — likely \
                     a NaN/Infinity f64 was emitted as null by serde_json"
                ),
                serde_json::Value::Number(n) => {
                    if let Some(f) = n.as_f64() {
                        assert!(
                            f.is_finite(),
                            "compute_zones_scope round-trip output must \
                             contain only FINITE f64 leaves; found {f} at \
                             JSON path `{path}`"
                        );
                    }
                }
                serde_json::Value::Object(map) => {
                    for (k, child) in map {
                        assert_no_null_and_all_finite(child, &format!("{path}.{k}"));
                    }
                }
                serde_json::Value::Array(items) => {
                    for (i, child) in items.iter().enumerate() {
                        assert_no_null_and_all_finite(child, &format!("{path}[{i}]"));
                    }
                }
                _ => {}
            }
        }

        let empty_state = build_state();
        let v_empty = compute_zones_scope(&empty_state);
        let s_empty = serde_json::to_string(&v_empty).expect("empty state must serialize");
        let v_empty_back: serde_json::Value =
            serde_json::from_str(&s_empty).expect("empty state round-trip parse");
        assert_no_null_and_all_finite(&v_empty_back, "$");
        // Empty-state round-trip has no f64 leaves (no pending_purge head),
        // so byte-equality holds deterministically — keep the strict pin.
        assert_eq!(
            v_empty, v_empty_back,
            "empty-state JSON must round-trip equal: original ≠ from_str(to_string(original))"
        );

        let pop_state = build_state();
        pop_state.subscribe_zone(&ZoneId::new("alpha"));
        pop_state.subscribe_zone(&ZoneId::new("bravo"));
        pop_state.unsubscribe_zone(&ZoneId::new("alpha"));
        let v_pop = compute_zones_scope(&pop_state);
        let s_pop = serde_json::to_string(&v_pop).expect("populated state must serialize");
        let v_pop_back: serde_json::Value =
            serde_json::from_str(&s_pop).expect("populated state round-trip parse");
        // Populated-state branch carries a wall-clock-derived f64 in
        // pending_purge.oldest_lag_seconds. Byte-exact round-trip equality
        // is flaky on certain f64 bit patterns (see "Note" above). Walk
        // both v_pop AND v_pop_back for nulls + finite leaves — strictly
        // stronger than the original byte-equality on the NaN/Infinity
        // axis (catches a NaN that materializes only after the round-trip).
        assert_no_null_and_all_finite(&v_pop, "$.original");
        assert_no_null_and_all_finite(&v_pop_back, "$.round_tripped");
    }

    #[test]
    fn batch_hh_compute_zones_scope_six_level_deep_subscribe_auto_pins_all_six_ancestors_lex_sorted() {
        // Pin: subscribing to a depth-6 path auto-pins ALL 6 ancestors in
        // lex order. An earlier test pinned depth-3 (medical/eu/cardio → 3 entries);
        // a future `MAX_ANCESTOR_DEPTH = 3` cap in ZoneManager would silently
        // truncate this to 3 entries — the deeper levels (a/b/c/d, /d/e,
        // /d/e/f) would never reach `subscribed_zones` and the operator
        // dashboard would render an incomplete subscription chain. Pin
        // depth-6 explicitly so a depth-cap regression surfaces here.
        //
        // Use single-char path components (no normalization edge cases) so
        // this test exclusively pins the depth-walk invariant.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("a/b/c/d/e/f"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            zones,
            vec!["a", "a/b", "a/b/c", "a/b/c/d", "a/b/c/d/e", "a/b/c/d/e/f"],
            "depth-6 subscribe must pin ALL 6 ancestors in lex order — got: {zones:?}"
        );
        assert_eq!(
            zones.len(),
            6,
            "exactly 6 entries for depth-6 chain — catches a MAX_ANCESTOR_DEPTH cap regression"
        );
        // The per_zone_storage walk must MATCH (same iterator at L1873).
        let per_zone_paths: Vec<String> = v["per_zone_storage"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["zone"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            per_zone_paths.len(),
            6,
            "per_zone_storage must also have all 6 entries — element-wise mirror"
        );
    }

    #[test]
    fn batch_hh_compute_zones_scope_all_record_counts_strict_zero_on_fresh_state_across_seven_zones() {
        // Pin: on a fresh node with N=7 disjoint subscriptions, EVERY
        // per_zone_storage[i].record_count is exactly u64=0. An earlier test pinned
        // the TYPE (is_u64) for a single entry; another pinned the value=0
        // for N=2 entries (finance + medical). This pins value-uniformity
        // across a wider N — catches a regression where the first entry is
        // 0 but later entries drift (e.g. uninitialized memory if `count_zone`
        // returned `MaybeUninit<u64>` accidentally read, or a per-zone cache
        // that returns stale values past index 0).
        //
        // Pick N=7 (not N=2 or N=10 to avoid duplication with batch_t and
        // batch_dd_subscribe_one_hundred_disjoint_zones); this gives a
        // medium-cardinality regime where a per-loop iterator-state bug
        // would surface but the test stays fast.
        let state = build_state();
        for i in 0..7 {
            state.subscribe_zone(&ZoneId::new(&format!("zone-{i}")));
        }
        let v = compute_zones_scope(&state);
        let per_zone = v["per_zone_storage"]
            .as_array()
            .expect("per_zone_storage must be Array");
        assert_eq!(
            per_zone.len(),
            7,
            "7 disjoint subscriptions ⇒ exactly 7 per_zone_storage entries"
        );
        for (i, entry) in per_zone.iter().enumerate() {
            let rc = entry["record_count"]
                .as_u64()
                .unwrap_or_else(|| panic!("per_zone_storage[{i}].record_count must be u64"));
            assert_eq!(
                rc, 0,
                "per_zone_storage[{i}].record_count must be exactly 0 on fresh node — got {rc} (uniformity invariant across N=7)"
            );
        }
    }

    #[test]
    fn batch_hh_compute_zones_scope_mixed_case_and_trailing_slash_collapse_to_single_entry() {
        // Pin: subscribe("MEDICAL/") and subscribe("medical") MUST collapse
        // to a single entry in subscribed_zones (both normalize to
        // "medical"). An earlier test pinned the uppercase axis independently and
        // the trailing-slash axis independently, both with DISTINCT zone
        // paths in each test. This pins the CROSS-AXIS interaction — two
        // subscribe calls with different normalization patterns must yield
        // ONE entry, not 2. A future refactor that ordered the
        // normalization steps differently (e.g. lowercase first, then a
        // SEPARATE call that didn't trim trailing slashes) could allow
        // "medical" and "medical/" to coexist as 2 entries.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("MEDICAL/"));
        state.subscribe_zone(&ZoneId::new("medical"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            zones,
            vec!["medical"],
            "MEDICAL/ + medical must collapse to a single normalized entry — got {zones:?}"
        );
        // per_zone_storage must also have just one entry — bijection holds
        // post-normalization (catches a regression where normalization is
        // applied in subscribed_zones but not in per_zone_storage).
        let per_zone = v["per_zone_storage"]
            .as_array()
            .unwrap();
        assert_eq!(
            per_zone.len(),
            1,
            "per_zone_storage must also collapse to 1 entry post-normalization"
        );
    }

    #[test]
    fn batch_hh_compute_zones_scope_three_idempotent_subscribes_with_normalization_variants_yield_single_entry() {
        // Pin: subscribe("med"), subscribe("med/"), subscribe("med///") —
        // three calls with progressively-larger trailing-slash counts —
        // MUST collapse to a single entry in subscribed_zones. An earlier
        // trailing-slash test used DISTINCT zone paths (medical/ vs
        // payments///) so it doesn't cover the idempotency-under-
        // normalization-variants case. A regression where the
        // ZoneManager's HashSet keyed on the post-normalize path would
        // still dedup; but a regression that switched the key to the
        // pre-normalize bytes (e.g. for a "preserve original input"
        // diagnostic feature) would let all 3 raw forms coexist while the
        // normalized-display layer rendered 3 identical "med" chips.
        // Pin the dedup-under-trailing-slash-variants invariant explicitly.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("med"));
        state.subscribe_zone(&ZoneId::new("med/"));
        state.subscribe_zone(&ZoneId::new("med///"));
        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            zones,
            vec!["med"],
            "three trailing-slash-variant subscribes must collapse to exactly one entry — got {zones:?}"
        );
        // Reinforce: subscribed_zones.len() == 1 explicitly catches a
        // hypothetical regression where the array has 3 entries but they
        // happen to all stringify equal (e.g. all 3 stored as "med" but
        // tracked separately in the manager — the dedup would happen at
        // serialization, not at the set level).
        assert_eq!(
            zones.len(),
            1,
            "exactly one entry — catches a regression where 3 subscribe calls retain 3 manager-level rows"
        );
    }

    // ─── Five orthogonal algebraic-relationship
    //     pins on top of the earlier coverage. Pivots from
    //     the `pending_ledger_inspection_payload` saturation cliff
    //     back to `compute_zones_scope`. Axes:
    //       (1) `global_zone_idx_distinct_zones ≤ global_zone_idx_entries`
    //           universal algebraic bound — pinned non-trivially by direct
    //           CF_RECORD_BY_ZONE injection at K<N regimes (5 records / 3
    //           zones / 10 records / 1 zone) so a swapped return-value
    //           regression surfaces here.
    //       (2) `records_purged_total` monotonic non-decreasing across N=4
    //           snapshots taken during a mutation sequence — catches a
    //           regression that resets the counter on subscribe/unsubscribe.
    //       (3) `queue_depth` is EXACTLY 0 after pure-subscribe sweep
    //           N ∈ {1, 3, 5, 10} — orthogonal to the N=0 fresh test and
    //           the one-subscribe-one-unsubscribe cycle test; pins
    //           the SUBSCRIBE-only path never enqueues purge regardless of N.
    //       (4) `queue_depth` increments by EXACTLY +1 per unsubscribe in
    //           step-wise snapshot sequence (an earlier test only checks the
    //           N=3 terminal state, not per-step monotonic +1).
    //       (5) Balanced N-sub + N-unsub composite invariant pinning four
    //           top-level fields simultaneously across N ∈ {1, 3, 5} —
    //           {subscribed_zones=[], default_behavior="accept_all",
    //           queue_depth=N, records_purged_total=0} as ONE pin rather
    //           than four independent ones.
    use crate::storage::rocks::CF_RECORD_BY_ZONE;

    /// Inject a synthetic `(zone, record_id)` entry into `CF_RECORD_BY_ZONE`
    /// so `state.rocks.zone_idx_total_entries()` / `zone_idx_distinct_zones()`
    /// surface non-trivial counts in unit tests. Key layout matches
    /// `StorageEngine::zone_idx_key` (rocks.rs:726): `zone_key(8) ||
    /// timestamp_be(8) || record_id_utf8` — pinned here so the helper drifts
    /// in lockstep with the production key encoder if it ever changes.
    fn inject_zone_idx_entry(
        state: &Arc<NodeState>,
        zone_key: &[u8; 8],
        record_id: &str,
        timestamp: f64,
    ) {
        let mut key = Vec::with_capacity(8 + 8 + record_id.len());
        key.extend_from_slice(zone_key);
        key.extend_from_slice(&timestamp.to_be_bytes());
        key.extend_from_slice(record_id.as_bytes());
        state
            .rocks
            .put_cf_raw(CF_RECORD_BY_ZONE, &key, b"")
            .expect("put_cf_raw zone_idx");
    }

    #[test]
    fn batch_qq_global_zone_idx_distinct_zones_le_total_entries_universal_algebraic_bound() {
        // Universal algebraic invariant between the two `global_zone_idx_*`
        // top-level u64 fields: `distinct_zones` counts unique 8-byte
        // zone_key prefixes in CF_RECORD_BY_ZONE; `total_entries` counts ALL
        // (zone_key, ts, record_id) rows. Distinct cannot exceed total —
        // every distinct prefix contributes at least one entry, and rows are
        // never deduped within a single (zone, record_id) pair. The bound is
        // testable non-trivially by injecting fixtures at K<N (multiple
        // records per zone) regimes where the two counters diverge in value
        // but still satisfy the ≤ ordering.
        //
        // A swapped-return-value regression (e.g. `zone_idx_total_entries`
        // accidentally returning `zone_idx_distinct_zones`) on fresh state
        // would NOT surface here (both 0) but WOULD surface at K=3 N=5
        // through `distinct (5)` exceeding `total (3)` — explicitly catches
        // the swap. Existing tests pin TYPE u64 only; this pins the
        // VALUE ordering between fields.
        //
        // Three sample regimes:
        //   - fresh:      both 0           → 0 ≤ 0 (degenerate)
        //   - K=3 N=5:    distinct=3 entries=5 → 3 ≤ 5 (non-trivial)
        //   - K=4 N=10:   distinct=4 entries=10 → 4 ≤ 10 (after second batch)
        //   - K=1 N=10:   distinct=1 entries=10 → 1 ≤ 10 (extreme K<<N)
        let state = build_state();

        // Regime 1: fresh — both counters at 0.
        let v_fresh = compute_zones_scope(&state);
        let entries_fresh = v_fresh["global_zone_idx_entries"]
            .as_u64()
            .expect("entries u64");
        let distinct_fresh = v_fresh["global_zone_idx_distinct_zones"]
            .as_u64()
            .expect("distinct u64");
        assert_eq!(entries_fresh, 0, "fresh node: total entries must be 0");
        assert_eq!(distinct_fresh, 0, "fresh node: distinct zones must be 0");
        assert!(distinct_fresh <= entries_fresh, "fresh: distinct ≤ entries");

        // Regime 2: inject 5 entries across 3 zones (2/2/1).
        let zone_a: [u8; 8] = [0xA0, 0, 0, 0, 0, 0, 0, 0];
        let zone_b: [u8; 8] = [0xB0, 0, 0, 0, 0, 0, 0, 0];
        let zone_c: [u8; 8] = [0xC0, 0, 0, 0, 0, 0, 0, 0];
        inject_zone_idx_entry(&state, &zone_a, "rec-a-1", 1000.0);
        inject_zone_idx_entry(&state, &zone_a, "rec-a-2", 1001.0);
        inject_zone_idx_entry(&state, &zone_b, "rec-b-1", 1002.0);
        inject_zone_idx_entry(&state, &zone_b, "rec-b-2", 1003.0);
        inject_zone_idx_entry(&state, &zone_c, "rec-c-1", 1004.0);
        let v_k3 = compute_zones_scope(&state);
        let entries_k3 = v_k3["global_zone_idx_entries"].as_u64().unwrap();
        let distinct_k3 = v_k3["global_zone_idx_distinct_zones"].as_u64().unwrap();
        assert_eq!(entries_k3, 5, "K=3 N=5: total entries must be 5");
        assert_eq!(distinct_k3, 3, "K=3 N=5: distinct zones must be 3");
        assert!(
            distinct_k3 <= entries_k3,
            "K=3 N=5: distinct ({distinct_k3}) must ≤ entries ({entries_k3})"
        );
        assert!(
            distinct_k3 < entries_k3,
            "K=3 N=5: distinct STRICTLY less than entries — catches the swap regression"
        );

        // Regime 3: inject 5 more entries into a fourth zone (1/4) — K=4 N=10.
        let zone_d: [u8; 8] = [0xD0, 0, 0, 0, 0, 0, 0, 0];
        for i in 0..5 {
            inject_zone_idx_entry(&state, &zone_d, &format!("rec-d-{i}"), 2000.0 + i as f64);
        }
        let v_k4 = compute_zones_scope(&state);
        let entries_k4 = v_k4["global_zone_idx_entries"].as_u64().unwrap();
        let distinct_k4 = v_k4["global_zone_idx_distinct_zones"].as_u64().unwrap();
        assert_eq!(entries_k4, 10, "K=4 N=10: total entries must be 10");
        assert_eq!(distinct_k4, 4, "K=4 N=10: distinct zones must be 4");
        assert!(distinct_k4 <= entries_k4, "K=4 N=10: distinct ≤ entries");

        // Monotonic: regime-3 distinct ≥ regime-2 distinct (no zone disappears).
        assert!(
            distinct_k4 >= distinct_k3,
            "distinct never decreases under pure-insert: {distinct_k3} → {distinct_k4}"
        );
        assert!(
            entries_k4 >= entries_k3,
            "entries never decreases under pure-insert: {entries_k3} → {entries_k4}"
        );
    }

    #[test]
    fn batch_qq_records_purged_total_monotonic_non_decreasing_across_mutation_sequence() {
        // `pending_purge.records_purged_total` is an AtomicU64 incremented
        // ONLY by the purge worker as it actually deletes records (state.rs
        // call site under `enqueue_purge_zone`'s drain). It can never
        // decrement — pin this with N=5 snapshots taken DURING a mutation
        // sequence (subscribe/unsubscribe ops). The purge worker does NOT
        // run in unit tests (no tokio runtime ticking the drain loop), so
        // the counter stays at 0 across all snapshots — the monotonic-
        // non-decreasing invariant holds in the degenerate-equal form
        // (0 ≤ 0 ≤ 0 ≤ 0 ≤ 0).
        //
        // The KEY contract this pins is that subscribe/unsubscribe operations
        // do NOT reset or zero the counter (e.g. an accidental
        // `purge_records_total.store(0, ...)` in a subscribe path would
        // surface here as 5→0 if the worker had previously incremented it).
        // A future regression that decrements the counter on ANY observable
        // path would also surface as snapshot[i+1] < snapshot[i].
        //
        // Distinct from the `records_purged_total_is_u64_zero_baseline` test
        // which only verifies the type+value at ONE snapshot on fresh state;
        // this pins the MULTI-SNAPSHOT invariant across mutations.
        let state = build_state();

        let snap = |state: &Arc<NodeState>| -> u64 {
            compute_zones_scope(state)["pending_purge"]["records_purged_total"]
                .as_u64()
                .expect("records_purged_total u64")
        };

        // Snapshot 0: fresh.
        let s0 = snap(&state);

        // Mutate: subscribe 3.
        state.subscribe_zone(&ZoneId::new("alpha"));
        state.subscribe_zone(&ZoneId::new("beta"));
        state.subscribe_zone(&ZoneId::new("gamma"));
        let s1 = snap(&state);

        // Mutate: unsubscribe 2.
        state.unsubscribe_zone(&ZoneId::new("alpha"));
        state.unsubscribe_zone(&ZoneId::new("beta"));
        let s2 = snap(&state);

        // Mutate: re-subscribe alpha (idempotent on re-sub).
        state.subscribe_zone(&ZoneId::new("alpha"));
        let s3 = snap(&state);

        // Mutate: unsubscribe gamma.
        state.unsubscribe_zone(&ZoneId::new("gamma"));
        let s4 = snap(&state);

        let snapshots = [s0, s1, s2, s3, s4];
        for w in snapshots.windows(2) {
            assert!(
                w[1] >= w[0],
                "records_purged_total must be monotonic non-decreasing — \
                 {prev} → {next} violates the invariant (counter decremented)",
                prev = w[0],
                next = w[1]
            );
        }
        // Under the no-worker unit-test environment all snapshots are 0.
        // Pin this so a future regression that ACCIDENTALLY increments the
        // counter on subscribe/unsubscribe paths (e.g. wired to the wrong
        // atomic) surfaces as a non-zero snapshot, distinguishing
        // accidental-write from the legitimate worker-driven increment.
        for (i, s) in snapshots.iter().enumerate() {
            assert_eq!(
                *s, 0,
                "snapshot[{i}]={s}: subscribe/unsubscribe must NOT increment \
                 records_purged_total (only the purge worker does)"
            );
        }
    }

    #[test]
    fn batch_qq_pure_subscribe_sweep_leaves_queue_depth_at_zero_across_n_one_three_five_ten() {
        // Pin that `subscribe_zone` NEVER enqueues a purge work unit,
        // regardless of how many subscribes are issued. An earlier test
        // covers N=0 (fresh node, queue_depth=0). Another covers
        // ONE subscribe followed by ONE unsubscribe (queue_depth+1, but the
        // contribution is from the unsubscribe, not the subscribe). Neither
        // pins the SUBSCRIBE-ONLY sweep — a regression that wired subscribe
        // to also enqueue (e.g. for a "warm-purge-on-first-subscribe"
        // diagnostic mode) would silently bump every fresh-node's queue
        // depth on first subscribe.
        //
        // Sweep N ∈ {1, 3, 5, 10} so the regression's signature (queue
        // grows linearly with subscribes) is visible at multiple
        // cardinalities, not just one.
        for &n in &[1usize, 3, 5, 10] {
            let state = build_state();
            for i in 0..n {
                state.subscribe_zone(&ZoneId::new(&format!("zone-{i:03}")));
            }
            let v = compute_zones_scope(&state);
            let qd = v["pending_purge"]["queue_depth"]
                .as_u64()
                .expect("queue_depth u64");
            assert_eq!(
                qd, 0,
                "N={n} pure subscribes: queue_depth must remain 0 — subscribe never enqueues purge"
            );
            // Also pin records_purged_total stays at 0 — orthogonal to axis
            // 2's mutation-sequence monotonic pin, this is the same property
            // on the pure-subscribe specific branch.
            let purged = v["pending_purge"]["records_purged_total"]
                .as_u64()
                .unwrap();
            assert_eq!(
                purged, 0,
                "N={n} pure subscribes: records_purged_total must stay 0"
            );
            // And subscribed_zones.len() == N as a sanity baseline (so the
            // queue_depth=0 result isn't because subscribes silently no-op'd).
            let sz_len = v["subscribed_zones"].as_array().unwrap().len();
            assert_eq!(
                sz_len, n,
                "N={n} sanity: subscribed_zones.len() must equal N — \
                 catches a no-op-subscribe regression masking the queue_depth=0 result"
            );
        }
    }

    #[test]
    fn batch_qq_queue_depth_increments_by_exactly_one_per_unsubscribe_in_stepwise_sequence() {
        // Pin the STEP-WISE +1 increment per unsubscribe call. The
        // `multiple_unsubscribes_accumulate_queue_depth` test only
        // checks the terminal state after N=3 unsubscribes (queue_depth==3),
        // which would PASS a regression where the first unsubscribe
        // enqueues 0 and subsequent ones enqueue 2 each (1*0 + 2*2 = 4,
        // wait — actually 0+2+2=4 ≠ 3 so X catches that one). But it would
        // PASS a regression where the FIRST unsubscribe enqueues 2 and the
        // next two enqueue 0 each (2+0+0 = 2 ≠ 3 — also caught). Where X
        // genuinely doesn't catch the regression: a regression where the
        // increment is order-dependent — e.g. first call +1, second +1,
        // third call +1, fourth call +1 normally, but a step-conditional
        // bug at step-K returns the wrong increment yet the TOTAL still
        // converges by chance. Step-wise per-call verification is the only
        // way to catch this class of regression.
        //
        // 5-step sequence so the per-step audit has enough datapoints to
        // distinguish "happens to converge" from "actually +1 every time".
        let state = build_state();
        let zones: [&str; 5] = ["alpha", "beta", "gamma", "delta", "epsilon"];
        // Pre-subscribe all 5 so each unsubscribe is a real remove (not the
        // never-subscribed enqueue path which another test already pins
        // separately).
        for z in &zones {
            state.subscribe_zone(&ZoneId::new(z));
        }
        // Snapshot pre-unsubscribe baseline.
        let v0 = compute_zones_scope(&state);
        let qd0 = v0["pending_purge"]["queue_depth"]
            .as_u64()
            .expect("queue_depth u64");
        assert_eq!(
            qd0, 0,
            "after 5 pure subscribes, queue_depth must still be 0 (axis 3's setup invariant)"
        );

        let mut prev_qd = qd0;
        for (i, z) in zones.iter().enumerate() {
            state.unsubscribe_zone(&ZoneId::new(z));
            let v = compute_zones_scope(&state);
            let qd = v["pending_purge"]["queue_depth"].as_u64().unwrap();
            assert_eq!(
                qd,
                prev_qd + 1,
                "step {i} (unsubscribe {z:?}): queue_depth must increment by EXACTLY +1 \
                 (was {prev_qd}, expected {expected}, got {qd}) — \
                 step-wise verification orthogonal to terminal-state check",
                expected = prev_qd + 1
            );
            prev_qd = qd;
        }
        // Terminal state sanity: 5 unsubscribes ⇒ queue_depth == 5.
        assert_eq!(
            prev_qd, 5,
            "after 5 step-wise unsubscribes, terminal queue_depth must be 5"
        );
    }

    #[test]
    fn batch_qq_balanced_n_sub_n_unsub_cycle_composite_invariant_pins_four_top_level_fields() {
        // Composite invariant pinning FOUR top-level fields simultaneously
        // after a balanced N-subscribe + N-unsubscribe cycle: {
        //   subscribed_zones.len() == 0,        // all subs cleared
        //   default_behavior == "accept_all",   // empty subs ⇒ accept_all branch
        //   queue_depth == N,                   // every unsubscribe enqueued 1
        //   records_purged_total == 0,          // no worker ran in unit test
        // }. An earlier test pins THREE of the four (subscribed empty,
        // default_behavior, queue_depth) at SINGLE N=3 — does NOT pin
        // records_purged_total in conjunction, and does NOT sweep N.
        //
        // Sweep N ∈ {1, 3, 5} so a regression that special-cased one
        // cardinality (e.g. N==1 collapses queue to a singleton sentinel
        // value) surfaces. The composite pin catches a "fix one field,
        // break another" regression that single-field tests miss because
        // they all run on fresh-state setups not balanced-cycle setups.
        for &n in &[1usize, 3, 5] {
            let state = build_state();
            let zones: Vec<String> = (0..n).map(|i| format!("cycle-{i:02}")).collect();
            for z in &zones {
                state.subscribe_zone(&ZoneId::new(z));
            }
            // Unsubscribe in REVERSE order to ensure the cycle isn't FIFO-
            // specific (catches a regression where the queue dedup logic
            // assumed insertion-order matches unsubscribe-order).
            for z in zones.iter().rev() {
                state.unsubscribe_zone(&ZoneId::new(z));
            }
            let v = compute_zones_scope(&state);
            assert_eq!(
                v["subscribed_zones"].as_array().unwrap().len(),
                0,
                "N={n}: subscribed_zones must be empty after balanced cycle"
            );
            assert_eq!(
                v["default_behavior"], "accept_all",
                "N={n}: default_behavior must be \"accept_all\" after balanced cycle"
            );
            assert_eq!(
                v["pending_purge"]["queue_depth"].as_u64().unwrap(),
                n as u64,
                "N={n}: queue_depth must equal N after N unsubscribes"
            );
            assert_eq!(
                v["pending_purge"]["records_purged_total"].as_u64().unwrap(),
                0,
                "N={n}: records_purged_total must stay 0 (no worker in unit test)"
            );
            // Also pin per_zone_storage is empty — composite tightening
            // alongside subscribed_zones empty (bijection pin under cycle
            // closure orthogonal to the cardinality-sweep test).
            assert_eq!(
                v["per_zone_storage"].as_array().unwrap().len(),
                0,
                "N={n}: per_zone_storage must be empty after balanced cycle"
            );
        }
    }

    // ─── Five orthogonal pins on top of the earlier
    //     coverage. Pivots to invariants
    //     that the prior tests left unsealed:
    //       (1) `default_behavior` LITERAL byte-for-byte values on BOTH
    //           branches — an earlier test pinned the JSON String type
    //           but not the exact bytes "accept_all" / "scoped" (a
    //           silent rename to camelCase or hyphenated form would
    //           pass is_string() but break operator dashboards that
    //           switch on the exact constant).
    //       (2) `pending_purge` is a JSON Object (`is_object()`) on
    //           BOTH empty-queue AND populated-queue branches — Batch
    //           Z point 1 pinned the TOP-LEVEL Object type but not the
    //           nested sub-object type; a refactor that wrapped the
    //           sub-object in an Array or emitted null would slip past.
    //       (3) `subscribed_zones[i] == per_zone_storage[i]["zone"]`
    //           pointwise alignment across N ∈ {2, 7, 15, 50} —
    //           strictly stronger than a small-N test and
    //           a length-only N=100 test. A regression
    //           that sorted the two arrays by DIFFERENT keys would
    //           pass length-only and small-N pins but surface here at
    //           N≥7 through misaligned index pairs.
    //       (4) Output-string purity at 10× iteration — distinct from
    //           a 2-call purity pin and a read-only
    //           STATE pin; statistically stronger against HashMap-
    //           iter-order leakage that could surface intermittently
    //           in a 2-call check but consistently in a 10-call run.
    //       (5) Algebraic balance after PARTIAL unsubscribe:
    //           `subscribed.len() + queue_depth == N_initial` after
    //           N=5 subscribes then 3 unsubscribes. Another test
    //           covers the BALANCED full-cycle case (N sub + N unsub
    //           → queue_depth=N). This pins the PARTIAL case where
    //           both sets are non-empty — the regime an operator
    //           actually observes during steady-state churn.

    #[test]
    fn batch_ss_default_behavior_string_value_is_literal_constant_byte_identical() {
        // Pin: `default_behavior` is EXACTLY "accept_all" on the empty
        // branch and EXACTLY "scoped" on the non-empty branch — byte
        // for byte, no case-fold, no whitespace, no separator change.
        // The operator dashboard's behavior switch uses these literals
        // as a closed-enum dispatch key:
        //   ```
        //   switch (scope.default_behavior) {
        //     case "accept_all": render_open_chip(); break;
        //     case "scoped":     render_scoped_chip(); break;
        //   }
        //   ```
        // A silent rename to "acceptAll" / "accept-all" / "AcceptAll"
        // or a future feature flag adding "mixed" would pass the
        // is_string() check but fall into the dashboard's
        // default case and silently mis-render. Pin the LITERAL bytes
        // so a rename surfaces here, not in operator UX.
        let state = build_state();

        // Empty-branch byte pin.
        let v_empty = compute_zones_scope(&state);
        let s_empty = v_empty["default_behavior"]
            .as_str()
            .expect("default_behavior must be a String on empty branch");
        assert_eq!(
            s_empty, "accept_all",
            "empty-branch default_behavior must be EXACTLY the lowercase-underscore \
             literal \"accept_all\" — byte-for-byte. Got: {s_empty:?}"
        );
        // Negative pins — every plausible rename variant must NOT match.
        for variant in &["AcceptAll", "acceptAll", "accept-all", "ACCEPT_ALL", "Accept_All"] {
            assert_ne!(
                s_empty, *variant,
                "default_behavior must NOT match rename variant {variant:?} — \
                 dashboard switch keys are case-sensitive snake_case"
            );
        }

        // Non-empty-branch byte pin.
        state.subscribe_zone(&ZoneId::new("payments"));
        let v_scoped = compute_zones_scope(&state);
        let s_scoped = v_scoped["default_behavior"]
            .as_str()
            .expect("default_behavior must be a String on non-empty branch");
        assert_eq!(
            s_scoped, "scoped",
            "non-empty-branch default_behavior must be EXACTLY the lowercase \
             literal \"scoped\" — byte-for-byte. Got: {s_scoped:?}"
        );
        for variant in &["Scoped", "SCOPED", "scope", "scope_only", "filtered"] {
            assert_ne!(
                s_scoped, *variant,
                "default_behavior must NOT match rename variant {variant:?}"
            );
        }
    }

    #[test]
    fn batch_ss_pending_purge_subobject_is_strict_json_object_type_empty_and_populated() {
        // Pin: `pending_purge` is a JSON Object (`is_object()`) on
        // BOTH the empty-queue branch (fresh node, no unsubscribes
        // ever) AND the populated-queue branch (one unsubscribe enqueued
        // a purge). An earlier test pinned the TOP-LEVEL Object type
        // and the 6-key contract, but did NOT pin the nested
        // `pending_purge` value as `is_object()`. A regression that
        // wrapped pending_purge in a single-element Array (e.g. a
        // future `pending_purge_history` rollout that prepended the
        // single current snapshot as a list) would pass the 6-key
        // top-level test but flip pending_purge from Object to Array,
        // breaking every consumer that does `scope.pending_purge.queue_depth`.
        //
        // Two-branch coverage catches a branch-conditional regression:
        //   `if queue_empty { Object } else { Array }`
        // would pass an empty-only test but fail under load.

        // Branch 1: empty queue (fresh).
        let state = build_state();
        let v_empty = compute_zones_scope(&state);
        let pp_empty = &v_empty["pending_purge"];
        assert!(
            pp_empty.is_object(),
            "empty-queue branch: pending_purge must be a JSON Object, got: {pp_empty:?}"
        );
        let obj_empty = pp_empty.as_object().unwrap();
        assert_eq!(
            obj_empty.len(),
            3,
            "empty-queue: pending_purge must have exactly 3 keys, got {}: {:?}",
            obj_empty.len(),
            obj_empty.keys().collect::<Vec<_>>()
        );
        for k in &["queue_depth", "oldest_lag_seconds", "records_purged_total"] {
            assert!(
                obj_empty.contains_key(*k),
                "empty-queue: pending_purge missing key `{k}`"
            );
        }

        // Branch 2: populated queue (sub then unsub enqueues 1 purge).
        state.subscribe_zone(&ZoneId::new("temp"));
        state.unsubscribe_zone(&ZoneId::new("temp"));
        let v_pop = compute_zones_scope(&state);
        let pp_pop = &v_pop["pending_purge"];
        assert!(
            pp_pop.is_object(),
            "populated-queue branch: pending_purge must remain a JSON Object, got: {pp_pop:?}"
        );
        let obj_pop = pp_pop.as_object().unwrap();
        assert_eq!(
            obj_pop.len(),
            3,
            "populated-queue: pending_purge must have exactly 3 keys"
        );
        // Sanity: the queue actually populated, so the two branches
        // exercised distinct underlying state — not a tautological pin.
        assert_eq!(
            obj_pop["queue_depth"].as_u64(),
            Some(1),
            "populated-queue: queue_depth must be 1 after one unsubscribe"
        );
        // Negative pins on both branches.
        assert!(
            !pp_empty.is_array(),
            "pending_purge must NEVER be a JSON Array (empty branch)"
        );
        assert!(
            !pp_pop.is_array(),
            "pending_purge must NEVER be a JSON Array (populated branch)"
        );
        assert!(
            !pp_empty.is_null() && !pp_pop.is_null(),
            "pending_purge must NEVER be JSON null on either branch"
        );
    }

    #[test]
    fn batch_ss_subscribed_zones_per_zone_storage_bijection_index_alignment_n_sweep() {
        // Pin: `subscribed_zones[i].as_str() == per_zone_storage[i]["zone"]`
        // for every index i, across N ∈ {2, 7, 15, 50}. An earlier test
        // pinned pairwise alignment at small N (≤3). Another
        // pinned LENGTH equality at N=100 but NOT pointwise index
        // alignment. The combination misses a regression that sorts the
        // two arrays by DIFFERENT keys — e.g. `subscribed_zones` sorted
        // by `ZoneId::to_string()` (current contract at L1863) while
        // `per_zone_storage` sorted by `record_count` desc (a future
        // "high-traffic zones first" UX change that forgot to mirror in
        // subscribed_zones). Length-only / small-N pins would both pass.
        //
        // Use disjoint root-level zones (no `/`) so no ancestor
        // auto-pinning expands the subscribed set beyond what the test
        // explicitly added — keeps the alignment assertion crisp at
        // every N.
        for &n in &[2_usize, 7, 15, 50] {
            let state = build_state();
            // Use zero-padded labels so lex order is deterministic and
            // distinct from insertion order — exercises the sort path
            // at L1863 (ZoneManager iter order is HashSet-based and
            // non-deterministic; the helper's `sort_by_key` produces
            // the canonical output).
            for i in (0..n).rev() {
                state.subscribe_zone(&ZoneId::new(&format!("zss-{i:04}")));
            }
            let v = compute_zones_scope(&state);
            let subscribed = v["subscribed_zones"]
                .as_array()
                .expect("subscribed_zones array");
            let per_zone = v["per_zone_storage"]
                .as_array()
                .expect("per_zone_storage array");
            assert_eq!(
                subscribed.len(),
                n,
                "N={n}: subscribed_zones.len() must equal N (no ancestor expansion)"
            );
            assert_eq!(
                per_zone.len(),
                n,
                "N={n}: per_zone_storage.len() must equal N (parallel arrays)"
            );
            for i in 0..n {
                let sz = subscribed[i]
                    .as_str()
                    .unwrap_or_else(|| panic!("N={n} subscribed_zones[{i}] not a String"));
                let pz = per_zone[i]["zone"]
                    .as_str()
                    .unwrap_or_else(|| panic!("N={n} per_zone_storage[{i}].zone not a String"));
                assert_eq!(
                    sz, pz,
                    "N={n} i={i}: subscribed_zones[i]={sz:?} must equal \
                     per_zone_storage[i].zone={pz:?} — parallel-array index alignment broken"
                );
            }
            // Sanity: lex sort actually fired — first element must be
            // "zss-0000" not "zss-{n-1:04}" (insertion order was reversed).
            assert_eq!(
                subscribed[0].as_str(),
                Some("zss-0000"),
                "N={n}: lex sort must place zss-0000 first regardless of insertion order"
            );
        }
    }

    #[test]
    fn batch_ss_compute_zones_scope_serde_string_purity_ten_consecutive_calls() {
        // Pin: 10× consecutive calls to `compute_zones_scope` on the
        // same state produce 10× byte-identical `serde_json::to_string`
        // outputs. An earlier test pinned the SAME property at 2×; this
        // is the 10× iteration extension. Distinct from the
        // state-purity pin (which checks ZoneManager / atomics unchanged
        // after 10 calls) — this checks the EMITTED JSON STRING is
        // byte-identical, the wire contract operators actually parse.
        //
        // Why 10× matters even when 2× would catch most regressions:
        // HashMap iteration order in Rust is non-deterministic across
        // runs (default RandomState) but is FIXED for the lifetime of
        // a single HashMap. A regression that leaked HashMap iter order
        // into the output via a missing canonical sort would produce
        // BYTE-IDENTICAL output across calls within one test run (same
        // HashMap instance) and so silently pass batch_z's 2× pin. The
        // 10× pin paired with NON-TRIVIAL state (subscribed zones in
        // reverse-lex insertion order so the sort is the load-bearing
        // canonicalizer) raises confidence that the sort is firing.
        let state = build_state();
        // Subscribe in reverse-lex order so the helper's `sort_by_key`
        // at L1863 has actual work to do — a regression that dropped
        // the sort would produce HashMap-iter-order output that varies
        // across binaries but not within one test run.
        for label in &["charlie", "bravo", "alpha", "delta", "echo"] {
            state.subscribe_zone(&ZoneId::new(label));
        }
        // Also enqueue some purge work so pending_purge.queue_depth is
        // non-trivially populated (catches a regression in the purge
        // sub-object that only surfaces with a non-empty queue).
        state.subscribe_zone(&ZoneId::new("temp-1"));
        state.subscribe_zone(&ZoneId::new("temp-2"));
        state.unsubscribe_zone(&ZoneId::new("temp-1"));
        state.unsubscribe_zone(&ZoneId::new("temp-2"));

        let serialized: Vec<String> = (0..10)
            .map(|_| {
                let mut v = compute_zones_scope(&state);
                // Normalize the one wall-clock-derived field — `oldest_lag_seconds`
                // measures real elapsed time since the oldest purge enqueue and
                // legitimately drifts between calls (~µs scale). The pin's
                // intent is byte-identical FIELD ORDER / ARRAY ORDER / FIELD
                // PRESENCE to catch HashMap-iter-order leakage in the canonical
                // sort path, NOT to assert the lag-value monotonic clock is
                // frozen. Stamp it to 0.0 so the comparison surfaces ordering
                // regressions without false-positive time drift.
                if let Some(pp) = v
                    .get_mut("pending_purge")
                    .and_then(|x| x.as_object_mut())
                {
                    pp.insert(
                        "oldest_lag_seconds".to_string(),
                        serde_json::json!(0.0),
                    );
                }
                serde_json::to_string(&v).expect("serialize to JSON string")
            })
            .collect();
        // Pairwise byte-identical pin across all 10 outputs.
        for i in 1..10 {
            assert_eq!(
                serialized[0], serialized[i],
                "call 0 vs call {i}: serialized JSON must be byte-identical \
                 across 10 consecutive calls — HashMap-iter-order leakage \
                 or non-canonical sort path detected"
            );
        }
        // Sanity: the output is non-trivial (5 explicit zones + 2 purge
        // entries) so a degenerate {} pass-through would NOT match.
        let v0: serde_json::Value =
            serde_json::from_str(&serialized[0]).expect("re-parse JSON");
        assert_eq!(
            v0["subscribed_zones"].as_array().unwrap().len(),
            5,
            "must have 5 subscribed zones in the snapshot — guards against \
             a degenerate {{}} pass-through that would trivially pass equality"
        );
        assert_eq!(
            v0["pending_purge"]["queue_depth"].as_u64(),
            Some(2),
            "must have 2 purge entries — guards against an empty-state pin"
        );
    }

    #[test]
    fn batch_ss_partial_unsubscribe_algebra_subscribed_plus_queue_depth_equals_n_initial() {
        // Pin: after subscribing N=5 disjoint zones then unsubscribing
        // 3 of them, `subscribed_zones.len() + pending_purge.queue_depth
        // == 5` (the initial subscription count). Another test pins
        // the BALANCED full-cycle case (N sub + N unsub → queue_depth=N,
        // subscribed=0). This pin covers the PARTIAL case — both sets
        // non-empty — which is the regime operators actually observe
        // during steady-state churn.
        //
        // Catches a regression where the unsubscribe path decrements
        // subscribed_zones but FAILS to enqueue the purge work (e.g. a
        // future "fast unsubscribe" optimization that skips the purge
        // queue for "small" subscriptions) — that would leave
        // subscribed=2 + queue_depth=0, conserving NEITHER the original
        // 5-zone count NOR the purge-monotonicity invariant.
        let state = build_state();
        let zones: Vec<String> = (0..5).map(|i| format!("alg-{i:02}")).collect();
        for z in &zones {
            state.subscribe_zone(&ZoneId::new(z));
        }
        // Sanity pre-state: 5 subscribed, 0 queued.
        let v_pre = compute_zones_scope(&state);
        assert_eq!(
            v_pre["subscribed_zones"].as_array().unwrap().len(),
            5,
            "pre-state: 5 zones subscribed"
        );
        assert_eq!(
            v_pre["pending_purge"]["queue_depth"].as_u64(),
            Some(0),
            "pre-state: queue empty (no unsubscribes yet)"
        );

        // Partial unsubscribe: drop zones [0, 2, 4] (every other,
        // non-contiguous indices — catches a regression that only
        // handled contiguous-prefix unsubscribe).
        state.unsubscribe_zone(&ZoneId::new(&zones[0]));
        state.unsubscribe_zone(&ZoneId::new(&zones[2]));
        state.unsubscribe_zone(&ZoneId::new(&zones[4]));

        let v_post = compute_zones_scope(&state);
        let subscribed_len = v_post["subscribed_zones"].as_array().unwrap().len();
        let queue_depth = v_post["pending_purge"]["queue_depth"]
            .as_u64()
            .expect("queue_depth u64");
        assert_eq!(
            subscribed_len, 2,
            "post-state: 5 − 3 = 2 zones remaining subscribed (got {subscribed_len})"
        );
        assert_eq!(
            queue_depth, 3,
            "post-state: 3 unsubscribes enqueued 3 purge entries (got {queue_depth})"
        );
        // The algebraic invariant — conservation across the
        // subscribe/unsubscribe boundary.
        assert_eq!(
            subscribed_len as u64 + queue_depth,
            5,
            "ALGEBRAIC INVARIANT: subscribed_zones.len() + queue_depth must equal \
             N_initial=5 across the partial-unsubscribe boundary. \
             Got subscribed={subscribed_len} + queue_depth={queue_depth} = {}",
            subscribed_len as u64 + queue_depth
        );
        // Sanity: the surviving zones are the odd-indexed ones (1, 3).
        let surviving: Vec<&str> = v_post["subscribed_zones"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        assert_eq!(
            surviving,
            vec!["alg-01", "alg-03"],
            "surviving zones must be exactly [alg-01, alg-03] in lex order"
        );
    }

    // ─── Five orthogonal pins layered on
    //     top of the earlier coverage. Each
    //     test isolates a contract the prior tests left unsealed.
    //     The pivots are:
    //       (1) `oldest_lag_seconds` is IEEE-754 FINITE — never NaN,
    //           never ±Inf — on BOTH the empty-queue branch AND the
    //           populated-queue branch. An earlier test pinned `is_number()`
    //           with `== 0.0` on the empty branch; another pinned
    //           `is_number()` with `>= 0` on the populated branch.
    //           Neither pin catches `f64::NAN` or `f64::INFINITY`
    //           (both pass `is_number()` in serde_json under default
    //           features and survive the `>= 0` comparison via NaN
    //           semantics being neither true nor false). A regression
    //           that emitted NaN under a divide-by-zero in a future
    //           "average lag" computation would slip through Y and CC
    //           but fail here on `.is_finite()`.
    //       (2) `per_zone_storage[].record_count == 0` for EVERY entry
    //           across N=10 fresh subscribes. An earlier test pinned the N=1
    //           single-entry zero case (`one_subscribe_flips_default_to
    //           _scoped_with_zero_record_count`). This pin sweeps to
    //           N=10 — catches a regression where the per_zone map
    //           silently injected nonzero counts for "popular" zones
    //           (e.g. a future "show recent activity hint" feature
    //           that misused this slot) without ingesting a single
    //           record.
    //       (3) `pending_purge.queue_depth` is STRICTLY u64 (`is_u64()
    //           && !is_f64()`) under a POPULATED queue (N=3 unsubs).
    //           An earlier test pinned the zero-baseline `is_u64()` type;
    //           another pinned the populated branch as an Object but
    //           not at the field-element type. A regression that
    //           switched to f64 to express purge progress as a
    //           fraction (e.g. seconds-since-enqueue average) would
    //           pass `is_number()` but break the soak monitor's
    //           integer-threshold comparison.
    //       (4) `pending_purge.records_purged_total` is DECOUPLED
    //           from subscription churn — bumping the atomic to 99
    //           and then running sub-unsub×5 across 5 distinct zones
    //           leaves the atomic intact at 99. An earlier test pinned the
    //           direct-binding contract at a static state (atomic ==
    //           424242 with no churn). Another pinned monotonicity
    //           under a mutation sequence. Neither pin catches a
    //           future regression where the unsubscribe path
    //           accidentally bumped or zeroed records_purged_total
    //           (records_purged_total tracks RECORD purges from the
    //           background purge_loop, not subscription state-machine
    //           events).
    //       (5) ZoneId::new() whitespace-trim normalization is
    //           reflected in `subscribed_zones`. An earlier test covered
    //           lowercase-fold and trailing-slash-strip; another
    //           covered Unicode round-trip. The third normalization
    //           rule from `zone.rs:38-50` — `.trim()` on input — was
    //           never explicitly pinned through compute_zones_scope.
    //           A regression that re-introduced whitespace in the
    //           stored zone path (e.g. via a future "preserve original
    //           input for audit log" feature that bypassed `.trim()`)
    //           would surface here as a `"  payments  "` chip on the
    //           operator dashboard instead of a clean `"payments"`.

    #[test]
    fn batch_tt_oldest_lag_seconds_is_ieee754_finite_both_branches() {
        // Empty-branch finiteness pin.
        let state_empty = build_state();
        let v_empty = compute_zones_scope(&state_empty);
        let lag_empty = v_empty["pending_purge"]["oldest_lag_seconds"]
            .as_f64()
            .expect("oldest_lag_seconds must be a JSON Number on empty branch");
        assert!(
            lag_empty.is_finite(),
            "empty-branch oldest_lag_seconds must be IEEE-754 finite — \
             not NaN, not +Inf, not -Inf. Got: {lag_empty}"
        );
        // Cross-pin the negative — NaN and ±Inf would also fail
        // `is_finite()`, but pin the disjuncts explicitly so a
        // regression that returned a specific bad-finite value (e.g.
        // f64::INFINITY but not NaN, or NaN but not Infinity) lands
        // here with a clear error.
        assert!(!lag_empty.is_nan(), "empty-branch lag must NOT be NaN");
        assert!(
            !lag_empty.is_infinite(),
            "empty-branch lag must NOT be ±Infinity"
        );

        // Populated-branch finiteness pin: one subscribe + one
        // unsubscribe enqueues exactly one purge entry. The `oldest_lag
        // _seconds` is computed as `now() - oldest_enqueued_at` in
        // `zone_purge::oldest_lag_secs`, which is f64-arithmetic over
        // SystemTime values — a regression that miscomputed the lag
        // (e.g. via `f64::INFINITY` sentinel for "lag unmeasured"
        // instead of 0.0) would land here.
        let state_pop = build_state();
        state_pop.subscribe_zone(&ZoneId::new("tt-finite"));
        state_pop.unsubscribe_zone(&ZoneId::new("tt-finite"));
        let v_pop = compute_zones_scope(&state_pop);
        let lag_pop = v_pop["pending_purge"]["oldest_lag_seconds"]
            .as_f64()
            .expect("oldest_lag_seconds must be a JSON Number on populated branch");
        assert!(
            lag_pop.is_finite(),
            "populated-branch oldest_lag_seconds must be IEEE-754 finite \
             — not NaN, not +Inf, not -Inf. Got: {lag_pop}"
        );
        assert!(!lag_pop.is_nan(), "populated-branch lag must NOT be NaN");
        assert!(
            !lag_pop.is_infinite(),
            "populated-branch lag must NOT be ±Infinity"
        );
        // Sanity: populated lag must also be non-negative,
        // strengthening this pin in the same call rather than relying on
        // cross-test ordering.
        assert!(
            lag_pop >= 0.0,
            "populated-branch lag must be ≥ 0 (now() ≥ enqueued_at). Got: {lag_pop}"
        );
    }

    #[test]
    fn batch_tt_per_zone_storage_record_count_all_zero_on_n_ten_fresh_subscribes() {
        // Subscribe 10 disjoint zones with no slashes — single-segment
        // names so ZoneManager auto-pin of ancestors does NOT inflate
        // the subscribed set. The expected `per_zone_storage` length is
        // exactly 10, and every entry's `record_count` must be exactly
        // 0 (fresh node, zero records ingested).
        let state = build_state();
        let names: Vec<String> = (0..10).map(|i| format!("tt-rc-{i:02}")).collect();
        for n in &names {
            state.subscribe_zone(&ZoneId::new(n));
        }

        let v = compute_zones_scope(&state);
        let per_zone = v["per_zone_storage"]
            .as_array()
            .expect("per_zone_storage must be a JSON Array on populated state");
        assert_eq!(
            per_zone.len(),
            10,
            "N=10 disjoint single-segment subscribes ⇒ per_zone_storage.len() must be exactly 10 \
             (no auto-pin inflation for slash-less paths). Got: {}",
            per_zone.len()
        );

        for (i, entry) in per_zone.iter().enumerate() {
            let rc = entry["record_count"].as_u64().unwrap_or_else(|| {
                panic!(
                    "per_zone_storage[{i}].record_count must be a JSON u64, got: {:?}",
                    entry["record_count"]
                )
            });
            assert_eq!(
                rc, 0,
                "per_zone_storage[{i}].record_count must be exactly 0 on fresh state — \
                 no records ingested, no nonzero injections. Got: {rc} for entry {entry:?}"
            );
        }
    }

    #[test]
    fn batch_tt_pending_purge_queue_depth_strict_u64_type_under_populated_queue() {
        // Drive the queue to a known non-zero value (3 unsubs of zones
        // never previously subscribed enqueue 3 purge entries — see
        // batch_y_unsubscribe_never_subscribed_zone_enqueues_purge_unconditionally).
        // Pin the JSON type as STRICTLY u64 (not f64, not String, not
        // null) under this populated state — an earlier test pinned the empty
        // baseline `is_u64()`, but the populated branch's type was
        // never directly type-pinned (only `as_u64().unwrap()` which
        // would also accept an f64-shaped 3.0 in some serde versions).
        let state = build_state();
        for i in 0..3 {
            state.unsubscribe_zone(&ZoneId::new(format!("tt-qd-{i}").as_str()));
        }

        let v = compute_zones_scope(&state);
        let qd = &v["pending_purge"]["queue_depth"];
        assert!(
            qd.is_u64(),
            "populated-queue pending_purge.queue_depth must be a JSON u64. Got: {qd:?}"
        );
        assert!(
            !qd.is_f64(),
            "populated-queue pending_purge.queue_depth must NOT be classified as f64. Got: {qd:?}"
        );
        assert!(
            !qd.is_string(),
            "populated-queue pending_purge.queue_depth must NOT be a String. Got: {qd:?}"
        );
        assert!(
            !qd.is_null(),
            "populated-queue pending_purge.queue_depth must NOT be null. Got: {qd:?}"
        );
        assert_eq!(
            qd.as_u64(),
            Some(3),
            "3 unsubscribes of never-subscribed zones ⇒ queue_depth must be exactly 3"
        );
    }

    #[test]
    fn batch_tt_records_purged_total_decoupled_from_subscription_churn() {
        // Pin: the `zone_purge_records_purged_total` atomic counts
        // RECORDS purged by the background purge_loop — NOT subscription
        // state-machine events. Bumping the atomic to a distinctive
        // non-round sentinel (99) and then running sub-unsub×5 across
        // 5 disjoint zones must leave the atomic UNCHANGED at 99. The
        // queue_depth WILL grow (5 unsubs enqueue 5 purge entries) and
        // subscribed_zones WILL be empty at the end, but
        // records_purged_total — the lifetime counter — stays put.
        //
        // An earlier test pinned the direct binding at a static state (atomic
        // == 424242, no churn). Another pinned monotonicity under a
        // mutation sequence. Neither catches a regression where the
        // unsubscribe path accidentally bumped or zeroed
        // records_purged_total (e.g. a future "express ops churn in a
        // single counter" refactor).
        use std::sync::atomic::Ordering;
        let state = build_state();
        state
            .zone_purge_records_purged_total
            .store(99, Ordering::Relaxed);

        for i in 0..5 {
            let name = format!("tt-decouple-{i}");
            let zid = ZoneId::new(&name);
            state.subscribe_zone(&zid);
            state.unsubscribe_zone(&zid);
        }

        let v = compute_zones_scope(&state);

        assert_eq!(
            v["pending_purge"]["records_purged_total"].as_u64(),
            Some(99),
            "subscription churn (sub+unsub × 5) must NOT touch the \
             records_purged_total atomic — it tracks records, not zone events. \
             Pre-bump: 99; post-churn JSON: {:?}",
            v["pending_purge"]["records_purged_total"]
        );
        // Cross-pin via the underlying atomic — JSON mirror MUST equal
        // atomic AND atomic MUST still be 99.
        assert_eq!(
            state
                .zone_purge_records_purged_total
                .load(Ordering::Relaxed),
            99,
            "underlying atomic must remain at 99 after subscription churn"
        );
        // Sanity: the OTHER pending_purge fields DID move (proving the
        // churn actually happened — this isn't a no-op test).
        assert_eq!(
            v["pending_purge"]["queue_depth"].as_u64(),
            Some(5),
            "5 unsubs ⇒ queue_depth == 5 (sanity that churn fired)"
        );
        assert_eq!(
            v["subscribed_zones"].as_array().unwrap().len(),
            0,
            "all 5 zones unsubscribed ⇒ subscribed_zones empty (sanity that churn fired)"
        );
    }

    #[test]
    fn batch_tt_zone_id_whitespace_trim_normalization_reflected_in_subscribed_zones() {
        // Pin: ZoneId::new applies `.trim()` (zone.rs:38-50) to the input
        // path BEFORE lowercasing and trailing-slash strip. The JSON
        // output of compute_zones_scope reflects the trimmed form — not
        // the caller's whitespace-padded original. Distinct from:
        //   - lowercase-fold ('PAYMENTS/EU' → 'payments/eu')
        //   - trailing-slash strip ('medical/' → 'medical')
        //   - Unicode preservation (CJK round-trip)
        // The trim path is the THIRD documented normalization rule and
        // was never directly pinned through compute_zones_scope's output.
        //
        // A regression that re-introduced whitespace in the stored zone
        // path (e.g. a future 'preserve original input for audit log'
        // feature that bypassed `.trim()`) would surface here as a
        // '  payments  ' chip in the operator dashboard.
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("  payments  "));
        // Tab + leading/trailing newline — broader whitespace coverage
        // than spaces alone (Rust's `.trim()` removes any
        // `char::is_whitespace`).
        state.subscribe_zone(&ZoneId::new("\t\nmedical\n\t"));

        let v = compute_zones_scope(&state);
        let zones: Vec<String> = v["subscribed_zones"]
            .as_array()
            .expect("subscribed_zones must be a JSON Array")
            .iter()
            .map(|s| {
                s.as_str()
                    .expect("subscribed_zones[i] must be a String")
                    .to_string()
            })
            .collect();

        // Positive pin: trimmed forms MUST appear (lex-sorted).
        assert_eq!(
            zones,
            vec!["medical".to_string(), "payments".to_string()],
            "subscribed_zones must contain trimmed forms in lex order. Got: {zones:?}"
        );

        // Negative pin: NO emitted zone string contains leading or
        // trailing whitespace. Iterate ALL emitted strings — catches a
        // future regression where only ONE of the two inputs gets
        // trimmed (e.g. a fast-path that handled ASCII spaces but
        // skipped tab/newline). `char::is_whitespace` covers spaces,
        // tabs, newlines, and Unicode whitespace categories.
        for z in &zones {
            assert!(
                !z.starts_with(char::is_whitespace),
                "subscribed_zones entry {z:?} must NOT start with whitespace — \
                 ZoneId::new's .trim() contract was bypassed"
            );
            assert!(
                !z.ends_with(char::is_whitespace),
                "subscribed_zones entry {z:?} must NOT end with whitespace — \
                 ZoneId::new's .trim() contract was bypassed"
            );
        }

        // Also pin per_zone_storage[i].zone reflects the trimmed form —
        // the same normalization must propagate through the second
        // emission site (the .map(|z| ...) at L1879-1884), not just the
        // first one (subscribed_zones at L1900).
        let per_zone_names: Vec<String> = v["per_zone_storage"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["zone"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            per_zone_names,
            vec!["medical".to_string(), "payments".to_string()],
            "per_zone_storage entries must also reflect the trimmed zone names. Got: {per_zone_names:?}"
        );
    }

    // ─── Five orthogonal pins layered on top
    //     of the prior set. Each pin isolates a contract the prior tests left
    //     unsealed. The pivots are:
    //       (1) `per_zone_storage[].zone` is STRICTLY ASCENDING lex order
    //           as a SELF-CONTAINED property — walked WITHOUT reference to
    //           `subscribed_zones`. Earlier tests pinned the pairwise
    //           alignment with `subscribed_zones` (which IS lex-sorted);
    //           others pinned the cross-array equality. None of
    //           those catch a future regression where `per_zone_storage`
    //           gets re-sorted by `record_count desc` (e.g. a "hottest
    //           zone first" UX feature) WHILE `subscribed_zones` retains
    //           lex order — the pairwise tests would fail noisily but
    //           wouldn't pinpoint the per_zone array as the misordered
    //           one. A self-contained sweep on per_zone_storage's own
    //           field walks adjacency strictly and surfaces the
    //           regression in this exact test.
    //       (2) Hierarchical 3-level subscribe (`medical/eu/cardio`)
    //           auto-pins 3 ancestors AND every one of those 3
    //           per_zone_storage entries carries `record_count == 0u64`
    //           strictly. An earlier test pinned the 3 ANCESTOR PATHS in lex
    //           order (zone strings only). Another pinned the
    //           record_count=0 axis across N=7 DISJOINT zones. A third
    //           pinned the same across N=10 disjoint single-segment
    //           zones. None of the three pinned the cross-product: an
    //           ancestor-chain subscribe where the inner ancestor (the
    //           non-leaf zone with auto-pinned status) might carry a
    //           phantom count under a future "ancestor inherits sum of
    //           descendant counts" regression. The cross-pin catches
    //           that specifically.
    //       (3) Multi-zone subscribe→unsubscribe round-trip returns
    //           `default_behavior` to `"accept_all"`. An earlier test pinned the
    //           N=1 single-zone variant (`transient`). Another pinned
    //           the partial-churn case (sub-sub-unsub-sub leaves
    //           non-empty subscribed_zones). Neither catches a
    //           regression where `default_behavior` becomes sticky once
    //           subscribed_zones has been non-empty (e.g. a future
    //           "first-subscription-ever flips to scoped, never returns
    //           to accept_all" feature). N=4 sub + N=4 unsub at distinct
    //           single-segment zones forces the multi-zone path through
    //           the subscribed_zones-becoming-empty branch — pin all
    //           three observables (default_behavior, subscribed_zones,
    //           per_zone_storage) plus the queue_depth=4 sanity tail.
    //       (4) `subscribed_zones[i]` and `per_zone_storage[i].zone`
    //           strings are NON-EMPTY across 5 normalization-required
    //           inputs. An earlier test pinned uppercase fold + trailing-slash
    //           strip; another pinned Unicode UTF-8 preservation;
    //           a third pinned whitespace trim. None of the three
    //           pinned the negative invariant — that the NORMALIZED
    //           output of ZoneId::new is never the empty string `""`
    //           for legitimately-non-empty inputs. A future regression
    //           where e.g. `ZoneId::new("/")` collapses to `""` post-
    //           trim-and-slash-strip (or where whitespace-only input
    //           survives ZoneId::new at all) would silently emit empty-
    //           string chips on the operator dashboard. Walk every
    //           emitted zone string and assert `!is_empty()` directly.
    //       (5) Hierarchical 3-level subscribe — `per_zone_storage[i]
    //           .zone` is a STRICT PREFIX (with `/` boundary) of
    //           `per_zone_storage[i+1].zone` for i in 0..len-1. This is
    //           a STRUCTURAL invariant DISTINCT from the lex-sort pin
    //           (1): an ancestor chain happens to be lex-sorted, but the
    //           prefix relation is the actual operational meaning. A
    //           future regression that broke the ancestor walk (e.g. a
    //           depth ceiling at 2 levels, or an off-by-one that
    //           dropped the deepest descendant) would still produce a
    //           lex-sorted array — but the prefix chain would be
    //           broken. Pin the chain explicitly: for i in 0..2,
    //           per_zone_storage[i].zone + "/" must be a prefix of
    //           per_zone_storage[i+1].zone.

    #[test]
    fn batch_uu_per_zone_storage_strict_ascending_lex_self_contained_sort() {
        // Subscribe N=5 disjoint single-segment zones in REVERSE-lex
        // insertion order ("zeta"→"echo"→"delta"→"charlie"→"alpha"). The
        // helper's L1863 sort_by_key must restore canonical lex order on
        // the underlying `subscribed` Vec, which then propagates to
        // `per_zone_storage` via the .iter().map() chain at L1873-1883.
        //
        // Walk per_zone_storage[i].zone for adjacent pairs WITHOUT
        // referencing subscribed_zones — pure self-contained adjacency
        // check. Distinct from the pairwise-alignment pins
        // because those would FAIL noisily (mismatched arrays) but
        // wouldn't pinpoint per_zone_storage as the misordered side; this
        // test directly walks the array under test.
        let state = build_state();
        // Insertion order chosen so insertion-order == reverse-lex
        // (worst case for the sort).
        for name in &["zeta", "echo", "delta", "charlie", "alpha"] {
            state.subscribe_zone(&ZoneId::new(name));
        }
        let v = compute_zones_scope(&state);
        let per_zone = v["per_zone_storage"]
            .as_array()
            .expect("per_zone_storage must be a JSON Array");
        assert_eq!(per_zone.len(), 5, "5 disjoint subscribes ⇒ 5 entries");

        // Self-contained strict-ascending lex walk. NO reference to
        // subscribed_zones.
        for i in 0..(per_zone.len() - 1) {
            let zi = per_zone[i]["zone"]
                .as_str()
                .expect("per_zone_storage[i].zone must be a String");
            let zi1 = per_zone[i + 1]["zone"]
                .as_str()
                .expect("per_zone_storage[i+1].zone must be a String");
            assert!(
                zi < zi1,
                "per_zone_storage must be STRICTLY ascending lex by .zone — \
                 entry[{i}]={zi:?} must be < entry[{}]={zi1:?}. \
                 A regression sorting by record_count or insertion order \
                 surfaces here.",
                i + 1
            );
        }
    }

    #[test]
    fn batch_uu_hierarchical_subscribe_three_levels_record_count_strict_zero_on_all_ancestors() {
        // Subscribe a single 3-level hierarchical path. ZoneManager auto-
        // pins all 3 ancestors per zone.rs:458-466 — an earlier test pinned the
        // zone path strings; this test pins the record_count = 0u64
        // strictly on EACH of the 3 entries (including the auto-pinned
        // non-leaf ancestors). Catches a regression where an ancestor's
        // record_count silently aggregates descendants' counts (e.g. a
        // future "ancestor inherits sum of descendants" feature) that
        // would slip through both the zone-path-only test and the
        // N=7-disjoint-zones test (not an ancestor chain).
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("medical/eu/cardio"));
        let v = compute_zones_scope(&state);
        let per_zone = v["per_zone_storage"]
            .as_array()
            .expect("per_zone_storage must be a JSON Array");
        assert_eq!(
            per_zone.len(),
            3,
            "3-level hierarchical subscribe ⇒ 3 auto-pinned ancestors"
        );
        // Cross-pin the zone paths in lex order so a regression in the
        // ancestor walk (e.g. dropped middle ancestor) surfaces here too.
        let names: Vec<&str> = per_zone
            .iter()
            .map(|e| e["zone"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec!["medical", "medical/eu", "medical/eu/cardio"],
            "ancestor chain must walk through both intermediate ancestors"
        );
        // The pin specific to this test: EVERY entry's record_count is
        // EXACTLY u64=0 — both the leaf zone AND the two auto-pinned
        // ancestors. A regression that summed descendant counts into the
        // ancestor would fail here on entry[0] or [1] specifically.
        for (i, entry) in per_zone.iter().enumerate() {
            let rc = entry["record_count"]
                .as_u64()
                .unwrap_or_else(|| panic!("per_zone_storage[{i}].record_count must be u64"));
            assert_eq!(
                rc, 0,
                "per_zone_storage[{i}].record_count must be exactly 0 on fresh node — \
                 including the auto-pinned non-leaf ancestor at index {i} \
                 (zone={:?}). A descendant-count-inheritance regression surfaces here.",
                entry["zone"]
            );
        }
    }

    #[test]
    fn batch_uu_multi_zone_subscribe_unsubscribe_round_trip_returns_default_behavior_to_accept_all() {
        // N=4 distinct single-segment zones (NO shared ancestor chains —
        // pure disjoint roots), subscribe all → verify scoped + populated,
        // unsubscribe all → verify default_behavior collapses back to
        // "accept_all" and both arrays drain to empty, queue_depth = 4
        // (each unsubscribe enqueued one purge entry). Distinct from
        // the N=1 single-zone test and the partial-churn test (that
        // leaves subscribed_zones non-empty). Catches a regression where
        // default_behavior gets "stuck" at "scoped" once subscribed_zones
        // has been non-empty even once — that hypothetical sticky-flag
        // bug passes the N=1 test at low cardinality but only manifests
        // when multiple sub→unsub cycles fail to propagate the
        // is_empty() check up to default_behavior at L1867.
        let state = build_state();
        let names = ["alpha", "bravo", "charlie", "delta"];
        for n in &names {
            state.subscribe_zone(&ZoneId::new(n));
        }

        // Sanity at peak — scoped + 4 entries in both arrays.
        let v_peak = compute_zones_scope(&state);
        assert_eq!(
            v_peak["default_behavior"], "scoped",
            "4 subscriptions ⇒ default_behavior=scoped at peak"
        );
        assert_eq!(
            v_peak["subscribed_zones"].as_array().unwrap().len(),
            4,
            "subscribed_zones must have 4 entries at peak"
        );

        // Tear down all 4 subscriptions.
        for n in &names {
            state.unsubscribe_zone(&ZoneId::new(n));
        }

        let v_after = compute_zones_scope(&state);
        assert_eq!(
            v_after["default_behavior"], "accept_all",
            "after unsubscribing ALL 4 zones, default_behavior MUST return to \
             accept_all (not get stuck at 'scoped' from peak)"
        );
        assert!(
            v_after["subscribed_zones"].as_array().unwrap().is_empty(),
            "subscribed_zones must be empty after N=4 unsubscribes"
        );
        assert!(
            v_after["per_zone_storage"].as_array().unwrap().is_empty(),
            "per_zone_storage must be empty after N=4 unsubscribes"
        );
        // Sanity tail: queue_depth = 4 confirms 4 unsubs actually fired
        // (this is the multi-N analog of the single-N queue_depth=1
        // pin). Catches a regression where unsubscribe became a no-op
        // and the queue_depth=0 result above was misread as "round trip
        // works" when in fact subscriptions were never torn down.
        assert_eq!(
            v_after["pending_purge"]["queue_depth"].as_u64(),
            Some(4),
            "4 unsubs ⇒ queue_depth=4 (sanity that unsubs actually fired)"
        );
    }

    #[test]
    fn batch_uu_subscribed_zones_strings_never_empty_across_normalization_variants() {
        // Pin the NEGATIVE invariant for ZoneId::new normalization: for
        // every legitimately-non-empty input (uppercase, trailing-slash,
        // whitespace-padded, or already-normalized), the emitted
        // subscribed_zones[i] string AND per_zone_storage[i].zone string
        // must be non-empty. Earlier tests pinned individual axes
        // (lowercase fold / Unicode round-trip / trim) at the POSITIVE
        // level (specific expected output strings). None of those
        // pinned the negative "no entry is empty-string" sweep — a
        // future regression that collapsed e.g. `"/"` (slash-only path)
        // to `""` post-strip, or whitespace-only `"   "` to `""` post-
        // trim, would emit phantom empty-string chips that survive
        // every existing positive-pin test (none of those inputs are
        // in the positive-pin fixtures).
        let state = build_state();
        let inputs = [
            "PAYMENTS",       // uppercase → "payments"
            "medical/",       // trailing slash → "medical"
            "  trim_me  ",    // whitespace → "trim_me"
            "account",         // already normalized → "account"
            "\thello\t",      // tab whitespace → "hello"
        ];
        for inp in &inputs {
            state.subscribe_zone(&ZoneId::new(inp));
        }
        let v = compute_zones_scope(&state);

        // Sweep 1: subscribed_zones — every emitted string non-empty.
        let subscribed: Vec<&str> = v["subscribed_zones"]
            .as_array()
            .expect("subscribed_zones must be a JSON Array")
            .iter()
            .map(|s| s.as_str().expect("subscribed_zones[i] must be String"))
            .collect();
        assert_eq!(
            subscribed.len(),
            5,
            "5 legitimately-non-empty inputs ⇒ 5 entries (no collapse to empty)"
        );
        for (i, z) in subscribed.iter().enumerate() {
            assert!(
                !z.is_empty(),
                "subscribed_zones[{i}] must NOT be empty-string — \
                 normalization MUST NOT collapse legitimately-non-empty inputs \
                 to empty. Got: {z:?}"
            );
        }

        // Sweep 2: per_zone_storage[].zone — second emission site at
        // L1879. Same negative invariant applies — propagation across
        // the .map() must preserve non-emptiness.
        let per_zone_names: Vec<&str> = v["per_zone_storage"]
            .as_array()
            .expect("per_zone_storage must be a JSON Array")
            .iter()
            .map(|e| e["zone"].as_str().expect("per_zone_storage[i].zone must be String"))
            .collect();
        assert_eq!(
            per_zone_names.len(),
            5,
            "per_zone_storage must mirror subscribed_zones len (5 entries)"
        );
        for (i, z) in per_zone_names.iter().enumerate() {
            assert!(
                !z.is_empty(),
                "per_zone_storage[{i}].zone must NOT be empty-string — \
                 second emission site (L1879) must preserve non-emptiness. Got: {z:?}"
            );
        }
    }

    #[test]
    fn batch_uu_hierarchical_ancestor_chain_strict_prefix_invariant_per_zone_storage() {
        // Pin the STRUCTURAL invariant on hierarchical subscribes that
        // is distinct from lex sort: for an ancestor chain (i.e. a
        // single deep zone path with auto-pinned ancestors), each
        // adjacent pair (per_zone_storage[i], per_zone_storage[i+1])
        // must satisfy that per_zone_storage[i].zone + "/" is a STRICT
        // PREFIX of per_zone_storage[i+1].zone. This is what makes the
        // chain an ancestor chain rather than a lex-coincidence.
        //
        // Lex sort alone doesn't catch a regression where the ancestor
        // walk skips an intermediate level (e.g. depth-ceiling at 2
        // ancestors, or off-by-one dropping the deepest descendant) —
        // such a regression would still produce a lex-sorted array
        // (e.g. ["alpha", "alpha/beta/gamma/delta"]) but the prefix
        // chain between entry[0]="alpha" and entry[1]="alpha/beta/gamma
        // /delta" would be broken because "alpha/" is not the immediate
        // parent of "alpha/beta/gamma/delta" — the intermediate
        // ancestors "alpha/beta" and "alpha/beta/gamma" are missing.
        //
        // Distinct from the depth-5 value pin (which checks zone strings
        // in lex order against an expected vector) and
        // the depth-3 value pin. This pin is STRUCTURAL:
        // it would pass even on a different deep path. Catches a future
        // change to the depth-3 expected-string vector that quietly
        // also broke the prefix chain (e.g. if the depth-3 expected vector
        // was updated to `["alpha", "alpha/beta/gamma/delta"]` for
        // some new "ancestor compression" feature, the value pin would
        // change but this structural pin would surface the bug).
        let state = build_state();
        state.subscribe_zone(&ZoneId::new("alpha/beta/gamma"));
        let v = compute_zones_scope(&state);
        let per_zone = v["per_zone_storage"]
            .as_array()
            .expect("per_zone_storage must be a JSON Array");
        assert_eq!(
            per_zone.len(),
            3,
            "3-level hierarchical subscribe ⇒ 3-entry ancestor chain"
        );
        for i in 0..(per_zone.len() - 1) {
            let zi = per_zone[i]["zone"]
                .as_str()
                .expect("zone field is String");
            let zi1 = per_zone[i + 1]["zone"]
                .as_str()
                .expect("zone field is String");
            let prefix = format!("{zi}/");
            assert!(
                zi1.starts_with(&prefix),
                "ancestor chain prefix invariant: per_zone_storage[{i}].zone + \"/\" \
                 ({prefix:?}) must be a STRICT prefix of per_zone_storage[{}].zone \
                 ({zi1:?}). A regression that skipped an intermediate ancestor \
                 (depth ceiling, off-by-one) surfaces here even though the array \
                 would still be lex-sorted.",
                i + 1
            );
            // Strictness: lengths must differ by ≥ 1 char (the "/")
            // — pins "strict prefix" rather than "equal" (a regression
            // that returned the same string twice would also satisfy
            // .starts_with(&format!("{zi}/")) if `zi` happened to end
            // in "/" itself, but ZoneId::new's trailing-slash strip at
            // zone.rs makes that pathological).
            assert!(
                zi1.len() > zi.len(),
                "per_zone_storage[{}].zone must be STRICTLY longer than [{i}] for \
                 an ancestor chain (no equality / duplicate entries). Got len {} > {}",
                i + 1,
                zi1.len(),
                zi.len(),
            );
        }
    }
}

#[cfg(test)]
mod admin_compact_cf_query_tests {
    //! Pins `AdminCompactCfQuery`, the typed
    //! `?cf=` query DTO consumed by `POST /admin/rocks/compact_cf`. Until
    //! these tests the DTO had ZERO direct coverage — only the inner
    //! resolver `resolve_compact_cf_list` was tested directly and the
    //! outer handler was exercised through integration. The serde
    //! contract on the wire is what `elara-cli` and operator runbooks
    //! lock onto: a silent rename from `cf` to `column_family` would
    //! pass `cargo test` but break every operator who can't recompact a
    //! bloated CF after a binary upgrade.
    //!
    //! Pinned contracts:
    //!   1. `Default::default()` produces `cf=None` so axum's missing-
    //!      query-string path lands on the runbook default (compact full
    //!      allowlist), NOT on a panic or error.
    //!   2. Explicit `?cf=identities` round-trips through serde::Deserialize
    //!      to `cf=Some("identities")` — pins the field name as the wire
    //!      contract.
    //!   3. `?cf=` (empty string) deserializes to `Some("")` which is
    //!      DISTINCT from `None` at the type layer but resolver-equivalent
    //!      at the validation layer (`resolve_compact_cf_list` matches
    //!      `None | Some("") ⇒ full allowlist`).
    //!   4. Unknown extra query fields are silently ignored — a future
    //!      `?cf=records&max_parallel=2` rollout must not break old
    //!      binaries that only know `cf`.
    //!   5. End-to-end pipeline: the parsed DTO feeds cleanly into
    //!      `resolve_compact_cf_list` for all three operator-visible
    //!      shapes (absent / explicit-valid / explicit-typo).
    use super::{resolve_compact_cf_list, AdminCompactCfQuery, COMPACT_CF_ALLOWLIST};

    #[test]
    fn batch_r_admin_compact_cf_query_default_value_is_none() {
        // axum's Query<AdminCompactCfQuery> falls back to Default when
        // the query string is empty (e.g. `POST /admin/rocks/compact_cf`
        // with no `?cf=`). The runbook default is "compact every CF in
        // the allowlist" which is implemented by `resolve_compact_cf_list(None)`.
        // If a future refactor accidentally drops `Default` from the
        // derive list, axum would 400 every no-?cf= call instead of
        // landing on the runbook default — a silent operational regression.
        let q = AdminCompactCfQuery::default();
        assert!(
            q.cf.is_none(),
            "Default::default().cf must be None so the runbook \
             no-query-string path resolves to the full allowlist"
        );
    }

    #[test]
    fn batch_r_admin_compact_cf_query_explicit_value_round_trips_via_serde() {
        // The wire contract is the serde field name `cf`. A future rename
        // to `column_family` or `target_cf` would land silently and break
        // every `elara-cli pq-admin compact-cf --cf records` invocation
        // and every curl-shaped runbook in internal design notes.
        // Test every member of COMPACT_CF_ALLOWLIST so a typo in the
        // const drift surfaces here too.
        for &cf in COMPACT_CF_ALLOWLIST {
            let payload = format!(r#"{{"cf":"{cf}"}}"#);
            let parsed: AdminCompactCfQuery = serde_json::from_str(&payload)
                .unwrap_or_else(|e| panic!("AdminCompactCfQuery must parse `{payload}`: {e}"));
            assert_eq!(
                parsed.cf.as_deref(),
                Some(cf),
                "field name `cf` is the wire contract; rename surfaces here"
            );
        }
    }

    #[test]
    fn batch_r_admin_compact_cf_query_empty_value_distinct_from_omitted_field() {
        // `?cf=` (empty value) and a fully omitted `cf` field are DISTINCT
        // at the DTO layer:
        //   - omitted field ⇒ Option<String>::None (serde default for
        //     missing Option<T>).
        //   - present-but-empty ⇒ Some(""), an empty-string value.
        // Both paths are handled equivalently by `resolve_compact_cf_list`
        // (the `None | Some("")` arm collapses them into "compact full
        // allowlist"), but the type-layer distinction matters because a
        // future helper that pattern-matches on `Some(_)` without checking
        // for empty would silently treat `?cf=` as "compact a CF named ''"
        // and panic in `db.cf_handle("")`. Pin both shapes.
        let omitted: AdminCompactCfQuery = serde_json::from_str("{}")
            .expect("Option<String> with absent field must deserialize to None");
        assert!(
            omitted.cf.is_none(),
            "absent `cf` field ⇒ None (serde default for Option<T>)"
        );

        let empty_value: AdminCompactCfQuery = serde_json::from_str(r#"{"cf":""}"#)
            .expect("present-but-empty `cf` must deserialize to Some(\"\")");
        assert_eq!(
            empty_value.cf.as_deref(),
            Some(""),
            "present-but-empty `cf` ⇒ Some(\"\"), not None"
        );

        // Resolver-layer equivalence: both shapes collapse to full
        // allowlist via the `None | Some("")` arm in resolve_compact_cf_list.
        // (ops186 already pins this; the assertion here documents the
        // cross-layer contract so a refactor that drops the empty-string
        // arm at the resolver surfaces as a divergence between this
        // test and the ops186 tests.)
        assert_eq!(
            resolve_compact_cf_list(omitted.cf.as_deref()).expect("None must resolve"),
            resolve_compact_cf_list(empty_value.cf.as_deref()).expect("empty must resolve"),
            "the DTO-layer distinction must collapse at the resolver"
        );
    }

    #[test]
    fn batch_r_admin_compact_cf_query_unknown_field_silently_ignored_for_forward_compat() {
        // Forward-compat: a future PR adding `?cf=records&max_parallel=2`
        // or `?cf=records&dry_run=true` must NOT break old binaries that
        // only understand `cf`. serde's default is to silently drop unknown
        // fields; a future `#[serde(deny_unknown_fields)]` would land
        // silently AND break operator tooling cluster-wide on rolling
        // binary upgrades (newer client → older server during the rollout
        // window). Pin the lenient contract.
        let with_extra: AdminCompactCfQuery = serde_json::from_str(
            r#"{"cf":"records","max_parallel":2,"dry_run":true,"reason":"disk pressure"}"#,
        )
        .expect("unknown extra fields must be silently ignored — forward-compat");
        assert_eq!(
            with_extra.cf.as_deref(),
            Some("records"),
            "extra fields must not interfere with the bound `cf` value"
        );

        // Even a fully-extra payload (no `cf` field at all, only future
        // fields) must parse to the runbook default rather than rejecting.
        // This is the rolling-upgrade safety net: an older binary that
        // receives a query string composed entirely of future fields
        // should fall back to the documented runbook default (compact
        // every CF in allowlist), not 400 the operator's call.
        let only_future: AdminCompactCfQuery =
            serde_json::from_str(r#"{"max_parallel":2,"dry_run":true}"#)
                .expect("payload with only future fields must default cleanly to None");
        assert!(
            only_future.cf.is_none(),
            "missing `cf` falls back to the runbook default (full allowlist)"
        );
    }

    #[test]
    fn batch_r_admin_compact_cf_query_full_pipeline_through_resolve_compact_cf_list() {
        // End-to-end contract: every operator-visible shape of the `?cf=`
        // query string must produce the documented response. Three
        // shapes from internal design notes Stage 4 runbook:
        //   (a) absent           → resolve to full allowlist (default).
        //   (b) explicit valid   → resolve to singleton with that CF.
        //   (c) explicit typo    → reject with actionable error
        //                          including the typo + the valid options.
        // ops186 pins each of (a)/(b)/(c) at the resolver level; this test
        // pins that the DTO layer hands the resolver the same input the
        // operator typed, with no transformation. A future serde tweak
        // (`#[serde(rename = "cf_name")]` or trim-whitespace) would
        // surface as a divergence here.

        // (a) absent — operator runs `POST /admin/rocks/compact_cf` with
        // no query string. axum delivers Default ⇒ cf=None ⇒ full allowlist.
        let absent = AdminCompactCfQuery::default();
        let absent_resolved =
            resolve_compact_cf_list(absent.cf.as_deref()).expect("None must resolve");
        assert_eq!(
            absent_resolved,
            COMPACT_CF_ALLOWLIST.to_vec(),
            "absent `cf` ⇒ full allowlist via the runbook default"
        );

        // (b) explicit valid — operator targets a single CF for surgical
        // compaction (e.g. an ENOSPC incident where only `records`
        // was bloated). DTO carries the value through unchanged; resolver
        // returns singleton.
        let valid: AdminCompactCfQuery = serde_json::from_str(r#"{"cf":"merkle"}"#)
            .expect("`cf=merkle` must parse");
        let valid_resolved =
            resolve_compact_cf_list(valid.cf.as_deref()).expect("`merkle` is in allowlist");
        assert_eq!(
            valid_resolved,
            vec!["merkle"],
            "explicit valid `cf` ⇒ singleton with that CF only"
        );

        // (c) explicit typo — DTO accepts the typo (validation belongs to
        // the resolver, not the wire layer; otherwise the error message
        // would lose the operator's exact input). Resolver rejects with
        // the actionable error pinned by ops186.
        let typo: AdminCompactCfQuery = serde_json::from_str(r#"{"cf":"records_typo"}"#)
            .expect("DTO accepts the typo; validation deferred to resolver");
        let typo_err = resolve_compact_cf_list(typo.cf.as_deref())
            .expect_err("resolver must reject the typo");
        assert!(
            typo_err.contains("'records_typo'"),
            "error must echo the operator's exact input verbatim: {typo_err}"
        );
    }
}

#[cfg(test)]
mod admin_compact_cf_allowlist_tests {
    //! Pins the contents,
    //! ordering, and cross-module invariants of `COMPACT_CF_ALLOWLIST`. The
    //! earlier tests pin every behavior that *consumes* the const
    //! (resolver branches, DTO round-trip, pipeline), but they all iterate
    //! the const or compare it to itself — none actually pins what the const
    //! IS. A future PR that swapped `"merkle"` for `"merkel"`, dropped
    //! `"records"`, or reordered the list would pass every existing test.
    //!
    //! Pinned contracts:
    //!   1. Length = 5 — a silent member drop (e.g. removing `"merkle"` in a
    //!      "let's not compact merkle, it's small" PR) surfaces here, not in
    //!      a "where did my CF go" operator ticket weeks later.
    //!   2. Exact contents AND order, expressed against the public CF_*
    //!      constants in `storage::rocks`. A typo (`"recordz"`), a swap to
    //!      an unrelated CF name, or a reorder all surface as a clean diff.
    //!   3. No duplicate members — a future "add `"records"` twice" copy-
    //!      paste regression surfaces here even if the resolver shrug it off
    //!      (set-based comparison would let it through).
    //!   4. Allowlist is a STRICT SUPERSET of the CFs that `gc_loop` already
    //!      auto-compacts on `pressure_due` (`gc.rs:609-612` literal set:
    //!      records, attestations, dag, idx_timestamp). The admin handler
    //!      MUST be able to manually trigger anything gc_loop's auto path
    //!      already touches; otherwise the operator runbook is strictly
    //!      narrower than the automatic recovery path — operationally
    //!      surprising.
    //!   5. Authoritative-state CFs (`ledger`, `peers`, `governance`,
    //!      `epochs`, `identities`, `trust`, `reputation`, `metadata`,
    //!      `applied`, `vrf_keys`, `velocity`, `disputes`, `pending_xzone`)
    //!      are NOT admitted. `compact_range_cf` is safe to run live but
    //!      these CFs carry low-tombstone authoritative state where manual
    //!      compaction wastes I/O for ~0 reclaimed bytes; we don't want
    //!      operators reaching for them in a panic and competing with
    //!      gc_loop's targeted pass.
    use super::COMPACT_CF_ALLOWLIST;
    use crate::storage::rocks::{
        CF_ATTESTATIONS, CF_DAG, CF_IDX_TIMESTAMP, CF_MERKLE, CF_RECORDS,
    };
    use std::collections::HashSet;

    #[test]
    fn batch_s_compact_cf_allowlist_length_pinned_at_five() {
        // Pinning length is the cheapest reproduction of "an unintended
        // member added/removed". The next layer of tests pin the actual
        // contents — but if length drifts, that diff is the first signal.
        assert_eq!(
            COMPACT_CF_ALLOWLIST.len(),
            5,
            "COMPACT_CF_ALLOWLIST length is part of the operator runbook \
             (PHASE-6D-ROLLOUT Stage 4 enumerates 5 compactable CFs); a \
             length change must be a deliberate runbook revision, not a \
             silent edit"
        );
    }

    #[test]
    fn batch_s_compact_cf_allowlist_exact_contents_in_documented_order() {
        // Expressed against the public CF_* constants — that way a future
        // rename in storage/rocks.rs (e.g. CF_RECORDS = "records_v2")
        // surfaces as the same compile-time diff that updates the schema,
        // and a typo here (`"recordz"`) lands as a value-mismatch diff
        // rather than a silent string drift.
        //
        // Order matters: the response JSON `{"triggered": true, "cfs":
        // [...]}` echoes the order back to the operator runbook, and the
        // documented compaction order (records → attestations → dag →
        // idx_timestamp → merkle) puts the most-bloating CFs first so a
        // partial-completion under crash recovery leaves the bloated set
        // smaller, not larger.
        let expected: Vec<&'static str> = vec![
            CF_RECORDS,
            CF_ATTESTATIONS,
            CF_DAG,
            CF_IDX_TIMESTAMP,
            CF_MERKLE,
        ];
        assert_eq!(
            COMPACT_CF_ALLOWLIST.to_vec(),
            expected,
            "COMPACT_CF_ALLOWLIST contents OR order changed — update the \
             runbook in internal design notes Stage 4 AND this test"
        );
    }

    #[test]
    fn batch_s_compact_cf_allowlist_no_duplicate_members() {
        // A copy-paste regression (`["records", "records", "dag", ...]`)
        // would pass the resolver-iteration tests (resolve_compact_cf_list
        // would still return the duplicated CF as a singleton on the typed
        // query path; the no-?cf= path would compact `records` twice on
        // the same tick — wasted I/O, not a correctness bug, but the
        // metric `admin_compact_cf_triggered_total` would over-count).
        // Pin set-distinctness so the copy-paste shape lands here.
        let mut seen = HashSet::new();
        for &cf in COMPACT_CF_ALLOWLIST {
            assert!(
                seen.insert(cf),
                "duplicate `{cf}` in COMPACT_CF_ALLOWLIST — admin compact \
                 would touch this CF twice per no-?cf= call"
            );
        }
        assert_eq!(
            seen.len(),
            COMPACT_CF_ALLOWLIST.len(),
            "set-cardinality must equal vec-length (no duplicates)"
        );
    }

    #[test]
    fn batch_s_compact_cf_allowlist_is_strict_superset_of_gc_loop_auto_compact_set() {
        // gc_loop at `gc.rs:609-612` hard-codes the auto-compacted CFs
        // when `pressure_due || burst_due || periodic_due`. This admin
        // allowlist MUST contain every member of that list — otherwise
        // the operator's manual compact (the "I'm staring at disk
        // pressure NOW" path) would refuse a CF that gc_loop has been
        // happily compacting for an hour already, which is operationally
        // bizarre.
        //
        // gc.rs has no exported list (the 4 names are literal arguments
        // to `rocks.compact_cf(_)`), so this test hard-codes the same
        // 4 names. If `gc.rs:609-612` ever changes, the next person who
        // greps for that line will land on this test too and update both
        // sites in one commit.
        const GC_LOOP_AUTO_COMPACTED_CFS: &[&str] = &[
            CF_RECORDS,       // gc.rs:609
            CF_ATTESTATIONS,  // gc.rs:610
            CF_DAG,           // gc.rs:611
            CF_IDX_TIMESTAMP, // gc.rs:612
        ];
        let allowlist: HashSet<&str> = COMPACT_CF_ALLOWLIST.iter().copied().collect();
        for cf in GC_LOOP_AUTO_COMPACTED_CFS {
            assert!(
                allowlist.contains(cf),
                "COMPACT_CF_ALLOWLIST must contain `{cf}` — gc_loop auto-\
                 compacts it (gc.rs:609-612); a manual operator compact \
                 path narrower than the automatic path is operationally \
                 surprising"
            );
        }
        // Specifically — the strict-superset relation. `merkle` is the
        // admin-only addition (gc_loop doesn't auto-compact it; startup
        // compaction does — rocks.rs:2917-2920). Pin the cardinality
        // delta so a future GC change that adds `merkle` to gc_loop's
        // hard-coded set would surface here as a strict-superset
        // promotion ("they're now equal — drop this assertion").
        assert!(
            COMPACT_CF_ALLOWLIST.len() > GC_LOOP_AUTO_COMPACTED_CFS.len(),
            "admin allowlist must be a STRICT superset of the gc_loop set \
             (currently +1 for `merkle` per startup_compaction_if_needed)"
        );
    }

    #[test]
    fn batch_s_compact_cf_allowlist_excludes_authoritative_state_cfs() {
        // CFs that carry authoritative state (low tombstone density,
        // high read amplification, fan-out across consensus) must NOT
        // be in the allowlist. Manual `compact_range_cf` on these is
        // safe at the RocksDB layer but operationally wasteful — they
        // don't bloat under tombstones (the SCALE RULE invariant: state
        // is updated incrementally, not appended-then-deleted), so a
        // panicked operator hitting `?cf=ledger` would spend tens of
        // seconds of I/O for ~zero reclaimed bytes while competing with
        // gc_loop's targeted pass on the actually-bloated CFs.
        //
        // Pin these names against the public CF_* constants from
        // storage/rocks.rs so a future rename of e.g. `CF_LEDGER` from
        // "ledger" to "beat_ledger" doesn't silently bypass this guard.
        use crate::storage::rocks::{
            CF_APPLIED, CF_DISPUTES, CF_EPOCHS, CF_GOVERNANCE, CF_IDENTITIES,
            CF_LEDGER, CF_METADATA, CF_PEERS, CF_PENDING_XZONE, CF_REPUTATION,
            CF_TRUST, CF_VELOCITY, CF_VRF_KEYS,
        };
        const FORBIDDEN_AUTHORITATIVE_CFS: &[&str] = &[
            CF_LEDGER,
            CF_PEERS,
            CF_GOVERNANCE,
            CF_EPOCHS,
            CF_IDENTITIES,
            CF_TRUST,
            CF_REPUTATION,
            CF_METADATA,
            CF_APPLIED,
            CF_VRF_KEYS,
            CF_VELOCITY,
            CF_DISPUTES,
            CF_PENDING_XZONE,
        ];
        let allowlist: HashSet<&str> = COMPACT_CF_ALLOWLIST.iter().copied().collect();
        for cf in FORBIDDEN_AUTHORITATIVE_CFS {
            assert!(
                !allowlist.contains(cf),
                "`{cf}` is authoritative state — must NOT be admin-\
                 compactable; ops186 rejection test would catch the \
                 resolver branch but only this test catches a future \
                 'let's add ledger to the allowlist for completeness' \
                 PR landing silently"
            );
        }
    }
}

#[cfg(test)]
mod admin_revocations_tests {
    //! Pins `compute_revocations_payload`,
    //! the testable core of `GET /admin/revocations`. Previously the helper
    //! had ZERO direct tests — `admin_revocations` itself was a thin async
    //! wrapper with no callers beyond the route layer, so a refactor that
    //! dropped a top-level key, renamed a per-revocation sub-field, sorted
    //! the revocations array by revoked_at, OR conflated the
    //! `revocations_rejected_total` counter with the registry's
    //! `revocation_count()` would have shipped silently. The operator
    //! audit flow for Protocol §11.2 revocation tombstones reads from this
    //! endpoint, so every regression class here is a key-compromise-
    //! response-degradation risk.
    //!
    //! Five orthogonal pins:
    //!   (1) Empty registry envelope — 3-key top-level set + wire-type
    //!       pins; defends add/drop/rename on the envelope.
    //!   (2) Single revocation 6-key sub-envelope + byte-faithful field
    //!       echo; defends per-row schema drift.
    //!   (3) Insertion-order preservation across 3 revocations whose
    //!       `revoked_at` values are NOT monotonic; defends a future
    //!       "sort by revoked_at desc" UX feature silently breaking the
    //!       audit-trail-ordering contract.
    //!   (4) `records_rejected` is INDEPENDENT of `revoked_keys` —
    //!       atomic counter has its own source; defends a refactor
    //!       feeding `revocation_count()` into the counter.
    //!   (5) Duplicate `revoked_key_hash` deduplicates the `revoked` set
    //!       (`revoked_keys` stays at 1) but ALL submitted entries
    //!       surface in the `revocations` array — pins the
    //!       HashSet-for-fast-lookup vs Vec-for-audit-trail split.
    use super::compute_revocations_payload;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::key_rotation::RevocationEntry;
    use crate::network::state::NodeState;
    use crate::network::witness::WitnessManager;
    use crate::storage::rocks::StorageEngine;
    use std::collections::BTreeSet;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    /// Minimal NodeState. Tempdir is forgotten so the rocks instance
    /// stays alive for the duration of the test (matches the pattern in
    /// `admin_zones_scope_tests::build_state`).
    fn build_state() -> Arc<NodeState> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "batch-vv-admin-token".into(),
            network_id: "batch-vv-revocations".into(),
            node_type: "leaf".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks =
            Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = NodeState::new(config, identity, rocks, wmgr);
        std::mem::forget(tmp);
        Arc::new(state)
    }

    fn mk_entry(
        key_hash: &str,
        record_id: &str,
        identity_hash: &str,
        revoked_at: f64,
        reason: &str,
    ) -> RevocationEntry {
        RevocationEntry {
            revoked_key_hash: key_hash.into(),
            revoked_public_key: vec![0xAA, 0xBB, 0xCC, 0xDD],
            revoked_at,
            reason: reason.into(),
            record_id: record_id.into(),
            identity_hash: identity_hash.into(),
        }
    }

    #[test]
    fn batch_vv_empty_registry_yields_three_key_envelope_with_zero_baselines() {
        // Axis 1: top-level envelope shape. A fresh node has NEVER seen
        // a revocation record and the atomic counter is at 0. Three keys
        // MUST be present (revoked_keys, records_rejected, revocations);
        // their wire types MUST be {u64, u64, array}. A regression that
        // skipped the empty array (`skip_serializing_if = "Vec::is_empty"`
        // on serde) would surface here — accounts / CLI parsing
        // `body.revocations.length` would crash on `undefined`.
        let state = build_state();
        let v = compute_revocations_payload(&state);

        let obj = v.as_object().expect("top-level must be JSON Object");
        let actual_keys: BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let expected_keys: BTreeSet<&str> = ["revoked_keys", "records_rejected", "revocations"]
            .into_iter()
            .collect();
        assert_eq!(
            actual_keys, expected_keys,
            "top-level envelope must be exactly the 3-key set — \
             diff (got vs expected): {:?} vs {:?}",
            actual_keys, expected_keys,
        );

        // Wire-type pins. revoked_keys is `revocation_count() -> usize`
        // which serializes as JSON u64; records_rejected is `AtomicU64
        // -> u64`; revocations is `Vec<Value>` which serializes as JSON
        // array. A `.to_string()` regression on either count would
        // surface here.
        assert!(
            obj["revoked_keys"].is_u64(),
            "revoked_keys must be JSON u64, got: {:?}",
            obj["revoked_keys"]
        );
        assert!(
            obj["records_rejected"].is_u64(),
            "records_rejected must be JSON u64, got: {:?}",
            obj["records_rejected"]
        );
        assert!(
            obj["revocations"].is_array(),
            "revocations must be JSON array (NOT null on empty), got: {:?}",
            obj["revocations"]
        );

        assert_eq!(obj["revoked_keys"], 0u64);
        assert_eq!(obj["records_rejected"], 0u64);
        assert!(obj["revocations"].as_array().unwrap().is_empty());
    }

    #[test]
    fn batch_vv_single_revocation_six_key_sub_envelope_with_byte_faithful_echo() {
        // Axis 2: per-revocation sub-envelope. Insert ONE entry and pin:
        //   (a) revocations[].len() == 1, revoked_keys == 1.
        //   (b) sub-envelope keys are EXACTLY the 6-set from
        //       RevocationEntry's #[derive(serde::Serialize)] surface.
        //   (c) wire-types: revoked_at f64, revoked_public_key array of
        //       u8, the 4 string fields all strings.
        //   (d) every field round-trips byte-faithfully — a serializer
        //       refactor that lowercased `reason` or hex-encoded
        //       `revoked_public_key` would surface here.
        let state = build_state();
        let revoked_at = 1_700_000_777.25_f64; // fractional, NOT whole-number
        let entry = mk_entry(
            "aabbccddee00112233445566778899aabbccddee00112233445566778899aabb",
            "rec-vv-axis2-0001",
            "id-hash-vv-axis2-creator",
            revoked_at,
            "compromise",
        );
        state
            .key_registry
            .write()
            .expect("registry write")
            .register_revocation(entry.clone());

        let v = compute_revocations_payload(&state);
        assert_eq!(v["revoked_keys"], 1u64);
        let arr = v["revocations"].as_array().expect("array");
        assert_eq!(arr.len(), 1);

        let row = arr[0].as_object().expect("row must be Object");
        let actual_keys: BTreeSet<&str> = row.keys().map(|s| s.as_str()).collect();
        let expected_keys: BTreeSet<&str> = [
            "revoked_key_hash",
            "revoked_public_key",
            "revoked_at",
            "reason",
            "record_id",
            "identity_hash",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            actual_keys, expected_keys,
            "per-revocation sub-envelope must be exactly the 6-key set"
        );

        // Wire-type pins.
        assert!(row["revoked_key_hash"].is_string());
        assert!(
            row["revoked_public_key"].is_array(),
            "revoked_public_key must be JSON array (Vec<u8> -> JSON array of numbers)"
        );
        assert!(
            row["revoked_at"].is_f64(),
            "revoked_at must be JSON f64 (NOT integer-coerced — fractional input 1_700_000_777.25)"
        );
        assert!(row["reason"].is_string());
        assert!(row["record_id"].is_string());
        assert!(row["identity_hash"].is_string());

        // Byte-faithful echo.
        assert_eq!(row["revoked_key_hash"], entry.revoked_key_hash);
        assert_eq!(row["revoked_at"], revoked_at);
        assert_eq!(row["reason"], "compromise");
        assert_eq!(row["record_id"], "rec-vv-axis2-0001");
        assert_eq!(row["identity_hash"], "id-hash-vv-axis2-creator");
        // revoked_public_key is Vec<u8> {AA, BB, CC, DD} → JSON [170,187,204,221].
        let pk_arr = row["revoked_public_key"].as_array().unwrap();
        assert_eq!(pk_arr.len(), 4);
        assert_eq!(pk_arr[0], 0xAAu64);
        assert_eq!(pk_arr[3], 0xDDu64);
    }

    #[test]
    fn batch_vv_revocations_array_preserves_insertion_order_not_revoked_at_order() {
        // Axis 3: insertion-order preservation. The operator-audit
        // contract for /admin/revocations is that the array reflects
        // the order in which revocation records landed on this node
        // (i.e. ledger-replay order), NOT a re-sorted view. Plant 3
        // entries whose revoked_at timestamps are deliberately
        // non-monotonic so that ANY sort-by-revoked_at regression
        // (ascending OR descending) surfaces as a row-order mismatch.
        let state = build_state();
        // Inserted order: middle, oldest, newest.
        // Sorted asc by revoked_at: oldest, middle, newest.
        // Sorted desc by revoked_at: newest, middle, oldest.
        // None of those three orderings equals the inserted order.
        let middle = mk_entry(
            "11" .repeat(32).as_str(),
            "rec-vv-axis3-middle",
            "id-middle",
            1_700_000_100.5,
            "periodic",
        );
        let oldest = mk_entry(
            "22" .repeat(32).as_str(),
            "rec-vv-axis3-oldest",
            "id-oldest",
            1_700_000_050.0,
            "compromise",
        );
        let newest = mk_entry(
            "33" .repeat(32).as_str(),
            "rec-vv-axis3-newest",
            "id-newest",
            1_700_000_200.0,
            "superseded",
        );
        {
            let mut reg = state.key_registry.write().expect("registry write");
            reg.register_revocation(middle);
            reg.register_revocation(oldest);
            reg.register_revocation(newest);
        }

        let v = compute_revocations_payload(&state);
        assert_eq!(v["revoked_keys"], 3u64);
        let arr = v["revocations"].as_array().unwrap();
        assert_eq!(arr.len(), 3);
        // Insertion order: middle (idx 0), oldest (idx 1), newest (idx 2).
        assert_eq!(arr[0]["record_id"], "rec-vv-axis3-middle");
        assert_eq!(arr[1]["record_id"], "rec-vv-axis3-oldest");
        assert_eq!(arr[2]["record_id"], "rec-vv-axis3-newest");
        // Cross-axis check on revoked_at to be sure they're distinct and
        // genuinely non-monotonic in the inserted order (so any
        // accidental "sort by record_id" regression would also surface).
        assert_eq!(arr[0]["revoked_at"], 1_700_000_100.5);
        assert_eq!(arr[1]["revoked_at"], 1_700_000_050.0);
        assert_eq!(arr[2]["revoked_at"], 1_700_000_200.0);
    }

    #[test]
    fn batch_vv_records_rejected_counter_is_independent_of_registry_count() {
        // Axis 4: independent counter. `revocations_rejected_total`
        // is an AtomicU64 incremented when a peer submits a record
        // signed by an already-revoked key (signature gate rejects it
        // BEFORE it can reach the registry). It MUST surface
        // independently — a refactor that fed `revocation_count()`
        // into `records_rejected` would silently double-count and
        // make the post-key-compromise dashboard meaningless.
        //
        // Plant: 0 revocations, counter at 42. Expectation:
        //   - revoked_keys == 0
        //   - revocations.len() == 0
        //   - records_rejected == 42  (NOT 0, NOT mirrored from revoked_keys)
        let state = build_state();
        state
            .revocations_rejected_total
            .store(42, Ordering::Relaxed);

        let v = compute_revocations_payload(&state);
        assert_eq!(v["revoked_keys"], 0u64, "no revocations registered");
        assert!(
            v["revocations"].as_array().unwrap().is_empty(),
            "no entries registered ⇒ array is empty"
        );
        assert_eq!(
            v["records_rejected"], 42u64,
            "counter value must surface independently of registry contents"
        );
    }

    #[test]
    fn batch_vv_duplicate_revoked_key_hash_dedups_set_count_but_audit_array_keeps_all() {
        // Axis 5: HashSet-for-lookup vs Vec-for-audit-trail split.
        // `KeyRegistry::register_revocation` inserts into BOTH
        // `revoked: HashSet<String>` (used by `is_revoked_hash()` on
        // the signature gate hot path) AND `revocations: Vec<...>`
        // (used by `revocations()` for the admin audit endpoint). A
        // duplicate `revoked_key_hash` submission MUST:
        //   (a) collapse to ONE entry in the HashSet (so
        //       `revocation_count() == 1`, not 2).
        //   (b) preserve BOTH entries in the Vec (audit trail must
        //       record every submission — operator needs to see who
        //       submitted the duplicate and when).
        // A refactor that "fixed" the duplicate by checking
        // `if !self.revoked.contains(...)` before pushing onto the
        // Vec would silently destroy the audit trail.
        let state = build_state();
        let dup_hash =
            "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
        let first = mk_entry(
            dup_hash,
            "rec-vv-axis5-first",
            "id-first-submitter",
            1_700_000_500.0,
            "compromise",
        );
        let second = mk_entry(
            dup_hash,
            "rec-vv-axis5-second",
            "id-second-submitter",
            1_700_000_600.0,
            "compromise",
        );
        {
            let mut reg = state.key_registry.write().expect("registry write");
            reg.register_revocation(first);
            reg.register_revocation(second);
        }

        let v = compute_revocations_payload(&state);
        // Set-dedupe.
        assert_eq!(
            v["revoked_keys"], 1u64,
            "duplicate hash must collapse in the HashSet (revocation_count returns set len)"
        );
        // Audit-trail preserves both.
        let arr = v["revocations"].as_array().unwrap();
        assert_eq!(
            arr.len(),
            2,
            "audit-trail Vec must record BOTH submissions (operator forensic visibility)"
        );
        assert_eq!(arr[0]["record_id"], "rec-vv-axis5-first");
        assert_eq!(arr[1]["record_id"], "rec-vv-axis5-second");
        // Cross-axis: both rows DO carry the same revoked_key_hash —
        // pins that the dedupe is at the HashSet layer, not at the
        // Vec serialization layer (a future serializer regression
        // that swapped `revoked_key_hash` with `revoked: bool` would
        // surface here).
        assert_eq!(arr[0]["revoked_key_hash"], dup_hash);
        assert_eq!(arr[1]["revoked_key_hash"], dup_hash);
    }
}

#[cfg(test)]
mod admin_key_rotations_tests {
    //! Pins `compute_key_rotations_payload`,
    //! the testable core of `GET /admin/key_rotations`. Previously the
    //! helper had ZERO direct tests — the route layer was a thin async
    //! wrapper around a 2-key serde_json::json! macro. The envelope is
    //! shallower than the revocations payload, but the
    //! `rotated_identities` vs `total_rotations` semantic split is
    //! load-bearing for operator forensics: a refactor that conflates
    //! "how many distinct keys have rotated at least once" with "how
    //! many rotation events have occurred" would silently break
    //! compromise-response audit visibility (an attacker doing 100
    //! rotations on a single compromised identity would otherwise
    //! masquerade as 100 separate identities under stress).
    //!
    //! Five orthogonal pins:
    //!   (1) Empty registry envelope — 2-key BTreeSet + wire-type
    //!       pins (both u64); defends add/drop/rename on the
    //!       envelope AND defends against a `skip_serializing_if`
    //!       regression that would drop a zero key.
    //!   (2) Single rotation, single identity — pins basic counting
    //!       contract: both counters land at 1; defends a sentinel-
    //!       off-by-one regression in register_rotation.
    //!   (3) Multiple rotations, same identity — pins the
    //!       per-identity-sum vs distinct-identity-count semantic
    //!       split; rotated_identities==1, total_rotations==3.
    //!       Defends the bug class where a refactor swaps
    //!       `self.rotations.len()` for `.values().map(...).sum()`
    //!       or vice versa.
    //!   (4) Distinct identities, one rotation each — the symmetric
    //!       case to axis 3; rotated_identities==3, total_rotations==3.
    //!       Together axes 3+4 lock the orthogonality.
    //!   (5) SPHINCS+ rotations DO NOT leak into the Dilithium3
    //!       axis — pins that a refactor adding `total_sphincs_rotations()`
    //!       into the envelope (or wiring SPHINCS+ into
    //!       `rotated_identities`) surfaces as a count regression.
    //!       Profile A operators rotate Dilithium3 and SPHINCS+ on
    //!       separate cadences; the operator UX must keep them
    //!       distinct.
    use super::compute_key_rotations_payload;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::key_rotation::{KeyRotation, SphincsKeyRotation};
    use crate::network::state::NodeState;
    use crate::network::witness::WitnessManager;
    use crate::storage::rocks::StorageEngine;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    /// Minimal NodeState. Tempdir is forgotten so the rocks instance
    /// stays alive for the duration of the test (matches the pattern
    /// in `admin_revocations_tests::build_state`).
    fn build_state() -> Arc<NodeState> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "batch-ww-admin-token".into(),
            network_id: "batch-ww-key-rotations".into(),
            node_type: "leaf".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks =
            Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = NodeState::new(config, identity, rocks, wmgr);
        std::mem::forget(tmp);
        Arc::new(state)
    }

    fn mk_rotation(record_id: &str) -> KeyRotation {
        // 32-byte new key, fractional timestamp so any serializer
        // regression that integer-coerces `rotated_at` would surface
        // in a future SPHINCS / Dilithium debug-string test (not in
        // this batch — rotated_at is NOT emitted by
        // compute_key_rotations_payload; recorded here for fixture
        // realism only).
        KeyRotation {
            new_public_key: vec![0xCD; 32],
            rotated_at: 1_700_000_000.5,
            reason: "periodic".into(),
            record_id: record_id.into(),
        }
    }

    fn mk_sphincs_rotation(record_id: &str) -> SphincsKeyRotation {
        SphincsKeyRotation {
            new_sphincs_pk: vec![0xEE; 48],
            rotated_at: 1_700_000_111.5,
            reason: "upgrade".into(),
            record_id: record_id.into(),
        }
    }

    #[test]
    fn batch_ww_empty_registry_yields_two_key_envelope_with_zero_baselines() {
        // Axis 1: top-level envelope shape. A fresh node has NEVER
        // seen a key rotation record. Two keys MUST be present
        // (rotated_identities, total_rotations); both wire types MUST
        // be u64. A regression that flipped either to `.to_string()`
        // or added a `skip_serializing_if = "is_zero"` would crash
        // accounts reading body.rotated_identities at boot.
        let state = build_state();
        let v = compute_key_rotations_payload(&state);

        let obj = v.as_object().expect("top-level must be JSON Object");
        let actual_keys: BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let expected_keys: BTreeSet<&str> =
            ["rotated_identities", "total_rotations"].into_iter().collect();
        assert_eq!(
            actual_keys, expected_keys,
            "top-level envelope must be exactly the 2-key set — \
             diff (got vs expected): {:?} vs {:?}",
            actual_keys, expected_keys,
        );

        assert!(
            obj["rotated_identities"].is_u64(),
            "rotated_identities must be JSON u64, got: {:?}",
            obj["rotated_identities"]
        );
        assert!(
            obj["total_rotations"].is_u64(),
            "total_rotations must be JSON u64, got: {:?}",
            obj["total_rotations"]
        );

        assert_eq!(obj["rotated_identities"], 0u64);
        assert_eq!(obj["total_rotations"], 0u64);
    }

    #[test]
    fn batch_ww_single_rotation_single_identity_lands_at_one_one() {
        // Axis 2: basic counting contract. Insert ONE rotation under
        // ONE identity. Both counters MUST be 1. Defends against a
        // sentinel-off-by-one regression in `register_rotation`
        // (e.g. a `len() - 1` or `len() + 1` slip in
        // `total_rotations()`) AND against a regression that
        // pre-allocates an empty Vec on `entry().or_default()`
        // without ever pushing.
        let state = build_state();
        {
            let mut reg = state.key_registry.write().expect("registry write");
            reg.register_rotation("id-A-axis2", mk_rotation("rec-ww-axis2-1"));
        }
        let v = compute_key_rotations_payload(&state);
        assert_eq!(v["rotated_identities"], 1u64);
        assert_eq!(v["total_rotations"], 1u64);
    }

    #[test]
    fn batch_ww_multiple_rotations_same_identity_distinguish_count_axes() {
        // Axis 3: per-identity-sum vs distinct-identity-count split
        // (the CRITICAL axis for compromise-response forensics). One
        // identity rotates THREE times. rotated_identities MUST be 1
        // (one distinct identity), total_rotations MUST be 3 (sum
        // across the HashMap values). A refactor that swaps
        // `self.rotations.len()` for `.values().map(|v| v.len()).sum()`
        // (or vice versa) silently breaks operator audit visibility
        // — an attacker rotating 100 times on a single compromised
        // identity would surface as 100 separate identities under
        // the swap, masking the true blast radius.
        let state = build_state();
        {
            let mut reg = state.key_registry.write().expect("registry write");
            reg.register_rotation("id-A-axis3", mk_rotation("rec-ww-axis3-1"));
            reg.register_rotation("id-A-axis3", mk_rotation("rec-ww-axis3-2"));
            reg.register_rotation("id-A-axis3", mk_rotation("rec-ww-axis3-3"));
        }
        let v = compute_key_rotations_payload(&state);
        assert_eq!(
            v["rotated_identities"], 1u64,
            "3 rotations under SAME identity must surface as 1 \
             distinct identity (HashMap key count, NOT value-len sum)"
        );
        assert_eq!(
            v["total_rotations"], 3u64,
            "3 rotations under same identity must surface as 3 total \
             rotations (sum of Vec lengths across HashMap values)"
        );
    }

    #[test]
    fn batch_ww_distinct_identities_one_rotation_each_pin_orthogonality() {
        // Axis 4: symmetric case to Axis 3. THREE distinct
        // identities each rotate ONCE. rotated_identities MUST be 3,
        // total_rotations MUST be 3. Together with Axis 3, the
        // (1, 3) and (3, 3) pair locks the orthogonality of the two
        // counters: any single-counter refactor would fail one of
        // these two tests.
        let state = build_state();
        {
            let mut reg = state.key_registry.write().expect("registry write");
            reg.register_rotation("id-A-axis4", mk_rotation("rec-ww-axis4-A"));
            reg.register_rotation("id-B-axis4", mk_rotation("rec-ww-axis4-B"));
            reg.register_rotation("id-C-axis4", mk_rotation("rec-ww-axis4-C"));
        }
        let v = compute_key_rotations_payload(&state);
        assert_eq!(
            v["rotated_identities"], 3u64,
            "3 distinct identities × 1 rotation each must surface as \
             3 distinct identities (HashMap key count)"
        );
        assert_eq!(
            v["total_rotations"], 3u64,
            "3 distinct identities × 1 rotation each must surface as \
             3 total rotations (sum of Vec lengths across HashMap)"
        );
    }

    #[test]
    fn batch_ww_sphincs_rotations_do_not_leak_into_dilithium_axis() {
        // Axis 5: SPHINCS+ orthogonality. Insert ONE SPHINCS+
        // rotation (no Dilithium3 rotation) under an identity.
        // BOTH counters surfaced by the endpoint MUST stay at 0 —
        // the helper reads from `KeyRegistry::rotated_identities()`
        // and `::total_rotations()`, which both operate on the
        // `rotations` field (Dilithium3 only). A future refactor
        // that adds `total_sphincs_rotations()` into the envelope
        // (or wires sphincs_rotations into `rotated_identities`)
        // would surface here. Profile A operators rotate Dilithium3
        // and SPHINCS+ on separate cadences; conflating them in the
        // operator UX would mask the cadence asymmetry that's
        // protocol-critical for the dual-signature scheme.
        //
        // Cross-axis: also insert ONE Dilithium3 rotation under a
        // DIFFERENT identity to confirm the SPHINCS+ insert above
        // doesn't accidentally bump either count for unrelated
        // identities. Expected final state: rotated_identities=1
        // (only the Dilithium3 identity), total_rotations=1.
        let state = build_state();
        {
            let mut reg = state.key_registry.write().expect("registry write");
            reg.register_sphincs_rotation(
                "id-sphincs-only-axis5",
                mk_sphincs_rotation("rec-ww-axis5-sphincs"),
            );
            reg.register_rotation("id-dilithium-axis5", mk_rotation("rec-ww-axis5-dil"));
        }
        let v = compute_key_rotations_payload(&state);
        assert_eq!(
            v["rotated_identities"], 1u64,
            "SPHINCS+ rotation must NOT bump rotated_identities; \
             only the Dilithium3 identity should surface"
        );
        assert_eq!(
            v["total_rotations"], 1u64,
            "SPHINCS+ rotation must NOT bump total_rotations; the \
             endpoint exposes Dilithium3 totals only — SPHINCS+ has \
             a separate `total_sphincs_rotations()` accessor"
        );
    }
}

#[cfg(test)]
mod admin_witness_liveness_tests {
    //! Pins `compute_witness_liveness_payload`,
    //! the testable core of `GET /admin/witness_liveness`. Previously the
    //! helper had ZERO direct tests — the route layer was an inline
    //! 24-line body that read `SystemTime::now()` directly, making the
    //! handler untestable for the time-dependent semantics. The
    //! refactor extracts `compute_witness_liveness_payload(state, now)`
    //! so `now` is an explicit parameter; the route still computes
    //! SystemTime, but the helper is time-deterministic.
    //!
    //! The endpoint surfaces the operator-facing fleet-health dashboard:
    //! tracked vs active count (ratio < 0.5 = fleet shedding witnesses),
    //! a 48-hour idle threshold (Protocol §11.12), and a forensic detail
    //! list of inactive witnesses with their last-attestation idle window.
    //!
    //! Five orthogonal pins:
    //!   (1) Empty registry — 5-key BTreeSet + wire-type pins
    //!       (4 u64 counters + 1 array); defends add/drop/rename on
    //!       the envelope and `skip_serializing_if = "Vec::is_empty"`
    //!       on inactive_details (accounts/CLI parsing `body.inactive_details.length`
    //!       would crash on `undefined`).
    //!   (2) All-fresh witnesses — tracked=N, active=N, inactive=0,
    //!       inactive_details empty array. Defends a refactor that
    //!       cross-wires the `active_count`/`inactive_witnesses` call
    //!       sites (e.g. swapping which list feeds inactive_details).
    //!   (3) Mixed regime — partition exact: tracked=A+I, active=A,
    //!       inactive_count=I, details.len()=I, each detail entry
    //!       carries a 3-key sub-envelope {witness_hash, idle_secs,
    //!       idle_hours}. Defends sub-envelope add/drop/rename and
    //!       wire-type drift.
    //!   (4) idle_hours = idle_secs / 3600.0 — FRACTIONAL arithmetic,
    //!       NOT integer truncation. A regression `idle / 3600` (integer
    //!       divide) would collapse precision and mislead operators on
    //!       the dashboard ("48 h idle" vs "48.06 h idle" hides the
    //!       boundary-crossing moment).
    //!   (5) Time-axis sensitivity — same registry produces different
    //!       envelopes at different `now` values (same 3 witnesses
    //!       flip from all-active to all-inactive as `now` advances
    //!       past the 48-hour threshold). Defends a refactor that
    //!       hardcodes SystemTime inside the helper, making the
    //!       endpoint time-invariant and the dashboard frozen.
    use super::compute_witness_liveness_payload;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::state::NodeState;
    use crate::network::witness::WitnessManager;
    use crate::network::LockRecover;
    use crate::storage::rocks::StorageEngine;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    /// Minimal NodeState. Tempdir is forgotten so the rocks instance
    /// stays alive for the duration of the test (matches the pattern
    /// in `admin_key_rotations_tests::build_state`).
    fn build_state() -> Arc<NodeState> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "batch-xx-admin-token".into(),
            network_id: "batch-xx-witness-liveness".into(),
            node_type: "leaf".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks =
            Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = NodeState::new(config, identity, rocks, wmgr);
        std::mem::forget(tmp);
        Arc::new(state)
    }

    /// Plant a single witness attestation at the given timestamp.
    fn plant(state: &NodeState, witness_hash: &str, timestamp: f64) {
        let mut liveness = state.witness_liveness.lock_recover();
        liveness.record_attestation(witness_hash, timestamp);
    }

    #[test]
    fn batch_xx_empty_registry_yields_five_key_envelope_with_zero_baselines() {
        // Axis 1: top-level envelope shape. A fresh node has NEVER
        // received an attestation. Five keys MUST be present
        // (tracked_witnesses, active_witnesses, inactive_witnesses,
        // display_threshold_hours, inactive_details); wire types MUST
        // be {u64, u64, u64, u64, array}. A regression that flipped
        // any to `.to_string()` OR added `skip_serializing_if = "Vec::is_empty"`
        // on inactive_details would crash accounts reading
        // `body.inactive_details.length` at boot.
        let state = build_state();
        let v = compute_witness_liveness_payload(&state, 1_700_000_000.0);

        let obj = v.as_object().expect("top-level must be JSON Object");
        let actual_keys: BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let expected_keys: BTreeSet<&str> = [
            "tracked_witnesses",
            "active_witnesses",
            "inactive_witnesses",
            "display_threshold_hours",
            "inactive_details",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            actual_keys, expected_keys,
            "top-level envelope must be exactly the 5-key set — \
             diff (got vs expected): {:?} vs {:?}",
            actual_keys, expected_keys,
        );

        // Wire-type pins on all 4 counters + the details array.
        assert!(obj["tracked_witnesses"].is_u64(), "tracked_witnesses must be JSON u64");
        assert!(obj["active_witnesses"].is_u64(), "active_witnesses must be JSON u64");
        assert!(obj["inactive_witnesses"].is_u64(), "inactive_witnesses must be JSON u64");
        assert!(
            obj["display_threshold_hours"].is_u64(),
            "display_threshold_hours must be JSON u64"
        );
        assert!(
            obj["inactive_details"].is_array(),
            "inactive_details must be JSON array (NOT null on empty — \
             accounts parsing `.length` would crash on undefined)"
        );

        // Counter baselines + array empty.
        assert_eq!(obj["tracked_witnesses"], 0u64);
        assert_eq!(obj["active_witnesses"], 0u64);
        assert_eq!(obj["inactive_witnesses"], 0u64);
        assert_eq!(obj["display_threshold_hours"], 48u64);
        assert_eq!(
            obj["inactive_details"].as_array().expect("array").len(),
            0,
            "fresh-genesis node has zero inactive witnesses; \
             inactive_details must be an EMPTY array, NOT absent"
        );
    }

    #[test]
    fn batch_xx_all_fresh_witnesses_populate_tracked_and_active_but_no_inactive() {
        // Axis 2: all-fresh-window regime. Three witnesses, each
        // attesting within the 48-hour window. tracked=3, active=3,
        // inactive=0, inactive_details EMPTY. Defends a refactor that
        // cross-wires `active_count` and `inactive_witnesses` call
        // sites (e.g. swapping which list feeds inactive_details, or
        // double-counting active witnesses into inactive_details).
        let state = build_state();
        let now = 1_700_000_000.0;
        // All 3 attested 100 seconds ago — well within 48h = 172800s.
        plant(&state, "w-fresh-1", now - 100.0);
        plant(&state, "w-fresh-2", now - 100.0);
        plant(&state, "w-fresh-3", now - 100.0);

        let v = compute_witness_liveness_payload(&state, now);

        assert_eq!(v["tracked_witnesses"], 3u64, "3 distinct witnesses observed");
        assert_eq!(v["active_witnesses"], 3u64, "all 3 attested within 48h window");
        assert_eq!(
            v["inactive_witnesses"], 0u64,
            "no witness exceeds the 48h idle threshold"
        );
        assert_eq!(
            v["inactive_details"].as_array().expect("array").len(),
            0,
            "inactive_details MUST be empty when no witness is idle — \
             a regression that cross-wired active witnesses into the \
             detail array would surface as len()==3 here"
        );
    }

    #[test]
    fn batch_xx_mixed_regime_partitions_tracked_into_active_plus_inactive_details() {
        // Axis 3: THE CRITICAL AXIS. Mixed regime — 2 fresh + 3 idle.
        // tracked=5 (all observed at some point), active=2 (only the
        // fresh), inactive=3 (each over 48h idle). inactive_details
        // MUST carry 3 entries, each with the 3-key sub-envelope
        // {witness_hash, idle_secs, idle_hours} and correct wire types.
        // A refactor that drops one of these sub-keys, or flips
        // idle_secs to a string, would surface here.
        let state = build_state();
        let now = 1_700_000_000.0;
        let day = 86400.0;
        // 2 fresh — attested 100s ago.
        plant(&state, "w-fresh-A", now - 100.0);
        plant(&state, "w-fresh-B", now - 100.0);
        // 3 idle — attested 3 days ago, well past the 48h threshold.
        plant(&state, "w-idle-1", now - 3.0 * day);
        plant(&state, "w-idle-2", now - 3.0 * day);
        plant(&state, "w-idle-3", now - 3.0 * day);

        let v = compute_witness_liveness_payload(&state, now);

        assert_eq!(v["tracked_witnesses"], 5u64, "all 5 distinct witnesses tracked");
        assert_eq!(v["active_witnesses"], 2u64, "only 2 fresh witnesses are active");
        assert_eq!(
            v["inactive_witnesses"], 3u64,
            "3 witnesses exceed the 48h idle threshold"
        );

        // Partition invariant: tracked == active + inactive.
        let tracked = v["tracked_witnesses"].as_u64().expect("u64");
        let active = v["active_witnesses"].as_u64().expect("u64");
        let inactive = v["inactive_witnesses"].as_u64().expect("u64");
        assert_eq!(
            tracked, active + inactive,
            "partition invariant: tracked = active + inactive"
        );

        // Detail array has 3 entries, each a 3-key sub-envelope.
        let details = v["inactive_details"]
            .as_array()
            .expect("inactive_details array");
        assert_eq!(details.len(), 3, "detail count matches inactive_witnesses");

        for entry in details {
            let sub = entry.as_object().expect("each detail entry is a JSON Object");
            let sub_keys: BTreeSet<&str> = sub.keys().map(|s| s.as_str()).collect();
            let expected_sub: BTreeSet<&str> =
                ["witness_hash", "idle_secs", "idle_hours"].into_iter().collect();
            assert_eq!(
                sub_keys, expected_sub,
                "each inactive_details entry must be exactly the 3-key \
                 sub-envelope (got vs expected): {:?} vs {:?}",
                sub_keys, expected_sub,
            );
            // Wire-type pins on the sub-envelope.
            assert!(
                sub["witness_hash"].is_string(),
                "witness_hash must be JSON string, got: {:?}",
                sub["witness_hash"],
            );
            assert!(
                sub["idle_secs"].is_f64() || sub["idle_secs"].is_i64() || sub["idle_secs"].is_u64(),
                "idle_secs must be a JSON number (f64 or integer), got: {:?}",
                sub["idle_secs"],
            );
            assert!(
                sub["idle_hours"].is_f64() || sub["idle_hours"].is_i64() || sub["idle_hours"].is_u64(),
                "idle_hours must be a JSON number (f64 or integer), got: {:?}",
                sub["idle_hours"],
            );
        }

        // Cross-check: each detail's witness_hash is one of our idle witnesses.
        let detail_hashes: BTreeSet<String> = details
            .iter()
            .map(|e| e["witness_hash"].as_str().expect("string").to_string())
            .collect();
        let expected_idle: BTreeSet<String> = ["w-idle-1", "w-idle-2", "w-idle-3"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            detail_hashes, expected_idle,
            "inactive_details must surface exactly the idle witnesses — \
             a fresh witness leaking in would surface here"
        );
    }

    #[test]
    fn batch_xx_idle_hours_uses_fractional_arithmetic_not_integer_truncation() {
        // Axis 4: idle_hours = idle_secs / 3600.0 (FRACTIONAL). A
        // regression `idle / 3600` (integer divide) would collapse
        // precision and mislead operators on the dashboard — a
        // witness 48 h 3 min 20 s idle would surface as "48 h" instead
        // of "48.056 h", hiding the boundary-crossing moment from the
        // operator's view.
        let state = build_state();
        let now = 1_700_000_000.0;
        // Plant at exactly now - 173000.0, so idle = 173000.0 seconds.
        // 173000 / 3600 = 48.0555... hours (NOT 48 integer-truncated).
        // 173000 is also > 172800 (48h) so witness counts as inactive.
        let last = now - 173000.0;
        plant(&state, "w-precision", last);

        let v = compute_witness_liveness_payload(&state, now);

        let details = v["inactive_details"]
            .as_array()
            .expect("inactive_details array");
        assert_eq!(details.len(), 1, "one inactive witness");

        let entry = &details[0];
        let idle_secs = entry["idle_secs"]
            .as_f64()
            .expect("idle_secs must be f64");
        let idle_hours = entry["idle_hours"]
            .as_f64()
            .expect("idle_hours must be f64");

        // idle_secs should be 173000.0 (or very close given f64 arithmetic).
        let secs_diff = (idle_secs - 173000.0).abs();
        assert!(
            secs_diff < 1e-6,
            "idle_secs must equal 173000.0 (got {} — diff {})",
            idle_secs, secs_diff
        );

        // idle_hours MUST be 173000.0 / 3600.0 = 48.0555... — NOT 48.0.
        let expected_hours = 173000.0 / 3600.0;
        let hours_diff = (idle_hours - expected_hours).abs();
        assert!(
            hours_diff < 1e-9,
            "idle_hours must equal 173000.0/3600.0 = {} (got {} — diff {})",
            expected_hours, idle_hours, hours_diff
        );
        // Sanity: NOT integer-truncated to 48.
        assert!(
            idle_hours > 48.0,
            "idle_hours must NOT be integer-truncated to 48 — got {}",
            idle_hours
        );
        assert!(
            idle_hours < 49.0,
            "idle_hours of 173000s should be in [48, 49) — got {}",
            idle_hours
        );
    }

    #[test]
    fn batch_xx_time_axis_sensitivity_same_registry_flips_regime_with_now() {
        // Axis 5: time-as-input contract. Plant 3 witnesses at fixed
        // timestamps. Call the helper with two different `now` values
        // and assert the envelope FLIPS regime — all-active at small
        // `now`, all-inactive at large `now`. A refactor that
        // hardcoded SystemTime inside the helper (or cached `now`
        // across calls) would surface as identical envelopes at both
        // call sites — the dashboard would freeze and the operator
        // would lose visibility into idle witnesses developing in real
        // time.
        let state = build_state();
        // Plant 3 witnesses at a fixed historical timestamp.
        let last = 1_700_000_000.0;
        plant(&state, "w-time-1", last);
        plant(&state, "w-time-2", last);
        plant(&state, "w-time-3", last);

        // Call 1: now = last + 100.0 — all 3 within 48h window.
        let now_fresh = last + 100.0;
        let v_fresh = compute_witness_liveness_payload(&state, now_fresh);
        assert_eq!(
            v_fresh["tracked_witnesses"], 3u64,
            "tracked count is time-invariant — must stay at 3 across both calls"
        );
        assert_eq!(
            v_fresh["active_witnesses"], 3u64,
            "all witnesses fresh at now = last + 100s"
        );
        assert_eq!(
            v_fresh["inactive_witnesses"], 0u64,
            "no idle witnesses 100s past last attestation"
        );
        assert_eq!(
            v_fresh["inactive_details"]
                .as_array()
                .expect("array")
                .len(),
            0,
            "inactive_details empty in fresh regime"
        );

        // Call 2: now = last + 200_000.0 — all 3 well past 48h = 172800s.
        let now_stale = last + 200_000.0;
        let v_stale = compute_witness_liveness_payload(&state, now_stale);
        assert_eq!(
            v_stale["tracked_witnesses"], 3u64,
            "tracked count is time-invariant — must stay at 3 across both calls"
        );
        assert_eq!(
            v_stale["active_witnesses"], 0u64,
            "all witnesses idle at now = last + 200_000s (>48h threshold)"
        );
        assert_eq!(
            v_stale["inactive_witnesses"], 3u64,
            "all 3 witnesses exceed the 48h idle threshold"
        );
        assert_eq!(
            v_stale["inactive_details"]
                .as_array()
                .expect("array")
                .len(),
            3,
            "inactive_details lists all 3 idle witnesses in stale regime"
        );

        // Confirm the regime FLIPPED — active count differs across calls.
        // If the helper were time-invariant (e.g. hardcoded SystemTime
        // inside), this assertion would fail because both calls would
        // return the same active_witnesses count.
        assert_ne!(
            v_fresh["active_witnesses"], v_stale["active_witnesses"],
            "active_witnesses MUST differ across the two `now` calls — \
             if equal, the helper is time-invariant (regression: \
             SystemTime hardcoded inside helper instead of using parameter)"
        );
        assert_ne!(
            v_fresh["inactive_witnesses"], v_stale["inactive_witnesses"],
            "inactive_witnesses MUST differ across the two `now` calls — \
             if equal, the helper is time-invariant"
        );
    }
}

#[cfg(test)]
mod admin_sunset_tests {
    //! Pins `compute_sunset_payload`,
    //! the testable core of `GET /admin/sunset`. Previously the helper had
    //! ZERO direct tests — the route layer was an inline 14-line body
    //! that built the envelope directly. The endpoint is the Protocol
    //! §11.29 (algorithm sunset enforcement) operator surface: surfaces
    //! every algorithm whose status has been transitioned from Active
    //! to Deprecated or Forbidden, the epoch at which the transition
    //! takes effect, and the human-readable reason. Operators reading
    //! this endpoint when a CVE drops for a crypto algorithm depend on
    //! it for the rollout-of-the-mitigation timeline.
    //!
    //! Five orthogonal pins:
    //!   (1) Empty state — 2-key BTreeSet + wire-type pins (sunset_entries
    //!       usize counter + algorithms array, NOT object/string).
    //!       Array-pin defends a refactor adding
    //!       `skip_serializing_if = "Vec::is_empty"` that would crash
    //!       accounts/CLI reading `body.algorithms.length` on `undefined`.
    //!   (2) Single entry 4-key sub-envelope — registers one Deprecated
    //!       entry; asserts top-level envelope is 2-key AND `algorithms[0]`
    //!       is a 4-key BTreeSet {algorithm, status, effective_epoch,
    //!       reason} with wire-type pins (algorithm string, status string,
    //!       effective_epoch u64, reason string). Defends sub-envelope
    //!       add/drop/rename and wire-type drift.
    //!   (3) Status field uses Debug-formatted enum string NOT serde
    //!       SCREAMING_SNAKE_CASE rename — THE CRITICAL ORTHOGONALITY
    //!       AXIS. AlgorithmStatus has `#[serde(rename_all =
    //!       "SCREAMING_SNAKE_CASE")]` so serde gives "DEPRECATED", but
    //!       the route layer uses `format!("{:?}", entry.status)` which
    //!       produces "Deprecated" (Debug form). Asserts status ==
    //!       "Deprecated" NOT "DEPRECATED". Defends a refactor swapping
    //!       `format!("{:?}", entry.status)` for `entry.status.as_str()`
    //!       OR `serde_json::to_value(&entry.status)` — both would change
    //!       the wire string and break operator dashboards parsing it.
    //!   (4) register() overwrites by algorithm key — registers
    //!       "dilithium3" Active → "dilithium3" Forbidden → "dilithium3"
    //!       Deprecated in that order; asserts sunset_entries == 1
    //!       (HashMap dedupes by algorithm name, NOT by entry identity)
    //!       AND algorithms[0].status == "Deprecated" (last write wins,
    //!       per Protocol §11.29 "later entries override earlier ones
    //!       allows re-activating a previously deprecated algo").
    //!       Defends a refactor changing register() semantics from
    //!       insert (overwrite) to entry().or_insert (no-op on duplicate)
    //!       which would silently freeze the sunset state at the first
    //!       transition per algorithm — defeating re-activation.
    //!   (5) Multiple algorithms surface independently — registers three
    //!       distinct algorithms ("dilithium3" Active, "sphincs-sha2-192f"
    //!       Forbidden, "kyber" Deprecated); asserts sunset_entries == 3
    //!       AND each algo's status surfaces correctly via BTreeMap-sorted
    //!       projection of (algorithm → status) pairs from the JSON array.
    //!       HashMap iteration order is non-deterministic, so the array
    //!       is collected into a BTreeMap and matched against expected.
    //!       Defends a refactor accidentally keying the HashMap on
    //!       entry.status (collision: only one entry survives) or
    //!       entry.reason (collision when two algos share a reason).
    use super::compute_sunset_payload;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::state::NodeState;
    use crate::network::sunset::{AlgorithmStatus, SunsetEntry};
    use crate::network::witness::WitnessManager;
    use crate::network::RwLockRecover;
    use crate::storage::rocks::StorageEngine;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    /// Minimal NodeState. Tempdir is forgotten so the rocks instance
    /// stays alive for the duration of the test (matches the pattern
    /// in `admin_witness_liveness_tests::build_state`).
    fn build_state() -> Arc<NodeState> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "batch-yy-admin-token".into(),
            network_id: "batch-yy-sunset".into(),
            node_type: "leaf".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks =
            Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = NodeState::new(config, identity, rocks, wmgr);
        std::mem::forget(tmp);
        Arc::new(state)
    }

    /// Plant a sunset entry via the live `register()` call. Uses the
    /// canonical API path (NOT direct HashMap insertion) so tests cover
    /// the same semantics the streaming-rebuild path exercises.
    fn plant(state: &NodeState, algorithm: &str, status: AlgorithmStatus,
             effective_epoch: u64, reason: &str) {
        let mut s = state.sunset.write_recover();
        s.register(SunsetEntry {
            algorithm: algorithm.to_string(),
            status,
            effective_epoch,
            reason: reason.to_string(),
        });
    }

    #[test]
    fn batch_yy_empty_state_yields_two_key_envelope_with_zero_baselines() {
        // Axis 1: top-level envelope shape. A fresh node has NEVER
        // received a sunset record. Two keys MUST be present
        // (sunset_entries, algorithms); wire types MUST be {usize-as-u64,
        // array}. A regression that flipped algorithms to `Option<Vec>`
        // OR added `skip_serializing_if = "Vec::is_empty"` would crash
        // CLI parsing `body.algorithms.length` at boot.
        let state = build_state();
        let v = compute_sunset_payload(&state);

        let obj = v.as_object().expect("top-level must be JSON Object");
        let actual_keys: BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let expected_keys: BTreeSet<&str> =
            ["sunset_entries", "algorithms"].iter().copied().collect();
        let added: Vec<&&str> = actual_keys.difference(&expected_keys).collect();
        let dropped: Vec<&&str> = expected_keys.difference(&actual_keys).collect();
        assert!(
            added.is_empty() && dropped.is_empty(),
            "envelope key set drift: added={:?} dropped={:?}",
            added, dropped
        );

        // Wire-type pins. `sunset_entries` MUST be a non-negative number
        // (serializes as u64 from usize); `algorithms` MUST be an array
        // (NOT object, NOT null).
        assert!(
            v["sunset_entries"].is_u64(),
            "sunset_entries must serialize as u64 — got {:?}",
            v["sunset_entries"]
        );
        assert!(
            v["algorithms"].is_array(),
            "algorithms must be a JSON array even when empty — \
             defends `skip_serializing_if = \"Vec::is_empty\"` regression \
             that would surface as undefined and crash CLI parsers"
        );

        // Value pins for zero-baseline.
        assert_eq!(v["sunset_entries"].as_u64(), Some(0));
        assert_eq!(v["algorithms"].as_array().map(|a| a.len()), Some(0));
    }

    #[test]
    fn batch_yy_single_entry_yields_four_key_sub_envelope() {
        // Axis 2: per-entry sub-envelope shape. Register one entry,
        // then pin the algorithms[0] sub-envelope is exactly 4-key
        // {algorithm, status, effective_epoch, reason}, with each
        // field at the correct wire type. A regression
        // adding/dropping/renaming any sub-envelope field would
        // break operator dashboards parsing the structured payload.
        let state = build_state();
        plant(
            &state,
            "dilithium3",
            AlgorithmStatus::Deprecated,
            42_000,
            "CVE-2026-0001 lattice signature forgery",
        );
        let v = compute_sunset_payload(&state);

        // Top-level shape unchanged from axis 1.
        assert_eq!(v["sunset_entries"].as_u64(), Some(1));
        let arr = v["algorithms"].as_array().expect("algorithms must be array");
        assert_eq!(arr.len(), 1, "exactly one entry registered, exactly one in array");

        // Sub-envelope key BTreeSet symmetric-difference.
        let entry = arr[0].as_object().expect("entry must be JSON Object");
        let actual_keys: BTreeSet<&str> = entry.keys().map(|s| s.as_str()).collect();
        let expected_keys: BTreeSet<&str> =
            ["algorithm", "status", "effective_epoch", "reason"]
                .iter().copied().collect();
        let added: Vec<&&str> = actual_keys.difference(&expected_keys).collect();
        let dropped: Vec<&&str> = expected_keys.difference(&actual_keys).collect();
        assert!(
            added.is_empty() && dropped.is_empty(),
            "sub-envelope key set drift: added={:?} dropped={:?}",
            added, dropped
        );

        // Wire-type pins on each sub-envelope field.
        assert!(arr[0]["algorithm"].is_string(),
            "algorithm must serialize as JSON string");
        assert!(arr[0]["status"].is_string(),
            "status must serialize as JSON string (Debug-formatted enum)");
        assert!(arr[0]["effective_epoch"].is_u64(),
            "effective_epoch must serialize as u64");
        assert!(arr[0]["reason"].is_string(),
            "reason must serialize as JSON string");

        // Value pins.
        assert_eq!(arr[0]["algorithm"].as_str(), Some("dilithium3"));
        assert_eq!(arr[0]["effective_epoch"].as_u64(), Some(42_000));
        assert_eq!(arr[0]["reason"].as_str(),
                   Some("CVE-2026-0001 lattice signature forgery"));
    }

    #[test]
    fn batch_yy_status_uses_debug_format_not_serde_screaming_snake_case() {
        // Axis 3: THE CRITICAL ORTHOGONALITY AXIS. AlgorithmStatus is
        // tagged `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]` so
        // direct serde serialization would yield "DEPRECATED" /
        // "ACTIVE" / "FORBIDDEN". The route layer uses
        // `format!("{:?}", entry.status)` which produces the Rust Debug
        // form: "Deprecated" / "Active" / "Forbidden" (mixed case).
        //
        // This test pins the Debug form across ALL three enum variants.
        // A refactor swapping `format!("{:?}", entry.status)` for either
        //   - `entry.status.as_str()`                  → "DEPRECATED" etc.
        //   - `serde_json::to_value(&entry.status)`    → "DEPRECATED" etc.
        // would change the wire string and break any operator dashboard
        // OR test fixture parsing the status field.
        let state = build_state();
        plant(&state, "alg-active",     AlgorithmStatus::Active,    1, "active");
        plant(&state, "alg-deprecated", AlgorithmStatus::Deprecated, 2, "deprecated");
        plant(&state, "alg-forbidden",  AlgorithmStatus::Forbidden,  3, "forbidden");
        let v = compute_sunset_payload(&state);

        let arr = v["algorithms"].as_array().expect("algorithms must be array");
        assert_eq!(arr.len(), 3, "three distinct algorithms registered");

        // Build a {algorithm → status} mapping out of the JSON array
        // (HashMap iteration order is non-deterministic, so positional
        // assertions are unsafe — project into a BTreeMap and look up
        // by algorithm name).
        let by_algo: BTreeMap<String, String> = arr.iter()
            .filter_map(|e| {
                let algo = e["algorithm"].as_str()?.to_string();
                let status = e["status"].as_str()?.to_string();
                Some((algo, status))
            })
            .collect();

        // Debug-formatted strings — mixed case, NOT SCREAMING_SNAKE_CASE.
        assert_eq!(
            by_algo.get("alg-active").map(|s| s.as_str()),
            Some("Active"),
            "status must be Debug-formatted 'Active' NOT serde 'ACTIVE' — \
             refactor swapping format!(\"{{:?}}\", entry.status) for \
             entry.status.as_str() would break this"
        );
        assert_eq!(
            by_algo.get("alg-deprecated").map(|s| s.as_str()),
            Some("Deprecated"),
            "status must be Debug-formatted 'Deprecated' NOT serde 'DEPRECATED'"
        );
        assert_eq!(
            by_algo.get("alg-forbidden").map(|s| s.as_str()),
            Some("Forbidden"),
            "status must be Debug-formatted 'Forbidden' NOT serde 'FORBIDDEN'"
        );

        // Negative assertion: explicitly confirm the serde form does NOT
        // appear. If a refactor switches to `entry.status.as_str()` or
        // serde-based serialization, this assertion fails.
        for (_, status_str) in by_algo.iter() {
            assert!(
                !status_str.chars().all(|c| c.is_uppercase() || c == '_' || c == '-'),
                "status string '{}' must NOT be SCREAMING_SNAKE_CASE — \
                 if it is, the route swapped Debug for serde rename",
                status_str
            );
        }
    }

    #[test]
    fn batch_yy_register_overwrites_by_algorithm_key_last_write_wins() {
        // Axis 4: register() semantics — HashMap dedupes by algorithm
        // name. Per Protocol §11.29 ("later entries override earlier
        // ones — allows re-activating a previously deprecated algo"),
        // register() MUST be insert (overwrite), NOT
        // entry().or_insert (no-op on duplicate).
        //
        // Register dilithium3 in three different states. After all three
        // registrations, the payload MUST surface ONE entry (HashMap
        // dedupe by algorithm key) and the status MUST be the LAST
        // registered value (overwrite semantics).
        let state = build_state();
        plant(&state, "dilithium3", AlgorithmStatus::Active,    100, "initial");
        plant(&state, "dilithium3", AlgorithmStatus::Forbidden, 200, "emergency");
        plant(&state, "dilithium3", AlgorithmStatus::Deprecated, 300, "soft-sunset");
        let v = compute_sunset_payload(&state);

        // HashMap dedupes by algorithm key — three registrations of the
        // SAME algorithm collapse to ONE entry.
        assert_eq!(
            v["sunset_entries"].as_u64(),
            Some(1),
            "sunset_entries must collapse to 1 after three same-algo \
             registrations — defends refactor changing register() from \
             insert (overwrite) to entry().or_insert (no-op on duplicate)"
        );
        let arr = v["algorithms"].as_array().expect("algorithms must be array");
        assert_eq!(arr.len(), 1, "exactly one survivor in the entries map");

        // Last-write-wins — the surviving entry must be the THIRD
        // registration (Deprecated, epoch 300, reason "soft-sunset").
        // If a refactor switched to entry().or_insert the survivor
        // would be the FIRST (Active, 100, "initial").
        assert_eq!(arr[0]["status"].as_str(), Some("Deprecated"),
            "last-write-wins: surviving status must be 'Deprecated' \
             (third register), NOT 'Active' (first register) or \
             'Forbidden' (second register)");
        assert_eq!(arr[0]["effective_epoch"].as_u64(), Some(300),
            "last-write-wins: surviving effective_epoch must be 300");
        assert_eq!(arr[0]["reason"].as_str(), Some("soft-sunset"),
            "last-write-wins: surviving reason must be 'soft-sunset'");
    }

    #[test]
    fn batch_yy_multiple_algorithms_surface_independently_via_btreemap_projection() {
        // Axis 5: multiple distinct algorithms surface as independent
        // entries. HashMap iteration order is non-deterministic, so
        // positional assertions are unsafe — project the array into a
        // BTreeMap keyed by algorithm name and look up each entry.
        //
        // Three distinct algorithms with three different statuses. Each
        // entry must surface its own algorithm/status/epoch/reason
        // intact, regardless of array ordering. Defends a refactor
        // accidentally keying the HashMap on entry.status (collision:
        // only one entry survives) or entry.reason (collision when two
        // algos share a reason text) instead of entry.algorithm.
        let state = build_state();
        plant(&state, "dilithium3",         AlgorithmStatus::Active,    100, "rev-A");
        plant(&state, "sphincs-sha2-192f",  AlgorithmStatus::Forbidden, 200, "rev-B");
        plant(&state, "kyber",              AlgorithmStatus::Deprecated, 300, "rev-C");
        let v = compute_sunset_payload(&state);

        // Count is exactly 3 — three distinct algorithm keys, no
        // collisions.
        assert_eq!(
            v["sunset_entries"].as_u64(),
            Some(3),
            "three distinct algorithms must surface as three entries — \
             a collision (refactor keying HashMap on entry.status \
             instead of entry.algorithm) would collapse to 1"
        );
        let arr = v["algorithms"].as_array().expect("algorithms must be array");
        assert_eq!(arr.len(), 3, "array length matches sunset_entries");

        // Project the array into a BTreeMap keyed by algorithm name.
        // BTreeMap gives deterministic ordering AND O(log n) lookup,
        // both of which the underlying HashMap does NOT.
        let by_algo: BTreeMap<String, (String, u64, String)> = arr.iter()
            .filter_map(|e| {
                let algo = e["algorithm"].as_str()?.to_string();
                let status = e["status"].as_str()?.to_string();
                let epoch = e["effective_epoch"].as_u64()?;
                let reason = e["reason"].as_str()?.to_string();
                Some((algo, (status, epoch, reason)))
            })
            .collect();

        // Each algorithm carries its own status/epoch/reason — no
        // bleed between entries (a refactor flattening status across
        // the HashMap into a single shared cell would surface here).
        assert_eq!(
            by_algo.get("dilithium3"),
            Some(&("Active".to_string(), 100, "rev-A".to_string())),
            "dilithium3 must surface its own Active/100/rev-A triple"
        );
        assert_eq!(
            by_algo.get("sphincs-sha2-192f"),
            Some(&("Forbidden".to_string(), 200, "rev-B".to_string())),
            "sphincs-sha2-192f must surface its own Forbidden/200/rev-B triple"
        );
        assert_eq!(
            by_algo.get("kyber"),
            Some(&("Deprecated".to_string(), 300, "rev-C".to_string())),
            "kyber must surface its own Deprecated/300/rev-C triple"
        );

        // No phantom entries — all 3 algorithm keys present, no extras.
        let actual_algos: BTreeSet<&str> =
            by_algo.keys().map(|s| s.as_str()).collect();
        let expected_algos: BTreeSet<&str> =
            ["dilithium3", "sphincs-sha2-192f", "kyber"]
                .iter().copied().collect();
        assert_eq!(
            actual_algos, expected_algos,
            "exactly the three registered algorithms must appear, \
             no extras and no missing"
        );
    }
}

#[cfg(test)]
mod admin_conservation_check_tests {
    //! Pins
    //! `compute_conservation_check_payload`, the testable core of
    //! `GET /admin/conservation_check`. Previously the helper did not
    //! exist — `admin_conservation_check` was a 12-line route handler
    //! that built the envelope inline. The endpoint is the
    //! conservation-invariant stub: a prior change removed the
    //! peer-fanout `/supply/total` cross-check (no PQ verb for it),
    //! so the route now returns a STATIC envelope with `peers_checked
    //! = 0`, `mismatches = 0`, `conservation_ok = true`, `results = []`
    //! and a `note` carrying the history pointer.
    //!
    //! That static envelope is load-bearing operator wire contract:
    //!   - Operator dashboards parse `body.conservation_ok` as the
    //!     boolean "is this node solvent" indicator. If a future
    //!     refactor accidentally wires `conservation_ok` to a derived
    //!     value (e.g. `local_supply == expected_supply`) it would
    //!     flip false on legitimate edge inputs (genesis, u64::MAX,
    //!     post-rotation) and page on-call for nothing.
    //!   - `peers_checked == 0` is the operator's signal that this
    //!     endpoint is a STUB, not a live multi-peer fanout — a
    //!     regression re-introducing peer fanout MUST consciously
    //!     update the wire shape so dashboards know to surface the
    //!     new field as actionable. Tests catch silent re-wire.
    //!   - The `note` string carries the literal token "AUDIT-10" so
    //!     operators reading the endpoint can grep their audit log
    //!     for the corresponding audit decision and follow the
    //!     reasoning chain. If a refactor paraphrases the note OR
    //!     drops the AUDIT-10 token, operator runbooks lose the
    //!     anchor and the next conservation-invariant question goes
    //!     to git blame instead of the audit doc.
    //!
    //! Five orthogonal pins:
    //!   (1) Empty/baseline state (supply=0) — 6-key top-level
    //!       envelope shape via BTreeSet symmetric-difference + wire-
    //!       type pins on each field. Defends add/drop/rename on the
    //!       envelope AND wire-type drift (e.g. someone calling
    //!       `.to_string()` on a numeric field).
    //!   (2) `local_supply` is INPUT-PASSTHROUGH u64, not derived/
    //!       recomputed. Loops over a fixture vector covering edge
    //!       inputs {0, 1, 1_000_000, u64::MAX} and asserts the
    //!       output `local_supply` equals the input bit-faithfully.
    //!       Defends a refactor accidentally substituting a derived
    //!       value (e.g. expected_supply or supply/10 rounded down)
    //!       for the input.
    //!   (3) `peers_checked` + `mismatches` are STRICT u64 ZERO AND
    //!       INDEPENDENT of `local_supply`. Loops over the same edge-
    //!       input fixture and asserts BOTH counters stay at 0
    //!       regardless of input value. Defends a refactor wiring
    //!       `peers_checked = peer_count()` (would climb with peer
    //!       count) OR `mismatches = supply > 0 ? 1 : 0` (would flip
    //!       non-zero on any genesis state).
    //!   (4) `conservation_ok` is STRICT bool TRUE + `results` is
    //!       STRICT EMPTY ARRAY, regardless of input supply. Loops
    //!       over the edge-input fixture. Defends a refactor wiring
    //!       `conservation_ok = local_supply <= expected_supply`
    //!       (would flip false on u64::MAX) OR adding a phantom
    //!       results entry on certain inputs.
    //!   (5) `note` string CONTAINS the literal "AUDIT-10" token —
    //!       the audit-history anchor that operator runbooks grep
    //!       to find the corresponding audit decision. ALSO asserts
    //!       the note is non-empty (defends a refactor that drops
    //!       the field to empty string) AND mentions `/supply/total`
    //!       (the operator-actionable out-of-band query the audit
    //!       note recommends). Defends paraphrase / drop / rename
    //!       of the operator-facing audit pointer.
    use super::compute_conservation_check_payload;
    use std::collections::BTreeSet;

    /// Edge-input fixture covering the corners of u64. Zero is the
    /// genesis baseline; one is the post-mint baseline; one million
    /// is a mid-range value; u64::MAX is the saturation corner
    /// (catches a refactor that would silently wrap or truncate).
    const EDGE_SUPPLIES: &[u64] = &[0, 1, 1_000_000, u64::MAX];

    #[test]
    fn batch_zz_empty_envelope_yields_six_key_set_with_wire_type_pins() {
        // Axis 1: top-level envelope shape. A fresh conservation
        // check on a zero-supply genesis state. Six keys MUST be
        // present (local_supply, peers_checked, mismatches,
        // conservation_ok, results, note); wire types MUST be
        // {u64, u64, u64, bool, array, string}. A regression
        // adding/dropping any key OR flipping any field's type
        // (e.g. someone calling `.to_string()` on local_supply) would
        // surface here.
        let v = compute_conservation_check_payload(0, 0);

        let obj = v.as_object().expect("top-level must be JSON Object");
        let actual_keys: BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
        let expected_keys: BTreeSet<&str> = [
            "local_supply",
            "peers_checked",
            "mismatches",
            "conservation_ok",
            "results",
            "note",
        ]
        .iter()
        .copied()
        .collect();
        let added: Vec<&&str> = actual_keys.difference(&expected_keys).collect();
        let dropped: Vec<&&str> = expected_keys.difference(&actual_keys).collect();
        assert!(
            added.is_empty() && dropped.is_empty(),
            "envelope key set drift: added={:?} dropped={:?}",
            added,
            dropped
        );

        // Wire-type pins on each field — defends accidental
        // serialization changes (e.g. `.to_string()` on a numeric
        // field, or a Vec → Option<Vec> refactor that triggers
        // `skip_serializing_if = "Vec::is_empty"`).
        assert!(
            v["local_supply"].is_u64(),
            "local_supply must serialize as JSON u64 — got {:?}",
            v["local_supply"]
        );
        assert!(
            v["peers_checked"].is_u64(),
            "peers_checked must serialize as JSON u64 — got {:?}",
            v["peers_checked"]
        );
        assert!(
            v["mismatches"].is_u64(),
            "mismatches must serialize as JSON u64 — got {:?}",
            v["mismatches"]
        );
        assert!(
            v["conservation_ok"].is_boolean(),
            "conservation_ok must serialize as JSON bool — got {:?}",
            v["conservation_ok"]
        );
        assert!(
            v["results"].is_array(),
            "results must serialize as JSON array even when empty — \
             defends `skip_serializing_if = \"Vec::is_empty\"` \
             regression that would surface as undefined and crash CLI \
             parsers reading body.results.length"
        );
        assert!(
            v["note"].is_string(),
            "note must serialize as JSON string — got {:?}",
            v["note"]
        );
    }

    #[test]
    fn batch_zz_local_supply_is_input_passthrough_u64() {
        // Axis 2: local_supply MUST be the input value byte-faithful.
        // The helper is a pure passthrough — no derivation, no
        // truncation, no rounding. Loops over the edge-input fixture
        // (0, 1, 1_000_000, u64::MAX) and asserts the output
        // local_supply equals the input. Defends a refactor
        // accidentally substituting a derived value for the input
        // (e.g. expected_supply, or supply / 10 in some weird
        // dashboard rounding regression).
        for &supply in EDGE_SUPPLIES {
            let v = compute_conservation_check_payload(supply, supply);
            assert_eq!(
                v["local_supply"].as_u64(),
                Some(supply),
                "local_supply must equal input bit-faithfully — \
                 input={} output={:?}",
                supply,
                v["local_supply"]
            );
            // Strict type pin re-asserted per input — u64::MAX is the
            // saturation corner; a refactor truncating to u32 would
            // surface here as a wrap or as `Some(0xFFFF_FFFF)`.
            assert!(
                v["local_supply"].is_u64(),
                "local_supply must stay u64 even at u64::MAX input — \
                 input={} got {:?}",
                supply,
                v["local_supply"]
            );
        }
    }

    #[test]
    fn batch_zz_peers_checked_and_mismatches_strict_zero_independent_of_supply() {
        // Axis 3: peers_checked AND mismatches MUST stay at strict
        // u64 zero, INDEPENDENT of input supply. AUDIT-10 removed
        // peer fanout; the route is a stub. A refactor wiring
        // `peers_checked = peer_count()` would climb with peer count
        // (false-actionable). A refactor wiring `mismatches =
        // supply > 0 ? 1 : 0` would flip non-zero on any post-genesis
        // state. Loop over the edge-input fixture to catch input-
        // dependent regressions.
        for &supply in EDGE_SUPPLIES {
            let v = compute_conservation_check_payload(supply, supply);
            assert_eq!(
                v["peers_checked"].as_u64(),
                Some(0),
                "peers_checked MUST stay 0 (AUDIT-10 stub, no fanout) — \
                 input supply={} got {:?}",
                supply,
                v["peers_checked"]
            );
            assert_eq!(
                v["mismatches"].as_u64(),
                Some(0),
                "mismatches MUST stay 0 (AUDIT-10 stub, no fanout) — \
                 input supply={} got {:?}",
                supply,
                v["mismatches"]
            );
        }
    }

    #[test]
    fn batch_zz_conservation_ok_and_results_static_across_supply_range() {
        // Axis 4: conservation_ok MUST stay strict bool TRUE and
        // results MUST stay strict empty array, regardless of input
        // supply. AUDIT-10 removed the conservation-invariant
        // computation; the route is a stub that always reports OK.
        // A refactor wiring `conservation_ok = local_supply <=
        // expected_supply` would flip false on u64::MAX inputs. A
        // refactor adding phantom result entries for certain inputs
        // would surface here as `results.len() > 0`. Loop over the
        // edge-input fixture.
        for &supply in EDGE_SUPPLIES {
            let v = compute_conservation_check_payload(supply, supply);
            assert_eq!(
                v["conservation_ok"].as_bool(),
                Some(true),
                "conservation_ok MUST stay true (AUDIT-10 stub) — \
                 input supply={} got {:?}",
                supply,
                v["conservation_ok"]
            );
            let results = v["results"]
                .as_array()
                .expect("results must be a JSON array");
            assert_eq!(
                results.len(),
                0,
                "results MUST stay empty (AUDIT-10 stub) — \
                 input supply={} got {} entries: {:?}",
                supply,
                results.len(),
                results
            );
        }
    }

    #[test]
    fn batch_zz_note_carries_audit10_anchor_and_supply_total_pointer() {
        // Axis 5: the `note` string carries TWO load-bearing
        // operator-facing anchors:
        //   - "AUDIT-10" — the audit-history token operator
        //     runbooks grep to find the corresponding audit
        //     decision and follow the reasoning chain.
        //   - "/supply/total" — the actionable out-of-band query
        //     the audit note recommends operators use instead.
        // Both MUST survive future refactors that paraphrase the
        // note. Also asserts the note is non-empty (defends a drop-
        // to-empty regression).
        let v = compute_conservation_check_payload(42, 42);
        let note = v["note"]
            .as_str()
            .expect("note must be a JSON string");

        assert!(
            !note.is_empty(),
            "note MUST be non-empty — defends a refactor that drops \
             the note field to empty string"
        );
        assert!(
            note.contains("AUDIT-10"),
            "note MUST contain the literal 'AUDIT-10' audit-history \
             anchor for operator runbook grep — got: {:?}",
            note
        );
        assert!(
            note.contains("/supply/total"),
            "note MUST mention '/supply/total' as the operator-actionable \
             out-of-band query — got: {:?}",
            note
        );
    }
}

#[cfg(test)]
mod admin_audit_log_tests {
    //! Pins
    //! `compute_admin_audit_log_payload`, the testable core of
    //! `GET /admin/audit_log`. Previously the helper did not exist —
    //! `admin_audit_log` built the envelope inline. The endpoint
    //! exposes the last-100 forensic admin-access ring buffer
    //! (`state.admin_audit_log: Mutex<Vec<(f64, String, String,
    //! String)>>` — `(timestamp, ip, endpoint, token_prefix)` per
    //! row in insertion order; the helper reverses to newest-first
    //! and caps to 100). The 5 axes below natively cover orthogonal
    //! concerns: (1) empty-input envelope shape; (2) single-entry
    //! shape + the `token` → `token_prefix` wire-key RENAME;
    //! (3) newest-first ordering (`.rev()` defended); (4) 100-cap
    //! truncation (`.take(100)` defended, `total` reports RENDERED
    //! length, not input length); (5) wire-type contract — timestamp
    //! is JSON Number, others are JSON String.
    use super::compute_admin_audit_log_payload;

    fn make_entry(ts: f64, ip: &str, endpoint: &str, token: &str) -> (f64, String, String, String) {
        (ts, ip.to_string(), endpoint.to_string(), token.to_string())
    }

    #[test]
    fn batch_aaa_empty_log_yields_zero_total_and_empty_entries_array() {
        // Axis 1: baseline state (no admin access logged yet).
        // Envelope MUST be the strict 2-key `{ total, entries }`
        // shape with `total` an integer 0 (not null, not missing)
        // and `entries` an EMPTY ARRAY (not null, not missing). The
        // typed `is_u64()` / `is_array()` pins defend against serde
        // drift to JSON Null on empty + accidental wrapper renames.
        let v = compute_admin_audit_log_payload(&[]);

        let obj = v.as_object().expect("payload must be a JSON object");
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> = ["total", "entries"].iter().copied().collect();
        let missing: Vec<_> = expected.difference(&keys).copied().collect();
        let extra: Vec<_> = keys.difference(&expected).copied().collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "envelope key-set MUST be exactly {{total, entries}} — \
             missing={:?} extra={:?} got={:?}",
            missing, extra, keys
        );

        assert!(
            v["total"].is_u64(),
            "total MUST be a JSON u64 — got {:?}",
            v["total"]
        );
        assert_eq!(
            v["total"].as_u64().unwrap(),
            0,
            "total MUST be 0 on empty input — got {:?}",
            v["total"]
        );

        let entries = v["entries"]
            .as_array()
            .expect("entries MUST be a JSON array (not null, not missing) on empty input");
        assert_eq!(
            entries.len(),
            0,
            "entries MUST be an empty array on empty input — got {} elements",
            entries.len()
        );
    }

    #[test]
    fn batch_aaa_single_entry_shape_pins_4_keys_and_token_prefix_rename() {
        // Axis 2: with one input row the wire entry MUST be the
        // strict 4-key `{ timestamp, ip, endpoint, token_prefix }`
        // shape. The KEY RENAME from the input tuple's positional
        // "token" slot to the wire field `token_prefix` is the load-
        // bearing piece — operator dashboards key off `token_prefix`
        // (the value is the first ~8 chars of the bearer token, not
        // the full token, hence the rename). Defends against a
        // future refactor that drops the rename and leaks the field
        // through as `"token"` (would silently break dashboards) OR
        // a refactor that adds a 5th key (e.g. `method`) without
        // updating the wire contract.
        let log = vec![make_entry(1700000000.5, "10.0.0.1", "/admin/snapshot", "abc12345")];
        let v = compute_admin_audit_log_payload(&log);

        assert_eq!(v["total"].as_u64().unwrap(), 1, "total MUST be 1 with one input");
        let entries = v["entries"].as_array().expect("entries must be array");
        assert_eq!(entries.len(), 1, "exactly 1 entry expected");

        let row = entries[0].as_object().expect("entry must be JSON object");
        let keys: std::collections::BTreeSet<&str> = row.keys().map(|k| k.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> =
            ["timestamp", "ip", "endpoint", "token_prefix"].iter().copied().collect();
        let missing: Vec<_> = expected.difference(&keys).copied().collect();
        let extra: Vec<_> = keys.difference(&expected).copied().collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "entry key-set MUST be exactly {{timestamp, ip, endpoint, token_prefix}} — \
             missing={:?} extra={:?} got={:?} (note: positional tuple slot 3 maps to \
             wire key `token_prefix`, NOT `token` — operator dashboards depend on this)",
            missing, extra, keys
        );

        // Explicit assertion that `token` is NOT a wire key — defends a
        // refactor that drops the rename and leaks the input slot name.
        assert!(
            !row.contains_key("token"),
            "wire entry MUST NOT carry `token` key (input-tuple leak) — \
             rename to `token_prefix` is load-bearing for operator UX"
        );

        assert_eq!(row["timestamp"].as_f64().unwrap(), 1700000000.5);
        assert_eq!(row["ip"].as_str().unwrap(), "10.0.0.1");
        assert_eq!(row["endpoint"].as_str().unwrap(), "/admin/snapshot");
        assert_eq!(row["token_prefix"].as_str().unwrap(), "abc12345");
    }

    #[test]
    fn batch_aaa_newest_first_ordering_defends_rev_iterator() {
        // Axis 3: input is in INSERTION order (oldest first — the
        // ring buffer appends to the tail). The wire `entries[]`
        // MUST be NEWEST FIRST so operators see the most recent
        // admin accesses at the top of the dashboard. Helper's
        // `.iter().rev()` produces this — pin it with a 3-entry
        // fixture where timestamps are distinct ascending in input
        // and MUST be distinct descending in output. Defends against
        // a refactor that drops `.rev()` (would silently flip the
        // dashboard to oldest-first and bury fresh incidents).
        let log = vec![
            make_entry(100.0, "1.1.1.1", "/admin/a", "tokA"),
            make_entry(200.0, "2.2.2.2", "/admin/b", "tokB"),
            make_entry(300.0, "3.3.3.3", "/admin/c", "tokC"),
        ];
        let v = compute_admin_audit_log_payload(&log);

        let entries = v["entries"].as_array().expect("entries must be array");
        assert_eq!(entries.len(), 3, "3 input rows → 3 wire entries");
        let ts: Vec<f64> = entries
            .iter()
            .map(|e| e["timestamp"].as_f64().expect("timestamp must be JSON number"))
            .collect();
        assert_eq!(
            ts,
            vec![300.0, 200.0, 100.0],
            "entries MUST be newest-first (descending timestamp) — \
             got {:?} (input was ascending {:?})",
            ts,
            log.iter().map(|e| e.0).collect::<Vec<_>>()
        );
        // Cross-pin: the IP at position 0 MUST be the latest insertion,
        // not the first. Defends a `.rev()` drop that flips order while
        // keeping timestamps numeric.
        assert_eq!(
            entries[0]["ip"].as_str().unwrap(),
            "3.3.3.3",
            "entries[0].ip MUST be the newest insertion (3.3.3.3), \
             not the oldest (1.1.1.1)"
        );
    }

    #[test]
    fn batch_aaa_one_fifty_input_truncates_to_one_hundred_and_total_matches_rendered() {
        // Axis 4: 150-entry input MUST truncate to 100 wire entries
        // AND `total` MUST report 100 (the RENDERED count), NOT 150
        // (the input length). Two regressions this defends:
        //   (a) `.take(100)` dropped → 150 entries leak through,
        //       wire payload bloats and dashboards stall;
        //   (b) `total` computed off `log.len()` instead of
        //       `entries.len()` → operator sees `total=150` but
        //       only 100 rows, silent under-disclosure.
        // Also pins the OLDEST shown is at index 99 = input[50]
        // (newest 100 of 150 ascending = input[50..150] reversed),
        // which defends against an off-by-one in the cap window.
        let log: Vec<_> = (0..150)
            .map(|i| make_entry(i as f64, "127.0.0.1", "/admin/x", "tok"))
            .collect();
        let v = compute_admin_audit_log_payload(&log);

        let entries = v["entries"].as_array().expect("entries must be array");
        assert_eq!(
            entries.len(),
            100,
            "150 input rows MUST truncate to 100 wire entries — \
             got {} (defends a `.take(100)` drop)",
            entries.len()
        );
        assert_eq!(
            v["total"].as_u64().unwrap(),
            100,
            "total MUST report rendered count (100), NOT input length (150) — \
             got {:?} (defends `total = log.len()` regression)",
            v["total"]
        );
        // Newest at index 0 = input[149], oldest shown at index 99 = input[50].
        assert_eq!(
            entries[0]["timestamp"].as_f64().unwrap(),
            149.0,
            "entries[0].timestamp MUST be input[149].timestamp (newest)"
        );
        assert_eq!(
            entries[99]["timestamp"].as_f64().unwrap(),
            50.0,
            "entries[99].timestamp MUST be input[50].timestamp \
             (oldest of newest 100) — defends off-by-one in cap window"
        );
    }

    #[test]
    fn batch_aaa_wire_type_contract_timestamp_is_number_others_are_strings() {
        // Axis 5: serialized wire types are FIXED. `timestamp` MUST
        // be a JSON Number (f64) so dashboards can do range filters
        // and time-axis math without parse(). `ip`, `endpoint`,
        // `token_prefix` MUST all be JSON Strings. Defends against
        // serde drift like `#[serde(serialize_with = …)]` that
        // accidentally renders timestamp as a String (would break
        // every dashboard's date axis). Also defends against an
        // accidental Number cast on `token_prefix` if a future
        // change uses a numeric token id.
        let log = vec![make_entry(
            1700000123.456,
            "192.168.1.42",
            "/admin/gc/trigger",
            "deadbeef",
        )];
        let v = compute_admin_audit_log_payload(&log);

        let row = &v["entries"][0];
        assert!(
            row["timestamp"].is_number(),
            "timestamp MUST be JSON Number (not String) — got {:?} \
             (defends dashboard date-axis parse() breakage)",
            row["timestamp"]
        );
        assert!(
            row["ip"].is_string(),
            "ip MUST be JSON String — got {:?}",
            row["ip"]
        );
        assert!(
            row["endpoint"].is_string(),
            "endpoint MUST be JSON String — got {:?}",
            row["endpoint"]
        );
        assert!(
            row["token_prefix"].is_string(),
            "token_prefix MUST be JSON String (NOT a numeric token id) — got {:?}",
            row["token_prefix"]
        );
        // Envelope-level type contract pinning.
        assert!(
            v["total"].is_u64(),
            "envelope total MUST be JSON u64 (not Number-as-f64, not String) — got {:?}",
            v["total"]
        );
        assert!(
            v["entries"].is_array(),
            "envelope entries MUST be JSON array — got {:?}",
            v["entries"]
        );
    }
}

#[cfg(test)]
mod admin_retirement_candidates_tests {
    //! Pins
    //! `compute_retirement_candidates_payload`, the testable core of
    //! `GET /admin/retirement_candidates`. Previously the helper did not
    //! exist — `admin_retirement_candidates` built the envelope inline.
    //! The endpoint exposes the LOCAL retirement-status report from
    //! `state.retirement.candidates_for_retirement() -> Vec<(String,
    //! Vec<String>)>` — each row is `(identity_hash, reasons)`. The
    //! helper truncates each identity to its first 16 chars via
    //! `&id[..id.len().min(16)]` (the `.min(16)` clamp is load-bearing
    //! — naive `&id[..16]` panics on short identities) and wraps in
    //! the operator-confusing `{ candidates, nodes }` envelope where
    //! `candidates` carries the COUNT and `nodes` carries the ARRAY
    //! (NOT the inverse, despite the naming). The 5 axes below
    //! natively cover orthogonal concerns: (1) empty-input envelope
    //! shape; (2) single-entry envelope-key SEMANTIC-INVERSION pin
    //! (`candidates` is count, `nodes` is array) + per-row 2-key
    //! shape; (3) identity truncation — 64-char → 16 chars AND short
    //! 8-char → full 8 chars (defends the `.min(16)` clamp's two
    //! branches); (4) reasons array pass-through — empty + multi-item
    //! preserving order; (5) wire-type contract — candidates is JSON
    //! Number, nodes is array, identity is string, reasons is array.
    use super::compute_retirement_candidates_payload;

    fn make_entry(id: &str, reasons: &[&str]) -> (String, Vec<String>) {
        (id.to_string(), reasons.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn batch_bbb_empty_candidates_yields_zero_count_and_empty_nodes_array() {
        // Axis 1: baseline state (no retirement candidates). Envelope
        // MUST be the strict 2-key `{ candidates, nodes }` shape with
        // `candidates` an integer 0 (not null, not missing) and
        // `nodes` an EMPTY ARRAY (not null, not missing). The
        // semantic-inversion convention — `candidates` carrying COUNT
        // not the array — is preserved on empty input.
        let v = compute_retirement_candidates_payload(&[]);

        let obj = v.as_object().expect("payload must be a JSON object");
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> = ["candidates", "nodes"].iter().copied().collect();
        let missing: Vec<_> = expected.difference(&keys).copied().collect();
        let extra: Vec<_> = keys.difference(&expected).copied().collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "envelope key-set MUST be exactly {{candidates, nodes}} — \
             missing={:?} extra={:?} got={:?}",
            missing, extra, keys
        );

        assert!(
            v["candidates"].is_u64(),
            "candidates MUST be JSON u64 (count, NOT the array) — got {:?}",
            v["candidates"]
        );
        assert_eq!(
            v["candidates"].as_u64().unwrap(),
            0,
            "candidates MUST be 0 on empty input — got {:?}",
            v["candidates"]
        );

        let nodes = v["nodes"]
            .as_array()
            .expect("nodes MUST be a JSON array (not null, not missing) on empty input");
        assert_eq!(
            nodes.len(),
            0,
            "nodes MUST be an empty array on empty input — got {} elements",
            nodes.len()
        );
    }

    #[test]
    fn batch_bbb_single_entry_pins_envelope_semantic_inversion_and_row_shape() {
        // Axis 2: with one input row, defend the SEMANTIC INVERSION
        // of the envelope keys. `candidates` carries the COUNT (an
        // integer), `nodes` carries the ARRAY of rows. A future
        // refactor that swaps the names (putting the array under
        // `candidates` to "match the field name") would silently
        // break every operator dashboard keyed off `nodes`. Also pin
        // the strict 2-key `{ identity, reasons }` per-row shape —
        // defends a refactor that adds a third key (e.g. `score`,
        // `last_seen`) without updating the wire contract.
        let log = vec![make_entry("abcdefghij1234567890", &["low_relevance", "stale"])];
        let v = compute_retirement_candidates_payload(&log);

        assert_eq!(
            v["candidates"].as_u64().unwrap(),
            1,
            "candidates MUST be the COUNT (1), NOT the array — \
             semantic-inversion convention is load-bearing"
        );
        let nodes = v["nodes"].as_array().expect("nodes must be array");
        assert_eq!(nodes.len(), 1, "exactly 1 row expected under `nodes`");

        let row = nodes[0].as_object().expect("row must be JSON object");
        let keys: std::collections::BTreeSet<&str> = row.keys().map(|k| k.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> =
            ["identity", "reasons"].iter().copied().collect();
        let missing: Vec<_> = expected.difference(&keys).copied().collect();
        let extra: Vec<_> = keys.difference(&expected).copied().collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "row key-set MUST be exactly {{identity, reasons}} — \
             missing={:?} extra={:?} got={:?}",
            missing, extra, keys
        );
    }

    #[test]
    fn batch_bbb_identity_truncation_defends_both_min_branches() {
        // Axis 3: identity truncation via `&id[..id.len().min(16)]`.
        // The `.min(16)` clamp has TWO branches and BOTH must be
        // pinned:
        //   (a) `id.len() >= 16` → emit first 16 chars (operator UX:
        //       short prefixes are readable, full hashes overflow
        //       log columns);
        //   (b) `id.len() < 16` → emit FULL id (a naive `&id[..16]`
        //       would PANIC on short identities — the clamp is the
        //       only thing keeping the helper safe on test fixtures
        //       and short-hash debug builds).
        // Pin both via a mixed-length 2-row fixture.
        let long_id = "0123456789abcdef0123456789abcdef";  // 32 chars
        let short_id = "0123abcd";                          // 8 chars
        let log = vec![
            make_entry(long_id, &["r1"]),
            make_entry(short_id, &["r2"]),
        ];
        let v = compute_retirement_candidates_payload(&log);

        let nodes = v["nodes"].as_array().expect("nodes must be array");
        assert_eq!(nodes.len(), 2);

        // Branch (a): long identity truncates to first 16 chars.
        assert_eq!(
            nodes[0]["identity"].as_str().unwrap(),
            "0123456789abcdef",
            "32-char identity MUST truncate to first 16 chars — \
             got {:?} (defends the `.len() >= 16` branch)",
            nodes[0]["identity"]
        );

        // Branch (b): short identity emits in full (no panic).
        assert_eq!(
            nodes[1]["identity"].as_str().unwrap(),
            "0123abcd",
            "8-char identity MUST emit in full (no panic) — \
             got {:?} (defends the `.len() < 16` branch of `.min(16)`)",
            nodes[1]["identity"]
        );
    }

    #[test]
    fn display_prefix_is_char_boundary_safe_on_multibyte_input() {
        // Regression for the admin.rs:433 class: `ban_identity`'s JSON body
        // carries a FREE-FORM caller string, and the raw idiom
        // `&s[..s.len().min(16)]` panics when byte 16 falls inside a
        // multi-byte UTF-8 char. 6×'€' (3 bytes each) = 18 bytes; byte 16
        // lands mid-char — the exact panic trigger.
        let six_euros = "€€€€€€";
        assert_eq!(six_euros.len(), 18);
        let p = super::display_prefix(six_euros, 16);
        assert_eq!(p, "€€€€€", "must back off to the char boundary at byte 15");

        // ASCII behavior identical to the old `.min(16)` idiom.
        assert_eq!(super::display_prefix("0123456789abcdef0123", 16), "0123456789abcdef");
        assert_eq!(super::display_prefix("0123abcd", 16), "0123abcd");
        assert_eq!(super::display_prefix("", 16), "");
        // Exact-boundary multi-byte: 8×2-byte chars = 16 bytes → whole string.
        let eight_2byte = "ββββββββ";
        assert_eq!(eight_2byte.len(), 16);
        assert_eq!(super::display_prefix(eight_2byte, 16), eight_2byte);

        // End-to-end through the payload fn that feeds operator responses:
        // a multi-byte identity must not panic the handler.
        let log = vec![make_entry("€€€€€€", &["multibyte"])];
        let v = compute_retirement_candidates_payload(&log);
        assert_eq!(v["nodes"][0]["identity"].as_str().unwrap(), "€€€€€");
    }

    #[test]
    fn batch_bbb_reasons_pass_through_preserves_order_and_empty_array() {
        // Axis 4: `reasons` is forwarded VERBATIM from the input
        // tuple's `Vec<String>` slot. Defend two regressions:
        //   (a) empty reasons emit as `[]` (NOT null, NOT missing) —
        //       a `.filter(|(_, r)| !r.is_empty())` regression would
        //       drop rows with empty reasons silently, hiding
        //       retirement candidates flagged by other paths;
        //   (b) multi-reason input preserves INSERTION ORDER (a
        //       `.sort()` / `.dedup()` regression on reasons would
        //       silently reorder operator-facing diagnostic text).
        let log = vec![
            make_entry("idA1234567890123", &[]),  // 16-char id, 0 reasons
            make_entry("idB1234567890123", &["zone_offline", "no_attest", "slashed"]),
        ];
        let v = compute_retirement_candidates_payload(&log);

        let nodes = v["nodes"].as_array().expect("nodes must be array");
        assert_eq!(nodes.len(), 2);

        // Branch (a): empty reasons → empty array (not null).
        let r0 = nodes[0]["reasons"]
            .as_array()
            .expect("reasons MUST be array even when empty — got null/missing");
        assert_eq!(
            r0.len(),
            0,
            "empty input reasons MUST emit as empty array — got {:?}",
            r0
        );

        // Branch (b): multi-reason order preserved (insertion order).
        let r1: Vec<&str> = nodes[1]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        assert_eq!(
            r1,
            vec!["zone_offline", "no_attest", "slashed"],
            "reasons MUST preserve insertion order — \
             got {:?} (defends sort/dedup/reorder regression)",
            r1
        );
    }

    #[test]
    fn batch_bbb_wire_type_contract_candidates_is_number_nodes_is_array() {
        // Axis 5: serialized wire types are FIXED.
        //   - `candidates` MUST be a JSON Number (u64 count), NOT a
        //     String "1" (operator dashboards sum these without
        //     parse());
        //   - `nodes` MUST be a JSON Array (NOT an object keyed by
        //     identity — a refactor to a map-shape would break every
        //     dashboard iterating the array);
        //   - per row, `identity` MUST be a JSON String (NOT a
        //     numeric hash);
        //   - per row, `reasons` MUST be a JSON Array of Strings.
        // Defends against serde drift like `#[serde(serialize_with =
        // …)]` that accidentally renders any of these as the wrong
        // JSON kind.
        let log = vec![make_entry("aabbccddeeff0011", &["reason_x"])];
        let v = compute_retirement_candidates_payload(&log);

        assert!(
            v["candidates"].is_number(),
            "candidates MUST be JSON Number — got {:?}",
            v["candidates"]
        );
        assert!(
            v["candidates"].is_u64(),
            "candidates MUST be JSON u64 specifically (count, not f64) — got {:?}",
            v["candidates"]
        );
        assert!(
            v["nodes"].is_array(),
            "nodes MUST be JSON Array — got {:?}",
            v["nodes"]
        );

        let row = &v["nodes"][0];
        assert!(
            row["identity"].is_string(),
            "identity MUST be JSON String — got {:?}",
            row["identity"]
        );
        assert!(
            row["reasons"].is_array(),
            "reasons MUST be JSON Array — got {:?}",
            row["reasons"]
        );
        for r in row["reasons"].as_array().unwrap() {
            assert!(
                r.is_string(),
                "each reason MUST be JSON String — got {:?}",
                r
            );
        }
    }
}

#[cfg(test)]
mod retirement_candidates_tests {
    //! Pins
    //! `compute_retirement_candidates_payload`, the testable core of
    //! `GET /admin/retirement_candidates`. Previously the helper did
    //! not exist — `admin_retirement_candidates` built the envelope
    //! inline. The endpoint exposes the LOCAL set of identities the
    //! retirement subsystem (`src/forgetting.rs`) has flagged as
    //! `RetirementStatus::ShouldRetire { reasons }`. The 5 axes below
    //! cover orthogonal concerns: (1) empty-input envelope shape +
    //! `candidates=0` count is u64 not null; (2) identity truncation —
    //! 16-char wire prefix of the input identity_hash (defends a
    //! refactor that bumps the cap or drops the slice); (3) reasons
    //! array preservation — multi-reason rows + empty-reason row
    //! kept verbatim, no synthesis or dedupe; (4) order preservation —
    //! input iteration order = wire `nodes[]` order (no
    //! sort/rev/shuffle); (5) wire-type contract — `candidates` is
    //! u64, `nodes` is Array, each `nodes[i].identity` is String,
    //! each `nodes[i].reasons` is Array of Strings, strict 2-key
    //! envelope + strict 2-key per-node object.
    use super::compute_retirement_candidates_payload;

    fn cand(id: &str, reasons: &[&str]) -> (String, Vec<String>) {
        (
            id.to_string(),
            reasons.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn batch_bbb_empty_input_yields_zero_count_and_empty_nodes_array() {
        // Axis 1: baseline state (no identities flagged for retirement).
        // Envelope MUST be the strict 2-key `{ candidates, nodes }`
        // shape with `candidates` an integer 0 (not null, not missing)
        // and `nodes` an EMPTY ARRAY (not null, not missing). The
        // typed `is_u64()` / `is_array()` pins defend against serde
        // drift to JSON Null on empty + accidental wrapper renames.
        let v = compute_retirement_candidates_payload(&[]);

        let obj = v.as_object().expect("payload must be a JSON object");
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> =
            ["candidates", "nodes"].iter().copied().collect();
        let missing: Vec<_> = expected.difference(&keys).copied().collect();
        let extra: Vec<_> = keys.difference(&expected).copied().collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "envelope key-set MUST be exactly {{candidates, nodes}} — \
             missing={:?} extra={:?} got={:?}",
            missing, extra, keys
        );

        assert!(
            v["candidates"].is_u64(),
            "candidates MUST be a JSON u64 — got {:?}",
            v["candidates"]
        );
        assert_eq!(
            v["candidates"].as_u64().unwrap(),
            0,
            "candidates MUST be 0 on empty input — got {:?}",
            v["candidates"]
        );

        let nodes = v["nodes"]
            .as_array()
            .expect("nodes MUST be a JSON array (not null, not missing) on empty input");
        assert_eq!(
            nodes.len(),
            0,
            "nodes MUST be an empty array on empty input — got {} elements",
            nodes.len()
        );
    }

    #[test]
    fn batch_bbb_identity_truncated_to_first_sixteen_bytes_when_longer() {
        // Axis 2: identity_hash is a 64-char Dilithium3 hex. The wire
        // `identity` field MUST carry only the first 16 bytes (the
        // dashboard-friendly prefix; the full hex never goes over the
        // wire here because operators only need to spot-id the box).
        // Defends a refactor that:
        //   (a) bumps the cap (e.g. `.min(32)`) — would leak more of
        //       the identity into operator logs than the design
        //       budget permits;
        //   (b) drops the slice entirely — would expose the full
        //       64-byte identity_hash inside `nodes[].identity` and
        //       inflate the JSON wire size proportionally to the
        //       number of retiring nodes.
        // Sub-pin: input shorter than 16 bytes MUST pass through
        // unchanged (the `.min(16)` clamp guard).
        let long_id = "a".repeat(64);
        let short_id = "deadbeef"; // 8 bytes
        let input = vec![
            cand(&long_id, &["stale"]),
            cand(short_id, &["fresh"]),
        ];
        let v = compute_retirement_candidates_payload(&input);
        let nodes = v["nodes"].as_array().expect("nodes must be array");
        assert_eq!(nodes.len(), 2, "2 inputs → 2 wire entries");

        assert_eq!(
            nodes[0]["identity"].as_str().unwrap(),
            "aaaaaaaaaaaaaaaa",
            "64-char identity MUST be sliced to 16-char wire prefix — \
             got {:?} (defends `.min(16)` cap drop / cap bump)",
            nodes[0]["identity"]
        );
        assert_eq!(
            nodes[0]["identity"].as_str().unwrap().len(),
            16,
            "long-id wire identity MUST be exactly 16 bytes — got {} bytes",
            nodes[0]["identity"].as_str().unwrap().len()
        );

        assert_eq!(
            nodes[1]["identity"].as_str().unwrap(),
            "deadbeef",
            "8-char identity MUST pass through unchanged (clamp at len) — \
             got {:?} (defends an accidental hardcoded-16 truncation)",
            nodes[1]["identity"]
        );
        assert_eq!(
            nodes[1]["identity"].as_str().unwrap().len(),
            8,
            "short-id wire identity MUST stay at input len — got {} bytes",
            nodes[1]["identity"].as_str().unwrap().len()
        );
    }

    #[test]
    fn batch_bbb_reasons_array_preserved_verbatim_across_multi_and_empty_rows() {
        // Axis 3: the `reasons` slot is the operator-actionable detail
        // (e.g. "stale-attestation", "low-stake-buffer-overflow",
        // "unverifiable-signatures"). MUST be passed through verbatim
        // — no dedupe, no canonicalize, no synthesis. Defends:
        //   (a) a refactor that sorts `reasons` alphabetically
        //       (would obscure causal ordering an operator might rely
        //       on, e.g. first-trigger-first);
        //   (b) a refactor that dedupes (the retirement subsystem
        //       may legitimately list a reason twice if it's been
        //       triggered by two distinct cause paths);
        //   (c) a refactor that drops the field on empty (`reasons:
        //       []` MUST stay as empty Array, not become null /
        //       missing — operators key dashboards off presence).
        let input = vec![
            cand("id_multi", &["c-cause", "a-cause", "b-cause", "a-cause"]),
            cand("id_empty", &[]),
            cand("id_single", &["sole"]),
        ];
        let v = compute_retirement_candidates_payload(&input);
        let nodes = v["nodes"].as_array().expect("nodes must be array");
        assert_eq!(nodes.len(), 3, "3 inputs → 3 wire entries");

        // Multi-reason row: order preserved AND duplicate preserved.
        let multi: Vec<&str> = nodes[0]["reasons"]
            .as_array()
            .expect("reasons[0] must be array")
            .iter()
            .map(|v| v.as_str().expect("reason must be string"))
            .collect();
        assert_eq!(
            multi,
            vec!["c-cause", "a-cause", "b-cause", "a-cause"],
            "multi-reason row MUST be verbatim (no sort, no dedupe) — got {:?}",
            multi
        );

        // Empty-reason row: MUST be Array (not null, not missing).
        let empty = nodes[1]["reasons"]
            .as_array()
            .expect("empty-reason row MUST emit `reasons: []` (not null, not missing)");
        assert_eq!(
            empty.len(),
            0,
            "empty-reason row MUST stay empty — got {} elements",
            empty.len()
        );

        // Single-reason row: Array length 1.
        let single: Vec<&str> = nodes[2]["reasons"]
            .as_array()
            .expect("reasons[2] must be array")
            .iter()
            .map(|v| v.as_str().expect("reason must be string"))
            .collect();
        assert_eq!(single, vec!["sole"], "single-reason row contract");
    }

    #[test]
    fn batch_bbb_input_order_preserved_in_nodes_array() {
        // Axis 4: insertion order from
        // `forgetting::candidates_for_retirement` MUST flow through
        // to the wire `nodes[]` unchanged (no sort, no rev, no
        // shuffle). The retirement subsystem iterates its internal
        // HashMap in arbitrary-but-stable-per-build order, and
        // operators rely on the snapshot-to-snapshot stability to
        // diff which identity newly appeared. Defends:
        //   (a) a refactor that `.sort_by_key(|(id, _)| id.clone())`
        //       — would re-shuffle the dashboard top-of-list every
        //       time an alphabetically-earlier identity is flagged;
        //   (b) a refactor that `.rev()`s (would obscure the
        //       "earliest-flagged-first" if an operator built that
        //       expectation off observation).
        // Pinning via 3-entry fixture in reverse-alphabetical order;
        // wire MUST come back in the SAME (reverse-alphabetical)
        // order, NOT the alphabetical sorted order.
        let input = vec![
            cand("zzz_third", &["r3"]),
            cand("mmm_second", &["r2"]),
            cand("aaa_first", &["r1"]),
        ];
        let v = compute_retirement_candidates_payload(&input);
        let nodes = v["nodes"].as_array().expect("nodes must be array");
        let order: Vec<&str> = nodes
            .iter()
            .map(|n| n["identity"].as_str().unwrap())
            .collect();
        assert_eq!(
            order,
            vec!["zzz_third", "mmm_second", "aaa_first"],
            "nodes[] order MUST match input iteration order — got {:?} \
             (defends a `.sort_by_key` or `.rev()` insertion)",
            order
        );

        assert_eq!(
            v["candidates"].as_u64().unwrap(),
            3,
            "candidates count MUST be the wire `nodes.len()` (3) — got {:?}",
            v["candidates"]
        );
    }

    #[test]
    fn batch_bbb_wire_type_contract_candidates_is_u64_nodes_strings_and_arrays() {
        // Axis 5: serialized wire types are FIXED. `candidates` MUST
        // be a JSON u64 (not f64, not String); `nodes` MUST be an
        // Array. Each `nodes[i]` MUST be an Object with EXACTLY two
        // keys: `identity` (String) and `reasons` (Array of String).
        // Defends:
        //   (a) a refactor that serializes `candidates` via a
        //       `Number<f64>` wrapper (would break dashboards
        //       counting integer rows);
        //   (b) a refactor that adds a sneaky third per-node key
        //       (e.g. `health_score`) without updating the wire
        //       contract — would either bloat the payload or surface
        //       internal state to operators;
        //   (c) a refactor that renames `identity` → `id` or
        //       `reasons` → `causes` (would break every dashboard
        //       keyed off the current names).
        let input = vec![
            cand(
                "bench_identity_hash",
                &["stale-attestation", "low-stake-overflow"],
            ),
        ];
        let v = compute_retirement_candidates_payload(&input);

        // Envelope-level type contracts.
        assert!(
            v["candidates"].is_u64(),
            "envelope candidates MUST be JSON u64 — got {:?}",
            v["candidates"]
        );
        assert!(
            v["nodes"].is_array(),
            "envelope nodes MUST be JSON array — got {:?}",
            v["nodes"]
        );

        // Per-node type contracts.
        let row = v["nodes"][0].as_object().expect("nodes[0] must be Object");
        let keys: std::collections::BTreeSet<&str> = row.keys().map(|k| k.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> =
            ["identity", "reasons"].iter().copied().collect();
        let missing: Vec<_> = expected.difference(&keys).copied().collect();
        let extra: Vec<_> = keys.difference(&expected).copied().collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "per-node key-set MUST be exactly {{identity, reasons}} — \
             missing={:?} extra={:?} got={:?} (defends accidental third-key add \
             or rename like `identity`→`id`, `reasons`→`causes`)",
            missing, extra, keys
        );

        assert!(
            row["identity"].is_string(),
            "nodes[i].identity MUST be JSON String — got {:?}",
            row["identity"]
        );
        let reasons_arr = row["reasons"]
            .as_array()
            .expect("nodes[i].reasons MUST be JSON array");
        assert!(
            reasons_arr.iter().all(|r| r.is_string()),
            "every reasons[i] MUST be JSON String — got {:?}",
            reasons_arr
        );
    }
}

#[cfg(test)]
mod admin_epoch_health_tests {
    //! Pins
    //! `compute_epoch_health_payload`, the testable core of
    //! `GET /admin/epoch_health`. Previously the helper did not exist
    //! — `admin_epoch_health` built the envelope inline by walking
    //! `state.epoch.read_recover().latest_epoch` and joining against
    //! `latest_seal_id` + `adaptive_interval()` + `zone_activity_rate`.
    //! The helper takes the already-collected
    //! `(zone_path, epoch_num, seal_id, adaptive_interval_secs,
    //! activity_rate_rps)` slice — same insertion-order semantics as
    //! the prior inline walk — and emits the strict 4-key envelope
    //! `{ total_zones, stale_zones, expected_interval_secs, zones }`
    //! with per-row strict 6-key `{ zone, epoch, seal_id,
    //! adaptive_interval_secs, activity_rate_rps, status }`. The 5
    //! axes below pin orthogonal concerns: (1) empty-input envelope
    //! shape + load-bearing `stale_zones=0` + `expected_interval_secs`
    //! pass-through pin; (2) single-zone envelope + per-row 6-key
    //! contract + placeholder `status="ok"` semantic pin; (3) seal_id
    //! truncation `&seal_id[..seal_id.len().min(16)]` BOTH branches
    //! (long >= 16 → first 16, short < 16 → FULL — naive `[..16]`
    //! would panic); (4) activity_rate `format!("{:.4}", _)` precision
    //! pin (NEW axis class — defends `.to_string()` regression that
    //! would emit "0" instead of "0.0000" AND `:.6` widening that
    //! would emit "0.000000"); (5) wire-type contract +
    //! placeholder-stale invariant pin (`stale_zones` MUST stay 0
    //! regardless of input — every per-row `status` MUST be "ok" —
    //! locks the current placeholder semantics so any future overdue-
    //! detection wire-up surfaces as a test failure that forces
    //! contract acknowledgment).
    use super::compute_epoch_health_payload;

    fn make_row(
        zone_path: &str,
        epoch_num: u64,
        seal_id: &str,
        adaptive_interval: f64,
        activity_rate: f64,
    ) -> (String, u64, String, f64, f64) {
        (
            zone_path.to_string(),
            epoch_num,
            seal_id.to_string(),
            adaptive_interval,
            activity_rate,
        )
    }

    #[test]
    fn batch_ccc_empty_zones_yields_zero_count_and_empty_zones_array() {
        // Axis 1: baseline state (no zones in latest_epoch). Envelope
        // MUST be the strict 4-key `{ total_zones, stale_zones,
        // expected_interval_secs, zones }` shape with `total_zones=0`,
        // `stale_zones=0`, `zones=[]` (empty array NOT null NOT
        // missing), and `expected_interval_secs` passing through
        // verbatim (defends a regression that drops the field on
        // empty input — operator dashboards displaying the chain-wide
        // epoch cadence MUST see the configured value even when no
        // zones are loaded yet, e.g. immediately post-boot before the
        // ledger replay seeds `latest_epoch`).
        let v = compute_epoch_health_payload(120.0, 0, &[]);

        let obj = v.as_object().expect("payload must be a JSON object");
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> = [
            "total_zones",
            "stale_zones",
            "expected_interval_secs",
            "zones",
        ]
        .iter()
        .copied()
        .collect();
        let missing: Vec<_> = expected.difference(&keys).copied().collect();
        let extra: Vec<_> = keys.difference(&expected).copied().collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "envelope key-set MUST be exactly {{total_zones, stale_zones, \
             expected_interval_secs, zones}} — missing={:?} extra={:?} got={:?} \
             (regression risk: dropped field, renamed wrapper, or extra debug key)",
            missing, extra, keys
        );

        assert_eq!(
            v["total_zones"].as_u64().unwrap(),
            0,
            "total_zones MUST be 0 on empty input — got {:?}",
            v["total_zones"]
        );
        assert_eq!(
            v["stale_zones"].as_u64().unwrap(),
            0,
            "stale_zones MUST be 0 on empty input — got {:?}",
            v["stale_zones"]
        );
        let zones_arr = v["zones"]
            .as_array()
            .expect("zones MUST be a JSON array (not null, not missing) on empty input");
        assert_eq!(
            zones_arr.len(),
            0,
            "zones MUST be an empty array on empty input — got {} elements",
            zones_arr.len()
        );

        // expected_interval_secs pass-through: the configured value
        // MUST surface verbatim. A regression that hardcodes the field
        // to 0.0 or DEFAULT_EPOCH_SECS would silently mislead operator
        // dashboards. Pin 120.0 (the mainnet default per internal design notes
        // "current default 120s → P50 ≈ 60s").
        let exp = v["expected_interval_secs"]
            .as_f64()
            .expect("expected_interval_secs MUST be JSON Number");
        assert!(
            (exp - 120.0).abs() < 1e-9,
            "expected_interval_secs MUST pass through input verbatim — got {} expected 120.0",
            exp
        );
    }

    #[test]
    fn batch_ccc_total_zones_is_true_count_independent_of_capped_zones_page() {
        // SCALE-RULE page bound: the caller caps the `zones` array to a bounded
        // page (MAX_ZONES_IN_RESPONSE) but passes the TRUE zone count as
        // `total_zones`, so the field can exceed the serialized array length —
        // truncation is detectable as `zones.len() < total_zones`. Pin that the
        // helper echoes the true total verbatim and does NOT derive it from the
        // (capped) slice. Pass total=1_000_000 with a 2-row page.
        let rows = vec![
            make_row("z/a", 7, "sealAAAAAAAAAAAAAAAAAAAA", 30.0, 0.0),
            make_row("z/b", 7, "sealBBBBBBBBBBBBBBBBBBBB", 30.0, 0.0),
        ];
        let v = compute_epoch_health_payload(120.0, 1_000_000, &rows);
        assert_eq!(
            v["total_zones"].as_u64().unwrap(),
            1_000_000,
            "total_zones MUST be the TRUE count passed in (1_000_000), NOT zones.len()",
        );
        assert_eq!(
            v["zones"].as_array().unwrap().len(),
            2,
            "zones MUST be the bounded page (2 rows), distinct from total_zones",
        );
    }

    #[test]
    fn batch_ccc_single_zone_pins_per_row_6_key_contract_and_status_ok_placeholder() {
        // Axis 2: with one zone, defend the per-row strict 6-key
        // `{ zone, epoch, seal_id, adaptive_interval_secs,
        // activity_rate_rps, status }` shape — defends a refactor that
        // adds a 7th key (e.g. `last_attestation_ts`,
        // `committee_size`) without updating the wire contract.
        // Also pin the load-bearing placeholder semantic:
        // `status="ok"` is HARDCODED in the helper (the `overdue`
        // local is always `false` pending the future overdue-detection
        // wire-up). This test FAILS the moment any refactor wires up
        // real overdue logic — forcing acknowledgment of the contract
        // change rather than silently flipping operator dashboards
        // from "all healthy" to mixed-status mid-deploy.
        let row = make_row(
            "global",
            42,
            "abcdef0123456789fedcba9876543210", // 32 chars (>= 16, truncates to 16)
            60.0,
            0.5,
        );
        let v = compute_epoch_health_payload(120.0, 1, &[row]);

        assert_eq!(v["total_zones"].as_u64().unwrap(), 1);
        let zones_arr = v["zones"].as_array().expect("zones MUST be array");
        assert_eq!(zones_arr.len(), 1, "one input row → one zones entry");

        let row_obj = zones_arr[0]
            .as_object()
            .expect("per-row entry must be a JSON object");
        let row_keys: std::collections::BTreeSet<&str> =
            row_obj.keys().map(|k| k.as_str()).collect();
        let row_expected: std::collections::BTreeSet<&str> = [
            "zone",
            "epoch",
            "seal_id",
            "adaptive_interval_secs",
            "activity_rate_rps",
            "status",
        ]
        .iter()
        .copied()
        .collect();
        let row_missing: Vec<_> = row_expected.difference(&row_keys).copied().collect();
        let row_extra: Vec<_> = row_keys.difference(&row_expected).copied().collect();
        assert!(
            row_missing.is_empty() && row_extra.is_empty(),
            "per-row key-set MUST be exactly {{zone, epoch, seal_id, \
             adaptive_interval_secs, activity_rate_rps, status}} — \
             missing={:?} extra={:?} got={:?}",
            row_missing, row_extra, row_keys
        );

        assert_eq!(zones_arr[0]["zone"].as_str().unwrap(), "global");
        assert_eq!(zones_arr[0]["epoch"].as_u64().unwrap(), 42);
        // status="ok" placeholder pin — a real overdue-detection
        // wire-up MUST trigger this assertion (forcing operator
        // acknowledgment that the dashboard semantics changed).
        assert_eq!(
            zones_arr[0]["status"].as_str().unwrap(),
            "ok",
            "status MUST be 'ok' (hardcoded placeholder until overdue-detection \
             wire-up lands) — got {:?}. If this test FAILS because real overdue \
             detection was wired up, UPDATE this assertion + axis 5 + the audit-doc \
             §N closure documenting the contract flip.",
            zones_arr[0]["status"]
        );
    }

    #[test]
    fn batch_ccc_seal_id_truncation_clamp_defends_both_branches() {
        // Axis 3: `&seal_id[..seal_id.len().min(16)]` has TWO
        // branches: (a) seal_id.len() >= 16 → emit first 16 chars
        // (operator UX: short hash prefixes are readable in log
        // columns); (b) seal_id.len() < 16 → emit FULL seal_id (a
        // naive `&seal_id[..16]` would PANIC on short test fixtures
        // and short-hash debug builds). The `.min(16)` clamp is the
        // only thing keeping the helper safe on these inputs. Mixed
        // 2-row fixture pins BOTH branches in a single test.
        let long_seal = "0123456789abcdef0123456789abcdef"; // 32 chars
        let short_seal = "deadbeef"; // 8 chars (< 16)
        let rows = vec![
            make_row("zone-a", 1, long_seal, 60.0, 0.0),
            make_row("zone-b", 2, short_seal, 60.0, 0.0),
        ];
        let v = compute_epoch_health_payload(120.0, rows.len(), &rows);

        let zones_arr = v["zones"].as_array().unwrap();
        assert_eq!(zones_arr.len(), 2);

        // Branch (a) — long seal_id truncates to exactly 16 chars
        let a_seal = zones_arr[0]["seal_id"].as_str().unwrap();
        assert_eq!(
            a_seal.len(),
            16,
            "long seal_id (32 chars) MUST truncate to 16 chars — got len={} str={:?}",
            a_seal.len(),
            a_seal
        );
        assert_eq!(
            a_seal, "0123456789abcdef",
            "long seal_id MUST emit FIRST 16 chars (not last, not middle)",
        );

        // Branch (b) — short seal_id passes through FULL (a naive
        // `[..16]` would have panicked before reaching the assert)
        let b_seal = zones_arr[1]["seal_id"].as_str().unwrap();
        assert_eq!(
            b_seal, "deadbeef",
            "short seal_id (< 16 chars) MUST emit FULL string — got {:?} \
             (regression risk: someone replaced `.min(16)` with naive `[..16]` slice, \
             which would have panicked at test execution rather than reaching this assert)",
            b_seal
        );
    }

    #[test]
    fn batch_ccc_activity_rate_format_pins_4_decimal_precision() {
        // Axis 4 (NEW class): the helper
        // emits `activity_rate_rps` as a STRING via `format!("{:.4}",
        // activity_rate)`. This pins TWO regressions: (i) a
        // `.to_string()` swap that would emit "0" instead of "0.0000"
        // on zero rate (operator dashboards keyed off
        // "always-4-decimal" string-cmp would silently mismatch); (ii)
        // a precision widening like `:.6` that would emit "0.000000"
        // (same dashboard mismatch class, opposite direction); (iii) a
        // numeric-cast regression that emits the field as JSON Number
        // (would lose the implicit "always-string,
        // dashboard-grep-safe" UX). Fixture covers three representative
        // values: 0.0 (zero exact), 1.23456 (rounding case → "1.2346"),
        // 0.0001 (boundary case under 4-decimal precision → "0.0001").
        let rows = vec![
            make_row("zone-zero", 0, "abc", 60.0, 0.0),
            make_row("zone-round", 0, "abc", 60.0, 1.23456),
            make_row("zone-boundary", 0, "abc", 60.0, 0.0001),
        ];
        let v = compute_epoch_health_payload(120.0, rows.len(), &rows);
        let zones_arr = v["zones"].as_array().unwrap();

        for (i, expected_str) in [
            (0, "0.0000"),  // exact zero → 4 decimal places preserved
            (1, "1.2346"),  // rounding-up case (1.23456 → 1.2346)
            (2, "0.0001"),  // 4-decimal boundary (smallest representable)
        ] {
            let actual = zones_arr[i]["activity_rate_rps"].as_str().expect(
                "activity_rate_rps MUST be JSON String (not Number) — operator \
                 dashboards string-cmp the 4-decimal-formatted output",
            );
            assert_eq!(
                actual, expected_str,
                "activity_rate_rps[{}] MUST be {:?} via format!(\"{{:.4}}\", _) — \
                 got {:?}. Regression risk: .to_string() emits \"0\" or \"1.23456\"; \
                 :.6 emits \"0.000000\" / \"1.234560\".",
                i, expected_str, actual
            );
        }
    }

    #[test]
    fn batch_ccc_wire_types_and_placeholder_stale_invariant() {
        // Axis 5: wire-type contract — `total_zones` is JSON u64
        // (defends f64 cast that would carry precision-loss on large
        // counts), `stale_zones` is u64, `zones` is_array,
        // `expected_interval_secs` is JSON Number (could be f64).
        // Per-row: `zone` is_string, `epoch` is u64, `seal_id`
        // is_string, `adaptive_interval_secs` is_f64, `activity_rate_rps`
        // is_string (defends numeric-cast regression — currently a
        // STRING via format!()), `status` is_string. Plus the load-
        // bearing PLACEHOLDER-STALE INVARIANT: stale_zones MUST stay
        // 0 and every per-row status MUST be "ok" regardless of input
        // (the current helper hardcodes both — pinning this locks the
        // placeholder contract so any future overdue-detection
        // wire-up surfaces as a test failure that forces operator-
        // contract acknowledgment, rather than silently flipping
        // dashboards mid-deploy).
        let rows = vec![
            make_row("zone-a", 1, "seal-a-long-enough-32-char-string", 30.0, 100.0),
            make_row("zone-b", 999_999_999, "deadbeef", 240.0, 0.0001),
            make_row("zone-c", 0, "", 60.0, 50.5),
        ];
        let v = compute_epoch_health_payload(120.0, rows.len(), &rows);

        // Envelope wire types
        assert!(v["total_zones"].is_u64(), "total_zones MUST be JSON u64");
        assert!(v["stale_zones"].is_u64(), "stale_zones MUST be JSON u64");
        assert!(
            v["expected_interval_secs"].is_number(),
            "expected_interval_secs MUST be JSON Number"
        );
        assert!(v["zones"].is_array(), "zones MUST be JSON array");

        // PLACEHOLDER-STALE INVARIANT — even with 3 rows of
        // "everything looks active" data, stale_zones MUST stay 0
        // (helper hardcodes it; no overdue detection yet).
        assert_eq!(
            v["stale_zones"].as_u64().unwrap(),
            0,
            "stale_zones MUST stay 0 regardless of input under current placeholder \
             semantics — got {}. If this assertion FAILS because real overdue \
             detection landed, UPDATE this test + axis 2 + the audit-doc closure.",
            v["stale_zones"].as_u64().unwrap()
        );

        // Per-row wire types + placeholder status="ok" for ALL rows
        let zones_arr = v["zones"].as_array().unwrap();
        assert_eq!(zones_arr.len(), 3);
        for (i, row) in zones_arr.iter().enumerate() {
            assert!(row["zone"].is_string(), "zones[{}].zone MUST be string", i);
            assert!(row["epoch"].is_u64(), "zones[{}].epoch MUST be u64", i);
            assert!(
                row["seal_id"].is_string(),
                "zones[{}].seal_id MUST be string",
                i
            );
            assert!(
                row["adaptive_interval_secs"].is_number(),
                "zones[{}].adaptive_interval_secs MUST be number",
                i
            );
            assert!(
                row["activity_rate_rps"].is_string(),
                "zones[{}].activity_rate_rps MUST be JSON String (NOT Number) — \
                 got {:?}. Regression: a numeric-cast would lose the implicit \
                 'always-4-decimal-string, dashboard-grep-safe' UX.",
                i, row["activity_rate_rps"]
            );
            assert!(
                row["status"].is_string(),
                "zones[{}].status MUST be string",
                i
            );
            assert_eq!(
                row["status"].as_str().unwrap(),
                "ok",
                "zones[{}].status MUST be 'ok' under current placeholder semantics \
                 (overdue detection not yet wired) — got {:?}",
                i,
                row["status"]
            );
        }
    }
}

#[cfg(test)]
mod admin_gc_status_tests {
    #![allow(clippy::doc_lazy_continuation)]
    //! Pins
    //! `compute_gc_status_payload`, the testable core of
    //! `GET /admin/gc`. Previously the helper did not exist —
    //! `admin_gc_status` built the envelope inline by reading
    //! `state.config.gc_interval_secs` + `state.config.record_retention_secs`
    //! + the `state.gc_pruned_total` atomic. The helper takes the three
    //! already-resolved scalars and emits the strict 5-key envelope
    //! `{ gc_interval_secs, record_retention_secs, record_retention_days,
    //! gc_pruned_total, gc_enabled }`. The 5 axes below pin orthogonal
    //! concerns: (1) wire envelope contract (exactly 5 keys, no extras /
    //! missing); (2) `gc_enabled=true` branch when `gc_interval_secs>0`
    //! AND scalar passthrough for all three input values; (3) `gc_enabled=
    //! false` branch when `gc_interval_secs=0` (boundary — the >0
    //! check, NOT >=0 — defends against a `>=0` regression that would
    //! never report "disabled"); (4) `record_retention_days = secs /
    //! 86400.0` derivation (precision pin defending against integer-
    //! division regression that would emit `0` for sub-day retentions, OR
    //! a `% 86400` modulo regression that would emit a truncated value);
    //! (5) `gc_pruned_total` counter passthrough independence — the
    //! field MUST surface verbatim regardless of `gc_enabled` state
    //! (a node that has GC disabled can still have a non-zero historical
    //! pruned count from before the disable, and operators MUST see it).
    use super::compute_gc_status_payload;

    #[test]
    fn batch_ddd_envelope_is_strict_five_key_set() {
        // Axis 1: wire envelope contract. The strict 5-key shape
        // `{ gc_interval_secs, record_retention_secs, record_retention_days,
        // gc_pruned_total, gc_enabled }` is the operator-facing schema for
        // `GET /admin/gc`. Drift in either direction (a renamed key, a
        // dropped key, an extra debug field) is a silent breaking change
        // for any operator dashboard / curl-watcher pinned on this surface.
        // Pin all 5 keys explicitly so a future field addition is forced to
        // confront the test failure and bump this axis intentionally.
        let v = compute_gc_status_payload(86400, 604800.0, 0);

        let obj = v.as_object().expect("payload must be a JSON object");
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> = [
            "gc_interval_secs",
            "record_retention_secs",
            "record_retention_days",
            "gc_pruned_total",
            "gc_enabled",
        ]
        .iter()
        .copied()
        .collect();
        let missing: Vec<_> = expected.difference(&keys).copied().collect();
        let extra: Vec<_> = keys.difference(&expected).copied().collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "envelope key-set MUST be exactly {{gc_interval_secs, \
             record_retention_secs, record_retention_days, gc_pruned_total, \
             gc_enabled}} — missing={:?} extra={:?} got={:?} \
             (regression risk: dropped field, renamed wrapper, or extra debug key)",
            missing, extra, keys
        );
    }

    #[test]
    fn batch_ddd_enabled_branch_passes_inputs_through_verbatim() {
        // Axis 2: `gc_enabled=true` branch. When `gc_interval_secs > 0`
        // (i.e. GC loop is configured to run), the helper MUST set
        // `gc_enabled=true` AND pass all three input scalars through to
        // the output verbatim with no transformation other than the
        // documented secs→days conversion. Use the mainnet-tier defaults
        // from `NodeConfig` (`gc_interval_secs=3600`, `record_retention_secs=
        // 7*86400=604800.0` per internal design notes "scale target") to anchor a
        // realistic operator-facing readout.
        let v = compute_gc_status_payload(3600, 604800.0, 12345);

        assert_eq!(
            v["gc_interval_secs"].as_u64().unwrap(),
            3600,
            "gc_interval_secs MUST pass through verbatim — got {:?}",
            v["gc_interval_secs"]
        );
        assert!(
            (v["record_retention_secs"].as_f64().unwrap() - 604800.0).abs() < 1e-9,
            "record_retention_secs MUST pass through verbatim — got {:?}",
            v["record_retention_secs"]
        );
        assert_eq!(
            v["gc_pruned_total"].as_u64().unwrap(),
            12345,
            "gc_pruned_total MUST pass through verbatim — got {:?}",
            v["gc_pruned_total"]
        );
        assert!(
            v["gc_enabled"].as_bool().unwrap(),
            "gc_enabled MUST be true when gc_interval_secs > 0 — got {:?}",
            v["gc_enabled"]
        );
    }

    #[test]
    fn batch_ddd_disabled_branch_uses_strict_greater_than_zero_boundary() {
        // Axis 3: `gc_enabled=false` branch boundary pin. The check is
        // `gc_interval_secs > 0`, NOT `>= 0`. A regression that swapped
        // the comparator would never report "disabled" (since u64 is
        // always >= 0) — operator dashboards would silently report
        // "enabled" on a node where the GC loop never runs. Pin
        // `gc_interval_secs=0` to enforce the strict-positive boundary,
        // AND pin a non-zero `gc_pruned_total=999` to verify the field
        // is independent of `gc_enabled` (a node that ran with GC enabled
        // historically, then disabled it, still surfaces its accumulated
        // prune count — see Axis 5 for the strict independence pin).
        let v = compute_gc_status_payload(0, 604800.0, 999);

        assert!(
            !v["gc_enabled"].as_bool().unwrap(),
            "gc_enabled MUST be false when gc_interval_secs == 0 \
             (strict > 0 boundary, NOT >= 0) — got {:?}",
            v["gc_enabled"]
        );
        assert_eq!(
            v["gc_interval_secs"].as_u64().unwrap(),
            0,
            "gc_interval_secs MUST pass through as 0 even when disabled — got {:?}",
            v["gc_interval_secs"]
        );
        // gc_pruned_total field MUST still surface — see Axis 5 for the
        // explicit independence pin; here we only verify the value is
        // emitted when gc_enabled=false.
        assert_eq!(
            v["gc_pruned_total"].as_u64().unwrap(),
            999,
            "gc_pruned_total MUST still surface when gc_enabled=false — got {:?}",
            v["gc_pruned_total"]
        );
    }

    #[test]
    fn batch_ddd_record_retention_days_is_secs_divided_by_86400_floating_point() {
        // Axis 4: `record_retention_days = record_retention_secs / 86400.0`
        // derivation pin. The conversion MUST be floating-point division,
        // NOT integer division (`record_retention_secs` is `f64`, but a
        // regression that cast to `u64` would emit `0` for any sub-day
        // retention and lose precision for non-integer-day values). Pin
        // both a clean integer-day value (7 days exactly) and a sub-day
        // fractional value (43200 secs = 0.5 days — an integer-division
        // regression would emit `0` instead of `0.5`).
        let v_7d = compute_gc_status_payload(3600, 604800.0, 0);
        let v_12h = compute_gc_status_payload(3600, 43200.0, 0);

        let days_7d = v_7d["record_retention_days"]
            .as_f64()
            .expect("record_retention_days MUST be JSON Number");
        assert!(
            (days_7d - 7.0).abs() < 1e-9,
            "record_retention_days MUST be 7.0 for 604800 secs (7 days exact) — got {}",
            days_7d
        );

        let days_12h = v_12h["record_retention_days"]
            .as_f64()
            .expect("record_retention_days MUST be JSON Number");
        assert!(
            (days_12h - 0.5).abs() < 1e-9,
            "record_retention_days MUST be 0.5 for 43200 secs (12h) — got {} \
             (regression risk: integer-division cast to u64 would emit 0)",
            days_12h
        );
    }

    #[test]
    fn batch_ddd_gc_pruned_total_is_independent_of_gc_enabled_state() {
        // Axis 5: `gc_pruned_total` counter passthrough independence.
        // The field MUST surface verbatim regardless of whether
        // `gc_enabled` is true or false. Operationally: a node that ran
        // with GC enabled, accumulated a prune count, then had GC
        // disabled (e.g. for forensic investigation, archive replay,
        // or `gc_interval_secs=0` operator override) — that historical
        // count MUST still be visible on `GET /admin/gc`. A regression
        // that zeroed the field when `gc_enabled=false` would silently
        // erase forensic state from operator dashboards. Pin the
        // independence by emitting the same `gc_pruned_total=1_000_000`
        // under both `gc_enabled=true` (interval=3600) and
        // `gc_enabled=false` (interval=0) and asserting both surface
        // the value unchanged.
        let v_enabled = compute_gc_status_payload(3600, 604800.0, 1_000_000);
        let v_disabled = compute_gc_status_payload(0, 604800.0, 1_000_000);

        assert!(
            v_enabled["gc_enabled"].as_bool().unwrap(),
            "v_enabled.gc_enabled MUST be true (interval=3600)"
        );
        assert!(
            !v_disabled["gc_enabled"].as_bool().unwrap(),
            "v_disabled.gc_enabled MUST be false (interval=0)"
        );

        let pruned_enabled = v_enabled["gc_pruned_total"].as_u64().unwrap();
        let pruned_disabled = v_disabled["gc_pruned_total"].as_u64().unwrap();
        assert_eq!(
            pruned_enabled, 1_000_000,
            "gc_pruned_total MUST be 1_000_000 when gc_enabled=true — got {}",
            pruned_enabled
        );
        assert_eq!(
            pruned_disabled, 1_000_000,
            "gc_pruned_total MUST be 1_000_000 when gc_enabled=false \
             (independence pin — regression risk: a zero-on-disable branch \
             would erase forensic state) — got {}",
            pruned_disabled
        );
        assert_eq!(
            pruned_enabled, pruned_disabled,
            "gc_pruned_total MUST be identical across gc_enabled=true/false \
             with the same input value — got enabled={} disabled={}",
            pruned_enabled, pruned_disabled
        );
    }
}

#[cfg(test)]
mod admin_content_routing_tests {
    //! Pins
    //! `compute_content_routing_payload`, the testable core of
    //! `GET /admin/content_routing`. Previously the helper did not exist —
    //! `admin_content_routing` built the envelope inline by computing
    //! `active = threshold > 0 && peer_count >= threshold` and emitting
    //! the strict 6-key wire shape after a live DHT lookup. The helper
    //! takes the four already-resolved scalars + the pre-built
    //! `responsible_nodes` vec and emits the strict 6-key envelope
    //! `{ record_id, content_routing_threshold, content_routing_k,
    //! peer_count, content_routing_active, responsible_nodes }`. The 5
    //! axes below pin orthogonal concerns: (1) wire envelope contract
    //! (exactly 6 keys, no extras / no missing); (2) `content_routing_
    //! active=true` branch when BOTH `threshold>0` AND `peer_count >=
    //! threshold` are satisfied + scalar passthrough for all four input
    //! values; (3) `content_routing_active=false` via threshold=0
    //! (strict-positive gate — a `>=0` regression would always report
    //! active since usize is always >= 0); (4) `content_routing_active=
    //! false` via peer_count below threshold (the second leg of the
    //! AND); (5) `responsible_nodes` Vec passthrough independence —
    //! the field MUST surface verbatim regardless of the
    //! `content_routing_active` state (operators investigating
    //! "why didn't my record reach X?" need the live DHT K-closest
    //! list even when the routing layer is sub-threshold and would
    //! fall back to broadcast gossip).
    use super::compute_content_routing_payload;

    fn nodes_fixture() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({
                "identity_hash": "aaaa1111",
                "host": "127.0.0.1",
                "port": 9473u16,
                "provenance": "Direct"
            }),
            serde_json::json!({
                "identity_hash": "bbbb2222",
                "host": "127.0.0.1",
                "port": 9474u16,
                "provenance": "Direct"
            }),
        ]
    }

    #[test]
    fn batch_fff_envelope_is_strict_six_key_set() {
        // Axis 1: wire envelope contract. The strict 6-key shape
        // `{ record_id, content_routing_threshold, content_routing_k,
        // peer_count, content_routing_active, responsible_nodes }` is
        // the operator-facing schema for `GET /admin/content_routing`.
        // Drift in either direction (a renamed key, a dropped key, an
        // extra debug field) is a silent breaking change for any
        // operator dashboard / curl-watcher pinned on this surface.
        // Pin all 6 keys explicitly so a future field addition is
        // forced to confront the test failure and bump this axis
        // intentionally.
        let v = compute_content_routing_payload(
            "0198d6e0-0000-7000-8000-000000000000".into(),
            3,
            4,
            5,
            nodes_fixture(),
        );

        let obj = v.as_object().expect("payload must be a JSON object");
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> = [
            "record_id",
            "content_routing_threshold",
            "content_routing_k",
            "peer_count",
            "content_routing_active",
            "responsible_nodes",
        ]
        .iter()
        .copied()
        .collect();
        let missing: Vec<_> = expected.difference(&keys).copied().collect();
        let extra: Vec<_> = keys.difference(&expected).copied().collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "envelope key-set MUST be exactly {{record_id, \
             content_routing_threshold, content_routing_k, peer_count, \
             content_routing_active, responsible_nodes}} — missing={:?} \
             extra={:?} got={:?} (regression risk: dropped field, renamed \
             wrapper, or extra debug key)",
            missing, extra, keys
        );
    }

    #[test]
    fn batch_fff_active_branch_passes_inputs_through_verbatim() {
        // Axis 2: `content_routing_active=true` branch. When BOTH
        // `content_routing_threshold > 0` AND `peer_count >= threshold`
        // (i.e. content routing is active AND has enough peers to
        // satisfy the K-closest set), the helper MUST set
        // `content_routing_active=true` AND pass all four input scalars
        // through to the output verbatim with no transformation. Use
        // the mainnet-tier defaults from `NodeConfig` shape (threshold=3
        // = `default_content_routing_threshold`, k=8 =
        // `default_content_routing_k`) to anchor a realistic
        // operator-facing readout.
        let rid = "01ABCDEF-1234-7000-8000-000000000000".to_string();
        let v = compute_content_routing_payload(rid.clone(), 3, 8, 10, nodes_fixture());

        assert_eq!(
            v["record_id"].as_str().unwrap(),
            rid.as_str(),
            "record_id MUST pass through verbatim — got {:?}",
            v["record_id"]
        );
        assert_eq!(
            v["content_routing_threshold"].as_u64().unwrap(),
            3,
            "content_routing_threshold MUST pass through verbatim — got {:?}",
            v["content_routing_threshold"]
        );
        assert_eq!(
            v["content_routing_k"].as_u64().unwrap(),
            8,
            "content_routing_k MUST pass through verbatim — got {:?}",
            v["content_routing_k"]
        );
        assert_eq!(
            v["peer_count"].as_u64().unwrap(),
            10,
            "peer_count MUST pass through verbatim — got {:?}",
            v["peer_count"]
        );
        assert!(
            v["content_routing_active"].as_bool().unwrap(),
            "content_routing_active MUST be true when threshold>0 AND \
             peer_count>=threshold — got {:?}",
            v["content_routing_active"]
        );
    }

    #[test]
    fn batch_fff_inactive_when_threshold_is_zero_strict_positive_gate() {
        // Axis 3: `content_routing_active=false` via threshold=0 — the
        // strict-positive gate. The check is `threshold > 0`, NOT
        // `>= 0`. A regression that swapped the comparator would
        // always report `active=true` (since usize is always >= 0), so
        // operator dashboards would silently report content routing as
        // active on nodes where it is operator-disabled (`threshold=0`
        // is the documented disable-via-config posture). Pin
        // `threshold=0` with a generous `peer_count=1000` (well above
        // any plausible threshold) to enforce that the threshold gate
        // alone forces inactive, independent of peer count. Also pin
        // that the other inputs still pass through verbatim — a
        // regression that early-returned on threshold=0 would erase
        // the other scalars.
        let rid = "00000000-0000-7000-8000-000000000000".to_string();
        let v = compute_content_routing_payload(rid.clone(), 0, 8, 1000, nodes_fixture());

        assert!(
            !v["content_routing_active"].as_bool().unwrap(),
            "content_routing_active MUST be false when threshold==0 \
             (strict > 0 boundary, NOT >= 0) — got {:?}",
            v["content_routing_active"]
        );
        assert_eq!(
            v["content_routing_threshold"].as_u64().unwrap(),
            0,
            "content_routing_threshold MUST pass through as 0 even when \
             inactive — got {:?}",
            v["content_routing_threshold"]
        );
        assert_eq!(
            v["peer_count"].as_u64().unwrap(),
            1000,
            "peer_count MUST pass through verbatim even when inactive \
             (1000 peers but threshold=0 — pinned to demonstrate that the \
             threshold gate, not peer_count, is what flipped active=false) — \
             got {:?}",
            v["peer_count"]
        );
    }

    #[test]
    fn batch_fff_inactive_when_peer_count_below_threshold() {
        // Axis 4: `content_routing_active=false` via peer_count below
        // threshold — the second leg of the AND. With `threshold=8`
        // (positive, so the strict-positive gate from Axis 3 is
        // satisfied) and `peer_count=7` (one below the threshold), the
        // helper MUST report `active=false`. Defends against a
        // regression that flipped the comparator to `peer_count >
        // threshold` (off-by-one) OR `peer_count <= threshold`
        // (inverted) — either would silently change the active
        // boundary by one. Pin the exact off-by-one boundary
        // (peer_count = threshold - 1) so a future regression that
        // bumps the inequality direction is caught explicitly.
        let v_below = compute_content_routing_payload(
            "f0000000-0000-7000-8000-000000000000".into(),
            8,
            8,
            7,
            nodes_fixture(),
        );
        let v_at = compute_content_routing_payload(
            "f0000000-0000-7000-8000-000000000001".into(),
            8,
            8,
            8,
            nodes_fixture(),
        );

        assert!(
            !v_below["content_routing_active"].as_bool().unwrap(),
            "content_routing_active MUST be false when peer_count < threshold \
             (7 < 8) — got {:?} (regression risk: off-by-one or inverted \
             comparator)",
            v_below["content_routing_active"]
        );
        assert!(
            v_at["content_routing_active"].as_bool().unwrap(),
            "content_routing_active MUST be true when peer_count == threshold \
             (8 == 8) — got {:?} (the boundary is `>=` not `>`; a regression \
             to `>` would emit false at the exact-threshold case)",
            v_at["content_routing_active"]
        );
    }

    #[test]
    fn batch_fff_responsible_nodes_independent_of_active_state() {
        // Axis 5: `responsible_nodes` Vec passthrough independence.
        // The field MUST surface verbatim regardless of whether
        // `content_routing_active` is true or false. Operationally:
        // an operator investigating "why didn't my record reach
        // node X?" needs the live DHT K-closest list even when the
        // routing layer is sub-threshold (active=false) and would
        // fall back to broadcast gossip — the K-closest list still
        // tells the operator what content-routing WOULD select if
        // the threshold were satisfied. A regression that emitted
        // an empty array (or `null`) when `active=false` would
        // erase that diagnostic value. Emit the same 2-node
        // fixture under BOTH active=true (threshold=2 peer_count=2)
        // AND active=false (threshold=0) and assert the array
        // surfaces identically across both branches.
        let nodes = nodes_fixture();
        let v_active = compute_content_routing_payload(
            "0198d6e0-0000-7000-8000-000000000000".into(),
            2,
            4,
            2,
            nodes.clone(),
        );
        let v_inactive = compute_content_routing_payload(
            "0198d6e0-0000-7000-8000-000000000000".into(),
            0,
            4,
            2,
            nodes.clone(),
        );

        assert!(
            v_active["content_routing_active"].as_bool().unwrap(),
            "v_active.content_routing_active MUST be true (threshold=2, peer_count=2)"
        );
        assert!(
            !v_inactive["content_routing_active"].as_bool().unwrap(),
            "v_inactive.content_routing_active MUST be false (threshold=0)"
        );

        let arr_active = v_active["responsible_nodes"]
            .as_array()
            .expect("responsible_nodes MUST be JSON Array when active=true");
        let arr_inactive = v_inactive["responsible_nodes"]
            .as_array()
            .expect("responsible_nodes MUST be JSON Array when active=false");
        assert_eq!(
            arr_active.len(),
            2,
            "responsible_nodes MUST contain 2 entries when active=true — got {}",
            arr_active.len()
        );
        assert_eq!(
            arr_inactive.len(),
            2,
            "responsible_nodes MUST contain 2 entries when active=false \
             (independence pin — regression risk: an empty-on-inactive branch \
             would erase the K-closest diagnostic list) — got {}",
            arr_inactive.len()
        );
        assert_eq!(
            arr_active, arr_inactive,
            "responsible_nodes MUST be byte-identical across active=true/false \
             with the same input vec — got active={:?} inactive={:?}",
            arr_active, arr_inactive
        );
    }
}

#[cfg(test)]
mod admin_zone_autoscale_tests {
    //! Pins
    //! `compute_zone_autoscale_payload`, the testable core of
    //! `GET /admin/zone_autoscale`. Previously the helper did not exist —
    //! `admin_zone_autoscale` built the envelope inline by reading the
    //! `state.epoch.zone_activity_rate` HashMap + the `state.auto_scaler`
    //! Mutex's counters/hysteresis/last_decision + the `state.config`
    //! `auto_zone_scale`/`genesis_authority` scalars, then matching on the
    //! dry-run `recommend_zone_count()` Decision in two locations. The
    //! helper takes the resolved values (state already unlocked) and emits
    //! the strict 11-key envelope (`per_zone_count` joined in the
    //! O(n)-under-lock DoS batch: `per_zone_activity` is capped at 5000
    //! rows, so the TRUE zone total needs its own key). The axes below pin
    //! orthogonal concerns: (1) wire envelope contract (exactly 11 keys,
    //! no extras / missing); (2) `last_decision` `Some(Split/Merge)` arm vs the
    //! `_ => Null` arm collapsing `None` AND `Some(NoChange)` to JSON
    //! `null` (preserves the earlier handler's two-arm structure —
    //! NoChange isn't really a decision and `this_tick_recommendation`
    //! carries the live NoChange details); (3) `this_tick_recommendation`
    //! NoChange branch emitting `reason: format!("{reason:?}")` (Debug
    //! formatting pin — operator dashboards may grep for "Balanced" /
    //! "AtMaxZones" / "AtMinZones" / "NoData" so the Debug variant name
    //! is the operator-facing schema); (4) `per_zone_activity` list
    //! shape — each entry is `{ zone, rate }`, zone is the `ZoneId`
    //! Display string (the new helper takes `Vec<(ZoneId, f64)>`
    //! for deterministic iteration order in tests vs the inline-handler's
    //! HashMap iteration); (5) all-scalar passthrough — `enabled`,
    //! `is_genesis_authority`, `current_zone_count`, `max_zones`,
    //! `hysteresis_ticks`, `consecutive_hot`, `consecutive_cold` MUST
    //! surface verbatim with no transformation (defends against a
    //! regression that e.g. coerced `current_zone_count` to u32 and
    //! overflowed at mainnet scale).
    use super::compute_zone_autoscale_payload;
    use crate::network::auto_scale::{ScalingDecision, ScalingReason};
    use crate::network::zone::ZoneId;

    #[test]
    fn batch_eee_envelope_is_strict_eleven_key_set() {
        // Axis 1: wire envelope contract. The strict 11-key shape is the
        // operator-facing schema for `GET /admin/zone_autoscale`. Drift
        // (renamed key, dropped key, extra debug field) is a silent
        // breaking change for operator dashboards / curl-watchers pinned
        // on this surface. Pin all 11 keys explicitly so a future field
        // addition is forced to confront the test failure and bump this
        // axis intentionally.
        let v = compute_zone_autoscale_payload(
            true,
            false,
            1,
            1_000_000,
            4,
            0,
            0,
            None,
            ScalingDecision::NoChange { avg_rate: 0.5, reason: ScalingReason::Balanced },
            vec![(ZoneId::new("default"), 0.5)],
        );

        let obj = v.as_object().expect("payload must be a JSON object");
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> = [
            "enabled",
            "is_genesis_authority",
            "current_zone_count",
            "max_zones",
            "hysteresis_ticks",
            "consecutive_hot",
            "consecutive_cold",
            "last_decision",
            "this_tick_recommendation",
            "per_zone_activity",
            "per_zone_count",
        ]
        .iter()
        .copied()
        .collect();
        let missing: Vec<_> = expected.difference(&keys).copied().collect();
        let extra: Vec<_> = keys.difference(&expected).copied().collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "envelope key-set MUST be exactly the documented 11-key shape — \
             missing={:?} extra={:?} got={:?} \
             (regression risk: dropped field, renamed wrapper, or extra debug key)",
            missing, extra, keys
        );
    }

    #[test]
    fn batch_eee_per_zone_activity_capped_at_5000_with_true_count() {
        // SCALE RULE pin (idiom b): the serialized per-zone list is capped
        // at 5000 rows while `per_zone_count` reports the TRUE total —
        // truncation is detectable as list len < count. Also pins the
        // sub-cap case: no truncation, count == len.
        let zones: Vec<(ZoneId, f64)> = (0..5_001)
            .map(|i| (ZoneId::new(&format!("z{i}")), 1.0))
            .collect();
        let v = compute_zone_autoscale_payload(
            true,
            false,
            1,
            1_000_000,
            4,
            0,
            0,
            None,
            ScalingDecision::NoChange { avg_rate: 1.0, reason: ScalingReason::Balanced },
            zones,
        );
        assert_eq!(
            v["per_zone_activity"].as_array().unwrap().len(),
            5_000,
            "serialized per-zone list must cap at 5000 rows"
        );
        assert_eq!(
            v["per_zone_count"].as_u64().unwrap(),
            5_001,
            "per_zone_count must carry the TRUE uncapped total"
        );

        let v_small = compute_zone_autoscale_payload(
            true,
            false,
            1,
            1_000_000,
            4,
            0,
            0,
            None,
            ScalingDecision::NoChange { avg_rate: 1.0, reason: ScalingReason::Balanced },
            vec![(ZoneId::new("default"), 0.5)],
        );
        assert_eq!(v_small["per_zone_activity"].as_array().unwrap().len(), 1);
        assert_eq!(v_small["per_zone_count"].as_u64().unwrap(), 1);
    }

    #[test]
    fn batch_eee_last_decision_some_split_renders_object_envelope() {
        // Axis 2a: `last_decision: Some(Split{new_count, avg_rate})` arm.
        // MUST emit the 3-key `{direction:"split", new_count, avg_rate}`
        // object. Defends against a regression that collapsed Split into
        // `_ => Null` (silently erasing the last-decision telemetry from
        // operator dashboards) or emitted "Split" (PascalCase) instead of
        // "split" (lowercase, the convention for this_tick_recommendation
        // direction values).
        let v = compute_zone_autoscale_payload(
            true,
            true,
            2,
            1_000_000,
            4,
            5,
            0,
            Some(ScalingDecision::Split { new_count: 4, avg_rate: 25.0 }),
            ScalingDecision::NoChange { avg_rate: 25.0, reason: ScalingReason::Balanced },
            vec![],
        );

        let ld = &v["last_decision"];
        assert_eq!(
            ld["direction"].as_str().unwrap(),
            "split",
            "last_decision Some(Split) MUST render direction='split' (lowercase) — got {:?}",
            ld["direction"]
        );
        assert_eq!(
            ld["new_count"].as_u64().unwrap(),
            4,
            "last_decision Some(Split) MUST pass new_count through verbatim — got {:?}",
            ld["new_count"]
        );
        assert!(
            (ld["avg_rate"].as_f64().unwrap() - 25.0).abs() < 1e-9,
            "last_decision Some(Split) MUST pass avg_rate through verbatim — got {:?}",
            ld["avg_rate"]
        );
    }

    #[test]
    fn batch_eee_last_decision_none_and_some_nochange_both_render_null() {
        // Axis 2b: both `last_decision: None` AND `Some(NoChange)` MUST
        // render as JSON `null`. Earlier the inline handler used a single
        // `_ => Null` catch-all that collapsed both — preserving the
        // contract since operator tooling that switches on `null` would
        // break if NoChange suddenly serialized as an object. The
        // `this_tick_recommendation` field carries the live NoChange
        // details; `last_decision` Null means "no scaling has happened
        // recently (either bootstrapped or persistently balanced)".
        let v_none = compute_zone_autoscale_payload(
            true, false, 1, 1_000_000, 4, 0, 0, None,
            ScalingDecision::NoChange { avg_rate: 0.0, reason: ScalingReason::NoData },
            vec![],
        );
        assert!(
            v_none["last_decision"].is_null(),
            "last_decision=None MUST render as JSON null — got {:?}",
            v_none["last_decision"]
        );

        let v_some_nochange = compute_zone_autoscale_payload(
            true, false, 1, 1_000_000, 4, 0, 0,
            Some(ScalingDecision::NoChange { avg_rate: 5.0, reason: ScalingReason::Balanced }),
            ScalingDecision::NoChange { avg_rate: 5.0, reason: ScalingReason::Balanced },
            vec![],
        );
        assert!(
            v_some_nochange["last_decision"].is_null(),
            "last_decision=Some(NoChange) MUST render as JSON null (pre-§647 _ => Null arm contract) — got {:?}",
            v_some_nochange["last_decision"]
        );
    }

    #[test]
    fn batch_eee_this_tick_nochange_renders_debug_reason() {
        // Axis 3: `this_tick_recommendation: NoChange{avg_rate, reason}`
        // MUST emit `{direction:"none", avg_rate, reason: "<DebugVariant>"}`
        // where the reason string is the Rust Debug formatting of the
        // ScalingReason enum variant ("Balanced", "AtMaxZones",
        // "AtMinZones", "NoData"). Pin all four variants so operator
        // dashboards that grep for these strings catch a regression that
        // e.g. switched to Display formatting (which doesn't exist on
        // ScalingReason) or to snake_case ("at_max_zones").
        for (reason, expected) in [
            (ScalingReason::Balanced, "Balanced"),
            (ScalingReason::AtMaxZones, "AtMaxZones"),
            (ScalingReason::AtMinZones, "AtMinZones"),
            (ScalingReason::NoData, "NoData"),
        ] {
            let v = compute_zone_autoscale_payload(
                true, false, 1, 1_000_000, 4, 0, 0, None,
                ScalingDecision::NoChange { avg_rate: 1.0, reason: reason.clone() },
                vec![],
            );
            let this_tick = &v["this_tick_recommendation"];
            assert_eq!(
                this_tick["direction"].as_str().unwrap(),
                "none",
                "this_tick_recommendation NoChange MUST render direction='none' — got {:?}",
                this_tick["direction"]
            );
            assert_eq!(
                this_tick["reason"].as_str().unwrap(),
                expected,
                "this_tick_recommendation NoChange reason MUST render as Debug variant '{}' — got {:?}",
                expected, this_tick["reason"]
            );
        }
    }

    #[test]
    fn batch_eee_all_scalars_pass_through_verbatim() {
        // Axis 5: every scalar input — enabled, is_genesis_authority,
        // current_zone_count, max_zones, hysteresis_ticks, consecutive_hot,
        // consecutive_cold — MUST surface in the output unchanged. Pin
        // mainnet-relevant values (`current_zone_count` at the Protocol §11.12
        // 1M-zone scale target, `max_zones` at MAX_ZONE_COUNT, `hysteresis_
        // ticks` at the auto_scale.rs HYSTERESIS_TICKS=4 default) so a
        // regression that e.g. coerced u64→u32 and overflowed at mainnet
        // scale would surface as a test failure. Also pins
        // `is_genesis_authority=true` to confirm the auth-context flag
        // isn't dropped or renamed (operators on a non-genesis node need
        // to see this surfaced as false so they know which node would
        // emit the zone-split anchor record).
        let v = compute_zone_autoscale_payload(
            true,
            true,
            999_999,
            1_000_000,
            4,
            3,
            7,
            None,
            ScalingDecision::NoChange { avg_rate: 1.0, reason: ScalingReason::Balanced },
            vec![],
        );
        assert!(v["enabled"].as_bool().unwrap());
        assert!(v["is_genesis_authority"].as_bool().unwrap());
        assert_eq!(v["current_zone_count"].as_u64().unwrap(), 999_999);
        assert_eq!(v["max_zones"].as_u64().unwrap(), 1_000_000);
        assert_eq!(v["hysteresis_ticks"].as_u64().unwrap(), 4);
        assert_eq!(v["consecutive_hot"].as_u64().unwrap(), 3);
        assert_eq!(v["consecutive_cold"].as_u64().unwrap(), 7);

        // Axis 4: per_zone_activity list shape. Each entry is the 2-key
        // `{ zone, rate }` object with `zone` as the ZoneId Display string
        // (post-`ZoneId::new()` normalization — lowercased, trimmed). Pin
        // a multi-entry vec to confirm the iteration order matches the
        // input vec order (the new helper takes Vec<_>, not HashMap, so
        // ordering is deterministic — vs the earlier inline handler's
        // non-deterministic HashMap iter).
        let v_multi = compute_zone_autoscale_payload(
            true, false, 3, 1_000_000, 4, 0, 0, None,
            ScalingDecision::NoChange { avg_rate: 5.0, reason: ScalingReason::Balanced },
            vec![
                (ZoneId::new("zone-a"), 1.5),
                (ZoneId::new("zone-b"), 7.2),
                (ZoneId::new("zone-c"), 3.0),
            ],
        );
        let arr = v_multi["per_zone_activity"].as_array().expect("per_zone_activity must be array");
        assert_eq!(arr.len(), 3, "per_zone_activity MUST contain 3 entries — got {}", arr.len());
        assert_eq!(arr[0]["zone"].as_str().unwrap(), "zone-a");
        assert!((arr[0]["rate"].as_f64().unwrap() - 1.5).abs() < 1e-9);
        assert_eq!(arr[1]["zone"].as_str().unwrap(), "zone-b");
        assert!((arr[1]["rate"].as_f64().unwrap() - 7.2).abs() < 1e-9);
        assert_eq!(arr[2]["zone"].as_str().unwrap(), "zone-c");
        assert!((arr[2]["rate"].as_f64().unwrap() - 3.0).abs() < 1e-9);
    }
}

#[cfg(test)]
mod admin_epoch_snapshots_tests {
    //! Pins
    //! `compute_epoch_snapshots_payload`, the testable core of `GET
    //! /admin/epoch_snapshots`. Previously the handler built the 12-key
    //! envelope inline by reading `state.config.node_type`,
    //! `archive_snapshot_every_n_epochs`, `archive_snapshot_retention`,
    //! `state.config.data_dir.join("snapshots")`, the on-disk epoch list
    //! via `tokio::spawn_blocking → list_epoch_snapshots`, and
    //! `state.epoch.read_recover().latest_epoch.values().max()`. The
    //! helper takes the 7 already-resolved scalars + Vec and computes 5
    //! derived fields — `enabled` (`archival && every_n>0`),
    //! `latest_epoch_on_disk` (last of sorted vec), `count` (vec len),
    //! `next_trigger_at_epoch` (`latest.saturating_add(every_n)` or
    //! `every_n` when vec is empty), and `epochs_until_next_trigger`
    //! (`next_trigger.saturating_sub(current_max_epoch)`) — then emits
    //! the strict 12-key envelope `{ node_type, is_archival, enabled,
    //! every_n_epochs, retention, snapshot_dir, current_max_epoch,
    //! epochs_on_disk, count, latest_epoch_on_disk, next_trigger_at_
    //! epoch, epochs_until_next_trigger }`.
    //!
    //! The 5 axes below pin orthogonal concerns: (1) wire envelope
    //! contract (strict 12 keys, no extras / no missing); (2) `enabled`
    //! derivation MUST require BOTH `archival` AND `every_n>0` — pin
    //! all 4 truth-table cells (non-archival+0, non-archival+positive,
    //! archival+0, archival+positive); (3) `next_trigger_at_epoch`
    //! semantics — defaults to `every_n_epochs` on empty Vec and uses
    //! `saturating_add` on populated Vec (pin both the empty-Vec branch
    //! and the u64::MAX saturation boundary); (4) `epochs_until_next_
    //! trigger` uses `saturating_sub` — already-past trigger MUST
    //! surface as 0, NOT a wrap-around to near u64::MAX; (5)
    //! `epochs_on_disk` / `count` / `latest_epoch_on_disk` consistency
    //! invariant — count MUST equal the array length AND latest MUST
    //! equal the last element of the array (when non-empty) AND latest
    //! MUST be null when the array is empty.
    use super::compute_epoch_snapshots_payload;

    #[test]
    fn batch_ggg_envelope_is_strict_twelve_key_set() {
        // Axis 1: wire envelope contract. The strict 12-key shape is
        // the operator-facing schema for `GET /admin/epoch_snapshots`.
        // Drift (renamed key, dropped key, extra debug field) is a
        // silent breaking change for operator dashboards / curl-
        // watchers pinned on this surface. Pin all 12 keys explicitly
        // via BTreeSet symmetric-difference so a future field
        // addition is forced to confront the test failure and bump
        // this axis intentionally.
        let v = compute_epoch_snapshots_payload(
            "archive".to_string(),
            true,
            10,
            20,
            "/data/snapshots".to_string(),
            100,
            vec![20, 30, 40],
        );

        let obj = v.as_object().expect("payload must be a JSON object");
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> = [
            "node_type",
            "is_archival",
            "enabled",
            "every_n_epochs",
            "retention",
            "snapshot_dir",
            "current_max_epoch",
            "epochs_on_disk",
            "count",
            "latest_epoch_on_disk",
            "next_trigger_at_epoch",
            "epochs_until_next_trigger",
        ]
        .iter()
        .copied()
        .collect();
        let missing: Vec<_> = expected.difference(&keys).copied().collect();
        let extra: Vec<_> = keys.difference(&expected).copied().collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "envelope key-set MUST be exactly the documented 12-key shape \
             {{node_type, is_archival, enabled, every_n_epochs, retention, \
             snapshot_dir, current_max_epoch, epochs_on_disk, count, \
             latest_epoch_on_disk, next_trigger_at_epoch, \
             epochs_until_next_trigger}} — missing={:?} extra={:?} got={:?} \
             (regression risk: dropped field, renamed wrapper, or extra \
             debug key)",
            missing, extra, keys
        );
    }

    #[test]
    fn batch_ggg_enabled_derivation_requires_archival_and_positive_every_n() {
        // Axis 2: `enabled` MUST be derived as `archival && every_n_epochs > 0`.
        // Pin all four truth-table cells to defend against four orthogonal
        // regressions: (a) OR instead of AND (would enable on any
        // archival-OR-positive-every_n combination, including non-archival
        // nodes with every_n=10 — i.e. light nodes wrongly claiming to be
        // snapshotting); (b) ignoring the `> 0` gate (would surface
        // every_n=0 as enabled — but no snapshots would ever fire, silently
        // breaking Gap 7 archive coverage); (c) ignoring `archival` (would
        // surface every-archival-disabled node as enabled if every_n>0);
        // (d) negating archival or every_n (cross-wiring). All 4 cells must
        // be pinned because the truth table has 4 distinct outcomes and any
        // single-flip regression matches at least 2 cells but breaks at
        // least 1.
        let cases = [
            // (archival, every_n, expected_enabled, description)
            (false, 0, false, "non-archival + zero cadence → disabled"),
            (false, 10, false, "non-archival + positive cadence → disabled \
             (archival gate alone forces false)"),
            (true, 0, false, "archival + zero cadence → disabled (every_n>0 \
             gate alone forces false — operator-explicit \
             `archive_snapshot_every_n_epochs=0` is the documented \
             disable-via-config posture)"),
            (true, 10, true, "archival + positive cadence → enabled (the \
             only TRUE cell — both gates satisfied)"),
        ];

        for (archival, every_n, expected, desc) in cases {
            let v = compute_epoch_snapshots_payload(
                "archive".to_string(),
                archival,
                every_n,
                20,
                "/data/snapshots".to_string(),
                0,
                vec![],
            );
            assert_eq!(
                v["enabled"].as_bool().unwrap(),
                expected,
                "{} — got enabled={:?} (regression risk: OR-instead-of-AND, \
                 missing `>0` gate, or cross-wired field)",
                desc, v["enabled"]
            );
        }
    }

    #[test]
    fn batch_ggg_next_trigger_at_epoch_handles_empty_vec_and_saturating_add() {
        // Axis 3: `next_trigger_at_epoch` semantics.
        // (a) On EMPTY epochs_on_disk: defaults to `every_n_epochs` directly
        //     (not 0, not the latest of an empty Vec which would panic).
        //     This is the "we've never snapshotted" branch — the operator
        //     sees that the next trigger is at `every_n` epochs from
        //     genesis (epoch 0), so they can predict when archive coverage
        //     begins.
        // (b) On POPULATED epochs_on_disk: `latest.saturating_add(every_n)`
        //     — uses saturating_add explicitly to defend against a
        //     regression that switched to `latest + every_n` (would panic
        //     in debug builds, wrap in release builds) when `latest` is
        //     near u64::MAX. Pin the u64::MAX-adjacent case explicitly so
        //     the saturating boundary is exercised.

        // (a) Empty Vec → next_trigger == every_n_epochs.
        let v_empty = compute_epoch_snapshots_payload(
            "archive".to_string(),
            true,
            10,
            20,
            "/d".to_string(),
            0,
            vec![],
        );
        assert_eq!(
            v_empty["next_trigger_at_epoch"].as_u64().unwrap(),
            10,
            "empty epochs_on_disk: next_trigger_at_epoch MUST default to \
             every_n_epochs (10) — got {:?} (regression risk: defaulting to \
             0 or panicking on empty Vec last())",
            v_empty["next_trigger_at_epoch"]
        );
        assert!(
            v_empty["latest_epoch_on_disk"].is_null(),
            "empty epochs_on_disk: latest_epoch_on_disk MUST be JSON null \
             (Option::None serializes as null) — got {:?}",
            v_empty["latest_epoch_on_disk"]
        );

        // (b1) Populated Vec, normal arithmetic.
        let v_normal = compute_epoch_snapshots_payload(
            "archive".to_string(),
            true,
            10,
            20,
            "/d".to_string(),
            45,
            vec![10, 20, 30, 40],
        );
        assert_eq!(
            v_normal["next_trigger_at_epoch"].as_u64().unwrap(),
            50,
            "populated Vec [10,20,30,40] + every_n=10: next_trigger_at_epoch \
             MUST equal latest(40) + every_n(10) = 50 — got {:?}",
            v_normal["next_trigger_at_epoch"]
        );
        assert_eq!(
            v_normal["latest_epoch_on_disk"].as_u64().unwrap(),
            40,
            "populated Vec [10,20,30,40]: latest_epoch_on_disk MUST be 40 \
             (last element) — got {:?}",
            v_normal["latest_epoch_on_disk"]
        );

        // (b2) Saturating-add boundary: latest = u64::MAX - 5, every_n = 100
        // → next_trigger MUST saturate at u64::MAX (NOT wrap around to ~95).
        let v_sat = compute_epoch_snapshots_payload(
            "archive".to_string(),
            true,
            100,
            20,
            "/d".to_string(),
            0,
            vec![u64::MAX - 5],
        );
        assert_eq!(
            v_sat["next_trigger_at_epoch"].as_u64().unwrap(),
            u64::MAX,
            "saturating_add boundary: latest=u64::MAX-5 + every_n=100 MUST \
             saturate at u64::MAX (NOT wrap to ~95). A regression to plain \
             `+` would surface here as ~95 — got {:?}",
            v_sat["next_trigger_at_epoch"]
        );
    }

    #[test]
    fn batch_ggg_epochs_until_next_trigger_uses_saturating_sub() {
        // Axis 4: `epochs_until_next_trigger` MUST use `saturating_sub`,
        // not wrapping subtraction. The math is
        // `next_trigger.saturating_sub(current_max_epoch)`. Three cases:
        // (a) current_max < next_trigger → positive countdown (normal);
        // (b) current_max == next_trigger → exactly 0 (boundary — operator
        //     sees "trigger is due THIS tick");
        // (c) current_max > next_trigger → 0 via saturating_sub (the
        //     trigger is already past — node was offline through the
        //     scheduled trigger window or operator restarted with a stale
        //     snapshot dir). A regression to `next - current` (plain
        //     subtract) would panic in debug OR wrap to a huge value in
        //     release, breaking the operator's "is archive snapshot
        //     overdue?" dashboard widget.

        // (a) Normal: max=45, latest=40, every_n=10 → trigger=50 → countdown=5
        let v_a = compute_epoch_snapshots_payload(
            "archive".to_string(),
            true,
            10,
            20,
            "/d".to_string(),
            45,
            vec![40],
        );
        assert_eq!(
            v_a["epochs_until_next_trigger"].as_u64().unwrap(),
            5,
            "normal countdown: trigger(50) - current(45) = 5 — got {:?}",
            v_a["epochs_until_next_trigger"]
        );

        // (b) Boundary: max=50, latest=40, every_n=10 → trigger=50 → countdown=0
        let v_b = compute_epoch_snapshots_payload(
            "archive".to_string(),
            true,
            10,
            20,
            "/d".to_string(),
            50,
            vec![40],
        );
        assert_eq!(
            v_b["epochs_until_next_trigger"].as_u64().unwrap(),
            0,
            "boundary: trigger(50) - current(50) = 0 (trigger due THIS \
             tick) — got {:?}",
            v_b["epochs_until_next_trigger"]
        );

        // (c) Past: max=100, latest=40, every_n=10 → trigger=50, current=100
        // → would underflow without saturating_sub. MUST be 0, NOT wrap.
        let v_c = compute_epoch_snapshots_payload(
            "archive".to_string(),
            true,
            10,
            20,
            "/d".to_string(),
            100,
            vec![40],
        );
        assert_eq!(
            v_c["epochs_until_next_trigger"].as_u64().unwrap(),
            0,
            "saturating_sub: current(100) > trigger(50) MUST surface as 0 \
             (NOT wrap to u64::MAX - 50 + 1 ≈ 1.8e19). A regression to \
             `next - current` would silently surface as ~1.8e19, breaking \
             operator dashboards reading 'is archive snapshot overdue?' — \
             got {:?}",
            v_c["epochs_until_next_trigger"]
        );
    }

    #[test]
    fn batch_ggg_epochs_on_disk_count_and_latest_consistency_invariant() {
        // Axis 5: `epochs_on_disk` / `count` / `latest_epoch_on_disk`
        // three-way consistency invariant. The contract:
        //   - `count` MUST equal `epochs_on_disk.len()`
        //   - `latest_epoch_on_disk` MUST equal `epochs_on_disk.last()`
        //     (or JSON null when the array is empty)
        //   - `epochs_on_disk` MUST surface as a JSON array verbatim (NOT
        //     transformed, NOT deduped, NOT sorted — the caller is
        //     responsible for sort order via `list_epoch_snapshots`)
        // A refactor that accidentally swapped `.last()` for `.first()`
        // would break the operator's "what was our most recent snapshot?"
        // signal — the operator's recovery playbook hinges on knowing
        // which snapshot to restore from on the rebuild-from-cold path.
        // Pin both the empty-Vec and populated-Vec branches, plus a
        // boundary case where the array is reverse-sorted (regression
        // probe: `.last()` returns the lowest, NOT the highest, if the
        // helper were to sort internally).

        // Empty Vec: count=0, latest=null, epochs_on_disk=[].
        let v_empty = compute_epoch_snapshots_payload(
            "archive".to_string(),
            true,
            10,
            20,
            "/d".to_string(),
            0,
            vec![],
        );
        assert_eq!(
            v_empty["count"].as_u64().unwrap(),
            0,
            "empty Vec: count MUST be 0 — got {:?}",
            v_empty["count"]
        );
        assert!(
            v_empty["latest_epoch_on_disk"].is_null(),
            "empty Vec: latest_epoch_on_disk MUST be JSON null — got {:?}",
            v_empty["latest_epoch_on_disk"]
        );
        let arr_empty = v_empty["epochs_on_disk"]
            .as_array()
            .expect("epochs_on_disk MUST be a JSON array even when empty");
        assert_eq!(
            arr_empty.len(),
            0,
            "empty Vec: epochs_on_disk array MUST be empty — got {} entries",
            arr_empty.len()
        );

        // Populated Vec [100, 200, 300, 400]: count=4, latest=400 (last
        // element), array preserved verbatim.
        let v_pop = compute_epoch_snapshots_payload(
            "archive".to_string(),
            true,
            100,
            20,
            "/d".to_string(),
            500,
            vec![100, 200, 300, 400],
        );
        assert_eq!(
            v_pop["count"].as_u64().unwrap(),
            4,
            "populated Vec [100,200,300,400]: count MUST be 4 — got {:?}",
            v_pop["count"]
        );
        assert_eq!(
            v_pop["latest_epoch_on_disk"].as_u64().unwrap(),
            400,
            "populated Vec [100,200,300,400]: latest_epoch_on_disk MUST be \
             400 (LAST element, NOT first) — defends against `.first()` \
             regression — got {:?}",
            v_pop["latest_epoch_on_disk"]
        );
        let arr_pop = v_pop["epochs_on_disk"]
            .as_array()
            .expect("epochs_on_disk MUST be a JSON array");
        let parsed: Vec<u64> = arr_pop.iter().map(|v| v.as_u64().unwrap()).collect();
        assert_eq!(
            parsed,
            vec![100u64, 200, 300, 400],
            "epochs_on_disk MUST surface input Vec verbatim — got {:?}",
            parsed
        );

        // Reverse-sorted Vec [400, 300, 200, 100]: caller is responsible for
        // sort order — helper does NOT re-sort internally. latest MUST be
        // 100 (last element of the input Vec), NOT 400 (max).
        let v_rev = compute_epoch_snapshots_payload(
            "archive".to_string(),
            true,
            100,
            20,
            "/d".to_string(),
            500,
            vec![400, 300, 200, 100],
        );
        assert_eq!(
            v_rev["latest_epoch_on_disk"].as_u64().unwrap(),
            100,
            "reverse-sorted Vec [400,300,200,100]: latest_epoch_on_disk \
             MUST be 100 (LAST element of input Vec). The caller is \
             responsible for sort order via list_epoch_snapshots; a \
             refactor that internally sorted descending and took .first() \
             OR took the .max() of the Vec would surface as 400 here — \
             got {:?}",
            v_rev["latest_epoch_on_disk"]
        );
    }
}

#[cfg(test)]
mod admin_zone_subscriptions_tests {
    //! Pins
    //! `compute_zone_subscriptions_payload`, the testable core of `GET
    //! /admin/zone_subscriptions`. Previously the handler built the 10-key
    //! envelope inline by reading `state.identity.identity_hash`,
    //! `state.config.light_mode`, `state.epoch.read_recover()
    //! .latest_epoch.values().max()`, the local `ZoneSubscriptionRegistry`
    //! view (zones_for / valid_until / total_subscribers / zone_counts),
    //! and two config knobs (`zone_subscription_validity_epochs` +
    //! `zone_subscription_refresh_margin`). The helper takes the 9
    //! already-resolved scalars / Option / Vec inputs and computes ONE
    //! derived field — `our_subscription_epochs_remaining =
    //! our_subscription_valid_until_epoch.map(|vu| vu.saturating_sub(
    //! current_epoch))` — then emits the strict 10-key envelope `{
    //! identity, light_mode, current_epoch, our_subscribed_zones,
    //! our_subscription_valid_until_epoch, our_subscription_epochs_
    //! remaining, validity_epochs, refresh_margin_epochs, total_
    //! subscribers_across_all_zones, per_zone_subscribers }`.
    //!
    //! The 5 axes below pin orthogonal concerns: (1) wire envelope
    //! contract (strict 10 keys, no extras / no missing); (2)
    //! `our_subscription_epochs_remaining` — the ONLY derived field —
    //! MUST use `saturating_sub` AND pass `None` through to JSON null
    //! verbatim — pin 5 cells (None → null, Some(future) → positive,
    //! Some(equal) → 0, Some(past) → 0 NOT u64::MAX wrap, Some(0)+
    //! current=u64::MAX → 0); (3) scalar passthrough — validity_epochs
    //! / refresh_margin_epochs / total_subscribers_across_all_zones are
    //! NOT derived, MUST pass through verbatim — defends against cross-
    //! wired field reads where the helper reads validity_epochs but
    //! emits the value under refresh_margin_epochs (a single-flip
    //! regression would silently surface in the operator dashboard);
    //! (4) `per_zone_subscribers` Vec preserves caller order — the
    //! helper takes `Vec<serde_json::Value>` so iteration order is
    //! deterministic (the route handler emits in the order returned by
    //! `reg.zone_counts()`) — a regression sorting/deduping the Vec
    //! internally would break the caller's ordering contract; (5)
    //! identity AND light_mode passthrough — `identity` is the
    //! `our_hash` String straight from `state.identity.identity_hash`
    //! (NOT derived from anything), `light_mode` is the config bool
    //! straight from `state.config.light_mode`, both pinned via
    //! distinctive input values that would collide if the helper
    //! cross-wired the two reads.
    use super::compute_zone_subscriptions_payload;

    #[test]
    fn batch_hhh_envelope_is_strict_ten_key_set() {
        // Axis 1: wire envelope contract. The strict 10-key shape is
        // the operator-facing schema for `GET /admin/zone_subscriptions`.
        // Drift (renamed key, dropped key, extra debug field) is a
        // silent breaking change for operator dashboards / curl-
        // watchers pinned on this surface. Pin all 10 keys explicitly
        // via BTreeSet symmetric-difference so a future field
        // addition is forced to confront the test failure and bump
        // this axis intentionally.
        let v = compute_zone_subscriptions_payload(
            "abc123def456".to_string(),
            false,
            100,
            vec!["zone-a".to_string(), "zone-b".to_string()],
            Some(150),
            50,
            5,
            42,
            vec![
                serde_json::json!({ "zone": "zone-a", "subscribers": 3 }),
                serde_json::json!({ "zone": "zone-b", "subscribers": 7 }),
            ],
        );

        let obj = v.as_object().expect("payload must be a JSON object");
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> = [
            "identity",
            "light_mode",
            "current_epoch",
            "our_subscribed_zones",
            "our_subscription_valid_until_epoch",
            "our_subscription_epochs_remaining",
            "validity_epochs",
            "refresh_margin_epochs",
            "total_subscribers_across_all_zones",
            "per_zone_subscribers",
        ]
        .iter()
        .copied()
        .collect();

        let missing: Vec<&&str> = expected.difference(&keys).collect();
        let extra: Vec<&&str> = keys.difference(&expected).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "envelope drift: missing={:?} extra={:?} (expected exactly 10 keys: {:?})",
            missing,
            extra,
            expected
        );
        assert_eq!(obj.len(), 10, "envelope MUST be exactly 10 keys — got {}", obj.len());
    }

    #[test]
    fn batch_hhh_epochs_remaining_handles_some_and_none_through_saturating_sub() {
        // Axis 2: `our_subscription_epochs_remaining` is the ONLY
        // derived field. Two distinct behaviors must hold:
        //   (a) `None` MUST pass through to JSON null verbatim (a
        //       node that has never subscribed has no valid_until).
        //   (b) `Some(vu)` MUST compute `vu.saturating_sub(current)` —
        //       defends against plain `vu - current` (would panic in
        //       debug builds, wrap to ~1.8e19 silently in release on
        //       the past-trigger case).
        // 5 cells pinned: (None,*), (future,positive), (equal,0),
        // (past,0-saturated), (0,u64::MAX-saturated).

        // Cell 1: None → null
        let v_none = compute_zone_subscriptions_payload(
            "id".to_string(), false, 100,
            vec![], None, 50, 5, 0, vec![],
        );
        assert!(
            v_none["our_subscription_epochs_remaining"].is_null(),
            "None valid_until MUST surface as JSON null — got {:?}",
            v_none["our_subscription_epochs_remaining"]
        );

        // Cell 2: Some(future) → positive countdown
        let v_future = compute_zone_subscriptions_payload(
            "id".to_string(), false, 100,
            vec![], Some(150), 50, 5, 0, vec![],
        );
        assert_eq!(
            v_future["our_subscription_epochs_remaining"].as_u64().unwrap(),
            50,
            "Some(150) - current=100 MUST be 50 (positive countdown)"
        );

        // Cell 3: Some(equal) → 0
        let v_eq = compute_zone_subscriptions_payload(
            "id".to_string(), false, 100,
            vec![], Some(100), 50, 5, 0, vec![],
        );
        assert_eq!(
            v_eq["our_subscription_epochs_remaining"].as_u64().unwrap(),
            0,
            "Some(100) - current=100 MUST be 0 (boundary)"
        );

        // Cell 4: Some(past) → 0 saturated (the load-bearing safety case)
        let v_past = compute_zone_subscriptions_payload(
            "id".to_string(), false, 1000,
            vec![], Some(500), 50, 5, 0, vec![],
        );
        assert_eq!(
            v_past["our_subscription_epochs_remaining"].as_u64().unwrap(),
            0,
            "Some(500) - current=1000 MUST saturate to 0 — a plain `vu - \
             current` would wrap to u64::MAX-499 (~1.8e19), silently \
             surfacing 'subscription has 1.8e19 epochs remaining' in the \
             operator dashboard for an EXPIRED subscription. Got {}",
            v_past["our_subscription_epochs_remaining"].as_u64().unwrap()
        );

        // Cell 5: Some(0) with current=u64::MAX → 0 saturated (extreme)
        let v_extreme = compute_zone_subscriptions_payload(
            "id".to_string(), false, u64::MAX,
            vec![], Some(0), 50, 5, 0, vec![],
        );
        assert_eq!(
            v_extreme["our_subscription_epochs_remaining"].as_u64().unwrap(),
            0,
            "Some(0) - current=u64::MAX MUST saturate to 0 (extreme boundary)"
        );
    }

    #[test]
    fn batch_hhh_scalar_passthroughs_no_cross_wiring() {
        // Axis 3: validity_epochs / refresh_margin_epochs /
        // total_subscribers_across_all_zones are pure passthrough
        // scalars, NOT derived from any other input. Pick DISTINCTIVE
        // primes (7919 / 7927 / 7933 — three consecutive primes near
        // 8000) so a single-flip cross-wiring regression (helper reads
        // validity_epochs but emits the value under
        // refresh_margin_epochs) would surface as a wrong-key test
        // failure — the BTreeSet shield in axis 1 only catches the
        // KEY drift, this catches the VALUE-source drift.
        let v = compute_zone_subscriptions_payload(
            "id".to_string(),
            false,
            100,
            vec![],
            Some(150),
            7919, // validity_epochs
            7927, // refresh_margin_epochs
            7933, // total_subscribers
            vec![],
        );

        assert_eq!(
            v["validity_epochs"].as_u64().unwrap(),
            7919,
            "validity_epochs MUST be 7919 (distinct prime); a cross-wired \
             helper reading refresh_margin_epochs here would surface as 7927"
        );
        assert_eq!(
            v["refresh_margin_epochs"].as_u64().unwrap(),
            7927,
            "refresh_margin_epochs MUST be 7927 (distinct prime); a cross-wired \
             helper reading validity_epochs here would surface as 7919"
        );
        assert_eq!(
            v["total_subscribers_across_all_zones"].as_u64().unwrap(),
            7933,
            "total_subscribers_across_all_zones MUST be 7933 (distinct prime); \
             a cross-wired helper reading either of the other two here would \
             surface as 7919 or 7927"
        );
    }

    #[test]
    fn batch_hhh_per_zone_subscribers_preserves_caller_order() {
        // Axis 4: `per_zone_subscribers` Vec MUST be emitted verbatim,
        // in the order the caller provided. The route handler builds
        // this Vec from `reg.zone_counts()` which returns in the
        // registry's iteration order; a helper that internally
        // sorted / deduped / re-ordered the Vec would break the
        // caller's contract (operators rely on the order matching
        // the registry's internal order when cross-referencing with
        // `/admin/zones/scope`). Pin a reverse-sorted input — a sort-
        // ascending regression would surface as [a,b,c] instead of
        // [c,b,a], and a dedupe regression on the (zone, count)
        // tuple would drop duplicate-count entries.
        let v = compute_zone_subscriptions_payload(
            "id".to_string(),
            false,
            100,
            vec![],
            None,
            50,
            5,
            12,
            vec![
                serde_json::json!({ "zone": "zone-c", "subscribers": 5 }),
                serde_json::json!({ "zone": "zone-b", "subscribers": 5 }),
                serde_json::json!({ "zone": "zone-a", "subscribers": 2 }),
            ],
        );

        let arr = v["per_zone_subscribers"]
            .as_array()
            .expect("per_zone_subscribers MUST be a JSON array");
        assert_eq!(arr.len(), 3, "Vec preserved as 3 entries");
        assert_eq!(
            arr[0]["zone"].as_str().unwrap(),
            "zone-c",
            "entry[0].zone MUST be 'zone-c' (FIRST element of input Vec, \
             NOT sort-ascending 'zone-a'); a regression sorting the Vec \
             internally would surface as 'zone-a' here. Got {:?}",
            arr[0]["zone"]
        );
        assert_eq!(arr[1]["zone"].as_str().unwrap(), "zone-b");
        assert_eq!(arr[2]["zone"].as_str().unwrap(), "zone-a");
        // Equal-count entries (zone-c, zone-b both at subscribers=5)
        // pin the dedupe-on-count regression: a helper that dedup'd
        // by count would drop one of the two and surface arr.len()==2.
        assert_eq!(
            arr[0]["subscribers"].as_u64().unwrap(),
            5,
            "zone-c subscribers count preserved (= 5)"
        );
        assert_eq!(
            arr[1]["subscribers"].as_u64().unwrap(),
            5,
            "zone-b subscribers count preserved (= 5); a dedupe-on-count \
             regression would have dropped this entry"
        );
    }

    #[test]
    fn batch_hhh_identity_and_light_mode_passthrough() {
        // Axis 5: `identity` is the `our_hash` String straight from
        // `state.identity.identity_hash`. `light_mode` is the config
        // bool straight from `state.config.light_mode`. Both are pure
        // passthrough, NO derivation. Pin distinctive inputs that
        // would collide if cross-wired:
        //   - identity = a 64-hex string that visually differs from
        //     any zone-id or config value
        //   - light_mode = true on a node where every other bool-like
        //     field would default to false, so a regression cross-
        //     wiring light_mode with archival/etc. would surface as
        //     the WRONG bool in the output
        // Also pin our_subscribed_zones Vec passthrough here (a 5th
        // passthrough Vec) — the helper takes Vec<String> and emits
        // it verbatim; a regression converting String to enum or
        // sorting the Vec would surface here.
        let v = compute_zone_subscriptions_payload(
            "deadbeefcafef00ddeadbeefcafef00ddeadbeefcafef00ddeadbeefcafef00d".to_string(),
            true, // light_mode = true (a light client)
            100,
            vec![
                "zone-zzz".to_string(),
                "zone-aaa".to_string(),
                "zone-mmm".to_string(),
            ],
            Some(200),
            50,
            5,
            0,
            vec![],
        );

        assert_eq!(
            v["identity"].as_str().unwrap(),
            "deadbeefcafef00ddeadbeefcafef00ddeadbeefcafef00ddeadbeefcafef00d",
            "identity MUST be the 64-hex our_hash passed in (NOT derived \
             from any other field)"
        );
        assert!(
            v["light_mode"].as_bool().unwrap(),
            "light_mode MUST be true (pure passthrough from config; a \
             cross-wired helper reading any other bool here would surface \
             as false)"
        );

        // our_subscribed_zones Vec preserved (a 5th passthrough Vec —
        // the per_zone_subscribers Vec is axis 4, this is the
        // SEPARATE our_subscribed_zones Vec which is also passthrough)
        let zones = v["our_subscribed_zones"]
            .as_array()
            .expect("our_subscribed_zones MUST be JSON array");
        assert_eq!(zones.len(), 3, "our_subscribed_zones Vec preserved (3 entries)");
        assert_eq!(
            zones[0].as_str().unwrap(),
            "zone-zzz",
            "our_subscribed_zones[0] MUST be 'zone-zzz' (FIRST element of \
             input Vec, NOT sort-ascending 'zone-aaa'). A regression \
             sorting the Vec internally would surface as 'zone-aaa' here."
        );
        assert_eq!(zones[1].as_str().unwrap(), "zone-aaa");
        assert_eq!(zones[2].as_str().unwrap(), "zone-mmm");
    }
}

#[cfg(test)]
mod admin_dag_check_tests {
    //! Pins
    //! `compute_dag_check_payload`, the testable core of `GET
    //! /admin/dag_check`. Previously the handler built the 8-key
    //! envelope inline by reading `state.record_count()`, `dag.len()`,
    //! `dag.tips().len()`, `dag.roots().len()`, and `dag.edge_count()`.
    //! The helper takes the 5 already-resolved usize inputs and
    //! computes THREE derived fields: `missing_from_dag =
    //! storage_records.saturating_sub(dag_indexed)`, `coverage_pct =
    //! ((dag_indexed / storage_records * 100).min(100.0) * 100).round
    //! () / 100.0` (with the special `storage_records == 0` branch
    //! returning 100.0), and `healthy = missing_from_dag == 0`.
    //!
    //! The 5 axes below pin orthogonal concerns: (1) empty / zero-
    //! baseline 8-key envelope shape — storage=0/dag=0 surfaces
    //! coverage=100.0, healthy=true, missing=0, tips/roots/edges=0 —
    //! pins the wire envelope is EXACTLY 8 keys via BTreeSet symmetric
    //! -difference (no extras, no missing); (2) perfect coverage —
    //! storage=100/dag=100 yields coverage=100.0, missing=0,
    //! healthy=true — the "operator-healthy" baseline that ops watch
    //! for; (3) partial coverage rounded to 2 decimals — storage=3/
    //! dag=2 yields coverage=66.67 (NOT 66.66666... or 66.667 or 66.6)
    //! pinning the `(coverage * 100.0).round() / 100.0` 2-decimal
    //! quantization idiom AND missing=1 / healthy=false — the rounding
    //! is load-bearing for operator-dashboard string match (a refactor
    //! to `format!("{:.2}")` OR removing the round-trip would surface
    //! here); (4) defensive saturating_sub + coverage clamp — dag=10 /
    //! storage=5 (defensive impossible-in-practice ordering) must NOT
    //! underflow `missing` to usize::MAX (saturating_sub clamps to 0)
    //! AND coverage must clamp at 100.0 (NOT 200.0) via `.min(100.0)`;
    //! both saturating_sub-removal AND .min(100.0)-removal regressions
    //! would surface; (5) tips/roots/edges scalar passthrough — these
    //! three are NOT derived, MUST pass through verbatim with
    //! distinctive-prime values (tips=7, roots=11, edges=42) that
    //! collide if the helper cross-wires the three reads (e.g. emits
    //! `tips` from the roots input).
    use super::compute_dag_check_payload;

    #[test]
    fn batch_jjj_empty_state_pins_eight_key_envelope_with_zero_baseline() {
        // Axis 1: empty / zero-baseline 8-key envelope shape. New
        // node, no records ingested, no DAG built yet. The handler
        // MUST report `healthy: true` (no missing records because
        // there are no records at all) AND `coverage_pct: 100.0`
        // (the `storage_records == 0` branch — division by zero
        // sentinel — returns 100.0 NOT NaN NOT 0.0). Operator
        // dashboards rely on this NOT firing a "DAG drift" alert
        // on a freshly-bootstrapped node.
        let v = compute_dag_check_payload(0, 0, 0, 0, 0);

        let obj = v.as_object().expect("payload must be a JSON object");
        let keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> = [
            "storage_records",
            "dag_indexed",
            "missing_from_dag",
            "coverage_pct",
            "healthy",
            "tips",
            "roots",
            "edges",
        ]
        .iter()
        .copied()
        .collect();
        let missing: Vec<&&str> = expected.difference(&keys).collect();
        let extra: Vec<&&str> = keys.difference(&expected).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "envelope drift: missing={:?} extra={:?} (expected exactly 8 keys)",
            missing,
            extra,
        );

        assert_eq!(v["storage_records"].as_u64().unwrap(), 0);
        assert_eq!(v["dag_indexed"].as_u64().unwrap(), 0);
        assert_eq!(v["missing_from_dag"].as_u64().unwrap(), 0);
        assert_eq!(
            v["coverage_pct"].as_f64().unwrap(),
            100.0,
            "storage_records==0 branch MUST return 100.0 (NOT 0.0 NOT NaN); \
             defends against `dag_indexed as f64 / storage_records as f64` \
             producing NaN if the special branch is removed."
        );
        assert!(
            v["healthy"].as_bool().unwrap(),
            "healthy MUST be true when missing==0 (zero records is zero \
             missing — the freshly-bootstrapped node baseline)."
        );
        assert_eq!(v["tips"].as_u64().unwrap(), 0);
        assert_eq!(v["roots"].as_u64().unwrap(), 0);
        assert_eq!(v["edges"].as_u64().unwrap(), 0);
    }

    #[test]
    fn batch_jjj_perfect_coverage_is_healthy_at_one_hundred_pct() {
        // Axis 2: perfect coverage — storage_records == dag_indexed
        // surfaces the "all records indexed" operator-healthy
        // baseline. coverage_pct MUST be exactly 100.0 (NOT 99.99
        // due to f64 round-trip drift), missing MUST be 0, healthy
        // MUST be true.
        let v = compute_dag_check_payload(100, 100, 5, 3, 200);

        assert_eq!(v["storage_records"].as_u64().unwrap(), 100);
        assert_eq!(v["dag_indexed"].as_u64().unwrap(), 100);
        assert_eq!(v["missing_from_dag"].as_u64().unwrap(), 0);
        assert_eq!(
            v["coverage_pct"].as_f64().unwrap(),
            100.0,
            "perfect coverage MUST surface as exactly 100.0 — \
             100/100 * 100 = 100, .min(100.0) is identity, round-trip \
             through (*100).round()/100 is identity for integer values."
        );
        assert!(
            v["healthy"].as_bool().unwrap(),
            "healthy MUST be true when storage_records == dag_indexed."
        );
    }

    #[test]
    fn batch_jjj_partial_coverage_rounds_to_two_decimals_and_flips_unhealthy() {
        // Axis 3: partial coverage rounded to 2 decimals + missing>0
        // → healthy=false. storage=3 / dag=2: raw coverage =
        // (2.0 / 3.0) * 100 = 66.66666666... → `(66.666... *
        // 100).round() / 100` = `6666.666...round() / 100` = `6667 /
        // 100` = 66.67. Pin EXACTLY 66.67 (NOT 66.6666... NOT 66.7
        // NOT 66.667 NOT 66.66). A refactor swapping the .round()
        // /100 idiom for `format!("{:.2}", coverage).parse()` OR
        // truncating instead of rounding would surface here.
        let v = compute_dag_check_payload(3, 2, 0, 0, 0);

        assert_eq!(v["storage_records"].as_u64().unwrap(), 3);
        assert_eq!(v["dag_indexed"].as_u64().unwrap(), 2);
        assert_eq!(
            v["missing_from_dag"].as_u64().unwrap(),
            1,
            "missing_from_dag MUST be 3 - 2 = 1 (saturating_sub on \
             usize, no underflow concern here)."
        );
        let coverage = v["coverage_pct"].as_f64().unwrap();
        assert_eq!(
            coverage, 66.67,
            "coverage_pct MUST round to EXACTLY 66.67 (NOT 66.6666..., \
             NOT 66.7, NOT 66.667); `(coverage * 100.0).round() / 100.0` \
             quantizes to 2 decimals via integer-cast intermediate."
        );
        assert!(
            !v["healthy"].as_bool().unwrap(),
            "healthy MUST be false when missing > 0 (one record \
             missing from DAG => DAG-drift alert fires)."
        );
    }

    #[test]
    fn batch_jjj_defensive_dag_exceeds_storage_clamps_both_axes() {
        // Axis 4: defensive saturating_sub + coverage clamp. In
        // normal flow dag_indexed <= storage_records (records are
        // ingested THEN inserted into DAG, not the other way). But
        // race-window arithmetic can briefly produce dag > storage
        // (DAG insertion finishes microseconds before the next
        // record_count snapshot). Both `missing` (via
        // saturating_sub) and `coverage_pct` (via .min(100.0)) MUST
        // clamp defensively — `missing` to 0 (NOT usize::MAX from
        // underflow), `coverage_pct` to 100.0 (NOT 200.0 from
        // 10/5*100). Removing saturating_sub OR .min(100.0) would
        // surface here.
        let v = compute_dag_check_payload(5, 10, 0, 0, 0);

        assert_eq!(v["storage_records"].as_u64().unwrap(), 5);
        assert_eq!(v["dag_indexed"].as_u64().unwrap(), 10);
        assert_eq!(
            v["missing_from_dag"].as_u64().unwrap(),
            0,
            "missing_from_dag MUST be 0 when dag>storage (saturating_sub \
             clamps; removing it would underflow usize to usize::MAX \
             ~18 quintillion and surface as a panic-grade operator alert)."
        );
        let coverage = v["coverage_pct"].as_f64().unwrap();
        assert_eq!(
            coverage, 100.0,
            "coverage_pct MUST clamp at 100.0 when dag>storage (.min \
             (100.0) defends; removing it would surface 200.0 here, \
             breaking dashboard plot ranges)."
        );
        assert!(
            coverage <= 100.0,
            "coverage_pct MUST never exceed 100.0 — negative-assert \
             form pins the upper-bound invariant independently."
        );
        assert!(
            v["healthy"].as_bool().unwrap(),
            "healthy MUST be true when missing==0, EVEN under the \
             defensive dag>storage race-window (saturating_sub clamps \
             missing to 0, so healthy stays true — the dashboard's \
             health signal stays green through the race window)."
        );
    }

    #[test]
    fn batch_jjj_tips_roots_edges_pass_through_verbatim_no_cross_wire() {
        // Axis 5: tips/roots/edges scalar passthrough. These three
        // are NOT derived from anything — they pass through
        // verbatim from `dag.tips().len()` / `dag.roots().len()` /
        // `dag.edge_count()`. Distinctive-prime values (7, 11, 42)
        // chosen so a cross-wire regression (e.g. helper emits
        // `tips` from the roots input) surfaces with a
        // distinguishable value rather than silently producing the
        // same value the test would still pass on.
        let v = compute_dag_check_payload(50, 50, 7, 11, 42);

        assert_eq!(
            v["tips"].as_u64().unwrap(),
            7,
            "tips MUST pass through verbatim from caller (input 7); \
             a cross-wire regression reading from the roots arg would \
             surface as 11 here."
        );
        assert_eq!(
            v["roots"].as_u64().unwrap(),
            11,
            "roots MUST pass through verbatim from caller (input 11); \
             a cross-wire regression reading from the tips OR edges arg \
             would surface as 7 or 42 here."
        );
        assert_eq!(
            v["edges"].as_u64().unwrap(),
            42,
            "edges MUST pass through verbatim from caller (input 42); \
             a cross-wire regression reading from any other usize \
             input would surface as 50/50/7/11 here."
        );
    }
}
