//! Ledger route handlers: /balances, /stakes, /ledger/summary, /history,
//! /transactions/recent, /supply, /rpc/*, /bootstrap/*, /vesting/*.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::Json;
use tracing::warn;

use crate::errors::ElaraError;
use crate::accounting::types::{
    creator_identity_hash, extract_ledger_op, BASE_UNITS_PER_BEAT, MAX_SUPPLY,
};
use crate::accounting::validate;

use crate::network::gossip;
use crate::network::state::NodeState;
use crate::network::LockRecover;
use crate::network::RwLockRecover;

use super::super::server::{AppError, format_op, dag_tip_parents, insert_and_push,
    insert_and_push_admin, verify_rpc_auth};

/// Gap 8 — per-record progress between Sealed (~3-5s, 1 anchor sig) and
/// Finalized (~60s, 2/3 stake-weighted attestations). Whitepaper §11.12 promises
/// the two-stage UX; this helper exposes both stages on `/history` and
/// `/transactions/recent` so accounts can render a streaming progress bar
/// without polling `/seal/{id}` for every row.
///
/// Cost: one mutex lock per record on `state.consensus`. Bounded by the
/// caller's `limit` (≤200 for /history, ≤100 for /transactions/recent).
/// Reuses the already-held `finalized` read guard for the pruned-after-finality
/// fast path so no second `state.finalized` lock is taken.
///
/// Adds: `seal_state` (string), `attestation_count`, `stake_pct`,
/// `stake_threshold`, `effective_stake`, optional `sealed_at`, `finalized_at`.
/// Keeps `finalized: bool` unchanged (true iff seal_state >= "finalized") for
/// backwards compatibility with accounts that read the old field.
pub(crate) fn enrich_with_seal_state(
    tx: &mut serde_json::Value,
    state: &NodeState,
    record_id: &str,
    finalized: &crate::network::finalized::FinalizedIndex,
) {
    let progress = state.seal_progress(record_id);
    let in_finalized_set = finalized.contains(record_id);
    let (label, count, pct, threshold, effective, sealed_at, finalized_at) = match progress {
        Some(p) => {
            let pct = if p.stake_threshold > 0.0 {
                (p.effective_stake / p.stake_threshold).min(1.0)
            } else { 0.0 };
            let label = if p.settled || in_finalized_set { "finalized" } else { "sealed" };
            (label, p.attestation_count, pct, p.stake_threshold, p.effective_stake, p.registered_at, p.finalized_at)
        }
        None if in_finalized_set => ("finalized", 0usize, 1.0, 0.0, 0.0, None, None),
        None => ("pending", 0usize, 0.0, 0.0, 0.0, None, None),
    };
    tx["finalized"] = serde_json::json!(label == "finalized");
    tx["seal_state"] = serde_json::json!(label);
    tx["attestation_count"] = serde_json::json!(count);
    tx["stake_pct"] = serde_json::json!(pct);
    tx["stake_threshold"] = serde_json::json!(threshold);
    tx["effective_stake"] = serde_json::json!(effective);
    if let Some(t) = sealed_at { tx["sealed_at"] = serde_json::json!(t); }
    if let Some(t) = finalized_at { tx["finalized_at"] = serde_json::json!(t); }
}

// ─── /balances ───────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct BalanceQuery {
    identity: Option<String>,
    /// Gap 8 last-mile: include the last `with_recent` ledger records
    /// involving the queried identity, each enriched with seal_state.
    /// Ignored when `identity` is absent (would require a fleet-wide
    /// scan). Capped at `MAX_BALANCES_RECENT_RECORDS` (50). Defaults to None
    /// (off) so legacy account polls keep their O(1) ledger-read latency.
    with_recent: Option<usize>,
}

/// Cap on `with_recent` opt-in records-per-balance lookup. The
/// lookup is bounded by a `recent_record_ids` scan of `(N * 50).min(5000)`
/// timestamp-indexed entries plus N consensus mutex acquisitions. At N=50
/// that's ≤2500 record reads + 50 lock takes — well below `/history`'s
/// already-allowed limit of 200 — but kept lower because `/balances` is
/// polled at higher frequency than `/history` and shouldn't approach
/// /history latency just because the opt-in flag was set unbounded-high.
pub(crate) const MAX_BALANCES_RECENT_RECORDS: usize = 50;

/// Cap the unconditional `/balances` response. At 1M accounts the
/// pre-cap path was a 200 MB JSON body served on every account refresh. The
/// cap is large enough to cover testnet (≤100 accounts) and any realistic
/// near-term scale, while bounding the worst case at ~200 KB.
pub(crate) const MAX_BALANCES_RESPONSE: usize = 1000;

/// Minimum length for an identity prefix that is allowed to fall
/// through to the `accounts.iter().find(prefix-match)` slow path. Below this
/// the call is rejected — short prefixes that miss the exact-match probe
/// would otherwise scan every account on every request.
///
/// Identity hashes are SHA3-256 hex (64 chars). 8 hex chars = 32 bits of
/// entropy, enough that a real account that has truncated its own hash to 8+
/// chars can still find itself but an attacker cannot pick a guaranteed-miss
/// prefix that scans the whole map.
pub(crate) const MIN_BALANCES_PREFIX_LEN: usize = 8;

/// Compute `/balances` payload. Shared between the axum handler and the
/// PQ-transport router. `identity_filter = Some(id)`
/// mirrors `?identity=...`; `None` returns up to `MAX_BALANCES_RESPONSE`
/// accounts (with `truncated`/`total_count` flags set so callers can detect
/// the cap and switch to identity-filter or paginated reads).
pub(crate) async fn compute_balances(
    state: Arc<NodeState>,
    identity_filter: Option<String>,
    with_recent: Option<usize>,
) -> serde_json::Value {
    let ledger = state.ledger.read().await;
    if let Some(id) = identity_filter {
        // Try exact match first, then prefix match (mobile sends full hash,
        // ledger may store truncated).
        if ledger.accounts.contains_key(id.as_str()) {
            let acct = ledger.account(&id);
            drop(ledger);
            let mut body = serde_json::json!({
                "identity": id,
                "available": acct.available,
                "staked": acct.staked,
                "total": acct.total(),
                "tx_count": acct.tx_count,
                "last_active": acct.last_active,
            });
            attach_recent_records(&mut body, &state, &id, with_recent).await;
            return body;
        }
        // Short prefix below MIN_BALANCES_PREFIX_LEN does NOT trigger
        // the O(accounts) scan-fallback. Contract "always queryable, never 404"
        // is preserved by echoing the supplied id with zero balances — same
        // shape the unwrap_or_else default produced before. Only the worst-
        // case-O(N) scan branch is suppressed; a counter records the skip so
        // operators can tell the before/after traffic patterns apart.
        if id.len() < MIN_BALANCES_PREFIX_LEN {
            state
                .balances_short_prefix_rejected_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let acct = crate::accounting::ledger::AccountState::default();
            // Short-prefix rejection skips both ledger scan AND the
            // recent-records lookup. The supplied id is too short to identify
            // any single account, so a records lookup against it would either
            // (a) match too many records via `creator_identity_hash() == id`
            // string compare (always false for valid 64-char hashes vs the
            // short prefix) or (b) match zero. Cheaper to skip entirely and
            // preserve the existing "echo id with zero balances" contract.
            return serde_json::json!({
                "identity": id,
                "available": acct.available,
                "staked": acct.staked,
                "total": acct.total(),
                "tx_count": acct.tx_count,
                "last_active": acct.last_active,
            });
        }
        let (found_id, acct) = ledger.accounts.iter()
            .find(|(k, _)| k.starts_with(id.as_str()) || id.starts_with(k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .unwrap_or_else(|| (id.clone(), Default::default()));
        drop(ledger);
        let mut body = serde_json::json!({
            "identity": found_id.clone(),
            "available": acct.available,
            "staked": acct.staked,
            "total": acct.total(),
            "tx_count": acct.tx_count,
            "last_active": acct.last_active,
        });
        // Scan against the resolved (potentially-truncated) id, not
        // the user-supplied prefix — record creator/recipient hashes are
        // stored full-length and comparing against the prefix would never
        // match. `found_id` mirrors `acct` so the recent-records list is
        // attached to the same account whose balance we returned.
        attach_recent_records(&mut body, &state, &found_id, with_recent).await;
        body
    } else {
        let total_count = ledger.accounts.len();
        let truncated = total_count > MAX_BALANCES_RESPONSE;
        if truncated {
            state
                .balances_response_truncated_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let accounts: Vec<serde_json::Value> = ledger.accounts.iter()
            .take(MAX_BALANCES_RESPONSE)
            .map(|(id, acct)| {
                serde_json::json!({
                    "identity": id,
                    "available": acct.available,
                    "staked": acct.staked,
                    "total": acct.total(),
                    "tx_count": acct.tx_count,
                    "last_active": acct.last_active,
                })
            }).collect();
        serde_json::json!({
            "accounts": accounts,
            "returned_count": accounts.len(),
            "total_count": total_count,
            "truncated": truncated,
            "max_response": MAX_BALANCES_RESPONSE,
        })
    }
}

/// Gap 8 last-mile helper: scan the timestamp index for the last
/// `limit` ledger records that involve `identity`, enrich each with the
/// `seal_state` triple (Pending / Sealed / Finalized), and return
/// them newest-first. Bounded scan — `(limit * 50).min(5000)` index reads
/// is the worst case. Identity filter logic mirrors `tx_history` so accounts
/// see the same record set on `/balances?identity=X&with_recent=N` as on
/// `/history?identity=X&limit=N`.
///
/// Errors are non-fatal at the caller — `attach_recent_records` swallows
/// them rather than failing the whole `/balances` response. The `/balances`
/// endpoint must remain infallible (legacy account contract: never 404), so
/// a transient rocks scan failure becomes "no recent records surfaced this
/// poll" rather than a top-level error.
pub(crate) async fn fetch_recent_records_for_identity(
    state: &Arc<NodeState>,
    identity: &str,
    limit: usize,
) -> crate::errors::Result<Vec<serde_json::Value>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let state_clone = state.clone();
    let identity_clone = identity.to_string();
    let raw = tokio::task::spawn_blocking(move || -> crate::errors::Result<Vec<(crate::record::ValidationRecord, crate::accounting::types::ParsedLedgerOp)>> {
        let rocks = state_clone.rocks.as_ref();
        // Mirror tx_history: scan up to 50× limit recent ids, capped at 5000.
        // Most records are witness_rewards involving the genesis authority,
        // so identity-match rate is sparse — over-scan to find enough.
        // saturating_mul: defense-in-depth. The sole caller clamps to 50, but
        // this is pub(crate) and a future caller passing an uncapped limit would
        // panic on `limit * 50` under overflow-checks=true. min(5000) caps after.
        let scan_limit = limit.saturating_mul(50).min(5000);
        let recent_ids = rocks.recent_record_ids(0.0, scan_limit)?;
        // Same defense-in-depth on the capacity hint as scan_limit above: an
        // uncapped `limit` from a future pub(crate) caller would panic in
        // Vec::with_capacity (capacity-overflow) BEFORE the loop's
        // `results.len() >= limit` break ever bounds it. Cap to the same 5000.
        let mut results = Vec::with_capacity(limit.min(5000));
        for rid in &recent_ids {
            if let Ok(Some(record)) = rocks.get_record(rid) {
                if let Ok(Some(op)) = extract_ledger_op(&record) {
                    let creator = creator_identity_hash(&record);
                    let involved = creator == identity_clone || match &op {
                        crate::accounting::types::ParsedLedgerOp::Mint { to, .. }
                        | crate::accounting::types::ParsedLedgerOp::Transfer { to, .. } => to == &identity_clone,
                        crate::accounting::types::ParsedLedgerOp::WitnessReward { from, to, .. } => from == &identity_clone || to == &identity_clone,
                        crate::accounting::types::ParsedLedgerOp::Slash { offender, challenger, jury, .. } => {
                            offender == &identity_clone || challenger == &identity_clone || jury.iter().any(|j| j == &identity_clone)
                        }
                        crate::accounting::types::ParsedLedgerOp::DormancyReclaim { dormant_identity, .. } => dormant_identity == &identity_clone,
                        crate::accounting::types::ParsedLedgerOp::IdleDecay { batch } => {
                            batch.debits.iter().any(|(id, _)| id == &identity_clone)
                                || batch.staker_credits.iter().any(|(id, _)| id == &identity_clone)
                        }
                        crate::accounting::types::ParsedLedgerOp::XZoneTimeoutRefund { batch }
                        | crate::accounting::types::ParsedLedgerOp::XZoneStaleReap { batch } => {
                            batch.refunds.iter().any(|(_t, sender, _a)| sender == &identity_clone)
                        }
                        _ => false,
                    };
                    if involved {
                        results.push((record, op));
                        if results.len() >= limit { break; }
                    }
                }
            }
        }
        Ok(results)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    let finalized = state.finalized.read().await;
    Ok(raw.into_iter().map(|(record, op)| {
        let mut tx = format_op(&op);
        tx["record_id"] = serde_json::json!(record.id);
        tx["timestamp"] = serde_json::json!(record.timestamp);
        tx["from"] = serde_json::json!(creator_identity_hash(&record));
        enrich_with_seal_state(&mut tx, state, &record.id, &finalized);
        tx
    }).collect())
}

/// In-place attach of `recent_records` array to a balance JSON body
/// when the caller opted in via `?with_recent=N`. Caps at
/// `MAX_BALANCES_RECENT_RECORDS` (50). Silently skips on lookup failure to
/// preserve the existing infallible `/balances` contract.
async fn attach_recent_records(
    body: &mut serde_json::Value,
    state: &Arc<NodeState>,
    identity: &str,
    with_recent: Option<usize>,
) {
    let Some(n) = with_recent else { return };
    if n == 0 { return; }
    let limit = n.min(MAX_BALANCES_RECENT_RECORDS);
    match fetch_recent_records_for_identity(state, identity, limit).await {
        Ok(records) => {
            if let Some(obj) = body.as_object_mut() {
                obj.insert("recent_records".into(), serde_json::Value::Array(records));
            }
        }
        Err(e) => {
            tracing::warn!(
                "OPS-177 attach_recent_records: lookup failed for identity={}, skipping: {}",
                identity, e
            );
        }
    }
}

/// Axum adapter — thin wrapper around [`compute_balances`].
pub async fn query_balances(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<BalanceQuery>,
) -> Json<serde_json::Value> {
    Json(compute_balances(state, params.identity, params.with_recent).await)
}

// ─── /stakes ─────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct StakeQuery {
    identity: Option<String>,
    limit: Option<usize>,
}

/// Compute `/stakes` payload. Shared between the axum handler and the
/// PQ-transport router. `identity_filter = Some(id)`
/// returns active+inactive stakes for that staker; `None` returns every
/// active stake fleet-wide (matches axum behavior byte-for-byte).
/// Default / hard cap on the number of stakes the fleet-wide (`identity=None`)
/// `/stakes` response returns. `total` reports the TRUE active-stake count;
/// only the returned `stakes` array is bounded. The no-filter branch is a
/// fleet-wide enumeration reachable over the PQ `stakes` verb by any handshaked
/// peer, so a single call must not dump every active stake — SCALE RULE:
/// bounded, always. Truncation is detectable as `stakes.len() < total`. The
/// per-identity branch stays unbounded: one identity's stakes are naturally
/// capped by the ARCH-1 per-identity limits. Mirrors the `/epochs` bound.
const STAKES_DEFAULT_LIMIT: usize = 1000;
const STAKES_MAX_LIMIT: usize = 10_000;

pub(crate) async fn compute_stakes(
    state: Arc<NodeState>,
    identity_filter: Option<String>,
    limit: Option<usize>,
) -> serde_json::Value {
    let ledger = state.ledger.read().await;
    if let Some(id) = identity_filter {
        let stakes: Vec<serde_json::Value> = ledger.stakes_for(&id).iter().map(|s| {
            serde_json::json!({
                "record_id": s.record_id,
                "amount": s.amount,
                "purpose": s.purpose,
                "timestamp": s.timestamp,
                "active": s.active,
            })
        }).collect();
        serde_json::json!({"identity": id, "stakes": stakes})
    } else {
        let limit = limit.unwrap_or(STAKES_DEFAULT_LIMIT).min(STAKES_MAX_LIMIT);
        let mut stakes: Vec<serde_json::Value> = ledger.stakes.values().filter(|s| s.active).map(|s| {
            serde_json::json!({
                "record_id": s.record_id,
                "staker": s.staker,
                "amount": s.amount,
                "purpose": s.purpose,
                "timestamp": s.timestamp,
                "active": s.active,
            })
        }).collect();
        // Deterministic order so the bounded page is a stable lowest-record-id-
        // first slice across calls, not an arbitrary HashMap-iteration sample.
        stakes.sort_by(|a, b| {
            a.get("record_id").and_then(|v| v.as_str())
                .cmp(&b.get("record_id").and_then(|v| v.as_str()))
        });
        // True total captured BEFORE the page bound so `total` stays honest.
        let total = stakes.len();
        stakes.truncate(limit);
        serde_json::json!({"stakes": stakes, "total": total})
    }
}

pub async fn query_stakes(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<StakeQuery>,
) -> Json<serde_json::Value> {
    Json(compute_stakes(state, params.identity, params.limit).await)
}

// ─── /ledger/summary ─────────────────────────────────────────────────────────

pub async fn compute_ledger_summary(state: &Arc<NodeState>) -> serde_json::Value {
    let ledger = state.ledger.read().await;
    let summary = validate::summarize(&ledger);
    let mut json = serde_json::to_value(&summary).unwrap_or_default();
    if let Some(obj) = json.as_object_mut() {
        obj.insert("total_supply_beat_precise".into(), validate::format_beat_precise(summary.total_supply_micros).into());
        obj.insert("circulating_beat_precise".into(), validate::format_beat_precise(summary.circulating_micros).into());
        obj.insert("conservation_pool_beat_precise".into(), validate::format_beat_precise(summary.conservation_pool_micros).into());
        obj.insert("total_staked_beat_precise".into(), validate::format_beat_precise(summary.total_staked_micros).into());
    }
    json
}

pub async fn ledger_summary(
    State(state): State<Arc<NodeState>>,
) -> Json<serde_json::Value> {
    Json(compute_ledger_summary(&state).await)
}

// ─── /token/enforcement ──────────────────────────────────────────────────────

/// Compute `/token/enforcement` payload. Shared between the axum handler and
/// the PQ-transport router. Returns circuit-breaker,
/// velocity, acquisition, vesting, trust, and governance summary.
pub(crate) async fn compute_token_enforcement(state: Arc<NodeState>) -> serde_json::Value {
    // Acquire ledger and trust in separate scopes to avoid holding
    // ledger.read() across trust.read().await — blocks ledger.write() on 1-core nodes.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let (cb_level, cb_since, cb_vol24h, cb_vel_mult,
         vel_tracked, acq_tracked, acq_active, circulating,
         vest_active, vest_total, gov_proposals, gov_active, gov_passed,
         gov_rejected, gov_expired, gov_executed, gov_cancelled, gov_vetoed,
         gov_delegations) = {
        let ledger = state.ledger.read().await;
        let circ = ledger.total_supply.saturating_sub(ledger.total_staked);
        let (ga, gp, gr, ge, gx, gc, gv) = ledger.governance.proposal_counts();
        (
            ledger.circuit_breaker.level.as_str().to_string(),
            ledger.circuit_breaker.level_since,
            ledger.circuit_breaker.volume_in_window(now),
            ledger.circuit_breaker.velocity_multiplier(),
            ledger.velocity.tracked_identities(),
            ledger.acquisition.tracked_identities(),
            circ >= crate::accounting::acquisition::ACQUISITION_LIMIT_ACTIVATION,
            circ,
            ledger.vesting.active_vestings(),
            ledger.vesting.total_entries(),
            ledger.governance.proposals.len(),
            ga, gp, gr, ge, gx, gc, gv,
            ledger.governance.active_delegations_count as usize,
        )
    };
    let trust_tracked = {
        let trust = state.trust.read().await;
        trust.tracked_identities()
    };

    // Monetary velocity: fraction of circulating supply that turned over in the
    // last 24 h. Dimensionless ratio; 0.1 = 10% of supply transferred per day.
    let cb_vel24h = cb_vol24h as f64 / circulating.max(1) as f64;

    serde_json::json!({
        "circuit_breaker": {
            "level": cb_level,
            "level_since": cb_since,
            "volume_24h": cb_vol24h,
            "velocity_24h": cb_vel24h,
            "velocity_multiplier": cb_vel_mult,
        },
        "velocity": {
            "tracked_identities": vel_tracked,
            "window_seconds": crate::accounting::velocity::VELOCITY_WINDOW_SECS,
        },
        "acquisition": {
            "tracked_identities": acq_tracked,
            "max_rate": crate::accounting::acquisition::MAX_ACQUISITION_RATE,
            "window_seconds": crate::accounting::acquisition::ACQUISITION_WINDOW_SECS,
            "activation_threshold": crate::accounting::acquisition::ACQUISITION_LIMIT_ACTIVATION,
            "limits_active": acq_active,
        },
        "vesting": {
            "active_vestings": vest_active,
            "total_entries": vest_total,
            "duration_seconds": crate::accounting::acquisition::VESTING_DURATION_SECS,
            "threshold": crate::accounting::acquisition::LARGE_MINT_THRESHOLD,
        },
        "trust": {
            "tracked_identities": trust_tracked,
        },
        "governance": {
            "total_proposals": gov_proposals,
            "active": gov_active,
            "passed": gov_passed,
            "rejected": gov_rejected,
            "expired": gov_expired,
            "executed": gov_executed,
            "cancelled": gov_cancelled,
            "vetoed": gov_vetoed,
            "active_delegations": gov_delegations,
        },
        "circulating_supply": circulating,
    })
}

pub async fn token_enforcement(
    State(state): State<Arc<NodeState>>,
) -> Json<serde_json::Value> {
    Json(compute_token_enforcement(state).await)
}

// ─── /history ────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct HistoryQuery {
    identity: String,
    limit: Option<usize>,
    offset: Option<usize>,
}

/// Compute `/history` payload. Shared between the axum handler and the
/// PQ-transport router (account read-side migration
/// prereq). The `identity` arg is required; `limit` is clamped to 200
/// (matches axum) and defaults to 50; `offset` defaults to 0. Returns
/// the same `{identity, transactions, total, limit, offset}` envelope
/// byte-for-byte across both transports — used by `node.query_history`
/// migration in web/app.js Slice 2.
pub(crate) async fn compute_tx_history(
    state: Arc<NodeState>,
    identity: String,
    limit: usize,
    offset: usize,
) -> crate::errors::Result<serde_json::Value> {
    let limit = limit.min(200);

    // Scan recent records via timestamp index instead of full table scan.
    // Previous impl scanned ALL records (100K+, 10GB+ SST) — always timed out.
    let state2 = state.clone();
    let identity2 = identity.clone();
    let history = tokio::task::spawn_blocking(move || -> crate::errors::Result<Vec<(crate::record::ValidationRecord, crate::accounting::types::ParsedLedgerOp)>> {
        let rocks = state2.rocks.as_ref();
        // Scan up to 5000 recent records to find matches for this identity.
        // Most records are witness_rewards from genesis, so we need a wide scan.
        // offset is peer-supplied and uncapped; saturating ops avoid an
        // overflow panic (release sets overflow-checks=true) — a large offset
        // saturates to the 5000 scan cap, yielding an empty page as intended.
        let scan_limit = limit.saturating_add(offset).saturating_mul(50);
        let scan_limit = scan_limit.min(5000);
        let recent_ids = rocks.recent_record_ids(0.0, scan_limit)?;

        let mut results = Vec::new();
        for rid in &recent_ids {
            if let Ok(Some(record)) = rocks.get_record(rid) {
                if let Ok(Some(op)) = extract_ledger_op(&record) {
                    let creator = creator_identity_hash(&record);
                    let involved = creator == identity2 || match &op {
                        crate::accounting::types::ParsedLedgerOp::Mint { to, .. }
                        | crate::accounting::types::ParsedLedgerOp::Transfer { to, .. } => to == &identity2,
                        crate::accounting::types::ParsedLedgerOp::WitnessReward { from, to, .. } => from == &identity2 || to == &identity2,
                        crate::accounting::types::ParsedLedgerOp::Slash { offender, challenger, jury, .. } => {
                            offender == &identity2 || challenger == &identity2 || jury.iter().any(|j| j == &identity2)
                        }
                        crate::accounting::types::ParsedLedgerOp::DormancyReclaim { dormant_identity, .. } => dormant_identity == &identity2,
                        crate::accounting::types::ParsedLedgerOp::IdleDecay { batch } => {
                            batch.debits.iter().any(|(id, _)| id == &identity2)
                                || batch.staker_credits.iter().any(|(id, _)| id == &identity2)
                        }
                        crate::accounting::types::ParsedLedgerOp::XZoneTimeoutRefund { batch }
                        | crate::accounting::types::ParsedLedgerOp::XZoneStaleReap { batch } => {
                            batch.refunds.iter().any(|(_t, sender, _a)| sender == &identity2)
                        }
                        _ => false,
                    };
                    if involved {
                        results.push((record, op));
                        // offset is peer-supplied and uncapped (echoed verbatim,
                        // clamped nowhere); `limit + offset` panics under release
                        // overflow-checks=true once a match is pushed on a
                        // non-empty node. saturating_add: a huge offset pins the
                        // target at usize::MAX (break never fires), the loop runs
                        // to the scan cap, and `.skip(offset)` below yields the
                        // empty "past-the-end" page — same intent, no panic.
                        if results.len() >= limit.saturating_add(offset) { break; }
                    }
                }
            }
        }
        Ok(results)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    let finalized = state.finalized.read().await;
    let total = history.len();
    let page: Vec<serde_json::Value> = history
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|(record, op)| {
            let mut tx = format_op(&op);
            tx["record_id"] = serde_json::json!(record.id);
            tx["timestamp"] = serde_json::json!(record.timestamp);
            tx["from"] = serde_json::json!(creator_identity_hash(&record));
            enrich_with_seal_state(&mut tx, &state, &record.id, &finalized);
            tx
        })
        .collect();

    Ok(serde_json::json!({
        "identity": identity,
        "transactions": page,
        "total": total,
        "limit": limit,
        "offset": offset,
    }))
}

pub async fn tx_history(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HistoryQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = params.limit.unwrap_or(50);
    let offset = params.offset.unwrap_or(0);
    let body = compute_tx_history(state, params.identity, limit, offset).await?;
    Ok(Json(body))
}

// ─── /transactions/recent ────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct RecentQuery {
    limit: Option<usize>,
}

/// Compute `/transactions/recent` payload. Shared between axum and the
/// PQ verb `recent_transactions` (added alongside `tx_history` to fix
/// the `/transactions/recent → activity` shim misroute). Limit clamps
/// to 100, defaults to 20.
pub(crate) async fn compute_recent_transactions(
    state: Arc<NodeState>,
    limit: usize,
) -> crate::errors::Result<serde_json::Value> {
    let limit = limit.min(100);

    // Use the timestamp index to scan newest-first instead of loading ALL records.
    // Previous impl did extract_ledger_records() which scanned every record in RocksDB
    // (100K+ records, 10GB+ SST) — caused consistent timeouts on all nodes.
    let state2 = state.clone();
    let txs_raw = tokio::task::spawn_blocking(move || -> crate::errors::Result<Vec<(crate::record::ValidationRecord, crate::accounting::types::ParsedLedgerOp)>> {
        let rocks = state2.rocks.as_ref();
        // Scan up to 10x limit of recent record IDs to find enough ledger ops
        // (most records are witness_rewards, so we need to over-scan).
        let scan_limit = limit * 10;
        let recent_ids = rocks.recent_record_ids(0.0, scan_limit)?;

        let mut results = Vec::with_capacity(limit);
        for rid in &recent_ids {
            if let Ok(Some(record)) = rocks.get_record(rid) {
                if let Ok(Some(op)) = extract_ledger_op(&record) {
                    results.push((record, op));
                    if results.len() >= limit { break; }
                }
            }
        }
        Ok(results)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    let finalized = state.finalized.read().await;
    let txs: Vec<serde_json::Value> = txs_raw
        .into_iter()
        .map(|(record, op)| {
            let mut tx = format_op(&op);
            tx["record_id"] = serde_json::json!(record.id);
            tx["timestamp"] = serde_json::json!(record.timestamp);
            tx["from"] = serde_json::json!(creator_identity_hash(&record));
            enrich_with_seal_state(&mut tx, &state, &record.id, &finalized);
            tx
        })
        .collect();

    Ok(serde_json::json!({
        "transactions": txs,
        "count": txs.len(),
    }))
}

pub async fn recent_transactions(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<RecentQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = params.limit.unwrap_or(20);
    let body = compute_recent_transactions(state, limit).await?;
    Ok(Json(body))
}

// ─── /supply ─────────────────────────────────────────────────────────────────
//
// Extracted compute_* helpers shared between the axum text/plain
// surface (legacy account/CLI clients) and the PQ-native verbs
// supply_circulating / supply_total / supply_max. Returning (micros, beat)
// keeps both surfaces honest: PQ exposes both shapes as JSON and axum keeps
// the historical decimal-beat plain-text body.

pub async fn compute_supply_circulating(state: Arc<NodeState>) -> (u64, f64) {
    let ledger = state.ledger.read().await;
    let micros = ledger
        .total_supply
        .saturating_sub(ledger.total_staked)
        .saturating_sub(ledger.conservation_pool);
    (micros, micros as f64 / BASE_UNITS_PER_BEAT as f64)
}

pub async fn compute_supply_total(state: Arc<NodeState>) -> (u64, f64) {
    let ledger = state.ledger.read().await;
    let micros = ledger.total_supply;
    (micros, micros as f64 / BASE_UNITS_PER_BEAT as f64)
}

pub fn compute_supply_max() -> (u64, f64) {
    (MAX_SUPPLY, MAX_SUPPLY as f64 / BASE_UNITS_PER_BEAT as f64)
}

pub async fn supply_circulating(State(state): State<Arc<NodeState>>) -> impl IntoResponse {
    let (_, beat) = compute_supply_circulating(state).await;
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain")],
        format!("{beat}"),
    )
}

pub async fn supply_total(State(state): State<Arc<NodeState>>) -> impl IntoResponse {
    let (_, beat) = compute_supply_total(state).await;
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain")],
        format!("{beat}"),
    )
}

pub async fn supply_max() -> impl IntoResponse {
    let (_, max_beat) = compute_supply_max();
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain")],
        format!("{max_beat}"),
    )
}

// ─── /genesis/allocation ─────────────────────────────────────────────────────

pub async fn genesis_allocation(
    State(state): State<Arc<NodeState>>,
) -> Json<serde_json::Value> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    let gs = state.genesis_state.read_recover();
    Json(gs.summary(now))
}

// ─── /bootstrap/status ───────────────────────────────────────────────────────

pub async fn bootstrap_status(
    State(state): State<Arc<NodeState>>,
) -> Json<serde_json::Value> {
    let bs = state.bootstrap_state.read_recover();
    Json(bs.summary())
}

// ─── /rpc/transfer ───────────────────────────────────────────────────────────

pub async fn rpc_transfer(
    State(state): State<Arc<NodeState>>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_rpc_auth(&state, connect_info.0.ip(), &headers)?;

    // Use lock-free snapshot for pool check — avoids blocking on ledger write lock
    // held by gossip rebuild_ledger or epoch prediction evaluation.
    // Before this fix, RPC handlers took ledger.read().await BEFORE routing through
    // the priority channel, so the priority channel never helped when writes were held.
    let pool = if let Some(core) = state.state_core.get() {
        core.read_snapshot().conservation_pool
    } else {
        state.ledger.read().await.conservation_pool
    };
    if pool == 0 {
        return Err(ElaraError::Ledger(
            "node still bootstrapping — genesis mint not received yet. Try again in 30 seconds.".into()
        ).into());
    }

    let to = body["to"].as_str().ok_or(ElaraError::Wire("missing 'to'".into()))?;
    let amount = body["amount"].as_u64().ok_or(ElaraError::Wire("missing 'amount' (must be positive integer)".into()))?;
    let memo = body["memo"].as_str();

    // ── Input validation ──────────────────────────────────────────────
    // Identity hash must be exactly 64 hex characters (SHA3-256 output)
    if to.is_empty() {
        return Err(ElaraError::Wire("'to' cannot be empty".into()).into());
    }
    if to.len() != 64 {
        return Err(ElaraError::Wire(format!(
            "'to' must be 64-char hex identity hash, got {} chars", to.len()
        )).into());
    }
    if !to.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ElaraError::Wire("'to' must be valid hex (0-9, a-f)".into()).into());
    }
    if amount == 0 {
        return Err(ElaraError::Wire("'amount' must be greater than zero".into()).into());
    }
    // Cap memo at 1KB to prevent oversized records
    if let Some(m) = memo {
        if m.len() > 1024 {
            return Err(ElaraError::Wire(format!(
                "memo too large: {} bytes (max 1024)", m.len()
            )).into());
        }
    }

    tracing::info!("rpc_transfer: pool check passed ({}), acquiring rpc_lock...", pool);
    let _guard = state.rpc_lock.lock().await;
    tracing::info!("rpc_transfer: rpc_lock acquired, building record...");

    let meta = crate::accounting::types::transfer_metadata(amount, to, memo);
    let parents = dag_tip_parents(&state, 3).await;
    tracing::info!("rpc_transfer: record built with {} parents, inserting...", parents.len());
    let record = state.create_self_ledger_record(parents, meta)?;
    let record_id = record.id.clone();

    tracing::info!("rpc_transfer: calling insert_and_push for {}...", &record_id[..16]);
    insert_and_push(&state, record).await?;
    tracing::info!("rpc_transfer: SUCCESS — record {} inserted", &record_id[..16]);

    Ok(Json(serde_json::json!({
        "ok": true,
        "record_id": record_id,
        "op": "transfer",
        "amount": amount,
        "to": to,
    })))
}

// ─── /slot/next_nonce ────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct NextNonceQuery {
    pub account: String,
}

/// Return the next unused slot nonce for `account`.
///
/// External clients (CLI, mobile app) that build and sign records off-node
/// need a monotonic nonce so their `slot_key = <account>:<nonce>` doesn't
/// collide with a prior record and trip the SLOT EQUIVOCATION gate at ingest.
///
/// Semantics:
///   - Scans `CF_SLOT_INDEX` under prefix `<account>:` for the max nonce
///     already recorded on this node, returns `max + 1` (or `1` if the
///     account has no prior slots).
///   - Scale: O(self_records) prefix scan per call — bounded by the
///     requesting account's own history, never the fleet total.
///   - No auth: same posture as `/balances` — returns public chain state.
///   - Not a reservation: two concurrent callers for the same account can
///     both get the same value and race at ingest. Clients MUST retry on
///     SLOT EQUIVOCATION by re-querying `/slot/next_nonce`. (Reservation
///     would require stateful per-account counters, which is overkill for
///     a handful of CLI/mobile sessions per account.)
///   - Self-account caveat: if `account == node_identity_hash`, the on-disk
///     max can lag the in-memory `slot_nonce_self` atomic by up to N writes
///     in flight. External callers can't sign with the node's key anyway,
///     so this edge case is informational — we expose the higher of the two
///     to make the response sensible if the node's own tooling calls it.
pub async fn slot_next_nonce(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<NextNonceQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let account = params.account.trim();

    if account.len() != 64 {
        return Err(ElaraError::Wire(format!(
            "'account' must be 64-char hex identity hash, got {} chars",
            account.len()
        )).into());
    }
    if !account.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ElaraError::Wire("'account' must be valid hex (0-9, a-f)".into()).into());
    }
    let account_lc = account.to_ascii_lowercase();

    let storage_next = state.rocks.max_slot_nonce_for_account(&account_lc)
        .map_err(|e| AppError(ElaraError::Storage(format!("max_slot_nonce_for_account: {e}"))))?
        .map(|n| n.saturating_add(1))
        .unwrap_or(1);

    // For the node's own identity, the in-memory atomic may be ahead of
    // what's been flushed to CF_SLOT_INDEX (record is created with a nonce
    // before storage writes land). Take the max so we never hand out a
    // stale nonce if node-internal tooling ever hits this path.
    let self_hash = crate::crypto::hash::sha3_256_hex(&state.identity.public_key);
    let next = if account_lc == self_hash {
        let atomic_next = state
            .slot_nonce_self
            .load(std::sync::atomic::Ordering::Acquire);
        storage_next.max(atomic_next)
    } else {
        storage_next
    };

    Ok(Json(serde_json::json!({
        "account": account_lc,
        "next_nonce": next,
    })))
}

// ─── /rpc/xzone_lock ─────────────────────────────────────────────────────────

pub async fn rpc_xzone_lock(
    State(state): State<Arc<NodeState>>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_rpc_auth(&state, connect_info.0.ip(), &headers)?;

    let to = body["to"].as_str().ok_or(ElaraError::Wire("missing 'to'".into()))?;
    let amount = body["amount"].as_u64().ok_or(ElaraError::Wire("missing 'amount'".into()))?;
    let dest_zone = body["dest_zone"].as_str().ok_or(ElaraError::Wire("missing 'dest_zone'".into()))?;

    // Validate inputs
    if to.len() != 64 || !to.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ElaraError::Wire("'to' must be 64-char hex identity hash".into()).into());
    }
    if amount == 0 {
        return Err(ElaraError::Wire("'amount' must be > 0".into()).into());
    }

    // Determine source zone from the record ID (will be computed after record creation)
    // For now, compute which zone the sender's identity hashes to
    let source_zone = {
        let zc = crate::network::consensus::get_zone_count();
        crate::ZoneId::for_record_dynamic(&state.identity.identity_hash, zc).path().to_string()
    };

    if source_zone == dest_zone {
        return Err(ElaraError::Wire("source and dest zones must differ".into()).into());
    }

    let _guard = state.rpc_lock.lock().await;

    let meta = crate::accounting::types::xzone_lock_metadata(amount, to, &source_zone, dest_zone);
    let parents = dag_tip_parents(&state, 3).await;
    let record = state.create_self_ledger_record(parents, meta)?;
    let record_id = record.id.clone();

    insert_and_push(&state, record).await?;

    tracing::info!("rpc_xzone_lock: {} → zone {} (transfer_id={})", &to[..16], dest_zone, &record_id[..16]);

    Ok(Json(serde_json::json!({
        "ok": true,
        "record_id": record_id,
        "op": "xzone_lock",
        "transfer_id": record_id,
        "amount": amount,
        "to": to,
        "source_zone": source_zone,
        "dest_zone": dest_zone,
    })))
}

// ─── /rpc/xzone_claim ────────────────────────────────────────────────────────

pub async fn rpc_xzone_claim(
    State(state): State<Arc<NodeState>>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_rpc_auth(&state, connect_info.0.ip(), &headers)?;

    let transfer_id = body["transfer_id"].as_str().ok_or(ElaraError::Wire("missing 'transfer_id'".into()))?;
    let amount = body["amount"].as_u64().ok_or(ElaraError::Wire("missing 'amount'".into()))?;
    let to = body["to"].as_str().ok_or(ElaraError::Wire("missing 'to' (recipient)".into()))?;

    if to.len() != 64 || !to.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ElaraError::Wire("'to' must be 64-char hex identity hash".into()).into());
    }
    if amount == 0 {
        return Err(ElaraError::Wire("'amount' must be > 0".into()).into());
    }

    let _guard = state.rpc_lock.lock().await;

    let meta = crate::accounting::types::xzone_claim_metadata(transfer_id, amount, to);
    let parents = dag_tip_parents(&state, 3).await;
    let record = state.create_self_ledger_record(parents, meta)?;
    let record_id = record.id.clone();

    insert_and_push(&state, record).await?;

    tracing::info!("rpc_xzone_claim: {} claimed transfer {} ({})", &to[..16], transfer_id.chars().take(16).collect::<String>(), amount);

    Ok(Json(serde_json::json!({
        "ok": true,
        "record_id": record_id,
        "op": "xzone_claim",
        "transfer_id": transfer_id,
        "amount": amount,
        "to": to,
    })))
}

// ─── /rpc/xzone_abort (Gap 2 sealed-abort, Slice 3) ─────────────────────────

/// Submit a sealed-abort proof for a cross-zone transfer.
///
/// Accepts a fully-formed [`XZoneAbortBundle`] as the request body — anyone
/// can submit (the proof itself is the authorization, mirroring the public-good
/// nature of /rpc/xzone_claim). The handler:
///
/// 1. Deserializes the bundle.
/// 2. Calls [`XZoneAbortBundle::verify`] for a fail-fast pre-flight (saves
///    the submitter from paying record-creation cost when the proof is bad).
/// 3. Builds an `xzone_abort` ledger op with the bundle's signers + committee
///    snapshot in metadata.
/// 4. Creates a self-signed ledger record on this node and pushes it.
///
/// The source-zone validate/apply path independently re-verifies the proof
/// against the on-source `PendingTransfer` (resolving `dest_zone` and
/// `source_seal_epoch` from local state, NOT the bundle), so a malicious
/// submitter cannot trick the source side by lying about the transfer's
/// destination zone or seal epoch.
pub async fn rpc_xzone_abort(
    State(state): State<Arc<NodeState>>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(bundle): Json<crate::accounting::cross_zone::XZoneAbortBundle>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_rpc_auth(&state, connect_info.0.ip(), &headers)?;

    if bundle.transfer_id.is_empty() {
        return Err(ElaraError::Wire("xzone_abort: missing transfer_id".into()).into());
    }

    bundle
        .verify()
        .map_err(|e| ElaraError::Wire(format!("xzone_abort: bundle proof rejected: {e}")))?;

    let _guard = state.rpc_lock.lock().await;

    let meta = crate::accounting::types::xzone_abort_metadata(
        &bundle.transfer_id,
        &bundle.dest_committee_hash,
        bundle.dest_committee_size,
        &bundle.signers,
    );
    let parents = dag_tip_parents(&state, 3).await;
    let record = state.create_self_ledger_record(parents, meta)?;
    let record_id = record.id.clone();

    insert_and_push(&state, record).await?;

    tracing::info!(
        "rpc_xzone_abort: submitted abort for transfer {} (dest_zone={}, signers={})",
        &bundle.transfer_id[..bundle.transfer_id.len().min(16)],
        bundle.dest_zone.path(),
        bundle.signers.len()
    );

    Ok(Json(serde_json::json!({
        "ok": true,
        "record_id": record_id,
        "op": "xzone_abort",
        "transfer_id": bundle.transfer_id,
        "dest_zone": bundle.dest_zone.path(),
        "source_seal_epoch": bundle.source_seal_epoch,
        "signers_submitted": bundle.signers.len(),
        "dest_committee_size": bundle.dest_committee_size,
    })))
}

// ─── /rpc/stake ──────────────────────────────────────────────────────────────

pub async fn rpc_stake(
    State(state): State<Arc<NodeState>>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_rpc_auth(&state, connect_info.0.ip(), &headers)?;
    let amount = body["amount"].as_u64().ok_or(ElaraError::Wire("missing 'amount' (must be positive integer)".into()))?;
    let purpose_str = body["purpose"].as_str().unwrap_or("witness");
    let purpose = crate::accounting::types::StakePurpose::from_str(purpose_str)?;

    // Validate amount before creating record
    if amount == 0 {
        return Err(ElaraError::Wire("stake amount must be greater than zero".into()).into());
    }
    let min_stake = crate::accounting::types::MIN_STAKE;
    if amount < min_stake {
        return Err(ElaraError::Ledger(format!(
            "stake amount {} below minimum {} ({} beat)",
            amount, min_stake, min_stake / crate::accounting::types::BASE_UNITS_PER_BEAT
        )).into());
    }

    let meta = crate::accounting::types::stake_metadata(amount, &purpose);
    let parents = dag_tip_parents(&state, 3).await;
    let record = state.create_self_ledger_record(parents, meta)?;
    let record_id = record.id.clone();

    // Stake is admin-authenticated, bypass rate limits (otherwise chicken-and-egg:
    // need stake to get higher rate limits, can't stake due to rate limits)
    insert_and_push_admin(&state, record).await?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "record_id": record_id,
        "op": "stake",
        "amount": amount,
        "purpose": purpose_str,
    })))
}

// ─── /rpc/pool_fund ──────────────────────────────────────────────────────────

/// Fund the conservation pool from the genesis authority's balance
/// (economics §11.1 — the pool is the witness-reward source and starts
/// EMPTY at genesis, so rewards cannot mint until this runs). This is a
/// genesis-ceremony step: dev-net activation and the mainnet launch both
/// call it once right after init. Authorization is enforced at ledger
/// apply (`ParsedLedgerOp::PoolFund` rejects non-genesis-authority
/// creators); the route additionally pre-checks to fail fast with a clear
/// error instead of minting a doomed record.
pub async fn rpc_pool_fund(
    State(state): State<Arc<NodeState>>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_rpc_auth(&state, connect_info.0.ip(), &headers)?;
    let amount = body["amount"].as_u64().ok_or(ElaraError::Wire("missing 'amount' (must be positive integer base units; 10^9 = 1 beat)".into()))?;
    if amount == 0 {
        return Err(ElaraError::Wire("pool_fund amount must be greater than zero".into()).into());
    }
    if state.identity.identity_hash != state.config.genesis_authority {
        return Err(ElaraError::Ledger(
            "pool_fund is genesis-authority-only — this node is not the genesis authority".into(),
        ).into());
    }

    let meta = crate::accounting::types::pool_fund_metadata(amount);
    let parents = dag_tip_parents(&state, 3).await;
    let record = state.create_self_ledger_record(parents, meta)?;
    let record_id = record.id.clone();

    insert_and_push_admin(&state, record).await?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "record_id": record_id,
        "op": "pool_fund",
        "amount": amount,
    })))
}

// ─── /rpc/unstake ────────────────────────────────────────────────────────────

pub async fn rpc_unstake(
    State(state): State<Arc<NodeState>>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_rpc_auth(&state, connect_info.0.ip(), &headers)?;
    let stake_id = body["stake_id"].as_str().ok_or(ElaraError::Wire("missing 'stake_id'".into()))?;

    // Validate stake_id looks like a UUID v7 (36 chars with hyphens)
    if stake_id.len() != 36 || stake_id.chars().filter(|c| *c == '-').count() != 4 {
        return Err(ElaraError::Wire(format!(
            "invalid stake_id format: expected UUID (e.g. 01234567-abcd-7000-8000-000000000000), got '{}'",
            stake_id.chars().take(50).collect::<String>()
        )).into());
    }

    let meta = crate::accounting::types::unstake_metadata(stake_id);
    let parents = dag_tip_parents(&state, 3).await;
    let record = state.create_self_ledger_record(parents, meta)?;
    let record_id = record.id.clone();

    insert_and_push_admin(&state, record).await?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "record_id": record_id,
        "op": "unstake",
        "stake_id": stake_id,
    })))
}

// ─── /rpc/stamp ──────────────────────────────────────────────────────────────

pub async fn rpc_stamp(
    State(state): State<Arc<NodeState>>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_rpc_auth(&state, connect_info.0.ip(), &headers)?;
    let content_hash = body["content_hash"].as_str()
        .ok_or(ElaraError::Wire("missing 'content_hash'".into()))?;
    // SHA3-256 = exactly 64 hex chars. hex::decode("") succeeds, so without
    // this guard an empty hash mints a stamp of nothing (found live
    // 2026-06-11 during the launch rehearsal).
    if content_hash.len() != 64 {
        return Err(ElaraError::Wire(format!(
            "content_hash must be 64 hex chars (SHA3-256), got {}",
            content_hash.len()
        )).into());
    }
    let filename = body["filename"].as_str();
    let classification = match body["classification"].as_str().unwrap_or("public") {
        "private" => crate::record::Classification::Private,
        "restricted" => crate::record::Classification::Restricted,
        _ => crate::record::Classification::Public,
    };

    let content_bytes = hex::decode(content_hash)
        .map_err(|e| ElaraError::Wire(format!("invalid content_hash hex: {e}")))?;

    let mut metadata = std::collections::BTreeMap::new();
    if let Some(name) = filename {
        metadata.insert("stamp_filename".to_string(), serde_json::json!(name));
    }

    let mut record = crate::record::ValidationRecord::create(
        &content_bytes,
        state.identity.public_key.clone(),
        vec![],
        classification,
        Some(metadata),
    );
    // Monotonic slot nonce — every stamp from this identity must claim a
    // distinct slot, else the second stamp collides on (account, 0) and is
    // rejected as SLOT EQUIVOCATION. Stamp BEFORE signing so the v5 signable
    // bytes bind the nonce.
    record.nonce = state.next_slot_nonce();

    // Auto-generate ZK proof for Private/Restricted stamps (Protocol §5.3).
    // Content hash serves as the commitment — proves knowledge of content.
    if matches!(classification, crate::record::Classification::Private | crate::record::Classification::Restricted) {
        let content_arr: [u8; 32] = content_bytes.clone().try_into().unwrap_or([0u8; 32]);
        let blinding = crate::crypto::hash::sha3_256(
            &[content_arr.as_slice(), state.identity.identity_hash.as_bytes()].concat()
        );
        if let Ok(proof) = crate::crypto::commitment::prove_content_commitment(&content_arr, &blinding) {
            record.zk_proof = Some(proof.to_bytes());
        }
    }

    if state.config.light_mode {
        state.identity.sign_record_light(&mut record)?;
    } else {
        state.identity.sign_record(&mut record)?;
    }
    let record_id = record.id.clone();

    insert_and_push(&state, record).await?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "record_id": record_id,
        "content_hash": content_hash,
    })))
}

// ─── /rpc/stamp-private ─────────────────────────────────────────────────────

pub async fn rpc_stamp_private(
    State(state): State<Arc<NodeState>>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    verify_rpc_auth(&state, connect_info.0.ip(), &headers)?;
    let content_hash = body["content_hash"].as_str()
        .ok_or(ElaraError::Wire("missing 'content_hash'".into()))?;
    // SHA3-256 = exactly 64 hex chars. hex::decode("") succeeds, so without
    // this guard an empty hash mints a stamp of nothing (found live
    // 2026-06-11 during the launch rehearsal).
    if content_hash.len() != 64 {
        return Err(ElaraError::Wire(format!(
            "content_hash must be 64 hex chars (SHA3-256), got {}",
            content_hash.len()
        )).into());
    }
    let proof_type = body["proof_type"].as_str()
        .ok_or(ElaraError::Wire("missing 'proof_type' (balance_range or metadata_property)".into()))?;

    let content_bytes = hex::decode(content_hash)
        .map_err(|e| ElaraError::Wire(format!("invalid content_hash hex: {e}")))?;

    let zk_proof_bytes = match proof_type {
        "balance_range" => {
            let balance = body["balance"].as_u64()
                .ok_or(ElaraError::Wire("missing 'balance' (u64)".into()))?;
            let threshold = body["threshold"].as_u64()
                .ok_or(ElaraError::Wire("missing 'threshold' (u64)".into()))?;
            let blinding = crate::crypto::hash::sha3_256(
                &[&balance.to_le_bytes()[..], state.identity.identity_hash.as_bytes()].concat()
            );
            let proof = crate::crypto::commitment::prove_balance_range(balance, threshold, &blinding)
                .map_err(|e| ElaraError::Wire(format!("balance proof failed: {e}")))?;
            proof.to_bytes()
        }
        "metadata_property" => {
            let key = body["key"].as_str()
                .ok_or(ElaraError::Wire("missing 'key' (string)".into()))?;
            let value = body["value"].as_str()
                .ok_or(ElaraError::Wire("missing 'value' (string)".into()))?;
            let salt = crate::crypto::hash::sha3_256(
                format!("{}{}{}", content_hash, key, value).as_bytes()
            );
            let proof = crate::crypto::commitment::prove_metadata_property(key.as_bytes(), value.as_bytes(), &salt)
                .map_err(|e| ElaraError::Wire(format!("metadata proof failed: {e}")))?;
            proof.to_bytes()
        }
        "content_commitment" => {
            let content_bytes_arr: [u8; 32] = content_bytes.clone().try_into()
                .map_err(|_| ElaraError::Wire("content_hash must be exactly 32 bytes (64 hex chars)".into()))?;
            let blinding = crate::crypto::hash::sha3_256(
                &[content_bytes_arr.as_slice(), state.identity.identity_hash.as_bytes()].concat()
            );
            let proof = crate::crypto::commitment::prove_content_commitment(&content_bytes_arr, &blinding)
                .map_err(|e| ElaraError::Wire(format!("content proof failed: {e}")))?;
            proof.to_bytes()
        }
        _ => return Err(ElaraError::Wire(
            format!("unknown proof_type '{proof_type}' — use 'balance_range', 'metadata_property', or 'content_commitment'")
        ).into()),
    };

    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert("zk_proof_type".to_string(), serde_json::json!(proof_type));

    let mut record = crate::record::ValidationRecord::create(
        &content_bytes,
        state.identity.public_key.clone(),
        vec![],
        crate::record::Classification::Private,
        Some(metadata),
    );
    record.zk_proof = Some(zk_proof_bytes);
    // Slot nonce BEFORE signing — see rpc_stamp for rationale.
    record.nonce = state.next_slot_nonce();
    if state.config.light_mode {
        state.identity.sign_record_light(&mut record)?;
    } else {
        state.identity.sign_record(&mut record)?;
    }
    let record_id = record.id.clone();

    insert_and_push(&state, record).await?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "record_id": record_id,
        "classification": "PRIVATE",
        "content_hash": content_hash,
        "proof_type": proof_type,
    })))
}

// ─── /bootstrap/claim ────────────────────────────────────────────────────────

pub async fn bootstrap_claim(
    State(state): State<Arc<NodeState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    if state.identity.identity_hash != state.config.genesis_authority {
        return Ok(Json(serde_json::json!({
            "error": "bootstrap claims only accepted by genesis authority node"
        })));
    }

    let identity_hash = match body.get("identity_hash").and_then(|v| v.as_str()) {
        Some(h) if h.len() >= 16 => h.to_string(),
        _ => return Ok(Json(serde_json::json!({
            "error": "missing or invalid identity_hash"
        }))),
    };

    let (is_peer, peer_pow) = {
        let peers = state.peers.read().await;
        match peers.get(&identity_hash) {
            Some(peer) => (true, peer.pow_difficulty),
            None => (false, 0),
        }
    };

    if !is_peer {
        return Ok(Json(serde_json::json!({
            "error": "identity not found in peer table — must be a running elara-node",
            "identity_hash": identity_hash,
        })));
    }

    let min_pow = state.config.min_pow_difficulty;
    if min_pow > 0 && peer_pow < min_pow {
        return Ok(Json(serde_json::json!({
            "error": "insufficient PoW difficulty for bootstrap claim",
            "peer_pow": peer_pow,
            "required_pow": min_pow,
        })));
    }

    // G1 (internal design notes §2): production genesis pre-mints the
    // FULL supply to the authority, so a `genesis:bootstrap` mint trips the
    // duplicate-genesis-mint guard (ledger.rs, supply >= MAX_SUPPLY) and is
    // rejected at apply. The old path ignored that asymmetry: it marked
    // `bootstrap_claimed`, persisted + gossiped a doomed mint record, and
    // returned ok with a credited amount while crediting nothing — a phantom
    // claim that diverged bookkeeping from the ledger on every call. Fail
    // honestly instead, before mutating state. The real distribution path is a
    // TRANSFER from the authority's balance, gated on the sybil composition
    // (§4); until that lands the mint-based faucet is intentionally closed on a
    // fully-minted network. (On a sub-MAX test network the mint still applies.)
    if state.ledger.read().await.total_supply >= MAX_SUPPLY {
        return Ok(Json(serde_json::json!({
            "error": "bootstrap distribution unavailable: genesis supply is fully pre-minted; \
                      the mint-based faucet is superseded and transfer-based distribution is \
                      not yet wired (see internal design notes)",
        })));
    }

    let reward = {
        let mut genesis = state.genesis_state.write_recover();
        match genesis.claim_bootstrap(&identity_hash) {
            Ok(r) => r,
            Err(e) => return Ok(Json(serde_json::json!({
                "error": format!("{e}"),
            }))),
        }
    };

    let meta = crate::accounting::types::mint_metadata(
        reward, &identity_hash, "genesis:bootstrap",
    );
    let parents = dag_tip_parents(&state, 3).await;
    let record = state.create_self_ledger_record(parents, meta).map_err(AppError)?;

    let record_id = record.id.clone();
    match gossip::insert_record(&state, record.clone()).await {
        Ok(_) => {
            state.seen.lock_recover().insert(record_id.clone());
            NodeState::publish_record_with_fallback(&state, &record, None).await;
            Ok(Json(serde_json::json!({
                "ok": true,
                "record_id": record_id,
                "amount_micros": reward,
                "amount_beat": reward as f64 / BASE_UNITS_PER_BEAT as f64,
                "to": identity_hash,
                "source": "genesis:bootstrap",
            })))
        }
        Err(e) => {
            warn!("bootstrap claim insert failed for {}: {e} — rolling back {} micros to pool",
                &identity_hash[..identity_hash.len().min(16)], reward);
            {
                let mut genesis = state.genesis_state.write_recover();
                genesis.unclaim_bootstrap(&identity_hash, reward);
            }
            Err(AppError(e))
        }
    }
}


// ─── G1: bootstrap-claim phantom-claim guard ────────────────────────────────

#[cfg(test)]
mod g1_bootstrap_phantom_claim {
    use super::*;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::peer::{NodeType, PeerInfo, PeerProvenance, PeerState};
    use crate::network::state::NodeState;
    use crate::network::witness::WitnessManager;
    use crate::storage::rocks::StorageEngine;
    use std::sync::Arc;

    #[tokio::test]
    async fn full_supply_claim_fails_honestly_without_phantom() {
        // internal design notes §2 G1: on a fully-minted network the
        // genesis:bootstrap mint is rejected at apply (supply >= MAX_SUPPLY), so
        // the route must fail honestly WITHOUT marking bootstrap_claimed or
        // persisting a doomed record. Before the guard it returned ok:true with a
        // credited amount while crediting nothing — a phantom claim.
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("identity");
        let auth = identity.identity_hash.clone();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            // node IS the genesis authority (passes the first route gate)
            genesis_authority: auth.clone(),
            min_pow_difficulty: 0,
            mdns_enabled: false,
            health_check_interval_secs: 0,
            network_id: "g1-phantom-test".into(),
            ..Default::default()
        };
        let rocks = Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));

        // Seed the claimant as a peer (the route requires is_peer). Full literal
        // mirrors peer.rs::tests::make_peer — PeerInfo has no Default/new().
        let claimant = "claimant_node_phantom_test".to_string();
        {
            let peer = PeerInfo {
                identity_hash: claimant.clone(),
                host: "127.0.0.1".to_string(),
                port: 9473,
                node_type: NodeType::Leaf,
                last_seen: 1000.0,
                state: PeerState::Connected,
                failures: 0,
                successes: 0,
                valid_records: 0,
                invalid_records: 0,
                backoff_until: 0.0,
                pow_nonce: 0,
                pow_difficulty: 0,
                public_key_hex: String::new(),
                provenance: PeerProvenance::Outbound,
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
            };
            state.peers.write().await.insert(peer);
        }
        // Drive the ledger to full supply (production genesis pre-mint state).
        {
            let mut ledger = state.ledger.write().await;
            ledger.total_supply = MAX_SUPPLY;
        }

        let body = serde_json::json!({ "identity_hash": claimant });
        // AppError doesn't impl Debug, so match rather than .expect().
        let resp = match bootstrap_claim(State(state.clone()), Json(body)).await {
            Ok(j) => j,
            Err(_) => panic!("bootstrap_claim returned AppError; expected Ok(Json(error-body))"),
        };

        assert!(
            resp.0.get("error").is_some(),
            "must return an error on a fully-minted network, got: {}",
            resp.0
        );
        assert!(
            resp.0.get("ok").is_none(),
            "must NOT report ok:true (that was the phantom success)"
        );
        // Bookkeeping untouched: the doomed claim left no phantom mark.
        assert!(
            state
                .genesis_state
                .read_recover()
                .bootstrap_claimed
                .is_empty(),
            "G1: a doomed claim must not mark bootstrap_claimed"
        );
    }
}

// ─── /balances bounded-response tests ──────────────────────────────────────────

#[cfg(test)]
mod ops127_balances_bounded {
    use super::*;
    use crate::network::config::NodeConfig;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::state::NodeState;
    use crate::network::witness::WitnessManager;
    use crate::storage::rocks::StorageEngine;
    use crate::accounting::ledger::AccountState;
    use std::sync::Arc;

    fn temp_state() -> Arc<NodeState> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "ops127-balances-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
        std::mem::forget(tmp);
        state
    }

    async fn seed_accounts(state: &Arc<NodeState>, n: usize) {
        let mut ledger = state.ledger.write().await;
        for i in 0..n {
            let id = format!("{i:064x}");
            let acct = AccountState { available: i as u64, ..Default::default() };
            ledger.accounts.insert(id, acct);
        }
    }

    #[tokio::test]
    async fn no_filter_below_cap_returns_all_with_truncated_false() {
        let state = temp_state();
        seed_accounts(&state, 100).await;
        let v = compute_balances(state.clone(), None, None).await;
        assert_eq!(v["accounts"].as_array().unwrap().len(), 100);
        assert_eq!(v["returned_count"], 100);
        assert_eq!(v["total_count"], 100);
        assert_eq!(v["truncated"], false);
        assert_eq!(v["max_response"], MAX_BALANCES_RESPONSE);
        assert_eq!(
            state
                .balances_response_truncated_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn no_filter_above_cap_truncates_to_max() {
        let state = temp_state();
        seed_accounts(&state, MAX_BALANCES_RESPONSE + 500).await;
        let v = compute_balances(state.clone(), None, None).await;
        assert_eq!(
            v["accounts"].as_array().unwrap().len(),
            MAX_BALANCES_RESPONSE
        );
        assert_eq!(v["returned_count"], MAX_BALANCES_RESPONSE);
        assert_eq!(v["total_count"], MAX_BALANCES_RESPONSE + 500);
        assert_eq!(v["truncated"], true);
        assert_eq!(
            state
                .balances_response_truncated_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "truncated counter must increment exactly once per truncated response"
        );
    }

    #[tokio::test]
    async fn short_prefix_rejected_with_counter_bump() {
        let state = temp_state();
        seed_accounts(&state, 100).await;
        // 4-char prefix < MIN_BALANCES_PREFIX_LEN (8) skips the O(N) scan.
        // Contract preserved: never 404 — echo the supplied id with zero balances.
        let v = compute_balances(state.clone(), Some("abcd".into()), None).await;
        assert_eq!(v["identity"], "abcd");
        assert_eq!(v["available"], 0);
        assert_eq!(v["staked"], 0);
        assert_eq!(v["total"], 0);
        assert_eq!(
            state
                .balances_short_prefix_rejected_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        // Sanity: a fresh call with a different short prefix bumps again.
        let _ = compute_balances(state.clone(), Some("xy".into()), None).await;
        assert_eq!(
            state
                .balances_short_prefix_rejected_total
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }

    #[tokio::test]
    async fn full_hash_exact_match_unchanged() {
        let state = temp_state();
        seed_accounts(&state, 5).await;
        // Index 3 → "0..03" zero-padded to 64 hex chars. Exact match path
        // must return the seeded available=3 and skip both the short-prefix
        // gate and the prefix-scan fallback.
        let id = format!("{:064x}", 3u64);
        let v = compute_balances(state.clone(), Some(id.clone()), None).await;
        assert_eq!(v["identity"], id);
        assert_eq!(v["available"], 3);
        // Neither counter should fire on the exact-match fast path.
        assert_eq!(
            state
                .balances_short_prefix_rejected_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            state
                .balances_response_truncated_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn long_prefix_8_chars_falls_through_to_scan() {
        let state = temp_state();
        seed_accounts(&state, 10).await;
        // 8-char prefix matching the index-7 account (00000000000...07).
        // Should reach the prefix-scan slow path and find it via starts_with.
        let prefix = "00000000"; // 8 chars; matches every seeded account
        let v = compute_balances(state.clone(), Some(prefix.into()), None).await;
        // Either an account is returned (exact-or-prefix-match) or default —
        // we don't pin which one matches first since HashMap order is arbitrary.
        // The contract we ARE pinning: short-prefix counter must NOT fire
        // (8 = MIN_BALANCES_PREFIX_LEN, on-or-above the gate).
        assert!(v.get("identity").is_some());
        assert_eq!(
            state
                .balances_short_prefix_rejected_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    // ─── Gap 8 last-mile: with_recent opt-in tests ───────────────────────────

    #[tokio::test]
    async fn ops177_with_recent_none_omits_field() {
        // Default poll path: legacy accounts passing `?identity=X` (no
        // with_recent) must continue to receive the bounded-balances shape unchanged.
        // No `recent_records` key in the response — accounts that probe for
        // its presence interpret None-or-Missing as "field disabled".
        let state = temp_state();
        seed_accounts(&state, 5).await;
        let id = format!("{:064x}", 3u64);
        let v = compute_balances(state.clone(), Some(id.clone()), None).await;
        assert_eq!(v["identity"], id);
        assert!(
            v.get("recent_records").is_none(),
            "with_recent=None must NOT emit recent_records field (legacy contract)"
        );
    }

    #[tokio::test]
    async fn ops177_with_recent_zero_also_omits_field() {
        // `?with_recent=0` is semantically equivalent to None — the account
        // explicitly asked for zero records. We avoid an empty rocks scan in
        // this branch (cheap to skip) and avoid emitting an empty array
        // (matches None-shape so accounts see one consistent "off" surface).
        let state = temp_state();
        seed_accounts(&state, 5).await;
        let id = format!("{:064x}", 3u64);
        let v = compute_balances(state.clone(), Some(id.clone()), Some(0)).await;
        assert!(
            v.get("recent_records").is_none(),
            "with_recent=Some(0) must NOT emit recent_records field"
        );
    }

    #[tokio::test]
    async fn ops177_with_recent_set_emits_array_field() {
        // `?with_recent=10` opt-in: field must be present (Array) even when
        // the test ledger has no records that involve this identity. Empty
        // array is the contract — accounts distinguish "feature on, no
        // matches" (empty array) from "feature off" (field absent).
        let state = temp_state();
        seed_accounts(&state, 5).await;
        let id = format!("{:064x}", 3u64);
        let v = compute_balances(state.clone(), Some(id.clone()), Some(10)).await;
        assert_eq!(v["identity"], id);
        let recent = v
            .get("recent_records")
            .expect("with_recent=Some(N>0) must emit recent_records field");
        assert!(recent.is_array(), "recent_records must be a JSON array");
        assert_eq!(
            recent.as_array().unwrap().len(),
            0,
            "no records seeded → empty array (not null, not absent)"
        );
    }

    #[tokio::test]
    async fn ops177_with_recent_caps_at_max() {
        // The caller cannot exceed MAX_BALANCES_RECENT_RECORDS; an
        // unbounded-N opt-in must clamp silently rather than reject.
        // Indirect assertion: we can't see the internal `limit` from the
        // outside, but the response shape stays well-formed and the field
        // is still an array.
        let state = temp_state();
        seed_accounts(&state, 5).await;
        let id = format!("{:064x}", 3u64);
        let v = compute_balances(
            state.clone(),
            Some(id.clone()),
            Some(MAX_BALANCES_RECENT_RECORDS * 1000),
        )
        .await;
        let recent = v.get("recent_records").expect("field must be present");
        assert!(recent.is_array());
        assert!(
            recent.as_array().unwrap().len() <= MAX_BALANCES_RECENT_RECORDS,
            "internal cap must clamp the result, even on absurd N"
        );
    }

    #[tokio::test]
    async fn ops177_short_prefix_skips_recent_records() {
        // The short-prefix gate returns an echo-with-zero-balances
        // response. The recent-records lookup must NOT trigger a rocks scan for that branch:
        // the supplied id is too short to be a real account hash, so a
        // creator/recipient match against a 64-char hash would always be
        // false — wasting work. The recent_records field stays absent.
        let state = temp_state();
        seed_accounts(&state, 5).await;
        let v = compute_balances(state.clone(), Some("ab".into()), Some(10)).await;
        assert_eq!(v["identity"], "ab");
        assert_eq!(v["available"], 0);
        assert!(
            v.get("recent_records").is_none(),
            "short-prefix branch must NOT trigger the OPS-177 records lookup"
        );
        assert_eq!(
            state
                .balances_short_prefix_rejected_total
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "short-prefix counter must still increment in this branch"
        );
    }
}

// ─── Gap 8 seal-state helper tests ───────────────────────────────────────────

#[cfg(test)]
mod gap8_seal_state_helper {
    use super::*;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::consensus::{SealAttestation, WitnessProfile};
    use crate::network::state::NodeState;
    use crate::network::witness::WitnessManager;
    use crate::network::zone::ZoneId;
    use crate::network::LockRecover;
    use crate::storage::rocks::StorageEngine;
    use std::sync::Arc;

    fn temp_state() -> Arc<NodeState> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "gap8-seal-state-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
        std::mem::forget(tmp);
        state
    }

    fn profile(org: &str, subnet_byte: u8, geo: &str) -> WitnessProfile {
        WitnessProfile {
            organization: org.to_string(),
            subnet: format!("10.0.{subnet_byte}"),
            geo_zone: geo.to_string(),
        }
    }

    #[tokio::test]
    async fn pending_when_no_seal_no_finalized() {
        let state = temp_state();
        let mut tx = serde_json::json!({});
        let finalized = state.finalized.read().await;
        enrich_with_seal_state(&mut tx, &state, "rec-pending", &finalized);
        assert_eq!(tx["seal_state"], "pending");
        assert_eq!(tx["finalized"], false);
        assert_eq!(tx["attestation_count"], 0);
        assert_eq!(tx["stake_pct"], 0.0);
        assert!(tx.get("sealed_at").is_none());
        assert!(tx.get("finalized_at").is_none());
    }

    #[tokio::test]
    async fn sealed_when_seal_registered_no_attestations() {
        // First-proposal moment: a seal exists, no attestations have arrived yet.
        // SealProgress returns zero counts in this branch (consensus.rs:3917-3933) —
        // accounts need a stable "Sealed" anchor as soon as the seal is proposed
        // even though stake/threshold are not yet computable.
        let state = temp_state();
        {
            let mut consensus = state.consensus.lock_recover();
            consensus.register_zone_stake(ZoneId::from_legacy(0), 300);
            consensus.register_seal_records("seal-A", vec!["rec-sealed".to_string()]);
        }
        let mut tx = serde_json::json!({});
        let finalized = state.finalized.read().await;
        enrich_with_seal_state(&mut tx, &state, "rec-sealed", &finalized);
        assert_eq!(tx["seal_state"], "sealed");
        assert_eq!(tx["finalized"], false);
        assert_eq!(tx["attestation_count"], 0);
        assert_eq!(tx["stake_pct"], 0.0);
        assert!(tx.get("sealed_at").is_some(), "registered_at stamp must surface as sealed_at");
    }

    #[tokio::test]
    async fn sealed_with_partial_attestations_below_threshold() {
        let state = temp_state();
        let zone = ZoneId::from_legacy(0);
        {
            let mut consensus = state.consensus.lock_recover();
            consensus.register_zone_stake(zone.clone(), 300);
            consensus.register_profile("w1", profile("org-a", 1, "earth-us"));
            consensus.register_seal_records("seal-B", vec!["rec-partial".to_string()]);
            consensus.add_seal_attestation(SealAttestation {
                seal_id: "seal-B".to_string(),
                zone: zone.clone(),
                epoch_number: 0,
                witness_hash: "w1".to_string(),
                stake: 100,
                timestamp: 1.0,
            });
        }
        let mut tx = serde_json::json!({});
        let finalized = state.finalized.read().await;
        enrich_with_seal_state(&mut tx, &state, "rec-partial", &finalized);
        assert_eq!(tx["seal_state"], "sealed");
        assert_eq!(tx["finalized"], false);
        assert_eq!(tx["attestation_count"], 1);
        let pct = tx["stake_pct"].as_f64().unwrap();
        assert!(pct > 0.0 && pct < 1.0, "pct between 0 and 1 when below threshold, got {pct}");
    }

    #[tokio::test]
    async fn finalized_when_threshold_crossed() {
        // Three witnesses with fully independent profiles (distinct org+subnet+geo)
        // → independence ≈ 1.0 each → effective_stake ≈ 300 → crosses 2/3 of 300.
        let state = temp_state();
        let zone = ZoneId::from_legacy(0);
        {
            let mut consensus = state.consensus.lock_recover();
            consensus.register_zone_stake(zone.clone(), 300);
            consensus.register_profile("w1", profile("org-a", 1, "earth-us"));
            consensus.register_profile("w2", profile("org-b", 2, "earth-eu"));
            consensus.register_profile("w3", profile("org-c", 3, "mars-olympus"));
            consensus.register_seal_records("seal-C", vec!["rec-fin".to_string()]);
            for (i, wh) in ["w1", "w2", "w3"].iter().enumerate() {
                consensus.add_seal_attestation(SealAttestation {
                    seal_id: "seal-C".to_string(),
                    zone: zone.clone(),
                    epoch_number: 0,
                    witness_hash: wh.to_string(),
                    stake: 100,
                    timestamp: (i + 1) as f64,
                });
            }
        }
        let mut tx = serde_json::json!({});
        let finalized = state.finalized.read().await;
        enrich_with_seal_state(&mut tx, &state, "rec-fin", &finalized);
        assert_eq!(tx["seal_state"], "finalized");
        assert_eq!(tx["finalized"], true);
        assert_eq!(tx["attestation_count"], 3);
        assert_eq!(tx["stake_pct"], 1.0, "pct must clamp to 1.0 once threshold crossed");
        assert!(tx.get("finalized_at").is_some());
    }

    #[tokio::test]
    async fn finalized_via_pruned_set_when_no_seal_progress() {
        // Records that were finalized then pruned from consensus state still
        // need to report as finalized — the pruned-after-settlement fast path.
        let state = temp_state();
        {
            let mut fin = state.finalized.write().await;
            fin.insert("rec-pruned".to_string());
        }
        let mut tx = serde_json::json!({});
        let finalized = state.finalized.read().await;
        enrich_with_seal_state(&mut tx, &state, "rec-pruned", &finalized);
        assert_eq!(tx["seal_state"], "finalized");
        assert_eq!(tx["finalized"], true);
        assert_eq!(tx["attestation_count"], 0);
        assert_eq!(tx["stake_pct"], 1.0);
    }

    #[tokio::test]
    async fn backwards_compat_finalized_bool_matches_seal_state() {
        // The legacy `finalized: bool` field must remain wire-compatible:
        // true iff seal_state in {"finalized", "anchored"}, else false.
        // Wallets that only read the boolean must continue to work.
        let state = temp_state();
        let mut tx = serde_json::json!({});
        let finalized = state.finalized.read().await;
        enrich_with_seal_state(&mut tx, &state, "any-record", &finalized);
        let label = tx["seal_state"].as_str().unwrap();
        let bool_finalized = tx["finalized"].as_bool().unwrap();
        assert_eq!(bool_finalized, label == "finalized" || label == "anchored");
    }

    /// Pins the pure-fn `compute_supply_max`
    /// return tuple against the economics v1 hard cap. `MAX_SUPPLY` is the
    /// mainnet protocol-level supply ceiling — no minting beyond this point,
    /// ever — and `BASE_UNITS_PER_BEAT` is the wire-shape base-units→beat conversion
    /// constant that every account, explorer, and dashboard relies on. A drift
    /// in either constant would silently invalidate `/supply/max` for every
    /// downstream consumer.
    #[test]
    fn batch_a_compute_supply_max_pins_mainnet_default_10b_beat() {
        // Pin the underlying constants directly: 1 beat = 10^9 base units,
        // mainnet hard cap = 10B beat in base units (= 10^19 u64).
        assert_eq!(BASE_UNITS_PER_BEAT, 1_000_000_000,
            "BASE_UNITS_PER_BEAT = 10^9 — wire-shape constant for base-units→beat");
        assert_eq!(MAX_SUPPLY, 10_000_000_000u64 * BASE_UNITS_PER_BEAT,
            "MAX_SUPPLY = 10B beat in base units = 10^19 (economics v1 hard cap)");

        let (micros, beat) = compute_supply_max();
        assert_eq!(micros, MAX_SUPPLY,
            "compute_supply_max micros must equal MAX_SUPPLY exactly");
        assert_eq!(micros, 10_000_000_000_000_000_000u64,
            "compute_supply_max micros literal pin: 10B × 10^9 = 10^19");
        // f64 conversion: micros / BASE_UNITS_PER_BEAT = 10^19 / 10^9 = 10^10 beat.
        // u64 → f64 is exact up to 2^53; 10^19 fits within f64 precision at
        // this scale because we divide before observing.
        assert!((beat - 10_000_000_000.0).abs() < 1.0,
            "compute_supply_max beat must be ~10B (got {beat})");
    }

    /// Pins the balances const
    /// triad — exact values AND relative-ordering invariants. A regression
    /// that bumps MAX_BALANCES_RESPONSE above 1000 silently re-introduces
    /// the pre-cap ~200 MB JSON body; bumps MAX_BALANCES_RECENT_RECORDS
    /// above /history's 200 cap exposes /balances to unbounded read
    /// latency; drops MIN_BALANCES_PREFIX_LEN below 8 enables the
    /// guaranteed-miss-then-full-scan attack the prefix floor closed. All three
    /// values are LOAD-BEARING wire-contract numbers.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_ae_balances_const_triad_exact_values_and_relative_ordering() {
        // Exact-value pins (one assert per const, with the regression-class doc).
        assert_eq!(
            MAX_BALANCES_RECENT_RECORDS, 50,
            "OPS-177 with_recent cap — ≤2500 record reads + 50 lock takes per /balances call"
        );
        assert_eq!(
            MAX_BALANCES_RESPONSE, 1000,
            "OPS-127 unconditional response cap — ~200 KB ceiling at ~200 B/account"
        );
        assert_eq!(
            MIN_BALANCES_PREFIX_LEN, 8,
            "OPS-127 prefix floor — 8 hex chars = 32 bits of entropy (no guaranteed-miss attack)"
        );

        // Cross-const inequality invariants.
        assert!(
            MAX_BALANCES_RECENT_RECORDS < MAX_BALANCES_RESPONSE,
            "RECENT (per-identity, opt-in) must be < RESPONSE (no-filter, default) cap"
        );
        assert!(
            MIN_BALANCES_PREFIX_LEN < 64,
            "PREFIX_LEN must be strictly < full SHA3-256 hex length (64) — else exact-match only"
        );
        // /history's hard cap is 200; pin RECENT ≤ that as a cross-endpoint invariant.
        assert!(
            MAX_BALANCES_RECENT_RECORDS <= 200,
            "RECENT cap must be ≤ /history's 200 hard limit — docstring claim at token.rs:86"
        );
    }

    /// Pins the with_recent scan-budget math docstring
    /// claim at `token.rs:86-87` ("≤2500 record reads + 50 lock takes"). The
    /// 2500 is `MAX_BALANCES_RECENT_RECORDS * 50` where 50 is the per-identity
    /// scan multiplier from `(N * 50).min(5000)`. A regression that raises N
    /// without re-checking the `.min(5000)` ceiling would silently degrade
    /// /balances latency under sustained polling.
    #[test]
    fn batch_ae_balances_recent_records_scan_budget_bounded_by_docstring_2500() {
        let n = MAX_BALANCES_RECENT_RECORDS; // 50
        let per_id_scan_multiplier: usize = 50;
        let upper_bound_scan = n.saturating_mul(per_id_scan_multiplier);

        assert_eq!(
            upper_bound_scan, 2500,
            "MAX_BALANCES_RECENT_RECORDS * 50 = 2500 (OPS-177 docstring scan-budget)"
        );
        assert!(
            upper_bound_scan <= 5000,
            "scan upper-bound must stay ≤ the `.min(5000)` ceiling in compute_balances"
        );
        // Lock-take count per /balances call = N. Pin under /history's 200 cap.
        assert!(
            n <= 200,
            "per-call lock takes (= N = MAX_BALANCES_RECENT_RECORDS) must stay ≤ /history's 200"
        );
        // Saturating math sanity — confirms no overflow on the upper-bound math.
        assert!(
            upper_bound_scan >= n,
            "upper_bound_scan must be ≥ N (no overflow wraparound)"
        );
    }

    // ─── Query-struct wire-shape pins ──────────────────────────────────────────
    //
    // The five public Query structs
    // (one per token-route endpoint: BalanceQuery / StakeQuery / HistoryQuery /
    // RecentQuery / NextNonceQuery) had ZERO direct wire-shape pinning despite
    // backing the user-facing /balances /stakes /history /transactions/recent
    // /slot/next_nonce endpoints — flipping any field name silently breaks
    // every account/CLI client. These five fixture-free tests pin one struct
    // per axis with the field-name + required-vs-optional + type discipline.

    #[test]
    fn batch_b_balance_query_wire_shape_pins_identity_and_with_recent_optional_fields() {
        // Both fields optional. identity=None triggers fleet-wide balance
        // dump; with_recent ignored when identity absent (docstring at L74-77).
        // Pin so a future refactor that made `identity` required would
        // surface as a wire-break instead of a silent backend behavior shift.
        let full = serde_json::json!({
            "identity": "alice-pk",
            "with_recent": 25usize,
        });
        let parsed: BalanceQuery =
            serde_json::from_value(full).expect("full balance query must parse");
        assert_eq!(parsed.identity.as_deref(), Some("alice-pk"));
        assert_eq!(parsed.with_recent, Some(25));

        // Empty body — both default to None (no `#[serde(default)]` collapses
        // Some(0) to None which would be a different semantic).
        let empty: BalanceQuery =
            serde_json::from_value(serde_json::json!({})).expect("empty must parse");
        assert!(empty.identity.is_none());
        assert!(empty.with_recent.is_none());

        // with_recent=0 IS distinguishable from None at the wire layer (handler
        // is the one that may treat 0 as a no-op). Pin so a future
        // `deserialize_with` that collapsed 0 to None would surface here.
        let zero_recent: BalanceQuery =
            serde_json::from_value(serde_json::json!({"with_recent": 0usize}))
                .expect("with_recent=0 must parse as Some(0)");
        assert_eq!(zero_recent.with_recent, Some(0));

        // Huge with_recent parses at struct level — clamp to
        // MAX_BALANCES_RECENT_RECORDS (50) lives in the handler.
        let huge: BalanceQuery =
            serde_json::from_value(serde_json::json!({"with_recent": 1_000_000usize}))
                .expect("huge with_recent must parse");
        assert_eq!(huge.with_recent, Some(1_000_000));

        // Wrong-type identity rejects (number where String expected).
        let wrong_type =
            serde_json::from_value::<BalanceQuery>(serde_json::json!({"identity": 12345}));
        assert!(wrong_type.is_err(), "numeric identity must NOT parse");
    }

    #[test]
    fn batch_b_stake_query_wire_shape_pins_single_optional_identity_field() {
        // Single-field struct — identity Option<String>. The narrowest of
        // the five Query structs; pin so a future addition (e.g. `active_only`
        // filter) doesn't accidentally rename or rebind `identity`.
        let with_id = serde_json::json!({"identity": "validator-1"});
        let parsed: StakeQuery =
            serde_json::from_value(with_id).expect("with-identity must parse");
        assert_eq!(parsed.identity.as_deref(), Some("validator-1"));

        // Empty body → identity=None → fleet-wide stake dump (compute_stakes
        // L334-336 branch). Pin so a future "require identity" change would
        // be a deliberate wire-break, not a silent shift.
        let empty: StakeQuery =
            serde_json::from_value(serde_json::json!({})).expect("empty must parse");
        assert!(empty.identity.is_none());

        // Empty string identity parses (handler decides whether to special-case).
        let empty_str: StakeQuery =
            serde_json::from_value(serde_json::json!({"identity": ""})).expect("empty string");
        assert_eq!(empty_str.identity.as_deref(), Some(""));

        // Extra fields tolerated (no #[serde(deny_unknown_fields)]) so the
        // wire is forward-compatible with future query extensions.
        let with_extra: StakeQuery = serde_json::from_value(
            serde_json::json!({"identity": "v1", "future_filter": "active"}),
        )
        .expect("extra fields must be tolerated");
        assert_eq!(with_extra.identity.as_deref(), Some("v1"));
    }

    #[test]
    fn batch_b_history_query_wire_shape_pins_identity_required_with_limit_offset_optional() {
        // HistoryQuery is the only Query struct with a REQUIRED field
        // (identity is `String`, not `Option<String>`). The other 4
        // structs treat all fields as Optional. Pin this asymmetry — a
        // future refactor that flipped `identity` to Option would silently
        // accept identity-absent requests and the handler would either
        // 500 on the unwrap or fall through to a fleet-wide history scan
        // (DoS surface).
        let full = serde_json::json!({
            "identity": "carol-pk",
            "limit": 100usize,
            "offset": 50usize,
        });
        let parsed: HistoryQuery =
            serde_json::from_value(full).expect("full history must parse");
        assert_eq!(parsed.identity, "carol-pk");
        assert_eq!(parsed.limit, Some(100));
        assert_eq!(parsed.offset, Some(50));

        // Minimal — only identity present. limit/offset default to None
        // (handler clamps to limit=50, offset=0).
        let minimal = serde_json::json!({"identity": "dave-pk"});
        let parsed: HistoryQuery =
            serde_json::from_value(minimal).expect("identity-only must parse");
        assert_eq!(parsed.identity, "dave-pk");
        assert!(parsed.limit.is_none());
        assert!(parsed.offset.is_none());

        // Identity ABSENT MUST reject — this is the load-bearing pin. A
        // regression that flipped to Option<String> would silently parse
        // this as `identity: None` and the handler would either panic on
        // `.unwrap()` or DoS the node with a fleet-wide history scan.
        let no_identity = serde_json::json!({"limit": 50});
        let err = match serde_json::from_value::<HistoryQuery>(no_identity) {
            Ok(_) => panic!("identity-absent MUST reject"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("identity"),
            "rejection must name the missing required field, got: {err}"
        );

        // limit=0 parses at struct level (handler's `.min(200)` clamp keeps
        // it at 0 — handler must guard against limit=0 returning empty page).
        let zero_limit: HistoryQuery =
            serde_json::from_value(serde_json::json!({"identity": "e", "limit": 0}))
                .expect("limit=0 must parse");
        assert_eq!(zero_limit.limit, Some(0));

        // Above-cap limit parses (clamp at handler, not struct level).
        let huge_limit: HistoryQuery = serde_json::from_value(
            serde_json::json!({"identity": "f", "limit": 1_000_000usize}),
        )
        .expect("huge limit must parse");
        assert_eq!(huge_limit.limit, Some(1_000_000));
    }

    #[test]
    fn batch_b_recent_query_wire_shape_pins_single_optional_limit_field() {
        // Single-field RecentQuery — limit Option<usize>. Distinct from
        // HistoryQuery.limit because RecentQuery has no `identity` filter
        // (it returns fleet-wide recent token transactions). The handler
        // clamps to `.min(100)` defaulting to 20 (L595 comment).
        let with_limit = serde_json::json!({"limit": 50usize});
        let parsed: RecentQuery =
            serde_json::from_value(with_limit).expect("with-limit must parse");
        assert_eq!(parsed.limit, Some(50));

        // Empty body → handler default (20) applies — pin None at struct
        // level so a future `#[serde(default = "twenty")]` would surface.
        let empty: RecentQuery =
            serde_json::from_value(serde_json::json!({})).expect("empty must parse");
        assert!(empty.limit.is_none());

        // limit=0 parses (zero-record dump is a valid query — handler
        // decides whether to skip the scan).
        let zero: RecentQuery =
            serde_json::from_value(serde_json::json!({"limit": 0usize})).expect("zero");
        assert_eq!(zero.limit, Some(0));

        // Above-cap limit parses (clamp lives in handler at .min(100)).
        let huge: RecentQuery =
            serde_json::from_value(serde_json::json!({"limit": 10_000usize})).expect("huge");
        assert_eq!(huge.limit, Some(10_000));

        // Wrong-type limit (string) rejects.
        let wrong =
            serde_json::from_value::<RecentQuery>(serde_json::json!({"limit": "twenty"}));
        assert!(wrong.is_err(), "string limit must NOT parse");
    }

    #[test]
    fn batch_b_next_nonce_query_wire_shape_pins_required_account_field_with_pub_visibility() {
        // NextNonceQuery is the ONLY Query struct in this module with a
        // `pub` field (`pub account`). The other 4 structs hold their
        // fields private. Pin both (a) `account` is required (not Option)
        // and (b) the field is accessible by name from external callers
        // (PQ-transport router constructs this directly without going
        // through Deserialize when both sides of the IPC are in-process).
        let full = serde_json::json!({"account": "0xdeadbeef"});
        let parsed: NextNonceQuery =
            serde_json::from_value(full).expect("with-account must parse");
        assert_eq!(parsed.account, "0xdeadbeef");

        // Direct struct construction by external code (pub field check).
        // A regression that changed `pub account` → private would break
        // every PQ-router caller; this assertion compiles only if the
        // field remains pub-accessible.
        let direct = super::NextNonceQuery { account: "direct".to_string() };
        assert_eq!(direct.account, "direct");

        // Empty body MUST reject — account is required. A regression that
        // flipped to Option<String> would silently accept account-absent
        // requests and the handler would either panic on .unwrap or scan
        // every account on the node (DoS surface).
        let no_account = serde_json::json!({});
        let err = match serde_json::from_value::<NextNonceQuery>(no_account) {
            Ok(_) => panic!("account-absent MUST reject"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("account"),
            "rejection must name the missing field, got: {err}"
        );

        // Empty-string account parses at wire layer — handler decides
        // whether to special-case (CF_SLOT_INDEX prefix scan on empty
        // string yields no results, so handler returns 1 = first nonce).
        let empty_str: NextNonceQuery =
            serde_json::from_value(serde_json::json!({"account": ""})).expect("empty-string");
        assert!(empty_str.account.is_empty());

        // Wrong type (numeric account) rejects — type discipline.
        let wrong =
            serde_json::from_value::<NextNonceQuery>(serde_json::json!({"account": 42}));
        assert!(wrong.is_err(), "numeric account must NOT parse");
    }

    // ─── Orthogonal pins on the supply / ledger / stakes compute_* helpers ──────
    // Helpers exercised: compute_supply_total (663), compute_supply_circulating (654),
    // compute_ledger_summary (369), compute_stakes (329). Each axis is fixture-free
    // and orthogonal to every other test in this module.

    /// Pins that `compute_supply_total` (`token.rs:663`)
    /// returns `ledger.total_supply` VERBATIM — does NOT subtract `total_staked`
    /// nor `conservation_pool`. Distinct from `compute_supply_circulating`, which
    /// DOES subtract both. A regression that "harmonized" the two helpers (a
    /// common refactor temptation — both return `(u64, f64)` micros/beat tuples)
    /// would silently break every dashboard reading from `/supply/total`: e.g.
    /// `total_supply` is the protocol's "total tokens minted so far" metric
    /// (fixed at genesis — there is no post-genesis emission), NOT the "tokens
    /// currently liquid in accounts" metric. Asserts (a) micros echoes
    /// total_supply exactly, (b) beat
    /// conversion is `total_supply / 10^9`, (c) the staked + conservation_pool
    /// values present in the ledger DO NOT propagate into the returned tuple.
    #[tokio::test]
    async fn batch_www_compute_supply_total_echoes_total_supply_no_subtraction() {
        let state = temp_state();
        {
            let mut ledger = state.ledger.write().await;
            ledger.total_supply = 5_000_000_000; // 5 beat in base units
            ledger.total_staked = 1_000_000_000; // 1 beat in base units — must NOT subtract
            ledger.conservation_pool = 200_000_000; // 0.2 beat — must NOT subtract
        }
        let (micros, beat) = compute_supply_total(state.clone()).await;
        assert_eq!(
            micros, 5_000_000_000,
            "compute_supply_total micros must echo total_supply VERBATIM, not subtract staked or pool"
        );
        assert!(
            (beat - 5.0).abs() < 1e-9,
            "compute_supply_total beat = 5_000_000_000 / 10^9 = 5.0, got {beat}"
        );
        // Confirmation: if total_supply had been subtracted by staked + pool,
        // the result would be 5_000_000_000 - 1_000_000_000 - 200_000_000 =
        // 3_800_000_000 micros. Pin the disjoint result explicitly.
        assert_ne!(
            micros, 3_800_000_000,
            "compute_supply_total MUST NOT match the circulating formula (supply - staked - pool)"
        );
    }

    /// Pins `compute_supply_circulating`
    /// (`token.rs:654`) THREE-way subtraction: `total_supply - total_staked
    /// - conservation_pool`. The conservation_pool subtraction is structurally
    /// load-bearing: tokens in the pool are NOT circulating, even though they
    /// are technically "minted" (counted in total_supply). A regression that
    /// dropped the second saturating_sub (a likely "simplification" PR that
    /// thinks staked is the only deduction) would silently inflate the
    /// `/supply/circulating` value by the full pool size — directly visible on
    /// the explorer landing page and the beat price-derivation feed. Distinct
    /// from `batch_www_compute_supply_total_echoes_*` (which pins the NON-subtracting
    /// branch). Both branches share the (u64, f64) return shape; this axis
    /// confirms the arithmetic.
    #[tokio::test]
    async fn batch_www_compute_supply_circulating_three_way_subtract_with_beat_conversion() {
        let state = temp_state();
        {
            let mut ledger = state.ledger.write().await;
            ledger.total_supply = 5_000_000_000; // 5 beat
            ledger.total_staked = 1_000_000_000; // 1 beat staked
            ledger.conservation_pool = 500_000_000; // 0.5 beat in pool
        }
        let (micros, beat) = compute_supply_circulating(state.clone()).await;
        // 5_000_000_000 - 1_000_000_000 - 500_000_000 = 3_500_000_000 micros
        assert_eq!(
            micros, 3_500_000_000,
            "circulating = supply - staked - pool = 5e9 - 1e9 - 0.5e9 = 3.5e9 micros"
        );
        assert!(
            (beat - 3.5).abs() < 1e-9,
            "circulating beat = 3_500_000_000 / 10^9 = 3.5, got {beat}"
        );
        // Pin against the two-way-subtract regression (drops the conservation_pool
        // term): supply - staked alone would be 4_000_000_000 micros.
        assert_ne!(
            micros, 4_000_000_000,
            "regression to two-way subtraction (dropping pool) must NOT match — pool is non-circulating"
        );
    }

    /// Pins the `saturating_sub` semantics on
    /// `compute_supply_circulating` (`token.rs:656-659`) — when
    /// `total_staked > total_supply` (the brief invariant-violating window
    /// during snapshot apply or a restored chain where the staked counter is
    /// re-derived AHEAD of the supply counter), the helper must return 0 micros
    /// (and 0.0 beat), NOT panic in debug builds or underflow to a giant
    /// u64::MAX-adjacent number in release. A regression that swapped
    /// `saturating_sub` for plain `-` would: (a) on debug builds, panic the
    /// HTTP worker thread serving `/supply/circulating` during the
    /// snapshot-apply window — taking down the explorer landing page on every
    /// restart; (b) on release builds, return ~18.4 quintillion micros as a
    /// "circulating supply" — a catastrophic price-feed signal. The 0-floor is
    /// the only correct fallback under inversion.
    #[tokio::test]
    async fn batch_www_compute_supply_circulating_saturates_to_zero_when_staked_exceeds_supply() {
        let state = temp_state();
        {
            let mut ledger = state.ledger.write().await;
            // Deliberately invert: staked > supply. Real situations: snapshot
            // apply ordering, mid-restore counter re-derivation.
            ledger.total_supply = 100;
            ledger.total_staked = 200;
            ledger.conservation_pool = 0;
        }
        let (micros, beat) = compute_supply_circulating(state.clone()).await;
        assert_eq!(
            micros, 0,
            "saturating_sub MUST clamp to 0 when staked > supply — got {micros}"
        );
        assert!(
            beat.abs() < 1e-9,
            "beat conversion of 0 micros = 0.0, got {beat}"
        );
        // Second inversion: staked OK, but conservation_pool exceeds remainder.
        // After saturating_sub(staked): 100 - 50 = 50. Then saturating_sub(pool):
        // 50 - 200 = 0 (clamped). Pins the chained saturating_sub through both arms.
        {
            let mut ledger = state.ledger.write().await;
            ledger.total_supply = 100;
            ledger.total_staked = 50;
            ledger.conservation_pool = 200;
        }
        let (micros2, beat2) = compute_supply_circulating(state.clone()).await;
        assert_eq!(
            micros2, 0,
            "chained saturating_sub: after subtract staked=50, pool=200 > 50 → 0"
        );
        assert!(beat2.abs() < 1e-9);
    }

    /// Pins that `compute_ledger_summary` (`token.rs:369`)
    /// appends EXACTLY FOUR `*_beat_precise` String keys onto the serde-serialized
    /// `LedgerSummary`. Each `_precise` key uses `validate::format_beat_precise`
    /// (avoids f64 precision loss at the 10^10 beat / 10^19 micros scale) and is
    /// ADDITIVE — the original `*_beat` f64 keys MUST still be present alongside.
    /// A regression that replaced the f64 keys instead of supplementing them
    /// would break legacy dashboards reading the f64 fields; a regression that
    /// renamed the suffix from `_precise` would break the new precision-locked
    /// readers. Asserts (a) all 4 _precise keys present, (b) corresponding f64
    /// keys still present, (c) value type is JSON String (NOT a Number), (d)
    /// format pin: 1_000_000_000 micros → "1.0" (frac=0 branch of format_beat_precise),
    /// 1_500_000_000 → "1.5" (trim_end_matches('0') branch).
    #[tokio::test]
    async fn batch_www_compute_ledger_summary_appends_four_precise_string_keys_alongside_f64_originals() {
        let state = temp_state();
        {
            let mut ledger = state.ledger.write().await;
            // Pin exact values for format_beat_precise behavior:
            //   total_supply 10_000_000_000 micros → "10.0" (frac=0)
            //   total_staked 1_500_000_000 micros → "1.5" (frac→"5")
            //   conservation_pool 500_000_000 micros → "0.5" (frac→"5")
            //   circulating = 10e9 - 1.5e9 - 0.5e9 = 8_000_000_000 → "8.0"
            ledger.total_supply = 10_000_000_000;
            ledger.total_staked = 1_500_000_000;
            ledger.conservation_pool = 500_000_000;
        }
        let json = compute_ledger_summary(&state).await;
        let obj = json.as_object().expect("compute_ledger_summary must emit an Object");

        // (a) All 4 _precise keys present.
        for key in [
            "total_supply_beat_precise",
            "circulating_beat_precise",
            "conservation_pool_beat_precise",
            "total_staked_beat_precise",
        ] {
            assert!(
                obj.contains_key(key),
                "compute_ledger_summary MUST emit key '{key}' alongside the f64 _beat field"
            );
            assert!(
                obj[key].is_string(),
                "_precise value MUST be a JSON String (not Number) — got: {:?}",
                obj[key]
            );
        }

        // (b) Original f64 _beat keys still present (additive, not replacement).
        for key in [
            "total_supply_beat",
            "circulating_beat",
            "conservation_pool_beat",
            "total_staked_beat",
        ] {
            assert!(
                obj.contains_key(key),
                "f64 _beat key '{key}' MUST remain alongside the _precise variant"
            );
            assert!(
                obj[key].is_f64() || obj[key].is_i64() || obj[key].is_u64(),
                "f64 _beat value MUST be a JSON Number, got: {:?}",
                obj[key]
            );
        }

        // (c) Exact format pins through format_beat_precise.
        assert_eq!(
            obj["total_supply_beat_precise"], "10.0",
            "10_000_000_000 micros (frac=0) → \"10.0\""
        );
        assert_eq!(
            obj["total_staked_beat_precise"], "1.5",
            "1_500_000_000 micros (frac=500_000_000 → trim('0') → \"5\") → \"1.5\""
        );
        assert_eq!(
            obj["conservation_pool_beat_precise"], "0.5",
            "500_000_000 micros (whole=0, frac→\"5\") → \"0.5\""
        );
        assert_eq!(
            obj["circulating_beat_precise"], "8.0",
            "circulating = 10e9 - 1.5e9 - 0.5e9 = 8_000_000_000 → \"8.0\""
        );
    }

    /// Pins the asymmetric wire contract of
    /// `compute_stakes` (`token.rs:329`) between its two branches:
    /// (a) `identity_filter == None` — every per-stake JSON object HAS a `staker`
    /// key (so a consumer aggregating across identities can group by staker);
    /// (b) `identity_filter == Some(id)` — per-stake JSON omits the `staker`
    /// key (the staker is already known and echoed at the envelope `identity`
    /// field, redundant inside each element). A regression that "harmonized"
    /// the two branches (e.g. a refactor that DRY-ed the per-stake JSON
    /// builder) would either (i) ADD `staker` to the with-filter branch
    /// (causing accounts to see duplicate identity info inside each element) or
    /// (ii) REMOVE `staker` from the no-filter branch (breaking dashboards that
    /// scan global stakes and need to know who owns each one). Both branches
    /// ALSO filter to `active = true` only — pin that an inactive stake is
    /// omitted from both wire surfaces.
    #[tokio::test]
    async fn batch_www_compute_stakes_asymmetric_staker_field_and_active_only_filter() {
        use crate::accounting::ledger::StakeEntry;
        use crate::accounting::types::StakePurpose;

        let state = temp_state();
        let staker_a = format!("{:064x}", 0xAAu64);
        let staker_b = format!("{:064x}", 0xBBu64);
        {
            let mut ledger = state.ledger.write().await;
            ledger.stakes.insert(
                "stake-active-1".to_string(),
                StakeEntry {
                    record_id: "stake-active-1".to_string(),
                    amount: 100,
                    purpose: StakePurpose::Witness,
                    staker: staker_a.clone(),
                    timestamp: 100.0,
                    active: true,
                },
            );
            ledger.stakes.insert(
                "stake-active-2".to_string(),
                StakeEntry {
                    record_id: "stake-active-2".to_string(),
                    amount: 200,
                    purpose: StakePurpose::Governance,
                    staker: staker_b.clone(),
                    timestamp: 200.0,
                    active: true,
                },
            );
            ledger.stakes.insert(
                "stake-inactive-3".to_string(),
                StakeEntry {
                    record_id: "stake-inactive-3".to_string(),
                    amount: 300,
                    purpose: StakePurpose::Storage,
                    staker: staker_a.clone(),
                    timestamp: 300.0,
                    active: false,
                },
            );
            // Build the staker_index so stakes_for() works.
            ledger.rebuild_staker_index();
        }

        // ─── Branch (a): identity_filter = None ──────────────────────────
        let no_filter = compute_stakes(state.clone(), None, None).await;
        // Envelope shape: { stakes: [...] } — no top-level identity key.
        let obj = no_filter.as_object().expect("compute_stakes must emit an Object");
        assert!(
            !obj.contains_key("identity"),
            "no-filter branch envelope MUST NOT have a top-level 'identity' key (only with-filter does)"
        );
        let arr = obj["stakes"].as_array().expect("'stakes' must be an Array");
        assert_eq!(
            arr.len(),
            2,
            "no-filter MUST return ONLY the 2 active stakes (inactive filtered out), got {}",
            arr.len()
        );
        for el in arr {
            assert!(
                el.as_object().expect("element is Object").contains_key("staker"),
                "no-filter per-stake JSON MUST contain 'staker' key for cross-identity aggregation"
            );
            // Confirm none of the elements is the inactive one.
            assert_ne!(
                el["record_id"].as_str().unwrap(),
                "stake-inactive-3",
                "inactive stake MUST NOT appear in the no-filter result"
            );
        }

        // ─── Branch (b): identity_filter = Some(staker_a) ────────────────
        // Only stake-active-1 is staker_a's active stake — stake-inactive-3 is
        // also staker_a's but is inactive (stakes_for filters by active=true).
        let with_filter = compute_stakes(state.clone(), Some(staker_a.clone()), None).await;
        let obj = with_filter.as_object().expect("compute_stakes must emit an Object");
        assert_eq!(
            obj["identity"], staker_a,
            "with-filter envelope MUST echo the supplied identity at top-level"
        );
        let arr = obj["stakes"].as_array().expect("'stakes' must be an Array");
        assert_eq!(
            arr.len(),
            1,
            "with-filter MUST return ONLY staker_a's active stake (1), got {} — inactive should be excluded",
            arr.len()
        );
        for el in arr {
            let el_obj = el.as_object().expect("element is Object");
            assert!(
                !el_obj.contains_key("staker"),
                "with-filter per-stake JSON MUST NOT contain 'staker' (already at envelope 'identity'). Got: {:?}",
                el_obj.keys().collect::<Vec<_>>()
            );
            // Pin the 5 keys present in the with-filter branch.
            let mut keys: Vec<&str> = el_obj.keys().map(|k| k.as_str()).collect();
            keys.sort();
            assert_eq!(
                keys,
                vec!["active", "amount", "purpose", "record_id", "timestamp"],
                "with-filter per-stake JSON has EXACTLY these 5 keys (no 'staker')"
            );
            assert_eq!(el["record_id"], "stake-active-1");
            assert_eq!(el["active"], true);
            assert_eq!(el["purpose"], "witness", "StakePurpose serializes snake_case");
        }
    }

    #[tokio::test]
    async fn batch_www_compute_stakes_no_filter_bounds_returned_rows_while_total_reports_true_count() {
        use crate::accounting::ledger::StakeEntry;
        use crate::accounting::types::StakePurpose;
        // Public-surface response bound: the fleet-wide (identity=None) `/stakes`
        // response is reachable over the PQ verb by any handshaked peer, so a
        // single call must not dump every active stake. `limit` bounds the
        // returned `stakes` array while `total` reports the TRUE active-stake
        // count so a caller detects truncation as `stakes.len() < total`. Rows
        // are ordered by record_id for a deterministic page.
        let state = temp_state();
        {
            let mut ledger = state.ledger.write().await;
            for i in 0..5u64 {
                let rid = format!("stake-{i:02}");
                ledger.stakes.insert(
                    rid.clone(),
                    StakeEntry {
                        record_id: rid,
                        amount: 100 + i,
                        purpose: StakePurpose::Witness,
                        staker: format!("{i:064x}"),
                        timestamp: 100.0 + i as f64,
                        active: true,
                    },
                );
            }
        }
        // Request a page smaller than the active-stake set.
        let v = compute_stakes(state.clone(), None, Some(2)).await;
        let obj = v.as_object().expect("compute_stakes must emit an Object");
        let arr = obj["stakes"].as_array().expect("'stakes' must be an Array");
        assert_eq!(
            arr.len(),
            2,
            "returned stakes MUST be bounded by the requested limit",
        );
        assert_eq!(
            obj.get("total").and_then(|x| x.as_u64()),
            Some(5),
            "`total` MUST report the TRUE active-stake count regardless of the page cap",
        );
        // Deterministic ordering — lowest record_id first ("stake-00","stake-01").
        assert_eq!(
            arr[0]["record_id"].as_str(),
            Some("stake-00"),
            "page MUST be ordered by record_id — first row is the lowest",
        );
        assert_eq!(
            arr[1]["record_id"].as_str(),
            Some("stake-01"),
            "page MUST be ordered by record_id — second row is the next lowest",
        );
    }
}

// ─── compute_token_enforcement orthogonal pins ─────────────────────────────
//
// The pure-read helper at `routes/ledger.rs:393` is the wire-source for the
// `/token/enforcement` operator dashboard — it surfaces the four enforcement
// subsystems (circuit_breaker / velocity / acquisition / vesting), the trust
// tracker, the governance proposal-state counts (via the incremental
// counters), and the circulating-supply derivation. Previously the helper had
// ZERO direct test coverage at the route surface (only 2 references in the
// entire file: definition at L393 and handler call at L475 `token_enforcement`).
// Trade-offs of the slice: (1) the helper reads `state.ledger.read().await`
// + `state.trust.read().await` in sequence — pure-fn over a default ledger,
// no record-seeding required, so all 5 axes run without rocks-side setup;
// (2) the wire-envelope shape carries 7 top-level keys + 25 nested keys,
// so any silent serde-derive bloat or rename surfaces here even though the
// helper hand-rolls the envelope via `serde_json::json!`; (3) the saturating
// arithmetic + threshold-comparison axes catch high-blast-radius regressions
// that would otherwise need fleet-scale anomaly detection to surface.
#[cfg(test)]
mod batch_dddd_compute_token_enforcement {
    use super::*;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::state::NodeState;
    use crate::network::witness::WitnessManager;
    use crate::storage::rocks::StorageEngine;
    use std::sync::Arc;

    fn temp_state() -> Arc<NodeState> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "batch-dddd-token-enforcement-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
        std::mem::forget(tmp);
        state
    }

    /// (1) Pin the EXACT 7-key top-level envelope shape AND the nested
    /// key shapes for each sub-envelope. Using BTreeSet equality on the
    /// top-level so a silent 8th-key bloat (e.g., a new operator-diagnostic
    /// field auto-derived via `#[derive(Serialize)]` somewhere) and a
    /// missing-key regression (e.g., dropping `circulating_supply` from
    /// the envelope) both surface as set-mismatch. Per-sub-envelope key
    /// counts pinned literally so a field-add inside e.g. governance
    /// (4 → 10 status counters) surfaces here for
    /// review rather than silently shipping a wire change.
    #[tokio::test]
    async fn batch_dddd_compute_token_enforcement_emits_seven_key_envelope_with_pinned_nested_shapes() {
        use std::collections::BTreeSet;
        let state = temp_state();
        let v = compute_token_enforcement(state).await;
        let obj = v.as_object().expect("top-level must be JSON Object");

        // Top-level: exactly these 7 keys.
        let actual: BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        let expected: BTreeSet<&str> = [
            "circuit_breaker",
            "velocity",
            "acquisition",
            "vesting",
            "trust",
            "governance",
            "circulating_supply",
        ].iter().copied().collect();
        assert_eq!(
            actual, expected,
            "top-level envelope must have EXACTLY these 7 keys; any extra/missing surfaces here"
        );

        // Sub-envelopes: pin the key counts so a field add/remove surfaces.
        // circuit_breaker: {level, level_since, volume_24h, velocity_24h, velocity_multiplier} = 5
        let cb = obj["circuit_breaker"].as_object().expect("circuit_breaker is Object");
        let cb_keys: BTreeSet<&str> = cb.keys().map(|k| k.as_str()).collect();
        let cb_expected: BTreeSet<&str> = [
            "level", "level_since", "volume_24h", "velocity_24h", "velocity_multiplier",
        ].iter().copied().collect();
        assert_eq!(cb_keys, cb_expected, "circuit_breaker must have EXACTLY these 5 keys");

        // velocity: {tracked_identities, window_seconds} = 2
        let vel = obj["velocity"].as_object().expect("velocity is Object");
        let vel_keys: BTreeSet<&str> = vel.keys().map(|k| k.as_str()).collect();
        let vel_expected: BTreeSet<&str> = [
            "tracked_identities", "window_seconds",
        ].iter().copied().collect();
        assert_eq!(vel_keys, vel_expected, "velocity must have EXACTLY these 2 keys");

        // acquisition: {tracked_identities, max_rate, window_seconds, activation_threshold, limits_active} = 5
        let acq = obj["acquisition"].as_object().expect("acquisition is Object");
        let acq_keys: BTreeSet<&str> = acq.keys().map(|k| k.as_str()).collect();
        let acq_expected: BTreeSet<&str> = [
            "tracked_identities", "max_rate", "window_seconds",
            "activation_threshold", "limits_active",
        ].iter().copied().collect();
        assert_eq!(acq_keys, acq_expected, "acquisition must have EXACTLY these 5 keys");

        // vesting: {active_vestings, total_entries, duration_seconds, threshold} = 4
        let vest = obj["vesting"].as_object().expect("vesting is Object");
        let vest_keys: BTreeSet<&str> = vest.keys().map(|k| k.as_str()).collect();
        let vest_expected: BTreeSet<&str> = [
            "active_vestings", "total_entries", "duration_seconds", "threshold",
        ].iter().copied().collect();
        assert_eq!(vest_keys, vest_expected, "vesting must have EXACTLY these 4 keys");

        // trust: {tracked_identities} = 1
        let tr = obj["trust"].as_object().expect("trust is Object");
        assert_eq!(tr.len(), 1, "trust must have EXACTLY 1 key (tracked_identities)");
        assert!(tr.contains_key("tracked_identities"));

        // governance: {total_proposals, active, passed, rejected, expired,
        //              executed, cancelled, vetoed, active_delegations} = 9
        let gov = obj["governance"].as_object().expect("governance is Object");
        let gov_keys: BTreeSet<&str> = gov.keys().map(|k| k.as_str()).collect();
        let gov_expected: BTreeSet<&str> = [
            "total_proposals", "active", "passed", "rejected",
            "expired", "executed", "cancelled", "vetoed", "active_delegations",
        ].iter().copied().collect();
        assert_eq!(
            gov_keys, gov_expected,
            "governance must have EXACTLY these 9 keys (matches OPS-156 ProposalStatusCounts + active_delegations)"
        );
    }

    /// (2) Empty-state defaults: fresh tempdir state with no ledger
    /// mutations. All counters MUST be zero and the circuit breaker
    /// MUST be at "normal" level with velocity_multiplier=1.0 (the
    /// no-throttle baseline). A regression that initialized any
    /// counter to non-zero would surface as a fresh-node /token/enforcement
    /// reporting non-zero usage, breaking onboarding dashboards.
    #[tokio::test]
    async fn batch_dddd_compute_token_enforcement_empty_state_returns_normal_level_with_zero_counters() {
        let state = temp_state();
        let v = compute_token_enforcement(state).await;

        // circuit_breaker defaults: Normal level, multiplier 1.0
        assert_eq!(
            v["circuit_breaker"]["level"], "normal",
            "fresh CircuitBreaker::new() level must serialize as \"normal\" (BreakerLevel::Normal.as_str())"
        );
        assert_eq!(
            v["circuit_breaker"]["level_since"], 0.0,
            "fresh CircuitBreaker level_since must be 0.0"
        );
        assert_eq!(
            v["circuit_breaker"]["volume_24h"], 0.0,
            "fresh CircuitBreaker volume_in_window must be 0.0 (no entries)"
        );
        assert_eq!(
            v["circuit_breaker"]["velocity_24h"], 0.0,
            "velocity_24h = 0 / max(0, 1) = 0.0 on fresh node"
        );
        assert_eq!(
            v["circuit_breaker"]["velocity_multiplier"], 1.0,
            "Normal level velocity_multiplier must be 1.0 (no throttle on healthy chain)"
        );

        // velocity / acquisition / trust trackers: zero identities
        assert_eq!(v["velocity"]["tracked_identities"], 0);
        assert_eq!(v["acquisition"]["tracked_identities"], 0);
        assert_eq!(v["trust"]["tracked_identities"], 0);

        // acquisition.limits_active: false when circulating < threshold
        assert_eq!(
            v["acquisition"]["limits_active"], false,
            "limits_active must be false when circulating=0 < ACQUISITION_LIMIT_ACTIVATION"
        );

        // vesting: zero entries
        assert_eq!(v["vesting"]["active_vestings"], 0);
        assert_eq!(v["vesting"]["total_entries"], 0);

        // governance: zero across all 9 fields
        assert_eq!(v["governance"]["total_proposals"], 0);
        assert_eq!(v["governance"]["active"], 0);
        assert_eq!(v["governance"]["passed"], 0);
        assert_eq!(v["governance"]["rejected"], 0);
        assert_eq!(v["governance"]["expired"], 0);
        assert_eq!(v["governance"]["executed"], 0);
        assert_eq!(v["governance"]["cancelled"], 0);
        assert_eq!(v["governance"]["vetoed"], 0);
        assert_eq!(v["governance"]["active_delegations"], 0);

        // circulating_supply: zero on fresh ledger
        assert_eq!(v["circulating_supply"], 0);
    }

    /// (3) circulating_supply = total_supply.saturating_sub(total_staked).
    /// Three cases to pin the saturating semantics:
    /// (a) normal: supply > staked → diff = supply - staked
    /// (b) equal: supply == staked → 0
    /// (c) underflow: supply < staked → 0 (saturated, NOT wrap-around)
    /// A regression that swapped `saturating_sub` for plain `-` would
    /// panic in debug builds AND wrap to u64::MAX-N in release — silent
    /// catastrophic miscount of circulating supply on the production
    /// /token/enforcement endpoint (drives every supply-chart on every
    /// operator dashboard).
    #[tokio::test]
    async fn batch_dddd_compute_token_enforcement_circulating_supply_uses_saturating_sub_with_underflow_clamp() {
        // (a) Normal case: 1000 - 300 = 700
        {
            let state = temp_state();
            {
                let mut ledger = state.ledger.write().await;
                ledger.total_supply = 1000;
                ledger.total_staked = 300;
            }
            let v = compute_token_enforcement(state).await;
            assert_eq!(
                v["circulating_supply"], 700,
                "normal subtraction: 1000 - 300 must equal 700"
            );
        }

        // (b) Equal case: 500 - 500 = 0
        {
            let state = temp_state();
            {
                let mut ledger = state.ledger.write().await;
                ledger.total_supply = 500;
                ledger.total_staked = 500;
            }
            let v = compute_token_enforcement(state).await;
            assert_eq!(
                v["circulating_supply"], 0,
                "equal subtraction: 500 - 500 must equal 0 (not negative, not skipped)"
            );
        }

        // (c) Underflow case: 100 - 500 must saturate to 0 (NOT u64::MAX - 399)
        {
            let state = temp_state();
            {
                let mut ledger = state.ledger.write().await;
                ledger.total_supply = 100;
                ledger.total_staked = 500;
            }
            let v = compute_token_enforcement(state).await;
            assert_eq!(
                v["circulating_supply"], 0,
                "underflow case: 100 - 500 must SATURATE to 0; a regression to plain - would wrap to u64::MAX - 399"
            );
        }
    }

    /// (3b) velocity_24h = volume_24h / max(circulating, 1).
    /// Verifies the monetary-velocity ratio with known inputs: circulating=800,
    /// volume=400 → velocity_24h=0.5. Also pins the zero-circulating guard
    /// (denominator clamp to 1) via the empty-state assertion in test (2).
    #[tokio::test]
    async fn batch_dddd_compute_token_enforcement_velocity_24h_is_volume_over_circulating() {
        let state = temp_state();
        {
            let mut ledger = state.ledger.write().await;
            ledger.total_supply = 1000;
            ledger.total_staked = 200;
            // Use a far-future timestamp so the entry is always within the
            // 24-hour window regardless of wall-clock drift.
            ledger.circuit_breaker.record_volume(400, f64::MAX / 2.0);
        }
        let v = compute_token_enforcement(state).await;
        assert_eq!(v["circuit_breaker"]["volume_24h"], 400.0, "injected 400 must appear in volume_24h");
        let vel = v["circuit_breaker"]["velocity_24h"]
            .as_f64()
            .expect("velocity_24h must be a JSON number");
        assert!(
            (vel - 0.5).abs() < 1e-9,
            "velocity_24h = volume(400) / circulating(800) must equal 0.5, got {vel}"
        );
    }

    /// (4) acquisition.limits_active flips at `circ >= ACQUISITION_LIMIT_ACTIVATION`.
    /// Two cases pin the comparison operator:
    /// (a) circ = threshold - 1 → false (below)
    /// (b) circ = threshold     → true  (>= boundary, inclusive)
    /// A regression that flipped `>=` to `>` would leave the exactly-at-threshold
    /// case as false — operators reading "limits not yet active" would push
    /// past the threshold without realizing the activation point is
    /// crossed silently. Below-threshold case also catches an inverted
    /// comparison (`<=` would return true at threshold-1).
    #[tokio::test]
    async fn batch_dddd_compute_token_enforcement_acquisition_limits_active_uses_gte_comparison_at_activation_threshold() {
        use crate::accounting::acquisition::ACQUISITION_LIMIT_ACTIVATION;

        // (a) Below threshold by 1: limits_active = false
        {
            let state = temp_state();
            {
                let mut ledger = state.ledger.write().await;
                ledger.total_supply = ACQUISITION_LIMIT_ACTIVATION - 1;
                ledger.total_staked = 0;
            }
            let v = compute_token_enforcement(state).await;
            assert_eq!(
                v["acquisition"]["limits_active"], false,
                "circ = ACQUISITION_LIMIT_ACTIVATION - 1 (BELOW threshold) must give limits_active=false"
            );
            assert_eq!(
                v["circulating_supply"], ACQUISITION_LIMIT_ACTIVATION - 1,
                "cross-check: circulating_supply must equal the seeded total_supply at total_staked=0"
            );
        }

        // (b) Exactly at threshold: limits_active = true (>= is inclusive)
        {
            let state = temp_state();
            {
                let mut ledger = state.ledger.write().await;
                ledger.total_supply = ACQUISITION_LIMIT_ACTIVATION;
                ledger.total_staked = 0;
            }
            let v = compute_token_enforcement(state).await;
            assert_eq!(
                v["acquisition"]["limits_active"], true,
                "circ = ACQUISITION_LIMIT_ACTIVATION (EXACTLY at threshold) must give limits_active=true; pins >= vs >"
            );
            assert_eq!(
                v["circulating_supply"], ACQUISITION_LIMIT_ACTIVATION,
                "cross-check: circulating_supply must equal ACQUISITION_LIMIT_ACTIVATION exactly"
            );
        }
    }

    /// (5) Wire-surfaced constants must equal the LIVE crate constants —
    /// not hardcoded literals. A regression that hardcoded a value
    /// (e.g., refactor `"window_seconds": crate::accounting::velocity::VELOCITY_WINDOW_SECS`
    /// to `"window_seconds": 86400.0`) would break the live link: any
    /// future change to VELOCITY_WINDOW_SECS would silently desync the
    /// wire surface from the runtime behavior.
    ///
    /// The 6 pinned constants drive operator dashboards (window sizes,
    /// activation thresholds, vesting durations) — every account, every
    /// explorer, every audit pipeline reads these values; a hardcoded
    /// drift here would silently break every downstream consumer.
    #[tokio::test]
    async fn batch_dddd_compute_token_enforcement_exposed_constants_match_live_crate_constants() {
        use crate::accounting::acquisition::{
            ACQUISITION_LIMIT_ACTIVATION, ACQUISITION_WINDOW_SECS,
            LARGE_MINT_THRESHOLD, MAX_ACQUISITION_RATE, VESTING_DURATION_SECS,
        };
        use crate::accounting::velocity::VELOCITY_WINDOW_SECS;

        let state = temp_state();
        let v = compute_token_enforcement(state).await;

        // velocity.window_seconds == VELOCITY_WINDOW_SECS (24h in seconds = 86400)
        assert_eq!(
            v["velocity"]["window_seconds"].as_f64().unwrap(),
            VELOCITY_WINDOW_SECS,
            "velocity.window_seconds wire field must equal crate::accounting::velocity::VELOCITY_WINDOW_SECS"
        );

        // acquisition.max_rate == MAX_ACQUISITION_RATE
        assert_eq!(
            v["acquisition"]["max_rate"].as_f64().unwrap(),
            MAX_ACQUISITION_RATE,
            "acquisition.max_rate wire field must equal crate::accounting::acquisition::MAX_ACQUISITION_RATE"
        );

        // acquisition.window_seconds == ACQUISITION_WINDOW_SECS (30d in seconds)
        assert_eq!(
            v["acquisition"]["window_seconds"].as_f64().unwrap(),
            ACQUISITION_WINDOW_SECS,
            "acquisition.window_seconds wire field must equal crate::accounting::acquisition::ACQUISITION_WINDOW_SECS"
        );

        // acquisition.activation_threshold == ACQUISITION_LIMIT_ACTIVATION (1M beat in base units)
        assert_eq!(
            v["acquisition"]["activation_threshold"].as_u64().unwrap(),
            ACQUISITION_LIMIT_ACTIVATION,
            "acquisition.activation_threshold wire field must equal crate::accounting::acquisition::ACQUISITION_LIMIT_ACTIVATION"
        );

        // vesting.duration_seconds == VESTING_DURATION_SECS (365d in seconds)
        assert_eq!(
            v["vesting"]["duration_seconds"].as_f64().unwrap(),
            VESTING_DURATION_SECS,
            "vesting.duration_seconds wire field must equal crate::accounting::acquisition::VESTING_DURATION_SECS"
        );

        // vesting.threshold == LARGE_MINT_THRESHOLD (fraction-of-supply threshold, NOT the absolute MAX_SUPPLY)
        assert_eq!(
            v["vesting"]["threshold"].as_f64().unwrap(),
            LARGE_MINT_THRESHOLD,
            "vesting.threshold wire field must equal crate::accounting::acquisition::LARGE_MINT_THRESHOLD (NOT MAX_SUPPLY)"
        );
    }
}

#[cfg(test)]
mod batch_eeee_compute_recent_transactions {
    use super::*;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::state::NodeState;
    use crate::network::witness::WitnessManager;
    use crate::storage::rocks::StorageEngine;
    use std::sync::Arc;

    fn temp_state() -> Arc<NodeState> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "batch-eeee-recent-tx-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
        std::mem::forget(tmp);
        state
    }

    /// (1) Pin the EXACT 2-key top-level envelope shape on empty state.
    /// Using BTreeSet equality so a silent 3rd-key bloat (e.g., adding a
    /// `cursor` or `next_offset` for pagination) and a missing-key
    /// regression (e.g., dropping `count`) both surface as set-mismatch.
    /// Account/explorer clients parse this wire and silent additions break
    /// strict deserializers (Rust serde `deny_unknown_fields`).
    #[tokio::test]
    async fn batch_eeee_compute_recent_transactions_emits_two_key_envelope_on_empty_state() {
        use std::collections::BTreeSet;
        let state = temp_state();
        let v = compute_recent_transactions(state, 20).await.expect("compute_recent_transactions ok");
        let obj = v.as_object().expect("top-level must be JSON Object");
        let actual: BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        let expected: BTreeSet<&str> = ["transactions", "count"].iter().copied().collect();
        assert_eq!(
            actual, expected,
            "top-level envelope must have EXACTLY these 2 keys; any extra/missing surfaces here"
        );
    }

    /// (2) On empty state the `transactions` field must be an empty JSON
    /// Array (NOT null, NOT missing, NOT an Object). Account UIs iterate
    /// `tx_list.transactions.map(...)` and a null/missing field crashes
    /// the iterator on first-load. Pinning this also catches an
    /// accidental migration to `Option<Vec<...>>` somewhere upstream.
    #[tokio::test]
    async fn batch_eeee_transactions_field_is_empty_array_not_null_on_empty_state() {
        let state = temp_state();
        let v = compute_recent_transactions(state, 20).await.expect("compute_recent_transactions ok");
        assert!(
            v["transactions"].is_array(),
            "transactions field must be JSON Array; got {:?}",
            v["transactions"]
        );
        assert_eq!(
            v["transactions"].as_array().unwrap().len(),
            0,
            "transactions array must be empty on empty state"
        );
        assert!(
            !v["transactions"].is_null(),
            "transactions must NOT be JSON null on empty state"
        );
    }

    /// (3) On empty state `count` must be a JSON Number (u64) with value
    /// 0, NOT a string "0", NOT JSON null. Account code does
    /// `body.count as int` and a string-typed field silently breaks the
    /// cast. Pin both the type predicate (`is_u64`) and the value (0).
    #[tokio::test]
    async fn batch_eeee_count_field_is_u64_zero_not_string_or_null_on_empty_state() {
        let state = temp_state();
        let v = compute_recent_transactions(state, 20).await.expect("compute_recent_transactions ok");
        assert!(
            v["count"].is_u64(),
            "count field must be JSON Number (u64); got {:?}",
            v["count"]
        );
        assert_eq!(
            v["count"].as_u64().unwrap(),
            0,
            "count must be 0 on empty state"
        );
        assert!(!v["count"].is_string(), "count must NOT be String");
        assert!(!v["count"].is_null(), "count must NOT be null");
    }

    /// (4) Cross-field invariant: `count` must always equal
    /// `transactions.len()`. Pin this so a future refactor that returns
    /// a paginated subset of `transactions` while keeping `count` at the
    /// total (or vice versa) immediately surfaces — the invariant has
    /// always been "count IS the array length", and clients depend on it.
    /// Tested on empty state (both 0); a non-empty fixture would
    /// require RocksDB-seeded ledger records (deferred to a future slice
    /// — empty-state invariant pinning is the load-bearing axis here).
    #[tokio::test]
    async fn batch_eeee_count_equals_transactions_len_invariant() {
        let state = temp_state();
        let v = compute_recent_transactions(state, 20).await.expect("compute_recent_transactions ok");
        let count = v["count"].as_u64().expect("count is u64");
        let arr_len = v["transactions"].as_array().expect("transactions is Array").len() as u64;
        assert_eq!(
            count, arr_len,
            "count ({count}) must equal transactions.len() ({arr_len}) — wire invariant"
        );
    }

    /// (5) Determinism + limit-edge robustness combined: two consecutive
    /// calls on the same empty state must return byte-identical
    /// serialized JSON (no clock-driven fields, no random ordering).
    /// Additionally, `limit=0` and `limit=usize::MAX` must both produce
    /// the well-formed envelope without panic — the in-function clamp
    /// `limit.min(100)` and `scan_limit = limit * 10` must not overflow
    /// or short-circuit error on the edges.
    #[tokio::test]
    async fn batch_eeee_determinism_and_limit_edges_no_panic_no_drift() {
        let state = temp_state();

        // (a) Determinism: two calls with limit=20 produce byte-identical bytes.
        let v1 = compute_recent_transactions(state.clone(), 20).await.expect("call 1 ok");
        let v2 = compute_recent_transactions(state.clone(), 20).await.expect("call 2 ok");
        let b1 = serde_json::to_vec(&v1).expect("ser 1");
        let b2 = serde_json::to_vec(&v2).expect("ser 2");
        assert_eq!(
            b1, b2,
            "two consecutive calls on empty state must produce byte-identical JSON"
        );

        // (b) limit=0 → still a valid envelope with count=0 (the `scan_limit = 0 * 10 = 0`
        // path must not error out; the `recent_ids` scan returns Ok(empty) and the loop
        // is a no-op).
        let v0 = compute_recent_transactions(state.clone(), 0).await.expect("limit=0 must not error");
        assert_eq!(v0["count"].as_u64().unwrap(), 0, "limit=0 → count=0");
        assert_eq!(v0["transactions"].as_array().unwrap().len(), 0, "limit=0 → empty array");

        // (c) limit=usize::MAX → in-function clamp to 100 (line 591), then scan_limit = 100*10 = 1000.
        // Must not overflow (usize::MAX * 10 would wrap on 64-bit) — the clamp prevents that.
        // Empty state still yields count=0.
        let vmax = compute_recent_transactions(state.clone(), usize::MAX).await.expect("limit=MAX must not panic");
        assert_eq!(vmax["count"].as_u64().unwrap(), 0, "limit=MAX on empty state → count=0");
        assert_eq!(
            vmax["transactions"].as_array().unwrap().len(),
            0,
            "limit=MAX on empty state → empty array"
        );
    }
}

#[cfg(test)]
mod batch_gggg_compute_tx_history {
    use super::*;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::state::NodeState;
    use crate::network::witness::WitnessManager;
    use crate::storage::rocks::StorageEngine;
    use std::sync::Arc;

    fn temp_state() -> Arc<NodeState> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "batch-gggg-tx-history-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
        std::mem::forget(tmp);
        state
    }

    /// (1) Pin the EXACT 5-key top-level envelope shape on empty state.
    /// Using BTreeSet equality so a silent 6th-key bloat (e.g., adding
    /// `next_offset` for pagination cursors, or a `has_more` boolean
    /// derived from scan_limit hit) and a missing-key regression
    /// (e.g., dropping `offset` after a refactor toward cursor-based
    /// pagination) both surface as set-mismatch. Account/explorer code
    /// parses this wire and any silent addition breaks strict deserializers
    /// (Rust serde `deny_unknown_fields`); a missing field breaks the
    /// `node.query_history` migration target named in the doc-comment.
    #[tokio::test]
    async fn batch_gggg_compute_tx_history_emits_five_key_envelope_on_empty_state() {
        use std::collections::BTreeSet;
        let state = temp_state();
        let v = compute_tx_history(state, "abcd".into(), 50, 0)
            .await
            .expect("compute_tx_history ok");
        let obj = v.as_object().expect("top-level must be JSON Object");
        let actual: BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        let expected: BTreeSet<&str> = [
            "identity", "transactions", "total", "limit", "offset",
        ].iter().copied().collect();
        assert_eq!(
            actual, expected,
            "top-level envelope must have EXACTLY these 5 keys; any extra/missing surfaces here"
        );
    }

    /// (2) On empty state the `transactions` field must be an empty JSON
    /// Array (NOT null, NOT missing, NOT an Object), and `total` must be
    /// a JSON Number (u64) with value 0 (NOT a string "0", NOT JSON null).
    /// Account UIs iterate `body.transactions.map(...)` and do
    /// `body.total as int` — a null/missing array crashes the iterator
    /// on first-load, and a string-typed total silently breaks the cast.
    /// Both pins also catch an accidental migration to `Option<Vec<...>>`
    /// or `Option<u64>` somewhere upstream.
    #[tokio::test]
    async fn batch_gggg_transactions_field_is_empty_array_total_is_u64_zero_on_empty_state() {
        let state = temp_state();
        let v = compute_tx_history(state, "deadbeef".into(), 50, 0)
            .await
            .expect("compute_tx_history ok");
        assert!(
            v["transactions"].is_array(),
            "transactions field must be JSON Array; got {:?}",
            v["transactions"]
        );
        assert_eq!(
            v["transactions"].as_array().unwrap().len(),
            0,
            "transactions array must be empty on empty state"
        );
        assert!(
            !v["transactions"].is_null(),
            "transactions must NOT be JSON null on empty state"
        );
        assert!(
            v["total"].is_u64(),
            "total field must be JSON Number (u64); got {:?}",
            v["total"]
        );
        assert_eq!(
            v["total"].as_u64().unwrap(),
            0,
            "total must be 0 on empty state"
        );
        assert!(!v["total"].is_string(), "total must NOT be String");
        assert!(!v["total"].is_null(), "total must NOT be null");
    }

    /// (3) The `identity` field must be echoed back BYTE-FOR-BYTE as
    /// supplied — no casing normalization, no whitespace trim, no
    /// prefix-padding, no hex-canonicalization. Pin three orthogonal
    /// variants: (a) standard lowercase hex; (b) mixed-case hex (would
    /// catch a silent `.to_lowercase()` introduction); (c) non-hex
    /// string (would catch a silent hex-validation early-return that
    /// rewrites the field). The identity-echo contract is load-bearing
    /// because account clients use the echoed value as the React key in
    /// transaction-list rendering — a silent case change breaks
    /// React's reconciliation and double-renders the list.
    #[tokio::test]
    async fn batch_gggg_identity_field_echoed_verbatim_across_three_casing_variants() {
        let state = temp_state();

        // (a) standard lowercase hex (the canonical wire format)
        let v_low = compute_tx_history(state.clone(), "abc123def456".into(), 50, 0)
            .await
            .expect("compute_tx_history ok (lowercase)");
        assert_eq!(
            v_low["identity"], "abc123def456",
            "lowercase identity must be echoed verbatim"
        );

        // (b) mixed-case hex — would catch a silent .to_lowercase() introduction
        let v_mix = compute_tx_history(state.clone(), "AbC123dEF456".into(), 50, 0)
            .await
            .expect("compute_tx_history ok (mixed-case)");
        assert_eq!(
            v_mix["identity"], "AbC123dEF456",
            "mixed-case identity must be echoed verbatim (NO casing normalization)"
        );

        // (c) non-hex string — would catch a silent hex-validation rewrite
        let v_nonhex = compute_tx_history(state.clone(), "not-a-hex-string!".into(), 50, 0)
            .await
            .expect("compute_tx_history ok (non-hex)");
        assert_eq!(
            v_nonhex["identity"], "not-a-hex-string!",
            "non-hex identity must be echoed verbatim — no validation rewrites the field"
        );
    }

    /// (4) The in-function clamp `limit = limit.min(200)` at
    /// `routes/ledger.rs:500` must (a) clamp the ECHOED `limit` field
    /// in the envelope to 200 (NOT preserve the raw input), and (b)
    /// the downstream `scan_limit = (limit + offset) * 50` arithmetic
    /// must not panic on `limit=usize::MAX, offset=0` — the clamp at
    /// line 500 prevents the wrap. Two orthogonal sub-axes pinned:
    /// (a) input limit at the clamp threshold (200) echoes 200; (b)
    /// input limit AT usize::MAX echoes 200 and produces well-formed
    /// envelope without panic. The third axis (input below cap) is
    /// already pinned by test (1) at limit=50. Catches a silent
    /// removal of the `.min(200)` clamp (which would expose the
    /// scan_limit overflow on hostile clients) AND a silent change
    /// of the clamp threshold (e.g., 200 → 500 doubles the worst-case
    /// scan time without a wire-surface flag).
    #[tokio::test]
    async fn batch_gggg_limit_clamp_to_200_pins_clamp_threshold_and_overflow_floor() {
        let state = temp_state();

        // (a) limit exactly at clamp threshold — echo must be 200
        let v_at = compute_tx_history(state.clone(), "abcd".into(), 200, 0)
            .await
            .expect("limit=200 must succeed");
        assert_eq!(
            v_at["limit"].as_u64().unwrap(),
            200,
            "limit=200 (exactly at clamp threshold) must echo 200"
        );

        // (b) limit at usize::MAX — clamp prevents (MAX+0)*50 overflow, echoes 200
        let v_max = compute_tx_history(state.clone(), "abcd".into(), usize::MAX, 0)
            .await
            .expect("limit=usize::MAX must not panic (clamp at line 500 prevents scan_limit overflow)");
        assert_eq!(
            v_max["limit"].as_u64().unwrap(),
            200,
            "limit=usize::MAX must echo CLAMPED value 200, NOT the raw input"
        );
        assert_eq!(
            v_max["total"].as_u64().unwrap(),
            0,
            "limit=usize::MAX on empty state still yields total=0 (loop is no-op)"
        );
        assert_eq!(
            v_max["transactions"].as_array().unwrap().len(),
            0,
            "limit=usize::MAX on empty state yields empty transactions array"
        );

        // (c) offset at usize::MAX — the OTHER scan_limit operand. offset is
        // peer-supplied and uncapped (echoed verbatim per test (5)(b)), so the
        // overflow guard here is the saturating `(limit+offset)*50` math, NOT a
        // clamp. Must not panic (release sets overflow-checks=true); a revert to
        // `(limit + offset) * 50` would panic this case under test overflow-checks.
        let v_off_max = compute_tx_history(state.clone(), "abcd".into(), 50, usize::MAX)
            .await
            .expect("offset=usize::MAX must not panic (saturating scan_limit math)");
        assert_eq!(
            v_off_max["transactions"].as_array().unwrap().len(),
            0,
            "offset=usize::MAX on empty state yields empty transactions array"
        );
    }

    /// (5) Cross-field invariants on empty state:
    /// (a) `total` must equal `transactions.len()` — the pre-pagination
    ///     total is identical to the post-pagination page length when
    ///     no records exist (both 0); a future refactor that returns
    ///     `total = unfiltered_count` while pagination clips the array
    ///     would silently break this invariant on empty state too.
    /// (b) `offset` must be echoed verbatim from the input — pin both
    ///     offset=0 and offset=999 (large value, no clamp expected).
    ///     A silent introduction of `offset = offset.min(some_cap)`
    ///     would surface here.
    /// (c) Determinism: two consecutive calls on the same empty state
    ///     must return byte-identical serialized JSON — no clock-driven
    ///     fields (no `as_of` timestamp), no random ordering, no UUID.
    #[tokio::test]
    async fn batch_gggg_total_offset_determinism_cross_field_invariants_on_empty_state() {
        let state = temp_state();

        // (a) total == transactions.len() on empty state (both 0)
        let v0 = compute_tx_history(state.clone(), "abcd".into(), 50, 0)
            .await
            .expect("compute_tx_history ok");
        let total = v0["total"].as_u64().expect("total is u64");
        let arr_len = v0["transactions"].as_array().expect("transactions is Array").len() as u64;
        assert_eq!(
            total, arr_len,
            "total ({total}) must equal transactions.len() ({arr_len}) on empty state — wire invariant"
        );

        // (b) offset echoed verbatim — both small (0) and large (999) inputs
        assert_eq!(
            v0["offset"].as_u64().unwrap(),
            0,
            "offset=0 must be echoed as 0"
        );
        let v_off = compute_tx_history(state.clone(), "abcd".into(), 50, 999)
            .await
            .expect("compute_tx_history ok (offset=999)");
        assert_eq!(
            v_off["offset"].as_u64().unwrap(),
            999,
            "offset=999 must be echoed verbatim — NO silent clamp to scan_limit ceiling"
        );

        // (c) Determinism: two calls with identical inputs produce byte-identical JSON
        let v1 = compute_tx_history(state.clone(), "abcd".into(), 50, 0)
            .await
            .expect("call 1 ok");
        let v2 = compute_tx_history(state.clone(), "abcd".into(), 50, 0)
            .await
            .expect("call 2 ok");
        let b1 = serde_json::to_vec(&v1).expect("ser 1");
        let b2 = serde_json::to_vec(&v2).expect("ser 2");
        assert_eq!(
            b1, b2,
            "two consecutive calls on empty state must produce byte-identical JSON — no clock-driven fields"
        );
    }

    /// Minimal valid `ValidationRecord` for seeding RocksDB so the collection
    /// loop in `compute_tx_history` reaches its break line. Mirrors the
    /// `stub_record` fixture in `explorer/tests.rs` field-for-field.
    fn compute_tx_history_test_record(id: &str) -> crate::record::ValidationRecord {
        use crate::record::{Classification, ValidationRecord};
        use std::collections::BTreeMap;
        ValidationRecord {
            id: id.to_string(),
            version: crate::wire::WIRE_VERSION,
            content_hash: vec![0u8; 32],
            creator_public_key: vec![0xAA; 1952],
            timestamp: 1_700_000_000.0,
            parents: vec![],
            classification: Classification::Public,
            metadata: BTreeMap::new(),
            signature: Some(vec![0xBB; 3293]),
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: vec![],
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        }
    }

    /// (6) REGRESSION — live panic the empty-state tests above cannot catch.
    /// Tests (1)-(5) all run on EMPTY state where no record matches, so the
    /// collection loop never pushes and the `results.len() >= limit + offset`
    /// break in compute_tx_history is NEVER evaluated. A `limit + offset` overflow
    /// hid behind that blind spot: on a NON-empty node, a matching record plus
    /// a hostile `offset` near usize::MAX makes the loop push, evaluate
    /// `limit.min(200) + offset`, and panic under overflow-checks=true (both
    /// debug and the release profile). Seed ONE matching Transfer so the loop
    /// body is reached, then call with offset=usize::MAX. With the saturating
    /// fix this yields the well-formed empty "past-the-end" page; a revert to
    /// `limit + offset` panics this test. (Sibling of the scan_limit saturating
    /// fix in test (4)(c), which the empty-state setup could not reach here.)
    #[tokio::test]
    async fn batch_gggg_offset_max_with_matching_record_does_not_panic() {
        let state = temp_state();
        let victim = "1111111111111111111111111111111111111111111111111111111111111111";

        // A Transfer to `victim` makes `involved` true via the `to == identity2`
        // arm — no need to forge the creator hash to reach the break line.
        let mut rec = compute_tx_history_test_record("xz-offset-max-001");
        rec.metadata = crate::accounting::types::transfer_metadata(1_000, victim, None);
        state.rocks.put_record(&rec.id, &rec).expect("put_record");

        // Sanity: offset=0 surfaces the record — proves this fixture actually
        // drives the loop into the `limit + offset` break line, unlike (1)-(5).
        let v0 = compute_tx_history(state.clone(), victim.into(), 50, 0)
            .await
            .expect("offset=0 must succeed");
        assert_eq!(
            v0["total"].as_u64().unwrap(),
            1,
            "seeded Transfer to victim must surface (confirms loop reached the break line)"
        );

        // The fix: offset=usize::MAX with a match present must NOT panic.
        let v_max = compute_tx_history(state.clone(), victim.into(), 50, usize::MAX)
            .await
            .expect("offset=usize::MAX must NOT panic — saturating_add on the limit+offset break");
        assert_eq!(
            v_max["transactions"].as_array().unwrap().len(),
            0,
            "offset=usize::MAX → empty past-the-end page (skip(MAX) drops the match)"
        );
        assert_eq!(
            v_max["offset"].as_u64().unwrap(),
            u64::MAX,
            "offset still echoed verbatim (usize::MAX), NOT clamped"
        );
    }
}



// ─── slot_next_nonce orthogonal pins ───────────────────────────────────────
//
// `slot_next_nonce` (token.rs:991) is the only handler in this module whose
// validation-and-storage-lookup flow has ZERO direct unit coverage. It is on
// the hot path for every account `/rpc/transfer`, `/rpc/stake`, `/rpc/stamp`,
// `/rpc/xzone_*` flow — clients call it first to discover the next nonce, so
// a regression here breaks ALL outgoing token activity across the cluster.
//
// The handler fans into 5 independent decision axes that any zero-coverage
// state hides:
//   (1) length validation       — len(account.trim()) must be exactly 64
//   (2) hex-alphabet validation — every char must match `[0-9a-fA-F]`
//   (3) case normalization      — UPPERCASE input must echo back lowercase
//   (4) storage-empty floor     — `max_slot_nonce_for_account → None` ⇒ 1
//   (5) self-identity branch    — when account_lc == self_hash, the in-memory
//                                 `slot_nonce_self` atomic is consulted via
//                                 max(storage_next, atomic_self). For any
//                                 other account, the atomic is NEVER read.
// Plus the wire-envelope key set: exactly `{account, next_nonce}`, no more,
// no less. Account code (`/rpc/transfer` body builder) deserializes with
// `next_nonce: u64` against a strict shape; a silent third key would break
// `deny_unknown_fields` clients, a missing key would crash the builder.
#[cfg(test)]
mod batch_fffff_slot_next_nonce {
    use super::*;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::state::NodeState;
    use crate::network::witness::WitnessManager;
    use crate::storage::rocks::StorageEngine;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    fn temp_state() -> Arc<NodeState> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "batch-fffff-slot-next-nonce-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(
            StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
        );
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
        std::mem::forget(tmp);
        state
    }

    /// Build a 64-char distinct-from-self hex string. Picks a fixed pattern
    /// (all 'a') unless the node's own identity hash happens to also be all
    /// 'a' (probability ~ 16^-64). Used by all `other_account` axes to keep
    /// them away from the self-identity branch (axis 5).
    fn other_hex_64(state: &Arc<NodeState>) -> String {
        let candidate = "a".repeat(64);
        let self_hash = crate::crypto::hash::sha3_256_hex(&state.identity.public_key);
        if candidate == self_hash {
            // Astronomically improbable fallback for the all-'a' collision.
            "b".repeat(64)
        } else {
            candidate
        }
    }

    /// (1) Length-validation REJECT axis (under-cap). A 63-char input must
    /// hit the first guard and return Wire(...) with the actual count in
    /// the message — operator dashboards parse the count to surface the
    /// most common account-side malformed-hash bug ("user pasted 63 chars
    /// from a clipboard truncated by a UI bug"). The error msg's "got N
    /// chars" phrasing is load-bearing — a regression that swapped to a
    /// terse "bad length" would silently break operator runbooks.
    #[tokio::test]
    async fn batch_fffff_slot_next_nonce_under_64_chars_rejects_with_wire_error_naming_actual_count() {
        let state = temp_state();
        let result = super::slot_next_nonce(
            axum::extract::State(state.clone()),
            axum::extract::Query(NextNonceQuery { account: "a".repeat(63) }),
        )
        .await;
        let err = match result {
            Ok(_) => panic!("under-64-char account MUST reject"),
            Err(app) => app.0,
        };
        let msg = match err {
            ElaraError::Wire(s) => s,
            other => panic!("expected Wire error, got {:?}", other),
        };
        assert!(msg.contains("64-char hex"), "msg must name the 64-char contract: {msg}");
        assert!(msg.contains("got 63 chars"), "msg must echo the actual count (63): {msg}");
    }

    /// (1b) Length-validation REJECT axis (over-cap). A 65-char input must
    /// hit the same first guard. The two-sided length check is one branch
    /// in code (`!= 64`) but two pathologies in the wild — paste-bug
    /// truncation vs. paste-bug duplication. Pin both ends so a refactor
    /// to `>= 64` (silent accept of long input → potential storage-side
    /// prefix-scan blow-up) surfaces.
    #[tokio::test]
    async fn batch_fffff_slot_next_nonce_over_64_chars_rejects_with_wire_error_naming_actual_count() {
        let state = temp_state();
        let result = super::slot_next_nonce(
            axum::extract::State(state.clone()),
            axum::extract::Query(NextNonceQuery { account: "a".repeat(65) }),
        )
        .await;
        let err = match result {
            Ok(_) => panic!("over-64-char account MUST reject"),
            Err(app) => app.0,
        };
        let msg = match err {
            ElaraError::Wire(s) => s,
            other => panic!("expected Wire error, got {:?}", other),
        };
        assert!(msg.contains("got 65 chars"), "msg must echo the actual count (65): {msg}");
    }

    /// (2) Hex-alphabet validation. A 64-char input with a SINGLE non-hex
    /// char (e.g., 'g') passes the length gate but must fail the hex gate.
    /// The two-stage validation is critical because a length-only check
    /// would let RocksDB receive a non-hex prefix scan — silently empty
    /// result, no error reported, would confuse the account into spinning
    /// on a non-existent account. Error msg's "valid hex (0-9, a-f)"
    /// phrasing names the alphabet; a regression to "bad input" hides
    /// the actionable hint.
    #[tokio::test]
    async fn batch_fffff_slot_next_nonce_non_hex_char_rejected_with_alphabet_phrase_in_wire_message() {
        let state = temp_state();
        // 63 'a's + one 'g' (non-hex). Length is 64 → passes axis 1.
        let mut bad = "a".repeat(63);
        bad.push('g');
        assert_eq!(bad.len(), 64);
        let result = super::slot_next_nonce(
            axum::extract::State(state.clone()),
            axum::extract::Query(NextNonceQuery { account: bad }),
        )
        .await;
        let err = match result {
            Ok(_) => panic!("non-hex char MUST reject"),
            Err(app) => app.0,
        };
        let msg = match err {
            ElaraError::Wire(s) => s,
            other => panic!("expected Wire error, got {:?}", other),
        };
        assert!(msg.contains("valid hex"), "msg must name the alphabet: {msg}");
        assert!(msg.contains("0-9, a-f"), "msg must enumerate the alphabet: {msg}");
    }

    /// (3) Empty-storage floor for OTHER accounts. A fresh node's storage
    /// has zero `max_slot_nonce_for_account` results for any account, and
    /// the handler's `.unwrap_or(1)` MUST surface 1 — NOT 0 (Protocol
    /// nonces are 1-indexed, a 0 floor would race the first real record
    /// at nonce 1) and NOT crash. This axis stays on the OTHER-account
    /// branch (axis 5 covers self-identity) so the atomic-bypass code
    /// path is dormant.
    #[tokio::test]
    async fn batch_fffff_slot_next_nonce_empty_storage_other_account_returns_one_as_one_indexed_floor() {
        let state = temp_state();
        let account = other_hex_64(&state);
        let result = super::slot_next_nonce(
            axum::extract::State(state.clone()),
            axum::extract::Query(NextNonceQuery { account: account.clone() }),
        )
        .await;
        let result = match result {
            Ok(j) => j,
            Err(_) => panic!("well-formed query MUST succeed"),
        };
        let body = result.0;
        assert_eq!(
            body["next_nonce"].as_u64(),
            Some(1u64),
            "empty-storage floor MUST be 1, not 0 (Protocol nonces are 1-indexed)"
        );
        assert_eq!(
            body["account"].as_str(),
            Some(account.as_str()),
            "echo MUST match input verbatim on the all-lowercase path"
        );
    }

    /// (4) Case-normalization axis. UPPERCASE hex input is mathematically
    /// equivalent to lowercase but the storage layer is byte-keyed —
    /// without normalization the account would see "no records at
    /// 0xAB..." even when 0xab... has records. The handler calls
    /// `.to_ascii_lowercase()` before both the storage lookup and the
    /// echo field; both must use the lowercase form. Pin BOTH: (a) the
    /// echo is lowercase even though the input was uppercase, AND (b) the
    /// next_nonce computed equals the all-lowercase equivalent (here
    /// both = 1 on empty storage, but the SAME storage_next result must
    /// flow through both paths — which we sanity-check by comparing
    /// against an explicit lowercase round-trip).
    #[tokio::test]
    async fn batch_fffff_slot_next_nonce_uppercase_hex_normalized_to_lowercase_in_echo_and_storage_lookup() {
        let state = temp_state();
        // Build an UPPERCASE 64-char hex string that is distinct from the
        // self-identity hash (so we stay on the other-account branch).
        let lower = other_hex_64(&state);
        let upper: String = lower.chars().map(|c| c.to_ascii_uppercase()).collect();
        assert_ne!(lower, upper, "precondition: lower != upper (some chars must be A-F class)");

        let r_upper = super::slot_next_nonce(
            axum::extract::State(state.clone()),
            axum::extract::Query(NextNonceQuery { account: upper.clone() }),
        )
        .await;
        let r_upper = match r_upper {
            Ok(j) => j,
            Err(_) => panic!("uppercase hex must pass the alphabet check"),
        };
        let body_upper = r_upper.0;
        assert_eq!(
            body_upper["account"].as_str(),
            Some(lower.as_str()),
            "echo MUST be lowercase even when input was uppercase"
        );

        let r_lower = super::slot_next_nonce(
            axum::extract::State(state.clone()),
            axum::extract::Query(NextNonceQuery { account: lower.clone() }),
        )
        .await;
        let r_lower = match r_lower {
            Ok(j) => j,
            Err(_) => panic!("lowercase round-trip control"),
        };
        let body_lower = r_lower.0;
        assert_eq!(
            body_upper["next_nonce"], body_lower["next_nonce"],
            "next_nonce MUST be case-insensitive — same storage lookup"
        );
    }

    /// (5) Self-identity atomic-bypass axis. When the queried account ==
    /// sha3_256(self.identity.public_key), the handler MUST consult the
    /// in-memory `slot_nonce_self` atomic and return `max(storage_next,
    /// atomic_self)`. Empty storage path gives storage_next=1; storing
    /// atomic_self=42 before the call must surface 42 in the response.
    /// A regression that dropped the self-branch (just returned
    /// storage_next) would silently issue stale-nonce values to local
    /// tooling — every locally-created record would race against the
    /// next storage flush.
    #[tokio::test]
    async fn batch_fffff_slot_next_nonce_self_identity_takes_max_of_storage_floor_and_atomic_self() {
        let state = temp_state();
        let self_hash = crate::crypto::hash::sha3_256_hex(&state.identity.public_key);

        // Set atomic_self to a value strictly greater than the storage
        // floor (1) so the max-bypass is what surfaces.
        state.slot_nonce_self.store(42, Ordering::Release);

        let r = super::slot_next_nonce(
            axum::extract::State(state.clone()),
            axum::extract::Query(NextNonceQuery { account: self_hash.clone() }),
        )
        .await;
        let r = match r {
            Ok(j) => j,
            Err(_) => panic!("self-identity well-formed query MUST succeed"),
        };
        let body = r.0;
        assert_eq!(
            body["next_nonce"].as_u64(),
            Some(42u64),
            "self-identity branch MUST surface atomic value (42) > storage floor (1)"
        );

        // Symmetric: ANOTHER account with the same atomic state must
        // surface only storage_next (1) — proves the atomic is NOT read
        // for other-account queries.
        let other = other_hex_64(&state);
        assert_ne!(other, self_hash, "precondition: other != self");
        let r2 = super::slot_next_nonce(
            axum::extract::State(state.clone()),
            axum::extract::Query(NextNonceQuery { account: other }),
        )
        .await;
        let r2 = match r2 {
            Ok(j) => j,
            Err(_) => panic!("other-account well-formed query MUST succeed"),
        };
        let body2 = r2.0;
        assert_eq!(
            body2["next_nonce"].as_u64(),
            Some(1u64),
            "other-account branch MUST NOT read slot_nonce_self atomic (would return 42 if it did)"
        );
    }

    /// (6) Envelope contract. The response MUST be exactly the 2-key
    /// envelope `{account, next_nonce}` — no third key, no fourth key,
    /// no metadata bloat. Wallets parse with strict deserializers; a
    /// silent third key (e.g., a "version" stamp added during a routes
    /// refactor) would break `deny_unknown_fields` clients without any
    /// loud signal. Use BTreeSet equality so both "extra key added" and
    /// "key dropped" surface as set-mismatch.
    #[tokio::test]
    async fn batch_fffff_slot_next_nonce_envelope_pins_exactly_two_keys_account_and_next_nonce() {
        use std::collections::BTreeSet;
        let state = temp_state();
        let account = other_hex_64(&state);
        let r = super::slot_next_nonce(
            axum::extract::State(state.clone()),
            axum::extract::Query(NextNonceQuery { account }),
        )
        .await;
        let r = match r {
            Ok(j) => j,
            Err(_) => panic!("well-formed query MUST succeed"),
        };
        let body = r.0;
        let obj = body.as_object().expect("top-level MUST be JSON Object");
        let actual: BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        let expected: BTreeSet<&str> =
            ["account", "next_nonce"].iter().copied().collect();
        assert_eq!(
            actual, expected,
            "envelope MUST be exactly {{account, next_nonce}} — extra/missing keys surface here"
        );
    }

    /// (7) JSON-type discipline. `account` MUST be a JSON String (not a
    /// number, not an array) and `next_nonce` MUST be a JSON Number /
    /// u64 (not a string "1", not a JSON null). Wallets do
    /// `body.next_nonce as u64 + 1` for nonce sequencing — a string-
    /// typed next_nonce silently breaks the cast, and a null surfaces
    /// as undefined-behavior in arithmetic. Pin both types in one axis.
    #[tokio::test]
    async fn batch_fffff_slot_next_nonce_json_type_discipline_string_account_u64_next_nonce() {
        let state = temp_state();
        let account = other_hex_64(&state);
        let r = super::slot_next_nonce(
            axum::extract::State(state.clone()),
            axum::extract::Query(NextNonceQuery { account: account.clone() }),
        )
        .await;
        let r = match r {
            Ok(j) => j,
            Err(_) => panic!("well-formed query MUST succeed"),
        };
        let body = r.0;
        assert!(
            body["account"].is_string(),
            "account MUST be JSON String, got: {:?}",
            body["account"]
        );
        assert!(
            body["next_nonce"].is_u64(),
            "next_nonce MUST be JSON Number / u64, got: {:?}",
            body["next_nonce"]
        );
    }
}
