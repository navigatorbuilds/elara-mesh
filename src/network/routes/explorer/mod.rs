//! Explorer route handlers: /account/{id}, /record/{id}, /validate_address/{addr},
//! /network, /dag/*, /epochs, /consensus/*, /zones, /rewards, /witness/*,
//! /governance/*, /disputes, /challenges, /proofs/*, /itc, /peers/reputation.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::Json;

use crate::ZoneId;
use crate::errors::ElaraError;
use crate::storage::Storage;
use crate::record::Classification;
use crate::accounting::types::{
    creator_identity_hash, extract_ledger_op, BASE_UNITS_PER_BEAT, MAX_SUPPLY,
};
use crate::accounting::validate;

use crate::network::state::NodeState;
use crate::network::LockRecover;
use crate::network::RwLockRecover;

use super::super::server::{AppError, format_op};

// ─── /account/{identity} ─────────────────────────────────────────────────────

/// Compute `/account/{identity}` payload. Shared between the axum handler
/// and the PQ-transport router so accounts querying account state over PQ
/// get byte-for-byte the same JSON shape.
pub(crate) async fn compute_account_detail(
    state: Arc<NodeState>,
    identity: String,
) -> serde_json::Value {
    let ledger = state.ledger.read().await;
    let acct = ledger.account(&identity);
    let active_stakes: Vec<serde_json::Value> = ledger.stakes_for(&identity).iter().map(|s| {
        serde_json::json!({
            "record_id": s.record_id,
            "amount": s.amount,
            "purpose": s.purpose,
            "timestamp": s.timestamp,
        })
    }).collect();

    serde_json::json!({
        "identity": identity,
        "available": acct.available,
        "staked": acct.staked,
        "total": acct.total(),
        "tx_count": acct.tx_count,
        "last_active": acct.last_active,
        "active_stakes": active_stakes,
        "exists": ledger.accounts.contains_key(&identity),
    })
}

/// Axum adapter — thin wrapper around [`compute_account_detail`].
pub async fn account_detail(
    State(state): State<Arc<NodeState>>,
    AxumPath(identity): AxumPath<String>,
) -> Json<serde_json::Value> {
    Json(compute_account_detail(state, identity).await)
}

// ─── /proof/account/{identity} ───────────────────────────────────────────────
//
// Light-client state proof. Flushes any pending dirty SMT leaves so the
// returned proof is consistent with current ledger state, then returns the
// account's leaf + Merkle siblings against the current tree root. A light
// node recomputes the root from (state_hash, siblings) and compares it to
// the root signed in the latest epoch seal.
//
// @spec Protocol §11.12 (light client verification)
// @spec MESH-BFT Phase 3 Stage 2C

/// Compute `/proof/account/{identity}` payload. Shared between the axum
/// handler and the PQ-transport router so light clients polling over PQ get
/// byte-for-byte the same JSON shape they parse today over HTTPS
///.
pub(crate) async fn compute_account_proof(
    state: Arc<NodeState>,
    identity: String,
) -> crate::errors::Result<serde_json::Value> {
    // Decode identity hex → 32-byte account id (SHA3-256 of public key).
    // Client input validation → ElaraError::Wire so AppError::into_response maps
    // it to HTTP 400 (Bad Request), not the 500 that ElaraError::Network falls
    // through to. A malformed identity is the caller's error, not a server fault;
    // 500-on-bad-input pollutes error-rate monitoring and reads as instability to
    // a first-contact reviewer. Matches the sibling /records/by-hash hex guard.
    let id_bytes = hex::decode(&identity)
        .map_err(|_| ElaraError::Wire(format!(
            "invalid account identity (not hex): {identity}"
        )))?;
    if id_bytes.len() != 32 {
        return Err(ElaraError::Wire(format!(
            "invalid account identity length: {} bytes, expected 32",
            id_bytes.len()
        )));
    }
    let mut account_id = [0u8; 32];
    account_id.copy_from_slice(&id_bytes);

    // Gap 1 light-client semantics (2026-04-29): the proof endpoint MUST
    // anchor at the last-sealed SMT root, not the live in-memory state. If
    // we flushed `smt_dirty` here we'd advance the on-disk root past the
    // root that any signed epoch header references, so
    // `verify_account_proof_against_header` would always reject — exactly
    // the failure observed on the live testnet (proof.root = post-flush,
    // header.account_smt_root = last seal, mismatch → "no Gap-1 headers").
    //
    // Read the on-disk SMT directly. The persistent tree only advances at
    // seal time (epoch.rs:3399 `apply_snapshot` under the seal-emission
    // path). Between seals, smt_dirty accumulates mutations but the stored
    // tree stays at the last sealed root, which matches the
    // `account_smt_root` of the most recent epoch header.
    //
    // The returned `state_hash` is therefore the at-last-seal leaf hash.
    // The included `account_state` is the LIVE ledger view and may be
    // ahead of `state_hash` for accounts mutated between seals — the
    // `live_state_matches_sealed` boolean below tells callers which
    // regime they're in. SDK verification only consumes
    // `proof.state_hash` + `proof.siblings` + `proof.root` so the live
    // account_state cannot influence cryptographic outcomes.
    let (account_state_live, expected_state_hash, proof_opt, exclusion_opt, on_disk_root) = {
        use crate::network::account_merkle::{hash_account_state, AccountStateSMT};
        let ledger = state.ledger.read().await;
        let acct = ledger.accounts.get(&identity).cloned();
        let expected = acct.as_ref().map(hash_account_state);
        drop(ledger);
        let tree = AccountStateSMT::new(&state.rocks);
        let proof = tree.proof(&account_id)?;
        // For a genuinely-absent account, build a sound cryptographic exclusion
        // proof (folds an empty leaf to the signed root) instead of asserting
        // absence by bare root — a Byzantine server must now produce a fold that
        // reaches the signed root, which it cannot for an account that exists.
        let exclusion = if proof.is_none() {
            tree.exclusion_proof(&account_id)?
        } else {
            None
        };
        let root = tree.root()?;
        (acct, expected, proof, exclusion, root)
    };

    let account_exists_in_ledger = account_state_live.is_some();
    let account_exists_in_smt = proof_opt.is_some();

    // Gap 1: Resolve the latest sealed account-SMT binding up front so we
    // can attach it to ALL THREE response shapes — the full proof, the
    // pending_first_seal short-circuit, and the non-existence witness. Light
    // clients hitting a witness before the first witness flush has folded
    // this account into the SMT still need to know which seal to wait for —
    // without the binding the pending response is opaque (no epoch number,
    // no signed root to verify against on retry). The ABSENCE response needs
    // it for the same routing reason: an exclusion witness is only as strong
    // as its root binding (elara-verify --account-exclusion), and without
    // `seal_id` the harvester has no way to fetch WHICH seal committed the
    // witness's root short of side-channels (/status, a sibling account's
    // proof). Advisory only — verifiers bind against the fetched seal wire
    // itself, never this server-declared routing hint.
    //
    // Scale: O(1) lookup from EpochState — does not grow with zone count.
    //
    // Boot recovery: `EpochState::latest_sealed_account` is ephemeral —
    // populated by `register_seal` on each NEW seal but reset to None on
    // node restart (state.rs:1478 constructs `EpochState::new()`). Without
    // a fallback, fresh nodes return no binding until the next seal fires
    // — minutes-long blind window for light clients. Fall back to a
    // bounded reverse-scan of CF_EPOCHS to recover the binding from
    // on-disk seals so security is restored at boot, not at next-seal.
    let sealed_binding = match state.epoch.read() {
        Ok(es) => es.latest_sealed_account.clone(),
        Err(_) => None,
    };
    let sealed_binding = match sealed_binding {
        Some(b) => Some(b),
        None => crate::network::epoch::fallback_latest_sealed_account(&state.rocks),
    };

    // Account has never been seen anywhere → no leaf. Return a cryptographic
    // exclusion proof (verifies against the signed root via
    // `verify_account_non_membership_against_header`), not a trust-the-server
    // bare-root claim.
    if !account_exists_in_ledger && !account_exists_in_smt {
        let mut resp = match &exclusion_opt {
            Some(xp) => crate::network::account_merkle::exclusion_to_wire(xp),
            // Defensive: exclusion_proof returns None only if the account is
            // present, which contradicts this branch; fall back to the legacy
            // bare-root shape rather than panic.
            None => serde_json::json!({ "root": hex::encode(on_disk_root) }),
        };
        if let Some(obj) = resp.as_object_mut() {
            obj.insert("identity".into(), serde_json::json!(identity));
            obj.insert("exists".into(), serde_json::json!(false));
            // Same shape as the sibling branches below. `matches_proof_root`
            // compares against the WITNESS root: true = the witness folds to
            // the exact root this seal committed, so `seal_id` is the seal to
            // feed elara-verify --account-exclusion --seal.
            let (bound, sealed_json) = match &sealed_binding {
                Some((epoch_number, zone, seal_id, sealed_root, sealed_at)) => {
                    let matches = exclusion_opt
                        .as_ref()
                        .is_some_and(|xp| xp.root == *sealed_root);
                    (
                        matches,
                        serde_json::json!({
                            "epoch_number": epoch_number,
                            "zone": zone,
                            "seal_id": seal_id,
                            "account_smt_root": hex::encode(sealed_root),
                            "sealed_at": sealed_at,
                            "matches_proof_root": matches,
                        }),
                    )
                }
                None => (false, serde_json::Value::Null),
            };
            obj.insert("bound_to_seal".into(), serde_json::json!(bound));
            obj.insert("latest_sealed_account".into(), sealed_json);
        }
        return Ok(resp);
    }

    // Account is in the ledger but its first mutation hasn't been flushed
    // into the persistent SMT yet (the `smt_dirty` insert lands at op-apply
    // time but the tree write only happens at seal time). Surface this as
    // "pending first seal" rather than returning a phantom inclusion proof
    // — light clients should retry after one epoch.
    let proof = match proof_opt {
        Some(p) => p,
        None => {
            // Surface the binding so callers know which seal will (eventually)
            // sign the first leaf for this account, and can poll until then.
            let pending_sealed_json = match &sealed_binding {
                Some((epoch_number, zone, seal_id, sealed_root, sealed_at)) => {
                    serde_json::json!({
                        "epoch_number": epoch_number,
                        "zone": zone,
                        "seal_id": seal_id,
                        "account_smt_root": hex::encode(sealed_root),
                        "sealed_at": sealed_at,
                        "matches_proof_root": false,
                    })
                }
                None => serde_json::Value::Null,
            };
            return Ok(serde_json::json!({
                "identity": identity,
                "exists": true,
                "pending_first_seal": true,
                "bound_to_seal": false,
                "root": hex::encode(on_disk_root),
                "account_state": account_state_live
                    .as_ref()
                    .map(|s| serde_json::to_value(s).unwrap_or(serde_json::Value::Null))
                    .unwrap_or(serde_json::Value::Null),
                "latest_sealed_account": pending_sealed_json,
            }));
        }
    };

    // `proof.state_hash` may differ from `expected_state_hash` (live ledger
    // hash) when the account was mutated between seals. That's not an
    // inconsistency — it means live ledger advances past sealed state.
    // The proof remains cryptographically valid: it attests to the
    // at-last-seal state.
    let live_state_matches_sealed =
        expected_state_hash.is_some_and(|h| h == proof.state_hash);

    let (bound, sealed_json) = match sealed_binding {
        Some((epoch_number, zone, seal_id, sealed_root, sealed_at)) => {
            let bound = sealed_root == proof.root;
            (bound, serde_json::json!({
                "epoch_number": epoch_number,
                "zone": zone,
                "seal_id": seal_id,
                "account_smt_root": hex::encode(sealed_root),
                "sealed_at": sealed_at,
                "matches_proof_root": bound,
            }))
        }
        None => (false, serde_json::json!(null)),
    };

    // Include the full live AccountState for display convenience. SDKs MUST
    // NOT use account_state for cryptographic verification — only
    // `proof.state_hash` is signed-by-seal. When
    // `live_state_matches_sealed=false`, account_state is one or more
    // epochs ahead of state_hash.
    let account_state_json = account_state_live
        .as_ref()
        .map(|s| serde_json::to_value(s).unwrap_or(serde_json::Value::Null))
        .unwrap_or(serde_json::Value::Null);

    // Compressed inclusion proof core (account_id/identity/state_hash/root/
    // present/siblings) + endpoint display/binding fields.
    let mut resp = crate::network::account_merkle::proof_to_wire(&proof);
    if let Some(obj) = resp.as_object_mut() {
        obj.insert("identity".into(), serde_json::json!(identity));
        obj.insert("exists".into(), serde_json::json!(true));
        obj.insert("account_state".into(), account_state_json);
        obj.insert(
            "live_state_matches_sealed".into(),
            serde_json::json!(live_state_matches_sealed),
        );
        // Always true post-fix: proof.root == latest seal's account_smt_root
        // because we don't flush past it. Kept for backward compat + monitoring.
        obj.insert("bound_to_seal".into(), serde_json::json!(bound));
        obj.insert("latest_sealed_account".into(), sealed_json);
    }
    Ok(resp)
}

/// Axum adapter — thin wrapper around [`compute_account_proof`].
pub async fn account_proof(
    State(state): State<Arc<NodeState>>,
    AxumPath(identity): AxumPath<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let body = compute_account_proof(state, identity).await?;
    Ok(Json(body))
}

// ─── /record/{id} ────────────────────────────────────────────────────────────

/// Compute `/record/{id}` payload. Shared between the axum handler and the
/// PQ-transport router so accounts polling over PQ get byte-for-byte the same
/// JSON shape they parse today over HTTPS.
pub(crate) async fn compute_record_detail(
    state: Arc<NodeState>,
    id: String,
) -> crate::errors::Result<serde_json::Value> {
    let record_id = id.clone();
    let record = state.get_record(&record_id)?;

    let finalized = state.finalized.read().await;
    let is_finalized = finalized.contains(&id);

    // Bounded page: per-record attestation cardinality is attacker-controlled
    // (any verifying keypair is stored), and this is a public read on both
    // transports. Rows here are thin (~120 B) but the count must still bound.
    let (attestations, atts_capped) = {
        let mgr = state.witness_mgr.as_ref();
        mgr.get_attestations_page(
            &id,
            crate::network::witness::MAX_ATTESTATIONS_PER_RECORD_READ,
        )?
    };

    let att_list: Vec<serde_json::Value> = attestations.iter().map(|a| {
        serde_json::json!({
            "witness_hash": a.witness_hash,
            "timestamp": a.timestamp,
            "has_pubkey": a.witness_public_key.is_some(),
        })
    }).collect();

    let beat_op = extract_ledger_op(&record).ok().flatten().map(|op| format_op(&op));

    let confirmation = state.confirmation_level(&id);

    // Gap 8: surface live seal progress for streaming-attestation UX.
    // Wallets can render "3 of 4 witnesses attested / 62% of 67% threshold"
    // in real time rather than blocking on the full 2/3 settlement.
    let seal_progress = state.seal_progress(&id).map(|sp| {
        let stake_pct = if sp.zone_total_stake > 0 {
            (sp.effective_stake / sp.zone_total_stake as f64) * 100.0
        } else {
            0.0
        };
        let threshold_pct = if sp.zone_total_stake > 0 {
            (sp.stake_threshold / sp.zone_total_stake as f64) * 100.0
        } else {
            0.0
        };
        let progress_pct = if sp.stake_threshold > 0.0 {
            ((sp.effective_stake / sp.stake_threshold) * 100.0).min(100.0)
        } else {
            0.0
        };
        // Gap 8: explicit Sealed-vs-Finalized state for accounts. SealProgress
        // entry existing implies the seal is registered (anchor sig accepted),
        // so `sealed=true` is unconditional in this branch. `finalized` is the
        // clearer name for what we historically called `settled` (kept under
        // the old name for back-compat). `state` collapses both to one string
        // so the simplest account UI doesn't branch on multiple booleans.
        // Without these fields, accounts had to parse the parent's
        // `confirmation_level` string to distinguish optimistic-Sealed
        // (~3–5 s) from Finalized (2/3 attestation).
        let finalized = sp.settled;
        let state_str = if finalized { "finalized" } else { "sealed" };
        serde_json::json!({
            "seal_id": sp.seal_id,
            "epoch_number": sp.epoch_number,
            "zone_path": sp.zone_path,
            "attestation_count": sp.attestation_count,
            "effective_stake": sp.effective_stake,
            "zone_total_stake": sp.zone_total_stake,
            "stake_threshold": sp.stake_threshold,
            "stake_attested_pct": stake_pct,
            "stake_threshold_pct": threshold_pct,
            "progress_pct": progress_pct,
            // Gap 8 explicit Sealed-vs-Finalized surface.
            "sealed": true,
            "sealed_at": sp.registered_at,
            "finalized": finalized,
            "state": state_str,
            // Retained for back-compat with existing accounts/CLI.
            "settled": sp.settled,
            "is_global_seal": sp.is_global_seal,
            "finalized_at": sp.finalized_at,
            "registered_at": sp.registered_at,
        })
    });

    Ok(serde_json::json!({
        "id": record.id,
        "timestamp": record.timestamp,
        "creator": creator_identity_hash(&record),
        "parents": record.parents,
        "classification": format!("{:?}", record.classification),
        "has_signature": record.signature.is_some(),
        "has_sphincs_signature": record.sphincs_signature.is_some(),
        "has_itc_stamp": record.itc_stamp.is_some(),
        "zone_refs_count": record.zone_refs.len(),
        "metadata_keys": record.metadata.keys().collect::<Vec<_>>(),
        "beat_op": beat_op,
        "attestations": att_list,
        "attestation_count": attestations.len(),
        "attestations_capped": atts_capped,
        "confirmation_level": confirmation.name(),
        "finalized": is_finalized,
        "seal_progress": seal_progress,
    }))
}

/// Axum adapter — thin wrapper around [`compute_record_detail`].
pub async fn record_detail(
    State(state): State<Arc<NodeState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let body = compute_record_detail(state, id).await?;
    Ok(Json(body))
}

// ─── /record/{id}/wire ───────────────────────────────────────────────────────
//
// The record's canonical WIRE bytes — the form every signature covers and the
// only form `elara-verify` can grade offline. The JSON detail view above is
// for humans/explorers and deliberately does NOT carry signature bytes
// (`has_signature: true` is a fact ABOUT the record, not evidence), so it can
// never feed the verifier; this endpoint is the missing public read that
// makes the receipts flow (`site/receipts.html` step «3») actually executable:
//
//   curl <node>/record/<id>/wire > receipt.bin && elara-verify --receipt receipt.bin
//
// Bounded: O(1) point lookup by id; the payload is one record, already capped
// by the node's record-size limit at ingest. Same public-read posture as
// `/record/{id}` (the `/record/` prefix is in PUBLIC_ROUTE_PREFIXES).

/// `GET /record/{id}/wire` — canonical wire bytes, `application/octet-stream`.
pub async fn record_wire(
    State(state): State<Arc<NodeState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<impl axum::response::IntoResponse, AppError> {
    let record = state.get_record(&id)?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        record.to_bytes(),
    ))
}

// ─── /records/by-hash/{content_hash} ─────────────────────────────────────────
//
// Protocol §11.23 Layer A.
//
// Wallets and explorers know a record's content hash (sha3-256 of the wire
// body) before they know its `id`. Without this route they have to first
// scan to find the id, then call `/record/{id}` — which forces them to use
// the creator-keyed search (if they have the creator) or the timestamp
// fallback (O(records_in_window)). With this route, given just the hash,
// they get the record in one O(1) RocksDB point lookup off CF_IDX_HASH.
//
// Layer A slice 0 was local-only: a 404 means *this node* has no copy.
// Layer A slice 1 (this file + `network/record_hash_fetcher.rs` + PQ verb
// `resolve_content_hash`) adds OPT-IN peer-relay: callers add `?relay=1`
// to the query string and the local node fans out to up to 8 peers via
// PQ on local miss. First peer that holds it wins; if all 8 peers say no,
// fall through to 404.
//
// Relay is opt-in to keep the default latency profile predictable —
// accounts that just want a fast 404 don't pay the 8-peer round-trip cost.

/// Compute `/records/by-hash/{content_hash}` payload — LOCAL-ONLY.
///
/// Returns the same JSON shape as `/record/{id}` on hit, or `None` on a
/// local-index miss. Bumps the `records_by_hash_{hits,misses}_total`
/// counters either way for observability.
///
/// Use [`compute_record_by_hash_with_relay`] if the caller wants to opt
/// into peer-relay on local miss.
pub(crate) async fn compute_record_by_hash(
    state: Arc<NodeState>,
    content_hash: String,
) -> crate::errors::Result<Option<serde_json::Value>> {
    use std::sync::atomic::Ordering::Relaxed;

    let trimmed = content_hash.trim();
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        state.records_by_hash_misses_total.fetch_add(1, Relaxed);
        return Err(crate::errors::ElaraError::Wire(
            "content_hash must be 64 hex chars (sha3-256)".into(),
        ));
    }
    let lookup = trimmed.to_ascii_lowercase();

    match state.rocks.record_id_by_hash(&lookup) {
        Some(record_id) => {
            state.records_by_hash_hits_total.fetch_add(1, Relaxed);
            let body = compute_record_detail(state, record_id).await?;
            Ok(Some(body))
        }
        None => {
            state.records_by_hash_misses_total.fetch_add(1, Relaxed);
            Ok(None)
        }
    }
}

/// Compute `/records/by-hash/{content_hash}` payload with optional
/// peer-relay (§11.23 Layer A slice 1).
///
/// If `relay=false`: identical to [`compute_record_by_hash`].
/// If `relay=true` and the local index misses: fans out to up to 8 peers
/// over PQ verb `resolve_content_hash`. First peer that holds the record
/// returns the body verbatim. If all peers say no: returns `None` (404).
///
/// Counters:
///   * `records_by_hash_hits_total` / `_misses_total` — local-tier outcome.
///   * `records_by_hash_peer_relay_attempts_total` / `_hits_total` /
///     `_misses_total` — relay-tier outcome (only bumped when `relay=true`
///     AND local missed).
pub(crate) async fn compute_record_by_hash_with_relay(
    state: Arc<NodeState>,
    content_hash: String,
    relay: bool,
) -> crate::errors::Result<Option<serde_json::Value>> {
    let local = compute_record_by_hash(Arc::clone(&state), content_hash.clone()).await?;
    if local.is_some() || !relay {
        return Ok(local);
    }
    // Local miss + relay opted in — fan out to peers. The trimming +
    // shape validation already happened in `compute_record_by_hash`;
    // re-trim here so the fetcher sees the same lowercase-hex form the
    // local lookup used.
    let lookup = content_hash.trim().to_ascii_lowercase();
    match crate::network::record_hash_fetcher::fetch_record_from_peers(&state, &lookup).await {
        crate::network::record_hash_fetcher::FetchOutcome::Hit(body) => Ok(Some(body)),
        crate::network::record_hash_fetcher::FetchOutcome::Miss => Ok(None),
    }
}

/// Axum adapter — thin wrapper around [`compute_record_by_hash_with_relay`].
/// 404 on miss. Honors `?relay=1` (or any truthy value: `1`, `true`, `yes`)
/// to opt into peer-relay fall-back on local miss.
pub async fn record_by_hash(
    State(state): State<Arc<NodeState>>,
    AxumPath(content_hash): AxumPath<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let relay = params
        .get("relay")
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "TRUE" | "True"))
        .unwrap_or(false);
    match compute_record_by_hash_with_relay(state, content_hash, relay).await? {
        Some(body) => Ok(Json(body)),
        None => Err(AppError(crate::errors::ElaraError::RecordNotFound(
            "no record matches the given content_hash".into(),
        ))),
    }
}

// ─── Agent-mandate query (C4 slice 1) ───────────────────────────────────────

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `GET /mandate/{mandate_id}` — the mandate + its (principal-authorized)
/// revocation state. Public, read-only. `found: false` when unknown (rather than
/// 404) so the demo/widget renders a clean negative.
pub async fn mandate_detail(
    State(state): State<Arc<NodeState>>,
    AxumPath(mandate_id): AxumPath<String>,
) -> Json<serde_json::Value> {
    let mid = mandate_id.to_ascii_lowercase();
    match state.rocks.get_mandate(&mid) {
        None => Json(serde_json::json!({ "mandate_id": mid, "found": false })),
        Some(m) => {
            // Revocation is read-time authorized: only the PRINCIPAL's revocation counts.
            let revoked_at = state.rocks.get_revocation_ms(&mid, &m.principal_identity_hash);
            Json(serde_json::json!({
                "mandate_id": mid,
                "found": true,
                "network_id": m.network_id,
                "principal_identity_hash": m.principal_identity_hash,
                "agent_identity_hash": m.agent_identity_hash,
                "scope": {
                    "allowed_ops": m.scope.allowed_ops,
                    "allowed_zones": m.scope.allowed_zones,
                    "max_amount": m.scope.max_amount,
                },
                "not_before_ms": m.not_before_ms,
                "not_after_ms": m.not_after_ms,
                "parent_mandate_id": m.parent_mandate_id,
                "sub_delegation_max_depth": m.sub_delegation_max_depth,
                // v0 enforces scope only for wildcard mandates; a non-wildcard
                // scope is RECORDED but not yet enforced (honest labeling).
                "scope_enforced_v0": m.scope.is_wildcard(),
                "revoked": revoked_at.is_some(),
                "revoked_at_ms": revoked_at,
            }))
        }
    }
}

/// `GET /mandate/status/{record_id}` — the recomputed [`MandateFlag`] for an act
/// record that referenced a mandate. Public, read-only, always-current (the flag
/// is recomputed from live mandate+revocation state, never frozen). Anti-framing:
/// the named principal is echoed ONLY when the flag genuinely attributes the act
/// to that principal's mandate — never for NoChain/AgentMismatch/Malformed.
///
/// Coverage honesty (`authoritative_complete`): act entries (`CF_MANDATE_ACT`) are
/// built only by the live ingest hook and are NOT snapshot-carried, so a snapshot-
/// bootstrapped follower has no entry for an act sealed before its baseline and
/// returns `{is_mandate_act:false}` — a false negative. The flag of a *found* act,
/// by contrast, is judged entirely from snapshot-carried mandate+revocation state,
/// so it is authoritative on any node. Hence `authoritative_complete` is `true`
/// whenever the act is found, and on the not-found path is `true` only on a full-
/// history node (`!ledger_loaded_from_snapshot`): a `false` there means "this node
/// bootstrapped past it, query an archive", NOT "this record is not a mandate act".
/// Same coverage split as `/mandate/{id}/acts`.
pub async fn mandate_status(
    State(state): State<Arc<NodeState>>,
    AxumPath(record_id): AxumPath<String>,
) -> Json<serde_json::Value> {
    use crate::mandate::MandateFlag;
    let Some(entry) = state.rocks.get_mandate_act(&record_id) else {
        // is_mandate_act:false is node-local on a snapshot-bootstrapped follower
        // (CF_MANDATE_ACT is live-ingest-only, never snapshot-carried), so flag it
        // non-authoritative there — never let a follower's false negative read as
        // a definitive "not a mandate act". Mirrors `/mandate/{id}/acts`.
        let authoritative_complete = !state
            .ledger_loaded_from_snapshot
            .load(std::sync::atomic::Ordering::Relaxed);
        return Json(serde_json::json!({
            "record_id": record_id,
            "is_mandate_act": false,
            "authoritative_complete": authoritative_complete,
        }));
    };
    let network_id = &state.config.network_id;
    let resolver = crate::network::mandate_node::StorageMandateResolver { rocks: &state.rocks };
    let (flag, lineage) =
        crate::network::mandate_node::evaluate_act_entry_with_lineage(&entry, network_id, &resolver);
    let mandate = state.rocks.get_mandate(&entry.mandate_ref);
    let scope_deferred = mandate.as_ref().is_some_and(|m| !m.scope.is_wildcard());

    // A reference that isn't a well-formed mandate id is reported `malformed`
    // (an honest "this reference is not a valid mandate") — distinct from
    // `no_chain` (a well-formed id that simply doesn't resolve).
    let ref_ok = is_hex64(&entry.mandate_ref);
    let display_flag = if !ref_ok { "malformed" } else { flag.as_str() };
    let authorized = ref_ok && flag.is_authorized();

    let mut body = serde_json::json!({
        "record_id": record_id,
        "is_mandate_act": true,
        "mandate_ref": entry.mandate_ref,
        "agent_identity_hash": entry.signer_identity_hash,
        "act_timestamp_ms": entry.act_timestamp_ms,
        "flag": display_flag,
        "authorized": authorized,
        "scope_deferred": scope_deferred,
        // A found act is judged from snapshot-carried mandate+revocation state, so
        // this verdict is authoritative regardless of how the node bootstrapped
        // (contrast the not-found path, which a snapshot follower can't vouch for).
        "authoritative_complete": true,
    });

    if ref_ok {
        if let Some(m) = mandate.as_ref() {
            if flag.attributes_to_principal() {
                // The act is by the mandate's own agent under this principal —
                // genuine attribution.
                body["principal_identity_hash"] = serde_json::json!(m.principal_identity_hash);
            } else if flag == MandateFlag::AgentMismatch {
                // The principal authorized a DIFFERENT agent — exonerated, not party.
                body["principal_note"] = serde_json::json!(
                    "the referenced mandate authorized a different agent; its principal is NOT party to this act"
                );
            }
            // NoChain / Malformed / UnverifiedChain / reserved: no principal echo.
        }
    }

    // Verified sub-delegation lineage (leaf→root), surfaced ONLY for a `Valid`
    // verdict — the one case where every hop is proven authorizing — so a
    // non-authorizing or unverifiable chain never names an ancestor (anti-libel,
    // enforced in the evaluator: `lineage` is empty for every other flag). Each hop
    // is data already public per-hop via `GET /mandate/{id}`; this is the
    // pre-walked, pre-verified form. Bounded by `MANDATE_MAX_CHAIN_DEPTH` (≤16).
    if ref_ok && flag == MandateFlag::Valid && !lineage.is_empty() {
        let hops: Vec<serde_json::Value> = lineage
            .iter()
            .enumerate()
            .map(|(i, (mid, rec))| {
                serde_json::json!({
                    "hop_index": i,
                    "mandate_id": mid,
                    "principal_identity_hash": rec.principal_identity_hash,
                    "agent_identity_hash": rec.agent_identity_hash,
                })
            })
            .collect();
        body["chain_depth"] = serde_json::json!(hops.len());
        body["lineage"] = serde_json::json!(hops);
        body["lineage_note"] = serde_json::json!(
            "leaf→root verified delegation chain; hop 0's principal is this act's authorizer, \
             ancestors are the verified chain of authority — not accused"
        );
    }
    Json(body)
}

/// Compact per-act view for the `/mandate/{id}/acts` list — the SAME recomputed
/// flag + anti-framing semantics as [`mandate_status`], minus the per-act lineage
/// block (a list stays lean; drill into `/mandate/status/{record_id}` for the
/// verified chain). The principal is echoed ONLY for genuinely-attributing flags;
/// `AgentMismatch` exonerates; `NoChain`/`Malformed` name nobody.
fn render_act_compact(
    record_id: &str,
    entry: &crate::mandate::MandateActEntry,
    network_id: &str,
    resolver: &crate::network::mandate_node::StorageMandateResolver<'_>,
) -> serde_json::Value {
    use crate::mandate::MandateFlag;
    let flag = crate::network::mandate_node::evaluate_act_entry(entry, network_id, resolver);
    let ref_ok = is_hex64(&entry.mandate_ref);
    let display_flag = if !ref_ok { "malformed" } else { flag.as_str() };
    let authorized = ref_ok && flag.is_authorized();
    let mandate = resolver.rocks.get_mandate(&entry.mandate_ref);
    let scope_deferred = mandate.as_ref().is_some_and(|m| !m.scope.is_wildcard());

    let mut body = serde_json::json!({
        "record_id": record_id,
        "mandate_ref": entry.mandate_ref,
        "agent_identity_hash": entry.signer_identity_hash,
        "act_timestamp_ms": entry.act_timestamp_ms,
        "amount": entry.amount,
        "flag": display_flag,
        "authorized": authorized,
        "scope_deferred": scope_deferred,
    });
    if ref_ok {
        if let Some(m) = mandate.as_ref() {
            if flag.attributes_to_principal() {
                body["principal_identity_hash"] = serde_json::json!(m.principal_identity_hash);
            } else if flag == MandateFlag::AgentMismatch {
                body["principal_note"] = serde_json::json!(
                    "the referenced mandate authorized a different agent; its principal is NOT party to this act"
                );
            }
        }
    }
    body
}

/// `GET /mandate/{mandate_id}/acts?from=&limit=` — the bounded, keyset-paginated
/// list of act records performed under a mandate, each with its recomputed
/// [`crate::mandate::MandateFlag`]. Public, read-only. This is the "what did this
/// agent do under this authority?" accountability enumeration — the query the
/// observational mandate layer exists to answer.
///
/// Coverage is what THIS node has indexed: acts are built only by the live ingest
/// hook and are NOT snapshot-carried, so a node that bootstrapped from a snapshot
/// omits acts sealed before its baseline. The response's `authoritative_complete`
/// is `true` only on a node with full history (replayed from genesis); on a
/// snapshot-bootstrapped follower it is `false`, so `{mandate_found:true, count:0}`
/// there means "none indexed by this node", NOT "the agent never acted" — query an
/// archive for the authoritative list (same coverage split as `/mandate/status`).
/// Bounded by design: `limit` is hard-
/// capped at [`crate::storage::rocks::MANDATE_ACTS_PAGE_MAX`] server-side and
/// pagination is keyset (O(limit) per page, never an O(all_records) scan). Pass
/// the response's `next_from` back as `?from=` to page forward; `null` ends it.
pub async fn mandate_acts(
    State(state): State<Arc<NodeState>>,
    AxumPath(mandate_id): AxumPath<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let mid = mandate_id.to_ascii_lowercase();
    if !is_hex64(&mid) {
        return Json(serde_json::json!({
            "mandate_id": mid,
            "error": "malformed_mandate_id",
            "acts": [],
            "count": 0,
        }));
    }
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(50)
        .min(crate::storage::rocks::MANDATE_ACTS_PAGE_MAX);
    let from_bytes = params
        .get("from")
        .and_then(|h| hex::decode(h).ok());

    // A storage error is NOT an empty mandate. Serve the empty page (stable wire
    // contract) but carry the failure into authoritative_complete below, so a
    // RocksDB fault can never masquerade as a confident `{count:0}` truth.
    let (record_ids, next, query_ok) = match state
        .rocks
        .list_acts_for_mandate(&mid, from_bytes.as_deref(), limit)
    {
        Ok((ids, next)) => (ids, next, true),
        Err(e) => {
            tracing::warn!("list_acts_for_mandate({mid}) failed: {e} — serving empty page, authoritative_complete=false");
            (Vec::new(), None, false)
        }
    };

    let network_id = &state.config.network_id;
    let resolver = crate::network::mandate_node::StorageMandateResolver { rocks: &state.rocks };
    let acts: Vec<serde_json::Value> = record_ids
        .iter()
        .filter_map(|rid| {
            let entry = state.rocks.get_mandate_act(rid)?;
            Some(render_act_compact(rid, &entry, network_id, &resolver))
        })
        .collect();

    // Coverage honesty: act indexes are populated only by the live ingest hook
    // and are NOT snapshot-carried, so a snapshot-bootstrapped node omits acts
    // sealed before its baseline. `ledger_loaded_from_snapshot` is the exact
    // self-knowledge: false ⟺ this node replayed from genesis ⟺ full act history.
    // Surfaced so a follower's `{mandate_found:true, count:0}` is not misread as
    // "this agent never acted" on the flagship accountability query. `query_ok`
    // folds in storage-fault honesty: a failed enumeration is never authoritative.
    let authoritative_complete = query_ok
        && !state
            .ledger_loaded_from_snapshot
            .load(std::sync::atomic::Ordering::Relaxed);
    Json(serde_json::json!({
        "mandate_id": mid,
        // present-with-zero-acts vs unknown-mandate are different answers.
        "mandate_found": state.rocks.get_mandate(&mid).is_some(),
        "count": acts.len(),
        "acts": acts,
        "next_from": next.map(hex::encode),
        // true only on a full-history node; false on a snapshot-bootstrapped
        // follower whose enumeration may omit pre-baseline acts.
        "authoritative_complete": authoritative_complete,
    }))
}

/// `GET /agent/{agent_hash}/acts?from=&limit=` — the bounded, keyset-paginated
/// list of act records SIGNED BY a given agent identity, across ALL mandates,
/// each with its recomputed [`crate::mandate::MandateFlag`]. The agent-side
/// forensic view: "everything this key did that referenced a mandate, and under
/// whose authority" — the complement of `/mandate/{id}/acts` (which is scoped to
/// one authority).
///
/// LOOPBACK-ONLY by design (registered only on the full `routes()` router, NOT in
/// `PUBLIC_ROUTE_PREFIXES`, so `public_route_gate` 404s it for non-loopback peers).
/// A public by-signer index makes per-identity behavioral aggregation cheap — the
/// same deanonymization surface the protocol already gates for
/// `/records/search?creator=`; making bulk enumeration cheap is the harm, not its
/// mere possibility (fusion-audited 2026-06-26). A future slice may open a
/// principal-authenticated public path. The path is deliberately OUTSIDE the
/// `/mandate` prefix: that prefix is public, so a `/mandate/agent/...` route would
/// be public-by-accident AND would collide with `/mandate/{id}/acts` at router
/// construction.
///
/// Anti-libel: the index INCLUDES acts where the signer had no valid mandate
/// (`NoChain`/`AgentMismatch`) — that is the forensic point — so each row carries
/// its recomputed flag and the SAME anti-framing principal-echo as the per-mandate
/// list ([`render_act_compact`]): a principal is named only when the flag genuinely
/// attributes the act. The list is the SIGNER's own claims-and-verdicts, never a
/// dossier of any principal.
///
/// Coverage honesty identical to [`mandate_acts`]: acts are live-ingest-only and
/// NOT snapshot-carried, so `authoritative_complete` is false on a
/// snapshot-bootstrapped follower (its `{count:0}` means "none indexed by this
/// node", not "this agent never acted").
pub async fn agent_acts(
    State(state): State<Arc<NodeState>>,
    AxumPath(agent_hash): AxumPath<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let ah = agent_hash.to_ascii_lowercase();
    if !is_hex64(&ah) {
        return Json(serde_json::json!({
            "agent_identity_hash": ah,
            "error": "malformed_agent_hash",
            "acts": [],
            "count": 0,
        }));
    }
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(50)
        .min(crate::storage::rocks::MANDATE_ACTS_PAGE_MAX);
    let from_bytes = params.get("from").and_then(|h| hex::decode(h).ok());

    // A storage error is NOT an empty signer history; serve the empty page but
    // carry the failure into authoritative_complete so a RocksDB fault can never
    // masquerade as a confident "this identity never acted".
    let (record_ids, next, query_ok) = match state
        .rocks
        .list_acts_for_agent(&ah, from_bytes.as_deref(), limit)
    {
        Ok((ids, next)) => (ids, next, true),
        Err(e) => {
            tracing::warn!("list_acts_for_agent({ah}) failed: {e} — serving empty page, authoritative_complete=false");
            (Vec::new(), None, false)
        }
    };

    let network_id = &state.config.network_id;
    let resolver = crate::network::mandate_node::StorageMandateResolver { rocks: &state.rocks };
    let acts: Vec<serde_json::Value> = record_ids
        .iter()
        .filter_map(|rid| {
            let entry = state.rocks.get_mandate_act(rid)?;
            Some(render_act_compact(rid, &entry, network_id, &resolver))
        })
        .collect();

    let authoritative_complete = query_ok
        && !state
            .ledger_loaded_from_snapshot
            .load(std::sync::atomic::Ordering::Relaxed);
    Json(serde_json::json!({
        "agent_identity_hash": ah,
        "count": acts.len(),
        "acts": acts,
        "next_from": next.map(hex::encode),
        "authoritative_complete": authoritative_complete,
        "note": "acts that referenced a mandate and were SIGNED BY this identity; \
                 authorized:false rows are this signer's own unauthorized attempts; \
                 a named principal is party to a row only when authorized:true",
    }))
}

// ─── /record/{id}/causal-proof ───────────────────────────────────────────────

/// Node-count ceiling for the public DAG-walk endpoints (`/record/{id}/causal-proof`
/// and `/dag/record/{id}/graph`). A depth cap alone is NOT a bound: in a wide
/// mesh, the set reachable within `max_depth` hops can be most of the hot tier
/// (millions of records at mainnet), so an unauthenticated GET would clone
/// O(hot-tier) record-id strings under the DAG read lock — a small-request /
/// large-internal-work amplification + lock-hold lever. This caps each walk to a
/// bounded neighborhood; responses signal `*_capped` / `truncated` when hit.
pub(crate) const MAX_DAG_WALK_NODES: usize = 10_000;

/// Depth cap for the causal-proof ancestor/descendant counts.
const CAUSAL_PROOF_MAX_DEPTH: usize = 100;

/// Compute `/record/{id}/causal-proof` payload. Shared between the axum
/// handler and the PQ-transport router.
pub(crate) async fn compute_causal_proof(
    state: Arc<NodeState>,
    id: String,
) -> crate::errors::Result<serde_json::Value> {
    let dag = state.dag.read().await;

    if !dag.contains(&id) {
        return Err(ElaraError::RecordNotFound(id));
    }

    let parents = dag.parents(&id);
    // Bounded walks: a depth cap is not a bound on a wide mesh. The response
    // only needs the COUNTS, so a capped neighborhood is sufficient; `*_capped`
    // tells the caller the count is a floor, not the exact total.
    let (ancestors, ancestors_capped) =
        dag.ancestors_capped(&id, CAUSAL_PROOF_MAX_DEPTH, MAX_DAG_WALK_NODES);
    let (descendants, descendants_capped) =
        dag.descendants_capped(&id, CAUSAL_PROOF_MAX_DEPTH, MAX_DAG_WALK_NODES);

    let mut chain = Vec::new();
    let mut current = id.clone();
    for _ in 0..CAUSAL_PROOF_MAX_DEPTH {
        let p = dag.parents(&current);
        if p.is_empty() {
            break;
        }
        chain.push(p[0].clone());
        current = p[0].clone();
    }

    // Last DAG access; capture it, then drop the read guard so the response JSON
    // is built lock-free (uniform with `compute_dag_record_graph`). Every other
    // field is an already-materialized owned value.
    let is_tip = dag.children(&id).is_empty();
    drop(dag);

    Ok(serde_json::json!({
        "record_id": id,
        "causal_depth": ancestors.len(),
        "parents": parents,
        "ancestor_count": ancestors.len(),
        "descendant_count": descendants.len(),
        "ancestor_count_capped": ancestors_capped,
        "descendant_count_capped": descendants_capped,
        "parent_chain": chain,
        "is_root": parents.is_empty(),
        "is_tip": is_tip,
    }))
}

/// Axum adapter — thin wrapper around [`compute_causal_proof`].
pub async fn causal_proof(
    State(state): State<Arc<NodeState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let body = compute_causal_proof(state, id).await?;
    Ok(Json(body))
}

// ─── /seal/progress/{record_id} ──────────────────────────────────────────────
//
// Gap 8: dedicated lightweight RPC for accounts polling seal progress. Returns
// only the streaming-attestation state — does not fetch the full record,
// attestation list, or DAG context. Designed for sub-second polling from
// accounts while the seal is accumulating attestations toward Finalized.
//
// Response shape matches the `seal_progress` sub-object on `/record/{id}`
// so accounts can switch between endpoints without reshaping their parser.

/// Compute `/seal/progress/{id}` payload. Shared between the axum handler
/// and the PQ-transport router so accounts polling over PQ get byte-for-byte
/// the same JSON shape they parse today over HTTPS.
pub(crate) async fn compute_seal_progress(
    state: Arc<NodeState>,
    id: String,
) -> crate::errors::Result<serde_json::Value> {
    // Validate the record exists. Check the DAG hot window first (cheap),
    // then fall back to RocksDB so accounts polling a record that was just
    // finalized and pruned from the DAG still get a meaningful response
    // (confirmation_level=finalized + synthesized progress_pct=100) instead
    // of a 404 race. At a 5-15s floor the entire submit→finalize lifecycle
    // can fit inside one polling interval — without the fallback the account
    // would see the record appear and disappear in one poll.
    {
        let dag = state.dag.read().await;
        if !dag.contains(&id) {
            // Not in DAG — fall back to storage existence check.
            // `record_exists` is a bloom-filter + key probe on RocksDB,
            // cheaper than a full `get_record`.
            if !state.record_exists(&id).unwrap_or(false) {
                return Err(ElaraError::RecordNotFound(id));
            }
        }
    }

    let confirmation = state.confirmation_level(&id);

    let progress_json = state.seal_progress(&id).map(|sp| {
        let stake_pct = if sp.zone_total_stake > 0 {
            (sp.effective_stake / sp.zone_total_stake as f64) * 100.0
        } else {
            0.0
        };
        let threshold_pct = if sp.zone_total_stake > 0 {
            (sp.stake_threshold / sp.zone_total_stake as f64) * 100.0
        } else {
            0.0
        };
        // `progress_pct` is the headline number accounts should render:
        // 0% at Pending, climbs to 100% as effective_stake reaches the
        // settlement threshold. Clamped at 100% for display.
        let progress_pct = if sp.stake_threshold > 0.0 {
            ((sp.effective_stake / sp.stake_threshold) * 100.0).min(100.0)
        } else {
            0.0
        };
        // Gap 8: explicit Sealed-vs-Finalized state for accounts. SealProgress
        // entry existing implies the seal is registered (anchor sig accepted),
        // so `sealed=true` is unconditional in this branch. `finalized` is the
        // clearer name for what we historically called `settled` (kept under
        // the old name for back-compat). `state` collapses both to one string
        // so the simplest account UI doesn't branch on multiple booleans.
        // Without these fields, accounts had to parse the parent's
        // `confirmation_level` string to distinguish optimistic-Sealed
        // (~3–5 s) from Finalized (2/3 attestation).
        let finalized = sp.settled;
        let state_str = if finalized { "finalized" } else { "sealed" };
        serde_json::json!({
            "seal_id": sp.seal_id,
            "epoch_number": sp.epoch_number,
            "zone_path": sp.zone_path,
            "attestation_count": sp.attestation_count,
            "effective_stake": sp.effective_stake,
            "zone_total_stake": sp.zone_total_stake,
            "stake_threshold": sp.stake_threshold,
            "stake_attested_pct": stake_pct,
            "stake_threshold_pct": threshold_pct,
            "progress_pct": progress_pct,
            // Gap 8 explicit Sealed-vs-Finalized surface.
            "sealed": true,
            "sealed_at": sp.registered_at,
            "finalized": finalized,
            "state": state_str,
            // Retained for back-compat with existing accounts/CLI.
            "settled": sp.settled,
            "is_global_seal": sp.is_global_seal,
            "finalized_at": sp.finalized_at,
            "registered_at": sp.registered_at,
        })
    });

    // Fallback: if live seal state has been pruned but the record is still
    // in storage AND reached Finalized/Anchored, synthesize a "settled"
    // progress shape so accounts can stop polling and render success. Without
    // this, a account polling every 200ms during a fast finality cycle would
    // see progress climb, then flip to seal_progress=None on the next poll
    // with no signal that the seal actually settled.
    let progress_json = progress_json.or_else(|| {
        use crate::network::consensus::ConfirmationLevel;
        if matches!(confirmation, ConfirmationLevel::Finalized | ConfirmationLevel::Anchored) {
            Some(serde_json::json!({
                "seal_id": serde_json::Value::Null,
                "epoch_number": serde_json::Value::Null,
                "zone_path": serde_json::Value::Null,
                "attestation_count": serde_json::Value::Null,
                "effective_stake": serde_json::Value::Null,
                "zone_total_stake": serde_json::Value::Null,
                "stake_threshold": serde_json::Value::Null,
                "stake_attested_pct": serde_json::Value::Null,
                "stake_threshold_pct": serde_json::Value::Null,
                "progress_pct": 100.0,
                // Gap 8 explicit Sealed-vs-Finalized surface — pruned-but-finalized
                // record reads as finalized for both the explicit and back-compat
                // fields. `sealed_at` is unknown post-prune.
                "sealed": true,
                "sealed_at": serde_json::Value::Null,
                "finalized": true,
                "state": "finalized",
                // Retained for back-compat.
                "settled": true,
                "is_global_seal": serde_json::Value::Null,
                "finalized_at": serde_json::Value::Null,
                "registered_at": serde_json::Value::Null,
                "pruned": true,
            }))
        } else {
            None
        }
    });

    Ok(serde_json::json!({
        "record_id": id,
        "confirmation_level": confirmation.name(),
        "seal_progress": progress_json,
    }))
}

/// Axum adapter — thin wrapper around [`compute_seal_progress`].
pub async fn seal_progress_route(
    State(state): State<Arc<NodeState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let body = compute_seal_progress(state, id).await?;
    Ok(Json(body))
}

/// DISC-7 diagnostic endpoint.
///
/// One-shot dump of every input `is_seal_settled` consumes for a given
/// seal — attestation set, committee-vs-zone denominators, effective
/// diversity-weighted stake, and the 2/3 threshold. Lets operators
/// distinguish "seal has too few attestors" from "committee not
/// registered" from "diversity cap is dominating" with a single curl.
/// Transport-agnostic body for `/debug/seal/{id}`. Shared between the axum
/// handler and the PQ-transport router. Returns RecordNotFound when the
/// seal has no attestations yet (not proposed or no witness coverage).
pub fn compute_seal_debug(
    state: &Arc<NodeState>,
    id: &str,
) -> crate::errors::Result<serde_json::Value> {
    let debug = {
        let consensus = state.consensus.lock_recover();
        consensus.seal_debug(id)
    };
    match debug {
        // A serialize failure of a server-side struct is an internal fault, not
        // bad client input — route to Json (catch-all → 500, detail withheld by
        // AppError::into_response), not Config (400, which echoes the body).
        Some(d) => serde_json::to_value(d).map_err(ElaraError::Json),
        None => Err(ElaraError::RecordNotFound(format!(
            "seal {id} has no attestations (not yet proposed or no witness coverage)"
        ))),
    }
}

/// Axum adapter — thin wrapper around [`compute_seal_debug`].
pub async fn seal_debug_route(
    State(state): State<Arc<NodeState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let body = compute_seal_debug(&state, &id)?;
    Ok(Json(body))
}

// ─── /network ────────────────────────────────────────────────────────────────

/// Compute `/network` payload. Shared between the axum handler and the
/// PQ-transport router. Returns supply, DAG topology,
/// peer/DHT/consensus/gossip snapshots, and per-zone epoch state.
pub(crate) async fn compute_network_info(state: Arc<NodeState>) -> serde_json::Value {
    // Acquire each lock independently to avoid holding ledger.read() across
    // other .await points. Previously held 4 locks simultaneously, blocking
    // state_core's ledger.write() on 1-core nodes during monitoring polls.
    let (dag_len, dag_tips, dag_edges) = {
        let dag = state.dag.read().await;
        (dag.len(), dag.tips().len(), dag.edge_count())
    };
    let (summary, records_processed) = {
        let ledger = state.ledger.read().await;
        (validate::summarize(&ledger), ledger.records_processed)
    };
    let (peers_connected, peers_total, peers_by_type, avg_reputation) = {
        let peers = state.peers.read().await;
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut avg_rep = 0.0_f64;
        let mut rep_count = 0usize;
        for p in peers.all() {
            let nt = format!("{:?}", p.node_type).to_lowercase();
            *by_type.entry(nt).or_insert(0) += 1;
            let rep = peers.reputation(&p.identity_hash);
            if rep != 0.5 {
                avg_rep += rep;
                rep_count += 1;
            }
        }
        if rep_count > 0 { avg_rep /= rep_count as f64; } else { avg_rep = 0.5; }
        (peers.connected().len(), peers.len(), by_type, avg_rep)
    };
    let finalized_count = {
        let finalized = state.finalized.read().await;
        finalized.len()
    };

    let (dht_size, dht_occupied_buckets, dht_bucket_dist) = {
        let dht = state.dht.lock_recover();
        (dht.len(), dht.occupied_buckets(), dht.bucket_distribution())
    };

    let (consensus_attestations, consensus_settled, consensus_unsettled_count,
         witness_profiles_count, total_zone_stake) = {
        let c = state.consensus.lock_recover();
        (
            c.total_attestation_count(),
            c.settled_count(),
            c.unsettled_summary().len(),
            c.profiles().count(),
            c.total_zone_stake(ZoneId::from_legacy(0)),
        )
    };

    let epoch_zones: Vec<serde_json::Value> = {
        let epoch = state.epoch.read_recover();
        // EXP-2 (2026-07-03 audit): one JSON row per zone, uncapped — O(all_zones)
        // (up to ~1M at mainnet) on this public /network endpoint. Cap the detail
        // list so a single GET cannot pull a per-zone row for every zone.
        const MAX_ZONE_ROWS: usize = 5_000;
        epoch.latest_epoch.iter().take(MAX_ZONE_ROWS).map(|(zone, num)| {
            serde_json::json!({"zone": zone, "epoch_number": num})
        }).collect()
    };

    let gossip_push = state.gossip_push_total.load(std::sync::atomic::Ordering::Relaxed);
    let gossip_pull = state.gossip_pull_total.load(std::sync::atomic::Ordering::Relaxed);

    let supply = serde_json::json!({
        "max": MAX_SUPPLY,
        "max_beat": MAX_SUPPLY as f64 / BASE_UNITS_PER_BEAT as f64,
        "total": summary.total_supply_micros,
        "total_beat": summary.total_supply_beat,
        "circulating": summary.circulating_micros,
        "circulating_beat": summary.circulating_beat,
        "staked": summary.total_staked_micros,
        "staked_beat": summary.total_staked_beat,
        "conservation_pool": summary.conservation_pool_micros,
        "accounts": summary.num_accounts,
        "active_stakes": summary.num_active_stakes,
    });

    let dag_info = serde_json::json!({
        "size": dag_len,
        "tips": dag_tips,
        "edges": dag_edges,
        "records_processed": records_processed,
    });

    let dht_buckets: Vec<serde_json::Value> = dht_bucket_dist.iter()
        .map(|(i, c)| serde_json::json!({"bucket": i, "peers": c}))
        .collect();

    let topology = serde_json::json!({
        "peers_connected": peers_connected,
        "peers_total": peers_total,
        "peers_by_type": peers_by_type,
        "avg_peer_reputation": (avg_reputation * 10000.0).round() / 10000.0,
        "dht_size": dht_size,
        "dht_occupied_buckets": dht_occupied_buckets,
        "dht_total_buckets": 256,
        "dht_bucket_coverage_pct": (dht_occupied_buckets as f64 / 256.0) * 100.0,
        "dht_bucket_distribution": dht_buckets,
    });

    let consensus_info = serde_json::json!({
        "attestations": consensus_attestations,
        "settled": consensus_settled,
        "unsettled": consensus_unsettled_count,
        "finalized": finalized_count,
        "witness_profiles": witness_profiles_count,
        "total_zone_stake": total_zone_stake,
        "total_zone_stake_beat": crate::accounting::validate::format_beat_precise(total_zone_stake),
        "effective_hops": state.effective_max_hops(),
    });

    let gossip_info = serde_json::json!({
        "push_total": gossip_push,
        "pull_total": gossip_pull,
    });

    serde_json::json!({
        "ticker": "BEAT",
        "protocol": "Elara DAM",
        "consensus_algorithm": "AWC",
        "crypto": "Dilithium3",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": (state.uptime() * 100.0).round() / 100.0,
        "supply": supply,
        "dag": dag_info,
        "topology": topology,
        "consensus": consensus_info,
        "gossip": gossip_info,
        "epochs": epoch_zones,
    })
}

pub async fn network_info(State(state): State<Arc<NodeState>>) -> Json<serde_json::Value> {
    Json(compute_network_info(state).await)
}

// ─── /validate_address/{address} ─────────────────────────────────────────────

pub async fn compute_validate_address(
    state: Arc<NodeState>,
    address: String,
) -> serde_json::Value {
    let valid_format = address.len() == 64 && address.chars().all(|c| c.is_ascii_hexdigit());
    let exists = if valid_format {
        let ledger = state.ledger.read().await;
        ledger.accounts.contains_key(&address)
    } else {
        false
    };

    serde_json::json!({
        "address": address,
        "valid_format": valid_format,
        "exists": exists,
        "format": "sha3-256-hex",
    })
}

pub async fn validate_address(
    State(state): State<Arc<NodeState>>,
    AxumPath(address): AxumPath<String>,
) -> Json<serde_json::Value> {
    Json(compute_validate_address(state, address).await)
}

// ─── /identity/pk/{hash} ─────────────────────────────────────────────────────
//
// Identity Partitioning Phase D — on-miss peer fetch endpoint. PKs are public
// by definition (Protocol §7.5.1), so this is a public read endpoint shared
// between axum (HTTPS for legacy SDKs / Caddy upstream) and the PQ transport
// (peer-to-peer fetcher in `network::identity_fetcher`). When the hash isn't
// stored locally, returns `pk: null` and `tier: null` — callers MUST treat
// that as soft-fail per internal design notes §6.

pub async fn compute_identity_pk(
    state: Arc<NodeState>,
    identity_hash: String,
) -> serde_json::Value {
    match state.rocks.get_public_key_with_tier(&identity_hash) {
        Some((pk, tier)) => serde_json::json!({
            "identity_hash": identity_hash,
            "pk": hex::encode(&pk),
            "tier": tier,
        }),
        None => serde_json::json!({
            "identity_hash": identity_hash,
            "pk": serde_json::Value::Null,
            "tier": serde_json::Value::Null,
        }),
    }
}

pub async fn identity_pk_route(
    State(state): State<Arc<NodeState>>,
    AxumPath(identity_hash): AxumPath<String>,
) -> Json<serde_json::Value> {
    Json(compute_identity_pk(state, identity_hash).await)
}

// ─── /epochs ─────────────────────────────────────────────────────────────────

/// Default / hard cap on the number of per-zone rows `/epochs` returns in one
/// response. `total` always reports the TRUE number of zones the node tracks;
/// only the returned `epochs` array is bounded. This caps a public,
/// unauthenticated endpoint so a single GET cannot pull one row per zone for
/// the whole zone set (up to the 1M-zone design target) as a single JSON
/// payload — SCALE RULE: bounded, always. Truncation is detectable by a caller
/// as `epochs.len() < total`. Mirrors the `/dag/tips` frontier bound.
const EPOCHS_DEFAULT_LIMIT: usize = 1000;
const EPOCHS_MAX_LIMIT: usize = 10_000;

#[derive(serde::Deserialize)]
pub struct EpochsQuery {
    pub limit: Option<usize>,
}

/// Compute `/epochs` payload. Shared between the axum handler and the
/// PQ-transport `epoch_status` verb. `limit` bounds the returned per-zone
/// sample (default [`EPOCHS_DEFAULT_LIMIT`], hard max [`EPOCHS_MAX_LIMIT`]);
/// the reported `total` stays the true zone count regardless of `limit`.
pub async fn compute_epoch_status(
    state: &Arc<NodeState>,
    limit: Option<usize>,
) -> serde_json::Value {
    let limit = limit.unwrap_or(EPOCHS_DEFAULT_LIMIT).min(EPOCHS_MAX_LIMIT);
    let epoch = state.epoch.read_recover();
    // True zone count captured BEFORE truncation so `total` stays honest even
    // when the returned page is capped. HashMap::len is O(1).
    let total = epoch.latest_epoch.len();
    // Order by zone id so the returned page is a deterministic lowest-ids-first
    // slice across calls instead of an arbitrary HashMap-iteration sample, then
    // bound the per-zone JSON construction to `limit` rows. The sort is
    // O(z·log z) in `z` = zones THIS node tracks, which is bounded by the node's
    // committee membership (not the global 1M-zone count) for a participating
    // node; on a full-archive seed that tracks every zone it is a non-hot-path
    // explorer/bootstrap cost. If that ever measures as a concern, swap the
    // full sort for a bounded top-`limit` heap selection (O(z·log limit)).
    let mut entries: Vec<_> = epoch.latest_epoch.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let zones: Vec<serde_json::Value> = entries
        .into_iter()
        .take(limit)
        .map(|(zone, epoch_number)| {
            serde_json::json!({
                "zone": zone,
                "epoch_number": epoch_number,
                "latest_seal_id": epoch.latest_seal_id.get(zone).unwrap_or(&String::new()),
                "latest_seal_hash": epoch.latest_seal_hash.get(zone).map(hex::encode).unwrap_or_default(),
            })
        })
        .collect();
    serde_json::json!({ "epochs": zones, "total": total })
}

pub async fn epoch_status(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<EpochsQuery>,
) -> Json<serde_json::Value> {
    Json(compute_epoch_status(&state, params.limit).await)
}

// ─── /governance/* ───────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct GovernanceQuery {
    status: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

pub async fn compute_governance_proposals(
    state: Arc<NodeState>,
    status: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> serde_json::Value {
    let ledger = state.ledger.read().await;
    let limit = limit.unwrap_or(50).min(200);
    let offset = offset.unwrap_or(0);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    // Filter + order over lightweight refs FIRST — no per-proposal vote tally
    // yet. `tally_votes` is O(votes) per proposal, so tallying every proposal
    // before paging is O(all_proposals · votes) work even though the response is
    // capped at `limit`. Defer it to the page below so the cost is
    // O(page · votes). SCALE RULE: no O(all) work in a hot read path.
    let mut filtered: Vec<&crate::accounting::governance::Proposal> = ledger
        .governance
        .proposals
        .values()
        .filter(|p| {
            if let Some(ref s) = status {
                format!("{:?}", p.status).to_lowercase() == s.to_lowercase()
            } else {
                true
            }
        })
        .collect();

    // Newest first; total_cmp on created_at with a proposal-id tiebreak so
    // equal-timestamp proposals page deterministically (proposals is a HashMap,
    // so without a tiebreak the page would be an arbitrary iteration sample).
    filtered.sort_by(|a, b| {
        b.created_at.total_cmp(&a.created_at).then_with(|| a.id.cmp(&b.id))
    });

    let total = filtered.len();
    let page: Vec<serde_json::Value> = filtered
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|p| {
            let tally = crate::accounting::governance::tally_votes(p, now, None);
            serde_json::json!({
                "id": p.id,
                "proposer": p.proposer,
                "category": p.category.as_str(),
                "title": p.title,
                "status": format!("{:?}", p.status).to_lowercase(),
                "created_at": p.created_at,
                "voting_deadline": p.voting_deadline,
                "vote_count": p.votes.len(),
                "tally": {
                    "for": tally.for_conviction(),
                    "against": tally.against_conviction(),
                    "abstain": tally.abstain_conviction(),
                    "voters": tally.voter_count,
                    "raw_participating_stake": tally.raw_participating_stake,
                    "raw_participating_stake_beat": crate::accounting::validate::format_beat_precise(tally.raw_participating_stake),
                },
            })
        })
        .collect();

    serde_json::json!({
        "proposals": page,
        "total": total,
        "limit": limit,
        "offset": offset,
    })
}

pub async fn governance_proposals(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<GovernanceQuery>,
) -> Json<serde_json::Value> {
    Json(compute_governance_proposals(state, params.status, params.limit, params.offset).await)
}

pub async fn compute_governance_proposal_detail(
    state: Arc<NodeState>,
    id: String,
) -> crate::errors::Result<serde_json::Value> {
    let ledger = state.ledger.read().await;

    let proposal = ledger
        .governance
        .proposals
        .get(&id)
        .ok_or_else(|| ElaraError::Governance(format!("proposal not found: {id}")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let tally = crate::accounting::governance::tally_votes(proposal, now, None);
    let total_gov = crate::accounting::governance::total_governance_staked(&ledger.stakes);

    let votes: Vec<serde_json::Value> = proposal
        .votes
        .iter()
        .map(|v| {
            let duration = (now - v.voted_at).max(0.0);
            let raw_conv = crate::accounting::governance::conviction(v.stake, duration);
            let dampened = crate::accounting::governance::dampened_power(raw_conv);
            serde_json::json!({
                "voter": v.voter,
                "direction": v.direction.as_str(),
                "stake": v.stake,
                "voted_at": v.voted_at,
                "conviction": raw_conv,
                "dampened_power": dampened,
            })
        })
        .collect();

    // Ratio is scale-invariant, so the `_q` scale cancels (display only).
    let decisive_q = tally.for_conviction_q + tally.against_conviction_q;
    let for_fraction = if decisive_q > 0 {
        tally.for_conviction_q as f64 / decisive_q as f64
    } else {
        0.0
    };

    Ok(serde_json::json!({
        "id": proposal.id,
        "proposer": proposal.proposer,
        "category": proposal.category.as_str(),
        "title": proposal.title,
        "description": proposal.description,
        "status": format!("{:?}", proposal.status).to_lowercase(),
        "created_at": proposal.created_at,
        "voting_deadline": proposal.voting_deadline,
        "passed_at": proposal.passed_at,
        "can_execute": proposal.can_execute(now),
        "votes": votes,
        "tally": {
            "for_conviction": tally.for_conviction(),
            "against_conviction": tally.against_conviction(),
            "abstain_conviction": tally.abstain_conviction(),
            "voters": tally.voter_count,
            "raw_participating_stake": tally.raw_participating_stake,
            "raw_participating_stake_beat": crate::accounting::validate::format_beat_precise(tally.raw_participating_stake),
            "for_fraction": for_fraction,
            "supermajority_met": for_fraction >= crate::accounting::governance::SUPERMAJORITY_THRESHOLD,
        },
        "total_governance_staked": total_gov,
    }))
}

pub async fn governance_proposal_detail(
    State(state): State<Arc<NodeState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(compute_governance_proposal_detail(state, id).await?))
}

/// Compute `/governance/summary` payload. Shared between the axum handler
/// and the PQ-transport router. Returns proposal
/// counters + governance constants.
pub(crate) async fn compute_governance_summary(state: Arc<NodeState>) -> serde_json::Value {
    let ledger = state.ledger.read().await;
    let (active, passed, rejected, expired, executed, cancelled, vetoed) =
        ledger.governance.proposal_counts();
    let total_gov = crate::accounting::governance::total_governance_staked(&ledger.stakes);

    let active_delegations = ledger.governance.active_delegations_count as usize;

    serde_json::json!({
        "total_proposals": ledger.governance.proposals.len(),
        "active": active,
        "passed": passed,
        "rejected": rejected,
        "expired": expired,
        "executed": executed,
        "cancelled": cancelled,
        "vetoed": vetoed,
        "active_delegations": active_delegations,
        "total_governance_staked": total_gov,
        "min_proposal_stake": crate::accounting::governance::MIN_PROPOSAL_STAKE,
        "max_active_proposals_per_identity": crate::accounting::governance::MAX_ACTIVE_PROPOSALS_PER_IDENTITY,
        "voting_period_secs": crate::accounting::governance::VOTING_PERIOD_SECS,
        "execution_delay_secs": crate::accounting::governance::EXECUTION_DELAY_SECS,
        "supermajority_threshold": crate::accounting::governance::SUPERMAJORITY_THRESHOLD,
        "min_participation_fraction": crate::accounting::governance::MIN_PARTICIPATION_FRACTION,
    })
}

pub async fn governance_summary(
    State(state): State<Arc<NodeState>>,
) -> Json<serde_json::Value> {
    Json(compute_governance_summary(state).await)
}

/// Default / hard cap on the number of incoming delegations
/// `/governance/delegations/{identity}` serializes in `delegated_to_me`.
/// `delegated_to_me_count` reports the TRUE incoming count and
/// `total_effective_stake` sums over ALL incoming delegations — only the
/// serialized array is bounded. A well-known delegate can be the target of an
/// unbounded number of (sybil or legitimate) delegators, so the array must not
/// dump them all as one payload reachable over the PQ `governance_delegations`
/// verb. SCALE RULE: bounded, always. Truncation is detectable as
/// `delegated_to_me.len() < delegated_to_me_count`.
///
/// NOTE: `delegators_for` is itself an O(all_delegations) scan because
/// `delegations` is keyed by delegator, not delegate — a delegate's inbound set
/// has no index today. This page bound caps the RESPONSE; eliminating the scan
/// needs a reverse index (delegate → delegators) in the governance store, a
/// separate follow-up out of scope for this response-bounding pass.
const DELEGATIONS_DEFAULT_LIMIT: usize = 1000;
const DELEGATIONS_MAX_LIMIT: usize = 10_000;

pub async fn compute_governance_delegations(
    state: Arc<NodeState>,
    identity: String,
    limit: Option<usize>,
) -> serde_json::Value {
    let limit = limit
        .unwrap_or(DELEGATIONS_DEFAULT_LIMIT)
        .min(DELEGATIONS_MAX_LIMIT);
    let ledger = state.ledger.read().await;

    let outgoing = ledger.governance.delegation_of(&identity).map(|d| {
        serde_json::json!({
            "delegate": d.delegate,
            "created_at": d.created_at,
        })
    });

    let mut incoming: Vec<serde_json::Value> = ledger.governance.delegators_for(&identity)
        .iter()
        .map(|d| {
            let stake = crate::accounting::governance::governance_stake_for(&ledger.stakes, &d.delegator);
            serde_json::json!({
                "delegator": d.delegator,
                "stake": stake,
                "created_at": d.created_at,
            })
        })
        .collect();

    let own_stake = crate::accounting::governance::governance_stake_for(&ledger.stakes, &identity);
    // Sum + count over ALL incoming delegations BEFORE the page bound so
    // `total_effective_stake` and `delegated_to_me_count` stay honest even when
    // the serialized `delegated_to_me` array is capped. `saturating_add` so a
    // pathological stake sum can't wrap (mirrors the beat overflow-refund fix).
    let delegated_stake: u64 = incoming.iter()
        .filter_map(|d| d["stake"].as_u64())
        .fold(0u64, |acc, s| acc.saturating_add(s));
    let incoming_count = incoming.len();

    // Deterministic order so the bounded page is a stable delegator-sorted slice
    // across calls, not an arbitrary HashMap-iteration sample.
    incoming.sort_by(|a, b| {
        a.get("delegator").and_then(|v| v.as_str())
            .cmp(&b.get("delegator").and_then(|v| v.as_str()))
    });
    incoming.truncate(limit);

    serde_json::json!({
        "identity": identity,
        "own_governance_stake": own_stake,
        "delegated_to_me": incoming,
        "delegated_to_me_count": incoming_count,
        "delegated_from_me": outgoing,
        "total_effective_stake": own_stake.saturating_add(delegated_stake),
    })
}

pub async fn governance_delegations(
    State(state): State<Arc<NodeState>>,
    axum::extract::Path(identity): axum::extract::Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let limit = params.get("limit").and_then(|s| s.parse::<usize>().ok());
    Json(compute_governance_delegations(state, identity, limit).await)
}

/// Compute `/governance/params` payload. Shared between the axum handler
/// and the PQ-transport router.
pub(crate) async fn compute_governance_params(state: Arc<NodeState>) -> serde_json::Value {
    let ledger = state.ledger.read().await;
    let params = &ledger.governance.params;
    serde_json::json!({
        "propagation_rate_limit_per_hour": params.propagation_rate_limit_per_hour,
        "epoch_seal_interval_secs": params.epoch_seal_interval_secs,
        "witness_reward_micros": params.witness_reward_micros,
        "record_retention_secs": params.record_retention_secs,
        "stake_throughput_ratio": params.stake_throughput_ratio,
        "total_changes": ledger.governance.param_changes.len(),
    })
}

pub async fn governance_params(
    State(state): State<Arc<NodeState>>,
) -> Json<serde_json::Value> {
    Json(compute_governance_params(state).await)
}

/// `/governance/params/history` payload. Intentionally NOT page-bounded like
/// `/challenges`: `param_changes` only grows when a stake-weighted governance
/// proposal to change a parameter PASSES — it is not attacker-controllable at
/// volume and grows at governance cadence (a handful of entries over the
/// network's life), so it is not a fleet-wide dump vector. `param_changes` is a
/// `Vec` in chronological insertion order, so iteration is already
/// deterministic. `count` is the param-filtered total.
pub async fn compute_governance_params_history(
    state: Arc<NodeState>,
    param: Option<String>,
) -> serde_json::Value {
    let ledger = state.ledger.read().await;

    let changes: Vec<serde_json::Value> = ledger.governance.param_changes.iter()
        .filter(|c| param.as_deref().is_none_or(|f| c.name == f))
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "old_value": c.old_value,
                "new_value": c.new_value,
                "proposal_id": c.proposal_id,
                "applied_at": c.applied_at,
            })
        })
        .collect();

    serde_json::json!({
        "count": changes.len(),
        "changes": changes,
    })
}

pub async fn governance_params_history(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let param = params.get("param").cloned();
    Json(compute_governance_params_history(state, param).await)
}

// ─── §11.18 Slice 3: /governance/upgrade_outcomes ────────────────────────────
//
// Surfaces `GovernanceState.upgrade_outcomes` (ProtocolUpgrade execution
// outcomes recorded at Execute-dispatch) as JSON
// for operator inspection. Two endpoints:
//
//   • GET /governance/upgrade_outcomes?limit=N&offset=K → paginated list
//     (newest first by `recorded_at_ts`, default limit 50, cap 200).
//   • GET /governance/upgrade_outcomes/{proposal_id} → single record
//     (404 if no outcome for that proposal — either the proposal didn't
//     reach Execute, or the Execute record carried malformed metadata
//     which silently skipped outcome recording per governance.rs:1598).
//
// Wire shape mirrors the serde-derived `UpgradeOutcomeRecord` JSON.

#[derive(serde::Deserialize)]
pub struct UpgradeOutcomesQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub async fn compute_upgrade_outcomes(
    state: Arc<NodeState>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> serde_json::Value {
    let ledger = state.ledger.read().await;
    let limit = limit.unwrap_or(50).min(200);
    let offset = offset.unwrap_or(0);

    let mut outcomes: Vec<&crate::accounting::governance::UpgradeOutcomeRecord> =
        ledger.governance.upgrade_outcomes.values().collect();

    // Newest first by recorded_at_ts so operators see the latest dispatch
    // at the top — same ordering convention as `governance_proposals`
    // (by created_at desc).
    outcomes.sort_by(|a, b| {
        b.recorded_at_ts
            .total_cmp(&a.recorded_at_ts)
    });

    let total = outcomes.len();
    let page: Vec<serde_json::Value> = outcomes
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null))
        .collect();

    serde_json::json!({
        "outcomes": page,
        "total": total,
        "limit": limit,
        "offset": offset,
    })
}

pub async fn governance_upgrade_outcomes(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<UpgradeOutcomesQuery>,
) -> Json<serde_json::Value> {
    Json(compute_upgrade_outcomes(state, params.limit, params.offset).await)
}

pub async fn compute_upgrade_outcome_detail(
    state: Arc<NodeState>,
    proposal_id: String,
) -> crate::errors::Result<serde_json::Value> {
    let ledger = state.ledger.read().await;
    let record = ledger
        .governance
        .upgrade_outcomes
        .get(&proposal_id)
        .ok_or_else(|| {
            ElaraError::Governance(format!(
                "no upgrade outcome for proposal: {proposal_id}"
            ))
        })?;
    serde_json::to_value(record).map_err(|e| {
        ElaraError::Governance(format!("serialize upgrade outcome: {e}"))
    })
}

pub async fn governance_upgrade_outcome_detail(
    State(state): State<Arc<NodeState>>,
    axum::extract::Path(proposal_id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(
        compute_upgrade_outcome_detail(state, proposal_id).await?,
    ))
}

// ─── /consensus/* ────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ConsensusQuery {
    limit: Option<usize>,
}

pub async fn compute_consensus_status(
    state: Arc<NodeState>,
    limit: Option<usize>,
) -> serde_json::Value {
    let limit = limit.unwrap_or(20).min(100);

    let finalized = state.finalized.read().await;
    let finalized_count = finalized.len();
    drop(finalized);

    let consensus = state.consensus.lock_recover();
    let total_tracked = consensus.total_attestation_count();
    let settled_count = consensus.settled_count();

    let unsettled: Vec<serde_json::Value> = consensus
        .unsettled_summary()
        .into_iter()
        .take(limit)
        .map(|(rid, att_count, trust)| {
            serde_json::json!({
                "record_id": rid,
                "attestations": att_count,
                "trust_score": (trust * 10000.0).round() / 10000.0,
            })
        })
        .collect();

    let conf_summary = consensus.confirmation_summary();
    let confirmation_levels = serde_json::json!({
        "pending": conf_summary.get(&crate::network::consensus::ConfirmationLevel::Pending).copied().unwrap_or(0),
        "sealed": conf_summary.get(&crate::network::consensus::ConfirmationLevel::Sealed).copied().unwrap_or(0),
        "finalized": conf_summary.get(&crate::network::consensus::ConfirmationLevel::Finalized).copied().unwrap_or(0),
        "anchored": conf_summary.get(&crate::network::consensus::ConfirmationLevel::Anchored).copied().unwrap_or(0),
    });

    let (xzone_records, xzone_refs, xzone_boosts) = consensus.cross_zone_stats();

    serde_json::json!({
        "total_attestations": total_tracked,
        "settled": settled_count,
        "finalized": finalized_count,
        "confirmation_levels": confirmation_levels,
        "cross_zone": {
            "records_with_xzone_parents": xzone_records,
            "total_xzone_parent_refs": xzone_refs,
            "finality_boosts": xzone_boosts,
        },
        "waiting": unsettled,
    })
}

pub async fn consensus_status(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<ConsensusQuery>,
) -> Json<serde_json::Value> {
    Json(compute_consensus_status(state, params.limit).await)
}

pub async fn compute_consensus_record_detail(
    state: Arc<NodeState>,
    record_id: String,
) -> serde_json::Value {
    let detail = {
        let consensus = state.consensus.lock_recover();
        consensus.record_detail(&record_id)
    };

    let finalized = state.finalized.read().await.contains(&record_id);

    // Defensive page bound on the serialized attestations. In practice a
    // record's attestations are bounded by its zone committee, but across epoch
    // rotations / re-seals the set can accumulate, so cap the array as
    // defense-in-depth. `attestation_count` below stays the TRUE count
    // (truncation detectable as `attestations.len() < attestation_count`).
    // `detail.attestations` is an insertion-ordered Vec, so the capped slice is
    // already deterministic — no re-sort needed. SCALE RULE: bounded, always.
    const MAX_ATTESTATIONS_IN_DETAIL: usize = 4096;
    let attestations: Vec<serde_json::Value> = detail
        .attestations
        .iter()
        .take(MAX_ATTESTATIONS_IN_DETAIL)
        .map(|a| {
            serde_json::json!({
                "witness_hash": a.witness_hash,
                "stake": a.stake,
                "independence": (a.independence * 10000.0).round() / 10000.0,
                "timestamp": a.timestamp,
            })
        })
        .collect();

    let (confirmation, distinct_clusters) = {
        let consensus = state.consensus.lock_recover();
        (consensus.confirmation_level(&record_id), consensus.distinct_clusters(&record_id))
    };

    serde_json::json!({
        "record_id": record_id,
        "zone": detail.zone,
        "is_settled": detail.is_settled,
        "is_finalized": finalized,
        "confirmation_level": confirmation.name(),
        "distinct_clusters": distinct_clusters,
        "trust_score": (detail.trust_score * 10000.0).round() / 10000.0,
        "total_zone_stake": detail.total_zone_stake,
        "total_zone_stake_beat": crate::accounting::validate::format_beat_precise(detail.total_zone_stake),
        "attesting_stake": detail.attesting_stake,
        "attesting_stake_beat": crate::accounting::validate::format_beat_precise(detail.attesting_stake),
        "threshold_pct": (detail.threshold_pct * 100.0).round() / 100.0,
        "settlement_threshold": "66.67%",
        "attestation_count": detail.attestations.len(),
        "attestations": attestations,
    })
}

pub async fn consensus_record_detail(
    State(state): State<Arc<NodeState>>,
    AxumPath(record_id): AxumPath<String>,
) -> Json<serde_json::Value> {
    Json(compute_consensus_record_detail(state, record_id).await)
}

// ─── /witness/* ──────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct WitnessProfileBody {
    pub witness_hash: String,
    pub organization: String,
    pub subnet: String,
    pub geo_zone: String,
}

/// Transport-agnostic body for `POST /witness/profile`. Shared between the
/// axum handler and the PQ-transport router. Returns Wire when required
/// fields are missing so PQ surfaces BAD_REQUEST.
pub fn compute_register_witness_profile(
    state: &Arc<NodeState>,
    body: WitnessProfileBody,
) -> crate::errors::Result<serde_json::Value> {
    if body.witness_hash.is_empty() || body.organization.is_empty() {
        return Err(ElaraError::Wire("witness_hash and organization required".into()));
    }

    let profile = crate::network::consensus::WitnessProfile {
        organization: body.organization.clone(),
        subnet: body.subnet.clone(),
        geo_zone: body.geo_zone.clone(),
    };

    {
        let mut consensus = state.consensus.lock_recover();
        consensus.register_profile(&body.witness_hash, profile);
    }

    Ok(serde_json::json!({
        "registered": true,
        "witness_hash": body.witness_hash,
        "organization": body.organization,
        "subnet": body.subnet,
        "geo_zone": body.geo_zone,
    }))
}

/// Axum adapter — thin wrapper around [`compute_register_witness_profile`].
pub async fn register_witness_profile(
    State(state): State<Arc<NodeState>>,
    Json(body): Json<WitnessProfileBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let v = compute_register_witness_profile(&state, body)?;
    Ok(Json(v))
}

/// Default / hard cap on the number of witness profiles `/witnesses/profiles`
/// returns in one response. `count` always reports the TRUE profile total;
/// only the returned `profiles` array is bounded. The profile table is
/// reachable over the PQ verb by any handshaked peer and grows with the
/// witness set, so a single call must not dump every profile as one JSON
/// payload — SCALE RULE: bounded, always. Truncation is detectable by a caller
/// as `profiles.len() < count`. Mirrors the `/epochs` response bound.
const WITNESS_PROFILES_DEFAULT_LIMIT: usize = 1000;
const WITNESS_PROFILES_MAX_LIMIT: usize = 10_000;

#[derive(serde::Deserialize)]
pub struct WitnessProfilesQuery {
    pub limit: Option<usize>,
}

/// Compute `/witnesses/profiles` payload. Shared between the axum handler and
/// the PQ-transport `list_witness_profiles` verb. `limit` bounds the returned
/// profile sample (default [`WITNESS_PROFILES_DEFAULT_LIMIT`], hard max
/// [`WITNESS_PROFILES_MAX_LIMIT`]); `count` stays the true profile total.
pub async fn compute_list_witness_profiles(
    state: Arc<NodeState>,
    limit: Option<usize>,
) -> serde_json::Value {
    let limit = limit
        .unwrap_or(WITNESS_PROFILES_DEFAULT_LIMIT)
        .min(WITNESS_PROFILES_MAX_LIMIT);
    let consensus = state.consensus.lock_recover();
    let mut profiles: Vec<serde_json::Value> = consensus.profiles()
        .map(|(hash, profile)| {
            serde_json::json!({
                "witness_hash": hash,
                "organization": profile.organization,
                "subnet": profile.subnet,
                "geo_zone": profile.geo_zone,
            })
        })
        .collect();
    // Deterministic order so the bounded page is a stable lowest-hash-first
    // slice across calls, not an arbitrary profile-iteration sample.
    profiles.sort_by(|a, b| {
        a.get("witness_hash")
            .and_then(|v| v.as_str())
            .cmp(&b.get("witness_hash").and_then(|v| v.as_str()))
    });
    // True total captured BEFORE the page bound so `count` stays honest even
    // when the returned array is capped. `Vec::len` is O(1).
    let count = profiles.len();
    profiles.truncate(limit);

    serde_json::json!({
        "profiles": profiles,
        "count": count,
    })
}

pub async fn list_witness_profiles(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<WitnessProfilesQuery>,
) -> Json<serde_json::Value> {
    Json(compute_list_witness_profiles(state, params.limit).await)
}

#[derive(serde::Deserialize)]
pub struct CorrelationQuery {
    witness_a: String,
    witness_b: String,
}

pub fn compute_witness_correlation(
    state: Arc<NodeState>,
    witness_a: String,
    witness_b: String,
) -> serde_json::Value {
    let consensus = state.consensus.lock_recover();
    let corr = consensus.correlation(&witness_a, &witness_b);

    let profile_a = consensus.profiles().find(|(h, _)| *h == witness_a).map(|(_, p)| p.clone());
    let profile_b = consensus.profiles().find(|(h, _)| *h == witness_b).map(|(_, p)| p.clone());

    let mut result = serde_json::json!({
        "witness_a": witness_a,
        "witness_b": witness_b,
        "correlation": (corr * 10000.0).round() / 10000.0,
    });

    if let Some(p) = &profile_a {
        result["profile_a"] = serde_json::json!({
            "organization": p.organization,
            "subnet": p.subnet,
            "geo_zone": p.geo_zone,
        });
    }
    if let Some(p) = &profile_b {
        result["profile_b"] = serde_json::json!({
            "organization": p.organization,
            "subnet": p.subnet,
            "geo_zone": p.geo_zone,
        });
    }

    result
}

pub async fn witness_correlation(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<CorrelationQuery>,
) -> Json<serde_json::Value> {
    Json(compute_witness_correlation(state, params.witness_a, params.witness_b))
}

/// Default / hard cap on the number of witnesses the full-summary form of
/// `/witness/reputation` (no `witness` filter) returns. `tracked_witnesses`
/// reports the TRUE tracked count; only the `witnesses` array is bounded. The
/// reputation table grows with the witness population, so the unfiltered form —
/// reachable over the PQ `witness_reputation` verb — must not dump every tracked
/// witness as one payload. SCALE RULE: bounded, always. Single-witness lookups
/// (`witness` set) are O(1) and unaffected. Mirrors the `/witnesses/profiles`
/// bound; the page is the top witnesses by decayed score.
const WITNESS_REPUTATION_DEFAULT_LIMIT: usize = 1000;
const WITNESS_REPUTATION_MAX_LIMIT: usize = 10_000;

pub fn compute_witness_reputation(
    state: Arc<NodeState>,
    witness: Option<String>,
    limit: Option<usize>,
) -> serde_json::Value {
    let rep = state.reputation.lock_recover();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    if let Some(wh) = witness {
        if let Some(entry) = rep.get(&wh) {
            return serde_json::json!({
                "witness_hash": wh,
                "score": (entry.score * 100.0).round() / 100.0,
                "score_decayed": (entry.score_at(now) * 100.0).round() / 100.0,
                "trust_multiplier": (entry.trust_multiplier() * 10000.0).round() / 10000.0,
                "trust_multiplier_effective": (entry.trust_multiplier_at(now) * 10000.0).round() / 10000.0,
                "positive_events": entry.positive_events,
                "negative_events": entry.negative_events,
                "last_event": entry.last_event,
                "first_seen": entry.first_seen,
            });
        }
        return serde_json::json!({
            "witness_hash": wh,
            "score": 50.0,
            "score_decayed": 50.0,
            "trust_multiplier": 0.5,
            "positive_events": 0,
            "negative_events": 0,
            "last_event": null,
            "note": "unknown witness — default reputation"
        });
    }

    // Decayed view: score + trust_multiplier reflect the current half-life
    // effective values used by reward calculations (economics §12.4).
    let limit = limit
        .unwrap_or(WITNESS_REPUTATION_DEFAULT_LIMIT)
        .min(WITNESS_REPUTATION_MAX_LIMIT);
    let mut summary = rep.summary_at(now);
    // `summary_at` orders by decayed score descending but leaves equal-score
    // witnesses in `HashMap`-iteration order, so add a witness-hash tiebreak:
    // the bounded page (top witnesses by score) is then a stable slice across
    // calls. `tracked_witnesses` below stays the TRUE count, so truncation is
    // detectable as `witnesses.len() < tracked_witnesses`.
    summary.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    summary.truncate(limit);
    let witnesses: Vec<serde_json::Value> = summary.iter().map(|(wh, score, tm, pos, neg)| {
        serde_json::json!({
            "witness_hash": wh,
            "score": (*score * 100.0).round() / 100.0,
            "trust_multiplier": (*tm * 10000.0).round() / 10000.0,
            "positive_events": pos,
            "negative_events": neg,
        })
    }).collect();

    serde_json::json!({
        "tracked_witnesses": rep.tracked_count(),
        "witnesses": witnesses,
    })
}

pub async fn witness_reputation(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let limit = params.get("limit").and_then(|s| s.parse::<usize>().ok());
    Json(compute_witness_reputation(state, params.get("witness").cloned(), limit))
}

// ─── /peers/reputation ───────────────────────────────────────────────────────

/// Default / hard cap on the number of peers `/peers/reputation` returns in one
/// response. `count` reports the TRUE peer-table size; only the returned `peers`
/// array is bounded. The peer table grows with network size (10K+ nodes at the
/// mainnet target), so a single call reachable over the PQ `peer_reputation`
/// verb by any handshaked peer must not dump the whole table as one JSON payload
/// — SCALE RULE: bounded, always. Truncation is detectable as
/// `peers.len() < count`. Mirrors the `/peers` / `/challenges` bound.
const PEER_REPUTATION_DEFAULT_LIMIT: usize = 1000;
const PEER_REPUTATION_MAX_LIMIT: usize = 10_000;

pub async fn compute_peer_reputation(
    state: Arc<NodeState>,
    limit: Option<usize>,
) -> serde_json::Value {
    let limit = limit
        .unwrap_or(PEER_REPUTATION_DEFAULT_LIMIT)
        .min(PEER_REPUTATION_MAX_LIMIT);
    let peers = state.peers.read().await;
    let mut reputations: Vec<serde_json::Value> = peers
        .all()
        .iter()
        .map(|p| {
            serde_json::json!({
                "identity_hash": p.identity_hash,
                "host": format!("{}:{}", p.host, p.port),
                "node_type": p.node_type,
                "reputation": (peers.reputation(&p.identity_hash) * 10000.0).round() / 10000.0,
                "successes": p.successes,
                "failures": p.failures,
                "valid_records": p.valid_records,
                "invalid_records": p.invalid_records,
                "state": match p.state {
                    crate::network::peer::PeerState::Connected => "connected",
                    crate::network::peer::PeerState::Offline => "offline",
                    crate::network::peer::PeerState::Stale => "stale",
                },
            })
        })
        .collect();
    drop(peers);

    // Deterministic order so the bounded page is a stable identity-sorted slice
    // across calls, not an arbitrary peer-table-iteration sample.
    reputations.sort_by(|a, b| {
        a.get("identity_hash").and_then(|v| v.as_str())
            .cmp(&b.get("identity_hash").and_then(|v| v.as_str()))
    });
    // True peer-table size captured BEFORE the page bound so `count` stays honest.
    let count = reputations.len();
    reputations.truncate(limit);

    serde_json::json!({
        "peers": reputations,
        "count": count,
    })
}

pub async fn peer_reputation(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let limit = params.get("limit").and_then(|s| s.parse::<usize>().ok());
    Json(compute_peer_reputation(state, limit).await)
}

// ─── /rewards ────────────────────────────────────────────────────────────────

pub async fn compute_reward_stats(state: Arc<NodeState>) -> serde_json::Value {
    let ledger = state.ledger.read().await;
    let rewards_total = state.auto_rewards_total.load(std::sync::atomic::Ordering::Relaxed);
    let rewards_amount = state.auto_rewards_amount_total.load(std::sync::atomic::Ordering::Relaxed);

    serde_json::json!({
        "auto_rewards_total": rewards_total,
        "auto_rewards_amount_micros": rewards_amount,
        "auto_rewards_amount_beat": rewards_amount as f64 / BASE_UNITS_PER_BEAT as f64,
        "reward_per_attestation_micros": state.config.witness_reward_micros,
        "reward_per_attestation_beat": state.config.witness_reward_micros as f64 / BASE_UNITS_PER_BEAT as f64,
        "conservation_pool_micros": ledger.conservation_pool,
        "conservation_pool_beat": ledger.conservation_pool as f64 / BASE_UNITS_PER_BEAT as f64,
        "conservation_pool_cap_micros": ledger.pool_cap(),
        "conservation_pool_headroom_micros": ledger.pool_headroom(),
        "is_genesis_authority": state.identity.identity_hash == state.config.genesis_authority,
    })
}

pub async fn reward_stats(
    State(state): State<Arc<NodeState>>,
) -> Json<serde_json::Value> {
    Json(compute_reward_stats(state).await)
}

// ─── /zones ──────────────────────────────────────────────────────────────────

/// Compute `/zones` payload. Shared between the axum handler and the
/// PQ-transport router. Returns per-zone consensus
/// health + zone-state coverage summary.
pub(crate) async fn compute_zone_health(state: Arc<NodeState>) -> serde_json::Value {
    let consensus = state.consensus.lock_recover();
    let zones: Vec<serde_json::Value> = consensus
        .zone_health()
        .into_iter()
        .map(|(zone, stake, active, settled, witnesses)| {
            serde_json::json!({
                "zone": zone,
                "total_stake": stake,
                "active_records": active,
                "settled_records": settled,
                "unique_witnesses": witnesses,
            })
        })
        .collect();
    drop(consensus);

    let zone_coverage = {
        let zs = state.zone_state.lock_recover();
        let summary = zs.coverage_summary();
        let under = zs.under_witnessed_zones();
        (summary, under, zs.min_witnesses)
    };

    let coverage: Vec<serde_json::Value> = zone_coverage.0.iter().map(|(zone, count, witnesses, covered)| {
        serde_json::json!({
            "zone": zone,
            "record_count": count,
            "unique_witnesses": witnesses,
            "has_coverage": covered,
        })
    }).collect();

    serde_json::json!({
        "zones": zones,
        "total_zones": zones.len(),
        "coverage": coverage,
        "under_witnessed_zones": zone_coverage.1,
        "min_witnesses_required": zone_coverage.2,
    })
}

pub async fn zone_health(
    State(state): State<Arc<NodeState>>,
) -> Json<serde_json::Value> {
    Json(compute_zone_health(state).await)
}

// ─── /committees (Gap 5) ────────────────────────────────────────────────────

/// `GET /committees?epoch={n}&k={k}&from={zone}&limit={n}` —
/// paginated per-zone VRF committee snapshot.
///
/// For every active leaf zone in the registry on the requested page,
/// computes the stake-weighted VRF committee that the protocol would
/// pick for `(zone, epoch)` with committee-size `k`. Params:
///
/// - `epoch` (optional): defaults to the node's current epoch.
/// - `k` (optional): defaults to [`zone_committee::DEFAULT_COMMITTEE_SIZE`].
/// - `from` (optional): inclusive lower bound on zone path (lex). Used
///   to start the next page; pass the response's `next_from`.
/// - `limit` (optional): page size.
///   Defaults to [`zone_committee::DEFAULT_COMMITTEES_PAGE_SIZE`] (1000).
///
/// Without pagination, at 1M active zones a single
/// response would compute 1M committees and serialize a ~250 MB JSON
/// payload, OOM-ing the serving node and most operator dashboards.
/// The response includes `next_from`: a zone-path string to start the
/// next page from, or `null` when the active set is exhausted.
///
/// This is observability-only in Phase 5 — the committees are not yet
/// enforced at the attestation layer (that's Phase 6). Two honest
/// nodes on the same epoch with the same VRF registry + ledger must
/// return byte-identical JSON for the same `(epoch, k, from, limit)`;
/// operators can diff against peers to catch registry or stake
/// divergence.
pub async fn compute_committees_snapshot(
    state: Arc<NodeState>,
    epoch: Option<u64>,
    k: Option<usize>,
    from: Option<String>,
    limit: Option<usize>,
) -> serde_json::Value {
    let epoch = match epoch {
        Some(e) => e,
        None => state.dag.read().await.current_epoch(),
    };
    let k = k.unwrap_or(crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE);
    // Clamp the peer-supplied `?limit=` to MAX_COMMITTEES_PAGE_SIZE. Unclamped,
    // `?limit=1000000` would materialize a million-entry page (each entry runs a
    // per-zone committee draw) — an OOM-at-scale violation — and an absurd value
    // feeds the start_idx+limit pagination math downstream. .min() after unwrap
    // so the echoed `page_size` reflects the real cap, not the requested one.
    let limit = limit
        .unwrap_or(crate::network::zone_committee::DEFAULT_COMMITTEES_PAGE_SIZE)
        .min(crate::network::zone_committee::MAX_COMMITTEES_PAGE_SIZE);

    let (committees, next_from) =
        crate::network::zone_committee::state_committees_snapshot(
            &state,
            epoch,
            k,
            from.as_deref(),
            limit,
        )
        .await;

    serde_json::json!({
        "epoch": epoch,
        "committee_size": k,
        "page_size": limit,
        "zone_count": committees.len(),
        "next_from": next_from,
        "committees": committees,
    })
}

pub async fn committees_snapshot(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let epoch = params.get("epoch").and_then(|s| s.parse::<u64>().ok());
    let k = params.get("k").and_then(|s| s.parse::<usize>().ok());
    let from = params.get("from").cloned();
    let limit = params.get("limit").and_then(|s| s.parse::<usize>().ok());
    Json(compute_committees_snapshot(state, epoch, k, from, limit).await)
}

/// `GET /committees/is_member?zone=X&epoch=N&id=hash&k=K` — membership predicate.
///
/// Answers "is this identity in the committee for (zone, epoch)?"
/// Phase 6b (Gap 5 first slice): backed by the shared
/// `ZoneCommitteeResolver` cache on `NodeState`, so high-rate
/// dashboard polling doesn't redo the `O(n log n)` Efraimidis–Spirakis
/// sort. ADVISORY ONLY — the consensus hot path consults the resolver
/// behind `enforce_per_zone_vrf` (default off). Phase 6c will flip the
/// flag once the resolver soaks under live load.
///
/// Query params: `zone` (required, zone path string), `id` (required,
/// identity hash). Optional: `epoch` (defaults to current dag epoch),
/// `k` (defaults to `DEFAULT_COMMITTEE_SIZE`).
pub async fn compute_committees_is_member(
    state: Arc<NodeState>,
    zone: Option<String>,
    id: Option<String>,
    epoch: Option<u64>,
    k: Option<usize>,
) -> serde_json::Value {
    let zone = match zone {
        Some(z) => z,
        None => {
            return serde_json::json!({
                "error": "missing required query param: zone"
            });
        }
    };
    let id = match id {
        Some(i) => i,
        None => {
            return serde_json::json!({
                "error": "missing required query param: id"
            });
        }
    };
    let epoch = match epoch {
        Some(e) => e,
        None => state.dag.read().await.current_epoch(),
    };
    let k = k.unwrap_or(crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE);

    let (is_member, rank) =
        crate::network::zone_committee::state_is_in_committee(&state, &zone, epoch, k, &id).await;

    serde_json::json!({
        "zone": zone,
        "epoch": epoch,
        "committee_size": k,
        "identity": id,
        "is_member": is_member,
        "selection_rank": rank,
    })
}

pub async fn committees_is_member(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let zone = params.get("zone").cloned();
    let id = params.get("id").cloned();
    let epoch = params.get("epoch").and_then(|s| s.parse::<u64>().ok());
    let k = params.get("k").and_then(|s| s.parse::<usize>().ok());
    Json(compute_committees_is_member(state, zone, id, epoch, k).await)
}

// ─── /routing/resolve (Gap 4 close-out) ────────────────────────────────────

/// `GET /routing/resolve?record_id=X&key=HEX` — resolve a record to its
/// current leaf zone via the live [`ZoneRegistry`].
///
/// Given a `record_id`, this handler (1) computes the legacy flat-modulo
/// zone via [`super::super::consensus::zone_for_record`], then (2) walks
/// the registry's split/merge tree using the supplied 32-byte `key` —
/// typically `sha3(identity_hash)` in hex — to reach the current leaf.
///
/// The `key` query param is optional. If omitted, a 32-byte zero key is
/// used, which walks every split through its `child_low` branch. That's a
/// deterministic default for operator spot-checks but NOT the right key
/// for live routing: clients should pass the account-level routing hash
/// so accounts land consistently under split boundaries.
///
/// Observability-only: this endpoint does not influence any consensus
/// or ingest decision. Gap 4 enforcement (wiring `zone_for_record`
/// callers to resolve through the registry) is a follow-up that touches
/// 80+ call sites and is deferred.
///
/// Response shape:
/// ```json
/// {
///   "record_id": "...",
///   "routing_key": "<hex32>",
///   "naive_zone": "0",
///   "resolved_zone": "0/a",
///   "redirected": true,
///   "registry": { "active_count": 2, "highest_effective_epoch": 5 }
/// }
/// ```
/// Transport-agnostic body for `/routing/resolve`. Shared between the axum
/// handler and the PQ-transport router. Infallible-by-design: malformed
/// inputs (missing record_id, bad hex, wrong key length) return a 200 OK
/// with the in-band `{"error": ...}` envelope so PQ and HTTPS render the
/// same body byte-for-byte.
pub fn compute_routing_resolve(
    state: &Arc<NodeState>,
    record_id: Option<String>,
    key_hex: Option<String>,
) -> serde_json::Value {
    let record_id = match record_id {
        Some(r) if !r.is_empty() => r,
        _ => {
            return serde_json::json!({
                "error": "missing required query param: record_id"
            });
        }
    };

    let (routing_key, routing_key_hex) = match key_hex {
        Some(hex_str) => {
            let bytes = match hex::decode(&hex_str) {
                Ok(b) => b,
                Err(e) => {
                    return serde_json::json!({
                        "error": format!("invalid hex for key: {e}")
                    });
                }
            };
            if bytes.len() != 32 {
                return serde_json::json!({
                    "error": format!(
                        "key must decode to 32 bytes, got {}", bytes.len()
                    )
                });
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            (k, hex_str)
        }
        None => ([0u8; 32], hex::encode([0u8; 32])),
    };

    state
        .zone_routing_resolve_queries_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let naive = crate::network::consensus::zone_for_record(&record_id);

    let (resolution, active_count, highest_epoch) = {
        let reg = state.zone_registry.read_recover();
        let res = crate::network::zone_registry::resolve_current_leaf(
            &reg, &naive, &routing_key,
        );
        (res, reg.active_count(), reg.highest_effective_epoch())
    };

    if resolution.redirected {
        state
            .zone_routing_resolve_redirected_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    serde_json::json!({
        "record_id": record_id,
        "routing_key": routing_key_hex,
        "naive_zone": resolution.naive_zone.path(),
        "resolved_zone": resolution.resolved_zone.path(),
        "redirected": resolution.redirected,
        "registry": {
            "active_count": active_count,
            "highest_effective_epoch": highest_epoch,
        }
    })
}

/// Axum adapter — thin wrapper around [`compute_routing_resolve`].
pub async fn routing_resolve(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let record_id = params.get("record_id").cloned();
    let key_hex = params.get("key").cloned();
    Json(compute_routing_resolve(&state, record_id, key_hex))
}

// ─── /vrf/registry ───────────────────────────────────────────────────────────

/// GET `/vrf/registry` — per-anchor VRF key registry snapshot.
///
/// Returns every identity currently present in this node's `vrf_registry`,
/// with its registration metadata. Used to diagnose why a node's committee
/// observer reports `skipped_no_candidates` (empty registry) or why
/// peer-anchor VRF registration records aren't cross-registering via gossip.
///
/// Response:
/// ```json
/// {
///   "count": 2,
///   "self_identity": "<this node's identity hash>",
///   "genesis_authority": "<genesis authority identity hash>",
///   "registrations": [
///     {
///       "identity_hash": "<identity hash>",
///       "vrf_public_key_hex": "<32 bytes hex>",
///       "has_full_key": true,
///       "registered_at": 1729123456.789,
///       "record_id": "local-bootstrap",
///       "node_type": "anchor"
///     },
///     ...
///   ]
/// }
/// ```
///
/// `record_id == "local-bootstrap"` means this anchor auto-registered itself
/// locally. Any other value means the registration arrived via a DAG record
/// through gossip.
/// Default / hard cap on the number of registrations `/vrf/registry` returns
/// in one response. `count` always reports the TRUE registration total; only
/// the returned `registrations` array is bounded. The registry is reachable
/// over the PQ verb by any handshaked peer and grows with the anchor/witness
/// set, so a single call must not be able to dump the whole registry (up to
/// the 1M-zone-scale node population) as one JSON payload — SCALE RULE:
/// bounded, always. Truncation is detectable by a caller as
/// `registrations.len() < count`. Mirrors the `/epochs` response bound.
const VRF_REGISTRY_DEFAULT_LIMIT: usize = 1000;
const VRF_REGISTRY_MAX_LIMIT: usize = 10_000;

#[derive(serde::Deserialize)]
pub struct VrfRegistryQuery {
    pub limit: Option<usize>,
}

/// Compute `/vrf/registry` payload. Shared between the axum handler and
/// the PQ-transport router. `limit` bounds the returned registration sample
/// (default [`VRF_REGISTRY_DEFAULT_LIMIT`], hard max [`VRF_REGISTRY_MAX_LIMIT`]);
/// the reported `count` stays the true registration total regardless of `limit`.
pub(crate) fn compute_vrf_registry(
    state: Arc<NodeState>,
    limit: Option<usize>,
) -> serde_json::Value {
    use crate::network::RwLockRecover;

    let limit = limit
        .unwrap_or(VRF_REGISTRY_DEFAULT_LIMIT)
        .min(VRF_REGISTRY_MAX_LIMIT);
    let reg = state.vrf_registry.read_recover();
    let ids: Vec<String> = reg
        .registered_identities()
        .into_iter()
        .map(|s| s.to_string())
        .collect();

    let mut entries: Vec<serde_json::Value> = ids
        .iter()
        .filter_map(|id| reg.get_registration(id).map(|r| (id, r)))
        .map(|(id, r)| {
            serde_json::json!({
                "identity_hash": id,
                "vrf_public_key_hex": r.vrf_public_key_hex,
                "has_full_key": !r.vrf_full_public_key_hex.is_empty(),
                "registered_at": r.registered_at,
                "record_id": r.record_id,
                "node_type": r.node_type,
            })
        })
        .collect();
    // Deterministic order so the bounded page is a stable lowest-hash-first
    // slice across calls, not an arbitrary registry-iteration sample.
    entries.sort_by(|a, b| {
        a.get("identity_hash")
            .and_then(|v| v.as_str())
            .cmp(&b.get("identity_hash").and_then(|v| v.as_str()))
    });

    // True total captured BEFORE the page bound so `count` stays honest even
    // when the returned array is capped (caller detects `registrations.len()
    // < count`). `Vec::len` is O(1).
    let total = entries.len();
    entries.truncate(limit);

    serde_json::json!({
        "count": total,
        "self_identity": state.identity.identity_hash,
        "genesis_authority": state.config.genesis_authority,
        "registrations": entries,
    })
}

/// Axum adapter — thin wrapper around [`compute_vrf_registry`].
pub async fn vrf_registry(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<VrfRegistryQuery>,
) -> Json<serde_json::Value> {
    Json(compute_vrf_registry(state, params.limit))
}

// ─── /itc ────────────────────────────────────────────────────────────────────

pub fn compute_itc_status(state: Arc<NodeState>) -> serde_json::Value {
    let summary = {
        let clocks = state.zone_clocks.lock_recover();
        clocks.summary()
    };

    serde_json::json!({
        "itc": summary,
        "events_total": state.itc_events_total.load(std::sync::atomic::Ordering::Relaxed),
        "joins_total": state.itc_joins_total.load(std::sync::atomic::Ordering::Relaxed),
    })
}

pub async fn itc_status(State(state): State<Arc<NodeState>>) -> Json<serde_json::Value> {
    Json(compute_itc_status(state))
}

// ─── /dag/* ──────────────────────────────────────────────────────────────────

/// Compute `/dag/lifecycle` payload. Shared between the axum handler and
/// the PQ-transport router.
pub(crate) async fn compute_dag_lifecycle(
    state: Arc<NodeState>,
) -> serde_json::Value {
    let dag = state.dag.read().await;
    let finalized = state.finalized.read().await;
    let consensus = state.consensus.lock_recover();

    let total = dag.len();
    let finalized_count = finalized.len();
    let attested_count = consensus.tracked_count();
    let pending = total.saturating_sub(finalized_count).saturating_sub(attested_count);

    let tips = dag.tips().len();
    let edges = dag.edge_count();

    serde_json::json!({
        "total_records": total,
        "pending": pending,
        "attested": attested_count,
        "finalized": finalized_count,
        "dag_tips": tips,
        "dag_edges": edges,
        "avg_parents": if total > 0 { (edges as f64 / total as f64 * 100.0).round() / 100.0 } else { 0.0 },
    })
}

/// Axum adapter — thin wrapper around [`compute_dag_lifecycle`].
pub async fn dag_lifecycle(
    State(state): State<Arc<NodeState>>,
) -> Json<serde_json::Value> {
    Json(compute_dag_lifecycle(state).await)
}

/// Default / hard cap on the number of frontier entries `/dag/tips` samples
/// into one response. `tips_count`/`roots_count` always report the TRUE
/// frontier size; only the returned `tips`/`roots` arrays are bounded. This
/// caps the response of a public, unauthenticated endpoint so a single GET
/// cannot pull the entire hot-tier frontier (up to tens of thousands of UUID
/// strings) as one JSON payload — SCALE RULE: bounded, always. Truncation is
/// detectable by a caller as `tips.len() < tips_count`; the 4-key wire
/// envelope is unchanged so explorer decoders keep their fixed schema.
const DAG_TIPS_DEFAULT_LIMIT: usize = 1000;
const DAG_TIPS_MAX_LIMIT: usize = 10_000;

#[derive(serde::Deserialize)]
pub struct DagTipsQuery {
    pub limit: Option<usize>,
}

/// Compute `/dag/tips` payload. Shared between the axum handler and the
/// PQ-transport router. Infallible — returns an empty tips/roots list on a
/// fresh DAG. `limit` bounds the returned frontier sample (default
/// [`DAG_TIPS_DEFAULT_LIMIT`], hard max [`DAG_TIPS_MAX_LIMIT`]); the reported
/// `tips_count`/`roots_count` stay the true frontier sizes regardless of limit.
pub(crate) async fn compute_dag_tips(
    state: Arc<NodeState>,
    limit: Option<usize>,
) -> serde_json::Value {
    let limit = limit
        .unwrap_or(DAG_TIPS_DEFAULT_LIMIT)
        .min(DAG_TIPS_MAX_LIMIT);
    let dag = state.dag.read().await;
    let mut tips: Vec<String> = dag.tips();
    let mut roots: Vec<String> = dag.roots();
    // True frontier sizes captured BEFORE truncation so the reported counts
    // stay honest even when the returned sample is capped.
    let tips_count = tips.len();
    let roots_count = roots.len();
    tips.truncate(limit);
    roots.truncate(limit);

    serde_json::json!({
        "tips": tips,
        "tips_count": tips_count,
        "roots": roots,
        "roots_count": roots_count,
    })
}

/// Axum adapter — thin wrapper around [`compute_dag_tips`].
pub async fn dag_tips(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<DagTipsQuery>,
) -> Json<serde_json::Value> {
    Json(compute_dag_tips(state, params.limit).await)
}

#[derive(serde::Deserialize)]
pub struct GraphQuery {
    depth: Option<usize>,
    direction: Option<String>,
}

pub async fn compute_dag_record_graph(
    state: Arc<NodeState>,
    id: String,
    depth: Option<usize>,
    direction: Option<String>,
) -> serde_json::Value {
    let max_depth = depth.unwrap_or(5).min(20);
    let direction = direction.unwrap_or_else(|| "both".to_string());

    // Bounded walks (depth + node-count): this endpoint serializes the full
    // ancestor/descendant LISTS into the response, so an unbounded walk is both a
    // compute/lock-hold AND a response-size amplifier. `truncated` signals when
    // either neighborhood was clipped — never silently capped.
    //
    // Hold the DAG read lock for exactly the graph reads (existence + adjacency +
    // the two bounded BFS walks), then DROP it before the sort + JSON serialize.
    // Every accessor returns OWNED data, so the guard is not needed past the last
    // `dag.*` call. This endpoint is reachable on the public PQ transport, where
    // the per-IP HTTP rate limiter does not apply, so keeping the ~20K-id
    // sort+serialize OUT of the lock-hold window shrinks the interval that blocking
    // ingest writers (`dag.write()`) wait behind.
    let mut truncated = false;
    let (exists, parents, children, mut ancestors, mut descendants) = {
        let dag = state.dag.read().await;
        let exists = dag.contains(&id);
        let parents = dag.parents(&id);
        let children = dag.children(&id);
        let ancestors: Vec<String> = if direction == "both" || direction == "ancestors" {
            let (set, capped) = dag.ancestors_capped(&id, max_depth, MAX_DAG_WALK_NODES);
            truncated |= capped;
            set.into_iter().collect()
        } else {
            vec![]
        };
        let descendants: Vec<String> = if direction == "both" || direction == "descendants" {
            let (set, capped) = dag.descendants_capped(&id, max_depth, MAX_DAG_WALK_NODES);
            truncated |= capped;
            set.into_iter().collect()
        } else {
            vec![]
        };
        (exists, parents, children, ancestors, descendants)
    }; // dag read guard dropped here — sort + serialize below run lock-free

    ancestors.sort();
    descendants.sort();

    serde_json::json!({
        "record_id": id,
        "exists": exists,
        "depth": max_depth,
        "direction": direction,
        "parents": parents,
        "parents_count": parents.len(),
        "children": children,
        "children_count": children.len(),
        "ancestors": ancestors,
        "ancestors_count": ancestors.len(),
        "descendants": descendants,
        "descendants_count": descendants.len(),
        "truncated": truncated,
    })
}

pub async fn dag_record_graph(
    State(state): State<Arc<NodeState>>,
    AxumPath(id): AxumPath<String>,
    Query(params): Query<GraphQuery>,
) -> Json<serde_json::Value> {
    Json(compute_dag_record_graph(state, id, params.depth, params.direction).await)
}

#[derive(serde::Deserialize, Default)]
pub struct DagSearchQuery {
    pub op: Option<String>,
    pub creator: Option<String>,
    pub to: Option<String>,
    pub from: Option<String>,
    pub since: Option<f64>,
    pub until: Option<f64>,
    pub limit: Option<usize>,
    pub classification: Option<String>,
    pub has_key: Option<String>,
}

/// Transport-agnostic body for `/dag/search`. Shared between the axum handler
/// and the PQ-transport router (`pq_transport::router::handle_dag_search`)
/// so accounts/explorers reading via PQ get byte-identical results.
pub async fn compute_dag_search(
    state: Arc<NodeState>,
    params: DagSearchQuery,
) -> crate::errors::Result<serde_json::Value> {
    let limit = params.limit.unwrap_or(50).min(500);
    let since = params.since;
    let until = params.until;

    let classification = params.classification.as_deref().and_then(|c| {
        match c.to_lowercase().as_str() {
            "public" => Some(Classification::Public),
            "private" => Some(Classification::Private),
            "restricted" => Some(Classification::Restricted),
            "sovereign" => Some(Classification::Sovereign),
            _ => None,
        }
    });

    let fetch_limit = if params.op.is_some() || params.creator.is_some()
        || params.to.is_some() || params.from.is_some() || params.has_key.is_some()
    {
        limit * 10
    } else {
        limit
    };

    let state2 = state.clone();
    let records = tokio::task::spawn_blocking(move || -> crate::errors::Result<Vec<crate::record::ValidationRecord>> {
        let storage = state2.rocks.as_ref();
        storage.query(classification, None, since, until, fetch_limit)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    let op_filter = params.op.as_deref();
    let creator_filter = params.creator.as_deref();
    let to_filter = params.to.as_deref();
    let from_filter = params.from.as_deref();
    let has_key_filter = params.has_key.as_deref();

    let mut results: Vec<serde_json::Value> = Vec::new();

    for record in &records {
        if results.len() >= limit {
            break;
        }

        if let Some(want_creator) = creator_filter {
            let hash = creator_identity_hash(record);
            if hash != want_creator {
                continue;
            }
        }

        if let Some(want_op) = op_filter {
            match record.metadata.get("beat_op").and_then(|v| v.as_str()) {
                Some(op) if op == want_op => {}
                _ => continue,
            }
        }

        if let Some(want_to) = to_filter {
            match record.metadata.get("beat_to").and_then(|v| v.as_str()) {
                Some(to) if to == want_to => {}
                _ => continue,
            }
        }

        if let Some(want_from) = from_filter {
            match record.metadata.get("beat_from").and_then(|v| v.as_str()) {
                Some(from) if from == want_from => {}
                _ => continue,
            }
        }

        if let Some(key) = has_key_filter {
            if !record.metadata.contains_key(key) {
                continue;
            }
        }

        let mut entry = serde_json::json!({
            "id": record.id,
            "timestamp": record.timestamp,
            "classification": record.classification.name(),
            "creator_hash": creator_identity_hash(record),
            "parents": record.parents,
            "content_hash": hex::encode(&record.content_hash),
            "has_signature": record.signature.is_some(),
        });

        if let Ok(Some(op)) = extract_ledger_op(record) {
            entry["beat_op"] = format_op(&op);
        }

        if let Some(epoch_op) = record.metadata.get("epoch_op") {
            entry["epoch_op"] = epoch_op.clone();
            if let Some(n) = record.metadata.get("epoch_number") {
                entry["epoch_number"] = n.clone();
            }
        }

        results.push(entry);
    }

    Ok(serde_json::json!({
        "results": results,
        "count": results.len(),
        "limit": limit,
        "filters": {
            "op": op_filter,
            "creator": creator_filter,
            "to": to_filter,
            "from": from_filter,
            "since": since,
            "until": until,
            "classification": params.classification,
            "has_key": has_key_filter,
        },
    }))
}

/// Axum adapter — thin wrapper around [`compute_dag_search`].
pub async fn dag_search(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<DagSearchQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let body = compute_dag_search(state, params).await?;
    Ok(Json(body))
}

/// Cached dag_stats result with TTL. Computing stats requires a full CF_RECORDS
/// scan which takes 7-30+ seconds depending on disk speed and record count.
/// Cache for 30 minutes since these stats change slowly.
/// `warm_stats_cache` is now a no-op. The
/// `/dag/stats` endpoint reads `state.record_stats_snapshot_json()` (O(1)
/// atomic loads) instead of running an O(all_records) `for_each_record`
/// scan. The `EPOCH_HEADERS_CACHE` it used to populate is filled lazily by
/// `compute_dag_epoch_headers` on first request via the CF_EPOCHS index,
/// which is itself O(seals_returned). Kept as a public no-op so existing
/// boot-side and stale-cache callers (`compute_dag_stats`,
/// `compute_dag_epoch_headers`, `elara_node` startup) keep compiling without
/// each becoming a follow-up.
pub fn warm_stats_cache(_state: Arc<NodeState>) {}

pub async fn compute_dag_stats(
    state: Arc<NodeState>,
) -> crate::errors::Result<serde_json::Value> {
    // O(1) atomic load. Counters are bumped at the ingest
    // chokepoint (`ingest::insert_record_inner_direct`) and boot-seeded
    // from CF_IDX_TIMESTAMP via the existing subsystem rebuild scan.
    Ok(state.record_stats_snapshot_json())
}

pub async fn dag_stats(
    State(state): State<Arc<NodeState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(compute_dag_stats(state).await?))
}

// ─── /disputes ───────────────────────────────────────────────────────────────

/// `/disputes` payload. Intentionally NOT page-bounded like `/challenges`: the
/// dispute store is hard-capped at `MAX_DISPUTES = 1000` (dispute.rs — resolved
/// disputes auto-evicted past the cap), so `all_disputes()` is O(≤1000) and the
/// response can never dump more than the store cap. The bound lives at the store
/// layer, not here. `total` is the status-filtered count.
pub fn compute_list_disputes(
    state: Arc<NodeState>,
    status: Option<String>,
) -> serde_json::Value {
    let disputes = state.disputes.read_recover();

    let all: Vec<serde_json::Value> = disputes.all_disputes()
        .iter()
        .filter(|d| {
            status.as_deref().is_none_or(|s| {
                let ds = format!("{:?}", d.status).to_lowercase();
                ds == s.to_lowercase()
            })
        })
        .map(|d| serde_json::to_value(d).unwrap_or_default())
        .collect();

    let opened_total = state.disputes_opened_total.load(std::sync::atomic::Ordering::Relaxed);

    serde_json::json!({
        "total": all.len(),
        "disputes_opened_total": opened_total,
        "disputes": all,
    })
}

pub async fn list_disputes(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let status = params.get("status").cloned();
    Json(compute_list_disputes(state, status))
}

pub fn compute_dispute_detail(
    state: Arc<NodeState>,
    id: String,
) -> crate::errors::Result<serde_json::Value> {
    let disputes = state.disputes.read_recover();
    let dispute = disputes.get(&id)
        .ok_or_else(|| ElaraError::RecordNotFound(format!("dispute {id} not found")))?;
    Ok(serde_json::to_value(dispute).unwrap_or_default())
}

pub async fn dispute_detail(
    State(state): State<Arc<NodeState>>,
    AxumPath(id): AxumPath<String>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    Ok(Json(compute_dispute_detail(state, id)?))
}

// ─── /proofs/* ───────────────────────────────────────────────────────────────

/// Compute `/proofs/{record_id}` payload. Shared between the axum handler
/// and the PQ-transport router. Snapshots the active
/// ZoneRegistry (Gap 4 Phase C2) so the proof resolves the record's zone
/// through the transition tree instead of naive flat-modulo.
pub(crate) async fn compute_merkle_proof(
    state: Arc<NodeState>,
    record_id: String,
) -> crate::errors::Result<serde_json::Value> {
    let rid = record_id.clone();
    let registry_snapshot = {
        use crate::network::RwLockRecover;
        state.zone_registry.read_recover().clone()
    };
    let result = crate::network::light::generate_proof(&state.rocks, &rid, Some(&registry_snapshot))?;

    match result {
        Some((proof, zone)) => Ok(serde_json::json!({
            "record_id": record_id,
            "zone": zone,
            "leaf": hex::encode(proof.leaf),
            "root": hex::encode(proof.root),
            "siblings": proof.siblings.iter().map(|s| serde_json::json!({
                "hash": hex::encode(s.hash),
                "is_right": s.is_right,
            })).collect::<Vec<_>>(),
            "verified": crate::network::merkle::verify_proof(&proof),
        })),
        None => Err(ElaraError::RecordNotFound(format!("no proof for record {record_id}"))),
    }
}

/// Axum adapter — thin wrapper around [`compute_merkle_proof`].
pub async fn merkle_proof(
    State(state): State<Arc<NodeState>>,
    AxumPath(record_id): AxumPath<String>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let body = compute_merkle_proof(state, record_id).await?;
    Ok(Json(body))
}

/// Compute `/zone/{zone}/proof/{record_hash}` payload. Shared between the
/// axum handler and the PQ-transport router. Returns
/// the per-zone Sparse Merkle proof for a 32-byte record hash; verification
/// flag is computed inline so callers don't have to re-run it.
pub(crate) async fn compute_zone_merkle_proof(
    state: Arc<NodeState>,
    zone: u64,
    record_hash_hex: String,
) -> crate::errors::Result<serde_json::Value> {
    let hash_bytes = hex::decode(&record_hash_hex)
        .map_err(|_| ElaraError::Wire("invalid hex record_hash".into()))?;
    if hash_bytes.len() != 32 {
        return Err(ElaraError::Wire("record_hash must be 32 bytes (64 hex chars)".into()));
    }
    let mut leaf_hash = [0u8; 32];
    leaf_hash.copy_from_slice(&hash_bytes);

    let tree = crate::network::merkle::SparseMerkleTree::new(&state.rocks, ZoneId::from_legacy(zone));
    match tree.proof(&leaf_hash)? {
        Some(proof) => {
            let verified = crate::network::merkle::verify_proof(&proof);
            Ok(serde_json::json!({
                "zone": zone,
                "leaf": hex::encode(proof.leaf),
                "root": hex::encode(proof.root),
                "siblings": proof.siblings.iter().map(|s| serde_json::json!({
                    "hash": hex::encode(s.hash),
                    "is_right": s.is_right,
                })).collect::<Vec<_>>(),
                "verified": verified,
                "sibling_count": proof.siblings.len(),
            }))
        }
        None => Err(ElaraError::RecordNotFound(
            format!("no proof for hash {} in zone {}", record_hash_hex, zone)
        )),
    }
}

/// Axum adapter — thin wrapper around [`compute_zone_merkle_proof`].
pub async fn zone_merkle_proof(
    State(state): State<Arc<NodeState>>,
    AxumPath((zone, record_hash_hex)): AxumPath<(u64, String)>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let body = compute_zone_merkle_proof(state, zone, record_hash_hex).await?;
    Ok(Json(body))
}

// ─── /proofs/cross-zone (Protocol §11.22.1) ──────────────────────────────────

/// Compute `/proofs/cross-zone/{record_id}/{target_zone}` payload. Shared
/// between the axum handler and the PQ-transport router.
pub(crate) async fn compute_cross_zone_proof(
    state: Arc<NodeState>,
    record_id: String,
    target_zone_str: String,
) -> crate::errors::Result<serde_json::Value> {
    let target_zone = ZoneId::new(&target_zone_str);
    let rocks = state.rocks.clone();
    let rid = record_id.clone();
    // Gap 4 Phase C2: snapshot the registry OUTSIDE spawn_blocking so the
    // async read-lock does not cross the blocking boundary. The clone is a
    // bounded structure (depth ≤ 20 today) — fine at current scale.
    let registry_snapshot = {
        use crate::network::RwLockRecover;
        state.zone_registry.read_recover().clone()
    };

    let result = tokio::task::spawn_blocking(move || {
        crate::network::merkle::generate_cross_zone_proof(&rocks, &rid, &target_zone, Some(&registry_snapshot))
    }).await.map_err(|e| ElaraError::Storage(format!("spawn_blocking: {e}")))??;

    match result {
        Some(proof) => {
            let verification = crate::network::merkle::verify_cross_zone_proof(&proof);
            Ok(serde_json::json!({
                "record_id": proof.record_id,
                "record_hash": hex::encode(proof.record_hash),
                "source_zone": proof.source_zone.to_string(),
                "target_zone": proof.target_zone.to_string(),
                "target_epoch": proof.target_epoch,
                "seal_record_id": proof.seal_record_id,
                "seal_merkle_root": hex::encode(proof.seal_merkle_root),
                "proof": {
                    "leaf": hex::encode(proof.merkle_proof.leaf),
                    "root": hex::encode(proof.merkle_proof.root),
                    "siblings": proof.merkle_proof.siblings.iter().map(|s| serde_json::json!({
                        "hash": hex::encode(s.hash),
                        "is_right": s.is_right,
                    })).collect::<Vec<_>>(),
                },
                "verification": {
                    "proof_valid": verification.proof_valid,
                    "root_matches_seal": verification.root_matches_seal,
                    "zone_matches": verification.zone_matches,
                    "leaf_matches": verification.leaf_matches,
                    "verified": verification.verified,
                },
            }))
        }
        None => Err(ElaraError::RecordNotFound(
            format!("no cross-zone proof for {} in zone {}", record_id, target_zone_str)
        )),
    }
}

/// Axum adapter — thin wrapper around [`compute_cross_zone_proof`].
pub async fn cross_zone_proof(
    State(state): State<Arc<NodeState>>,
    AxumPath((record_id, target_zone_str)): AxumPath<(String, String)>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let body = compute_cross_zone_proof(state, record_id, target_zone_str).await?;
    Ok(Json(body))
}

// ─── Gap 2: /xzone introspection endpoints ──────────────────────────────────
//
// Reads come from `ledger.cross_zone` (in-memory `HashMap<transfer_id, ...>`).
// Size is bounded: only Locked/Claimed/Refunded records younger than
// `prune_completed`'s 48h cutoff are retained. Scans the map — O(pending_count)
// — and NEVER touches CF_RECORDS. Safe to call from accounts on every status
// poll.

/// `GET /xzone/stats` — summary counters + gauges for dashboards and scripts.
pub async fn compute_xzone_stats(state: Arc<NodeState>) -> serde_json::Value {
    use std::sync::atomic::Ordering::Relaxed;
    let locks = state.xzone_locks_total.load(Relaxed);
    let claims = state.xzone_claims_total.load(Relaxed);
    let refunds = state.xzone_refunds_total.load(Relaxed);
    let aborts = state.xzone_aborts_total.load(Relaxed);
    let cancels = state.xzone_cancels_total.load(Relaxed);
    let rejects = state.xzone_rejects_total.load(Relaxed);

    // Read pre-maintained per-status counters in O(1) instead of
    // scanning `pending.values()` (O(n) under ledger.read() lock — at 1M
    // concurrent transfers a 30s scrape blocks state_core writes for
    // hundreds of ms). The counters are kept in sync at every status
    // mutation site in `CrossZoneState`; the invariant is pinned by
    // `cross_zone::tests::ops152_status_counters_invariant_under_random_ops`.
    let ledger = state.ledger.read().await;
    let locked = ledger.cross_zone.locked_count;
    let claimed = ledger.cross_zone.claimed_count;
    let refunded = ledger.cross_zone.refunded_count;
    let aborted = ledger.cross_zone.aborted_count;
    let total_pending = ledger.cross_zone.pending.len() as u64;
    let total_locked_micros = ledger.pending_xzone_locked;
    drop(ledger);

    serde_json::json!({
        "counters": {
            "locks_total": locks,
            "claims_total": claims,
            "refunds_total": refunds,
            "aborts_total": aborts,
            "cancels_total": cancels,
            "rejects_total": rejects,
        },
        "pending": {
            "total": total_pending,
            "locked": locked,
            "claimed": claimed,
            "refunded": refunded,
            "aborted": aborted,
        },
        "currently_locked_micros": total_locked_micros,
        "claim_timeout_secs": crate::accounting::cross_zone::CLAIM_TIMEOUT_SECS,
    })
}

pub async fn xzone_stats(
    State(state): State<Arc<NodeState>>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    Ok(Json(compute_xzone_stats(state).await))
}

fn serialize_transfer(t: &crate::accounting::cross_zone::PendingTransfer) -> serde_json::Value {
    serde_json::json!({
        "transfer_id": t.transfer_id,
        "sender": t.sender,
        "recipient": t.recipient,
        "amount": t.amount,
        "source_zone": t.source_zone.to_string(),
        "dest_zone": t.dest_zone.to_string(),
        "locked_at": t.locked_at,
        "expires_at": t.expires_at,
        "status": match t.status {
            crate::accounting::cross_zone::TransferStatus::Locked => "locked",
            crate::accounting::cross_zone::TransferStatus::Claimed => "claimed",
            crate::accounting::cross_zone::TransferStatus::Refunded => "refunded",
            crate::accounting::cross_zone::TransferStatus::Aborted => "aborted",
        },
        "has_proof": !t.merkle_proof.is_empty(),
        "lock_record_hash": hex::encode(t.lock_record_hash),
        "source_merkle_root": hex::encode(t.source_merkle_root),
        "claim_record_id": t.claim_record_id,
    })
}

/// `GET /xzone/transfers?status=locked&limit=100` — list pending transfers.
///
/// Optional filters:
///   - `status=locked|claimed|refunded` (default: all)
///   - `sender=<identity_hash>` (exact match)
///   - `recipient=<identity_hash>` (exact match)
///   - `limit=N` (default 100, cap 1000)
pub async fn compute_xzone_transfers(
    state: Arc<NodeState>,
    status: Option<String>,
    sender: Option<String>,
    recipient: Option<String>,
    limit: Option<usize>,
) -> serde_json::Value {
    use crate::accounting::cross_zone::TransferStatus;

    let status_filter: Option<TransferStatus> = status.as_deref().and_then(|s| match s {
        "locked" => Some(TransferStatus::Locked),
        "claimed" => Some(TransferStatus::Claimed),
        "refunded" => Some(TransferStatus::Refunded),
        "aborted" => Some(TransferStatus::Aborted),
        _ => None,
    });
    let limit = limit.unwrap_or(100).min(1000);

    let ledger = state.ledger.read().await;
    let mut transfers: Vec<serde_json::Value> = ledger
        .cross_zone
        .pending
        .values()
        .filter(|t| {
            if let Some(ref s) = status_filter {
                if &t.status != s {
                    return false;
                }
            }
            if let Some(ref s) = sender {
                if &t.sender != s {
                    return false;
                }
            }
            if let Some(ref r) = recipient {
                if &t.recipient != r {
                    return false;
                }
            }
            true
        })
        .map(serialize_transfer)
        .collect();
    drop(ledger);

    // Sort: newest first by locked_at so accounts see recent activity up top.
    transfers.sort_by(|a, b| {
        let la = a["locked_at"].as_f64().unwrap_or(0.0);
        let lb = b["locked_at"].as_f64().unwrap_or(0.0);
        lb.total_cmp(&la)
    });
    let total = transfers.len();
    transfers.truncate(limit);

    serde_json::json!({
        "total": total,
        "returned": transfers.len(),
        "transfers": transfers,
    })
}

pub async fn xzone_transfers(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let status = params.get("status").cloned();
    let sender = params.get("sender").cloned();
    let recipient = params.get("recipient").cloned();
    let limit = params.get("limit").and_then(|v| v.parse().ok());
    Ok(Json(compute_xzone_transfers(state, status, sender, recipient, limit).await))
}

/// `GET /xzone/transfer/{transfer_id}` — detail for a single transfer.
///
/// Returns 404 if the transfer is not in the pending map (either never
/// existed or was pruned after 48h). Use `/records/{transfer_id}` to read
/// the underlying LOCK record directly.
pub async fn compute_xzone_transfer(
    state: Arc<NodeState>,
    transfer_id: String,
) -> crate::errors::Result<serde_json::Value> {
    let ledger = state.ledger.read().await;
    let t = ledger
        .cross_zone
        .get(&transfer_id)
        .cloned()
        .ok_or_else(|| ElaraError::RecordNotFound(format!("xzone transfer {transfer_id}")))?;
    drop(ledger);
    Ok(serialize_transfer(&t))
}

pub async fn xzone_transfer(
    State(state): State<Arc<NodeState>>,
    AxumPath(transfer_id): AxumPath<String>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    Ok(Json(compute_xzone_transfer(state, transfer_id).await?))
}

/// `GET /xzone/bundle/{transfer_id}` — self-contained, client-verifiable
/// proof that a cross-zone transfer reached source-zone finality (Gap 2.2).
///
/// Returns the JSON-serialized [`XZoneTransferBundle`] — a account, light
/// client, or destination-zone validator deserializes the body, calls
/// `XZoneTransferBundle::verify()`, and on success knows the lock is sealed
/// and the source-zone seal has 2/3 committee finality, all without
/// fetching the source-zone DAG. Distinct from `/xzone/transfer/{id}` which
/// returns metadata only (no merkle proof, no signers).
///
/// Status codes:
/// * 200 — bundle assembled. Caller verifies offline.
/// * 404 — transfer not found (never existed or pruned after 48h).
/// * 409 — transfer found but not yet sealed-and-finalized; the bundle's
///   merkle proof and committee signatures aren't populated yet. Retry
///   after the next epoch boundary.
pub async fn compute_xzone_bundle(
    state: Arc<NodeState>,
    transfer_id: String,
) -> crate::errors::Result<serde_json::Value> {
    let ledger = state.ledger.read().await;
    let pt = ledger
        .cross_zone
        .get(&transfer_id)
        .cloned()
        .ok_or_else(|| ElaraError::RecordNotFound(format!("xzone transfer {transfer_id}")))?;
    drop(ledger);
    let bundle = crate::accounting::cross_zone::XZoneTransferBundle::from_pending(&pt)
        .ok_or_else(|| {
            ElaraError::Wire(format!(
                "xzone transfer {transfer_id} not yet sealed-and-finalized — retry after next epoch boundary"
            ))
        })?;
    // Internal serialize fault → Json (500, detail withheld), not Wire (400, echoed).
    serde_json::to_value(&bundle).map_err(ElaraError::Json)
}

pub async fn xzone_bundle(
    State(state): State<Arc<NodeState>>,
    AxumPath(transfer_id): AxumPath<String>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    Ok(Json(compute_xzone_bundle(state, transfer_id).await?))
}

// ─── /epochs/headers ─────────────────────────────────────────────────────────

/// (cached_at, json values) — the value half is a list of JSON objects
/// (epoch-header summaries or super-seal summaries) whose schema differs
/// per cache instance.
type JsonListCache = std::sync::Mutex<Option<(std::time::Instant, Vec<serde_json::Value>)>>;

/// Cached epoch headers (full CF_RECORDS scan, same as dag_stats).
static EPOCH_HEADERS_CACHE: std::sync::LazyLock<JsonListCache> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));
const EPOCH_HEADERS_TTL: std::time::Duration = std::time::Duration::from_secs(1800);

/// Filter epoch-header entries to the canonical chain per zone.
///
/// The CF_RECORDS scan may surface multiple competing seal records at the
/// same (zone, epoch) — e.g. if a zone emitted a seal, reorg'd, and re-sealed.
/// Light clients walk by `previous_seal_hash`, so serving duplicates breaks
/// their chain-link verification (LightState::add_header rejects everything
/// after the first duplicate).
///
/// Given `tips` = `EpochState.latest_seal_hash` (the node's canonical tip
/// per zone), walk back via `previous_seal_hash` to collect the set of
/// canonical seal_record_hashes, then drop any entry not in that set.
///
/// Safety rails:
/// - If `tips` is empty (fresh node, no seals registered yet) the input
///   is returned unchanged — the node has nothing to compare against.
/// - If a tip IS present for a zone, entries for that zone are filtered
///   to the canonical chain.
/// - If a zone is present in `headers` but has NO registered tip in `tips`,
///   its entries are passed through unfiltered. (Tips can lag behind disk
///   right after a restart — `EpochSnapshot` is taken every 15 epochs so
///   the in-memory map can be empty for zones whose seals are on disk
///   but pre-snapshot. Dropping them blocks light-client cold sync.) The
///   light client's `LightState::add_header` does its own per-zone chain
///   check via `previous_seal_hash`, so passthrough is safe.
/// - Entries missing `seal_record_hash` (pre-fix emitters) are kept — the
///   next light-client sync will re-fetch once those upstream nodes upgrade.
/// - Cycle-safe (HashSet insert-first guards against bogus chains).
///
/// Complexity: O(N) index build + O(sum of chain lengths) walkback + O(N)
/// filter. At 2000 entries max per response this is negligible.
fn filter_canonical_chain(
    headers: Vec<serde_json::Value>,
    tips: &HashMap<ZoneId, [u8; 32]>,
) -> Vec<serde_json::Value> {
    if tips.is_empty() || headers.is_empty() {
        return headers;
    }

    // Index by seal_record_hash for O(1) walk-back lookup.
    let mut by_hash: HashMap<[u8; 32], usize> = HashMap::with_capacity(headers.len());
    for (i, h) in headers.iter().enumerate() {
        if let Some(hex_str) = h.get("seal_record_hash").and_then(|v| v.as_str()) {
            if let Ok(bytes) = hex::decode(hex_str) {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    by_hash.insert(arr, i);
                }
            }
        }
    }

    // For each zone with a tip, walk back via previous_seal_hash.
    let mut canonical: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for tip_hash in tips.values() {
        if *tip_hash == [0u8; 32] {
            continue;
        }
        let mut cur = *tip_hash;
        while cur != [0u8; 32] {
            if !canonical.insert(cur) {
                break; // cycle guard — shouldn't happen on honest data
            }
            let idx = match by_hash.get(&cur) {
                Some(i) => *i,
                None => break, // reached a hash we don't have (genesis or pruned)
            };
            let prev_hex = headers[idx]
                .get("previous_seal_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let prev_bytes = match hex::decode(prev_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => break,
            };
            cur.copy_from_slice(&prev_bytes);
        }
    }

    // Zones with a *non-zero* registered tip — entries for these zones MUST
    // be on the chain. Zones with a zero tip (init/genesis sentinel) are
    // treated as "no tip" so their entries pass through unfiltered (the
    // walkback above already skipped zero-tip zones, so canonical would
    // be empty for them — keeping them in tip_zones would drop everything).
    //
    // Also pass-through any zone whose tip we could
    // not seat in the walkback (`tip_hash` not in `by_hash`).  This
    // happens on paginated `/headers/from/0?limit=K` queries where the
    // returned slice contains the *earliest* K seals (epochs 0..K-1) but
    // the zone tip is at a much later epoch.  Walkback from the tip
    // breaks immediately at the first lookup, `canonical` stays empty,
    // and the filter would drop every returned header — exactly the
    // failure the light-client onboarding sweep exposed.  ZoneId
    // serializes as a JSON string, matching `header.zone` JSON encoding.
    let tip_zones: std::collections::HashSet<String> = tips
        .iter()
        .filter(|(_, hash)| **hash != [0u8; 32] && by_hash.contains_key(*hash))
        .map(|(z, _)| z.to_string())
        .collect();

    headers
        .into_iter()
        .filter(|h| {
            let zone_str = match h.get("zone") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(serde_json::Value::Number(n)) => n.to_string(),
                _ => return true, // unknown zone shape — keep
            };
            if !tip_zones.contains(&zone_str) {
                // Zone has no tip in the in-memory map (e.g. tip
                // hasn't been snapshotted yet, or this node doesn't
                // track that zone's chain). Pass through — light
                // client will chain-verify with its own state.
                return true;
            }
            let srh_str = match h.get("seal_record_hash").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return true, // pre-fix header, no way to verify — keep
            };
            let bytes = match hex::decode(srh_str) {
                Ok(b) if b.len() == 32 => b,
                _ => return true,
            };
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            canonical.contains(&arr)
        })
        .collect()
}

/// Compute `/epochs/headers` payload. Shared between the axum handler
/// (`epoch_headers` below, `headers_from_epoch` forwarder) and the
/// PQ-transport router (`pq_transport::router::handle_headers_from`),
/// so migrating accounts/light-clients off HTTPS doesn't
/// require re-implementing the cold-cache scan.
///
/// Returns `{total: usize, headers: [...]}` in the same shape every
/// caller already parses. No axum types in the signature.
pub async fn compute_epoch_headers(
    state: Arc<NodeState>,
    zone_filter: Option<crate::ZoneId>,
    since: Option<u64>,
    limit: usize,
) -> crate::errors::Result<serde_json::Value> {
    let limit = limit.min(2000);

    use crate::network::epoch::{self, EPOCH_OP_KEY};

    // Light-client request path: when `since > 0` we have a tight epoch lower
    // bound, so seek directly into CF_EPOCHS (bounded O(returned)) rather than
    // serving the (possibly weeks-stale) full-dump cache. The cache is sized
    // for the "show me everything" explorer use case — for header-from-epoch
    // sync we want fresh data with bounded work. Observed on testnet 2026-04-29:
    // EPOCH_HEADERS_CACHE held 420 headers (epoch 40-8898) while CF_EPOCHS had
    // 18K+ seals and current_epoch was 9500 — light clients calling
    // `/headers/from/{epoch}` would never see the post-cache seals, so
    // `LightClient::verify_account` failed with "no Gap-1 headers" forever.
    let bypass_cache = since.is_some_and(|s| s > 0);

    // Try cache first. If stale, return stale + refresh in background.
    //
    // Never trust an empty cached vec. The cache could be
    // poisoned at node startup — when CF_EPOCHS held zero entries the first
    // request computed an empty header list and stored it; once seals later
    // landed and the DISC-5 index populated, the cache continued serving the
    // stale empty vec until next process restart, and `/headers/from/0`
    // returned `{"total":0,"headers":[]}` despite the node holding 20K+ seals.
    // Observed across several nodes during light-client smoke testing, while
    // another node happened to scrape the cache after seals landed.  Light clients
    // onboarding from genesis (`since=0`) silently believed there was nothing
    // to sync.  Recomputing an empty cache costs at most one bounded
    // CF_EPOCHS prefix scan (50K-cap legacy fallback handles the genuinely
    // empty zone case too), so we always recompute when the cache is empty.
    let mut all_headers: Vec<serde_json::Value> = Vec::new();
    let mut need_compute = true;
    if !bypass_cache {
        if let Ok(guard) = EPOCH_HEADERS_CACHE.lock() {
            if let Some((when, ref cached)) = *guard {
                if !cached.is_empty() {
                    all_headers = cached.clone();
                    if when.elapsed() < EPOCH_HEADERS_TTL {
                        need_compute = false;
                    } else {
                        // Stale: return old data, refresh in background
                        drop(guard);
                        warm_stats_cache(state.clone());
                        need_compute = false;
                    }
                }
                // Empty cache + non-empty CF_EPOCHS = poisoned; fall
                // through to recompute below.  Recompute will repopulate
                // the cache so the cost is paid once per stuck node, not
                // once per request.
            }
        }
    }

    if need_compute && all_headers.is_empty() {
        // DISC-5: prefer the CF_EPOCHS prefix-iter index (O(seals_returned),
        // not O(all_records)). Falls back to legacy CF_RECORDS scan if the
        // index hasn't been backfilled yet — keeps fresh nodes serving until
        // the one-time startup backfill completes.
        let state2 = state.clone();
        let zone_filter_inner = zone_filter.clone();
        let since_epoch = since.unwrap_or(0);
        let limit_inner = limit;
        let mut computed: Vec<serde_json::Value> = tokio::task::spawn_blocking(move || -> crate::errors::Result<Vec<serde_json::Value>> {
            let rocks = state2.rocks.as_ref();
            let mut results = Vec::new();
            // Always attempt the CF_EPOCHS prefix-scan
            // index. RocksDB's `estimate-num-keys` (used by
            // `approximate_cf_size`) reports 0 for small/just-flushed CFs even
            // when entries exist, so the previous `use_index =
            // approximate_cf_size > 0` gate falsely skipped the index and
            // fell through to the bounded legacy scan that misses the index'd
            // seals. The prefix-scan is O(returned), not O(all), so trying it
            // unconditionally is cheap when the CF really is empty.
            let use_index = true;

            // Shared closure: build the JSON header for one seal record.
            // Centralized so the index path and the legacy fallback emit the
            // exact same shape for downstream consumers.
            let emit_seal = |rec: &crate::record::ValidationRecord, results: &mut Vec<serde_json::Value>| {
                if let Ok(Some(seal)) = epoch::extract_epoch_seal(rec) {
                    let header = crate::network::light::header_from_seal_with_hash(
                        &seal,
                        rec.record_hash(),
                    );
                    results.push(serde_json::json!({
                        "zone": header.zone,
                        "epoch_number": header.epoch_number,
                        "merkle_root": hex::encode(header.merkle_root),
                        "previous_seal_hash": hex::encode(header.previous_seal_hash),
                        "record_count": header.record_count,
                        "start": header.start,
                        "end": header.end,
                        "account_smt_root": header.account_smt_root.map(hex::encode),
                        "seal_record_hash": header.seal_record_hash.map(hex::encode),
                        "seal_id": rec.id.clone(),
                    }));
                }
            };

            if use_index {
                let seek = since_epoch.to_be_bytes().to_vec();
                rocks.range_scan_cf(crate::storage::rocks::CF_EPOCHS, &seek, |key, _val| {
                    if results.len() >= limit_inner {
                        return Ok(false);
                    }
                    let (_epoch, zone_str, record_id) =
                        match crate::network::epoch::parse_disc5_index_key(key) {
                            Some(t) => t,
                            None => return Ok(true),
                        };
                    if let Some(zf) = zone_filter_inner.as_ref() {
                        if zf.path() != zone_str {
                            return Ok(true);
                        }
                    }
                    if let Ok(Some(rec)) = rocks.get_record(record_id) {
                        emit_seal(&rec, &mut results);
                    }
                    Ok(true)
                })?;
            }

            // Belt-and-braces: if the index path produced nothing — either
            // because `use_index` was false (DISC-5 backfill not run) or
            // because every CF_EPOCHS entry pointed at a pruned record
            // (Hillsboro 2026-04-26: 12.5K index entries → 0 seals because
            // the canary's aggressive pruning removed the underlying
            // records from CF_RECORDS) — scan CF_IDX_TIMESTAMP for the most
            // recent records and pick out epoch seals.
            //
            // Skip this fallback when the caller is doing a `since>0` query
            // (bypass_cache path): light-client requests must remain bounded;
            // empty result → empty response is the right mainnet behavior.
            //
            // Capped at MAX_LEGACY_FALLBACK_SCAN via
            // `for_each_record_ordered_bounded` instead of the unbounded
            // `for_each_record` scan that was here before. At mainnet scale,
            // CF_EPOCHS is always populated and this branch is dead anyway;
            // the cap exists so a misconfigured node can't burn 10M-record
            // CPU per dashboard hit during the index-backfill window.
            const MAX_LEGACY_FALLBACK_SCAN: usize = 50_000;
            if results.is_empty() && !bypass_cache {
                rocks.for_each_record_ordered_bounded(MAX_LEGACY_FALLBACK_SCAN, |rec| {
                    if !rec.metadata.contains_key(EPOCH_OP_KEY) {
                        return;
                    }
                    emit_seal(rec, &mut results);
                })?;
            }
            Ok(results)
        })
        .await
        .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

        computed.sort_by(|a, b| {
            let za = a["zone"].as_u64().unwrap_or(0);
            let zb = b["zone"].as_u64().unwrap_or(0);
            za.cmp(&zb).then_with(|| {
                let ea = a["epoch_number"].as_u64().unwrap_or(0);
                let eb = b["epoch_number"].as_u64().unwrap_or(0);
                ea.cmp(&eb)
            })
        });

        // Only cache when we computed the full unfiltered list (since=0 path).
        // The bypass_cache path returns a since-filtered subset and would
        // poison the cache with a partial view.
        if !bypass_cache {
            if let Ok(mut guard) = EPOCH_HEADERS_CACHE.lock() {
                *guard = Some((std::time::Instant::now(), computed.clone()));
            }
        }
        all_headers = computed;
    }

    // Filter duplicates out: multiple competing seal records can land in
    // CF_RECORDS for the same (zone, epoch). Light clients walk via
    // `previous_seal_hash`, so duplicates break their chain. Use the current
    // `latest_seal_hash` per zone from EpochState to walk back the canonical
    // chain and drop any entry not in it.
    //
    // Skip the canonical filter on the bypass_cache path. The walkback
    // starts at `latest_seal_hash[zone]` (current tip) and walks
    // backwards via `previous_seal_hash`. With `since>0, limit=K` we
    // return only K seals starting at epoch `since`, which is strictly
    // less than tip's epoch — so the tip's hash is NEVER in our
    // returned set, the walkback breaks on the first lookup, the
    // canonical set is empty, and every returned header gets dropped.
    // The light-client SDK already verifies chain integrity locally
    // by walking `previous_seal_hash` itself, so the canonical filter
    // here is duplication-prevention, not security. CF_EPOCHS is
    // populated once per seal at register time so duplicates are rare;
    // when they do occur, the SDK's chain walk catches them.
    if !bypass_cache {
        let tips: HashMap<ZoneId, [u8; 32]> = match state.epoch.read() {
            Ok(ep) => ep.latest_seal_hash.clone(),
            Err(_) => HashMap::new(), // poisoned — skip filter, serve raw
        };
        all_headers = filter_canonical_chain(all_headers, &tips);
    }

    // Apply filters on the canonical/computed list
    let mut headers: Vec<serde_json::Value> = all_headers.into_iter().filter(|h| {
        if let Some(ref z) = zone_filter {
            if h["zone"].as_str().is_none_or(|zs| zs != z.to_string())
                && h["zone"].as_u64().is_none_or(|zn| crate::ZoneId::from_legacy(zn) != *z)
            {
                return false;
            }
        }
        if let Some(s) = since {
            if h["epoch_number"].as_u64().unwrap_or(0) < s {
                return false;
            }
        }
        true
    }).collect();
    headers.truncate(limit);

    Ok(serde_json::json!({
        "total": headers.len(),
        "headers": headers,
    }))
}

/// Axum adapter — thin wrapper around [`compute_epoch_headers`].
pub async fn epoch_headers(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let zone_filter: Option<crate::ZoneId> = params.get("zone").map(|v| crate::ZoneId::new(v));
    let since: Option<u64> = params.get("since").and_then(|v| v.parse().ok());
    let limit: usize = params.get("limit").and_then(|v| v.parse().ok()).unwrap_or(500);
    let body = compute_epoch_headers(state, zone_filter, since, limit).await?;
    Ok(Json(body))
}

// ─── /headers/from/{epoch} ───────────────────────────────────────────────────
//
// Gap 1 light-client shortcut: returns headers with `epoch_number >= {epoch}`.
// Forwards to `epoch_headers` with `since` pre-populated from the path param.
// Retains query params (`zone`, `limit`) so operators can narrow results.
//
// @spec Protocol §11.3 (light client header sync)

pub async fn headers_from_epoch(
    state: State<Arc<NodeState>>,
    AxumPath(epoch): AxumPath<u64>,
    Query(mut params): Query<HashMap<String, String>>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    // Path param overrides any `?since=` that sneaks in — avoids footguns.
    params.insert("since".to_string(), epoch.to_string());
    epoch_headers(state, Query(params)).await
}

// ─── /records/from/{epoch} ───────────────────────────────────────────────────
//
// ZSP Phase C: zone-scoped record sync surface. Bootstrapping leaf nodes that
// only subscribe to a small set of zones MUST be able to ask the responder
// "give me records since epoch N for zone X" — without paying for the other
// 999,999 zones a `FullZone` peer holds.
//
// Path param: `{epoch}` is the per-zone epoch number whose `start` timestamp
// becomes the lower bound of the response. Behavior:
//
//   - `?zone=<id>` REQUIRED to make the epoch number meaningful — different
//     zones epoch at different times. Without `?zone=` we have no mapping
//     from a bare epoch number to a wall-clock timestamp; we serve a 400.
//   - The seal record for `(zone, epoch)` is looked up via the CF_EPOCHS
//     prefix index (no full scan). Its `start` timestamp seeds `since` on
//     the underlying `query_records` call.
//   - The handler then dispatches to `query_records` with `zone`, `since`,
//     `creator`, `limit` so the wire payload is identical to `/records`.
//   - When `?zone=` is set, the underlying handler iterates
//     `CF_RECORD_BY_ZONE` (Phase B index) — bytes-on-wire is bounded by zone
//     size, not global record count.
//
// @spec internal design notes §3 Gap D, §4 Phase C
pub async fn records_from_epoch(
    State(state): State<Arc<NodeState>>,
    AxumPath(epoch): AxumPath<u64>,
    Query(params): Query<HashMap<String, String>>,
) -> std::result::Result<Json<Vec<String>>, AppError> {
    use crate::network::routes::core::{query_records, RecordQuery};

    let zone_str = params.get("zone").cloned().ok_or_else(|| {
        // 400 Bad Request: client supplied an underspecified query. Wire is
        // the right variant — Network maps to 500 in `AppError::into_response`,
        // which would mislead callers into thinking the responder broke.
        ElaraError::Wire(
            "/records/from/{epoch} requires ?zone=<id>; bare epoch number has no \
             cross-zone mapping (different zones seal at different times)".into()
        )
    })?;
    let zone_id = ZoneId::new(&zone_str);

    let limit: usize = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(100);
    let creator: Option<String> = params.get("creator").cloned();

    // Find the seal for `(zone, epoch)` — its `start` timestamp is the lower
    // bound for the record fetch. Walk CF_EPOCHS forward from `epoch` and
    // pick the first matching zone. O(seals_for_higher_epochs_until_first_match)
    // bounded by zone count, never a full scan.
    let state_ts = state.clone();
    let zone_for_seal = zone_id.clone();
    let since_ts = tokio::task::spawn_blocking(move || -> crate::errors::Result<f64> {
        let rocks = state_ts.rocks.as_ref();
        let seek = epoch.to_be_bytes().to_vec();
        let mut found: Option<f64> = None;
        rocks.range_scan_cf(crate::storage::rocks::CF_EPOCHS, &seek, |key, _val| {
            let (e, zone_str, record_id) =
                match crate::network::epoch::parse_disc5_index_key(key) {
                    Some(t) => t,
                    None => return Ok(true),
                };
            if e != epoch { return Ok(false); } // walked past target epoch
            // Match either path-form ("medical/eu") or legacy numeric.
            if zone_str != zone_for_seal.path()
                && ZoneId::new(zone_str) != zone_for_seal
            {
                return Ok(true);
            }
            if let Ok(Some(rec)) = rocks.get_record(record_id) {
                if let Ok(Some(seal)) = crate::network::epoch::extract_epoch_seal(&rec) {
                    found = Some(seal.start);
                    return Ok(false);
                }
            }
            Ok(true)
        })?;
        // Fallback: no seal found for that (zone, epoch) — return 0.0 so the
        // caller still gets *some* records (those from epoch 0 onward). A
        // light client can detect "epoch not found yet" by getting back fewer
        // records than expected and re-syncing.
        Ok(found.unwrap_or(0.0))
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    // Build a RecordQuery and dispatch to the canonical handler so wire
    // shape, limits, creator filter, and zone-scoped iter are identical to
    // `/records?since=...&zone=...`.
    let query = RecordQuery::__from_parts(Some(since_ts), Some(limit), creator, Some(zone_str));
    query_records(State(state), Query(query)).await
}

// ─── /checkpoints/latest/{zone} ──────────────────────────────────────────────
//
// Gap 3: Light clients sync from the most-recent super-seal instead of
// replaying every individual seal from genesis. Returns the latest super-seal
// metadata (start/end epoch, merkle root, signed record id + hash) for `zone`.
// 404s if no super-seal has been registered for that zone yet.
//
// Does NOT scan storage — reads O(1) from `EpochState.latest_super_seal`.

/// Transport-agnostic body for `/checkpoints/latest/{zone}`. Shared between
/// the axum handler and the PQ-transport router. Infallible-by-design:
/// returns a 200 with the in-band `{"error": "...", "zone": ...}` envelope
/// when no super-seal has been registered yet, so PQ and HTTPS surface the
/// same body byte-for-byte.
pub async fn compute_checkpoint_latest(
    state: Arc<NodeState>,
    zone: String,
) -> crate::errors::Result<serde_json::Value> {
    let zone_id = crate::ZoneId::new(&zone);
    let latest = {
        let epoch = state.epoch.read().map_err(|e| ElaraError::Storage(e.to_string()))?;
        epoch.latest_super_seal.get(&zone_id).cloned()
    };
    Ok(match latest {
        Some((end_epoch, record_id, record_hash, committee_hash)) => {
            let start_epoch = end_epoch.saturating_sub(crate::network::epoch::SUPER_SEAL_INTERVAL - 1);
            serde_json::json!({
                "zone": zone_id.to_string(),
                "start_epoch": start_epoch,
                "end_epoch": end_epoch,
                "seal_count": crate::network::epoch::SUPER_SEAL_INTERVAL,
                "record_id": record_id,
                "record_hash": hex::encode(record_hash),
                "committee_hash": hex::encode(committee_hash),
            })
        }
        None => serde_json::json!({
            "error": "no super-seal yet for this zone",
            "zone": zone_id.to_string(),
        }),
    })
}

/// Axum adapter — thin wrapper around [`compute_checkpoint_latest`].
pub async fn checkpoint_latest(
    State(state): State<Arc<NodeState>>,
    AxumPath(zone): AxumPath<String>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let body = compute_checkpoint_latest(state, zone).await?;
    Ok(Json(body))
}

// ─── /checkpoints/from/{epoch} ───────────────────────────────────────────────
//
// Gap 3: Returns super-seal records covering `end_epoch >= {epoch}`. Cached
// (TTL identical to epoch_headers). Optional `?zone=` narrows to one zone,
// `?limit=` caps result size. Scale: one full CF scan per cache miss (shared
// with other stats caches), then indexed reads from the cache.

static SUPER_SEALS_CACHE: std::sync::LazyLock<JsonListCache> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));
const SUPER_SEALS_TTL: std::time::Duration = std::time::Duration::from_secs(1800);

pub async fn checkpoints_from_epoch(
    State(state): State<Arc<NodeState>>,
    AxumPath(epoch): AxumPath<u64>,
    Query(params): Query<HashMap<String, String>>,
) -> std::result::Result<Json<serde_json::Value>, AppError> {
    let zone_filter: Option<crate::ZoneId> = params.get("zone").map(|v| crate::ZoneId::new(v));
    let limit: usize = params.get("limit").and_then(|v| v.parse().ok()).unwrap_or(500).min(2000);
    let v = compute_checkpoints_from(&state, epoch, zone_filter, limit).await?;
    Ok(Json(v))
}

/// Transport-agnostic `/checkpoints/from/{epoch}` body. Used by both the axum
/// handler above and the PQ transport router so both surfaces return the same
/// JSON. AUDIT-10 Milestone B step 3b.
pub async fn compute_checkpoints_from(
    state: &Arc<NodeState>,
    epoch: u64,
    zone_filter: Option<crate::ZoneId>,
    limit: usize,
) -> crate::errors::Result<serde_json::Value> {
    use crate::network::epoch::{self, EPOCH_OP_KEY};

    let mut all_checkpoints: Vec<serde_json::Value> = Vec::new();
    let mut need_compute = true;
    if let Ok(guard) = SUPER_SEALS_CACHE.lock() {
        if let Some((when, ref cached)) = *guard {
            all_checkpoints = cached.clone();
            if when.elapsed() < SUPER_SEALS_TTL {
                need_compute = false;
            }
        }
    }

    if need_compute && all_checkpoints.is_empty() {
        // Scale fix (internal design notes rule 9): the previous implementation did a full
        // CF_RECORDS scan (`rocks.for_each_record`) which is O(total_records)
        // and times out at ~350K records. Instead, iterate the bounded
        // in-memory `latest_super_seal` map (one entry per active zone) and
        // fetch the super-seal record per entry. O(active_zones) gets.
        //
        // Limitation: this returns only the LATEST super-seal per zone (which
        // is what light clients actually need — older checkpoints are
        // redundant once a newer one is signed). A historical CF_SUPER_SEALS
        // prefix-iter index remains a follow-up if full history is ever
        // required per §11.12 light-client sync.
        let latest_map: Vec<(String, String)> = {
            use crate::network::RwLockRecover;
            let ep = state.epoch.read_recover();
            ep.latest_super_seal
                .iter()
                .map(|(zone, (_end, rid, _rh, _ch))| (zone.to_string(), rid.clone()))
                .collect()
        };

        if latest_map.is_empty() {
            // No super-seals registered anywhere — short-circuit, cache
            // empty result, skip spawn_blocking entirely.
            if let Ok(mut guard) = SUPER_SEALS_CACHE.lock() {
                *guard = Some((std::time::Instant::now(), Vec::new()));
            }
            return Ok(serde_json::json!({
                "total": 0,
                "super_seal_interval": crate::network::epoch::SUPER_SEAL_INTERVAL,
                "checkpoints": [],
            }));
        }

        let state2 = state.clone();
        let mut computed: Vec<serde_json::Value> = tokio::task::spawn_blocking(
            move || -> crate::errors::Result<Vec<serde_json::Value>> {
                let rocks = state2.rocks.as_ref();
                let mut results = Vec::with_capacity(latest_map.len());
                for (_zone_str, record_id) in latest_map {
                    let rec = match rocks.get_record(&record_id)? {
                        Some(r) => r,
                        None => continue,
                    };
                    if !rec.metadata.contains_key(EPOCH_OP_KEY) {
                        continue;
                    }
                    if let Ok(Some(ss)) = epoch::extract_super_seal(&rec) {
                        results.push(serde_json::json!({
                            "zone": ss.zone.to_string(),
                            "start_epoch": ss.start_epoch,
                            "end_epoch": ss.end_epoch,
                            "seal_count": ss.seal_count,
                            "merkle_root": hex::encode(ss.merkle_root),
                            "previous_super_seal_hash": hex::encode(ss.previous_super_seal_hash),
                            "committee_hash": hex::encode(ss.committee_hash),
                            "record_id": rec.id,
                            "record_hash": hex::encode(rec.record_hash()),
                        }));
                    }
                }
                Ok(results)
            },
        )
        .await
        .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

        computed.sort_by(|a, b| {
            let za = a["zone"].as_str().unwrap_or("");
            let zb = b["zone"].as_str().unwrap_or("");
            za.cmp(zb).then_with(|| {
                let ea = a["end_epoch"].as_u64().unwrap_or(0);
                let eb = b["end_epoch"].as_u64().unwrap_or(0);
                ea.cmp(&eb)
            })
        });

        if let Ok(mut guard) = SUPER_SEALS_CACHE.lock() {
            *guard = Some((std::time::Instant::now(), computed.clone()));
        }
        all_checkpoints = computed;
    }

    let mut checkpoints: Vec<serde_json::Value> = all_checkpoints
        .into_iter()
        .filter(|c| {
            if let Some(ref z) = zone_filter {
                if c["zone"].as_str().is_none_or(|zs| zs != z.to_string()) {
                    return false;
                }
            }
            c["end_epoch"].as_u64().is_none_or(|e| e >= epoch)
        })
        .collect();
    checkpoints.truncate(limit);

    Ok(serde_json::json!({
        "total": checkpoints.len(),
        "super_seal_interval": crate::network::epoch::SUPER_SEAL_INTERVAL,
        "checkpoints": checkpoints,
    }))
}

// ─── /challenges ─────────────────────────────────────────────────────────────

/// Default / hard cap on the number of challenges `/challenges` returns in one
/// response. `total` reports the TRUE (status-filtered) challenge count; only
/// the returned `challenges` array is bounded. Unlike disputes — capped at
/// `MAX_DISPUTES = 1000` in the store (dispute.rs) — the challenge map keeps
/// active AND historical challenges with no prune, so it grows unbounded over
/// the network's lifetime. A single call reachable over the PQ `list_challenges`
/// verb by any handshaked peer must not dump the whole history as one JSON
/// payload — SCALE RULE: bounded, always. Truncation is detectable by a caller
/// as `challenges.len() < total`. Mirrors the `/peers` / `/stakes` bound.
const CHALLENGES_DEFAULT_LIMIT: usize = 1000;
const CHALLENGES_MAX_LIMIT: usize = 10_000;

pub fn compute_list_challenges(
    state: Arc<NodeState>,
    status: Option<String>,
    limit: Option<usize>,
) -> serde_json::Value {
    let limit = limit
        .unwrap_or(CHALLENGES_DEFAULT_LIMIT)
        .min(CHALLENGES_MAX_LIMIT);
    let ch = state.challenges.read_recover();

    let mut challenges: Vec<serde_json::Value> = ch.all()
        .filter(|c| {
            if let Some(sf) = status.as_deref() {
                c.status.as_str() == sf
            } else {
                true
            }
        })
        .map(|c| serde_json::json!({
            "id": c.id,
            "challenger": c.challenger,
            "accused": c.accused,
            "challenge_type": c.challenge_type.as_str(),
            "status": c.status.as_str(),
            "filed_at": c.filed_at,
            "jury_size": c.jury.len(),
            "votes_cast": c.votes.len(),
        }))
        .collect();

    // Deterministic order so the bounded page is a stable lowest-id-first slice
    // across calls, not an arbitrary HashMap-iteration sample.
    challenges.sort_by(|a, b| {
        a.get("id").and_then(|v| v.as_str())
            .cmp(&b.get("id").and_then(|v| v.as_str()))
    });
    // True (status-filtered) total captured BEFORE the page bound so `total`
    // stays honest even when the returned array is capped. `Vec::len` is O(1).
    let total = challenges.len();
    challenges.truncate(limit);

    serde_json::json!({
        "total": total,
        "filed_total": state.challenges_filed_total.load(std::sync::atomic::Ordering::Relaxed),
        "challenges": challenges,
    })
}

pub async fn list_challenges(
    State(state): State<Arc<NodeState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let status = params.get("status").cloned();
    let limit = params.get("limit").and_then(|s| s.parse::<usize>().ok());
    Json(compute_list_challenges(state, status, limit))
}

/// `/challenge/{id}` detail. Intentionally NOT page-bounded like the
/// `/challenges` list: `c.votes` is bounded by the challenge's jury, whose size
/// is a protocol constant (`DEFAULT_JURY_SIZE = 13`, `APPEAL_JURY_SIZE = 26` —
/// `fisherman.rs`), so the votes array can never exceed ~26 entries and is not
/// an attacker-controllable dump vector. `c.jury` is likewise jury-bounded. The
/// single-challenge lookup is O(1).
pub fn compute_challenge_detail(
    state: Arc<NodeState>,
    id: String,
) -> serde_json::Value {
    let ch = state.challenges.read_recover();
    match ch.get(&id) {
        Some(c) => {
            let votes: Vec<serde_json::Value> = c.votes.iter().map(|v| {
                serde_json::json!({ "juror": v.juror, "guilty": v.guilty, "timestamp": v.timestamp })
            }).collect();

            serde_json::json!({
                "id": c.id,
                "challenger": c.challenger,
                "accused": c.accused,
                "challenge_type": c.challenge_type.as_str(),
                "status": c.status.as_str(),
                "filed_at": c.filed_at,
                "evidence": c.evidence,
                "jury": c.jury,
                "votes": votes,
                "verdict": c.verdict,
                "verdict_at": c.verdict_at,
                "is_appeal": c.is_appeal,
                "slash_amount": c.slash_amount,
            })
        }
        None => serde_json::json!({ "error": "challenge not found" }),
    }
}

pub async fn challenge_detail(
    State(state): State<Arc<NodeState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<serde_json::Value> {
    Json(compute_challenge_detail(state, id))
}

// ─── /versions/* (Protocol §11.30 — Content Versioning) ────────────────────

/// Compute `/versions/{record_id}` payload. Shared between the axum handler
/// and the PQ-transport router. Infallible — unknown
/// record ids return an in-band `{"error": ..., "record_id": ...}` envelope
/// to preserve the axum body shape exactly.
pub(crate) fn compute_version_info(
    state: Arc<NodeState>,
    record_id: String,
) -> serde_json::Value {
    let vs = state.version_state.lock_recover();
    match vs.get_version(&record_id) {
        Some(ver) => {
            let chain: Vec<serde_json::Value> = vs.chain_to_root(&record_id)
                .iter()
                .map(|v| serde_json::json!({
                    "record_id": v.record_id,
                    "version_number": v.version_number,
                    "previous_version": v.previous_version,
                    "change_summary": v.change_summary,
                    "creator": v.creator,
                    "content_hash": v.content_hash,
                }))
                .collect();
            let children = vs.children_of(&record_id);
            serde_json::json!({
                "version": {
                    "record_id": ver.record_id,
                    "version_number": ver.version_number,
                    "previous_version": ver.previous_version,
                    "change_summary": ver.change_summary,
                    "creator": ver.creator,
                    "content_hash": ver.content_hash,
                },
                "chain_length": chain.len(),
                "chain": chain,
                "children": children,
            })
        }
        None => serde_json::json!({
            "error": "version record not found",
            "record_id": record_id,
        }),
    }
}

/// GET /versions/{record_id} — version record info + chain to root.
pub async fn version_info(
    State(state): State<Arc<NodeState>>,
    AxumPath(record_id): AxumPath<String>,
) -> Json<serde_json::Value> {
    Json(compute_version_info(state, record_id))
}

/// Compute `/versions/{record_id}/forks` payload. Shared between the axum
/// handler and the PQ-transport router. Infallible —
/// unknown record ids return the same in-band error envelope as
/// `compute_version_info`.
pub(crate) fn compute_version_forks(
    state: Arc<NodeState>,
    record_id: String,
) -> serde_json::Value {
    let vs = state.version_state.lock_recover();
    match vs.root_for(&record_id) {
        Some(root) => {
            let forks = vs.detect_forks();
            let root_id = root.record_id.clone();
            let latest = vs.latest_versions(&root_id);
            serde_json::json!({
                "root": root_id,
                "forks": forks.iter().map(|f| serde_json::json!({
                    "parent": f.parent,
                    "branches": f.branches,
                })).collect::<Vec<_>>(),
                "tips": latest.iter().map(|v| serde_json::json!({
                    "record_id": v.record_id,
                    "version_number": v.version_number,
                    "creator": v.creator,
                })).collect::<Vec<_>>(),
            })
        }
        None => serde_json::json!({
            "error": "version record not found",
            "record_id": record_id,
        }),
    }
}

/// GET /versions/{record_id}/forks — detect forks from this version's root chain.
pub async fn version_forks(
    State(state): State<Arc<NodeState>>,
    AxumPath(record_id): AxumPath<String>,
) -> Json<serde_json::Value> {
    Json(compute_version_forks(state, record_id))
}

/// Compute `/versions/stats` payload. Shared between the axum handler and
/// the PQ-transport router.
pub(crate) fn compute_version_stats(state: Arc<NodeState>) -> serde_json::Value {
    let vs = state.version_state.lock_recover();
    let forks = vs.detect_forks();
    serde_json::json!({
        "version_count": vs.version_count(),
        "chain_count": vs.chain_count(),
        "diff_count": vs.diff_count(),
        "fork_count": forks.len(),
    })
}

/// GET /versions/stats — aggregate versioning statistics.
pub async fn version_stats(
    State(state): State<Arc<NodeState>>,
) -> Json<serde_json::Value> {
    Json(compute_version_stats(state))
}

// ─── /activity/{identity} (Protocol §11.23 — Identity Activity Timeline) ────

/// Transport-agnostic body for the activity endpoint. Shared by the axum
/// handler and the PQ `activity` verb — both serve byte-identical JSON.
/// Combines trust, ledger, continuity, reputation, and key-registry
/// snapshots for one identity. All O(1) in-memory lookups — no CF scan.
pub fn compute_activity(state: &Arc<NodeState>, identity: &str) -> serde_json::Value {
    let now = crate::network::ingest::now();
    let mut found = false;

    let trust_info = if let Ok(trust) = state.trust.try_read() {
        if let Some(profile) = trust.get_profile(identity) {
            found = true;
            let tier = profile.tier(now);
            let entropy = profile.entropy();
            Some(serde_json::json!({
                "tier": format!("{:?}", tier),
                "entropy": (entropy * 10000.0).round() / 10000.0,
                "first_seen": profile.first_seen,
                "last_seen": profile.last_seen,
                "total_records": profile.total_records,
                "daily_count": profile.daily_count(now),
            }))
        } else {
            None
        }
    } else {
        None
    };

    let ledger_info = if let Ok(ledger) = state.ledger.try_read() {
        let balance = ledger.balance(identity);
        let staked = ledger.staked(identity);
        if balance > 0 || staked > 0 {
            found = true;
            Some(serde_json::json!({
                "balance_micros": balance,
                "balance_beat": balance as f64 / crate::accounting::types::BASE_UNITS_PER_BEAT as f64,
                "staked_micros": staked,
                "staked_beat": staked as f64 / crate::accounting::types::BASE_UNITS_PER_BEAT as f64,
            }))
        } else {
            None
        }
    } else {
        None
    };

    let continuity_score = if let Ok(cont) = state.continuity.try_lock() {
        let s = cont.score(identity, now);
        if s > 0.0 { found = true; }
        Some((s * 10000.0).round() / 10000.0)
    } else {
        None
    };

    let reputation_score = if let Ok(rep) = state.reputation.try_lock() {
        let s = rep.score_at(identity, now);
        if s != 0.0 { found = true; }
        Some((s * 10000.0).round() / 10000.0)
    } else {
        None
    };

    let key_info = if let Ok(registry) = state.key_registry.try_read() {
        let rotations = registry.rotations_for(identity);
        if rotations > 0 { found = true; }
        Some(serde_json::json!({
            "key_rotations": rotations,
        }))
    } else {
        None
    };

    let is_genesis = identity == state.config.genesis_authority;
    if is_genesis { found = true; }

    if !found {
        return serde_json::json!({
            "error": "identity not found",
            "identity": identity,
        });
    }

    serde_json::json!({
        "identity": identity,
        "is_genesis_authority": is_genesis,
        "trust": trust_info,
        "ledger": ledger_info,
        "continuity_score": continuity_score,
        "reputation_score": reputation_score,
        "keys": key_info,
    })
}

/// GET /activity/{identity} — aggregated activity summary for an identity.
///
/// Combines data from trust engine, ledger, continuity tracker, reputation,
/// and consensus. All O(1) in-memory lookups — no CF scan. Returns a 404-style
/// JSON if the identity has never been seen by any subsystem.
pub async fn identity_activity(
    State(state): State<Arc<NodeState>>,
    AxumPath(identity): AxumPath<String>,
) -> Json<serde_json::Value> {
    Json(compute_activity(&state, &identity))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
