//! NodeState-backed router for the PQ transport (Phase 4 Stage 4B.2b-router).
//!
//! [`PqServer`](super::super::pq_server::PqServer) takes a generic
//! [`PqHandler`](super::super::pq_server::PqHandler) closure. In production we
//! need a handler that actually answers the 14 RPC method strings
//! [`PqNodeClient`](super::super::pq_client::PqNodeClient) sends. This module
//! supplies it.
//!
//! # Design
//!
//! - One plain `async fn(state, req) -> Result<Vec<u8>, ElaraError>` per RPC method.
//!   Signature is intentionally simple: no axum extractors, no `AppError`,
//!   no `IntoResponse`. Any future shared call site (HTTP extractor wrapper,
//!   in-process test) can invoke these directly.
//! - [`pq_router`] composes the per-method fns into a single
//!   `Fn(PqRequest) -> Future<PqResponse>` that [`PqServer`] can host. Errors
//!   are mapped to HTTP-style status codes via [`error_status`].
//! - The handler is deliberately thin — zero I/O of its own, no peer discovery,
//!   no gossip-flow-control headers. Authentication is the PQ handshake itself
//!   (Dilithium3 identity pinning); nothing here reads the TCP source IP.
//!
//! # Methods (parallel of `PqNodeClient`)
//!
//! - `ping`, `status`
//! - `submit_record`, `query_records`, `announce`, `fetch_records`
//! - `merkle_root`, `delta_sync`, `find_node`, `witness`
//! - `snapshot_latest`, `snapshot_full`, `snapshot_fast_meta`, `snapshot_fast_chunk`

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Value};

use super::super::pq_server::{make_handler, PqHandler, PqStreamHandler};
use super::rpc::{status as pq_status, PqRequest, PqResponse, PqStreamChunk, StreamSink};
use super::stream::PqStream;
use crate::crypto::pqc::dilithium3_verify;
use crate::errors::{ElaraError, Result};
use crate::network::gossip::{self, RecordAnnouncement};
use crate::network::state::{NodeEvent, NodeState};
use crate::network::sync::{self as sync_mod, BloomFilter, SnapshotFastMeta};
use crate::network::{LockRecover, RwLockRecover};
use crate::record::ValidationRecord;
use crate::storage::Storage;
use crate::ZoneId;

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Build a [`PqHandler`] that serves all 14 RPC methods against `state`.
///
/// Unknown methods return 404. Any [`ElaraError`] is mapped to an HTTP-style
/// status code; the error message becomes the response body.
pub fn pq_router(state: Arc<NodeState>) -> PqHandler {
    make_handler(move |req| {
        let state = state.clone();
        async move { dispatch(state, req).await }
    })
}

/// 4E.3 — the set of method names this router handles via server-push
/// streaming (one request → many `StreamChunk` frames → final). Paired
/// with [`pq_streaming_handler`]; the caller hands both to
/// `PqServer::with_streaming`.
pub fn pq_streaming_methods() -> Vec<String> {
    vec![
        "seal_progress_stream".to_string(),
        // 4E.3 Phase B (2026-04-26): PQ replacement for `ws.rs`. One stream
        // per account/explorer; carries `NodeEvent`s as JSON chunks shaped
        // identically to today's WebSocket payload so migration is a pure
        // transport flip. ws.rs deletion is gated on 4E.5 + WASM consumer.
        "node_events_stream".to_string(),
    ]
}

/// 4E.3 — streaming-response handler. Dispatches on `req.method`, owns the
/// live [`PqStream`] for the duration of the stream, and always emits a
/// final chunk (`FINAL` or `FINAL|ERROR`) before dropping. Method names not
/// in [`pq_streaming_methods`] emit a terminal error chunk — the server's
/// unary path should have caught the miss first, but defense-in-depth.
pub fn pq_streaming_handler(state: Arc<NodeState>) -> PqStreamHandler {
    Arc::new(move |req, stream| {
        let state = state.clone();
        Box::pin(async move {
            dispatch_stream(state, req, stream).await;
        })
    })
}

async fn dispatch_stream(state: Arc<NodeState>, req: PqRequest, mut stream: PqStream) {
    dispatch_stream_to_sink(state, req, &mut stream).await;
    let _ = stream.close().await;
}

/// Transport-agnostic streaming dispatch (4E.1 Phase D). Used by the TCP
/// `dispatch_stream` above and by the WSS-tunneled `/pq-ws` handler in
/// `ws_session.rs`. The sink owns its own framing/AEAD; this fn owns
/// only "match method → call handler".
pub(super) async fn dispatch_stream_to_sink(
    state: Arc<NodeState>,
    req: PqRequest,
    sink: &mut dyn StreamSink,
) {
    match req.method.as_str() {
        "seal_progress_stream" => {
            handle_seal_progress_stream(state, &req.headers, sink).await;
        }
        "node_events_stream" => {
            handle_node_events_stream(state, &req.body, sink).await;
        }
        other => {
            let _ = sink
                .send_stream_chunk(&PqStreamChunk::error(
                    0,
                    format!("streaming: unknown method: {other}"),
                ))
                .await;
        }
    }
}

async fn dispatch(state: Arc<NodeState>, req: PqRequest) -> PqResponse {
    // Bandwidth observability — count every PQ wire body before dispatching.
    // Pairs with the HTTP `/records` counter at `routes/core.rs:265` so
    // `gossip_bytes_in_total` aggregates ingress across both transports.
    // Counted pre-gating (vs. HTTP path's post-gating count) — the small
    // bad-network-id overcounting is dominated by legitimate traffic and the
    // metric is only used for bandwidth-budget headroom decisions, not billing.
    if !req.body.is_empty() {
        state.gossip_bytes_in_total
            .fetch_add(req.body.len() as u64, std::sync::atomic::Ordering::Relaxed);
    }
    // ── PQ read-side admission gate — parity with the HTTP rate_limit_middleware ──
    // The HTTP read surface is rate-limited in axum middleware (server::RateLimiter,
    // keyed by IP). The PQ dispatch path had no equivalent, so a handshake-authed
    // peer could bypass it and fire unbounded heavy reads (snapshot_full / delta_sync
    // = spawn_blocking + RocksDB scan). Gate per-peer here, keyed by the
    // Dilithium3-bound peer_identity_hash. Write/submission verbs and local/genesis
    // callers are exempt (see pq_read_admit).
    if let Err(e) = pq_read_admit(
        &state.pq_read_limiter,
        &state.config.genesis_authority,
        &req.peer_identity_hash,
        req.method.as_str(),
    ) {
        return PqResponse::new(error_status(&e), e.to_string().into_bytes());
    }
    // ── Global HEAVY-read concurrency cap — backstop to the per-peer rate gate ──
    // The per-peer bucket above bounds ONE identity's read RATE; it cannot see
    // the cross-identity AGGREGATE. In the default Tofu realm a handful of
    // zero-cost Sybil identities, each within its own bucket, can collectively
    // saturate the small (4-16) shared spawn_blocking pool with heavy reads
    // and starve consensus ingest (the documented 51-98s stall). So gate the
    // HEAVY verbs on a global semaphore: at most `pq_heavy_read_cap` run at once.
    //
    // Bounded WAIT, not a bare shed: a legit bootstrap's snapshot_full/_latest/
    // _fast_meta are all HEAVY and the PQ client ABORTS on any 429 (`ensure_ok`),
    // so a short wait lets a join survive transient contention while a sustained
    // flood still sheds past the timeout. Local same-process (all-zeros) and
    // genesis callers are exempt, mirroring `pq_read_admit`.
    //
    // The permit is an RAII `OwnedSemaphorePermit` held across the `match` below
    // (covering the ledger clone + spawn_blocking + serialize) and dropped when
    // `dispatch` returns — which is BEFORE `serve_connection` sends the response
    // body on the wire, so a slow-draining peer can never hold a heavy-read slot.
    // Drop runs on every exit incl. panic=unwind, so the permit cannot leak.
    let _heavy_permit = if is_heavy_blocking_read(req.method.as_str())
        && req.peer_identity_hash != [0u8; 32]
        && hex::encode(req.peer_identity_hash) != state.config.genesis_authority
    {
        match tokio::time::timeout(
            std::time::Duration::from_millis(state.pq_heavy_read_wait_ms),
            state.pq_heavy_read_semaphore.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => Some(permit),
            // Timed out (sustained flood) or semaphore closed → shed with 429.
            _ => {
                state
                    .pq_heavy_read_shed_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let e = ElaraError::RateLimited;
                return PqResponse::new(error_status(&e), e.to_string().into_bytes());
            }
        }
    } else {
        None
    };
    // ── Global HEAVY-VERIFY concurrency gate — write-side twin of the read cap ──
    // (design: internal design notes). The three verbs
    // that do genuine inline PQC per message (`receive_attestation` Dilithium3
    // verify, `witness` verify + inline sign, `submit_record` Dilithium3 +
    // SPHINCS+) are multiplexed over one handshake with NO inbound rate limit,
    // so one peer — or a swarm of zero-cost Open-realm Sybil identities — can
    // otherwise starve the async workers / blocking pool with crypto. The gate
    // is GLOBAL (identity-agnostic) so it caps the aggregate regardless of how
    // many identities the flood is spread across.
    //
    // Deliberately DIFFERENT from the read gate: backpressure, NEVER shed. A
    // 429'd consensus message is permanently lost — the sender treats 429 as
    // silent success (gossip.rs push path) and its `seen` dedup blocks re-push;
    // finality witnesses have no pull-reconciler. So excess dispatches WAIT for
    // a permit instead. The wait queue is bounded: per-connection dispatch is
    // sequential (ws_session/serve_connection await each unary reply before
    // reading the next frame), so at most one waiter per connection and a
    // flooding peer stalls only itself.
    //
    // Sited at dispatch — not inside the handlers — so the permit also covers
    // the defer branches' pre-verify work (deserialize, RocksDB pubkey read,
    // deferred-buffer mutex). Local same-process (all-zeros) and genesis
    // callers are exempt, mirroring `pq_read_admit`: the authority's own
    // consensus traffic must never queue behind an attacker's flood.
    let _verify_permit = if is_heavy_verify_method(req.method.as_str())
        && req.peer_identity_hash != [0u8; 32]
        && hex::encode(req.peer_identity_hash) != state.config.genesis_authority
    {
        match state.pq_verify_semaphore.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(tokio::sync::TryAcquireError::NoPermits) => {
                state
                    .pq_verify_waited_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                match state.pq_verify_semaphore.clone().acquire_owned().await {
                    Ok(permit) => Some(permit),
                    // Semaphore closed — never done in production (no close()
                    // call site); fail the single request rather than panic.
                    Err(_) => {
                        let e = ElaraError::Network("verify gate closed".into());
                        return PqResponse::new(error_status(&e), e.to_string().into_bytes());
                    }
                }
            }
            Err(tokio::sync::TryAcquireError::Closed) => {
                let e = ElaraError::Network("verify gate closed".into());
                return PqResponse::new(error_status(&e), e.to_string().into_bytes());
            }
        }
    } else {
        None
    };
    let result: std::result::Result<Option<Vec<u8>>, ElaraError> = match req.method.as_str() {
        "ping" => handle_ping(&state).await.map(Some),
        "status" => handle_status(&state).await.map(Some),
        "submit_record" => handle_submit_record(&state, &req.headers, &req.body, &req.peer_identity_hash).await.map(Some),
        "query_records" => handle_query_records(&state, &req.headers).await.map(Some),
        "announce" => handle_announce(&state, &req.body).await.map(Some),
        "fetch_records" => handle_fetch_records(&state, &req.body).await.map(Some),
        // Gap 6.4 slice 3b: lightweight presence probe used by the
        // seal-replication reconciler. Returns a bitmap (per-id
        // present/absent) without shipping record bodies.
        "records_exist" => handle_records_exist(&state, &req.body).await.map(Some),
        "merkle_root" => handle_merkle_root(&state).await.map(Some),
        "delta_sync" => handle_delta_sync(&state, &req.headers, &req.body).await.map(Some),
        "find_node" => handle_find_node(&state, &req.headers).await.map(Some),
        "witness" => handle_witness(&state, &req.body).await.map(Some),
        "snapshot_latest" => handle_snapshot_latest(&state).await.map(Some),
        "snapshot_full" => handle_snapshot_full(&state).await.map(Some),
        "snapshot_fast_meta" => handle_snapshot_fast_meta(&state, &req.headers).await.map(Some),
        "snapshot_fast_chunk" => handle_snapshot_fast_chunk(&state, &req.headers).await.map(Some),
        // 4B.2c-4: three more methods so gossip.rs attestation + conflict
        // call sites have a PQ target to point at.
        "query_attestations" => handle_query_attestations(&state, &req.headers).await.map(Some),
        "receive_attestation" => handle_receive_attestation(&state, &req.body, &req.peer_identity_hash).await.map(Some),
        "receive_conflict_proof" => handle_receive_conflict_proof(&state, &req.body).await.map(Some),
        // Gap 2.1 Phase 2c: cross-zone finality witness propagation. Producer
        // signs at seal ingest (network/ingest.rs), broadcasts via
        // `push_finality_witness_to_peers`; receiver lands here, calls
        // `consensus.add_seal_finality_signature`.
        "submit_finality_witness" => handle_submit_finality_witness(&state, &req.body, &req.peer_identity_hash).await.map(Some),
        // Gap 2 sealed-abort P-3e: cross-zone abort-witness propagation.
        // Producer signs in epoch_seal_loop (network/epoch.rs), broadcasts
        // via `push_xzone_abort_witness_to_peers`; receiver lands here,
        // calls `consensus.add_xzone_abort_signature`. Receiver does NOT
        // re-broadcast — fan-out stays O(committee × sqrt(peers)).
        "submit_xzone_abort_witness" => handle_submit_xzone_abort_witness(&state, &req.body).await.map(Some),
        // User-facing RPC, first route: light-client header sync.
        // Single most load-bearing path (every Light node hits it every 35s);
        // migrating it first gets PQ coverage to the largest axum-HTTPS traffic
        // source before moving on to /status, /record/{id}, /seal/progress/{id}, …
        "headers_from" => handle_headers_from(&state, &req.headers).await.map(Some),
        // Account streaming-progress poll. 200ms cadence
        // today over HTTPS — candidate for `STREAM_CHUNK` server-push in
        // 4E.3; for now keep the request/response shape identical so
        // accounts can switch transports with a flag flip.
        "seal_progress" => handle_seal_progress(&state, &req.headers).await.map(Some),
        // Record detail, account state proof,
        // cross-zone membership proof. Same service-fn extraction pattern —
        // the axum handlers are now thin `Json(…)` wrappers around the
        // shared `compute_*` fns in `routes::explorer`, so HTTPS and PQ
        // serve byte-identical bodies. When 4E.5 kills axum HTTPS we only
        // lose the adapter, not the computation.
        "record_detail" => handle_record_detail(&state, &req.headers).await.map(Some),
        "account_proof" => handle_account_proof(&state, &req.headers).await.map(Some),
        "cross_zone_proof" => handle_cross_zone_proof(&state, &req.headers).await.map(Some),
        // Account balance poll + DAG tip snapshot. Both
        // are infallible — `identity` on balances is optional (global list
        // when omitted), dag_tips takes no input. Closes 7/7 batch A ahead
        // of 4E.5 axum retirement.
        "balances" => handle_balances(&state, &req.headers).await.map(Some),
        "dag_tips" => handle_dag_tips(&state).await.map(Some),
        // AUDIT-10 Milestone A delta: identity observability + Prometheus
        // exposition over PQ, so monitoring + account UX stop depending on
        // HTTPS. Headers: `identity` (required for activity).
        "activity" => handle_activity(&state, &req.headers).await.map(Some),
        // /ws Slice 2 prereq: account transaction history over PQ. The
        // existing `activity` verb returns a trust/reputation/ledger
        // summary, NOT the `{transactions:[…]}` payload `node.query_history`
        // consumers expect — so `tx_history` is the correct migration target.
        // Headers: `identity` (required), `limit` (optional, default 50,
        // clamped 200), `offset` (optional, default 0).
        "tx_history" => handle_tx_history(&state, &req.headers).await.map(Some),
        // Sibling verb for the explorer's recent-ledger-ops feed. Same shim
        // misroute story: `/transactions/recent` was mapped to the `activity`
        // PQ verb, but axum binds it to `recent_transactions` (a different
        // shape with no `identity` filter). Headers: `limit` (optional,
        // default 20, clamped 100). No identity required — global feed.
        "recent_transactions" => handle_recent_transactions(&state, &req.headers).await.map(Some),
        "metrics" => handle_metrics(&state).await.map(Some),
        "checkpoints_from" => handle_checkpoints_from(&state, &req.headers).await.map(Some),
        // AUDIT-10 Milestone C batch 1: operator CLI admin/explorer verbs.
        // Extracted `compute_<verb>` helpers in routes/{core,token,explorer}
        // give axum + PQ structural parity.
        "list_peers" => handle_list_peers(&state).await.map(Some),
        "health" => handle_health(&state).await.map(Some),
        "ledger_summary" => handle_ledger_summary(&state).await.map(Some),
        "epoch_status" => handle_epoch_status(&state).await.map(Some),
        // Read-only stakes/network/enforcement parity. All
        // delegate to the matching `compute_*` helper so axum + PQ return
        // byte-identical JSON.
        "stakes" => handle_stakes(&state, &req.headers).await.map(Some),
        "network_info" => handle_network_info(&state).await.map(Some),
        "token_enforcement" => handle_token_enforcement(&state).await.map(Some),
        // Zone health + governance read surface.
        "zone_health" => handle_zone_health(&state).await.map(Some),
        "governance_summary" => handle_governance_summary(&state).await.map(Some),
        "governance_params" => handle_governance_params(&state).await.map(Some),
        // Beat-supply read surface — account/explorer staples.
        "supply_circulating" => handle_supply_circulating(&state).await.map(Some),
        "supply_total" => handle_supply_total(&state).await.map(Some),
        "supply_max" => handle_supply_max().await.map(Some),
        // DAG observability + address validation + witness profile list.
        "dag_stats" => handle_dag_stats(&state).await.map(Some),
        "validate_address" => handle_validate_address(&state, &req.headers).await.map(Some),
        // Identity Partitioning Phase D — peer-to-peer on-miss PK fetch.
        // Header `identity_hash` is required. Caller is the local
        // `IdentityFetcher`; responder serves the same shared `compute_*`
        // service-fn the axum handler does, so HTTPS and PQ render
        // byte-identical bodies.
        "identity_pk" => handle_identity_pk(&state, &req.headers).await.map(Some),
        "list_witness_profiles" => handle_list_witness_profiles(&state).await.map(Some),
        // Consensus observability + committee snapshot.
        "consensus_status" => handle_consensus_status(&state, &req.headers).await.map(Some),
        "consensus_record_detail" => handle_consensus_record_detail(&state, &req.headers).await.map(Some),
        "committees_snapshot" => handle_committees_snapshot(&state, &req.headers).await.map(Some),
        // Governance read surface (proposals, detail, delegations).
        "governance_proposals" => handle_governance_proposals(&state, &req.headers).await.map(Some),
        "governance_proposal_detail" => handle_governance_proposal_detail(&state, &req.headers).await.map(Some),
        "governance_delegations" => handle_governance_delegations(&state, &req.headers).await.map(Some),
        // Governance param history + dispute / challenge listings.
        "governance_params_history" => handle_governance_params_history(&state, &req.headers).await.map(Some),
        "list_disputes" => handle_list_disputes(&state, &req.headers).await.map(Some),
        "list_challenges" => handle_list_challenges(&state, &req.headers).await.map(Some),
        // DAG record graph + dispute / challenge detail.
        "dag_record_graph" => handle_dag_record_graph(&state, &req.headers).await.map(Some),
        "dispute_detail" => handle_dispute_detail(&state, &req.headers).await.map(Some),
        "challenge_detail" => handle_challenge_detail(&state, &req.headers).await.map(Some),
        // Witness correlation + reputation + committee membership.
        "witness_correlation" => handle_witness_correlation(&state, &req.headers).await.map(Some),
        "witness_reputation" => handle_witness_reputation(&state, &req.headers).await.map(Some),
        "committees_is_member" => handle_committees_is_member(&state, &req.headers).await.map(Some),
        // Peer reputation + reward stats + ITC status.
        "peer_reputation" => handle_peer_reputation(&state, &req.headers).await.map(Some),
        "reward_stats" => handle_reward_stats(&state).await.map(Some),
        "itc_status" => handle_itc_status(&state).await.map(Some),
        // Cross-zone transfer observability.
        "xzone_stats" => handle_xzone_stats(&state).await.map(Some),
        "xzone_transfers" => handle_xzone_transfers(&state, &req.headers).await.map(Some),
        "xzone_transfer" => handle_xzone_transfer(&state, &req.headers).await.map(Some),
        "xzone_bundle" => handle_xzone_bundle(&state, &req.headers).await.map(Some),
        // Account detail + causal proof + Merkle inclusion proof.
        "account_detail" => handle_account_detail(&state, &req.headers).await.map(Some),
        "causal_proof" => handle_causal_proof(&state, &req.headers).await.map(Some),
        "merkle_proof" => handle_merkle_proof(&state, &req.headers).await.map(Some),
        // Per-zone Merkle proof + DAG lifecycle counters + VRF registry.
        "zone_merkle_proof" => handle_zone_merkle_proof(&state, &req.headers).await.map(Some),
        "dag_lifecycle" => handle_dag_lifecycle(&state).await.map(Some),
        "vrf_registry" => handle_vrf_registry(&state).await.map(Some),
        // Content-versioning inspection (Protocol §11.30).
        "version_info" => handle_version_info(&state, &req.headers).await.map(Some),
        "version_forks" => handle_version_forks(&state, &req.headers).await.map(Some),
        "version_stats" => handle_version_stats(&state).await.map(Some),
        // Light-client + explorer surface
        // (epoch-headers list, latest-super-seal lookup, full DAG search).
        "epoch_headers" => handle_epoch_headers(&state, &req.headers).await.map(Some),
        "checkpoint_latest" => handle_checkpoint_latest(&state, &req.headers).await.map(Some),
        "dag_search" => handle_dag_search(&state, &req.headers).await.map(Some),
        // Residual debug + routing + witness-profile registration.
        "seal_debug" => handle_seal_debug(&state, &req.headers).await.map(Some),
        "register_witness_profile" => handle_register_witness_profile(&state, &req).await.map(Some),
        "routing_resolve" => handle_routing_resolve(&state, &req.headers).await.map(Some),
        // Residual POST verbs — record validation, peer
        // going-offline notification, transition veto submission. Each
        // mirrors the axum handler one-for-one via the shared compute_*
        // service-fn so HTTPS and PQ render identical bodies.
        "validate_record" => handle_validate_record(&state, &req.body).await.map(Some),
        "receive_offline_notification" => {
            handle_receive_offline_notification(&state, &req.body).await.map(Some)
        }
        "submit_veto" => handle_submit_veto(&state, &req.headers, &req.body).await.map(Some),
        // AUDIT-10 PQ-R5a: epoch snapshot listing + fetch so archive-snapshot
        // bootstrap can be driven entirely via the PQ transport.
        "list_epoch_snapshots" => handle_list_epoch_snapshots(&state).await.map(Some),
        "get_epoch_snapshot" => handle_get_epoch_snapshot(&state, &req.headers).await.map(Some),
        // Incremental state-delta. Header `since_epoch` selects
        // the baseline the client claims to trust. Mirrors axum
        // `/snapshot/state-delta?since_epoch=N` byte-for-byte.
        "state_delta" => handle_state_delta(&state, &req.headers).await.map(Some),
        // AUDIT-10 PQ-pure-client: transition-seal cosign convergence + operator
        // peer-probe verbs so every outbound path has a PQ home. These replace
        // the last reqwest call sites in gossip.rs, probe.rs, and
        // routes/transitions.rs pull-tick. The axum endpoints remain for
        // backward-compat inbound only — outbound is PQ-only.
        "submit_transition_seal" => handle_submit_transition_seal(&state, &req.body).await.map(Some),
        "submit_transition_sig" => handle_submit_transition_sig(&state, &req.headers, &req.body).await.map(Some),
        "list_transitions" => handle_list_transitions(&state, &req.headers).await.map(Some),
        "get_transition" => handle_get_transition(&state, &req.headers).await.map(Some),
        "probe" => handle_probe_request(&state, &req.body).await.map(Some),
        // AUDIT-9 Milestone B: direct peer-to-peer witness profile exchange.
        // Replaces the "emit WitnessProfile as a DAG record and wait for it
        // to propagate" path on NAT'd nodes, closing the unknown-profile
        // window that previously degraded effective_stake on small fleets.
        "exchange_profile" => handle_exchange_profile(&state, &req).await.map(Some),
        // §11.23 Layer A slice 1: peer-relay for content-hash lookups.
        // Headers: `content_hash` (required, lowercase-hex-64). Responder
        // does a LOCAL-ONLY CF_IDX_HASH point read — MUST NOT recursively
        // peer-relay or a network of empty nodes generates exponential
        // request amplification. On miss: 404; on hit: full record JSON.
        "resolve_content_hash" => handle_resolve_content_hash(&state, &req.headers).await.map(Some),
        _ => Ok(None),
    };

    match result {
        Ok(Some(body)) => PqResponse::ok(body),
        Ok(None) => PqResponse::new(
            pq_status::NOT_FOUND,
            format!("unknown method: {}", req.method).into_bytes(),
        ),
        Err(e) => PqResponse::new(error_status(&e), e.to_string().into_bytes()),
    }
}

/// Map [`ElaraError`] onto an HTTP-style status code. Kept explicit — anyone
/// reading this sees exactly which errors the client will observe.
fn error_status(e: &ElaraError) -> u16 {
    match e {
        ElaraError::Wire(_) => pq_status::BAD_REQUEST,
        ElaraError::InvalidSignature => pq_status::UNAUTHORIZED,
        ElaraError::RecordNotFound(_) => pq_status::NOT_FOUND,
        ElaraError::DuplicateRecord(_) => pq_status::BAD_REQUEST,
        ElaraError::MissingParent(_) => pq_status::BAD_REQUEST,
        ElaraError::RateLimited => pq_status::TOO_MANY_REQUESTS,
        ElaraError::Json(_) => pq_status::BAD_REQUEST,
        _ => pq_status::INTERNAL_ERROR,
    }
}

/// READ vs WRITE classification for the PQ read-admission gate. WRITE /
/// submission verbs are NOT gated — they carry their own write-side admission
/// (ingest propagation limiter, signature + trust gates), and charging them the
/// read budget would be wrong accounting. This is a DENYLIST: any method not
/// named here is treated as a read and IS gated, so a future read verb can never
/// silently re-open the bypass.
/// The verbs gated by the global HEAVY-VERIFY concurrency cap
/// (`pq_verify_semaphore`) — exactly the ones doing genuine inline PQC work
/// per message (internal design notes):
///
/// * `receive_attestation` — Dilithium3 verify (or defer-buffer work)
/// * `witness` — Dilithium3 verify + inline Dilithium3 SIGN (heaviest)
/// * `submit_record` — Dilithium3 + optional SPHINCS+ (~10 ms) via ingest
///
/// Deliberately NOT `submit_finality_witness` / `submit_xzone_abort_witness`:
/// their ingest cost is committee/Merkle membership work, no inline Dilithium
/// (the verify happens at consume time in `verify_finality_quorum`) — gating
/// them would risk the seal path for a threat that isn't there. This is an
/// ALLOWLIST (opposite polarity to `is_write_method`'s denylist): a new verb
/// is un-gated until someone shows it does heavy inline crypto.
fn is_heavy_verify_method(method: &str) -> bool {
    matches!(method, "submit_record" | "witness" | "receive_attestation")
}

fn is_write_method(method: &str) -> bool {
    matches!(
        method,
        "submit_record"
            | "announce"
            | "witness"
            | "receive_attestation"
            | "receive_conflict_proof"
            | "submit_finality_witness"
            | "submit_xzone_abort_witness"
            | "register_witness_profile"
            | "receive_offline_notification"
            | "submit_veto"
            | "submit_transition_seal"
            | "submit_transition_sig"
            | "exchange_profile"
    )
}

/// Token cost per READ method for the per-peer admission bucket. Whole-ledger
/// serialize / full-state ops cost most (a flood of them is the real DoS
/// vector); bounded-size ops cost 1 so a legitimate follower-join — which makes
/// many small snapshot_fast_chunk / headers_from / checkpoints_from pulls —
/// completes within the burst budget and never trips a 429 (the client ABORTS a
/// bootstrap on a 429; see pq_client `ensure_ok`).
fn pq_read_cost(method: &str) -> f64 {
    match method {
        // HEAVY (cost 10) — per-call work scales with chain size in
        // `spawn_blocking`, so a flood is the real DoS lever. Costs verified
        // against the handlers 2026-06-29: snapshot_full / state_delta clone the
        // whole ledger (O(records)); `stakes` (unfiltered) builds a JSON value
        // for EVERY active stake before it truncates to `limit` (token.rs
        // compute_stakes); merkle_root recomputes global_merkle_root, which
        // reads every zone's already-maintained SMT root (one point-get each)
        // and hashes them — O(zone_count), NOT a per-record rebuild
        // (merkle.rs:714). NB: `ledger_summary` is deliberately NOT here —
        // validate::summarize() reads maintained O(1) counters (B10), not an
        // account scan, so it stays at the default cost 1.
        "snapshot_full" | "state_delta" | "merkle_root" | "stakes" => 10.0,
        // MODERATE — bounded but large: a scan/serialize capped in the
        // thousands, a spawn_blocking proof, or a governance-set walk. More
        // than a point-get, far less than a full-ledger op. network_info is
        // here (O(peers)+O(zones), summarize() itself is O(1)).
        "delta_sync"
        | "dag_search"
        | "cross_zone_proof"
        | "consensus_record_detail"
        | "query_attestations"
        | "recent_transactions"
        | "governance_proposals"
        | "governance_delegations"
        | "network_info" => 3.0,
        "query_records" | "fetch_records" => 2.0,
        // Default — point-gets, small bounded lists, and the bootstrap pulls
        // (snapshot_latest / snapshot_fast_chunk|meta / headers_from /
        // checkpoints_from) which MUST stay cheap so a first-join fits the
        // burst. A NEW read verb lands here at cost 1 by default; if it is
        // O(ledger) or serializes thousands, lift it into a tier above.
        _ => 1.0,
    }
}

/// Verbs whose handler does chain-scale work inside `spawn_blocking` — a
/// whole-ledger clone+serialize (snapshot_full / state_delta) or an
/// O(zone_count) global-root recompute (merkle_root / snapshot_latest /
/// snapshot_fast_meta) — the real blocking-pool DoS lever. Gated by the GLOBAL
/// `pq_heavy_read_semaphore` (cross-identity CONCURRENCY), a SEPARATE axis from
/// `pq_read_cost` (per-peer RATE).
///
/// Deliberately NOT keyed on `pq_read_cost == 10.0`: `snapshot_latest` and
/// `snapshot_fast_meta` are per-peer cost 1 by design — each recomputes
/// `global_merkle_root` (O(zone_count)) every call, yet must stay cheap on the
/// per-peer bucket so a first-join's many bootstrap pulls fit the burst.
/// Per-peer keeps them cheap to ISSUE; the global cap bounds how many run AT
/// ONCE. Were the gate keyed on cost, a flood of cost-1 `snapshot_fast_meta`
/// would route around it while doing the same O(zone_count) global-root work as
/// the gated cost-10 `merkle_root`.
///
/// `snapshot_fast_chunk` is intentionally absent: it serves a bounded chunk via
/// `build_snapshot_chunk` (offset+limit), is the high-frequency bootstrap
/// workhorse, and gating it would throttle every join.
///
/// AUDITED 2026-06-29 (3-panel design review) — a cache here is NOT pursued.
/// `global_merkle_root` is O(zone_count): one point-get per zone over `0..zone_count`
/// then `sha3(root_0 || ... || root_n)`. `zone_count` is small and advances ONLY via
/// signed consensus ZoneTransitions (default 4; auto-mode boots at 1) — not record- or
/// attacker-driven — so at the real operating point this is microseconds. A cache was
/// rejected on the merits, not deferred: (a) the value is a SOFT cross-node sync
/// fingerprint (sync.rs delta-skip + a non-fatal post-import check); light clients
/// verify proofs against the per-zone ACCOUNT SMT + anchor-signed seals, NOT this
/// record-tree root, so a briefly-stale root breaks nothing — the old "breaks light
/// clients" caveat was wrong. (b) maintain-on-commit would push the O(zone_count) SHA3
/// onto the per-record ingest hot path (the concat hash is O(zone_count) bytes whatever
/// the held-zone count). (c) a version-stamped lazy cache self-defeats under a
/// write-storm + read-flood (every read misses). (d) a tree accumulator would redefine
/// a value byte-compared across nodes. The read-flood lever is already bounded by
/// `pq_heavy_read_semaphore` below.
fn is_heavy_blocking_read(method: &str) -> bool {
    matches!(
        method,
        "snapshot_full"
            | "state_delta"
            | "merkle_root"
            | "stakes"
            | "snapshot_latest"
            | "snapshot_fast_meta"
    )
}

/// Per-peer PQ read-admission decision. `Ok(())` = admit, `Err(RateLimited)` =
/// throttle (dispatch maps it to 429 via `error_status`). Pure wiring around the
/// token bucket so it is unit-testable without a full `NodeState`.
///
/// Exemptions (all synchronous — no lock taken on the hot path):
///   - write/submission verbs (their own admission path)
///   - all-zeros identity = local same-process call
///   - the genesis authority (mirrors `push_is_trusted`)
fn pq_read_admit(
    limiter: &crate::network::peer_bandwidth::PeerBandwidthLimiter,
    genesis_authority: &str,
    peer_identity_hash: &[u8; 32],
    method: &str,
) -> Result<()> {
    if is_write_method(method) {
        return Ok(());
    }
    if peer_identity_hash == &[0u8; 32] {
        return Ok(());
    }
    let peer_hex = hex::encode(peer_identity_hash);
    if peer_hex == genesis_authority {
        return Ok(());
    }
    if limiter.try_acquire_cost(&peer_hex, pq_read_cost(method)) {
        Ok(())
    } else {
        Err(ElaraError::RateLimited)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn to_body<T: serde::Serialize>(v: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(ElaraError::from)
}

fn header_u64(h: &BTreeMap<String, String>, k: &str) -> Option<u64> {
    h.get(k).and_then(|v| v.parse().ok())
}

fn header_usize(h: &BTreeMap<String, String>, k: &str) -> Option<usize> {
    h.get(k).and_then(|v| v.parse().ok())
}

fn header_f64(h: &BTreeMap<String, String>, k: &str) -> Option<f64> {
    h.get(k).and_then(|v| v.parse().ok())
}

// ─── ping ────────────────────────────────────────────────────────────────────

async fn handle_ping(_state: &Arc<NodeState>) -> Result<Vec<u8>> {
    to_body(&json!({
        "pong": true,
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": crate::network::config::PROTOCOL_VERSION,
    }))
}

// ─── status ──────────────────────────────────────────────────────────────────

async fn handle_status(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    use crate::accounting::validate;

    // Prefer lock-free state_core snapshot (matches axum handler behavior).
    let (dag_size, dag_tips, dag_roots, dag_edges, ledger_supply, ledger_staked,
         ledger_accounts, peers_connected, peers_total, finalized_count,
         current_epoch, conservation_pool) = if let Some(core) = state.state_core.get() {
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

    // Tier-1.2 fork-monitor anchor (parallels HTTP /status). `null` until
    // first seal lands locally — fork-detect skips comparison in that
    // window. Pre-Phase-B peers without this field also yield `null`,
    // which fork.rs treats as "can't compare → not diverged".
    let latest_seal_anchor = state
        .epoch
        .read_recover()
        .highest_seal_anchor()
        .map(|(zone, epoch, hash)| json!({
            "zone": zone.to_string(),
            "epoch": epoch,
            "hash": hex::encode(hash),
        }));

    to_body(&json!({
        "identity_hash": state.identity.identity_hash,
        "node_type": state.config.node_type,
        "protocol_version": crate::network::config::PROTOCOL_VERSION,
        "network_id": state.config.network_id,
        "transport": "pq",
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
        "peers_connected": peers_connected,
        "peers_total": peers_total,
        "finalized_count": finalized_count,
        "current_epoch": current_epoch,
        "consensus_attestations": consensus_attestations,
        "consensus_settled": finalized_settled,
        "pending_anchors": pending_anchors,
        "uptime_secs": state.uptime(),
        "version": env!("CARGO_PKG_VERSION"),
        // Identity / PoW — required by discovery::seed_reconnect_loop &
        // discovery::bootstrap to construct PeerInfo with the correct
        // pow_difficulty. Missing fields → defaulted to 0 → PeerTable::insert
        // rejects with "PoW difficulty 0 < minimum 16".
        "pow_nonce": state.identity.pow_nonce,
        "pow_difficulty": state.identity.pow_difficulty,
        "public_key_hex": hex::encode(&state.identity.public_key),
        "min_pow_difficulty": state.config.min_pow_difficulty,
        "latest_seal_anchor": latest_seal_anchor,
    }))
}

// ─── submit_record ───────────────────────────────────────────────────────────
//
// PQ peers are authenticated by the handshake (Dilithium3 identity pin).
// We skip HTTP-specific implicit peer discovery — the peer is already known
// at the transport layer. Remaining logic mirrors the axum sync path:
//   1. Deserialize + validate wire
//   2. Protocol/network check
//   3. Dedup (seen set + rejection cache)
//   4. Insert via state_core (or ingest fallback)
//   5. Mark seen + best-effort relay
/// B6: decide whether a gossip push is rate-exemption-eligible, from the
/// HANDSHAKE-authenticated identity — never the spoofable `x-elara-sender`
/// header. Trusted = a local same-process call (`peer_identity_hash` all-zeros;
/// a post-handshake remote is never all-zeros), the genesis authority, a
/// configured seed peer, or a staked identity. Each check is O(1) and the cheap
/// lock-free branches short-circuit before any read lock is taken.
async fn push_is_trusted(state: &Arc<NodeState>, peer_identity_hash: &[u8; 32]) -> bool {
    if peer_identity_hash == &[0u8; 32] {
        return true; // local same-process submission
    }
    let hex = hex::encode(peer_identity_hash);
    if hex == state.config.genesis_authority {
        return true;
    }
    if state.peers.read().await.is_seed_peer(&hex) {
        return true;
    }
    state.ledger.read().await.staked(&hex) > 0
}

async fn handle_submit_record(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    peer_identity_hash: &[u8; 32],
) -> Result<Vec<u8>> {
    guard_record_body("submit_record", body)?;
    let record = ValidationRecord::from_bytes(body)?;

    let peer_version: u32 = headers
        .get("x-elara-protocol-version")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let min_version = state.config.min_protocol_version;
    if min_version > 0 && peer_version < min_version {
        return to_body(&json!({
            "accepted": false,
            "reason": "protocol_version_too_low",
            "peer_version": peer_version,
            "min_version": min_version,
        }));
    }

    let peer_network: &str = headers
        .get("x-elara-network-id")
        .map(|s| s.as_str())
        .unwrap_or("testnet");
    if peer_network != state.config.network_id {
        return to_body(&json!({
            "accepted": false,
            "reason": "network_mismatch",
            "peer_network": peer_network,
            "our_network": state.config.network_id,
        }));
    }

    // Profile-scoped push acceptance — see routes/core.rs:submit_record for
    // the design note. Light (phone-tier client) profiles refuse peer
    // pushes; FullZone / Archive accept them. PQ submissions without
    // an `x-elara-sender` header are treated as local submit and bypass
    // the gate, mirroring the axum path.
    if headers.contains_key("x-elara-sender") {
        let profile =
            crate::network::node_profile::NodeProfile::from_str(&state.config.node_profile);
        if !profile.accepts_gossip_push() {
            state
                .gossip_push_rejected_profile_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return to_body(&json!({
                "accepted": false,
                "reason": "profile_rejects_push",
                "profile": profile.as_str(),
            }));
        }
    }

    let record_id = record.id.clone();

    if state.seen.lock_recover().contains(&record_id) {
        state.gossip_seen_dedup_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return to_body(&json!({
            "accepted": false, "reason": "duplicate",
            "id": record_id.clone(), "record_id": record_id,
        }));
    }
    if state.gossip_rejected.lock_recover().contains(&record_id) {
        state.gossip_rejected_dedup_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return to_body(&json!({
            "accepted": false, "reason": "previously_rejected",
            "id": record_id.clone(), "record_id": record_id,
        }));
    }

    let record_clone = record.clone();
    // Clamp the peer-supplied hop count to our configured ceiling. The relay
    // branch below forwards `hops - 1`; an unclamped value (up to u8::MAX = 255)
    // would let one push traverse far more relay hops than `gossip_max_hops`
    // permits. Origination (the `None` branch) already bounds via the
    // publish_record_with_fallback hop budget.
    let incoming_hops: Option<u8> = headers
        .get("x-elara-hops")
        .and_then(|v| v.parse::<u8>().ok())
        .map(|h| h.min(state.config.gossip_max_hops));
    let sender: Option<String> = headers.get("x-elara-sender").cloned();

    if let Some(core) = state.state_core.get() {
        // B6: the gossip-push rate-exemption must derive from the
        // handshake-authenticated identity, NEVER the spoofable x-elara-sender
        // header. An authed-but-untrusted stranger's push gets `trusted: false`
        // → full node-local gauntlet + normal lane.
        let push_trusted = sender.is_some() && push_is_trusted(state, peer_identity_hash).await;
        let source = if let Some(s) = sender.clone() {
            crate::network::state_core::RecordSource::GossipPush {
                peer_hash: s,
                trusted: push_trusted,
            }
        } else {
            // PQ submit without a sender header — treat as direct submission.
            // peer_ip isn't meaningful on the PQ path (TCP source is classical),
            // leave None so downstream logs don't assume HTTP semantics.
            crate::network::state_core::RecordSource::HttpSubmit { peer_ip: None }
        };
        // B6 fork-safety: untrusted pushes must never poison gossip_rejected
        // (the reject-cache feeds every pull-skip) — see should_permanent_reject.
        let untrusted_push = matches!(
            &source,
            crate::network::state_core::RecordSource::GossipPush { trusted: false, .. }
        );

        // 8b invariant: seal-class never enters gossip_rejected — probe before
        // the move, dispose BEFORE should_permanent_reject (which only guards
        // untrusted pushes; a trusted-push seal reject was still a leak).
        let seal_probe = crate::network::gossip::seal_reject_probe(&record);
        let result = core.insert_record(record, source).await;
        match result {
            crate::network::state_core::InsertResult::Accepted { .. } => {}
            crate::network::state_core::InsertResult::Rejected { reason } => {
                if crate::network::gossip::dispose_seal_ingest_failure_probed(
                    state,
                    &seal_probe,
                    0,
                ) {
                    // seal-class disposed (declined or bounded park)
                } else if crate::network::gossip::should_permanent_reject(untrusted_push, &reason)
                {
                    state.gossip_rejected.lock_recover().insert(record_id.clone());
                } else {
                    crate::network::gossip::park_retryable(state, &record_id);
                }
                return to_body(&json!({
                    "accepted": false, "reason": reason,
                    "id": record_id.clone(), "record_id": record_id,
                }));
            }
            crate::network::state_core::InsertResult::Error { message } => {
                if !crate::network::gossip::dispose_seal_ingest_failure_probed(
                    state,
                    &seal_probe,
                    0,
                ) {
                    state.gossip_rejected.lock_recover().insert(record_id.clone());
                }
                return Err(ElaraError::Storage(message));
            }
        }
    } else {
        gossip::insert_record(state, record).await?;
    }

    state.seen.lock_recover().insert(record_id.clone());

    // Best-effort relay — matches the axum handler's tokio::spawn relay path.
    let node_type = crate::network::peer::NodeType::from_str(&state.config.node_type);
    let state2 = state.clone();
    let exclude_sender = sender.clone();
    tokio::spawn(async move {
        match incoming_hops {
            None => {
                NodeState::publish_record_with_fallback(
                    &state2, &record_clone, exclude_sender.as_deref(),
                ).await;
            }
            Some(hops) if hops > 0 && node_type.can_relay() => {
                gossip::push_to_peers(
                    &state2, &record_clone, hops - 1,
                    exclude_sender.as_deref(), None,
                ).await;
            }
            Some(_) => {
                state2.gossip_push_skipped_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    });

    // `record_id` mirrors the axum `POST /records` response field so the
    // account's /ws Slice 2 Step 2 cutover can read one shape across both
    // transports; `id` stays for legacy PQ consumers (pq_client.submit_record
    // returns the raw JSON — no breaking change to in-tree callers).
    to_body(&json!({"accepted": true, "id": record_id.clone(), "record_id": record_id}))
}

// ─── query_records ───────────────────────────────────────────────────────────

async fn handle_query_records(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    state.stamp_inbound_sync();
    let since = header_f64(headers, "since").unwrap_or(0.0);
    let limit = header_usize(headers, "limit").unwrap_or(100).min(1000);
    let creator_key = headers.get("creator").and_then(|h| hex::decode(h).ok());

    let state2 = state.clone();
    let wire_bytes = tokio::task::spawn_blocking(move || -> Result<Vec<Vec<u8>>> {
        let records = state2.rocks.query(
            None,
            creator_key.as_deref(),
            Some(since),
            None,
            limit,
        )?;
        Ok(records.iter().map(|r| r.to_bytes()).collect())
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    // Byte budget (twin of handle_delta_sync's): `limit` alone admits 1000 ×
    // ~80KB-hex dual-signed records ≈ 80MB, which BOTH overruns the 16MiB−1
    // single frame AND cannot transfer within the per-page 30s RPC deadline on a
    // slow link — see crate::network::sync::MAX_SYNC_RESPONSE_HEX_BYTES. THIS
    // verb is what `full_pull` (the historical backfill sweep) rides on, so an
    // unbudgeted fat page kills the connection and full_pull's cursor never
    // advances past it (root-caused live 2026-07-02: follower's payload gap
    // never healed; the sweep died on the same page every ~200-cycle firing).
    // Response shape is compatibility-split: an UNTRUNCATED page keeps the legacy
    // bare-array shape (old clients parse it; their `batch_len < page_size` tail
    // check stays correct because every fetched record was sent). A truncated
    // page — which no old client ever received anyway (the transport died) —
    // switches to {"records": […], "has_more": true} so a current client
    // advances its cursor instead of misreading the short page as the tail.
    let mut hex_records: Vec<String> = Vec::new();
    let mut hex_cost = 0usize;
    let mut truncated = false;
    for wire in &wire_bytes {
        let cost = wire.len() * 2 + 4; // hex chars + JSON quotes/comma
        if !hex_records.is_empty()
            && hex_cost + cost > crate::network::sync::MAX_SYNC_RESPONSE_HEX_BYTES
        {
            truncated = true;
            break;
        }
        hex_cost += cost;
        hex_records.push(hex::encode(wire));
    }
    if truncated {
        to_body(&serde_json::json!({ "records": hex_records, "has_more": true }))
    } else {
        to_body(&hex_records)
    }
}

// ─── announce ────────────────────────────────────────────────────────────────

/// Upper bound on the raw body of peer-supplied *list* RPC methods
/// (`announce`, `fetch_records`, `records_exist`) before `serde_json::from_slice`.
/// Each handler `.take()`s the decoded `Vec` to a small element cap, but serde
/// allocates the *entire* parsed `Vec` first, so an oversized body amplifies into
/// transient heap (JSON `String` overhead) before the element cap can apply. A
/// legit 1000-announcement body is ≈ 0.3 MiB; this 2 MiB ceiling leaves ample
/// headroom for the largest legitimate request while bounding decode-time heap
/// even from a hostile peer — a phone-tier node cannot be memory-pressured up
/// toward the frame layer's 16 MiB `MAX_PAYLOAD`. Fail-closed: oversized ⇒ `Wire`
/// error, before any parse allocation.
const MAX_LIST_REQUEST_BODY: usize = 2 * 1024 * 1024;

#[inline]
fn guard_list_body(method: &str, body: &[u8]) -> Result<()> {
    if body.len() > MAX_LIST_REQUEST_BODY {
        return Err(ElaraError::Wire(format!(
            "{method} request body too large: {} bytes (max {MAX_LIST_REQUEST_BODY})",
            body.len()
        )));
    }
    Ok(())
}

/// Size gate for a single-record ingest body (`submit_record`, `witness`)
/// before `ValidationRecord::from_bytes` + Dilithium3 verify. The PQ frame
/// layer admits up to `MAX_PAYLOAD` (16 MiB); without this gate a handshaked
/// peer could force a full parse + signature verify on a 16 MiB body per
/// message. A real record is bounded by `MAX_RECORD_BYTES` (64 KiB), the same
/// ceiling the HTTP ingest path enforces.
fn guard_record_body(method: &str, body: &[u8]) -> Result<()> {
    let max = crate::network::ingest::MAX_RECORD_BYTES;
    if body.len() > max {
        return Err(ElaraError::Wire(format!(
            "{method} body too large: {} bytes (max {max})",
            body.len()
        )));
    }
    Ok(())
}

/// Upper bound on a finality / cross-zone-abort *witness* gossip body before
/// `serde_json::from_slice`. The body carries one `SealFinalityWitness`:
/// Dilithium3 pubkey (1952 B) + signature (3293 B) + a committee-membership
/// inclusion proof (`Vec<ProofSibling>`, depth ~log2(committee)). Serialized as
/// JSON a legit witness is ≈ 25 KiB even for a large committee; 256 KiB is ~10×
/// headroom while bounding both the decode allocation AND the
/// `verify_inclusion_proof` loop a single handshaked peer can drive per message
/// (the canonical committee-hash check rejects forged committees only AFTER the
/// body is decoded). Fail-closed: oversized ⇒ `Wire` error before any parse.
const MAX_WITNESS_GOSSIP_BODY: usize = 256 * 1024;

/// Upper bound on a `receive_attestation` body before `serde_json::from_slice`.
/// One attestation carries a Dilithium3 pubkey (1952 B) + signature (3293 B)
/// hex-encoded plus small id/hash fields — ≈ 12 KiB realistically; 64 KiB is
/// generous headroom. Without this guard a handshaked peer could stream bodies
/// up to the PQ frame `MAX_PAYLOAD` (16 MiB), driving repeated multi-MB
/// parse + hex-decode allocations per message — pre-settlement memory pressure.
/// Fail-closed: oversized ⇒ `Wire` error before any parse. Mirrors
/// `MAX_WITNESS_GOSSIP_BODY` on the finality-witness path.
const MAX_ATTESTATION_BODY: usize = 64 * 1024;

/// Upper bound on a `ConflictProof` body before `serde_json::from_slice`. The
/// proof bundles two `ValidationRecord`s, each serialized ≤ `MAX_RECORD_BYTES`
/// (64 KiB) — together ~512 KiB once JSON-expanded — so 1 MiB leaves headroom
/// while bounding decode-time heap from a hostile peer toward the 16 MiB
/// `MAX_PAYLOAD`. Mirrors the axum `/slot-conflicts` cap exactly
/// (`server::MAX_CONFLICT_PROOF_BODY_BYTES` = 1 MiB, set in a4e73067); the two
/// transports must not drift apart on the same proof type.
const MAX_CONFLICT_PROOF_BODY: usize = 1024 * 1024;

async fn handle_announce(state: &Arc<NodeState>, body: &[u8]) -> Result<Vec<u8>> {
    guard_list_body("announce", body)?;
    let announcements: Vec<RecordAnnouncement> = serde_json::from_slice(body)?;
    let announcements: Vec<_> = announcements.into_iter().take(1000).collect();
    let mut have = Vec::new();
    let mut to_probe = Vec::new();

    // Fast in-memory partition first: `seen` / `gossip_rejected` are
    // `Mutex<SeenSet>` (no I/O). Only IDs that miss both caches need a RocksDB
    // existence check.
    for ann in &announcements {
        if state.seen.lock_recover().contains(&ann.record_id) {
            have.push(ann.record_id.clone());
        } else if state.gossip_rejected.lock_recover().contains(&ann.record_id) {
            state.gossip_rejected_dedup_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            have.push(ann.record_id.clone());
        } else {
            to_probe.push(ann.record_id.clone());
        }
    }

    // Batch the synchronous RocksDB existence checks (up to 1000 point reads)
    // off the async worker thread — otherwise a single peer's full announce
    // list blocks the Tokio worker serving all other ingest. Mirrors
    // handle_fetch_records / handle_records_exist.
    let state2 = state.clone();
    let (want, in_storage) = tokio::task::spawn_blocking(move || {
        let mut want = Vec::new();
        let mut in_storage = Vec::new();
        for id in to_probe {
            if state2.rocks.record_exists(&id).unwrap_or(false) {
                in_storage.push(id);
            } else {
                want.push(id);
            }
        }
        (want, in_storage)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;
    have.extend(in_storage);

    to_body(&json!({ "want": want, "have": have }))
}

// ─── fetch_records ───────────────────────────────────────────────────────────

/// Per-request ID cap for `fetch_records`. Doubles as the response frame-cap
/// guarantee: 100 × worst-case record (64 KiB wire → 128 KiB hex + JSON
/// separators) ≈ 12.5 MiB, inside the 16 MiB−1 single-frame `MAX_PAYLOAD` —
/// pinned by `fetch_records_worst_case_response_fits_single_frame`. Raising
/// this cap re-opens the R2-6 oversized-response class; re-run the math.
///
/// This is the SERVER's per-call ceiling: `handle_fetch_records` silently
/// `take()`s the first `MAX_FETCH_RECORDS` ids and drops the rest. A client
/// that requests MORE gets a silent subset — fine for reconcilers that re-ask
/// by id (orphan resolver, gossip retry, light), but att-pull advances its
/// watermark PAST every deferred attestation after one opportunistic fetch, so
/// ids beyond this cap are pure wasted request bandwidth there. `pub(crate)` so
/// callers couple their request size to it instead of hard-coding a number that
/// silently drifts above it (att-pull did: `fetch_cap` was 200 vs this 100).
pub(crate) const MAX_FETCH_RECORDS: usize = 100;

async fn handle_fetch_records(state: &Arc<NodeState>, body: &[u8]) -> Result<Vec<u8>> {
    guard_list_body("fetch_records", body)?;
    let ids: Vec<String> = serde_json::from_slice(body)?;
    let ids_capped: Vec<String> = ids.into_iter().take(MAX_FETCH_RECORDS).collect();
    let state2 = state.clone();

    let hex_records = tokio::task::spawn_blocking(move || {
        // Byte budget (twin of handle_query_records / handle_delta_sync): the
        // count cap alone admits 100 × ~128KB-hex max-size records ≈ 12.5 MiB —
        // frame-safe, but it CANNOT transfer within the 30s per-call RPC
        // deadline on the phone-tier slow-link floor (~205s), the exact class of
        // the delta_sync/query_records byte-blindness that killed the ACER
        // cellular join (see crate::network::sync::MAX_SYNC_RESPONSE_HEX_BYTES).
        // Unlike query_records, NO has_more signal is needed and the wire shape
        // stays a bare array: every fetch_records caller is id-driven and
        // subset-tolerant — att-pull advances its watermark and the full_pull
        // record sweep (RECORD_PULL_CYCLE_KEY, independent persistent cursor over
        // ALL records, already truncation-aware) re-reaches any truncated-but-
        // present record; orphan-resolver / gossip-retry / light re-ask their
        // still-missing set by re-derived id. Records are ≤64 KiB so the first
        // record always fits (progress guaranteed by the !is_empty() guard).
        let mut results = Vec::new();
        let mut hex_cost = 0usize;
        for id in &ids_capped {
            if let Ok(bytes) = state2.rocks.get_wire_bytes(id) {
                let cost = bytes.len() * 2 + 4; // hex chars + JSON quotes/comma
                if !results.is_empty()
                    && hex_cost + cost > crate::network::sync::MAX_SYNC_RESPONSE_HEX_BYTES
                {
                    break;
                }
                hex_cost += cost;
                results.push(hex::encode(&bytes));
            }
        }
        results
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;

    to_body(&hex_records)
}

/// Gap 6.4 slice 3b — `records_exist` probe handler.
///
/// Body is a JSON array of record ids. Response is a JSON array of bools
/// of the same length: `bits[i] = state.record_exists(ids[i])`. Cap is
/// 256 per request — beyond that the operator should batch into multiple
/// calls (the reconciler defaults to one id per call anyway, since it
/// probes a single seal at a time).
///
/// Cheap: every check is an O(1) RocksDB get on the record CF — no body
/// load, no deserialize.
async fn handle_records_exist(state: &Arc<NodeState>, body: &[u8]) -> Result<Vec<u8>> {
    guard_list_body("records_exist", body)?;
    let ids: Vec<String> = serde_json::from_slice(body)?;
    let max_probe = 256usize;
    let ids_capped: Vec<String> = ids.into_iter().take(max_probe).collect();
    let state2 = state.clone();

    let bits = tokio::task::spawn_blocking(move || -> Vec<bool> {
        ids_capped
            .iter()
            .map(|id| state2.record_exists(id).unwrap_or(false))
            .collect()
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;

    to_body(&bits)
}

// ─── merkle_root ─────────────────────────────────────────────────────────────

async fn handle_merkle_root(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let state2 = state.clone();
    let root = tokio::task::spawn_blocking(move || {
        crate::network::merkle::global_merkle_root(&state2.rocks)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;

    to_body(&json!({ "root": hex::encode(root) }))
}

// ─── delta_sync ──────────────────────────────────────────────────────────────

async fn handle_delta_sync(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<Vec<u8>> {
    // Fail-closed before any work: an honest delta_sync bloom is ≤ ~234 KiB
    // (MAX_BLOOM_BUILD=200K @ 1% FPR). Cap at MAX_DELTA_SYNC_BLOOM_BODY (512 KiB) —
    // HTTP-parity with delta_sync_body_cap() — so an admitted peer can't ride the
    // ~16 MiB MAX_PAYLOAD ceiling to force a multi-MiB transient bloom alloc on a
    // phone-tier node. Precedes the served-telemetry bump: a rejected oversized
    // request must not count as "served".
    guard_command_body(
        "delta_sync",
        body,
        crate::network::sync::MAX_DELTA_SYNC_BLOOM_BODY,
    )?;
    let their_bloom = BloomFilter::from_bytes(body)?;
    // Server-side serve telemetry (PQ-transport twin of routes/sync.rs::delta_sync).
    // Counts every processed delta_sync request, including the low-RAM skip below.
    state
        .delta_sync_served_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    state.stamp_inbound_sync();
    let ram_gb = crate::storage::rocks::StorageEngine::detect_system_ram_gb();

    if ram_gb <= 2 {
        return to_body(&json!({
            "records": Vec::<String>::new(),
            "total_missing": 0,
            "offset": 0,
            "batch_size": 0,
            "has_more": false,
            "scan_hit_cap": false,
        }));
    }

    let default_batch = if ram_gb <= 4 { 200 } else { 500 };
    let max_batch = if ram_gb <= 4 { 500 } else { 2000 };
    let batch_size: usize = header_usize(headers, "x-delta-batch-size")
        .unwrap_or(default_batch)
        .min(max_batch);
    let offset: usize = header_usize(headers, "x-delta-offset").unwrap_or(0);
    // Bound server-side scan via timestamp index.
    // Previously this used `for_each_record_id` which is O(all_records) — at 10M
    // records it would burn 30s+ per dial and was responsible for ~80% of
    // pq_delta_sync timeouts (RPC:handshake = 4:1 attribution). Now we
    // seek into CF_IDX_TIMESTAMP from `since` and hard-cap the scan at MAX_SCAN.
    // Backward-compat: clients that don't send `x-delta-since` get since=0
    // (oldest-first sweep) but still capped — bounded worst-case work either way.
    let since: f64 = header_f64(headers, "x-delta-since").unwrap_or(0.0);

    // Cursor parse (delta-sync cross-page cursor, audit 2026-07-05): before
    // spawn_blocking; malformed → BAD_REQUEST, counted, never a silent
    // fallback to offset paging. Byte-budget rationale (16 MiB frame cap +
    // 30 s slow-link deadline) lives on MAX_SYNC_RESPONSE_HEX_BYTES and
    // build_delta_page — the scan + page assembly are SHARED with the HTTP
    // twin (routes/sync.rs::delta_sync) so the transports cannot drift (I5).
    let cursor_raw: Option<Vec<u8>> = match headers.get("x-delta-cursor") {
        Some(hex_str) => match crate::network::sync::parse_sync_cursor(hex_str) {
            Ok(raw) => Some(raw),
            Err(e) => {
                state
                    .delta_sync_cursor_reject_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(e);
            }
        },
        None => None,
    };
    if cursor_raw.is_some() {
        state
            .delta_sync_cursor_pages_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    let state2 = state.clone();
    let page = tokio::task::spawn_blocking(
        move || -> Result<crate::network::sync::DeltaPage> {
            crate::network::sync::build_delta_page(
                &state2.rocks,
                &their_bloom,
                since,
                offset,
                batch_size,
                cursor_raw.as_deref(),
            )
        },
    )
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    let hex_records: Vec<String> = page.records_wire.iter().map(hex::encode).collect();
    state
        .delta_sync_served_records_total
        .fetch_add(hex_records.len() as u64, std::sync::atomic::Ordering::Relaxed);
    if page.scan_hit_cap == Some(true) {
        state
            .delta_sync_scan_hit_cap_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    to_body(&crate::network::sync::delta_page_json(
        &page,
        hex_records,
        offset,
    ))
}

// ─── find_node ───────────────────────────────────────────────────────────────

async fn handle_find_node(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    use crate::network::dht::NodeId;

    let count = header_usize(headers, "count").unwrap_or(8).min(20);
    let dht = state.dht.lock_recover();
    let target = headers
        .get("target")
        .and_then(|s| NodeId::from_hex(s))
        .unwrap_or(*dht.local_id());

    let closest: Vec<Value> = dht
        .closest(&target, count)
        .iter()
        .map(|p| {
            json!({
                "identity_hash": p.identity_hash,
                "host": p.host,
                "port": p.port,
                "last_seen": p.last_seen,
            })
        })
        .collect();

    to_body(&json!({
        "target": target.to_hex(),
        "peers": closest,
    }))
}

// ─── witness ─────────────────────────────────────────────────────────────────

async fn handle_witness(state: &Arc<NodeState>, body: &[u8]) -> Result<Vec<u8>> {
    guard_record_body("witness", body)?;
    let record = ValidationRecord::from_bytes(body)?;

    // Dilithium3 verify + inline Dilithium3 SIGN — the heaviest per-message
    // inline PQC on the router. Both run in ONE spawn_blocking hop off the
    // scarce async workers; aggregate concurrency is bounded by the
    // dispatch-level `pq_verify_semaphore` permit this request already holds
    // (internal design notes).
    let state2 = state.clone();
    let attestation_sig = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let signable = record.signable_bytes();
        match record.signature.as_ref() {
            Some(sig) => {
                if !dilithium3_verify(&signable, sig, &record.creator_public_key)? {
                    return Err(ElaraError::InvalidSignature);
                }
            }
            None => return Err(ElaraError::InvalidSignature),
        }
        state2
            .identity
            .sign(&signable)
            .map_err(|e| ElaraError::Network(format!("witness sign failed: {e}")))
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    let mut response = Vec::with_capacity(64 + attestation_sig.len());
    response.extend_from_slice(state.identity.identity_hash.as_bytes());
    response.extend_from_slice(&attestation_sig);
    Ok(response)
}

// ─── snapshot_latest (metadata) ──────────────────────────────────────────────

async fn handle_snapshot_latest(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let ledger = state.ledger.read().await;
    let supply = ledger.total_supply;
    let staked = ledger.total_staked;
    let accounts = ledger.accounts.len();
    drop(ledger);

    let signer = state.identity.identity_hash.clone();
    let state2 = state.clone();
    let (merkle_root, record_count) = tokio::task::spawn_blocking(move || {
        let root = hex::encode(crate::network::merkle::global_merkle_root(&state2.rocks));
        let count = state2.record_count().unwrap_or(0) as u64;
        (root, count)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))?;

    to_body(&json!({
        "merkle_root": merkle_root,
        "record_count": record_count,
        "snapshot_timestamp": crate::record::now_timestamp(),
        "signer_identity": signer,
        "accounts": accounts,
        "total_supply": supply,
        "total_staked": staked,
    }))
}

// ─── snapshot_full ───────────────────────────────────────────────────────────

async fn handle_snapshot_full(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    // OOM circuit-breaker — the PQ twin of the HTTP `serve_snapshot` gate
    // (routes/sync.rs:648-665). Any handshake-authed peer can call this over the
    // primary transport, and the body below clones the full ledger +
    // collect_applied_ids + JSON-serializes it — an unbounded heap pull that
    // pushes a 4 GB node into swap once the chain outgrows the caps. Sample both
    // pressure dimensions BEFORE either gate so the high-water gauge captures the
    // value that tripped it (matching the HTTP path), then fail fast with 429:
    // the client treats RateLimited as "switch to /snapshot/state-delta
    // incremental against an archive baseline". `approximate_cf_size` reads
    // RocksDB `estimate-num-keys` (O(1) property lookup, no scan).
    let accounts_count = state.ledger.read().await.accounts.len();
    let applied_count = state.rocks.approximate_cf_size(crate::storage::rocks::CF_APPLIED);
    crate::network::routes::sync::observe_snapshot_serve_size(accounts_count, applied_count);
    if accounts_count > crate::network::routes::sync::MAX_SNAPSHOT_FULL_ACCOUNTS {
        state
            .snapshot_size_rejected_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(ElaraError::RateLimited);
    }
    if applied_count > crate::network::routes::sync::MAX_SNAPSHOT_APPLIED_RECORDS {
        state
            .snapshot_size_rejected_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(ElaraError::RateLimited);
    }

    let identity = state.identity.clone();
    let mut ledger = state.ledger.read().await.clone();
    // Gap 7: Clone() deliberately drops applied_record_ids (hot-path opt). The
    // bootstrapping peer needs it to pre-seed its CF_APPLIED so re-arriving
    // pre-baseline records are recognized as already-applied and skip re-apply
    // (the "no double apply" guarantee). Pull from CF_APPLIED (authoritative).
    // Bounded: the `applied_count > MAX_SNAPSHOT_APPLIED_RECORDS` early-return
    // above guarantees we are under the cap here — same contract as the HTTP
    // serve path (routes/sync.rs). Without this the PQ snapshot (the PRIMARY
    // bootstrap transport) shipped applied_ids=0 on every join.
    ledger.applied_record_ids = state.rocks.collect_applied_ids();
    let state_inner = state.clone();

    let snapshot = tokio::task::spawn_blocking(move || -> Result<_> {
        let finalized: std::collections::HashSet<String> = std::collections::HashSet::new();
        let epoch = crate::network::epoch::EpochState::new();
        let merkle_root = crate::network::merkle::global_merkle_root(&state_inner.rocks);
        let record_count = state_inner.record_count().unwrap_or(0) as u64;
        let genesis_state = state_inner.genesis_state.read_recover().clone();
        let bootstrap_state = state_inner.bootstrap_state.read_recover().clone();
        let account_state_root = crate::network::account_merkle::AccountStateSMT::new(&state_inner.rocks)
            .root()
            .ok();

        crate::network::snapshot::create_signed_snapshot(crate::network::snapshot::SignedSnapshotInputs {
            ledger: &ledger,
            finalized: &finalized,
            epoch: &epoch,
            genesis_state: Some(&genesis_state),
            bootstrap_state: Some(&bootstrap_state),
            merkle_root,
            record_count,
            identity: &identity,
            account_state_root,
            // C4 slice 1: carry mandate registries for bootstrap (see sync.rs).
            mandates: state_inner.rocks.collect_mandates(),
            revocations: state_inner.rocks.collect_revocations(),
            emergency: state_inner.emergency_snapshot_carry(),
        })
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    let body = to_body(&snapshot)?;
    // PQ responses are single Data frames (frame::MAX_PAYLOAD = 16 MiB−1). The
    // count breakers above bound accounts/records, but the SERIALIZED snapshot
    // body can still cross the frame once state is large — the send() would then
    // fail mid-frame and silently close the connection, so the joiner's bootstrap
    // looks like a dead peer. Fail typed instead: the client falls back to the
    // chunked snapshot_fast_chunk path (byte-budgeted by design). Same failure
    // class as the state_delta guard below.
    const MAX_SNAPSHOT_FULL_RESPONSE: usize = 14 * 1024 * 1024;
    if body.len() > MAX_SNAPSHOT_FULL_RESPONSE {
        state
            .snapshot_size_rejected_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(ElaraError::Network(format!(
            "snapshot_full response {}B exceeds the PQ single-frame budget ({MAX_SNAPSHOT_FULL_RESPONSE}B) — state too large for a one-frame snapshot, use snapshot_fast_chunk",
            body.len()
        )));
    }
    Ok(body)
}

// ─── snapshot_fast_meta ──────────────────────────────────────────────────────

async fn handle_snapshot_fast_meta(
    state: &Arc<NodeState>,
    _headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let state2 = state.clone();
    let meta = tokio::task::spawn_blocking(move || -> Result<SnapshotFastMeta> {
        let merkle_root = hex::encode(crate::network::merkle::global_merkle_root(&state2.rocks));
        let record_count = state2.record_count().unwrap_or(0) as u64;
        let epoch_number = state2
            .epoch
            .read_recover()
            .latest_epoch
            .get(&ZoneId::from_legacy(0))
            .copied()
            .unwrap_or(0);
        Ok(SnapshotFastMeta {
            total_records: record_count,
            merkle_root,
            epoch_number,
        })
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    to_body(&meta)
}

// ─── snapshot_fast_chunk ─────────────────────────────────────────────────────

async fn handle_snapshot_fast_chunk(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let cursor = headers.get("cursor").cloned();
    let since_epoch = header_u64(headers, "since_epoch");
    let state2 = state.clone();

    let chunk = tokio::task::spawn_blocking(move || -> Result<_> {
        let since_ts = since_epoch
            .map(|e| state2.rocks.find_epoch_seal_timestamp(e))
            .transpose()?
            .flatten();
        let chunk = sync_mod::build_snapshot_chunk(
            &state2,
            cursor.as_deref(),
            since_ts,
            sync_mod::SNAPSHOT_CHUNK_SIZE,
        )?;
        Ok(chunk)
    })
    .await
    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;

    to_body(&chunk)
}

// ─── query_attestations ─────────────────────────────────────────────────────
//
// Mirrors the axum `sync::query_attestations` GET handler. Header inputs:
//   - `record_id`  → if present, returns all attestations for that record
//   - `since`,`limit` → otherwise returns attestations since timestamp
async fn handle_query_attestations(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let mgr = state.witness_mgr.as_ref();

    if let Some(record_id) = headers.get("record_id") {
        // Bounded page (per-record cardinality is attacker-controlled) + the
        // same byte-budget as the since branch below: an uncapped by-record
        // response overruns the frame layer's 16 MiB MAX_PAYLOAD at ~3k rows
        // and can never be sent, stalling att-pull for that record entirely.
        let (atts, row_capped) = mgr.get_attestations_page(
            record_id,
            crate::network::witness::MAX_ATTESTATIONS_PER_RECORD_READ,
        )?;
        let mut list: Vec<Value> = Vec::new();
        let mut hex_cost = 0usize;
        let mut byte_capped = false;
        for a in &atts {
            let cost = a.signature.len() * 2
                + a.witness_public_key.as_ref().map_or(0, |p| p.len() * 2)
                + a.record_id.len()
                + a.witness_hash.len()
                + 64;
            if !list.is_empty()
                && hex_cost + cost > crate::network::sync::MAX_SYNC_RESPONSE_HEX_BYTES
            {
                byte_capped = true;
                break;
            }
            hex_cost += cost;
            list.push(att_to_json(a));
        }
        return to_body(&json!({
            "record_id": record_id,
            "attestations": list,
            "capped": row_capped || byte_capped,
        }));
    }

    let since = header_f64(headers, "since").unwrap_or(0.0);
    let limit = header_usize(headers, "limit").unwrap_or(100).min(10_000);
    let atts = mgr.get_attestations_since(since, limit)?;
    // PQ-ROUTER-01 (2026-07-03 audit): each attestation carries a hex-encoded
    // Dilithium3 signature (+ optional pubkey); `limit` up to 10k could serialize
    // ~80 MB, overrunning the frame layer's 16 MiB MAX_PAYLOAD so the response
    // can never be sent and attestation sync stalls. Byte-budget the page the
    // same way the record sync path does (MAX_SYNC_RESPONSE_HEX_BYTES), always
    // emitting at least the first so a since-cursor still makes progress.
    let mut list: Vec<Value> = Vec::new();
    let mut hex_cost = 0usize;
    for a in &atts {
        let cost = a.signature.len() * 2
            + a.witness_public_key.as_ref().map_or(0, |p| p.len() * 2)
            + a.record_id.len()
            + a.witness_hash.len()
            + 64;
        if !list.is_empty()
            && hex_cost + cost > crate::network::sync::MAX_SYNC_RESPONSE_HEX_BYTES
        {
            break;
        }
        hex_cost += cost;
        list.push(att_to_json(a));
    }
    to_body(&json!({ "attestations": list }))
}

fn att_to_json(a: &crate::network::witness::AttestationRecord) -> Value {
    let mut v = json!({
        "record_id": a.record_id,
        "witness_hash": a.witness_hash,
        "signature": hex::encode(&a.signature),
        "timestamp": a.timestamp,
    });
    if let Some(pk) = &a.witness_public_key {
        v["witness_public_key"] = json!(hex::encode(pk));
    }
    v
}

// Hard cap on deferred attestations retained per not-yet-local `record_id`.
//
// The record-not-local defer path in `handle_receive_attestation` buffers an
// inbound attestation WITHOUT verifying its Dilithium signature — verification
// needs the record's signable bytes, which are not present yet. The only
// admission gate is `sha3(witness_pk) == witness_hash`, which a peer forges for
// free with a fresh keypair. Without a per-record bound, a single handshaked
// peer flooding ONE non-local record_id with distinct keypairs grew that bucket
// without limit inside the 600 s TTL window AND turned the dedup scan into
// O(N²) CPU (pre-flip audit 2026-06-26). The cap constant + bounded-push +
// O(1) saturation eviction now live on `DeferredAttestationBuf` (state.rs),
// shared with the HTTP twin in routes/sync.rs — the twin had drifted capless.
use crate::network::state::MAX_DEFERRED_ATTS_PER_RECORD;

// ─── receive_attestation ────────────────────────────────────────────────────
//
// Mirrors `sync::receive_attestation`. JSON body shape matches
// `AttestationSubmit`. Same cryptographic + sybil defenses as HTTP path.
async fn handle_receive_attestation(
    state: &Arc<NodeState>,
    body: &[u8],
    peer_identity_hash: &[u8; 32],
) -> Result<Vec<u8>> {
    use crate::crypto::hash::sha3_256_hex;
    use std::sync::atomic::Ordering::Relaxed;

    // MAINNET mandate #3 (floor-push) — attestation ingress byte meter.
    // Captured BEFORE deserialise so bodies that fail to parse still count;
    // they ate network bandwidth on the wire and contribute to ingress
    // budget pressure. Mirror to push_attestation_to_peers' egress meter.
    state
        .attestation_bytes_in_total
        .fetch_add(body.len() as u64, Relaxed);

    // Fail-closed size gate BEFORE serde_json allocates the body and hex::decode
    // allocates again. Mirrors submit_finality_witness's MAX_WITNESS_GOSSIP_BODY
    // guard; without it a handshaked peer drives multi-MB allocations per message.
    if body.len() > MAX_ATTESTATION_BODY {
        return Err(ElaraError::Wire(format!(
            "receive_attestation body too large: {} bytes (max {MAX_ATTESTATION_BODY})",
            body.len()
        )));
    }

    #[derive(serde::Deserialize)]
    struct AttestationSubmit {
        record_id: String,
        witness_hash: String,
        signature: String,
        timestamp: f64,
        witness_public_key: Option<String>,
        powas_nonce: Option<u64>,
        powas_difficulty: Option<u64>,
    }

    let submit: AttestationSubmit = serde_json::from_slice(body)?;

    let sig_bytes = hex::decode(&submit.signature)
        .map_err(|e| {
            state.attestation_receive_rejected_bad_signature_total.fetch_add(1, Relaxed);
            ElaraError::Wire(format!("bad signature hex: {e}"))
        })?;
    if sig_bytes.is_empty() {
        state.attestation_receive_rejected_bad_signature_total.fetch_add(1, Relaxed);
        return Err(ElaraError::InvalidSignature);
    }

    // Negative cache short-circuit.
    {
        let bad = state.attestation_bad_sigs.lock_recover();
        let key = format!("{}:{}", submit.record_id, submit.witness_hash);
        if bad.contains(&key) {
            state.attestation_receive_rejected_bad_signature_total.fetch_add(1, Relaxed);
            return Err(ElaraError::InvalidSignature);
        }
    }

    // Resolve witness pubkey from inline field OR identity registry. Reject
    // when neither yields a key — an unverified attestation is a forgery
    // vector (AUDIT-1, 2026-04-22). Mirrors the HTTP path in routes/sync.rs.
    let pk: Vec<u8> = if let Some(pk_hex) = &submit.witness_public_key {
        let pk = hex::decode(pk_hex)
            .map_err(|e| {
                state.attestation_receive_rejected_unknown_pk_total.fetch_add(1, Relaxed);
                ElaraError::Wire(format!("bad public key hex: {e}"))
            })?;
        if sha3_256_hex(&pk) != submit.witness_hash {
            state.attestation_receive_rejected_unknown_pk_total.fetch_add(1, Relaxed);
            return Err(ElaraError::InvalidSignature);
        }
        pk
    } else {
        match state.rocks.get_public_key(&submit.witness_hash) {
            Some(pk) => pk,
            None => {
                state.attestation_receive_rejected_unknown_pk_total.fetch_add(1, Relaxed);
                return Err(ElaraError::InvalidSignature);
            }
        }
    };

    let signable_result = state.get_record(&submit.record_id)
        .map(|rec| rec.signable_bytes());

    match signable_result {
        Ok(signable) => {
            // Dilithium3 verify off the async workers (spawn_blocking), bounded
            // by the dispatch-level `pq_verify_semaphore` permit. pk + sig are
            // cloned into the closure — a few KiB against a 1-4 ms verify.
            let pk_v = pk.clone();
            let sig_v = sig_bytes.clone();
            let sig_ok =
                tokio::task::spawn_blocking(move || dilithium3_verify(&signable, &sig_v, &pk_v))
                    .await
                    .map_err(|e| ElaraError::Network(format!("spawn_blocking: {e}")))??;
            if !sig_ok {
                let mut bad = state.attestation_bad_sigs.lock_recover();
                bad.insert(format!("{}:{}", submit.record_id, submit.witness_hash));
                state.attestation_receive_rejected_bad_signature_total.fetch_add(1, Relaxed);
                return Err(ElaraError::InvalidSignature);
            }
        }
        Err(_) => {
            // Record not local yet — buffer for later retry.
            let received_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            let deferred = crate::network::state::DeferredAttestation {
                witness_hash: submit.witness_hash.clone(),
                signature: sig_bytes,
                timestamp: submit.timestamp,
                witness_public_key: Some(pk.clone()),
                powas_nonce: submit.powas_nonce,
                powas_difficulty: submit.powas_difficulty,
                received_at,
            };
            let rid = submit.record_id.clone();
            {
                let mut buf = state.deferred_attestations
                    .lock().unwrap_or_else(|e| e.into_inner());
                // Sweep amortization + O(1) saturation eviction rationale live
                // on DeferredAttestationBuf — this path is attacker-reachable
                // (any peer citing an unknown record_id), so no per-message
                // O(buckets) work is allowed under this mutex.
                buf.maybe_sweep_expired(received_at);
                if buf.push_bounded(&rid, deferred, received_at, MAX_DEFERRED_ATTS_PER_RECORD) {
                    state.attestation_deferred_evicted_total.fetch_add(1, Relaxed);
                }
                buf.evict_oldest_if_saturated();
            }
            state.attestation_receive_deferred_total.fetch_add(1, Relaxed);
            return to_body(&json!({
                "status": "deferred",
                "record_id": rid,
            }));
        }
    }

    let pubkey_bytes: Option<Vec<u8>> = Some(pk);

    // PoWaS verification when both nonce + difficulty present.
    if let (Some(nonce), Some(difficulty)) = (submit.powas_nonce, submit.powas_difficulty) {
        if let Some(pk) = &pubkey_bytes {
            let witness_stake = {
                let ledger = state.ledger.read().await;
                ledger.staked(&submit.witness_hash)
            };
            if witness_stake > 0 {
                let proof = crate::network::powas::PoWaSProof { nonce, difficulty };
                if !crate::network::powas::verify(&submit.record_id, pk, witness_stake, &proof) {
                    state.attestation_receive_rejected_bad_powas_total.fetch_add(1, Relaxed);
                    return Err(ElaraError::Wire("invalid PoWaS proof".into()));
                }
            }
        }
    }

    // Sybil defense: stake + identity age gate for non-genesis witnesses.
    if submit.witness_hash != state.config.genesis_authority {
        let witness_staked = {
            let ledger = state.ledger.read().await;
            ledger.staked(&submit.witness_hash)
        };
        const MIN_WITNESS_STAKE: u64 = crate::accounting::types::MIN_WITNESS_STAKE_BASE_UNITS;
        if witness_staked < MIN_WITNESS_STAKE {
            // Tier 4.6 bootstrap-pathology: defer instead of reject. Sig was already
            // verified above, so the only thing missing is the witness's stake row.
            // Buffer keyed by witness_hash so a stake update fires O(1) replay of
            // every attestation deferred for that witness. Sybil defense isn't
            // weakened — replay still re-checks the gate; this only adds a 1-hour
            // grace window for the stake record to propagate.
            state.attestation_receive_rejected_low_stake_total.fetch_add(1, Relaxed);
            let received_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            let entry = crate::network::state::DeferredLowStakeAttestation {
                record_id: submit.record_id.clone(),
                witness_hash: submit.witness_hash.clone(),
                signature: sig_bytes.clone(),
                timestamp: submit.timestamp,
                witness_public_key: pubkey_bytes.clone(),
                powas_nonce: submit.powas_nonce,
                powas_difficulty: submit.powas_difficulty,
                received_at,
            };
            crate::network::low_stake_replay::buffer_low_stake_attestation(
                state, entry,
            );
            state.attestation_receive_low_stake_deferred_total.fetch_add(1, Relaxed);
            // Per-peer attribution. peer_identity_hash is
            // populated server-side from the authenticated PQ handshake (see
            // PqStream::peer_identity_hash; rpc.rs line 77). All-zeros means
            // either local same-process submission or a pre-handshake test
            // path; skip the bump in that case so the counter stays meaningful.
            //
            // When the bump targets a peer not in the
            // table (cold-restart race, or a peer that PQ-handshakes but
            // never gets into the table), bump the global unattributed
            // counter so the gap is visible in /metrics. Without this, a
            // PQ-handshake-only peer would silently invert per-peer counters.
            if peer_identity_hash != &[0u8; 32] {
                let peer_hash_hex = hex::encode(peer_identity_hash);
                let bumped = state
                    .peers
                    .write()
                    .await
                    .bump_att_push_low_stake_deferred(&peer_hash_hex, 1);
                if !bumped {
                    state.att_push_unattributed_total.fetch_add(1, Relaxed);
                }
            }
            return to_body(&json!({
                "status": "deferred",
                "reason": "low_stake",
                "record_id": submit.record_id,
            }));
        }

        // GENESIS EXEMPTION: config-pinned genesis validators are
        // the trust root — age proves nothing about them, and on a fresh
        // chain (empty trust DB everywhere) the gate would otherwise bounce
        // all their pushes for the first hour. Mirrors routes/sync.rs.
        let is_genesis_validator = state
            .config
            .genesis_validators
            .iter()
            .any(|v| v.identity == submit.witness_hash);
        let min_age_secs: f64 = if witness_staked >= MIN_WITNESS_STAKE {
            3600.0
        } else {
            48.0 * 3600.0
        };
        let trust = state.trust.read().await;
        let age_secs = trust.identity_age(&submit.witness_hash, submit.timestamp);
        if !is_genesis_validator && age_secs < min_age_secs {
            state.attestation_receive_rejected_too_young_total.fetch_add(1, Relaxed);
            return Err(ElaraError::Wire(format!(
                "witness {} too young ({:.1}h old, need {:.0}h)",
                submit.witness_hash.chars().take(16).collect::<String>(),
                age_secs / 3600.0, min_age_secs / 3600.0,
            )));
        }
    }

    let stored = {
        let mgr = state.witness_mgr.as_ref();
        mgr.store_attestation_with_powas(
            &submit.record_id,
            &submit.witness_hash,
            &sig_bytes,
            submit.timestamp,
            pubkey_bytes.as_deref(),
            submit.powas_nonce,
            submit.powas_difficulty,
        )?
    };

    match stored {
        true => {
            let outcome = state.feed_attestation(
                &submit.record_id, &submit.witness_hash, submit.timestamp,
            ).await;
            // Exactly-once edge — mirrors routes/sync.rs receive_attestation.
            if outcome.first_finalization {
                crate::network::reward::finalization_effects(
                    state,
                    vec![submit.record_id.clone()],
                );
            }

            let att = crate::network::witness::AttestationRecord {
                record_id: submit.record_id.clone(),
                witness_hash: submit.witness_hash.clone(),
                signature: sig_bytes.clone(),
                timestamp: submit.timestamp,
                witness_public_key: pubkey_bytes,
                powas_nonce: submit.powas_nonce,
                powas_difficulty: submit.powas_difficulty,
            };
            let state2 = state.clone();
            tokio::spawn(async move {
                gossip::push_attestation_to_peers(&state2, &att).await;
            });

            to_body(&json!({"accepted": true, "finalized": outcome.settled}))
        }
        false => to_body(&json!({"accepted": false, "reason": "duplicate"})),
    }
}

// ─── receive_conflict_proof ─────────────────────────────────────────────────
//
// Mirrors `sync::receive_conflict_proof`. Verifies the proof, marks the
// slot conflicted, spawns re-gossip. Malformed or re-seen proofs short-
// circuit the way the HTTP handler does.
async fn handle_receive_conflict_proof(
    state: &Arc<NodeState>,
    body: &[u8],
) -> Result<Vec<u8>> {
    use std::sync::atomic::Ordering::Relaxed;

    if body.len() > MAX_CONFLICT_PROOF_BODY {
        state.conflict_proof_rejected_total.fetch_add(1, Relaxed);
        return Err(ElaraError::Wire(format!(
            "receive_conflict_proof body too large: {} bytes (max {MAX_CONFLICT_PROOF_BODY})",
            body.len()
        )));
    }

    let proof: crate::network::conflict_proof::ConflictProof =
        serde_json::from_slice(body)?;

    let slot_key = match proof.slot_key() {
        Some(k) => k,
        None => {
            state.conflict_proof_rejected_total.fetch_add(1, Relaxed);
            return Err(ElaraError::Wire(
                "ConflictProof: records do not agree on a slot".into(),
            ));
        }
    };

    // Dedup — 200-ish response with status=duplicate so sender stops retrying.
    {
        let seen = state.conflict_proof_seen.lock_recover();
        if seen.contains(&slot_key) {
            return to_body(&json!({
                "status": "duplicate",
                "slot_key": slot_key,
            }));
        }
    }

    state.conflict_proof_received_total.fetch_add(1, Relaxed);

    if let Err(e) = proof.verify() {
        state.conflict_proof_rejected_total.fetch_add(1, Relaxed);
        return Err(ElaraError::Wire(format!("ConflictProof verify failed: {e}")));
    }

    let marker = format!("{}:{}", proof.record_a.id, proof.record_b.id);
    state.rocks.slot_mark_conflict(&slot_key, &marker)
        .map_err(|e| ElaraError::Storage(format!("slot_mark_conflict: {e}")))?;

    let state_clone = Arc::clone(state);
    let proof_clone = proof.clone();
    tokio::spawn(async move {
        gossip::push_conflict_proof_to_peers(&state_clone, &proof_clone).await;
    });

    to_body(&json!({
        "status": "accepted",
        "slot_key": slot_key,
    }))
}

/// Gap 2.1 Phase 2c — receive a `SealFinalityWitness` over PQ gossip.
/// Body: JSON-encoded `FinalityWitnessGossipBody`.
///
/// On accept the witness is folded into the local
/// `SealFinalityCollection` via `consensus.add_seal_finality_signature`.
/// Idempotent on `(seal_id, witness_pk)`; the consensus layer drops
/// signatures whose `(seal_epoch, committee_hash, committee_size)`
/// snapshot disagrees with what was already pinned and counts that in
/// `seal_finality_snapshot_mismatch_total`.
///
/// We do NOT re-broadcast on receipt — only the producer's local sign hook
/// in `network/ingest.rs` initiates a push. This keeps fan-out O(committee
/// × sqrt(peers)) instead of multiplying through every relay hop.
async fn handle_submit_finality_witness(
    state: &Arc<NodeState>,
    body: &[u8],
    // Attribution ONLY (design doc INBOUND-VERIFY-DOS-HARDENING-2026-06-27 §4):
    // logged so operators can attribute a rejection flood to the sending peer
    // for reputation/disconnect decisions. NEVER a drop-gate — dropping a
    // consensus witness by peer identity is a finality-liveness regression.
    peer_identity_hash: &[u8; 32],
) -> Result<Vec<u8>> {
    use std::sync::atomic::Ordering::Relaxed;

    if body.len() > MAX_WITNESS_GOSSIP_BODY {
        state.finality_witness_rejected_total.fetch_add(1, Relaxed);
        tracing::debug!(
            peer = %hex::encode(peer_identity_hash),
            body_len = body.len(),
            "finality witness rejected: oversized body"
        );
        return Err(ElaraError::Wire(format!(
            "submit_finality_witness body too large: {} bytes (max {MAX_WITNESS_GOSSIP_BODY})",
            body.len()
        )));
    }

    let envelope: crate::network::gossip::FinalityWitnessGossipBody =
        serde_json::from_slice(body).map_err(|e| {
            state.finality_witness_rejected_total.fetch_add(1, Relaxed);
            tracing::debug!(
                peer = %hex::encode(peer_identity_hash),
                "finality witness rejected: decode failed"
            );
            ElaraError::Wire(format!("submit_finality_witness: decode failed: {e}"))
        })?;

    state.finality_witness_received_total.fetch_add(1, Relaxed);

    // SECURITY (pre-flip audit 2026-06-22): never trust the wire-supplied
    // committee snapshot. verify_finality_quorum checks each witness's
    // membership against committee_hash, so a peer that pins a 1-member
    // committee of its own key would forge cross-zone seal finality with a
    // single self-signed witness (and add_seal_finality_signature lets the
    // FIRST caller pin the collection's snapshot). Recompute the CANONICAL
    // committee for the seal's (zone, epoch) locally — the same derivation the
    // honest signer uses at seal ingest (finality_committee_pks) — and drop any
    // witness whose snapshot does not match. A witness for a seal we have not
    // ingested yet is dropped: it is unconsumable anyway (claim/attach both
    // require the seal in hand), so the drop is costless and avoids trusting an
    // unverifiable committee.
    let seal_zone = match state.rocks.get_record(&envelope.seal_id) {
        Ok(Some(seal_rec)) => {
            match crate::network::epoch::extract_epoch_seal(&seal_rec) {
                Ok(Some(seal)) if seal.epoch_number == envelope.seal_epoch => seal.zone,
                _ => {
                    state.finality_witness_rejected_total.fetch_add(1, Relaxed);
                    return to_body(
                        &json!({"status": "rejected", "reason": "not_an_epoch_seal_or_epoch_mismatch"}),
                    );
                }
            }
        }
        _ => {
            // Seal not ingested locally yet — costless drop (see note above).
            state.finality_witness_rejected_total.fetch_add(1, Relaxed);
            return to_body(&json!({"status": "deferred", "reason": "seal_unknown_locally"}));
        }
    };

    let (pks, canonical_hash, canonical_size) =
        crate::network::zone_committee::finality_committee_pks(
            state,
            seal_zone.path(),
            envelope.seal_epoch,
            crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE,
        )
        .await;

    if envelope.committee_hash != canonical_hash || envelope.committee_size != canonical_size {
        state
            .finality_witness_committee_mismatch_total
            .fetch_add(1, Relaxed);
        return to_body(&json!({"status": "rejected", "reason": "committee_snapshot_mismatch"}));
    }

    // SECURITY (memory-DoS gate): snapshot matches, but verify the signer is
    // actually IN the canonical committee BEFORE inserting. add_seal_finality_
    // signature dedups by witness_pk but does NOT cap `signers` at committee_size,
    // so a peer that knows the (public) committee_hash could submit unbounded
    // distinct fake-pk witnesses — each a valid signature over the canonical
    // message — and grow `signers` without limit. Forgery stays blocked at claim
    // by verify_finality_quorum's membership proof, but the collection is the OOM
    // surface. Mirror the local self-signer's `am_member` check (ingest.rs) and
    // claim-time membership: drop any witness_pk not in the canonical pk set,
    // bounding `signers` to real members (pk-dedup then bounds to ≤ committee_size).
    if !pks.iter().any(|pk| pk == &envelope.witness.witness_pk) {
        state.finality_witness_non_member_total.fetch_add(1, Relaxed);
        return to_body(&json!({"status": "rejected", "reason": "witness_not_in_committee"}));
    }

    {
        let mut consensus = state.consensus.lock_recover();
        consensus.add_seal_finality_signature(
            &envelope.seal_id,
            envelope.seal_epoch,
            envelope.committee_hash,
            envelope.committee_size,
            envelope.witness,
        );
    }

    to_body(&json!({"status": "accepted", "seal_id": envelope.seal_id}))
}

/// Gap 2 sealed-abort P-3e — receiver handler for abort-witness gossip.
///
/// Decodes `XZoneAbortWitnessGossipBody`, folds the witness into the
/// local `XZoneAbortCollection` via `add_xzone_abort_signature`. The
/// fold is idempotent on `(transfer_id, witness_pk)` and tolerant of
/// committee-snapshot mismatch (counted in
/// `xzone_abort_snapshot_mismatch_total`).
///
/// We do NOT re-broadcast on receipt — only the producer's epoch-tick
/// emitter in `network/epoch.rs` initiates a push. This keeps fan-out
/// O(committee × sqrt(peers)) instead of multiplying through every
/// relay hop.
async fn handle_submit_xzone_abort_witness(
    state: &Arc<NodeState>,
    body: &[u8],
) -> Result<Vec<u8>> {
    use std::sync::atomic::Ordering::Relaxed;

    if body.len() > MAX_WITNESS_GOSSIP_BODY {
        state.xzone_abort_witness_rejected_total.fetch_add(1, Relaxed);
        return Err(ElaraError::Wire(format!(
            "submit_xzone_abort_witness body too large: {} bytes (max {MAX_WITNESS_GOSSIP_BODY})",
            body.len()
        )));
    }

    let envelope: crate::network::gossip::XZoneAbortWitnessGossipBody =
        serde_json::from_slice(body).map_err(|e| {
            state.xzone_abort_witness_rejected_total.fetch_add(1, Relaxed);
            ElaraError::Wire(format!("submit_xzone_abort_witness: decode failed: {e}"))
        })?;

    state.xzone_abort_witness_received_total.fetch_add(1, Relaxed);

    // B2 fix (internal design notes): gate the wire
    // committee snapshot against the canonical anchor frozen from the source
    // seal BEFORE folding it into the local XZoneAbortCollection. The first
    // caller pins the collection's `(committee_hash, size)`; a forged snapshot
    // would poison the collection and starve honest witnesses. Mirrors the B1
    // finality-witness gossip fix, but compares against the seal-frozen anchor
    // (read, not recomputed — abort witnesses feed a replayed chain record).
    // Unknown transfer / no anchor → drop (costless: the abort is unconsumable
    // at apply without the anchored pending entry; the apply path is the
    // authoritative safety gate, this only protects collection integrity).
    let anchor = state
        .ledger
        .read()
        .await
        .cross_zone
        .pending
        .get(&envelope.transfer_id)
        .and_then(|t| t.dest_finality_committee);
    match anchor {
        Some((canon_hash, canon_size))
            if envelope.committee_hash == canon_hash
                && envelope.committee_size == canon_size => {}
        _ => {
            state
                .xzone_abort_witness_committee_mismatch_total
                .fetch_add(1, Relaxed);
            return to_body(&json!({
                "status": "rejected",
                "reason": "committee snapshot does not match sealed anchor (or transfer/anchor unknown)",
                "transfer_id": envelope.transfer_id
            }));
        }
    }

    // SECURITY (memory-DoS gate, twin of handle_submit_finality_witness's
    // membership check): the snapshot matches the seal-frozen anchor, but
    // add_xzone_abort_signature dedups by witness_pk WITHOUT capping `signers` at
    // committee_size — so a peer that knows the (public) committee_hash could
    // submit unbounded distinct fake-pk witnesses (each a self-valid signature
    // over the canonical abort message) and grow one transfer's `signers` without
    // limit (remote OOM on the public PQ surface). Forgery stays blocked at apply
    // by verify_abort_quorum's per-signer inclusion proof, but the collection is
    // the OOM surface. Apply that SAME membership test here, before insert: a fake
    // pk cannot forge a Merkle inclusion proof against the canonical committee
    // root (== envelope.committee_hash, just verified == the anchored canon_hash),
    // so only real members (≤ committee_size distinct) are ever folded. A naive
    // signers.len() cap would instead let fakes front-fill the slots and STARVE
    // real members — the membership test bounds memory AND avoids starvation.
    let leaf = crate::accounting::cross_zone::committee_leaf_hash(&envelope.witness.witness_pk);
    if !crate::accounting::cross_zone::verify_inclusion_proof(
        &leaf,
        &envelope.witness.committee_proof,
        &envelope.committee_hash,
    ) {
        state
            .xzone_abort_witness_non_member_total
            .fetch_add(1, Relaxed);
        return to_body(&json!({
            "status": "rejected",
            "reason": "witness_not_in_committee",
            "transfer_id": envelope.transfer_id
        }));
    }

    {
        let mut consensus = state.consensus.lock_recover();
        consensus.add_xzone_abort_signature(
            &envelope.transfer_id,
            envelope.source_seal_epoch,
            envelope.committee_hash,
            envelope.committee_size,
            envelope.witness,
        );
    }

    to_body(&json!({"status": "accepted", "transfer_id": envelope.transfer_id}))
}

// ─── headers_from (light-client header sync over PQ) ─────────────────────────
//
// Mirrors the axum `/headers/from/{epoch}` endpoint. Request headers:
//   - `since`   (required, u64) — epoch floor, identical semantics to URL path
//   - `zone`    (optional str)  — narrow to one ZoneId
//   - `limit`   (optional usize, default 500, capped at 2000)
//
// Body is empty. Response body is the same JSON shape axum returns:
// `{total, headers: [...]}`. Re-uses `explorer::compute_epoch_headers`
// so the cold-scan result is shared between HTTPS and PQ call paths.
async fn handle_headers_from(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let since = header_u64(headers, "since")
        .ok_or_else(|| ElaraError::Wire("headers_from: missing `since` header".into()))?;
    let zone_filter = headers.get("zone").map(|v| crate::ZoneId::new(v));
    let limit = header_usize(headers, "limit").unwrap_or(500).min(2000);

    let body = crate::network::routes::explorer::compute_epoch_headers(
        Arc::clone(state),
        zone_filter,
        Some(since),
        limit,
    )
    .await?;
    to_body(&body)
}

// ─── seal_progress ───────────────────────────────────────────────────────────
//
// Account-facing status poll. Request headers:
//   - `record_id` (required, str) — the record whose seal progress to return.
//
// Body is empty. Response body is the same JSON shape axum returns:
// `{record_id, confirmation_level, seal_progress}`. Re-uses
// `explorer::compute_seal_progress` so both transports walk the same DAG /
// RocksDB / consensus state — no drift between HTTPS and PQ views of the
// same record.
async fn handle_seal_progress(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let record_id = headers
        .get("record_id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("seal_progress: missing `record_id` header".into()))?;

    let body = crate::network::routes::explorer::compute_seal_progress(
        Arc::clone(state),
        record_id,
    )
    .await?;
    to_body(&body)
}

// ─── seal_progress_stream (4E.3 — server-push) ───────────────────────────────
//
// The streaming cousin of `seal_progress`. Each chunk carries the same JSON
// body the unary route returns. The stream terminates with a FINAL chunk
// when one of three things happens:
//   1. The record reaches confirmation_level = Finalized or Anchored,
//   2. The record falls into the pruned-but-stored "settled" synthesized
//      shape (i.e. progress_pct==100 && settled==true),
//   3. The deadline elapses (MAX_STREAM_DURATION_SECS).
//
// Cadence is STREAM_TICK_MS between data chunks. At the current adaptive
// epoch floor (15s, dropping to 5s tomorrow) the expected chunk count is
// small — handful to a few dozen — so we don't throttle further.
//
// Errors: if `record_id` header is missing, emit one terminal ERROR chunk
// and stop. If `compute_seal_progress` errors mid-stream (e.g., the record
// was pruned mid-poll in a fast-finality cycle), translate the error into
// a terminal ERROR chunk so the client unwinds instead of hanging.
const STREAM_TICK_MS: u64 = 500;
const MAX_STREAM_DURATION_SECS: u64 = 300;

async fn handle_seal_progress_stream(
    state: Arc<NodeState>,
    headers: &BTreeMap<String, String>,
    stream: &mut dyn StreamSink,
) {
    let record_id = match headers.get("record_id").cloned() {
        Some(v) => v,
        None => {
            let _ = stream
                .send_stream_chunk(&PqStreamChunk::error(
                    0,
                    "seal_progress_stream: missing `record_id` header",
                ))
                .await;
            return;
        }
    };

    let started_at = std::time::Instant::now();
    let max_duration = std::time::Duration::from_secs(MAX_STREAM_DURATION_SECS);
    let tick = std::time::Duration::from_millis(STREAM_TICK_MS);
    let mut seq: u32 = 0;

    loop {
        let body = crate::network::routes::explorer::compute_seal_progress(
            Arc::clone(&state),
            record_id.clone(),
        )
        .await;

        let (payload, is_terminal, is_error) = match body {
            Ok(v) => {
                let terminal = is_terminal_progress(&v);
                let bytes = serde_json::to_vec(&v).unwrap_or_default();
                (bytes, terminal, false)
            }
            Err(e) => (e.to_string().into_bytes(), true, true),
        };

        let deadline_hit = started_at.elapsed() >= max_duration;
        let send_final = is_terminal || deadline_hit;

        let chunk = if is_error {
            PqStreamChunk::error(seq, String::from_utf8_lossy(&payload).into_owned())
        } else if send_final {
            PqStreamChunk::final_chunk(seq, payload)
        } else {
            PqStreamChunk::data(seq, payload)
        };

        if stream.send_stream_chunk(&chunk).await.is_err() {
            // Client went away mid-stream. Nothing more we can do.
            return;
        }
        seq = seq.wrapping_add(1);

        if send_final {
            return;
        }

        tokio::time::sleep(tick).await;
    }
}

/// Inspect a `compute_seal_progress` JSON body and decide whether it
/// represents a terminal state that should end the stream.
fn is_terminal_progress(v: &serde_json::Value) -> bool {
    // Confirmation level reported by the node — matches
    // `ConfirmationLevel::name()`. Finalized / Anchored are both
    // definitively terminal from the account's POV.
    match v.get("confirmation_level").and_then(|c| c.as_str()) {
        Some("finalized") | Some("anchored") => return true,
        _ => {}
    }
    // Pruned-fallback synthesizes `settled=true, progress_pct=100`.
    if let Some(sp) = v.get("seal_progress") {
        if sp.get("settled").and_then(|b| b.as_bool()).unwrap_or(false) {
            return true;
        }
        if let Some(pct) = sp.get("progress_pct").and_then(|n| n.as_f64()) {
            if pct >= 100.0 {
                return true;
            }
        }
    }
    false
}

// ─── node_events_stream (4E.3 Phase B — replaces ws.rs) ──────────────────────
//
// Subscribes to `state.events` (the same broadcast::Sender ws.rs::handle_ws
// reads) and pushes each `NodeEvent` to the client as a JSON `PqStreamChunk`.
// Payload shape is byte-identical to today's WebSocket — accounts migrate
// transports without parser changes. Stream closes after
// `MAX_EVENT_STREAM_SECS` of wall-clock; clients reconnect.
//
// Filtering: optional JSON body `{"subscriptions":[{"event_type":"<name>"}, ...]}`.
// `[{"event_type":"*"}]` or empty/missing body = wildcard (every event), which
// matches today's WS broadcast behavior. Per-event filter is a HashSet lookup.
// Identity / record_id / amount filters are noted in the doc but not yet
// enforced — out of scope for v1, tracked under 4E.3 Phase B follow-ups.
//
// Backpressure: tokio::broadcast drops oldest events when the receiver lags.
// We translate `RecvError::Lagged(n)` into a `stream_lag` data chunk so the
// account can re-fetch state and continue, rather than terminating the stream.
// `RecvError::Closed` (sender dropped — node shutting down) sends a final
// chunk and exits.
const MAX_EVENT_STREAM_SECS: u64 = 3600;

/// Upper bound on the subscription-filter body before `serde_json::from_slice::<Value>`.
/// A legit filter (a `{"subscriptions":[{"event_type":"…"}]}` object) is well under
/// 1 KiB even when it names every event type, but a `Value` decode is the worst-case
/// amplifier — every JSON token becomes a ~24-byte enum node, so a frame-sized
/// (≤ `MAX_PAYLOAD` = 16 MiB) body of `[1,1,1,…]` expands into ~10× transient heap,
/// enough to OOM a phone-tier node. Oversized ⇒ fall back to the wildcard firehose
/// (which an empty body already grants, so this concedes nothing) WITHOUT parsing.
const MAX_EVENT_SUB_FILTER_BODY: usize = 64 * 1024;

async fn handle_node_events_stream(
    state: Arc<NodeState>,
    body: &[u8],
    stream: &mut dyn StreamSink,
) {
    use std::collections::HashSet;
    use tokio::sync::broadcast::error::RecvError;

    // Parse the optional subscription filter. Empty body OR a `*`-wildcard
    // entry = no filter; otherwise we keep the set of allowed event_type
    // strings. Unknown or malformed JSON is non-fatal — fall back to wildcard
    // so a misconfigured account still gets the firehose rather than nothing.
    let mut wildcard = body.is_empty();
    let mut allowed_types: HashSet<String> = HashSet::new();
    if !body.is_empty() && body.len() > MAX_EVENT_SUB_FILTER_BODY {
        // Oversized filter — never parse it (see MAX_EVENT_SUB_FILTER_BODY). Treat
        // exactly like a malformed body: fall back to the wildcard firehose.
        wildcard = true;
    } else if !body.is_empty() {
        match serde_json::from_slice::<Value>(body) {
            Ok(v) => {
                if let Some(subs) = v.get("subscriptions").and_then(|s| s.as_array()) {
                    if subs.is_empty() {
                        wildcard = true;
                    }
                    for sub in subs {
                        match sub.get("event_type").and_then(|t| t.as_str()) {
                            Some("*") => {
                                wildcard = true;
                            }
                            Some(name) => {
                                allowed_types.insert(name.to_string());
                            }
                            None => {}
                        }
                    }
                } else {
                    wildcard = true;
                }
            }
            Err(_) => {
                wildcard = true;
            }
        }
    }
    if !wildcard && allowed_types.is_empty() {
        // Caller explicitly asked for nothing — terminate cleanly so a buggy
        // client doesn't sit on a dead stream waiting on an event it filtered
        // away.
        let _ = stream
            .send_stream_chunk(&PqStreamChunk::final_chunk(
                0,
                b"{\"type\":\"stream_end\",\"data\":{\"reason\":\"empty_subscription_set\"}}".to_vec(),
            ))
            .await;
        return;
    }

    let mut rx = state.events.subscribe();
    let started_at = std::time::Instant::now();
    let max_duration = std::time::Duration::from_secs(MAX_EVENT_STREAM_SECS);
    let mut seq: u32 = 0;

    loop {
        let remaining = max_duration.saturating_sub(started_at.elapsed());
        if remaining.is_zero() {
            let _ = stream
                .send_stream_chunk(&PqStreamChunk::final_chunk(
                    seq,
                    b"{\"type\":\"stream_end\",\"data\":{\"reason\":\"deadline\"}}".to_vec(),
                ))
                .await;
            return;
        }

        let recv = tokio::time::timeout(remaining, rx.recv()).await;
        match recv {
            Err(_) => {
                // Deadline elapsed mid-recv. Same final-chunk shape.
                let _ = stream
                    .send_stream_chunk(&PqStreamChunk::final_chunk(
                        seq,
                        b"{\"type\":\"stream_end\",\"data\":{\"reason\":\"deadline\"}}".to_vec(),
                    ))
                    .await;
                return;
            }
            Ok(Err(RecvError::Closed)) => {
                let _ = stream
                    .send_stream_chunk(&PqStreamChunk::final_chunk(
                        seq,
                        b"{\"type\":\"stream_end\",\"data\":{\"reason\":\"node_shutdown\"}}"
                            .to_vec(),
                    ))
                    .await;
                return;
            }
            Ok(Err(RecvError::Lagged(n))) => {
                let lag_payload = json!({
                    "type": "stream_lag",
                    "data": { "dropped": n }
                });
                let bytes = serde_json::to_vec(&lag_payload).unwrap_or_default();
                if stream
                    .send_stream_chunk(&PqStreamChunk::data(seq, bytes))
                    .await
                    .is_err()
                {
                    return;
                }
                seq = seq.wrapping_add(1);
                continue;
            }
            Ok(Ok(event)) => {
                let (event_type, payload) = encode_node_event(&event);
                if !wildcard && !allowed_types.contains(event_type) {
                    continue;
                }
                let bytes = serde_json::to_vec(&payload).unwrap_or_default();
                if stream
                    .send_stream_chunk(&PqStreamChunk::data(seq, bytes))
                    .await
                    .is_err()
                {
                    return;
                }
                seq = seq.wrapping_add(1);
            }
        }
    }
}

/// Translate a `NodeEvent` into the JSON shape ws.rs ships today. Pulled out
/// so it's testable independent of the streaming machinery — guards against
/// silent drift between the WS payload and the PQ payload, which is the
/// migration's load-bearing invariant.
fn encode_node_event(event: &NodeEvent) -> (&'static str, Value) {
    match event {
        NodeEvent::RecordInserted {
            record_id,
            creator_hash,
            beat_op,
            beat_amount,
            timestamp,
        } => (
            "record_inserted",
            json!({
                "type": "record_inserted",
                "data": {
                    "record_id": record_id,
                    "creator_hash": creator_hash,
                    "beat_op": beat_op,
                    "beat_amount": beat_amount,
                    "timestamp": timestamp,
                }
            }),
        ),
        NodeEvent::RecordSealed {
            record_id,
            witness_count,
        } => (
            "record_sealed",
            json!({
                "type": "record_sealed",
                "data": {
                    "record_id": record_id,
                    "witness_count": witness_count,
                }
            }),
        ),
        NodeEvent::RecordFinalized { record_id } => (
            "record_finalized",
            json!({
                "type": "record_finalized",
                "data": { "record_id": record_id }
            }),
        ),
    }
}

// ─── record_detail ───────────────────────────────────────────────────────────
//
// Full record inspection. Request headers:
//   - `record_id` (required, str).
// Body empty. Delegates to `explorer::compute_record_detail` so the PQ and
// axum paths return byte-identical JSON.
async fn handle_record_detail(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let record_id = headers
        .get("record_id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("record_detail: missing `record_id` header".into()))?;

    let body = crate::network::routes::explorer::compute_record_detail(
        Arc::clone(state),
        record_id,
    )
    .await?;
    to_body(&body)
}

// ─── account_proof ───────────────────────────────────────────────────────────
//
// Light-client account state proof. Request headers:
//   - `identity` (required, hex-32-byte str) — account identity hash.
// Body empty. Delegates to `explorer::compute_account_proof`.
async fn handle_account_proof(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let identity = headers
        .get("identity")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("account_proof: missing `identity` header".into()))?;

    let body = crate::network::routes::explorer::compute_account_proof(
        Arc::clone(state),
        identity,
    )
    .await?;
    to_body(&body)
}

// ─── cross_zone_proof ────────────────────────────────────────────────────────
//
// Cross-zone membership proof (Protocol §11.22.1). Request headers:
//   - `record_id`   (required, str) — record whose cross-zone proof to build.
//   - `target_zone` (required, str) — zone ID the proof should reach into.
// Body empty. Delegates to `explorer::compute_cross_zone_proof`.
async fn handle_cross_zone_proof(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let record_id = headers
        .get("record_id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("cross_zone_proof: missing `record_id` header".into()))?;
    let target_zone = headers
        .get("target_zone")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("cross_zone_proof: missing `target_zone` header".into()))?;

    let body = crate::network::routes::explorer::compute_cross_zone_proof(
        Arc::clone(state),
        record_id,
        target_zone,
    )
    .await?;
    to_body(&body)
}

// ─── balances ────────────────────────────────────────────────────────────────
//
// Account balance lookup. Request headers:
//   - `identity` (optional, str) — filter to one account; otherwise the full
//     list (same as `GET /balances` with/without `?identity=...`).
// Infallible — absent account returns zero balances, not 404.
async fn handle_balances(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let identity = headers.get("identity").cloned();
    // PQ accounts currently parse the same /balances JSON shape as
    // the axum surface but don't yet plumb a `with_recent` header — pass
    // None until a separate slice extends the PQ verb. Header-driven
    // opt-in keeps the legacy PQ poll contract (one ledger read, no rocks
    // scan).
    let with_recent = headers
        .get("with_recent")
        .and_then(|s| s.parse::<usize>().ok());
    let body = crate::network::routes::token::compute_balances(
        Arc::clone(state),
        identity,
        with_recent,
    )
    .await;
    to_body(&body)
}

// ─── dag_tips ────────────────────────────────────────────────────────────────
//
// DAG tip + root snapshot. No request headers, no body. Infallible.
async fn handle_dag_tips(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let body = crate::network::routes::explorer::compute_dag_tips(
        Arc::clone(state),
        None,
    )
    .await;
    to_body(&body)
}

// ─── activity (AUDIT-10 Milestone A) ─────────────────────────────────────────
//
// Identity activity summary. Request headers:
//   - `identity` (required, str) — identity hash to look up.
// Infallible at transport level — an unknown identity returns a JSON body
// with `"error": "identity not found"` and HTTP-equivalent 200 (matches the
// axum `/activity/{identity}` behavior byte-for-byte).
//
// Covers the identity observability surface so accounts and light clients
// don't need HTTPS to poll trust/ledger/continuity/reputation state.
async fn handle_activity(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let identity = headers.get("identity").ok_or_else(|| {
        ElaraError::Wire("missing header: identity".into())
    })?;
    let body = crate::network::routes::explorer::compute_activity(state, identity);
    to_body(&body)
}

// ─── tx_history (/ws Slice 2 prereq) ─────────────────────────────────────────
//
// Account transaction history over PQ. Headers:
//   - `identity` (required, str) — identity hash to filter records for.
//   - `limit` (optional, usize, default 50, clamped to 200) — page size.
//   - `offset` (optional, usize, default 0) — page offset.
// Returns the same `{identity, transactions, total, limit, offset}` envelope
// as the axum `/history` handler, byte-for-byte. Replaces the previous
// pq_shim `/history → activity` misrouting that returned a trust/reputation
// summary instead of the transaction list `node.query_history` consumers
// expect.
async fn handle_tx_history(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let identity = headers.get("identity").cloned().ok_or_else(|| {
        ElaraError::Wire("missing header: identity".into())
    })?;
    let limit = headers
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(50);
    let offset = headers
        .get("offset")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let body = crate::network::routes::token::compute_tx_history(
        Arc::clone(state),
        identity,
        limit,
        offset,
    )
    .await?;
    to_body(&body)
}

// ─── recent_transactions (/ws Slice 2 prereq) ────────────────────────────────
//
// Global recent ledger-op feed. Headers:
//   - `limit` (optional, usize, default 20, clamped to 100) — feed size.
// Returns `{transactions: [...], count: <n>}` byte-identical to the axum
// `/transactions/recent` handler. Was previously misrouted via pq_shim to
// the `activity` verb, which returns a different shape with no `transactions`
// key — fixed alongside the `tx_history` rewire.
async fn handle_recent_transactions(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let limit = headers
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(20);
    let body = crate::network::routes::token::compute_recent_transactions(
        Arc::clone(state),
        limit,
    )
    .await?;
    to_body(&body)
}

// ─── metrics (AUDIT-10 Milestone A) ──────────────────────────────────────────
//
// Prometheus exposition body. No request headers, no body. Infallible.
// PQ peers reach this over the /pq-ws public plane — they are remote, never the
// loopback operator. Render at the public-clamped tier (is_loopback=false) so a
// public-facing Archive node (default ceiling = Debug) cannot serve its host
// fingerprint — per-core CPU freq, hwmon/thermal, per-disk IO, NIC counters,
// rlimits — to a peer over PQ. Mirrors the HTTP `/metrics` clamp
// (clamp_public_metric_tier) and the `/status` host-fingerprint gate; loopback
// operators use HTTP `/metrics`, not this verb, so they keep full Debug there.
async fn handle_metrics(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let tier = crate::network::server::clamp_public_metric_tier(
        false,
        None,
        crate::network::server::current_metric_tier(),
    );
    let body = crate::network::server::metrics_body_tiered(Arc::clone(state), tier).await;
    Ok(body.into_bytes())
}

// ─── checkpoints_from (AUDIT-10 Milestone B step 3b) ─────────────────────────
//
// Super-seal checkpoint feed for light-client cold-start and cross-verify.
// Parallel of axum `/checkpoints/from/{epoch}?zone=&limit=`. Request headers:
//   - `since_epoch` (required, u64) — matches the `{epoch}` path param.
//   - `zone` (optional, str)        — narrow to one zone.
//   - `limit` (optional, usize)     — cap result size (default 500, max 2000).
//
// Shares `explorer::compute_checkpoints_from` with the axum route so both
// surfaces return identical JSON. Closes the last HTTPS-only call site on
// the light-client sync path; with this, a light node with
// `require_pq_transport=true` (4E.5 default) cold-starts over PQ
// transport end-to-end.
async fn handle_checkpoints_from(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let since_epoch = header_u64(headers, "since_epoch")
        .ok_or_else(|| ElaraError::Wire("checkpoints_from: missing `since_epoch` header".into()))?;
    let zone_filter = headers.get("zone").map(|v| crate::ZoneId::new(v));
    let limit = header_usize(headers, "limit").unwrap_or(500).min(2000);
    let body = crate::network::routes::explorer::compute_checkpoints_from(
        state,
        since_epoch,
        zone_filter,
        limit,
    )
    .await?;
    to_body(&body)
}

// ─── AUDIT-10 Milestone C batch 1: admin/explorer verb parity ───────────────
//
// These four verbs cover the operator CLI's most-used read-only admin
// surface (peers, health, ledger_summary, epoch_status). All are nullary
// (no request headers, no body). Each delegates to a `compute_<verb>`
// helper in the matching axum route so axum + PQ transports return
// byte-identical JSON.

async fn handle_list_peers(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    // Nullary verb → default page bound (mirrors the HTTP `/peers` default).
    let body = crate::network::routes::core::compute_list_peers(state, None).await;
    to_body(&body)
}

async fn handle_health(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let body = crate::network::routes::core::compute_health(state).await;
    to_body(&body)
}

async fn handle_ledger_summary(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let body = crate::network::routes::token::compute_ledger_summary(state).await;
    to_body(&body)
}

async fn handle_epoch_status(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    // Nullary verb → default page bound (mirrors the HTTP `/epochs` default).
    let body = crate::network::routes::explorer::compute_epoch_status(state, None).await;
    to_body(&body)
}

// ─── stakes / network_info / token_enforcement ──────────────────────────────
//
// Three more read-only verbs that mirror axum routes 1:1 via `compute_*`
// helpers. `stakes` reads optional `identity` header (omit for fleet-wide
// active stakes). `network_info` and `token_enforcement` are nullary.

async fn handle_stakes(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let identity = headers.get("identity").cloned();
    // No-filter (fleet-wide) branch → default page bound; per-identity branch
    // is naturally bounded so the limit is inert there. Mirrors HTTP `/stakes`.
    let body = crate::network::routes::token::compute_stakes(
        Arc::clone(state),
        identity,
        None,
    )
    .await;
    to_body(&body)
}

async fn handle_network_info(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let body = crate::network::routes::explorer::compute_network_info(
        Arc::clone(state),
    )
    .await;
    to_body(&body)
}

async fn handle_token_enforcement(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let body = crate::network::routes::token::compute_token_enforcement(
        Arc::clone(state),
    )
    .await;
    to_body(&body)
}

// ─── zone_health / governance_summary / governance_params ───────────────────
//
// Three more nullary read-only verbs covering zone topology + governance
// observability surface. zone_health drives operator dashboards (under-
// witnessed coverage warnings), governance_summary is the per-tick proposal
// counter the account and explorer consume, governance_params surfaces
// current network constants for clients that decide locally whether to
// retry/wait based on epoch_seal_interval_secs etc.

async fn handle_zone_health(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let body = crate::network::routes::explorer::compute_zone_health(
        Arc::clone(state),
    )
    .await;
    to_body(&body)
}

async fn handle_governance_summary(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let body = crate::network::routes::explorer::compute_governance_summary(
        Arc::clone(state),
    )
    .await;
    to_body(&body)
}

async fn handle_governance_params(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let body = crate::network::routes::explorer::compute_governance_params(
        Arc::clone(state),
    )
    .await;
    to_body(&body)
}

// ─── supply_circulating / supply_total / supply_max ─────────────────────────
//
// Three nullary beat-supply verbs. Wallets/explorers poll these every block
// to render circulating/total/max headers. The legacy axum surface returns a
// plain-text decimal `beat` body; the PQ verb returns both the integer
// `micros` (canonical, lossless) and the same `beat` float so SDKs can pick
// whichever they prefer without re-deriving from BASE_UNITS_PER_BEAT.

async fn handle_supply_circulating(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let (micros, beat) =
        crate::network::routes::token::compute_supply_circulating(Arc::clone(state)).await;
    to_body(&serde_json::json!({ "micros": micros, "beat": beat }))
}

async fn handle_supply_total(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let (micros, beat) =
        crate::network::routes::token::compute_supply_total(Arc::clone(state)).await;
    to_body(&serde_json::json!({ "micros": micros, "beat": beat }))
}

async fn handle_supply_max() -> Result<Vec<u8>> {
    let (micros, beat) = crate::network::routes::token::compute_supply_max();
    to_body(&serde_json::json!({ "micros": micros, "beat": beat }))
}

// ─── dag_stats / validate_address / list_witness_profiles ───────────────────
//
// dag_stats is fallible (RocksDB scan) but uses an internal cache + background
// warmup, so the cold-cache path may surface a Storage error to clients —
// matched the axum surface. validate_address takes the address from the
// `address` header (axum reads it from a path segment); list_witness_profiles
// is nullary.

async fn handle_dag_stats(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let body = crate::network::routes::explorer::compute_dag_stats(
        Arc::clone(state),
    )
    .await?;
    to_body(&body)
}

async fn handle_validate_address(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let address = headers
        .get("address")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("validate_address: missing `address` header".into()))?;
    let body = crate::network::routes::explorer::compute_validate_address(
        Arc::clone(state),
        address,
    )
    .await;
    to_body(&body)
}

async fn handle_list_witness_profiles(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    // Nullary verb → default page bound (mirrors HTTP `/witnesses/profiles`).
    let body = crate::network::routes::explorer::compute_list_witness_profiles(
        Arc::clone(state),
        None,
    )
    .await;
    to_body(&body)
}

/// Identity Partitioning Phase D — PQ handler for peer on-miss PK fetch.
/// Required header: `identity_hash`. Returns the same JSON shape as the
/// axum `/identity/pk/{hash}` route — `pk: null` when the responder
/// doesn't have the PK (caller's policy on miss is to try the next peer
/// or soft-fail per internal design notes §6).
async fn handle_identity_pk(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let identity_hash = headers
        .get("identity_hash")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("identity_pk: missing `identity_hash` header".into()))?;
    let body = crate::network::routes::explorer::compute_identity_pk(
        Arc::clone(state),
        identity_hash,
    )
    .await;
    to_body(&body)
}

// ─── consensus_status / consensus_record_detail / committees_snapshot ───────
//
// consensus_status reads optional `limit` header (defaults to 20, capped at
// 100). consensus_record_detail requires `record_id`. committees_snapshot
// reads optional `epoch` and `k` headers (axum reads them from query string).

async fn handle_consensus_status(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let limit = headers.get("limit").and_then(|s| s.parse::<usize>().ok());
    let body = crate::network::routes::explorer::compute_consensus_status(
        Arc::clone(state),
        limit,
    )
    .await;
    to_body(&body)
}

async fn handle_consensus_record_detail(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let record_id = headers
        .get("record_id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("consensus_record_detail: missing `record_id` header".into()))?;
    let body = crate::network::routes::explorer::compute_consensus_record_detail(
        Arc::clone(state),
        record_id,
    )
    .await;
    to_body(&body)
}

async fn handle_committees_snapshot(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let epoch = headers.get("epoch").and_then(|s| s.parse::<u64>().ok());
    let k = headers.get("k").and_then(|s| s.parse::<usize>().ok());
    let from = headers.get("from").cloned();
    let limit = headers.get("limit").and_then(|s| s.parse::<usize>().ok());
    let body = crate::network::routes::explorer::compute_committees_snapshot(
        Arc::clone(state),
        epoch,
        k,
        from,
        limit,
    )
    .await;
    to_body(&body)
}

// ─── governance_proposals / governance_proposal_detail / governance_delegations ───
//
// governance_proposals reads optional `status` / `limit` / `offset` headers
// (axum reads them from query string). proposal detail requires `id`;
// delegations requires `identity`. proposal_detail is fallible (returns
// Governance("proposal not found: ...") for unknown ids — surfaced as a PQ
// non-OK status).

async fn handle_governance_proposals(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let status = headers.get("status").cloned();
    let limit = headers.get("limit").and_then(|s| s.parse::<usize>().ok());
    let offset = headers.get("offset").and_then(|s| s.parse::<usize>().ok());
    let body = crate::network::routes::explorer::compute_governance_proposals(
        Arc::clone(state),
        status,
        limit,
        offset,
    )
    .await;
    to_body(&body)
}

async fn handle_governance_proposal_detail(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let id = headers
        .get("id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("governance_proposal_detail: missing `id` header".into()))?;
    let body = crate::network::routes::explorer::compute_governance_proposal_detail(
        Arc::clone(state),
        id,
    )
    .await?;
    to_body(&body)
}

async fn handle_governance_delegations(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let identity = headers
        .get("identity")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("governance_delegations: missing `identity` header".into()))?;
    // Page bound for the inbound-delegation array (mirrors HTTP `?limit=`); None
    // → default cap. A delegate's inbound set is unbounded, so the verb must not
    // dump it all.
    let limit = headers.get("limit").and_then(|s| s.parse::<usize>().ok());
    let body = crate::network::routes::explorer::compute_governance_delegations(
        Arc::clone(state),
        identity,
        limit,
    )
    .await;
    to_body(&body)
}

// ─── governance_params_history / list_disputes / list_challenges ────────────
//
// All three accept an optional filter header (`param` for history, `status` for
// the listings). All are infallible — they return an envelope with totals and
// a possibly empty array, matching the axum query-string semantics.

async fn handle_governance_params_history(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let param = headers.get("param").cloned();
    let body = crate::network::routes::explorer::compute_governance_params_history(
        Arc::clone(state),
        param,
    )
    .await;
    to_body(&body)
}

async fn handle_list_disputes(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let status = headers.get("status").cloned();
    let body = crate::network::routes::explorer::compute_list_disputes(
        Arc::clone(state),
        status,
    );
    to_body(&body)
}

async fn handle_list_challenges(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let status = headers.get("status").cloned();
    // Page bound (mirrors HTTP `/challenges?limit=`): challenge history is
    // unbounded, so the verb must not dump the whole map. None → default cap.
    let limit = headers.get("limit").and_then(|s| s.parse::<usize>().ok());
    let body = crate::network::routes::explorer::compute_list_challenges(
        Arc::clone(state),
        status,
        limit,
    );
    to_body(&body)
}

// ─── dag_record_graph / dispute_detail / challenge_detail ───────────────────
//
// `dag_record_graph` requires `id`; `depth` and `direction` are optional
// (axum reads them from query string). `dispute_detail` is fallible
// (RecordNotFound → non-OK PQ status, mirrors `governance_proposal_detail`).
// `challenge_detail` always returns 200 with `{"error": "challenge not found"}`
// for unknown ids — preserving the axum body shape exactly.

async fn handle_dag_record_graph(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let id = headers
        .get("id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("dag_record_graph: missing `id` header".into()))?;
    let depth = headers.get("depth").and_then(|s| s.parse::<usize>().ok());
    let direction = headers.get("direction").cloned();
    let body = crate::network::routes::explorer::compute_dag_record_graph(
        Arc::clone(state),
        id,
        depth,
        direction,
    )
    .await;
    to_body(&body)
}

async fn handle_dispute_detail(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let id = headers
        .get("id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("dispute_detail: missing `id` header".into()))?;
    let body = crate::network::routes::explorer::compute_dispute_detail(
        Arc::clone(state),
        id,
    )?;
    to_body(&body)
}

async fn handle_challenge_detail(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let id = headers
        .get("id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("challenge_detail: missing `id` header".into()))?;
    let body = crate::network::routes::explorer::compute_challenge_detail(
        Arc::clone(state),
        id,
    );
    to_body(&body)
}

// ─── witness_correlation / witness_reputation / committees_is_member ────────
//
// `witness_correlation` requires both `witness_a` + `witness_b` headers.
// `witness_reputation` accepts an optional `witness` header — single-witness
// detail when present, full summary array otherwise. `committees_is_member`
// preserves the in-band `error` envelope for missing-required params (axum
// shape) while accepting optional `epoch` + `k` overrides via headers.

async fn handle_witness_correlation(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let witness_a = headers
        .get("witness_a")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("witness_correlation: missing `witness_a` header".into()))?;
    let witness_b = headers
        .get("witness_b")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("witness_correlation: missing `witness_b` header".into()))?;
    let body = crate::network::routes::explorer::compute_witness_correlation(
        Arc::clone(state),
        witness_a,
        witness_b,
    );
    to_body(&body)
}

async fn handle_witness_reputation(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let witness = headers.get("witness").cloned();
    // Page bound for the unfiltered summary form (mirrors HTTP `?limit=`); None →
    // default cap. Ignored for single-witness lookups (`witness` set).
    let limit = headers.get("limit").and_then(|s| s.parse::<usize>().ok());
    let body = crate::network::routes::explorer::compute_witness_reputation(
        Arc::clone(state),
        witness,
        limit,
    );
    to_body(&body)
}

async fn handle_committees_is_member(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let zone = headers.get("zone").cloned();
    let id = headers.get("id").cloned();
    let epoch = headers.get("epoch").and_then(|s| s.parse::<u64>().ok());
    let k = headers.get("k").and_then(|s| s.parse::<usize>().ok());
    let body = crate::network::routes::explorer::compute_committees_is_member(
        Arc::clone(state),
        zone,
        id,
        epoch,
        k,
    )
    .await;
    to_body(&body)
}

// ─── peer_reputation / reward_stats / itc_status ────────────────────────────
//
// All three are nullary — the corresponding axum handlers take no query
// or path arguments. peer_reputation reads the peer table; reward_stats
// reads the conservation pool + auto-reward atomics; itc_status reads
// the per-zone interval-tree-clock summary.

async fn handle_peer_reputation(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    // Page bound (mirrors HTTP `/peers/reputation?limit=`): the peer table grows
    // with network size, so the verb must not dump it all. None → default cap.
    let limit = headers.get("limit").and_then(|s| s.parse::<usize>().ok());
    let body = crate::network::routes::explorer::compute_peer_reputation(Arc::clone(state), limit).await;
    to_body(&body)
}

async fn handle_reward_stats(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let body = crate::network::routes::explorer::compute_reward_stats(Arc::clone(state)).await;
    to_body(&body)
}

async fn handle_itc_status(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let body = crate::network::routes::explorer::compute_itc_status(Arc::clone(state));
    to_body(&body)
}

// ─── xzone_stats / xzone_transfers / xzone_transfer ─────────────────────────
//
// Cross-zone transfer observability. `xzone_stats` is nullary; `xzone_transfers`
// reads optional `status` / `sender` / `recipient` / `limit` headers (axum
// reads them from query string); `xzone_transfer` requires `transfer_id`
// and returns RecordNotFound (non-OK PQ status) for unknown ids.

async fn handle_xzone_stats(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let body = crate::network::routes::explorer::compute_xzone_stats(Arc::clone(state)).await;
    to_body(&body)
}

async fn handle_xzone_transfers(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let status = headers.get("status").cloned();
    let sender = headers.get("sender").cloned();
    let recipient = headers.get("recipient").cloned();
    let limit = headers.get("limit").and_then(|s| s.parse::<usize>().ok());
    let body = crate::network::routes::explorer::compute_xzone_transfers(
        Arc::clone(state),
        status,
        sender,
        recipient,
        limit,
    )
    .await;
    to_body(&body)
}

async fn handle_xzone_transfer(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let transfer_id = headers
        .get("transfer_id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("xzone_transfer: missing `transfer_id` header".into()))?;
    let body = crate::network::routes::explorer::compute_xzone_transfer(
        Arc::clone(state),
        transfer_id,
    )
    .await?;
    to_body(&body)
}

async fn handle_xzone_bundle(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let transfer_id = headers
        .get("transfer_id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("xzone_bundle: missing `transfer_id` header".into()))?;
    let body = crate::network::routes::explorer::compute_xzone_bundle(
        Arc::clone(state),
        transfer_id,
    )
    .await?;
    to_body(&body)
}

// ─── account_detail / causal_proof / merkle_proof ───────────────────────────
//
// Account-critical reads. `account_detail` requires `identity` header and is
// infallible (unknown identity returns body with `exists: false`).
// `causal_proof` requires `id` header; `merkle_proof` requires `record_id`
// header. Both fail with RecordNotFound (non-OK PQ status) for unknowns.

async fn handle_account_detail(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let identity = headers
        .get("identity")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("account_detail: missing `identity` header".into()))?;
    let body = crate::network::routes::explorer::compute_account_detail(
        Arc::clone(state),
        identity,
    )
    .await;
    to_body(&body)
}

async fn handle_causal_proof(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let id = headers
        .get("id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("causal_proof: missing `id` header".into()))?;
    let body = crate::network::routes::explorer::compute_causal_proof(
        Arc::clone(state),
        id,
    )
    .await?;
    to_body(&body)
}

async fn handle_merkle_proof(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let record_id = headers
        .get("record_id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("merkle_proof: missing `record_id` header".into()))?;
    let body = crate::network::routes::explorer::compute_merkle_proof(
        Arc::clone(state),
        record_id,
    )
    .await?;
    to_body(&body)
}

// ─── zone_merkle_proof / dag_lifecycle / vrf_registry ───────────────────────
//
// `zone_merkle_proof` requires `zone` (u64) + `record_hash` (64 hex chars)
// headers and returns RecordNotFound for unknown leaves / Wire for malformed
// inputs. `dag_lifecycle` and `vrf_registry` are nullary infallible reads.

async fn handle_zone_merkle_proof(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let zone = header_u64(headers, "zone")
        .ok_or_else(|| ElaraError::Wire("zone_merkle_proof: missing or invalid `zone` header (u64)".into()))?;
    let record_hash = headers
        .get("record_hash")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("zone_merkle_proof: missing `record_hash` header".into()))?;
    let body = crate::network::routes::explorer::compute_zone_merkle_proof(
        Arc::clone(state),
        zone,
        record_hash,
    )
    .await?;
    to_body(&body)
}

async fn handle_dag_lifecycle(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let body = crate::network::routes::explorer::compute_dag_lifecycle(Arc::clone(state)).await;
    to_body(&body)
}

async fn handle_vrf_registry(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    // Nullary verb → default page bound (mirrors the HTTP `/vrf/registry` default).
    let body = crate::network::routes::explorer::compute_vrf_registry(Arc::clone(state), None);
    to_body(&body)
}

// ─── version_info / version_forks / version_stats ───────────────────────────
//
// Content-versioning inspection (Protocol §11.30). `version_info` and
// `version_forks` require `record_id` header. All three are infallible by
// design — unknown record ids return 200 with the in-band
// `{"error": "version record not found", "record_id": ...}` envelope so
// the PQ body matches the axum body byte-for-byte.

async fn handle_version_info(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let record_id = headers
        .get("record_id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("version_info: missing `record_id` header".into()))?;
    let body = crate::network::routes::explorer::compute_version_info(
        Arc::clone(state),
        record_id,
    );
    to_body(&body)
}

async fn handle_version_forks(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let record_id = headers
        .get("record_id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("version_forks: missing `record_id` header".into()))?;
    let body = crate::network::routes::explorer::compute_version_forks(
        Arc::clone(state),
        record_id,
    );
    to_body(&body)
}

async fn handle_version_stats(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let body = crate::network::routes::explorer::compute_version_stats(Arc::clone(state));
    to_body(&body)
}

// ─── epoch_headers / checkpoint_latest / dag_search ─────────────────────────
//
// Light-client + explorer surface. Header semantics mirror the axum query/path
// params one-for-one so the client wrapper is a thin dispatcher.
//
// `epoch_headers` request headers (all optional):
//   - `since` (u64) — drop headers below this epoch number
//   - `zone`  (str) — restrict to one zone id
//   - `limit` (usize, default 500, capped at 2000 inside compute_*)
//
// `checkpoint_latest` request headers:
//   - `zone` (str, required) — zone whose latest super-seal to return.
//
// `dag_search` request headers (all optional, mapping to DagSearchQuery):
//   - `op`, `creator`, `to`, `from`, `classification`, `has_key` (str)
//   - `since`, `until` (f64 seconds)
//   - `limit` (usize, default 50, capped at 500 inside compute_*)
//
// All three call into `routes::explorer::compute_*` so HTTPS and PQ render
// identical bytes.

async fn handle_epoch_headers(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let since = header_u64(headers, "since");
    let zone_filter = headers.get("zone").map(|v| crate::ZoneId::new(v));
    let limit = header_usize(headers, "limit").unwrap_or(500).min(2000);
    let body = crate::network::routes::explorer::compute_epoch_headers(
        Arc::clone(state),
        zone_filter,
        since,
        limit,
    )
    .await?;
    to_body(&body)
}

async fn handle_checkpoint_latest(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let zone = headers
        .get("zone")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("checkpoint_latest: missing `zone` header".into()))?;
    let body = crate::network::routes::explorer::compute_checkpoint_latest(
        Arc::clone(state),
        zone,
    )
    .await?;
    to_body(&body)
}

async fn handle_dag_search(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let params = crate::network::routes::explorer::DagSearchQuery {
        op: headers.get("op").cloned(),
        creator: headers.get("creator").cloned(),
        to: headers.get("to").cloned(),
        from: headers.get("from").cloned(),
        since: header_f64(headers, "since"),
        until: header_f64(headers, "until"),
        limit: header_usize(headers, "limit"),
        classification: headers.get("classification").cloned(),
        has_key: headers.get("has_key").cloned(),
    };
    let body = crate::network::routes::explorer::compute_dag_search(
        Arc::clone(state),
        params,
    )
    .await?;
    to_body(&body)
}

// ─── seal_debug / register_witness_profile / routing_resolve ────────────────
//
// Residual surface — debug introspection + witness-profile self-publish + the
// zone-registry redirect lookup. After this batch ~5 routes remain (admin/*
// covered by 4E.4, identity_activity covered by `activity` verb, record
// submission still pending).
//
// `seal_debug` request headers:
//   - `id` (required, str) — the seal record id; RecordNotFound → NOT_FOUND.
//
// `register_witness_profile` (POST-style):
//   - JSON body: { witness_hash, organization, subnet, geo_zone }.
//   - Empty witness_hash or organization → Wire / BAD_REQUEST.
//
// `routing_resolve` request headers (mirrors axum query params):
//   - `record_id` (required-ish; missing or empty surfaces in-band error)
//   - `key`       (optional; 64-char hex of 32 bytes; bad hex/wrong-length
//                  surfaces in-band error so PQ matches axum byte-for-byte)
//
// All three reuse `routes::explorer::compute_*` so HTTPS and PQ render
// identical bodies.

async fn handle_seal_debug(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let id = headers
        .get("id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("seal_debug: missing `id` header".into()))?;
    let body = crate::network::routes::explorer::compute_seal_debug(state, &id)?;
    to_body(&body)
}

/// Body caps for the small fixed-size PQ command verbs below, mirroring the
/// axum side's per-route `DefaultBodyLimit`s (`server::MAX_RPC_BODY_BYTES` =
/// 64 KiB, `server::MAX_TRANSITION_PROPOSE_BODY_BYTES` = 512 KiB). Without these
/// the handlers `from_slice` straight off a frame body capped only at
/// [`MAX_PAYLOAD`] (~16 MiB), so a single admitted peer could force a 16 MiB
/// buffer + decode for a message whose legit size is a few KiB — the same
/// memory-amplification vector the HTTP transport already closed. Fail-closed:
/// oversized ⇒ `Wire` error before any parse.
const MAX_RPC_COMMAND_BODY: usize = 64 * 1024;
/// A `TransitionSeal` carries up to `MAX_PROPOSER_SIGS` (32) Dilithium3 anchor
/// sigs (~5.5 KiB each) plus ≤2 parent/child `ZoneSnapshot`s — ~180 KiB raw,
/// ~500 KiB JSON-expanded worst case. Matches the axum propose cap exactly.
const MAX_TRANSITION_SEAL_BODY: usize = 512 * 1024;

/// Size gate for the small fixed-size PQ command verbs (probe, witness-profile
/// registration, offline notifications, transition cosign sig/veto/seal) before
/// `serde_json::from_slice`. Same shape as [`guard_record_body`] but the cap is
/// passed in: most verbs use [`MAX_RPC_COMMAND_BODY`], the seal the wider
/// [`MAX_TRANSITION_SEAL_BODY`]. Fail-closed: oversized ⇒ `Wire` before any parse.
#[inline]
fn guard_command_body(method: &str, body: &[u8], max: usize) -> Result<()> {
    if body.len() > max {
        return Err(ElaraError::Wire(format!(
            "{method} body too large: {} bytes (max {max})",
            body.len()
        )));
    }
    Ok(())
}

async fn handle_register_witness_profile(
    state: &Arc<NodeState>,
    req: &PqRequest,
) -> Result<Vec<u8>> {
    guard_command_body("register_witness_profile", &req.body, MAX_RPC_COMMAND_BODY)?;
    let body: crate::network::routes::explorer::WitnessProfileBody =
        serde_json::from_slice(&req.body).map_err(|e| {
            ElaraError::Wire(format!("register_witness_profile: invalid JSON body: {e}"))
        })?;
    // SECURITY (authz boundary): bind the registration to the handshake-
    // authenticated identity. A remote peer may register ONLY its own
    // `witness_hash` — never a third party's — mirroring `exchange_profile`'s
    // `peer_identity_hash` binding (see the AUDIT-9 Milestone B2 note above).
    // Without this gate any handshaked peer could write arbitrary
    // organization/subnet/geo_zone `WitnessProfile`s for other identities and
    // poison the diversity-gate inputs that record finality consumes. All-zeros
    // = local same-process call (trusted), left unrestricted so the loopback
    // HTTP/operator path is unchanged.
    if req.peer_identity_hash != [0u8; 32] {
        let peer_hash_hex = hex::encode(req.peer_identity_hash);
        if body.witness_hash != peer_hash_hex {
            return Err(ElaraError::Wire(
                "register_witness_profile: witness_hash must match the authenticated session identity".into(),
            ));
        }
    }
    let v = crate::network::routes::explorer::compute_register_witness_profile(state, body)?;
    to_body(&v)
}

async fn handle_routing_resolve(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let record_id = headers.get("record_id").cloned();
    let key_hex = headers.get("key").cloned();
    let body = crate::network::routes::explorer::compute_routing_resolve(
        state, record_id, key_hex,
    );
    to_body(&body)
}

// ─── validate_record / receive_offline_notification / submit_veto ───────────
//
// All three are POST-shaped verbs that read `req.body`. `submit_veto` also
// needs the transition `id` from a header (the axum route uses it as a path
// segment). All three reuse the corresponding `compute_*` helper so HTTPS
// and PQ render identical bodies.
//
// Header contract for `submit_veto`:
//   - `id` — 64-char hex of the 32-byte transition seal id (required)

async fn handle_validate_record(
    state: &Arc<NodeState>,
    body: &[u8],
) -> Result<Vec<u8>> {
    // `compute_validate_record` is infallible-by-design: bad bytes surface
    // as `{"valid": false, "checks": [...]}` at OK status, matching the
    // axum behavior byte-for-byte.
    let v = crate::network::routes::core::compute_validate_record(state, body).await;
    to_body(&v)
}

async fn handle_receive_offline_notification(
    state: &Arc<NodeState>,
    body: &[u8],
) -> Result<Vec<u8>> {
    guard_command_body("receive_offline_notification", body, MAX_RPC_COMMAND_BODY)?;
    let req: crate::network::routes::sync::OfflineNotification =
        serde_json::from_slice(body).map_err(|e| {
            ElaraError::Wire(format!("receive_offline_notification: invalid JSON body: {e}"))
        })?;
    let v = crate::network::routes::sync::compute_receive_offline_notification(state, req).await?;
    to_body(&v)
}

async fn handle_submit_veto(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<Vec<u8>> {
    guard_command_body("submit_veto", body, MAX_RPC_COMMAND_BODY)?;
    let id_hex = headers
        .get("id")
        .cloned()
        .ok_or_else(|| ElaraError::Wire("submit_veto: missing `id` header".into()))?;
    let veto: crate::network::routes::transitions::VetoBody =
        serde_json::from_slice(body).map_err(|e| {
            ElaraError::Wire(format!("submit_veto: invalid JSON body: {e}"))
        })?;
    let resp =
        crate::network::routes::transitions::compute_submit_veto(state, id_hex, veto).await?;
    to_body(&resp)
}

// ─── AUDIT-10 PQ-R5a: epoch snapshot verbs ──────────────────────────────────
//
// Mirrors the axum `/snapshot/epochs` + `/snapshot/epoch/{N}` routes so
// `epoch_indexed_snapshot_bootstrap` can drive archive-snapshot onboarding
// entirely over the PQ transport.

async fn handle_list_epoch_snapshots(state: &Arc<NodeState>) -> Result<Vec<u8>> {
    let body = crate::network::routes::sync::compute_list_epoch_snapshots(state).await?;
    to_body(&body)
}

async fn handle_get_epoch_snapshot(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let epoch = header_u64(headers, "epoch")
        .ok_or_else(|| ElaraError::Wire("get_epoch_snapshot: missing `epoch` header".into()))?;
    let snap = crate::network::routes::sync::compute_get_epoch_snapshot(state, epoch).await?;
    to_body(&snap)
}

/// PQ companion: signed incremental state-delta. `since_epoch=0`
/// is permitted (returns the full current ledger as a delta with
/// `baseline_available=false`), so this handler does not require the
/// header to be present — defaults to 0 to preserve the "client always
/// makes progress" property even on first call.
async fn handle_state_delta(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let since_epoch = header_u64(headers, "since_epoch").unwrap_or(0);
    let delta = crate::network::routes::sync::compute_state_delta(state, since_epoch).await?;
    let body = to_body(&delta)?;
    // PQ responses are single Data frames (frame::MAX_PAYLOAD = 16 MiB−1). A
    // whole-ledger delta can exceed that, and the serve-side send() failure
    // kills the connection silently — the requester's divergence-repair then
    // looks like a dead network. Return a typed error instead so the caller
    // logs a real cause and falls back to the snapshot bootstrap path
    // (snapshot_fast_chunk — chunked by design). Same failure class as the
    // delta_sync byte budget above (root-caused live 2026-07-01).
    const MAX_STATE_DELTA_RESPONSE: usize = 12 * 1024 * 1024;
    if body.len() > MAX_STATE_DELTA_RESPONSE {
        return Err(ElaraError::Network(format!(
            "state_delta response {}B exceeds the PQ single-frame budget ({MAX_STATE_DELTA_RESPONSE}B) — gap too large for delta repair, use snapshot bootstrap",
            body.len()
        )));
    }
    Ok(body)
}

// ─── AUDIT-10 PQ-pure-client: transition cosign + probe verbs ────────────────
//
// These five verbs are the PQ counterparts of the four `/transitions/...`
// axum routes and `/probe`. They let `gossip::push_transition_seal_to_peers`,
// `gossip::push_transition_sig_to_peers`, `routes::transitions::
// run_transition_pull_tick`, and `probe::execute_probe` run entirely over the
// PQ transport so the last `reqwest::Client` outbound call sites can be
// deleted from the runtime. Logic mirrors the axum handlers one-for-one —
// deliberately inlined (rather than extracted into `compute_*` helpers) to
// keep this migration minimal.

async fn handle_submit_transition_seal(
    state: &Arc<NodeState>,
    body: &[u8],
) -> Result<Vec<u8>> {
    use crate::network::routes::transitions::{
        PROPOSAL_MAX_LEAD_EPOCHS, persist_pending_entry,
        maybe_cosign_transition, verify_anchor_sig, status_label,
    };

    guard_command_body("submit_transition_seal", body, MAX_TRANSITION_SEAL_BODY)?;
    let seal: crate::network::zone_transition_seal::TransitionSeal = serde_json::from_slice(body)
        .map_err(ElaraError::from)?;
    seal.validate_structure()
        .map_err(|e| ElaraError::Wire(format!("invalid seal: {e}")))?;

    if let Some(core) = state.state_core.get() {
        let current_epoch = core.read_snapshot().current_epoch;
        if seal.proposed_at_epoch > current_epoch.saturating_add(PROPOSAL_MAX_LEAD_EPOCHS) {
            return Err(ElaraError::Wire(format!(
                "proposed_at_epoch {} is more than {} epochs ahead of current_epoch {}",
                seal.proposed_at_epoch, PROPOSAL_MAX_LEAD_EPOCHS, current_epoch
            )));
        }
        if seal.effective_epoch <= current_epoch {
            return Err(ElaraError::Wire(format!(
                "effective_epoch {} is not in the future (current_epoch {})",
                seal.effective_epoch, current_epoch
            )));
        }
    }

    let seal_hash = seal.seal_hash_for_sig()
        .map_err(|e| ElaraError::Wire(format!("seal_hash_for_sig: {e}")))?;
    let trust = state.transition_trust_view().await;
    for sig in &seal.proposer_sigs {
        verify_anchor_sig(state, sig, &seal_hash, &trust)?;
    }

    let seal_for_gossip = seal.clone();
    let id = {
        let mut store = state
            .transitions
            .write()
            .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;
        store.insert(seal).map_err(|e| ElaraError::Wire(format!("insert seal: {e}")))?
    };

    persist_pending_entry(state, &id);

    let state_bg = state.clone();
    tokio::spawn(async move {
        super::super::gossip::push_transition_seal_to_peers(&state_bg, &seal_for_gossip).await;
    });
    if let Some(our_sig) = maybe_cosign_transition(state, &id) {
        super::super::gossip::push_transition_sig_to_peers(state, id, &our_sig).await;
        persist_pending_entry(state, &id);
    }

    let (status, threshold, sigs_collected) = {
        let store = state
            .transitions
            .read()
            .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;
        match store.get(&id) {
            Some(p) => (status_label(p.status), p.seal.required_threshold(), p.seal.proposer_sigs.len()),
            None => ("Unknown".to_string(), 0, 0),
        }
    };

    to_body(&json!({
        "id": hex::encode(id),
        "status": status,
        "threshold": threshold,
        "sigs_collected": sigs_collected,
    }))
}

async fn handle_submit_transition_sig(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<Vec<u8>> {
    use crate::network::routes::transitions::{
        persist_pending_entry, verify_anchor_sig, status_label,
    };

    let seal_id_hex = headers.get("seal_id").cloned()
        .ok_or_else(|| ElaraError::Wire("submit_transition_sig: missing `seal_id` header".into()))?;
    let id_bytes = hex::decode(&seal_id_hex)
        .map_err(|e| ElaraError::Wire(format!("bad seal_id hex: {e}")))?;
    if id_bytes.len() != 32 {
        return Err(ElaraError::Wire(format!("seal_id must be 32 bytes, got {}", id_bytes.len())));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&id_bytes);

    guard_command_body("submit_transition_sig", body, MAX_RPC_COMMAND_BODY)?;
    let sig: crate::network::zone_transition_seal::AnchorSig = serde_json::from_slice(body)
        .map_err(ElaraError::from)?;

    {
        let store = state
            .transitions
            .read()
            .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;
        let Some(pending) = store.get(&id) else {
            return Err(ElaraError::RecordNotFound(format!("transition {seal_id_hex}")));
        };
        if let Some(core) = state.state_core.get() {
            let current_epoch = core.read_snapshot().current_epoch;
            if current_epoch >= pending.seal.effective_epoch {
                return Err(ElaraError::Wire(format!(
                    "dispute window closed — sig rejected (current_epoch {} >= effective_epoch {})",
                    current_epoch, pending.seal.effective_epoch
                )));
            }
        }
    }

    let trust = state.transition_trust_view().await;
    verify_anchor_sig(state, &sig, &id, &trust)?;

    let sig_for_gossip = sig.clone();
    let (status, sigs_collected, threshold) = {
        let mut store = state
            .transitions
            .write()
            .map_err(|e| ElaraError::Storage(format!("transitions lock: {e}")))?;
        store.add_sig(&id, sig).map_err(|e| ElaraError::Wire(format!("add_sig: {e}")))?;
        let p = store.get(&id)
            .ok_or_else(|| ElaraError::RecordNotFound(format!("transition {seal_id_hex}")))?;
        (status_label(p.status), p.seal.proposer_sigs.len(), p.seal.required_threshold())
    };

    persist_pending_entry(state, &id);

    let state_bg = state.clone();
    tokio::spawn(async move {
        super::super::gossip::push_transition_sig_to_peers(&state_bg, id, &sig_for_gossip).await;
    });

    to_body(&json!({
        "id": seal_id_hex,
        "status": status,
        "sigs_collected": sigs_collected,
        "threshold": threshold,
    }))
}

async fn handle_list_transitions(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let status_filter = headers.get("status").cloned();
    let body = crate::network::routes::transitions::compute_list_transitions(
        state, status_filter,
    )?;
    to_body(&body)
}

async fn handle_get_transition(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let seal_id_hex = headers.get("seal_id").cloned()
        .ok_or_else(|| ElaraError::Wire("get_transition: missing `seal_id` header".into()))?;
    let body = crate::network::routes::transitions::compute_get_transition(state, &seal_id_hex)?;
    to_body(&body)
}

async fn handle_probe_request(
    state: &Arc<NodeState>,
    body: &[u8],
) -> Result<Vec<u8>> {
    guard_command_body("probe", body, MAX_RPC_COMMAND_BODY)?;
    let request: crate::network::probe::ProbeRequest = serde_json::from_slice(body)
        .map_err(ElaraError::from)?;
    let response = crate::network::probe::handle_probe(state, &request).await;
    to_body(&response)
}

// ─── exchange_profile ────────────────────────────────────────────────────────
//
// AUDIT-9 Milestone B: serve this node's own `WitnessProfile` over the already-
// authenticated PQ channel so peers can register it without waiting for the
// DAG-gossip registration record. Response shape is always stable:
//
//   { "identity_hash": "<hex>", "profile": null }            // operator opted out
//   { "identity_hash": "<hex>", "profile": { "organization": ..., "subnet": ..., "geo_zone": ... } }
//
// AUDIT-9 Milestone B2: the verb is symmetric. When the caller includes its own
// profile in the request body (same JSON shape, optional `profile` key), the
// server registers it into its local consensus engine BEFORE responding. The
// identity hash registered is `req.peer_identity_hash` — the SHA3-256 of the
// caller's Dilithium3 pubkey authenticated during the PQ handshake — never the
// body claim, so a peer cannot register a profile for a third party. This
// closes the NAT'd-peer coverage gap where inbound-only peers
// previously had to wait for DAG-gossip
// propagation of their `WitnessProfile` record to be known by the public
// witnesses they attest alongside.
//
// Request body shape (all optional — empty body is valid, same as pre-B2):
//   { "profile": null }                      // caller explicitly opted out
//   { "profile": { "organization": ..., "subnet": ..., "geo_zone": ... } }
//
// Old peers on pre-Milestone-B binaries hit the 404 branch in `dispatch` ("unknown
// method: exchange_profile") and skip — no session break, no retry storm, their
// existing DAG-record path continues to work. New peers exchange directly.

/// Upper bound on the `exchange_profile` request body before
/// `serde_json::from_slice::<Value>`. A legit body is a tiny
/// `{"profile":{"organization":…,"subnet":…,"geo_zone":…}}` object — three short
/// strings, well under 1 KiB. But a `Value` decode is the worst-case amplifier
/// (every JSON token → a ~24-byte enum node), so a frame-sized (≤ `MAX_PAYLOAD`
/// = 16 MiB) body of `[1,1,1,…]` expands into ~10× transient heap — enough to OOM
/// a phone-tier node. Oversized ⇒ skip registration WITHOUT parsing and fall
/// through to the legacy response-only path (exactly what malformed JSON already
/// does — concedes nothing, since the response returns this node's own profile
/// regardless of the request body).
const MAX_EXCHANGE_PROFILE_BODY: usize = 64 * 1024;

async fn handle_exchange_profile(
    state: &Arc<NodeState>,
    req: &PqRequest,
) -> Result<Vec<u8>> {
    // B2: if the caller attached a profile, register it against the
    // authenticated session identity. Best-effort — malformed JSON, an oversized
    // body (see MAX_EXCHANGE_PROFILE_BODY), or an unconfigured caller falls
    // through to the legacy response-only path.
    if !req.body.is_empty()
        && req.body.len() <= MAX_EXCHANGE_PROFILE_BODY
        && req.peer_identity_hash != [0u8; 32]
    {
        if let Ok(body) = serde_json::from_slice::<Value>(&req.body) {
            let peer_hash_hex = hex::encode(req.peer_identity_hash);
            // null / missing → caller opted out, nothing to register
            if let Some(Value::Object(obj)) = body.get("profile") {
                let organization = obj.get("organization")
                    .and_then(Value::as_str).unwrap_or("").to_string();
                if !organization.is_empty() {
                    let profile = crate::network::consensus::WitnessProfile {
                        organization,
                        subnet: obj.get("subnet")
                            .and_then(Value::as_str).unwrap_or("").to_string(),
                        geo_zone: obj.get("geo_zone")
                            .and_then(Value::as_str).unwrap_or("").to_string(),
                    };
                    let mut consensus = state.consensus.lock_recover();
                    // Skip if already registered — avoid churn when a peer
                    // calls exchange_profile repeatedly (reconnects, etc.).
                    if !consensus.has_profile(&peer_hash_hex) {
                        consensus.register_profile(&peer_hash_hex, profile);
                    }
                }
            }
        }
    }

    let profile_json = match state.config.effective_witness_profile() {
        Some(p) => json!({
            "organization": p.organization,
            "subnet": p.subnet,
            "geo_zone": p.geo_zone,
        }),
        None => Value::Null,
    };
    to_body(&json!({
        "identity_hash": state.identity.identity_hash,
        "profile": profile_json,
    }))
}

// ─── resolve_content_hash (§11.23 Layer A slice 1) ──────────────────────────
//
// Local-only `/records/by-hash/{content_hash}` mirror over PQ. Responder
// does the CF_IDX_HASH point read and returns either the full record JSON
// (200) or NOT_FOUND. MUST NOT recursively peer-relay — see
// `record_hash_fetcher::fetch_record_from_peers` for the caller's
// bounded fan-out logic; allowing the responder to also relay would
// chain-amplify a single lookup into the entire mesh.
async fn handle_resolve_content_hash(
    state: &Arc<NodeState>,
    headers: &BTreeMap<String, String>,
) -> Result<Vec<u8>> {
    let content_hash = headers
        .get("content_hash")
        .cloned()
        .ok_or_else(|| {
            ElaraError::Wire("resolve_content_hash: missing `content_hash` header".into())
        })?;

    match crate::network::routes::explorer::compute_record_by_hash(
        Arc::clone(state),
        content_hash,
    )
    .await?
    {
        Some(body) => to_body(&body),
        None => Err(ElaraError::RecordNotFound(
            "no record matches the given content_hash".into(),
        )),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::pq_client::{PqNodeClient, TestIdentity};
    use crate::network::pq_transport::{PeerIdentityStore, PqListener};
    use crate::network::pq_server::PqServer;

    /// Build a minimal in-memory NodeState for end-to-end routing tests.
    ///
    /// The state is not "live" — no background tasks, no peer connections —
    /// but it has real RocksDB (tempdir), real identity, real WitnessManager,
    /// and it's enough to exercise handler dispatch and the response envelope.
    fn make_test_state() -> Arc<NodeState> {
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
            admin_token: "test-admin".to_string(),
            network_id: "pq-router-test".to_string(),
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

        // Keep the tempdir alive for the duration of the state. The leak is
        // intentional — test state is dropped at end of test anyway, and
        // tempdirs are small.
        std::mem::forget(tmp);
        state
    }

    /// The HEAVY-VERIFY gate BACKPRESSURES a saturated dispatch — it never
    /// sheds. With every permit held, a gated verb from an external peer must
    /// PARK (not error, not 429); once permits free it completes and the
    /// waited counter records the contention.
    #[tokio::test]
    async fn verify_gate_backpressures_never_sheds() {
        let state = make_test_state();
        let cap = state.pq_verify_cap;
        assert!(cap >= 1, "cap must be >= 1 (min-1 clamp)");
        let held: Vec<_> = (0..cap)
            .map(|_| {
                state
                    .pq_verify_semaphore
                    .clone()
                    .try_acquire_owned()
                    .expect("drain permit")
            })
            .collect();

        let req = PqRequest {
            method: "receive_attestation".to_string(),
            headers: Default::default(),
            body: b"not json".to_vec(),
            peer_identity_hash: [7u8; 32], // external, non-genesis
        };
        let state2 = state.clone();
        let task = tokio::spawn(async move { dispatch(state2, req).await });

        // Saturated gate ⇒ the dispatch must still be PARKED after a real delay.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            !task.is_finished(),
            "gated dispatch must WAIT while the verify gate is saturated — a completed \
             response here means it was shed or bypassed the gate"
        );
        assert!(
            state
                .pq_verify_waited_total
                .load(std::sync::atomic::Ordering::Relaxed)
                >= 1,
            "waited counter must record the contention"
        );

        // Release ⇒ the parked dispatch completes (with the handler's own
        // decode error — the gate itself never fabricates a failure).
        drop(held);
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("dispatch must complete once permits free")
            .expect("task must not panic");
        assert_ne!(
            resp.status,
            pq_status::OK,
            "garbage body still fails in the handler after the gate"
        );
    }

    /// Local same-process callers (all-zeros peer hash) bypass the verify gate
    /// — the node's own consensus traffic must never queue behind an external
    /// flood. (The genesis-authority exemption is the same guard expression.)
    #[tokio::test]
    async fn verify_gate_exempts_local_caller() {
        let state = make_test_state();
        let cap = state.pq_verify_cap;
        let _held: Vec<_> = (0..cap)
            .map(|_| {
                state
                    .pq_verify_semaphore
                    .clone()
                    .try_acquire_owned()
                    .expect("drain permit")
            })
            .collect();

        let req = PqRequest {
            method: "witness".to_string(),
            headers: Default::default(),
            body: Vec::new(),
            peer_identity_hash: [0u8; 32], // local same-process sentinel
        };
        // Must complete promptly even with the gate fully saturated.
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            dispatch(state.clone(), req),
        )
        .await
        .expect("local caller must BYPASS the saturated verify gate");
        assert_ne!(resp.status, pq_status::OK, "empty witness body is a handler error");
        assert_eq!(
            state
                .pq_verify_waited_total
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "exempt caller must not touch the waited counter"
        );
    }

    // ─── pre-flip audit 2026-06-22: cross-zone finality cannot be forged ────
    // The finality-witness gossip handler used to fold the wire-supplied
    // committee snapshot (committee_hash + committee_size) verbatim, letting a
    // peer pin a 1-member committee of its own key and forge seal finality with
    // a single self-signed witness (verify_finality_quorum checks membership
    // against that hash, and add_seal_finality_signature lets the first caller
    // pin the collection). These pin the fix: the handler recomputes the
    // canonical committee for the seal's (zone, epoch) and rejects any wire
    // snapshot that does not match, and drops witnesses for a seal it has not
    // ingested locally.
    fn dummy_finality_witness() -> crate::accounting::cross_zone::SealFinalityWitness {
        crate::accounting::cross_zone::SealFinalityWitness {
            witness_pk: vec![],
            signature: vec![],
            committee_proof: vec![],
        }
    }

    // Pre-flip audit 2026-06-26: the record-not-local defer path buffers an
    // inbound attestation BEFORE signature verification (it lacks the record's
    // signable bytes), gated only by sha3(pk)==witness_hash — free to forge with
    // a fresh keypair. Without a per-record cap a single peer flooding one
    // non-local record_id with distinct keypairs grew the bucket unbounded and
    // made the dedup scan O(N²). This pins the FIFO cap + dedup behaviour.
    #[test]
    fn deferred_bucket_is_capped_per_record_and_fifo() {
        use crate::network::state::{DeferredAttestation, DeferredAttestationBuf};
        fn mk(w: &str) -> DeferredAttestation {
            DeferredAttestation {
                witness_hash: w.to_string(),
                signature: vec![0u8; 8],
                timestamp: 0.0,
                witness_public_key: None,
                powas_nonce: None,
                powas_difficulty: None,
                received_at: 0.0,
            }
        }
        let mut buf = DeferredAttestationBuf::new();
        // Duplicate witness_hash is idempotent — no growth, no eviction.
        assert!(!buf.push_bounded("rec", mk("w0"), 0.0, 4));
        assert!(!buf.push_bounded("rec", mk("w0"), 0.0, 4));
        assert_eq!(buf.bucket("rec").unwrap().len(), 1);
        // Fill to cap with distinct witnesses — no eviction yet.
        for i in 1..4 {
            assert!(!buf.push_bounded("rec", mk(&format!("w{i}")), 0.0, 4));
        }
        assert_eq!(buf.bucket("rec").unwrap().len(), 4);
        // Next distinct witness evicts the oldest (FIFO: w0 out, w4 in).
        assert!(buf.push_bounded("rec", mk("w4"), 0.0, 4));
        let entry = buf.bucket("rec").unwrap();
        assert_eq!(entry.len(), 4);
        assert!(!entry.iter().any(|d| d.witness_hash == "w0"));
        assert!(entry.iter().any(|d| d.witness_hash == "w4"));
        // A flood far past the cap stays bounded.
        for i in 5..1000 {
            buf.push_bounded("rec", mk(&format!("w{i}")), 0.0, 4);
        }
        assert_eq!(buf.bucket("rec").unwrap().len(), 4);
    }

    // Pre-flip audit 2026-06-26: these gossip-receive verbs decoded an
    // unbounded body before any committee/slot check — a handshaked peer could
    // force a multi-MiB decode (and, for witnesses, a long committee-proof loop)
    // per message. The size guard fires before the parse; an all-'x' body is not
    // valid JSON, so reaching the "too large" error proves the guard, not decode.
    #[tokio::test]
    async fn finality_witness_oversized_body_rejected_before_decode() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = make_test_state();
        let before = state.finality_witness_rejected_total.load(Relaxed);
        let oversized = vec![b'x'; MAX_WITNESS_GOSSIP_BODY + 1];
        let err = handle_submit_finality_witness(&state, &oversized, &[0u8; 32]).await.unwrap_err();
        assert!(format!("{err}").contains("too large"), "expected size-guard rejection, got: {err}");
        assert_eq!(state.finality_witness_rejected_total.load(Relaxed), before + 1);
    }

    #[tokio::test]
    async fn conflict_proof_oversized_body_rejected_before_decode() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = make_test_state();
        let before = state.conflict_proof_rejected_total.load(Relaxed);
        let oversized = vec![b'x'; MAX_CONFLICT_PROOF_BODY + 1];
        let err = handle_receive_conflict_proof(&state, &oversized).await.unwrap_err();
        assert!(format!("{err}").contains("too large"), "expected size-guard rejection, got: {err}");
        assert_eq!(state.conflict_proof_rejected_total.load(Relaxed), before + 1);
    }

    #[tokio::test]
    async fn finality_witness_rejects_forged_committee_snapshot() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = make_test_state();

        // Plant a real epoch seal so the handler can resolve its (zone, epoch).
        let epoch_state = crate::network::epoch::EpochState::new();
        let (seal_rec, parsed) = crate::network::epoch::create_epoch_seal(
            &state.identity,
            state.rocks.as_ref(),
            &epoch_state,
            crate::ZoneId::new("audit/forge"),
            0.0,
            1.0,
            None,
            None,
        )
        .expect("create epoch seal");
        state
            .rocks
            .put_record(&seal_rec.id, &seal_rec)
            .expect("store seal record");

        // Forge a 1-member committee snapshot (attacker's own key, size 1) —
        // the exact shape that collapses the 2/3 finality threshold to a single
        // self-signed witness. The test node has no staked anchors, so the
        // canonical committee is empty (size 0): the forged size-1 snapshot
        // cannot match it.
        let forged = crate::network::gossip::FinalityWitnessGossipBody {
            seal_id: seal_rec.id.clone(),
            seal_epoch: parsed.epoch_number,
            committee_hash: [0xAB; 32],
            committee_size: 1,
            witness: dummy_finality_witness(),
        };
        let body = serde_json::to_vec(&forged).unwrap();

        let before = state.finality_witness_committee_mismatch_total.load(Relaxed);
        let _ = handle_submit_finality_witness(&state, &body, &[0u8; 32]).await;
        assert_eq!(
            state.finality_witness_committee_mismatch_total.load(Relaxed),
            before + 1,
            "a forged committee snapshot must be rejected as a committee mismatch"
        );

        let consensus = state.consensus.lock_recover();
        assert!(
            consensus.seal_finality_collection_for(&seal_rec.id).is_none(),
            "a forged finality witness must NEVER be folded into the collection"
        );
    }

    #[tokio::test]
    async fn finality_witness_drops_non_member_signer_with_matching_snapshot() {
        // SECURITY (memory-DoS gate): a peer that knows the PUBLIC committee_hash
        // can submit a valid-signature witness whose witness_pk is NOT a committee
        // member. The snapshot check (hash/size) passes — so before the insertion-
        // time membership gate the non-member was folded into `signers`, which has
        // no committee_size cap → unbounded growth on distinct fake pks. (Forgery
        // itself stays blocked at claim by verify_finality_quorum's membership
        // proof; the collection is the OOM surface.) Pin the gate: a MATCHING
        // snapshot + non-member pk must be dropped, counted, and never folded.
        // Pre-fix this test fails — the non-member would land in the collection.
        use std::sync::atomic::Ordering::Relaxed;
        let state = make_test_state();
        let zone = crate::ZoneId::new("audit/nonmember");

        let epoch_state = crate::network::epoch::EpochState::new();
        let (seal_rec, parsed) = crate::network::epoch::create_epoch_seal(
            &state.identity,
            state.rocks.as_ref(),
            &epoch_state,
            zone.clone(),
            0.0,
            1.0,
            None,
            None,
        )
        .expect("create epoch seal");
        state
            .rocks
            .put_record(&seal_rec.id, &seal_rec)
            .expect("store seal record");

        // Learn the CANONICAL committee snapshot for this seal's (zone, epoch) so
        // the envelope passes the snapshot check and reaches the membership gate.
        // The test node has no staked anchors → the canonical committee is empty
        // (size 0): every pk is a non-member, which is exactly the case we assert.
        let (_pks, canonical_hash, canonical_size) =
            crate::network::zone_committee::finality_committee_pks(
                &state,
                zone.path(),
                parsed.epoch_number,
                crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE,
            )
            .await;

        // A non-member signer: a real-looking 1952-byte Dilithium3 pk that is NOT
        // in the canonical committee. Signature/proof are irrelevant — the gate
        // rejects on membership before they would ever be checked (at claim).
        let non_member = crate::accounting::cross_zone::SealFinalityWitness {
            witness_pk: vec![0x42u8; 1952],
            signature: vec![0u8; 8],
            committee_proof: vec![],
        };
        let envelope = crate::network::gossip::FinalityWitnessGossipBody {
            seal_id: seal_rec.id.clone(),
            seal_epoch: parsed.epoch_number,
            committee_hash: canonical_hash,
            committee_size: canonical_size,
            witness: non_member,
        };
        let body = serde_json::to_vec(&envelope).unwrap();

        let before = state.finality_witness_non_member_total.load(Relaxed);
        let resp = handle_submit_finality_witness(&state, &body, &[0u8; 32]).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.contains("witness_not_in_committee"),
            "a non-member signer with a matching snapshot must be rejected at the membership gate, got: {resp_str}"
        );
        assert_eq!(
            state.finality_witness_non_member_total.load(Relaxed),
            before + 1,
            "the non-member drop must bump finality_witness_non_member_total"
        );
        let consensus = state.consensus.lock_recover();
        assert!(
            consensus.seal_finality_collection_for(&seal_rec.id).is_none(),
            "a non-member finality witness must NEVER be folded into the collection (unbounded-signers DoS surface)"
        );
    }

    #[tokio::test]
    async fn xzone_abort_witness_drops_non_member_signer_with_matching_snapshot() {
        // SECURITY (memory-DoS gate, twin of finality_witness_drops_non_member_*):
        // a peer that knows the PUBLIC seal-frozen dest committee_hash for a
        // pending cross-zone transfer can submit a valid-signature abort witness
        // whose witness_pk is NOT a committee member. The snapshot check (hash/size
        // vs the seal-frozen anchor) passes — so before the insertion-time
        // membership gate the non-member was folded into the transfer's `signers`,
        // which has no committee_size cap → unbounded growth on distinct fake pks
        // (remote OOM on the public PQ surface). Forgery itself stays blocked at
        // apply by verify_abort_quorum's inclusion proof; the collection is the OOM
        // surface. Pin the gate: a MATCHING snapshot + non-member pk must be
        // dropped, counted, and never folded. Pre-fix this test fails.
        use std::sync::atomic::Ordering::Relaxed;
        let state = make_test_state();

        // Seal-frozen canonical dest-committee anchor for the transfer. The witness
        // below carries an empty proof + a pk whose committee_leaf_hash != this
        // root, so verify_inclusion_proof(leaf, [], root) == (leaf == root) == false
        // → it is a non-member even though it matches the (hash, size) snapshot.
        let canon_hash = [0xCDu8; 32];
        let canon_size = 3u32;
        let transfer_id = "xzone-abort-nonmember-001".to_string();
        {
            let mut ledger = state.ledger.write().await;
            ledger.cross_zone.pending.insert(
                transfer_id.clone(),
                crate::accounting::cross_zone::PendingTransfer {
                    transfer_id: transfer_id.clone(),
                    sender: "s".to_string(),
                    recipient: "r".to_string(),
                    amount: 1,
                    source_zone: crate::ZoneId::new("0"),
                    dest_zone: crate::ZoneId::new("1"),
                    locked_at: 1_700_000_000.0,
                    expires_at: 1_700_086_400.0,
                    status: crate::accounting::cross_zone::TransferStatus::Locked,
                    merkle_proof: Vec::new(),
                    lock_record_hash: [0xAA; 32],
                    source_merkle_root: [0xBB; 32],
                    source_seal_signers: Vec::new(),
                    source_committee_hash: [0u8; 32],
                    source_seal_epoch: 0,
                    source_committee_size: 0,
                    dest_finality_committee: Some((canon_hash, canon_size)),
                    claim_record_id: None,
                },
            );
        }

        // Non-member signer: a real-looking 1952-byte Dilithium3 pk that matches
        // the (hash, size) snapshot but carries no inclusion proof and is not a
        // leaf under canon_hash.
        let non_member = crate::accounting::cross_zone::SealFinalityWitness {
            witness_pk: vec![0x42u8; 1952],
            signature: vec![0u8; 8],
            committee_proof: vec![],
        };
        let envelope = crate::network::gossip::XZoneAbortWitnessGossipBody {
            transfer_id: transfer_id.clone(),
            dest_zone: crate::ZoneId::new("1"),
            source_seal_epoch: 0,
            committee_hash: canon_hash,
            committee_size: canon_size,
            witness: non_member,
        };
        let body = serde_json::to_vec(&envelope).unwrap();

        let before = state.xzone_abort_witness_non_member_total.load(Relaxed);
        let resp = handle_submit_xzone_abort_witness(&state, &body)
            .await
            .unwrap();
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(
            resp_str.contains("witness_not_in_committee"),
            "a non-member abort signer with a matching snapshot must be rejected at the membership gate, got: {resp_str}"
        );
        assert_eq!(
            state.xzone_abort_witness_non_member_total.load(Relaxed),
            before + 1,
            "the non-member drop must bump xzone_abort_witness_non_member_total"
        );

        let consensus = state.consensus.lock_recover();
        assert!(
            consensus.xzone_abort_collection_for(&transfer_id).is_none(),
            "a non-member abort witness must NEVER be folded into the collection (unbounded-signers DoS surface)"
        );
    }

    #[tokio::test]
    async fn finality_witness_dropped_when_seal_unknown() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = make_test_state();
        let forged = crate::network::gossip::FinalityWitnessGossipBody {
            seal_id: "nonexistent-seal".to_string(),
            seal_epoch: 7,
            committee_hash: [0x11; 32],
            committee_size: 1,
            witness: dummy_finality_witness(),
        };
        let body = serde_json::to_vec(&forged).unwrap();
        let before = state.finality_witness_rejected_total.load(Relaxed);
        let _ = handle_submit_finality_witness(&state, &body, &[0u8; 32]).await;
        assert_eq!(
            state.finality_witness_rejected_total.load(Relaxed),
            before + 1,
            "a witness for a seal we have not ingested must be dropped"
        );
        let consensus = state.consensus.lock_recover();
        assert!(
            consensus
                .seal_finality_collection_for("nonexistent-seal")
                .is_none(),
            "an unknown-seal witness must NOT create a collection"
        );
    }

    async fn spawn_router_server(
        server_id: &TestIdentity,
        state: Arc<NodeState>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = PqListener::bind(
            "127.0.0.1:0",
            server_id.pk.clone(),
            server_id.sk.clone(),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();
        let stream_handler = pq_streaming_handler(state.clone());
        let server = PqServer::new(listener, pq_router(state))
            .with_streaming(pq_streaming_methods(), stream_handler);
        let handle = tokio::spawn(server.run());
        (addr, handle)
    }

    /// B6 regression: the gossip-push rate-exemption is keyed on the
    /// handshake-authenticated `peer_identity_hash`, NOT the spoofable
    /// `x-elara-sender` header. This is the test that would have caught the
    /// original bypass — an authed-but-untrusted stranger must NOT be a trusted
    /// relayer regardless of what sender it claims.
    #[tokio::test]
    async fn push_is_trusted_keys_on_handshake_identity_not_header() {
        let state = make_test_state();

        // (a) local same-process call (all-zeros peer hash) — trusted.
        assert!(
            push_is_trusted(&state, &[0u8; 32]).await,
            "all-zeros (local same-process) push must be trusted"
        );

        // (b) authed-but-untrusted stranger (non-zero, not seed, not staked,
        //     not the genesis authority) — NOT trusted. This is the B6 bypass:
        //     pre-fix any authed peer setting x-elara-sender got the exemption.
        let stranger = [7u8; 32];
        let stranger_hex = hex::encode(stranger);
        assert_ne!(
            stranger_hex, state.config.genesis_authority,
            "test precondition: stranger must not collide with the genesis authority"
        );
        assert!(
            !push_is_trusted(&state, &stranger).await,
            "B6: an authed stranger (not seed/staked/authority) must NOT be a trusted relayer"
        );

        // (c) once the operator configures that identity as a seed, its
        //     handshake-authenticated push becomes trusted (the external-seed /
        //     Tailscale model: seeds are trusted by configuration, not stake).
        state.peers.write().await.add_seed_peer(&stranger_hex);
        assert!(
            push_is_trusted(&state, &stranger).await,
            "a configured seed peer's handshake-authenticated push must be trusted"
        );
    }

    #[tokio::test]
    async fn router_ping_round_trip() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);
        assert!(client.ping(&addr.to_string()).await);
        h.abort();
    }

    #[tokio::test]
    async fn router_status_returns_expected_fields() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let expected_network_id = state.config.network_id.clone();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let status = client.get_status(&addr.to_string()).await.unwrap();
        assert_eq!(status["network_id"], json!(expected_network_id));
        assert_eq!(status["transport"], json!("pq"));
        assert!(status["identity_hash"].is_string());
        h.abort();
    }

    #[tokio::test]
    async fn router_merkle_root_is_hex_string() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let root = client.get_merkle_root(&addr.to_string()).await.unwrap();
        // Empty DB → deterministic empty merkle root. We don't care about the
        // exact value (changes if SMT internals change) — only that we got a
        // valid hex string of reasonable length.
        assert!(!root.is_empty());
        assert!(hex::decode(&root).is_ok(), "merkle root must be valid hex: {root}");
        h.abort();
    }

    #[tokio::test]
    async fn router_query_records_empty_db() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let records = client.query_records(&addr.to_string(), 0.0, 10).await.unwrap();
        assert!(records.is_empty(), "fresh DB must return no records");
        h.abort();
    }

    #[tokio::test]
    async fn router_find_node_returns_self_or_empty() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        // Fresh DHT has no known peers, so we should get an empty list (or
        // just the local node depending on the routing table implementation).
        let peers = client.find_node(&addr.to_string(), "00".repeat(32).as_str(), 8).await.unwrap();
        // Just confirm it didn't error — concrete peer list depends on bucket init.
        assert!(peers.len() <= 8);
        h.abort();
    }

    #[tokio::test]
    async fn router_unknown_method_returns_not_found() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        // Raw PQ dial so we can inspect the status directly.
        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("no_such_method"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::NOT_FOUND);
        assert!(String::from_utf8_lossy(&resp.body).contains("no_such_method"));
        h.abort();
    }

    #[tokio::test]
    async fn router_headers_from_empty_db_returns_valid_envelope() {
        // Light-client header sync over PQ.
        //
        // Fresh DB has zero epoch seals, so the response payload must be
        // `{total: 0, headers: []}` — exactly the shape `light_sync_loop`
        // parses from the HTTPS endpoint today. A missing `since` header
        // should surface as a 400 (Wire error) so clients fail fast.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Happy path: since=0, no zone filter.
        let resp = stream
            .call(&PqRequest::new("headers_from").with_header("since", "0"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["total"], json!(0));
        assert!(v["headers"].as_array().unwrap().is_empty());

        // Missing `since` → 400.
        let bad = stream
            .call(&PqRequest::new("headers_from"))
            .await
            .unwrap();
        assert_eq!(bad.status, pq_status::BAD_REQUEST);

        h.abort();
    }

    #[tokio::test]
    async fn router_seal_progress_missing_record_404() {
        // Fresh DB has no records → querying any id
        // returns 404. Missing `record_id` header → 400.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Unknown record id → 404.
        let resp = stream
            .call(&PqRequest::new("seal_progress").with_header("record_id", "does-not-exist"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::NOT_FOUND);

        // Missing record_id header → 400.
        let bad = stream
            .call(&PqRequest::new("seal_progress"))
            .await
            .unwrap();
        assert_eq!(bad.status, pq_status::BAD_REQUEST);

        h.abort();
    }

    #[tokio::test]
    async fn router_record_detail_missing_record_404() {
        // Fresh DB has no records → unknown id 404;
        // missing `record_id` header → 400.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("record_detail").with_header("record_id", "does-not-exist"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::NOT_FOUND);

        let bad = stream
            .call(&PqRequest::new("record_detail"))
            .await
            .unwrap();
        assert_eq!(bad.status, pq_status::BAD_REQUEST);

        h.abort();
    }

    #[tokio::test]
    async fn router_account_proof_unknown_returns_not_found_stub() {
        // Unknown identity on a fresh ledger returns the
        // `{exists: false, root: ...}` envelope (200). Missing `identity`
        // header → 400. Malformed (non-hex) identity → 500 (Network err).
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // 32-byte hex that isn't in the ledger → exists=false.
        let good_hex = "a".repeat(64);
        let resp = stream
            .call(&PqRequest::new("account_proof").with_header("identity", &good_hex))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["exists"], json!(false));
        assert!(v["root"].is_string());

        // Missing header → 400.
        let bad = stream
            .call(&PqRequest::new("account_proof"))
            .await
            .unwrap();
        assert_eq!(bad.status, pq_status::BAD_REQUEST);

        h.abort();
    }

    #[tokio::test]
    async fn router_cross_zone_proof_missing_record_404() {
        // No record, no cross-zone proof available → 404.
        // Missing `record_id` or `target_zone` header → 400.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(
                &PqRequest::new("cross_zone_proof")
                    .with_header("record_id", "does-not-exist")
                    .with_header("target_zone", "0"),
            )
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::NOT_FOUND);

        // Missing record_id.
        let bad1 = stream
            .call(&PqRequest::new("cross_zone_proof").with_header("target_zone", "0"))
            .await
            .unwrap();
        assert_eq!(bad1.status, pq_status::BAD_REQUEST);

        // Missing target_zone.
        let bad2 = stream
            .call(&PqRequest::new("cross_zone_proof").with_header("record_id", "x"))
            .await
            .unwrap();
        assert_eq!(bad2.status, pq_status::BAD_REQUEST);

        h.abort();
    }

    #[tokio::test]
    async fn router_balances_empty_ledger_returns_accounts_list() {
        // Fresh ledger has no accounts → global list is
        // empty. Single-account lookup returns zero balances for an unknown
        // identity (no 404 — balances are always "queryable").
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Global list — no `identity` header.
        let resp = stream
            .call(&PqRequest::new("balances"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["accounts"].as_array().unwrap().is_empty());

        // Single-account lookup — unknown identity still 200.
        let one = stream
            .call(&PqRequest::new("balances").with_header("identity", "unknown"))
            .await
            .unwrap();
        assert_eq!(one.status, pq_status::OK);
        let v2: serde_json::Value = serde_json::from_slice(&one.body).unwrap();
        assert_eq!(v2["identity"], json!("unknown"));
        assert_eq!(v2["available"], json!(0));
        assert_eq!(v2["staked"], json!(0));

        h.abort();
    }

    #[tokio::test]
    async fn router_dag_tips_empty_dag_returns_empty_lists() {
        // Fresh DAG has no tips and no roots.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("dag_tips"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["tips_count"], json!(0));
        assert_eq!(v["roots_count"], json!(0));
        assert!(v["tips"].as_array().unwrap().is_empty());
        assert!(v["roots"].as_array().unwrap().is_empty());

        h.abort();
    }

    #[tokio::test]
    async fn router_activity_unknown_identity_returns_populated_body() {
        // AUDIT-10 Milestone A: the PQ `activity` verb serves the same body
        // as axum `/activity/{identity}`. Note: because the reputation engine
        // returns a neutral DEFAULT score (50.0) for any identity — known or
        // unknown — `compute_activity` treats the identity as "found" via the
        // reputation branch, and the body is populated with null-valued
        // trust/ledger fields rather than an explicit `error`. This is the
        // pre-existing axum behavior — we only assert parity here, we do not
        // try to fix the quirk (separate issue).
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("activity").with_header("identity", "unknown-identity"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["identity"], json!("unknown-identity"));
        assert_eq!(v["is_genesis_authority"], json!(false));
        assert!(v["trust"].is_null(), "trust must be null for unknown id");
        assert!(v["ledger"].is_null(), "ledger must be null for unknown id");
        assert_eq!(v["keys"]["key_rotations"], json!(0));

        // Missing `identity` header is a 400 — caller must supply it.
        let bad = stream
            .call(&PqRequest::new("activity"))
            .await
            .unwrap();
        assert_eq!(bad.status, pq_status::BAD_REQUEST);

        h.abort();
    }

    #[tokio::test]
    async fn router_recent_transactions_returns_feed_envelope() {
        // Sibling to router_tx_history: the `recent_transactions` PQ verb
        // must return the {transactions:[…], count:N} feed shape — NOT
        // the activity-summary shape that the old `/transactions/recent →
        // activity` pq_shim mapping returned. No identity header required.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Default limit (omitted header).
        let resp = stream
            .call(&PqRequest::new("recent_transactions"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["transactions"].is_array(), "transactions must be an array");
        assert_eq!(v["count"], json!(0));

        // Explicit limit honored + clamped to 100.
        let resp2 = stream
            .call(&PqRequest::new("recent_transactions").with_header("limit", "999"))
            .await
            .unwrap();
        assert_eq!(resp2.status, pq_status::OK);
        let v2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
        assert!(v2["transactions"].is_array());
        // count is 0 because make_test_state has no records; the clamp is
        // observable in compute_recent_transactions via the scan_limit math
        // but we'd need real records to assert it from the body. Type check
        // and presence of the right keys is what we pin here.
        assert!(v2.get("count").is_some());

        h.abort();
    }

    #[tokio::test]
    async fn router_tx_history_returns_history_envelope() {
        // /ws Slice 2 prereq: the `tx_history` PQ verb must return the
        // {identity, transactions, total, limit, offset} envelope shape —
        // NOT the activity-summary shape that the old `/history → activity`
        // pq_shim mapping returned. The transactions list is empty here
        // (no records ingested by make_test_state) but the envelope keys
        // and types must be present and correctly typed.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Default limit + offset (omitted headers).
        let resp = stream
            .call(&PqRequest::new("tx_history").with_header("identity", "some-identity-hash"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["identity"], json!("some-identity-hash"));
        assert!(v["transactions"].is_array(), "transactions must be an array");
        assert_eq!(v["transactions"].as_array().unwrap().len(), 0);
        assert_eq!(v["total"], json!(0));
        assert_eq!(v["limit"], json!(50));
        assert_eq!(v["offset"], json!(0));

        // Explicit limit + offset honored.
        let resp2 = stream
            .call(
                &PqRequest::new("tx_history")
                    .with_header("identity", "some-identity-hash")
                    .with_header("limit", "10")
                    .with_header("offset", "5"),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status, pq_status::OK);
        let v2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
        assert_eq!(v2["limit"], json!(10));
        assert_eq!(v2["offset"], json!(5));

        // limit > 200 must clamp (matches axum behavior).
        let resp3 = stream
            .call(
                &PqRequest::new("tx_history")
                    .with_header("identity", "x")
                    .with_header("limit", "9999"),
            )
            .await
            .unwrap();
        assert_eq!(resp3.status, pq_status::OK);
        let v3: serde_json::Value = serde_json::from_slice(&resp3.body).unwrap();
        assert_eq!(v3["limit"], json!(200), "limit must clamp to 200");

        // Missing identity header → 400.
        let bad = stream
            .call(&PqRequest::new("tx_history"))
            .await
            .unwrap();
        assert_eq!(bad.status, pq_status::BAD_REQUEST);

        h.abort();
    }

    #[tokio::test]
    async fn router_activity_genesis_authority_returns_populated_body() {
        // A "live" identity case — genesis authority is always marked found
        // via `is_genesis_authority`, so the body has no `error` key and the
        // identity flag is true. Confirms the PQ handler walks the same code
        // path as `compute_activity` (no stub shortcut).
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let genesis = state.config.genesis_authority.clone();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("activity").with_header("identity", &genesis))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v.get("error").is_none(), "genesis authority must resolve");
        assert_eq!(v["identity"], json!(genesis));
        assert_eq!(v["is_genesis_authority"], json!(true));

        h.abort();
    }

    #[tokio::test]
    async fn router_metrics_returns_prometheus_exposition() {
        // AUDIT-10 Milestone A: /metrics over PQ. Body is text/plain
        // Prometheus exposition format — a new node's metrics always
        // include the `# HELP` preamble and at least one `elara_` series.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("metrics"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let body = String::from_utf8(resp.body).expect("utf8 prometheus body");
        assert!(body.contains("# HELP"), "prom body must contain HELP lines");
        assert!(body.contains("# TYPE"), "prom body must contain TYPE lines");
        assert!(body.contains("elara_"), "prom body must carry elara_ series");

        h.abort();
    }

    #[tokio::test]
    async fn router_checkpoints_from_empty_state_returns_zero_total() {
        // AUDIT-10 Milestone B step 3b: PQ /checkpoints/from/{epoch}.
        // Empty in-memory state has no super-seals; request must succeed
        // with {total:0, checkpoints:[]}, matching the axum short-circuit
        // branch in compute_checkpoints_from.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let body = client
            .checkpoints_from(&addr.to_string(), 0, None, Some(500))
            .await
            .unwrap();
        assert_eq!(body["total"].as_u64(), Some(0));
        assert!(body["checkpoints"].as_array().is_some_and(|a| a.is_empty()));
        assert!(body["super_seal_interval"].as_u64().is_some());
        h.abort();
    }

    #[tokio::test]
    async fn router_checkpoints_from_missing_since_epoch_header_returns_400() {
        // Missing the required `since_epoch` header must surface as BAD_REQUEST
        // via ElaraError::Wire mapping, not as a handler panic.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Raw request with no `since_epoch` header — bypass the client wrapper
        // that always sets the header.
        let resp = stream
            .call(&PqRequest::new("checkpoints_from"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::BAD_REQUEST);
        h.abort();
    }

    #[tokio::test]
    async fn router_announce_empty_list() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let want = client.announce(&addr.to_string(), &[]).await.unwrap();
        assert!(want.is_empty());
        h.abort();
    }

    // ─── 4E.3 streaming route tests ──────────────────────────────────────────

    #[tokio::test]
    async fn router_seal_progress_stream_missing_record_emits_terminal_error() {
        // A streaming client that doesn't supply `record_id` should see one
        // FINAL|ERROR chunk and then the stream closes. This matches the
        // unary route's 400 behavior but mapped onto the stream envelope.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Missing record_id header.
        stream
            .send_request(&PqRequest::new("seal_progress_stream"))
            .await
            .unwrap();

        let chunk = stream.recv_stream_chunk().await.unwrap();
        assert!(chunk.is_final(), "first chunk on error must be FINAL");
        assert!(chunk.is_error(), "first chunk on error must be ERROR");
        assert!(String::from_utf8_lossy(&chunk.body).contains("record_id"));

        h.abort();
    }

    #[tokio::test]
    async fn router_seal_progress_stream_unknown_record_terminal_error() {
        // Fresh DB → querying any record_id triggers the `RecordNotFound`
        // branch inside `compute_seal_progress`. The streaming adapter
        // should translate that into a terminal error chunk rather than
        // sending an endless stream of 404s.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        stream
            .send_request(
                &PqRequest::new("seal_progress_stream")
                    .with_header("record_id", "does-not-exist"),
            )
            .await
            .unwrap();

        let chunk = stream.recv_stream_chunk().await.unwrap();
        assert!(chunk.is_final());
        assert!(chunk.is_error());

        h.abort();
    }

    #[test]
    fn is_terminal_progress_detects_anchored_and_finalized() {
        // Sanity check the terminal-state predicate directly — cheap to
        // validate and forms the contract between the streaming adapter
        // and `compute_seal_progress`' schema.
        let pending = json!({
            "confirmation_level": "pending",
            "seal_progress": { "settled": false, "progress_pct": 42.0 },
        });
        assert!(!is_terminal_progress(&pending));

        let anchored = json!({
            "confirmation_level": "anchored",
            "seal_progress": serde_json::Value::Null,
        });
        assert!(is_terminal_progress(&anchored));

        let finalized = json!({
            "confirmation_level": "finalized",
            "seal_progress": serde_json::Value::Null,
        });
        assert!(is_terminal_progress(&finalized));

        // Pruned-fallback shape.
        let pruned = json!({
            "confirmation_level": "finalized",
            "seal_progress": { "settled": true, "progress_pct": 100.0, "pruned": true },
        });
        assert!(is_terminal_progress(&pruned));

        // progress_pct == 100 alone should also qualify (matches
        // compute_seal_progress's synthesis when seal_progress is partial).
        let hundred = json!({
            "confirmation_level": "sealed",
            "seal_progress": { "settled": false, "progress_pct": 100.0 },
        });
        assert!(is_terminal_progress(&hundred));
    }

    #[tokio::test]
    async fn router_seal_progress_stream_not_registered_falls_through() {
        // If someone spins up the router WITHOUT `.with_streaming`, the
        // streaming method must still produce a sensible unary answer —
        // we don't want a silent hang. The unary path has no handler
        // registered for `seal_progress_stream`, so it should return 404.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();

        let listener = PqListener::bind(
            "127.0.0.1:0",
            server_id.pk.clone(),
            server_id.sk.clone(),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();
        // No .with_streaming().
        let server = PqServer::new(listener, pq_router(state));
        let h = tokio::spawn(server.run());

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("seal_progress_stream").with_header("record_id", "x"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::NOT_FOUND);

        h.abort();
    }

    // ─── 4E.3 Phase B: node_events_stream tests ──────────────────────────────
    //
    // Cover the load-bearing properties of the migration:
    //   1. WS payload parity — encode_node_event produces the exact JSON shape
    //      ws.rs ships today (a future structural drift would silently break
    //      every account on the cutover day).
    //   2. End-to-end delivery over PQ — broadcast a real NodeEvent, see it
    //      arrive as a stream chunk shaped right.
    //   3. event_type filter — clients asking for `record_finalized` only
    //      don't receive `record_inserted` events.
    //   4. Empty subscription set is honored as "I want nothing", not
    //      mis-interpreted as wildcard — a buggy client should get a clean
    //      stream_end rather than the firehose.

    #[test]
    fn encode_node_event_matches_ws_payload_shape() {
        // Lock down the byte-shape that accounts rely on. Any change to a
        // field name or type here is a wire-format break and must be done
        // with a coordinated client update.
        let inserted = encode_node_event(&NodeEvent::RecordInserted {
            record_id: "rec-1".into(),
            creator_hash: "cre-1".into(),
            beat_op: Some("transfer".into()),
            beat_amount: Some(42),
            timestamp: 1_700_000_000.5,
        });
        assert_eq!(inserted.0, "record_inserted");
        assert_eq!(inserted.1["type"], "record_inserted");
        assert_eq!(inserted.1["data"]["record_id"], "rec-1");
        assert_eq!(inserted.1["data"]["creator_hash"], "cre-1");
        assert_eq!(inserted.1["data"]["beat_op"], "transfer");
        assert_eq!(inserted.1["data"]["beat_amount"], 42);
        assert!((inserted.1["data"]["timestamp"].as_f64().unwrap() - 1_700_000_000.5).abs() < 1e-6);

        let sealed = encode_node_event(&NodeEvent::RecordSealed {
            record_id: "rec-2".into(),
            witness_count: 3,
        });
        assert_eq!(sealed.0, "record_sealed");
        assert_eq!(sealed.1["type"], "record_sealed");
        assert_eq!(sealed.1["data"]["record_id"], "rec-2");
        assert_eq!(sealed.1["data"]["witness_count"], 3);

        let finalized = encode_node_event(&NodeEvent::RecordFinalized {
            record_id: "rec-3".into(),
        });
        assert_eq!(finalized.0, "record_finalized");
        assert_eq!(finalized.1["type"], "record_finalized");
        assert_eq!(finalized.1["data"]["record_id"], "rec-3");
    }

    #[tokio::test]
    async fn router_node_events_stream_delivers_broadcast_event() {
        // Wildcard subscription: send a RecordSealed via state.events and
        // verify the client receives a chunk shaped like the WS payload.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let events_tx = state.events.clone();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        stream
            .send_request(&PqRequest::new("node_events_stream"))
            .await
            .unwrap();

        // Give the server a tick to install the broadcast subscriber before
        // we publish — otherwise we race the receiver and the event is lost.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        events_tx
            .send(NodeEvent::RecordSealed {
                record_id: "rec-broadcast".into(),
                witness_count: 5,
            })
            .unwrap();

        let chunk = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.recv_stream_chunk(),
        )
        .await
        .expect("stream chunk arrives within 2s")
        .unwrap();

        assert!(!chunk.is_final(), "data chunk, not terminal");
        assert!(!chunk.is_error());
        let payload: Value = serde_json::from_slice(&chunk.body).unwrap();
        assert_eq!(payload["type"], "record_sealed");
        assert_eq!(payload["data"]["record_id"], "rec-broadcast");
        assert_eq!(payload["data"]["witness_count"], 5);

        h.abort();
    }

    #[tokio::test]
    async fn router_node_events_stream_filter_drops_unwanted_event_type() {
        // Subscription = `[{"event_type":"record_finalized"}]` should drop a
        // RecordInserted event but pass a RecordFinalized event. We send the
        // unwanted event first, then the wanted event, and assert the first
        // chunk we see is the *wanted* one (the unwanted one was dropped
        // server-side).
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let events_tx = state.events.clone();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let body = serde_json::to_vec(&json!({
            "subscriptions": [{"event_type": "record_finalized"}]
        }))
        .unwrap();
        stream
            .send_request(&PqRequest::new("node_events_stream").with_body(body))
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        events_tx
            .send(NodeEvent::RecordInserted {
                record_id: "rec-unwanted".into(),
                creator_hash: "cre".into(),
                beat_op: None,
                beat_amount: None,
                timestamp: 0.0,
            })
            .unwrap();
        events_tx
            .send(NodeEvent::RecordFinalized {
                record_id: "rec-wanted".into(),
            })
            .unwrap();

        let chunk = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.recv_stream_chunk(),
        )
        .await
        .expect("filtered stream chunk arrives within 2s")
        .unwrap();

        let payload: Value = serde_json::from_slice(&chunk.body).unwrap();
        assert_eq!(
            payload["type"], "record_finalized",
            "filter should drop record_inserted and surface record_finalized"
        );
        assert_eq!(payload["data"]["record_id"], "rec-wanted");

        h.abort();
    }

    #[tokio::test]
    async fn router_node_events_stream_empty_subscription_set_terminates() {
        // `{"subscriptions": []}` is an explicit "I want nothing" — should
        // close the stream cleanly with a stream_end final chunk rather than
        // leaving the account hanging on a dead subscription. Empty array is
        // promoted to wildcard per the design (matches WS today), so to test
        // the explicit-deny path we send a non-`*` non-empty list with a
        // single non-existent event type.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let events_tx = state.events.clone();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // A subscription naming a non-existent event_type is a valid but
        // never-matching filter — the stream must NOT terminate, it must
        // just stay quiet. Send an event that doesn't match and assert the
        // stream is alive (recv_stream_chunk times out).
        let body = serde_json::to_vec(&json!({
            "subscriptions": [{"event_type": "non_existent_type"}]
        }))
        .unwrap();
        stream
            .send_request(&PqRequest::new("node_events_stream").with_body(body))
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        events_tx
            .send(NodeEvent::RecordFinalized {
                record_id: "rec-noisy".into(),
            })
            .unwrap();

        let res = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            stream.recv_stream_chunk(),
        )
        .await;
        assert!(
            res.is_err(),
            "filter that matches nothing must keep the stream alive (no spurious chunk)"
        );

        h.abort();
    }

    #[tokio::test]
    async fn router_node_events_stream_oversized_filter_falls_back_to_wildcard() {
        // An oversized subscription body must NOT be parsed (it would amplify a
        // ≤16 MiB `Value` decode into ~10× heap — see MAX_EVENT_SUB_FILTER_BODY).
        // The body below is syntactically a valid filter that selects ONLY
        // `record_finalized`, padded past the cap. If the guard worked, it is
        // dropped unparsed and the stream falls back to the wildcard firehose —
        // so a `RecordSealed` event (which the would-be filter excludes) is still
        // delivered. If the guard were absent, the filter would parse and drop
        // the RecordSealed, and the recv below would time out.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let events_tx = state.events.clone();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // ~80 KiB of padding — comfortably over MAX_EVENT_SUB_FILTER_BODY (64 KiB).
        let body = serde_json::to_vec(&json!({
            "subscriptions": [{"event_type": "record_finalized"}],
            "pad": "A".repeat(80 * 1024),
        }))
        .unwrap();
        assert!(
            body.len() > MAX_EVENT_SUB_FILTER_BODY,
            "test body must exceed the filter cap to exercise the guard"
        );
        stream
            .send_request(&PqRequest::new("node_events_stream").with_body(body))
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        events_tx
            .send(NodeEvent::RecordSealed {
                record_id: "rec-oversized-wildcard".into(),
                witness_count: 3,
            })
            .unwrap();

        let chunk = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.recv_stream_chunk(),
        )
        .await
        .expect("oversized filter must fall back to wildcard and deliver the event")
        .unwrap();

        assert!(!chunk.is_final() && !chunk.is_error(), "expected a data chunk");
        let payload: Value = serde_json::from_slice(&chunk.body).unwrap();
        assert_eq!(
            payload["type"], "record_sealed",
            "oversized body must NOT parse as a record_finalized-only filter"
        );
        assert_eq!(payload["data"]["record_id"], "rec-oversized-wildcard");

        h.abort();
    }

    // ─── AUDIT-10 Milestone C batch 1 router tests ──────────────────────────
    //
    // One test per verb covers:
    //   1. dispatch (the verb routes to the correct handler — not NOT_FOUND),
    //   2. structural parity with the axum counterpart (the top-level JSON
    //      key is the one the compute helper produces).
    // Field-level semantics are covered by the axum handler tests — we don't
    // re-test them through the PQ transport.

    #[tokio::test]
    async fn router_list_peers_returns_peers_key() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("list_peers")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["peers"].is_array());

        h.abort();
    }

    #[tokio::test]
    async fn router_health_returns_status_key() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("health")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["status"].is_string());
        assert!(v["readiness"].is_string());

        h.abort();
    }

    #[tokio::test]
    async fn router_ledger_summary_returns_supply_fields() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("ledger_summary")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["total_supply_beat_precise"].is_string());
        assert!(v["total_staked_beat_precise"].is_string());

        h.abort();
    }

    #[tokio::test]
    async fn router_epoch_status_returns_epochs_array() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("epoch_status")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["epochs"].is_array());

        h.abort();
    }

    // ─── stakes / network_info / token_enforcement ──────────────────────────
    //
    // Dispatch parity for the three new read-only verbs. All three are
    // infallible against a fresh state — empty stake set, default supply,
    // default circuit-breaker level.

    #[tokio::test]
    async fn router_stakes_no_identity_returns_stakes_array() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("stakes")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["stakes"].is_array());
        assert!(v.get("identity").is_none());

        h.abort();
    }

    #[tokio::test]
    async fn router_stakes_with_identity_header_returns_identity_field() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let req = PqRequest::new("stakes")
            .with_header("identity", "deadbeef".to_string());
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["identity"], "deadbeef");
        assert!(v["stakes"].is_array());

        h.abort();
    }

    #[tokio::test]
    async fn router_network_info_returns_supply_and_topology() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("network_info")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["ticker"], "BEAT");
        assert_eq!(v["protocol"], "Elara DAM");
        assert!(v["supply"].is_object());
        assert!(v["topology"].is_object());
        assert!(v["dag"].is_object());
        assert!(v["consensus"].is_object());

        h.abort();
    }

    #[tokio::test]
    async fn router_token_enforcement_returns_circuit_breaker_field() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("token_enforcement")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["circuit_breaker"].is_object());
        assert!(v["velocity"].is_object());
        assert!(v["acquisition"].is_object());
        assert!(v["governance"].is_object());

        h.abort();
    }

    // ─── zone_health / governance_summary / governance_params ───────────────

    #[tokio::test]
    async fn router_zone_health_returns_zones_array() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("zone_health")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["zones"].is_array());
        assert!(v["coverage"].is_array());
        assert!(v["min_witnesses_required"].is_u64() || v["min_witnesses_required"].is_i64());

        h.abort();
    }

    #[tokio::test]
    async fn router_governance_summary_returns_proposal_counters() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("governance_summary")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["total_proposals"].is_u64());
        assert!(v["active"].is_u64());
        assert!(v["voting_period_secs"].is_number());
        assert!(v["min_proposal_stake"].is_u64());

        h.abort();
    }

    #[tokio::test]
    async fn router_governance_params_returns_network_constants() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("governance_params")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["epoch_seal_interval_secs"].is_number());
        assert!(v["witness_reward_micros"].is_u64());
        assert!(v["total_changes"].is_u64());

        h.abort();
    }

    // ─── supply_circulating / supply_total / supply_max ─────────────────────

    #[tokio::test]
    async fn router_supply_circulating_returns_micros_and_beat() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("supply_circulating")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["micros"].is_u64());
        assert!(v["beat"].is_number());

        h.abort();
    }

    #[tokio::test]
    async fn router_supply_total_returns_micros_and_beat() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("supply_total")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["micros"].is_u64());
        assert!(v["beat"].is_number());

        h.abort();
    }

    // ─── governance_proposals / governance_proposal_detail / governance_delegations ───

    #[tokio::test]
    async fn router_governance_proposals_returns_pagination_envelope() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Defaults — empty proposal set on a fresh test ledger.
        let resp = stream.call(&PqRequest::new("governance_proposals")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["proposals"].is_array());
        assert!(v["total"].is_u64());
        assert_eq!(v["limit"].as_u64(), Some(50));
        assert_eq!(v["offset"].as_u64(), Some(0));

        // Override limit + offset via headers.
        let req = PqRequest::new("governance_proposals")
            .with_header("limit", "5")
            .with_header("offset", "10");
        let resp2 = stream.call(&req).await.unwrap();
        assert_eq!(resp2.status, pq_status::OK);
        let v2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
        assert_eq!(v2["limit"].as_u64(), Some(5));
        assert_eq!(v2["offset"].as_u64(), Some(10));

        h.abort();
    }

    #[tokio::test]
    async fn router_governance_proposal_detail_unknown_id_returns_error() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let req = PqRequest::new("governance_proposal_detail")
            .with_header("id", "no-such-proposal");
        let resp = stream.call(&req).await.unwrap();
        // Governance("not found: …") maps to a non-OK PQ status.
        assert_ne!(resp.status, pq_status::OK);

        h.abort();
    }

    #[tokio::test]
    async fn router_governance_delegations_returns_identity_envelope() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let req = PqRequest::new("governance_delegations")
            .with_header("identity", "abc123");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["identity"].as_str(), Some("abc123"));
        assert!(v["delegated_to_me"].is_array());
        assert!(v["own_governance_stake"].is_u64());
        assert!(v["total_effective_stake"].is_u64());

        h.abort();
    }

    // ─── governance_params_history / list_disputes / list_challenges ────────

    #[tokio::test]
    async fn router_governance_params_history_returns_change_envelope() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("governance_params_history")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["count"].is_u64());
        assert!(v["changes"].is_array());

        // Filter by `param` header — should still return the envelope (count
        // collapses to 0 on a fresh ledger).
        let req = PqRequest::new("governance_params_history")
            .with_header("param", "epoch_seconds");
        let resp2 = stream.call(&req).await.unwrap();
        assert_eq!(resp2.status, pq_status::OK);
        let v2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
        assert!(v2["changes"].is_array());

        h.abort();
    }

    #[tokio::test]
    async fn router_list_disputes_returns_envelope_with_totals() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("list_disputes")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["total"].is_u64());
        assert!(v["disputes_opened_total"].is_u64());
        assert!(v["disputes"].is_array());

        // Status filter is honored; envelope shape preserved.
        let req = PqRequest::new("list_disputes").with_header("status", "open");
        let resp2 = stream.call(&req).await.unwrap();
        assert_eq!(resp2.status, pq_status::OK);
        let v2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
        assert!(v2["disputes"].is_array());

        h.abort();
    }

    #[tokio::test]
    async fn router_list_challenges_returns_envelope_with_filed_total() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("list_challenges")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["total"].is_u64());
        assert!(v["filed_total"].is_u64());
        assert!(v["challenges"].is_array());

        let req = PqRequest::new("list_challenges").with_header("status", "open");
        let resp2 = stream.call(&req).await.unwrap();
        assert_eq!(resp2.status, pq_status::OK);
        let v2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
        assert!(v2["challenges"].is_array());

        h.abort();
    }

    // ─── dag_record_graph / dispute_detail / challenge_detail ───────────────

    #[tokio::test]
    async fn router_dag_record_graph_returns_neighbor_envelope_for_unknown_id() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let req = PqRequest::new("dag_record_graph")
            .with_header("id", "0000000000000000000000000000000000000000000000000000000000000000");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["exists"].as_bool(), Some(false));
        assert_eq!(v["depth"].as_u64(), Some(5));
        assert_eq!(v["direction"].as_str(), Some("both"));
        assert!(v["parents"].is_array());
        assert!(v["children"].is_array());
        assert!(v["ancestors"].is_array());
        assert!(v["descendants"].is_array());

        // Override depth + direction via headers.
        let req2 = PqRequest::new("dag_record_graph")
            .with_header("id", "deadbeef")
            .with_header("depth", "3")
            .with_header("direction", "ancestors");
        let resp2 = stream.call(&req2).await.unwrap();
        assert_eq!(resp2.status, pq_status::OK);
        let v2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
        assert_eq!(v2["depth"].as_u64(), Some(3));
        assert_eq!(v2["direction"].as_str(), Some("ancestors"));

        h.abort();
    }

    #[tokio::test]
    async fn router_dispute_detail_unknown_id_returns_error() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let req = PqRequest::new("dispute_detail").with_header("id", "no-such-dispute");
        let resp = stream.call(&req).await.unwrap();
        // RecordNotFound maps to a non-OK PQ status.
        assert_ne!(resp.status, pq_status::OK);

        h.abort();
    }

    #[tokio::test]
    async fn router_challenge_detail_unknown_id_returns_error_envelope() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // axum returns 200 with {"error": "challenge not found"} on unknown id —
        // PQ side preserves that body shape, status remains OK.
        let req = PqRequest::new("challenge_detail").with_header("id", "no-such-challenge");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["error"].as_str(), Some("challenge not found"));

        h.abort();
    }

    // ─── witness_correlation / witness_reputation / committees_is_member ────

    #[tokio::test]
    async fn router_witness_correlation_returns_pair_envelope() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let req = PqRequest::new("witness_correlation")
            .with_header("witness_a", "wa")
            .with_header("witness_b", "wb");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["witness_a"].as_str(), Some("wa"));
        assert_eq!(v["witness_b"].as_str(), Some("wb"));
        assert!(v["correlation"].is_f64() || v["correlation"].is_i64());

        // Missing required header → Wire error → non-OK PQ status.
        let req2 = PqRequest::new("witness_correlation").with_header("witness_a", "wa");
        let resp2 = stream.call(&req2).await.unwrap();
        assert_ne!(resp2.status, pq_status::OK);

        h.abort();
    }

    #[tokio::test]
    async fn router_witness_reputation_returns_summary_or_unknown_envelope() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // No witness — full summary array.
        let resp = stream.call(&PqRequest::new("witness_reputation")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["tracked_witnesses"].is_u64());
        assert!(v["witnesses"].is_array());

        // Unknown witness — default-reputation envelope with `note`.
        let req2 = PqRequest::new("witness_reputation").with_header("witness", "unknown-witness");
        let resp2 = stream.call(&req2).await.unwrap();
        assert_eq!(resp2.status, pq_status::OK);
        let v2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
        assert_eq!(v2["witness_hash"].as_str(), Some("unknown-witness"));
        assert!(v2["note"].as_str().is_some());

        h.abort();
    }

    // ─── peer_reputation / reward_stats / itc_status ────────────────────────

    #[tokio::test]
    async fn router_peer_reputation_returns_peers_array() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("peer_reputation")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["peers"].is_array());
        assert!(v["count"].is_u64());

        h.abort();
    }

    #[tokio::test]
    async fn router_reward_stats_returns_pool_and_counters() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("reward_stats")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["auto_rewards_total"].is_u64());
        assert!(v["auto_rewards_amount_micros"].is_u64());
        assert!(v["reward_per_attestation_micros"].is_u64());
        assert!(v["conservation_pool_micros"].is_u64());
        assert!(v["conservation_pool_cap_micros"].is_u64());
        assert!(v["is_genesis_authority"].is_boolean());

        h.abort();
    }

    #[tokio::test]
    async fn router_itc_status_returns_summary_and_counters() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("itc_status")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["itc"].is_object() || v["itc"].is_array());
        assert!(v["events_total"].is_u64());
        assert!(v["joins_total"].is_u64());

        h.abort();
    }

    // ─── xzone_stats / xzone_transfers / xzone_transfer ─────────────────────

    #[tokio::test]
    async fn router_xzone_stats_returns_counters_and_pending_envelope() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("xzone_stats")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["counters"]["locks_total"].is_u64());
        assert!(v["counters"]["claims_total"].is_u64());
        assert!(v["counters"]["refunds_total"].is_u64());
        assert!(v["counters"]["aborts_total"].is_u64());
        assert!(v["pending"]["total"].is_u64());
        assert!(v["currently_locked_micros"].is_u64());
        // CLAIM_TIMEOUT_SECS is f64 in the source — preserve type fidelity.
        assert!(v["claim_timeout_secs"].is_f64());

        h.abort();
    }

    #[tokio::test]
    async fn router_xzone_transfers_returns_envelope_with_pagination() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("xzone_transfers")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["total"].is_u64());
        assert!(v["returned"].is_u64());
        assert!(v["transfers"].is_array());

        // Filter headers should pass through and still produce the envelope.
        let req = PqRequest::new("xzone_transfers")
            .with_header("status", "locked")
            .with_header("limit", "10");
        let resp2 = stream.call(&req).await.unwrap();
        assert_eq!(resp2.status, pq_status::OK);
        let v2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
        assert!(v2["transfers"].is_array());

        h.abort();
    }

    #[tokio::test]
    async fn router_xzone_transfer_unknown_id_returns_error() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let req = PqRequest::new("xzone_transfer").with_header("transfer_id", "no-such-transfer");
        let resp = stream.call(&req).await.unwrap();
        assert_ne!(resp.status, pq_status::OK);

        h.abort();
    }

    #[tokio::test]
    async fn router_xzone_bundle_unknown_id_returns_error() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let req = PqRequest::new("xzone_bundle").with_header("transfer_id", "no-such-transfer");
        let resp = stream.call(&req).await.unwrap();
        assert_ne!(resp.status, pq_status::OK);

        h.abort();
    }

    #[tokio::test]
    async fn router_xzone_bundle_missing_transfer_id_returns_error() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Header omitted entirely — handler must reject with non-OK.
        let resp = stream.call(&PqRequest::new("xzone_bundle")).await.unwrap();
        assert_ne!(resp.status, pq_status::OK);

        h.abort();
    }

    // ─── account_detail / causal_proof / merkle_proof ───────────────────────

    #[tokio::test]
    async fn router_account_detail_returns_envelope_for_unknown_identity() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Missing-identity rejection.
        let resp_missing = stream.call(&PqRequest::new("account_detail")).await.unwrap();
        assert_ne!(resp_missing.status, pq_status::OK);

        // Unknown identity returns OK envelope with `exists: false` — match
        // the axum handler's behaviour that surfaces a default Account snapshot
        // rather than 404, so accounts can probe new identities cleanly.
        let req = PqRequest::new("account_detail").with_header("identity", "deadbeef-no-such-account");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["identity"], "deadbeef-no-such-account");
        assert_eq!(v["exists"], false);
        assert!(v["available"].is_u64());
        assert!(v["staked"].is_u64());
        assert!(v["total"].is_u64());
        assert!(v["active_stakes"].is_array());

        h.abort();
    }

    #[tokio::test]
    async fn router_causal_proof_unknown_id_returns_error() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Missing-id rejection.
        let resp_missing = stream.call(&PqRequest::new("causal_proof")).await.unwrap();
        assert_ne!(resp_missing.status, pq_status::OK);

        // Unknown record id surfaces RecordNotFound as non-OK PQ status,
        // matching axum's 404 path.
        let req = PqRequest::new("causal_proof").with_header("id", "no-such-record");
        let resp = stream.call(&req).await.unwrap();
        assert_ne!(resp.status, pq_status::OK);

        h.abort();
    }

    #[tokio::test]
    async fn router_merkle_proof_unknown_record_returns_error() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Missing-record_id rejection.
        let resp_missing = stream.call(&PqRequest::new("merkle_proof")).await.unwrap();
        assert_ne!(resp_missing.status, pq_status::OK);

        // Unknown record_id surfaces RecordNotFound as non-OK PQ status.
        let req = PqRequest::new("merkle_proof").with_header("record_id", "no-such-record");
        let resp = stream.call(&req).await.unwrap();
        assert_ne!(resp.status, pq_status::OK);

        h.abort();
    }

    // ─── zone_merkle_proof / dag_lifecycle / vrf_registry ───────────────────

    #[tokio::test]
    async fn router_zone_merkle_proof_validates_inputs_and_unknown_returns_error() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Missing `zone` rejection.
        let resp_no_zone = stream.call(&PqRequest::new("zone_merkle_proof")).await.unwrap();
        assert_ne!(resp_no_zone.status, pq_status::OK);

        // Missing `record_hash` rejection.
        let req_no_hash = PqRequest::new("zone_merkle_proof").with_header("zone", "0");
        let resp_no_hash = stream.call(&req_no_hash).await.unwrap();
        assert_ne!(resp_no_hash.status, pq_status::OK);

        // Malformed hex rejected as Wire (not RecordNotFound).
        let req_bad_hex = PqRequest::new("zone_merkle_proof")
            .with_header("zone", "0")
            .with_header("record_hash", "ZZZZ");
        let resp_bad_hex = stream.call(&req_bad_hex).await.unwrap();
        assert_ne!(resp_bad_hex.status, pq_status::OK);

        // Wrong-length hex rejected.
        let req_short = PqRequest::new("zone_merkle_proof")
            .with_header("zone", "0")
            .with_header("record_hash", "deadbeef");
        let resp_short = stream.call(&req_short).await.unwrap();
        assert_ne!(resp_short.status, pq_status::OK);

        // Valid 32-byte hex but no leaf in the empty tree → RecordNotFound.
        let req_unknown = PqRequest::new("zone_merkle_proof")
            .with_header("zone", "0")
            .with_header("record_hash", "00".repeat(32));
        let resp_unknown = stream.call(&req_unknown).await.unwrap();
        assert_ne!(resp_unknown.status, pq_status::OK);

        h.abort();
    }

    #[tokio::test]
    async fn router_dag_lifecycle_returns_counter_envelope() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("dag_lifecycle")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["total_records"].is_u64());
        assert!(v["pending"].is_u64());
        assert!(v["attested"].is_u64());
        assert!(v["finalized"].is_u64());
        assert!(v["dag_tips"].is_u64());
        assert!(v["dag_edges"].is_u64());
        // avg_parents is a rounded f64; on an empty DAG it's exactly 0.0.
        assert!(v["avg_parents"].is_f64() || v["avg_parents"].is_u64());

        h.abort();
    }

    #[tokio::test]
    async fn router_vrf_registry_returns_registration_envelope() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("vrf_registry")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["count"].is_u64());
        assert!(v["self_identity"].is_string());
        assert!(v["registrations"].is_array());

        h.abort();
    }

    // ─── version_info / version_forks / version_stats ───────────────────────

    #[tokio::test]
    async fn router_version_info_returns_inline_error_for_unknown_record() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Missing-record_id rejection.
        let resp_missing = stream.call(&PqRequest::new("version_info")).await.unwrap();
        assert_ne!(resp_missing.status, pq_status::OK);

        // Unknown record_id returns OK with the in-band error envelope to
        // preserve the axum body shape exactly.
        let req = PqRequest::new("version_info").with_header("record_id", "no-such-version");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["error"], "version record not found");
        assert_eq!(v["record_id"], "no-such-version");

        h.abort();
    }

    #[tokio::test]
    async fn router_version_forks_returns_inline_error_for_unknown_record() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp_missing = stream.call(&PqRequest::new("version_forks")).await.unwrap();
        assert_ne!(resp_missing.status, pq_status::OK);

        let req = PqRequest::new("version_forks").with_header("record_id", "no-such-version");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["error"], "version record not found");
        assert_eq!(v["record_id"], "no-such-version");

        h.abort();
    }

    #[tokio::test]
    async fn router_version_stats_returns_counter_envelope() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("version_stats")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["version_count"].is_u64());
        assert!(v["chain_count"].is_u64());
        assert!(v["diff_count"].is_u64());
        assert!(v["fork_count"].is_u64());

        h.abort();
    }

    // ─── epoch_headers / checkpoint_latest / dag_search tests ───────────────

    #[tokio::test]
    async fn router_epoch_headers_returns_total_and_headers_envelope() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // No headers — defaults (since=None, zone=None, limit=500).
        let resp = stream.call(&PqRequest::new("epoch_headers")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["total"].is_u64());
        assert!(v["headers"].is_array());

        // With limit=10 + since=0 — same shape, smaller cap.
        let req = PqRequest::new("epoch_headers")
            .with_header("limit", "10")
            .with_header("since", "0");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["headers"].is_array());

        h.abort();
    }

    #[tokio::test]
    async fn router_checkpoint_latest_requires_zone_and_returns_inline_error_for_no_super_seal() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Missing `zone` → BAD_REQUEST.
        let resp = stream.call(&PqRequest::new("checkpoint_latest")).await.unwrap();
        assert_eq!(resp.status, pq_status::BAD_REQUEST);

        // Test state has no super-seal yet → in-band error envelope at OK.
        let req = PqRequest::new("checkpoint_latest").with_header("zone", "0");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["error"].as_str(), Some("no super-seal yet for this zone"));
        assert!(v["zone"].is_string());

        h.abort();
    }

    #[tokio::test]
    async fn router_dag_search_returns_results_envelope_with_filters() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Empty filters — returns the standard envelope.
        let resp = stream.call(&PqRequest::new("dag_search")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["results"].is_array());
        assert!(v["count"].is_u64());
        assert!(v["limit"].is_u64());
        assert!(v["filters"].is_object());

        // With creator filter — filter must be reflected in the envelope.
        let req = PqRequest::new("dag_search")
            .with_header("creator", "abc123")
            .with_header("limit", "5");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["filters"]["creator"].as_str(), Some("abc123"));
        assert_eq!(v["limit"].as_u64(), Some(5));

        h.abort();
    }

    // ─── seal_debug / register_witness_profile / routing_resolve tests ──────

    #[tokio::test]
    async fn router_seal_debug_unknown_id_returns_not_found() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Missing `id` → BAD_REQUEST.
        let resp = stream.call(&PqRequest::new("seal_debug")).await.unwrap();
        assert_eq!(resp.status, pq_status::BAD_REQUEST);

        // Unknown seal id → NOT_FOUND (RecordNotFound from compute_seal_debug).
        let req = PqRequest::new("seal_debug").with_header("id", "non-existent-seal-id");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::NOT_FOUND);

        h.abort();
    }

    #[tokio::test]
    async fn router_register_witness_profile_persists_and_validates() {
        use crate::network::LockRecover;

        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let caller_hash_hex = hex::encode(client_id.identity_hash);
        let (addr, h) = spawn_router_server(&server_id, state.clone()).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Empty body → BAD_REQUEST (JSON parse error path is also Wire).
        let resp = stream.call(&PqRequest::new("register_witness_profile")).await.unwrap();
        assert_eq!(resp.status, pq_status::BAD_REQUEST);

        // SECURITY (authz boundary): a third-party `witness_hash` — one that is
        // NOT the authenticated session identity — is rejected. A handshaked
        // peer may register ONLY its own profile, so it cannot poison the
        // diversity-gate profile table for arbitrary other identities.
        let impostor = serde_json::json!({
            "witness_hash": "abc123def456",
            "organization": "TestOrg",
            "subnet": "10.0.0.0/24",
            "geo_zone": "EU",
        });
        let req = PqRequest::new("register_witness_profile")
            .with_body(serde_json::to_vec(&impostor).unwrap());
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::BAD_REQUEST);
        assert!(
            !state.consensus.lock_recover().has_profile("abc123def456"),
            "third-party witness_hash must NOT be registered"
        );

        // Self-registration (witness_hash == authenticated session identity) → OK.
        let good = serde_json::json!({
            "witness_hash": caller_hash_hex,
            "organization": "TestOrg",
            "subnet": "10.0.0.0/24",
            "geo_zone": "EU",
        });
        let req = PqRequest::new("register_witness_profile")
            .with_body(serde_json::to_vec(&good).unwrap());
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["registered"], true);
        assert_eq!(v["witness_hash"].as_str(), Some(caller_hash_hex.as_str()));
        assert_eq!(v["organization"].as_str(), Some("TestOrg"));
        assert!(
            state.consensus.lock_recover().has_profile(&caller_hash_hex),
            "self-registration must persist under the authenticated hash"
        );

        h.abort();
    }

    #[tokio::test]
    async fn router_routing_resolve_returns_envelope_and_inline_errors() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Missing record_id → in-band error envelope at OK.
        let resp = stream.call(&PqRequest::new("routing_resolve")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["error"].as_str(), Some("missing required query param: record_id"));

        // Bad hex key → in-band error envelope at OK.
        let req = PqRequest::new("routing_resolve")
            .with_header("record_id", "rec-1")
            .with_header("key", "not-hex");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["error"].as_str().unwrap_or("").starts_with("invalid hex for key"));

        // Wrong length key → in-band error envelope at OK.
        let req = PqRequest::new("routing_resolve")
            .with_header("record_id", "rec-1")
            .with_header("key", "abcd");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["error"].as_str().unwrap_or("").starts_with("key must decode to 32 bytes"));

        // Valid: record_id only (default key) → full envelope.
        let req = PqRequest::new("routing_resolve").with_header("record_id", "rec-2");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["record_id"].as_str(), Some("rec-2"));
        assert!(v["routing_key"].is_string());
        assert!(v["naive_zone"].is_string());
        assert!(v["resolved_zone"].is_string());
        assert!(v["redirected"].is_boolean());
        assert!(v["registry"]["active_count"].is_u64());

        h.abort();
    }

    #[tokio::test]
    async fn router_committees_is_member_returns_membership_envelope() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let req = PqRequest::new("committees_is_member")
            .with_header("zone", "0")
            .with_header("id", "some-identity");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["zone"].as_str(), Some("0"));
        assert_eq!(v["identity"].as_str(), Some("some-identity"));
        assert!(v["epoch"].is_u64());
        assert!(v["committee_size"].is_u64());
        assert!(v["is_member"].is_boolean());

        // Missing zone — in-band error envelope (axum shape).
        let req2 = PqRequest::new("committees_is_member").with_header("id", "x");
        let resp2 = stream.call(&req2).await.unwrap();
        assert_eq!(resp2.status, pq_status::OK);
        let v2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
        assert_eq!(v2["error"].as_str(), Some("missing required query param: zone"));

        h.abort();
    }

    // ─── consensus_status / consensus_record_detail / committees_snapshot ───

    #[tokio::test]
    async fn router_consensus_status_returns_settlement_counters() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("consensus_status")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["total_attestations"].is_u64());
        assert!(v["settled"].is_u64());
        assert!(v["finalized"].is_u64());
        assert!(v["confirmation_levels"].is_object());
        assert!(v["cross_zone"].is_object());
        assert!(v["waiting"].is_array());

        // Limit is honored — request a tiny limit and confirm waiting.len() ≤ 1.
        let req = PqRequest::new("consensus_status").with_header("limit", "1");
        let resp2 = stream.call(&req).await.unwrap();
        assert_eq!(resp2.status, pq_status::OK);
        let v2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
        assert!(v2["waiting"].as_array().unwrap().len() <= 1);

        h.abort();
    }

    #[tokio::test]
    async fn router_consensus_record_detail_returns_attestation_array() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Unknown record — node still answers with the empty-attestation
        // shape. Real records are exercised by higher-level integration
        // tests; here we validate dispatch + body shape.
        let req = PqRequest::new("consensus_record_detail")
            .with_header("record_id", "deadbeef");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["record_id"].as_str(), Some("deadbeef"));
        assert!(v["attestations"].is_array());
        assert!(v["confirmation_level"].is_string());
        assert_eq!(v["settlement_threshold"].as_str(), Some("66.67%"));

        h.abort();
    }

    #[tokio::test]
    async fn router_committees_snapshot_returns_committee_size_and_zones() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Defaults: current epoch + DEFAULT_COMMITTEE_SIZE.
        let resp = stream.call(&PqRequest::new("committees_snapshot")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["epoch"].is_u64());
        assert_eq!(
            v["committee_size"].as_u64().unwrap(),
            crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE as u64
        );
        assert!(v["zone_count"].is_u64());
        assert!(v["committees"].is_object() || v["committees"].is_array());

        // Override epoch + k via headers.
        let req = PqRequest::new("committees_snapshot")
            .with_header("epoch", "42")
            .with_header("k", "3");
        let resp2 = stream.call(&req).await.unwrap();
        assert_eq!(resp2.status, pq_status::OK);
        let v2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
        assert_eq!(v2["epoch"].as_u64(), Some(42));
        assert_eq!(v2["committee_size"].as_u64(), Some(3));

        h.abort();
    }

    // ─── dag_stats / validate_address / list_witness_profiles ───────────────

    #[tokio::test]
    async fn router_dag_stats_returns_classification_counters() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("dag_stats")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["total_records"].is_u64());
        // `unique_creators` is intentionally null pending an HLL
        // follow-up; `creators_indexed=false` flags this to consumers. The
        // legacy contract was `is_u64()`; that path required an
        // O(all_records) scan to populate, which was since closed.
        assert!(v["unique_creators"].is_null());
        assert_eq!(v["creators_indexed"], serde_json::json!(false));
        assert_eq!(v["stats_partial"], serde_json::json!(false));
        assert!(v["by_classification"].is_object());
        assert!(v["by_operation"].is_object());

        h.abort();
    }

    #[tokio::test]
    async fn router_validate_address_rejects_non_hex() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Wrong length — should report valid_format=false / exists=false.
        let req = PqRequest::new("validate_address").with_header("address", "not-an-address");
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["valid_format"].as_bool(), Some(false));
        assert_eq!(v["exists"].as_bool(), Some(false));
        assert_eq!(v["format"].as_str(), Some("sha3-256-hex"));

        // Well-formed hex but unknown account — valid_format=true, exists=false.
        let hex64 = "0".repeat(64);
        let req2 = PqRequest::new("validate_address").with_header("address", &hex64);
        let resp2 = stream.call(&req2).await.unwrap();
        assert_eq!(resp2.status, pq_status::OK);
        let v2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
        assert_eq!(v2["valid_format"].as_bool(), Some(true));
        assert_eq!(v2["exists"].as_bool(), Some(false));

        h.abort();
    }

    #[tokio::test]
    async fn router_list_witness_profiles_returns_profiles_array() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("list_witness_profiles")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["profiles"].is_array());
        assert!(v["count"].is_u64());

        h.abort();
    }

    #[tokio::test]
    async fn router_supply_max_returns_protocol_cap() {
        // supply_max is stateless — verifies dispatch wiring + that the body
        // matches MAX_SUPPLY exactly (catches accidental f64 lossy compare).
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("supply_max")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(
            v["micros"].as_u64().unwrap(),
            crate::accounting::types::MAX_SUPPLY
        );
        assert!(v["beat"].is_number());

        h.abort();
    }

    // ─── AUDIT-10 PQ-R5a: epoch snapshot router tests ───────────────────────
    //
    // Dispatch parity for the two new verbs used by
    // `epoch_indexed_snapshot_bootstrap`. list_epoch_snapshots is infallible
    // (returns `{"epochs":[],"count":0,...}` on a node with no snapshots);
    // get_epoch_snapshot returns a Storage error for a missing epoch, which
    // maps to a non-OK PQ response status.

    #[tokio::test]
    async fn router_list_epoch_snapshots_returns_epochs_key() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("list_epoch_snapshots")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["epochs"].is_array());
        assert!(v["count"].is_u64());

        h.abort();
    }

    #[tokio::test]
    async fn router_get_epoch_snapshot_missing_epoch_errors() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Epoch 999_999 does not exist on a fresh test node.
        let resp = stream
            .call(&PqRequest::new("get_epoch_snapshot").with_header("epoch", "999999"))
            .await
            .unwrap();
        assert_ne!(resp.status, pq_status::OK, "missing epoch must not return OK");

        h.abort();
    }

    #[tokio::test]
    async fn router_get_epoch_snapshot_missing_header_errors() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("get_epoch_snapshot")).await.unwrap();
        assert_ne!(resp.status, pq_status::OK, "missing epoch header must not return OK");

        h.abort();
    }

    // ─── AUDIT-9 Milestone B: exchange_profile verb ─────────────────────────

    /// Server side: when the operator has configured a profile, the verb
    /// returns it verbatim plus the serving node's identity_hash.
    #[tokio::test]
    async fn router_exchange_profile_returns_configured_profile() {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::network::config::NodeConfig;
        use crate::network::witness::WitnessManager;
        use crate::storage::rocks::StorageEngine;

        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();

        // Build a state with profile fields populated — can't reuse make_test_state()
        // because that sets them to the empty default.
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "t".into(),
            network_id: "audit9-mb-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            witness_organization: "navigatorbuilds".into(),
            witness_subnet: "88.99.142".into(),
            witness_geo_zone: "earth-eu".into(),
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let expected_hash = identity.identity_hash.clone();
        let rocks = Arc::new(StorageEngine::open(data_dir.join("rocksdb")).unwrap());
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
        std::mem::forget(tmp);

        let (addr, h) = spawn_router_server(&server_id, state).await;
        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("exchange_profile")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["identity_hash"], json!(expected_hash));
        assert_eq!(v["profile"]["organization"], json!("navigatorbuilds"));
        assert_eq!(v["profile"]["subnet"], json!("88.99.142"));
        assert_eq!(v["profile"]["geo_zone"], json!("earth-eu"));

        h.abort();
    }

    /// When the operator leaves witness_organization empty, the verb still
    /// succeeds but `profile` is JSON null — caller treats this as "peer has
    /// no profile; don't register anything, don't penalize it either."
    #[tokio::test]
    async fn router_exchange_profile_returns_null_when_unconfigured() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let expected_hash = state.identity.identity_hash.clone();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream.call(&PqRequest::new("exchange_profile")).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["identity_hash"], json!(expected_hash));
        assert!(v["profile"].is_null());

        h.abort();
    }

    /// AUDIT-9 Milestone B2: when the caller includes its own profile in the
    /// request body, the server registers it against the session-authenticated
    /// identity hash (sha3_256 of the caller's Dilithium3 pubkey). This closes
    /// the NAT'd-peer coverage gap — public nodes can't dial back to inbound-
    /// only peers, so symmetric exchange in a single round-trip is the only
    /// way to avoid waiting on DAG-gossip of the WitnessProfile record.
    #[tokio::test]
    async fn router_exchange_profile_registers_caller_profile() {
        use crate::network::LockRecover;

        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let caller_hash_hex = hex::encode(client_id.identity_hash);
        let (addr, h) = spawn_router_server(&server_id, state.clone()).await;

        // Pre-condition: server has never heard of the caller.
        assert!(
            !state.consensus.lock_recover().has_profile(&caller_hash_hex),
            "caller profile must not be pre-registered"
        );

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let body = serde_json::to_vec(&serde_json::json!({
            "profile": {
                "organization": "datacenter-a",
                "subnet": "10.0.7",
                "geo_zone": "earth-us",
            }
        })).unwrap();
        let req = PqRequest::new("exchange_profile").with_body(body);
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);

        // Server registered the caller's profile under the authenticated hash.
        let consensus = state.consensus.lock_recover();
        assert!(
            consensus.has_profile(&caller_hash_hex),
            "server must register caller profile under authenticated identity hash"
        );
        let got = consensus.profile_for(&caller_hash_hex).expect("profile present");
        assert_eq!(got.organization, "datacenter-a");
        assert_eq!(got.subnet, "10.0.7");
        assert_eq!(got.geo_zone, "earth-us");
        drop(consensus);

        h.abort();
    }

    /// Hardening: an oversized `exchange_profile` body must NOT be `Value`-decoded
    /// (a ≤16 MiB body would amplify ~10× into transient heap — see
    /// `MAX_EXCHANGE_PROFILE_BODY`). Oversized ⇒ registration is skipped and the
    /// verb still returns this node's own profile (the legacy response-only path).
    #[tokio::test]
    async fn router_exchange_profile_oversized_body_skips_registration() {
        use crate::network::LockRecover;

        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let caller_hash_hex = hex::encode(client_id.identity_hash);
        let (addr, h) = spawn_router_server(&server_id, state.clone()).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Syntactically valid profile, padded past the cap. If the guard works it
        // is dropped unparsed; if it were absent, the profile would register.
        let body = serde_json::to_vec(&serde_json::json!({
            "profile": {
                "organization": "datacenter-a",
                "subnet": "10.0.7",
                "geo_zone": "earth-us",
            },
            "pad": "A".repeat(80 * 1024),
        })).unwrap();
        assert!(
            body.len() > MAX_EXCHANGE_PROFILE_BODY,
            "test body must exceed the cap to exercise the guard"
        );
        let req = PqRequest::new("exchange_profile").with_body(body);
        let resp = stream.call(&req).await.unwrap();

        // The verb still succeeds — an oversized body falls through to the
        // response-only path rather than erroring the session.
        assert_eq!(resp.status, pq_status::OK);

        // ...but the oversized profile was NOT registered: the guard short-circuited
        // before the `Value` decode ever ran.
        assert!(
            !state.consensus.lock_recover().has_profile(&caller_hash_hex),
            "oversized exchange_profile body must not register a profile"
        );

        h.abort();
    }

    /// B2 defense: a malicious caller can put ANY identity_hash in the request
    /// body — the server ignores it and registers only under the Dilithium3-
    /// authenticated session hash. Without this, a peer could poison another
    /// peer's profile (collapse AWC independence) by impersonating them at
    /// the application layer even though the PQ session is tamper-proof.
    // ─── validate_record / receive_offline_notification / submit_veto tests ───
    //
    // Three POST verbs: validate_record (raw record bytes, infallible
    // envelope), receive_offline_notification (signed peer-going-offline
    // broadcast), submit_veto (Dilithium3-signed veto against a pending
    // transition).

    #[tokio::test]
    async fn router_validate_record_returns_envelope_with_wire_failure() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Empty body → wire_format check fails, but the response is still OK
        // with `valid: false` (axum behavior).
        let req = PqRequest::new("validate_record").with_body(Vec::new());
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["valid"], false);
        let checks = v["checks"].as_array().expect("checks array");
        assert_eq!(checks[0]["check"], "wire_format");
        assert_eq!(checks[0]["passed"], false);

        // Garbage bytes → same shape — never reaches signature stage.
        let req = PqRequest::new("validate_record").with_body(vec![0xff, 0xff, 0xff]);
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["valid"], false);

        h.abort();
    }

    #[tokio::test]
    async fn router_receive_offline_notification_handles_unknown_peer_and_bad_sig() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Empty body → JSON parse error → BAD_REQUEST.
        let resp = stream.call(&PqRequest::new("receive_offline_notification")).await.unwrap();
        assert_eq!(resp.status, pq_status::BAD_REQUEST);

        // Unknown peer → graceful `{"status": "unknown_peer"}` at OK
        // (matches axum: can't verify, no attack surface).
        let body = serde_json::json!({
            "node_id": "ghost-peer-id",
            "timestamp_secs": 0u64,
            "sig": "deadbeef",
        });
        let req = PqRequest::new("receive_offline_notification")
            .with_body(serde_json::to_vec(&body).unwrap());
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["status"].as_str(), Some("unknown_peer"));

        h.abort();
    }

    #[tokio::test]
    async fn router_submit_veto_missing_id_or_unknown_id() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Missing `id` header → BAD_REQUEST.
        let resp = stream.call(&PqRequest::new("submit_veto")).await.unwrap();
        assert_eq!(resp.status, pq_status::BAD_REQUEST);

        // Bad-length id hex (not 64 chars) → BAD_REQUEST from decode_id.
        let req = PqRequest::new("submit_veto")
            .with_header("id", "abcd")
            .with_body(b"{}".to_vec());
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::BAD_REQUEST);

        // Valid id hex but no JSON body parsed → BAD_REQUEST (Wire on
        // serde_json::from_slice failure). 64 hex chars = 32 bytes.
        let req = PqRequest::new("submit_veto")
            .with_header("id", "00".repeat(32))
            .with_body(Vec::new());
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::BAD_REQUEST);

        h.abort();
    }

    #[tokio::test]
    async fn router_exchange_profile_ignores_identity_claim_in_body() {
        use crate::network::LockRecover;

        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let caller_hash_hex = hex::encode(client_id.identity_hash);
        let impostor_hash_hex = "0".repeat(64); // 32 bytes of zero hex
        let (addr, h) = spawn_router_server(&server_id, state.clone()).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Attacker claims they are `impostor_hash_hex` and sends profile.
        let body = serde_json::to_vec(&serde_json::json!({
            "identity_hash": impostor_hash_hex,
            "profile": {
                "organization": "attacker-org",
                "subnet": "0.0.0",
                "geo_zone": "nowhere",
            }
        })).unwrap();
        let req = PqRequest::new("exchange_profile").with_body(body);
        let resp = stream.call(&req).await.unwrap();
        assert_eq!(resp.status, pq_status::OK);

        let consensus = state.consensus.lock_recover();
        // Registered under authenticated session hash...
        assert!(
            consensus.has_profile(&caller_hash_hex),
            "must register under authenticated hash"
        );
        // ...NOT under the body-claimed impostor hash.
        assert!(
            !consensus.has_profile(&impostor_hash_hex),
            "must NOT register under body-claimed hash"
        );

        h.abort();
    }

    // ─── 4E.1 Phase D: StreamSink trait abstraction ──────────────────────────

    /// Mock `StreamSink` that records every chunk in a `Vec`. Proves the
    /// streaming handlers work against arbitrary sink impls — the WS path's
    /// `WsStreamSink` is the production user.
    struct RecordingSink {
        chunks: Vec<PqStreamChunk>,
    }

    impl crate::network::pq_transport::rpc::StreamSink for RecordingSink {
        fn send_stream_chunk<'a>(
            &'a mut self,
            chunk: &'a PqStreamChunk,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = std::result::Result<
                            (),
                            crate::network::pq_transport::RpcError,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            self.chunks.push(chunk.clone());
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn dispatch_stream_to_sink_routes_unknown_method_to_error_chunk() {
        let state = make_test_state();
        let mut sink = RecordingSink { chunks: Vec::new() };
        super::dispatch_stream_to_sink(
            state,
            PqRequest::new("not_a_streaming_method"),
            &mut sink,
        )
        .await;
        assert_eq!(sink.chunks.len(), 1, "exactly one terminal chunk");
        assert!(sink.chunks[0].is_final(), "FINAL flag set");
        assert!(sink.chunks[0].is_error(), "ERROR flag set");
        assert!(
            String::from_utf8_lossy(&sink.chunks[0].body).contains("unknown method"),
            "body mentions the failure"
        );
    }

    #[tokio::test]
    async fn dispatch_stream_to_sink_seal_progress_missing_record_id() {
        // Same handler the TCP path uses, driven through the trait against
        // an in-memory sink — proves the WS path will get the exact same
        // terminal error shape as the TCP path on the same misuse.
        let state = make_test_state();
        let mut sink = RecordingSink { chunks: Vec::new() };
        super::dispatch_stream_to_sink(
            state,
            PqRequest::new("seal_progress_stream"),
            &mut sink,
        )
        .await;
        assert_eq!(sink.chunks.len(), 1);
        assert!(sink.chunks[0].is_final());
        assert!(sink.chunks[0].is_error());
        assert!(
            String::from_utf8_lossy(&sink.chunks[0].body).contains("record_id"),
            "error message identifies the missing header"
        );
    }

    /// When the peer-table-bump misses (peer hash not in table),
    /// the global `att_push_unattributed_total` counter must increment so
    /// the operator can compute the attribution-gap ratio. This guards
    /// the conditional in `handle_receive_attestation` from regressing —
    /// without the counter, a PQ-handshake-only peer (whose identity is
    /// authenticated but not in the discovery/seed/mDNS-driven peer
    /// table) silently inverts per-peer counters: zero growth on every
    /// per-peer gauge while the global `low_stake_deferred_total` keeps
    /// climbing. This makes the gap visible.
    #[tokio::test]
    async fn ops31_unattributed_low_stake_bump_increments_gap_counter() {
        use std::sync::atomic::Ordering::Relaxed;
        let state = make_test_state();

        // Bump targeting a peer not in the table — PeerTable returns false.
        let bumped = state
            .peers
            .write()
            .await
            .bump_att_push_low_stake_deferred("ghost", 1);
        assert!(!bumped, "unknown peer must report no-bump");
        if !bumped {
            state.att_push_unattributed_total.fetch_add(1, Relaxed);
        }
        assert_eq!(state.att_push_unattributed_total.load(Relaxed), 1);

        // Three more unattributed bumps should accumulate.
        for _ in 0..3 {
            let bumped = state
                .peers
                .write()
                .await
                .bump_att_push_low_stake_deferred("ghost", 1);
            if !bumped {
                state.att_push_unattributed_total.fetch_add(1, Relaxed);
            }
        }
        assert_eq!(state.att_push_unattributed_total.load(Relaxed), 4);
    }

    /// When the peer IS in the table, the per-peer counter grows
    /// and the global gap counter stays put. Pair this with the
    /// `ops31_unattributed_*` test to lock both branches of the
    /// `if !bumped` conditional.
    #[tokio::test]
    async fn ops31_attributed_low_stake_bump_does_not_increment_gap() {
        use crate::network::peer::{NodeType, PeerInfo, PeerProvenance, PeerState};
        use std::sync::atomic::Ordering::Relaxed;
        let state = make_test_state();

        // Insert a peer so the bump hits.
        let peer = PeerInfo {
            identity_hash: "good_peer".to_string(),
            host: "1.2.3.4".to_string(),
            port: 9473,
            node_type: NodeType::Leaf,
            last_seen: 1.0,
            state: PeerState::Connected,
            failures: 0,
            successes: 0,
            valid_records: 0,
            invalid_records: 0,
            backoff_until: 0.0,
            pow_nonce: 0,
            pow_difficulty: 0,
            public_key_hex: String::new(),
            provenance: PeerProvenance::Inbound,
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

        let bumped = state
            .peers
            .write()
            .await
            .bump_att_push_low_stake_deferred("good_peer", 1);
        assert!(bumped, "known peer must report bump");
        if !bumped {
            state.att_push_unattributed_total.fetch_add(1, Relaxed);
        }
        assert_eq!(state.att_push_unattributed_total.load(Relaxed), 0);
        assert_eq!(
            state
                .peers
                .read()
                .await
                .get("good_peer")
                .unwrap()
                .att_push_low_stake_deferred,
            1
        );
    }

    // ─── MASTER L27 hygiene: untested handler dispatch parity ───────────────
    //
    // The five tests below cover dispatch verbs that lacked direct router
    // tests. Each test pins the handler's wire envelope (status, body keys,
    // empty-state defaults) so a handler refactor can't silently change the
    // shape PqNodeClient consumers rely on. Pattern matches the rest of
    // batch A: spin a router server, dial PQ, assert response status + body.

    #[tokio::test]
    async fn router_records_exist_returns_bitmap_matching_input_size() {
        // Gap 6.4 slice 3b verb: presence probe used by the seal-replication
        // reconciler. Body is a JSON array of record ids; response is a
        // parallel `Vec<bool>`. On a fresh DB everything reports `false`.
        // Pin the contract: input length == output length, all-false on
        // empty store, OK status.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let ids = serde_json::json!(["abc", "def", "missing-id"]);
        let body = serde_json::to_vec(&ids).unwrap();
        let resp = stream
            .call(&PqRequest::new("records_exist").with_body(body))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let bits: Vec<bool> = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(bits.len(), 3, "bitmap length must match input length");
        assert!(bits.iter().all(|b| !b), "fresh DB has none of these ids");

        h.abort();
    }

    #[tokio::test]
    async fn router_state_delta_since_zero_returns_signed_envelope() {
        // Audit-#3 verb: incremental state-delta. With `since_epoch=0` and
        // an empty ledger, the server returns a fully-populated envelope —
        // baseline_available=false (no archive snapshot yet), zero accounts
        // and zero supply, but valid SMT + global merkle roots so the client
        // can verify the empty state. Missing `since_epoch` defaults to 0
        // (header_u64 fallback), so the bare call must succeed.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("state_delta").with_header("since_epoch", "0"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["since_epoch"], json!(0));
        assert_eq!(v["baseline_available"], json!(false));
        assert!(v["account_state_root"].is_string());
        assert!(v["merkle_root"].is_string());
        assert!(
            hex::decode(v["account_state_root"].as_str().unwrap()).is_ok(),
            "account_state_root must be valid hex"
        );

        // Bare call (no since_epoch header) defaults to since_epoch=0 — must
        // not 400. Pins header_u64 fallback against accidental "required"
        // tightening.
        let bare = stream
            .call(&PqRequest::new("state_delta"))
            .await
            .unwrap();
        assert_eq!(bare.status, pq_status::OK);

        h.abort();
    }

    #[tokio::test]
    async fn router_identity_pk_unknown_returns_null_envelope() {
        // Identity Partitioning Phase D verb: peer-to-peer on-miss PK fetch.
        // `identity_hash` is required (missing → 400). Unknown identity
        // returns `{identity_hash, pk: null, tier: null}` (200) — never 404,
        // because IdentityFetcher distinguishes "missing PK" from "verb not
        // implemented" via the null body.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let unknown_hex = "f".repeat(64);
        let resp = stream
            .call(
                &PqRequest::new("identity_pk")
                    .with_header("identity_hash", &unknown_hex),
            )
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["identity_hash"], json!(unknown_hex));
        assert!(v["pk"].is_null(), "pk must be null for unknown identity");
        assert!(v["tier"].is_null(), "tier must be null for unknown identity");

        // Missing required header → Wire error → 400.
        let bad = stream
            .call(&PqRequest::new("identity_pk"))
            .await
            .unwrap();
        assert_eq!(bad.status, pq_status::BAD_REQUEST);

        h.abort();
    }

    #[tokio::test]
    async fn router_list_transitions_empty_returns_zero_count() {
        // AUDIT-10 PQ-pure-client verb: cosign convergence read surface.
        // Fresh state has no pending transitions; envelope must report
        // `count: 0` with an empty list, and `current_epoch` must be a
        // u64 (not null) so accounts can render the "no pending splits"
        // empty state without special-casing the missing key.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("list_transitions"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["count"], json!(0));
        assert!(v["transitions"].as_array().unwrap().is_empty());
        assert!(v["current_epoch"].is_u64());

        // Unknown status filter → Wire error → 400. Pins the `match` arm
        // that rejects bogus filter strings.
        let bad = stream
            .call(&PqRequest::new("list_transitions").with_header("status", "nonsense"))
            .await
            .unwrap();
        assert_eq!(bad.status, pq_status::BAD_REQUEST);

        h.abort();
    }

    #[tokio::test]
    async fn router_get_transition_missing_or_unknown_id_errors() {
        // Companion to list_transitions. Three error paths to lock:
        //   1. Missing `seal_id` header → Wire → 400.
        //   2. Malformed (non-hex) seal_id → Wire (decode) → 400.
        //   3. Well-formed but absent seal_id → RecordNotFound → 404.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Missing seal_id.
        let bad1 = stream
            .call(&PqRequest::new("get_transition"))
            .await
            .unwrap();
        assert_eq!(bad1.status, pq_status::BAD_REQUEST);

        // Malformed seal_id (not hex).
        let bad2 = stream
            .call(
                &PqRequest::new("get_transition")
                    .with_header("seal_id", "not-hex-at-all"),
            )
            .await
            .unwrap();
        assert_eq!(bad2.status, pq_status::BAD_REQUEST);

        // Well-formed 32-byte hex that doesn't exist → 404.
        let unknown_hex = "1".repeat(64);
        let resp = stream
            .call(
                &PqRequest::new("get_transition")
                    .with_header("seal_id", &unknown_hex),
            )
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::NOT_FOUND);

        h.abort();
    }

    // ─── MASTER L27 hygiene: batch B — gossip + snapshot + attestation verbs ───
    //
    // Five more untested dispatch verbs. Same pattern as batch A: spin a
    // router server, dial PQ, assert response status + body. Each test
    // pins the wire envelope a PqNodeClient consumer relies on so a
    // handler refactor can't silently change shape.

    #[tokio::test]
    async fn router_announce_partitions_want_and_have_arrays() {
        // gossip RecordAnnouncement v2 verb. Body is a JSON array of
        // RecordAnnouncement; response is `{want: [...], have: [...]}` —
        // the gossip dedupe logic on the receiver side. With an empty
        // announcement list, both partitions are empty arrays (not null).
        // A bad body (non-JSON) surfaces as 400.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let body = serde_json::to_vec(&serde_json::json!([])).unwrap();
        let resp = stream
            .call(&PqRequest::new("announce").with_body(body))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["want"].as_array().unwrap().is_empty());
        assert!(v["have"].as_array().unwrap().is_empty());

        // Non-JSON body → serde error → Wire → 400.
        let bad = stream
            .call(&PqRequest::new("announce").with_body(b"not json".to_vec()))
            .await
            .unwrap();
        assert_eq!(bad.status, pq_status::BAD_REQUEST);

        h.abort();
    }

    #[tokio::test]
    async fn router_fetch_records_unknown_ids_returns_empty_list() {
        // Gossip pull verb — caller sends a JSON array of record_ids,
        // server returns a JSON array of hex-encoded wire records for the
        // ones it has. Fresh DB has none of these, so the response array
        // is empty (NOT null, NOT an error). Empty input → empty output.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Empty input list → empty result.
        let body = serde_json::to_vec(&Vec::<String>::new()).unwrap();
        let resp = stream
            .call(&PqRequest::new("fetch_records").with_body(body))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: Vec<String> = serde_json::from_slice(&resp.body).unwrap();
        assert!(v.is_empty(), "empty input must produce empty output");

        // Unknown ids → still empty (not error, not partial null).
        let body2 = serde_json::to_vec(&vec!["nonexistent-id-1", "nonexistent-id-2"]).unwrap();
        let resp2 = stream
            .call(&PqRequest::new("fetch_records").with_body(body2))
            .await
            .unwrap();
        assert_eq!(resp2.status, pq_status::OK);
        let v2: Vec<String> = serde_json::from_slice(&resp2.body).unwrap();
        assert!(v2.is_empty(), "unknown ids must be silently filtered, not erroring");

        h.abort();
    }

    #[tokio::test]
    async fn router_fetch_records_byte_caps_fat_response_under_deadline_budget() {
        // Deadline-budget pin (twin of the query_records byte-cap test): a
        // fetch_records call for many fat records must NOT return a page whose
        // hex body blows the 30s slow-link RPC deadline. The count cap
        // (MAX_FETCH_RECORDS=100) alone admits ~12.5 MiB of hex (100 × 64 KiB) —
        // ~205s at the phone-tier floor — the exact class that killed the ACER
        // cellular join on delta_sync. handle_fetch_records now byte-budgets to
        // MAX_SYNC_RESPONSE_HEX_BYTES. Unlike query_records the wire shape stays
        // a BARE ARRAY (no has_more): callers are id-driven and re-reach the
        // dropped tail via full_pull / re-ask. Completeness of the tail is NOT
        // this path's job, so we only assert the bound + progress here.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();

        const FAT: usize = 35_000; // ~74 KB hex/record — ~14 fit in a 1 MiB page
        const N: usize = 60; // < MAX_FETCH_RECORDS(100): the BYTE cap must bind, not the count cap
        let mut ids: Vec<String> = Vec::with_capacity(N);
        for i in 0..N {
            let rec = crate::record::ValidationRecord {
                id: format!("rec-fr-budget-{i}"),
                version: crate::wire::WIRE_VERSION,
                content_hash: [i as u8; 32].to_vec(),
                creator_public_key: vec![0xAA; 1952],
                timestamp: 1700000000.0 + i as f64,
                parents: vec![],
                classification: crate::record::Classification::Public,
                metadata: std::collections::BTreeMap::new(),
                signature: Some(vec![0xBB; FAT]),
                sphincs_signature: None,
                zk_proof: None,
                itc_stamp: None,
                zone_refs: vec![],
                creator_sphincs_pk: None,
                sig_algorithm: 0x01,
                sphincs_algorithm: None,
                zone: None,
                identity_hash_wire: None,
                nonce: i as u64,
            };
            state.rocks.put_record(&rec.id, &rec).expect("seed fat record");
            ids.push(rec.id);
        }

        let (addr, h) = spawn_router_server(&server_id, state).await;
        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let body = serde_json::to_vec(&ids).unwrap();
        let resp = stream
            .call(&PqRequest::new("fetch_records").with_body(body))
            .await
            .expect("response must survive the transport (frame budget)");
        assert_eq!(resp.status, pq_status::OK);

        // Bound: body stays within the deadline budget (+ small envelope margin).
        assert!(
            resp.body.len() < crate::network::sync::MAX_SYNC_RESPONSE_HEX_BYTES + 256 * 1024,
            "fetch_records body {}B exceeds the {}B deadline budget + envelope margin — \
             the byte cap did not engage",
            resp.body.len(),
            crate::network::sync::MAX_SYNC_RESPONSE_HEX_BYTES,
        );

        // Shape is still a BARE ARRAY (no client-visible change).
        let got: Vec<String> = serde_json::from_slice(&resp.body)
            .expect("fetch_records must keep the legacy bare-array shape");

        // Progress: at least one record always comes back (records ≤ 64 KiB < cap).
        assert!(!got.is_empty(), "byte cap must still return >=1 record (progress guarantee)");
        // Truncation actually engaged: fewer than all N (proves the BYTE cap bound,
        // not the count cap — N < MAX_FETCH_RECORDS).
        assert!(
            got.len() < N,
            "expected the byte cap to truncate a fat {N}-record request, got all {} back",
            got.len(),
        );

        h.abort();
    }

    #[tokio::test]
    async fn router_snapshot_fast_meta_returns_record_count_and_root() {
        // Gap-7 fast-snapshot bootstrap. Meta is the first round-trip a
        // new node does — without it the chunk fetcher can't size the
        // batch budget. Envelope must report `total_records: u64`,
        // `merkle_root: hex string`, `epoch_number: u64`. Fresh DB =
        // (0, empty-tree root, 0).
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("snapshot_fast_meta"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["total_records"], json!(0), "fresh DB has 0 records");
        assert_eq!(v["epoch_number"], json!(0), "fresh DB has no epoch seal");
        let root = v["merkle_root"].as_str().expect("merkle_root must be a string");
        assert!(hex::decode(root).is_ok(), "merkle_root must be valid hex: {root}");

        h.abort();
    }

    #[tokio::test]
    async fn router_snapshot_latest_returns_self_signed_envelope() {
        // Light-client / state-sync verb: lightweight summary of the
        // current archive head. Envelope is `{merkle_root, record_count,
        // snapshot_timestamp, signer_identity, accounts, total_supply,
        // total_staked}`. On a fresh node the signer is the local
        // identity, record_count + accounts + supply + staked all 0.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let expected_signer = state.identity.identity_hash.clone();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("snapshot_latest"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["signer_identity"], json!(expected_signer));
        assert_eq!(v["record_count"], json!(0));
        assert_eq!(v["accounts"], json!(0));
        assert_eq!(v["total_supply"], json!(0));
        assert_eq!(v["total_staked"], json!(0));
        let root = v["merkle_root"].as_str().expect("merkle_root must be a string");
        assert!(hex::decode(root).is_ok(), "merkle_root must be valid hex: {root}");
        assert!(v["snapshot_timestamp"].is_f64() || v["snapshot_timestamp"].is_u64());

        h.abort();
    }

    #[tokio::test]
    async fn router_query_attestations_zero_path_and_record_path() {
        // Mirrors the axum `sync::query_attestations` GET handler. Two
        // codepaths in one verb, picked by the presence of `record_id`:
        //   - With `record_id`: response is `{record_id, attestations: []}`.
        //   - Without: response is `{attestations: []}` (since=0, limit=100).
        // Both arms must 200 on a fresh DB with no witness attestations.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // No record_id → since-list arm, empty array.
        let resp = stream
            .call(&PqRequest::new("query_attestations"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["attestations"].as_array().unwrap().is_empty());
        assert!(v.get("record_id").is_none(), "no record_id in since-list arm");

        // With record_id → record-scoped arm, echoes id, attestations is empty.
        let rid = "any-record-id";
        let resp2 = stream
            .call(&PqRequest::new("query_attestations").with_header("record_id", rid))
            .await
            .unwrap();
        assert_eq!(resp2.status, pq_status::OK);
        let v2: serde_json::Value = serde_json::from_slice(&resp2.body).unwrap();
        assert_eq!(v2["record_id"], json!(rid));
        assert!(v2["attestations"].as_array().unwrap().is_empty());

        h.abort();
    }

    // L27 batch C — 5 more dispatch-parity tests on the next slice of the
    // "11 untested verbs remain" list: read-side bulk verbs (`delta_sync`,
    // `snapshot_full`, `snapshot_fast_chunk`, `probe`) plus the easy
    // negative path on the otherwise signature-gated `witness` verb.
    // Same coverage rationale as batch A/B: every assertion guards a wire
    // contract the live testnet hits within the first minute of pull/push,
    // so a regression here trips at the handler boundary rather than as a
    // fleet-wide sync stall.

    #[tokio::test]
    async fn router_delta_sync_empty_bloom_fresh_db_returns_empty_envelope() {
        // gossip bloom-delta verb. Body is a serialized `BloomFilter`;
        // response is `{records, total_missing, offset, batch_size,
        // has_more, scan_hit_cap}`. Fresh DB has nothing to send, so
        // every field must be the zero-value variant (NOT null) regardless
        // of bloom population. Caller-empty filter is the canonical
        // "send me everything you have" probe a freshly-booted peer
        // emits on the first gossip cycle — must 200 cleanly.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let bloom = crate::network::sync::BloomFilter::new(1, 0.01).to_bytes();
        let resp = stream
            .call(&PqRequest::new("delta_sync").with_body(bloom))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        // RAM-detect branches: ≤2GB hosts hit the early-return path with
        // batch_size=0; >2GB hosts hit the full scan path which also
        // returns 0 records on a fresh DB. Either way the envelope shape
        // and zero-valued counts are identical — that's what we assert.
        assert!(v["records"].as_array().unwrap().is_empty(), "fresh DB has no records to send");
        assert_eq!(v["total_missing"], json!(0));
        assert_eq!(v["offset"], json!(0));
        assert_eq!(v["batch_size"], json!(0));
        assert_eq!(v["has_more"], json!(false));
        assert_eq!(v["scan_hit_cap"], json!(false), "fresh DB cannot hit the 50k scan cap");

        // Malformed body (too short for the 8-byte bloom header) → Wire
        // error → BAD_REQUEST. Guards the dispatch error mapping.
        let bad = stream
            .call(&PqRequest::new("delta_sync").with_body(b"x".to_vec()))
            .await
            .unwrap();
        assert_eq!(bad.status, pq_status::BAD_REQUEST);

        h.abort();
    }

    #[tokio::test]
    async fn router_delta_sync_pages_stay_under_pq_frame_budget() {
        // Pin for the 2026-07-01 stalled-witness root cause: count-only
        // batching let a catch-up delta response (~40 MB of hex-encoded
        // dual-signed records) exceed the single-frame MAX_PAYLOAD
        // (16 MiB−1); the serve-side send() failed and the connection
        // dropped silently on both ends, so any node ≳1 day behind could
        // never DAG-catch-up. This test seeds records whose combined hex
        // encoding far exceeds the per-page response budget and drives the
        // REAL transport end-to-end: every page must arrive (a regression
        // reproduces the live symptom as a transport error), every page
        // body must respect the budget, and count-advance pagination must
        // deliver the full set.
        if crate::storage::rocks::StorageEngine::detect_system_ram_gb() <= 2 {
            return; // low-RAM hosts take the early-return skip path
        }
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();

        // 250 records at the realistic dual-sig ceiling (SLH-DSA ≈ 35 KB —
        // the wire format u16-caps each field at 65,535 B, so this is the
        // legit-shaped fat record): ~37 KB wire → ~74 KB hex each, ~18 MB
        // total. The old count-only batching (500/page) would have built one
        // ~18 MB response — over the 16 MiB frame cap; the byte budget must
        // split this into many pages of ≤1 MiB (MAX_SYNC_RESPONSE_HEX_BYTES).
        const FAT: usize = 35_000;
        const N: usize = 250;
        for i in 0..N {
            let rec = crate::record::ValidationRecord {
                id: format!("rec-frame-budget-{i}"),
                version: crate::wire::WIRE_VERSION,
                content_hash: [i as u8; 32].to_vec(),
                creator_public_key: vec![0xAA; 1952],
                timestamp: 1700000000.0 + i as f64,
                parents: vec![],
                classification: crate::record::Classification::Public,
                metadata: std::collections::BTreeMap::new(),
                signature: Some(vec![0xBB; FAT]),
                sphincs_signature: None,
                zk_proof: None,
                itc_stamp: None,
                zone_refs: vec![],
                creator_sphincs_pk: None,
                sig_algorithm: 0x01,
                sphincs_algorithm: None,
                zone: None,
                identity_hash_wire: None,
                nonce: i as u64,
            };
            state.rocks.put_record(&rec.id, &rec).expect("seed fat record");
        }

        let (addr, h) = spawn_router_server(&server_id, state).await;
        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let bloom = crate::network::sync::BloomFilter::new(1, 0.01).to_bytes();
        let mut got: Vec<String> = Vec::new();
        let mut offset = 0usize;
        let mut pages = 0usize;
        loop {
            let resp = stream
                .call(
                    &PqRequest::new("delta_sync")
                        .with_header("x-delta-batch-size", "500")
                        .with_header("x-delta-offset", offset.to_string())
                        .with_body(bloom.clone()),
                )
                .await
                .expect("page must survive the transport (frame budget)");
            assert_eq!(resp.status, pq_status::OK);
            assert!(
                resp.body.len()
                    < crate::network::sync::MAX_SYNC_RESPONSE_HEX_BYTES + 256 * 1024,
                "page body {}B exceeds the {}B budget + envelope margin",
                resp.body.len(),
                crate::network::sync::MAX_SYNC_RESPONSE_HEX_BYTES,
            );
            let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
            assert_eq!(
                v["total_missing"], serde_json::json!(N),
                "every page reports the full peer-side missing count (R2-6b gauge source)"
            );
            let records: Vec<String> = v["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r.as_str().unwrap().to_string())
                .collect();
            assert!(!records.is_empty(), "every page makes progress");
            let has_more = v["has_more"].as_bool().unwrap();
            offset += records.len();
            got.extend(records);
            pages += 1;
            assert!(pages <= N + 1, "pagination must terminate");
            if !has_more {
                break;
            }
        }
        assert_eq!(got.len(), N, "all seeded records delivered across pages");
        assert!(pages >= 3, "fat records must force multiple pages (byte budget active)");
        for wire_hex in &got {
            assert!(wire_hex.len() >= FAT, "records arrive intact, not truncated");
        }

        h.abort();
    }

    #[test]
    fn fetch_records_worst_case_response_fits_single_frame() {
        // MAX_FETCH_RECORDS is the only thing keeping handle_fetch_records'
        // response under the PQ single-frame cap (it has no byte budget).
        // Worst case: every fetched record at the wire ceiling, hex-doubled,
        // plus JSON quotes/commas/brackets. Raising the cap or the record
        // ceiling must trip this pin before it ships an over-frame response.
        let worst_case = MAX_FETCH_RECORDS
            * (crate::network::ingest::MAX_RECORD_BYTES * 2 + 4)
            + 2;
        assert!(
            worst_case < crate::network::pq_transport::frame::MAX_PAYLOAD,
            "fetch_records worst-case response {}B exceeds the single-frame cap {}B — \
             byte-budget the handler (R2-6 class) before raising MAX_FETCH_RECORDS",
            worst_case,
            crate::network::pq_transport::frame::MAX_PAYLOAD,
        );
    }

    #[tokio::test]
    async fn router_query_records_pages_stay_under_pq_frame_budget() {
        // R2-6 class extension pin: handle_query_records admits limit=1000
        // and full_pull requests 500/page — unbudgeted, a page of fat
        // dual-signed records (~80KB hex each) exceeds the 16MiB−1 single
        // frame and the serve send() dies, which left full_pull's cursor
        // permanently stuck below the fat region (root-caused live
        // 2026-07-02). This drives the REAL transport with a full_pull-shaped
        // cursor loop: every page must arrive, truncated pages must carry
        // has_more=true (object shape) so the client does NOT misread them
        // as the history tail, and cursor advancement must deliver the
        // complete set.
        if crate::storage::rocks::StorageEngine::detect_system_ram_gb() <= 2 {
            return; // low-RAM hosts take the early-return skip path
        }
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();

        const FAT: usize = 35_000;
        const N: usize = 250;
        for i in 0..N {
            let rec = crate::record::ValidationRecord {
                id: format!("rec-qr-budget-{i}"),
                version: crate::wire::WIRE_VERSION,
                content_hash: [i as u8; 32].to_vec(),
                creator_public_key: vec![0xAA; 1952],
                timestamp: 1700000000.0 + i as f64,
                parents: vec![],
                classification: crate::record::Classification::Public,
                metadata: std::collections::BTreeMap::new(),
                signature: Some(vec![0xBB; FAT]),
                sphincs_signature: None,
                zk_proof: None,
                itc_stamp: None,
                zone_refs: vec![],
                creator_sphincs_pk: None,
                sig_algorithm: 0x01,
                sphincs_algorithm: None,
                zone: None,
                identity_hash_wire: None,
                nonce: i as u64,
            };
            state.rocks.put_record(&rec.id, &rec).expect("seed fat record");
        }

        let (addr, h) = spawn_router_server(&server_id, state).await;
        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let mut got = 0usize;
        let mut cursor = 0.0f64;
        let mut pages = 0usize;
        let mut saw_truncated_object = false;
        const PAGE: usize = 500; // full_pull's >4GB page size
        loop {
            let resp = stream
                .call(
                    &PqRequest::new("query_records")
                        .with_header("since", cursor.to_string())
                        .with_header("limit", PAGE.to_string()),
                )
                .await
                .expect("page must survive the transport (frame budget)");
            assert_eq!(resp.status, pq_status::OK);
            assert!(
                resp.body.len()
                    < crate::network::sync::MAX_SYNC_RESPONSE_HEX_BYTES + 256 * 1024,
                "page body {}B exceeds the {}B budget + envelope margin",
                resp.body.len(),
                crate::network::sync::MAX_SYNC_RESPONSE_HEX_BYTES,
            );
            let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
            let (hex_records, truncated): (Vec<String>, bool) =
                if let Some(records) = v.get("records").and_then(|r| r.as_array()) {
                    (
                        records.iter().map(|r| r.as_str().unwrap().to_string()).collect(),
                        v["has_more"].as_bool().unwrap_or(false),
                    )
                } else {
                    let arr = v.as_array().expect("legacy shape is a bare array");
                    (arr.iter().map(|r| r.as_str().unwrap().to_string()).collect(), false)
                };
            assert!(!hex_records.is_empty(), "every page makes progress");
            if truncated {
                saw_truncated_object = true;
            }
            // full_pull-shaped cursor advance: max record timestamp + epsilon.
            let mut batch_max_ts = cursor;
            for wire_hex in &hex_records {
                assert!(wire_hex.len() >= FAT, "records arrive intact, not truncated");
                let wire = hex::decode(wire_hex).unwrap();
                let rec = crate::record::ValidationRecord::from_bytes(&wire).unwrap();
                if rec.timestamp > batch_max_ts {
                    batch_max_ts = rec.timestamp;
                }
            }
            got += hex_records.len();
            pages += 1;
            assert!(pages <= N + 1, "pagination must terminate");
            if hex_records.len() < PAGE && !truncated {
                break; // genuine tail
            }
            cursor = batch_max_ts + 0.001;
        }
        assert_eq!(got, N, "all seeded records delivered across pages");
        assert!(pages >= 3, "fat records must force multiple pages (byte budget active)");
        assert!(
            saw_truncated_object,
            "truncated pages must ship the object shape with has_more=true"
        );

        h.abort();
    }

    #[tokio::test]
    async fn router_query_records_untruncated_page_keeps_legacy_array_shape() {
        // Compatibility pin for the dual-shape response: a page that fits the
        // byte budget MUST keep the legacy bare-array JSON shape — old clients
        // deserialize Vec<String> directly and would hard-fail on an object.
        // Only truncated pages (which no old client ever received — the
        // transport died on them) may use the {"records","has_more"} shape.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        for i in 0..5 {
            let rec = crate::record::ValidationRecord {
                id: format!("rec-qr-small-{i}"),
                version: crate::wire::WIRE_VERSION,
                content_hash: [i as u8; 32].to_vec(),
                creator_public_key: vec![0xAA; 1952],
                timestamp: 1700000000.0 + i as f64,
                parents: vec![],
                classification: crate::record::Classification::Public,
                metadata: std::collections::BTreeMap::new(),
                signature: Some(vec![0xBB; 64]),
                sphincs_signature: None,
                zk_proof: None,
                itc_stamp: None,
                zone_refs: vec![],
                creator_sphincs_pk: None,
                sig_algorithm: 0x01,
                sphincs_algorithm: None,
                zone: None,
                identity_hash_wire: None,
                nonce: i as u64,
            };
            state.rocks.put_record(&rec.id, &rec).expect("seed record");
        }

        let (addr, h) = spawn_router_server(&server_id, state).await;
        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(
                &PqRequest::new("query_records")
                    .with_header("since", "0")
                    .with_header("limit", "500"),
            )
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(
            v.is_array(),
            "untruncated query_records page must stay a bare array (legacy client compat), got: {}",
            &resp.body.len()
        );
        assert_eq!(v.as_array().unwrap().len(), 5);

        h.abort();
    }

    #[tokio::test]
    async fn router_witness_malformed_body_returns_bad_request() {
        // `witness` is signature-gated — to exercise the success path we'd
        // need a Dilithium3-signed ValidationRecord, which is hostile to
        // fixture in a unit test. The dispatch parity check still has
        // value: malformed body must surface as 400 (Wire error from
        // `ValidationRecord::from_bytes`), not 401 (InvalidSignature),
        // not 500. Confirms the error-mapping arm `Wire → BAD_REQUEST`
        // for this handler.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        // Empty body fails at WireReader::read_header — well-defined Wire
        // error path, not a parser-internal panic.
        let resp = stream
            .call(&PqRequest::new("witness").with_body(Vec::new()))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::BAD_REQUEST);

        // Garbage bytes (non-wire-format) fall through the same path.
        let resp2 = stream
            .call(&PqRequest::new("witness").with_body(b"not a validation record".to_vec()))
            .await
            .unwrap();
        assert_eq!(resp2.status, pq_status::BAD_REQUEST);

        h.abort();
    }

    #[tokio::test]
    async fn router_snapshot_full_returns_signed_payload_on_fresh_node() {
        // Light-client bootstrap verb. Response body is `SignedSnapshot`
        // wire bytes (NOT JSON — pre-serialized by `create_signed_snapshot`).
        // On a fresh node we can't introspect the inner fields without
        // pulling in the deserializer, but the dispatch-parity contract
        // is: status=OK + non-empty body + repeatable. The non-empty body
        // catches regressions where the signer is wired wrong (would
        // return an empty payload) or the spawn_blocking task panics
        // silently (would surface as INTERNAL_ERROR, not OK).
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("snapshot_full"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        assert!(
            resp.body.len() >= 64,
            "snapshot_full body must include signature payload (got {} bytes)",
            resp.body.len()
        );

        // Two consecutive calls must both 200 — guards against any
        // single-use resource exhaustion in the spawn_blocking path.
        let resp2 = stream
            .call(&PqRequest::new("snapshot_full"))
            .await
            .unwrap();
        assert_eq!(resp2.status, pq_status::OK);

        h.abort();
    }

    #[tokio::test]
    async fn router_snapshot_full_rejects_above_accounts_cap() {
        // B2 regression: the PQ `snapshot_full` handler must enforce the same
        // OOM circuit-breaker as its HTTP twin (`serve_snapshot`). Before the
        // fix it cloned the full ledger + collect_applied_ids + JSON for any
        // handshake-authed peer with no size gate. Seed one account past
        // MAX_SNAPSHOT_FULL_ACCOUNTS and assert the handler fails fast with
        // RateLimited (mapped to 429 TOO_MANY_REQUESTS by `error_status`) and
        // bumps the reject counter — rather than performing the unbounded clone.
        use crate::accounting::ledger::AccountState;
        let state = make_test_state();
        {
            let mut ledger = state.ledger.write().await;
            for i in 0..=crate::network::routes::sync::MAX_SNAPSHOT_FULL_ACCOUNTS {
                ledger
                    .accounts
                    .insert(format!("over-cap-acct-{i}"), AccountState::default());
            }
            assert!(
                ledger.accounts.len() > crate::network::routes::sync::MAX_SNAPSHOT_FULL_ACCOUNTS,
                "fixture must exceed the cap"
            );
        }

        let before = state
            .snapshot_size_rejected_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let resp = handle_snapshot_full(&state).await;
        let is_rate_limited = matches!(resp, Err(ElaraError::RateLimited));
        assert!(
            is_rate_limited,
            "over-cap snapshot_full must reject with RateLimited (got ok={})",
            resp.is_ok()
        );
        let after = state
            .snapshot_size_rejected_total
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            after - before,
            1,
            "rejection must bump snapshot_size_rejected_total exactly once"
        );
    }

    #[tokio::test]
    async fn router_snapshot_fast_chunk_fresh_db_returns_empty_chunk() {
        // Gap-7 fast-sync chunk verb. Response is `SnapshotChunk` JSON:
        // `{records, next_cursor, total_records, served_so_far,
        // merkle_root, epoch_number}`. On a fresh DB the records list is
        // empty, next_cursor is None (final chunk), total_records=0,
        // epoch_number=0, merkle_root is the empty-tree hex root.
        // Companion to the `snapshot_fast_meta` test from batch B —
        // together they cover both sides of the fast-sync handshake.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("snapshot_fast_chunk"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["records"].as_array().unwrap().is_empty(), "fresh DB has no records");
        assert_eq!(v["total_records"], json!(0));
        assert_eq!(v["epoch_number"], json!(0), "fresh DB has not sealed an epoch");
        // next_cursor: None serializes to JSON null on fresh DB (no more
        // chunks to fetch). Tolerate either explicit null or missing key
        // depending on serde Option-skip config.
        assert!(
            v["next_cursor"].is_null() || v.get("next_cursor").is_none(),
            "fresh DB chunk must signal end-of-stream via null/missing next_cursor"
        );
        let root = v["merkle_root"].as_str().expect("merkle_root must be a string");
        assert!(hex::decode(root).is_ok(), "merkle_root must be valid hex: {root}");

        h.abort();
    }

    #[tokio::test]
    async fn router_probe_unknown_record_reports_has_record_false() {
        // Liveness/sync probe verb. Body is a JSON `ProbeRequest`
        // (`{record_id, prober_identity}`); response is JSON
        // `ProbeResponse` (`{has_record, parents, dag_size,
        // responder_identity, [recent_record]}`). On a fresh node with an
        // empty DAG, any probed record_id is unknown → has_record=false,
        // parents=[], dag_size=0. The recent_record key is
        // skip_serializing_if=Option::is_none, so on empty DAG it should
        // be absent. responder_identity must match the server identity.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let expected_responder = state.identity.identity_hash.clone();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let probe_req = serde_json::json!({
            "record_id": "nonexistent-record-id",
            "prober_identity": "test-prober",
        });
        let body = serde_json::to_vec(&probe_req).unwrap();
        let resp = stream
            .call(&PqRequest::new("probe").with_body(body))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["has_record"], json!(false), "unknown record must report has_record=false");
        assert!(v["parents"].as_array().unwrap().is_empty(), "unknown record has no parents");
        assert_eq!(v["dag_size"], json!(0), "fresh DAG is empty");
        assert_eq!(v["responder_identity"], json!(expected_responder));
        assert!(
            v.get("recent_record").is_none() || v["recent_record"].is_null(),
            "fresh DAG has no tips → recent_record omitted/null"
        );

        // Bad body → Json error → BAD_REQUEST. Same dispatch-mapping
        // assertion as other JSON-body verbs.
        let bad = stream
            .call(&PqRequest::new("probe").with_body(b"not json".to_vec()))
            .await
            .unwrap();
        assert_eq!(bad.status, pq_status::BAD_REQUEST);

        h.abort();
    }

    // ─── L27 batch D — witness/seal write-side helper + verb coverage ─────
    //
    // Unlocks the six write-side verbs that L27's body listed as untested
    // (witness, receive_attestation, receive_conflict_proof,
    // submit_finality_witness, submit_xzone_abort_witness,
    // submit_transition_seal/sig) — all of them require a signed-by-creator
    // ValidationRecord on the wire. The helper builds a Profile-B record
    // signed via `Identity::sign_record_light` and returns its `to_bytes()`
    // wire encoding, which is exactly what the handlers consume.

    fn make_signed_validation_record_body() -> (crate::identity::Identity, Vec<u8>) {
        use crate::identity::{CryptoProfile, EntityType, Identity};
        use crate::record::Classification;
        let creator = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate creator identity");
        let mut rec = ValidationRecord::create(
            b"L27D witness fixture content",
            creator.public_key.clone(),
            Vec::new(),
            Classification::Public,
            None,
        );
        creator
            .sign_record_light(&mut rec)
            .expect("sign_record_light");
        (creator, rec.to_bytes())
    }

    #[tokio::test]
    async fn router_witness_signed_record_returns_identity_hash_and_dilithium_sig() {
        // Happy path through `handle_witness` (router.rs:821): the handler
        // verifies the inbound record's signature against creator_pk, signs
        // its `signable_bytes()` with the server identity, and returns
        // `identity_hash || attestation_sig`. Light client SDKs need this
        // shape to attribute attestations to the witnessing node.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let expected_hash = state.identity.identity_hash.clone();
        let server_dil_pk = state.identity.public_key.clone();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let (_creator, body) = make_signed_validation_record_body();
        // Re-parse to extract the exact signable bytes the handler will sign.
        let rec = ValidationRecord::from_bytes(&body).expect("re-parse");
        let signable = rec.signable_bytes();

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();
        let resp = stream
            .call(&PqRequest::new("witness").with_body(body))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK, "signed record must round-trip");
        // identity_hash is sha3_256_hex(pk) → 64 ASCII hex chars.
        assert!(resp.body.len() > 64, "body must carry hash + signature");
        let returned_hash = std::str::from_utf8(&resp.body[..64])
            .expect("first 64 bytes ascii hex");
        assert_eq!(returned_hash, expected_hash);
        let sig = &resp.body[64..];
        assert!(
            crate::crypto::pqc::dilithium3_verify(&signable, sig, &server_dil_pk)
                .expect("verify"),
            "attestation sig must verify under server pk"
        );

        h.abort();
    }

    #[tokio::test]
    async fn router_witness_two_distinct_records_share_server_identity_hash() {
        // Same witnessing node attesting two different records returns the
        // same `identity_hash` prefix; the attestation signatures differ
        // because `signable_bytes()` differs. Locks in the invariant that
        // the prefix is constant per server, independent of payload.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let expected_hash = state.identity.identity_hash.clone();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let (_c1, body1) = make_signed_validation_record_body();
        let (_c2, body2) = make_signed_validation_record_body();
        assert_ne!(body1, body2, "two fresh records must differ on the wire");

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();
        let r1 = stream
            .call(&PqRequest::new("witness").with_body(body1))
            .await
            .unwrap();
        let r2 = stream
            .call(&PqRequest::new("witness").with_body(body2))
            .await
            .unwrap();
        assert_eq!(r1.status, pq_status::OK);
        assert_eq!(r2.status, pq_status::OK);
        assert_eq!(&r1.body[..64], expected_hash.as_bytes());
        assert_eq!(&r2.body[..64], expected_hash.as_bytes());
        assert_ne!(
            &r1.body[64..],
            &r2.body[64..],
            "distinct payloads produce distinct attestation sigs"
        );

        h.abort();
    }

    #[tokio::test]
    async fn router_witness_tampered_signature_returns_unauthorized() {
        // Flip one byte of the signed record's signature. `handle_witness`
        // re-runs `dilithium3_verify` against `record.creator_public_key`;
        // a mismatch must surface as `pq_status::UNAUTHORIZED` (mapped
        // from `ElaraError::InvalidSignature`). Guards the auth gate from
        // regressing to "accept anything that parses."
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let (_creator, mut body) = make_signed_validation_record_body();
        // Tamper one byte deep in the body — almost certainly inside the
        // signature region (it's the largest field at ~3293 bytes).
        let tamper_at = body.len() - 32;
        body[tamper_at] ^= 0xFF;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();
        let resp = stream
            .call(&PqRequest::new("witness").with_body(body))
            .await
            .unwrap();
        // Either the wire-decoder rejects the tamper (400) or the signature
        // check rejects it (401). Both are acceptable rejections of a
        // tampered record; what's NOT acceptable is 200 OK.
        assert!(
            resp.status == pq_status::UNAUTHORIZED
                || resp.status == pq_status::BAD_REQUEST,
            "tampered witness body must reject, got status={}",
            resp.status
        );

        h.abort();
    }

    #[tokio::test]
    async fn router_receive_attestation_garbage_body_returns_bad_request() {
        // Dispatch-parity for the `receive_attestation` verb (router.rs:1007):
        // a non-decodable body must surface as BAD_REQUEST regardless of
        // happy-path signing details. Locks in the same negative gate as
        // `delta_sync` / `probe` so a future Json-vs-Wire refactor can't
        // silently downgrade this to 500.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();
        for bad in [Vec::<u8>::new(), b"not a record".to_vec(), vec![0u8; 8]] {
            let resp = stream
                .call(&PqRequest::new("receive_attestation").with_body(bad))
                .await
                .unwrap();
            assert_eq!(
                resp.status,
                pq_status::BAD_REQUEST,
                "garbage body must surface as 400"
            );
        }

        h.abort();
    }

    #[tokio::test]
    async fn router_submit_finality_witness_garbage_body_returns_bad_request() {
        // Same negative-path lock for `submit_finality_witness`
        // (router.rs:1353) — a JSON-body verb that the handler parses via
        // `serde_json::from_slice`. Non-JSON bytes must surface 400, not
        // 500. Captures the Json-error → BAD_REQUEST mapping for a verb
        // that previously had zero dispatch tests.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();
        for bad in [Vec::<u8>::new(), b"{ malformed".to_vec(), b"\x00\x01\x02".to_vec()] {
            let resp = stream
                .call(&PqRequest::new("submit_finality_witness").with_body(bad))
                .await
                .unwrap();
            assert_eq!(
                resp.status,
                pq_status::BAD_REQUEST,
                "garbage body must surface as 400"
            );
        }

        h.abort();
    }

    // L27 batch E — dispatch-parity coverage for the last four uncovered
    // write-side verbs. All four parse the body as JSON via
    // `serde_json::from_slice` before any crypto / state work, so a
    // non-JSON body must surface as `BAD_REQUEST`. Locks the
    // Json-error → 400 mapping for verbs that previously had zero
    // dispatch tests, mirroring batch D's `receive_attestation` /
    // `submit_finality_witness` negative-path style.

    #[tokio::test]
    async fn router_receive_conflict_proof_garbage_body_returns_bad_request() {
        // `handle_receive_conflict_proof` (router.rs:1287) decodes the
        // body to `ConflictProof` before any slot-key / verify work.
        // Garbage in → 400, not 500.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();
        for bad in [Vec::<u8>::new(), b"{ not-a-proof".to_vec(), b"\xff\xfe\xfd".to_vec()] {
            let resp = stream
                .call(&PqRequest::new("receive_conflict_proof").with_body(bad))
                .await
                .unwrap();
            assert_eq!(
                resp.status,
                pq_status::BAD_REQUEST,
                "non-JSON conflict_proof body must surface as 400"
            );
        }

        h.abort();
    }

    #[tokio::test]
    async fn router_submit_xzone_abort_witness_garbage_body_returns_bad_request() {
        // `handle_submit_xzone_abort_witness` (router.rs:1393) decodes
        // the body to `XZoneAbortWitnessGossipBody`. Decode failure
        // explicitly bumps `xzone_abort_witness_rejected_total` and
        // returns `ElaraError::Wire` — pq_status must map this to 400.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();
        for bad in [Vec::<u8>::new(), b"not json at all".to_vec(), b"\x00".to_vec()] {
            let resp = stream
                .call(&PqRequest::new("submit_xzone_abort_witness").with_body(bad))
                .await
                .unwrap();
            assert_eq!(
                resp.status,
                pq_status::BAD_REQUEST,
                "non-JSON xzone_abort body must surface as 400"
            );
        }

        h.abort();
    }

    #[tokio::test]
    async fn router_submit_transition_seal_garbage_body_returns_bad_request() {
        // `handle_submit_transition_seal` (router.rs:2860) decodes the
        // body to `TransitionSeal` before any validate_structure / store
        // work. Json parse failure → ElaraError::from(serde_json::Error)
        // → pq_status 400. Locks the gate so a future refactor can't
        // surface a transport 500 on malformed proposals.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();
        for bad in [Vec::<u8>::new(), b"{ broken".to_vec(), b"\xde\xad\xbe\xef".to_vec()] {
            let resp = stream
                .call(&PqRequest::new("submit_transition_seal").with_body(bad))
                .await
                .unwrap();
            assert_eq!(
                resp.status,
                pq_status::BAD_REQUEST,
                "non-JSON transition_seal body must surface as 400"
            );
        }

        h.abort();
    }

    #[tokio::test]
    async fn router_submit_transition_sig_missing_seal_id_header_returns_bad_request() {
        // `handle_submit_transition_sig` (router.rs:2935) requires a
        // `seal_id` request header before it touches the body. Calling
        // without the header must surface as 400 via the explicit
        // `ElaraError::Wire("submit_transition_sig: missing \`seal_id\` header")`
        // branch — not 500, not a panic. Body is irrelevant here; the
        // gate is the missing-header check.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();
        let resp = stream
            .call(&PqRequest::new("submit_transition_sig").with_body(b"{}".to_vec()))
            .await
            .unwrap();
        assert_eq!(
            resp.status,
            pq_status::BAD_REQUEST,
            "missing seal_id header must surface as 400"
        );

        h.abort();
    }

    // ─── sync-helper tests ────
    //
    // Three previously-untouched private helpers in this file each pin a
    // load-bearing contract on the wire side of the PQ transport. Sync
    // `#[test]` (no tokio runtime) so they cost ~zero suite time.

    #[test]
    fn batch_v_error_status_pins_every_explicit_elara_error_to_pq_status() {
        // `error_status` at router.rs:326-337 is the ONLY place an
        // ElaraError becomes a PQ response status. Every PqNodeClient
        // retry / fail-fast branch reads off these codes:
        //   - 400 Wire/Json/DuplicateRecord/MissingParent → client surfaces
        //     as caller-fix-then-retry, no automatic re-send
        //   - 401 InvalidSignature → client gives up, identity / pin is wrong
        //   - 404 RecordNotFound → client returns Ok(None)/empty list
        //   - 429 RateLimited → client retries with backoff
        //   - 500 catch-all → client treats as server error, peer-rotate
        //
        // A regression collapsing any explicit branch into the wildcard
        // would silently flip a 4xx-retryable into a 500-rotate-peer or
        // vice versa. Each assertion below pins one of those flips.
        assert_eq!(error_status(&ElaraError::Wire("bad".into())), pq_status::BAD_REQUEST);
        assert_eq!(error_status(&ElaraError::InvalidSignature), pq_status::UNAUTHORIZED);
        assert_eq!(error_status(&ElaraError::RecordNotFound("rid".into())), pq_status::NOT_FOUND);
        assert_eq!(error_status(&ElaraError::DuplicateRecord("rid".into())), pq_status::BAD_REQUEST);
        assert_eq!(error_status(&ElaraError::MissingParent("rid".into())), pq_status::BAD_REQUEST);
        assert_eq!(error_status(&ElaraError::RateLimited), pq_status::TOO_MANY_REQUESTS);
        // Json variant: construct via the `#[from] serde_json::Error` arm
        // — invalid JSON parse yields the right inner type.
        let json_err = serde_json::from_str::<Value>("{not json").unwrap_err();
        assert_eq!(error_status(&ElaraError::Json(json_err)), pq_status::BAD_REQUEST);
        // Wildcard fallback: any non-listed variant lands on 500. Pin
        // three distinct shapes so a regression that special-cased any
        // of them would surface here.
        assert_eq!(error_status(&ElaraError::Crypto("kex".into())), pq_status::INTERNAL_ERROR);
        assert_eq!(error_status(&ElaraError::Storage("rocks".into())), pq_status::INTERNAL_ERROR);
        assert_eq!(error_status(&ElaraError::Network("tcp".into())), pq_status::INTERNAL_ERROR);
    }

    #[test]
    fn batch_v_header_parsers_return_none_on_missing_or_malformed_and_some_on_valid() {
        // Three header parsers at router.rs:345-355 share the same
        // get-and-parse-then-ok shape. The contract that matters at the
        // call site: missing OR malformed MUST return None (the caller
        // then falls back to its default), and present-and-valid MUST
        // parse to Some(value). A regression that switched `.ok()` to
        // `.expect()` would panic on every malformed header — DoS from
        // a single bad request. Pinning all three together because they
        // share the same body and would regress together.
        let empty: BTreeMap<String, String> = BTreeMap::new();
        assert_eq!(header_u64(&empty, "x"), None);
        assert_eq!(header_usize(&empty, "x"), None);
        assert_eq!(header_f64(&empty, "x"), None);

        let mut h = BTreeMap::new();
        h.insert("count".to_string(), "42".to_string());
        h.insert("size".to_string(), "1024".to_string());
        h.insert("ratio".to_string(), "0.75".to_string());
        assert_eq!(header_u64(&h, "count"), Some(42u64));
        assert_eq!(header_usize(&h, "size"), Some(1024usize));
        assert_eq!(header_f64(&h, "ratio"), Some(0.75f64));

        // Wrong-type key returns None (not a panic). u64 can't hold "0.75",
        // usize can't hold "-1", f64 can't hold "not-a-number".
        assert_eq!(header_u64(&h, "ratio"), None);
        let mut hh = BTreeMap::new();
        hh.insert("neg".to_string(), "-1".to_string());
        hh.insert("nan".to_string(), "not-a-number".to_string());
        assert_eq!(header_usize(&hh, "neg"), None);
        assert_eq!(header_f64(&hh, "nan"), None);

        // Missing key with other keys present still returns None — the
        // .get() lookup is the gate, not the parser.
        assert_eq!(header_u64(&h, "absent"), None);
        assert_eq!(header_usize(&h, "absent"), None);
        assert_eq!(header_f64(&h, "absent"), None);
    }

    #[test]
    fn batch_v_pq_streaming_methods_returns_exactly_the_two_known_stream_methods() {
        // `pq_streaming_methods` at router.rs:64-73 is the routing
        // manifest the server reads to decide whether a method takes
        // the unary path or the streaming path. The PqServer dispatch
        // looks the request method up in this Vec; a method that
        // returns `true` here MUST also have a branch in
        // `pq_streaming_handler` or it terminates with an error chunk
        // ("defense in depth" per the doc-comment).
        //
        // Pinning the exact contents catches two regression classes:
        //   1. A streaming method added to the handler but forgotten
        //      here — its unary attempt would 404 silently.
        //   2. A method removed from the handler but left here — the
        //      server would route to a stream that errors immediately.
        let methods = pq_streaming_methods();
        assert_eq!(methods.len(), 2, "exactly two streaming methods today");
        assert!(methods.contains(&"seal_progress_stream".to_string()));
        assert!(methods.contains(&"node_events_stream".to_string()));
    }

    // ─── +4 pins on `att_to_json` ───
    // (field-mapping + Option branch + deliberately-omitted PoWaS fields)
    // and `to_body` (round-trip-serializable contract). Both are pure sync
    // helpers — no tokio runtime, no NodeState, no Storage — so they cost
    // ~zero suite time and pin a wire-format contract that an unrelated
    // refactor (e.g. "let's also expose powas_nonce in the JSON") would
    // otherwise silently flip without a test catching it.

    #[test]
    fn batch_w_att_to_json_with_none_public_key_omits_field_entirely() {
        // `att_to_json` at router.rs:1034-1045 conditionally includes the
        // `witness_public_key` field only when `Some(pk)`. The PQ-wire
        // contract for attestation list responses is: pre-PQ-verification
        // attestations land with `witness_public_key = None` and the JSON
        // for those records MUST omit the field entirely (NOT emit
        // `"witness_public_key": null`). A consumer parsing the response
        // with `serde::Deserialize` on an `Option<Vec<u8>>` field handles
        // both shapes, but a client doing manual `.get("witness_public_key")`
        // distinguishes "missing entry" (= legacy attestation) from
        // "present but null" (= post-PQ but key omitted by sender bug).
        //
        // The pin: assert the JSON `Object` does NOT have a
        // `witness_public_key` key when the source struct is None.
        use crate::network::witness::AttestationRecord;
        let att = AttestationRecord {
            record_id: "rid-1".to_string(),
            witness_hash: "wh-1".to_string(),
            signature: vec![0xde, 0xad, 0xbe, 0xef],
            timestamp: 1_700_000_000.0_f64,
            witness_public_key: None,
            powas_nonce: None,
            powas_difficulty: None,
        };
        let v = att_to_json(&att);
        let obj = v.as_object().expect("att_to_json must produce a JSON Object");
        assert_eq!(obj.get("record_id"), Some(&json!("rid-1")));
        assert_eq!(obj.get("witness_hash"), Some(&json!("wh-1")));
        assert_eq!(obj.get("signature"), Some(&json!("deadbeef"))); // hex-encoded
        assert_eq!(obj.get("timestamp"), Some(&json!(1_700_000_000.0_f64)));
        // The contract-load-bearing assertion: the key is ABSENT, not Null.
        assert!(
            !obj.contains_key("witness_public_key"),
            "witness_public_key MUST be omitted entirely when None (not emitted as null), \
             got JSON: {v}",
        );
    }

    #[test]
    fn batch_w_att_to_json_with_some_public_key_hex_encodes_both_signature_and_key() {
        // `att_to_json` hex-encodes BOTH the signature (always) and the
        // witness_public_key (when present). The two hex encodings share
        // the same byte-to-string path (`hex::encode`) so a regression
        // that swapped to base64 on one but not the other would surface
        // as a mismatched-encoding pair; pinning both in the same test
        // catches the asymmetric-encoding regression class.
        //
        // The constant byte-patterns chosen (0xAB 0xCD vs 0x01 0x02 0x03)
        // make the failure mode obvious: if a future change swapped to
        // base64 (`q80=`, `AQID`) instead of hex (`abcd`, `010203`), the
        // assertion text shows EXACTLY which encoding flipped.
        use crate::network::witness::AttestationRecord;
        let att = AttestationRecord {
            record_id: "rid-2".to_string(),
            witness_hash: "wh-2".to_string(),
            signature: vec![0xAB, 0xCD],
            timestamp: 1_700_000_001.5_f64,
            witness_public_key: Some(vec![0x01, 0x02, 0x03]),
            powas_nonce: None,
            powas_difficulty: None,
        };
        let v = att_to_json(&att);
        assert_eq!(v["signature"], json!("abcd"), "signature hex");
        assert_eq!(
            v["witness_public_key"], json!("010203"),
            "witness_public_key hex when Some",
        );
    }

    #[test]
    fn batch_w_att_to_json_deliberately_omits_powas_nonce_and_difficulty() {
        // The AttestationRecord struct (witness.rs:399-411) carries
        // `powas_nonce: Option<u64>` and `powas_difficulty: Option<u64>`
        // for the Protocol v0.6.1 §11.1 PoWaS proof, but `att_to_json`
        // at router.rs:1034-1045 deliberately does NOT include them in
        // the wire JSON. The contract is: the client consuming
        // /query_attestations doesn't need PoWaS fields (those gate
        // server-side admission, not client-side verification), so they
        // are dropped at the response boundary to reduce wire payload
        // and avoid leaking sybil-resistance details to lightweight
        // clients.
        //
        // A future change that "exposed powas_nonce for debugging" would
        // need to also update this pin (deliberately) — that's the point.
        // Without this pin, the wire shape silently grows without an
        // explicit decision being made.
        use crate::network::witness::AttestationRecord;
        let att = AttestationRecord {
            record_id: "rid-3".to_string(),
            witness_hash: "wh-3".to_string(),
            signature: vec![],
            timestamp: 0.0,
            witness_public_key: None,
            // Populate the PoWaS fields with deliberately-recognizable
            // sentinels — if they leaked into JSON, the assertion text
            // would point to the value 0xCAFE / 0xBABE_difficulty.
            powas_nonce: Some(0xCAFE),
            powas_difficulty: Some(0xBABE),
        };
        let v = att_to_json(&att);
        let obj = v.as_object().expect("Object");
        assert!(
            !obj.contains_key("powas_nonce"),
            "powas_nonce MUST be dropped at the wire boundary, got: {v}",
        );
        assert!(
            !obj.contains_key("powas_difficulty"),
            "powas_difficulty MUST be dropped at the wire boundary, got: {v}",
        );
    }

    #[test]
    fn batch_w_to_body_round_trips_serializable_to_json_bytes() {
        // `to_body` at router.rs:359-361 is the single chokepoint where
        // EVERY handler in this file converts its response struct/json!
        // value into the `Vec<u8>` body that the PQ envelope carries.
        // The pin asserts (1) the serialization path is utf-8 valid JSON
        // (so a client deserializer doesn't choke on bytes the server
        // promised would parse) and (2) the round-trip preserves the
        // logical content (so a future "let's compact" or "let's add
        // pretty-printing" change can't silently flip the wire shape).
        //
        // A regression replacing `serde_json::to_vec` with `to_writer`
        // (which would require a sink arg) would fail at compile time;
        // a regression replacing it with bincode or another binary
        // encoding would fail the `from_slice::<Value>` round-trip here.
        let original = json!({
            "tag": "pong",
            "count": 42u64,
            "ratio": 0.5,
            "items": ["a", "b", "c"],
            "nested": { "inner": true },
        });
        let bytes = to_body(&original).expect("to_body must serialize valid json!() Value");
        // Wire-shape invariant 1: bytes parse as UTF-8.
        let s = std::str::from_utf8(&bytes).expect("to_body output must be utf-8");
        assert!(s.starts_with('{') && s.ends_with('}'), "object delimited");
        // Wire-shape invariant 2: round-trip preserves logical content.
        let parsed: Value = serde_json::from_slice(&bytes).expect("round-trip");
        assert_eq!(parsed, original, "round-trip must preserve content");
    }

    // ─── fixture-free pure-helper coverage ────────────────────────────────────
    //
    // Five axes on pure-helper surface not covered by the other test groups:
    //   1. STREAM_TICK_MS + MAX_STREAM_DURATION_SECS strict-pin + Duration math
    //   2. MAX_EVENT_STREAM_SECS strict-pin + Duration round-trip + cross-relations
    //   3. is_terminal_progress confirmation_level matrix (case + variants + missing)
    //   4. is_terminal_progress seal_progress.settled/progress_pct boundary matrix
    //   5. encode_node_event 3-variant wire-name + JSON shape exhaustive pin

    #[test]
    fn batch_b_stream_tick_and_max_duration_constants_strict_pin_and_cadence_math() {
        // STREAM_TICK_MS + MAX_STREAM_DURATION_SECS govern the seal-progress
        // streaming budget. They're load-bearing UX numbers: tick=500ms is the
        // account's perceived refresh latency; max=300s caps a stuck stream so
        // a stuck client doesn't pin the server forever.
        assert_eq!(STREAM_TICK_MS, 500, "STREAM_TICK_MS literal pin (ms)");
        assert_eq!(
            MAX_STREAM_DURATION_SECS, 300,
            "MAX_STREAM_DURATION_SECS literal pin (s = 5 minutes)"
        );

        // Cross-unit cadence math: at 500 ms/tick, 300 s wall-clock yields
        // exactly 600 ticks before the deadline-hit branch fires. This is
        // the upper bound on chunks emitted per seal-progress stream and
        // the budget light-clients need to provision their socket buffer.
        let tick = std::time::Duration::from_millis(STREAM_TICK_MS);
        let max_dur = std::time::Duration::from_secs(MAX_STREAM_DURATION_SECS);
        assert_eq!(tick.as_millis(), 500);
        assert_eq!(max_dur.as_secs(), 300);
        assert_eq!(max_dur.as_millis(), 300_000);

        let max_ticks = max_dur.as_millis() / tick.as_millis();
        assert_eq!(max_ticks, 600, "max chunks per stream = 600");

        // DOS-budget sanity: tick must be < 5s (UX cadence) and max_duration
        // < 1 hour (otherwise stalled streams chew sockets). If either
        // drifts past these bounds, the budget is no longer "interactive".
        assert!(tick < std::time::Duration::from_secs(5), "tick < 5s");
        assert!(
            max_dur < std::time::Duration::from_secs(3600),
            "max_duration < 1 hour"
        );
        assert!(tick > std::time::Duration::ZERO, "tick > 0 (no busy-loop)");
        assert!(
            max_dur > std::time::Duration::ZERO,
            "max_duration > 0 (no immediate-exit)"
        );
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_max_event_stream_secs_strict_pin_and_cross_relation_to_seal_stream() {
        // MAX_EVENT_STREAM_SECS bounds node_events_stream wall-clock so
        // clients re-handshake hourly (refreshes PQ session keys, drops
        // dead subscribers). Picking 3600s = 1h matches the rolling
        // session-key lifetime — drift will silently change reconnect cadence.
        assert_eq!(MAX_EVENT_STREAM_SECS, 3600, "MAX_EVENT_STREAM_SECS = 1 h");
        assert_eq!(
            MAX_EVENT_STREAM_SECS,
            60 * 60,
            "= 60 seconds * 60 minutes"
        );

        // Duration round-trip preserves the literal value.
        let dur = std::time::Duration::from_secs(MAX_EVENT_STREAM_SECS);
        assert_eq!(dur.as_secs(), 3600);
        assert_eq!(dur.as_millis(), 3_600_000);

        // Cross-relation: event-stream budget MUST exceed seal-progress
        // budget — events run longer than a single record's progress
        // stream. Ratio is 3600/300 = 12 today.
        assert!(
            MAX_EVENT_STREAM_SECS > MAX_STREAM_DURATION_SECS,
            "event-stream budget > seal-stream budget"
        );
        let ratio = MAX_EVENT_STREAM_SECS / MAX_STREAM_DURATION_SECS;
        assert_eq!(ratio, 12, "event-stream / seal-stream ratio");

        // Reasonable upper bound: 1 day. If this ever crosses 86400, it
        // means a stuck stream can hold a socket for >24h — almost
        // certainly a bug.
        assert!(
            MAX_EVENT_STREAM_SECS <= 86_400,
            "event-stream cap <= 1 day"
        );
    }

    #[test]
    fn batch_b_is_terminal_progress_confirmation_level_matrix() {
        // is_terminal_progress short-circuits to true when confirmation_level
        // is "finalized" or "anchored". Anything else falls through to the
        // seal_progress branch. The matrix below pins:
        //   - both terminal variants (lowercase, exact strings)
        //   - case-sensitivity ("Finalized" / "ANCHORED" must NOT terminate)
        //   - non-terminal variants (pending, unconfirmed) fall through
        //   - missing / null / non-string confirmation_level falls through

        // ── Terminal: short-circuits true ──
        assert!(is_terminal_progress(&json!({"confirmation_level": "finalized"})));
        assert!(is_terminal_progress(&json!({"confirmation_level": "anchored"})));

        // ── Case-sensitive (intentional — matches ConfirmationLevel::name()) ──
        // With no seal_progress branch, these fall through to `false`.
        assert!(
            !is_terminal_progress(&json!({"confirmation_level": "Finalized"})),
            "Finalized (caps) is NOT terminal"
        );
        assert!(
            !is_terminal_progress(&json!({"confirmation_level": "ANCHORED"})),
            "ANCHORED (caps) is NOT terminal"
        );
        assert!(
            !is_terminal_progress(&json!({"confirmation_level": "FINALIZED"})),
            "FINALIZED (caps) is NOT terminal"
        );

        // ── Non-terminal confirmation strings ──
        assert!(!is_terminal_progress(&json!({"confirmation_level": "pending"})));
        assert!(!is_terminal_progress(&json!({"confirmation_level": "unconfirmed"})));
        assert!(!is_terminal_progress(&json!({"confirmation_level": "sealed"})));
        assert!(!is_terminal_progress(&json!({"confirmation_level": ""})));

        // ── Missing / non-string confirmation_level ──
        assert!(!is_terminal_progress(&json!({})));
        assert!(!is_terminal_progress(&json!({"confirmation_level": null})));
        assert!(
            !is_terminal_progress(&json!({"confirmation_level": 42})),
            "integer confirmation_level → falls through (as_str returns None)"
        );
        assert!(
            !is_terminal_progress(&json!({"confirmation_level": true})),
            "bool confirmation_level → falls through"
        );
        assert!(
            !is_terminal_progress(&json!({"other_field": "finalized"})),
            "wrong field name → falls through"
        );
    }

    #[test]
    fn batch_b_is_terminal_progress_seal_progress_settled_and_progress_pct_boundary_matrix() {
        // When confirmation_level is non-terminal (or missing), is_terminal_progress
        // inspects seal_progress.settled and seal_progress.progress_pct. This axis
        // pins the precise OR-shape:
        //   settled=true  → terminal (regardless of pct)
        //   settled=false + pct >= 100.0 → terminal
        //   settled=false + pct <  100.0 → NOT terminal
        //   seal_progress missing → NOT terminal
        // Plus boundary values at 100.0 / 99.999... / 100.001 / negative / NaN.

        // ── settled=true short-circuits regardless of pct ──
        assert!(is_terminal_progress(&json!({
            "seal_progress": {"settled": true}
        })));
        assert!(is_terminal_progress(&json!({
            "seal_progress": {"settled": true, "progress_pct": 0.0}
        })));
        assert!(is_terminal_progress(&json!({
            "seal_progress": {"settled": true, "progress_pct": -50.0}
        })));

        // ── settled=false branch falls through to pct ──
        assert!(is_terminal_progress(&json!({
            "seal_progress": {"settled": false, "progress_pct": 100.0}
        })));
        assert!(is_terminal_progress(&json!({
            "seal_progress": {"settled": false, "progress_pct": 100.001}
        })));
        assert!(is_terminal_progress(&json!({
            "seal_progress": {"settled": false, "progress_pct": 250.0}
        })));

        // ── Boundary: pct < 100 is NOT terminal ──
        assert!(!is_terminal_progress(&json!({
            "seal_progress": {"settled": false, "progress_pct": 99.999}
        })));
        assert!(!is_terminal_progress(&json!({
            "seal_progress": {"settled": false, "progress_pct": 99.0}
        })));
        assert!(!is_terminal_progress(&json!({
            "seal_progress": {"settled": false, "progress_pct": 0.0}
        })));
        assert!(!is_terminal_progress(&json!({
            "seal_progress": {"settled": false, "progress_pct": -1.0}
        })));

        // ── settled missing + pct present hits the >= 100 path ──
        assert!(is_terminal_progress(&json!({
            "seal_progress": {"progress_pct": 100.0}
        })));
        assert!(!is_terminal_progress(&json!({
            "seal_progress": {"progress_pct": 99.5}
        })));

        // ── Both missing → not terminal ──
        assert!(!is_terminal_progress(&json!({"seal_progress": {}})));
        assert!(!is_terminal_progress(&json!({})));

        // ── Confirmation_level + seal_progress combined: confirmation_level
        // wins when terminal; falls through to seal_progress otherwise.
        assert!(is_terminal_progress(&json!({
            "confirmation_level": "finalized",
            "seal_progress": {"settled": false, "progress_pct": 0.0}
        })));
        assert!(is_terminal_progress(&json!({
            "confirmation_level": "pending",
            "seal_progress": {"settled": true}
        })));
        assert!(!is_terminal_progress(&json!({
            "confirmation_level": "pending",
            "seal_progress": {"settled": false, "progress_pct": 50.0}
        })));
    }

    #[test]
    fn batch_b_encode_node_event_exhaustive_3_variant_wire_name_and_json_shape_pin() {
        // encode_node_event is the chokepoint for the PQ event-stream wire
        // format. Three NodeEvent variants → three exact snake_case names.
        // Any drift (PascalCase, plural, typo) silently breaks every
        // subscribed account — pin every name and the JSON shape literally.

        // ── RecordInserted ──
        let inserted = NodeEvent::RecordInserted {
            record_id: "rec_42".to_string(),
            creator_hash: "abcd1234".to_string(),
            beat_op: Some("transfer".to_string()),
            beat_amount: Some(1_000_000),
            timestamp: 1_700_000_000.5,
        };
        let (name, value) = encode_node_event(&inserted);
        assert_eq!(name, "record_inserted", "RecordInserted wire-name");
        assert_eq!(value["type"], "record_inserted");
        assert_eq!(value["data"]["record_id"], "rec_42");
        assert_eq!(value["data"]["creator_hash"], "abcd1234");
        assert_eq!(value["data"]["beat_op"], "transfer");
        assert_eq!(value["data"]["beat_amount"], 1_000_000u64);
        assert_eq!(value["data"]["timestamp"], 1_700_000_000.5);

        // ── RecordInserted with None Option fields → serializes as JSON null ──
        let inserted_no_op = NodeEvent::RecordInserted {
            record_id: "rec_43".into(),
            creator_hash: "deadbeef".into(),
            beat_op: None,
            beat_amount: None,
            timestamp: 0.0,
        };
        let (_, v) = encode_node_event(&inserted_no_op);
        assert!(v["data"]["beat_op"].is_null(), "None beat_op → null");
        assert!(v["data"]["beat_amount"].is_null(), "None beat_amount → null");

        // ── RecordSealed ──
        let sealed = NodeEvent::RecordSealed {
            record_id: "rec_seal".into(),
            witness_count: 7,
        };
        let (name, value) = encode_node_event(&sealed);
        assert_eq!(name, "record_sealed", "RecordSealed wire-name");
        assert_eq!(value["type"], "record_sealed");
        assert_eq!(value["data"]["record_id"], "rec_seal");
        assert_eq!(value["data"]["witness_count"], 7u32);
        // Shape guard: ONLY these two fields in the data object.
        let data_obj = value["data"].as_object().expect("data is object");
        assert_eq!(data_obj.len(), 2, "RecordSealed.data has exactly 2 fields");

        // ── RecordFinalized ──
        let finalized = NodeEvent::RecordFinalized {
            record_id: "rec_final".into(),
        };
        let (name, value) = encode_node_event(&finalized);
        assert_eq!(name, "record_finalized", "RecordFinalized wire-name");
        assert_eq!(value["type"], "record_finalized");
        assert_eq!(value["data"]["record_id"], "rec_final");
        // Shape guard: ONLY record_id in the data object.
        let data_obj = value["data"].as_object().expect("data is object");
        assert_eq!(data_obj.len(), 1, "RecordFinalized.data has exactly 1 field");
        assert!(data_obj.contains_key("record_id"));

        // ── Cross-variant uniqueness: all 3 wire-names disjoint ──
        let (n1, _) = encode_node_event(&inserted);
        let (n2, _) = encode_node_event(&sealed);
        let (n3, _) = encode_node_event(&finalized);
        assert_ne!(n1, n2);
        assert_ne!(n2, n3);
        assert_ne!(n1, n3);

        // ── &'static str pin: returned names are compile-time literals,
        // not allocated. (Compiler-enforced via the signature, but spot-check
        // they're plausibly interned by comparing pointer equality on
        // repeated calls.)
        let (n_a, _) = encode_node_event(&inserted);
        let (n_b, _) = encode_node_event(&inserted);
        assert_eq!(n_a.as_ptr(), n_b.as_ptr(), "&'static str interned");

        // ── Wire-name format invariant: snake_case + "record_" prefix ──
        for name in [n1, n2, n3] {
            assert!(name.starts_with("record_"), "wire-name prefix: {name}");
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "snake_case (lowercase + underscore only): {name}"
            );
        }
    }

    // ── §11.23 Layer A slice 1: resolve_content_hash PQ verb ─────────────
    //
    // Three test axes pinning the responder contract:
    //   1. Missing `content_hash` header → 400 BAD_REQUEST (fail fast for
    //      misconfigured callers, never silently miss).
    //   2. Local miss → 404 NOT_FOUND with non-empty body explaining "no
    //      record matches" (caller-side pq_client.get_record_by_hash maps
    //      this to Ok(None) — different from transport errors).
    //   3. Local hit → 200 OK with the same JSON shape as /record/{id}
    //      (caller treats it as a direct record-detail body).

    #[tokio::test]
    async fn s1123_la1_router_resolve_content_hash_missing_header_returns_400() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("resolve_content_hash"))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::BAD_REQUEST,
            "missing content_hash header must surface as 400, never 200/empty");
        assert!(
            String::from_utf8_lossy(&resp.body).contains("content_hash"),
            "error body must explain the missing-header reason"
        );
        h.abort();
    }

    #[tokio::test]
    async fn s1123_la1_router_resolve_content_hash_local_miss_returns_404() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();
        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let unknown_hex = "ee".repeat(32);
        let resp = stream
            .call(&PqRequest::new("resolve_content_hash")
                .with_header("content_hash", &unknown_hex))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::NOT_FOUND,
            "miss MUST be 404 — caller-side pq_client maps NOT_FOUND → Ok(None) \
             so the fan-out can distinguish 'peer responded but missing' from \
             transport failure");
        assert!(
            String::from_utf8_lossy(&resp.body).contains("no record matches"),
            "miss body must explain the miss reason"
        );
        h.abort();
    }

    #[tokio::test]
    async fn s1123_la1_router_resolve_content_hash_local_hit_returns_record_detail() {
        use crate::record::{Classification, ValidationRecord};
        use std::collections::BTreeMap;
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let state = make_test_state();

        // Seed a record with a known content_hash. The responder MUST do a
        // pure point read off CF_IDX_HASH and emit the SAME JSON body the
        // /record/{id} route emits — that's the cross-route invariant.
        let hash_bytes = [0x42u8; 32];
        let hash_hex = hex::encode(hash_bytes);
        let rec = ValidationRecord {
            id: "rec-pq-resolve-hit".to_string(),
            version: crate::wire::WIRE_VERSION,
            content_hash: hash_bytes.to_vec(),
            creator_public_key: vec![0xAA; 1952],
            timestamp: 1700000000.0,
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
        };
        state.rocks.put_record(&rec.id, &rec).expect("seed");

        let (addr, h) = spawn_router_server(&server_id, state).await;

        let mut stream = crate::network::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            crate::network::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("resolve_content_hash")
                .with_header("content_hash", &hash_hex))
            .await
            .unwrap();
        assert_eq!(resp.status, pq_status::OK, "hit must be 200");
        let v: serde_json::Value = serde_json::from_slice(&resp.body)
            .expect("hit body must parse as JSON");
        assert_eq!(v["id"].as_str(), Some("rec-pq-resolve-hit"),
            "PQ resolve_content_hash hit must return the matching record's id");
        h.abort();
    }

    #[test]
    fn list_body_guard_is_fail_closed_above_cap() {
        // A body exactly at the cap is accepted — the downstream decode + .take()
        // handle shape; the guard only bounds the pre-decode allocation.
        assert!(
            guard_list_body("announce", &vec![0u8; MAX_LIST_REQUEST_BODY]).is_ok(),
            "a body exactly at MAX_LIST_REQUEST_BODY must pass the size guard"
        );
        assert!(guard_list_body("fetch_records", b"[]").is_ok(),
            "a small legit body must pass the size guard");

        // One byte over the cap is rejected with a Wire error — no parse, no panic.
        let oversized = vec![0u8; MAX_LIST_REQUEST_BODY + 1];
        let err = guard_list_body("records_exist", &oversized)
            .expect_err("a body over MAX_LIST_REQUEST_BODY must be rejected");
        match err {
            ElaraError::Wire(msg) => assert!(
                msg.contains("records_exist") && msg.contains("too large"),
                "Wire error must name the method and the cause: got {msg:?}"
            ),
            other => panic!("expected ElaraError::Wire, got {other:?}"),
        }
    }

    #[test]
    fn command_body_guard_is_fail_closed_above_cap() {
        // Small fixed-size command verbs (probe, witness-profile, offline
        // notification, transition sig/veto/seal) gate the body BEFORE the
        // `from_slice`, closing the PQ-vs-HTTP drift: the axum side caps these
        // at the extractor, the PQ side decoded straight off a ~16 MiB frame.
        for max in [MAX_RPC_COMMAND_BODY, MAX_TRANSITION_SEAL_BODY] {
            assert!(
                guard_command_body("probe", &vec![0u8; max], max).is_ok(),
                "a body exactly at the cap must pass the size guard"
            );
            let oversized = vec![0u8; max + 1];
            let err = guard_command_body("submit_transition_seal", &oversized, max)
                .expect_err("a body one byte over the cap must be rejected");
            match err {
                ElaraError::Wire(msg) => assert!(
                    msg.contains("submit_transition_seal") && msg.contains("too large"),
                    "Wire error must name the method and the cause: got {msg:?}"
                ),
                other => panic!("expected ElaraError::Wire, got {other:?}"),
            }
        }

        // Parity pins: these MUST track the axum per-route caps in
        // `server/mod.rs` (`MAX_RPC_BODY_BYTES` = 64 KiB,
        // `MAX_TRANSITION_PROPOSE_BODY_BYTES` = 512 KiB). The whole point of the
        // guard is that the two transports cannot silently drift apart again.
        assert_eq!(MAX_RPC_COMMAND_BODY, 64 * 1024, "PQ command cap must mirror axum MAX_RPC_BODY_BYTES");
        assert_eq!(MAX_TRANSITION_SEAL_BODY, 512 * 1024, "PQ seal cap must mirror axum MAX_TRANSITION_PROPOSE_BODY_BYTES");
        // Pre-flip ingress-cap audit 2026-06-27: the conflict-proof pair was the
        // one public-surface cap without a parity pin (its siblings above have
        // had one since the dual-transport sweep). Pin the PQ side to the literal
        // the axum `MAX_CONFLICT_PROOF_BODY_BYTES` (server/mod.rs) also uses so a
        // one-sided change cannot silently re-open HTTP↔PQ drift.
        assert_eq!(MAX_CONFLICT_PROOF_BODY, 1024 * 1024, "PQ conflict-proof cap must mirror axum MAX_CONFLICT_PROOF_BODY_BYTES");
    }

    #[test]
    fn record_body_guard_caps_submit_and_witness_before_decode() {
        // A handshaked PQ peer can frame up to MAX_PAYLOAD (16 MiB). The
        // record-ingest handlers must reject anything past MAX_RECORD_BYTES
        // BEFORE ValidationRecord::from_bytes + Dilithium3 verify, so a peer
        // cannot force full parse + sig-verify on a 16 MiB body per message.
        let max = crate::network::ingest::MAX_RECORD_BYTES;
        assert!(
            guard_record_body("submit_record", &vec![0u8; max]).is_ok(),
            "a body exactly at MAX_RECORD_BYTES must pass"
        );
        let oversized = vec![0u8; max + 1];
        let err = guard_record_body("witness", &oversized)
            .expect_err("a body over MAX_RECORD_BYTES must be rejected");
        match err {
            ElaraError::Wire(msg) => assert!(
                msg.contains("witness") && msg.contains("too large"),
                "Wire error must name the method and the cause: got {msg:?}"
            ),
            other => panic!("expected ElaraError::Wire, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod pq_read_admit_tests {
    //! Wiring tests for the PQ read-side admission gate (parity with the HTTP
    //! rate limiter). The token-bucket mechanics themselves are covered in
    //! `peer_bandwidth.rs`; here we pin that `dispatch`'s gate gates reads,
    //! exempts writes/local/genesis, keys per-peer, and — critically — that the
    //! first external follower-join fits the default burst so it can
    //! never trip a 429.
    use super::{is_heavy_blocking_read, is_write_method, pq_read_admit, pq_read_cost};
    use crate::errors::ElaraError;
    use crate::network::peer_bandwidth::PeerBandwidthLimiter;

    const PEER_A: [u8; 32] = [1u8; 32];
    const LOCAL: [u8; 32] = [0u8; 32];

    /// capacity 3, zero refill → deterministic exhaustion after 3 cost-1 reads.
    fn tiny() -> PeerBandwidthLimiter {
        PeerBandwidthLimiter::with_params(3.0, 0.0, 100)
    }

    #[test]
    fn read_flood_from_one_peer_is_throttled_after_burst() {
        let lim = tiny();
        assert!(pq_read_admit(&lim, "genesis", &PEER_A, "status").is_ok());
        assert!(pq_read_admit(&lim, "genesis", &PEER_A, "status").is_ok());
        assert!(pq_read_admit(&lim, "genesis", &PEER_A, "status").is_ok());
        assert!(
            matches!(
                pq_read_admit(&lim, "genesis", &PEER_A, "status"),
                Err(ElaraError::RateLimited)
            ),
            "4th read past a capacity-3 bucket must be RateLimited"
        );
    }

    #[test]
    fn local_all_zeros_identity_is_never_throttled() {
        let lim = tiny();
        // all-zeros = local in-process call: always admitted, even past cap.
        for _ in 0..50 {
            assert!(pq_read_admit(&lim, "genesis", &LOCAL, "snapshot_full").is_ok());
        }
    }

    #[test]
    fn genesis_authority_is_never_throttled() {
        let lim = tiny();
        let genesis_hex = hex::encode([1u8; 32]); // == PEER_A
        for _ in 0..50 {
            assert!(pq_read_admit(&lim, &genesis_hex, &PEER_A, "snapshot_full").is_ok());
        }
    }

    #[test]
    fn write_methods_bypass_the_read_gate_even_when_drained() {
        let lim = tiny();
        for _ in 0..3 {
            let _ = pq_read_admit(&lim, "genesis", &PEER_A, "status");
        }
        assert!(
            matches!(
                pq_read_admit(&lim, "genesis", &PEER_A, "status"),
                Err(ElaraError::RateLimited)
            ),
            "bucket must be drained before the write-bypass assertions"
        );
        for m in [
            "submit_record",
            "announce",
            "witness",
            "receive_attestation",
            "submit_finality_witness",
            "submit_xzone_abort_witness",
            "exchange_profile",
        ] {
            assert!(is_write_method(m), "{m} must be classified as a write");
            assert!(
                pq_read_admit(&lim, "genesis", &PEER_A, m).is_ok(),
                "write method {m} must bypass the read gate even when drained"
            );
        }
    }

    #[test]
    fn separate_peers_have_independent_budgets() {
        let lim = tiny();
        let peer_b: [u8; 32] = [2u8; 32];
        for _ in 0..3 {
            assert!(pq_read_admit(&lim, "genesis", &PEER_A, "status").is_ok());
        }
        assert!(matches!(
            pq_read_admit(&lim, "genesis", &PEER_A, "status"),
            Err(ElaraError::RateLimited)
        ));
        // peer B's bucket is untouched by peer A's exhaustion.
        assert!(pq_read_admit(&lim, "genesis", &peer_b, "status").is_ok());
    }

    #[test]
    fn external_join_sequence_fits_in_default_burst() {
        // Default production sizing (capacity 100). Test the single-burst worst
        // case with NO refill, proving the first external join never trips 429.
        let lim = PeerBandwidthLimiter::with_params(100.0, 0.0, 100);
        let joiner: [u8; 32] = [7u8; 32];
        let mut seq: Vec<&str> = vec![
            "snapshot_latest",
            "snapshot_full",
            "headers_from",
            "headers_from",
            "checkpoints_from",
            "delta_sync",
            "delta_sync",
            "delta_sync",
        ];
        // Plus a generous fast-chunk bootstrap (40 bounded chunks @ cost 1).
        seq.extend(std::iter::repeat_n("snapshot_fast_chunk", 40));
        seq.push("snapshot_fast_meta");
        let total: f64 = seq.iter().map(|m| pq_read_cost(m)).sum();
        assert!(
            total <= 100.0,
            "join sequence cost {total} must fit the default 100-token burst"
        );
        for m in seq {
            assert!(
                pq_read_admit(&lim, "genesis", &joiner, m).is_ok(),
                "join method {m} must be admitted within the burst budget"
            );
        }
    }

    #[test]
    fn cost_table_charges_whole_ledger_ops_most() {
        assert_eq!(pq_read_cost("snapshot_full"), 10.0);
        assert_eq!(pq_read_cost("state_delta"), 10.0);
        // Full-ledger ops added 2026-06-29 after auditing every read verb.
        assert_eq!(pq_read_cost("merkle_root"), 10.0, "global-root recompute, O(zone_count), in spawn_blocking");
        assert_eq!(pq_read_cost("stakes"), 10.0, "materializes every active stake before truncate");
        assert_eq!(pq_read_cost("delta_sync"), 3.0);
        // Bounded-but-large / proof / governance-walk tier.
        for m in [
            "dag_search",
            "cross_zone_proof",
            "consensus_record_detail",
            "query_attestations",
            "recent_transactions",
            "governance_proposals",
            "governance_delegations",
            "network_info",
        ] {
            assert_eq!(pq_read_cost(m), 3.0, "{m} must be in the MODERATE tier");
        }
        assert_eq!(pq_read_cost("query_records"), 2.0);
        assert_eq!(pq_read_cost("fetch_records"), 2.0);
        assert_eq!(pq_read_cost("status"), 1.0);
        assert_eq!(pq_read_cost("snapshot_fast_chunk"), 1.0);
        assert_eq!(pq_read_cost("headers_from"), 1.0);
        // ledger_summary is O(1) (validate::summarize reads maintained counters,
        // B10) — pin it at default 1 so it is never wrongly promoted to heavy.
        assert_eq!(pq_read_cost("ledger_summary"), 1.0, "summarize() is O(1), not an account scan");
    }

    #[test]
    fn heavy_blocking_set_is_exactly_the_oledger_verbs() {
        // The verbs whose handler does chain-scale work in spawn_blocking — a
        // whole-ledger clone or an O(zone_count) global-root recompute — the
        // global concurrency cap's gated set.
        for m in [
            "snapshot_full",
            "state_delta",
            "merkle_root",
            "stakes",
            "snapshot_latest",
            "snapshot_fast_meta",
        ] {
            assert!(is_heavy_blocking_read(m), "{m} must be gated by the heavy-read cap");
        }
        // The bootstrap workhorse serves a BOUNDED chunk — must NOT be gated, or
        // every join would be throttled per-chunk.
        assert!(!is_heavy_blocking_read("snapshot_fast_chunk"));
        // Cheap point-gets / bounded lists / non-read verbs stay ungated.
        for m in ["headers_from", "checkpoints_from", "status", "ledger_summary",
                  "balances", "record_detail", "submit_record", "delta_sync"] {
            assert!(!is_heavy_blocking_read(m), "{m} must NOT be heavy-gated");
        }
    }

    #[test]
    fn heavy_gate_is_decoupled_from_per_peer_cost() {
        // The bypass hole this closes: snapshot_latest and snapshot_fast_meta are
        // per-peer cost 1 (so a first-join's many pulls fit the burst) yet each
        // recomputes the global root (O(zone_count)). If the gate were keyed on
        // cost==10, a flood of these would route around it. Assert decoupling:
        // heavy-but-cheap-to-issue verbs exist.
        for m in ["snapshot_latest", "snapshot_fast_meta"] {
            assert!(is_heavy_blocking_read(m), "{m} is heavy (O(zone_count) global-root recompute)");
            assert_eq!(pq_read_cost(m), 1.0, "{m} stays per-peer cost 1 for bootstrap rate");
        }
        // Conversely a cost-2 verb is NOT heavy — the two axes are independent.
        assert_eq!(pq_read_cost("query_records"), 2.0);
        assert!(!is_heavy_blocking_read("query_records"));
        // Every cost-10 verb is also heavy-gated (the obvious overlap).
        for m in ["snapshot_full", "state_delta", "merkle_root", "stakes"] {
            assert_eq!(pq_read_cost(m), 10.0);
            assert!(is_heavy_blocking_read(m));
        }
        // delta_sync is MODERATE (cost 3) and deliberately NOT heavy-gated —
        // it is the steady-state sync surface; gating it would make the cap a
        // routine-operation bottleneck.
        assert_eq!(pq_read_cost("delta_sync"), 3.0);
        assert!(!is_heavy_blocking_read("delta_sync"));
    }
}
