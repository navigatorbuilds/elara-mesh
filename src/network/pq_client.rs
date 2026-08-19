//! Post-quantum node-to-node client — parallel of `NodeClient` over `PqStream`.
//!
//! This is the client half of Phase 4 Stage 4B.2. Every method mirrors the
//! matching method on `NodeClient` in `client.rs`, but instead of reqwest +
//! rustls it uses a freshly handshaken `PqStream` per call. Request bodies
//! and response shapes are identical — JSON, hex-encoded wire bytes, etc. —
//! so the server-side router (Stage 4B.2-server) only has to translate
//! method strings to the same handlers the HTTP routes already call.
//!
//! # Addressing
//!
//! The HTTP client takes `base_url: &str` ("http://host:port"). This client
//! takes `peer_addr: &str` ("host:port") — raw TCP. The difference is load-
//! bearing: a URL implies a transport (HTTP/HTTPS), a socket addr doesn't.
//!
//! # Identity pinning
//!
//! Every call consults the shared `PeerIdentityStore`:
//! - First contact with an unknown peer: TOFU. After the handshake
//!   succeeds, the observed hash is pinned.
//! - Subsequent contacts: Pinned(hash). If the peer's identity doesn't
//!   match, the handshake itself aborts and the call returns `Network`.
//!
//! # Connection reuse
//!
//! Each `PqNodeClient` holds a per-peer pool of idle [`PqStream`]s
//! (Stage 4B.2d). The first call to a peer handshakes; subsequent
//! calls reuse the cached stream and pay only one round-trip + AEAD
//! cost. If reuse fails for any reason (peer-closed, AEAD, frame, IO,
//! timeout) the stream is dropped and the call transparently falls
//! back to a fresh handshake — same observable behavior as the old
//! per-call-handshake path. Pool is bounded at [`MAX_POOL_ENTRIES`]
//! peers; concurrent calls to the same peer serialize on a per-slot
//! mutex (acceptable — gossip already iterates peers sequentially per
//! cycle).
//!
//! # Method names
//!
//! Stable lowercase snake_case. The server router matches on these:
//!
//! - `ping`, `status`
//! - `submit_record`, `query_records`, `announce`, `fetch_records`
//! - `merkle_root`, `delta_sync`, `find_node`, `witness`
//! - `snapshot_latest`, `snapshot_full`, `snapshot_fast_meta`, `snapshot_fast_chunk`

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use serde::Deserialize;
#[cfg(test)]
use serde::Serialize;
use tokio::sync::Mutex as AsyncMutex;

use crate::errors::{ElaraError, Result};

use super::pq_transport::{
    pq_dial_with_admission, status, AdmissionContext, PeerIdentityStore,
    PqRequest, PqResponse, PqStream,
};

/// Per-peer pool entry. Holds at most one idle PqStream plus a per-slot
/// async mutex to serialize concurrent RPCs to the same peer.
type PoolSlot = Arc<AsyncMutex<Option<PqStream>>>;

/// PQ-transport equivalent of `NodeClient`. Cheap to clone — the keypair,
/// pin store, and connection pool are all held behind `Arc`s.
#[derive(Clone)]
pub struct PqNodeClient {
    my_dil_pk: Arc<Vec<u8>>,
    my_dil_sk: Arc<Vec<u8>>,
    pins: Arc<PeerIdentityStore>,
    /// Per-peer idle-connection cache. Outer mutex only guards
    /// lookup/creation — never held across await.
    pool: Arc<StdMutex<HashMap<String, PoolSlot>>>,
    /// REALMS P1 slice (b3): realm admission context presented when a
    /// dialed responder challenges us (its realm is not Open). `None`
    /// (constructor default, all tests) = pre-realm behavior; the
    /// production node attaches `network_id` + its membership cert at
    /// NodeState construction.
    admission: Option<AdmissionContext>,
    /// Per-request `x-elara-network-id` attached to client submits
    /// (`submit_record`). `None` (constructor default) = omit the header, so
    /// the node applies its `"testnet"` backward-compat default. When an
    /// `AdmissionContext` is set its `network_id` is authoritative and wins
    /// over this field (see `effective_network_id`) — the realm cert is the
    /// proven source of truth, so the on-wire header can never contradict it.
    network_id: Option<String>,
}

/// Default per-call timeout. Covers TCP connect + PQ handshake + RPC round-trip.
/// Chosen to match the existing reqwest defaults (long tail) without being
/// unbounded.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Soft ceiling on the number of per-peer pool entries. When exceeded, the
/// oldest (first-inserted) entry is dropped on next insertion. Generous for
/// testnet (≤10 peers) and safe for early mainnet — mainnet-scale networks
/// can raise this or add LRU eviction.
pub const MAX_POOL_ENTRIES: usize = 64;

// Compile-time invariant: 0 would disable pooling entirely. Surface that
// as a build error, not a runtime test failure.
const _: () = assert!(
    MAX_POOL_ENTRIES > 0,
    "MAX_POOL_ENTRIES must be > 0 — 0 would disable connection pooling entirely"
);

/// Headers carried on gossip-flavored PQ requests so receivers can implement
/// TTL (`hops`), peer attribution (`sender_identity_hash`), trace correlation
/// (`trace_id`), and network/version gating (`network_id`, `protocol_version`).
///
/// Bundled into a parameter struct because every `*_gossip` method takes the
/// same set, and call sites used to pass 5–6 individual args. Borrowed
/// fields stay borrowed — no allocation, no clone of identity strings on the
/// hot push path.
pub struct GossipHeaders<'a> {
    pub hops: u8,
    pub sender_identity_hash: &'a str,
    pub trace_id: Option<&'a str>,
    pub network_id: &'a str,
    pub protocol_version: u32,
}

impl<'a> GossipHeaders<'a> {
    /// Apply the gossip headers to a `PqRequest`. `trace_id` is set only when
    /// present so receivers don't see an empty header that the router would
    /// then have to special-case.
    fn apply(&self, mut req: PqRequest) -> PqRequest {
        req = req
            .with_header("x-elara-hops", self.hops.to_string())
            .with_header("x-elara-sender", self.sender_identity_hash)
            .with_header("x-elara-network-id", self.network_id)
            .with_header("x-elara-protocol-version", self.protocol_version.to_string());
        if let Some(tid) = self.trace_id {
            req = req.with_header("x-elara-trace-id", tid);
        }
        req
    }
}

impl PqNodeClient {
    pub fn new(
        my_dil_pk: Vec<u8>,
        my_dil_sk: Vec<u8>,
        pins: Arc<PeerIdentityStore>,
    ) -> Self {
        Self {
            my_dil_pk: Arc::new(my_dil_pk),
            my_dil_sk: Arc::new(my_dil_sk),
            pins,
            pool: Arc::new(StdMutex::new(HashMap::new())),
            admission: None,
            network_id: None,
        }
    }

    /// REALMS P1 slice (b3): attach the realm admission context every
    /// outbound dial presents when challenged. Production wiring lives at
    /// `NodeState::new` — tests and tools that skip this keep `None`
    /// (pre-realm dial behavior, only viable against Open responders).
    pub fn with_admission_context(mut self, ctx: AdmissionContext) -> Self {
        self.admission = Some(ctx);
        self
    }

    /// Set the per-request network id (realm) attached to client record
    /// submissions. Operators source it from `ELARA_NETWORK_ID` / a
    /// `--network` flag. Without it, `submit_record` omits the header and the
    /// node defaults to `"testnet"` — so writes to a node running any other
    /// `network_id` are rejected with `network_mismatch`. When an
    /// `AdmissionContext` is also set, the cert's `network_id` is
    /// authoritative and overrides this value (`effective_network_id`).
    pub fn with_network_id(mut self, network_id: impl Into<String>) -> Self {
        self.network_id = Some(network_id.into());
        self
    }

    /// The network id to stamp on outbound client submits. The admission
    /// cert's `network_id` wins when present (cryptographically-proven realm
    /// membership is the single source of truth, so a divergent
    /// `with_network_id` can never reach the wire); otherwise the explicitly
    /// configured `network_id`; otherwise `None` (omit header → node default).
    fn effective_network_id(&self) -> Option<&str> {
        self.admission
            .as_ref()
            .map(|a| a.network_id.as_str())
            .or(self.network_id.as_deref())
    }

    /// Build the `submit_record` PQ request, attaching the network/version
    /// gating headers the node ingest gate checks (`routes/core.rs` +
    /// `pq_transport/router.rs`). `x-elara-protocol-version` is always sent
    /// (a static property of this binary, strictly safer than the missing→0
    /// default the gate would otherwise see); `x-elara-network-id` is sent
    /// only when configured, preserving the node's `"testnet"` default for
    /// unconfigured clients. Deliberately does NOT set `x-elara-sender` —
    /// that would route the submit through the gossip-push profile gate.
    fn build_submit_record_request(&self, wire_bytes: &[u8]) -> PqRequest {
        let mut req = PqRequest::new("submit_record")
            .with_body(wire_bytes.to_vec())
            .with_header(
                "x-elara-protocol-version",
                crate::network::config::PROTOCOL_VERSION.to_string(),
            );
        if let Some(network_id) = self.effective_network_id() {
            req = req.with_header("x-elara-network-id", network_id);
        }
        req
    }

    /// Reference to the underlying pin store (admin / debug).
    pub fn pins(&self) -> &PeerIdentityStore {
        &self.pins
    }

    /// Number of peers currently holding a pooled connection slot. Admin / test.
    pub fn pool_size(&self) -> usize {
        self.pool
            .lock()
            .map(|p| p.len())
            .unwrap_or(0)
    }

    /// Drop the cached stream for `peer_addr`, if any. The slot itself stays
    /// so future calls still serialize through the same per-peer mutex.
    /// Used by reputation / backoff code that wants to force a fresh handshake.
    pub async fn drop_pooled(&self, peer_addr: &str) {
        let slot = {
            let map = match self.pool.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            map.get(peer_addr).cloned()
        };
        if let Some(slot) = slot {
            let mut guard = slot.lock().await;
            *guard = None;
        }
    }

    // ── Pool management ───────────────────────────────────────────────────

    /// Test-only accessor that exposes the same per-peer slot the call
    /// path uses. Lets tests hold the slot to simulate a long-running heal
    /// cycle without spinning up a real PQ listener.
    #[cfg(test)]
    pub(crate) fn slot_for_test(&self, peer_addr: &str) -> PoolSlot {
        self.slot_for(peer_addr)
    }

    /// Acquire the per-peer slot, creating it on first contact. Performs
    /// soft-cap eviction when inserting into a full pool.
    fn slot_for(&self, peer_addr: &str) -> PoolSlot {
        let mut map = match self.pool.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let Some(slot) = map.get(peer_addr) {
            return slot.clone();
        }
        // Cap enforcement: drop one arbitrary entry before inserting. We
        // deliberately don't LRU — testnet will never hit the cap; mainnet
        // wants a real policy (separate work).
        if map.len() >= MAX_POOL_ENTRIES {
            if let Some(victim) = map.keys().next().cloned() {
                map.remove(&victim);
            }
        }
        let slot: PoolSlot = Arc::new(AsyncMutex::new(None));
        map.insert(peer_addr.to_string(), slot.clone());
        slot
    }

    // ── Core round-trip ───────────────────────────────────────────────────

    /// Run `req` against `peer_addr`, preferring a pooled stream.
    ///
    /// Path:
    /// 1. Acquire the per-peer slot (serializes concurrent RPCs to the same peer).
    /// 2. If a cached stream exists, try it. On any error, drop the stream
    ///    and fall through.
    /// 3. Handshake a new stream, call, cache it on success.
    ///
    /// TOFU happens on the handshake; subsequent pooled reuses don't touch
    /// the pin store (pin was verified at handshake time; no way the same
    /// open stream is to a different peer mid-session).
    async fn call(&self, peer_addr: &str, req: &PqRequest) -> Result<PqResponse> {
        self.call_inner(peer_addr, req, None).await
    }

    /// Same as [`call`] but bounds the wait on the per-peer slot mutex.
    /// If the slot is held longer than `lock_timeout`, returns
    /// `ElaraError::Network("slot busy")` immediately rather than queueing.
    ///
    /// Use this from ops/monitoring endpoints (e.g. `/convergence`) so a
    /// long-running heal cycle on the same peer doesn't hang the operator's
    /// curl. The default unbounded `call()` remains the right choice for
    /// gossip / sync paths that *must* serialize per peer.
    pub async fn call_with_lock_timeout(
        &self,
        peer_addr: &str,
        req: &PqRequest,
        lock_timeout: Duration,
    ) -> Result<PqResponse> {
        self.call_inner(peer_addr, req, Some(lock_timeout)).await
    }

    async fn call_inner(
        &self,
        peer_addr: &str,
        req: &PqRequest,
        lock_timeout: Option<Duration>,
    ) -> Result<PqResponse> {
        let slot = self.slot_for(peer_addr);
        let mut guard = match lock_timeout {
            Some(d) => match tokio::time::timeout(d, slot.lock()).await {
                Ok(g) => g,
                Err(_) => {
                    return Err(ElaraError::Network(format!(
                        "pq_client slot busy for {peer_addr} after {}ms",
                        d.as_millis()
                    )));
                }
            },
            None => slot.lock().await,
        };

        // ── 1. Try cached stream ─────────────────────────────────────────
        if let Some(mut stream) = guard.take() {
            // Revalidate: the pin store may have been rotated since the
            // handshake (admin forget + repin). If the cached stream's
            // peer hash no longer matches the current expectation, drop it
            // so the fresh-handshake path below re-enforces the new pin.
            let pin_still_matches = match self.pins.expectation_for(peer_addr) {
                super::pq_transport::PeerExpectation::Pinned(expected) => {
                    stream.peer_identity_hash() == expected
                }
                // Tofu means pin was forgotten — our cached stream points at
                // a now-unpinned peer; force fresh handshake to re-TOFU.
                super::pq_transport::PeerExpectation::Tofu => false,
            };
            if pin_still_matches {
                match tokio::time::timeout(DEFAULT_CALL_TIMEOUT, stream.call(req)).await {
                    Ok(Ok(resp)) => {
                        // Reuse worked — park back in the slot.
                        *guard = Some(stream);
                        return Ok(resp);
                    }
                    // Drop the stream on ANY failure — timeout, peer-closed,
                    // AEAD, frame. Fall through to a fresh handshake.
                    _ => {
                        drop(stream);
                    }
                }
            } else {
                drop(stream);
            }
        }

        // ── 2. Fresh handshake ───────────────────────────────────────────
        let expectation = self.pins.expectation_for(peer_addr);
        let mut stream = tokio::time::timeout(
            DEFAULT_CALL_TIMEOUT,
            pq_dial_with_admission(
                peer_addr,
                (*self.my_dil_pk).clone(),
                (*self.my_dil_sk).clone(),
                expectation,
                self.admission.clone(),
            ),
        )
        .await
        .map_err(|_| ElaraError::Network(format!("pq_dial {peer_addr} timed out")))?
        .map_err(|e| ElaraError::Network(format!("pq_dial {peer_addr}: {e}")))?;

        // On successful handshake we know the peer's identity hash. Pin it
        // (TOFU) or refresh last_seen (match). Pin mismatch is impossible
        // here — pq_dial would have errored on expectation mismatch — but
        // we still call pin_or_verify so TOFU gets persisted.
        let peer_hash = stream.peer_identity_hash();
        if let Err(e) = self.pins.pin_or_verify(peer_addr, peer_hash) {
            return Err(ElaraError::Network(format!(
                "pin store rejected {peer_addr}: {e}"
            )));
        }

        let resp = tokio::time::timeout(DEFAULT_CALL_TIMEOUT, stream.call(req))
            .await
            .map_err(|_| ElaraError::Network(format!("rpc {peer_addr} timed out")))?
            .map_err(|e| ElaraError::Network(format!("rpc {peer_addr}: {e}")))?;

        // Cache the stream for reuse. If the caller wanted a single-shot
        // behaviour (e.g., known-bad peer) they can drop_pooled() after.
        *guard = Some(stream);

        Ok(resp)
    }

    fn ensure_ok(resp: PqResponse, what: &str) -> Result<Vec<u8>> {
        if !resp.is_success() {
            return Err(ElaraError::Network(format!(
                "{what} returned status {}",
                resp.status
            )));
        }
        Ok(resp.body)
    }

    fn json_body<T: for<'de> Deserialize<'de>>(body: &[u8], what: &str) -> Result<T> {
        serde_json::from_slice(body)
            .map_err(|e| ElaraError::Network(format!("{what} parse: {e}")))
    }

    // ── Mirrored NodeClient API ───────────────────────────────────────────

    pub async fn ping(&self, peer_addr: &str) -> bool {
        let req = PqRequest::new("ping");
        match self.call(peer_addr, &req).await {
            Ok(resp) => resp.is_success(),
            Err(_) => false,
        }
    }

    pub async fn get_status(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("status")).await?;
        let body = Self::ensure_ok(resp, "status")?;
        Self::json_body(&body, "status")
    }

    /// Lock-bounded variant of [`get_status`] for ops endpoints — see
    /// [`call_with_lock_timeout`].
    pub async fn get_status_with_lock_timeout(
        &self,
        peer_addr: &str,
        lock_timeout: Duration,
    ) -> Result<serde_json::Value> {
        let resp = self
            .call_with_lock_timeout(peer_addr, &PqRequest::new("status"), lock_timeout)
            .await?;
        let body = Self::ensure_ok(resp, "status")?;
        Self::json_body(&body, "status")
    }

    /// AUDIT-9 Milestone B / B2: symmetric peer-to-peer witness-profile
    /// exchange over the already-authenticated PQ channel.
    ///
    /// - Sends `own_profile` (if any) in the request body so the server can
    ///   register it under the session-authenticated identity hash — closes
    ///   the coverage gap for NAT'd nodes that only ever connect outbound.
    /// - Returns `(identity_hash, Some(profile))` when the peer has one
    ///   configured, `(identity_hash, None)` when the peer runs without a
    ///   profile, and `Err(NotFound)` / `Err(Network)` when the peer is on
    ///   a pre-Milestone-B binary that doesn't know the verb (router returns
    ///   404) — callers should log at debug and move on, not retry.
    pub async fn exchange_profile(
        &self,
        peer_addr: &str,
        own_profile: Option<&crate::network::consensus::WitnessProfile>,
    ) -> Result<(String, Option<crate::network::consensus::WitnessProfile>)> {
        let body_bytes = match own_profile {
            Some(p) => serde_json::to_vec(&serde_json::json!({
                "profile": {
                    "organization": p.organization,
                    "subnet": p.subnet,
                    "geo_zone": p.geo_zone,
                }
            })).unwrap_or_default(),
            None => serde_json::to_vec(&serde_json::json!({ "profile": null }))
                .unwrap_or_default(),
        };
        let req = PqRequest::new("exchange_profile").with_body(body_bytes);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "exchange_profile")?;
        let v: serde_json::Value = Self::json_body(&body, "exchange_profile")?;
        let identity_hash = v["identity_hash"]
            .as_str()
            .unwrap_or("")
            .to_string();
        if identity_hash.is_empty() {
            return Err(ElaraError::Network(
                "exchange_profile: missing identity_hash".into(),
            ));
        }
        let profile = match v.get("profile") {
            Some(serde_json::Value::Null) | None => None,
            Some(obj) => {
                let organization = obj["organization"].as_str().unwrap_or("").to_string();
                if organization.is_empty() {
                    None
                } else {
                    Some(crate::network::consensus::WitnessProfile {
                        organization,
                        subnet: obj["subnet"].as_str().unwrap_or("").to_string(),
                        geo_zone: obj["geo_zone"].as_str().unwrap_or("").to_string(),
                    })
                }
            }
        };
        Ok((identity_hash, profile))
    }

    /// PQ counterpart of `GET /headers/from/{epoch}` — the light-client
    /// header sync path. Returns `{total, headers: [...]}` exactly as the
    /// axum endpoint does, so callers migrated off HTTPS parse the same
    /// JSON shape.
    ///
    /// `since` is required (epoch floor). `zone` and `limit` are
    /// optional; server default is 500, cap 2000.
    pub async fn headers_from(
        &self,
        peer_addr: &str,
        since: u64,
        zone: Option<&str>,
        limit: Option<usize>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("headers_from")
            .with_header("since", since.to_string());
        if let Some(z) = zone {
            req = req.with_header("zone", z);
        }
        if let Some(l) = limit {
            req = req.with_header("limit", l.to_string());
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "headers_from")?;
        Self::json_body(&body, "headers_from")
    }

    /// PQ counterpart of `GET /seal/progress/{id}` — account polling for
    /// streaming attestation progress. Returns the same JSON shape the
    /// HTTPS endpoint does: `{record_id, confirmation_level, seal_progress}`.
    pub async fn seal_progress(
        &self,
        peer_addr: &str,
        record_id: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("seal_progress")
            .with_header("record_id", record_id);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "seal_progress")?;
        Self::json_body(&body, "seal_progress")
    }

    /// PQ counterpart of `GET /record/{id}` — full record inspection including
    /// attestations, confirmation level, seal progress. Same JSON shape axum
    /// returns.
    pub async fn record_detail(
        &self,
        peer_addr: &str,
        record_id: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("record_detail")
            .with_header("record_id", record_id);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "record_detail")?;
        Self::json_body(&body, "record_detail")
    }

    /// PQ counterpart of `GET /proof/account/{identity}` — light-client
    /// account state proof. `identity` is the 32-byte hex identity hash.
    pub async fn account_proof(
        &self,
        peer_addr: &str,
        identity: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("account_proof")
            .with_header("identity", identity);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "account_proof")?;
        Self::json_body(&body, "account_proof")
    }

    /// PQ counterpart of `GET /proofs/cross-zone/{record_id}/{target_zone}`
    /// — Protocol §11.22.1 cross-zone membership proof.
    pub async fn cross_zone_proof(
        &self,
        peer_addr: &str,
        record_id: &str,
        target_zone: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("cross_zone_proof")
            .with_header("record_id", record_id)
            .with_header("target_zone", target_zone);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "cross_zone_proof")?;
        Self::json_body(&body, "cross_zone_proof")
    }

    /// PQ counterpart of `GET /balances[?identity=...]` — account balance
    /// poll. Pass `None` for a global list, `Some(id)` for a single account.
    pub async fn balances(
        &self,
        peer_addr: &str,
        identity: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("balances");
        if let Some(id) = identity {
            req = req.with_header("identity", id);
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "balances")?;
        Self::json_body(&body, "balances")
    }

    /// PQ counterpart of `GET /dag/tips` — DAG tip + root snapshot.
    pub async fn dag_tips(
        &self,
        peer_addr: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("dag_tips");
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "dag_tips")?;
        Self::json_body(&body, "dag_tips")
    }

    pub async fn submit_record(
        &self,
        peer_addr: &str,
        wire_bytes: &[u8],
    ) -> Result<serde_json::Value> {
        let req = self.build_submit_record_request(wire_bytes);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "submit_record")?;
        Self::json_body(&body, "submit_record")
    }

    /// Gossip-flavored `submit_record`: carries the `x-elara-*` headers the
    /// router honors (hops, sender, trace-id, network-id, protocol-version).
    ///
    /// Returns the raw `PqResponse` so the caller can distinguish success,
    /// rate-limited (429), and peer-level failures the same way the HTTP
    /// `push_single` does — status-code-driven, not just Ok/Err.
    pub async fn submit_record_gossip(
        &self,
        peer_addr: &str,
        wire_bytes: &[u8],
        headers: GossipHeaders<'_>,
    ) -> Result<PqResponse> {
        let req = headers.apply(
            PqRequest::new("submit_record").with_body(wire_bytes.to_vec()),
        );
        self.call(peer_addr, &req).await
    }

    /// Gossip-flavored attestation push. Mirrors the HTTP
    /// `POST /attestations` route. Body is the JSON `AttestationSubmit`
    /// payload the router expects (record_id, attestation, pubkey_hex,
    /// optional powas proof, hops).
    pub async fn receive_attestation_gossip(
        &self,
        peer_addr: &str,
        body_json: &[u8],
        headers: GossipHeaders<'_>,
    ) -> Result<PqResponse> {
        let req = headers.apply(
            PqRequest::new("receive_attestation").with_body(body_json.to_vec()),
        );
        self.call(peer_addr, &req).await
    }

    /// Gossip-flavored finality-witness push. Body is bincode-encoded
    /// `FinalityWitnessGossipBody { seal_id, seal_epoch, committee_hash,
    /// committee_size, witness }` — see router.rs `handle_submit_finality_witness`.
    /// Idempotent on (seal_id, witness_pk); divergent committee snapshots are
    /// silently dropped on the receiver and counted in
    /// `seal_finality_snapshot_mismatch_total`.
    pub async fn submit_finality_witness_gossip(
        &self,
        peer_addr: &str,
        body_bytes: &[u8],
        headers: GossipHeaders<'_>,
    ) -> Result<PqResponse> {
        let req = headers.apply(
            PqRequest::new("submit_finality_witness").with_body(body_bytes.to_vec()),
        );
        self.call(peer_addr, &req).await
    }

    /// Gap 2 sealed-abort P-3e: gossip-flavored abort-witness push. Body
    /// is JSON-encoded `XZoneAbortWitnessGossipBody { transfer_id,
    /// dest_zone, source_seal_epoch, committee_hash, committee_size,
    /// witness }` — see router.rs `handle_submit_xzone_abort_witness`.
    /// Idempotent on (transfer_id, witness_pk); divergent committee
    /// snapshots are silently dropped on the receiver and counted in
    /// `xzone_abort_snapshot_mismatch_total`.
    pub async fn submit_xzone_abort_witness_gossip(
        &self,
        peer_addr: &str,
        body_bytes: &[u8],
        headers: GossipHeaders<'_>,
    ) -> Result<PqResponse> {
        let req = headers.apply(
            PqRequest::new("submit_xzone_abort_witness").with_body(body_bytes.to_vec()),
        );
        self.call(peer_addr, &req).await
    }

    /// Gossip-flavored conflict-proof push. Mirrors the HTTP
    /// `POST /slot-conflicts` route. Body is the serialized ConflictProof
    /// JSON.
    pub async fn submit_conflict_proof_gossip(
        &self,
        peer_addr: &str,
        body_json: &[u8],
        headers: GossipHeaders<'_>,
    ) -> Result<PqResponse> {
        let req = headers.apply(
            PqRequest::new("receive_conflict_proof").with_body(body_json.to_vec()),
        );
        self.call(peer_addr, &req).await
    }

    /// Query attestations since a timestamp. Mirrors `GET /attestations`.
    /// Returns the raw JSON array body on success, or None for 404.
    pub async fn query_attestations_since(
        &self,
        peer_addr: &str,
        since: f64,
        limit: usize,
    ) -> Result<Option<serde_json::Value>> {
        let req = PqRequest::new("query_attestations")
            .with_header("since", since.to_string())
            .with_header("limit", limit.to_string());
        let resp = self.call(peer_addr, &req).await?;
        if resp.status == status::NOT_FOUND {
            return Ok(None);
        }
        let body = Self::ensure_ok(resp, "query_attestations")?;
        let v: serde_json::Value = Self::json_body(&body, "query_attestations")?;
        Ok(Some(v))
    }

    /// Query attestations for a specific record. Mirrors
    /// `GET /attestations?record_id=<id>`.
    pub async fn query_attestations_for_record(
        &self,
        peer_addr: &str,
        record_id: &str,
    ) -> Result<Option<serde_json::Value>> {
        let req = PqRequest::new("query_attestations")
            .with_header("record_id", record_id.to_string());
        let resp = self.call(peer_addr, &req).await?;
        if resp.status == status::NOT_FOUND {
            return Ok(None);
        }
        let body = Self::ensure_ok(resp, "query_attestations")?;
        let v: serde_json::Value = Self::json_body(&body, "query_attestations")?;
        Ok(Some(v))
    }

    pub async fn query_records(
        &self,
        peer_addr: &str,
        since: f64,
        limit: usize,
    ) -> Result<Vec<Vec<u8>>> {
        self.query_records_filtered(peer_addr, since, limit, None)
            .await
            .map(|(records, _)| records)
    }

    /// Cursor-paged variant surfacing the server's truncation signal. The
    /// returned bool is `true` when the server byte-budgeted the page below
    /// the requested `limit` (PQ single-frame cap, see `handle_query_records`)
    /// — the caller MUST then treat a short page as "more remains at this
    /// cursor", NOT as the end of the peer's history. `full_pull`'s tail
    /// check (`batch_len < page_size` → cursor reset) is the load-bearing
    /// consumer: without this signal a truncated page would falsely reset
    /// the sweep to timestamp 0 and the >budget region would never be
    /// crossed.
    pub async fn query_records_paged(
        &self,
        peer_addr: &str,
        since: f64,
        limit: usize,
    ) -> Result<(Vec<Vec<u8>>, bool)> {
        self.query_records_filtered(peer_addr, since, limit, None)
            .await
    }

    pub async fn query_records_filtered(
        &self,
        peer_addr: &str,
        since: f64,
        limit: usize,
        creator_pubkey_hex: Option<&str>,
    ) -> Result<(Vec<Vec<u8>>, bool)> {
        let mut req = PqRequest::new("query_records")
            .with_header("since", since.to_string())
            .with_header("limit", limit.to_string());
        if let Some(creator) = creator_pubkey_hex {
            req = req.with_header("creator", creator.to_string());
        }

        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "query_records")?;
        // Dual-shape response (same pattern as delta_sync): legacy servers and
        // untruncated pages are a bare array; a byte-budget-truncated page is
        // {"records": […], "has_more": true}. Absent field ⇒ not truncated.
        let parsed: serde_json::Value = Self::json_body(&body, "query_records")?;
        let (items, truncated): (Vec<String>, bool) =
            if let Some(records) = parsed.get("records").and_then(|r| r.as_array()) {
                (
                    records
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect(),
                    parsed
                        .get("has_more")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                )
            } else if let Some(arr) = parsed.as_array() {
                (
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect(),
                    false,
                )
            } else {
                return Err(ElaraError::Network(
                    "unexpected query_records response format".into(),
                ));
            };

        let records = items
            .iter()
            .map(|h| hex::decode(h).map_err(|e| ElaraError::Network(format!("bad hex: {e}"))))
            .collect::<Result<Vec<Vec<u8>>>>()?;
        Ok((records, truncated))
    }

    pub async fn announce(
        &self,
        peer_addr: &str,
        announcements: &[super::gossip::RecordAnnouncement],
    ) -> Result<Vec<String>> {
        let body_bytes = serde_json::to_vec(announcements)
            .map_err(|e| ElaraError::Network(format!("announce serialize: {e}")))?;
        let req = PqRequest::new("announce").with_body(body_bytes);
        let resp = self.call(peer_addr, &req).await?;

        if resp.status == status::NOT_FOUND {
            // Peer doesn't support announcements — treat all as wanted, mirror
            // NodeClient's fallback so the gossip caller falls back to full push.
            return Ok(announcements.iter().map(|a| a.record_id.clone()).collect());
        }
        let body = Self::ensure_ok(resp, "announce")?;
        let parsed: serde_json::Value = Self::json_body(&body, "announce")?;
        Ok(parsed["want"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default())
    }

    pub async fn fetch_records(
        &self,
        peer_addr: &str,
        ids: &[String],
    ) -> Result<Vec<Vec<u8>>> {
        let body_bytes = serde_json::to_vec(ids)
            .map_err(|e| ElaraError::Network(format!("fetch_records serialize: {e}")))?;
        let req = PqRequest::new("fetch_records").with_body(body_bytes);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "fetch_records")?;
        let hex_list: Vec<String> = Self::json_body(&body, "fetch_records")?;

        hex_list
            .iter()
            .map(|h| hex::decode(h).map_err(|e| ElaraError::Network(format!("bad hex: {e}"))))
            .collect()
    }

    /// Gap 6.4 slice 3b — lightweight presence probe used by the
    /// seal-replication reconciler.
    ///
    /// Sends a list of record ids; receives a same-length bitmap where
    /// `true` means the peer has the record persisted, `false` means
    /// it does not. Far cheaper than `fetch_records` because no record
    /// body is shipped — at mainnet seal cadences the bandwidth saved
    /// is multiplicative in K (replication factor).
    ///
    /// Capped at 256 ids per request server-side to bound work.
    pub async fn records_exist(
        &self,
        peer_addr: &str,
        ids: &[String],
    ) -> Result<Vec<bool>> {
        let body_bytes = serde_json::to_vec(ids)
            .map_err(|e| ElaraError::Network(format!("records_exist serialize: {e}")))?;
        let req = PqRequest::new("records_exist").with_body(body_bytes);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "records_exist")?;
        let bits: Vec<bool> = Self::json_body(&body, "records_exist")?;
        Ok(bits)
    }

    pub async fn get_merkle_root(&self, peer_addr: &str) -> Result<String> {
        let resp = self
            .call(peer_addr, &PqRequest::new("merkle_root"))
            .await?;
        let body = Self::ensure_ok(resp, "merkle_root")?;
        let data: serde_json::Value = Self::json_body(&body, "merkle_root")?;
        data["root"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ElaraError::Network("merkle_root missing 'root' field".into()))
    }

    /// Lock-bounded variant of [`get_merkle_root`] for ops endpoints — see
    /// [`call_with_lock_timeout`].
    pub async fn get_merkle_root_with_lock_timeout(
        &self,
        peer_addr: &str,
        lock_timeout: Duration,
    ) -> Result<String> {
        let resp = self
            .call_with_lock_timeout(peer_addr, &PqRequest::new("merkle_root"), lock_timeout)
            .await?;
        let body = Self::ensure_ok(resp, "merkle_root")?;
        let data: serde_json::Value = Self::json_body(&body, "merkle_root")?;
        data["root"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ElaraError::Network("merkle_root missing 'root' field".into()))
    }

    /// Identity Partitioning Phase D — peer on-miss PK fetch.
    ///
    /// Returns `Ok(Some(pk_bytes))` when the peer has the PK,
    /// `Ok(None)` when the peer responded but does not have it, or
    /// `Err(_)` for transport/decode failures (caller treats as
    /// `None` for the soft-fail path).
    ///
    /// Spec: internal design notes §3.3 + §4 Phase D.
    pub async fn get_identity_pk(
        &self,
        peer_addr: &str,
        identity_hash: &str,
    ) -> Result<Option<Vec<u8>>> {
        let req = PqRequest::new("identity_pk").with_header("identity_hash", identity_hash);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "identity_pk")?;
        let data: serde_json::Value = Self::json_body(&body, "identity_pk")?;
        match data.get("pk") {
            Some(serde_json::Value::String(hex_pk)) => hex::decode(hex_pk)
                .map(Some)
                .map_err(|e| ElaraError::Network(format!("identity_pk: bad hex: {e}"))),
            Some(serde_json::Value::Null) | None => Ok(None),
            Some(other) => Err(ElaraError::Network(format!(
                "identity_pk: unexpected pk shape: {other}"
            ))),
        }
    }

    /// §11.23 Layer A slice 1 — peer-relay for `/records/by-hash/{hash}`.
    /// Caller is `record_hash_fetcher::fetch_record_from_peers`; responder
    /// is `pq_transport/router.rs::handle_resolve_content_hash`.
    ///
    /// Returns `Ok(Some(body))` when the peer holds a record matching
    /// `content_hash` (body shape matches `/record/{id}`); `Ok(None)`
    /// when the peer responded with NOT_FOUND (genuine miss — record
    /// genuinely absent on that peer); `Err(_)` for transport/decode
    /// failures (caller logs and tries the next peer).
    ///
    /// `content_hash` must already be lowercase-hex-64; this method does
    /// NOT re-validate the shape.
    pub async fn get_record_by_hash(
        &self,
        peer_addr: &str,
        content_hash: &str,
    ) -> Result<Option<serde_json::Value>> {
        let req = PqRequest::new("resolve_content_hash")
            .with_header("content_hash", content_hash);
        let resp = self.call(peer_addr, &req).await?;
        if resp.status == crate::network::pq_transport::rpc::status::NOT_FOUND {
            return Ok(None);
        }
        let body = Self::ensure_ok(resp, "resolve_content_hash")?;
        let v: serde_json::Value = Self::json_body(&body, "resolve_content_hash")?;
        Ok(Some(v))
    }

    /// Paginated delta sync. Each loop iteration does its own handshake —
    /// expensive, and exactly why the connection pool is on the roadmap.
    ///
    /// `since` is a unix timestamp (f64); the server uses it to seek into
    /// CF_IDX_TIMESTAMP and bloom-test only records whose timestamp ≥ `since`.
    /// Pass 0.0 to request a full-history scan (server will still cap at its
    /// own MAX_SCAN — see `handle_delta_sync` in `pq_transport/router.rs`).
    /// The `since` parameter replaced an unbounded O(all_records) server
    /// scan that was the dominant pq_delta_sync timeout source (the RPC
    /// verb handler, not the handshake, was the bottleneck).
    /// Returns `(records, peer_total_missing)` — the second element is the
    /// peer's freshest `total_missing` report (how many records the peer's
    /// scan window says WE lack). Non-zero after the pull completes = a gap
    /// the bounded window/batching did not close this cycle; the caller
    /// persists it as the dag-gap gauge (R2-6b honest surface).
    /// Returns `(records, peer_missing_remaining, guard_tripped,
    /// cycle_exhausted)` — the two trailing bools are client-side cursor
    /// telemetry the CALLER counts (PqNodeClient is deliberately
    /// NodeState-free): `guard_tripped` = the server echoed a different
    /// cursor than sent or failed to advance the frontier (audit C6);
    /// `cycle_exhausted` = MAX_PAGES_PER_CYCLE bound with `has_more=true`
    /// (the cursor-path "still behind after a full cycle" signal).
    pub async fn delta_sync(
        &self,
        peer_addr: &str,
        bloom_bytes: &[u8],
        since: f64,
    ) -> Result<(Vec<Vec<u8>>, u64, bool, bool)> {
        let mut all_records: Vec<Vec<u8>> = Vec::new();
        let mut peer_total_missing: u64 = 0;
        let mut offset = 0usize;
        // Cross-page cursor (audit 2026-07-05): page 1 is cursor-less; a
        // `next_cursor` in the response upgrades the loop onto the cursor
        // path (0-record pages keep paging on `has_more`); a server without
        // it keeps today's offset loop.
        let mut cursor: Option<String> = None;
        let mut pages = 0usize;
        let mut guard_tripped = false;
        let mut cycle_exhausted = false;
        const BATCH_SIZE: usize = 500;
        const MAX_TOTAL_RECORDS: usize = 1000;
        // 64 pages × PAGE_SCAN(10K) = 640K index entries walkable per cycle;
        // also 64 sequential PQ handshakes (no connection reuse yet) — the
        // accepted per-cycle bound; dropped remainder re-covers next cycle.
        const MAX_PAGES_PER_CYCLE: usize = 64;

        loop {
            let mut req = PqRequest::new("delta_sync")
                .with_header("x-delta-batch-size", BATCH_SIZE.to_string())
                .with_header("x-delta-since", format!("{since}"))
                .with_body(bloom_bytes.to_vec());
            req = match &cursor {
                Some(c) => req.with_header("x-delta-cursor", c.clone()),
                None => req.with_header("x-delta-offset", offset.to_string()),
            };

            let resp = self.call(peer_addr, &req).await?;
            let body = Self::ensure_ok(resp, "delta_sync")?;
            let parsed: serde_json::Value = Self::json_body(&body, "delta_sync")?;

            let (items, has_more) = if let Some(records) =
                parsed.get("records").and_then(|r| r.as_array())
            {
                let items: Vec<String> = records
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                let more = parsed
                    .get("has_more")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                // Freshest page wins; legacy array-shape responses carry none.
                if let Some(tm) = parsed.get("total_missing").and_then(|v| v.as_u64()) {
                    peer_total_missing = tm;
                }
                (items, more)
            } else if let Some(arr) = parsed.as_array() {
                let items: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                (items, false)
            } else {
                return Err(ElaraError::Network(
                    "unexpected delta_sync response format".into(),
                ));
            };

            let batch_len = items.len();
            for hex_str in &items {
                let wire = hex::decode(hex_str)
                    .map_err(|e| ElaraError::Network(format!("bad hex: {e}")))?;
                all_records.push(wire);
            }
            pages += 1;

            let next_cursor = parsed
                .get("next_cursor")
                .and_then(|v| v.as_str())
                .map(String::from);
            // C6 guards, only when we SENT a cursor: the echo must match and
            // the frontier must strictly advance — else a buggy/hostile
            // server could loop us on page 1 disguised as progress. A server
            // that DROPS next_cursor mid-cycle while claiming has_more is
            // the same silent-ignore class (falling through to the offset
            // arm would re-page from a stale offset — duplicates, not
            // progress); next_cursor=None with has_more=false is the honest
            // end-of-window and breaks below without a trip.
            if let Some(sent) = &cursor {
                let echo = parsed.get("cursor_echo").and_then(|v| v.as_str());
                let advanced = next_cursor.as_deref() != Some(sent.as_str());
                let dropped = next_cursor.is_none() && has_more;
                if echo != Some(sent.as_str()) || !advanced || dropped {
                    tracing::warn!(
                        "delta_sync cursor guard trip: echo_ok={} advanced={advanced} dropped={dropped} — breaking cycle",
                        echo == Some(sent.as_str())
                    );
                    guard_tripped = true;
                    break;
                }
            }

            if !has_more || all_records.len() >= MAX_TOTAL_RECORDS {
                // R3-2(b): truncation was previously invisible to the caller —
                // surface it. Not a correctness gap: `since` is a rolling 24 h
                // window floor (sync.rs::delta_sync_since_floor), so the
                // remainder (and any record slipped by offset paging under
                // concurrent server ingest) is re-listed next cycle via the
                // bloom filter; `peer_total_missing` carries the deficit.
                if has_more && all_records.len() >= MAX_TOTAL_RECORDS {
                    tracing::info!(
                        "delta_sync truncated at {MAX_TOTAL_RECORDS} records with server has_more=true \
                         (peer_total_missing={peer_total_missing}); remainder re-covered next cycle"
                    );
                }
                break;
            }
            if pages >= MAX_PAGES_PER_CYCLE {
                cycle_exhausted = true;
                tracing::info!(
                    "delta_sync cursor cycle exhausted at {MAX_PAGES_PER_CYCLE} pages with has_more=true; \
                     remainder re-covered next cycle"
                );
                break;
            }
            match next_cursor {
                // Cursor path: 0-record pages keep paging (bloom-dense
                // ranges advance the frontier without payload).
                Some(nc) => cursor = Some(nc),
                // Offset path (old server): empty page = drained, exactly
                // today's termination.
                None => {
                    if batch_len == 0 {
                        break;
                    }
                    offset += batch_len;
                }
            }
        }

        // The gauge must reflect what remains AFTER this pull: records we
        // received this cycle are no longer missing. (Cursor pages omit
        // `total_missing`, so this stays anchored on page 1's window figure
        // — audit C5.)
        let remaining = peer_total_missing.saturating_sub(all_records.len() as u64);
        Ok((all_records, remaining, guard_tripped, cycle_exhausted))
    }

    pub async fn find_node(
        &self,
        peer_addr: &str,
        target_hex: &str,
        count: usize,
    ) -> Result<Vec<serde_json::Value>> {
        let req = PqRequest::new("find_node")
            .with_header("target", target_hex.to_string())
            .with_header("count", count.to_string());
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "find_node")?;
        let data: serde_json::Value = Self::json_body(&body, "find_node")?;
        Ok(data["peers"].as_array().cloned().unwrap_or_default())
    }

    pub async fn witness_record(
        &self,
        peer_addr: &str,
        wire_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        let req = PqRequest::new("witness").with_body(wire_bytes.to_vec());
        let resp = self.call(peer_addr, &req).await?;
        Self::ensure_ok(resp, "witness")
    }

    pub async fn get_snapshot_metadata(
        &self,
        peer_addr: &str,
    ) -> Result<serde_json::Value> {
        let resp = self
            .call(peer_addr, &PqRequest::new("snapshot_latest"))
            .await?;
        let body = Self::ensure_ok(resp, "snapshot_latest")?;
        Self::json_body(&body, "snapshot_latest")
    }

    pub async fn get_snapshot(
        &self,
        peer_addr: &str,
    ) -> Result<super::snapshot::NodeSnapshot> {
        let resp = self
            .call(peer_addr, &PqRequest::new("snapshot_full"))
            .await?;
        let body = Self::ensure_ok(resp, "snapshot_full")?;
        Self::json_body(&body, "snapshot_full")
    }

    pub async fn get_snapshot_fast_meta(
        &self,
        peer_addr: &str,
        since_epoch: Option<u64>,
    ) -> Result<super::sync::SnapshotFastMeta> {
        let mut req = PqRequest::new("snapshot_fast_meta").with_header("meta_only", "true");
        if let Some(epoch) = since_epoch {
            req = req.with_header("since_epoch", epoch.to_string());
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "snapshot_fast_meta")?;
        Self::json_body(&body, "snapshot_fast_meta")
    }

    pub async fn get_snapshot_fast_chunk(
        &self,
        peer_addr: &str,
        cursor: Option<&str>,
        since_epoch: Option<u64>,
    ) -> Result<super::sync::SnapshotChunk> {
        let mut req = PqRequest::new("snapshot_fast_chunk");
        if let Some(c) = cursor {
            req = req.with_header("cursor", c.to_string());
        }
        if let Some(epoch) = since_epoch {
            req = req.with_header("since_epoch", epoch.to_string());
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "snapshot_fast_chunk")?;
        Self::json_body(&body, "snapshot_fast_chunk")
    }

    /// AUDIT-10 PQ-R5a: PQ counterpart of `GET /snapshot/epochs`.
    ///
    /// Returns `{ "epochs": [u64], "count", "latest", ... }` — byte-identical to
    /// the axum handler because both share `compute_list_epoch_snapshots`.
    pub async fn list_epoch_snapshots(
        &self,
        peer_addr: &str,
    ) -> Result<serde_json::Value> {
        let resp = self
            .call(peer_addr, &PqRequest::new("list_epoch_snapshots"))
            .await?;
        let body = Self::ensure_ok(resp, "list_epoch_snapshots")?;
        Self::json_body(&body, "list_epoch_snapshots")
    }

    /// AUDIT-10 PQ-R5a: PQ counterpart of `GET /snapshot/epoch/{N}`.
    ///
    /// Returns the signed `NodeSnapshot` for that epoch. Matches axum 404
    /// behavior via the shared `compute_get_epoch_snapshot` — missing epoch
    /// surfaces as an `ElaraError::Storage` wrapped in the PQ response status.
    pub async fn get_epoch_snapshot(
        &self,
        peer_addr: &str,
        epoch: u64,
    ) -> Result<super::snapshot::NodeSnapshot> {
        let req = PqRequest::new("get_epoch_snapshot")
            .with_header("epoch", epoch.to_string());
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "get_epoch_snapshot")?;
        Self::json_body(&body, "get_epoch_snapshot")
    }

    /// AUDIT-10 Milestone B step 3b: PQ counterpart of
    /// `GET /checkpoints/from/{epoch}?zone=&limit=` for light-client super-seal
    /// cold start. Returns the same JSON body as the axum handler; shares
    /// `explorer::compute_checkpoints_from` server-side.
    pub async fn checkpoints_from(
        &self,
        peer_addr: &str,
        since_epoch: u64,
        zone: Option<&str>,
        limit: Option<usize>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("checkpoints_from")
            .with_header("since_epoch", since_epoch.to_string());
        if let Some(z) = zone {
            req = req.with_header("zone", z);
        }
        if let Some(l) = limit {
            req = req.with_header("limit", l.to_string());
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "checkpoints_from")?;
        Self::json_body(&body, "checkpoints_from")
    }

    // ─── AUDIT-10 Milestone C batch 1: admin/explorer verb parity ──────────
    //
    // Nullary PQ counterparts of the operator CLI's most-used read-only
    // admin endpoints. Each mirrors the axum route byte-for-byte via a
    // shared `compute_<verb>` helper on the server side.

    /// PQ counterpart of `GET /peers` — peer list with reachability metadata.
    pub async fn list_peers(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("list_peers")).await?;
        let body = Self::ensure_ok(resp, "list_peers")?;
        Self::json_body(&body, "list_peers")
    }

    /// PQ counterpart of `GET /health` — liveness + readiness checks.
    pub async fn health(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("health")).await?;
        let body = Self::ensure_ok(resp, "health")?;
        Self::json_body(&body, "health")
    }

    /// PQ counterpart of `GET /ledger/summary` — supply + staked + conservation.
    pub async fn ledger_summary(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("ledger_summary")).await?;
        let body = Self::ensure_ok(resp, "ledger_summary")?;
        Self::json_body(&body, "ledger_summary")
    }

    /// PQ counterpart of `GET /epochs` — per-zone latest epoch + seal hash.
    pub async fn epoch_status(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("epoch_status")).await?;
        let body = Self::ensure_ok(resp, "epoch_status")?;
        Self::json_body(&body, "epoch_status")
    }

    /// PQ counterpart of `GET /stakes?identity=...` — per-staker stake list,
    /// or every active stake fleet-wide when `identity` is `None`.
    pub async fn stakes(
        &self,
        peer_addr: &str,
        identity: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("stakes");
        if let Some(id) = identity {
            req = req.with_header("identity", id.to_string());
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "stakes")?;
        Self::json_body(&body, "stakes")
    }

    /// PQ counterpart of `GET /network` — supply + DAG + topology + consensus
    /// + gossip + epoch snapshot.
    pub async fn network_info(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("network_info")).await?;
        let body = Self::ensure_ok(resp, "network_info")?;
        Self::json_body(&body, "network_info")
    }

    /// PQ counterpart of `GET /token/enforcement` — circuit-breaker + velocity
    /// + acquisition + vesting + governance counters.
    pub async fn token_enforcement(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("token_enforcement")).await?;
        let body = Self::ensure_ok(resp, "token_enforcement")?;
        Self::json_body(&body, "token_enforcement")
    }

    /// PQ counterpart of `GET /zones` — per-zone consensus health + coverage
    /// summary.
    pub async fn zone_health(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("zone_health")).await?;
        let body = Self::ensure_ok(resp, "zone_health")?;
        Self::json_body(&body, "zone_health")
    }

    /// PQ counterpart of `GET /governance/summary` — proposal counters +
    /// governance constants.
    pub async fn governance_summary(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("governance_summary")).await?;
        let body = Self::ensure_ok(resp, "governance_summary")?;
        Self::json_body(&body, "governance_summary")
    }

    /// PQ counterpart of `GET /governance/params` — current network constants
    /// (epoch interval, witness reward, etc).
    pub async fn governance_params(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("governance_params")).await?;
        let body = Self::ensure_ok(resp, "governance_params")?;
        Self::json_body(&body, "governance_params")
    }

    /// PQ counterpart of `GET /supply` — circulating supply
    /// (`total_supply - total_staked - conservation_pool`).
    /// Returns `{ "micros": u64, "beat": f64 }`.
    pub async fn supply_circulating(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("supply_circulating")).await?;
        let body = Self::ensure_ok(resp, "supply_circulating")?;
        Self::json_body(&body, "supply_circulating")
    }

    /// PQ counterpart of `GET /supply/total` — total supply currently issued.
    /// Returns `{ "micros": u64, "beat": f64 }`.
    pub async fn supply_total(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("supply_total")).await?;
        let body = Self::ensure_ok(resp, "supply_total")?;
        Self::json_body(&body, "supply_total")
    }

    /// PQ counterpart of `GET /supply/max` — protocol cap (`MAX_SUPPLY`).
    /// Returns `{ "micros": u64, "beat": f64 }`.
    pub async fn supply_max(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("supply_max")).await?;
        let body = Self::ensure_ok(resp, "supply_max")?;
        Self::json_body(&body, "supply_max")
    }

    /// PQ counterpart of `GET /dag/stats` — record-classification + operation
    /// counters across the local CF_RECORDS scan. Cached
    /// node-side; cold-cache path can surface a Storage error.
    pub async fn dag_stats(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("dag_stats")).await?;
        let body = Self::ensure_ok(resp, "dag_stats")?;
        Self::json_body(&body, "dag_stats")
    }

    /// PQ counterpart of `GET /validate_address/{address}` — checks 32-byte
    /// hex format and ledger-account existence.
    pub async fn validate_address(
        &self,
        peer_addr: &str,
        address: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("validate_address")
            .with_header("address", address);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "validate_address")?;
        Self::json_body(&body, "validate_address")
    }

    /// PQ counterpart of `GET /witness/profiles` — enumerates witness profiles
    /// (organization, subnet, geo_zone) used by the diversity scorer.
    pub async fn list_witness_profiles(
        &self,
        peer_addr: &str,
    ) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("list_witness_profiles")).await?;
        let body = Self::ensure_ok(resp, "list_witness_profiles")?;
        Self::json_body(&body, "list_witness_profiles")
    }

    /// PQ counterpart of `GET /consensus/status` — settlement counters,
    /// confirmation level histogram, cross-zone stats, and a sample of
    /// unsettled records. `limit` caps the unsettled sample
    /// (default 20, max 100).
    pub async fn consensus_status(
        &self,
        peer_addr: &str,
        limit: Option<usize>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("consensus_status");
        if let Some(l) = limit {
            req = req.with_header("limit", l.to_string());
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "consensus_status")?;
        Self::json_body(&body, "consensus_status")
    }

    /// PQ counterpart of `GET /consensus/record/{record_id}` — full per-record
    /// consensus snapshot (attestations, settlement state, threshold).
    pub async fn consensus_record_detail(
        &self,
        peer_addr: &str,
        record_id: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("consensus_record_detail")
            .with_header("record_id", record_id);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "consensus_record_detail")?;
        Self::json_body(&body, "consensus_record_detail")
    }

    /// PQ counterpart of `GET /committees/snapshot` — per-zone deterministic
    /// committee membership for a given epoch + committee size.
    /// `epoch` defaults to the node's current DAG epoch; `k` defaults to
    /// `DEFAULT_COMMITTEE_SIZE`.
    pub async fn committees_snapshot(
        &self,
        peer_addr: &str,
        epoch: Option<u64>,
        k: Option<usize>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("committees_snapshot");
        if let Some(e) = epoch {
            req = req.with_header("epoch", e.to_string());
        }
        if let Some(k) = k {
            req = req.with_header("k", k.to_string());
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "committees_snapshot")?;
        Self::json_body(&body, "committees_snapshot")
    }

    /// PQ counterpart of `GET /governance/proposals` — paginated proposal
    /// listing with optional status filter. `limit` defaults
    /// to 50 (max 200); `offset` defaults to 0.
    pub async fn governance_proposals(
        &self,
        peer_addr: &str,
        status: Option<&str>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("governance_proposals");
        if let Some(s) = status {
            req = req.with_header("status", s);
        }
        if let Some(l) = limit {
            req = req.with_header("limit", l.to_string());
        }
        if let Some(o) = offset {
            req = req.with_header("offset", o.to_string());
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "governance_proposals")?;
        Self::json_body(&body, "governance_proposals")
    }

    /// PQ counterpart of `GET /governance/proposal/{id}` — single proposal
    /// with full vote breakdown + tally. Returns Governance
    /// error (NOT_FOUND-equivalent on the PQ side) for unknown ids.
    pub async fn governance_proposal_detail(
        &self,
        peer_addr: &str,
        id: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("governance_proposal_detail").with_header("id", id);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "governance_proposal_detail")?;
        Self::json_body(&body, "governance_proposal_detail")
    }

    /// PQ counterpart of `GET /governance/delegations/{identity}` —
    /// incoming + outgoing delegation graph for one identity.
    pub async fn governance_delegations(
        &self,
        peer_addr: &str,
        identity: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("governance_delegations").with_header("identity", identity);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "governance_delegations")?;
        Self::json_body(&body, "governance_delegations")
    }

    /// PQ counterpart of `GET /governance/params/history` — applied governance
    /// parameter changes. Optional `param` filters by name.
    pub async fn governance_params_history(
        &self,
        peer_addr: &str,
        param: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("governance_params_history");
        if let Some(p) = param {
            req = req.with_header("param", p);
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "governance_params_history")?;
        Self::json_body(&body, "governance_params_history")
    }

    /// PQ counterpart of `GET /disputes` — full dispute listing with the
    /// cumulative `disputes_opened_total` counter.
    pub async fn list_disputes(
        &self,
        peer_addr: &str,
        status: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("list_disputes");
        if let Some(s) = status {
            req = req.with_header("status", s);
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "list_disputes")?;
        Self::json_body(&body, "list_disputes")
    }

    /// PQ counterpart of `GET /challenges` — challenge listing with the
    /// cumulative `filed_total` counter.
    pub async fn list_challenges(
        &self,
        peer_addr: &str,
        status: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("list_challenges");
        if let Some(s) = status {
            req = req.with_header("status", s);
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "list_challenges")?;
        Self::json_body(&body, "list_challenges")
    }

    /// PQ counterpart of `GET /dag/record/{id}/graph` — parents + children +
    /// ancestor / descendant sets up to `depth` (default 5, max 20).
    /// `direction` ∈ `both` | `ancestors` | `descendants`.
    pub async fn dag_record_graph(
        &self,
        peer_addr: &str,
        id: &str,
        depth: Option<usize>,
        direction: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("dag_record_graph").with_header("id", id);
        if let Some(d) = depth {
            req = req.with_header("depth", d.to_string());
        }
        if let Some(dir) = direction {
            req = req.with_header("direction", dir);
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "dag_record_graph")?;
        Self::json_body(&body, "dag_record_graph")
    }

    /// PQ counterpart of `GET /dispute/{id}` — full dispute body.
    /// Returns RecordNotFound (non-OK PQ status) for unknown ids.
    pub async fn dispute_detail(
        &self,
        peer_addr: &str,
        id: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("dispute_detail").with_header("id", id);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "dispute_detail")?;
        Self::json_body(&body, "dispute_detail")
    }

    /// PQ counterpart of `GET /challenge/{id}` — full challenge body with
    /// jury + per-juror votes + verdict. Unknown ids return
    /// 200 with `{"error": "challenge not found"}` to preserve axum shape.
    pub async fn challenge_detail(
        &self,
        peer_addr: &str,
        id: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("challenge_detail").with_header("id", id);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "challenge_detail")?;
        Self::json_body(&body, "challenge_detail")
    }

    /// PQ counterpart of `GET /witness/correlation` — pairwise correlation +
    /// optional profile metadata for two witnesses.
    pub async fn witness_correlation(
        &self,
        peer_addr: &str,
        witness_a: &str,
        witness_b: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("witness_correlation")
            .with_header("witness_a", witness_a)
            .with_header("witness_b", witness_b);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "witness_correlation")?;
        Self::json_body(&body, "witness_correlation")
    }

    /// PQ counterpart of `GET /witness/reputation` — single-witness detail
    /// when `witness` is provided, full summary array otherwise.
    /// Unknown witnesses return a 200 envelope with
    /// `note: "unknown witness — default reputation"`.
    pub async fn witness_reputation(
        &self,
        peer_addr: &str,
        witness: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("witness_reputation");
        if let Some(w) = witness {
            req = req.with_header("witness", w);
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "witness_reputation")?;
        Self::json_body(&body, "witness_reputation")
    }

    /// PQ counterpart of `GET /committees/is_member` — advisory committee
    /// membership check for (zone, identity) at an optional epoch.
    /// Missing `zone` or `id` return 200 with `{"error": "..."}`
    /// to preserve the axum body shape.
    pub async fn committees_is_member(
        &self,
        peer_addr: &str,
        zone: &str,
        identity: &str,
        epoch: Option<u64>,
        k: Option<usize>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("committees_is_member")
            .with_header("zone", zone)
            .with_header("id", identity);
        if let Some(e) = epoch {
            req = req.with_header("epoch", e.to_string());
        }
        if let Some(kv) = k {
            req = req.with_header("k", kv.to_string());
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "committees_is_member")?;
        Self::json_body(&body, "committees_is_member")
    }

    /// PQ counterpart of `GET /peers/reputation` — peer table snapshot with
    /// rolling reputation score per peer.
    pub async fn peer_reputation(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("peer_reputation")).await?;
        let body = Self::ensure_ok(resp, "peer_reputation")?;
        Self::json_body(&body, "peer_reputation")
    }

    /// PQ counterpart of `GET /rewards` — auto-reward counters + conservation
    /// pool depth + per-attestation reward constant.
    pub async fn reward_stats(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("reward_stats")).await?;
        let body = Self::ensure_ok(resp, "reward_stats")?;
        Self::json_body(&body, "reward_stats")
    }

    /// PQ counterpart of `GET /itc` — per-zone interval-tree-clock summary
    /// + ITC event/join cumulative counters.
    pub async fn itc_status(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("itc_status")).await?;
        let body = Self::ensure_ok(resp, "itc_status")?;
        Self::json_body(&body, "itc_status")
    }

    /// PQ counterpart of `GET /xzone/stats` — pending cross-zone transfer
    /// counters + currently-locked micros.
    pub async fn xzone_stats(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("xzone_stats")).await?;
        let body = Self::ensure_ok(resp, "xzone_stats")?;
        Self::json_body(&body, "xzone_stats")
    }

    /// PQ counterpart of `GET /xzone/transfers` — pending transfer listing
    /// with optional status / sender / recipient filters.
    /// `limit` defaults to 100 (cap 1000); newest-first by `locked_at`.
    pub async fn xzone_transfers(
        &self,
        peer_addr: &str,
        status: Option<&str>,
        sender: Option<&str>,
        recipient: Option<&str>,
        limit: Option<usize>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("xzone_transfers");
        if let Some(s) = status {
            req = req.with_header("status", s);
        }
        if let Some(s) = sender {
            req = req.with_header("sender", s);
        }
        if let Some(r) = recipient {
            req = req.with_header("recipient", r);
        }
        if let Some(l) = limit {
            req = req.with_header("limit", l.to_string());
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "xzone_transfers")?;
        Self::json_body(&body, "xzone_transfers")
    }

    /// PQ counterpart of `GET /xzone/transfer/{transfer_id}` — single
    /// transfer detail. Returns RecordNotFound (non-OK PQ
    /// status) for transfers that have been pruned or never existed.
    pub async fn xzone_transfer(
        &self,
        peer_addr: &str,
        transfer_id: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("xzone_transfer").with_header("transfer_id", transfer_id);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "xzone_transfer")?;
        Self::json_body(&body, "xzone_transfer")
    }

    /// PQ counterpart of `GET /xzone/bundle/{transfer_id}` — Gap 2.2
    /// self-contained finality proof. Returns the JSON-serialized
    /// `XZoneTransferBundle`; deserialize and call
    /// `XZoneTransferBundle::verify()` to confirm 2/3 source-zone
    /// committee finality without fetching the source-zone DAG. Returns
    /// non-OK PQ status if the transfer is not yet sealed-and-finalized
    /// or has been pruned.
    pub async fn xzone_bundle(
        &self,
        peer_addr: &str,
        transfer_id: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("xzone_bundle").with_header("transfer_id", transfer_id);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "xzone_bundle")?;
        Self::json_body(&body, "xzone_bundle")
    }

    /// PQ counterpart of `GET /account/{identity}` — account-facing account
    /// balance + active stake snapshot. Returns OK with
    /// `exists: false` for unknown identities (matches axum behaviour).
    pub async fn account_detail(
        &self,
        peer_addr: &str,
        identity: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("account_detail").with_header("identity", identity);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "account_detail")?;
        Self::json_body(&body, "account_detail")
    }

    /// PQ counterpart of `GET /record/{id}/causal-proof`.
    /// Returns RecordNotFound (non-OK PQ status) for unknown ids.
    pub async fn causal_proof(
        &self,
        peer_addr: &str,
        id: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("causal_proof").with_header("id", id);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "causal_proof")?;
        Self::json_body(&body, "causal_proof")
    }

    /// PQ counterpart of `GET /proofs/{record_id}` — Merkle inclusion proof
    /// for a record against the active zone registry. Returns
    /// RecordNotFound for unknown record ids.
    pub async fn merkle_proof(
        &self,
        peer_addr: &str,
        record_id: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("merkle_proof").with_header("record_id", record_id);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "merkle_proof")?;
        Self::json_body(&body, "merkle_proof")
    }

    /// PQ counterpart of `GET /zone/{zone}/proof/{record_hash}` — per-zone
    /// Sparse Merkle proof for a 32-byte leaf hash. `record_hash`
    /// must be 64 hex characters; malformed/wrong-length inputs surface as
    /// non-OK PQ status (Wire), unknown leaves as RecordNotFound.
    pub async fn zone_merkle_proof(
        &self,
        peer_addr: &str,
        zone: u64,
        record_hash_hex: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("zone_merkle_proof")
            .with_header("zone", zone.to_string())
            .with_header("record_hash", record_hash_hex);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "zone_merkle_proof")?;
        Self::json_body(&body, "zone_merkle_proof")
    }

    /// PQ counterpart of `GET /dag/lifecycle` — DAG lifecycle counters
    /// (total/pending/attested/finalized + tips/edges).
    pub async fn dag_lifecycle(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("dag_lifecycle")).await?;
        let body = Self::ensure_ok(resp, "dag_lifecycle")?;
        Self::json_body(&body, "dag_lifecycle")
    }

    /// PQ counterpart of `GET /vrf/registry` — VRF registry snapshot
    /// (per-identity public key + node_type + registration provenance).
    pub async fn vrf_registry(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("vrf_registry")).await?;
        let body = Self::ensure_ok(resp, "vrf_registry")?;
        Self::json_body(&body, "vrf_registry")
    }

    /// PQ counterpart of `GET /versions/{record_id}` — content-version
    /// record info + chain to root (Protocol §11.30). Returns
    /// OK with `{"error": "version record not found", "record_id": ...}`
    /// envelope for unknown ids (preserves axum body shape).
    pub async fn version_info(
        &self,
        peer_addr: &str,
        record_id: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("version_info").with_header("record_id", record_id);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "version_info")?;
        Self::json_body(&body, "version_info")
    }

    /// PQ counterpart of `GET /versions/{record_id}/forks` — fork detection
    /// from a version's root chain. Same in-band error
    /// envelope as `version_info` for unknown records.
    pub async fn version_forks(
        &self,
        peer_addr: &str,
        record_id: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("version_forks").with_header("record_id", record_id);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "version_forks")?;
        Self::json_body(&body, "version_forks")
    }

    /// PQ counterpart of `GET /versions/stats` — aggregate versioning
    /// counters (version_count / chain_count / diff_count / fork_count).
    pub async fn version_stats(&self, peer_addr: &str) -> Result<serde_json::Value> {
        let resp = self.call(peer_addr, &PqRequest::new("version_stats")).await?;
        let body = Self::ensure_ok(resp, "version_stats")?;
        Self::json_body(&body, "version_stats")
    }

    /// PQ counterpart of `GET /epochs/headers` — light-client header sync
    /// (Protocol §11.3). All filters optional.
    pub async fn epoch_headers(
        &self,
        peer_addr: &str,
        zone: Option<&str>,
        since: Option<u64>,
        limit: Option<usize>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("epoch_headers");
        if let Some(z) = zone {
            req = req.with_header("zone", z);
        }
        if let Some(s) = since {
            req = req.with_header("since", s.to_string());
        }
        if let Some(l) = limit {
            req = req.with_header("limit", l.to_string());
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "epoch_headers")?;
        Self::json_body(&body, "epoch_headers")
    }

    /// PQ counterpart of `GET /checkpoints/latest/{zone}` — Gap 3 super-seal
    /// lookup. Returns OK with `{"error": "no super-seal yet
    /// for this zone", "zone": ...}` when no super-seal has been registered.
    pub async fn checkpoint_latest(
        &self,
        peer_addr: &str,
        zone: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("checkpoint_latest").with_header("zone", zone);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "checkpoint_latest")?;
        Self::json_body(&body, "checkpoint_latest")
    }

    /// PQ counterpart of `GET /debug/seal/{id}` — internal seal-attestation
    /// snapshot. RecordNotFound surfaces as non-OK status
    /// when the seal has no attestations yet (not proposed or no witnesses).
    pub async fn seal_debug(
        &self,
        peer_addr: &str,
        id: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("seal_debug").with_header("id", id);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "seal_debug")?;
        Self::json_body(&body, "seal_debug")
    }

    /// PQ counterpart of `POST /witness/profile` — self-publish witness
    /// metadata. Body fields: witness_hash, organization,
    /// subnet, geo_zone. Empty witness_hash or organization → BAD_REQUEST.
    pub async fn register_witness_profile(
        &self,
        peer_addr: &str,
        witness_hash: &str,
        organization: &str,
        subnet: &str,
        geo_zone: &str,
    ) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "witness_hash": witness_hash,
            "organization": organization,
            "subnet": subnet,
            "geo_zone": geo_zone,
        });
        let req = PqRequest::new("register_witness_profile")
            .with_body(serde_json::to_vec(&body).map_err(crate::errors::ElaraError::from)?);
        let resp = self.call(peer_addr, &req).await?;
        let resp = Self::ensure_ok(resp, "register_witness_profile")?;
        Self::json_body(&resp, "register_witness_profile")
    }

    /// PQ counterpart of `GET /routing/resolve` — zone-registry redirect
    /// lookup. Infallible-by-design: missing record_id and
    /// bad/wrong-length key surface as `{"error": ...}` at status OK.
    pub async fn routing_resolve(
        &self,
        peer_addr: &str,
        record_id: &str,
        key_hex: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("routing_resolve").with_header("record_id", record_id);
        if let Some(k) = key_hex {
            req = req.with_header("key", k);
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "routing_resolve")?;
        Self::json_body(&body, "routing_resolve")
    }

    /// PQ counterpart of `POST /validate` — record-level validation diagnostic.
    /// Body is the canonical wire-format `ValidationRecord`.
    /// Infallible-by-design: bad bytes surface as
    /// `{"valid": false, "checks": [{"check": "wire_format", ...}]}` at OK
    /// status, matching axum byte-for-byte.
    pub async fn validate_record(
        &self,
        peer_addr: &str,
        record_bytes: Vec<u8>,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("validate_record").with_body(record_bytes);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "validate_record")?;
        Self::json_body(&body, "validate_record")
    }

    /// PQ counterpart of `POST /peers/offline_notification` — signed
    /// going-offline broadcast. Body fields: node_id,
    /// timestamp_secs, sig (Dilithium3 hex). Unknown peers return
    /// `{"status": "unknown_peer"}` at OK; bad sig hex / sig verify failure
    /// surface as BAD_REQUEST.
    pub async fn receive_offline_notification(
        &self,
        peer_addr: &str,
        node_id: &str,
        timestamp_secs: u64,
        sig: &str,
    ) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "node_id": node_id,
            "timestamp_secs": timestamp_secs,
            "sig": sig,
        });
        let req = PqRequest::new("receive_offline_notification")
            .with_body(serde_json::to_vec(&body).map_err(crate::errors::ElaraError::from)?);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "receive_offline_notification")?;
        Self::json_body(&body, "receive_offline_notification")
    }

    /// PQ counterpart of `POST /transitions/{id}/veto` — submit a signed
    /// veto against a pending transition seal.
    ///
    /// `id_hex` is the 64-char hex-encoded 32-byte transition id; sent as
    /// the `id` header. `veto_bytes` is the JSON-encoded `TransitionVeto`
    /// struct (caller is responsible for the encoding to keep the client
    /// from depending on the seal type definition).
    ///
    /// Returns `VetoResponse { id, status, vetoes_count }`. Unknown id →
    /// NOT_FOUND. Vetoer pubkey not registered, signature verify failure,
    /// or out-of-window epoch → BAD_REQUEST.
    pub async fn submit_veto(
        &self,
        peer_addr: &str,
        id_hex: &str,
        veto_bytes: Vec<u8>,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("submit_veto")
            .with_header("id", id_hex)
            .with_body(veto_bytes);
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "submit_veto")?;
        Self::json_body(&body, "submit_veto")
    }

    /// PQ counterpart of `GET /dag/search` — full DAG search with optional
    /// filters. All filters are optional and forwarded as
    /// headers; the server reconstructs `DagSearchQuery` server-side.
    #[allow(clippy::too_many_arguments)]
    pub async fn dag_search(
        &self,
        peer_addr: &str,
        op: Option<&str>,
        creator: Option<&str>,
        to: Option<&str>,
        from: Option<&str>,
        since: Option<f64>,
        until: Option<f64>,
        limit: Option<usize>,
        classification: Option<&str>,
        has_key: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("dag_search");
        if let Some(v) = op {
            req = req.with_header("op", v);
        }
        if let Some(v) = creator {
            req = req.with_header("creator", v);
        }
        if let Some(v) = to {
            req = req.with_header("to", v);
        }
        if let Some(v) = from {
            req = req.with_header("from", v);
        }
        if let Some(v) = since {
            req = req.with_header("since", v.to_string());
        }
        if let Some(v) = until {
            req = req.with_header("until", v.to_string());
        }
        if let Some(v) = limit {
            req = req.with_header("limit", v.to_string());
        }
        if let Some(v) = classification {
            req = req.with_header("classification", v);
        }
        if let Some(v) = has_key {
            req = req.with_header("has_key", v);
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "dag_search")?;
        Self::json_body(&body, "dag_search")
    }

    /// PQ counterpart of `GET /activity/{identity}` — identity activity summary
    /// (Protocol §11.23). Server-side dispatch lands in `handle_activity`,
    /// which calls `routes::explorer::compute_activity`.
    pub async fn get_activity(
        &self,
        peer_addr: &str,
        identity: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("activity").with_header("identity", identity.to_string());
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "activity")?;
        Self::json_body(&body, "activity")
    }

    /// PQ counterpart of `GET /metrics` — Prometheus exposition body. Returns
    /// the raw `text/plain` body identical to the axum handler; the PQ frame
    /// carries no content-type so the caller knows the verb name. Used by
    /// AUDIT-10 Milestone D operators that want PQ-only metric scrape.
    pub async fn get_metrics(&self, peer_addr: &str) -> Result<String> {
        let resp = self.call(peer_addr, &PqRequest::new("metrics")).await?;
        let body = Self::ensure_ok(resp, "metrics")?;
        String::from_utf8(body)
            .map_err(|e| ElaraError::Network(format!("metrics utf8: {e}")))
    }

    // ── AUDIT-10 PQ-pure-client: transition cosign + probe verbs ──────────
    //
    // These close out the last reqwest outbound call sites so NodeClient
    // can be deleted. Logic mirrors the axum `/transitions/...` and
    // `/probe` endpoints; the server handlers in `pq_transport::router`
    // inline the same store walks so PQ + HTTPS return identical JSON.

    /// PQ counterpart of `POST /transitions/propose` — broadcast a freshly
    /// proposed `TransitionSeal` to one relay peer. Replaces the
    /// `push_transition_seal_to_peers` reqwest path.
    pub async fn submit_transition_seal(
        &self,
        peer_addr: &str,
        seal_json: &[u8],
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("submit_transition_seal").with_body(seal_json.to_vec());
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "submit_transition_seal")?;
        Self::json_body(&body, "submit_transition_seal")
    }

    /// PQ counterpart of `POST /transitions/{seal_id}/sig` — fan in a single
    /// anchor signature. Replaces the `push_transition_sig_to_peers`
    /// reqwest path.
    pub async fn submit_transition_sig(
        &self,
        peer_addr: &str,
        seal_id_hex: &str,
        sig_json: &[u8],
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("submit_transition_sig")
            .with_header("seal_id", seal_id_hex.to_string())
            .with_body(sig_json.to_vec());
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "submit_transition_sig")?;
        Self::json_body(&body, "submit_transition_sig")
    }

    /// PQ counterpart of `GET /transitions?status=<status>` — used by the
    /// cosign pull tick to list in-flight proposals on a relay peer.
    pub async fn list_transitions(
        &self,
        peer_addr: &str,
        status_filter: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut req = PqRequest::new("list_transitions");
        if let Some(s) = status_filter {
            req = req.with_header("status", s);
        }
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "list_transitions")?;
        Self::json_body(&body, "list_transitions")
    }

    /// PQ counterpart of `GET /transitions/{seal_id}` — used by the cosign
    /// pull tick to fetch a seal the local store doesn't yet hold.
    pub async fn get_transition(
        &self,
        peer_addr: &str,
        seal_id_hex: &str,
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("get_transition")
            .with_header("seal_id", seal_id_hex.to_string());
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "get_transition")?;
        Self::json_body(&body, "get_transition")
    }

    /// PQ counterpart of `POST /probe` — liveness-probe verb. Replaces
    /// the `execute_probe` reqwest path. Returns the `ProbeResponse`
    /// JSON body the axum handler serializes.
    pub async fn probe(
        &self,
        peer_addr: &str,
        request_json: &[u8],
    ) -> Result<serde_json::Value> {
        let req = PqRequest::new("probe").with_body(request_json.to_vec());
        let resp = self.call(peer_addr, &req).await?;
        let body = Self::ensure_ok(resp, "probe")?;
        Self::json_body(&body, "probe")
    }

    // ── 4E.3 streaming: seal_progress_stream ──────────────────────────────
    //
    // Open a long-lived PQ stream to `peer_addr` for the `seal_progress_stream`
    // method. Each server-emitted chunk is parsed as JSON and forwarded over
    // the returned channel. The task exits (and the sender is dropped) on
    // any of: FINAL chunk, FINAL|ERROR chunk, stream transport failure, or
    // parse failure.
    //
    // The returned receiver is bounded (32 outstanding messages) — accounts /
    // benches must drain to keep the server's in-flight cadence. If the
    // consumer stops reading for too long the internal task blocks on
    // `send().await` until the receiver is dropped, which then triggers
    // close-on-next-iteration via `send` returning Err.
    //
    // This is a *streaming subscription*, not a pooled unary call — the PQ
    // stream it owns is NOT returned to `self.pool`. Every call opens a
    // fresh handshake. Consolidating multiple concurrent streams from the
    // same caller is out of scope for 4E.3 Part B.
    pub async fn stream_seal_progress(
        &self,
        peer_addr: &str,
        record_id: &str,
    ) -> Result<tokio::sync::mpsc::Receiver<StreamProgressMessage>> {
        let expectation = self.pins.expectation_for(peer_addr);
        let mut stream = tokio::time::timeout(
            DEFAULT_CALL_TIMEOUT,
            pq_dial_with_admission(
                peer_addr,
                (*self.my_dil_pk).clone(),
                (*self.my_dil_sk).clone(),
                expectation,
                self.admission.clone(),
            ),
        )
        .await
        .map_err(|_| ElaraError::Network(format!("pq_dial {peer_addr} timed out")))?
        .map_err(|e| ElaraError::Network(format!("pq_dial {peer_addr}: {e}")))?;

        // Pin / refresh after successful handshake — matches `call()`.
        let peer_hash = stream.peer_identity_hash();
        if let Err(e) = self.pins.pin_or_verify(peer_addr, peer_hash) {
            return Err(ElaraError::Network(format!(
                "pin store rejected {peer_addr}: {e}"
            )));
        }

        // Send the streaming request before spawning the pump task. If the
        // request itself fails (e.g., peer closed immediately after handshake)
        // the caller gets a synchronous error and no receiver to manage.
        let req = PqRequest::new("seal_progress_stream")
            .with_header("record_id", record_id.to_string());
        stream
            .send_request(&req)
            .await
            .map_err(|e| ElaraError::Network(format!("send_request: {e}")))?;

        let (tx, rx) = tokio::sync::mpsc::channel::<StreamProgressMessage>(32);
        tokio::spawn(async move {
            loop {
                let chunk = match stream.recv_stream_chunk().await {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = tx
                            .send(StreamProgressMessage::Error(format!(
                                "stream recv: {e}"
                            )))
                            .await;
                        return;
                    }
                };

                let is_final = chunk.is_final();
                let is_error = chunk.is_error();

                let msg = if is_error {
                    StreamProgressMessage::Error(
                        String::from_utf8_lossy(&chunk.body).into_owned(),
                    )
                } else {
                    match serde_json::from_slice::<serde_json::Value>(&chunk.body) {
                        Ok(v) => StreamProgressMessage::Progress(v),
                        Err(e) => StreamProgressMessage::Error(format!(
                            "chunk parse: {e}"
                        )),
                    }
                };

                if tx.send(msg).await.is_err() {
                    // Consumer dropped — stop reading.
                    return;
                }
                if is_final {
                    return;
                }
            }
        });

        Ok(rx)
    }
}

/// Messages delivered on a `stream_seal_progress` channel.
#[derive(Debug, Clone)]
pub enum StreamProgressMessage {
    /// A non-terminal or final success chunk carrying a JSON body that
    /// matches the unary `seal_progress` shape.
    Progress(serde_json::Value),
    /// Terminal error — the stream is closed.
    Error(String),
}

impl std::fmt::Debug for PqNodeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqNodeClient")
            .field("my_dil_pk_len", &self.my_dil_pk.len())
            .field("pins", &self.pins.as_ref())
            .finish()
    }
}

/// Helper used by tests to mint a fresh Dilithium3 keypair and derive the
/// SHA3-256 identity hash of the public key.
#[cfg(test)]
pub(crate) struct TestIdentity {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    pub identity_hash: [u8; 32],
}

#[cfg(test)]
impl TestIdentity {
    pub fn new() -> Self {
        use sha3::{Digest, Sha3_256};

        let kp = crate::crypto::pqc::dilithium3_keygen()
            .expect("dilithium3_keygen in TestIdentity");
        let (pk, sk) = kp.into_parts();
        let mut hasher = Sha3_256::new();
        hasher.update(&pk);
        let digest = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        Self { pk, sk, identity_hash: hash }
    }
}

#[cfg(test)]
#[derive(Serialize, Deserialize)]
struct WantReply {
    want: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::pq_transport::{pq_dial, PqListener, PqStream};

    /// Tiny handler that answers every known RPC method against
    /// hard-coded fixtures. Used by integration tests below.
    async fn serve_one(mut stream: PqStream) {
        // Accept up to 8 back-to-back requests on one connection.
        for _ in 0..8 {
            let req = match stream.recv_request().await {
                Ok(r) => r,
                Err(_) => return, // peer closed or frame error — done
            };

            let resp = match req.method.as_str() {
                "ping" => PqResponse::ok(b"pong".to_vec()),
                "status" => {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "ok": true,
                        "node": "test"
                    }))
                    .unwrap();
                    PqResponse::ok(body)
                }
                "submit_record" => {
                    // Echo the wire bytes length back as JSON receipt.
                    let body = serde_json::to_vec(&serde_json::json!({
                        "accepted": true,
                        "bytes": req.body.len()
                    }))
                    .unwrap();
                    PqResponse::ok(body)
                }
                "query_records" => {
                    // Return two fake hex records.
                    let body = serde_json::to_vec(&vec![
                        "aabbcc".to_string(),
                        "ddeeff".to_string(),
                    ])
                    .unwrap();
                    PqResponse::ok(body)
                }
                "announce" => {
                    let body = serde_json::to_vec(&WantReply {
                        want: vec!["rec-1".to_string()],
                    })
                    .unwrap();
                    PqResponse::ok(body)
                }
                "fetch_records" => {
                    let body = serde_json::to_vec(&vec!["aabb".to_string()]).unwrap();
                    PqResponse::ok(body)
                }
                "merkle_root" => {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "root": "deadbeef"
                    }))
                    .unwrap();
                    PqResponse::ok(body)
                }
                "delta_sync" => {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "records": ["aabb"],
                        "has_more": false,
                    }))
                    .unwrap();
                    PqResponse::ok(body)
                }
                "find_node" => {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "peers": []
                    }))
                    .unwrap();
                    PqResponse::ok(body)
                }
                "witness" => PqResponse::ok(b"witnessed".to_vec()),
                "activity" => {
                    let identity = req.headers.get("identity").cloned().unwrap_or_default();
                    let body = serde_json::to_vec(&serde_json::json!({
                        "identity": identity,
                        "is_genesis_authority": false,
                        "trust": null,
                        "ledger": null,
                    }))
                    .unwrap();
                    PqResponse::ok(body)
                }
                "metrics" => PqResponse::ok(
                    b"# HELP elara_dag_size DAG size\n# TYPE elara_dag_size gauge\nelara_dag_size 42\n".to_vec(),
                ),
                "query_attestations" => {
                    // Echo the since/limit/record_id headers back so the client
                    // can confirm header forwarding without any real DB.
                    let since = req.headers.get("since").cloned().unwrap_or_default();
                    let limit = req.headers.get("limit").cloned().unwrap_or_default();
                    let record_id = req.headers.get("record_id").cloned().unwrap_or_default();
                    let body = serde_json::to_vec(&serde_json::json!({
                        "echo": { "since": since, "limit": limit, "record_id": record_id },
                        "attestations": []
                    }))
                    .unwrap();
                    PqResponse::ok(body)
                }
                "seal_progress" => {
                    let record_id = req.headers.get("record_id").cloned().unwrap_or_default();
                    let body = serde_json::to_vec(&serde_json::json!({
                        "record_id": record_id,
                        "confirmation_level": "sealed",
                        "seal_progress": { "attest_count": 1, "stake_pct": 33.3 },
                    }))
                    .unwrap();
                    PqResponse::ok(body)
                }
                "record_detail" => {
                    let record_id = req.headers.get("record_id").cloned().unwrap_or_default();
                    let body = serde_json::to_vec(&serde_json::json!({
                        "record_id": record_id,
                        "confirmation_level": "pending",
                        "attestations": [],
                    }))
                    .unwrap();
                    PqResponse::ok(body)
                }
                "account_proof" => {
                    let identity = req.headers.get("identity").cloned().unwrap_or_default();
                    let body = serde_json::to_vec(&serde_json::json!({
                        "identity": identity,
                        "balance": 0,
                        "proof": { "siblings": [], "root": "deadbeef" },
                    }))
                    .unwrap();
                    PqResponse::ok(body)
                }
                "headers_from" => {
                    let since = req.headers.get("since").cloned().unwrap_or_default();
                    let zone = req.headers.get("zone").cloned().unwrap_or_default();
                    let limit = req.headers.get("limit").cloned().unwrap_or_default();
                    let body = serde_json::to_vec(&serde_json::json!({
                        "since": since,
                        "zone": zone,
                        "limit": limit,
                        "headers": [],
                    }))
                    .unwrap();
                    PqResponse::ok(body)
                }
                _ => PqResponse::new(status::NOT_FOUND, Vec::new()),
            };

            if stream.send_response(&resp).await.is_err() {
                return;
            }
        }
    }

    async fn start_listener(server_id: &TestIdentity) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = PqListener::bind("127.0.0.1:0", server_id.pk.clone(), server_id.sk.clone())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            // Serve a small number of connections in a loop; tests tear
            // down via drop when finished.
            for _ in 0..8 {
                let (stream, _peer) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                tokio::spawn(serve_one(stream));
            }
        });

        (addr, handle)
    }

    #[tokio::test]
    async fn ping_tofu_and_pin() {
        let server = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, _h) = start_listener(&server).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins.clone());

        let addr_str = addr.to_string();
        assert!(client.ping(&addr_str).await);

        // After TOFU the pin must match the server's identity hash.
        let list = pins.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, addr_str);
        assert_eq!(list[0].1, hex::encode(server.identity_hash));
    }

    #[tokio::test]
    async fn pin_mismatch_on_server_rotation() {
        let server_a = TestIdentity::new();
        let server_b = TestIdentity::new();

        let client_id = TestIdentity::new();
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins.clone());

        // First: pin server_a on some addr.
        let (addr_a, _h) = start_listener(&server_a).await;
        let addr_a_str = addr_a.to_string();
        assert!(client.ping(&addr_a_str).await);

        // Now tell the store server_b lives at server_a's addr. Next call
        // will dial server_a and the handshake will reject because the
        // pinned hash doesn't match.
        pins.forget(&addr_a_str).unwrap();
        pins.pin_or_verify(&addr_a_str, server_b.identity_hash)
            .unwrap();

        // Ping returns false on any error (matches NodeClient behavior) —
        // but get_status surfaces it as ElaraError::Network.
        let err = client.get_status(&addr_a_str).await.unwrap_err();
        match err {
            ElaraError::Network(msg) => {
                assert!(
                    msg.contains("pq_dial") || msg.contains("handshake"),
                    "unexpected error: {msg}"
                );
            }
            _ => panic!("expected Network error, got {err:?}"),
        }
    }

    #[tokio::test]
    async fn get_status_returns_json() {
        let server = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, _h) = start_listener(&server).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let v = client.get_status(&addr.to_string()).await.unwrap();
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["node"], serde_json::json!("test"));
    }

    #[tokio::test]
    async fn query_records_round_trip() {
        let server = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, _h) = start_listener(&server).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let recs = client
            .query_records(&addr.to_string(), 0.0, 10)
            .await
            .unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0], hex::decode("aabbcc").unwrap());
        assert_eq!(recs[1], hex::decode("ddeeff").unwrap());
    }

    #[tokio::test]
    async fn announce_parses_want_list() {
        let server = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, _h) = start_listener(&server).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let anns = vec![crate::network::gossip::RecordAnnouncement {
            record_id: "rec-1".into(),
            content_hash: "00".repeat(32),
            creator_hash: "11".repeat(32),
            classification: 0,
            zone: "z1".into(),
            timestamp: 1.0,
            wire_len: 10,
        }];
        let want = client.announce(&addr.to_string(), &anns).await.unwrap();
        assert_eq!(want, vec!["rec-1".to_string()]);
    }

    /// Counting listener: hands back an Arc<AtomicUsize> incremented on
    /// each accepted TCP connection. Used to prove the pool is reusing.
    async fn start_counting_listener(
        server_id: &TestIdentity,
    ) -> (
        std::net::SocketAddr,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = PqListener::bind("127.0.0.1:0", server_id.pk.clone(), server_id.sk.clone())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = std::sync::Arc::new(AtomicUsize::new(0));
        let accepts_srv = accepts.clone();
        let handle = tokio::spawn(async move {
            for _ in 0..8 {
                let (stream, _peer) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                accepts_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve_one(stream));
            }
        });
        (addr, accepts, handle)
    }

    #[tokio::test]
    async fn pool_reuses_same_connection() {
        let server = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, accepts, _h) = start_counting_listener(&server).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);
        let addr_str = addr.to_string();

        // Three sequential RPCs. With pooling, only ONE handshake happens.
        assert!(client.ping(&addr_str).await);
        let _ = client.get_status(&addr_str).await.unwrap();
        assert!(client.ping(&addr_str).await);

        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "pool must reuse the same TCP connection across 3 RPCs"
        );
        assert_eq!(client.pool_size(), 1);
    }

    #[tokio::test]
    async fn pool_handshakes_again_after_drop_pooled() {
        let server = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, accepts, _h) = start_counting_listener(&server).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);
        let addr_str = addr.to_string();

        assert!(client.ping(&addr_str).await);
        assert_eq!(accepts.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Force a fresh handshake on the next call.
        client.drop_pooled(&addr_str).await;
        assert!(client.ping(&addr_str).await);

        assert_eq!(
            accepts.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "drop_pooled must force a fresh handshake on next call"
        );
    }

    #[tokio::test]
    async fn pool_size_caps_at_max_entries() {
        // We don't spawn MAX_POOL_ENTRIES + 1 real servers — instead we
        // slot-for() synthetic addresses and watch the map size.
        let client_id = TestIdentity::new();
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        for i in 0..(MAX_POOL_ENTRIES + 5) {
            let _slot = client.slot_for(&format!("127.0.0.1:{}", 40000 + i));
        }
        assert_eq!(
            client.pool_size(),
            MAX_POOL_ENTRIES,
            "pool must not exceed MAX_POOL_ENTRIES"
        );
    }

    #[tokio::test]
    async fn get_activity_round_trip() {
        // AUDIT-10 Milestone A delta — `activity` PQ verb client wrapper
        // mirrors `GET /activity/{identity}`. The mock returns a populated
        // body keyed by the supplied identity, confirming the header is
        // forwarded and the JSON body is parsed.
        let server = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, _h) = start_listener(&server).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let v = client.get_activity(&addr.to_string(), "abcd1234").await.unwrap();
        assert_eq!(v["identity"], serde_json::json!("abcd1234"));
        assert_eq!(v["is_genesis_authority"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn get_metrics_returns_text_body() {
        // AUDIT-10 Milestone A delta — `metrics` PQ verb returns a Prometheus
        // exposition string verbatim. The wrapper must surface it as `String`
        // (not JSON) so monitoring tooling can scrape PQ-only nodes.
        let server = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, _h) = start_listener(&server).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let body = client.get_metrics(&addr.to_string()).await.unwrap();
        assert!(body.contains("# TYPE elara_dag_size gauge"));
        assert!(body.contains("elara_dag_size 42"));
    }

    // ── AUDIT-10 Milestone A — pin-based TOFU round-trip per §3.2 verb ──
    //
    // One round-trip test per §3.2 verb is the doc's stated exit criterion.
    // The verbs already had server handlers + client wrappers; what was
    // missing was the wire-level confirmation that the client sends a
    // properly-formed PqRequest, the listener accepts it under TOFU, and
    // the response decodes through the typed wrapper. Each test pins via
    // a fresh in-memory PeerIdentityStore so TOFU runs end-to-end.

    #[tokio::test]
    async fn submit_record_round_trip() {
        let server = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, _h) = start_listener(&server).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let wire = b"\x01\x02\x03\x04";
        let v = client.submit_record(&addr.to_string(), wire).await.unwrap();
        assert_eq!(v["accepted"], serde_json::json!(true));
        assert_eq!(v["bytes"], serde_json::json!(wire.len()));
    }

    #[tokio::test]
    async fn query_attestations_since_round_trip() {
        let server = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, _h) = start_listener(&server).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let v = client
            .query_attestations_since(&addr.to_string(), 100.0, 50)
            .await
            .unwrap()
            .expect("OK envelope, not 404");
        assert_eq!(v["echo"]["since"], serde_json::json!("100"));
        assert_eq!(v["echo"]["limit"], serde_json::json!("50"));
    }

    #[tokio::test]
    async fn seal_progress_round_trip() {
        let server = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, _h) = start_listener(&server).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let v = client
            .seal_progress(&addr.to_string(), "rec-xyz")
            .await
            .unwrap();
        assert_eq!(v["record_id"], serde_json::json!("rec-xyz"));
        assert_eq!(v["confirmation_level"], serde_json::json!("sealed"));
    }

    #[tokio::test]
    async fn record_detail_round_trip() {
        let server = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, _h) = start_listener(&server).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let v = client
            .record_detail(&addr.to_string(), "rec-abc")
            .await
            .unwrap();
        assert_eq!(v["record_id"], serde_json::json!("rec-abc"));
        assert!(v["attestations"].is_array());
    }

    #[tokio::test]
    async fn account_proof_round_trip() {
        let server = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, _h) = start_listener(&server).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let v = client
            .account_proof(&addr.to_string(), "deadbeef00000000")
            .await
            .unwrap();
        assert_eq!(v["identity"], serde_json::json!("deadbeef00000000"));
        assert_eq!(v["proof"]["root"], serde_json::json!("deadbeef"));
    }

    #[tokio::test]
    async fn headers_from_round_trip() {
        let server = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, _h) = start_listener(&server).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let v = client
            .headers_from(&addr.to_string(), 7, Some("zone-a"), Some(64))
            .await
            .unwrap();
        assert_eq!(v["since"], serde_json::json!("7"));
        assert_eq!(v["zone"], serde_json::json!("zone-a"));
        assert_eq!(v["limit"], serde_json::json!("64"));
    }

    #[tokio::test]
    async fn unknown_method_is_not_found() {
        // Connect manually, send a bogus method, confirm 404.
        let server = TestIdentity::new();
        let (addr, _h) = start_listener(&server).await;

        let client_id = TestIdentity::new();
        let mut stream = pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            super::super::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();

        let resp = stream
            .call(&PqRequest::new("does_not_exist"))
            .await
            .unwrap();
        assert_eq!(resp.status, status::NOT_FOUND);
    }

    // ── 4E.3 client-side streaming subscription ─────────────────────────

    #[tokio::test]
    async fn stream_seal_progress_delivers_all_chunks_in_order() {
        // Spin up a bespoke listener that answers `seal_progress_stream` by
        // emitting 3 Progress chunks then a FINAL terminator. Verify the
        // client helper delivers Progress × 4 (3 non-final + 1 final) in the
        // same order with matching record_id.
        use super::super::pq_transport::rpc::PqStreamChunk;
        let server_id = TestIdentity::new();
        let listener = PqListener::bind(
            "127.0.0.1:0",
            server_id.pk.clone(),
            server_id.sk.clone(),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let (mut stream, _peer) = listener.accept().await.unwrap();
            // Read the request frame (we ignore its payload here).
            let _req = stream.recv_request().await.unwrap();
            // Emit 3 non-final chunks then a final one.
            for i in 0..3u32 {
                let body = serde_json::to_vec(&serde_json::json!({
                    "record_id": "r-1", "seq": i, "progress_pct": (i as f64) * 25.0,
                }))
                .unwrap();
                stream
                    .send_stream_chunk(&PqStreamChunk::data(i, body))
                    .await
                    .unwrap();
            }
            let final_body = serde_json::to_vec(&serde_json::json!({
                "record_id": "r-1", "confirmation_level": "finalized",
                "seal_progress": { "settled": true, "progress_pct": 100.0 },
            }))
            .unwrap();
            stream
                .send_stream_chunk(&PqStreamChunk::final_chunk(3, final_body))
                .await
                .unwrap();
        });

        let client_id = TestIdentity::new();
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let mut rx = client
            .stream_seal_progress(&addr.to_string(), "r-1")
            .await
            .unwrap();

        let mut seen = Vec::new();
        while let Some(msg) = rx.recv().await {
            seen.push(msg);
        }
        assert_eq!(seen.len(), 4, "must receive exactly 4 chunks");

        // First 3 are non-final Progress with increasing seq.
        for (i, msg) in seen.iter().take(3).enumerate() {
            match msg {
                StreamProgressMessage::Progress(v) => {
                    assert_eq!(v["seq"], serde_json::json!(i));
                }
                StreamProgressMessage::Error(e) => panic!("unexpected error at i={i}: {e}"),
            }
        }
        // Last is the FINAL chunk — Progress variant carrying the settled body.
        match &seen[3] {
            StreamProgressMessage::Progress(v) => {
                assert_eq!(v["confirmation_level"], serde_json::json!("finalized"));
            }
            StreamProgressMessage::Error(e) => panic!("unexpected error on final: {e}"),
        }

        h.await.unwrap();
    }

    /// `call_with_lock_timeout` must return promptly with a
    /// "slot busy" error when another caller already holds the per-peer
    /// slot. The previous unbounded `call()` would queue indefinitely
    /// behind a long heal cycle, hanging ops endpoints like /convergence.
    #[tokio::test]
    async fn call_with_lock_timeout_returns_busy_when_slot_held() {
        let client_id = TestIdentity::new();
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let peer_addr = "127.0.0.1:1"; // unrouted — no real listener needed
        let slot = client.slot_for_test(peer_addr);

        // Hold the slot in a separate task — simulates fork_monitor_loop
        // mid-heal.
        let held = slot.clone();
        let _holder = tokio::spawn(async move {
            let _guard = held.lock().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        // Give the holder time to acquire.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let start = std::time::Instant::now();
        let result = client
            .call_with_lock_timeout(
                peer_addr,
                &PqRequest::new("ping"),
                Duration::from_millis(200),
            )
            .await;
        let elapsed = start.elapsed();

        // Must fail fast (≤ ~500ms — well under the holder's 5s sleep).
        assert!(
            elapsed < Duration::from_secs(2),
            "call_with_lock_timeout must return promptly, took {elapsed:?}"
        );
        match result {
            Err(ElaraError::Network(msg)) => {
                assert!(
                    msg.contains("slot busy"),
                    "expected 'slot busy' error, got: {msg}"
                );
            }
            Ok(_) => panic!("call must fail when slot is held"),
            Err(other) => panic!("expected Network('slot busy ...'), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stream_seal_progress_surfaces_terminal_error() {
        // Listener emits a single FINAL|ERROR chunk. The client helper must
        // deliver exactly one StreamProgressMessage::Error and then close.
        use super::super::pq_transport::rpc::PqStreamChunk;
        let server_id = TestIdentity::new();
        let listener = PqListener::bind(
            "127.0.0.1:0",
            server_id.pk.clone(),
            server_id.sk.clone(),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let (mut stream, _peer) = listener.accept().await.unwrap();
            let _req = stream.recv_request().await.unwrap();
            stream
                .send_stream_chunk(&PqStreamChunk::error(0, "record pruned"))
                .await
                .unwrap();
        });

        let client_id = TestIdentity::new();
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let mut rx = client
            .stream_seal_progress(&addr.to_string(), "r-1")
            .await
            .unwrap();

        let first = rx.recv().await.expect("at least one message");
        match first {
            StreamProgressMessage::Error(e) => assert!(e.contains("record pruned")),
            StreamProgressMessage::Progress(v) => panic!("expected Error, got Progress: {v}"),
        }
        assert!(rx.recv().await.is_none(), "stream must close after terminal error");

        h.await.unwrap();
    }

    // ─── Wire-constant + gossip-header sync tests ──────────────────────────────
    //
    // The async PqStream integration tests cover the integration paths and
    // pool management. These three sync tests pin the wire-significant
    // constants and the gossip-header threading that the async suite doesn't
    // touch:
    //   1. DEFAULT_CALL_TIMEOUT and MAX_POOL_ENTRIES constants.
    //   2. GossipHeaders::apply with trace_id=None — exactly 4 x-elara-*
    //      headers, NO empty x-elara-trace-id (receiver special-case avoided).
    //   3. GossipHeaders::apply with trace_id=Some — 5 headers, trace_id
    //      threaded through; pinning the conditional branch separately so a
    //      future regression that flipped always-include / never-include
    //      surfaces with the precise broken direction.

    #[test]
    fn batch_ae_default_call_timeout_and_max_pool_entries_constants_pin_to_documented_values() {
        // DEFAULT_CALL_TIMEOUT is the per-call ceiling covering TCP connect +
        // PQ handshake + RPC round-trip. The 30s default matches reqwest's
        // long-tail defaults so a future drift (e.g. 60s, 15s) would silently
        // change every RPC's worst-case latency budget and stall reputation /
        // backoff code that times itself against this constant.
        assert_eq!(
            DEFAULT_CALL_TIMEOUT,
            std::time::Duration::from_secs(30),
            "DEFAULT_CALL_TIMEOUT drift breaks the per-call ceiling baked \
             into rpc_call + drop_pooled + heal cycle timings"
        );
        assert!(
            DEFAULT_CALL_TIMEOUT > std::time::Duration::from_secs(0),
            "zero timeout would cause every call to fail immediately"
        );

        // MAX_POOL_ENTRIES is the soft cap on per-peer connection-pool
        // entries. 64 is generous for testnet (≤10 peers) and safe for early
        // mainnet. Drift to 0 would disable pooling entirely; drift upward
        // without an LRU would let the map grow unboundedly under churn.
        assert_eq!(
            MAX_POOL_ENTRIES, 64,
            "MAX_POOL_ENTRIES drift breaks the connection-pool soft cap"
        );
        // Lower-bound `> 0` invariant pinned at compile time via the
        // `const _: () = assert!(..)` block next to the const declaration
        // (pq_client.rs ~L89). Runtime assert removed
        // (clippy::assertions_on_constants — both operands const-eval).
    }

    #[test]
    fn batch_ae_gossip_headers_apply_with_no_trace_id_sets_four_x_elara_headers() {
        let req = crate::network::pq_transport::rpc::PqRequest::new("gossip_push");
        let initial_header_count = req.headers.len();
        let headers = GossipHeaders {
            hops: 3,
            sender_identity_hash: "alice-hash",
            trace_id: None,
            network_id: "elara-mainnet",
            protocol_version: 42,
        };
        let out = headers.apply(req);

        // Exactly 4 x-elara-* headers added when trace_id is None — the
        // conditional at apply() L114 must NOT emit an empty x-elara-trace-id
        // (the rationale at L106-107 says receivers shouldn't have to
        // special-case the empty header).
        assert_eq!(
            out.headers.len(),
            initial_header_count + 4,
            "trace_id=None must add exactly 4 headers, got {}",
            out.headers.len() - initial_header_count
        );
        assert_eq!(out.headers.get("x-elara-hops").map(String::as_str), Some("3"));
        assert_eq!(
            out.headers.get("x-elara-sender").map(String::as_str),
            Some("alice-hash")
        );
        assert_eq!(
            out.headers.get("x-elara-network-id").map(String::as_str),
            Some("elara-mainnet")
        );
        assert_eq!(
            out.headers.get("x-elara-protocol-version").map(String::as_str),
            Some("42"),
            "protocol_version stringified via to_string() — pinning the form so \
             a future shift to binary encoding surfaces here"
        );
        assert!(
            !out.headers.contains_key("x-elara-trace-id"),
            "trace_id=None must NOT add x-elara-trace-id — otherwise receivers \
             would have to special-case the empty header"
        );
    }

    #[test]
    fn batch_ae_gossip_headers_apply_with_trace_id_includes_x_elara_trace_id_header() {
        // Mirror of the prior test but with trace_id=Some — pinning the
        // OTHER branch of the conditional so a future regression that
        // flipped always-include vs never-include surfaces with the precise
        // broken direction (one test alone could not distinguish).
        let req = crate::network::pq_transport::rpc::PqRequest::new("gossip_relay");
        let initial_header_count = req.headers.len();
        let trace = "trace-abc-123";
        let headers = GossipHeaders {
            hops: 1,
            sender_identity_hash: "bob-hash",
            trace_id: Some(trace),
            network_id: "elara-testnet",
            protocol_version: 7,
        };
        let out = headers.apply(req);

        assert_eq!(
            out.headers.len(),
            initial_header_count + 5,
            "trace_id=Some must add exactly 5 headers (4 baseline + trace_id)"
        );
        assert_eq!(
            out.headers.get("x-elara-trace-id").map(String::as_str),
            Some(trace),
            "trace_id payload must be threaded through verbatim"
        );
        // Baseline headers still present (regression guard for an accidental
        // path where the trace branch took over the baseline assignment).
        assert_eq!(out.headers.get("x-elara-hops").map(String::as_str), Some("1"));
        assert_eq!(out.headers.get("x-elara-sender").map(String::as_str), Some("bob-hash"));
        assert_eq!(
            out.headers.get("x-elara-network-id").map(String::as_str),
            Some("elara-testnet")
        );
        assert_eq!(
            out.headers.get("x-elara-protocol-version").map(String::as_str),
            Some("7")
        );
    }

    // ─── submit_record network/version header plumbing (CLI/SDK write gap) ─

    fn test_client() -> PqNodeClient {
        let kp = crate::crypto::pqc::dilithium3_keygen().expect("dilithium3_keygen");
        let (pk, sk) = kp.into_parts();
        PqNodeClient::new(pk, sk, Arc::new(PeerIdentityStore::in_memory()))
    }

    #[test]
    fn submit_record_request_carries_network_and_version_headers() {
        // A configured client must stamp x-elara-network-id (else any node on
        // a non-"testnet" network_id rejects the write with network_mismatch)
        // plus x-elara-protocol-version — the two gates at routes/core.rs +
        // pq_transport/router.rs read exactly these headers.
        let client = test_client().with_network_id("my-realm");
        let req = client.build_submit_record_request(b"wire");
        assert_eq!(
            req.headers.get("x-elara-network-id").map(String::as_str),
            Some("my-realm"),
            "configured network_id must reach the wire"
        );
        assert_eq!(
            req.headers.get("x-elara-protocol-version").map(String::as_str),
            Some(crate::network::config::PROTOCOL_VERSION.to_string().as_str()),
            "protocol version is always stamped (static binary property)"
        );
        // Never x-elara-sender — that would route the submit through the
        // gossip-push profile gate on the receiver.
        assert!(!req.headers.contains_key("x-elara-sender"));
    }

    #[test]
    fn submit_record_unconfigured_omits_network_header_keeps_version() {
        // No network_id + no admission ctx = omit x-elara-network-id so the
        // node applies its "testnet" backward-compat default (zero behavior
        // change for existing callers). protocol-version is still stamped.
        let req = test_client().build_submit_record_request(b"wire");
        assert!(
            !req.headers.contains_key("x-elara-network-id"),
            "unconfigured client must omit the header (node defaults to testnet)"
        );
        assert!(req.headers.contains_key("x-elara-protocol-version"));
    }

    #[test]
    fn submit_record_admission_network_id_wins_over_configured() {
        // Security invariant: the admission cert's network_id is proven realm
        // membership and is authoritative — a divergent with_network_id can
        // NEVER reach the wire, so a client can't mislabel records for a realm
        // it isn't admitted to.
        let client = test_client()
            .with_network_id("attacker-claimed")
            .with_admission_context(AdmissionContext {
                network_id: "proven-realm".to_string(),
                cert: None,
            });
        assert_eq!(client.effective_network_id(), Some("proven-realm"));
        let req = client.build_submit_record_request(b"wire");
        assert_eq!(
            req.headers.get("x-elara-network-id").map(String::as_str),
            Some("proven-realm"),
            "admission cert network_id must override the configured field"
        );
    }

    // ─── ensure_ok / json_body / pins / drop_pooled helper tests ──────────
    //
    // The wire-round-trip integration tests cover the public RPC surface but
    // the two private associated helpers `ensure_ok` (L322) + `json_body` (L332) are
    // shared by ~70 public RPC wrappers and have ZERO direct pinning — every
    // single one of those wrappers funnels its status check + body parse
    // through these two helpers, so a regression to either silently breaks
    // the entire client. The remaining tests pin `pins()` accessor (L136)
    // and the `drop_pooled` unknown-addr no-op branch (L151-163) which the
    // existing `pool_handshakes_again_after_drop_pooled` covers only the
    // known-addr side of.

    #[test]
    fn batch_af_ensure_ok_success_returns_body_unchanged() {
        // 2xx response → body returned verbatim. Pins the success path of
        // every RPC wrapper that does `Self::ensure_ok(resp, "verb")?`.
        let body = b"hello world".to_vec();
        let resp = PqResponse::ok(body.clone());
        let out = PqNodeClient::ensure_ok(resp, "test").expect("2xx must succeed");
        assert_eq!(out, body, "success path must return body bytes unchanged");

        // Empty body 200 — common for verbs that signal status-only (e.g. ping).
        let empty_resp = PqResponse::ok(Vec::new());
        let empty_out = PqNodeClient::ensure_ok(empty_resp, "test")
            .expect("2xx with empty body must succeed");
        assert!(empty_out.is_empty(), "empty 200 must return empty Vec");
    }

    #[test]
    fn batch_af_ensure_ok_non_success_returns_network_error_with_label_and_status() {
        // 404 → Network error containing BOTH the caller-supplied label
        // ("what") AND the wire status code. The label is load-bearing —
        // ~70 RPC wrappers pass distinct labels so operator logs can
        // distinguish which verb failed (e.g. "merkle_root returned status
        // 404" vs "delta_sync returned status 404").
        let resp = PqResponse::new(404, b"not found".to_vec());
        let err = PqNodeClient::ensure_ok(resp, "merkle_root")
            .expect_err("404 must error");
        match err {
            ElaraError::Network(msg) => {
                assert!(msg.contains("merkle_root"), "label missing: {msg}");
                assert!(msg.contains("404"), "status code missing: {msg}");
            }
            _ => panic!("expected Network error, got {err:?}"),
        }

        // 500 — server-side failure path. Same contract: label + status
        // must surface so a regression that swallowed the label (e.g.
        // "returned status 500") would still tell ops which verb broke.
        let resp_500 = PqResponse::new(500, b"oops".to_vec());
        let err_500 = PqNodeClient::ensure_ok(resp_500, "delta_sync")
            .expect_err("5xx must error");
        match err_500 {
            ElaraError::Network(msg) => {
                assert!(msg.contains("delta_sync"), "label missing on 500: {msg}");
                assert!(msg.contains("500"), "500 status missing: {msg}");
            }
            _ => panic!("expected Network error, got {err_500:?}"),
        }

        // Boundary: status 199 is NOT success (success range is 200..300).
        let resp_199 = PqResponse::new(199, Vec::new());
        assert!(
            PqNodeClient::ensure_ok(resp_199, "edge").is_err(),
            "199 must be treated as failure — success range is 200..300"
        );

        // Boundary: status 300 is NOT success (exclusive upper bound).
        let resp_300 = PqResponse::new(300, Vec::new());
        assert!(
            PqNodeClient::ensure_ok(resp_300, "edge").is_err(),
            "300 must be treated as failure — success range is 200..300"
        );
    }

    #[test]
    fn batch_af_json_body_parses_typed_struct_and_value() {
        // Typed-struct deserialize via the for<'de> bound. Pins the
        // happy path of every wrapper that goes
        // `Self::json_body::<MyDto>(&body, "verb")`.
        #[derive(Deserialize, Serialize, PartialEq, Debug)]
        struct Dto {
            x: i64,
            name: String,
        }
        let wire = serde_json::to_vec(&Dto { x: 42, name: "elara".into() }).unwrap();
        let dto: Dto = PqNodeClient::json_body(&wire, "test")
            .expect("valid JSON must deserialize");
        assert_eq!(dto, Dto { x: 42, name: "elara".into() });

        // `serde_json::Value` is the most common usage — pin the loose
        // form too so a future shift in serde_json semantics surfaces here.
        let value_wire = br#"{"ok":true,"count":7}"#;
        let v: serde_json::Value =
            PqNodeClient::json_body(value_wire, "test").expect("valid Value JSON");
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["count"], serde_json::json!(7));
    }

    #[test]
    fn batch_af_json_body_invalid_returns_network_error_with_parse_prefix_and_label() {
        // Malformed JSON → Network error whose message contains BOTH the
        // "parse:" prefix AND the caller-supplied label. Both are load-
        // bearing for the same operator-log reasons as `ensure_ok`.
        let err: Result<serde_json::Value> =
            PqNodeClient::json_body(b"not a json doc", "consensus_status");
        let e = err.expect_err("malformed JSON must error");
        match e {
            ElaraError::Network(msg) => {
                assert!(msg.contains("parse:"), "missing 'parse:' marker: {msg}");
                assert!(
                    msg.contains("consensus_status"),
                    "label missing from error: {msg}"
                );
            }
            _ => panic!("expected Network error, got {e:?}"),
        }

        // Type-mismatch is also a parse error (serde_json::from_slice
        // returns Err when the JSON shape doesn't match the target type).
        // Pin this branch so a future refactor that tried to be
        // "permissive" silently doesn't bypass the error contract.
        #[derive(Deserialize, Debug)]
        struct Strict {
            #[allow(dead_code)]
            n: u64,
        }
        let wire = br#"{"n":"not-a-number"}"#;
        let err: Result<Strict> = PqNodeClient::json_body(wire, "ledger_summary");
        let e = err.expect_err("type-mismatch must error");
        match e {
            ElaraError::Network(msg) => {
                assert!(msg.contains("ledger_summary"), "label missing: {msg}");
                assert!(msg.contains("parse:"), "missing 'parse:' marker: {msg}");
            }
            _ => panic!("expected Network error, got {e:?}"),
        }
    }

    #[tokio::test]
    async fn batch_af_drop_pooled_on_unknown_addr_is_a_no_op() {
        // `drop_pooled` must NOT panic and MUST NOT create a pool entry
        // when asked to drop a peer that has never been contacted. The
        // existing `pool_handshakes_again_after_drop_pooled` covers the
        // known-addr side; this one pins the unknown-addr branch (which
        // the implementation reaches by getting `None` from the map and
        // skipping the inner lock). A regression that "helpfully"
        // inserted a fresh slot on miss would silently inflate
        // pool_size unboundedly under churn.
        let client_id = TestIdentity::new();
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);
        assert_eq!(client.pool_size(), 0);

        // Dropping a peer we've never spoken to.
        client.drop_pooled("127.0.0.1:65535").await;
        assert_eq!(client.pool_size(), 0, "drop_pooled on unknown addr must not seed a slot");
    }

    #[test]
    fn batch_af_pins_accessor_round_trips_via_shared_arc() {
        // `pins()` returns the underlying store reference so admin /
        // debug callers can list pinned identities without holding their
        // own copy of the Arc. Pin the round-trip: identity pinned via
        // the externally-held Arc must show up via `client.pins()` and
        // vice versa — they MUST be the same store.
        let client_id = TestIdentity::new();
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins.clone());

        // Pin one identity via the outer Arc.
        let fake_hash = [7u8; 32];
        pins.pin_or_verify("127.0.0.1:7777", fake_hash).unwrap();

        // The accessor surface MUST observe the same pin.
        let listed = client.pins().list();
        assert_eq!(listed.len(), 1, "pins().list() must see externally-set pin");
        assert_eq!(listed[0].0, "127.0.0.1:7777");
        assert_eq!(listed[0].1, hex::encode(fake_hash));
    }

    // ─── slot_for pool-population path tests ──────────────────────────────
    //
    // Earlier tests covered the response-shape helpers (`ensure_ok`,
    // `json_body`) and the accessor / unknown-addr edge of `drop_pooled`.
    // The slot-table is the remaining unpinned
    // surface: `slot_for` (L177) is the private pool-population path that
    // every RPC call funnels through, and the existing suite covers only
    // the upper bound (`pool_size_caps_at_max_entries` at L2488). What's
    // NOT pinned: Arc identity on repeated lookup (a future "helpful"
    // rewrite that returned a fresh Arc per call would silently break
    // per-peer serialization), distinct-addr slot separation, the
    // pool_size accounting on the growth side, the byte-exact keying
    // contract (any normalization would silently merge slots), and the
    // drop_pooled-on-known-peer contract that the slot ENTRY persists.

    #[tokio::test]
    async fn batch_ah_slot_for_returns_same_arc_for_repeated_lookups() {
        // `slot_for` is the per-peer-mutex anchor for `call_inner`. If two
        // lookups returned distinct Arcs, concurrent RPCs against the same
        // peer would no longer serialize through one tokio Mutex — they'd
        // both rush into the cached-stream branch and step on each other.
        // Pin Arc identity (ptr_eq) so a future rewrite to a HashMap-free
        // sharded design either preserves the contract or trips this test.
        let client_id = TestIdentity::new();
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let a = client.slot_for_test("127.0.0.1:50001");
        let b = client.slot_for_test("127.0.0.1:50001");
        assert!(
            Arc::ptr_eq(&a, &b),
            "slot_for must return the same Arc for repeated lookups on the same peer"
        );
        // Sanity: pool grew by exactly one entry.
        assert_eq!(client.pool_size(), 1, "two lookups on same peer must seed one slot");
    }

    #[tokio::test]
    async fn batch_ah_slot_for_returns_distinct_arcs_for_different_peers() {
        // Sibling of the prior test on the other side of the keying
        // boundary: different peers MUST get distinct Arcs so per-peer
        // RPCs don't share a serialization point. A regression that
        // accidentally returned the same Arc would silently funnel all
        // RPCs through one mutex.
        let client_id = TestIdentity::new();
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let a = client.slot_for_test("127.0.0.1:50101");
        let b = client.slot_for_test("127.0.0.1:50102");
        assert!(
            !Arc::ptr_eq(&a, &b),
            "slot_for must return distinct Arcs for different peers"
        );
        assert_eq!(client.pool_size(), 2, "two distinct peers must seed two slots");
    }

    #[tokio::test]
    async fn batch_ah_slot_for_grows_pool_size_one_per_new_peer() {
        // Pool accounting on the growth side. The upper-bound test
        // `pool_size_caps_at_max_entries` confirms the cap; this one
        // pins the linear growth side below the cap so a regression
        // that double-counted or under-counted on insert surfaces here
        // BEFORE the cap behaviour masks it.
        let client_id = TestIdentity::new();
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        assert_eq!(client.pool_size(), 0, "pool is empty at construction");
        for i in 0..7 {
            let _ = client.slot_for_test(&format!("127.0.0.1:{}", 50200 + i));
            assert_eq!(
                client.pool_size(),
                i + 1,
                "pool_size must grow by exactly one per new peer (i={i})"
            );
        }
        // Repeating a known peer must NOT grow the pool (idempotency at
        // the size level, not just at the Arc level).
        let _ = client.slot_for_test("127.0.0.1:50200");
        assert_eq!(client.pool_size(), 7, "repeat lookup must not grow pool");
    }

    #[tokio::test]
    async fn batch_ah_slot_for_keys_by_exact_addr_string_no_normalization() {
        // The keying contract is byte-exact `peer_addr.to_string()`. No
        // trim, no lowercase, no port-normalization. Pin this so a future
        // refactor that tried to be "helpful" (e.g. parse as SocketAddr
        // and re-format) doesn't silently merge two callers that intended
        // distinct slots, or split two callers that intended the same.
        let client_id = TestIdentity::new();
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let canonical = client.slot_for_test("127.0.0.1:50301");
        let with_space = client.slot_for_test(" 127.0.0.1:50301");
        let with_trailing = client.slot_for_test("127.0.0.1:50301 ");
        assert!(
            !Arc::ptr_eq(&canonical, &with_space),
            "leading whitespace must produce a distinct slot — no trim normalization"
        );
        assert!(
            !Arc::ptr_eq(&canonical, &with_trailing),
            "trailing whitespace must produce a distinct slot — no trim normalization"
        );
        assert_eq!(
            client.pool_size(),
            3,
            "three byte-distinct addr strings must yield three distinct slots"
        );
    }

    #[tokio::test]
    async fn batch_ah_drop_pooled_on_known_peer_keeps_slot_entry() {
        // `drop_pooled` nukes the cached stream INSIDE the slot
        // (`*guard = None`) but MUST keep the slot entry itself in the
        // map — otherwise the next call would observe a fresh Arc and
        // an in-flight concurrent RPC would no longer serialize behind
        // the original mutex. The existing `pool_handshakes_again_after_drop_pooled`
        // tests the reuse-from-fresh-handshake side; this one pins the
        // slot-entry-persistence contract at the pool-size level so a
        // future refactor that "cleaned up" by removing the entry
        // surfaces here.
        let client_id = TestIdentity::new();
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        // Seed the slot via slot_for (no real handshake needed — the
        // PqStream inside stays None, which is fine for this test).
        let before = client.slot_for_test("127.0.0.1:50401");
        assert_eq!(client.pool_size(), 1);

        // drop_pooled on the known addr.
        client.drop_pooled("127.0.0.1:50401").await;

        // Pool size unchanged AND the next lookup returns the SAME Arc
        // (proving the entry was preserved, not silently replaced).
        assert_eq!(
            client.pool_size(),
            1,
            "drop_pooled must keep the slot entry — only the inner stream is cleared"
        );
        let after = client.slot_for_test("127.0.0.1:50401");
        assert!(
            Arc::ptr_eq(&before, &after),
            "slot entry must persist across drop_pooled so concurrent RPCs stay serialized"
        );
    }

    // ─── StreamProgressMessage + Debug-redaction tests ────────────────────
    //
    // The pool / RPC surface is now solidly pinned but the two `pub` items
    // outside the RPC body still ship without unit pins:
    //
    //   • `StreamProgressMessage` (L2085) is the channel-shape of
    //     `stream_seal_progress`; only the integration tests at L2744 /
    //     L2846 touch its variants. No test pins the enum's `Clone` deep-
    //     copy semantics, the variant count, or the discriminant
    //     distinctness — so a future refactor that (a) added a third
    //     variant breaking exhaustive matches in downstream consumers, or
    //     (b) collapsed Progress + Error into a single Result-typed
    //     variant, would only fail at the consumer site (or worse, silently
    //     compile under a `_` catch-all).
    //   • `Debug for PqNodeClient` (L2093) is the only operator-visible
    //     surface that touches the client struct. Today it deliberately
    //     redacts `my_dil_sk` and `pool` (secret-key + internal mutex state
    //     would leak through structured logs otherwise). Nothing pins that
    //     contract, so a future "helpful" `derive(Debug)` switch would
    //     silently start logging the secret key bytes on the next
    //     `tracing::debug!("{:?}", client)`.

    #[test]
    fn batch_ai_stream_progress_message_two_variant_exhaustive_destructure_with_distinct_discriminants() {
        // Exhaustive match WITHOUT a `_` catch-all. If a third variant is
        // ever added to `StreamProgressMessage` this match stops
        // compiling, forcing the author to update every consumer
        // (including `stream_seal_progress` at L2744 / L2846).
        let progress = StreamProgressMessage::Progress(serde_json::json!(null));
        let error = StreamProgressMessage::Error("e".into());
        match &progress {
            StreamProgressMessage::Progress(_) | StreamProgressMessage::Error(_) => {}
        }
        match &error {
            StreamProgressMessage::Progress(_) | StreamProgressMessage::Error(_) => {}
        }

        // Discriminant distinctness. A regression that collapsed
        // Progress + Error into a single Result-typed variant would pass
        // the exhaustive match above (one variant still exhausts) but
        // fail here.
        assert_ne!(
            std::mem::discriminant(&progress),
            std::mem::discriminant(&error),
            "Progress and Error must be distinct enum variants — \
             collapsing them would silently break channel-side matches"
        );

        // Same-variant pins (sanity): two Progress values share a
        // discriminant regardless of payload; two Error values likewise.
        let progress_b = StreamProgressMessage::Progress(serde_json::json!({"x": 1}));
        assert_eq!(
            std::mem::discriminant(&progress),
            std::mem::discriminant(&progress_b),
            "Progress(_) discriminant must be payload-independent"
        );
        let error_b = StreamProgressMessage::Error("different".into());
        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&error_b),
            "Error(_) discriminant must be payload-independent"
        );
    }

    #[test]
    fn batch_ai_stream_progress_message_progress_clone_is_deep_copy_of_serde_value() {
        // Clone for `Progress(serde_json::Value)` must produce an
        // independent Value — mutating the clone's payload MUST NOT
        // affect the original. A regression to `Progress(Arc<Value>)`
        // would silently share state and break the send-once contract
        // of the mpsc channel.
        let original = StreamProgressMessage::Progress(serde_json::json!({"x": 1, "tag": "a"}));
        let mut cloned = original.clone();

        // Mutate the clone in place.
        match &mut cloned {
            StreamProgressMessage::Progress(v) => {
                v["x"] = serde_json::json!(999);
                v["tag"] = serde_json::json!("MUTATED");
            }
            StreamProgressMessage::Error(e) => panic!("clone changed variant: {e}"),
        }

        // Original payload must be untouched.
        match &original {
            StreamProgressMessage::Progress(v) => {
                assert_eq!(v["x"], serde_json::json!(1), "x must NOT have changed in original");
                assert_eq!(v["tag"], serde_json::json!("a"), "tag must NOT have changed in original");
            }
            StreamProgressMessage::Error(e) => panic!("original changed variant: {e}"),
        }

        // Clone must reflect the mutation (sanity: we actually changed something).
        match &cloned {
            StreamProgressMessage::Progress(v) => {
                assert_eq!(v["x"], serde_json::json!(999));
                assert_eq!(v["tag"], serde_json::json!("MUTATED"));
            }
            StreamProgressMessage::Error(e) => panic!("post-mutation variant flipped: {e}"),
        }
    }

    #[test]
    fn batch_ai_stream_progress_message_error_clone_is_deep_copy_of_string() {
        // Sibling of the Progress test on the Error side. Pins that
        // `Error(String)` clones independently — a regression to
        // `Error(Arc<str>)` (or any reference-shared form) would let
        // append-mutations on the clone visibly leak into the original.
        let original = StreamProgressMessage::Error("upstream timeout".to_string());
        let mut cloned = original.clone();

        match &mut cloned {
            StreamProgressMessage::Error(s) => s.push_str(" (retried)"),
            StreamProgressMessage::Progress(v) => panic!("clone changed variant: {v}"),
        }

        match &original {
            StreamProgressMessage::Error(s) => assert_eq!(
                s, "upstream timeout",
                "original Error string must be unchanged after clone mutation"
            ),
            StreamProgressMessage::Progress(v) => panic!("original changed variant: {v}"),
        }

        match &cloned {
            StreamProgressMessage::Error(s) => assert_eq!(s, "upstream timeout (retried)"),
            StreamProgressMessage::Progress(v) => panic!("post-mutation variant flipped: {v}"),
        }
    }

    #[test]
    fn batch_ai_debug_for_pq_node_client_redacts_secret_key_and_pool_state() {
        // The hand-rolled `Debug for PqNodeClient` (L2093) deliberately
        // omits `my_dil_sk` and `pool`. A future `#[derive(Debug)]`
        // switch (or a "helpful" addition of those fields) would start
        // logging the secret key bytes on every `tracing::debug!("{:?}",
        // client)` — pin the redaction contract.
        let marker_sk = b"DO_NOT_LEAK_THIS_BYTE_PATTERN_IN_DEBUG_OUTPUT".to_vec();
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(vec![0u8; 16], marker_sk, pins);

        let dbg = format!("{client:?}");

        assert!(
            !dbg.contains("my_dil_sk"),
            "secret-key field name MUST NOT appear in Debug — would leak \
             secret bytes through structured logs. Got: {dbg}"
        );
        assert!(
            !dbg.contains("pool"),
            "pool field name MUST NOT appear in Debug — internal mutex \
             state is operator-noise + leaks peer addrs to logs. Got: {dbg}"
        );
        assert!(
            !dbg.contains("DO_NOT_LEAK"),
            "marker bytes from the synthetic secret key MUST NOT surface \
             in Debug output. Got: {dbg}"
        );

        // Sanity: the redaction didn't accidentally strip the OK fields.
        assert!(
            dbg.contains("PqNodeClient"),
            "Debug must still tag the struct name: {dbg}"
        );
        assert!(
            dbg.contains("my_dil_pk_len"),
            "Debug must still expose the public-key length field: {dbg}"
        );
        assert!(
            dbg.contains("pins"),
            "Debug must still expose the pin-store field for operator \
             observability: {dbg}"
        );
    }

    #[test]
    fn batch_ai_debug_for_pq_node_client_my_dil_pk_len_tracks_input_pk_length() {
        // `my_dil_pk_len` in Debug is `self.my_dil_pk.len()` — a future
        // refactor that swapped this for e.g. `Arc::strong_count(&self.my_dil_pk)`
        // would silently render `1` on every Debug print and break the
        // operator's ability to spot a malformed key length at a glance.
        // Pin the formula across three lengths: empty (degenerate), small
        // (synthetic), and real Dilithium3 (1952 bytes).
        for len in [0_usize, 7, 1952] {
            let pins = Arc::new(PeerIdentityStore::in_memory());
            let client = PqNodeClient::new(vec![0u8; len], Vec::new(), pins);
            let dbg = format!("{client:?}");
            let needle = format!("my_dil_pk_len: {len}");
            assert!(
                dbg.contains(&needle),
                "Debug must render exact pk length as '{needle}' (formula \
                 = self.my_dil_pk.len()), got: {dbg}"
            );
        }

        // Boundary: changing the pk length between two clients of the
        // same struct shape MUST produce two distinct Debug renders so
        // operators can distinguish them in side-by-side log diffs.
        let pins1 = Arc::new(PeerIdentityStore::in_memory());
        let pins2 = Arc::new(PeerIdentityStore::in_memory());
        let small = PqNodeClient::new(vec![0u8; 7], Vec::new(), pins1);
        let large = PqNodeClient::new(vec![0u8; 1952], Vec::new(), pins2);
        assert_ne!(
            format!("{small:?}"),
            format!("{large:?}"),
            "two clients with different pk lengths must produce distinct Debug renders"
        );
    }
}
