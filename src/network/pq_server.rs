//! Post-quantum server — the listener counterpart of `PqNodeClient`.
//!
//! Owns a `PqListener` plus a user-supplied dispatch closure and runs
//! an accept loop that pumps every incoming request through the closure.
//! Each connection is handled on its own tokio task, so a slow handler
//! for one peer cannot stall the accept loop or block other peers.
//!
//! # Dispatch model
//!
//! The server is deliberately method-agnostic. It does NOT hard-code the
//! 14 RPC methods `PqNodeClient` sends — instead it takes a handler
//! closure of shape `Fn(PqRequest) -> Future<PqResponse>` and routes
//! every request through it. Stage 4B.2b-router will supply a handler
//! that switches on `req.method` and calls the existing route logic;
//! tests can supply any stub.
//!
//! # Connection lifetime
//!
//! A connection may carry multiple back-to-back requests. The server
//! keeps reading until the peer closes, a frame error is seen, or the
//! handshake times out on the next read. No keep-alive pings — the
//! client side owns reconnect.
//!
//! # Graceful shutdown
//!
//! `PqServer` is a resource; drop it and the underlying listener closes.
//! For more controlled shutdown, spawn `run()` on a tokio task and
//! abort the JoinHandle.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;

use super::pq_transport::{
    FrameError, HandshakeError, PqListener, PqRequest, PqResponse, PqStream, RpcError,
    TransportError,
};

/// Boxed future returned by a handler. `'static` because the handler is
/// `Arc`-shared across connection tasks and can't borrow from the caller.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Handler signature: takes a request, returns a future that resolves to a response.
pub type PqHandler = Arc<dyn Fn(PqRequest) -> BoxFuture<PqResponse> + Send + Sync>;

/// Streaming handler signature (4E.3): takes a request AND the underlying
/// [`PqStream`], emits any number of `StreamChunk` frames via
/// [`PqStream::send_stream_chunk`], and finally drops the stream. The server
/// hands the connection off entirely — after this handler returns, the
/// connection closes. Use [`PqStreamChunk::final_chunk`] or
/// [`PqStreamChunk::error`] on the last emission so the client can unwind
/// cleanly (see `pq_transport::rpc`).
pub type PqStreamHandler =
    Arc<dyn Fn(PqRequest, PqStream) -> BoxFuture<()> + Send + Sync>;

/// Build a `PqHandler` from a closure + async body.
///
/// ```ignore
/// let handler = make_handler(|req| async move {
///     PqResponse::ok(format!("got {}", req.method).into_bytes())
/// });
/// ```
pub fn make_handler<F, Fut>(f: F) -> PqHandler
where
    F: Fn(PqRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = PqResponse> + Send + 'static,
{
    Arc::new(move |req| {
        let fut = f(req);
        Box::pin(fut) as BoxFuture<PqResponse>
    })
}

pub struct PqServer {
    listener: PqListener,
    handler: PqHandler,
    /// Optional streaming-handler slot (4E.3). If the first request on a
    /// connection has a method name in `streaming_methods`, the stream is
    /// handed to `stream_handler` and the unary loop exits. Unary and
    /// streaming methods share the same PqHandler set; this is a second
    /// path, not a replacement.
    streaming_methods: HashSet<String>,
    stream_handler: Option<PqStreamHandler>,
    /// B8: accept-path handshake limiter + counters, injected from `NodeState`
    /// via [`with_accept_limiter`](Self::with_accept_limiter). All `Option` so
    /// the simulator/test constructors that never call it run UNLIMITED (no
    /// semaphore, no shedding) — bit-identical to pre-B8 behavior for them.
    /// When set, `run` runs each handshake in a detached task bounded by the
    /// semaphore (over-budget connections are shed, `shed` bumped) and counts
    /// in-task handshake failures in `fail`.
    handshake_sem: Option<Arc<tokio::sync::Semaphore>>,
    handshake_fail_ctr: Option<Arc<AtomicU64>>,
    handshake_shed_ctr: Option<Arc<AtomicU64>>,
    /// STREAM-F1 defense-in-depth: post-handshake serve-connection population
    /// bound, injected from `NodeState` via
    /// [`with_serve_limiter`](Self::with_serve_limiter). The handshake permit
    /// is released before serving BY DESIGN (long-lived request connections
    /// must not consume the handshake budget) and the serve loop's idle
    /// read-deadline bounds how long an idle connection lives — this bounds
    /// how MANY live ones a swarm of handshake-completing peers can pin.
    /// Over-budget connections are shed right after the handshake (stream
    /// dropped → fd freed, `serve_shed_ctr` bumped), never queued. `None`
    /// (sim/tests) = unlimited, pre-existing behavior.
    serve_sem: Option<Arc<tokio::sync::Semaphore>>,
    serve_shed_ctr: Option<Arc<AtomicU64>>,
    /// Post-handshake serve-path frame-decrypt-failure counter, injected from
    /// `NodeState` via [`with_serve_metrics`](Self::with_serve_metrics). When
    /// set, `serve_connection` bumps it ONLY on `TransportError::AeadFailed`
    /// (a peer that completed the handshake then sent an undecryptable frame)
    /// instead of swallowing it in the `Err(_) => return` teardown — the
    /// seed-side symmetric of the follower's `_other_rpc`. `None` in
    /// sim/tests that never call the setter (no counting, pre-existing
    /// behavior).
    serve_decrypt_fail_ctr: Option<Arc<AtomicU64>>,
    /// Accept-path handshake-failure *class* discriminator: the subset of
    /// `handshake_fail_ctr` caused by PQ-wire incompatibility — an explicit
    /// wire-version reject (`Frame(UnsupportedVersion)`: the peer's first
    /// handshake frame carried a different `WIRE_VERSION` byte, caught at
    /// `Frame::decode` before the transcript even matters) or a transcript/AEAD
    /// divergence (`AeadFailed` / `Handshake(AeadFailed)`: keys derived from a
    /// divergent transcript — the secondary belt-and-suspenders catch). Both
    /// are the deterministic signature of a stale/mis-built peer, so a sustained
    /// non-zero on a fresh external join = "that peer built a different commit —
    /// rebuild it to the seed's". Wired via
    /// [`with_handshake_class_metrics`](Self::with_handshake_class_metrics);
    /// `None` in sim/tests = no split, pre-existing behavior.
    handshake_wire_mismatch_ctr: Option<Arc<AtomicU64>>,
}

impl PqServer {
    pub fn new(listener: PqListener, handler: PqHandler) -> Self {
        Self {
            listener,
            handler,
            streaming_methods: HashSet::new(),
            stream_handler: None,
            handshake_sem: None,
            handshake_fail_ctr: None,
            handshake_shed_ctr: None,
            serve_sem: None,
            serve_shed_ctr: None,
            serve_decrypt_fail_ctr: None,
            handshake_wire_mismatch_ctr: None,
        }
    }

    /// STREAM-F1: wire the post-handshake serve-connection cap from
    /// `NodeState` (the `Semaphore` sized by `config.pq_serve_concurrency`,
    /// plus the `pq_serve_shed_total` counter). Once set, a connection that
    /// completes the handshake while the serve population is at capacity is
    /// dropped in O(1) (shed, counted) instead of joining the serve loop.
    /// Production (`elara_node`) always calls this; sim/tests may not.
    pub fn with_serve_limiter(
        mut self,
        sem: Arc<tokio::sync::Semaphore>,
        shed: Arc<AtomicU64>,
    ) -> Self {
        self.serve_sem = Some(sem);
        self.serve_shed_ctr = Some(shed);
        self
    }

    /// B8: wire the accept-path handshake limiter from `NodeState` (the
    /// `Semaphore` sized by `config.pq_handshake_concurrency`, plus the
    /// `pq_handshake_failed_total` / `pq_handshake_shed_total` counters). Once
    /// set, `run` no longer blocks on a slow inbound peer: each handshake runs
    /// in a detached task gated by `try_acquire` (shed-on-saturation, never
    /// queued). Production (`elara_node`) always calls this; sim/tests may not.
    pub fn with_accept_limiter(
        mut self,
        sem: Arc<tokio::sync::Semaphore>,
        fail: Arc<AtomicU64>,
        shed: Arc<AtomicU64>,
    ) -> Self {
        self.handshake_sem = Some(sem);
        self.handshake_fail_ctr = Some(fail);
        self.handshake_shed_ctr = Some(shed);
        self
    }

    /// Wire the post-handshake serve-path frame-decrypt-failure counter from
    /// `NodeState` (`pq_serve_frame_decrypt_failed_total`). Once set,
    /// `serve_connection` discriminates the `recv_request` error: a clean
    /// close (`PeerClosed`/`Io`) tears down silently as before, but a
    /// `TransportError::AeadFailed` — a peer that completed the handshake then
    /// sent an undecryptable frame — bumps this counter so the silent
    /// wire-break is visible on the seed (the box an operator watches when a
    /// new external follower joins), not just on the follower as `_other_rpc`.
    /// Production (`elara_node`) always calls this; sim/tests may not.
    pub fn with_serve_metrics(mut self, decrypt_fail: Arc<AtomicU64>) -> Self {
        self.serve_decrypt_fail_ctr = Some(decrypt_fail);
        self
    }

    /// Wire the accept-path PQ-wire-incompatibility class counter
    /// (`pq_handshake_wire_mismatch_total`) from `NodeState`. It splits the
    /// wire-incompatibility subset (explicit `Frame(UnsupportedVersion)` reject,
    /// plus `AeadFailed`/`Handshake(AeadFailed)` transcript divergence) out of the
    /// opaque `pq_handshake_failed_total` aggregate (which still counts ALL
    /// causes): both are the signature of a peer on an incompatible PQ
    /// `WIRE_VERSION`, so this counter self-diagnoses the #1 first-external-join
    /// failure mode — the one that otherwise just "looks like the network is
    /// dead". Production (`elara_node`) always calls this; sim/tests may not.
    pub fn with_handshake_class_metrics(mut self, wire_mismatch: Arc<AtomicU64>) -> Self {
        self.handshake_wire_mismatch_ctr = Some(wire_mismatch);
        self
    }

    /// Attach a streaming handler for the listed method names (4E.3). When
    /// a connection's first request carries one of these methods, the
    /// server hands the live `PqStream` to the streaming handler instead
    /// of answering unary. Methods not in the set still dispatch through
    /// the existing unary path.
    pub fn with_streaming(
        mut self,
        methods: impl IntoIterator<Item = String>,
        stream_handler: PqStreamHandler,
    ) -> Self {
        self.streaming_methods = methods.into_iter().collect();
        self.stream_handler = Some(stream_handler);
        self
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Run the accept loop forever (until the listener dies).
    ///
    /// Spawn on its own tokio task; abort the JoinHandle to shut down.
    /// Per-connection tasks run on `tokio::spawn` and are orphaned on abort
    /// — they'll finish on their own within the handshake timeout.
    pub async fn run(self) {
        // B8: the accept loop now does ONLY the cheap, serial TCP accept; the
        // responder handshake (the slow, attacker-controllable phase) runs in a
        // detached task, so one slow/half-open inbound peer can no longer stall
        // new-peer admission. When a limiter is wired (production via
        // `with_accept_limiter`), each handshake task first TRY-acquires a
        // semaphore permit: over-budget connections are SHED (TCP dropped,
        // `pq_handshake_shed_total` bumped) rather than queued, so a flood can't
        // pile up parked tasks holding fds. The permit is held only across the
        // handshake — NOT across serve_connection — so long-lived request
        // connections don't consume the handshake budget. Per-connection
        // handshake errors are counted (`pq_handshake_failed_total`) in-task;
        // pre-B8 they surfaced to a recoverable-error match here, which post-
        // split only ever sees true listener-level accept(2) errors.
        let streaming_methods = Arc::new(self.streaming_methods);
        let stream_handler = self.stream_handler;
        let handler = self.handler;
        let handshake_sem = self.handshake_sem;
        let handshake_fail_ctr = self.handshake_fail_ctr;
        let handshake_shed_ctr = self.handshake_shed_ctr;
        let serve_sem = self.serve_sem;
        let serve_shed_ctr = self.serve_shed_ctr;
        let serve_decrypt_fail_ctr = self.serve_decrypt_fail_ctr;
        let handshake_wire_mismatch_ctr = self.handshake_wire_mismatch_ctr;
        loop {
            // accept_tcp() errors are LISTENER-level (the freshly-accepted TCP
            // never reaches here pre-handshake). Keep accepting after them —
            // do NOT take down the listener on a transient accept(2) failure.
            let (tcp, _peer) = match self.listener.accept_tcp().await {
                Ok(t) => t,
                Err(_) => continue,
            };
            // Shed-on-saturation: take the permit BEFORE spawning so a flood is
            // rejected in O(1) without spawning a task or holding an fd. With no
            // limiter wired (sim/tests) the path is unlimited, as pre-B8.
            let permit = match &handshake_sem {
                Some(sem) => match sem.clone().try_acquire_owned() {
                    Ok(p) => Some(p),
                    Err(_) => {
                        if let Some(c) = &handshake_shed_ctr {
                            c.fetch_add(1, Relaxed);
                        }
                        drop(tcp); // fast reject; the dialer retries
                        continue;
                    }
                },
                None => None,
            };
            let params = self.listener.handshake_params();
            let handler = handler.clone();
            let sm = streaming_methods.clone();
            let sh = stream_handler.clone();
            let fail_ctr = handshake_fail_ctr.clone();
            let wire_mismatch_ctr = handshake_wire_mismatch_ctr.clone();
            let sdf = serve_decrypt_fail_ctr.clone();
            let ssem = serve_sem.clone();
            let sshed = serve_shed_ctr.clone();
            tokio::spawn(async move {
                let permit = permit; // held across the handshake only
                match PqListener::finish_handshake_accepted(tcp, params).await {
                    Ok(stream) => {
                        drop(permit); // free the handshake slot before serving
                        // STREAM-F1: admission to the serve population. Taken
                        // AFTER the handshake, not before — a pre-handshake
                        // acquire would let half-open dials consume serve
                        // slots for free; completing the handshake costs the
                        // peer real PQ work first. Shed-not-queue: a queued
                        // connection would hold the fd the cap exists to
                        // protect. No limiter wired (sim/tests) = unlimited.
                        let _serve_permit = match &ssem {
                            Some(sem) => match sem.clone().try_acquire_owned() {
                                Ok(p) => Some(p),
                                Err(_) => {
                                    if let Some(c) = &sshed {
                                        c.fetch_add(1, Relaxed);
                                    }
                                    return; // stream drops here → fd freed
                                }
                            },
                            None => None,
                        };
                        serve_connection(stream, handler, sm, sh, sdf).await;
                    }
                    Err(e) => {
                        // Per-connection handshake failure (timeout / malformed
                        // / sovereign-denied / admission-rejected / AEAD). Drop
                        // the connection and count it so it is not silent — this
                        // counter is the post-split replacement for the pre-B8
                        // accept-loop recoverable-error match's visibility.
                        if let Some(c) = &fail_ctr {
                            c.fetch_add(1, Relaxed);
                        }
                        // Split out the PQ-wire-incompatibility sub-cause: an
                        // explicit wire-version reject (the peer's first frame
                        // carried a different WIRE_VERSION byte) or a transcript/
                        // AEAD divergence. Both are the signature of a peer on an
                        // incompatible commit. Counting it separately
                        // self-diagnoses the first-external-join "network looks
                        // dead" trap without log-flooding this attacker-reachable
                        // accept path.
                        if is_handshake_wire_mismatch(&e) {
                            if let Some(c) = &wire_mismatch_ctr {
                                c.fetch_add(1, Relaxed);
                            }
                        }
                        // permit (if any) drops here too.
                    }
                }
            });
        }
    }
}

/// True ONLY for the post-handshake silent-wire-break signal: a peer that
/// completed the PQ handshake then sent a frame whose AEAD tag did not verify
/// (`RpcError::Transport(TransportError::AeadFailed)`). A clean teardown
/// (`Transport(PeerClosed)`, `Transport(Io)` EOF), the envelope-decode class
/// (`TooShort`/`HeaderOverflow`/`BadHeaderJson` — shape drift, the follower's
/// `_other_decode`, not a frame-decrypt failure), and every other variant
/// return false, so the serve-decrypt counter tracks genuine AEAD wire/key
/// divergence — NOT connection churn or header drift. Extracted as the single
/// seam the counter's correctness depends on: collapsing `serve_connection`'s
/// match back to a blind `Err(_)` would have to delete this and its test.
fn is_serve_decrypt_failure(e: &RpcError) -> bool {
    matches!(e, RpcError::Transport(TransportError::AeadFailed))
}

/// True for the PQ-wire-incompatibility signatures at the handshake: an
/// explicit wire-version reject (`Frame(UnsupportedVersion)` — the peer's first
/// handshake frame carried a `WIRE_VERSION` byte this node doesn't speak,
/// caught at `Frame::decode` on msg1 before the transcript matters; the
/// deterministic signature of a stale/mis-built peer) OR a transcript/AEAD
/// divergence (`AeadFailed` / `Handshake(AeadFailed)` — session keys derived
/// from divergent transcripts; the secondary belt-and-suspenders catch). Every
/// other failure (timeout / clean close / admission / sovereign-deny /
/// malformed) returns false, so `pq_handshake_wire_mismatch_total` isolates
/// "this peer built an incompatible commit; rebuild it" from the opaque
/// `pq_handshake_failed_total` aggregate. The single seam the split's
/// correctness depends on (mirrors `is_serve_decrypt_failure`): collapsing the
/// accept-loop `Err(e)` match back to a blind `Err(_)` would have to delete
/// this and its test.
fn is_handshake_wire_mismatch(e: &TransportError) -> bool {
    matches!(
        e,
        TransportError::Frame(FrameError::UnsupportedVersion(_))
            | TransportError::AeadFailed
            | TransportError::Handshake(HandshakeError::AeadFailed)
    )
}

async fn serve_connection(
    mut stream: PqStream,
    handler: PqHandler,
    streaming_methods: Arc<HashSet<String>>,
    stream_handler: Option<PqStreamHandler>,
    decrypt_fail_ctr: Option<Arc<AtomicU64>>,
) {
    // Bound the per-connection request count so a single long-lived
    // client can't hog a connection forever. Production caller can
    // raise or remove this — but for an MVP accept loop a hard cap
    // keeps the footprint predictable.
    const MAX_REQUESTS_PER_CONNECTION: usize = 1024;

    // STREAM-F1: cap how long a post-handshake peer may hold this serve task
    // (and its file descriptor) without delivering a full request frame. The
    // handshake accept-limiter permit is released BEFORE serving (see run()),
    // and `read_frame` does a bare `read_exact` with no deadline — so without
    // this bound a peer that completes the handshake then withholds or dribbles
    // bytes pins the task forever at zero cost to itself. On a single-authority
    // seed that is a direct path from one joiner to fd/OOM exhaustion of the
    // sole sealing node. A legitimate request frame is small and arrives in
    // well under this window; an idle kept-alive connection is expected to
    // reconnect (this side runs no keep-alive pings), so reaping it is correct.
    const SERVE_IDLE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

    // Write-side twin of the read deadline: `send_response` bottoms out in a
    // bare `write_all`, so a peer that stops draining its socket pins this
    // serve task (and fd) forever — the read timeout can't fire while a write
    // is in flight. 60 s passes the largest legit frame (16 MiB − 1) even on a
    // slow-but-honest link; a stalled peer is dropped (2026-07-12 sweep A7).
    const SERVE_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

    // Bind every request this connection yields to the authenticated peer
    // identity from the PQ handshake. Method handlers that need to act on
    // behalf of the caller (e.g. AUDIT-9 Milestone B2 symmetric profile
    // registration) read `req.peer_identity_hash` instead of trusting any
    // identity claim in the request body.
    let peer_hash = stream.peer_identity_hash();

    for _ in 0..MAX_REQUESTS_PER_CONNECTION {
        let recv = match tokio::time::timeout(SERVE_IDLE_READ_TIMEOUT, stream.recv_request()).await
        {
            Ok(r) => r,
            Err(_elapsed) => {
                // STREAM-F1: the peer held the connection past the idle window
                // without completing a request frame. Drop it — the stream
                // (and its fd) frees on return. Debug, not warn: a slow or
                // idle peer is not an error, just uninteresting to keep.
                tracing::debug!(
                    "pq serve: idle read timeout ({}s), dropping connection peer={}",
                    SERVE_IDLE_READ_TIMEOUT.as_secs(),
                    hex::encode(&peer_hash[..8.min(peer_hash.len())]),
                );
                return;
            }
        };
        let mut req = match recv {
            Ok(r) => r,
            Err(e) => {
                // Discriminate the silent wire-break from a clean teardown.
                // A peer that completed the handshake then sent an
                // undecryptable frame (`AeadFailed`) is the seed-side
                // symmetric of the follower's `_other_rpc`; a clean close is
                // `PeerClosed`/`Io` and MUST NOT bump the counter (it would
                // then just mirror connection count). See
                // `pq_serve_frame_decrypt_failed_total`.
                if is_serve_decrypt_failure(&e) {
                    if let Some(c) = &decrypt_fail_ctr {
                        c.fetch_add(1, Relaxed);
                    }
                }
                return;
            }
        };
        req.peer_identity_hash = peer_hash;

        // 4E.3 streaming path: if the method is registered as streaming and
        // a handler is configured, hand the stream over and exit the loop.
        // One streaming request consumes the whole connection — subsequent
        // unary requests on the same connection are not supported. This
        // keeps the dispatch rules simple and matches how HTTP/1 /events
        // and gRPC server-streams behave.
        if streaming_methods.contains(&req.method) {
            if let Some(sh) = &stream_handler {
                sh(req, stream).await;
                return;
            }
            // No handler wired but method name is registered — fall through
            // to unary path and emit NOT_IMPLEMENTED so we don't silently
            // hang. Shouldn't happen in production (both sides come from
            // the same router), but harden the edge anyway.
            let resp = PqResponse::new(
                super::pq_transport::rpc::status::NOT_IMPLEMENTED,
                b"streaming method registered without handler".to_vec(),
            );
            let _ = tokio::time::timeout(SERVE_WRITE_TIMEOUT, stream.send_response(&resp)).await;
            return;
        }

        let method = req.method.clone();
        let resp = handler(req).await;

        match tokio::time::timeout(SERVE_WRITE_TIMEOUT, stream.send_response(&resp)).await {
            Err(_elapsed) => {
                // Peer completed a request then stopped draining the response.
                tracing::warn!(
                    "pq serve: response send timed out ({}s) method={} status={} body={}B peer={} — dropping connection",
                    SERVE_WRITE_TIMEOUT.as_secs(),
                    method,
                    resp.status,
                    resp.body.len(),
                    hex::encode(&peer_hash[..8.min(peer_hash.len())]),
                );
                return;
            }
            Ok(Err(e)) => {
                // Never drop a serve-side send failure silently: an oversized
                // handler response ("payload too large", frame cap 16 MiB−1)
                // otherwise presents as a wordless connection close on BOTH ends
                // — the 2026-07-01 stalled-witness incident hid behind exactly
                // this line. Handlers must chunk/budget; this WARN names the
                // method so the offender is greppable.
                tracing::warn!(
                    "pq serve: response send failed method={} status={} body={}B peer={}: {e} — dropping connection",
                    method,
                    resp.status,
                    resp.body.len(),
                    hex::encode(&peer_hash[..8.min(peer_hash.len())]),
                );
                return;
            }
            Ok(Ok(())) => {}
        }
    }

    // Best-effort close; we're dropping the stream either way.
    let _ = stream.close().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::pq_client::{PqNodeClient, TestIdentity};
    use crate::network::pq_transport::{status, PeerIdentityStore};

    fn echo_handler() -> PqHandler {
        make_handler(|req| async move {
            match req.method.as_str() {
                "ping" => PqResponse::ok(b"pong".to_vec()),
                "merkle_root" => {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "root": "cafebabe"
                    }))
                    .unwrap();
                    PqResponse::ok(body)
                }
                "status" => {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "ok": true, "method": "pq_server"
                    }))
                    .unwrap();
                    PqResponse::ok(body)
                }
                // Echo arbitrary methods back in body for general-purpose tests
                other => PqResponse::ok(format!("method={other}").into_bytes()),
            }
        })
    }

    async fn spawn_server(
        server_id: &TestIdentity,
        handler: PqHandler,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = PqListener::bind(
            "127.0.0.1:0",
            server_id.pk.clone(),
            server_id.sk.clone(),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = PqServer::new(listener, handler);
        let handle = tokio::spawn(server.run());
        (addr, handle)
    }

    /// Like `spawn_server` but wires the post-handshake serve-decrypt counter
    /// so a test can assert on `pq_serve_frame_decrypt_failed_total` behavior.
    async fn spawn_server_with_serve_ctr(
        server_id: &TestIdentity,
        handler: PqHandler,
        serve_ctr: Arc<AtomicU64>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = PqListener::bind(
            "127.0.0.1:0",
            server_id.pk.clone(),
            server_id.sk.clone(),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = PqServer::new(listener, handler).with_serve_metrics(serve_ctr);
        let handle = tokio::spawn(server.run());
        (addr, handle)
    }

    #[test]
    fn is_serve_decrypt_failure_counts_only_aead_not_clean_close() {
        // The counter's whole correctness rests on this discrimination: a
        // post-handshake AEAD failure is the silent-wire-break signal and MUST
        // count; a clean teardown (PeerClosed / Io EOF) and every other frame
        // error MUST NOT, or the metric degrades into a connection-churn
        // tracker indistinguishable from `Err(_) => return`.
        assert!(is_serve_decrypt_failure(&RpcError::Transport(
            TransportError::AeadFailed
        )));
        assert!(!is_serve_decrypt_failure(&RpcError::Transport(
            TransportError::PeerClosed
        )));
        assert!(!is_serve_decrypt_failure(&RpcError::Transport(
            TransportError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        )));
        assert!(!is_serve_decrypt_failure(&RpcError::Transport(
            TransportError::RecvCounterExhausted
        )));
        // Envelope-decode (shape-drift) class must NOT count — that is the
        // follower's `_other_decode`, distinct from a frame-decrypt failure.
        assert!(!is_serve_decrypt_failure(&RpcError::TooShort));
    }

    #[tokio::test]
    async fn serve_decrypt_counter_bumps_on_post_handshake_aead_tamper() {
        // Complete a REAL PQ handshake, then send a frame whose Poly1305 tag is
        // corrupted: the seed decrypts post-handshake, fails, and must surface
        // it on the counter instead of swallowing it in the teardown path.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let ctr = Arc::new(AtomicU64::new(0));
        let (addr, h) =
            spawn_server_with_serve_ctr(&server_id, echo_handler(), ctr.clone()).await;

        let mut stream = super::super::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            super::super::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();
        stream
            .send_tampered_data_frame(b"undecryptable")
            .await
            .unwrap();

        // Let the detached serve task recv + classify the tampered frame.
        for _ in 0..50 {
            if ctr.load(Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            ctr.load(Relaxed),
            1,
            "post-handshake AEAD frame-decrypt failure must bump the serve-decrypt counter"
        );
        h.abort();
    }

    #[tokio::test]
    async fn serve_decrypt_counter_silent_on_clean_traffic_and_close() {
        // A full valid request/response then a clean client drop must leave the
        // counter at 0 — the false-positive guard that separates this metric
        // from a blind per-connection teardown count.
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let ctr = Arc::new(AtomicU64::new(0));
        let (addr, h) =
            spawn_server_with_serve_ctr(&server_id, echo_handler(), ctr.clone()).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);
        assert!(client.ping(&addr.to_string()).await);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            ctr.load(Relaxed),
            0,
            "valid traffic followed by a clean close must NOT bump the serve-decrypt counter"
        );
        h.abort();
    }

    #[tokio::test]
    async fn client_ping_server_returns_pong() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, h) = spawn_server(&server_id, echo_handler()).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        assert!(client.ping(&addr.to_string()).await);
        h.abort();
    }

    #[tokio::test]
    async fn client_status_round_trip() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, h) = spawn_server(&server_id, echo_handler()).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let v = client.get_status(&addr.to_string()).await.unwrap();
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["method"], serde_json::json!("pq_server"));
        h.abort();
    }

    #[tokio::test]
    async fn client_merkle_root_round_trip() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, h) = spawn_server(&server_id, echo_handler()).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        let root = client.get_merkle_root(&addr.to_string()).await.unwrap();
        assert_eq!(root, "cafebabe");
        h.abort();
    }

    #[tokio::test]
    async fn handler_closure_sees_every_method_string() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_handler = {
            let c = counter.clone();
            make_handler(move |req| {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    PqResponse::ok(req.method.into_bytes())
                }
            })
        };

        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, h) = spawn_server(&server_id, counter_handler).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);

        // 3 different methods — each call opens a fresh connection today
        // (no client-side pool yet).
        let _ = client.ping(&addr.to_string()).await;
        let _ = client.get_status(&addr.to_string()).await;
        let _ = client.get_merkle_root(&addr.to_string()).await;

        // Allow the spawned connection tasks to run the handler.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert_eq!(counter.load(Ordering::SeqCst), 3);
        h.abort();
    }

    #[tokio::test]
    async fn unknown_method_returns_not_found_when_handler_chooses_to() {
        let nf_handler = make_handler(|req| async move {
            match req.method.as_str() {
                "ping" => PqResponse::ok(b"p".to_vec()),
                _ => PqResponse::new(status::NOT_FOUND, Vec::new()),
            }
        });

        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, h) = spawn_server(&server_id, nf_handler).await;

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let _client = PqNodeClient::new(client_id.pk.clone(), client_id.sk.clone(), pins);

        // Bypass the client's happy-path helpers and send a raw request so we
        // can inspect the status code directly.
        let mut stream = super::super::pq_transport::pq_dial(
            addr,
            client_id.pk,
            client_id.sk,
            super::super::pq_transport::PeerExpectation::Tofu,
        )
        .await
        .unwrap();
        let resp = stream.call(&PqRequest::new("bogus")).await.unwrap();
        assert_eq!(resp.status, status::NOT_FOUND);
        h.abort();
    }

    #[tokio::test]
    async fn hostile_garbage_does_not_kill_accept_loop() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, h) = spawn_server(&server_id, echo_handler()).await;

        // Send plain TCP garbage — the PQ handshake rejects it, and the
        // server loop must keep accepting afterwards.
        {
            use tokio::io::AsyncWriteExt;
            let mut junk = tokio::net::TcpStream::connect(addr).await.unwrap();
            junk.write_all(b"GET /status HTTP/1.1\r\n\r\n").await.unwrap();
            drop(junk);
        }

        // After the garbage drop, a legitimate client must still succeed.
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);
        assert!(client.ping(&addr.to_string()).await);
        h.abort();
    }

    // ─── PqServer builder + make_handler invariants ────
    // Each test pins a private-field or builder-contract invariant the existing
    // round-trip tests don't catch.

    #[allow(clippy::doc_lazy_continuation)]
    /// `make_handler` produces a `Send + Sync + 'static` `PqHandler`. The
    /// type-alias contract is `Arc<dyn Fn(PqRequest) -> BoxFuture<PqResponse>
    /// + Send + Sync>`; a future async-fn-trait refactor that lost `Send`
    /// (e.g. accidentally captured `Rc<...>` or returned a non-Send future)
    /// would compile here as long as the closure type satisfies `Fn`, but
    /// would fail downstream where the handler is shared across spawned
    /// per-connection tokio tasks. Pin the trait-object bounds at the SDK
    /// boundary so the regression surfaces at this test, not at runtime.
    #[test]
    fn batch_b_make_handler_produces_send_sync_static_pq_handler() {
        fn assert_send_sync_static<T: Send + Sync + 'static>(_: &T) {}
        let h: PqHandler = make_handler(|req| async move {
            PqResponse::ok(req.method.into_bytes())
        });
        assert_send_sync_static(&h);
    }

    /// `PqServer::new` initialises streaming routing as an EMPTY registration:
    /// `streaming_methods` is an empty HashSet AND `stream_handler` is `None`.
    /// A future "set sensible defaults" refactor that injected a sentinel
    /// streaming method (or a default no-op stream handler) would silently
    /// route an incoming request through the streaming path even when the
    /// caller only ever asked for unary dispatch — the per-connection loop
    /// would hand off the stream and the unary loop would never run for that
    /// method. Pin both private fields directly (test module sees them).
    #[tokio::test]
    async fn batch_b_pq_server_new_initialises_empty_streaming_routing() {
        let server_id = TestIdentity::new();
        let listener = super::super::pq_transport::PqListener::bind(
            "127.0.0.1:0",
            server_id.pk.clone(),
            server_id.sk.clone(),
        )
        .await
        .unwrap();
        let server = PqServer::new(listener, echo_handler());
        assert!(
            server.streaming_methods.is_empty(),
            "PqServer::new must initialise streaming_methods as empty — got {} entries",
            server.streaming_methods.len(),
        );
        assert!(
            server.stream_handler.is_none(),
            "PqServer::new must initialise stream_handler as None",
        );
    }

    /// `PqServer::with_streaming` populates BOTH `streaming_methods` AND
    /// `stream_handler` in a single builder call. Pin that a partial-population
    /// regression (e.g. handler stored but method names dropped via a typo in
    /// the field assignment, or vice versa) fails here — at runtime the
    /// per-connection dispatch path would silently fall through to the unary
    /// handler with a `NOT_IMPLEMENTED` response, masking the wiring bug.
    #[tokio::test]
    async fn batch_b_pq_server_with_streaming_populates_both_methods_and_handler() {
        let server_id = TestIdentity::new();
        let listener = super::super::pq_transport::PqListener::bind(
            "127.0.0.1:0",
            server_id.pk.clone(),
            server_id.sk.clone(),
        )
        .await
        .unwrap();
        let stream_h: PqStreamHandler = Arc::new(|_req, _stream| {
            Box::pin(async move {})
        });
        let server = PqServer::new(listener, echo_handler()).with_streaming(
            [
                "subscribe_headers".to_string(),
                "subscribe_records".to_string(),
            ],
            stream_h,
        );
        assert_eq!(
            server.streaming_methods.len(),
            2,
            "with_streaming must register exactly the supplied method count",
        );
        assert!(
            server.streaming_methods.contains("subscribe_headers"),
            "subscribe_headers must be registered",
        );
        assert!(
            server.streaming_methods.contains("subscribe_records"),
            "subscribe_records must be registered",
        );
        assert!(
            server.stream_handler.is_some(),
            "with_streaming must install the stream handler",
        );
    }

    /// `PqServer::with_streaming` second call REPLACES the prior registration
    /// — it is NOT additive. A chain of
    /// `.with_streaming(["a"], h1).with_streaming(["b"], h2)` must leave the
    /// server with only "b" registered. Pin against a future "merge on
    /// rebuild" refactor that accumulated method names across builder calls;
    /// such a refactor would silently retain stale handlers for "a" while the
    /// caller believed only "b" was active — routing ambiguity that surfaces
    /// only as a per-request mystery at the streaming dispatch path.
    #[tokio::test]
    async fn batch_b_pq_server_with_streaming_second_call_replaces_not_accumulates() {
        let server_id = TestIdentity::new();
        let listener = super::super::pq_transport::PqListener::bind(
            "127.0.0.1:0",
            server_id.pk.clone(),
            server_id.sk.clone(),
        )
        .await
        .unwrap();
        let stream_h1: PqStreamHandler =
            Arc::new(|_req, _stream| Box::pin(async move {}));
        let stream_h2: PqStreamHandler =
            Arc::new(|_req, _stream| Box::pin(async move {}));
        let server = PqServer::new(listener, echo_handler())
            .with_streaming(["alpha".to_string()], stream_h1)
            .with_streaming(["beta".to_string()], stream_h2);
        assert_eq!(
            server.streaming_methods.len(),
            1,
            "second with_streaming call must replace, not accumulate — got {} registrations",
            server.streaming_methods.len(),
        );
        assert!(
            server.streaming_methods.contains("beta"),
            "second-call method 'beta' must be present",
        );
        assert!(
            !server.streaming_methods.contains("alpha"),
            "first-call method 'alpha' must be dropped (not retained)",
        );
        assert!(
            server.stream_handler.is_some(),
            "stream_handler must still be installed after second call",
        );
    }

    /// `PqServer::with_streaming` dedups duplicate method names in the input
    /// iterable via `HashSet<String>::collect()`. Passing
    /// `["a", "a", "b"]` (one duplicate) yields a 2-element registration. Pin
    /// against a future refactor that switched the field to `Vec<String>` for
    /// "ordered routes" — the linear lookup `streaming_methods.contains(...)`
    /// would still work, masking the bug, but every duplicate would silently
    /// inflate the per-request scan cost and could mask routing ambiguity if
    /// a future "first match wins" iteration order replaces set semantics.
    #[tokio::test]
    async fn batch_b_pq_server_with_streaming_dedups_duplicate_method_names() {
        let server_id = TestIdentity::new();
        let listener = super::super::pq_transport::PqListener::bind(
            "127.0.0.1:0",
            server_id.pk.clone(),
            server_id.sk.clone(),
        )
        .await
        .unwrap();
        let stream_h: PqStreamHandler =
            Arc::new(|_req, _stream| Box::pin(async move {}));
        let dup_input = vec![
            "subscribe_headers".to_string(),
            "subscribe_headers".to_string(), // duplicate
            "subscribe_records".to_string(),
        ];
        let server = PqServer::new(listener, echo_handler())
            .with_streaming(dup_input, stream_h);
        assert_eq!(
            server.streaming_methods.len(),
            2,
            "duplicate method names must collapse via HashSet semantics — got {} entries from a 3-item input with one dup",
            server.streaming_methods.len(),
        );
        assert!(server.streaming_methods.contains("subscribe_headers"));
        assert!(server.streaming_methods.contains("subscribe_records"));
    }

    // ── B8: concurrent accept-path handshake (fusion-audited 2026-06-19) ──────
    // The handshake now runs in a detached task so one slow/half-open inbound
    // peer can no longer stall new-peer admission; a Semaphore bounds in-flight
    // handshakes and sheds over-budget connections (never queues).

    /// THE load-bearing regression: a silent peer that completes TCP but never
    /// sends its Hello frame must NOT block admission of a legitimate peer.
    /// Pre-B8 the serial `accept()` held the loop for the full 10s handshake
    /// timeout; post-B8 the silent peer's handshake is detached and the legit
    /// client is admitted in milliseconds.
    #[tokio::test]
    async fn b8_slow_peer_does_not_block_new_admissions() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let (addr, h) = spawn_server(&server_id, echo_handler()).await;

        // Silent peer: connect TCP, then send nothing (holds a handshake slot
        // for the full timeout). Pre-B8 this wedges the serial accept loop.
        let _silent = tokio::net::TcpStream::connect(addr).await.unwrap();

        // A legitimate client must still be admitted well within the 10s
        // handshake timeout — bound at 3s to prove the loop is not serialized.
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);
        let pinged = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client.ping(&addr.to_string()),
        )
        .await;
        assert!(
            matches!(pinged, Ok(true)),
            "legit client must be admitted within 3s despite a silent peer holding a handshake slot — got {pinged:?}"
        );
        drop(_silent);
        h.abort();
    }

    /// Saturated limiter sheds inbound connections in O(1) (drops TCP, bumps
    /// `shed`), never queues — and a shed is NOT counted as a handshake failure.
    #[tokio::test]
    async fn b8_handshake_shed_when_limiter_saturated() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let listener = PqListener::bind(
            "127.0.0.1:0",
            server_id.pk.clone(),
            server_id.sk.clone(),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();

        let sem = Arc::new(tokio::sync::Semaphore::new(1));
        let fail = Arc::new(AtomicU64::new(0));
        let shed = Arc::new(AtomicU64::new(0));
        let server = PqServer::new(listener, echo_handler())
            .with_accept_limiter(sem.clone(), fail.clone(), shed.clone());
        let h = tokio::spawn(server.run());

        // Exhaust the only permit so every inbound handshake is shed.
        let held = sem.acquire_owned().await.unwrap();

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk, client_id.sk, pins);
        // Dial: server accepts TCP, try_acquire fails, sheds (drops TCP). The
        // counter is the real signal; don't hang on the dial result.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.ping(&addr.to_string()),
        )
        .await;

        let mut shed_seen = false;
        for _ in 0..60 {
            if shed.load(Relaxed) >= 1 {
                shed_seen = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(shed_seen, "a saturated limiter must shed the inbound connection");
        assert_eq!(fail.load(Relaxed), 0, "a shed connection is not a handshake failure");
        drop(held);
        h.abort();
    }

    /// STREAM-F1 defense-in-depth: a saturated serve-connection cap sheds a
    /// connection AFTER its handshake completes (stream dropped → fd freed,
    /// `pq_serve_shed_total` bumped, request never served), and a freed slot
    /// admits the next connection normally.
    #[tokio::test]
    async fn stream_f1_serve_cap_sheds_post_handshake_when_saturated() {
        let server_id = TestIdentity::new();
        let client_id = TestIdentity::new();
        let listener = PqListener::bind(
            "127.0.0.1:0",
            server_id.pk.clone(),
            server_id.sk.clone(),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();

        let serve_sem = Arc::new(tokio::sync::Semaphore::new(1));
        let serve_shed = Arc::new(AtomicU64::new(0));
        let server = PqServer::new(listener, echo_handler())
            .with_serve_limiter(serve_sem.clone(), serve_shed.clone());
        let h = tokio::spawn(server.run());

        // Exhaust the only serve slot so the next post-handshake connection
        // is shed. (Holding the permit externally stands in for a live
        // connection mid-serve.)
        let held = serve_sem.clone().acquire_owned().await.unwrap();

        let pins = Arc::new(PeerIdentityStore::in_memory());
        let client = PqNodeClient::new(client_id.pk.clone(), client_id.sk.clone(), pins);
        // The handshake COMPLETES (no accept limiter here), then the server
        // drops the stream before serving — the request must fail, not hang.
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.ping(&addr.to_string()),
        )
        .await;
        assert!(
            !matches!(r, Ok(true)),
            "a shed connection must not be served — got {r:?}"
        );
        let mut shed_seen = false;
        for _ in 0..60 {
            if serve_shed.load(Relaxed) >= 1 {
                shed_seen = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(shed_seen, "a saturated serve cap must bump pq_serve_shed_total");

        // Free the slot: a fresh connection must be admitted and served.
        drop(held);
        let pins2 = Arc::new(PeerIdentityStore::in_memory());
        let client2 = PqNodeClient::new(client_id.pk, client_id.sk, pins2);
        let r2 = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client2.ping(&addr.to_string()),
        )
        .await;
        assert!(
            matches!(r2, Ok(true)),
            "after a slot frees, the next connection must be served — got {r2:?}"
        );
        h.abort();
    }

    /// An in-task handshake failure (malformed frame) increments
    /// `pq_handshake_failed_total` — the post-split replacement for the pre-B8
    /// accept-loop recoverable-error visibility — and is NOT a shed.
    #[tokio::test]
    async fn b8_handshake_failure_increments_fail_counter() {
        use tokio::io::AsyncWriteExt;
        let server_id = TestIdentity::new();
        let listener = PqListener::bind(
            "127.0.0.1:0",
            server_id.pk.clone(),
            server_id.sk.clone(),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();

        let sem = Arc::new(tokio::sync::Semaphore::new(8));
        let fail = Arc::new(AtomicU64::new(0));
        let shed = Arc::new(AtomicU64::new(0));
        let wire_mismatch = Arc::new(AtomicU64::new(0));
        let server = PqServer::new(listener, echo_handler())
            .with_accept_limiter(sem, fail.clone(), shed.clone())
            .with_handshake_class_metrics(wire_mismatch.clone());
        let h = tokio::spawn(server.run());

        // A well-formed 9-byte frame header with BAD magic and ZERO payload
        // length: read_frame reads the header, reads 0 payload bytes, then
        // Frame::decode rejects on BadMagic — a FAST handshake failure. (Raw
        // garbage would set a bogus large length field, blocking read_exact
        // until the 10s handshake timeout instead.) magic "XXXX" ≠ "ELPQ",
        // version 0x01, type 0x00, len 0x000000.
        let mut peer = tokio::net::TcpStream::connect(addr).await.unwrap();
        peer.write_all(&[b'X', b'X', b'X', b'X', 0x01, 0x00, 0x00, 0x00, 0x00]).await.unwrap();
        let _ = peer.flush().await;

        let mut fail_seen = false;
        for _ in 0..60 {
            if fail.load(Relaxed) >= 1 {
                fail_seen = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(fail_seen, "a malformed handshake must increment pq_handshake_failed_total");
        assert_eq!(shed.load(Relaxed), 0, "a malformed handshake is a failure, not a shed");
        // Real-path discrimination: a BadMagic frame is rejected at decode as
        // FrameError::BadMagic — NOT a wire-version reject or AEAD divergence —
        // so it counts in the aggregate but must stay OUT of the
        // wire-mismatch split. (The wrong-WIRE_VERSION case is exercised
        // end-to-end in b8_wrong_wire_version_increments_wire_mismatch_split.)
        assert_eq!(
            wire_mismatch.load(Relaxed),
            0,
            "a BadMagic malformed handshake is not a PQ-wire incompatibility — \
             pq_handshake_wire_mismatch_total must not count it"
        );
        drop(peer);
        h.abort();
    }

    /// A handshake frame with a VALID ELPQ magic but a `WIRE_VERSION` byte this
    /// node doesn't speak is rejected at frame decode (`UnsupportedVersion`) and
    /// must increment BOTH the aggregate `pq_handshake_failed_total` AND the
    /// `pq_handshake_wire_mismatch_total` split — the live signature of a
    /// stale/mis-built peer (e.g. a fleet node left on an older WIRE_VERSION). This is
    /// the first-external-join "looks like the network is dead" trap, now
    /// self-diagnosing on the seed an operator watches.
    #[tokio::test]
    async fn b8_wrong_wire_version_increments_wire_mismatch_split() {
        use tokio::io::AsyncWriteExt;
        let server_id = TestIdentity::new();
        let listener = PqListener::bind(
            "127.0.0.1:0",
            server_id.pk.clone(),
            server_id.sk.clone(),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();

        let sem = Arc::new(tokio::sync::Semaphore::new(8));
        let fail = Arc::new(AtomicU64::new(0));
        let shed = Arc::new(AtomicU64::new(0));
        let wire_mismatch = Arc::new(AtomicU64::new(0));
        let server = PqServer::new(listener, echo_handler())
            .with_accept_limiter(sem, fail.clone(), shed.clone())
            .with_handshake_class_metrics(wire_mismatch.clone());
        let h = tokio::spawn(server.run());

        // Valid magic "ELPQ", a version byte that differs from the current
        // WIRE_VERSION, type 0x00, zero payload len. Frame::decode accepts the
        // magic, then rejects with UnsupportedVersion(wrong) → the frame read in
        // handshake_responder surfaces TransportError::Frame(UnsupportedVersion).
        let wrong = crate::network::pq_transport::WIRE_VERSION.wrapping_add(1);
        let mut peer = tokio::net::TcpStream::connect(addr).await.unwrap();
        peer.write_all(&[b'E', b'L', b'P', b'Q', wrong, 0x00, 0x00, 0x00, 0x00]).await.unwrap();
        let _ = peer.flush().await;

        let mut seen = false;
        for _ in 0..60 {
            if wire_mismatch.load(Relaxed) >= 1 {
                seen = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(seen, "a wrong-WIRE_VERSION handshake frame must increment pq_handshake_wire_mismatch_total");
        assert!(fail.load(Relaxed) >= 1, "a version reject is also a handshake failure (counts in the aggregate)");
        assert_eq!(shed.load(Relaxed), 0, "a version reject is a failure, not a shed");
        drop(peer);
        h.abort();
    }

    /// The split's correctness seam: ONLY the PQ-wire-incompatibility variants
    /// (explicit version reject + transcript/AEAD divergence) trip
    /// `pq_handshake_wire_mismatch_total`; every other failure class stays in
    /// the aggregate only.
    #[test]
    fn is_handshake_wire_mismatch_isolates_wire_variants() {
        // explicit wire-version reject — the stale-built-peer signature
        assert!(is_handshake_wire_mismatch(&TransportError::Frame(
            FrameError::UnsupportedVersion(0x01)
        )));
        // transcript/AEAD divergence — secondary catch
        assert!(is_handshake_wire_mismatch(&TransportError::AeadFailed));
        assert!(is_handshake_wire_mismatch(&TransportError::Handshake(
            HandshakeError::AeadFailed
        )));
        // NOT wire-incompatibility: these stay in the aggregate only
        assert!(!is_handshake_wire_mismatch(&TransportError::Frame(FrameError::BadMagic)));
        assert!(!is_handshake_wire_mismatch(&TransportError::PeerClosed));
        assert!(!is_handshake_wire_mismatch(&TransportError::HandshakeTimeout(
            std::time::Duration::from_secs(10)
        )));
        assert!(!is_handshake_wire_mismatch(&TransportError::Handshake(
            HandshakeError::Malformed("x")
        )));
        assert!(!is_handshake_wire_mismatch(&TransportError::SovereignDenied("x".into())));
    }
}
