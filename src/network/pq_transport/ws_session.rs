//! WSS-tunneled ELPQ session for browser/explorer clients (4E.1 Phase C).
//!
//! Browsers cannot open raw TCP sockets, so the runtime exposes a parallel
//! ELPQ entry point on `/pq-ws`. The wire shape:
//!
//! - One WebSocket binary message body = one ELPQ message body.
//! - Three messages drive the handshake (Hello / Challenge / Auth).
//! - Post-handshake, each WS binary message body is one AEAD ciphertext
//!   over the standard `PqRequest`/`PqResponse` envelope. The pre-AEAD
//!   plaintext is identical to what `PqStream::send`/`recv` would carry
//!   on a TCP-backed `PqStream` — so the same `pq_router` dispatch
//!   handles both transports.
//!
//! No `Frame` magic header on the WS path: WebSocket frames already
//! provide message boundaries, and the handshake message order is fixed.
//! TCP path keeps its `Frame` envelope (`Hello`/`Challenge`/`Auth`/`Data`/…)
//! because raw TCP streams need an in-band type discriminator. Two
//! transports, two framings, one identical inner protocol.
//!
//! # AEAD post-handshake
//!
//! Both sides exit the handshake with `k_send.counter = 1` and
//! `next_recv_counter = 1` — counter 0 is consumed by the AEAD-wrapped
//! `Auth` payload during handshake. Each Data exchange increments by 1
//! on each side independently.
//!
//! # Lifecycle
//!
//! `pq_ws_session` runs the responder handshake (with a 10-second
//! deadline matching `DEFAULT_HANDSHAKE_TIMEOUT`), then loops:
//! decrypt-request → `PqHandler` dispatch → encrypt-response → write.
//! Returns when the peer closes, the AEAD fails, or `recv` errors.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures_util::StreamExt;

use super::crypto::AeadKey;
use super::handshake::{HandshakeError, PqHandshake};
use super::router::{dispatch_stream_to_sink, pq_router, pq_streaming_methods};
use super::rpc::{status as pq_status, PqRequest, PqResponse, PqStreamChunk, RpcError, StreamSink};
use super::stream::TransportError;
use crate::network::pq_server::PqHandler;
use crate::network::state::NodeState;

/// Same ceiling as the TCP path; DOS-resistance against half-open peers.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-message ceiling for the `/pq-ws` socket. tungstenite's default is
/// 64 MiB, which an UNAUTHENTICATED peer can force the node to buffer per
/// connection before any crypto runs — at `ws_max_connections` that is a
/// node-wide OOM lever on phone-tier hardware. We cap at the TCP data
/// ceiling ([`MAX_PAYLOAD`](super::frame::MAX_PAYLOAD)) plus AEAD/framing
/// overhead, so all legitimate traffic is unaffected while the worst-case
/// pre-auth buffer drops ~4×. Handshake messages are far smaller (msg2 =
/// 6397 B); a tighter handshake-phase cap would need per-RPC-method size
/// audits and is tracked as a follow-up.
const MAX_WS_MESSAGE: usize = super::frame::MAX_PAYLOAD + 4096;

// Compile-time DoS-cap invariants (enforced in EVERY build, not just `cargo test`).
// An unauthenticated `/pq-ws` peer must not be able to make the node buffer
// tungstenite's 64 MiB per-message default before any crypto runs (× ws_max_connections
// = node OOM); the cap must still cover a full `MAX_PAYLOAD` (~16 MiB) data frame plus
// AEAD/framing overhead so legitimate traffic is never clipped. A future bump back
// toward 64 MiB must update these deliberately.
const _: () = assert!(
    MAX_WS_MESSAGE < (64 << 20),
    "MAX_WS_MESSAGE must shed the 64 MiB tungstenite default"
);
const _: () = assert!(
    MAX_WS_MESSAGE >= super::frame::MAX_PAYLOAD,
    "MAX_WS_MESSAGE must cover a full data-frame payload"
);

/// Releases one `/pq-ws` connection slot on drop. The slot is reserved
/// atomically in [`pq_ws_handler`] BEFORE the upgrade so concurrent upgrades
/// cannot race past a load-then-increment gap and overshoot the cap (each
/// live slot can buffer up to [`MAX_WS_MESSAGE`]). Holding the release in a
/// guard captured by the `on_upgrade` closure means the slot is freed on
/// every exit path — session end, mid-session connection drop, OR the
/// upgrade callback being dropped without ever running — so a reserved slot
/// can never leak.
struct WsSlotGuard(Arc<NodeState>);

impl Drop for WsSlotGuard {
    fn drop(&mut self) {
        self.0
            .ws_connections
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WsSessionError {
    #[error("ws closed before handshake completed")]
    PeerClosedDuringHandshake,
    #[error("non-binary ws frame received (text/ping/pong are protocol violations on /pq-ws)")]
    NonBinaryFrame,
    #[error("handshake: {0}")]
    Handshake(#[from] HandshakeError),
    #[error("handshake timed out after {0:?}")]
    HandshakeTimeout(Duration),
    #[error("ws transport error: {0}")]
    WsTransport(String),
    #[error("aead verification failed (transit corruption or tampering)")]
    AeadFailed,
    #[error("recv counter exhausted")]
    RecvCounterExhausted,
}

/// Read one binary frame off the WebSocket. `Some(None)` is the "peer
/// gracefully closed" signal; we treat it the same as an error inside
/// the handshake but as a clean session end post-handshake.
async fn read_binary(ws: &mut WebSocket) -> Result<Option<Vec<u8>>, WsSessionError> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(bytes))) => return Ok(Some(bytes.to_vec())),
            // Pings/pongs are handled by axum's tungstenite layer
            // automatically — we shouldn't see them here, but if a
            // client sends one explicitly, ignore and keep reading.
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | None => return Ok(None),
            Some(Ok(Message::Text(_))) => return Err(WsSessionError::NonBinaryFrame),
            Some(Err(e)) => return Err(WsSessionError::WsTransport(e.to_string())),
        }
    }
}

async fn write_binary(ws: &mut WebSocket, bytes: Vec<u8>) -> Result<(), WsSessionError> {
    ws.send(Message::Binary(bytes.into()))
        .await
        .map_err(|e| WsSessionError::WsTransport(e.to_string()))
}

/// Drive the responder handshake to completion over `ws`. Returns the
/// completed handshake (containing session keys + peer identity) on
/// success.
async fn run_responder_handshake(
    ws: &mut WebSocket,
    my_dil_pk: Vec<u8>,
    my_dil_sk: Vec<u8>,
) -> Result<super::handshake::CompletedHandshake, WsSessionError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut hs = PqHandshake::new_responder(my_dil_pk, my_dil_sk, now)?;

    let msg1 = read_binary(ws)
        .await?
        .ok_or(WsSessionError::PeerClosedDuringHandshake)?;
    let msg2 = hs.responder_process_msg1(&msg1)?;
    write_binary(ws, msg2).await?;

    let msg3 = read_binary(ws)
        .await?
        .ok_or(WsSessionError::PeerClosedDuringHandshake)?;
    hs.responder_process_msg3(&msg3)?;

    Ok(hs.into_completed()?)
}

/// `StreamSink` adapter over a live WS session. Holds mutable
/// references to the socket and the send-side AEAD key so each chunk
/// is encrypted with the next counter and written as one binary frame
/// — wire-identical to the WS path's unary response framing, just
/// repeated until the handler emits a FINAL chunk.
struct WsStreamSink<'a> {
    ws: &'a mut WebSocket,
    k_send: &'a mut AeadKey,
}

impl<'a> StreamSink for WsStreamSink<'a> {
    fn send_stream_chunk<'b>(
        &'b mut self,
        chunk: &'b PqStreamChunk,
    ) -> Pin<Box<dyn Future<Output = Result<(), RpcError>> + Send + 'b>> {
        Box::pin(async move {
            let pt = chunk.encode();
            let ct = self
                .k_send
                .encrypt(&[], &pt)
                .map_err(|_| RpcError::Transport(TransportError::AeadFailed))?;
            self.ws
                .send(Message::Binary(ct.into()))
                .await
                .map_err(|e| {
                    RpcError::Transport(TransportError::Io(std::io::Error::other(e.to_string())))
                })?;
            Ok(())
        })
    }
}

/// Run a complete `/pq-ws` session: handshake, then repeated
/// request/response cycles via `handler`, until the peer closes or an
/// error surfaces. Errors are returned to the caller (the axum upgrade
/// task) so the connection counter can be decremented and the failure
/// optionally logged.
///
/// Streaming methods (see `pq_streaming_methods()` — currently
/// `seal_progress_stream` and `node_events_stream`) are dispatched
/// through `dispatch_stream_to_sink` with a `WsStreamSink`. Each
/// chunk is encrypted with the next k_send counter and emitted as one
/// WS binary frame, so a account can subscribe to seal progress or node
/// events over the same `/pq-ws` socket it uses for unary RPCs.
pub async fn pq_ws_session(
    mut ws: WebSocket,
    my_dil_pk: Vec<u8>,
    my_dil_sk: Vec<u8>,
    handler: PqHandler,
    state: Arc<NodeState>,
) -> Result<(), WsSessionError> {
    // Bound the handshake — slow-loris attackers must not hold sockets.
    let mut completed = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        run_responder_handshake(&mut ws, my_dil_pk, my_dil_sk),
    )
    .await
    {
        Ok(res) => res?,
        Err(_) => return Err(WsSessionError::HandshakeTimeout(HANDSHAKE_TIMEOUT)),
    };

    let peer_identity_hash = completed.peer_identity_hash;
    let mut next_recv_counter: u64 = 1;
    let streaming_methods = pq_streaming_methods();

    // STREAM-F1 parity with the TCP serve loop (pq_server.rs): a handshaked
    // peer that goes silent must not pin this task + its ws slot forever, and
    // one connection must not serve unbounded requests. Same bounds as the TCP
    // twin's SERVE_IDLE_READ_TIMEOUT / MAX_REQUESTS_PER_CONNECTION — the WS
    // path simply never got them (2026-07-12 sweep A7).
    const WS_IDLE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
    const WS_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
    const WS_MAX_REQUESTS_PER_CONNECTION: usize = 1024;

    for _ in 0..WS_MAX_REQUESTS_PER_CONNECTION {
        // Decrypt incoming request frame. Idle timeout = quiet drop: a legit
        // idle client reconnects (this side runs no keep-alive pings).
        let ct = match tokio::time::timeout(WS_IDLE_READ_TIMEOUT, read_binary(&mut ws)).await {
            Err(_elapsed) => return Ok(()),
            Ok(r) => match r? {
                Some(b) => b,
                None => return Ok(()), // Clean close.
            },
        };
        let plaintext = match completed.session.k_recv.decrypt(next_recv_counter, &[], &ct) {
            Ok(pt) => pt,
            Err(_) => {
                // Post-handshake AEAD failure on the /pq-ws read surface — the
                // same seed-side wire-break signal as the TCP serve path, so it
                // shares the `pq_serve_frame_decrypt_failed_total` counter.
                // Count before tearing the session down; a clean close returns
                // `None` from `read_binary` above and never reaches here.
                state
                    .pq_serve_frame_decrypt_failed_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(WsSessionError::AeadFailed);
            }
        };
        next_recv_counter = next_recv_counter
            .checked_add(1)
            .ok_or(WsSessionError::RecvCounterExhausted)?;

        // Parse the envelope. Decode failure replies with a 400 unary
        // response — a buggy client shouldn't terminate the account's
        // connection.
        let req = match PqRequest::decode(&plaintext) {
            Ok(mut req) => {
                req.peer_identity_hash = peer_identity_hash;
                req
            }
            Err(e) => {
                let resp =
                    PqResponse::new(pq_status::BAD_REQUEST, format!("{e}").into_bytes());
                let ct = completed
                    .session
                    .k_send
                    .encrypt(&[], &resp.encode())
                    .map_err(|_| WsSessionError::AeadFailed)?;
                match tokio::time::timeout(WS_WRITE_TIMEOUT, write_binary(&mut ws, ct)).await {
                    Err(_elapsed) => {
                        tracing::warn!("pq-ws: 400-reply send timed out, dropping connection");
                        return Ok(());
                    }
                    Ok(r) => r?,
                }
                continue;
            }
        };

        if streaming_methods.iter().any(|m| m == &req.method) {
            // Streaming dispatch: hand the WS session over to the same
            // handlers the TCP path uses, via a borrowed sink. The handler
            // returns when it has emitted a FINAL chunk — control returns
            // here and the loop continues for the next request on the same
            // socket.
            let mut sink = WsStreamSink {
                ws: &mut ws,
                k_send: &mut completed.session.k_send,
            };
            dispatch_stream_to_sink(state.clone(), req, &mut sink).await;
        } else {
            let resp = handler(req).await;
            // Encrypt + write response. encrypt() bumps k_send.counter for us.
            let ct = completed
                .session
                .k_send
                .encrypt(&[], &resp.encode())
                .map_err(|_| WsSessionError::AeadFailed)?;
            // Write-side deadline: a peer that stops draining otherwise pins
            // this task on write_binary forever (the read timeout can't fire
            // while a write is in flight). WARN, not silent — the 2026-07-01
            // stalled-witness incident hid behind a wordless send failure.
            match tokio::time::timeout(WS_WRITE_TIMEOUT, write_binary(&mut ws, ct)).await {
                Err(_elapsed) => {
                    tracing::warn!(
                        "pq-ws: response send timed out ({}s), dropping connection",
                        WS_WRITE_TIMEOUT.as_secs()
                    );
                    return Ok(());
                }
                Ok(r) => r?,
            }
        }
    }
    // Request budget exhausted — close; a long-lived legit client reconnects
    // (mirrors the TCP twin falling out of its bounded serve loop).
    Ok(())
}

/// Axum handler for the `/pq-ws` route. Upgrades the HTTP connection to a
/// WebSocket and runs an ELPQ session backed by `pq_router(state)`. The
/// node's own Dilithium3 long-term identity is reused — same identity the
/// TCP `PqListener` binds to, so a account can reach the same node identity
/// via either transport.
///
/// Capacity: uses the per-node `ws_connections` counter as the single
/// WebSocket budget. /ws Slice 3c retired the legacy `/ws` route, so this
/// transport is the only one charging against the gauge.
pub async fn pq_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<NodeState>>,
) -> impl IntoResponse {
    let max = state.config.ws_max_connections;
    // Reserve the slot atomically up front. A load-then-increment (the prior
    // shape) let N concurrent upgrades all observe `current < max` and all
    // proceed, overshooting the cap by the in-flight request count — and each
    // admitted connection can buffer up to MAX_WS_MESSAGE, so an unbounded
    // count is a direct OOM lever. fetch_add returns the prior value: if it
    // already met a positive ceiling, roll the reservation back and shed.
    let prev = state
        .ws_connections
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    if max > 0 && prev >= max as u64 {
        state
            .ws_connections
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    // From here the slot is owned by `slot`; its Drop releases it on every
    // path below (including a never-run upgrade callback).
    let slot = WsSlotGuard(state.clone());

    let pk = state.identity.public_key.clone();
    let sk = state.identity.secret_key_bytes();
    let handler = pq_router(state.clone());
    let conn_state = state.clone();
    let session_state = state.clone();

    // Cap the buffer tungstenite assembles per message before handing us
    // bytes — its 64 MiB default is an unauthenticated amplification lever.
    ws.max_message_size(MAX_WS_MESSAGE)
        .on_upgrade(move |socket| async move {
            let _slot = slot; // released when this future ends or is dropped
            conn_state
                .pq_ws_sessions_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _ = pq_ws_session(socket, pk, sk, handler, session_state).await;
        })
        .into_response()
}

// End-to-end testing of `pq_ws_session` against a real axum server requires
// a WS client crate (tokio-tungstenite) which isn't currently in dev-deps.
// The protocol logic this module assembles is heavily covered by:
//   - `handshake.rs` tests for the 3-message state machine (incl. AEAD wrap of
//     msg2/msg3 over transcript-bound ad)
//   - `rpc.rs` tests for `PqRequest`/`PqResponse` envelope round-trips
//   - `stream.rs` tests for post-handshake AEAD encrypt/decrypt counter flow
// What this module adds on top is purely the I/O glue: read one binary WS
// frame, drive the state machine, write one binary WS frame. End-to-end
// coverage lands when the browser-node consumer (Phase C client side) ships
// against a local node — that is the natural integration test for this path.
//
// The tests below pin a few invariants that the I/O glue alone is responsible
// for (timeout parity with the TCP path, user-facing Display strings, the
// `#[from] HandshakeError` shortcut) so that regressions in those land as a
// failing `cargo test`, not as a silent runtime drift.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::pq_transport::DEFAULT_HANDSHAKE_TIMEOUT;

    #[test]
    fn handshake_timeout_matches_tcp_default() {
        // Doc comment promises parity with the TCP path. If one constant
        // is bumped without the other, the WS path becomes either a
        // slow-loris hole or a too-aggressive disconnect.
        assert_eq!(HANDSHAKE_TIMEOUT, DEFAULT_HANDSHAKE_TIMEOUT);
    }

    #[test]
    fn ws_session_error_display_strings_are_user_visible() {
        // Each variant's Display string must be non-empty and free of
        // the placeholder Debug shape (`Variant {`), so log scrapers and
        // operators see a real message rather than the enum name.
        let cases: Vec<WsSessionError> = vec![
            WsSessionError::PeerClosedDuringHandshake,
            WsSessionError::NonBinaryFrame,
            WsSessionError::HandshakeTimeout(HANDSHAKE_TIMEOUT),
            WsSessionError::WsTransport("connection reset".into()),
            WsSessionError::AeadFailed,
            WsSessionError::RecvCounterExhausted,
        ];
        for err in cases {
            let s = err.to_string();
            assert!(!s.is_empty(), "Display empty for {err:?}");
            assert!(
                !s.starts_with("WsSessionError"),
                "Display fell back to Debug for {err:?}: {s}"
            );
        }
    }

    #[test]
    fn handshake_error_converts_via_from() {
        // The `?` operator inside `run_responder_handshake` relies on
        // `HandshakeError -> WsSessionError` via #[from]. Removing the
        // attribute would silently break that path; this test pins it.
        let inner = HandshakeError::Malformed("bad msg1");
        let outer: WsSessionError = inner.into();
        match outer {
            WsSessionError::Handshake(HandshakeError::Malformed(s)) => {
                assert_eq!(s, "bad msg1");
            }
            other => panic!("expected Handshake(Malformed), got {other:?}"),
        }
    }

    #[test]
    fn handshake_timeout_is_literal_ten_seconds() {
        // The TCP-parity assertion above passes vacuously if BOTH constants
        // get bumped together. This pin locks the absolute floor — the
        // slow-loris DOS budget the `/pq-ws` route exposes is 10s, not
        // "whatever DEFAULT_HANDSHAKE_TIMEOUT happens to be today". A
        // raise needs to be deliberate (update both this test AND the
        // shared constant), not silent.
        assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(10));
    }

    #[test]
    fn handshake_error_source_chain_is_walkable() {
        // `#[error("handshake: {0}")]` on the Handshake variant must leave
        // the inner HandshakeError reachable via std::error::Error::source.
        // Log scrapers that walk source() to surface the root-cause string
        // depend on this — `e.to_string()` alone collapses to "handshake: …"
        // and discards which HandshakeError variant fired.
        use std::error::Error;
        let outer = WsSessionError::Handshake(HandshakeError::SignatureInvalid);
        let src = outer.source().expect("source chain present");
        let inner = src
            .downcast_ref::<HandshakeError>()
            .expect("source downcasts to HandshakeError");
        assert!(matches!(inner, HandshakeError::SignatureInvalid));
    }

    #[test]
    fn handshake_timeout_display_includes_duration() {
        // The `HandshakeTimeout(Duration)` variant carries the actual
        // configured deadline so an operator reading the log can tell a
        // 10s-window expiry from a hypothetical 60s-tuning regression.
        // The empty-string check upstairs would pass even if the Duration
        // were dropped from the format — this pins the field is rendered.
        let err = WsSessionError::HandshakeTimeout(Duration::from_secs(10));
        let s = err.to_string();
        assert!(
            s.contains("10s"),
            "Display should surface the duration; got {s:?}"
        );
    }

    // ────────────────────────────────────────────────────────────────────
    // Coverage tests on uncovered invariants.
    // The existing 6 tests pin Display-non-emptiness, From conversion,
    // source-chain presence, timeout parity, and the 10s literal. They
    // do NOT pin the EXACT Display prose, the source-chain ABSENCE on
    // flat variants, Send+Sync auto-traits required by the tokio loop,
    // the WsTransport(String) field rendering matrix, or HANDSHAKE_TIMEOUT
    // unit-cross-arithmetic / DOS-budget bounds. These tests close those.
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn batch_b_handshake_timeout_unit_cross_arithmetic_and_dos_budget_bounds() {
        // HANDSHAKE_TIMEOUT carries the slow-loris DOS budget for /pq-ws.
        // Test 4 already pins the seconds-level literal. This axis pins
        // the value across every Duration accessor (ms/µs/ns), proves
        // it's non-zero (else timeout::timeout short-circuits and the
        // handshake state machine can hang forever on a slow client),
        // and bounds it in [1s, 60s] so a future operator who bumps
        // either floor or ceiling must update this test (and think
        // about whether the DOS surface is acceptable).
        assert_eq!(HANDSHAKE_TIMEOUT.as_secs(), 10);
        assert_eq!(HANDSHAKE_TIMEOUT.as_millis(), 10_000);
        assert_eq!(HANDSHAKE_TIMEOUT.as_micros(), 10_000_000);
        assert_eq!(HANDSHAKE_TIMEOUT.as_nanos(), 10_000_000_000);
        assert!(!HANDSHAKE_TIMEOUT.is_zero(),
            "zero timeout disables tokio::time::timeout — slow-loris hole");
        assert!(HANDSHAKE_TIMEOUT >= Duration::from_secs(1),
            "real-world ELPQ handshake floor; <1s is a false-positive risk");
        assert!(HANDSHAKE_TIMEOUT <= Duration::from_secs(60),
            "DOS budget ceiling — a /pq-ws socket must not be held >60s pre-auth");
        // Cross-product consistency: ms = secs*1000, ns = secs*1e9, etc.
        // A future Duration with a sub-second component would break this.
        assert_eq!(HANDSHAKE_TIMEOUT.subsec_nanos(), 0,
            "HANDSHAKE_TIMEOUT must be whole seconds (debug Display renders e.g. '10s', not '10.5s')");
        assert_eq!(
            HANDSHAKE_TIMEOUT.as_millis() as u64,
            HANDSHAKE_TIMEOUT.as_secs() * 1_000
        );
        assert_eq!(
            HANDSHAKE_TIMEOUT.as_nanos() as u64,
            HANDSHAKE_TIMEOUT.as_secs() * 1_000_000_000
        );
    }

    #[test]
    fn batch_b_ws_session_error_7_variant_exhaustive_exact_display_prose_pin() {
        // The existing display test only pins non-empty + not-debug-fallback.
        // This axis pins the EXACT phrasing of each variant — a log-scraper
        // grepping for "ws closed before handshake" or "aead verification
        // failed" would silently miss matches if the prose drifted. Pinning
        // exact strings forces a deliberate cross-update (test + thiserror
        // attribute + downstream scraper / SOC rule).
        assert_eq!(
            WsSessionError::PeerClosedDuringHandshake.to_string(),
            "ws closed before handshake completed"
        );
        assert_eq!(
            WsSessionError::NonBinaryFrame.to_string(),
            "non-binary ws frame received (text/ping/pong are protocol violations on /pq-ws)"
        );
        assert_eq!(
            WsSessionError::AeadFailed.to_string(),
            "aead verification failed (transit corruption or tampering)"
        );
        assert_eq!(
            WsSessionError::RecvCounterExhausted.to_string(),
            "recv counter exhausted"
        );
        // HandshakeTimeout uses {0:?} on Duration → exact "10s" rendering.
        assert_eq!(
            WsSessionError::HandshakeTimeout(Duration::from_secs(10)).to_string(),
            "handshake timed out after 10s"
        );
        // WsTransport(String) uses {0} (Display, not Debug) → inner string verbatim.
        assert_eq!(
            WsSessionError::WsTransport("connection reset by peer".into()).to_string(),
            "ws transport error: connection reset by peer"
        );
        // Handshake wrapper format pin: "handshake: " prefix + inner Display.
        // SignatureInvalid is one of the 7 inner variants; the wrapper format
        // must surface BOTH the wrapper prefix AND the inner prose verbatim.
        let inner_signature_display =
            "Dilithium3 signature invalid — peer does not hold the claimed identity";
        assert_eq!(
            WsSessionError::Handshake(HandshakeError::SignatureInvalid).to_string(),
            format!("handshake: {inner_signature_display}")
        );
    }

    #[test]
    fn batch_b_ws_session_error_send_sync_static_required_for_tokio_loop() {
        // `pq_ws_session` returns `Result<(), WsSessionError>` from an `async fn`
        // crossing multiple .await points (read_binary, write_binary, decrypt,
        // handler.await). For the resulting Future to be Send (so the axum
        // upgrade task can move it across threads), WsSessionError MUST be
        // Send + Sync + 'static. A future variant carrying a non-Send field
        // (e.g. Rc<…>, MutexGuard) would silently demote the whole error type
        // and the compiler error would surface at a confusing call site
        // (axum's IntoFuture bound) rather than here.
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        fn assert_static<T: 'static>() {}
        fn assert_std_error<T: std::error::Error>() {}
        fn assert_display<T: std::fmt::Display>() {}
        fn assert_debug<T: std::fmt::Debug>() {}
        assert_send::<WsSessionError>();
        assert_sync::<WsSessionError>();
        assert_static::<WsSessionError>();
        assert_std_error::<WsSessionError>();
        assert_display::<WsSessionError>();
        assert_debug::<WsSessionError>();
        // The whole error type must also fit comfortably inside the Result
        // discriminant — a 4KB error variant inflates every async frame's
        // size. Cap at 512 bytes (current shape is ~32-48 bytes, plenty
        // of headroom for future small-string fields).
        let size = std::mem::size_of::<WsSessionError>();
        assert!(
            size <= 512,
            "WsSessionError size = {size} bytes; tokio async frames inline this — keep small"
        );
    }

    #[test]
    fn batch_b_ws_session_error_source_chain_only_handshake_variant_has_source() {
        // The existing test pins that Handshake(inner).source() returns the
        // inner HandshakeError. This axis pins the COMPLEMENT: every other
        // variant returns source() == None, because they don't wrap a foreign
        // error type. A future maintainer adding `#[source]` to e.g. WsTransport
        // would silently change scraper behaviour (log walkers expect a single
        // .source() hop to the HandshakeError leaf, not two). Pin negative too.
        use std::error::Error;
        let cases_no_source: Vec<WsSessionError> = vec![
            WsSessionError::PeerClosedDuringHandshake,
            WsSessionError::NonBinaryFrame,
            WsSessionError::HandshakeTimeout(Duration::from_secs(10)),
            WsSessionError::WsTransport("io".into()),
            WsSessionError::AeadFailed,
            WsSessionError::RecvCounterExhausted,
        ];
        for err in cases_no_source {
            assert!(
                err.source().is_none(),
                "variant {err:?} unexpectedly has a source() chain — only Handshake should"
            );
        }
        // Cover multiple Handshake inner variants to prove the chain is
        // surfaced regardless of which inner HandshakeError fired.
        let handshake_cases = [
            HandshakeError::SignatureInvalid,
            HandshakeError::IdentityPinMismatch,
            HandshakeError::AeadFailed,
            HandshakeError::Malformed("bad msg1"),
            HandshakeError::WrongState("expected msg3"),
            HandshakeError::TimestampSkew {
                skew_secs: 9999,
                max_secs: 300,
            },
        ];
        for inner in handshake_cases {
            let outer = WsSessionError::Handshake(inner);
            let src = outer.source().expect("Handshake variant must have source");
            let downcast = src.downcast_ref::<HandshakeError>();
            assert!(
                downcast.is_some(),
                "source must downcast to HandshakeError for {outer:?}"
            );
        }
    }

    #[test]
    fn batch_b_ws_transport_string_field_rendering_and_handshake_timeout_duration_format_matrix() {
        // The WsTransport(String) variant uses `{0}` (Display, not Debug) on
        // the inner string, so the message is rendered verbatim — no escaping,
        // no quoting, no truncation. This axis pins that contract across a
        // matrix (empty, ASCII, multi-line, UTF-8, surrounding-whitespace)
        // because operators paste these strings directly into incident
        // tickets and a silent encoding change would break copy-paste.
        for (inner, want_suffix) in [
            ("", ""),
            ("connection reset", "connection reset"),
            ("multi\nline", "multi\nline"),
            ("utf8: ñ é 🌀", "utf8: ñ é 🌀"),
            ("  spaces  ", "  spaces  "),
        ] {
            let s = WsSessionError::WsTransport(inner.into()).to_string();
            assert_eq!(s, format!("ws transport error: {want_suffix}"),
                "WsTransport Display must render inner verbatim with prefix");
        }

        // Companion: HandshakeTimeout(Duration) uses {0:?} on Duration.
        // Duration's Debug picks the largest whole unit that divides the
        // value — pin the matrix so a stdlib change (or a fmt rewrite of
        // the #[error] attribute) trips this test instead of silently
        // shifting account/operator log shapes.
        let duration_cases: Vec<(Duration, &str)> = vec![
            (Duration::from_secs(10), "handshake timed out after 10s"),
            (Duration::from_secs(60), "handshake timed out after 60s"),
            (Duration::from_secs(1), "handshake timed out after 1s"),
            (Duration::from_millis(500), "handshake timed out after 500ms"),
            (Duration::from_millis(2_500), "handshake timed out after 2.5s"),
            (Duration::from_micros(750), "handshake timed out after 750µs"),
        ];
        for (d, want) in duration_cases {
            assert_eq!(
                WsSessionError::HandshakeTimeout(d).to_string(),
                want,
                "Duration Debug format must match for {d:?}"
            );
        }
    }
}
