//! Minimal request/response envelope over [`PqStream`].
//!
//! gossip.rs / sync.rs / server.rs today make HTTP calls shaped like
//! `(method = URL path, headers, body) → (status, body)`. Stage 4B.2
//! replaces each of those with a [`PqStream`] round-trip. To avoid
//! every call site inventing its own framing, this module pins one
//! canonical envelope.
//!
//! # Wire format
//!
//! Request (one [`super::frame::FrameType::Data`] frame's plaintext):
//!
//! ```text
//! | header_len:u32 BE | header_json:bytes | body:bytes |
//! ```
//!
//! where `header_json` is `{"method": "<path>", "headers": {...}}`,
//! and `body` is opaque bytes (often JSON, sometimes CBOR / binary).
//!
//! Response (one frame's plaintext):
//!
//! ```text
//! | status:u16 BE | body:bytes |
//! ```
//!
//! Status codes use HTTP semantics (200 OK, 4xx client error, 5xx server
//! error) so call sites can mirror the existing reqwest-based logic.
//!
//! # Scope
//!
//! - No pipelining. Strict serial req/resp per `PqStream`. Pools of
//!   `PqStream`s can handle concurrency at the caller level.
//! - No framing inside the body. If the body exceeds a single frame's
//!   capacity (≈16 MiB minus envelope overhead) the caller must chunk.
//!   In practice every current call site sends ≪ 1 MiB.
//! - No compression. Add later if real workloads prove it worthwhile.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};

use super::stream::{PqStream, TransportError};

/// HTTP-style status for replies. Not an exhaustive enum — any u16 is
/// valid on the wire; these are sentinels callers can reach for.
pub mod status {
    pub const OK: u16 = 200;
    pub const BAD_REQUEST: u16 = 400;
    pub const UNAUTHORIZED: u16 = 401;
    pub const NOT_FOUND: u16 = 404;
    pub const TOO_MANY_REQUESTS: u16 = 429;
    pub const INTERNAL_ERROR: u16 = 500;
    pub const NOT_IMPLEMENTED: u16 = 501;
    pub const SERVICE_UNAVAILABLE: u16 = 503;
}

/// Errors specific to the RPC envelope layer. Transport-level failures
/// surface as [`TransportError`] instead.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("envelope too short to be a valid request/response")]
    TooShort,
    #[error("declared header_len {declared} exceeds frame size {total}")]
    HeaderOverflow { declared: usize, total: usize },
    #[error("declared header_len {declared} exceeds cap {max}")]
    HeaderTooLarge { declared: usize, max: usize },
    #[error("malformed header JSON: {0}")]
    BadHeaderJson(#[from] serde_json::Error),
    #[error("header missing required field: {0}")]
    MissingField(&'static str),
    #[error("header encode: {0}")]
    EncodeJson(#[source] serde_json::Error),
}

/// Cap on the declared request-header length before `serde_json::from_slice`.
/// The header is a tiny `{method, headers}` map — a method name plus a handful
/// of short routing headers (`id`/`seal_id`/`since_epoch`, or at most a hex
/// pubkey ~4 KiB) — so a few KiB at most. Without this cap an admitted peer
/// could declare a header up to the frame ceiling (`MAX_PAYLOAD` ~16 MiB) and
/// force a 16 MiB `from_slice` into a `BTreeMap` (~10× transient heap) on EVERY
/// request, before dispatch — the same decode-amplifier the body verbs guard.
/// Fail-closed: oversized ⇒ `HeaderTooLarge` before any parse.
const MAX_REQ_HEADER_BYTES: usize = 64 * 1024;

/// Decoded form of a request envelope on either side of the wire.
///
/// `peer_identity_hash` is NOT on the wire — it's populated by the server
/// after the PQ handshake completes (from `PqStream::peer_identity_hash()`)
/// so method handlers can bind their actions to the authenticated caller
/// without trusting claims in the request body. All-zeros on the client
/// side and for freshly decoded (pre-dispatch) requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqRequest {
    pub method: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub peer_identity_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct ReqHeaderOnWire {
    method: String,
    headers: BTreeMap<String, String>,
}

impl PqRequest {
    pub fn new<M: Into<String>>(method: M) -> Self {
        Self {
            method: method.into(),
            headers: BTreeMap::new(),
            body: Vec::new(),
            peer_identity_hash: [0u8; 32],
        }
    }

    pub fn with_header<K: Into<String>, V: Into<String>>(mut self, k: K, v: V) -> Self {
        self.headers.insert(k.into(), v.into());
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    pub fn encode(&self) -> Result<Vec<u8>, RpcError> {
        let header = ReqHeaderOnWire {
            method: self.method.clone(),
            headers: self.headers.clone(),
        };
        let header_bytes = serde_json::to_vec(&header).map_err(RpcError::EncodeJson)?;
        let mut out = Vec::with_capacity(4 + header_bytes.len() + self.body.len());
        out.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RpcError> {
        if bytes.len() < 4 {
            return Err(RpcError::TooShort);
        }
        let header_len =
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if header_len > MAX_REQ_HEADER_BYTES {
            return Err(RpcError::HeaderTooLarge {
                declared: header_len,
                max: MAX_REQ_HEADER_BYTES,
            });
        }
        let header_end = 4usize.checked_add(header_len).ok_or(RpcError::TooShort)?;
        if bytes.len() < header_end {
            return Err(RpcError::HeaderOverflow {
                declared: header_len,
                total: bytes.len(),
            });
        }
        let header: ReqHeaderOnWire = serde_json::from_slice(&bytes[4..header_end])?;
        let body = bytes[header_end..].to_vec();
        Ok(Self {
            method: header.method,
            headers: header.headers,
            body,
            peer_identity_hash: [0u8; 32],
        })
    }
}

/// Decoded form of a response envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl PqResponse {
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    pub fn ok(body: Vec<u8>) -> Self {
        Self { status: status::OK, body }
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.body.len());
        out.extend_from_slice(&self.status.to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RpcError> {
        if bytes.len() < 2 {
            return Err(RpcError::TooShort);
        }
        let status = u16::from_be_bytes([bytes[0], bytes[1]]);
        let body = bytes[2..].to_vec();
        Ok(Self { status, body })
    }
}

// ─── Streaming response envelope (4E.3, FrameType::StreamChunk) ──────────

/// Flag bits for [`PqStreamChunk::flags`]. Bit positions are wire format.
pub mod stream_flags {
    /// Last chunk in the stream. The receiver stops after processing it.
    pub const FINAL: u8 = 0b0000_0001;
    /// Chunk carries an error payload; `body` is a UTF-8 error message.
    pub const ERROR: u8 = 0b0000_0010;
}

/// A single chunk in a streaming response.
///
/// # Wire format (payload of one [`super::frame::FrameType::StreamChunk`] frame)
///
/// ```text
/// | flags: u8 | seq: u32 BE | body: bytes |
/// ```
///
/// - `flags` is a bitfield ([`stream_flags`]).
/// - `seq` is a monotonic sequence number starting at 0. The receiver
///   MAY reject out-of-order chunks.
/// - `body` is opaque bytes (usually JSON matching the shape the
///   non-streaming version of the endpoint returns).
///
/// A streaming response is a contiguous series of chunks sharing the
/// same underlying [`PqStream`] as the request that opened it. The last
/// chunk MUST have `flags & FINAL != 0`; no more frames follow. If a
/// chunk carries `ERROR`, the server SHOULD also set `FINAL` in the
/// same chunk so the receiver can unwind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqStreamChunk {
    pub flags: u8,
    pub seq: u32,
    pub body: Vec<u8>,
}

impl PqStreamChunk {
    /// Build a non-final chunk with the given sequence number and body.
    pub fn data(seq: u32, body: Vec<u8>) -> Self {
        Self { flags: 0, seq, body }
    }

    /// Build the final chunk (terminates the stream).
    pub fn final_chunk(seq: u32, body: Vec<u8>) -> Self {
        Self { flags: stream_flags::FINAL, seq, body }
    }

    /// Build a terminal error chunk. Sets both FINAL and ERROR. The
    /// body is the UTF-8 error message.
    pub fn error(seq: u32, msg: impl Into<String>) -> Self {
        Self {
            flags: stream_flags::FINAL | stream_flags::ERROR,
            seq,
            body: msg.into().into_bytes(),
        }
    }

    pub fn is_final(&self) -> bool {
        self.flags & stream_flags::FINAL != 0
    }

    pub fn is_error(&self) -> bool {
        self.flags & stream_flags::ERROR != 0
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 4 + self.body.len());
        out.push(self.flags);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RpcError> {
        if bytes.len() < 5 {
            return Err(RpcError::TooShort);
        }
        let flags = bytes[0];
        let seq = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let body = bytes[5..].to_vec();
        Ok(Self { flags, seq, body })
    }
}

// ─── StreamSink — abstract sink for streaming chunks (4E.1 Phase D) ──────

/// Object-safe sink for streaming responses. Decouples the streaming
/// handlers (`handle_seal_progress_stream`, `handle_node_events_stream`)
/// from the underlying transport so the same handler can drive a TCP
/// `PqStream` or a WSS-tunneled session — the Phase C `/pq-ws` route
/// gets server-push without duplicating handler bodies.
///
/// Implementors are responsible for any framing and AEAD; from the
/// handler's POV `send_stream_chunk` is "encrypt + write one chunk" and
/// the handler stops when it has emitted a chunk with the FINAL flag set.
pub trait StreamSink: Send {
    fn send_stream_chunk<'a>(
        &'a mut self,
        chunk: &'a PqStreamChunk,
    ) -> Pin<Box<dyn Future<Output = Result<(), RpcError>> + Send + 'a>>;
}

impl StreamSink for PqStream {
    fn send_stream_chunk<'a>(
        &'a mut self,
        chunk: &'a PqStreamChunk,
    ) -> Pin<Box<dyn Future<Output = Result<(), RpcError>> + Send + 'a>> {
        // Delegate to the inherent `PqStream::send_stream_chunk` defined
        // below. Inherent methods take priority over trait methods, so
        // calling `self.send_stream_chunk` inside this impl would loop;
        // use a direct `send_typed` call to avoid the ambiguity.
        Box::pin(async move {
            self.send_typed(super::frame::FrameType::StreamChunk, &chunk.encode())
                .await
                .map_err(RpcError::from)
        })
    }
}

// ─── Convenience methods on PqStream ─────────────────────────────────────

impl PqStream {
    /// Send a request envelope as a single Data frame.
    pub async fn send_request(&mut self, req: &PqRequest) -> Result<(), RpcError> {
        self.send(&req.encode()?).await.map_err(RpcError::from)
    }

    /// Receive one Data frame and parse it as a request.
    pub async fn recv_request(&mut self) -> Result<PqRequest, RpcError> {
        let bytes = self.recv().await.map_err(RpcError::from)?;
        PqRequest::decode(&bytes)
    }

    /// Send a response envelope as a single Data frame.
    pub async fn send_response(&mut self, resp: &PqResponse) -> Result<(), RpcError> {
        self.send(&resp.encode()).await.map_err(RpcError::from)
    }

    /// Receive one Data frame and parse it as a response.
    pub async fn recv_response(&mut self) -> Result<PqResponse, RpcError> {
        let bytes = self.recv().await.map_err(RpcError::from)?;
        PqResponse::decode(&bytes)
    }

    /// Client round-trip: send request, receive response.
    pub async fn call(&mut self, req: &PqRequest) -> Result<PqResponse, RpcError> {
        self.send_request(req).await?;
        self.recv_response().await
    }

    // ─── Streaming response helpers (4E.3) ────────────────────────────

    /// Send one chunk of a streaming response. Sends a
    /// [`FrameType::StreamChunk`] frame rather than `Data` so the receiver
    /// can distinguish stream chunks from a singleton response.
    pub async fn send_stream_chunk(
        &mut self,
        chunk: &PqStreamChunk,
    ) -> Result<(), RpcError> {
        self.send_typed(
            super::frame::FrameType::StreamChunk,
            &chunk.encode(),
        )
        .await
        .map_err(RpcError::from)
    }

    /// Receive one chunk of a streaming response. Errors if the peer sends
    /// a non-StreamChunk frame (which would indicate a protocol violation
    /// mid-stream). Callers loop until `chunk.is_final()`.
    pub async fn recv_stream_chunk(&mut self) -> Result<PqStreamChunk, RpcError> {
        let (ft, bytes) = self.recv_typed().await.map_err(RpcError::from)?;
        if ft != super::frame::FrameType::StreamChunk {
            return Err(RpcError::Transport(
                super::stream::TransportError::UnexpectedFrame(ft),
            ));
        }
        PqStreamChunk::decode(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::handshake::PeerExpectation;
    use super::super::stream::{pq_dial, PqListener};
    use crate::crypto::hash::sha3_256;
    use crate::crypto::pqc::dilithium3_keygen;

    fn gen_peer() -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let kp = dilithium3_keygen().unwrap();
        let (pk, sk) = kp.into_parts();
        let hash = sha3_256(&pk);
        (pk, sk, hash)
    }

    #[test]
    fn request_roundtrip_preserves_fields() {
        let req = PqRequest::new("records/push")
            .with_header("x-elara-hops", "2")
            .with_header("x-elara-sender", "node-abc")
            .with_body(b"<record bytes>".to_vec());
        let wire = req.encode().unwrap();
        let decoded = PqRequest::decode(&wire).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn request_roundtrip_empty_body() {
        let req = PqRequest::new("ping");
        let wire = req.encode().unwrap();
        let decoded = PqRequest::decode(&wire).unwrap();
        assert_eq!(decoded, req);
        assert!(decoded.body.is_empty());
    }

    #[test]
    fn response_roundtrip() {
        let resp = PqResponse::new(200, b"{\"status\":\"ok\"}".to_vec());
        let wire = resp.encode();
        let decoded = PqResponse::decode(&wire).unwrap();
        assert_eq!(decoded, resp);
        assert!(decoded.is_success());
    }

    #[test]
    fn response_error_statuses_recognized() {
        let resp = PqResponse::new(status::TOO_MANY_REQUESTS, b"slow down".to_vec());
        assert!(!resp.is_success());
        let wire = resp.encode();
        let decoded = PqResponse::decode(&wire).unwrap();
        assert_eq!(decoded.status, 429);
    }

    #[test]
    fn request_decode_rejects_short_input() {
        assert!(matches!(PqRequest::decode(&[1, 2]), Err(RpcError::TooShort)));
    }

    #[test]
    fn request_decode_rejects_empty_and_3_byte_inputs() {
        assert!(matches!(PqRequest::decode(&[]), Err(RpcError::TooShort)));
        assert!(matches!(PqRequest::decode(&[0, 0, 0]), Err(RpcError::TooShort)));
    }

    #[test]
    fn request_decode_rejects_header_overflow() {
        // header_len within the cap but larger than the bytes actually present
        // after the 4-byte length prefix → HeaderOverflow (distinct from the
        // HeaderTooLarge cap, which now pre-empts the old 0xFFFFFFFF case).
        let bytes = [0, 0, 0x03, 0xE8, 0, 0, 0, 0]; // header_len = 1000, total = 8
        match PqRequest::decode(&bytes) {
            Err(RpcError::HeaderOverflow { declared, total }) => {
                assert_eq!(declared, 1000);
                assert_eq!(total, 8);
            }
            other => panic!("expected HeaderOverflow, got {other:?}"),
        }
    }

    #[test]
    fn request_decode_rejects_oversized_header_before_parse() {
        // A declared header_len above the cap is rejected as HeaderTooLarge
        // BEFORE any from_slice — closes the ~16 MiB-header decode-amplifier on
        // the per-request hot path (ws_session decodes every frame here). The
        // cap check pre-empts HeaderOverflow.
        let oversized = (MAX_REQ_HEADER_BYTES + 1) as u32;
        let mut bytes = oversized.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"{}"); // tiny actual buffer — never parsed
        match PqRequest::decode(&bytes) {
            Err(RpcError::HeaderTooLarge { declared, max }) => {
                assert_eq!(declared, MAX_REQ_HEADER_BYTES + 1);
                assert_eq!(max, MAX_REQ_HEADER_BYTES);
            }
            other => panic!("expected HeaderTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn request_decode_rejects_bad_json() {
        let mut bytes = Vec::new();
        let bad = b"{not valid json";
        bytes.extend_from_slice(&(bad.len() as u32).to_be_bytes());
        bytes.extend_from_slice(bad);
        assert!(matches!(
            PqRequest::decode(&bytes),
            Err(RpcError::BadHeaderJson(_))
        ));
    }

    /// Performance sanity: one handshake, then a tight request/response
    /// loop with a gossip-sized (2 KiB) payload.
    ///
    /// Measured baseline on dev machine (single-threaded current_thread
    /// tokio runtime, localhost): handshake ~40 ms, ~400 single-stream
    /// QPS. Per-stream QPS is scheduler-bound on localhost (one task
    /// switch per await on each side) — see stream.rs
    /// perf_concurrent_streams_scale for the aggregate picture.
    ///
    /// Assertion floors are deliberately loose: a regressed build would
    /// be orders of magnitude worse. We catch catastrophe here, not
    /// fine-grained drift.
    ///
    /// Marked `#[ignore]` because `cargo test` parallelism makes perf
    /// measurements flaky. Run explicitly:
    /// `cargo test --features node --lib perf_sanity -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn perf_sanity_handshake_and_sustained_rpc() {
        use std::time::Instant;

        let (server_pk, server_sk, server_hash) = gen_peer();
        let (client_pk, client_sk, _) = gen_peer();

        let listener = PqListener::bind("127.0.0.1:0", server_pk, server_sk)
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        // Server echoes the body back with a 200 OK, for N rounds then closes.
        const ROUNDS: usize = 2_000;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            for _ in 0..ROUNDS {
                let req = match stream.recv_request().await {
                    Ok(r) => r,
                    Err(_) => break,
                };
                stream
                    .send_response(&PqResponse::ok(req.body))
                    .await
                    .unwrap();
            }
        });

        // Measure handshake latency in isolation.
        let t0 = Instant::now();
        let mut client = pq_dial(
            addr,
            client_pk,
            client_sk,
            PeerExpectation::Pinned(server_hash),
        )
        .await
        .unwrap();
        let handshake_ms = t0.elapsed().as_secs_f64() * 1000.0;

        // 2 KiB payload approximates a small gossiped record.
        let payload = vec![0x42u8; 2048];
        let req = PqRequest::new("records/push")
            .with_header("x-elara-hops", "2")
            .with_body(payload);

        let t1 = Instant::now();
        for _ in 0..ROUNDS {
            let resp = client.call(&req).await.unwrap();
            assert_eq!(resp.status, status::OK);
            assert_eq!(resp.body.len(), 2048);
        }
        let rpc_secs = t1.elapsed().as_secs_f64();
        let qps = ROUNDS as f64 / rpc_secs;

        println!(
            "PQ transport perf: handshake={handshake_ms:.1}ms, \
             sustained RPC (2KiB round-trip)={qps:.0} QPS ({ROUNDS} rounds in {rpc_secs:.2}s)"
        );

        // Loose bars: a badly regressed build would be well below these.
        // Dev box should see handshake <500ms, QPS >3K. CI on small VMs
        // gets these loose thresholds.
        assert!(
            handshake_ms < 2000.0,
            "handshake too slow: {handshake_ms:.0}ms — profile Dilithium3/ML-KEM"
        );
        assert!(
            qps > 200.0,
            "sustained RPC too slow: {qps:.0} QPS — profile AEAD or frame path"
        );

        drop(client);
        let _ = server.await;
    }

    #[tokio::test]
    async fn end_to_end_rpc_over_pqstream() {
        let (server_pk, server_sk, server_hash) = gen_peer();
        let (client_pk, client_sk, _) = gen_peer();

        let listener = PqListener::bind("127.0.0.1:0", server_pk, server_sk)
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        // Server: read a request, echo method + body into response, close.
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let req = stream.recv_request().await.unwrap();
            let mut body = format!("method={} ", req.method).into_bytes();
            body.extend_from_slice(&req.body);
            stream
                .send_response(&PqResponse::ok(body))
                .await
                .unwrap();
            stream.close().await.unwrap();
        });

        let mut client = pq_dial(
            addr,
            client_pk,
            client_sk,
            PeerExpectation::Pinned(server_hash),
        )
        .await
        .unwrap();

        let req = PqRequest::new("peer/push")
            .with_header("x-elara-hops", "3")
            .with_body(b"payload-bytes".to_vec());

        let resp = client.call(&req).await.unwrap();
        assert_eq!(resp.status, status::OK);
        assert_eq!(resp.body, b"method=peer/push payload-bytes".to_vec());
        server.await.unwrap();
    }

    // ─── Streaming envelope + PqStream tests (4E.3) ─────────────────────

    #[test]
    fn stream_chunk_roundtrip_data() {
        let c = PqStreamChunk::data(0, b"tick-0".to_vec());
        let wire = c.encode();
        let d = PqStreamChunk::decode(&wire).unwrap();
        assert_eq!(d, c);
        assert!(!d.is_final());
        assert!(!d.is_error());
    }

    #[test]
    fn stream_chunk_roundtrip_final() {
        let c = PqStreamChunk::final_chunk(7, b"done".to_vec());
        let wire = c.encode();
        let d = PqStreamChunk::decode(&wire).unwrap();
        assert_eq!(d, c);
        assert_eq!(d.seq, 7);
        assert!(d.is_final());
        assert!(!d.is_error());
    }

    #[test]
    fn stream_chunk_roundtrip_error() {
        let c = PqStreamChunk::error(99, "state_core timeout");
        let wire = c.encode();
        let d = PqStreamChunk::decode(&wire).unwrap();
        assert_eq!(d, c);
        assert!(d.is_final(), "error chunks MUST be final");
        assert!(d.is_error());
        assert_eq!(d.body, b"state_core timeout");
    }

    #[test]
    fn stream_chunk_decode_rejects_short_input() {
        // 5-byte header (flags 1 + seq 4); anything shorter fails.
        assert!(matches!(
            PqStreamChunk::decode(&[0u8; 4]),
            Err(RpcError::TooShort)
        ));
    }

    #[test]
    fn stream_chunk_empty_body() {
        let c = PqStreamChunk::final_chunk(42, Vec::new());
        let wire = c.encode();
        assert_eq!(wire.len(), 5);
        let d = PqStreamChunk::decode(&wire).unwrap();
        assert_eq!(d, c);
        assert!(d.body.is_empty());
    }

    #[test]
    fn stream_chunk_wire_header_layout() {
        // flags=0b11, seq=0xDEADBEEF, body=[0xCA, 0xFE]
        let c = PqStreamChunk {
            flags: stream_flags::FINAL | stream_flags::ERROR,
            seq: 0xDEADBEEF,
            body: vec![0xCA, 0xFE],
        };
        let wire = c.encode();
        assert_eq!(wire[0], 0b11);
        assert_eq!(&wire[1..5], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(&wire[5..], &[0xCA, 0xFE]);
    }

    #[tokio::test]
    async fn end_to_end_streaming_response() {
        // Classic server-sent event shape: one request, N chunks, final bit.
        let (server_pk, server_sk, server_hash) = gen_peer();
        let (client_pk, client_sk, _) = gen_peer();

        let listener = PqListener::bind("127.0.0.1:0", server_pk, server_sk)
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        const N_CHUNKS: u32 = 5;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let req = stream.recv_request().await.unwrap();
            assert_eq!(req.method, "seal_progress_stream");
            for seq in 0..N_CHUNKS {
                let body = format!("tick-{seq}").into_bytes();
                let chunk = if seq + 1 == N_CHUNKS {
                    PqStreamChunk::final_chunk(seq, body)
                } else {
                    PqStreamChunk::data(seq, body)
                };
                stream.send_stream_chunk(&chunk).await.unwrap();
            }
            stream.close().await.unwrap();
        });

        let mut client = pq_dial(
            addr,
            client_pk,
            client_sk,
            PeerExpectation::Pinned(server_hash),
        )
        .await
        .unwrap();

        let req = PqRequest::new("seal_progress_stream");
        client.send_request(&req).await.unwrap();

        let mut received = 0u32;
        loop {
            let chunk = client.recv_stream_chunk().await.unwrap();
            assert_eq!(chunk.seq, received);
            assert_eq!(chunk.body, format!("tick-{received}").as_bytes());
            received += 1;
            if chunk.is_final() {
                break;
            }
        }
        assert_eq!(received, N_CHUNKS);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn streaming_server_can_emit_error_terminal() {
        // Server returns an error chunk mid-computation. Client sees FINAL + ERROR.
        let (server_pk, server_sk, server_hash) = gen_peer();
        let (client_pk, client_sk, _) = gen_peer();

        let listener = PqListener::bind("127.0.0.1:0", server_pk, server_sk)
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _req = stream.recv_request().await.unwrap();
            stream
                .send_stream_chunk(&PqStreamChunk::data(0, b"progress-1".to_vec()))
                .await
                .unwrap();
            stream
                .send_stream_chunk(&PqStreamChunk::error(1, "consensus lock timeout"))
                .await
                .unwrap();
            stream.close().await.unwrap();
        });

        let mut client = pq_dial(
            addr,
            client_pk,
            client_sk,
            PeerExpectation::Pinned(server_hash),
        )
        .await
        .unwrap();

        client.send_request(&PqRequest::new("seal_progress_stream")).await.unwrap();

        let c0 = client.recv_stream_chunk().await.unwrap();
        assert_eq!(c0.seq, 0);
        assert!(!c0.is_final());
        assert!(!c0.is_error());

        let c1 = client.recv_stream_chunk().await.unwrap();
        assert_eq!(c1.seq, 1);
        assert!(c1.is_final(), "error chunk must also be final");
        assert!(c1.is_error());
        assert_eq!(c1.body, b"consensus lock timeout");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn recv_strict_rejects_stream_chunk_as_response() {
        // If the server sends a StreamChunk but the client expected a
        // singleton response via recv_response, that's a protocol
        // violation and should error rather than silently drop the type.
        let (server_pk, server_sk, server_hash) = gen_peer();
        let (client_pk, client_sk, _) = gen_peer();

        let listener = PqListener::bind("127.0.0.1:0", server_pk, server_sk)
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _req = stream.recv_request().await.unwrap();
            // Wrong: send a StreamChunk where caller expects a PqResponse.
            stream
                .send_stream_chunk(&PqStreamChunk::final_chunk(0, b"surprise".to_vec()))
                .await
                .unwrap();
            stream.close().await.unwrap();
        });

        let mut client = pq_dial(
            addr,
            client_pk,
            client_sk,
            PeerExpectation::Pinned(server_hash),
        )
        .await
        .unwrap();

        client.send_request(&PqRequest::new("peer/push")).await.unwrap();
        let err = client.recv_response().await.unwrap_err();
        // Accepted surface: either UnexpectedFrame transport error or
        // decode error mapped back to the caller. Either way, not OK.
        match err {
            RpcError::Transport(_) => {}
            other => panic!("expected Transport(UnexpectedFrame), got {other:?}"),
        }
        server.await.unwrap();
    }

    // ─────────────────────────────────────────────────────────────────────
    // Fixture-free tests (5 distinct uncovered axes)
    // ─────────────────────────────────────────────────────────────────────

    /// **Axis 1**: pin the literal HTTP-status sentinels in `status::`.
    /// Stage 4B.2 chose HTTP semantics so call sites can mirror existing
    /// reqwest-based logic. A future-me refactor that introduces protocol
    /// -specific codes (e.g., 470 instead of 429 to "namespace" them) would
    /// quietly break the contract every existing call site assumes. Pin
    /// the values so the wire-level codes stay HTTP-canonical.
    #[test]
    fn batch_b_status_sentinels_literal_pin() {
        assert_eq!(status::OK, 200);
        assert_eq!(status::BAD_REQUEST, 400);
        assert_eq!(status::UNAUTHORIZED, 401);
        assert_eq!(status::NOT_FOUND, 404);
        assert_eq!(status::TOO_MANY_REQUESTS, 429);
        assert_eq!(status::INTERNAL_ERROR, 500);
        assert_eq!(status::NOT_IMPLEMENTED, 501);
        assert_eq!(status::SERVICE_UNAVAILABLE, 503);
    }

    /// **Axis 2**: pin the literal wire-byte layout of an encoded
    /// `PqRequest`. The existing `request_roundtrip_preserves_fields`
    /// test only proves encode→decode is the identity — it would pass
    /// even if both encode and decode silently swapped to little-endian
    /// header_len. This test pins the actual on-wire bytes so a real
    /// inter-version compatibility break gets caught.
    ///
    /// Spec: `| header_len:u32 BE | header_json:bytes | body:bytes |`.
    #[test]
    fn batch_b_pq_request_encode_pins_be_header_len_and_layout() {
        // Build a request with a non-empty body so we can verify the
        // suffix positioning.
        let req = PqRequest::new("X").with_body(b"BB".to_vec());
        let wire = req.encode().unwrap();
        assert!(wire.len() >= 6, "wire must include 4-byte length + header + body");

        // First four bytes are header_len in BIG-ENDIAN. The BE value
        // must equal the byte length of the JSON header that follows.
        let header_len_be = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]);
        let header_len_le = u32::from_le_bytes([wire[0], wire[1], wire[2], wire[3]]);
        // Sanity: a small two-digit decimal length is NOT byte-palindromic
        // so BE-decoded and LE-decoded values must differ — that's what
        // makes this a real endianness pin (not just a tautology).
        assert_ne!(
            header_len_be, header_len_le,
            "the chosen header_len must not be byte-palindromic, else BE/LE indistinguishable"
        );
        // BE interpretation must be small (< 1 KiB); LE interpretation
        // would be in the hundreds-of-millions range and clearly wrong.
        assert!(
            header_len_be < 1024,
            "BE-decoded header_len {header_len_be} should be small; if it isn't, length-prefix is LE"
        );
        assert!(
            header_len_le >= (1u32 << 24),
            "LE-decoded length {header_len_le} should be huge — confirms BE wire format"
        );

        // Header JSON immediately follows the 4-byte length.
        let header_end = 4 + header_len_be as usize;
        assert!(wire.len() >= header_end + 2, "body must fit in trailing 2 bytes");
        let header_bytes = &wire[4..header_end];
        let parsed: serde_json::Value =
            serde_json::from_slice(header_bytes).expect("header is JSON");
        assert_eq!(parsed["method"], "X");
        assert!(parsed["headers"].is_object());

        // Body is the suffix.
        assert_eq!(&wire[header_end..], b"BB", "body must be wire suffix");
    }

    /// **Axis 3**: `PqResponse::is_success` boundary semantics.
    /// Existing tests probe 200 (OK round-trip) and 429 (false). This
    /// axis pins the full `200..300` half-open interval explicitly:
    /// 199 false, 200 true, 299 true, 300 false. Plus the saturation
    /// corners (0 and u16::MAX). Plus pin `PqResponse::ok(body)` builds
    /// status==200.
    #[test]
    fn batch_b_pq_response_is_success_boundary() {
        // ok(body) constructs status=200 with the given body.
        let r = PqResponse::ok(b"hi".to_vec());
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hi");
        assert!(r.is_success());

        // 200..300 half-open: inclusive at 200, exclusive at 300.
        assert!(!PqResponse::new(199, vec![]).is_success(), "199 < 200");
        assert!(PqResponse::new(200, vec![]).is_success(), "200 inclusive");
        assert!(PqResponse::new(250, vec![]).is_success(), "250 inside");
        assert!(PqResponse::new(299, vec![]).is_success(), "299 inclusive");
        assert!(!PqResponse::new(300, vec![]).is_success(), "300 exclusive");
        assert!(!PqResponse::new(404, vec![]).is_success());
        assert!(!PqResponse::new(500, vec![]).is_success());

        // Saturation corners.
        assert!(!PqResponse::new(0, vec![]).is_success());
        assert!(!PqResponse::new(u16::MAX, vec![]).is_success());
    }

    /// **Axis 4**: pin the literal flag bit positions and constructor
    /// semantics for `PqStreamChunk`. `stream_chunk_wire_header_layout`
    /// pins one composite (flags=0b11) but not the individual bit
    /// positions per constructor. A bit-position swap (FINAL=0b10,
    /// ERROR=0b01) would be a wire-format break and pass the existing
    /// wire test. Pin per-constructor bit shape so the break is caught.
    #[test]
    fn batch_b_stream_flag_bit_positions_and_constructors() {
        // Literal bit positions (wire format).
        assert_eq!(stream_flags::FINAL, 0b0000_0001);
        assert_eq!(stream_flags::ERROR, 0b0000_0010);
        assert_ne!(stream_flags::FINAL, stream_flags::ERROR, "bits must not collide");

        // data() → flags=0, no FINAL, no ERROR.
        let d = PqStreamChunk::data(11, b"x".to_vec());
        assert_eq!(d.flags, 0);
        assert!(!d.is_final());
        assert!(!d.is_error());
        assert_eq!(d.seq, 11);

        // final_chunk() → flags=FINAL only.
        let f = PqStreamChunk::final_chunk(22, b"end".to_vec());
        assert_eq!(f.flags, stream_flags::FINAL);
        assert!(f.is_final());
        assert!(!f.is_error(), "final_chunk must NOT set ERROR");

        // error() → flags=FINAL|ERROR.
        let e = PqStreamChunk::error(33, "oops");
        assert_eq!(e.flags, stream_flags::FINAL | stream_flags::ERROR);
        assert!(e.is_final(), "error chunks must be final");
        assert!(e.is_error());
        assert_eq!(e.body, b"oops");

        // is_final / is_error are pure mask checks — verify they tolerate
        // unrelated high bits (forward-compat: future flags in bits 2..7).
        let synthetic = PqStreamChunk {
            flags: stream_flags::FINAL | 0b1000_0000,
            seq: 0,
            body: vec![],
        };
        assert!(synthetic.is_final());
        assert!(!synthetic.is_error(), "ERROR bit not set despite other high bits");
    }

    /// **Axis 5**: pin `PqRequest`'s builder semantics — header
    /// overwrite-on-collision, body replacement, and the
    /// `peer_identity_hash` zero-init invariant. `peer_identity_hash`
    /// is NOT on the wire: it's filled in by the server post-handshake
    /// from `PqStream::peer_identity_hash()`. A freshly built or
    /// decoded request MUST be `[0u8; 32]` so a future-me refactor
    /// that accidentally serializes a "trusted" peer hash into the
    /// wire envelope is caught here, not in production.
    #[test]
    fn batch_b_pq_request_builder_and_peer_identity_zero_init() {
        // `new()` initialises peer_identity_hash to all zeros.
        let r = PqRequest::new("/foo");
        assert_eq!(r.peer_identity_hash, [0u8; 32]);
        assert_eq!(r.method, "/foo");
        assert!(r.headers.is_empty());
        assert!(r.body.is_empty());

        // `with_header` chains and overwrites on key collision.
        let r = PqRequest::new("/foo")
            .with_header("Content-Type", "application/json")
            .with_header("Content-Type", "application/cbor"); // overwrite
        assert_eq!(r.headers.len(), 1, "duplicate key must overwrite");
        assert_eq!(r.headers.get("Content-Type").unwrap(), "application/cbor");

        // `with_body` replaces (not appends).
        let r = PqRequest::new("/foo")
            .with_body(b"first".to_vec())
            .with_body(b"second".to_vec());
        assert_eq!(r.body, b"second", "with_body must replace, not append");

        // Decoded request also zero-inits peer_identity_hash (server
        // fills it after PQ handshake). Encode + decode round-trip
        // preserves all on-wire fields but the peer_identity_hash is
        // re-zeroed on the decode path.
        let mut authored = PqRequest::new("/x").with_header("k", "v").with_body(b"body".to_vec());
        // Simulate a server having stamped the peer_identity_hash post-
        // handshake — encode should not persist it onto the wire.
        authored.peer_identity_hash = [0x42; 32];
        let wire = authored.encode().unwrap();
        let decoded = PqRequest::decode(&wire).unwrap();
        assert_eq!(
            decoded.peer_identity_hash, [0u8; 32],
            "peer_identity_hash MUST NOT appear on the wire — decode zero-inits"
        );
        // Other fields survive the round-trip.
        assert_eq!(decoded.method, "/x");
        assert_eq!(decoded.headers.get("k").unwrap(), "v");
        assert_eq!(decoded.body, b"body");
    }

    #[test]
    fn encode_returns_ok_and_encode_json_error_variant_is_reachable() {
        // encode() now returns Result — verify the happy path returns Ok
        // and that the EncodeJson variant exists in the error type (so
        // future callers relying on it are not silently broken by a refactor).
        let req = PqRequest::new("/probe").with_header("x-zone", "7");
        assert!(
            req.encode().is_ok(),
            "encode must succeed for a BTreeMap<String,String> header"
        );

        // Construct EncodeJson explicitly to verify the variant compiles
        // and its Display surfaces the inner error message.
        let inner = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let err = RpcError::EncodeJson(inner);
        let msg = err.to_string();
        assert!(
            msg.starts_with("header encode:"),
            "EncodeJson display must start with 'header encode:'; got {msg}"
        );
        use std::error::Error;
        assert!(
            err.source().is_some(),
            "EncodeJson must chain to the inner serde_json::Error via #[source]"
        );
    }
}
