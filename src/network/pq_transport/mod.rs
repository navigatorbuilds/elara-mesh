//! Post-quantum transport layer (Phase 4A — 2026-04-16).
//!
//! End-to-end PQ network: hybrid ML-KEM-768 + X25519 handshake with
//! Dilithium3 identity binding, ChaCha20-Poly1305 AEAD bulk encryption,
//! and a dedicated length-prefixed frame format. Replaces rustls for
//! inter-node traffic.
//!
//! # Architecture
//!
//! - [`frame`]: wire format (magic "ELPQ" + type + length-prefixed payload).
//! - [`crypto`]: HKDF key schedule, ChaCha20-Poly1305 AEAD, transcript hash.
//! - [`handshake`]: hand-rolled Noise_XX-style 3-message state machine.
//!
//! # Stage 4A scope
//!
//! This stage delivers the primitive layer with unit tests only. Stage 4B
//! wires it into `client.rs` / `server.rs` and replaces reqwest/rustls
//! call sites; Stage 4C runs the wire audit; Stage 4D updates the
//! whitepaper.
//!
//! # Hard rules (spec, 2026-04-16)
//!
//! 1. Never classical-only. The handshake always combines ML-KEM-768 and
//!    X25519; if either primitive is broken, the session remains secure.
//! 2. No downgrade parser. Anything that does not start with `ELPQ\x02`
//!    is rejected immediately; we never polyglot-parse TLS or HTTP probes.
//! 3. The transcript hash covers every handshake byte up to the signature.
//!    MITM resistance rests on this even if ML-KEM is broken.
//! 4. `k_send` ≠ `k_recv`: cross-direction replay is structurally impossible.
//! 5. Long-term Dilithium3 keys never become session secrets directly.

// Wire frame codec, session crypto (HKDF key schedule, ChaCha20-Poly1305
// AEAD, SHA3-256 transcript), and the hybrid ML-KEM-768 + X25519 + Dilithium3
// handshake state machine live in the standalone `elara-pq-transport` crate
// (MIT/Apache, Lane 3). Re-exported here so `super::frame::*`, `super::crypto::*`
// and `super::handshake::*` resolve unchanged for the stream/rpc/ws layers
// still in the node.
pub use elara_pq_transport::{crypto, frame, handshake};
pub mod peer_store;
pub mod router;
pub mod rpc;
pub mod stream;
pub mod ws_session;

pub use crypto::{derive_session_keys, AeadKey, SessionKeys, TranscriptHash};
pub use frame::{Frame, FrameType, FrameError, ELPQ_MAGIC, WIRE_VERSION};
pub use handshake::{HandshakeError, HandshakeRole, PeerExpectation, PqHandshake};
pub use peer_store::{PeerIdentityStore, PeerStoreError};
pub use router::{pq_router, pq_streaming_handler, pq_streaming_methods};
pub use rpc::{status, PqRequest, PqResponse, PqStreamChunk, RpcError, StreamSink};
pub use stream::{
    handshake_initiator, handshake_responder, pq_dial, pq_dial_with_admission,
    AdmissionContext, HandshakeParams, PqListener, PqStream, RealmGate, TransportError,
    DEFAULT_HANDSHAKE_TIMEOUT,
};
