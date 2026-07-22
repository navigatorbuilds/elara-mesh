//! Post-quantum network transport — wire framing and session crypto.
//!
//! The transport for a hybrid post-quantum channel, built in layers:
//!
//! - [`frame`]: a downgrade-proof wire frame — a fixed 9-byte header
//!   (`magic "ELPQ" | version | type | 3-byte big-endian length`) followed
//!   by a length-prefixed payload. No negotiation, no polyglot parser.
//! - [`crypto`]: the session key schedule and bulk cipher —
//!   `HKDF-SHA256(salt = transcript_hash, ikm = x25519_ss || ml_kem_ss)`
//!   expanded under direction-separated labels into two ChaCha20-Poly1305
//!   keys (`k_send` ≠ `k_recv`, so cross-direction replay is impossible),
//!   plus the SHA3-256 [`crypto::TranscriptHash`] that binds every
//!   handshake byte.
//!
//! # Design invariants
//!
//! - **No downgrade.** Anything that does not start with `ELPQ\x02` is
//!   rejected before any payload byte is read.
//! - **Direction separation.** `k_send` and `k_recv` derive from distinct
//!   HKDF labels; a frame can never decrypt under the reverse-direction key.
//! - **Bounded.** The 3-byte length field caps a frame at `2^24 − 1` bytes.
//!
//! # Scope
//!
//! This crate is the framing + session-crypto + handshake core of the Elara
//! Protocol's hybrid ML-KEM-768 + X25519 key agreement with Dilithium3
//! identity binding:
//!
//! - [`frame`]: the downgrade-proof ELPQ wire frame.
//! - [`crypto`]: the HKDF session key schedule + ChaCha20-Poly1305 AEAD.
//! - [`kem`]: ML-KEM-768 key encapsulation (FIPS 203) — the post-quantum
//!   half of the key exchange. Behind the default-on `oqs` feature.
//! - [`sig`]: Dilithium3 / ML-DSA-65 (FIPS 204) identity signatures — pure
//!   Rust.
//! - [`handshake`]: the hand-rolled Noise_XX-style 3-message state machine
//!   that binds the two together. Requires the `oqs` feature.
//!
//! The async stream/RPC wrappers remain in the node for now; the layers here
//! carry no protocol dependencies.
//!
//! # Platform support
//!
//! This is a native node↔node transport: ML-KEM-768 is liboqs (C). The
//! `kem`, `sig`, and `handshake` layers are compiled for non-`wasm32` targets
//! only. On `wasm32` the crate degrades to the pure-Rust [`frame`] + [`crypto`]
//! layers, so it can sit in the dependency graph of a wasm consumer (e.g.
//! `browser-node` via the node crate) without pulling liboqs or a `getrandom`
//! backend. Verifying Elara proofs in the browser is the job of the separate
//! pure-Rust light-client SDK, not this transport crate.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod frame;

// KEM (liboqs/C), Dilithium signatures (dilithium-rs → getrandom), and the
// handshake that drives them are native-only. wasm32 builds get the pure-Rust
// frame/crypto layers only — no liboqs, no getrandom backend choice forced on
// wasm consumers.
#[cfg(not(target_arch = "wasm32"))]
pub mod sig;
#[cfg(all(not(target_arch = "wasm32"), feature = "oqs"))]
pub mod kem;
#[cfg(all(not(target_arch = "wasm32"), feature = "oqs"))]
pub mod handshake;

pub use crypto::{derive_session_keys, AeadKey, CryptoError, SessionKeys, TranscriptHash};
pub use frame::{
    Frame, FrameError, FrameType, ELPQ_MAGIC, HEADER_LEN, MAX_PAYLOAD, WIRE_VERSION,
};
#[cfg(not(target_arch = "wasm32"))]
pub use sig::{dilithium3_keygen, dilithium3_sign_with_pk, dilithium3_verify, SigError};

#[cfg(all(not(target_arch = "wasm32"), feature = "oqs"))]
pub use handshake::{
    CompletedHandshake, HandshakeError, HandshakeRole, PeerExpectation, PqHandshake,
    MAX_HANDSHAKE_SKEW_SECS,
};
#[cfg(all(not(target_arch = "wasm32"), feature = "oqs"))]
pub use kem::{
    mlkem768_decapsulate, mlkem768_encapsulate, mlkem768_keygen, KemEncapsulation, KemError,
    KemKeypair, MlKem768Sizes,
};
