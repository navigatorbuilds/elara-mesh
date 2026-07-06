//! Key schedule, transcript hash, and AEAD for the PQ transport.
//!
//! # Key derivation
//!
//! After the handshake both parties hold:
//! - `ml_kem_ss` (32 B, ML-KEM-768 decapsulation output)
//! - `x25519_ss` (32 B, X25519 shared secret)
//! - `transcript_hash` (32 B, SHA3-256 over every handshake byte)
//!
//! We derive `k_send` / `k_recv` via:
//!
//! ```text
//! prk = HKDF-SHA256-Extract(salt = transcript_hash,
//!                           ikm  = x25519_ss || ml_kem_ss)
//! k_send = HKDF-Expand(prk, info = "ELPQ session v1 k_send", L = 32)
//! k_recv = HKDF-Expand(prk, info = "ELPQ session v1 k_recv", L = 32)
//! ```
//!
//! The initiator treats `k_send` as its send key and `k_recv` as its
//! receive key; the responder swaps them. Different HKDF labels mean the
//! two directions are cryptographically independent and cross-replay is
//! impossible.
//!
//! # AEAD
//!
//! ChaCha20-Poly1305 with a 96-bit monotonic counter nonce, one counter
//! per direction. No nonce reuse within a rekey window (2^30 bytes or
//! 5 minutes). Nonce values do not collide across directions because
//! `k_send ≠ k_recv`.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

/// Errors from the session key schedule and AEAD primitives.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("AEAD nonce counter exhausted")]
    NonceExhausted,
    #[error("AEAD encrypt failed")]
    EncryptFailed,
    #[error("AEAD decrypt failed")]
    DecryptFailed,
    #[error("HKDF expand k_send failed")]
    HkdfExpandSend,
    #[error("HKDF expand k_recv failed")]
    HkdfExpandRecv,
}

type Result<T> = core::result::Result<T, CryptoError>;

/// Size of every symmetric key derived here.
pub const AEAD_KEY_LEN: usize = 32;
/// ChaCha20-Poly1305 nonce size.
pub const AEAD_NONCE_LEN: usize = 12;

/// HKDF info labels — wire-level constants, do not change without bumping
/// the handshake version.
const LABEL_K_SEND: &[u8] = b"ELPQ session v1 k_send";
const LABEL_K_RECV: &[u8] = b"ELPQ session v1 k_recv";

/// Size of all three inputs (ml_kem, x25519, transcript).
const SS_LEN: usize = 32;

/// Running SHA3-256 transcript. Every handshake byte both parties see
/// gets folded in; the responder signs the final hash with Dilithium3,
/// which closes the MITM gap even if ML-KEM is broken.
#[derive(Default, Clone)]
pub struct TranscriptHash {
    inner: Sha3_256,
}

impl TranscriptHash {
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorb a chunk of handshake bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Snapshot the current digest without consuming the hasher.
    pub fn snapshot(&self) -> [u8; 32] {
        let h = self.inner.clone();
        h.finalize().into()
    }
}

/// A symmetric AEAD key with its monotonic nonce counter.
///
/// The caller is responsible for rekeying before the counter wraps
/// (2^96 messages — practically unreachable before the byte-count rekey
/// threshold fires).
pub struct AeadKey {
    key: [u8; AEAD_KEY_LEN],
    counter: u64,
}

impl AeadKey {
    pub fn new(key: [u8; AEAD_KEY_LEN]) -> Self {
        Self { key, counter: 0 }
    }

    /// Encrypt `plaintext` under this key. Increments the internal counter.
    pub fn encrypt(&mut self, associated_data: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce_from_counter(self.counter);
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(CryptoError::NonceExhausted)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::EncryptFailed)
    }

    /// Decrypt a frame produced by the matching direction's `encrypt`.
    /// The `counter` argument is the sender's counter value for this
    /// frame; a receiver tracks its peer's expected counter independently
    /// and supplies it here.
    pub fn decrypt(
        &self,
        counter: u64,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce = nonce_from_counter(counter);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::DecryptFailed)
    }

    /// How many frames have been sent under this key.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Test-only access to the raw key bytes. Used by handshake tests
    /// to assert that ephemerals produce distinct sessions across runs.
    ///
    /// Gated behind the `test-helpers` feature (and the crate's own
    /// `cfg(test)`) so it is never reachable in a production build — the
    /// node enables `test-helpers` only through its dev-dependency.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn key_bytes(&self) -> [u8; AEAD_KEY_LEN] {
        self.key
    }
}

impl Drop for AeadKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// The two AEAD keys a completed handshake yields.
pub struct SessionKeys {
    pub k_send: AeadKey,
    pub k_recv: AeadKey,
}

/// Build a 96-bit ChaCha20-Poly1305 nonce from a 64-bit counter.
/// Layout: 4 bytes zero prefix, then 8 bytes big-endian counter.
fn nonce_from_counter(counter: u64) -> [u8; AEAD_NONCE_LEN] {
    let mut n = [0u8; AEAD_NONCE_LEN];
    n[4..12].copy_from_slice(&counter.to_be_bytes());
    n
}

/// Run the full handshake-to-session key derivation.
///
/// `role_is_initiator` swaps the labels so the responder's `k_send`
/// equals the initiator's `k_recv` and vice versa — that way each party
/// encrypts with the label the other party will use to decrypt.
pub fn derive_session_keys(
    x25519_ss: &[u8; SS_LEN],
    ml_kem_ss: &[u8; SS_LEN],
    transcript_hash: &[u8; SS_LEN],
    role_is_initiator: bool,
) -> Result<SessionKeys> {
    // Concatenate IKM in fixed order (X25519 first, ML-KEM second). Order
    // is spec-stable and must match between peers.
    let mut ikm = [0u8; SS_LEN * 2];
    ikm[..SS_LEN].copy_from_slice(x25519_ss);
    ikm[SS_LEN..].copy_from_slice(ml_kem_ss);

    let hk = Hkdf::<Sha256>::new(Some(transcript_hash), &ikm);
    ikm.zeroize();

    let mut k1 = [0u8; AEAD_KEY_LEN];
    let mut k2 = [0u8; AEAD_KEY_LEN];
    hk.expand(LABEL_K_SEND, &mut k1)
        .map_err(|_| CryptoError::HkdfExpandSend)?;
    hk.expand(LABEL_K_RECV, &mut k2)
        .map_err(|_| CryptoError::HkdfExpandRecv)?;

    // The initiator uses LABEL_K_SEND for its send direction; the
    // responder flips so the two parties' send/recv pair up.
    let (send_bytes, recv_bytes) = if role_is_initiator {
        (k1, k2)
    } else {
        (k2, k1)
    };

    Ok(SessionKeys {
        k_send: AeadKey::new(send_bytes),
        k_recv: AeadKey::new(recv_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_is_deterministic() {
        let mut t1 = TranscriptHash::new();
        let mut t2 = TranscriptHash::new();
        t1.update(b"abc");
        t1.update(b"def");
        t2.update(b"abcdef");
        assert_eq!(t1.snapshot(), t2.snapshot());
    }

    #[test]
    fn transcript_distinguishes_different_streams() {
        let mut t1 = TranscriptHash::new();
        let mut t2 = TranscriptHash::new();
        t1.update(b"hello world");
        t2.update(b"hello_world");
        assert_ne!(t1.snapshot(), t2.snapshot());
    }

    #[test]
    fn transcript_snapshot_does_not_consume() {
        let mut t = TranscriptHash::new();
        t.update(b"part1");
        let snap1 = t.snapshot();
        t.update(b"part2");
        let snap2 = t.snapshot();
        assert_ne!(snap1, snap2);
        // Re-snapshotting at the same point must be stable.
        let snap2_again = t.snapshot();
        assert_eq!(snap2, snap2_again);
    }

    #[test]
    fn session_keys_are_mirrored_across_roles() {
        let x = [7u8; 32];
        let k = [9u8; 32];
        let th = [1u8; 32];
        let init = derive_session_keys(&x, &k, &th, true).unwrap();
        let resp = derive_session_keys(&x, &k, &th, false).unwrap();
        // initiator.send == responder.recv
        assert_eq!(init.k_send.key, resp.k_recv.key);
        // initiator.recv == responder.send
        assert_eq!(init.k_recv.key, resp.k_send.key);
        // Opposite directions use distinct keys.
        assert_ne!(init.k_send.key, init.k_recv.key);
    }

    #[test]
    fn different_transcripts_produce_different_keys() {
        let x = [7u8; 32];
        let k = [9u8; 32];
        let th_a = [0u8; 32];
        let th_b = [0xFFu8; 32];
        let a = derive_session_keys(&x, &k, &th_a, true).unwrap();
        let b = derive_session_keys(&x, &k, &th_b, true).unwrap();
        assert_ne!(a.k_send.key, b.k_send.key);
    }

    #[test]
    fn changing_either_ss_changes_the_key() {
        let th = [1u8; 32];
        let base = derive_session_keys(&[0u8; 32], &[0u8; 32], &th, true).unwrap();
        let only_x = derive_session_keys(&[1u8; 32], &[0u8; 32], &th, true).unwrap();
        let only_k = derive_session_keys(&[0u8; 32], &[1u8; 32], &th, true).unwrap();
        // Both primitives contribute: flipping either yields a different key.
        assert_ne!(base.k_send.key, only_x.k_send.key);
        assert_ne!(base.k_send.key, only_k.k_send.key);
        assert_ne!(only_x.k_send.key, only_k.k_send.key);
    }

    #[test]
    fn aead_roundtrip() {
        let mut keys = derive_session_keys(&[7u8; 32], &[9u8; 32], &[1u8; 32], true).unwrap();
        let peer = derive_session_keys(&[7u8; 32], &[9u8; 32], &[1u8; 32], false).unwrap();
        let ad = b"frame-header";
        let msg = b"hello post-quantum world";
        let ct = keys.k_send.encrypt(ad, msg).unwrap();
        let pt = peer.k_recv.decrypt(0, ad, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn aead_rejects_tampered_ciphertext() {
        let mut keys = derive_session_keys(&[7u8; 32], &[9u8; 32], &[1u8; 32], true).unwrap();
        let peer = derive_session_keys(&[7u8; 32], &[9u8; 32], &[1u8; 32], false).unwrap();
        let mut ct = keys.k_send.encrypt(b"", b"payload").unwrap();
        ct[0] ^= 1;
        assert!(peer.k_recv.decrypt(0, b"", &ct).is_err());
    }

    #[test]
    fn aead_rejects_ad_mismatch() {
        let mut keys = derive_session_keys(&[7u8; 32], &[9u8; 32], &[1u8; 32], true).unwrap();
        let peer = derive_session_keys(&[7u8; 32], &[9u8; 32], &[1u8; 32], false).unwrap();
        let ct = keys.k_send.encrypt(b"header-a", b"payload").unwrap();
        assert!(peer.k_recv.decrypt(0, b"header-b", &ct).is_err());
    }

    #[test]
    fn aead_counter_advances_per_encrypt() {
        let mut keys = derive_session_keys(&[7u8; 32], &[9u8; 32], &[1u8; 32], true).unwrap();
        let peer = derive_session_keys(&[7u8; 32], &[9u8; 32], &[1u8; 32], false).unwrap();
        let ct0 = keys.k_send.encrypt(b"ad", b"msg0").unwrap();
        let ct1 = keys.k_send.encrypt(b"ad", b"msg1").unwrap();
        // Counters diverged: caller must track them for the receiver.
        assert_eq!(peer.k_recv.decrypt(0, b"ad", &ct0).unwrap(), b"msg0");
        assert_eq!(peer.k_recv.decrypt(1, b"ad", &ct1).unwrap(), b"msg1");
        // Wrong counter ⇒ MAC fails.
        assert!(peer.k_recv.decrypt(0, b"ad", &ct1).is_err());
    }

    #[test]
    fn cross_direction_replay_is_impossible() {
        // A frame sent by initiator must not decrypt under responder's send key,
        // because k_send ≠ k_recv.
        let mut init = derive_session_keys(&[7u8; 32], &[9u8; 32], &[1u8; 32], true).unwrap();
        let resp = derive_session_keys(&[7u8; 32], &[9u8; 32], &[1u8; 32], false).unwrap();
        let ct = init.k_send.encrypt(b"", b"msg").unwrap();
        // resp.k_send is the reversed-direction key; feeding this frame to
        // it (simulating a reflected / replayed packet) must fail.
        assert!(resp.k_send.decrypt(0, b"", &ct).is_err());
        // Sanity: the correct-direction decrypt works.
        assert_eq!(resp.k_recv.decrypt(0, b"", &ct).unwrap(), b"msg");
        // Silence unused-mut warnings.
        let _ = init.k_send.counter();
    }

    // ────────────────────────────────────────────────────────────────────
    // batch_b axes — fixture-free density tests on uncovered invariants.
    // Existing 11 tests cover transcript distinctness, AEAD round-trip /
    // tamper / AD-mismatch / counter-advance / cross-direction-replay.
    // They do NOT pin the AEAD constants + HKDF labels (wire-compat), the
    // nonce-from-counter exact byte layout (12B = 4B zero + 8B BE counter),
    // the FIPS-202 SHA3-256("") known-answer, AeadKey counter() getter
    // semantics, or IKM concatenation-order asymmetry. batch_b closes those.
    // ────────────────────────────────────────────────────────────────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_aead_const_strict_pin_and_label_wire_format_invariants() {
        // AEAD_KEY_LEN = 32 (ChaCha20-Poly1305 key size — bumping this is
        // not actually possible without changing the cipher).
        assert_eq!(AEAD_KEY_LEN, 32);
        // AEAD_NONCE_LEN = 12 (ChaCha20-Poly1305 nonce — fixed by RFC 8439).
        assert_eq!(AEAD_NONCE_LEN, 12);
        // SS_LEN = AEAD_KEY_LEN (the three handshake outputs and the
        // derived keys all live in the same 32-byte space).
        assert_eq!(SS_LEN, 32);
        assert_eq!(SS_LEN, AEAD_KEY_LEN);
        // Cross-relation: nonce smaller than key (otherwise the nonce
        // counter encoding wouldn't fit the layout we picked).
        assert!(AEAD_NONCE_LEN < AEAD_KEY_LEN);
        // Memory: AeadKey storage is the key bytes + a u64 counter.
        // Pin this so a future field addition is a deliberate choice.
        let one_key_storage = std::mem::size_of::<AeadKey>();
        assert!(
            one_key_storage <= 64,
            "AeadKey size = {one_key_storage}; should stay close to 40 (32 key + 8 counter)"
        );

        // LABEL_K_SEND / LABEL_K_RECV are wire-level constants. Changing
        // either silently breaks every peer that derived keys with the
        // old labels — pin them by exact bytes.
        assert_eq!(LABEL_K_SEND, b"ELPQ session v1 k_send");
        assert_eq!(LABEL_K_RECV, b"ELPQ session v1 k_recv");
        assert_eq!(LABEL_K_SEND.len(), 22);
        assert_eq!(LABEL_K_RECV.len(), 22);
        // Labels MUST differ (else k_send == k_recv and direction loses meaning).
        assert_ne!(LABEL_K_SEND, LABEL_K_RECV);
        // Cross-prefix defense — neither label may be a prefix of the other.
        // HKDF's domain separation collapses if the labels share a prefix
        // that the underlying mac would treat as the message boundary.
        assert!(!LABEL_K_SEND.starts_with(LABEL_K_RECV));
        assert!(!LABEL_K_RECV.starts_with(LABEL_K_SEND));
        // Shared "ELPQ session v1 " prefix (16 bytes) — version + project tag.
        // A bump to "ELPQ session v2 " is a deliberate handshake rev — pin
        // the v1 prefix so a typo bump trips this test.
        assert_eq!(&LABEL_K_SEND[..16], b"ELPQ session v1 ");
        assert_eq!(&LABEL_K_RECV[..16], b"ELPQ session v1 ");
        // The diverging suffix is exactly "k_send" / "k_recv".
        assert_eq!(&LABEL_K_SEND[16..], b"k_send");
        assert_eq!(&LABEL_K_RECV[16..], b"k_recv");
        // Both labels are pure ASCII (no embedded NUL, no UTF-8 multibyte).
        assert!(LABEL_K_SEND.iter().all(|b| b.is_ascii() && *b != 0));
        assert!(LABEL_K_RECV.iter().all(|b| b.is_ascii() && *b != 0));
    }

    #[test]
    fn batch_b_nonce_from_counter_byte_layout_matrix_with_be_endianness_and_zero_prefix() {
        // Wire-level nonce layout: 12 bytes total = 4-byte zero prefix
        // + 8-byte big-endian counter. A switch to little-endian or to a
        // smaller zero prefix would silently desync every active session.
        // Pin the layout against a matrix of counter values.

        // counter = 0 → all-zero nonce
        let n = nonce_from_counter(0);
        assert_eq!(n, [0u8; AEAD_NONCE_LEN]);
        assert_eq!(n.len(), AEAD_NONCE_LEN);

        // counter = 1 → last byte is 0x01, rest zero
        let n = nonce_from_counter(1);
        assert_eq!(&n[0..4], &[0u8; 4][..], "4-byte zero prefix");
        assert_eq!(&n[4..11], &[0u8; 7][..], "BE high bytes are zero for counter=1");
        assert_eq!(n[11], 0x01, "BE low byte is 0x01 for counter=1");

        // counter = 0x12_34_56_78_9a_bc_de_f0 → pin every byte
        let cnt: u64 = 0x12_34_56_78_9a_bc_de_f0;
        let n = nonce_from_counter(cnt);
        assert_eq!(&n[0..4], &[0u8; 4][..]);
        assert_eq!(
            &n[4..12],
            &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0][..],
            "big-endian byte order, MSB first"
        );

        // counter = u64::MAX → bytes 4..12 all 0xFF
        let n = nonce_from_counter(u64::MAX);
        assert_eq!(&n[0..4], &[0u8; 4][..]);
        assert_eq!(&n[4..12], &[0xFFu8; 8][..]);

        // counter sequential — pin that incrementing by 1 only touches the
        // low byte (proves BE, not LE: in LE, +1 would touch bytes[4]).
        for c in 0u64..=10 {
            let n = nonce_from_counter(c);
            assert_eq!(&n[0..4], &[0u8; 4][..]);
            assert_eq!(&n[4..11], &[0u8; 7][..]);
            assert_eq!(n[11], c as u8);
        }

        // Negative-pin: bumping from 0x00FF → 0x0100 carries to byte[10]
        // (not byte[5], which would be the LE expectation).
        let n_ff = nonce_from_counter(0xFF);
        let n_100 = nonce_from_counter(0x100);
        assert_eq!(n_ff[10], 0x00);
        assert_eq!(n_ff[11], 0xFF);
        assert_eq!(n_100[10], 0x01);
        assert_eq!(n_100[11], 0x00);
    }

    #[test]
    fn batch_b_transcript_default_eq_new_and_fips202_empty_sha3_known_answer_and_clone() {
        // Default and new() must agree — a future custom Default would
        // silently change initial digest state for everyone using ::default().
        let a = TranscriptHash::new();
        let b = TranscriptHash::default();
        assert_eq!(a.snapshot(), b.snapshot(),
            "Default and new() must produce the same initial state");

        // FIPS 202 known answer: SHA3-256("") = a7ffc6f8…4348434a.
        // The transcript starts empty, so snapshot() must match this exact
        // 32-byte value. Any drift means we're not running SHA3-256.
        let expected_empty_sha3_256: [u8; 32] = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
            0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
            0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
        ];
        assert_eq!(a.snapshot(), expected_empty_sha3_256,
            "Empty TranscriptHash must equal FIPS-202 SHA3-256(\"\") known-answer");

        // Clone semantics: cloning at a state preserves it, then independent
        // updates diverge the two hashers — Clone must be a deep-copy.
        let mut t1 = TranscriptHash::new();
        t1.update(b"shared-prefix");
        let mut t2 = t1.clone();
        assert_eq!(t1.snapshot(), t2.snapshot(),
            "fresh clone must match source state");
        t1.update(b"branch-a");
        t2.update(b"branch-b");
        assert_ne!(t1.snapshot(), t2.snapshot(),
            "diverged after independent updates");

        // Cumulative-fold property: arbitrary chunking yields same result.
        let mut chunked = TranscriptHash::new();
        chunked.update(b"a");
        chunked.update(b"b");
        chunked.update(b"c");
        chunked.update(b"d");
        chunked.update(b"e");
        let mut atomic = TranscriptHash::new();
        atomic.update(b"abcde");
        assert_eq!(chunked.snapshot(), atomic.snapshot(),
            "5-chunk and 1-chunk updates must produce same digest");

        // Empty update is a no-op.
        let mut t = TranscriptHash::new();
        let before = t.snapshot();
        t.update(b"");
        let after = t.snapshot();
        assert_eq!(before, after,
            "update(\"\") must not change the digest");
    }

    #[test]
    fn batch_b_aead_key_counter_getter_monotonic_strict_and_decrypt_static() {
        // Pin AeadKey::counter() semantics: starts at 0, strictly +1 per
        // encrypt, decrypt is read-only (does NOT advance counter).
        let mut keys = derive_session_keys(&[3u8; 32], &[5u8; 32], &[7u8; 32], true).unwrap();
        let peer = derive_session_keys(&[3u8; 32], &[5u8; 32], &[7u8; 32], false).unwrap();

        // Initial state: counter == 0.
        assert_eq!(keys.k_send.counter(), 0,
            "fresh AeadKey must start at counter==0 (this counter value is consumed by the first encrypt)");
        assert_eq!(keys.k_recv.counter(), 0);
        assert_eq!(peer.k_send.counter(), 0);

        // Strict +1 per encrypt, across many calls.
        let mut frames = Vec::new();
        for n in 1u64..=20 {
            let ct = keys.k_send.encrypt(b"ad", &n.to_be_bytes()).unwrap();
            assert_eq!(keys.k_send.counter(), n,
                "after {n} encrypts, counter must equal {n}; got {}", keys.k_send.counter());
            frames.push(ct);
        }

        // Decrypt is read-only: replaying 50 decrypts against peer.k_recv
        // must NOT advance peer.k_recv.counter() (which stays at 0).
        for (i, ct) in frames.iter().enumerate() {
            let _ = peer.k_recv.decrypt(i as u64, b"ad", ct).unwrap();
        }
        assert_eq!(peer.k_recv.counter(), 0,
            "decrypt() takes &self — must NOT advance the receive counter");

        // Encrypting an empty payload still advances the counter (the
        // counter is per-frame, not per-byte).
        let mut k = derive_session_keys(&[1u8; 32], &[2u8; 32], &[3u8; 32], true).unwrap();
        assert_eq!(k.k_send.counter(), 0);
        let _ = k.k_send.encrypt(b"", b"").unwrap();
        assert_eq!(k.k_send.counter(), 1,
            "empty-payload encrypt must still advance the counter");

        // AeadKey::new() with arbitrary bytes also starts at counter==0.
        let raw = AeadKey::new([0xAB; AEAD_KEY_LEN]);
        assert_eq!(raw.counter(), 0);
        // key_bytes (test-only) must return exactly what new() got.
        assert_eq!(raw.key_bytes(), [0xAB; AEAD_KEY_LEN]);
    }

    #[test]
    fn batch_b_derive_session_keys_ikm_concat_order_x25519_first_then_ml_kem_asymmetry() {
        // The doc declares "X25519 first, ML-KEM second" in the IKM
        // concatenation (line 180-184). This ordering is wire-stable —
        // a peer that flipped the order would derive different keys and
        // every session would fail at the first AEAD decrypt. Pin the
        // asymmetry with a swap-test: derive(x=A,k=B) != derive(x=B,k=A).
        let th = [0x11u8; 32];
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];

        let keys_ab = derive_session_keys(&a, &b, &th, true).unwrap();
        let keys_ba = derive_session_keys(&b, &a, &th, true).unwrap();

        // Different IKM concat order → different derived keys.
        assert_ne!(keys_ab.k_send.key_bytes(), keys_ba.k_send.key_bytes(),
            "swapping x25519/ml_kem arguments must change the derived key (concat order pin)");
        assert_ne!(keys_ab.k_recv.key_bytes(), keys_ba.k_recv.key_bytes());

        // Equal inputs in BOTH slots → deterministic same-keys.
        let same_input = derive_session_keys(&a, &a, &th, true).unwrap();
        let same_input2 = derive_session_keys(&a, &a, &th, true).unwrap();
        assert_eq!(same_input.k_send.key_bytes(), same_input2.k_send.key_bytes(),
            "deterministic: same inputs → same output");

        // Role flip (initiator vs responder) swaps k_send / k_recv (existing
        // test 4 covers this with one input pair; pin it for multiple to
        // defend against a regression that only mirrors for some inputs).
        for ts in [[0u8; 32], [0xFFu8; 32], [0x55u8; 32]] {
            let init = derive_session_keys(&a, &b, &ts, true).unwrap();
            let resp = derive_session_keys(&a, &b, &ts, false).unwrap();
            assert_eq!(init.k_send.key_bytes(), resp.k_recv.key_bytes(),
                "initiator.k_send == responder.k_recv must hold for any transcript");
            assert_eq!(init.k_recv.key_bytes(), resp.k_send.key_bytes(),
                "initiator.k_recv == responder.k_send must hold for any transcript");
        }

        // SS_LEN contract: every input array must be exactly 32 bytes.
        // The function signature enforces this at compile time — pin the
        // SS_LEN constant equals the array width so a change here would
        // also need to change the signature.
        assert_eq!(SS_LEN, 32);
        let _: &[u8; SS_LEN] = &a;
        let _: &[u8; SS_LEN] = &b;
        let _: &[u8; SS_LEN] = &th;
    }

    #[test]
    fn kat_session_keys_and_aead_exact_hex_wire_vectors() {
        // ABSOLUTE known-answer vectors for the session key schedule + AEAD.
        // The relation/label/layout tests above pin *structure*; these pin
        // the EXACT output bytes. A relation test still passes if `hkdf` /
        // `chacha20poly1305` / `sha2` resolve to a different implementation
        // that produces different bytes — only an absolute KAT catches that,
        // which is what makes the elara-pq-transport crate extraction
        // provably byte-identical on the wire (and gives external
        // re-implementers a vector to test against). Inputs are distinct,
        // non-trivial fixtures so a transposed/truncated derivation can't
        // accidentally match.
        let x25519_ss = [0x01u8; 32];
        let ml_kem_ss = [0x02u8; 32];
        let transcript = [0x03u8; 32];

        let mut init = derive_session_keys(&x25519_ss, &ml_kem_ss, &transcript, true).unwrap();
        // HKDF-SHA256(salt=transcript, ikm=x25519_ss||ml_kem_ss) → expand
        // under LABEL_K_SEND / LABEL_K_RECV. Exact 32-byte keys:
        assert_eq!(
            hex::encode(init.k_send.key_bytes()),
            "296dce8943346463d33eaa64af36ae3b36ac18cf957da7fa1f8480458ce1425c",
            "k_send wire vector drifted — HKDF-SHA256 key schedule changed"
        );
        assert_eq!(
            hex::encode(init.k_recv.key_bytes()),
            "8ab7a20c97ea0e0cacf224f2a42c6b1296ae0c79d24c2308c93ae17a3348b244",
            "k_recv wire vector drifted"
        );

        // ChaCha20-Poly1305 at counter 0 under k_send, AD="ELPQ-AD",
        // plaintext="known-answer-test" (17 B) → 17 B ciphertext + 16 B tag.
        // Pins the full AEAD output including the Poly1305 tag.
        let ct = init.k_send.encrypt(b"ELPQ-AD", b"known-answer-test").unwrap();
        assert_eq!(
            hex::encode(&ct),
            "bccc2381b651dde828bf16280562f5dab9c09889048d7187da05dacf6993e80596",
            "AEAD ciphertext+tag wire vector drifted"
        );
        // Round-trips back to the plaintext under the peer's matching recv key.
        let peer = derive_session_keys(&x25519_ss, &ml_kem_ss, &transcript, false).unwrap();
        assert_eq!(
            peer.k_recv.decrypt(0, b"ELPQ-AD", &ct).unwrap(),
            b"known-answer-test"
        );

        // Frame-type AD vector: a post-handshake Data frame binds the 1-byte
        // frame type into the AEAD AD (the node's `PqStream::decrypt_frame` /
        // `send_typed`; 0x04 is FrameType::Data, pinned in frame.rs type tests).
        // Pinning the EXACT ciphertext for AD=[0x04] at counter 0 means a
        // regression to empty AD — the 483569ea silent-wire-break class — or any
        // other frame-AD change flips this vector and fails CI. Fresh keys so the
        // send counter starts at 0 (the ELPQ-AD vector above advanced init's).
        let mut frame_keys = derive_session_keys(&x25519_ss, &ml_kem_ss, &transcript, true).unwrap();
        let ct_data = frame_keys.k_send.encrypt(&[0x04u8], b"data-frame-ad").unwrap();
        assert_eq!(
            hex::encode(&ct_data),
            "b3c33897f51acee736ad5e3b4c96d38031d9c3d4c55e1ce09e49b5e1ca",
            "Data-frame AEAD AD vector drifted — the post-handshake frame-type AD construction changed"
        );
        let frame_peer = derive_session_keys(&x25519_ss, &ml_kem_ss, &transcript, false).unwrap();
        assert_eq!(
            frame_peer.k_recv.decrypt(0, &[0x04u8], &ct_data).unwrap(),
            b"data-frame-ad"
        );
    }

    /// Append-only ledger pairing every shipped `frame::WIRE_VERSION` with the
    /// SHA3-256 fingerprint of the crate's wire-defining behavior. Rows are
    /// history: NEVER edit or delete one — a wire change gets a NEW row with a
    /// bumped version, in the same commit.
    ///
    /// Why this exists: commit `483569ea` changed the frame AEAD AD
    /// (empty → `[frame_type]`) without bumping `WIRE_VERSION`, reasoning
    /// "no external peers yet" — forgetting the fleet itself is a mixed-build
    /// network. Stale peers completed the handshake then silently failed every
    /// frame for a full day (13,836 rejects). The KATs above catch the *drift*;
    /// this ledger forces the *decision*: you cannot make the fingerprint test
    /// green again without either reverting the wire change or explicitly
    /// bumping the version — the "doesn't matter yet" shortcut now has to say
    /// so in a diff line that reviews loudly.
    const WIRE_LEDGER: &[(u8, &str)] = &[
        // 0x01: pre-a981edd2 era (empty frame AD, unseeded transcript).
        // Retired before this ledger shipped; tombstone keeps the history
        // complete so the append-only rule starts at the real beginning.
        (0x01, "RETIRED-PRE-LEDGER"),
        (
            0x02,
            "bafbf3adc612440ba1aebac8f2182222dd7172188c92350dfef1c6672de1b8a6",
        ),
    ];

    #[test]
    fn wire_fingerprint_ledger_forces_version_bump() {
        // Deterministic digest over every wire-defining surface this crate
        // controls: header constants, frame-type numbering, exact frame
        // encoding, the HKDF session-key schedule, and the AEAD construction
        // including the frame-type AD binding. Same fixed inputs as the KAT
        // above, so the two fail together on real drift.
        let mut h = Sha3_256::new();
        h.update(b"ELPQ-WIRE-FP-v1");
        h.update([crate::frame::WIRE_VERSION]);
        h.update(crate::frame::ELPQ_MAGIC);
        h.update((crate::frame::HEADER_LEN as u32).to_be_bytes());
        h.update((crate::frame::MAX_PAYLOAD as u64).to_be_bytes());
        h.update([
            crate::frame::FrameType::Hello as u8,
            crate::frame::FrameType::Challenge as u8,
            crate::frame::FrameType::Auth as u8,
            crate::frame::FrameType::Data as u8,
            crate::frame::FrameType::Rekey as u8,
            crate::frame::FrameType::Close as u8,
            crate::frame::FrameType::StreamChunk as u8,
            crate::frame::FrameType::Admission as u8,
        ]);
        h.update(
            crate::frame::Frame::new(crate::frame::FrameType::Data, b"fp-probe".to_vec())
                .unwrap()
                .encode(),
        );
        let mut keys = derive_session_keys(&[0x01; 32], &[0x02; 32], &[0x03; 32], true).unwrap();
        h.update(keys.k_send.key_bytes());
        h.update(keys.k_recv.key_bytes());
        // Counter starts at 0 on fresh keys; AD = frame-type byte (483569ea).
        h.update(
            keys.k_send
                .encrypt(&[crate::frame::FrameType::Data as u8], b"fp-probe")
                .unwrap(),
        );
        let fp = hex::encode(h.finalize());

        let (last_version, last_fp) = *WIRE_LEDGER.last().unwrap();
        assert_eq!(
            last_version,
            crate::frame::WIRE_VERSION,
            "WIRE_VERSION {:#04x} has no ledger row — append (WIRE_VERSION, fingerprint), never edit old rows",
            crate::frame::WIRE_VERSION,
        );
        assert_eq!(
            fp, last_fp,
            "wire fingerprint drifted from the ledger row for {last_version:#04x}: \
             the wire format changed. Bump frame::WIRE_VERSION and APPEND a new \
             ledger row with this computed fingerprint — do NOT edit the existing \
             row (deployed peers hold that history). If the change must not be a \
             wire break, revert it instead.",
        );
        // Append-only discipline: versions strictly increase, fingerprints unique.
        for w in WIRE_LEDGER.windows(2) {
            assert!(
                w[0].0 < w[1].0,
                "ledger versions must be strictly increasing ({:#04x} then {:#04x})",
                w[0].0,
                w[1].0,
            );
            assert_ne!(
                w[0].1, w[1].1,
                "adjacent ledger rows share a fingerprint — a version bump with \
                 no wire change is a lie; revert the bump or fix the fingerprint",
            );
        }
    }
}
