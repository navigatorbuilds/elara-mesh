//! Hand-rolled Noise_XX-style 3-message hybrid handshake.
//!
//! # Message layout
//!
//! ```text
//! msg1  init → resp:   timestamp(8) || e_x25519_pk(32) || e_mlkem_pk(1184)
//! msg2  resp → init:   e_x25519_pk(32) || e_mlkem_ct(1088) || AEAD(pk_dil || sig_dil)
//! msg3  init → resp:                                         AEAD(pk_dil || sig_dil)
//! ```
//!
//! The transcript is seeded with the 1-byte `frame::WIRE_VERSION` BEFORE
//! `msg1`, so two peers built against different wire versions derive
//! divergent session keys and fail the handshake AEAD cleanly rather than
//! desyncing silently on the first post-handshake frame. Each side absorbs
//! its OWN compile-time constant, never the peer's cleartext header byte.
//!
//! - `AEAD` is ChaCha20-Poly1305 under the session key pair derived from
//!   `HKDF(salt=transcript_hash, ikm=x25519_ss || ml_kem_ss)`. The AD is
//!   the transcript hash at the point of encryption. Tampering with any
//!   prior byte flips the hash and kills the MAC.
//! - `sig_dil` signs the running transcript hash at signing time. This
//!   is the MITM killer even if ML-KEM is broken: an attacker cannot
//!   forge Dilithium3 over a transcript it did not participate in.
//! - The responder checks `SHA3-256(pk_dil) == expected_identity_hash`
//!   (if known) or simply pins it on first contact (TOFU).
//!
//! # State machine (synchronous driver)
//!
//! Callers drive the handshake manually for testability. For an asynchronous
//! stream wrapper this same state machine runs against `tokio::io::AsyncRead`
//! / `AsyncWrite`.

use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Pub};
use zeroize::Zeroizing;

use crate::crypto::{derive_session_keys, CryptoError, SessionKeys, TranscriptHash};
use crate::kem::{
    mlkem768_decapsulate, mlkem768_encapsulate, mlkem768_keygen, KemError, KemKeypair,
    MlKem768Sizes,
};
use crate::sig::{dilithium3_sign_with_pk, dilithium3_verify, sha3_256, SigError};

/// 8 bytes for big-endian Unix-seconds timestamp.
const TS_LEN: usize = 8;
/// X25519 public keys and shared secrets are 32 bytes.
const X25519_LEN: usize = 32;
/// Maximum allowed clock skew between peers for the handshake timestamp.
/// Per spec, 30 s. Handshakes older than this are rejected unsigned —
/// the signed transcript will catch them anyway, but this is the fast
/// abort path.
pub const MAX_HANDSHAKE_SKEW_SECS: u64 = 30;

/// Dilithium3 sizes (ML-DSA-65, FIPS 204).
const DIL_PK_LEN: usize = 1952;
const DIL_SIG_LEN: usize = 3309;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

/// What the initiator expects from the responder's identity.
///
/// - `Pinned(hash)`: if the received Dilithium3 pubkey doesn't hash to
///   this, abort (strict mode for subsequent contacts via SSH-style pin).
/// - `Tofu`: accept any identity on first contact and let the caller
///   decide what to do with it (typically store for future comparison).
#[derive(Debug, Clone)]
pub enum PeerExpectation {
    Pinned([u8; 32]),
    Tofu,
}

/// Result of a completed handshake: the peer's long-term identity and
/// the session keys for bulk data.
pub struct CompletedHandshake {
    pub peer_dilithium_pk: Vec<u8>,
    pub peer_identity_hash: [u8; 32],
    pub session: SessionKeys,
}

// Manual Debug: never leak session key bytes. Only identity is safe to print.
impl std::fmt::Debug for CompletedHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletedHandshake")
            .field("peer_identity_hash", &hex::encode(self.peer_identity_hash))
            .field("peer_dilithium_pk_len", &self.peer_dilithium_pk.len())
            .field("session", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("wrong state: {0}")]
    WrongState(&'static str),
    #[error("malformed handshake message: {0}")]
    Malformed(&'static str),
    #[error("handshake timestamp out of window (skew {skew_secs}s, max {max_secs}s)")]
    TimestampSkew { skew_secs: u64, max_secs: u64 },
    #[error("AEAD verification failed — transcript mismatch or wrong keys")]
    AeadFailed,
    #[error("identity pin mismatch: peer's Dilithium3 hash != expected")]
    IdentityPinMismatch,
    #[error("Dilithium3 signature invalid — peer does not hold the claimed identity")]
    SignatureInvalid,
    #[error("key encapsulation error: {0}")]
    Kem(#[from] KemError),
    #[error("signature error: {0}")]
    Sig(#[from] SigError),
    #[error("session crypto error: {0}")]
    SessionCrypto(#[from] CryptoError),
}

/// Handshake state.
enum State {
    /// Responder just constructed; awaiting the initiator's msg1.
    ///
    /// Distinct from `Done` (which previously doubled as the fresh-responder
    /// sentinel): keeping the two apart lets `responder_process_msg1` reject a
    /// replayed msg1 on an already-advanced responder instead of absorbing it
    /// into the finalized transcript.
    RespIdle,
    /// Initiator just constructed; msg1 already emitted.
    InitWaitingForMsg2 {
        e_x25519: EphemeralSecret,
        e_mlkem: KemKeypair,
    },
    /// Responder processed msg1; has ephemerals from the initiator.
    RespWaitingForMsg3 {
        /// Already-derived session keys.
        session: SessionKeys,
        /// Transcript at the point the initiator will sign.
        transcript_snapshot_for_sig: [u8; 32],
    },
    /// Handshake completed successfully on this side.
    Done,
    /// Terminal error — do not allow further use.
    Poisoned,
}

pub struct PqHandshake {
    role: HandshakeRole,
    /// Our own Dilithium3 identity. Stored as (pk, sk) so we can sign
    /// without repeated decompression.
    my_dil_pk: Vec<u8>,
    /// Wrapped in `Zeroizing` so the long-lived signing key is wiped from the
    /// heap when the (per-connection, possibly short-lived) handshake drops —
    /// without a manual `Drop` impl, which would forbid moving `completed` out
    /// in `into_completed`. Mirrors the zeroize-on-drop on `KemKeypair`.
    my_dil_sk: Zeroizing<Vec<u8>>,
    /// Only the initiator has a peer expectation.
    peer_expectation: Option<PeerExpectation>,
    /// Timestamp injected at handshake start. In production this is
    /// `SystemTime::now()`; tests inject fixed values.
    now_unix_secs: u64,
    transcript: TranscriptHash,
    state: State,
    /// Set when the handshake completes. Take it via `into_completed`.
    completed: Option<CompletedHandshake>,
}

impl PqHandshake {
    /// Start a new initiator handshake.
    ///
    /// Returns the state machine plus `msg1` bytes to send to the peer.
    /// The caller wraps `msg1` in a [`crate::frame::Frame`] of type
    /// [`crate::frame::FrameType::Hello`].
    pub fn new_initiator(
        my_dil_pk: Vec<u8>,
        my_dil_sk: Vec<u8>,
        peer_expectation: PeerExpectation,
        now_unix_secs: u64,
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        // Production always binds the compile-time wire version. The version is
        // threaded through a private helper so tests can drive a *stale* peer (a
        // different wire version) and prove the transcript-divergence abort path
        // end-to-end — see `cross_wire_version_handshake_aborts_clean`.
        Self::new_initiator_with_wire_version(
            my_dil_pk,
            my_dil_sk,
            peer_expectation,
            now_unix_secs,
            crate::frame::WIRE_VERSION,
        )
    }

    fn new_initiator_with_wire_version(
        my_dil_pk: Vec<u8>,
        my_dil_sk: Vec<u8>,
        peer_expectation: PeerExpectation,
        now_unix_secs: u64,
        wire_version: u8,
    ) -> Result<(Self, Vec<u8>), HandshakeError> {
        if my_dil_pk.len() != DIL_PK_LEN {
            return Err(HandshakeError::Malformed("initiator dilithium pk wrong length"));
        }
        let e_x25519 = EphemeralSecret::random_from_rng(OsRng);
        let e_x25519_pub = X25519Pub::from(&e_x25519);
        let e_mlkem = mlkem768_keygen()?;

        let mut msg1 = Vec::with_capacity(TS_LEN + X25519_LEN + MlKem768Sizes::PUBLIC_KEY);
        msg1.extend_from_slice(&now_unix_secs.to_be_bytes());
        msg1.extend_from_slice(e_x25519_pub.as_bytes());
        msg1.extend_from_slice(&e_mlkem.public_key);

        let mut transcript = TranscriptHash::new();
        // Bind the local wire version into the transcript before any handshake
        // byte. A peer on a different WIRE_VERSION absorbs a different leading
        // byte, so its transcript — and thus the HKDF-derived session keys
        // (salt = transcript) — diverge; the very next handshake AEAD (msg2
        // decrypt) fails the Poly1305 tag and the handshake aborts CLEANLY,
        // instead of the silent post-handshake frame-decrypt desync that an
        // un-versioned wire change (e.g. 483569ea's AEAD-AD change) produces.
        transcript.update(&[wire_version]);
        transcript.update(&msg1);

        let hs = Self {
            role: HandshakeRole::Initiator,
            my_dil_pk,
            my_dil_sk: Zeroizing::new(my_dil_sk),
            peer_expectation: Some(peer_expectation),
            now_unix_secs,
            transcript,
            state: State::InitWaitingForMsg2 { e_x25519, e_mlkem },
            completed: None,
        };
        Ok((hs, msg1))
    }

    /// Start a new responder handshake. Produces the state machine but
    /// no wire bytes — the responder waits for `msg1`.
    pub fn new_responder(
        my_dil_pk: Vec<u8>,
        my_dil_sk: Vec<u8>,
        now_unix_secs: u64,
    ) -> Result<Self, HandshakeError> {
        Self::new_responder_with_wire_version(
            my_dil_pk,
            my_dil_sk,
            now_unix_secs,
            crate::frame::WIRE_VERSION,
        )
    }

    fn new_responder_with_wire_version(
        my_dil_pk: Vec<u8>,
        my_dil_sk: Vec<u8>,
        now_unix_secs: u64,
        wire_version: u8,
    ) -> Result<Self, HandshakeError> {
        if my_dil_pk.len() != DIL_PK_LEN {
            return Err(HandshakeError::Malformed("responder dilithium pk wrong length"));
        }
        // Seed the transcript with the local wire version BEFORE msg1 is
        // absorbed (in responder_process_msg1), symmetric to new_initiator —
        // keeps the [version || msg1 || …] transcript byte-identical to a
        // same-version initiator and divergent from a stale one.
        let mut transcript = TranscriptHash::new();
        transcript.update(&[wire_version]);
        Ok(Self {
            role: HandshakeRole::Responder,
            my_dil_pk,
            my_dil_sk: Zeroizing::new(my_dil_sk),
            peer_expectation: None,
            now_unix_secs,
            transcript,
            state: State::RespIdle,
            completed: None,
        })
    }

    /// Responder: ingest the initiator's `msg1` and emit `msg2`.
    pub fn responder_process_msg1(&mut self, msg1: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if self.role != HandshakeRole::Responder {
            return Err(HandshakeError::WrongState(
                "only responders call responder_process_msg1",
            ));
        }
        // Reject a replayed/duplicate msg1: only a fresh responder may ingest
        // msg1. Without this guard a second valid msg1 would re-`update` the
        // already-finalized transcript and re-derive session keys, corrupting
        // the pending handshake — the honest initiator's msg3, signed over the
        // first transcript, would then fail to verify. Fails closed: no session
        // is ever established under the manipulated transcript, but an on-path
        // peer could otherwise abort the handshake (DoS) and force a second
        // msg2 emission. This guard turns that into a clean WrongState error.
        if !matches!(self.state, State::RespIdle) {
            return Err(HandshakeError::WrongState(
                "responder already ingested msg1",
            ));
        }
        let expected = TS_LEN + X25519_LEN + MlKem768Sizes::PUBLIC_KEY;
        if msg1.len() != expected {
            return Err(HandshakeError::Malformed("msg1 wrong length"));
        }

        // 1. Timestamp skew check (fast-path abort; signed check happens below).
        let mut ts_bytes = [0u8; TS_LEN];
        ts_bytes.copy_from_slice(&msg1[..TS_LEN]);
        let init_ts = u64::from_be_bytes(ts_bytes);
        let skew = self.now_unix_secs.abs_diff(init_ts);
        if skew > MAX_HANDSHAKE_SKEW_SECS {
            self.state = State::Poisoned;
            return Err(HandshakeError::TimestampSkew {
                skew_secs: skew,
                max_secs: MAX_HANDSHAKE_SKEW_SECS,
            });
        }

        // 2. Parse initiator ephemerals.
        let mut init_x25519 = [0u8; X25519_LEN];
        init_x25519.copy_from_slice(&msg1[TS_LEN..TS_LEN + X25519_LEN]);
        let init_x25519_pub = X25519Pub::from(init_x25519);
        let init_mlkem_pk = &msg1[TS_LEN + X25519_LEN..];

        // 3. Absorb msg1 into transcript.
        self.transcript.update(msg1);

        // 4. Generate responder ephemerals.
        let resp_x25519 = EphemeralSecret::random_from_rng(OsRng);
        let resp_x25519_pub = X25519Pub::from(&resp_x25519);

        // 5. Compute shared secrets.
        //    X25519: ECDH between ephemeral secret and peer ephemeral public.
        let x25519_ss_shared = resp_x25519.diffie_hellman(&init_x25519_pub);
        let mut x25519_ss = [0u8; 32];
        x25519_ss.copy_from_slice(x25519_ss_shared.as_bytes());
        //    ML-KEM: responder encapsulates under initiator's ML-KEM pk.
        let encap = mlkem768_encapsulate(init_mlkem_pk)?;
        if encap.shared_secret.len() != 32 {
            return Err(HandshakeError::Malformed("ml-kem shared secret wrong length"));
        }
        let mut ml_kem_ss = [0u8; 32];
        ml_kem_ss.copy_from_slice(&encap.shared_secret);

        // 6. Build msg2 public parts (ephemeral x25519 pub || ml-kem ciphertext).
        let public_len = X25519_LEN + MlKem768Sizes::CIPHERTEXT;
        let mut msg2_public = Vec::with_capacity(public_len);
        msg2_public.extend_from_slice(resp_x25519_pub.as_bytes());
        msg2_public.extend_from_slice(&encap.ciphertext);

        // 7. Absorb msg2 public parts into transcript, snapshot for signing.
        self.transcript.update(&msg2_public);
        let transcript_for_sig = self.transcript.snapshot();

        // 8. Derive session keys at responder role.
        let mut session = derive_session_keys(
            &x25519_ss,
            &ml_kem_ss,
            &transcript_for_sig,
            /* initiator = */ false,
        )?;

        // 9. Sign transcript snapshot with our Dilithium3 key.
        let sig = dilithium3_sign_with_pk(&transcript_for_sig, &self.my_dil_sk, &self.my_dil_pk)?;
        if sig.len() != DIL_SIG_LEN {
            return Err(HandshakeError::Malformed("our dilithium sig wrong length"));
        }

        // 10. AEAD-encrypt (pk || sig) under transcript-snapshot AD.
        let mut inner = Vec::with_capacity(DIL_PK_LEN + DIL_SIG_LEN);
        inner.extend_from_slice(&self.my_dil_pk);
        inner.extend_from_slice(&sig);
        let aead_blob = session
            .k_send
            .encrypt(&transcript_for_sig, &inner)
            .map_err(HandshakeError::from)?;

        // 11. Absorb AEAD blob into transcript (so msg3 signs it too).
        self.transcript.update(&aead_blob);
        let transcript_snapshot_for_init_sig = self.transcript.snapshot();

        // 12. Assemble final msg2 wire bytes.
        let mut msg2 = Vec::with_capacity(public_len + aead_blob.len());
        msg2.extend_from_slice(&msg2_public);
        msg2.extend_from_slice(&aead_blob);

        self.state = State::RespWaitingForMsg3 {
            session,
            transcript_snapshot_for_sig: transcript_snapshot_for_init_sig,
        };
        Ok(msg2)
    }

    /// Initiator: ingest `msg2` and emit `msg3`.
    pub fn initiator_process_msg2(&mut self, msg2: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let (e_x25519, e_mlkem) = match std::mem::replace(&mut self.state, State::Poisoned) {
            State::InitWaitingForMsg2 { e_x25519, e_mlkem } => (e_x25519, e_mlkem),
            _ => return Err(HandshakeError::WrongState("initiator not waiting for msg2")),
        };

        let aead_overhead = 16; // Poly1305 tag.
        let min_len =
            X25519_LEN + MlKem768Sizes::CIPHERTEXT + DIL_PK_LEN + DIL_SIG_LEN + aead_overhead;
        if msg2.len() != min_len {
            return Err(HandshakeError::Malformed("msg2 wrong length"));
        }

        // 1. Parse public parts.
        let resp_x25519_bytes: [u8; X25519_LEN] = msg2[..X25519_LEN]
            .try_into()
            .map_err(|_| HandshakeError::Malformed("bad x25519"))?;
        let resp_x25519_pub = X25519Pub::from(resp_x25519_bytes);
        let mlkem_ct = &msg2[X25519_LEN..X25519_LEN + MlKem768Sizes::CIPHERTEXT];
        let aead_blob = &msg2[X25519_LEN + MlKem768Sizes::CIPHERTEXT..];

        let msg2_public_len = X25519_LEN + MlKem768Sizes::CIPHERTEXT;
        self.transcript.update(&msg2[..msg2_public_len]);
        let transcript_for_sig = self.transcript.snapshot();

        // 2. Compute hybrid shared secrets.
        let x25519_ss_shared = e_x25519.diffie_hellman(&resp_x25519_pub);
        let mut x25519_ss = [0u8; 32];
        x25519_ss.copy_from_slice(x25519_ss_shared.as_bytes());
        let ml_kem_ss_vec = mlkem768_decapsulate(&e_mlkem.secret_key, mlkem_ct)?;
        if ml_kem_ss_vec.len() != 32 {
            return Err(HandshakeError::Malformed("ml-kem ss wrong length"));
        }
        let mut ml_kem_ss = [0u8; 32];
        ml_kem_ss.copy_from_slice(&ml_kem_ss_vec);

        // 3. Derive session keys at initiator role.
        let mut session = derive_session_keys(
            &x25519_ss,
            &ml_kem_ss,
            &transcript_for_sig,
            /* initiator = */ true,
        )?;

        // 4. AEAD-decrypt the responder's identity + signature. counter=0 (first AEAD frame).
        let inner = session
            .k_recv
            .decrypt(0, &transcript_for_sig, aead_blob)
            .map_err(|_| HandshakeError::AeadFailed)?;
        if inner.len() != DIL_PK_LEN + DIL_SIG_LEN {
            return Err(HandshakeError::Malformed("decrypted inner wrong length"));
        }
        let peer_pk = &inner[..DIL_PK_LEN];
        let peer_sig = &inner[DIL_PK_LEN..];

        // 5. Identity pin check.
        let peer_identity_hash = sha3_256(peer_pk);
        match self.peer_expectation.as_ref() {
            Some(PeerExpectation::Pinned(expected)) => {
                if expected != &peer_identity_hash {
                    return Err(HandshakeError::IdentityPinMismatch);
                }
            }
            Some(PeerExpectation::Tofu) | None => { /* accept */ }
        }

        // 6. Signature verification.
        let valid = dilithium3_verify(&transcript_for_sig, peer_sig, peer_pk)?;
        if !valid {
            return Err(HandshakeError::SignatureInvalid);
        }

        // 7. Absorb AEAD blob into transcript (must match what responder
        //    signed in msg3 expectation).
        self.transcript.update(aead_blob);
        let transcript_for_our_sig = self.transcript.snapshot();

        // 8. Sign the new transcript and AEAD-wrap (pk || sig) under the
        //    same running key schedule (counter advances to 1).
        let our_sig =
            dilithium3_sign_with_pk(&transcript_for_our_sig, &self.my_dil_sk, &self.my_dil_pk)?;
        if our_sig.len() != DIL_SIG_LEN {
            return Err(HandshakeError::Malformed("our dilithium sig wrong length"));
        }
        let mut inner3 = Vec::with_capacity(DIL_PK_LEN + DIL_SIG_LEN);
        inner3.extend_from_slice(&self.my_dil_pk);
        inner3.extend_from_slice(&our_sig);
        let aead3 = session
            .k_send
            .encrypt(&transcript_for_our_sig, &inner3)
            .map_err(HandshakeError::from)?;

        self.completed = Some(CompletedHandshake {
            peer_dilithium_pk: peer_pk.to_vec(),
            peer_identity_hash,
            session,
        });
        self.state = State::Done;
        Ok(aead3)
    }

    /// Responder: ingest `msg3` and complete.
    pub fn responder_process_msg3(&mut self, msg3: &[u8]) -> Result<(), HandshakeError> {
        let (session, transcript_snapshot_for_sig) =
            match std::mem::replace(&mut self.state, State::Poisoned) {
                State::RespWaitingForMsg3 {
                    session,
                    transcript_snapshot_for_sig,
                } => (session, transcript_snapshot_for_sig),
                _ => return Err(HandshakeError::WrongState("responder not waiting for msg3")),
            };

        // Decrypt with k_recv, counter = 0 (first AEAD frame in this direction).
        let inner = session
            .k_recv
            .decrypt(0, &transcript_snapshot_for_sig, msg3)
            .map_err(|_| HandshakeError::AeadFailed)?;
        if inner.len() != DIL_PK_LEN + DIL_SIG_LEN {
            return Err(HandshakeError::Malformed("decrypted msg3 wrong length"));
        }
        let peer_pk = &inner[..DIL_PK_LEN];
        let peer_sig = &inner[DIL_PK_LEN..];

        let valid = dilithium3_verify(&transcript_snapshot_for_sig, peer_sig, peer_pk)?;
        if !valid {
            return Err(HandshakeError::SignatureInvalid);
        }

        let peer_identity_hash = sha3_256(peer_pk);
        self.completed = Some(CompletedHandshake {
            peer_dilithium_pk: peer_pk.to_vec(),
            peer_identity_hash,
            session,
        });
        self.state = State::Done;
        Ok(())
    }

    /// True when [`into_completed`](Self::into_completed) will succeed.
    pub fn is_complete(&self) -> bool {
        matches!(self.state, State::Done) && self.completed.is_some()
    }

    /// Consume the handshake and return the completed session.
    pub fn into_completed(self) -> Result<CompletedHandshake, HandshakeError> {
        self.completed
            .ok_or(HandshakeError::WrongState("handshake not completed"))
    }

    pub fn role(&self) -> HandshakeRole {
        self.role
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::dilithium3_keygen;

    struct TestPeer {
        pk: Vec<u8>,
        sk: Vec<u8>,
        identity_hash: [u8; 32],
    }

    fn gen_peer() -> TestPeer {
        let (pk, sk) = dilithium3_keygen().unwrap();
        let identity_hash = sha3_256(&pk);
        TestPeer {
            pk,
            sk,
            identity_hash,
        }
    }

    /// Drive a full handshake. Returns the two completed peer views
    /// (initiator's view, responder's view).
    fn run_handshake(
        init: &TestPeer,
        resp: &TestPeer,
        init_expectation: PeerExpectation,
        init_ts: u64,
        resp_ts: u64,
    ) -> Result<(CompletedHandshake, CompletedHandshake), HandshakeError> {
        let (mut init_hs, msg1) =
            PqHandshake::new_initiator(init.pk.clone(), init.sk.clone(), init_expectation, init_ts)?;
        let mut resp_hs = PqHandshake::new_responder(resp.pk.clone(), resp.sk.clone(), resp_ts)?;
        let msg2 = resp_hs.responder_process_msg1(&msg1)?;
        let msg3 = init_hs.initiator_process_msg2(&msg2)?;
        resp_hs.responder_process_msg3(&msg3)?;
        Ok((init_hs.into_completed()?, resp_hs.into_completed()?))
    }

    /// Pre-auth robustness: the three message processors must reject every
    /// truncated / over-length / garbage buffer with an `Err` and must never
    /// panic — and all of this happens *before* the peer is authenticated, so
    /// it is reachable by any hostile prober. The other tests only feed
    /// correctly-sized messages (valid, or valid-then-bit-flipped), which
    /// exercise the AEAD/signature guards but never the length guards
    /// (`msg1.len() != expected`, `msg2.len() != min_len`, and msg3's AEAD-tag
    /// rejection of a wrong-length ciphertext). This pins those guards: a
    /// future refactor of this (public, MIT/Apache) crate that drops a length
    /// check fails here instead of silently reintroducing a pre-auth
    /// slice-index panic on a crafted handshake frame.
    #[test]
    fn handshake_processors_reject_malformed_without_panic() {
        let init = gen_peer();
        let resp = gen_peer();
        const TS: u64 = 1_000_000;

        // Capture one valid buffer of each message by driving a real handshake.
        let (_i0, valid_msg1) = PqHandshake::new_initiator(
            init.pk.clone(),
            init.sk.clone(),
            PeerExpectation::Tofu,
            TS,
        )
        .unwrap();
        let valid_msg2 = {
            let mut r =
                PqHandshake::new_responder(resp.pk.clone(), resp.sk.clone(), TS).unwrap();
            r.responder_process_msg1(&valid_msg1).unwrap()
        };
        let valid_msg3 = {
            let (mut i, m1) = PqHandshake::new_initiator(
                init.pk.clone(),
                init.sk.clone(),
                PeerExpectation::Tofu,
                TS,
            )
            .unwrap();
            let mut r =
                PqHandshake::new_responder(resp.pk.clone(), resp.sk.clone(), TS).unwrap();
            let m2 = r.responder_process_msg1(&m1).unwrap();
            i.initiator_process_msg2(&m2).unwrap()
        };

        // Malformed buffers from a valid one: strided truncations (always incl.
        // 0 / 1 / len-1), one over-length, and zero/0xFF fills at boundary and
        // exact-length sizes. `stride` bounds per-input crypto cost; only
        // wrong-length inputs get an `Err` assertion (a correct-length garbage
        // buffer is content-rejected by skew/AEAD, but we assert only no-panic
        // there to avoid coupling the test to those internals).
        fn corpus(valid: &[u8], stride: usize) -> Vec<Vec<u8>> {
            let len = valid.len();
            let mut sizes: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
            sizes.insert(0);
            if len >= 1 {
                sizes.insert(1);
                sizes.insert(len - 1);
            }
            let mut n = 0usize;
            while n < len {
                sizes.insert(n);
                n += stride.max(1);
            }
            let mut out: Vec<Vec<u8>> = sizes.iter().map(|&l| valid[..l].to_vec()).collect();
            let mut over = valid.to_vec();
            over.extend_from_slice(&[0xABu8; 17]);
            out.push(over);
            for &sz in &[1usize, 8, 16, 32, 64, len.saturating_sub(1), len, len + 1] {
                out.push(vec![0u8; sz]);
                out.push(vec![0xFFu8; sz]);
            }
            out
        }

        // 1. responder_process_msg1 — fresh responder per input (cheap: the
        //    length guard returns before any crypto, so a full sweep is fine).
        for bad in corpus(&valid_msg1, 1) {
            let mut hs =
                PqHandshake::new_responder(resp.pk.clone(), resp.sk.clone(), TS).unwrap();
            let r = hs.responder_process_msg1(&bad);
            if bad.len() != valid_msg1.len() {
                assert!(r.is_err(), "msg1 len={} must be rejected", bad.len());
            }
        }

        // 2. initiator_process_msg2 — fresh initiator (InitWaitingForMsg2) per
        //    input; each new_initiator does one ephemeral keygen, hence stride.
        for bad in corpus(&valid_msg2, 64) {
            let (mut hs, _m1) = PqHandshake::new_initiator(
                init.pk.clone(),
                init.sk.clone(),
                PeerExpectation::Tofu,
                TS,
            )
            .unwrap();
            let r = hs.initiator_process_msg2(&bad);
            if bad.len() != valid_msg2.len() {
                assert!(r.is_err(), "msg2 len={} must be rejected", bad.len());
            }
        }

        // 3. responder_process_msg3 — fresh responder advanced to
        //    RespWaitingForMsg3 per input. No explicit input-length guard here;
        //    a wrong-length msg3 must still be rejected by the AEAD tag check.
        for bad in corpus(&valid_msg3, 64) {
            let mut hs =
                PqHandshake::new_responder(resp.pk.clone(), resp.sk.clone(), TS).unwrap();
            hs.responder_process_msg1(&valid_msg1).unwrap();
            let r = hs.responder_process_msg3(&bad);
            if bad.len() != valid_msg3.len() {
                assert!(r.is_err(), "msg3 len={} must be rejected", bad.len());
            }
        }
    }

    /// Deterministic seeded fuzz sweep that reaches the *post-gate* crypto paths
    /// the corpus test above cannot.
    ///
    /// `handshake_processors_reject_malformed_without_panic` is thorough on the
    /// length guards, but its only EXACT-length inputs are all-zero / all-0xFF —
    /// and for msg1 BOTH die at the timestamp-skew gate (`skew > 30s`) before
    /// `mlkem768_encapsulate(init_mlkem_pk)` ever runs. So the residual pre-auth
    /// panic surface — the ML-KEM / AEAD operations on structurally-valid-length
    /// but CORRUPTED bytes, reachable by any unauthenticated prober that opens a
    /// socket — was never exercised by a malformed input. This sweep closes that:
    /// it starts from a VALID buffer of each message and applies structured
    /// mutations that keep the size valid (and, for msg1, the timestamp intact),
    /// so the encapsulate / decapsulate / AEAD-decrypt calls run on attacker-
    /// shaped bytes. Invariant: every processor RETURNS (Err or Ok) — never
    /// panics/aborts. Seeded splitmix64 so a failure is replayable; zero added
    /// deps (matches the deterministic-sweep philosophy — no proptest/libfuzzer
    /// in a soon-public MIT/Apache crate).
    #[test]
    fn fuzz_handshake_processors_reach_post_gate_crypto_without_panic() {
        // Tiny deterministic splitmix64 — same generator as the node tree's
        // `decoder_fuzz` sweep, kept local so the crate adds no rand/proptest dep.
        struct Rng(u64);
        impl Rng {
            fn next_u64(&mut self) -> u64 {
                self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^ (z >> 31)
            }
            fn below(&mut self, b: usize) -> usize {
                if b == 0 {
                    0
                } else {
                    (self.next_u64() % b as u64) as usize
                }
            }
        }
        /// Clobber `k` random bytes of `base` inside `[lo, hi)`; length preserved.
        fn mutate_region(rng: &mut Rng, base: &[u8], lo: usize, hi: usize, k: usize) -> Vec<u8> {
            let mut v = base.to_vec();
            if hi > lo && hi <= v.len() {
                for _ in 0..k {
                    let i = lo + rng.below(hi - lo);
                    v[i] = (rng.next_u64() & 0xff) as u8;
                }
            }
            v
        }

        let init = gen_peer();
        let resp = gen_peer();
        const TS: u64 = 1_000_000;

        // One valid buffer of each message (same construction as the corpus test).
        let (_i0, valid_msg1) =
            PqHandshake::new_initiator(init.pk.clone(), init.sk.clone(), PeerExpectation::Tofu, TS)
                .unwrap();
        let valid_msg2 = {
            let mut r = PqHandshake::new_responder(resp.pk.clone(), resp.sk.clone(), TS).unwrap();
            r.responder_process_msg1(&valid_msg1).unwrap()
        };
        let valid_msg3 = {
            let (mut i, m1) = PqHandshake::new_initiator(
                init.pk.clone(),
                init.sk.clone(),
                PeerExpectation::Tofu,
                TS,
            )
            .unwrap();
            let mut r = PqHandshake::new_responder(resp.pk.clone(), resp.sk.clone(), TS).unwrap();
            let m2 = r.responder_process_msg1(&m1).unwrap();
            i.initiator_process_msg2(&m2).unwrap()
        };

        let seed = 0x9171_0001u64;
        let mut rng = Rng(seed);

        // ── msg1 (responder, PRE-AUTH — the most exposed surface). Keeping the
        //    8-byte timestamp intact pins skew=0, so a corrupted x25519/ML-KEM
        //    region reaches `mlkem768_encapsulate` on a malformed public key.
        //    NOTE: liboqs ML-KEM encaps does NOT validate pk *content* (only the
        //    1184-byte length, checked by `public_key_from_bytes`), so a valid-
        //    length garbage pk runs the full encaps → `derive_session_keys` →
        //    Dilithium3 SIGN pipeline — i.e. each such iter costs one real PQ
        //    signature. Counts are therefore sized to that per-iter crypto cost,
        //    not to a 30k pure-decoder sweep: a few hundred structured mutations
        //    fully cover the (content-branch-free) crypto paths for panic-safety.
        //    ~half the iters mutate the whole buffer (random timestamp → usually
        //    skew-rejected, exercising that gate on diverse content too).
        const MSG1_ITERS: usize = 256;
        for i in 0..MSG1_ITERS {
            let m1 = if rng.next_u64() & 1 == 0 {
                let k = 1 + rng.below(16);
                mutate_region(&mut rng, &valid_msg1, TS_LEN, valid_msg1.len(), k)
            } else {
                let k = 1 + rng.below(24);
                mutate_region(&mut rng, &valid_msg1, 0, valid_msg1.len(), k)
            };
            let mut hs =
                PqHandshake::new_responder(resp.pk.clone(), resp.sk.clone(), TS).unwrap();
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = hs.responder_process_msg1(&m1);
            }));
            assert!(
                r.is_ok(),
                "responder_process_msg1 PANICKED on mutated-valid msg1 — not fail-closed. seed={seed:#x} iter={i}",
            );
        }

        // ── msg2 (initiator). No timestamp gate; a corrupted exact-length buffer
        //    reaches `mlkem768_decapsulate` (ML-KEM implicit rejection returns a
        //    pseudo-random ss, never panicking) then the AEAD decrypt, which
        //    fails closed before any sign (one decaps per iter, no signature).
        const MSG2_ITERS: usize = 256;
        for i in 0..MSG2_ITERS {
            let k = 1 + rng.below(24);
            let m2 = mutate_region(&mut rng, &valid_msg2, 0, valid_msg2.len(), k);
            let (mut ihs, _m1b) = PqHandshake::new_initiator(
                init.pk.clone(),
                init.sk.clone(),
                PeerExpectation::Tofu,
                TS,
            )
            .unwrap();
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = ihs.initiator_process_msg2(&m2);
            }));
            assert!(
                r.is_ok(),
                "initiator_process_msg2 PANICKED on mutated-valid msg2 — not fail-closed. seed={seed:#x} iter={i}",
            );
        }

        // ── msg3 (responder, advanced past a real msg1). Straight to the AEAD
        //    decrypt on a corrupted ciphertext. Advancing the responder costs one
        //    real Dilithium sign per iter (state is consumed by msg3, so a fresh
        //    advance is required each time) → a smaller loop keeps wall-time low.
        const MSG3_ITERS: usize = 48;
        for i in 0..MSG3_ITERS {
            let k = 1 + rng.below(24);
            let m3 = mutate_region(&mut rng, &valid_msg3, 0, valid_msg3.len(), k);
            let mut rhs =
                PqHandshake::new_responder(resp.pk.clone(), resp.sk.clone(), TS).unwrap();
            rhs.responder_process_msg1(&valid_msg1).unwrap();
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = rhs.responder_process_msg3(&m3);
            }));
            assert!(
                r.is_ok(),
                "responder_process_msg3 PANICKED on mutated-valid msg3 — not fail-closed. seed={seed:#x} iter={i}",
            );
        }
    }

    #[test]
    fn handshake_completes() {
        let init = gen_peer();
        let resp = gen_peer();
        let (init_view, resp_view) = run_handshake(
            &init,
            &resp,
            PeerExpectation::Pinned(resp.identity_hash),
            1_000_000,
            1_000_000,
        )
        .expect("handshake should complete");

        // Each side sees the other's identity.
        assert_eq!(init_view.peer_dilithium_pk, resp.pk);
        assert_eq!(init_view.peer_identity_hash, resp.identity_hash);
        assert_eq!(resp_view.peer_dilithium_pk, init.pk);
        assert_eq!(resp_view.peer_identity_hash, init.identity_hash);

        // Session keys are mirrored: initiator's k_send == responder's k_recv.
        // Test via an encrypt/decrypt round-trip (counter 0 used during
        // handshake already; next frame counter is 1).
        let mut init_view = init_view;
        let resp_view = resp_view;
        let ct = init_view
            .session
            .k_send
            .encrypt(b"data-frame", b"hello")
            .unwrap();
        let pt = resp_view
            .session
            .k_recv
            .decrypt(1, b"data-frame", &ct)
            .unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn handshake_rejects_tampered_transcript() {
        let init = gen_peer();
        let resp = gen_peer();

        let (mut init_hs, msg1) = PqHandshake::new_initiator(
            init.pk.clone(),
            init.sk.clone(),
            PeerExpectation::Pinned(resp.identity_hash),
            1_000_000,
        )
        .unwrap();
        let mut resp_hs =
            PqHandshake::new_responder(resp.pk.clone(), resp.sk.clone(), 1_000_000).unwrap();
        let mut msg2 = resp_hs.responder_process_msg1(&msg1).unwrap();

        // Flip one byte in the responder's ephemeral X25519 public key.
        // The initiator's transcript hash will diverge from the one the
        // responder signed, so either the AEAD or the Dilithium sig check
        // must fail.
        msg2[0] ^= 0x01;
        let err = init_hs.initiator_process_msg2(&msg2).unwrap_err();
        assert!(
            matches!(
                err,
                HandshakeError::AeadFailed | HandshakeError::SignatureInvalid
            ),
            "expected AEAD or sig failure, got {err:?}"
        );
    }

    /// A node built on a *different* PQ `WIRE_VERSION` — the stale-peer case that
    /// silently desynced a follower off its seed before `a981edd2` — must fail the
    /// handshake CLEANLY, not complete it and then silently drop every frame.
    /// Both constructors seed the transcript with their own compile-time wire
    /// version before msg1; a version skew therefore diverges the HKDF session
    /// keys and the initiator's msg2 AEAD decrypt fails closed (`AeadFailed`).
    ///
    /// This is the ONLY test that pins the seeding itself: every same-version
    /// test stays green even if `transcript.update(&[wire_version])` is deleted
    /// from *both* constructors (they'd just drop a symmetric byte), so only a
    /// cross-version drive catches that regression. Both directions are exercised
    /// so dropping the seed from either constructor alone is also caught. The
    /// wire version is never sent on the wire (each side absorbs its own
    /// compile-time constant), so msg1/msg2 parse and the KEM exchange succeed —
    /// the abort lands precisely at the first AEAD under the diverged keys.
    #[test]
    fn cross_wire_version_handshake_aborts_clean() {
        let init = gen_peer();
        let resp = gen_peer();
        const TS: u64 = 1_000_000;

        // Drive a handshake with explicit per-side wire versions. msg1/msg2 are
        // version-independent on the wire, so the only `?` that can fail is the
        // initiator's msg2 AEAD decrypt — exactly where a version skew aborts.
        let drive = |v_init: u8, v_resp: u8| -> Result<(PqHandshake, PqHandshake, Vec<u8>), HandshakeError> {
            let (mut init_hs, msg1) = PqHandshake::new_initiator_with_wire_version(
                init.pk.clone(),
                init.sk.clone(),
                PeerExpectation::Pinned(resp.identity_hash),
                TS,
                v_init,
            )?;
            let mut resp_hs = PqHandshake::new_responder_with_wire_version(
                resp.pk.clone(),
                resp.sk.clone(),
                TS,
                v_resp,
            )?;
            let msg2 = resp_hs.responder_process_msg1(&msg1)?;
            let msg3 = init_hs.initiator_process_msg2(&msg2)?;
            Ok((init_hs, resp_hs, msg3))
        };

        let v = crate::frame::WIRE_VERSION;
        let stale = v.wrapping_add(1); // any value != v; only the mismatch matters
        for (v_i, v_r, label) in [(v, stale, "stale responder"), (stale, v, "stale initiator")] {
            match drive(v_i, v_r) {
                Err(HandshakeError::AeadFailed) => {}
                Err(other) => panic!("{label}: expected clean AeadFailed on wire-version skew, got {other:?}"),
                Ok(_) => panic!(
                    "{label}: wire-version skew COMPLETED the handshake — the transcript \
                     version-seed is no longer bound (regression of a981edd2)"
                ),
            }
        }

        // Positive control: identical (non-default) version on both sides
        // completes, proving the aborts above are the *mismatch*, not the
        // forced-version path being broken — and that a uniform fleet on any
        // single wire version handshakes normally.
        let (init_hs, mut resp_hs, msg3) =
            drive(stale, stale).expect("uniform wire version must complete the handshake");
        resp_hs
            .responder_process_msg3(&msg3)
            .expect("responder accepts msg3 under matching wire version");
        init_hs.into_completed().expect("initiator session established");
        resp_hs.into_completed().expect("responder session established");
    }

    #[test]
    fn responder_rejects_replayed_msg1_without_corrupting_state() {
        // A replayed msg1 on a responder that has already produced msg2 must be
        // rejected (WrongState), not absorbed into the finalized transcript.
        // Regression for the missing state guard in responder_process_msg1: the
        // old code left the fresh-responder sentinel as `State::Done`, so a
        // second valid msg1 re-derived keys over a corrupted transcript.
        let init = gen_peer();
        let resp = gen_peer();

        let (_init_hs, msg1) = PqHandshake::new_initiator(
            init.pk.clone(),
            init.sk.clone(),
            PeerExpectation::Pinned(resp.identity_hash),
            1_000_000,
        )
        .unwrap();
        let mut resp_hs =
            PqHandshake::new_responder(resp.pk.clone(), resp.sk.clone(), 1_000_000).unwrap();

        // First msg1 succeeds and advances the responder past RespIdle.
        let _msg2 = resp_hs.responder_process_msg1(&msg1).unwrap();

        // Replaying the same valid msg1 must be rejected without panicking.
        let err = resp_hs.responder_process_msg1(&msg1).unwrap_err();
        assert!(
            matches!(err, HandshakeError::WrongState(_)),
            "expected WrongState on replayed msg1, got {err:?}"
        );

        // A different but equally valid msg1 must also be rejected — the guard
        // is on responder state, not on msg1 content.
        let (_init_hs2, msg1b) = PqHandshake::new_initiator(
            init.pk.clone(),
            init.sk.clone(),
            PeerExpectation::Pinned(resp.identity_hash),
            1_000_000,
        )
        .unwrap();
        let err2 = resp_hs.responder_process_msg1(&msg1b).unwrap_err();
        assert!(
            matches!(err2, HandshakeError::WrongState(_)),
            "expected WrongState on second distinct msg1, got {err2:?}"
        );
    }

    #[test]
    fn handshake_rejects_expired_timestamp() {
        let init = gen_peer();
        let resp = gen_peer();
        // Initiator stamps at t=1000, responder's clock is at t=1000+31 → over 30s skew.
        let err = run_handshake(
            &init,
            &resp,
            PeerExpectation::Pinned(resp.identity_hash),
            1_000,
            1_031,
        )
        .unwrap_err();
        assert!(
            matches!(err, HandshakeError::TimestampSkew { skew_secs: 31, .. }),
            "expected TimestampSkew, got {err:?}"
        );
    }

    #[test]
    fn handshake_rejects_wrong_identity() {
        let init = gen_peer();
        let actual_resp = gen_peer();
        let imposter = gen_peer(); // Pin this instead; actual responder won't match.
        let err = run_handshake(
            &init,
            &actual_resp,
            PeerExpectation::Pinned(imposter.identity_hash),
            1_000_000,
            1_000_000,
        )
        .unwrap_err();
        assert!(
            matches!(err, HandshakeError::IdentityPinMismatch),
            "expected IdentityPinMismatch, got {err:?}"
        );
    }

    #[test]
    fn handshake_tofu_accepts_any_identity() {
        let init = gen_peer();
        let resp = gen_peer();
        let (init_view, _) = run_handshake(
            &init,
            &resp,
            PeerExpectation::Tofu,
            1_000_000,
            1_000_000,
        )
        .expect("TOFU handshake should complete");
        // Caller can now pin this hash for future contacts.
        assert_eq!(init_view.peer_identity_hash, resp.identity_hash);
    }

    #[test]
    fn handshake_rejects_corrupted_signature() {
        let init = gen_peer();
        let resp = gen_peer();

        let (mut init_hs, msg1) = PqHandshake::new_initiator(
            init.pk.clone(),
            init.sk.clone(),
            PeerExpectation::Pinned(resp.identity_hash),
            1_000_000,
        )
        .unwrap();
        let mut resp_hs =
            PqHandshake::new_responder(resp.pk.clone(), resp.sk.clone(), 1_000_000).unwrap();
        let mut msg2 = resp_hs.responder_process_msg1(&msg1).unwrap();

        // Flip a byte in the AEAD ciphertext region (last byte is the MAC;
        // any flip kills the AEAD).
        let len = msg2.len();
        msg2[len - 1] ^= 0xFF;
        let err = init_hs.initiator_process_msg2(&msg2).unwrap_err();
        assert!(matches!(err, HandshakeError::AeadFailed));
    }

    #[test]
    fn handshake_forward_secrecy_across_runs() {
        let init = gen_peer();
        let resp = gen_peer();
        let (a_init, _a_resp) = run_handshake(
            &init,
            &resp,
            PeerExpectation::Pinned(resp.identity_hash),
            1_000_000,
            1_000_000,
        )
        .unwrap();
        let (b_init, _b_resp) = run_handshake(
            &init,
            &resp,
            PeerExpectation::Pinned(resp.identity_hash),
            1_000_001,
            1_000_001,
        )
        .unwrap();
        // Ephemerals differ, so session keys must differ across runs
        // even with the same long-term identities.
        assert_ne!(
            a_init.session.k_send.key_bytes(),
            b_init.session.k_send.key_bytes()
        );
    }

    // ---- Density (+5) — constants, error display, input validation, wire shape, secret hygiene ----

    /// Axis 1: protocol constants. These are wire-format and FIPS-204 spec
    /// values — any drift breaks interop with peers. Pin all five so a future
    /// "let me bump the skew window" lands a deliberate change (multi-file
    /// diff) rather than a silent drift.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn test_constants_pin() {
        // Big-endian Unix-seconds timestamp prefix.
        assert_eq!(TS_LEN, 8);
        // X25519 public key + shared secret length.
        assert_eq!(X25519_LEN, 32);
        // Spec §11 handshake window — 30 s max skew.
        assert_eq!(MAX_HANDSHAKE_SKEW_SECS, 30);
        // FIPS 204 ML-DSA-65 (Dilithium3) public key length.
        assert_eq!(DIL_PK_LEN, 1952);
        // FIPS 204 ML-DSA-65 (Dilithium3) signature length.
        assert_eq!(DIL_SIG_LEN, 3309);
        // Sanity: sig is longer than PK (~1.7× ratio is canonical for ML-DSA-65).
        assert!(DIL_SIG_LEN > DIL_PK_LEN);
    }

    /// Axis 2: `HandshakeError::TimestampSkew` Display formatting renders the
    /// actual `skew_secs` and `max_secs` numbers — this is the log line
    /// operators grep when diagnosing clock-drift incidents. Pin the rendered
    /// text so a future refactor that drops `{skew_secs}` or rewords the
    /// message lands a deliberate string change.
    #[test]
    fn test_error_display_contains_skew_values() {
        let err = HandshakeError::TimestampSkew {
            skew_secs: 47,
            max_secs: 30,
        };
        let s = format!("{err}");
        // Both numbers MUST appear verbatim in the rendered message.
        assert!(s.contains("47"), "skew_secs value missing: {s}");
        assert!(s.contains("30"), "max_secs value missing: {s}");
        // Keyword "skew" anchors operator grep patterns.
        assert!(s.to_lowercase().contains("skew"), "missing 'skew' keyword: {s}");

        // The identity-mismatch variant has no payload but its rendered
        // message must still describe the failure clearly.
        let pin_err = HandshakeError::IdentityPinMismatch;
        let pin_s = format!("{pin_err}");
        assert!(pin_s.to_lowercase().contains("pin"));
    }

    /// Axis 3: `new_initiator` boundary — passing a Dilithium3 PK of the
    /// wrong length must fail fast with `HandshakeError::Malformed`, NOT panic
    /// and NOT generate ephemerals before checking the input. This is the
    /// input-validation fast-path that protects against caller-side memory
    /// corruption.
    #[test]
    fn test_new_initiator_rejects_wrong_length_pk() {
        // `PqHandshake` deliberately doesn't impl Debug (would leak SK on
        // .unwrap_err()), so we destructure via `match` instead of unwrap_err().
        let empty_pk: Vec<u8> = Vec::new();
        let dummy_sk = vec![0u8; 32];
        match PqHandshake::new_initiator(empty_pk, dummy_sk.clone(), PeerExpectation::Tofu, 1_000_000)
        {
            Err(HandshakeError::Malformed(_)) => {}
            Err(other) => panic!("expected Malformed for empty PK, got {other:?}"),
            Ok(_) => panic!("expected Malformed for empty PK, got Ok"),
        }

        // PK of length 1951 (off-by-one below DIL_PK_LEN) — also rejected.
        let almost_pk = vec![0u8; DIL_PK_LEN - 1];
        match PqHandshake::new_initiator(almost_pk, dummy_sk, PeerExpectation::Tofu, 1_000_000) {
            Err(HandshakeError::Malformed(_)) => {}
            Err(other) => panic!("expected Malformed for off-by-one PK, got {other:?}"),
            Ok(_) => panic!("expected Malformed for off-by-one PK, got Ok"),
        }
    }

    /// Axis 4: `new_initiator` produces a `msg1` whose wire shape is exactly
    /// `TS_LEN(8 BE) + X25519_LEN(32) + ML_KEM_768_PK_LEN(1184)`. First 8
    /// bytes MUST be the timestamp we passed in, big-endian. The responder
    /// side parses these offsets by position, so any drift in the layout
    /// breaks every existing peer in the wild.
    #[test]
    fn test_new_initiator_msg1_wire_shape() {
        let init = gen_peer();
        let ts: u64 = 0x0123_4567_89AB_CDEF;
        let (_hs, msg1) =
            PqHandshake::new_initiator(init.pk.clone(), init.sk.clone(), PeerExpectation::Tofu, ts)
                .expect("valid PK must construct");

        // Exact length = TS + X25519 + ML-KEM-768 PK.
        assert_eq!(
            msg1.len(),
            TS_LEN + X25519_LEN + MlKem768Sizes::PUBLIC_KEY,
            "msg1 wire length must equal sum of fixed-size header components"
        );
        // First 8 bytes = our timestamp, big-endian.
        assert_eq!(
            &msg1[..TS_LEN],
            &ts.to_be_bytes(),
            "timestamp prefix MUST be big-endian and at offset 0"
        );
    }

    /// Axis 5: `CompletedHandshake`'s manual `Debug` impl MUST NOT leak the
    /// symmetric session key bytes — `k_send` / `k_recv` are formatted as the
    /// literal string "<redacted>". A bare `#[derive(Debug)]` would print the
    /// AEAD keys into log files; this test pins the manual redaction so a
    /// future refactor can't silently restore the leak.
    #[test]
    fn test_completed_handshake_debug_redacts_session() {
        let init = gen_peer();
        let resp = gen_peer();
        let (init_view, _resp_view) = run_handshake(
            &init,
            &resp,
            PeerExpectation::Pinned(resp.identity_hash),
            1_000_000,
            1_000_000,
        )
        .expect("valid handshake completes");

        let dbg = format!("{init_view:?}");
        // The redaction marker MUST be present.
        assert!(
            dbg.contains("<redacted>"),
            "session keys MUST be redacted in Debug output: got {dbg}"
        );
        // The exact key bytes MUST NOT appear in the rendered Debug output.
        // We hex-encode the first 16 bytes of the send key and search the
        // Debug string for that substring — if it's there, the manual Debug
        // impl is broken.
        let key_bytes = init_view.session.k_send.key_bytes();
        let key_prefix_hex = hex::encode(&key_bytes[..16]);
        assert!(
            !dbg.contains(&key_prefix_hex),
            "session key bytes leaked into Debug output"
        );
        // The identity hash IS safe to print — confirm it appears.
        assert!(
            dbg.contains(&hex::encode(init_view.peer_identity_hash)),
            "peer identity hash MUST appear in Debug (it's not secret)"
        );
    }
}
