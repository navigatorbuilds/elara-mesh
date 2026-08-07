//! Elara PQ Client SDK — account-grade post-quantum client library.
//!
//! AUDIT-10 Milestone C exit criterion #1. Wraps the internal
//! [`PqNodeClient`](crate::network::pq_client::PqNodeClient) into an
//! opinionated, narrow surface for accounts and external integrators:
//! Dilithium3 TOFU + the four verbs accounts actually need.
//!
//! # Why a separate module
//!
//! [`PqNodeClient`] exposes ~50 verbs covering gossip, sync, snapshot,
//! transition cosign, and witness fan-in. Wallets touch a small subset.
//! Letting account authors copy-paste from the node client invites two
//! bugs: (1) calling a peer-only verb that depends on validator privileges,
//! (2) skipping the TOFU pin step. The SDK collapses the surface to four
//! verbs and threads the pin store through every call.
//!
//! # The four account verbs
//!
//! | SDK method | Wire verb | Mirrors |
//! |---|---|---|
//! | [`AccountClient::submit_record`] | `submit_record` | `POST /records` |
//! | [`AccountClient::account_proof`] | `account_proof` | `GET /proof/account/{id}` |
//! | [`AccountClient::seal_progress`] | `seal_progress` | `GET /seal-progress/{rec}` |
//! | [`AccountClient::activity`] | `activity` | `GET /activity/{id}` |
//!
//! These are the verbs Protocol §11.22 (light-client account proofs),
//! §11.18 (seal progress streaming), and §11.23 (activity summary)
//! enumerate as account-facing. Anything else (cross-zone proofs,
//! attestation fan-in, gossip submit) is validator territory.
//!
//! # Identity & pinning
//!
//! Every [`AccountClient`] owns:
//!
//! 1. A Dilithium3 keypair that authenticates the account to peers. Use
//!    [`AccountClient::ephemeral`] to mint a fresh one per session, or
//!    [`AccountClient::with_keypair`] to bring your own (for accounts that
//!    persist identity across launches).
//! 2. A [`PeerIdentityStore`] that records the Dilithium3 pubkey hash of
//!    every peer the account has talked to. First contact pins via TOFU;
//!    every subsequent call rejects the handshake if the peer's identity
//!    rotated.
//!
//! The pin store is shared across all calls on one client. Persistence
//! across account launches is a follow-up slice; today the in-memory store
//! is enough for short-lived account sessions.
//!
//! # Future bindings
//!
//! Milestone C exit criterion #1 also calls for WASM and Python bindings.
//! Those are follow-up slices — they wrap [`AccountClient`] without
//! changing its public Rust surface, so account code written today against
//! this module keeps working when the bindings land.

use std::sync::Arc;

use crate::errors::Result;
use crate::network::pq_client::PqNodeClient;
use crate::network::pq_transport::PeerIdentityStore;

mod light;
mod account_client;

pub use light::{LightClient, VerifiedAccount};
pub use account_client::AccountClient;

/// Re-export the pin store so SDK consumers don't need to reach into
/// `network::pq_transport` to construct one.
pub use crate::network::pq_transport::PeerIdentityStore as PinStore;

/// Mint a fresh Dilithium3 keypair for client use. Returns
/// `(public_key, secret_key)` as raw bytes — feed them to
/// [`AccountClient::with_keypair`] if you want to persist identity across
/// account sessions.
pub fn dilithium3_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let kp = crate::crypto::pqc::dilithium3_keygen()?;
    let (pk, sk) = kp.into_parts();
    Ok((pk, sk))
}

/// Build a [`PqNodeClient`] directly. Most callers should prefer
/// [`AccountClient`] — this escape hatch exists for tooling that needs the
/// full verb surface (e.g. `elara_cli` running diagnostics).
pub fn raw_client(
    pk: Vec<u8>,
    sk: Vec<u8>,
    pins: Arc<PeerIdentityStore>,
) -> PqNodeClient {
    PqNodeClient::new(pk, sk, pins)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pqc::{
        dilithium3_sign_with_pk, dilithium3_verify, DILITHIUM3_PUBLIC_KEY_LEN,
    };

    const DILITHIUM3_SECRET_KEY_LEN: usize = 4032;
    const DILITHIUM3_SIGNATURE_LEN: usize = 3309;

    #[test]
    fn dilithium3_keypair_returns_fips204_sized_keys() {
        let (pk, sk) = dilithium3_keypair().expect("keygen");
        assert_eq!(pk.len(), DILITHIUM3_PUBLIC_KEY_LEN, "pk must be FIPS 204 ML-DSA-65 1952 bytes");
        assert_eq!(sk.len(), DILITHIUM3_SECRET_KEY_LEN, "sk must be FIPS 204 ML-DSA-65 4032 bytes");
    }

    #[test]
    fn dilithium3_keypair_signs_and_verifies() {
        let (pk, sk) = dilithium3_keypair().expect("keygen");
        let msg = b"elara account smoke";
        let sig = dilithium3_sign_with_pk(msg, &sk, &pk).expect("sign");
        assert_eq!(sig.len(), DILITHIUM3_SIGNATURE_LEN, "sig must be 3309 bytes");
        assert!(dilithium3_verify(msg, &sig, &pk).expect("verify"));
    }

    #[test]
    fn dilithium3_keypair_yields_distinct_keys_per_call() {
        let (pk1, sk1) = dilithium3_keypair().expect("keygen 1");
        let (pk2, sk2) = dilithium3_keypair().expect("keygen 2");
        assert_ne!(pk1, pk2, "non-deterministic keygen must produce distinct pks");
        assert_ne!(sk1, sk2, "non-deterministic keygen must produce distinct sks");
    }

    #[test]
    fn raw_client_threads_supplied_pin_store_through_to_node_client() {
        let (pk, sk) = dilithium3_keypair().expect("keygen");
        let pins = Arc::new(PinStore::in_memory());
        let client = raw_client(pk, sk, Arc::clone(&pins));
        assert_eq!(client.pool_size(), 0, "fresh client must hold no pooled connections");
        assert!(client.pins().list().is_empty(), "raw_client must expose the supplied (empty) pin store");
    }

    // ─── cryptographic correctness invariants ──────

    /// Byte-length invariant must hold across MANY calls — not just one.
    /// A regression where dilithium3_keygen leaks variable-length output
    /// (e.g. trims trailing zeros, switches scheme variant) would silently
    /// break a non-trivial fraction of generated keypairs while passing
    /// the single-call test. Pin N=20 with strict equality on every entry.
    #[test]
    fn batch_b_dilithium3_keypair_byte_lengths_invariant_across_n_calls() {
        for i in 0..20 {
            let (pk, sk) = dilithium3_keypair().expect("keygen");
            assert_eq!(pk.len(), DILITHIUM3_PUBLIC_KEY_LEN, "iter {i}: pk length drifted to {}", pk.len());
            assert_eq!(sk.len(), DILITHIUM3_SECRET_KEY_LEN, "iter {i}: sk length drifted to {}", sk.len());
        }
    }

    /// Cross-keypair signature isolation: a signature minted under keypair-1
    /// must NOT verify under keypair-2's public key. The most catastrophic
    /// account bug imaginable is "any sig validates under any pk" — pin against
    /// it directly so a future verifier short-circuit (e.g. const-true) breaks
    /// loudly here, not silently in mainnet.
    #[test]
    fn batch_b_dilithium3_signature_does_not_verify_under_different_keypair_pk() {
        let (pk1, sk1) = dilithium3_keypair().expect("keygen 1");
        let (pk2, _sk2) = dilithium3_keypair().expect("keygen 2");
        assert_ne!(pk1, pk2, "fresh keygens must differ");
        let msg = b"elara account cross-key isolation";
        let sig = dilithium3_sign_with_pk(msg, &sk1, &pk1).expect("sign with kp1");
        // Sig from kp1 must NOT verify under kp2.pk
        let verifies_under_other = dilithium3_verify(msg, &sig, &pk2).expect("verify call must not error");
        assert!(!verifies_under_other, "sig signed by kp1 must NOT verify under kp2.pk");
    }

    /// Signature must bind to message content, not just keypair. A one-bit
    /// flip in the payload invalidates the signature. Pin so a future
    /// "ignore last byte" optimization (or domain-separation regression)
    /// fails here instead of letting attackers swap message tails.
    #[test]
    fn batch_b_dilithium3_signature_rejects_one_bit_tampered_message() {
        let (pk, sk) = dilithium3_keypair().expect("keygen");
        let msg = b"elara account message-binding probe".to_vec();
        let sig = dilithium3_sign_with_pk(&msg, &sk, &pk).expect("sign");
        // Confirm clean verify works first (sanity gate)
        assert!(dilithium3_verify(&msg, &sig, &pk).expect("verify"));
        // Flip the lowest bit of the LAST byte — minimal mutation
        let mut tampered = msg.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_ne!(tampered, msg, "tamper must actually change bytes");
        let verifies = dilithium3_verify(&tampered, &sig, &pk).expect("verify call must not error");
        assert!(!verifies, "one-bit flipped message must NOT verify under original sig");
    }

    /// Empty payload edge case — sign/verify of a zero-length message must
    /// produce a valid 3309-byte signature and round-trip cleanly. Wallets
    /// occasionally need to sign empty challenges (e.g. session-establishment
    /// pings); pin against a future "reject empty input" regression at the
    /// SDK boundary.
    #[test]
    fn batch_b_dilithium3_signs_and_verifies_empty_payload() {
        let (pk, sk) = dilithium3_keypair().expect("keygen");
        let empty: &[u8] = &[];
        let sig = dilithium3_sign_with_pk(empty, &sk, &pk).expect("sign empty");
        assert_eq!(sig.len(), DILITHIUM3_SIGNATURE_LEN, "empty-payload sig length must still be 3309");
        assert!(dilithium3_verify(empty, &sig, &pk).expect("verify empty"), "empty-payload sig must verify");
    }

    /// Large-payload roundtrip — 4096-byte message still produces a
    /// 3309-byte signature (signature size is independent of input length
    /// under FIPS 204) and verifies. Pin so the SDK wrapper can't silently
    /// chunk or truncate large account payloads in the future.
    #[test]
    fn batch_b_dilithium3_signs_and_verifies_large_payload() {
        let (pk, sk) = dilithium3_keypair().expect("keygen");
        // Deterministic pseudo-random pattern, 4 KiB.
        let large: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(2654435769) & 0xFF) as u8).collect();
        let sig = dilithium3_sign_with_pk(&large, &sk, &pk).expect("sign large");
        assert_eq!(sig.len(), DILITHIUM3_SIGNATURE_LEN, "4KiB-payload sig length must still be 3309");
        assert!(dilithium3_verify(&large, &sig, &pk).expect("verify large"), "4KiB-payload sig must verify");
    }
}
