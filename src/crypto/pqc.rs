//! Post-quantum cryptography: ML-DSA-65 (FIPS 204) + SPHINCS+-SHA2-192f.
//!
//! Pure Rust implementation via `dilithium-rs` crate. No C libraries.
//! Works identically on native, WASM, and all CPU architectures.
//!
//! Key/signature sizes (ML-DSA-65): pk=1952, sk=4032, sig=3309 bytes.
//! Compatible with PQClean outputs — same FIPS 204 standard.
//!
//! SPHINCS+: pure Rust via `lattice-slh-dsa` crate. Works on all platforms.
//! Profile A = dual-sig (Dilithium3 + SPHINCS+). Profile B = Dilithium3 only.

//!
//! Spec references:
//!   @spec Protocol §4.2
//!   @spec Protocol §4.3

use crate::errors::{ElaraError, Result};

/// A Dilithium3 keypair (public key + secret key).
/// Secret key is zeroized on drop to prevent memory disclosure.
pub struct DilithiumKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl DilithiumKeypair {
    pub fn into_parts(mut self) -> (Vec<u8>, Vec<u8>) {
        let pk = std::mem::take(&mut self.public_key);
        let sk = std::mem::take(&mut self.secret_key);
        (pk, sk)
    }
}

impl Drop for DilithiumKeypair {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret_key.zeroize();
    }
}

/// A SPHINCS+ keypair.
/// Secret key is zeroized on drop to prevent memory disclosure.
pub struct SphincsKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl SphincsKeypair {
    pub fn into_parts(mut self) -> (Vec<u8>, Vec<u8>) {
        let pk = std::mem::take(&mut self.public_key);
        let sk = std::mem::take(&mut self.secret_key);
        (pk, sk)
    }
}

impl Drop for SphincsKeypair {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret_key.zeroize();
    }
}

// ─── Dilithium3 / ML-DSA-65 (pure Rust, all platforms) ─────────────────────

use dilithium::safe_api::DilithiumKeyPair;
use dilithium::params::DilithiumMode;

// Verify-only primitives (dilithium3_verify, sphincs_verify) live in the permissive
// elara-record crate so the verifier can embed them without the AGPL node; keygen/sign
// stay here (secret-key paths). Re-exported so crate::crypto::pqc::* call sites are unchanged.
pub use elara_record::pqc::{dilithium3_verify, sphincs_verify};

const MODE: DilithiumMode = DilithiumMode::Dilithium3;

/// Generate a Dilithium3 (ML-DSA-65) keypair deterministically from a 32-byte seed.
///
/// The seed is passed directly to `ML-DSA.KeyGen_internal(ξ)` per FIPS 204, which
/// expands it internally via SHAKE-256 to derive (rho, rho', K) and the matrix A.
/// No SHA3 pre-hash is needed — the FIPS algorithm is already the canonical PRF.
///
/// AUDIT-8: prior implementation called non-deterministic `DilithiumKeyPair::generate(MODE)`
/// and discarded `seed` entirely, despite the name and docstring promising determinism.
/// dilithium-rs 0.2 exposes `generate_deterministic(mode, &[u8; SEEDBYTES=32])` — there
/// was never a missing API. Callers (VrfSecretKey::from_bytes, from_seed) relied on the
/// promised contract; a single seed that reproducibly derives the same keypair is required
/// for VRF key portability and for any deterministic test fixture.
pub fn dilithium3_keypair_from_seed(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
    let kp = DilithiumKeyPair::generate_deterministic(MODE, seed);
    Ok((kp.public_key().to_vec(), kp.private_key().to_vec()))
}

pub fn dilithium3_keygen() -> Result<DilithiumKeypair> {
    let kp = DilithiumKeyPair::generate(MODE)
        .map_err(|e| ElaraError::Crypto(format!("ML-DSA-65 keygen failed: {e:?}")))?;
    Ok(DilithiumKeypair {
        public_key: kp.public_key().to_vec(),
        secret_key: kp.private_key().to_vec(),
    })
}

/// Sign with both secret key and public key. Required by pure Rust ML-DSA-65.
pub fn dilithium3_sign_with_pk(message: &[u8], secret_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    let kp = DilithiumKeyPair::from_keys(secret_key, public_key, MODE)
        .map_err(|e| ElaraError::Crypto(format!("invalid ML-DSA-65 keys: {e:?}")))?;
    let sig = kp.sign(message, b"")
        .map_err(|e| ElaraError::Crypto(format!("ML-DSA-65 sign failed: {e:?}")))?;
    Ok(sig.as_bytes().to_vec())
}

// dilithium3_verify moved to elara-record::pqc (re-exported at the top of this module).

// ─── SPHINCS+ / SLH-DSA-SHA2-192f (pure Rust, all platforms) ────────────────

use slh_dsa::safe_api::SlhDsaKeyPair;
use slh_dsa::params::SLH_DSA_SHA2_192F;

pub fn sphincs_keygen() -> Result<SphincsKeypair> {
    let kp = SlhDsaKeyPair::generate(SLH_DSA_SHA2_192F)
        .map_err(|e| ElaraError::Crypto(format!("SLH-DSA keygen failed: {e:?}")))?;
    Ok(SphincsKeypair {
        public_key: kp.public_key().to_vec(),
        secret_key: kp.secret_key().to_vec(),
    })
}

/// Sign with both secret key and public key.
pub fn sphincs_sign_with_pk(message: &[u8], secret_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    let kp = SlhDsaKeyPair::from_bytes(SLH_DSA_SHA2_192F, public_key, secret_key)
        .map_err(|e| ElaraError::Crypto(format!("invalid SLH-DSA keys: {e:?}")))?;
    let sig = kp.sign(message)
        .map_err(|e| ElaraError::Crypto(format!("SLH-DSA sign failed: {e:?}")))?;
    Ok(sig.to_bytes().to_vec())
}

// sphincs_verify moved to elara-record::pqc (re-exported at the top of this module).

// ─── Public algorithm constants ─────────────────────────────────────────────

/// Algorithm ID for ML-DSA-65 (FIPS 204) — Dilithium3.
pub const ALG_DILITHIUM3: u8 = 1;
/// Algorithm ID for SPHINCS+-SHA2-192f (Profile A secondary sig).
pub const ALG_SPHINCS_SHA2_192F: u8 = 2;

/// Dilithium3 / ML-DSA-65 public key size in bytes (FIPS 204).
pub const DILITHIUM3_PUBLIC_KEY_LEN: usize = 1952;
/// SPHINCS+-SHA2-192f / SLH-DSA public key size in bytes (FIPS 205).
pub const SPHINCS_SHA2_192F_PUBLIC_KEY_LEN: usize = 48;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium3_keygen() {
        let kp = dilithium3_keygen().unwrap();
        assert_eq!(kp.public_key.len(), 1952);
        assert_eq!(kp.secret_key.len(), 4032);
    }

    #[test]
    fn test_dilithium3_sign_verify() {
        let kp = dilithium3_keygen().unwrap();
        let msg = b"elara protocol test message";
        let sig = dilithium3_sign_with_pk(msg, &kp.secret_key, &kp.public_key).unwrap();
        assert_eq!(sig.len(), 3309);
        assert!(dilithium3_verify(msg, &sig, &kp.public_key).unwrap());
    }

    #[test]
    fn test_dilithium3_wrong_message() {
        let kp = dilithium3_keygen().unwrap();
        let sig = dilithium3_sign_with_pk(b"correct", &kp.secret_key, &kp.public_key).unwrap();
        assert!(!dilithium3_verify(b"wrong", &sig, &kp.public_key).unwrap());
    }

    #[test]
    fn test_dilithium3_wrong_key() {
        let kp1 = dilithium3_keygen().unwrap();
        let kp2 = dilithium3_keygen().unwrap();
        let msg = b"test";
        let sig = dilithium3_sign_with_pk(msg, &kp1.secret_key, &kp1.public_key).unwrap();
        assert!(!dilithium3_verify(msg, &sig, &kp2.public_key).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_sphincs_keygen() {
        let kp = sphincs_keygen().unwrap();
        assert_eq!(kp.public_key.len(), 48);
        assert!(!kp.secret_key.is_empty());
    }

    #[test]
    fn test_sphincs_sign_verify() {
        let kp = sphincs_keygen().unwrap();
        let msg = b"sphincs test message";
        let sig = sphincs_sign_with_pk(msg, &kp.secret_key, &kp.public_key).unwrap();
        assert_eq!(sig.len(), 35664);
        assert!(sphincs_verify(msg, &sig, &kp.public_key).unwrap());
    }

    #[test]
    fn test_sphincs_wrong_message() {
        let kp = sphincs_keygen().unwrap();
        let sig = sphincs_sign_with_pk(b"correct", &kp.secret_key, &kp.public_key).unwrap();
        assert!(!sphincs_verify(b"wrong", &sig, &kp.public_key).unwrap());
    }

    /// AUDIT-8: the same 32-byte seed MUST produce the same Dilithium3 keypair
    /// bytes, every call, forever. Before the fix this function silently generated
    /// fresh OS-random keypairs and discarded the seed — callers relying on
    /// `from_seed → store seed → reload → same key` saw divergent keys.
    #[test]
    fn test_audit8_seeded_keygen_is_deterministic() {
        let seed = [7u8; 32];
        let (pk1, sk1) = dilithium3_keypair_from_seed(&seed).unwrap();
        let (pk2, sk2) = dilithium3_keypair_from_seed(&seed).unwrap();
        assert_eq!(pk1, pk2, "same seed must yield same public key");
        assert_eq!(sk1, sk2, "same seed must yield same secret key");
        assert_eq!(pk1.len(), 1952);
        assert_eq!(sk1.len(), 4032);
    }

    /// AUDIT-8: different seeds MUST produce different keypairs.
    /// Guards against a lazy fix that hardcoded a single keypair.
    #[test]
    fn test_audit8_distinct_seeds_yield_distinct_keypairs() {
        let (pk_a, _) = dilithium3_keypair_from_seed(&[1u8; 32]).unwrap();
        let (pk_b, _) = dilithium3_keypair_from_seed(&[2u8; 32]).unwrap();
        let (pk_c, _) = dilithium3_keypair_from_seed(&[0u8; 32]).unwrap();
        assert_ne!(pk_a, pk_b);
        assert_ne!(pk_a, pk_c);
        assert_ne!(pk_b, pk_c);
    }

    /// AUDIT-8: seeded keypair signatures still verify correctly, so the
    /// deterministic path is a drop-in replacement for the non-deterministic one.
    #[test]
    fn test_audit8_seeded_keypair_signs_and_verifies() {
        let seed = [42u8; 32];
        let (pk, sk) = dilithium3_keypair_from_seed(&seed).unwrap();
        let msg = b"AUDIT-8 deterministic keygen";
        let sig = dilithium3_sign_with_pk(msg, &sk, &pk).unwrap();
        assert!(dilithium3_verify(msg, &sig, &pk).unwrap());
    }

    /// AUDIT-8: VRF public key derivation is now stable under a stored seed.
    /// Two `VrfSecretKey::from_bytes` calls with the same seed must yield the
    /// same `public_key().as_bytes()`. This is the contract that jury selection,
    /// VRF registry persistence, and anchor identity all rely on.
    #[test]
    fn test_audit8_vrf_public_key_is_stable_under_seed() {
        use crate::crypto::vrf::VrfSecretKey;
        let seed = [99u8; 32];
        let sk_a = VrfSecretKey::from_bytes(seed).unwrap();
        let sk_b = VrfSecretKey::from_bytes(seed).unwrap();
        assert_eq!(sk_a.public_key().as_bytes(), sk_b.public_key().as_bytes());
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_algorithm_id_constants_strict_pin_and_distinctness_matrix() {
        // Wire-format tag identifiers must be stable across releases —
        // any divergence corrupts cross-version signature container parsing.
        assert_eq!(ALG_DILITHIUM3, 1u8, "FIPS 204 ML-DSA-65 algorithm tag must be 1");
        assert_eq!(ALG_SPHINCS_SHA2_192F, 2u8, "SLH-DSA-SHA2-192f algorithm tag must be 2");

        // Tag-space distinctness: no two PQC algorithms share an ID.
        assert_ne!(ALG_DILITHIUM3, ALG_SPHINCS_SHA2_192F);
        assert_ne!(ALG_DILITHIUM3, 0u8, "0 reserved for none/unset");
        assert_ne!(ALG_SPHINCS_SHA2_192F, 0u8, "0 reserved for none/unset");

        // Dedup-stability of the full tag tuple.
        let mut tags = vec![ALG_DILITHIUM3, ALG_SPHINCS_SHA2_192F];
        tags.sort();
        tags.dedup();
        assert_eq!(tags.len(), 2, "all PQC algorithm tags must be pairwise distinct");

        // Tag ordering invariant: Dilithium3 (primary) < SPHINCS+ (secondary in Profile A).
        assert!(ALG_DILITHIUM3 < ALG_SPHINCS_SHA2_192F,
            "Profile A primary signer (Dilithium3) must precede secondary (SPHINCS+) in tag order");
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_key_size_constants_strict_pin_and_dilithium_dominates_sphincs() {
        // FIPS 204 / FIPS 205 public-key sizes — used for wire-format length checks.
        assert_eq!(DILITHIUM3_PUBLIC_KEY_LEN, 1952usize, "FIPS 204 ML-DSA-65 PK bytes");
        assert_eq!(SPHINCS_SHA2_192F_PUBLIC_KEY_LEN, 48usize, "FIPS 205 SLH-DSA-SHA2-192f PK bytes");

        // Cross-relation: SPHINCS+ PK is much smaller than Dilithium3 PK.
        assert!(SPHINCS_SHA2_192F_PUBLIC_KEY_LEN < DILITHIUM3_PUBLIC_KEY_LEN,
            "SPHINCS+ PK ({}) must be smaller than Dilithium3 PK ({})",
            SPHINCS_SHA2_192F_PUBLIC_KEY_LEN, DILITHIUM3_PUBLIC_KEY_LEN);

        // Size ratio: Dilithium3 PK is ~40× larger (1952 / 48 ≈ 40.67).
        let ratio = DILITHIUM3_PUBLIC_KEY_LEN / SPHINCS_SHA2_192F_PUBLIC_KEY_LEN;
        assert_eq!(ratio, 40,
            "expected floor(1952/48)=40 size ratio, got {ratio} — key-size constants changed?");

        // Non-zero (defensive — both must be positive for fixed-size network buffers).
        assert!(DILITHIUM3_PUBLIC_KEY_LEN > 0);
        assert!(SPHINCS_SHA2_192F_PUBLIC_KEY_LEN > 0);

        // Multiples-of-8 byte alignment (both spec-mandated).
        assert_eq!(DILITHIUM3_PUBLIC_KEY_LEN % 8, 0, "Dilithium3 PK must be byte-aligned to 8");
        assert_eq!(SPHINCS_SHA2_192F_PUBLIC_KEY_LEN % 8, 0, "SPHINCS+ PK must be byte-aligned to 8");
    }

    #[test]
    fn batch_b_dilithium3_verify_signature_length_gate_strict_pin_sweep() {
        // The 3309-byte gate at dilithium3_verify() rejects pre-Dilithium-3
        // legacy OQS signatures (3293 bytes) and any other malformed length —
        // without ever calling the slow lattice verify.
        let kp = dilithium3_keygen().unwrap();
        let msg = b"length-gate strict-pin probe";

        // Sweep of bad lengths must all return Err with "expected 3309" in message.
        let bad_lengths = [0usize, 1, 16, 1024, 3293, 3308, 3310, 3311, 4000, 6618, 100_000];
        for &bad_len in &bad_lengths {
            let bad_sig = vec![0u8; bad_len];
            let r = dilithium3_verify(msg, &bad_sig, &kp.public_key);
            assert!(r.is_err(), "len={bad_len} must trip length gate");
            let err_msg = format!("{:?}", r.unwrap_err());
            assert!(err_msg.contains("3309"),
                "len={bad_len}: error message must mention 'expected 3309': {err_msg}");
            assert!(err_msg.contains(&bad_len.to_string()),
                "len={bad_len}: error message must mention actual length: {err_msg}");
        }

        // Sanity: the correct length (3309) does NOT trip the length gate
        // (it proceeds to actual lattice verification, which returns Ok(_)).
        let zero_sig_correct_len = vec![0u8; 3309];
        let r_correct = dilithium3_verify(msg, &zero_sig_correct_len, &kp.public_key);
        assert!(r_correct.is_ok(), "len=3309 must proceed past length gate (got {:?})", r_correct);
        // It will verify-false (the signature is all zeros), but it's not a length-gate error.
        assert!(!r_correct.unwrap(), "all-zero signature at correct length must verify-false");
    }

    #[test]
    fn batch_b_dilithium3_keypair_from_seed_determinism_matrix_across_sentinel_seeds() {
        // Four sentinel seed shapes: all-0xFF, all-0xAA, alternating 0xFF/0x00, counter [0,1,2..31].
        let mut alt = [0u8; 32];
        for (i, b) in alt.iter_mut().enumerate() { *b = if i % 2 == 0 { 0xFF } else { 0x00 }; }
        let mut counter = [0u8; 32];
        for (i, b) in counter.iter_mut().enumerate() { *b = i as u8; }
        let seeds: [[u8; 32]; 4] = [[255u8; 32], [0xAAu8; 32], alt, counter];

        // For each seed: 3 successive calls must produce bit-identical (pk, sk).
        let mut pks: Vec<Vec<u8>> = Vec::with_capacity(4);
        for (idx, seed) in seeds.iter().enumerate() {
            let (pk1, sk1) = dilithium3_keypair_from_seed(seed).unwrap();
            let (pk2, sk2) = dilithium3_keypair_from_seed(seed).unwrap();
            let (pk3, sk3) = dilithium3_keypair_from_seed(seed).unwrap();
            assert_eq!(pk1, pk2, "seed[{idx}]: PK call 1 vs 2 must match");
            assert_eq!(pk2, pk3, "seed[{idx}]: PK call 2 vs 3 must match");
            assert_eq!(sk1, sk2, "seed[{idx}]: SK call 1 vs 2 must match");
            assert_eq!(sk2, sk3, "seed[{idx}]: SK call 2 vs 3 must match");
            assert_eq!(pk1.len(), DILITHIUM3_PUBLIC_KEY_LEN);
            assert_eq!(sk1.len(), 4032);
            pks.push(pk1);
        }

        // Pairwise distinctness: all 4 sentinel seeds must yield distinct PKs.
        // (Guards against hardcoded-keypair lazy "fix" regressing AUDIT-8.)
        for i in 0..pks.len() {
            for j in (i + 1)..pks.len() {
                assert_ne!(pks[i], pks[j],
                    "seeds[{i}] and seeds[{j}] must yield distinct public keys (AUDIT-8 invariant)");
            }
        }
    }

    #[test]
    fn batch_b_dilithium3_into_parts_byte_roundtrip_and_public_key_size_pin() {
        // DilithiumKeypair::into_parts() returns (pk, sk) owned vectors
        // that bit-equal the originals — used by Identity to extract PQC
        // halves without copying through &self.
        let kp = dilithium3_keygen().unwrap();
        let pk_orig = kp.public_key.clone();
        let sk_orig = kp.secret_key.clone();
        let pk_orig_len = pk_orig.len();
        let sk_orig_len = sk_orig.len();

        // into_parts consumes self (compile-time enforced by `mut self`).
        let (pk_extracted, sk_extracted) = kp.into_parts();
        assert_eq!(pk_extracted, pk_orig, "extracted PK must bit-equal original");
        assert_eq!(sk_extracted, sk_orig, "extracted SK must bit-equal original");
        assert_eq!(pk_extracted.len(), pk_orig_len);
        assert_eq!(sk_extracted.len(), sk_orig_len);

        // Spec-mandated sizes still hold after extraction.
        assert_eq!(pk_extracted.len(), DILITHIUM3_PUBLIC_KEY_LEN,
            "extracted PK must remain {} bytes", DILITHIUM3_PUBLIC_KEY_LEN);
        assert_eq!(sk_extracted.len(), 4032, "extracted SK must remain 4032 bytes");

        // Extracted bytes are non-empty + non-trivial (not all zeros — Dilithium3
        // keygen produces high-entropy output regardless of internal randomness path).
        assert!(pk_extracted.iter().any(|&b| b != 0), "extracted PK must not be all zeros");
        assert!(sk_extracted.iter().any(|&b| b != 0), "extracted SK must not be all zeros");

        // A second keygen + into_parts produces distinct bytes from the first
        // (proves into_parts isn't returning a stale shared buffer).
        let kp2 = dilithium3_keygen().unwrap();
        let (pk2, sk2) = kp2.into_parts();
        assert_ne!(pk2, pk_extracted, "two independent keygens must yield distinct PKs");
        assert_ne!(sk2, sk_extracted, "two independent keygens must yield distinct SKs");
    }
}
