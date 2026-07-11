//! Dilithium3-based verifiable selection function (post-quantum sortition).
//!
//! Post-quantum replacement for EC-VRF (Ed25519, RFC 9381). IMPORTANT: this is
//! a *verifiable, unique, unforgeable* selection function — NOT a full RFC-9381
//! VRF. ML-DSA-65 signing is randomized (FIPS 204), so the output cannot be
//! derived from the signature; instead it is derived from the public key and
//! input, and the signature proves authorization:
//!   prove(sk, alpha) → (output, proof):
//!     output = SHA3-256("elara-vrf-v1" || pk || alpha)  // deterministic; unique per (pk, alpha)
//!     proof  = dilithium3_sign(output, sk)              // unforgeable: only the sk-holder can produce it
//!
//!   verify(pk, alpha, proof) → output:
//!     recompute output = SHA3-256("elara-vrf-v1" || pk || alpha)
//!     accept iff dilithium3_verify(output, proof, pk)
//!
//! Properties provided: uniqueness (one valid output per (pk, alpha)),
//! verifiability (anyone checks with pk), unforgeability (no valid proof without
//! sk). Property NOT provided: output secrecy — the output is a public function
//! of (pk, alpha), so anyone holding pk can compute it without the proof. The
//! selection is therefore unpredictable only insofar as `alpha` carries entropy
//! not known in advance; do not rely on this primitive for output pseudorandomness
//! against a holder of pk. Used for per-zone committee sortition.
//!
//! Proof size: 80 → ~3,309 bytes. Legacy EC-VRF proofs (algorithm tag 0x10) are
//! rejected — the EC-VRF verifier and the legacy `groth16-legacy` arkworks tree
//! have been removed.
//!
//! Spec references:
//!   @spec Protocol §11.12

use sha3::{Sha3_256, Digest};
use zeroize::Zeroize;

use crate::errors::{ElaraError, Result};

/// Cumulative count of legacy EC-VRF (Ed25519, alg=0x10) proofs verified.
/// Should stay zero on mainnet after the 2026-03-31 genesis wipe; operators
/// can monitor this via /status `legacy_vrf_proof_count` or the Prometheus
/// counter `elara_legacy_vrf_proof_total`.
static LEGACY_VRF_PROOF_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Fires the deprecation WARN log exactly once per process lifetime.
static LEGACY_VRF_WARN_ONCE: std::sync::Once = std::sync::Once::new();

/// Return the cumulative count of legacy EC-VRF proofs verified.
pub fn legacy_vrf_proof_total() -> u64 {
    LEGACY_VRF_PROOF_TOTAL.load(std::sync::atomic::Ordering::Relaxed)
}

// ─── Constants ───────────────────────────────────────────────────────────

/// Algorithm identifier for legacy EC-VRF (Ed25519).
pub const ALG_ECVRF_ED25519: u8 = 0x10;

/// Algorithm identifier for Dilithium3 VRF.
pub const ALG_DILITHIUM_VRF: u8 = 0x11;

/// Current default algorithm.
pub const ALG_CURRENT: u8 = ALG_DILITHIUM_VRF;

/// Maximum VRF proof size (Dilithium3 signature: 3,309 bytes).
/// Legacy EC-VRF proofs are 80 bytes (VRF_PROOF_SIZE_LEGACY).
pub const VRF_PROOF_SIZE_MAX: usize = 4096;

/// Legacy proof size for backward compatibility references.
pub const VRF_PROOF_SIZE: usize = 80;

// ─── Types ──────────────────────────────────────────────────────────────

/// VRF secret key — wraps a Dilithium3 secret key.
///
/// Zeroized on drop to prevent key material from persisting in memory.
/// The 32-byte seed is expanded to a full Dilithium3 keypair internally.
pub struct VrfSecretKey {
    seed: [u8; 32],
    dilithium_sk: Vec<u8>,
    dilithium_pk: Vec<u8>,
}

impl Drop for VrfSecretKey {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.dilithium_sk.zeroize();
    }
}

/// VRF public key — wraps a Dilithium3 public key hash (32 bytes for storage/display)
/// plus the full Dilithium3 public key (1,952 bytes for verification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfPublicKey {
    /// SHA3-256 hash of the full Dilithium3 public key (for compact storage).
    hash: [u8; 32],
    /// Full Dilithium3 public key bytes (1,952 bytes).
    full_pk: Vec<u8>,
}

/// VRF proof — a Dilithium3 signature over SHA3-256(alpha).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfProof {
    /// Algorithm tag (0x10 = EC-VRF legacy, 0x11 = Dilithium VRF).
    pub algorithm: u8,
    /// Dilithium3 signature (3,309 bytes).
    pub signature: Vec<u8>,
}

/// VRF output (32 bytes — SHA3-256 of the signature).
///
/// Used as unpredictable seed for jury selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfOutput(pub [u8; 32]);

// ─── Key management ─────────────────────────────────────────────────────

impl VrfSecretKey {
    /// Generate a new VRF secret key from OS randomness.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| ElaraError::Crypto(format!("VRF key generation failed: {e}")))?;
        Self::from_seed(seed)
    }

    /// Create from a 32-byte seed (e.g., loaded from encrypted storage).
    /// The seed is fed directly into FIPS 204 `ML-DSA.KeyGen_internal(ξ)` which
    /// expands it via SHAKE-256 to produce a deterministic keypair. Same seed
    /// → same (pk, sk) byte-for-byte across all calls and platforms.
    fn from_seed(seed: [u8; 32]) -> Result<Self> {
        let (pk, sk) = crate::crypto::pqc::dilithium3_keypair_from_seed(&seed)?;
        Ok(Self {
            seed,
            dilithium_sk: sk,
            dilithium_pk: pk,
        })
    }

    /// Create from raw 32-byte seed.
    ///
    /// AUDIT-8: seeded Dilithium3 keygen is now deterministic (fixed in
    /// `pqc::dilithium3_keypair_from_seed`). For performance, callers that
    /// store long-lived VRF keys still prefer `from_full_bytes()` to skip
    /// the keygen cost on restart — but correctness no longer depends on it.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        Self::from_seed(bytes)
    }

    /// Create from the full serialized keypair (seed + pk + sk).
    /// This is the preferred way to load a VRF key after initial generation.
    pub fn from_full_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 34 {
            return Err(ElaraError::Crypto("VRF key data too short".into()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&data[..32]);
        let pk_len = u16::from_be_bytes([data[32], data[33]]) as usize;
        if data.len() < 34 + pk_len + 2 {
            return Err(ElaraError::Crypto("VRF key data truncated (pk)".into()));
        }
        let dilithium_pk = data[34..34 + pk_len].to_vec();
        let sk_offset = 34 + pk_len;
        let sk_len = u16::from_be_bytes([data[sk_offset], data[sk_offset + 1]]) as usize;
        if data.len() < sk_offset + 2 + sk_len {
            return Err(ElaraError::Crypto("VRF key data truncated (sk)".into()));
        }
        let dilithium_sk = data[sk_offset + 2..sk_offset + 2 + sk_len].to_vec();
        Ok(Self { seed, dilithium_sk, dilithium_pk })
    }

    /// Serialize the full keypair for persistent storage.
    pub fn to_full_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 2 + self.dilithium_pk.len() + 2 + self.dilithium_sk.len());
        buf.extend_from_slice(&self.seed);
        buf.extend_from_slice(&(self.dilithium_pk.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.dilithium_pk);
        buf.extend_from_slice(&(self.dilithium_sk.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.dilithium_sk);
        buf
    }

    /// Get raw seed bytes (legacy compat — 32 bytes).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> VrfPublicKey {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.dilithium_pk);
        let hash: [u8; 32] = hasher.finalize().into();
        VrfPublicKey {
            hash,
            full_pk: self.dilithium_pk.clone(),
        }
    }
}

impl VrfPublicKey {
    /// Create from the compact 32-byte hash (for deserialization from storage).
    /// NOTE: This creates a key that can display/compare but NOT verify proofs.
    /// For verification, use `from_full_bytes()`.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            hash: bytes,
            full_pk: Vec::new(), // No full key — display-only
        }
    }

    /// Create from the full Dilithium3 public key bytes.
    pub fn from_full_bytes(pk_bytes: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(pk_bytes);
        let hash: [u8; 32] = hasher.finalize().into();
        Self {
            hash,
            full_pk: pk_bytes.to_vec(),
        }
    }

    /// Get the 32-byte hash (compact representation).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Get the full Dilithium3 public key bytes (for verification).
    pub fn full_pk(&self) -> &[u8] {
        &self.full_pk
    }

    /// Hex-encode the compact hash.
    pub fn to_hex(&self) -> String {
        hex::encode(self.hash)
    }

    /// Decode from hex string (compact hash).
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| ElaraError::Crypto(format!("bad VRF public key hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(ElaraError::Crypto(format!(
                "VRF public key must be 32 bytes, got {}", bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(arr))
    }
}

// ─── Proof serialization ────────────────────────────────────────────────

impl VrfProof {
    /// Serialize to wire format: [algorithm:1][sig_len:2][signature:N].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.signature.len());
        out.push(self.algorithm);
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Deserialize from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 3 {
            return Err(ElaraError::Crypto("VRF proof too short".into()));
        }
        let algorithm = bytes[0];
        let sig_len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        if bytes.len() < 3 + sig_len {
            return Err(ElaraError::Crypto(format!(
                "VRF proof truncated: expected {} bytes, got {}", 3 + sig_len, bytes.len()
            )));
        }
        Ok(Self {
            algorithm,
            signature: bytes[3..3 + sig_len].to_vec(),
        })
    }

    /// Hex-encode the proof.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| ElaraError::Crypto(format!("bad VRF proof hex: {e}")))?;
        Self::from_bytes(&bytes)
    }
}

impl VrfOutput {
    /// Get the 32-byte output (for use as randomness seed).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex-encode the output.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Decode from hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| ElaraError::Crypto(format!("bad VRF output hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(ElaraError::Crypto(format!(
                "VRF output must be 32 bytes, got {}", bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

// ─── Core VRF operations ────────────────────────────────────────────────

/// Dilithium3 VRF prove: generate a VRF output and proof for input `alpha`.
///
/// The output is deterministic: SHA3-256(dilithium3_pk || alpha).
/// The proof is a Dilithium3 signature over the output, proving
/// knowledge of the secret key that corresponds to the public key.
///
/// Unlike traditional VRFs where the output is derived from the signature,
/// ML-DSA-65 uses randomized signing (FIPS 204), so the signature itself
/// is not deterministic. Instead, the output is derived from the public key
/// and input (deterministic), and the signature proves authorization.
pub fn vrf_prove(sk: &VrfSecretKey, alpha: &[u8]) -> Result<(VrfOutput, VrfProof)> {
    // Step 1: Output = SHA3-256(dilithium3_pk || alpha) — deterministic
    let output = VrfOutput(vrf_output_hash(&sk.dilithium_pk, alpha));

    // Step 2: Sign the output to prove we hold the secret key
    let sig = crate::crypto::pqc::dilithium3_sign_with_pk(
        output.as_bytes(), &sk.dilithium_sk, &sk.dilithium_pk,
    )?;

    // Step 3: Proof = (algorithm tag, signature)
    let proof = VrfProof {
        algorithm: ALG_DILITHIUM_VRF,
        signature: sig,
    };

    Ok((output, proof))
}

/// Dilithium3 VRF verify: verify a VRF proof and return the output if valid.
///
/// Recomputes output = SHA3-256(pk || alpha), then verifies the Dilithium3
/// signature over that output. Returns the output if verification succeeds.
pub fn vrf_verify(pk: &VrfPublicKey, alpha: &[u8], proof: &VrfProof) -> Result<VrfOutput> {
    if proof.algorithm == ALG_ECVRF_ED25519 {
        // Legacy EC-VRF proof — delegate to legacy module.
        // After the 2026-03-31 genesis wipe, no legacy proofs should appear on
        // mainnet. Count and warn once so operators know migration is needed.
        LEGACY_VRF_PROOF_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        LEGACY_VRF_WARN_ONCE.call_once(|| {
            // `tracing` only ships under the `node` / `node-windows` feature
            // flags. Default / wasm builds (browser-node, mobile) get a
            // best-effort eprintln so the migration path is still observable
            // without forcing tracing into the wasm pipeline.
            #[cfg(feature = "node-core")]
            tracing::warn!(
                "LEGACY EC-VRF PROOF DETECTED (alg=0x10, Ed25519). \
                 These proofs are deprecated and will be rejected in a future release. \
                 Monitor /status legacy_vrf_proof_count — should be 0 on mainnet. \
                 Ensure all nodes and clients have migrated to Dilithium3 VRF (alg=0x11)."
            );
            #[cfg(not(feature = "node-core"))]
            eprintln!(
                "[elara-runtime] WARN: legacy EC-VRF proof detected — deprecated"
            );
        });
        return vrf_verify_legacy(pk, alpha, proof);
    }

    if proof.algorithm != ALG_DILITHIUM_VRF {
        return Err(ElaraError::Crypto(format!(
            "unknown VRF algorithm: 0x{:02x}", proof.algorithm
        )));
    }

    if pk.full_pk.is_empty() {
        return Err(ElaraError::Crypto(
            "VRF verification requires full Dilithium3 public key".into()
        ));
    }

    // Recompute the expected output deterministically
    let expected_output = vrf_output_hash(&pk.full_pk, alpha);

    // Verify the signature over the output using the Dilithium3 public key
    if !crate::crypto::pqc::dilithium3_verify(&expected_output, &proof.signature, &pk.full_pk)? {
        return Err(ElaraError::InvalidSignature);
    }

    Ok(VrfOutput(expected_output))
}

/// Reject a legacy EC-VRF proof (algorithm tag 0x10).
///
/// The EC-VRF verifier (the `vrf_legacy` module) has been removed. After the
/// 2026-03-31 full wipe + fresh genesis no legacy proofs exist on-chain, so
/// any 0x10 proof is a replay or crafted peer message: it is rejected with a
/// clear error rather than silently accepted. New proofs use the Dilithium3
/// VRF (algorithm tag 0x11).
fn vrf_verify_legacy(_pk: &VrfPublicKey, _alpha: &[u8], _proof: &VrfProof) -> Result<VrfOutput> {
    Err(ElaraError::Crypto(
        "legacy EC-VRF verification unavailable: the EC-VRF verifier was \
         removed — use the Dilithium3 VRF for new proofs".into()
    ))
}

/// Compute VRF output hash: SHA3-256("elara-vrf-v1" || pk || alpha).
/// This is deterministic for a given (pk, alpha) pair.
fn vrf_output_hash(pk: &[u8], alpha: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"elara-vrf-v1");
    hasher.update(pk);
    hasher.update(alpha);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrf_keypair_generation() {
        let sk = VrfSecretKey::generate().unwrap();
        let pk = sk.public_key();
        assert!(!pk.full_pk().is_empty());
        assert_ne!(pk.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_vrf_prove_verify_roundtrip() {
        let sk = VrfSecretKey::generate().unwrap();
        let pk = sk.public_key();
        let alpha = b"epoch-42-zone-0";

        let (output1, proof) = vrf_prove(&sk, alpha).unwrap();
        let output2 = vrf_verify(&pk, alpha, &proof).unwrap();

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_vrf_deterministic() {
        let sk = VrfSecretKey::generate().unwrap();
        let alpha = b"same-input";

        let (out1, _) = vrf_prove(&sk, alpha).unwrap();
        let (out2, _) = vrf_prove(&sk, alpha).unwrap();

        assert_eq!(out1, out2, "same (sk, alpha) must produce same output");
    }

    #[test]
    fn test_vrf_different_inputs_different_outputs() {
        let sk = VrfSecretKey::generate().unwrap();

        let (out1, _) = vrf_prove(&sk, b"input-a").unwrap();
        let (out2, _) = vrf_prove(&sk, b"input-b").unwrap();

        assert_ne!(out1, out2, "different inputs must produce different outputs");
    }

    #[test]
    fn test_vrf_wrong_key_fails_verification() {
        let sk1 = VrfSecretKey::generate().unwrap();
        let sk2 = VrfSecretKey::generate().unwrap();
        let pk2 = sk2.public_key();
        let alpha = b"test";

        let (_, proof) = vrf_prove(&sk1, alpha).unwrap();
        assert!(vrf_verify(&pk2, alpha, &proof).is_err());
    }

    #[test]
    fn test_vrf_proof_serialization_roundtrip() {
        let sk = VrfSecretKey::generate().unwrap();
        let (_, proof) = vrf_prove(&sk, b"test").unwrap();

        let bytes = proof.to_bytes();
        let parsed = VrfProof::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.algorithm, ALG_DILITHIUM_VRF);
        assert_eq!(parsed.signature, proof.signature);
    }

    #[test]
    fn test_vrf_proof_hex_roundtrip() {
        let sk = VrfSecretKey::generate().unwrap();
        let (_, proof) = vrf_prove(&sk, b"test").unwrap();

        let hex_str = proof.to_hex();
        let parsed = VrfProof::from_hex(&hex_str).unwrap();
        assert_eq!(parsed, proof);
    }

    #[test]
    fn test_vrf_output_hex_roundtrip() {
        let sk = VrfSecretKey::generate().unwrap();
        let (output, _) = vrf_prove(&sk, b"test").unwrap();

        let hex_str = output.to_hex();
        let parsed = VrfOutput::from_hex(&hex_str).unwrap();
        assert_eq!(parsed, output);
    }

    #[test]
    fn test_vrf_public_key_hex_roundtrip() {
        let sk = VrfSecretKey::generate().unwrap();
        let pk = sk.public_key();

        let hex_str = pk.to_hex();
        let parsed = VrfPublicKey::from_hex(&hex_str).unwrap();
        assert_eq!(parsed.as_bytes(), pk.as_bytes());
    }

    #[test]
    fn test_vrf_full_bytes_roundtrip() {
        // Save and reload full keypair — must produce identical key
        let sk1 = VrfSecretKey::generate().unwrap();
        let pk1 = sk1.public_key();
        let full_bytes = sk1.to_full_bytes();

        let sk2 = VrfSecretKey::from_full_bytes(&full_bytes).unwrap();
        let pk2 = sk2.public_key();
        assert_eq!(pk1, pk2, "full-bytes roundtrip must preserve keypair");

        // Prove with both and verify output matches
        let (out1, _) = vrf_prove(&sk1, b"test").unwrap();
        let (out2, _) = vrf_prove(&sk2, b"test").unwrap();
        assert_eq!(out1, out2, "same keypair must produce same output");
    }

    #[test]
    fn test_vrf_unknown_algorithm_rejected() {
        let proof = VrfProof {
            algorithm: 0xFF,
            signature: vec![0; 100],
        };
        let pk = VrfPublicKey::from_bytes([0; 32]);
        assert!(vrf_verify(&pk, b"test", &proof).is_err());
    }

    #[test]
    fn test_legacy_ecvrf_always_rejected() {
        // The EC-VRF verifier was removed: any proof tagged 0x10 must be
        // rejected with a clear explanation — never silently accepted.
        let wrapped_proof = VrfProof {
            algorithm: ALG_ECVRF_ED25519,
            signature: vec![0u8; 80],
        };
        let wrapped_pk = VrfPublicKey::from_bytes([0u8; 32]);

        let err = vrf_verify(&wrapped_pk, b"anything", &wrapped_proof).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("legacy") && msg.contains("EC-VRF"),
            "error should explain legacy EC-VRF removal: got {msg}"
        );
    }

    // ─── fixture-free, pure helpers ──────────────────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_vrf_constants_strict_pin_and_alg_current_alias_invariant() {
        // 5 wire-format constants. All five are load-bearing for protocol
        // version compatibility: changing any breaks proof routing.
        assert_eq!(ALG_ECVRF_ED25519, 0x10);
        assert_eq!(ALG_DILITHIUM_VRF, 0x11);
        assert_eq!(VRF_PROOF_SIZE_MAX, 4096);
        assert_eq!(VRF_PROOF_SIZE, 80);

        // ALG_CURRENT is the active-default alias. The protocol routes new
        // proofs through this — when we eventually rotate to a successor
        // algorithm, ONLY this constant should change. If a future PR sets
        // ALG_CURRENT to anything other than ALG_DILITHIUM_VRF without
        // updating tests, the algorithm-tag emission test below catches it.
        assert_eq!(ALG_CURRENT, ALG_DILITHIUM_VRF);
        assert_eq!(ALG_CURRENT, 0x11);

        // Cross-relations:
        // (a) The two algorithm tags must be distinct so vrf_verify's
        //     dispatch routes correctly.
        assert_ne!(ALG_ECVRF_ED25519, ALG_DILITHIUM_VRF);
        // (b) MAX must comfortably exceed the legacy 80-byte size AND fit
        //     a real Dilithium3 signature (~3309 bytes).
        assert!(VRF_PROOF_SIZE_MAX > VRF_PROOF_SIZE);
        assert!(VRF_PROOF_SIZE_MAX > 3309);
        assert_eq!(VRF_PROOF_SIZE_MAX, 1 << 12);
        // (c) The size constants fit a u16 wire prefix (sig_len in VrfProof).
        assert!(VRF_PROOF_SIZE_MAX < u16::MAX as usize);
        assert!(VRF_PROOF_SIZE < u16::MAX as usize);
        // (d) Algorithm tags fit in a single u8 — they ARE u8 by type, but
        //     this also guards against accidental widening to u16.
        let _: u8 = ALG_ECVRF_ED25519;
        let _: u8 = ALG_DILITHIUM_VRF;
        let _: u8 = ALG_CURRENT;
    }

    #[test]
    fn batch_b_vrf_proof_wire_layout_byte_exact_and_truncation_overclaim_sweep() {
        // Wire layout: [algorithm:1][sig_len:2 BE u16][signature:N].
        // Empty signature produces exactly 3 bytes (the header).
        let empty = VrfProof {
            algorithm: ALG_DILITHIUM_VRF,
            signature: Vec::new(),
        };
        let bytes = empty.to_bytes();
        assert_eq!(bytes.len(), 3, "empty sig should serialize to exactly 3 bytes");
        assert_eq!(bytes[0], ALG_DILITHIUM_VRF, "byte 0 = algorithm tag");
        assert_eq!(&bytes[1..3], &[0u8, 0u8][..], "bytes 1..3 = BE u16 sig_len = 0");

        // 100-byte signature → exactly 103 bytes.
        let sig100 = VrfProof {
            algorithm: 0x42,
            signature: vec![0xABu8; 100],
        };
        let b100 = sig100.to_bytes();
        assert_eq!(b100.len(), 103);
        assert_eq!(b100[0], 0x42);
        // u16 BE of 100 = [0x00, 0x64]
        assert_eq!(b100[1], 0x00);
        assert_eq!(b100[2], 0x64);
        assert_eq!(&b100[3..103], &[0xABu8; 100][..]);

        // Round-trip preserves all three fields, including the algorithm
        // tag (no validation at serialize/deserialize layer — that's
        // vrf_verify's job).
        for alg in [0x00u8, 0x10, 0x11, 0x42, 0xFE, 0xFF] {
            let p = VrfProof {
                algorithm: alg,
                signature: vec![alg ^ 0x5A; 25],
            };
            let b = p.to_bytes();
            let parsed = VrfProof::from_bytes(&b).unwrap();
            assert_eq!(parsed.algorithm, alg, "algorithm passthrough for 0x{alg:02x}");
            assert_eq!(parsed.signature, p.signature);
        }

        // Truncation gates: any input < 3 bytes → Err.
        for n in [0usize, 1, 2] {
            let short: Vec<u8> = (0..n).map(|i| i as u8).collect();
            assert!(
                VrfProof::from_bytes(&short).is_err(),
                "len={n} should be rejected as too short",
            );
        }

        // Sig_len overclaim: header says 1000 bytes but body has only 10.
        let mut overclaim = vec![ALG_DILITHIUM_VRF];
        overclaim.extend_from_slice(&1000u16.to_be_bytes());
        overclaim.extend_from_slice(&[0u8; 10]);
        assert!(
            VrfProof::from_bytes(&overclaim).is_err(),
            "overclaimed sig_len must be rejected",
        );

        // Sig_len == actual remaining bytes → accepted, even with
        // unfamiliar algorithm tag (parser is permissive; verifier rejects).
        let mut exact = vec![0xCCu8];
        exact.extend_from_slice(&5u16.to_be_bytes());
        exact.extend_from_slice(&[0x11u8; 5]);
        let parsed = VrfProof::from_bytes(&exact).unwrap();
        assert_eq!(parsed.algorithm, 0xCC);
        assert_eq!(parsed.signature, vec![0x11u8; 5]);

        // Hex round-trip for arbitrary algorithm tag.
        for alg in [0x00u8, 0x11, 0xFE] {
            let p = VrfProof { algorithm: alg, signature: vec![0x77u8; 32] };
            let s = p.to_hex();
            assert_eq!(s.len(), 2 * (3 + 32), "hex chars = 2 * byte count");
            assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
            let parsed = VrfProof::from_hex(&s).unwrap();
            assert_eq!(parsed.algorithm, alg);
            assert_eq!(parsed.signature, p.signature);
        }

        // Hex with bad input → Err.
        assert!(VrfProof::from_hex("not-hex").is_err());
        assert!(VrfProof::from_hex("ab").is_err()); // valid hex but too short for header
    }

    #[test]
    fn batch_b_vrf_public_key_display_only_vs_verification_asymmetry_and_hex_error_sweep() {
        // from_bytes: display-only constructor. hash field populated,
        // full_pk field EMPTY — cannot be used to verify a proof.
        let bytes = [0x33u8; 32];
        let pk_compact = VrfPublicKey::from_bytes(bytes);
        assert_eq!(pk_compact.as_bytes(), &bytes);
        assert!(pk_compact.full_pk().is_empty(), "from_bytes must produce empty full_pk");

        // from_full_bytes: verification-capable constructor. hash is
        // SHA3-256 of the input full_pk; full_pk field is populated.
        let full_pk_input = vec![0xAAu8; 1952]; // Dilithium3 pk length
        let pk_full = VrfPublicKey::from_full_bytes(&full_pk_input);
        let expected_hash: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(&full_pk_input);
            h.finalize().into()
        };
        assert_eq!(pk_full.as_bytes(), &expected_hash, "from_full_bytes hash = SHA3 of input");
        assert_eq!(pk_full.full_pk(), &full_pk_input[..]);
        assert_eq!(pk_full.full_pk().len(), 1952);

        // PartialEq compares BOTH hash and full_pk. Two keys with the same
        // hash but different full_pk states (one empty, one populated)
        // are NOT equal — this protects against treating a compact-loaded
        // key as interchangeable with a verification-capable key.
        let same_hash_compact = VrfPublicKey::from_bytes(expected_hash);
        assert_eq!(same_hash_compact.as_bytes(), pk_full.as_bytes());
        assert_ne!(
            same_hash_compact, pk_full,
            "compact and full keys with same hash must NOT compare equal (full_pk differs)",
        );

        // to_hex produces 64 lowercase ASCII hex chars (the compact hash).
        let s = pk_full.to_hex();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        // from_hex roundtrip preserves the compact hash (full_pk is dropped
        // — the hex format is documentary, not verification-grade).
        let roundtrip = VrfPublicKey::from_hex(&s).unwrap();
        assert_eq!(roundtrip.as_bytes(), pk_full.as_bytes());
        assert!(roundtrip.full_pk().is_empty(), "from_hex always loses full_pk");

        // from_hex error sweep: wrong byte count + non-hex.
        for hex_len in [0usize, 1, 16, 31, 33, 63, 65, 100, 128] {
            let s: String = (0..hex_len).map(|i| char::from(b'0' + (i as u8 % 10))).collect();
            assert!(
                VrfPublicKey::from_hex(&s).is_err(),
                "hex_len={hex_len} should be rejected (need exactly 64)",
            );
        }
        assert!(VrfPublicKey::from_hex("zz".repeat(32).as_str()).is_err(), "non-hex must reject");
        assert!(VrfPublicKey::from_hex("").is_err());
    }

    #[test]
    fn batch_b_vrf_output_newtype_shape_hex_format_and_from_hex_error_sweep() {
        // VrfOutput is a newtype wrapping [u8; 32]. Direct field access via
        // .0 is pub — callers can pass the raw 32 bytes to RNG seeders
        // without an accessor call.
        let raw = [0x7Bu8; 32];
        let out = VrfOutput(raw);
        assert_eq!(out.0, raw); // direct pub field access
        assert_eq!(out.as_bytes(), &raw); // accessor matches direct

        // to_hex is 64 lowercase ASCII hex chars.
        let s = out.to_hex();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(s, hex::encode(raw));

        // Round-trip preserves the bytes.
        let parsed = VrfOutput::from_hex(&s).unwrap();
        assert_eq!(parsed, out);
        assert_eq!(parsed.0, raw);

        // PartialEq + Clone + Debug.
        let cloned = out.clone();
        assert_eq!(cloned, out);
        let other = VrfOutput([0x7Cu8; 32]);
        assert_ne!(other, out);
        let dbg = format!("{:?}", out);
        assert!(!dbg.is_empty());

        // from_hex error sweep — anything not exactly 32 bytes (64 hex chars)
        // must error.
        for hex_len in [0usize, 1, 31, 33, 62, 63, 65, 66, 128] {
            let s: String = (0..hex_len).map(|i| char::from(b'a' + (i as u8 % 6))).collect();
            assert!(
                VrfOutput::from_hex(&s).is_err(),
                "hex_len={hex_len} should be rejected (need exactly 64)",
            );
        }
        assert!(VrfOutput::from_hex("not-actual-hex").is_err());
    }

    #[test]
    fn batch_b_vrf_prove_emits_alg_current_pk_binding_and_signature_nondet_with_det_output() {
        // legacy_vrf_proof_total returns u64 and is monotonic non-decreasing.
        // Calling twice without any vrf_verify in between must return the
        // same value.
        let count_a = legacy_vrf_proof_total();
        let count_b = legacy_vrf_proof_total();
        assert!(count_b >= count_a, "counter must be monotonic non-decreasing");

        // vrf_prove emits ALG_CURRENT in the algorithm tag. This is the
        // load-bearing protocol-version contract — if a future PR rotates
        // ALG_CURRENT but forgets to update vrf_prove, the test below
        // catches it. Combined with the ALG_CURRENT==ALG_DILITHIUM_VRF
        // pin above, this asserts proofs are dilithium-tagged today.
        let sk = VrfSecretKey::generate().unwrap();
        let (_, proof_a) = vrf_prove(&sk, b"alpha-1").unwrap();
        assert_eq!(proof_a.algorithm, ALG_CURRENT);
        assert_eq!(proof_a.algorithm, ALG_DILITHIUM_VRF);
        assert_eq!(proof_a.algorithm, 0x11);

        // Empty alpha is accepted (boundary).
        let (out_empty, _) = vrf_prove(&sk, b"").unwrap();
        assert_ne!(out_empty.as_bytes(), &[0u8; 32], "empty alpha output should be non-zero");

        // pk-binding witness: TWO DIFFERENT secret keys over the SAME
        // alpha produce DIFFERENT outputs. This is the public-key binding
        // property of the VRF — output = SHA3("elara-vrf-v1" || pk || alpha)
        // makes the output a function of pk too, not just alpha.
        let sk2 = VrfSecretKey::generate().unwrap();
        let (out_sk1, _) = vrf_prove(&sk, b"common-alpha").unwrap();
        let (out_sk2, _) = vrf_prove(&sk2, b"common-alpha").unwrap();
        assert_ne!(
            out_sk1, out_sk2,
            "different sk over same alpha must produce different output (pk-binding)",
        );

        // ML-DSA-65 uses RANDOMIZED signing (FIPS 204) — same (sk, alpha)
        // can yield DIFFERENT signature bytes across calls. But the OUTPUT
        // is deterministic (SHA3 of pk||alpha, not of signature). Verify
        // both invariants in one shot.
        let sk3 = VrfSecretKey::generate().unwrap();
        let (out_x, proof_x) = vrf_prove(&sk3, b"randomized-check").unwrap();
        let (out_y, proof_y) = vrf_prove(&sk3, b"randomized-check").unwrap();
        assert_eq!(out_x, out_y, "same (sk, alpha) must produce SAME deterministic output");
        // Note: we do not assert proof_x.signature != proof_y.signature
        // because ML-DSA-65 randomized signing CAN coincidentally repeat
        // (cryptographically negligible but not impossible). The output
        // determinism is the load-bearing invariant.
        let _ = (proof_x.algorithm, proof_y.algorithm);
        assert_eq!(proof_x.algorithm, ALG_CURRENT);
        assert_eq!(proof_y.algorithm, ALG_CURRENT);
    }

    #[test]
    fn from_bytes_returns_ok_and_produces_usable_key() {
        let seed = [0x42u8; 32];
        let sk = VrfSecretKey::from_bytes(seed).expect("valid 32-byte seed must succeed");
        let (out, proof) = vrf_prove(&sk, b"test-alpha").unwrap();
        let pk = sk.public_key();
        let verified = vrf_verify(&pk, b"test-alpha", &proof).unwrap();
        assert_eq!(out, verified);
    }
}
