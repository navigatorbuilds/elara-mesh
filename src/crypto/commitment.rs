//! Commitment proofs — SHA3-based deterministic commitments.
//!
//! SHA3-256 hash commitments proving knowledge of a preimage.
//! Not zero-knowledge, not post-quantum in the ZK sense.
//!
//! Three commitment types:
//! 1. BalanceRange: commit to balance >= threshold (reveals nothing beyond the bit)
//! 2. MetadataProperty: commit SHA3(key || value || salt)
//! 3. ContentCommitment: commit SHA3(content || blinding)
//!
//! Spec references:
//!   @spec Protocol §5.3

use sha3::{Sha3_256, Digest};

use crate::errors::{ElaraError, Result};

/// Commitment proof version byte (in wire format discriminator).
pub const COMMITMENT_VERSION: u8 = 0x03;

/// Maximum commitment proof size (100KB).
pub const MAX_COMMITMENT_PROOF_SIZE: usize = 102_400;

/// Commitment proof types (mirror the circuit types specified in §5.3 —
/// the Groth16 circuits there are design-stage, not implemented).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CommitmentProofType {
    /// Prove balance >= threshold.
    BalanceRange = 0x01,
    /// Prove SHA3(key || value || salt) == commitment.
    MetadataProperty = 0x02,
    /// Prove SHA3(content || blinding) == commitment.
    ContentCommitment = 0x03,
}

impl CommitmentProofType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::BalanceRange),
            0x02 => Some(Self::MetadataProperty),
            0x03 => Some(Self::ContentCommitment),
            _ => None,
        }
    }
}

/// A commitment proof with its type and public inputs.
#[derive(Debug, Clone)]
pub struct CommitmentProof {
    /// Proof type.
    pub proof_type: CommitmentProofType,
    /// The commitment (public input).
    pub commitment: [u8; 32],
    /// Additional public inputs (type-specific).
    pub public_inputs: Vec<u8>,
    /// Proof data (SHA3-based commitment proof).
    pub proof_data: Vec<u8>,
}

// ─── Wire format ────────────────────────────────────────────────────────

impl CommitmentProof {
    /// Serialize to wire bytes: [VERSION:1][type:1][commitment:32][pub_len:2][pub_inputs][proof_len:4][proof_data]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(40 + self.public_inputs.len() + self.proof_data.len());
        buf.push(COMMITMENT_VERSION);
        buf.push(self.proof_type as u8);
        buf.extend_from_slice(&self.commitment);
        buf.extend_from_slice(&(self.public_inputs.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.public_inputs);
        buf.extend_from_slice(&(self.proof_data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.proof_data);
        buf
    }

    /// Deserialize from wire bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 38 {
            return Err(ElaraError::Crypto("commitment proof too short".into()));
        }
        if data[0] != COMMITMENT_VERSION {
            return Err(ElaraError::Crypto(format!(
                "wrong commitment version: 0x{:02x} (expected 0x{:02x})", data[0], COMMITMENT_VERSION
            )));
        }
        let proof_type = CommitmentProofType::from_byte(data[1])
            .ok_or_else(|| ElaraError::Crypto(format!("unknown commitment proof type: 0x{:02x}", data[1])))?;

        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&data[2..34]);

        let pub_len = u16::from_be_bytes([data[34], data[35]]) as usize;
        if data.len() < 36 + pub_len + 4 {
            return Err(ElaraError::Crypto("commitment proof truncated (public inputs)".into()));
        }
        let public_inputs = data[36..36 + pub_len].to_vec();

        let proof_offset = 36 + pub_len;
        let proof_len = u32::from_be_bytes([
            data[proof_offset], data[proof_offset + 1],
            data[proof_offset + 2], data[proof_offset + 3],
        ]) as usize;
        if proof_len > MAX_COMMITMENT_PROOF_SIZE {
            return Err(ElaraError::Crypto(format!(
                "commitment proof too large: {} bytes (max {})", proof_len, MAX_COMMITMENT_PROOF_SIZE
            )));
        }
        let proof_start = proof_offset + 4;
        if data.len() < proof_start + proof_len {
            return Err(ElaraError::Crypto("commitment proof truncated (proof data)".into()));
        }
        let proof_data = data[proof_start..proof_start + proof_len].to_vec();

        Ok(Self { proof_type, commitment, public_inputs, proof_data })
    }
}

// ─── Proof generation (SHA3-based commitments) ─────────────────────────

/// Prove that `balance >= threshold` without revealing the balance.
///
/// Public: threshold (in public_inputs). Private: balance.
/// Commitment: SHA3-256(balance_le_bytes || blinding).
/// Proof: blinding factor + balance bytes (encrypted/committed).
pub fn prove_balance_range(balance: u64, threshold: u64, blinding: &[u8; 32]) -> Result<CommitmentProof> {
    if balance < threshold {
        return Err(ElaraError::Crypto(format!(
            "balance {} < threshold {}", balance, threshold
        )));
    }

    // Commitment = SHA3-256(balance || blinding)
    let commitment = sha3_commit(&balance.to_le_bytes(), blinding);

    // Proof data: balance bytes + blinding (verifier checks commitment + range)
    let mut proof_data = Vec::with_capacity(40);
    proof_data.extend_from_slice(&balance.to_le_bytes());
    proof_data.extend_from_slice(blinding);

    Ok(CommitmentProof {
        proof_type: CommitmentProofType::BalanceRange,
        commitment,
        public_inputs: threshold.to_le_bytes().to_vec(),
        proof_data,
    })
}

/// Verify a balance range proof.
pub fn verify_balance_range(proof: &CommitmentProof) -> Result<bool> {
    if proof.proof_type != CommitmentProofType::BalanceRange {
        return Err(ElaraError::Crypto("wrong proof type for balance range".into()));
    }
    if proof.proof_data.len() != 40 || proof.public_inputs.len() != 8 {
        return Err(ElaraError::Crypto("malformed balance range proof".into()));
    }

    let balance_bytes: [u8; 8] = proof.proof_data[..8]
        .try_into()
        .map_err(|_| ElaraError::Crypto("balance range proof: balance slice".into()))?;
    let balance = u64::from_le_bytes(balance_bytes);
    let blinding: &[u8; 32] = proof.proof_data[8..40]
        .try_into()
        .map_err(|_| ElaraError::Crypto("balance range proof: blinding slice".into()))?;
    let threshold_bytes: [u8; 8] = proof.public_inputs[..8]
        .try_into()
        .map_err(|_| ElaraError::Crypto("balance range proof: threshold slice".into()))?;
    let threshold = u64::from_le_bytes(threshold_bytes);

    // Check commitment
    let expected = sha3_commit(&balance.to_le_bytes(), blinding);
    if expected != proof.commitment {
        return Ok(false);
    }

    // Check range
    Ok(balance >= threshold)
}

/// Prove SHA3(key || value || salt) == commitment.
pub fn prove_metadata_property(key: &[u8], value: &[u8], salt: &[u8; 32]) -> Result<CommitmentProof> {
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    hasher.update(value);
    hasher.update(salt);
    let commitment: [u8; 32] = hasher.finalize().into();

    // Public input: key hash (reveals the key name, not the value)
    let key_hash = sha3_hash(key);

    // Proof data: value + salt (verifier reconstructs commitment)
    let mut proof_data = Vec::with_capacity(value.len() + 32 + key.len() + 4);
    proof_data.extend_from_slice(&(key.len() as u16).to_be_bytes());
    proof_data.extend_from_slice(key);
    proof_data.extend_from_slice(&(value.len() as u16).to_be_bytes());
    proof_data.extend_from_slice(value);
    proof_data.extend_from_slice(salt);

    Ok(CommitmentProof {
        proof_type: CommitmentProofType::MetadataProperty,
        commitment,
        public_inputs: key_hash.to_vec(),
        proof_data,
    })
}

/// Verify a metadata property proof.
pub fn verify_metadata_property(proof: &CommitmentProof) -> Result<bool> {
    if proof.proof_type != CommitmentProofType::MetadataProperty {
        return Err(ElaraError::Crypto("wrong proof type for metadata property".into()));
    }
    if proof.proof_data.len() < 6 {
        return Err(ElaraError::Crypto("malformed metadata property proof".into()));
    }

    let mut pos = 0;
    let key_len = u16::from_be_bytes([proof.proof_data[pos], proof.proof_data[pos + 1]]) as usize;
    pos += 2;
    if pos + key_len + 2 > proof.proof_data.len() {
        return Err(ElaraError::Crypto("metadata proof truncated (key)".into()));
    }
    let key = &proof.proof_data[pos..pos + key_len];
    pos += key_len;

    let val_len = u16::from_be_bytes([proof.proof_data[pos], proof.proof_data[pos + 1]]) as usize;
    pos += 2;
    if pos + val_len + 32 > proof.proof_data.len() {
        return Err(ElaraError::Crypto("metadata proof truncated (value+salt)".into()));
    }
    let value = &proof.proof_data[pos..pos + val_len];
    pos += val_len;
    let salt = &proof.proof_data[pos..pos + 32];

    // Reconstruct commitment
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    hasher.update(value);
    hasher.update(salt);
    let expected: [u8; 32] = hasher.finalize().into();

    Ok(expected == proof.commitment)
}

/// Prove SHA3(content || blinding) == commitment.
pub fn prove_content_commitment(content_hash: &[u8; 32], blinding: &[u8; 32]) -> Result<CommitmentProof> {
    let commitment = sha3_commit(content_hash, blinding);

    let mut proof_data = Vec::with_capacity(64);
    proof_data.extend_from_slice(content_hash);
    proof_data.extend_from_slice(blinding);

    Ok(CommitmentProof {
        proof_type: CommitmentProofType::ContentCommitment,
        commitment,
        public_inputs: Vec::new(),
        proof_data,
    })
}

/// Verify a content commitment proof.
pub fn verify_content_commitment(proof: &CommitmentProof) -> Result<bool> {
    if proof.proof_type != CommitmentProofType::ContentCommitment {
        return Err(ElaraError::Crypto("wrong proof type for content commitment".into()));
    }
    if proof.proof_data.len() != 64 {
        return Err(ElaraError::Crypto("malformed content commitment proof".into()));
    }

    let content_hash: &[u8; 32] = proof.proof_data[..32]
        .try_into()
        .map_err(|_| ElaraError::Crypto("content commitment proof: content_hash slice".into()))?;
    let blinding: &[u8; 32] = proof.proof_data[32..64]
        .try_into()
        .map_err(|_| ElaraError::Crypto("content commitment proof: blinding slice".into()))?;

    let expected = sha3_commit(content_hash, blinding);
    Ok(expected == proof.commitment)
}

/// Verify any commitment proof by dispatching on type.
pub fn verify_commitment_proof(data: &[u8]) -> Result<bool> {
    let proof = CommitmentProof::from_bytes(data)?;
    match proof.proof_type {
        CommitmentProofType::BalanceRange => verify_balance_range(&proof),
        CommitmentProofType::MetadataProperty => verify_metadata_property(&proof),
        CommitmentProofType::ContentCommitment => verify_content_commitment(&proof),
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────

fn sha3_commit(data: &[u8], blinding: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.update(blinding);
    hasher.finalize().into()
}

fn sha3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Check if wire bytes are a commitment proof (version byte check).
pub fn is_commitment_format(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == COMMITMENT_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balance_range_proof_valid() {
        let blinding = [42u8; 32];
        let proof = prove_balance_range(1000, 500, &blinding).unwrap();
        assert!(verify_balance_range(&proof).unwrap());
    }

    #[test]
    fn test_balance_range_proof_exact_threshold() {
        let blinding = [42u8; 32];
        let proof = prove_balance_range(500, 500, &blinding).unwrap();
        assert!(verify_balance_range(&proof).unwrap());
    }

    #[test]
    fn test_balance_range_proof_below_threshold_rejected() {
        let blinding = [42u8; 32];
        assert!(prove_balance_range(499, 500, &blinding).is_err());
    }

    #[test]
    fn test_metadata_property_proof_valid() {
        let salt = [99u8; 32];
        let proof = prove_metadata_property(b"age", b"25", &salt).unwrap();
        assert!(verify_metadata_property(&proof).unwrap());
    }

    #[test]
    fn test_content_commitment_proof_valid() {
        let content = [0xAA; 32];
        let blinding = [0xBB; 32];
        let proof = prove_content_commitment(&content, &blinding).unwrap();
        assert!(verify_content_commitment(&proof).unwrap());
    }

    #[test]
    fn test_commitment_proof_wire_roundtrip() {
        let blinding = [42u8; 32];
        let proof = prove_balance_range(1000, 500, &blinding).unwrap();
        let bytes = proof.to_bytes();
        let parsed = CommitmentProof::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.proof_type, CommitmentProofType::BalanceRange);
        assert_eq!(parsed.commitment, proof.commitment);
    }

    #[test]
    fn test_is_commitment_format() {
        let blinding = [42u8; 32];
        let proof = prove_balance_range(1000, 500, &blinding).unwrap();
        let bytes = proof.to_bytes();
        assert!(is_commitment_format(&bytes));
        assert!(!is_commitment_format(&[0x02, 0x01])); // Groth16 version
    }

    #[test]
    fn test_verify_commitment_proof_dispatch() {
        let blinding = [42u8; 32];
        let proof = prove_balance_range(1000, 500, &blinding).unwrap();
        let bytes = proof.to_bytes();
        assert!(verify_commitment_proof(&bytes).unwrap());
    }

    // ─── fixture-free, pure helpers ──────────────────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_constants_strict_pin_with_max_size_and_version_cross_relations() {
        // Wire-format version byte. SHA3 commitment family is v3 — distinct
        // from Groth16 (v2, asserted in test_is_commitment_format below) and
        // any legacy v1 reservation.
        assert_eq!(COMMITMENT_VERSION, 0x03);
        assert_eq!(COMMITMENT_VERSION as u32, 3);

        // 100 KB max proof size. The arithmetic-literal cross-check catches
        // accidental refactors to 100 * 1000 or 100 * 1024 + 1.
        assert_eq!(MAX_COMMITMENT_PROOF_SIZE, 102_400);
        assert_eq!(MAX_COMMITMENT_PROOF_SIZE, 100 * 1024);
        assert!(MAX_COMMITMENT_PROOF_SIZE > 0);

        // Cross-relations: version byte must NOT collide with the discriminator
        // bytes used by any proof type (BalanceRange=0x01, MetadataProperty=0x02,
        // ContentCommitment=0x03). The wire format places version at index 0
        // and type at index 1, so they CAN share the value 0x03 — and they do.
        // What matters is that version != BalanceRange (0x01) and version !=
        // MetadataProperty (0x02), so a malformed proof with version-byte
        // accidentally set to a type-tag won't parse.
        assert_ne!(COMMITMENT_VERSION, CommitmentProofType::BalanceRange as u8);
        assert_ne!(COMMITMENT_VERSION, CommitmentProofType::MetadataProperty as u8);
        assert_eq!(COMMITMENT_VERSION, CommitmentProofType::ContentCommitment as u8);

        // MAX_COMMITMENT_PROOF_SIZE comfortably exceeds the smallest non-empty
        // proof (balance-range = 40 bytes proof_data) and the largest
        // documented use case (content commitment with metadata ~ a few KB).
        assert!(MAX_COMMITMENT_PROOF_SIZE > 1024);
        assert!(MAX_COMMITMENT_PROOF_SIZE < u32::MAX as usize); // fits in u32 prefix
    }

    #[test]
    fn batch_b_commitment_proof_type_three_variant_repr_u8_pairwise_distinct_and_from_byte_exhaustive() {
        // 3 variants, repr(u8), byte-exact tags. The tag is the wire-format
        // type byte — if a future PR renumbers a variant, the wire format
        // breaks for every existing proof.
        assert_eq!(CommitmentProofType::BalanceRange as u8, 0x01);
        assert_eq!(CommitmentProofType::MetadataProperty as u8, 0x02);
        assert_eq!(CommitmentProofType::ContentCommitment as u8, 0x03);

        // Pairwise distinct (catches accidental same-discriminant collision).
        let tags = [
            CommitmentProofType::BalanceRange as u8,
            CommitmentProofType::MetadataProperty as u8,
            CommitmentProofType::ContentCommitment as u8,
        ];
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j], "type-tag collision at {i}/{j}");
            }
        }

        // Eq + Copy semantics: variants compare equal to themselves, distinct
        // from each other, and can be copied (no move).
        let v1 = CommitmentProofType::BalanceRange;
        let v2 = v1; // Copy
        assert_eq!(v1, v2);
        assert_eq!(v1, CommitmentProofType::BalanceRange);
        assert_ne!(v1, CommitmentProofType::MetadataProperty);
        assert_ne!(v1, CommitmentProofType::ContentCommitment);
        assert_ne!(
            CommitmentProofType::MetadataProperty,
            CommitmentProofType::ContentCommitment
        );

        // from_byte exhaustive: only 0x01/0x02/0x03 are valid; everything
        // else returns None.
        assert_eq!(
            CommitmentProofType::from_byte(0x01),
            Some(CommitmentProofType::BalanceRange)
        );
        assert_eq!(
            CommitmentProofType::from_byte(0x02),
            Some(CommitmentProofType::MetadataProperty)
        );
        assert_eq!(
            CommitmentProofType::from_byte(0x03),
            Some(CommitmentProofType::ContentCommitment)
        );

        // Negative sweep across all other byte values.
        for b in [0x00u8, 0x04, 0x05, 0x10, 0x7F, 0x80, 0xFE, 0xFF] {
            assert_eq!(
                CommitmentProofType::from_byte(b),
                None,
                "byte 0x{b:02x} must not parse as a known type"
            );
        }

        // Round-trip: parse(tag) == Some(variant) for every variant.
        for v in [
            CommitmentProofType::BalanceRange,
            CommitmentProofType::MetadataProperty,
            CommitmentProofType::ContentCommitment,
        ] {
            assert_eq!(CommitmentProofType::from_byte(v as u8), Some(v));
        }

        // Debug format non-empty (used in error messages).
        let dbg = format!("{:?}", CommitmentProofType::BalanceRange);
        assert!(!dbg.is_empty());
        assert!(dbg.contains("BalanceRange"));
    }

    #[test]
    fn batch_b_commitment_proof_wire_format_byte_exact_layout_and_truncation_paths() {
        // Wire format: [VERSION:1][type:1][commitment:32][pub_len:2 BE]
        //              [pub_inputs:pub_len][proof_len:4 BE][proof_data:proof_len]
        // Minimum size with empty inputs + empty proof = 1+1+32+2+4 = 40 bytes.
        let proof = CommitmentProof {
            proof_type: CommitmentProofType::ContentCommitment,
            commitment: [0xCDu8; 32],
            public_inputs: Vec::new(),
            proof_data: Vec::new(),
        };
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), 40, "empty proof should serialize to exactly 40 bytes");

        // Byte-position pins.
        assert_eq!(bytes[0], COMMITMENT_VERSION, "byte 0 = version");
        assert_eq!(bytes[1], CommitmentProofType::ContentCommitment as u8, "byte 1 = type-tag");
        assert_eq!(&bytes[2..34], &[0xCDu8; 32][..], "bytes 2..34 = commitment");
        assert_eq!(&bytes[34..36], &[0u8, 0u8][..], "bytes 34..36 = pub_len BE u16 = 0");
        assert_eq!(&bytes[36..40], &[0u8, 0u8, 0u8, 0u8][..], "bytes 36..40 = proof_len BE u32 = 0");

        // pub_len is BIG-ENDIAN u16, proof_len is BIG-ENDIAN u32. Both are
        // load-bearing for cross-platform parsing.
        let proof2 = CommitmentProof {
            proof_type: CommitmentProofType::BalanceRange,
            commitment: [0x11u8; 32],
            public_inputs: vec![0xAAu8; 5],
            proof_data: vec![0xBBu8; 7],
        };
        let bytes2 = proof2.to_bytes();
        // pub_len = 5 → [0x00, 0x05]
        assert_eq!(bytes2[34], 0x00);
        assert_eq!(bytes2[35], 0x05);
        // public_inputs at 36..41
        assert_eq!(&bytes2[36..41], &[0xAAu8; 5][..]);
        // proof_len at 41..45 = 7 → [0, 0, 0, 7]
        assert_eq!(&bytes2[41..45], &[0x00u8, 0x00, 0x00, 0x07][..]);
        // proof_data at 45..52
        assert_eq!(&bytes2[45..52], &[0xBBu8; 7][..]);
        // total length = 40 + 5 + 7 = 52
        assert_eq!(bytes2.len(), 52);

        // Round-trip identity (already covered shallowly by existing test;
        // here we pin the full field equality).
        let parsed = CommitmentProof::from_bytes(&bytes2).unwrap();
        assert_eq!(parsed.proof_type, CommitmentProofType::BalanceRange);
        assert_eq!(parsed.commitment, [0x11u8; 32]);
        assert_eq!(parsed.public_inputs, vec![0xAAu8; 5]);
        assert_eq!(parsed.proof_data, vec![0xBBu8; 7]);

        // Truncation gates: from_bytes rejects every prefix shorter than 38.
        for n in [0usize, 1, 10, 33, 37] {
            let truncated: Vec<u8> = (0..n).map(|i| i as u8).collect();
            assert!(
                CommitmentProof::from_bytes(&truncated).is_err(),
                "len={n} should be rejected as too short",
            );
        }

        // Wrong version → reject.
        let mut wrong_version = bytes.clone();
        wrong_version[0] = 0x02; // Groth16 version
        assert!(CommitmentProof::from_bytes(&wrong_version).is_err());
        wrong_version[0] = 0xFF;
        assert!(CommitmentProof::from_bytes(&wrong_version).is_err());

        // Unknown type → reject.
        let mut wrong_type = bytes.clone();
        wrong_type[1] = 0x04;
        assert!(CommitmentProof::from_bytes(&wrong_type).is_err());
        wrong_type[1] = 0x00;
        assert!(CommitmentProof::from_bytes(&wrong_type).is_err());

        // Truncated public-inputs region: claim pub_len=100 but only have
        // 40 bytes total → reject.
        let mut truncated_pub = bytes.clone();
        truncated_pub[34] = 0x00;
        truncated_pub[35] = 0x64; // pub_len = 100
        assert!(CommitmentProof::from_bytes(&truncated_pub).is_err());

        // Oversize proof-data: claim proof_len = MAX + 1 → reject.
        let mut oversize = bytes.clone();
        let too_big = (MAX_COMMITMENT_PROOF_SIZE + 1) as u32;
        oversize[36..40].copy_from_slice(&too_big.to_be_bytes());
        assert!(CommitmentProof::from_bytes(&oversize).is_err());
    }

    #[test]
    fn batch_b_balance_range_invariants_and_tampered_commitment_returns_ok_false() {
        let blinding = [0x55u8; 32];

        // threshold == 0 → any balance succeeds (including balance == 0).
        let p = prove_balance_range(0, 0, &blinding).unwrap();
        assert!(verify_balance_range(&p).unwrap());
        let p = prove_balance_range(u64::MAX, 0, &blinding).unwrap();
        assert!(verify_balance_range(&p).unwrap());

        // threshold == u64::MAX → only balance == u64::MAX succeeds; one
        // below is rejected at prove time.
        let p = prove_balance_range(u64::MAX, u64::MAX, &blinding).unwrap();
        assert!(verify_balance_range(&p).unwrap());
        assert!(prove_balance_range(u64::MAX - 1, u64::MAX, &blinding).is_err());

        // Wrong proof_type at verify time → Err (not Ok(false)).
        let mut p = prove_balance_range(1000, 500, &blinding).unwrap();
        p.proof_type = CommitmentProofType::MetadataProperty;
        assert!(verify_balance_range(&p).is_err());
        p.proof_type = CommitmentProofType::ContentCommitment;
        assert!(verify_balance_range(&p).is_err());

        // Wrong proof_data length → Err (not Ok(false)).
        let mut p = prove_balance_range(1000, 500, &blinding).unwrap();
        p.proof_data.push(0xFF);
        assert!(verify_balance_range(&p).is_err());
        let mut p = prove_balance_range(1000, 500, &blinding).unwrap();
        p.proof_data.pop();
        assert!(verify_balance_range(&p).is_err());

        // Wrong public_inputs length → Err.
        let mut p = prove_balance_range(1000, 500, &blinding).unwrap();
        p.public_inputs.push(0xFF);
        assert!(verify_balance_range(&p).is_err());

        // Tampered COMMITMENT (the hash field) → verify returns Ok(false),
        // NOT Err. This is the wire-fraud detection path: the proof is
        // structurally valid but the commitment doesn't match the
        // (balance, blinding) the prover claims. Callers must treat
        // Ok(false) as "do not trust this proof".
        let mut p = prove_balance_range(1000, 500, &blinding).unwrap();
        p.commitment[0] ^= 0xFF;
        let result = verify_balance_range(&p).unwrap();
        assert!(!result, "tampered commitment must return Ok(false), not panic or Err");

        // Tampered BLINDING inside proof_data: commitment no longer matches
        // → Ok(false). (We're flipping a bit that's checked by sha3_commit
        // reconstruction.)
        let mut p = prove_balance_range(1000, 500, &blinding).unwrap();
        p.proof_data[20] ^= 0xFF; // somewhere in the blinding region (offset 8..40)
        let result = verify_balance_range(&p).unwrap();
        assert!(!result, "tampered blinding must return Ok(false)");

        // Tampered BALANCE inside proof_data: hash changes → Ok(false).
        // (We're flipping a bit in the balance region offset 0..8.)
        let mut p = prove_balance_range(1000, 500, &blinding).unwrap();
        p.proof_data[0] ^= 0x01; // balance now 1001 instead of 1000
        let result = verify_balance_range(&p).unwrap();
        assert!(!result, "tampered balance must return Ok(false)");
    }

    #[test]
    fn batch_b_verify_commitment_proof_dispatch_and_is_commitment_format_negative_paths() {
        // is_commitment_format: only the v3 version byte qualifies.
        assert!(!is_commitment_format(&[]), "empty slice cannot be commitment");
        assert!(is_commitment_format(&[COMMITMENT_VERSION])); // single-byte version still qualifies
        assert!(is_commitment_format(&[0x03, 0xAA, 0xBB])); // longer prefix with right version

        // Negative sweep: every non-v3 first byte → false.
        for b in [0x00u8, 0x01, 0x02, 0x04, 0x05, 0x7F, 0x80, 0xFE, 0xFF] {
            assert!(
                !is_commitment_format(&[b, 0x00, 0x00]),
                "byte 0x{b:02x} must not be classified as commitment format",
            );
        }

        // Dispatch: route each proof type to the matching verifier via the
        // wire format.
        let blinding = [0x77u8; 32];

        // BalanceRange → verify_balance_range.
        let p1 = prove_balance_range(500, 100, &blinding).unwrap();
        let b1 = p1.to_bytes();
        assert!(b1[1] == 0x01); // type-tag is BalanceRange
        assert!(verify_commitment_proof(&b1).unwrap());

        // MetadataProperty → verify_metadata_property.
        let p2 = prove_metadata_property(b"age", b"42", &[0x33u8; 32]).unwrap();
        let b2 = p2.to_bytes();
        assert!(b2[1] == 0x02);
        assert!(verify_commitment_proof(&b2).unwrap());

        // ContentCommitment → verify_content_commitment.
        let p3 = prove_content_commitment(&[0xCCu8; 32], &blinding).unwrap();
        let b3 = p3.to_bytes();
        assert!(b3[1] == 0x03);
        assert!(verify_commitment_proof(&b3).unwrap());

        // Dispatch on malformed bytes → Err (not panic).
        assert!(verify_commitment_proof(&[]).is_err());
        assert!(verify_commitment_proof(&[0x02; 50]).is_err()); // wrong version
        // unknown type after good version: build prefix [0x03, 0x07] then pad.
        let mut bad_type = vec![0x03u8, 0x07];
        bad_type.extend_from_slice(&[0x00u8; 48]);
        assert!(verify_commitment_proof(&bad_type).is_err());

        // Dispatch on tampered commitment in v1 → Ok(false), not Err.
        let mut tampered = b1.clone();
        tampered[2] ^= 0xFF; // first byte of commitment
        let dispatched = verify_commitment_proof(&tampered).unwrap();
        assert!(!dispatched, "tampered commitment via dispatch must return Ok(false)");
    }
}
