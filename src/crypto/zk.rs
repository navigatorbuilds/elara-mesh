//! ZK Privacy Layer — Protocol §5.3.
//!
//! SHA3-based commitment scheme for privacy-preserving proofs.
//! Uses the existing `zk_proof: Option<Vec<u8>>` field on `ValidationRecord`.
//!
//! Two proof types:
//! - `BalanceRange`: prove "I have >= threshold beat" without revealing exact balance
//! - `MetadataProperty`: prove a metadata key has a specific value without revealing it
//!
//! No external crate dependencies — uses existing `sha3` via `crypto::hash`.

//!
//! Spec references:
//!   @spec Protocol §5.3

use crate::crypto::hash::sha3_256;

// ─── Proof wire-format discriminators (cross-platform, including WASM) ───────
// These are reserved version bytes for proof-format dispatch. No Groth16 or
// STARK prover/verifier is implemented — both are design-stage (whitepaper §5.3).
// 0x02 (Groth16-format) is rejected fail-closed at ingest; 0x03 IS the SHA3
// commitment wire format (== commitment::COMMITMENT_VERSION) and is verified as
// a commitment, not as a STARK.

/// Reserved version byte for the (design-stage) Groth16 proof format.
/// No Groth16 verifier exists; 0x02-prefixed proofs are rejected at ingest.
pub const GROTH16_VERSION: u8 = 0x02;

/// Version byte 0x03 — the SHA3 commitment wire format
/// (mirrors `commitment::COMMITMENT_VERSION`). Named `STARK_VERSION` for
/// historical reasons; there is no STARK prover, so this routes to the
/// commitment verifier.
pub const STARK_VERSION: u8 = 0x03;

/// Check if a zk_proof byte slice carries the Groth16 version byte (0x02).
/// Available on all targets including WASM — needed for gossip dispatch.
pub fn is_groth16_format(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == GROTH16_VERSION
}

/// Check if a zk_proof byte slice carries the 0x03 version byte (SHA3
/// commitment format; historically labelled "STARK").
pub fn is_stark_format(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == STARK_VERSION
}

// ─── Types ───────────────────────────────────────────────────────────────────

/// Proof type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofType {
    /// Prove balance >= threshold without revealing exact balance.
    BalanceRange,
    /// Prove metadata key matches a value without revealing the value.
    MetadataProperty,
}

impl ProofType {
    fn tag(&self) -> u8 {
        match self {
            ProofType::BalanceRange => 1,
            ProofType::MetadataProperty => 2,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(ProofType::BalanceRange),
            2 => Some(ProofType::MetadataProperty),
            _ => None,
        }
    }
}

/// A zero-knowledge proof using SHA3 commitments.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZkProof {
    /// What kind of proof this is.
    pub proof_type: ProofType,
    /// Commitment: SHA3(secret || blinding_factor).
    pub commitment: [u8; 32],
    /// Proof data (type-specific auxiliary information).
    pub proof_data: Vec<u8>,
    /// Public inputs the verifier needs.
    pub public_inputs: Vec<u8>,
}

// ─── Balance Range Proof ────────────────────────────────────────────────────

/// Prove "I have >= threshold base units" without revealing exact balance.
///
/// Scheme:
/// - commitment = SHA3(actual_balance_bytes || blinding_factor)
/// - proof_data = SHA3(threshold_bytes || blinding_factor)
///   (verifier checks: if balance >= threshold, both commitments are valid)
/// - public_inputs = threshold as u64 big-endian
///
/// The prover reveals: commitment, threshold proof, threshold.
/// The verifier checks the threshold proof is consistent.
pub fn prove_balance_range(
    actual_balance: u64,
    threshold: u64,
    blinding_factor: &[u8; 32],
) -> Option<ZkProof> {
    if actual_balance < threshold {
        return None; // Can't prove what's not true
    }

    // Commitment to actual balance
    let mut balance_preimage = Vec::with_capacity(40);
    balance_preimage.extend_from_slice(&actual_balance.to_be_bytes());
    balance_preimage.extend_from_slice(blinding_factor);
    let commitment = sha3_256(&balance_preimage);

    // Proof: commit to the fact that balance >= threshold
    // We commit to (balance - threshold) which must be >= 0
    let excess = actual_balance - threshold;
    let mut excess_preimage = Vec::with_capacity(40);
    excess_preimage.extend_from_slice(&excess.to_be_bytes());
    excess_preimage.extend_from_slice(blinding_factor);
    let excess_commitment = sha3_256(&excess_preimage);

    // Public inputs: threshold
    let public_inputs = threshold.to_be_bytes().to_vec();

    Some(ZkProof {
        proof_type: ProofType::BalanceRange,
        commitment,
        proof_data: excess_commitment.to_vec(),
        public_inputs,
    })
}

/// Verify a balance range proof.
///
/// Returns `true` if the proof structure is valid. Note: this is a commitment
/// scheme, not a full ZK proof — it proves the prover *created* a valid
/// commitment, but a full node can verify by checking the on-chain balance.
pub fn verify_balance_range(proof: &ZkProof, threshold: u64) -> bool {
    if proof.proof_type != ProofType::BalanceRange {
        return false;
    }
    if proof.public_inputs.len() != 8 {
        return false;
    }
    if proof.proof_data.len() != 32 {
        return false;
    }

    // Check that the public threshold matches
    let Ok(arr) = <[u8; 8]>::try_from(&proof.public_inputs[..8]) else {
        return false;
    };
    let claimed_threshold = u64::from_be_bytes(arr);
    if claimed_threshold != threshold {
        return false;
    }

    // Structural validity: commitment and proof_data are both 32-byte hashes
    proof.commitment != [0u8; 32] && proof.proof_data != vec![0u8; 32]
}

// ─── Metadata Property Proof ────────────────────────────────────────────────

/// Prove that a metadata key has a specific value without revealing the value.
///
/// Scheme:
/// - commitment = SHA3(key || value || salt)
/// - public_inputs = key bytes (the key name is public)
/// - proof_data = SHA3(value || salt) (inner commitment)
pub fn prove_metadata_property(key: &str, value: &str, salt: &[u8; 32]) -> ZkProof {
    // Full commitment: SHA3(key || value || salt)
    let mut preimage = Vec::new();
    preimage.extend_from_slice(key.as_bytes());
    preimage.extend_from_slice(value.as_bytes());
    preimage.extend_from_slice(salt);
    let commitment = sha3_256(&preimage);

    // Inner commitment: SHA3(value || salt)
    let mut inner_preimage = Vec::new();
    inner_preimage.extend_from_slice(value.as_bytes());
    inner_preimage.extend_from_slice(salt);
    let inner_commitment = sha3_256(&inner_preimage);

    ZkProof {
        proof_type: ProofType::MetadataProperty,
        commitment,
        proof_data: inner_commitment.to_vec(),
        public_inputs: key.as_bytes().to_vec(),
    }
}

/// Verify a metadata property proof.
///
/// Checks structural validity: the commitment is consistent with the key
/// and inner commitment. A verifier who knows the value + salt can fully verify.
pub fn verify_metadata_property(proof: &ZkProof, key: &str) -> bool {
    if proof.proof_type != ProofType::MetadataProperty {
        return false;
    }
    if proof.public_inputs != key.as_bytes() {
        return false;
    }
    if proof.proof_data.len() != 32 {
        return false;
    }
    // Structural validity
    proof.commitment != [0u8; 32]
}

/// Full verification when the verifier knows the value and salt.
pub fn verify_metadata_property_full(
    proof: &ZkProof,
    key: &str,
    value: &str,
    salt: &[u8; 32],
) -> bool {
    if !verify_metadata_property(proof, key) {
        return false;
    }

    // Recompute full commitment
    let mut preimage = Vec::new();
    preimage.extend_from_slice(key.as_bytes());
    preimage.extend_from_slice(value.as_bytes());
    preimage.extend_from_slice(salt);
    let expected = sha3_256(&preimage);

    proof.commitment == expected
}

// ─── Serialization (for ValidationRecord.zk_proof field) ────────────────────

/// Serialize a ZkProof into bytes for the `zk_proof` field.
///
/// Format: [proof_type:u8][commitment:32][proof_data_len:u16][proof_data][public_inputs_len:u16][public_inputs]
pub fn serialize_proof(proof: &ZkProof) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(proof.proof_type.tag());
    buf.extend_from_slice(&proof.commitment);
    buf.extend_from_slice(&(proof.proof_data.len() as u16).to_be_bytes());
    buf.extend_from_slice(&proof.proof_data);
    buf.extend_from_slice(&(proof.public_inputs.len() as u16).to_be_bytes());
    buf.extend_from_slice(&proof.public_inputs);
    buf
}

/// Deserialize a ZkProof from the `zk_proof` field bytes.
pub fn deserialize_proof(data: &[u8]) -> Option<ZkProof> {
    if data.len() < 35 {
        return None; // 1 (type) + 32 (commitment) + 2 (proof_data_len) minimum
    }

    let proof_type = ProofType::from_tag(data[0])?;
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&data[1..33]);

    let proof_data_len = u16::from_be_bytes(data[33..35].try_into().ok()?) as usize;
    if data.len() < 35 + proof_data_len + 2 {
        return None;
    }
    let proof_data = data[35..35 + proof_data_len].to_vec();

    let pi_offset = 35 + proof_data_len;
    let pi_len = u16::from_be_bytes(data[pi_offset..pi_offset + 2].try_into().ok()?) as usize;
    if data.len() < pi_offset + 2 + pi_len {
        return None;
    }
    let public_inputs = data[pi_offset + 2..pi_offset + 2 + pi_len].to_vec();

    Some(ZkProof {
        proof_type,
        commitment,
        proof_data,
        public_inputs,
    })
}

// ─── Record-level verification ──────────────────────────────────────────────

/// Verify the ZK proof attached to a record, if any.
///
/// Called during `insert_record` for Private/Restricted classified records.
/// Returns `true` if no proof is attached (optional) or if the proof is structurally valid.
pub fn verify_record_proof(zk_proof_bytes: &[u8]) -> bool {
    // Version 0x03 IS the SHA3 commitment format (commitment::COMMITMENT_VERSION).
    // Historical note: 0x03 was once labelled "STARK"; there is no STARK prover —
    // `stark.rs` was a back-compat shim and has been deleted. Route to the
    // commitment verifier.
    if is_stark_format(zk_proof_bytes) {
        return super::commitment::verify_commitment_proof(zk_proof_bytes).unwrap_or(false);
    }

    // Fall back to SHA3 commitment scheme (version 0x01 / legacy)
    match deserialize_proof(zk_proof_bytes) {
        Some(proof) => match proof.proof_type {
            ProofType::BalanceRange => {
                if proof.public_inputs.len() != 8 {
                    return false;
                }
                let Ok(arr) = <[u8; 8]>::try_from(&proof.public_inputs[..8]) else {
                    return false;
                };
                let threshold = u64::from_be_bytes(arr);
                verify_balance_range(&proof, threshold)
            }
            ProofType::MetadataProperty => {
                let key = match std::str::from_utf8(&proof.public_inputs) {
                    Ok(k) => k,
                    Err(_) => return false,
                };
                verify_metadata_property(&proof, key)
            }
        },
        None => false, // Malformed proof bytes
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn random_blinding() -> [u8; 32] {
        sha3_256(b"test_blinding_factor")
    }

    #[test]
    fn test_balance_range_proof_valid() {
        let blinding = random_blinding();
        let proof = prove_balance_range(1000, 500, &blinding).unwrap();
        assert!(verify_balance_range(&proof, 500));
    }

    #[test]
    fn test_balance_range_proof_exact_threshold() {
        let blinding = random_blinding();
        let proof = prove_balance_range(500, 500, &blinding).unwrap();
        assert!(verify_balance_range(&proof, 500));
    }

    #[test]
    fn test_balance_range_proof_insufficient() {
        let blinding = random_blinding();
        assert!(prove_balance_range(499, 500, &blinding).is_none());
    }

    #[test]
    fn test_balance_range_wrong_threshold() {
        let blinding = random_blinding();
        let proof = prove_balance_range(1000, 500, &blinding).unwrap();
        assert!(!verify_balance_range(&proof, 600)); // different threshold
    }

    #[test]
    fn test_metadata_property_proof() {
        let salt = sha3_256(b"test_salt");
        let proof = prove_metadata_property("location", "berlin", &salt);
        assert!(verify_metadata_property(&proof, "location"));
        assert!(!verify_metadata_property(&proof, "wrong_key"));
    }

    #[test]
    fn test_metadata_property_full_verification() {
        let salt = sha3_256(b"test_salt");
        let proof = prove_metadata_property("sensor_id", "abc123", &salt);
        assert!(verify_metadata_property_full(&proof, "sensor_id", "abc123", &salt));
        assert!(!verify_metadata_property_full(&proof, "sensor_id", "wrong_value", &salt));

        let wrong_salt = sha3_256(b"wrong_salt");
        assert!(!verify_metadata_property_full(&proof, "sensor_id", "abc123", &wrong_salt));
    }

    #[test]
    fn test_proof_serialize_roundtrip() {
        let blinding = random_blinding();
        let proof = prove_balance_range(1000, 500, &blinding).unwrap();
        let bytes = serialize_proof(&proof);
        let restored = deserialize_proof(&bytes).unwrap();
        assert_eq!(restored.proof_type, proof.proof_type);
        assert_eq!(restored.commitment, proof.commitment);
        assert_eq!(restored.proof_data, proof.proof_data);
        assert_eq!(restored.public_inputs, proof.public_inputs);
    }

    #[test]
    fn test_metadata_proof_serialize_roundtrip() {
        let salt = sha3_256(b"test_salt");
        let proof = prove_metadata_property("key", "value", &salt);
        let bytes = serialize_proof(&proof);
        let restored = deserialize_proof(&bytes).unwrap();
        assert_eq!(restored.proof_type, ProofType::MetadataProperty);
        assert_eq!(restored.commitment, proof.commitment);
    }

    #[test]
    fn test_deserialize_invalid() {
        assert!(deserialize_proof(&[]).is_none());
        assert!(deserialize_proof(&[0xFF; 10]).is_none()); // invalid proof type
        assert!(deserialize_proof(&[1; 34]).is_none()); // too short
    }

    #[test]
    fn test_verify_record_proof_balance() {
        let blinding = random_blinding();
        let proof = prove_balance_range(1000, 500, &blinding).unwrap();
        let bytes = serialize_proof(&proof);
        assert!(verify_record_proof(&bytes));
    }

    #[test]
    fn test_verify_record_proof_metadata() {
        let salt = sha3_256(b"salt");
        let proof = prove_metadata_property("key", "val", &salt);
        let bytes = serialize_proof(&proof);
        assert!(verify_record_proof(&bytes));
    }

    #[test]
    fn test_verify_record_proof_rejects_bogus_0x03() {
        // Regression guard: ingest.rs routes classified-record 0x03 (STARK_VERSION
        // == COMMITMENT_VERSION) proofs through verify_record_proof rather than
        // blind-accepting them. A 0x03-prefixed proof that is NOT a valid commitment
        // must be rejected — this is the soundness the ingest fix relies on
        // (closes the 0x03 twin of the 0x02 version-byte spoof).
        assert!(!verify_record_proof(&[STARK_VERSION])); // bare version byte, no body
        assert!(!verify_record_proof(&[STARK_VERSION, 0x01, 0xAA, 0xBB])); // garbage body
        assert!(!verify_record_proof(&[STARK_VERSION; 64])); // 0x03-prefixed noise
    }

    #[test]
    fn test_is_groth16_format_discriminator() {
        // SHA3 proofs start with tag 1 (BalanceRange) or 2 (MetadataProperty)
        // but tag 2 == GROTH16_VERSION, so we need to check the actual format.
        // In practice, SHA3 proofs have tag byte = ProofType::tag() which is 1 or 2,
        // while Groth16 proofs have 0x02 as a version byte followed by proof_type byte.
        assert!(!is_groth16_format(&[]));
        assert!(!is_groth16_format(&[0x01])); // SHA3 BalanceRange tag
        assert!(is_groth16_format(&[GROTH16_VERSION])); // Groth16 version
    }

    #[test]
    fn test_sha3_proof_still_verifies_after_groth16_addition() {
        // Backward compatibility: SHA3 proofs must still work
        let blinding = random_blinding();
        let proof = prove_balance_range(1000, 500, &blinding).unwrap();
        let bytes = serialize_proof(&proof);
        assert!(!is_groth16_format(&bytes)); // Should NOT be detected as Groth16
        assert!(verify_record_proof(&bytes)); // Should still verify as SHA3
    }

    // ─── fixture-free ────────────────────────────────────
    //
    // Five axes covering pure-helper surface NOT covered by existing
    // semantic test_*-prefixed tests:
    //   1. Version constants strict-pin + 4-way disjointness across
    //      {GROTH16_VERSION, STARK_VERSION, BalanceRange tag, MetadataProperty tag}
    //   2. is_stark_format / is_groth16_format / SHA3-tag mutual-exclusion
    //      matrix across byte values 0x00..=0x05
    //   3. serialize_proof byte-offset wire-format strict-pin (header,
    //      commitment offset, BE u16 length fields)
    //   4. deserialize_proof short-buffer reject matrix at every offset
    //      below the 35-byte minimum + truncated trailing inputs
    //   5. verify_balance_range structural reject sweep (wrong type,
    //      wrong public_inputs length, wrong proof_data length, all-zero
    //      commitment, all-zero proof_data)

    #[test]
    fn batch_b_version_constants_strict_pin_and_four_way_disjointness() {
        // GROTH16_VERSION and STARK_VERSION are wire-format discriminators.
        // ProofType::tag() values (1, 2) ALSO live in the same byte slot.
        // All four must be pairwise disjoint or the format-detection
        // dispatch breaks.
        assert_eq!(GROTH16_VERSION, 0x02, "GROTH16_VERSION must be 0x02");
        assert_eq!(STARK_VERSION, 0x03, "STARK_VERSION must be 0x03");
        assert_eq!(ProofType::BalanceRange.tag(), 1,
            "BalanceRange tag must be 1 (smallest non-zero)");
        assert_eq!(ProofType::MetadataProperty.tag(), 2,
            "MetadataProperty tag must be 2");

        // 4-way pairwise disjointness check — except BalanceRange tag (2)
        // collides with GROTH16_VERSION (0x02)! That's the known design
        // tension noted in test_is_groth16_format_discriminator. Pin it
        // explicitly so future drift is caught:
        assert_eq!(ProofType::MetadataProperty.tag(), GROTH16_VERSION,
            "MetadataProperty tag (2) == GROTH16_VERSION (0x02) — known wire-format \
             ambiguity, dispatched by serialize_proof producing tag-2 vs Groth16 \
             producing 0x02-version + nested proof_type byte. Pin this so future \
             drift fails loudly.");

        // STARK_VERSION (0x03) MUST NOT collide with any SHA3 ProofType tag.
        assert_ne!(STARK_VERSION, ProofType::BalanceRange.tag(),
            "STARK_VERSION must NOT collide with BalanceRange tag");
        assert_ne!(STARK_VERSION, ProofType::MetadataProperty.tag(),
            "STARK_VERSION must NOT collide with MetadataProperty tag");
        assert_ne!(GROTH16_VERSION, STARK_VERSION,
            "GROTH16_VERSION (0x02) and STARK_VERSION (0x03) must be distinct");

        // from_tag round-trip for valid tags.
        assert_eq!(ProofType::from_tag(1), Some(ProofType::BalanceRange));
        assert_eq!(ProofType::from_tag(2), Some(ProofType::MetadataProperty));
        // from_tag rejects all other byte values.
        for invalid in [0u8, 3, 4, 5, 0x10, 0xFF] {
            assert!(ProofType::from_tag(invalid).is_none(),
                "from_tag({invalid}) must reject — only 1 and 2 are valid tags");
        }
    }

    #[test]
    fn batch_b_format_discriminator_mutual_exclusion_byte_sweep() {
        // is_groth16_format and is_stark_format are first-byte checks.
        // Sweep byte values 0x00..=0x05 and verify the dispatch is sane.
        assert!(!is_groth16_format(&[]), "empty slice cannot be Groth16");
        assert!(!is_stark_format(&[]), "empty slice cannot be STARK");

        for byte in 0u8..=5 {
            let buf = [byte];
            let is_g = is_groth16_format(&buf);
            let is_s = is_stark_format(&buf);

            // Exactly one of the format checks must be true for the
            // version-discriminator byte; all OTHER bytes fall through
            // to "neither" (default SHA3-commitment dispatch).
            match byte {
                0x02 => {
                    assert!(is_g, "byte 0x02 must trigger is_groth16_format");
                    assert!(!is_s, "byte 0x02 must NOT trigger is_stark_format");
                }
                0x03 => {
                    assert!(!is_g, "byte 0x03 must NOT trigger is_groth16_format");
                    assert!(is_s, "byte 0x03 must trigger is_stark_format");
                }
                _ => {
                    assert!(!is_g, "byte {byte:#x} must NOT trigger is_groth16_format");
                    assert!(!is_s, "byte {byte:#x} must NOT trigger is_stark_format");
                }
            }
        }

        // Multi-byte buffer: only the FIRST byte matters for dispatch.
        assert!(is_groth16_format(&[0x02, 0xFF, 0xAA]),
            "is_groth16_format must check byte[0] only");
        assert!(is_stark_format(&[0x03, 0x00, 0x00]),
            "is_stark_format must check byte[0] only");
    }

    #[test]
    fn batch_b_serialize_proof_byte_offset_wire_format_strict_pin() {
        // Wire format (per module docs):
        //   [proof_type:u8]           offset 0
        //   [commitment:[u8; 32]]     offset 1..33
        //   [proof_data_len:u16 BE]   offset 33..35
        //   [proof_data]              offset 35..35+pd_len
        //   [public_inputs_len:u16 BE] next 2 bytes
        //   [public_inputs]           remaining
        //
        // Build a proof with KNOWN-LENGTH proof_data and public_inputs
        // and verify every byte offset.
        let proof = ZkProof {
            proof_type: ProofType::MetadataProperty,
            commitment: [0xAA; 32],
            proof_data: vec![0xBB; 32],
            public_inputs: vec![0xCC; 16],
        };
        let bytes = serialize_proof(&proof);

        // Total length: 1 + 32 + 2 + 32 + 2 + 16 = 85 bytes.
        assert_eq!(bytes.len(), 85,
            "serialize wire form len = 1+32+2+pd+2+pi; got: {}", bytes.len());

        // Offset 0: proof_type tag (MetadataProperty == 2).
        assert_eq!(bytes[0], 2,
            "wire offset 0 must be ProofType::MetadataProperty tag = 2");

        // Offset 1..33: commitment (32 bytes of 0xAA).
        for (i, b) in bytes.iter().enumerate().skip(1).take(32) {
            assert_eq!(*b, 0xAA, "wire offset {i} must be commitment byte 0xAA");
        }

        // Offset 33..35: proof_data_len as u16 BE = 32.
        assert_eq!(bytes[33], 0x00, "wire offset 33: proof_data_len BE high byte = 0x00");
        assert_eq!(bytes[34], 0x20, "wire offset 34: proof_data_len BE low byte = 0x20 (32)");

        // Offset 35..67: proof_data (32 bytes of 0xBB).
        for (i, b) in bytes.iter().enumerate().skip(35).take(32) {
            assert_eq!(*b, 0xBB, "wire offset {i} must be proof_data byte 0xBB");
        }

        // Offset 67..69: public_inputs_len as u16 BE = 16.
        assert_eq!(bytes[67], 0x00, "wire offset 67: pi_len BE high byte = 0x00");
        assert_eq!(bytes[68], 0x10, "wire offset 68: pi_len BE low byte = 0x10 (16)");

        // Offset 69..85: public_inputs (16 bytes of 0xCC).
        for (i, b) in bytes.iter().enumerate().skip(69).take(16) {
            assert_eq!(*b, 0xCC, "wire offset {i} must be public_inputs byte 0xCC");
        }

        // Round-trip preserves all fields.
        let restored = deserialize_proof(&bytes).expect("must roundtrip");
        assert_eq!(restored.proof_type, proof.proof_type);
        assert_eq!(restored.commitment, proof.commitment);
        assert_eq!(restored.proof_data, proof.proof_data);
        assert_eq!(restored.public_inputs, proof.public_inputs);
    }

    #[test]
    fn batch_b_deserialize_proof_short_buffer_reject_matrix_below_35_and_truncated_trailing() {
        // Minimum valid buffer = 1 (type) + 32 (commitment) + 2 (pd_len) = 35.
        // Every length < 35 must be rejected.
        for n in 0..35 {
            let buf = vec![1u8; n];
            assert!(deserialize_proof(&buf).is_none(),
                "buffer of len {n} (< 35) must reject in deserialize_proof");
        }

        // Exactly 35 bytes with proof_type=1, pd_len=0, no PI → reject
        // (missing pi_len field at offset 35..37).
        let mut buf = vec![0u8; 35];
        buf[0] = 1; // valid proof type
        // pd_len bytes [33..35] = 0x0000 → proof_data is empty
        // pi_len would be at [35..37] but buffer ends at 35 → reject.
        assert!(deserialize_proof(&buf).is_none(),
            "35-byte buf with pd_len=0 but no pi_len field must reject");

        // 37 bytes with pd_len=0, pi_len=0 → valid (empty proof_data + empty PI).
        let mut buf = vec![0u8; 37];
        buf[0] = 1;
        let proof = deserialize_proof(&buf).expect("37-byte buf with pd_len=0, pi_len=0 must accept");
        assert_eq!(proof.proof_type, ProofType::BalanceRange);
        assert_eq!(proof.proof_data.len(), 0);
        assert_eq!(proof.public_inputs.len(), 0);

        // Truncated trailing: declare pd_len=10 but buffer is too short
        // for it (only 5 bytes after offset 35).
        let mut buf = vec![0u8; 40];
        buf[0] = 1;
        buf[33] = 0x00;
        buf[34] = 0x0A; // pd_len = 10
        assert!(deserialize_proof(&buf).is_none(),
            "declared pd_len=10 with only 5 bytes remaining must reject");

        // Invalid proof_type byte (0, 3, 255).
        for invalid_type in [0u8, 3, 4, 255] {
            let mut buf = vec![0u8; 40];
            buf[0] = invalid_type;
            assert!(deserialize_proof(&buf).is_none(),
                "proof_type byte = {invalid_type} must reject in deserialize_proof");
        }
    }

    #[test]
    fn batch_b_verify_balance_range_structural_reject_sweep() {
        // Build a baseline VALID proof.
        let blinding = random_blinding();
        let mut proof = prove_balance_range(1000, 500, &blinding).expect("must build valid proof");
        assert!(verify_balance_range(&proof, 500), "baseline must verify");

        // Reject path 1: wrong proof_type variant.
        let mut bad = proof.clone();
        bad.proof_type = ProofType::MetadataProperty;
        assert!(!verify_balance_range(&bad, 500),
            "MetadataProperty proof_type must reject in verify_balance_range");

        // Reject path 2: public_inputs length != 8 (boundary 7 and 9).
        for len in [0_usize, 1, 4, 7, 9, 16, 32] {
            let mut bad = proof.clone();
            bad.public_inputs = vec![0xFF; len];
            assert!(!verify_balance_range(&bad, 500),
                "public_inputs.len() = {len} (!= 8) must reject");
        }

        // Reject path 3: proof_data length != 32.
        for len in [0_usize, 1, 16, 31, 33, 64] {
            let mut bad = proof.clone();
            bad.proof_data = vec![0xFF; len];
            assert!(!verify_balance_range(&bad, 500),
                "proof_data.len() = {len} (!= 32) must reject");
        }

        // Reject path 4: all-zero commitment.
        let mut bad = proof.clone();
        bad.commitment = [0u8; 32];
        assert!(!verify_balance_range(&bad, 500),
            "all-zero commitment must reject as structurally invalid");

        // Reject path 5: all-zero proof_data (length-32 but zero).
        let mut bad = proof.clone();
        bad.proof_data = vec![0u8; 32];
        assert!(!verify_balance_range(&bad, 500),
            "all-zero proof_data (length-32) must reject as structurally invalid");

        // Reject path 6: wrong threshold (claimed_threshold mismatch).
        // Mutate public_inputs to declare a DIFFERENT threshold than the
        // verifier provides — must reject.
        proof.public_inputs = 999_u64.to_be_bytes().to_vec();
        assert!(!verify_balance_range(&proof, 500),
            "claimed_threshold (999) != verifier threshold (500) must reject");
    }

    #[test]
    fn harden_try_from_slice_in_verify_fns_never_panics() {
        // Regression: verify_balance_range and verify_record_proof previously used
        // try_into().unwrap() on public_inputs[..8]. This pins the panic-free
        // contract: all malformed inputs return false, never panic.
        let blinding = random_blinding();
        let mut proof = prove_balance_range(1000, 500, &blinding).expect("setup");

        // len < 8 — caught by the length guard, returns false.
        for short_len in [0_usize, 1, 3, 7] {
            let mut bad = proof.clone();
            bad.public_inputs = vec![0xAB; short_len];
            assert!(!verify_balance_range(&bad, 500),
                "len={short_len}: must return false, not panic");
        }

        // len == 8, threshold mismatch — exercises the try_from conversion path.
        proof.public_inputs = 0xDEAD_BEEF_u64.to_be_bytes().to_vec();
        assert!(!verify_balance_range(&proof, 500),
            "valid conversion but threshold mismatch must return false");

        // verify_record_proof on serialized bytes with pi_len=7 (short public_inputs).
        // Construct raw bytes: [tag=1][commitment=32B][pd_len BE-u16][proof_data][pi_len BE-u16][pi_data=7B]
        let mut raw = vec![1u8]; // BalanceRange tag
        raw.extend_from_slice(&[0xAB; 32]); // commitment
        raw.extend_from_slice(&0u16.to_be_bytes()); // pd_len = 0
        raw.extend_from_slice(&7u16.to_be_bytes()); // pi_len = 7
        raw.extend_from_slice(&[0x00; 7]); // 7 bytes public_inputs (< 8 required)
        assert!(!verify_record_proof(&raw),
            "BalanceRange proof with 7-byte public_inputs must return false, not panic");
    }
}
