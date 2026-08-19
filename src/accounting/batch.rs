//! Batch validation — aggregate multiple readings into a single record.
//!
//! Protocol v0.6.2 Section 11.8: IoT-specific compression. A sensor producing
//! 1 reading/second can batch 3,600 readings into one hourly validation record.
//! Storage reduction: 3,600x with no loss of verifiability.
//!
//! Batch records are regular `ValidationRecord`s with `batch_op` metadata.
//! The batch Merkle root allows individual readings to be proved later via
//! the Merkle tree.

//!
//! Spec references:
//!   @spec economics §16.1

use std::collections::BTreeMap;

use serde_json::Value as JsonValue;

use crate::crypto::hash::sha3_256;
use crate::errors::{ElaraError, Result};
use crate::record::ValidationRecord;

// ─── Constants ─────────────────────────────────────────────────────────────

pub const BATCH_OP_KEY: &str = "batch_op";

// ─── Parsed batch ──────────────────────────────────────────────────────────

/// Parsed metadata from a batch validation record.
#[derive(Debug, Clone)]
pub struct ParsedBatch {
    /// Number of individual readings aggregated.
    pub count: u64,
    /// Merkle root over all individual reading hashes.
    pub merkle_root: [u8; 32],
    /// Timestamp of the first reading in the batch.
    pub start: f64,
    /// Timestamp of the last reading in the batch.
    pub end: f64,
    /// Number of distinct devices that contributed readings (optional, 0 = unspecified).
    pub device_count: u64,
}

// ─── Metadata builder ──────────────────────────────────────────────────────

/// Build metadata for a batch validation record.
pub fn batch_metadata(
    count: u64,
    merkle_root: &[u8; 32],
    start: f64,
    end: f64,
    device_count: u64,
) -> BTreeMap<String, JsonValue> {
    let mut m = BTreeMap::new();
    m.insert(BATCH_OP_KEY.into(), serde_json::json!("aggregate"));
    m.insert("batch_count".into(), serde_json::json!(count));
    m.insert("batch_merkle_root".into(), serde_json::json!(hex::encode(merkle_root)));
    m.insert("batch_start".into(), serde_json::json!(start));
    m.insert("batch_end".into(), serde_json::json!(end));
    if device_count > 0 {
        m.insert("batch_device_count".into(), serde_json::json!(device_count));
    }
    m
}

// ─── Extract / parse ───────────────────────────────────────────────────────

/// Extract a batch validation from a record's metadata, if present.
/// Returns `Ok(None)` if the record is not a batch record.
pub fn extract_batch(record: &ValidationRecord) -> Result<Option<ParsedBatch>> {
    let op_val = match record.metadata.get(BATCH_OP_KEY) {
        Some(v) => v,
        None => return Ok(None),
    };

    let op_str = op_val
        .as_str()
        .ok_or_else(|| ElaraError::Wire("batch_op must be a string".into()))?;

    if op_str != "aggregate" {
        return Err(ElaraError::Wire(format!("unknown batch_op: {op_str}")));
    }

    let count = record.metadata.get("batch_count")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ElaraError::Wire("missing batch_count".into()))?;

    let merkle_root_hex = record.metadata.get("batch_merkle_root")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ElaraError::Wire("missing batch_merkle_root".into()))?;
    let merkle_root_vec = hex::decode(merkle_root_hex)
        .map_err(|e| ElaraError::Wire(format!("bad batch_merkle_root hex: {e}")))?;
    if merkle_root_vec.len() != 32 {
        return Err(ElaraError::Wire("batch_merkle_root must be 32 bytes".into()));
    }
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&merkle_root_vec);

    let start = record.metadata.get("batch_start")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| ElaraError::Wire("missing batch_start".into()))?;

    let end = record.metadata.get("batch_end")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| ElaraError::Wire("missing batch_end".into()))?;

    let device_count = record.metadata.get("batch_device_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    Ok(Some(ParsedBatch {
        count,
        merkle_root,
        start,
        end,
        device_count,
    }))
}

// ─── Batch creation helpers ────────────────────────────────────────────────

/// Compute the Merkle root over a set of individual reading hashes.
///
/// Each reading is hashed independently (SHA3-256 of the reading bytes).
/// The sorted hashes are then combined into a Merkle tree.
pub fn compute_batch_root(reading_hashes: &[[u8; 32]]) -> [u8; 32] {
    if reading_hashes.is_empty() {
        return [0u8; 32];
    }

    let mut sorted = reading_hashes.to_vec();
    sorted.sort();

    // Simple iterative pair-wise hashing (same as MerkleTree::root in sync module)
    let mut current = sorted;
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for chunk in current.chunks(2) {
            if chunk.len() == 2 {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&chunk[0]);
                combined.extend_from_slice(&chunk[1]);
                next.push(sha3_256(&combined));
            } else {
                next.push(chunk[0]);
            }
        }
        current = next;
    }
    current[0]
}

/// Generate a Merkle inclusion proof for a specific reading in the batch.
///
/// Returns the sibling hashes needed to reconstruct the root, plus the
/// index path (left=false, right=true at each level).
pub fn merkle_proof(reading_hashes: &[[u8; 32]], index: usize) -> Option<Vec<([u8; 32], bool)>> {
    if index >= reading_hashes.len() || reading_hashes.is_empty() {
        return None;
    }

    let mut sorted = reading_hashes.to_vec();
    sorted.sort();

    // Find the actual index of our hash in the sorted list
    let target = reading_hashes[index];
    let sorted_index = sorted.iter().position(|h| *h == target)?;

    let mut proof = Vec::new();
    let mut current_layer = sorted;
    let mut idx = sorted_index;

    while current_layer.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        let is_right = idx % 2 == 0; // sibling is to the right

        if sibling_idx < current_layer.len() {
            proof.push((current_layer[sibling_idx], is_right));
        }

        // Build next layer
        let mut next = Vec::with_capacity(current_layer.len().div_ceil(2));
        for chunk in current_layer.chunks(2) {
            if chunk.len() == 2 {
                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&chunk[0]);
                combined.extend_from_slice(&chunk[1]);
                next.push(sha3_256(&combined));
            } else {
                next.push(chunk[0]);
            }
        }
        current_layer = next;
        idx /= 2;
    }

    Some(proof)
}

/// Verify a Merkle inclusion proof.
pub fn verify_proof(leaf: &[u8; 32], proof: &[([u8; 32], bool)], root: &[u8; 32]) -> bool {
    let mut current = *leaf;
    for (sibling, sibling_is_right) in proof {
        let mut combined = Vec::with_capacity(64);
        if *sibling_is_right {
            combined.extend_from_slice(&current);
            combined.extend_from_slice(sibling);
        } else {
            combined.extend_from_slice(sibling);
            combined.extend_from_slice(&current);
        }
        current = sha3_256(&combined);
    }
    current == *root
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Classification;

    fn test_record_with_meta(meta: BTreeMap<String, JsonValue>) -> ValidationRecord {
        ValidationRecord::create(
            b"batch-test",
            vec![0u8; 32],
            vec![],
            Classification::Public,
            Some(meta),
        )
    }

    #[test]
    fn test_batch_metadata_roundtrip() {
        let root = sha3_256(b"test readings");
        let meta = batch_metadata(3600, &root, 1000.0, 4600.0, 10);

        assert_eq!(meta.get(BATCH_OP_KEY).unwrap().as_str().unwrap(), "aggregate");
        assert_eq!(meta.get("batch_count").unwrap().as_u64().unwrap(), 3600);
        assert_eq!(meta.get("batch_merkle_root").unwrap().as_str().unwrap(), hex::encode(root));
        assert_eq!(meta.get("batch_start").unwrap().as_f64().unwrap(), 1000.0);
        assert_eq!(meta.get("batch_end").unwrap().as_f64().unwrap(), 4600.0);
        assert_eq!(meta.get("batch_device_count").unwrap().as_u64().unwrap(), 10);
    }

    #[test]
    fn test_extract_none_for_non_batch() {
        let record = ValidationRecord::create(
            b"normal", vec![0u8; 32], vec![], Classification::Public, None,
        );
        assert!(extract_batch(&record).unwrap().is_none());
    }

    #[test]
    fn test_extract_valid_batch() {
        let root = sha3_256(b"readings");
        let meta = batch_metadata(100, &root, 500.0, 600.0, 5);
        let record = test_record_with_meta(meta);

        let batch = extract_batch(&record).unwrap().unwrap();
        assert_eq!(batch.count, 100);
        assert_eq!(batch.merkle_root, root);
        assert_eq!(batch.start, 500.0);
        assert_eq!(batch.end, 600.0);
        assert_eq!(batch.device_count, 5);
    }

    #[test]
    fn test_extract_missing_count() {
        let mut meta = BTreeMap::new();
        meta.insert(BATCH_OP_KEY.into(), serde_json::json!("aggregate"));
        // Missing batch_count
        meta.insert("batch_merkle_root".into(), serde_json::json!(hex::encode([0u8; 32])));
        meta.insert("batch_start".into(), serde_json::json!(0.0));
        meta.insert("batch_end".into(), serde_json::json!(100.0));
        let record = test_record_with_meta(meta);
        assert!(extract_batch(&record).is_err());
    }

    #[test]
    fn test_extract_invalid_op() {
        let mut meta = BTreeMap::new();
        meta.insert(BATCH_OP_KEY.into(), serde_json::json!("unknown"));
        let record = test_record_with_meta(meta);
        assert!(extract_batch(&record).is_err());
    }

    #[test]
    fn test_extract_no_device_count_defaults_zero() {
        let root = sha3_256(b"test");
        let mut meta = BTreeMap::new();
        meta.insert(BATCH_OP_KEY.into(), serde_json::json!("aggregate"));
        meta.insert("batch_count".into(), serde_json::json!(50));
        meta.insert("batch_merkle_root".into(), serde_json::json!(hex::encode(root)));
        meta.insert("batch_start".into(), serde_json::json!(0.0));
        meta.insert("batch_end".into(), serde_json::json!(100.0));
        let record = test_record_with_meta(meta);

        let batch = extract_batch(&record).unwrap().unwrap();
        assert_eq!(batch.device_count, 0);
    }

    #[test]
    fn test_compute_batch_root_empty() {
        assert_eq!(compute_batch_root(&[]), [0u8; 32]);
    }

    #[test]
    fn test_compute_batch_root_single() {
        let hash = sha3_256(b"reading1");
        assert_eq!(compute_batch_root(&[hash]), hash);
    }

    #[test]
    fn test_compute_batch_root_deterministic() {
        let hashes: Vec<[u8; 32]> = (0..10u32)
            .map(|i| sha3_256(format!("reading-{i}").as_bytes()))
            .collect();

        let root1 = compute_batch_root(&hashes);
        let root2 = compute_batch_root(&hashes);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_compute_batch_root_order_independent() {
        let hashes: Vec<[u8; 32]> = (0..5u32)
            .map(|i| sha3_256(format!("r-{i}").as_bytes()))
            .collect();
        let mut reversed = hashes.clone();
        reversed.reverse();

        // Should produce same root regardless of input order (sorted internally)
        assert_eq!(compute_batch_root(&hashes), compute_batch_root(&reversed));
    }

    #[test]
    fn test_merkle_proof_and_verify() {
        let hashes: Vec<[u8; 32]> = (0..8u32)
            .map(|i| sha3_256(format!("item-{i}").as_bytes()))
            .collect();

        let root = compute_batch_root(&hashes);

        // Prove each item and verify
        for i in 0..hashes.len() {
            let proof = merkle_proof(&hashes, i).unwrap();
            assert!(
                verify_proof(&hashes[i], &proof, &root),
                "proof failed for index {i}",
            );
        }
    }

    #[test]
    fn test_merkle_proof_wrong_leaf_fails() {
        let hashes: Vec<[u8; 32]> = (0..4u32)
            .map(|i| sha3_256(format!("item-{i}").as_bytes()))
            .collect();

        let root = compute_batch_root(&hashes);
        let proof = merkle_proof(&hashes, 0).unwrap();

        // Wrong leaf should not verify
        let wrong_leaf = sha3_256(b"not in the tree");
        assert!(!verify_proof(&wrong_leaf, &proof, &root));
    }

    #[test]
    fn test_merkle_proof_out_of_bounds() {
        let hashes = vec![sha3_256(b"only one")];
        assert!(merkle_proof(&hashes, 1).is_none());
        assert!(merkle_proof(&[], 0).is_none());
    }

    #[test]
    fn test_batch_3600_readings_compression() {
        // Simulate 1 hour of sensor readings (1/sec = 3600)
        let hashes: Vec<[u8; 32]> = (0..3600u32)
            .map(|i| sha3_256(format!("temp:{}.{}C", 22 + (i % 3), i % 10).as_bytes()))
            .collect();

        let root = compute_batch_root(&hashes);

        // Build batch record metadata
        let meta = batch_metadata(3600, &root, 1000.0, 4600.0, 1);
        let record = test_record_with_meta(meta);
        let batch = extract_batch(&record).unwrap().unwrap();

        assert_eq!(batch.count, 3600);

        // Prove a specific reading
        let proof = merkle_proof(&hashes, 1800).unwrap(); // middle reading
        assert!(verify_proof(&hashes[1800], &proof, &root));
    }

    // ── batch validation tests (economics §16.1) ───────────────

    #[test]
    fn batch_b_batch_op_key_const_pin_with_cross_module_disjointness() {
        assert_eq!(BATCH_OP_KEY, "batch_op");
        // Cross-module namespace disjointness — every ledger op key MUST be unique.
        assert_ne!(BATCH_OP_KEY, crate::accounting::dormancy::DORMANCY_OP_KEY);
        assert_ne!(BATCH_OP_KEY, crate::accounting::storage_market::STORAGE_OP_KEY);
        // snake_case lowercase invariant.
        assert!(BATCH_OP_KEY.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        assert!(!BATCH_OP_KEY.starts_with('_') && !BATCH_OP_KEY.ends_with('_'));
        // Op-string sentinel ("aggregate" — there's only one valid value).
        // The batch_metadata builder MUST emit this literal so extract_batch parses it.
        let m = batch_metadata(1, &[0u8; 32], 0.0, 1.0, 0);
        assert_eq!(m.get(BATCH_OP_KEY).unwrap().as_str().unwrap(), "aggregate");
    }

    #[test]
    fn batch_b_parsed_batch_clone_preserves_all_five_fields_with_distinct_leaves() {
        let mr = sha3_256(b"some root payload");
        let original = ParsedBatch {
            count: 12345,
            merkle_root: mr,
            start: 1_700_000_000.0,
            end: 1_700_003_600.0,
            device_count: 42,
        };
        let cloned = original.clone();
        assert_eq!(cloned.count, 12345);
        assert_eq!(cloned.merkle_root, mr);
        assert_eq!(cloned.start, 1_700_000_000.0);
        assert_eq!(cloned.end, 1_700_003_600.0);
        assert_eq!(cloned.device_count, 42);
        // Mutating clone doesn't bleed back to original (independent storage).
        let mut mutant = cloned.clone();
        mutant.count = 99;
        assert_eq!(mutant.count, 99);
        assert_eq!(original.count, 12345);
    }

    #[test]
    fn batch_b_batch_metadata_device_count_zero_omits_key_not_zero_value() {
        let root = sha3_256(b"x");
        let m_with = batch_metadata(10, &root, 0.0, 1.0, 5);
        let m_without = batch_metadata(10, &root, 0.0, 1.0, 0);
        // device_count > 0 → key present with that value.
        assert!(m_with.contains_key("batch_device_count"));
        assert_eq!(m_with.get("batch_device_count").unwrap().as_u64().unwrap(), 5);
        // device_count == 0 → key OMITTED entirely (NOT key with value 0).
        // This is load-bearing: extract_batch fills device_count=0 as the "unspecified"
        // sentinel; serializing as missing-key saves wire bytes per batch.
        assert!(!m_without.contains_key("batch_device_count"));
        // All other keys MUST still be present in both.
        for key in [BATCH_OP_KEY, "batch_count", "batch_merkle_root", "batch_start", "batch_end"] {
            assert!(m_with.contains_key(key), "with-devices missing {key}");
            assert!(m_without.contains_key(key), "without-devices missing {key}");
        }
    }

    #[test]
    fn batch_b_compute_batch_root_distinct_leaf_counts_produce_distinct_roots() {
        // Different N produce different roots (no collision across leaf counts at low N).
        let leaf = sha3_256(b"same leaf");
        let r1 = compute_batch_root(&[leaf]);
        let r2 = compute_batch_root(&[leaf, leaf]);
        let r3 = compute_batch_root(&[leaf, leaf, leaf]);
        // Single-leaf root == leaf (existing test pins this).
        assert_eq!(r1, leaf);
        // Multi-leaf root != leaf (real hashing happens at N≥2).
        assert_ne!(r2, leaf);
        assert_ne!(r3, leaf);
        // Distinct N → distinct roots (since hashing involves count-dependent structure).
        assert_ne!(r1, r2);
        assert_ne!(r2, r3);
        // Empty root is well-defined sentinel [0;32], not a real leaf.
        assert_eq!(compute_batch_root(&[]), [0u8; 32]);
        assert_ne!(compute_batch_root(&[]), r1);
    }

    #[test]
    fn batch_b_verify_proof_rejects_tampered_sibling_and_direction_bit() {
        let hashes: Vec<[u8; 32]> = (0..4u32)
            .map(|i| sha3_256(format!("leaf-{i}").as_bytes()))
            .collect();
        let root = compute_batch_root(&hashes);
        let proof = merkle_proof(&hashes, 0).unwrap();
        // Baseline: untampered proof verifies.
        assert!(verify_proof(&hashes[0], &proof, &root));
        // Tamper 1: flip a byte in a sibling hash → must reject.
        let mut tampered = proof.clone();
        if !tampered.is_empty() {
            tampered[0].0[0] ^= 0xFF;
            assert!(!verify_proof(&hashes[0], &tampered, &root), "tampered sibling accepted");
        }
        // Tamper 2: flip direction bit → must reject (unless hash happens to be the same,
        // which is astronomically unlikely for sha3_256).
        let mut flipped = proof.clone();
        if !flipped.is_empty() {
            flipped[0].1 = !flipped[0].1;
            assert!(!verify_proof(&hashes[0], &flipped, &root), "flipped direction accepted");
        }
        // Tamper 3: truncate proof → wrong tree height, must reject.
        if proof.len() > 1 {
            let truncated = proof[..proof.len() - 1].to_vec();
            assert!(!verify_proof(&hashes[0], &truncated, &root), "truncated proof accepted");
        }
        // Tamper 4: wrong root → must reject.
        let wrong_root = sha3_256(b"not the root");
        assert!(!verify_proof(&hashes[0], &proof, &wrong_root));
    }
}
