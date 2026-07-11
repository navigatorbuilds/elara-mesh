//! Witness attestation store — RocksDB-backed persistence for attestations.

//!
//! Spec references:
//!   @spec Protocol §11.12
//!   @spec economics §11.1

use std::sync::Arc;

use crate::crypto::hash::sha3_256_hex;
use crate::crypto::pqc::dilithium3_verify;
use crate::errors::{ElaraError, Result};
use crate::storage::rocks::{StorageEngine, CF_ATTESTATIONS, CF_IDX_ATT_TIME};

/// Key prefix for attestation entries in the attestations CF.
const ATT_PREFIX: &[u8] = b"att:";

/// Row cap for PUBLIC by-record attestation reads (`get_attestations_page`).
///
/// Attestation storage admits any keypair whose Dilithium signature verifies
/// over the record's signable bytes (`verify_and_store_attestation` — PoWaS is
/// optional), so per-record cardinality is attacker-controlled and an uncapped
/// public read is a response-amplification surface. 1000 is ~15× the largest
/// committee (small-network floor 10, mainnet per-zone ~5-64), so the cap never
/// binds for honest traffic. Internal consensus-adjacent readers deliberately
/// stay unbounded — see `get_attestations`.
pub const MAX_ATTESTATIONS_PER_RECORD_READ: usize = 1000;

/// RocksDB-backed attestation store.
///
/// Stores attestations in the attestations CF with key format:
///   `att:{record_id}:{witness_hash}` -> JSON-encoded AttestationData
///
/// Supports prefix iteration for per-record and full-table queries.
pub struct WitnessManager {
    rocks: Arc<StorageEngine>,
}

/// Internal serializable attestation data (stored as JSON in RocksDB).
#[derive(serde::Serialize, serde::Deserialize)]
struct AttestationData {
    record_id: String,
    witness_hash: String,
    signature: Vec<u8>,
    timestamp: f64,
    witness_public_key: Option<Vec<u8>>,
    powas_nonce: Option<u64>,
    powas_difficulty: Option<u64>,
}

impl WitnessManager {
    /// Create a WitnessManager backed by the given RocksDB storage engine.
    pub fn new(rocks: Arc<StorageEngine>) -> Self {
        Self { rocks }
    }

    /// Build the key for a specific attestation.
    fn att_key(record_id: &str, witness_hash: &str) -> Vec<u8> {
        format!("att:{record_id}:{witness_hash}").into_bytes()
    }

    /// Build the prefix for all attestations of a given record.
    fn record_prefix(record_id: &str) -> Vec<u8> {
        format!("att:{record_id}:").into_bytes()
    }

    /// Build the timestamp index key: `timestamp_be(8B) + record_id + ":" + witness_hash`.
    fn time_idx_key(timestamp: f64, record_id: &str, witness_hash: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(8 + record_id.len() + 1 + witness_hash.len());
        key.extend_from_slice(&timestamp.to_be_bytes());
        key.extend_from_slice(record_id.as_bytes());
        key.push(b':');
        key.extend_from_slice(witness_hash.as_bytes());
        key
    }

    /// Store an attestation. Returns false if duplicate (already witnessed by this witness).
    pub fn store_attestation(
        &self,
        record_id: &str,
        witness_hash: &str,
        signature: &[u8],
        timestamp: f64,
        witness_public_key: Option<&[u8]>,
    ) -> Result<bool> {
        self.store_attestation_with_powas(record_id, witness_hash, signature, timestamp, witness_public_key, None, None)
    }

    /// Store an attestation with PoWaS proof. Returns false if duplicate.
    #[allow(clippy::too_many_arguments)]
    pub fn store_attestation_with_powas(
        &self,
        record_id: &str,
        witness_hash: &str,
        signature: &[u8],
        timestamp: f64,
        witness_public_key: Option<&[u8]>,
        powas_nonce: Option<u64>,
        powas_difficulty: Option<u64>,
    ) -> Result<bool> {
        let key = Self::att_key(record_id, witness_hash);

        // Check for duplicate
        if self.rocks.get_cf_raw(CF_ATTESTATIONS, &key)?.is_some() {
            return Ok(false);
        }

        let data = AttestationData {
            record_id: record_id.to_string(),
            witness_hash: witness_hash.to_string(),
            signature: signature.to_vec(),
            timestamp,
            witness_public_key: witness_public_key.map(|pk| pk.to_vec()),
            powas_nonce,
            powas_difficulty,
        };

        let bytes = serde_json::to_vec(&data)
            .map_err(|e| ElaraError::Storage(format!("serialize attestation: {e}")))?;
        self.rocks.put_cf_raw(CF_ATTESTATIONS, &key, &bytes)?;

        // Write timestamp index entry (empty value — key encodes everything)
        let idx_key = Self::time_idx_key(timestamp, record_id, witness_hash);
        self.rocks.put_cf_raw(CF_IDX_ATT_TIME, &idx_key, &[])?;

        Ok(true)
    }

    /// Store an attestation ONLY after verifying the witness signature against
    /// the record's signable_bytes(). This is the preferred entry point for
    /// attestations received from the network.
    ///
    /// Verification steps:
    /// 1. witness_public_key must be provided (reject otherwise).
    /// 2. SHA3-256(witness_public_key) must equal witness_hash.
    /// 3. dilithium3_verify(signable_bytes, signature, witness_public_key) must succeed.
    ///
    /// Returns Ok(true) if stored, Ok(false) if duplicate, Err on verification failure.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_and_store_attestation(
        &self,
        record_id: &str,
        witness_hash: &str,
        signature: &[u8],
        timestamp: f64,
        witness_public_key: &[u8],
        signable_bytes: &[u8],
        powas_nonce: Option<u64>,
        powas_difficulty: Option<u64>,
    ) -> Result<bool> {
        // 1. Verify public key hash matches witness_hash
        let computed_hash = sha3_256_hex(witness_public_key);
        if computed_hash != witness_hash {
            return Err(ElaraError::InvalidSignature);
        }

        // 2. Verify the witness actually signed the record's signable_bytes
        let valid = dilithium3_verify(signable_bytes, signature, witness_public_key)?;
        if !valid {
            return Err(ElaraError::InvalidSignature);
        }

        // Signature verified — safe to store
        self.store_attestation_with_powas(
            record_id,
            witness_hash,
            signature,
            timestamp,
            Some(witness_public_key),
            powas_nonce,
            powas_difficulty,
        )
    }

    /// Get all attestations for a record.
    ///
    /// UNBOUNDED by design — internal consumers (ingest weight scan, auto-witness
    /// already-witnessed checks, gossip att-push, boot re-seed) need the complete
    /// set: a row cap here would let an attacker's low-lex witness rows crowd
    /// honest attestations out of consensus-adjacent reads (finality-liveness
    /// trap). PUBLIC by-record handlers must use `get_attestations_page` instead;
    /// per-record cardinality is attacker-controlled (storage admits any keypair
    /// whose Dilithium signature verifies over the record bytes).
    pub fn get_attestations(&self, record_id: &str) -> Result<Vec<AttestationRecord>> {
        let prefix = Self::record_prefix(record_id);
        let mut rows = Vec::new();
        self.rocks.prefix_scan(CF_ATTESTATIONS, &prefix, |_key, value| {
            if let Ok(data) = serde_json::from_slice::<AttestationData>(value) {
                rows.push(AttestationRecord::from_data(data));
            }
            Ok(())
        })?;
        Ok(rows)
    }

    /// Bounded by-record read for PUBLIC handlers (HTTP `/attestations?record_id=`,
    /// PQ `query_attestations` record branch, `/record/{id}` detail). Returns at
    /// most `max_rows` attestations plus a truncated flag; the scan stops at the
    /// store layer instead of materializing the full (attacker-controlled) range.
    ///
    /// Row order is key order (`att:{record_id}:{witness_hash}` — witness-hash
    /// lex), deterministic across nodes. `MAX_ATTESTATIONS_PER_RECORD_READ` never
    /// binds for honest traffic (committee sizes are orders of magnitude smaller);
    /// under a fake-witness flood the truncated page is strictly better than
    /// today's unbounded response, which also overruns the PQ 16 MiB frame at
    /// ~3k rows and can never be sent at all.
    pub fn get_attestations_page(
        &self,
        record_id: &str,
        max_rows: usize,
    ) -> Result<(Vec<AttestationRecord>, bool)> {
        let prefix = Self::record_prefix(record_id);
        let mut rows = Vec::new();
        let mut truncated = false;
        self.rocks.prefix_scan_bounded(CF_ATTESTATIONS, &prefix, |_key, value| {
            if rows.len() >= max_rows {
                truncated = true;
                return Ok(false);
            }
            if let Ok(data) = serde_json::from_slice::<AttestationData>(value) {
                rows.push(AttestationRecord::from_data(data));
            }
            Ok(true)
        })?;
        Ok((rows, truncated))
    }

    /// Count attestations for a record.
    pub fn attestation_count(&self, record_id: &str) -> Result<usize> {
        let prefix = Self::record_prefix(record_id);
        let mut count = 0usize;
        self.rocks.prefix_scan(CF_ATTESTATIONS, &prefix, |_key, _value| {
            count += 1;
            Ok(())
        })?;
        Ok(count)
    }

    /// Total attestation count across all records.
    ///
    /// Uses `full_scan_cf` because CF_ATTESTATIONS carries a 41-byte prefix
    /// extractor (DISC-4 D-8). A 4-byte `ATT_PREFIX` against that extractor is
    /// out of domain and `prefix_scan` would return nothing.
    pub fn total_count(&self) -> Result<usize> {
        let mut count = 0usize;
        self.rocks.full_scan_cf(CF_ATTESTATIONS, |key, _value| {
            if key.starts_with(ATT_PREFIX) {
                count += 1;
            }
            Ok(())
        })?;
        Ok(count)
    }

    /// Get attestations since a given timestamp, ordered by timestamp ASC.
    ///
    /// Uses CF_IDX_ATT_TIME for O(new) range scan instead of O(all) full scan.
    /// Falls back to full scan if index is empty (pre-migration data).
    pub fn get_attestations_since(&self, since: f64, limit: usize) -> Result<Vec<AttestationRecord>> {
        // Try index-based range scan first
        let start_key = since.to_be_bytes();
        let mut rows = Vec::new();
        let mut used_index = false;

        self.rocks.range_scan_cf(CF_IDX_ATT_TIME, &start_key, |key, _value| {
            if key.len() < 8 {
                return Ok(true);
            }
            used_index = true;

            // Extract timestamp from first 8 bytes
            let ts = f64::from_be_bytes(key[..8].try_into().unwrap_or([0u8; 8]));
            if ts <= since {
                return Ok(true); // skip exact match (we want > since)
            }

            // Extract record_id and witness_hash from remainder
            let suffix = &key[8..];
            if let Ok(suffix_str) = std::str::from_utf8(suffix) {
                if let Some((record_id, witness_hash)) = suffix_str.rsplit_once(':') {
                    // Fetch the full attestation from primary CF
                    let att_key = Self::att_key(record_id, witness_hash);
                    if let Ok(Some(data_bytes)) = self.rocks.get_cf_raw(CF_ATTESTATIONS, &att_key) {
                        if let Ok(data) = serde_json::from_slice::<AttestationData>(&data_bytes) {
                            rows.push(AttestationRecord::from_data(data));
                        }
                    }
                }
            }

            // Already sorted by timestamp (key order) — just check limit
            Ok(rows.len() < limit)
        })?;

        if used_index {
            return Ok(rows);
        }

        // Fallback: full scan (pre-migration data with no index entries).
        // full_scan_cf because the 41-byte prefix extractor makes short
        // prefix_scan seeks return nothing (DISC-4 D-8).
        self.rocks.full_scan_cf(CF_ATTESTATIONS, |key, value| {
            if !key.starts_with(ATT_PREFIX) {
                return Ok(());
            }
            if let Ok(data) = serde_json::from_slice::<AttestationData>(value) {
                if data.timestamp > since {
                    rows.push(AttestationRecord::from_data(data));
                }
            }
            Ok(())
        })?;
        rows.sort_by(|a, b| a.timestamp.total_cmp(&b.timestamp));
        rows.truncate(limit);
        Ok(rows)
    }

    /// Get the most recent attestations (newest first), up to `limit`.
    ///
    /// Reverse-scans the time index so the rebuild budget goes to the most
    /// recent attestations — the ones most likely to form live settlements.
    /// Old attestations for long-finalized records waste rebuild budget.
    pub fn get_latest_attestations(&self, limit: usize) -> Result<Vec<AttestationRecord>> {
        let mut rows = Vec::with_capacity(limit);

        self.rocks.range_scan_cf_reverse(CF_IDX_ATT_TIME, |key, _value| {
            if key.len() < 8 {
                return Ok(true);
            }

            let suffix = &key[8..];
            if let Ok(suffix_str) = std::str::from_utf8(suffix) {
                if let Some((record_id, witness_hash)) = suffix_str.rsplit_once(':') {
                    let att_key = Self::att_key(record_id, witness_hash);
                    if let Ok(Some(data_bytes)) = self.rocks.get_cf_raw(CF_ATTESTATIONS, &att_key) {
                        if let Ok(data) = serde_json::from_slice::<AttestationData>(&data_bytes) {
                            rows.push(AttestationRecord::from_data(data));
                        }
                    }
                }
            }

            Ok(rows.len() < limit)
        })?;

        Ok(rows)
    }

    /// Get the timestamp of the latest attestation (for pull cursor tracking).
    ///
    /// Uses reverse scan on CF_IDX_ATT_TIME — O(1) instead of O(all).
    /// Falls back to full scan if index is empty.
    pub fn get_latest_timestamp(&self) -> Result<f64> {
        // Try reverse scan on timestamp index (last key = latest timestamp)
        if let Some(ts) = self.rocks.last_key_timestamp_cf(CF_IDX_ATT_TIME)? {
            return Ok(ts);
        }

        // Fallback: full scan (pre-migration). full_scan_cf for D-8 prefix-
        // extractor compatibility.
        let mut max_ts = 0.0f64;
        self.rocks.full_scan_cf(CF_ATTESTATIONS, |key, value| {
            if !key.starts_with(ATT_PREFIX) {
                return Ok(());
            }
            if let Ok(data) = serde_json::from_slice::<AttestationData>(value) {
                if data.timestamp > max_ts {
                    max_ts = data.timestamp;
                }
            }
            Ok(())
        })?;
        Ok(max_ts)
    }

    /// Get the latest attestation timestamp per witness (for liveness rebuild).
    ///
    /// full_scan_cf for D-8 prefix-extractor compatibility.
    pub fn latest_per_witness(&self) -> Result<Vec<(String, f64)>> {
        let mut map = std::collections::HashMap::new();
        self.rocks.full_scan_cf(CF_ATTESTATIONS, |key, value| {
            if !key.starts_with(ATT_PREFIX) {
                return Ok(());
            }
            if let Ok(data) = serde_json::from_slice::<AttestationData>(value) {
                let entry = map.entry(data.witness_hash).or_insert(0.0f64);
                if data.timestamp > *entry {
                    *entry = data.timestamp;
                }
            }
            Ok(())
        })?;
        Ok(map.into_iter().collect())
    }

    /// Delete attestations older than the given timestamp.
    /// Returns the number of pruned entries. Also cleans up CF_IDX_ATT_TIME.
    pub fn prune_before(&self, cutoff_ts: f64) -> Result<usize> {
        let mut att_keys_to_delete = Vec::new();
        let mut idx_keys_to_delete = Vec::new();

        self.rocks.full_scan_cf(CF_ATTESTATIONS, |key, value| {
            if !key.starts_with(ATT_PREFIX) {
                return Ok(());
            }
            if let Ok(data) = serde_json::from_slice::<AttestationData>(value) {
                if data.timestamp < cutoff_ts {
                    att_keys_to_delete.push(key.to_vec());
                    // Build matching index key for cleanup
                    idx_keys_to_delete.push(Self::time_idx_key(
                        data.timestamp, &data.record_id, &data.witness_hash,
                    ));
                }
            }
            Ok(())
        })?;

        let count = att_keys_to_delete.len();
        for key in att_keys_to_delete {
            self.rocks.delete_cf_raw(CF_ATTESTATIONS, &key)?;
        }
        for key in idx_keys_to_delete {
            self.rocks.delete_cf_raw(CF_IDX_ATT_TIME, &key)?;
        }
        Ok(count)
    }

    /// Backfill CF_IDX_ATT_TIME from existing attestations.
    /// Called once on startup to migrate pre-index data. Idempotent.
    pub fn backfill_time_index(&self) -> Result<usize> {
        let mut count = 0usize;
        // full_scan_cf for D-8 prefix-extractor compatibility.
        self.rocks.full_scan_cf(CF_ATTESTATIONS, |key, value| {
            if !key.starts_with(ATT_PREFIX) {
                return Ok(());
            }
            if let Ok(data) = serde_json::from_slice::<AttestationData>(value) {
                let idx_key = Self::time_idx_key(data.timestamp, &data.record_id, &data.witness_hash);
                self.rocks.put_cf_raw(CF_IDX_ATT_TIME, &idx_key, &[])?;
                count += 1;
            }
            Ok(())
        })?;
        Ok(count)
    }
}

/// A stored attestation record.
#[derive(Debug, Clone)]
pub struct AttestationRecord {
    pub record_id: String,
    pub witness_hash: String,
    pub signature: Vec<u8>,
    pub timestamp: f64,
    /// Witness's Dilithium3 public key (for signature verification).
    /// Optional for backward compatibility with pre-verification attestations.
    pub witness_public_key: Option<Vec<u8>>,
    /// PoWaS proof nonce (Protocol v0.6.1 Section 11.1).
    pub powas_nonce: Option<u64>,
    /// PoWaS effective difficulty used.
    pub powas_difficulty: Option<u64>,
}

impl AttestationRecord {
    fn from_data(data: AttestationData) -> Self {
        Self {
            record_id: data.record_id,
            witness_hash: data.witness_hash,
            signature: data.signature,
            timestamp: data.timestamp,
            witness_public_key: data.witness_public_key,
            powas_nonce: data.powas_nonce,
            powas_difficulty: data.powas_difficulty,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn test_mgr() -> (WitnessManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let engine = StorageEngine::open(dir.path()).unwrap();
        (WitnessManager::new(Arc::new(engine)), dir)
    }

    #[test]
    fn test_time_index_range_scan() {
        let (mgr, _dir) = test_mgr();

        // Store attestations at different timestamps
        mgr.store_attestation("rec_a", "wit_1", b"sig1", 100.0, None).unwrap();
        mgr.store_attestation("rec_b", "wit_2", b"sig2", 200.0, None).unwrap();
        mgr.store_attestation("rec_c", "wit_3", b"sig3", 300.0, None).unwrap();
        mgr.store_attestation("rec_d", "wit_4", b"sig4", 400.0, None).unwrap();

        // Range scan from 150 should return rec_b, rec_c, rec_d
        let rows = mgr.get_attestations_since(150.0, 100).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].record_id, "rec_b");
        assert_eq!(rows[1].record_id, "rec_c");
        assert_eq!(rows[2].record_id, "rec_d");
    }

    #[test]
    fn test_time_index_respects_limit() {
        let (mgr, _dir) = test_mgr();

        for i in 0..10 {
            mgr.store_attestation(&format!("rec_{i}"), "wit_1", b"sig", (i as f64) * 10.0, None).unwrap();
        }

        let rows = mgr.get_attestations_since(0.0, 3).unwrap();
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn get_attestations_page_caps_rows_and_flags_truncation() {
        let (mgr, _dir) = test_mgr();

        // UUID-shaped record ids: the CF_ATTESTATIONS prefix extractor
        // (DISC-4 D-8) is 41 bytes = "att:" + 36-char id + ":".
        let rid = "00000000-0000-7000-8000-000000000001";
        let other = "00000000-0000-7000-8000-000000000002";
        for i in 0..5 {
            mgr.store_attestation(rid, &format!("wit_{i}"), b"sig", 100.0 + i as f64, None)
                .unwrap();
        }
        mgr.store_attestation(other, "wit_x", b"sig", 999.0, None).unwrap();

        // Below cap → full set, not truncated, no sibling-record leakage.
        let (rows, truncated) = mgr.get_attestations_page(rid, 10).unwrap();
        assert_eq!(rows.len(), 5);
        assert!(!truncated);
        assert!(rows.iter().all(|a| a.record_id == rid));

        // Over cap → capped + flagged.
        let (rows, truncated) = mgr.get_attestations_page(rid, 3).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(truncated);

        // Exact-cardinality boundary → full set, no flag.
        let (rows, truncated) = mgr.get_attestations_page(rid, 5).unwrap();
        assert_eq!(rows.len(), 5);
        assert!(!truncated);

        // Parity with the unbounded internal read.
        assert_eq!(mgr.get_attestations(rid).unwrap().len(), 5);
    }

    #[test]
    fn test_time_index_prune_cleans_index() {
        let (mgr, _dir) = test_mgr();

        mgr.store_attestation("rec_old", "wit_1", b"sig", 50.0, None).unwrap();
        mgr.store_attestation("rec_new", "wit_2", b"sig", 200.0, None).unwrap();

        // Prune everything before 100
        let pruned = mgr.prune_before(100.0).unwrap();
        assert_eq!(pruned, 1);

        // Index should only have rec_new
        let rows = mgr.get_attestations_since(0.0, 100).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].record_id, "rec_new");
    }

    #[test]
    fn test_latest_timestamp_uses_index() {
        let (mgr, _dir) = test_mgr();

        mgr.store_attestation("rec_a", "wit_1", b"sig", 100.0, None).unwrap();
        mgr.store_attestation("rec_b", "wit_2", b"sig", 500.0, None).unwrap();
        mgr.store_attestation("rec_c", "wit_3", b"sig", 300.0, None).unwrap();

        let latest = mgr.get_latest_timestamp().unwrap();
        assert!((latest - 500.0).abs() < 0.001);
    }

    #[test]
    fn test_backfill_creates_index_entries() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Arc::new(StorageEngine::open(dir.path()).unwrap());
        let mgr = WitnessManager::new(engine.clone());

        // Store attestations (index entries created automatically)
        mgr.store_attestation("rec_a", "wit_1", b"sig", 100.0, None).unwrap();
        mgr.store_attestation("rec_b", "wit_2", b"sig", 200.0, None).unwrap();

        // Delete index entries manually to simulate pre-migration state
        let idx_key_a = WitnessManager::time_idx_key(100.0, "rec_a", "wit_1");
        let idx_key_b = WitnessManager::time_idx_key(200.0, "rec_b", "wit_2");
        engine.delete_cf_raw(CF_IDX_ATT_TIME, &idx_key_a).unwrap();
        engine.delete_cf_raw(CF_IDX_ATT_TIME, &idx_key_b).unwrap();

        // Verify index is empty — falls back to full scan
        let latest = mgr.get_latest_timestamp().unwrap();
        assert!((latest - 200.0).abs() < 0.001); // fallback works

        // Backfill
        let count = mgr.backfill_time_index().unwrap();
        assert_eq!(count, 2);

        // Now index-based range scan should work
        let rows = mgr.get_attestations_since(50.0, 100).unwrap();
        assert_eq!(rows.len(), 2);
    }

    /// DISC-4 D-9/D-10 regression guard: the per-record prefix scan
    /// (`get_attestations`) is the hot path that runs unlocked under
    /// `spawn_blocking` in ingest. After D-10 inlined the free function back
    /// into the method, this test pins the contract: prefix-scan returns ONLY
    /// the requested record's rows, not adjacent records'.
    ///
    /// CF_ATTESTATIONS carries a 41-byte prefix extractor (DISC-4 D-8) that
    /// matches `att:{36-char UUIDv7}:` exactly. We use 36-char IDs so this test
    /// exercises the same scan path production hits. Shorter IDs would be
    /// out-of-domain and prefix_scan would return empty — that's a separate
    /// invariant covered indirectly by total_count's full_scan_cf path.
    #[test]
    fn test_get_attestations_isolates_record() {
        let (mgr, _dir) = test_mgr();

        let alpha_id = "019dc876-a413-7301-aaaa-000000000001";
        let beta_id  = "019dc876-a413-7302-bbbb-000000000002";
        let gamma_id = "019dc876-a413-7303-cccc-000000000003";
        let zzz_id   = "019dc876-a413-7399-dead-beefbeefbeef";
        assert_eq!(alpha_id.len(), 36);

        mgr.store_attestation(alpha_id, "wit_1", b"sig1", 100.0, None).unwrap();
        mgr.store_attestation(alpha_id, "wit_2", b"sig2", 110.0, None).unwrap();
        mgr.store_attestation(alpha_id, "wit_3", b"sig3", 120.0, None).unwrap();
        mgr.store_attestation(beta_id,  "wit_1", b"sig4", 130.0, None).unwrap();
        mgr.store_attestation(gamma_id, "wit_2", b"sig5", 140.0, None).unwrap();

        let alpha = mgr.get_attestations(alpha_id).unwrap();
        assert_eq!(alpha.len(), 3, "alpha should have 3 attestations");
        for row in &alpha {
            assert_eq!(row.record_id, alpha_id);
        }

        let beta = mgr.get_attestations(beta_id).unwrap();
        assert_eq!(beta.len(), 1);
        assert_eq!(beta[0].record_id, beta_id);
        assert_eq!(beta[0].witness_hash, "wit_1");

        let missing = mgr.get_attestations(zzz_id).unwrap();
        assert!(missing.is_empty(), "missing record should return empty vec, not error");

        // attestation_count uses the same prefix; verify it agrees.
        assert_eq!(mgr.attestation_count(alpha_id).unwrap(), 3);
        assert_eq!(mgr.attestation_count(beta_id).unwrap(), 1);
        assert_eq!(mgr.attestation_count(gamma_id).unwrap(), 1);
        assert_eq!(mgr.attestation_count(zzz_id).unwrap(), 0);
    }

    /// DISC-4 D-10 regression guard: WitnessManager has no interior mutability
    /// after the std::Mutex envelope was removed; thread-safety relies on
    /// RocksDB's internal locking. Concurrent reads of `get_attestations`
    /// from many threads must produce consistent, complete results — no torn
    /// reads, no panics, no double-counting.
    #[test]
    fn test_concurrent_get_attestations_after_d10() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Arc::new(StorageEngine::open(dir.path()).unwrap());
        let mgr = Arc::new(WitnessManager::new(engine));

        let hot_id = "019dc876-a413-7300-bead-000000000000";
        for i in 0..20 {
            mgr.store_attestation(hot_id, &format!("wit_{i}"), b"sig", (i as f64) * 10.0, None).unwrap();
        }

        let mut handles = Vec::new();
        for _ in 0..8 {
            let mgr_c = Arc::clone(&mgr);
            let id_c = hot_id.to_string();
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    let rows = mgr_c.get_attestations(&id_c).unwrap();
                    assert_eq!(rows.len(), 20, "torn read: expected 20, got {}", rows.len());
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_index_matches_full_scan() {
        let (mgr, _dir) = test_mgr();

        // Store a bunch of attestations with various timestamps
        let timestamps = [10.0, 50.0, 50.1, 100.0, 200.0, 999.0];
        for (i, ts) in timestamps.iter().enumerate() {
            mgr.store_attestation(&format!("rec_{i}"), &format!("wit_{i}"), b"sig", *ts, None).unwrap();
        }

        // Index-based query
        let indexed = mgr.get_attestations_since(50.0, 100).unwrap();

        // All after 50.0: 50.1, 100.0, 200.0, 999.0
        assert_eq!(indexed.len(), 4);
        // Should be in timestamp order
        for w in indexed.windows(2) {
            assert!(w[0].timestamp <= w[1].timestamp);
        }
    }

    // ---- Fixture-free byte-format / round-trip / duplicate-store pins ----

    /// `att_key` byte format is the literal ASCII
    /// `att:{record_id}:{witness_hash}` with no padding, no length prefix,
    /// and a single ASCII colon between segments. RocksDB CF_ATTESTATIONS
    /// carries a 41-byte prefix extractor (DISC-4 D-8) that depends on this
    /// exact shape — any drift in the separator or prefix would silently
    /// break `prefix_scan` for `get_attestations` / `attestation_count`.
    #[test]
    fn test_batch_b_att_key_byte_format_pin() {
        let key = WitnessManager::att_key("rec_alpha", "wit_x");
        assert_eq!(key, b"att:rec_alpha:wit_x".to_vec());
        // ASCII colon (0x3a) appears exactly twice: after "att" and between id+hash.
        assert_eq!(key.iter().filter(|b| **b == b':').count(), 2);
        // Starts with the ATT_PREFIX constant byte-for-byte.
        assert!(key.starts_with(ATT_PREFIX));
        // 41-byte D-8 extractor is exercised when record_id is 36-char UUIDv7.
        let uuid_key = WitnessManager::att_key("019dc876-a413-7301-aaaa-000000000001", "w");
        assert_eq!(uuid_key.len(), 4 + 36 + 1 + 1, "att:{{36}}:{{1}} = 42 bytes");
    }

    /// `record_prefix` MUST end with a colon. Without the
    /// trailing colon, a prefix scan for record `rec_a` would also match
    /// `rec_ab`, `rec_abc`, etc. This colon is the per-record isolation
    /// guarantee the D-10 hot path relies on.
    #[test]
    fn test_batch_b_record_prefix_trailing_colon_pin() {
        let p = WitnessManager::record_prefix("rec_a");
        assert_eq!(p, b"att:rec_a:".to_vec());
        assert_eq!(*p.last().unwrap(), b':', "record_prefix must end in ':'");
        // record_prefix for "rec_a" must NOT be a byte-prefix of an att_key
        // for record_id "rec_ab" — the trailing ':' enforces this.
        let key_for_rec_ab = WitnessManager::att_key("rec_ab", "wit_1");
        assert!(!key_for_rec_ab.starts_with(&p),
            "prefix 'att:rec_a:' must not match 'att:rec_ab:wit_1'");
        // But it MUST be a byte-prefix of the matching record's att_key.
        let key_for_rec_a = WitnessManager::att_key("rec_a", "wit_1");
        assert!(key_for_rec_a.starts_with(&p));
    }

    /// `time_idx_key` puts an 8-byte big-endian f64 at the
    /// front so RocksDB's byte-order scan IS the chronological-order scan.
    /// Pin: a key at ts=100.0 must compare strictly less than ts=200.0,
    /// independent of record_id / witness_hash content. This is the
    /// invariant `get_attestations_since` and `range_scan_cf_reverse` rely on
    /// — break it and `get_latest_attestations` returns garbage order.
    #[test]
    fn test_batch_b_time_idx_key_big_endian_chronological() {
        let k_early = WitnessManager::time_idx_key(100.0, "zzz_late", "wit");
        let k_late = WitnessManager::time_idx_key(200.0, "aaa_early", "wit");
        assert!(k_early < k_late,
            "earlier timestamp must sort first regardless of suffix content");
        // Pin the exact first-8-bytes encoding.
        assert_eq!(&k_early[..8], &100.0f64.to_be_bytes());
        assert_eq!(&k_late[..8], &200.0f64.to_be_bytes());
        // After 8-byte ts comes record_id + ':' + witness_hash (no other separator).
        assert_eq!(&k_early[8..], b"zzz_late:wit");
        // Total length = 8 + record_id.len() + 1 + witness_hash.len()
        assert_eq!(k_early.len(), 8 + "zzz_late".len() + 1 + "wit".len());
    }

    /// `AttestationRecord::from_data` round-trips every
    /// field of `AttestationData` field-by-field — including the three
    /// `Option<…>` fields (witness_public_key, powas_nonce, powas_difficulty).
    /// If a future refactor drops a field from the public AttestationRecord
    /// or silently transforms an Option, this test catches the divergence
    /// before it ships to the JSON wire surface in routes/explorer.
    #[test]
    fn test_batch_b_attestation_record_from_data_field_roundtrip() {
        let data = AttestationData {
            record_id: "rec_xyz".to_string(),
            witness_hash: "hash_42".to_string(),
            signature: vec![0xde, 0xad, 0xbe, 0xef],
            timestamp: 1234.567,
            witness_public_key: Some(vec![1, 2, 3]),
            powas_nonce: Some(987654321u64),
            powas_difficulty: Some(64u64),
        };
        let rec = AttestationRecord::from_data(data);
        assert_eq!(rec.record_id, "rec_xyz");
        assert_eq!(rec.witness_hash, "hash_42");
        assert_eq!(rec.signature, vec![0xde, 0xad, 0xbe, 0xef]);
        assert!((rec.timestamp - 1234.567).abs() < 1e-9);
        assert_eq!(rec.witness_public_key, Some(vec![1, 2, 3]));
        assert_eq!(rec.powas_nonce, Some(987654321u64));
        assert_eq!(rec.powas_difficulty, Some(64u64));

        // None-side of the three Options also flows through unchanged.
        let none_data = AttestationData {
            record_id: "r".to_string(),
            witness_hash: "w".to_string(),
            signature: vec![],
            timestamp: 0.0,
            witness_public_key: None,
            powas_nonce: None,
            powas_difficulty: None,
        };
        let none_rec = AttestationRecord::from_data(none_data);
        assert!(none_rec.witness_public_key.is_none());
        assert!(none_rec.powas_nonce.is_none());
        assert!(none_rec.powas_difficulty.is_none());
    }

    /// `store_attestation` returns Ok(false) on duplicate
    /// (same record_id + witness_hash) AND must NOT overwrite the original
    /// signature/timestamp. The "first write wins" contract is the basis
    /// of attestation idempotency under gossip-flood replay.
    ///
    /// Uses a 36-char UUIDv7 record_id so CF_ATTESTATIONS' 41-byte prefix
    /// extractor (DISC-4 D-8) is in-domain for `get_attestations` /
    /// `attestation_count` — short IDs return empty (separate invariant).
    #[test]
    fn test_batch_b_duplicate_store_returns_false_and_preserves_first() {
        let (mgr, _dir) = test_mgr();
        let dup_id = "019dc876-a413-73dd-dddd-000000000001";
        assert_eq!(dup_id.len(), 36);

        let first = mgr.store_attestation(dup_id, "wit_x", b"FIRST_SIG", 100.0, None).unwrap();
        assert!(first, "first store must succeed (Ok(true))");

        // Second store with same (record_id, witness_hash) — DIFFERENT sig + ts —
        // must report duplicate and leave the first row intact.
        let second = mgr.store_attestation(dup_id, "wit_x", b"SECOND_SIG", 999.0, None).unwrap();
        assert!(!second, "duplicate store must return Ok(false)");

        // Verify the original signature and timestamp were preserved.
        let rows = mgr.get_attestations(dup_id).unwrap();
        assert_eq!(rows.len(), 1, "still exactly one attestation row");
        assert_eq!(rows[0].signature, b"FIRST_SIG".to_vec(),
            "first signature must be preserved (no silent overwrite)");
        assert!((rows[0].timestamp - 100.0).abs() < 1e-9,
            "first timestamp must be preserved");
        // attestation_count agrees: still 1.
        assert_eq!(mgr.attestation_count(dup_id).unwrap(), 1);
    }
}
