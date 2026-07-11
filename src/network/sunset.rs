//! Algorithm sunset enforcement — Protocol v0.6.1 Section 11.29.
//!
//! Sunset records deprecate cryptographic algorithms after a specified epoch.
//! When a new record arrives signed with a deprecated algorithm and its epoch
//! exceeds the effective sunset epoch, the record is rejected during gossip.
//!
//! Sunset records are regular `ValidationRecord`s with `sunset_op` metadata,
//! following the same pattern as ledger ops (`beat_op`) and epoch seals (`epoch_op`).
//! Only genesis authority can create them.
//!
//! Old records (pre-sunset) remain verifiable for historical purposes but cannot
//! be used as the basis for new claims.

//!
//! Spec references:
//!   @spec Protocol §11.29
//!   @spec Protocol §4.4

use std::collections::HashMap;

use tracing::info;
#[cfg(test)]
use tracing::warn;

use crate::errors::{ElaraError, Result};
use crate::record::ValidationRecord;
#[cfg(test)]
use crate::storage::Storage;
use crate::accounting::types::creator_identity_hash;

// ─── Constants ─────────────────────────────────────────────────────────────

pub const SUNSET_OP_KEY: &str = "sunset_op";

/// Algorithm status values.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AlgorithmStatus {
    /// Algorithm is fully supported.
    Active,
    /// Algorithm is deprecated — new records rejected after effective_epoch.
    Deprecated,
    /// Algorithm is forbidden — all verification disabled (emergency).
    Forbidden,
}

impl AlgorithmStatus {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "ACTIVE" => Some(Self::Active),
            "DEPRECATED" => Some(Self::Deprecated),
            "FORBIDDEN" => Some(Self::Forbidden),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Deprecated => "DEPRECATED",
            Self::Forbidden => "FORBIDDEN",
        }
    }
}

// ─── Sunset entry ──────────────────────────────────────────────────────────

/// A parsed algorithm sunset record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SunsetEntry {
    /// Algorithm identifier (e.g. "dilithium3", "sphincs-sha2-192f").
    pub algorithm: String,
    /// New status for this algorithm.
    pub status: AlgorithmStatus,
    /// Epoch after which the sunset takes effect.
    pub effective_epoch: u64,
    /// Human-readable reason for the sunset.
    pub reason: String,
}

// ─── State tracking ────────────────────────────────────────────────────────

/// Tracks algorithm sunset decisions. Maintained in memory, rebuilt from
/// storage on startup.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SunsetState {
    /// Algorithm name → latest sunset entry.
    entries: HashMap<String, SunsetEntry>,
}

impl SunsetState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a single record during streaming rebuild. Checks for sunset_op
    /// metadata from genesis authority. O(1) per record.
    pub fn process_record(&mut self, rec: &crate::record::ValidationRecord, genesis_authority: &str) {
        if rec.metadata.contains_key(SUNSET_OP_KEY) {
            if let Ok(Some(entry)) = extract_sunset(rec) {
                if crate::accounting::types::creator_identity_hash(rec) == genesis_authority {
                    self.register(entry);
                }
            }
        }
    }

    /// Register a sunset entry. Later entries override earlier ones for the
    /// same algorithm (allows re-activating a previously deprecated algo).
    pub fn register(&mut self, entry: SunsetEntry) {
        info!(
            "algorithm sunset registered: {} → {} at epoch {}",
            entry.algorithm,
            entry.status.as_str(),
            entry.effective_epoch
        );
        self.entries.insert(entry.algorithm.clone(), entry);
    }

    /// Check if an algorithm is allowed for new records at the given epoch.
    ///
    /// Returns `Ok(())` if allowed, `Err` with reason if rejected.
    pub fn check_algorithm(&self, algorithm: &str, current_epoch: u64) -> Result<()> {
        if let Some(entry) = self.entries.get(algorithm) {
            match entry.status {
                AlgorithmStatus::Active => Ok(()),
                AlgorithmStatus::Deprecated => {
                    if current_epoch >= entry.effective_epoch {
                        Err(ElaraError::Wire(format!(
                            "algorithm '{}' deprecated at epoch {} (reason: {})",
                            algorithm, entry.effective_epoch, entry.reason
                        )))
                    } else {
                        Ok(()) // Not yet effective
                    }
                }
                AlgorithmStatus::Forbidden => {
                    Err(ElaraError::Wire(format!(
                        "algorithm '{}' forbidden (reason: {})",
                        algorithm, entry.reason
                    )))
                }
            }
        } else {
            Ok(()) // Unknown algorithm = allowed (no sunset registered)
        }
    }

    /// Get all sunset entries (for API/metrics).
    pub fn entries(&self) -> &HashMap<String, SunsetEntry> {
        &self.entries
    }

    /// Number of tracked algorithms.
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

// ─── Metadata helpers ──────────────────────────────────────────────────────

/// Build metadata for a sunset record.
pub fn sunset_metadata(
    algorithm: &str,
    status: &AlgorithmStatus,
    effective_epoch: u64,
    reason: &str,
) -> std::collections::BTreeMap<String, String> {
    let mut meta = std::collections::BTreeMap::new();
    meta.insert(SUNSET_OP_KEY.to_string(), "deprecate".to_string());
    meta.insert("sunset_algorithm".to_string(), algorithm.to_string());
    meta.insert("sunset_status".to_string(), status.as_str().to_string());
    meta.insert("sunset_effective_epoch".to_string(), effective_epoch.to_string());
    meta.insert("sunset_reason".to_string(), reason.to_string());
    meta
}

/// Extract a sunset entry from a record's metadata.
/// Returns `Ok(None)` if the record is not a sunset record.
pub fn extract_sunset(record: &ValidationRecord) -> Result<Option<SunsetEntry>> {
    let op = match record.metadata.get(SUNSET_OP_KEY).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Ok(None),
    };

    if op != "deprecate" {
        return Err(ElaraError::Wire(format!("unknown sunset_op: {op}")));
    }

    let algorithm = record
        .metadata
        .get("sunset_algorithm")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| ElaraError::Wire("missing sunset_algorithm".into()))?;

    let status_str = record
        .metadata
        .get("sunset_status")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ElaraError::Wire("missing sunset_status".into()))?;

    let status = AlgorithmStatus::from_str(status_str)
        .ok_or_else(|| ElaraError::Wire(format!("invalid sunset_status: {status_str}")))?;

    let effective_epoch = record
        .metadata
        .get("sunset_effective_epoch")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| ElaraError::Wire("missing/invalid sunset_effective_epoch".into()))?;

    let reason = record
        .metadata
        .get("sunset_reason")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default();

    Ok(Some(SunsetEntry {
        algorithm,
        status,
        effective_epoch,
        reason,
    }))
}

/// Verify a sunset record: must be from genesis authority.
pub fn verify_sunset(
    record: &ValidationRecord,
    genesis_authority: &str,
) -> Result<SunsetEntry> {
    let creator = creator_identity_hash(record);
    if creator != genesis_authority {
        return Err(ElaraError::Wire(format!(
            "sunset record not from genesis authority (creator={})",
            &creator[..creator.len().min(16)]
        )));
    }

    extract_sunset(record)?
        .ok_or_else(|| ElaraError::Wire("not a sunset record".into()))
}

/// Rebuild sunset state from storage by scanning all records.
///
/// This helper is `cfg(test)`-gated. The unbounded `query(usize::MAX)` materializes
/// every record on the chain (~80 GB at 10M records) and would OOM any node.
/// Production boot uses `rebuild_sunset_state_from_records` driven by the
/// streaming `for_each_record_ordered_bounded` callback in `bin/elara_node.rs`.
/// Keep this helper only for unit tests that build a small in-memory fixture.
#[cfg(test)]
pub fn rebuild_sunset_state(storage: &dyn Storage, genesis_authority: &str) -> SunsetState {
    match storage.query(None, None, None, None, usize::MAX) {
        Ok(records) => rebuild_sunset_state_from_records(&records, genesis_authority),
        Err(e) => {
            warn!("failed to rebuild sunset state: {e}");
            SunsetState::new()
        }
    }
}

/// Rebuild sunset state from a pre-loaded record slice (single-pass startup).
pub fn rebuild_sunset_state_from_records(all_records: &[ValidationRecord], genesis_authority: &str) -> SunsetState {
    let mut state = SunsetState::new();
    let mut count = 0;
    for record in all_records {
        if record.metadata.contains_key(SUNSET_OP_KEY) {
            if let Ok(Some(entry)) = extract_sunset(record) {
                // Only trust sunset records from genesis authority
                if creator_identity_hash(record) == genesis_authority {
                    state.register(entry);
                    count += 1;
                }
            }
        }
    }
    if count > 0 {
        info!("rebuilt sunset state: {count} sunset records");
    }
    state
}

// ─── Algorithm detection ───────────────────────────────────────────────────

/// Detect the signature algorithm used by a record.
///
/// Currently all records use Dilithium3. When new algorithms are added,
/// this function should inspect the record's metadata or wire format.
pub fn record_algorithm(_record: &ValidationRecord) -> &'static str {
    // All current records use Dilithium3
    // Future: check record metadata for algorithm field
    "dilithium3"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Classification;

    /// Create a minimal test record with empty metadata.
    fn test_record() -> ValidationRecord {
        ValidationRecord::create(
            b"test",
            vec![0u8; 32],
            vec![],
            Classification::Public,
            None,
        )
    }

    /// Create a test record with pre-populated metadata.
    fn test_record_with_meta(meta: std::collections::BTreeMap<String, String>) -> ValidationRecord {
        let json_meta: std::collections::BTreeMap<String, serde_json::Value> = meta
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        ValidationRecord::create(
            b"test",
            vec![0u8; 32],
            vec![],
            Classification::Public,
            Some(json_meta),
        )
    }

    #[test]
    fn test_sunset_state_new() {
        let state = SunsetState::new();
        assert_eq!(state.count(), 0);
        assert!(state.check_algorithm("dilithium3", 0).is_ok());
    }

    #[test]
    fn test_sunset_register_deprecated() {
        let mut state = SunsetState::new();
        state.register(SunsetEntry {
            algorithm: "old_algo".to_string(),
            status: AlgorithmStatus::Deprecated,
            effective_epoch: 100,
            reason: "broken".to_string(),
        });

        // Before effective epoch — allowed
        assert!(state.check_algorithm("old_algo", 99).is_ok());
        // At effective epoch — rejected
        assert!(state.check_algorithm("old_algo", 100).is_err());
        // After effective epoch — rejected
        assert!(state.check_algorithm("old_algo", 200).is_err());
        // Different algorithm — allowed
        assert!(state.check_algorithm("dilithium3", 200).is_ok());
    }

    #[test]
    fn test_sunset_register_forbidden() {
        let mut state = SunsetState::new();
        state.register(SunsetEntry {
            algorithm: "broken_algo".to_string(),
            status: AlgorithmStatus::Forbidden,
            effective_epoch: 0,
            reason: "emergency".to_string(),
        });

        // Forbidden at any epoch
        assert!(state.check_algorithm("broken_algo", 0).is_err());
        assert!(state.check_algorithm("broken_algo", 999).is_err());
    }

    #[test]
    fn test_sunset_reactivate() {
        let mut state = SunsetState::new();

        // First: deprecate
        state.register(SunsetEntry {
            algorithm: "algo_x".to_string(),
            status: AlgorithmStatus::Deprecated,
            effective_epoch: 50,
            reason: "suspected weakness".to_string(),
        });
        assert!(state.check_algorithm("algo_x", 100).is_err());

        // Then: re-activate (new analysis shows it's fine)
        state.register(SunsetEntry {
            algorithm: "algo_x".to_string(),
            status: AlgorithmStatus::Active,
            effective_epoch: 0,
            reason: "re-evaluated, safe".to_string(),
        });
        assert!(state.check_algorithm("algo_x", 100).is_ok());
    }

    #[test]
    fn test_sunset_unknown_algorithm() {
        let state = SunsetState::new();
        // Unknown algorithms are allowed (no sunset registered)
        assert!(state.check_algorithm("future_algo", 999).is_ok());
    }

    #[test]
    fn test_sunset_metadata_roundtrip() {
        let meta = sunset_metadata(
            "dilithium3",
            &AlgorithmStatus::Deprecated,
            10000,
            "lattice cryptanalysis advance",
        );

        assert_eq!(meta.get(SUNSET_OP_KEY).unwrap(), "deprecate");
        assert_eq!(meta.get("sunset_algorithm").unwrap(), "dilithium3");
        assert_eq!(meta.get("sunset_status").unwrap(), "DEPRECATED");
        assert_eq!(meta.get("sunset_effective_epoch").unwrap(), "10000");
        assert_eq!(meta.get("sunset_reason").unwrap(), "lattice cryptanalysis advance");
    }

    #[test]
    fn test_extract_sunset_none() {
        let record = test_record();
        assert!(extract_sunset(&record).unwrap().is_none());
    }

    #[test]
    fn test_extract_sunset_valid() {
        let meta = sunset_metadata("dilithium3", &AlgorithmStatus::Deprecated, 5000, "test");
        let record = test_record_with_meta(meta);

        let entry = extract_sunset(&record).unwrap().unwrap();
        assert_eq!(entry.algorithm, "dilithium3");
        assert_eq!(entry.status, AlgorithmStatus::Deprecated);
        assert_eq!(entry.effective_epoch, 5000);
        assert_eq!(entry.reason, "test");
    }

    #[test]
    fn test_extract_sunset_invalid_status() {
        let mut meta = std::collections::BTreeMap::new();
        meta.insert(SUNSET_OP_KEY.to_string(), "deprecate".to_string());
        meta.insert("sunset_algorithm".to_string(), "dilithium3".to_string());
        meta.insert("sunset_status".to_string(), "UNKNOWN".to_string());
        meta.insert("sunset_effective_epoch".to_string(), "100".to_string());
        let record = test_record_with_meta(meta);

        assert!(extract_sunset(&record).is_err());
    }

    #[test]
    fn test_extract_sunset_missing_algorithm() {
        let mut meta = std::collections::BTreeMap::new();
        meta.insert(SUNSET_OP_KEY.to_string(), "deprecate".to_string());
        meta.insert("sunset_status".to_string(), "DEPRECATED".to_string());
        meta.insert("sunset_effective_epoch".to_string(), "100".to_string());
        let record = test_record_with_meta(meta);

        assert!(extract_sunset(&record).is_err());
    }

    #[test]
    fn test_algorithm_status_from_str() {
        assert_eq!(AlgorithmStatus::from_str("ACTIVE"), Some(AlgorithmStatus::Active));
        assert_eq!(AlgorithmStatus::from_str("deprecated"), Some(AlgorithmStatus::Deprecated));
        assert_eq!(AlgorithmStatus::from_str("FORBIDDEN"), Some(AlgorithmStatus::Forbidden));
        assert_eq!(AlgorithmStatus::from_str("bogus"), None);
    }

    #[test]
    fn test_record_algorithm() {
        let record = test_record();
        assert_eq!(record_algorithm(&record), "dilithium3");
    }

    #[test]
    fn test_verify_sunset_wrong_authority() {
        let meta = sunset_metadata("dilithium3", &AlgorithmStatus::Deprecated, 100, "test");
        let record = test_record_with_meta(meta);
        // Record creator is from test key, genesis is something else
        assert!(verify_sunset(&record, "genesis_hash_abc").is_err());
    }

    #[test]
    fn test_process_record_genesis_authority() {
        let mut state = SunsetState::new();
        let meta = sunset_metadata("dilithium3", &AlgorithmStatus::Deprecated, 1000, "lattice attack");
        let record = test_record_with_meta(meta);
        let genesis = creator_identity_hash(&record);

        state.process_record(&record, &genesis);

        assert_eq!(state.count(), 1);
        let entry = state.entries().get("dilithium3").unwrap();
        assert_eq!(entry.status, AlgorithmStatus::Deprecated);
        assert_eq!(entry.effective_epoch, 1000);
        assert!(state.check_algorithm("dilithium3", 1000).is_err());
    }

    #[test]
    fn test_process_record_non_genesis_ignored() {
        let mut state = SunsetState::new();
        let meta = sunset_metadata("dilithium3", &AlgorithmStatus::Forbidden, 0, "fake attack");
        let record = test_record_with_meta(meta);

        // Genesis authority is some OTHER hash — not this record's creator.
        // Security boundary: non-genesis sunset records must be silently ignored.
        state.process_record(&record, "different_genesis_hash_abcdef0123456789");

        assert_eq!(state.count(), 0);
        assert!(state.check_algorithm("dilithium3", 100).is_ok());
    }

    #[test]
    fn test_rebuild_from_records_latest_wins() {
        // Streaming-rebuild semantics: when multiple sunset records exist for the
        // same algorithm, register() inserts into a HashMap so the LAST record
        // applied wins. Verifies the boot-time rebuild path matches the
        // re-activation behaviour exercised by test_sunset_reactivate.
        let r1 = test_record_with_meta(sunset_metadata(
            "algo_x",
            &AlgorithmStatus::Deprecated,
            10,
            "suspected weakness",
        ));
        let r2 = test_record_with_meta(sunset_metadata(
            "algo_x",
            &AlgorithmStatus::Active,
            20,
            "re-evaluated, safe",
        ));
        let genesis = creator_identity_hash(&r1);

        let state = rebuild_sunset_state_from_records(&[r1, r2], &genesis);

        assert_eq!(state.count(), 1);
        assert_eq!(state.entries().get("algo_x").unwrap().status, AlgorithmStatus::Active);
        assert!(state.check_algorithm("algo_x", 100).is_ok());
    }

    // ─── fixture-free axes ────────────────────────
    // Pins surface invariants not covered by the legacy tests above:
    //  (1) SUNSET_OP_KEY strict-pin + cross-module disjointness
    //  (2) AlgorithmStatus 3-variant exhaustive (serde + from_str/as_str + pairwise)
    //  (3) check_algorithm() epoch-boundary matrix (>= effective is STRICT)
    //  (4) sunset_metadata exact 5-key shape + extract_sunset negative-path matrix
    //  (5) SunsetState register override + serde + rebuild + record_algorithm const

    #[test]
    fn batch_b_sunset_op_key_strict_pin_and_cross_module_disjointness() {
        // SUNSET_OP_KEY="sunset_op" — 9-char strict pin.
        assert_eq!(SUNSET_OP_KEY, "sunset_op",
            "SUNSET_OP_KEY strict-pin (chain-breaking if changed — drift between encoder/decoder mis-dispatches records)");
        assert_eq!(SUNSET_OP_KEY.len(), 9,
            "SUNSET_OP_KEY length pin");

        // ASCII lowercase snake_case.
        assert!(SUNSET_OP_KEY.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "SUNSET_OP_KEY must be ASCII lowercase + underscore");
        assert!(!SUNSET_OP_KEY.starts_with('_'),
            "SUNSET_OP_KEY must not lead with underscore");
        assert!(!SUNSET_OP_KEY.ends_with('_'),
            "SUNSET_OP_KEY must not trail underscore");
        assert!(SUNSET_OP_KEY.contains('_'),
            "SUNSET_OP_KEY has snake_case form (single underscore)");
        assert_eq!(SUNSET_OP_KEY.matches('_').count(), 1,
            "SUNSET_OP_KEY has exactly 1 underscore");

        // The 5 metadata keys this module owns (4 sub-keys + the op-key itself).
        // sunset_metadata writes exactly these 5 keys; pin the set so a refactor
        // can't silently add/rename a key without forcing the test to update.
        let sunset_meta_keys = [
            SUNSET_OP_KEY,
            "sunset_algorithm",
            "sunset_status",
            "sunset_effective_epoch",
            "sunset_reason",
        ];
        for k in sunset_meta_keys {
            assert!(k.starts_with("sunset_") || k == SUNSET_OP_KEY,
                "all sunset module keys live under the 'sunset_' namespace: {k}");
        }
        // Pairwise distinct within the sunset namespace.
        for (i, k1) in sunset_meta_keys.iter().enumerate() {
            for (j, k2) in sunset_meta_keys.iter().enumerate() {
                if i != j {
                    assert_ne!(k1, k2,
                        "sunset metadata keys pairwise distinct: ({k1}, {k2})");
                }
            }
        }

        // Cross-module disjointness vs other op-keys that live in the same
        // metadata namespace and would mis-dispatch records on collision.
        let cross_module_op_keys = [
            crate::network::dispute::DISPUTE_OP_KEY,
            crate::collaboration::COLLABORATION_OP_KEY,
            crate::seed_vault::SEED_VAULT_OP_KEY,
            crate::succession::SUCCESSION_OP_KEY,
        ];
        for other in cross_module_op_keys {
            assert_ne!(SUNSET_OP_KEY, other,
                "SUNSET_OP_KEY must NOT collide with {other}");
            assert!(!SUNSET_OP_KEY.starts_with(other) && !other.starts_with(SUNSET_OP_KEY),
                "neither SUNSET_OP_KEY nor {other} may be a prefix of the other (substring-misdispatch defense)");
        }
    }

    #[test]
    fn batch_b_algorithm_status_3_variant_exhaustive_serde_screaming_snake_and_from_str_as_str() {
        let variants = [
            AlgorithmStatus::Active,
            AlgorithmStatus::Deprecated,
            AlgorithmStatus::Forbidden,
        ];
        assert_eq!(variants.len(), 3,
            "AlgorithmStatus has EXACTLY 3 variants");

        // Pairwise 3x3 PartialEq distinctness (derive #[PartialEq, Eq]).
        for (i, vi) in variants.iter().enumerate() {
            for (j, vj) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(vi, vj);
                } else {
                    assert_ne!(vi, vj,
                        "AlgorithmStatus pairwise distinct: ({vi:?}, {vj:?})");
                }
            }
        }

        // as_str() exhaustive — SCREAMING_SNAKE_CASE labels.
        assert_eq!(AlgorithmStatus::Active.as_str(), "ACTIVE");
        assert_eq!(AlgorithmStatus::Deprecated.as_str(), "DEPRECATED");
        assert_eq!(AlgorithmStatus::Forbidden.as_str(), "FORBIDDEN");

        // Labels pairwise distinct.
        let labels: Vec<&str> = variants.iter().map(|v| v.as_str()).collect();
        for (i, l1) in labels.iter().enumerate() {
            for (j, l2) in labels.iter().enumerate() {
                if i != j {
                    assert_ne!(l1, l2,
                        "as_str labels pairwise distinct");
                }
            }
        }

        // All labels ASCII uppercase (SCREAMING_SNAKE_CASE).
        for s in &labels {
            assert!(s.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                "label must be ASCII uppercase + underscore: {s}");
            assert!(!s.is_empty());
            assert!(!s.starts_with('_'));
            assert!(!s.ends_with('_'));
        }

        // serde JSON wire-format pin — rename_all = "SCREAMING_SNAKE_CASE".
        // Each variant serializes to its uppercase label as a bare string.
        assert_eq!(
            serde_json::to_string(&AlgorithmStatus::Active).unwrap(),
            "\"ACTIVE\"",
            "JSON tag for Active");
        assert_eq!(
            serde_json::to_string(&AlgorithmStatus::Deprecated).unwrap(),
            "\"DEPRECATED\"");
        assert_eq!(
            serde_json::to_string(&AlgorithmStatus::Forbidden).unwrap(),
            "\"FORBIDDEN\"");

        // serde JSON round-trip per variant.
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let parsed: AlgorithmStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, *v,
                "JSON round-trip preserves variant: {v:?}");
        }

        // from_str() case-INSENSITIVE (per source line 50: `s.to_uppercase()`).
        for input in ["ACTIVE", "active", "Active", "AcTiVe"] {
            assert_eq!(AlgorithmStatus::from_str(input), Some(AlgorithmStatus::Active),
                "from_str case-insensitive for input: {input}");
        }
        for input in ["DEPRECATED", "deprecated", "Deprecated"] {
            assert_eq!(AlgorithmStatus::from_str(input), Some(AlgorithmStatus::Deprecated));
        }
        for input in ["FORBIDDEN", "forbidden", "Forbidden"] {
            assert_eq!(AlgorithmStatus::from_str(input), Some(AlgorithmStatus::Forbidden));
        }

        // from_str() negative matrix.
        for input in ["", "bogus", "INACTIVE", "UNDEPRECATED", "DEPRECATE"] {
            assert_eq!(AlgorithmStatus::from_str(input), None,
                "from_str rejects unknown variant: {input}");
        }

        // Debug rendering preserves variant names.
        assert!(format!("{:?}", AlgorithmStatus::Active).contains("Active"));
        assert!(format!("{:?}", AlgorithmStatus::Deprecated).contains("Deprecated"));
        assert!(format!("{:?}", AlgorithmStatus::Forbidden).contains("Forbidden"));

        // Clone semantics (derived).
        let original = AlgorithmStatus::Deprecated;
        let cloned = original.clone();
        assert_eq!(cloned, original);
    }

    #[test]
    fn batch_b_check_algorithm_epoch_boundary_strict_gte_matrix() {
        // check_algorithm() epoch-gate matrix:
        //   Active                -> Ok at any epoch
        //   Deprecated, e>=eff    -> Err
        //   Deprecated, e< eff    -> Ok
        //   Forbidden             -> Err at any epoch
        //   Unknown algorithm     -> Ok (not registered = no gate)
        let mut state = SunsetState::new();

        // ── Active: Ok at every epoch ─────────────────────────────────
        state.register(SunsetEntry {
            algorithm: "active_algo".to_string(),
            status: AlgorithmStatus::Active,
            effective_epoch: 100, // effective_epoch is moot for Active
            reason: "fully supported".to_string(),
        });
        for e in [0u64, 1, 99, 100, 101, 1_000, u64::MAX] {
            assert!(state.check_algorithm("active_algo", e).is_ok(),
                "Active is Ok at epoch {e} regardless of effective_epoch");
        }

        // ── Deprecated: STRICT >= effective_epoch is the rejection gate ─
        state.register(SunsetEntry {
            algorithm: "depr_algo".to_string(),
            status: AlgorithmStatus::Deprecated,
            effective_epoch: 100,
            reason: "weakness found".to_string(),
        });
        // Before effective: Ok.
        assert!(state.check_algorithm("depr_algo", 0).is_ok());
        assert!(state.check_algorithm("depr_algo", 99).is_ok(),
            "deprecated allowed at epoch effective-1");
        // At exact effective: REJECT (>= boundary is STRICT).
        let err = state.check_algorithm("depr_algo", 100).unwrap_err();
        let err_msg = format!("{err:?}");
        assert!(err_msg.contains("depr_algo"),
            "error message contains algorithm name: {err_msg}");
        assert!(err_msg.contains("100"),
            "error message contains effective epoch: {err_msg}");
        assert!(err_msg.contains("weakness found"),
            "error message contains reason: {err_msg}");
        // After effective: REJECT.
        assert!(state.check_algorithm("depr_algo", 101).is_err());
        assert!(state.check_algorithm("depr_algo", 200).is_err());
        assert!(state.check_algorithm("depr_algo", u64::MAX).is_err(),
            "deprecated rejected at epoch u64::MAX");

        // ── Forbidden: Err at every epoch including epoch 0 ───────────
        state.register(SunsetEntry {
            algorithm: "forbid_algo".to_string(),
            status: AlgorithmStatus::Forbidden,
            effective_epoch: 999, // effective_epoch is moot for Forbidden
            reason: "totally broken".to_string(),
        });
        for e in [0u64, 1, 998, 999, 1000, u64::MAX] {
            let r = state.check_algorithm("forbid_algo", e);
            assert!(r.is_err(),
                "Forbidden rejects at epoch {e}");
            let msg = format!("{:?}", r.unwrap_err());
            assert!(msg.contains("forbid_algo"),
                "Forbidden err includes algorithm name");
            assert!(msg.contains("totally broken"),
                "Forbidden err includes reason");
        }

        // ── Unknown algorithm: Ok ──────────────────────────────────────
        for algo in ["unknown1", "future_algo", "", "DILITHIUM5"] {
            assert!(state.check_algorithm(algo, 0).is_ok(),
                "unknown algorithm {algo} -> Ok (no sunset registered)");
            assert!(state.check_algorithm(algo, u64::MAX).is_ok());
        }

        // ── Boundary regression: effective_epoch = 0 with Deprecated ──
        // current_epoch >= 0 is ALWAYS true, so Deprecated with effective_epoch=0
        // rejects every epoch including 0 itself.
        let mut state2 = SunsetState::new();
        state2.register(SunsetEntry {
            algorithm: "depr0".to_string(),
            status: AlgorithmStatus::Deprecated,
            effective_epoch: 0,
            reason: "immediate deprecation".to_string(),
        });
        assert!(state2.check_algorithm("depr0", 0).is_err(),
            "Deprecated@0 rejects at epoch 0 (0 >= 0 STRICT)");
        assert!(state2.check_algorithm("depr0", 1).is_err());
    }

    #[test]
    fn batch_b_sunset_metadata_5_key_shape_and_extract_negative_path_matrix() {
        // sunset_metadata writes EXACTLY 5 BTreeMap keys.
        let meta = sunset_metadata(
            "dilithium3",
            &AlgorithmStatus::Deprecated,
            12345,
            "test reason",
        );
        assert_eq!(meta.len(), 5,
            "sunset_metadata has EXACTLY 5 keys");
        assert!(meta.contains_key(SUNSET_OP_KEY));
        assert!(meta.contains_key("sunset_algorithm"));
        assert!(meta.contains_key("sunset_status"));
        assert!(meta.contains_key("sunset_effective_epoch"));
        assert!(meta.contains_key("sunset_reason"));

        // op-value is "deprecate" literal.
        assert_eq!(meta.get(SUNSET_OP_KEY).unwrap(), "deprecate",
            "op-value pin: SUNSET_OP_KEY -> 'deprecate'");

        // Status serialized as SCREAMING_SNAKE_CASE label.
        assert_eq!(meta.get("sunset_status").unwrap(), "DEPRECATED",
            "status serialized as SCREAMING_SNAKE_CASE");

        // effective_epoch serialized as u64.to_string().
        assert_eq!(meta.get("sunset_effective_epoch").unwrap(), "12345");

        // BTreeMap iteration is ASCII-sorted by key.
        let keys: Vec<&str> = meta.keys().map(|s| s.as_str()).collect();
        let mut sorted_keys = keys.clone();
        sorted_keys.sort();
        assert_eq!(keys, sorted_keys,
            "BTreeMap iteration is ASCII-sorted by key");

        // Round-trip through extract_sunset.
        let record = test_record_with_meta(meta);
        let entry = extract_sunset(&record).unwrap().unwrap();
        assert_eq!(entry.algorithm, "dilithium3");
        assert_eq!(entry.status, AlgorithmStatus::Deprecated);
        assert_eq!(entry.effective_epoch, 12345);
        assert_eq!(entry.reason, "test reason");

        // ── extract_sunset negative path matrix ────────────────────────
        // (a) Empty metadata -> Ok(None) (not a sunset record).
        let r = test_record();
        assert!(matches!(extract_sunset(&r), Ok(None)),
            "record without SUNSET_OP_KEY -> Ok(None)");

        // (b) Op-key present but op-value NOT "deprecate" -> Err.
        let mut m = std::collections::BTreeMap::new();
        m.insert(SUNSET_OP_KEY.to_string(), "unknown_op".to_string());
        let r = test_record_with_meta(m);
        let res = extract_sunset(&r);
        assert!(res.is_err(),
            "unknown op-value rejected");
        let msg = format!("{:?}", res.unwrap_err());
        assert!(msg.contains("unknown sunset_op"));

        // (c) Missing sunset_algorithm.
        let mut m = std::collections::BTreeMap::new();
        m.insert(SUNSET_OP_KEY.to_string(), "deprecate".to_string());
        m.insert("sunset_status".to_string(), "DEPRECATED".to_string());
        m.insert("sunset_effective_epoch".to_string(), "100".to_string());
        let r = test_record_with_meta(m);
        let err = extract_sunset(&r).unwrap_err();
        assert!(format!("{err:?}").contains("missing sunset_algorithm"));

        // (d) Missing sunset_status.
        let mut m = std::collections::BTreeMap::new();
        m.insert(SUNSET_OP_KEY.to_string(), "deprecate".to_string());
        m.insert("sunset_algorithm".to_string(), "x".to_string());
        m.insert("sunset_effective_epoch".to_string(), "100".to_string());
        let r = test_record_with_meta(m);
        let err = extract_sunset(&r).unwrap_err();
        assert!(format!("{err:?}").contains("missing sunset_status"));

        // (e) Invalid sunset_status value.
        let mut m = std::collections::BTreeMap::new();
        m.insert(SUNSET_OP_KEY.to_string(), "deprecate".to_string());
        m.insert("sunset_algorithm".to_string(), "x".to_string());
        m.insert("sunset_status".to_string(), "BOGUS".to_string());
        m.insert("sunset_effective_epoch".to_string(), "100".to_string());
        let r = test_record_with_meta(m);
        let err = extract_sunset(&r).unwrap_err();
        assert!(format!("{err:?}").contains("invalid sunset_status"));

        // (f) Missing sunset_effective_epoch.
        let mut m = std::collections::BTreeMap::new();
        m.insert(SUNSET_OP_KEY.to_string(), "deprecate".to_string());
        m.insert("sunset_algorithm".to_string(), "x".to_string());
        m.insert("sunset_status".to_string(), "DEPRECATED".to_string());
        let r = test_record_with_meta(m);
        let err = extract_sunset(&r).unwrap_err();
        assert!(format!("{err:?}").contains("missing/invalid sunset_effective_epoch"));

        // (g) Non-numeric sunset_effective_epoch.
        let mut m = std::collections::BTreeMap::new();
        m.insert(SUNSET_OP_KEY.to_string(), "deprecate".to_string());
        m.insert("sunset_algorithm".to_string(), "x".to_string());
        m.insert("sunset_status".to_string(), "DEPRECATED".to_string());
        m.insert("sunset_effective_epoch".to_string(), "not_a_number".to_string());
        let r = test_record_with_meta(m);
        let err = extract_sunset(&r).unwrap_err();
        assert!(format!("{err:?}").contains("missing/invalid sunset_effective_epoch"));

        // (h) Missing reason: unwrap_or_default -> empty string (per source line 218).
        let mut m = std::collections::BTreeMap::new();
        m.insert(SUNSET_OP_KEY.to_string(), "deprecate".to_string());
        m.insert("sunset_algorithm".to_string(), "x".to_string());
        m.insert("sunset_status".to_string(), "ACTIVE".to_string());
        m.insert("sunset_effective_epoch".to_string(), "0".to_string());
        let r = test_record_with_meta(m);
        let entry = extract_sunset(&r).unwrap().unwrap();
        assert_eq!(entry.reason, "",
            "missing reason -> empty string via unwrap_or_default");
    }

    #[test]
    fn batch_b_sunset_state_register_override_serde_roundtrip_and_record_algorithm_const() {
        // SunsetState::new() initial state.
        let s = SunsetState::new();
        assert_eq!(s.count(), 0,
            "new() count == 0");
        assert!(s.entries().is_empty(),
            "new() entries empty");

        // Default::default() (derived) matches new().
        let d = SunsetState::default();
        assert_eq!(d.count(), 0);
        assert_eq!(d.count(), s.count(),
            "default == new()");

        // register() inserts new entries; count grows for distinct algorithms.
        let mut s = SunsetState::new();
        s.register(SunsetEntry {
            algorithm: "a".to_string(),
            status: AlgorithmStatus::Deprecated,
            effective_epoch: 10,
            reason: "r1".to_string(),
        });
        s.register(SunsetEntry {
            algorithm: "b".to_string(),
            status: AlgorithmStatus::Forbidden,
            effective_epoch: 20,
            reason: "r2".to_string(),
        });
        assert_eq!(s.count(), 2,
            "two distinct algorithms -> count == 2");

        // Same-algorithm re-register OVERRIDES (HashMap.insert) and count
        // does NOT grow.
        s.register(SunsetEntry {
            algorithm: "a".to_string(),
            status: AlgorithmStatus::Active,
            effective_epoch: 0,
            reason: "r3-override".to_string(),
        });
        assert_eq!(s.count(), 2,
            "re-register same algorithm -> count unchanged");
        let entry_a = s.entries().get("a").unwrap();
        assert_eq!(entry_a.status, AlgorithmStatus::Active,
            "later register() overrides earlier — re-activation supported");
        assert_eq!(entry_a.reason, "r3-override",
            "all fields overridden, not merged");

        // entries() returns a reference (read-only view).
        let r: &HashMap<String, SunsetEntry> = s.entries();
        assert_eq!(r.len(), 2);

        // serde JSON round-trip preserves all entries (SunsetState derives
        // Serialize/Deserialize on entries: HashMap<String, SunsetEntry>).
        let json = serde_json::to_string(&s).unwrap();
        let parsed: SunsetState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.count(), 2);
        let pa = parsed.entries().get("a").unwrap();
        assert_eq!(pa.status, AlgorithmStatus::Active);
        assert_eq!(pa.reason, "r3-override");
        let pb = parsed.entries().get("b").unwrap();
        assert_eq!(pb.status, AlgorithmStatus::Forbidden);
        assert_eq!(pb.effective_epoch, 20);

        // rebuild_sunset_state_from_records: empty slice -> empty state.
        let empty = rebuild_sunset_state_from_records(&[], "any_genesis");
        assert_eq!(empty.count(), 0,
            "empty records -> empty state");

        // rebuild from non-sunset records -> empty state (no SUNSET_OP_KEY).
        let non_sunset = test_record();
        let genesis = creator_identity_hash(&non_sunset);
        let s = rebuild_sunset_state_from_records(&[non_sunset], &genesis);
        assert_eq!(s.count(), 0,
            "non-sunset records -> empty state");

        // rebuild with WRONG genesis -> sunset record silently ignored.
        let meta = sunset_metadata("x", &AlgorithmStatus::Forbidden, 0, "test");
        let rec = test_record_with_meta(meta);
        let s = rebuild_sunset_state_from_records(&[rec], "different_genesis_hash");
        assert_eq!(s.count(), 0,
            "wrong genesis silently ignores the record");

        // record_algorithm always returns "dilithium3" (currently constant).
        let r1 = test_record();
        assert_eq!(record_algorithm(&r1), "dilithium3",
            "record_algorithm currently returns dilithium3 for every record");
        // Even with sunset metadata, record_algorithm doesn't change.
        let meta = sunset_metadata("sphincs", &AlgorithmStatus::Active, 0, "");
        let r2 = test_record_with_meta(meta);
        assert_eq!(record_algorithm(&r2), "dilithium3",
            "record_algorithm is hardcoded constant; future-multi-algo work will need to extend this");
    }
}
