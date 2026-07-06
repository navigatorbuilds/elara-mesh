//! Key rotation & revocation.
//!
//! ⚠ IMPLEMENTATION STATUS (2026-07-04, findings KR-2/KR-3): key ROTATION is
//! **specified but NOT yet operational** — do not rely on it. Two gaps.
//!
//! KR-2: the active-key / grace-window validators in this module
//! (`is_key_valid`, `active_key`, `is_sphincs_key_valid`, `active_sphincs_key`)
//! are **not consulted by any signature-verification path** — the ingest
//! verifier checks the record's own embedded `creator_public_key` and the
//! revocation tombstone, never a rotated active key.
//!
//! KR-3: `identity_hash` is derived from the CURRENT signing key
//! (`sha3_256_hex(creator_public_key)`), so it is **not** rotation-stable:
//! a record signed by a rotated-in key resolves to a different account, and
//! stake/trust/balance (keyed on the old hash) are stranded.
//!
//! Key REVOCATION (Protocol §11.2, the compromised-key tombstone) IS live and
//! is authenticated (self-revocation only, KR-1 fix `8e1c0af2`).
//! Real rotation support (a stable on-record identity + an identity→active-key
//! index consulted at ingest) is queued audit-first post-flip. Everything below
//! this banner describes the TARGET design, not shipped behavior.
//!
//! [target] The `identity_hash` is meant to be the permanent anchor (SHA3-256
//! of the original public key). Rotation creates a DAG record signed by the OLD
//! key, containing the NEW public key; after acceptance the new key is intended
//! to become the active signing key for that identity.
//!
//! Key revocation (Protocol §11.2) creates a permanent tombstone for a compromised
//! key. Once revoked, any record signed by that key is rejected.
//!
//! [target] Grace period: both old and new keys accepted for `ROTATION_GRACE_SECS`
//! after the rotation record's timestamp, then only the new key — see the status
//! banner above: this gate is not yet wired into verification.
//!
//! Rotation records have metadata:
//! ```json
//! {
//!   "key_rotation": true,
//!   "new_public_key": "<hex>",
//!   "rotation_reason": "periodic|compromise|upgrade"
//! }
//! ```
//!
//! Revocation records have metadata:
//! ```json
//! {
//!   "key_revocation": true,
//!   "revoked_public_key": "<hex>",
//!   "revocation_reason": "compromise|decommission|superseded"
//! }
//! ```
//!
//! Spec references:
//!   @spec Protocol §11.2

//!
//! Content hash = SHA3-256("key_rotation:{identity_hash}:{epoch}")

use std::collections::{HashMap, HashSet};

use crate::record::ValidationRecord;

/// Grace period: both old and new keys accepted for 24 hours after rotation.
pub const ROTATION_GRACE_SECS: f64 = 86400.0;

/// Metadata key for key rotation records.
pub const KEY_ROTATION_KEY: &str = "key_rotation";

/// Metadata key for key revocation records (Protocol §11.2).
pub const REVOCATION_OP_KEY: &str = "key_revocation";

/// Metadata key for SPHINCS+ key rotation records.
pub const SPHINCS_ROTATION_KEY: &str = "sphincs_key_rotation";

/// A key revocation tombstone (Protocol §11.2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RevocationEntry {
    /// The revoked public key (hex-encoded SHA3-256 hash for fast lookup).
    pub revoked_key_hash: String,
    /// The raw revoked public key bytes.
    pub revoked_public_key: Vec<u8>,
    /// Timestamp when the revocation record was created.
    pub revoked_at: f64,
    /// Reason for revocation.
    pub reason: String,
    /// Record ID of the revocation record.
    pub record_id: String,
    /// Identity hash of the key owner who issued the revocation.
    pub identity_hash: String,
}

/// A single key rotation event.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyRotation {
    /// The new public key (raw bytes).
    pub new_public_key: Vec<u8>,
    /// Timestamp when the rotation record was created.
    pub rotated_at: f64,
    /// Reason for rotation.
    pub reason: String,
    /// Record ID of the rotation record.
    pub record_id: String,
}

/// A SPHINCS+ key rotation event (Profile A secondary key).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SphincsKeyRotation {
    /// The new SPHINCS+ public key (48 bytes).
    pub new_sphincs_pk: Vec<u8>,
    /// Timestamp when the rotation record was created.
    pub rotated_at: f64,
    /// Reason for rotation.
    pub reason: String,
    /// Record ID of the rotation record.
    pub record_id: String,
}

/// Active key registry — maps identity_hash → current active key chain.
///
/// Thread-safe when wrapped in Mutex (which NodeState does for std::sync fields)
/// or when accessed through the RwLock-wrapped state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyRegistry {
    /// identity_hash → list of Dilithium3 rotations (ordered by time).
    rotations: HashMap<String, Vec<KeyRotation>>,
    /// identity_hash → list of SPHINCS+ rotations (ordered by time).
    sphincs_rotations: HashMap<String, Vec<SphincsKeyRotation>>,
    /// Set of revoked public key hashes (SHA3-256 hex of the raw public key).
    /// Once a key is in this set, any record signed by it is permanently rejected.
    revoked: HashSet<String>,
    /// Full revocation entries for admin/audit visibility.
    revocations: Vec<RevocationEntry>,
}

impl Default for KeyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyRegistry {
    pub fn new() -> Self {
        Self {
            rotations: HashMap::new(),
            sphincs_rotations: HashMap::new(),
            revoked: HashSet::new(),
            revocations: Vec::new(),
        }
    }

    /// Process a single record during streaming rebuild. Checks for key rotation,
    /// SPHINCS+ rotation, and revocation metadata. O(1) per record.
    pub fn process_record(&mut self, rec: &crate::record::ValidationRecord) {
        if let Some(rotation) = extract_key_rotation(rec) {
            let identity_hash = crate::accounting::types::creator_identity_hash(rec);
            self.register_rotation(&identity_hash, rotation);
        }
        if let Some(sphincs_rotation) = extract_sphincs_rotation(rec) {
            let identity_hash = crate::accounting::types::creator_identity_hash(rec);
            self.register_sphincs_rotation(&identity_hash, sphincs_rotation);
        }
        if revocation_authorized(rec) {
            if let Some(revocation) = extract_revocation(rec) {
                self.register_revocation(revocation);
            }
        }
    }

    /// Check if a public key has been revoked (Protocol §11.2).
    /// Takes the raw public key bytes, computes SHA3-256 hash for lookup.
    pub fn is_revoked(&self, public_key: &[u8]) -> bool {
        let key_hash = crate::crypto::hash::sha3_256_hex(public_key);
        self.revoked.contains(&key_hash)
    }

    /// Check if a public key hash (hex) is in the revoked set.
    pub fn is_revoked_hash(&self, key_hash: &str) -> bool {
        self.revoked.contains(key_hash)
    }

    /// Register a key revocation. The revocation record must have already been
    /// verified (signed by a valid key for this identity).
    pub fn register_revocation(&mut self, entry: RevocationEntry) {
        self.revoked.insert(entry.revoked_key_hash.clone());
        self.revocations.push(entry);
    }

    /// Total number of revoked keys.
    pub fn revocation_count(&self) -> usize {
        self.revoked.len()
    }

    /// Get all revocation entries (for admin endpoint).
    pub fn revocations(&self) -> &[RevocationEntry] {
        &self.revocations
    }

    /// Register a key rotation. The rotation record must have already been
    /// verified (signed by the previous active key for this identity).
    pub fn register_rotation(
        &mut self,
        identity_hash: &str,
        rotation: KeyRotation,
    ) {
        self.rotations
            .entry(identity_hash.to_string())
            .or_default()
            .push(rotation);
    }

    /// Get the currently active public key for an identity at a given time.
    ///
    /// Returns `None` if no rotation has occurred (use the original public key).
    /// Returns `Some(key)` if a rotation exists and the grace period has passed.
    pub fn active_key(&self, identity_hash: &str, at_time: f64) -> Option<&[u8]> {
        let rotations = self.rotations.get(identity_hash)?;
        // Find the latest rotation whose grace period has ended
        rotations
            .iter()
            .rev()
            .find(|r| at_time >= r.rotated_at + ROTATION_GRACE_SECS)
            .map(|r| r.new_public_key.as_slice())
    }

    /// Check if a given public key is valid for an identity at a given time.
    ///
    /// During the grace period after rotation, BOTH old and new keys are valid.
    /// Before any rotation, only the original key is valid.
    /// After grace period, only the latest rotated key is valid.
    pub fn is_key_valid(
        &self,
        identity_hash: &str,
        public_key: &[u8],
        original_key: &[u8],
        at_time: f64,
    ) -> bool {
        let Some(rotations) = self.rotations.get(identity_hash) else {
            // No rotations — only original key is valid
            return public_key == original_key;
        };

        if rotations.is_empty() {
            return public_key == original_key;
        }

        // Check if key matches any valid key at this time
        let latest = &rotations[rotations.len() - 1];

        if at_time < latest.rotated_at + ROTATION_GRACE_SECS {
            // In grace period — both old and new are valid
            let previous_key = if rotations.len() >= 2 {
                &rotations[rotations.len() - 2].new_public_key
            } else {
                original_key
            };
            public_key == latest.new_public_key.as_slice()
                || public_key == previous_key
        } else {
            // Grace period expired — only latest key is valid
            public_key == latest.new_public_key.as_slice()
        }
    }

    /// Number of identities with rotations.
    pub fn rotated_identities(&self) -> usize {
        self.rotations.len()
    }

    /// Total rotation count across all identities.
    /// Number of Dilithium3 key rotations for a specific identity.
    pub fn rotations_for(&self, identity: &str) -> usize {
        self.rotations.get(identity).map_or(0, |v| v.len())
    }

    pub fn total_rotations(&self) -> usize {
        self.rotations.values().map(|v| v.len()).sum()
    }

    /// Get rotation history for an identity.
    pub fn history(&self, identity_hash: &str) -> Vec<&KeyRotation> {
        self.rotations
            .get(identity_hash)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    // ─── SPHINCS+ key rotation (Profile A secondary key) ────────────────

    /// Register a SPHINCS+ key rotation for a Profile A identity.
    pub fn register_sphincs_rotation(
        &mut self,
        identity_hash: &str,
        rotation: SphincsKeyRotation,
    ) {
        self.sphincs_rotations
            .entry(identity_hash.to_string())
            .or_default()
            .push(rotation);
    }

    /// Get the currently active SPHINCS+ key for an identity at a given time.
    /// Returns `None` if no SPHINCS+ rotation has occurred.
    pub fn active_sphincs_key(&self, identity_hash: &str, at_time: f64) -> Option<&[u8]> {
        let rotations = self.sphincs_rotations.get(identity_hash)?;
        rotations
            .iter()
            .rev()
            .find(|r| at_time >= r.rotated_at + ROTATION_GRACE_SECS)
            .map(|r| r.new_sphincs_pk.as_slice())
    }

    /// Check if a SPHINCS+ public key is valid for an identity at a given time.
    pub fn is_sphincs_key_valid(
        &self,
        identity_hash: &str,
        sphincs_pk: &[u8],
        original_sphincs_pk: &[u8],
        at_time: f64,
    ) -> bool {
        let Some(rotations) = self.sphincs_rotations.get(identity_hash) else {
            return sphincs_pk == original_sphincs_pk;
        };

        if rotations.is_empty() {
            return sphincs_pk == original_sphincs_pk;
        }

        let latest = &rotations[rotations.len() - 1];

        if at_time < latest.rotated_at + ROTATION_GRACE_SECS {
            let previous_key = if rotations.len() >= 2 {
                &rotations[rotations.len() - 2].new_sphincs_pk
            } else {
                original_sphincs_pk
            };
            sphincs_pk == latest.new_sphincs_pk.as_slice()
                || sphincs_pk == previous_key
        } else {
            sphincs_pk == latest.new_sphincs_pk.as_slice()
        }
    }

    /// Get SPHINCS+ rotation history for an identity.
    pub fn sphincs_history(&self, identity_hash: &str) -> Vec<&SphincsKeyRotation> {
        self.sphincs_rotations
            .get(identity_hash)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Total SPHINCS+ rotation count across all identities.
    pub fn total_sphincs_rotations(&self) -> usize {
        self.sphincs_rotations.values().map(|v| v.len()).sum()
    }
}

/// Extract a key rotation from a record's metadata, if present.
pub fn extract_key_rotation(record: &ValidationRecord) -> Option<KeyRotation> {
    let is_rotation = record
        .metadata
        .get(KEY_ROTATION_KEY)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !is_rotation {
        return None;
    }

    let new_pk_hex = record
        .metadata
        .get("new_public_key")
        .and_then(|v| v.as_str())?;

    let new_public_key = hex::decode(new_pk_hex).ok()?;

    let reason = record
        .metadata
        .get("rotation_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("unspecified")
        .to_string();

    Some(KeyRotation {
        new_public_key,
        rotated_at: record.timestamp,
        reason,
        record_id: record.id.clone(),
    })
}

/// Build metadata for a key rotation record.
pub fn rotation_metadata(
    new_public_key: &[u8],
    reason: &str,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(KEY_ROTATION_KEY.into(), serde_json::json!(true));
    m.insert("new_public_key".into(), serde_json::json!(hex::encode(new_public_key)));
    m.insert("rotation_reason".into(), serde_json::json!(reason));
    m
}

/// Extract a SPHINCS+ key rotation from a record's metadata, if present.
pub fn extract_sphincs_rotation(record: &ValidationRecord) -> Option<SphincsKeyRotation> {
    let is_rotation = record
        .metadata
        .get(SPHINCS_ROTATION_KEY)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !is_rotation {
        return None;
    }

    let new_pk_hex = record
        .metadata
        .get("new_sphincs_public_key")
        .and_then(|v| v.as_str())?;

    let new_sphincs_pk = hex::decode(new_pk_hex).ok()?;

    let reason = record
        .metadata
        .get("rotation_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("unspecified")
        .to_string();

    Some(SphincsKeyRotation {
        new_sphincs_pk,
        rotated_at: record.timestamp,
        reason,
        record_id: record.id.clone(),
    })
}

/// Build metadata for a SPHINCS+ key rotation record.
pub fn sphincs_rotation_metadata(
    new_sphincs_pk: &[u8],
    reason: &str,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(SPHINCS_ROTATION_KEY.into(), serde_json::json!(true));
    m.insert("new_sphincs_public_key".into(), serde_json::json!(hex::encode(new_sphincs_pk)));
    m.insert("rotation_reason".into(), serde_json::json!(reason));
    m
}

/// Extract a key revocation from a record's metadata, if present.
pub fn extract_revocation(record: &ValidationRecord) -> Option<RevocationEntry> {
    let is_revocation = record
        .metadata
        .get(REVOCATION_OP_KEY)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !is_revocation {
        return None;
    }

    let revoked_pk_hex = record
        .metadata
        .get("revoked_public_key")
        .and_then(|v| v.as_str())?;

    let revoked_public_key = hex::decode(revoked_pk_hex).ok()?;
    let revoked_key_hash = crate::crypto::hash::sha3_256_hex(&revoked_public_key);

    let reason = record
        .metadata
        .get("revocation_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("unspecified")
        .to_string();

    let identity_hash = crate::accounting::types::creator_identity_hash(record);

    Some(RevocationEntry {
        revoked_key_hash,
        revoked_public_key,
        revoked_at: record.timestamp,
        reason,
        record_id: record.id.clone(),
        identity_hash,
    })
}

/// KR-1 authorization gate (2026-07-03 audit): is a revocation record allowed
/// to take effect?
///
/// A revocation may only target the key that SIGNED the carrying record —
/// self-revocation. Without this bind, any actor could sign a record carrying a
/// *victim's* public key and permanently lock that identity out fleet-wide:
/// [`KeyRegistry::register_revocation`] is applied at ingest on every node and
/// ingest then rejects every record signed by a revoked key. Because
/// `creator_identity_hash(record) == sha3(creator_public_key)`, requiring the
/// revoked-key hash to equal the signer hash means "you can only revoke the key
/// you are currently signing with."
///
/// This is intentionally strict. Revoking a *compromised prior* key you no
/// longer control needs a recovery-key mechanism and the rotation-model rework
/// tracked as audit item KR-3; it is out of scope for closing this lockout hole.
/// Callers that turn an untrusted record into registry state (ingest, streaming
/// rebuild) MUST gate `register_revocation` on this.
pub fn revocation_authorized(record: &ValidationRecord) -> bool {
    let revoked_hex = match record
        .metadata
        .get("revoked_public_key")
        .and_then(|v| v.as_str())
    {
        Some(h) => h,
        None => return false,
    };
    let revoked_bytes = match hex::decode(revoked_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let revoked_hash = crate::crypto::hash::sha3_256_hex(&revoked_bytes);
    revoked_hash == crate::accounting::types::creator_identity_hash(record)
}

/// Build metadata for a key revocation record.
pub fn revocation_metadata(
    revoked_public_key: &[u8],
    reason: &str,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(REVOCATION_OP_KEY.into(), serde_json::json!(true));
    m.insert("revoked_public_key".into(), serde_json::json!(hex::encode(revoked_public_key)));
    m.insert("revocation_reason".into(), serde_json::json!(reason));
    m
}

/// Rebuild the key registry from storage by scanning all records for rotation metadata.
///
/// cfg(test)-gated. Production boot uses
/// `rebuild_registry_from_records` driven by `for_each_record_ordered_bounded`
/// in `bin/elara_node.rs`. The unbounded `query(usize::MAX)` allocates
/// ~80 GB at 10M records.
#[cfg(test)]
pub fn rebuild_registry(
    storage: &dyn crate::storage::Storage,
) -> crate::errors::Result<KeyRegistry> {
    let records = storage.query(None, None, None, None, usize::MAX)?;
    Ok(rebuild_registry_from_records(&records))
}

/// Rebuild the key registry from a pre-loaded record slice (single-pass startup).
pub fn rebuild_registry_from_records(
    all_records: &[crate::record::ValidationRecord],
) -> KeyRegistry {
    use crate::accounting::types::creator_identity_hash;

    let mut sorted: Vec<&crate::record::ValidationRecord> = all_records.iter().collect();
    // Total-order replay: timestamp + record-ID tiebreak (mirrors ledger.rs/epoch.rs).
    // Rotation records must replay in an identical total order across nodes so the
    // rebuilt chain is deterministic (equal-timestamp rotations tiebreak on id).
    // NOTE: today this ordering only affects the rebuilt rotation view — the
    // active-key gate it was written to protect (is_key_valid) is not yet wired
    // into signature verification (KR-2). Keep the total order so the gate is
    // correct once it lands.
    sorted.sort_by(|a, b| {
        a.timestamp.total_cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id))
    });

    let mut registry = KeyRegistry::new();
    for record in &sorted {
        if let Some(rotation) = extract_key_rotation(record) {
            let identity_hash = creator_identity_hash(record);
            registry.register_rotation(&identity_hash, rotation);
        }
        if let Some(sphincs_rotation) = extract_sphincs_rotation(record) {
            let identity_hash = creator_identity_hash(record);
            registry.register_sphincs_rotation(&identity_hash, sphincs_rotation);
        }
        if let Some(revocation) = extract_revocation(record) {
            registry.register_revocation(revocation);
        }
    }

    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-1 (2026-07-03 audit): a revocation may only target the signer's own
    /// key. An attacker carrying a victim's pubkey must NOT be able to revoke it.
    #[test]
    fn kr1_revocation_authorized_only_for_self_revocation() {
        use crate::record::{Classification, ValidationRecord};
        let signer_key = vec![7u8, 7, 7, 7];
        let victim_key = vec![9u8, 9, 9, 9];
        let mk = |revoked: &[u8]| {
            ValidationRecord::create(
                b"x",
                signer_key.clone(),
                vec![],
                Classification::Public,
                Some(revocation_metadata(revoked, "compromise")),
            )
        };

        // Attack: try to revoke a key that is NOT the signer's.
        let attack = mk(&victim_key);
        assert!(
            !revocation_authorized(&attack),
            "revoking a non-signer key must be rejected (KR-1)"
        );
        let mut reg = KeyRegistry::new();
        reg.process_record(&attack);
        assert_eq!(reg.revocation_count(), 0, "unauthorized revocation must not register");
        assert!(!reg.is_revoked(&victim_key), "attacker must not revoke a victim's key");

        // Self-revocation: revoke the very key that signs the record.
        let legit = mk(&signer_key);
        assert!(revocation_authorized(&legit), "self-revocation must be allowed");
        reg.process_record(&legit);
        assert!(reg.is_revoked(&signer_key), "self-revocation must take effect");
        assert_eq!(reg.revocation_count(), 1);
    }

    #[test]
    fn test_registry_no_rotations() {
        let registry = KeyRegistry::new();
        assert!(registry.active_key("id1", 100.0).is_none());
        assert!(registry.is_key_valid("id1", b"orig", b"orig", 100.0));
        assert!(!registry.is_key_valid("id1", b"other", b"orig", 100.0));
    }

    #[test]
    fn test_registry_during_grace_period() {
        let mut registry = KeyRegistry::new();
        registry.register_rotation("id1", KeyRotation {
            new_public_key: b"new_key".to_vec(),
            rotated_at: 1000.0,
            reason: "test".to_string(),
            record_id: "rot_1".to_string(),
        });

        // During grace period — both keys valid
        let during_grace = 1000.0 + ROTATION_GRACE_SECS / 2.0;
        assert!(registry.is_key_valid("id1", b"orig", b"orig", during_grace));
        assert!(registry.is_key_valid("id1", b"new_key", b"orig", during_grace));
        assert!(!registry.is_key_valid("id1", b"random", b"orig", during_grace));
    }

    #[test]
    fn test_registry_after_grace_period() {
        let mut registry = KeyRegistry::new();
        registry.register_rotation("id1", KeyRotation {
            new_public_key: b"new_key".to_vec(),
            rotated_at: 1000.0,
            reason: "test".to_string(),
            record_id: "rot_1".to_string(),
        });

        // After grace period — only new key valid
        let after_grace = 1000.0 + ROTATION_GRACE_SECS + 1.0;
        assert!(!registry.is_key_valid("id1", b"orig", b"orig", after_grace));
        assert!(registry.is_key_valid("id1", b"new_key", b"orig", after_grace));
    }

    #[test]
    fn test_registry_double_rotation() {
        let mut registry = KeyRegistry::new();
        registry.register_rotation("id1", KeyRotation {
            new_public_key: b"key_v2".to_vec(),
            rotated_at: 1000.0,
            reason: "first".to_string(),
            record_id: "rot_1".to_string(),
        });
        registry.register_rotation("id1", KeyRotation {
            new_public_key: b"key_v3".to_vec(),
            rotated_at: 200_000.0,
            reason: "second".to_string(),
            record_id: "rot_2".to_string(),
        });

        // During second grace — key_v2 and key_v3 valid, orig NOT valid
        let during = 200_000.0 + ROTATION_GRACE_SECS / 2.0;
        assert!(registry.is_key_valid("id1", b"key_v2", b"orig", during));
        assert!(registry.is_key_valid("id1", b"key_v3", b"orig", during));
        assert!(!registry.is_key_valid("id1", b"orig", b"orig", during));

        // After second grace — only key_v3 valid
        let after = 200_000.0 + ROTATION_GRACE_SECS + 1.0;
        assert!(!registry.is_key_valid("id1", b"key_v2", b"orig", after));
        assert!(registry.is_key_valid("id1", b"key_v3", b"orig", after));
    }

    /// Regression: rebuild_registry_from_records must be order-invariant for
    /// equal-timestamp rotations. is_key_valid() after grace returns the LAST-applied
    /// rotation's key, so without the record-ID tiebreak two nodes with different
    /// record load orders accept different keys → consensus fork on signature checks.
    #[test]
    fn rebuild_registry_equal_timestamp_replay_is_order_invariant() {
        use crate::record::{Classification, ValidationRecord};

        let pubkey = vec![7u8; 32];
        let ts = 1000.0;

        let mk = |new_key: &[u8], reason: &str, id: &str| {
            let mut rec = ValidationRecord::create(
                b"rotation-test",
                pubkey.clone(),
                vec![],
                Classification::Public,
                Some(rotation_metadata(new_key, reason)),
            );
            rec.timestamp = ts; // force the equal-timestamp tie
            rec.id = id.to_string();
            rec
        };

        // Two rotations for the SAME identity at the SAME timestamp, different keys.
        let rec_a = mk(b"key_A", "a", "rot_aaa");
        let rec_b = mk(b"key_B", "b", "rot_bbb");
        let identity = crate::accounting::types::creator_identity_hash(&rec_a);

        let reg_ab = rebuild_registry_from_records(&[rec_a.clone(), rec_b.clone()]);
        let reg_ba = rebuild_registry_from_records(&[rec_b.clone(), rec_a.clone()]);

        // Both input orderings must agree on every key's validity after grace.
        let after = ts + ROTATION_GRACE_SECS + 1.0;
        for key in [b"key_A".as_slice(), b"key_B".as_slice()] {
            assert_eq!(
                reg_ab.is_key_valid(&identity, key, b"orig", after),
                reg_ba.is_key_valid(&identity, key, b"orig", after),
                "key validity for {key:?} must be replay-order-invariant",
            );
        }
        // Deterministic winner: larger record-ID ("rot_bbb") applies last → key_B wins.
        assert!(reg_ab.is_key_valid(&identity, b"key_B", b"orig", after));
        assert!(!reg_ab.is_key_valid(&identity, b"key_A", b"orig", after));
    }

    #[test]
    fn test_active_key() {
        let mut registry = KeyRegistry::new();
        assert!(registry.active_key("id1", 100.0).is_none());

        registry.register_rotation("id1", KeyRotation {
            new_public_key: b"new_key".to_vec(),
            rotated_at: 1000.0,
            reason: "test".to_string(),
            record_id: "rot_1".to_string(),
        });

        // During grace — no "active" key yet (both are valid)
        assert!(registry.active_key("id1", 1000.0 + 100.0).is_none());

        // After grace — new key is THE active key
        assert_eq!(
            registry.active_key("id1", 1000.0 + ROTATION_GRACE_SECS + 1.0),
            Some(b"new_key".as_slice()),
        );
    }

    #[test]
    fn test_extract_key_rotation_none() {
        let record = ValidationRecord::create(
            b"test",
            vec![1, 2, 3],
            vec![],
            crate::record::Classification::Public,
            None,
        );
        assert!(extract_key_rotation(&record).is_none());
    }

    #[test]
    fn test_extract_key_rotation_valid() {
        let meta = rotation_metadata(b"new_pub_key", "periodic");
        let record = ValidationRecord::create(
            b"test",
            vec![1, 2, 3],
            vec![],
            crate::record::Classification::Public,
            Some(meta),
        );
        let rotation = extract_key_rotation(&record).unwrap();
        assert_eq!(rotation.new_public_key, b"new_pub_key");
        assert_eq!(rotation.reason, "periodic");
    }

    #[test]
    fn test_rotation_metadata_roundtrip() {
        let meta = rotation_metadata(b"\x01\x02\x03", "compromise");
        assert_eq!(meta.get(KEY_ROTATION_KEY).unwrap(), &serde_json::json!(true));
        assert_eq!(meta.get("new_public_key").unwrap(), &serde_json::json!("010203"));
        assert_eq!(meta.get("rotation_reason").unwrap(), &serde_json::json!("compromise"));
    }

    #[test]
    fn test_registry_counts() {
        let mut registry = KeyRegistry::new();
        assert_eq!(registry.rotated_identities(), 0);
        assert_eq!(registry.total_rotations(), 0);

        registry.register_rotation("id1", KeyRotation {
            new_public_key: b"k1".to_vec(),
            rotated_at: 100.0,
            reason: "test".to_string(),
            record_id: "r1".to_string(),
        });
        registry.register_rotation("id2", KeyRotation {
            new_public_key: b"k2".to_vec(),
            rotated_at: 200.0,
            reason: "test".to_string(),
            record_id: "r2".to_string(),
        });

        assert_eq!(registry.rotated_identities(), 2);
        assert_eq!(registry.total_rotations(), 2);
    }

    #[test]
    fn test_history() {
        let mut registry = KeyRegistry::new();
        registry.register_rotation("id1", KeyRotation {
            new_public_key: b"k1".to_vec(),
            rotated_at: 100.0,
            reason: "first".to_string(),
            record_id: "r1".to_string(),
        });
        registry.register_rotation("id1", KeyRotation {
            new_public_key: b"k2".to_vec(),
            rotated_at: 200.0,
            reason: "second".to_string(),
            record_id: "r2".to_string(),
        });

        let history = registry.history("id1");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].reason, "first");
        assert_eq!(history[1].reason, "second");
        assert!(registry.history("id_unknown").is_empty());
    }

    // ── Revocation tests ──────────────────────────────────────────────

    #[test]
    fn test_revocation_basic() {
        let mut registry = KeyRegistry::new();
        assert!(!registry.is_revoked(b"some_key"));
        assert_eq!(registry.revocation_count(), 0);

        let key_hash = crate::crypto::hash::sha3_256_hex(b"compromised_key");
        registry.register_revocation(RevocationEntry {
            revoked_key_hash: key_hash.clone(),
            revoked_public_key: b"compromised_key".to_vec(),
            revoked_at: 1000.0,
            reason: "compromise".to_string(),
            record_id: "rev-001".to_string(),
            identity_hash: "id1".to_string(),
        });

        assert!(registry.is_revoked(b"compromised_key"));
        assert!(registry.is_revoked_hash(&key_hash));
        assert!(!registry.is_revoked(b"other_key"));
        assert_eq!(registry.revocation_count(), 1);
        assert_eq!(registry.revocations().len(), 1);
        assert_eq!(registry.revocations()[0].reason, "compromise");
    }

    #[test]
    fn test_revocation_multiple_keys() {
        let mut registry = KeyRegistry::new();
        for i in 0..3 {
            let key = format!("key_{i}");
            let key_hash = crate::crypto::hash::sha3_256_hex(key.as_bytes());
            registry.register_revocation(RevocationEntry {
                revoked_key_hash: key_hash,
                revoked_public_key: key.as_bytes().to_vec(),
                revoked_at: 1000.0 + i as f64,
                reason: "decommission".to_string(),
                record_id: format!("rev-{i}"),
                identity_hash: "id1".to_string(),
            });
        }
        assert_eq!(registry.revocation_count(), 3);
        assert!(registry.is_revoked(b"key_0"));
        assert!(registry.is_revoked(b"key_1"));
        assert!(registry.is_revoked(b"key_2"));
        assert!(!registry.is_revoked(b"key_3"));
    }

    #[test]
    fn test_revocation_idempotent() {
        let mut registry = KeyRegistry::new();
        let key_hash = crate::crypto::hash::sha3_256_hex(b"key");
        for _ in 0..3 {
            registry.register_revocation(RevocationEntry {
                revoked_key_hash: key_hash.clone(),
                revoked_public_key: b"key".to_vec(),
                revoked_at: 1000.0,
                reason: "compromise".to_string(),
                record_id: "rev-dup".to_string(),
                identity_hash: "id1".to_string(),
            });
        }
        // HashSet deduplicates, but revocations vec keeps all entries
        assert_eq!(registry.revocation_count(), 1);
        assert_eq!(registry.revocations().len(), 3);
    }

    /// Metric-semantics codification for the
    /// `elara_key_revocation_count` gauge. The gauge value MUST equal
    /// the size of the HashSet tombstone set — distinct revoked keys
    /// resident locally — never the number of revocation records seen,
    /// never the number of rotations.
    ///
    /// Operators rely on:
    ///   * gauge climbing in lockstep with `_rejected_total` =
    ///     revocation propagation lag — peers still signing with the
    ///     just-revoked key reach this node before the revocation does.
    ///   * gauge stable while `_rejected_total` climbs = active
    ///     compromised-key replay (revocation propagated, attacker is
    ///     replaying pre-revocation captures).
    ///   * gauge growing while `_rejected_total` flat = healthy: keys
    ///     are being revoked and propagation is reaching peers before
    ///     they sign with stale keys.
    ///   * rotation events never inflate revocation_count — the two
    ///     subsystems share the registry but have disjoint tombstone /
    ///     active-key state.
    #[test]
    fn ops_45_revocation_count_pins_distinct_revoked_keys_for_gauge() {
        let mut registry = KeyRegistry::new();
        assert_eq!(registry.revocation_count(), 0,
            "fresh registry has no tombstones");

        // Register N distinct keys → gauge advances by N.
        for n in 0..5u64 {
            let key = format!("compromised_{n}");
            registry.register_revocation(RevocationEntry {
                revoked_key_hash: crate::crypto::hash::sha3_256_hex(key.as_bytes()),
                revoked_public_key: key.as_bytes().to_vec(),
                revoked_at: 1000.0 + n as f64,
                reason: "compromise".to_string(),
                record_id: format!("rev-{n}"),
                identity_hash: "victim".to_string(),
            });
        }
        assert_eq!(registry.revocation_count(), 5,
            "5 distinct keys revoked → gauge=5");

        // Re-revoking the SAME keys must NOT inflate the gauge — HashSet
        // semantics. This is the propagation-lag scenario: same revocation
        // record arrives twice via different gossip paths.
        for n in 0..5u64 {
            let key = format!("compromised_{n}");
            registry.register_revocation(RevocationEntry {
                revoked_key_hash: crate::crypto::hash::sha3_256_hex(key.as_bytes()),
                revoked_public_key: key.as_bytes().to_vec(),
                revoked_at: 2000.0 + n as f64,
                reason: "compromise".to_string(),
                record_id: format!("rev-dup-{n}"),
                identity_hash: "victim".to_string(),
            });
        }
        assert_eq!(registry.revocation_count(), 5,
            "duplicate revocations of same keys = gauge unchanged");
        // The audit list (revocations()) DOES record duplicates — distinct from gauge.
        assert_eq!(registry.revocations().len(), 10,
            "audit list keeps every entry; gauge dedupes");

        // Rotations must not touch revocation_count. The two subsystems
        // share the registry but are independent — rotating a key is NOT
        // a revocation, and a wired metric must never confuse the two.
        for n in 0..3u64 {
            registry.register_rotation(
                &format!("identity_{n}"),
                KeyRotation {
                    new_public_key: format!("new_key_{n}").as_bytes().to_vec(),
                    rotated_at: 3000.0 + n as f64,
                    reason: "periodic".to_string(),
                    record_id: format!("rot-{n}"),
                },
            );
        }
        assert_eq!(registry.revocation_count(), 5,
            "rotations are NOT revocations — gauge unchanged");
        assert_eq!(registry.total_rotations(), 3,
            "rotation counter advanced independently");

        // Adding ONE new revocation while existing tombstones stand →
        // gauge advances by exactly 1. Rules out off-by-one in HashSet
        // bookkeeping.
        registry.register_revocation(RevocationEntry {
            revoked_key_hash: crate::crypto::hash::sha3_256_hex(b"compromised_brand_new"),
            revoked_public_key: b"compromised_brand_new".to_vec(),
            revoked_at: 4000.0,
            reason: "compromise".to_string(),
            record_id: "rev-new".to_string(),
            identity_hash: "victim2".to_string(),
        });
        assert_eq!(registry.revocation_count(), 6,
            "new distinct revocation → gauge += 1 exactly");
    }

    #[test]
    fn test_extract_revocation_none() {
        let record = ValidationRecord::create(
            b"test",
            vec![1, 2, 3],
            vec![],
            crate::record::Classification::Public,
            None,
        );
        assert!(extract_revocation(&record).is_none());
    }

    #[test]
    fn test_extract_revocation_valid() {
        let meta = revocation_metadata(b"bad_key", "compromise");
        let record = ValidationRecord::create(
            b"test",
            vec![1, 2, 3],
            vec![],
            crate::record::Classification::Public,
            Some(meta),
        );
        let entry = extract_revocation(&record).unwrap();
        assert_eq!(entry.revoked_public_key, b"bad_key");
        assert_eq!(entry.reason, "compromise");
        assert_eq!(entry.revoked_key_hash, crate::crypto::hash::sha3_256_hex(b"bad_key"));
    }

    #[test]
    fn test_revocation_metadata_roundtrip() {
        let meta = revocation_metadata(b"\x01\x02\x03", "decommission");
        assert_eq!(meta.get(REVOCATION_OP_KEY).unwrap(), &serde_json::json!(true));
        assert_eq!(meta.get("revoked_public_key").unwrap(), &serde_json::json!("010203"));
        assert_eq!(meta.get("revocation_reason").unwrap(), &serde_json::json!("decommission"));
    }

    #[test]
    fn test_revocation_blocks_key_validation() {
        let mut registry = KeyRegistry::new();
        // Key is valid before revocation
        assert!(registry.is_key_valid("id1", b"orig", b"orig", 100.0));

        // Revoke the key
        let key_hash = crate::crypto::hash::sha3_256_hex(b"orig");
        registry.register_revocation(RevocationEntry {
            revoked_key_hash: key_hash,
            revoked_public_key: b"orig".to_vec(),
            revoked_at: 200.0,
            reason: "compromise".to_string(),
            record_id: "rev-001".to_string(),
            identity_hash: "id1".to_string(),
        });

        // Key should show as revoked (caller must check is_revoked separately)
        assert!(registry.is_revoked(b"orig"));
    }

    #[test]
    fn test_revocation_with_rotation() {
        let mut registry = KeyRegistry::new();

        // Rotate key
        registry.register_rotation("id1", KeyRotation {
            new_public_key: b"new_key".to_vec(),
            rotated_at: 1000.0,
            reason: "periodic".to_string(),
            record_id: "rot-001".to_string(),
        });

        // Revoke old key
        let key_hash = crate::crypto::hash::sha3_256_hex(b"old_key");
        registry.register_revocation(RevocationEntry {
            revoked_key_hash: key_hash,
            revoked_public_key: b"old_key".to_vec(),
            revoked_at: 1001.0,
            reason: "superseded".to_string(),
            record_id: "rev-001".to_string(),
            identity_hash: "id1".to_string(),
        });

        assert!(registry.is_revoked(b"old_key"));
        assert!(!registry.is_revoked(b"new_key"));
    }

    // ── SPHINCS+ key rotation tests ─────────────────────────────────────

    #[test]
    fn test_sphincs_no_rotations() {
        let registry = KeyRegistry::new();
        assert!(registry.active_sphincs_key("id1", 100.0).is_none());
        assert!(registry.is_sphincs_key_valid("id1", b"orig_sphincs", b"orig_sphincs", 100.0));
        assert!(!registry.is_sphincs_key_valid("id1", b"other", b"orig_sphincs", 100.0));
        assert_eq!(registry.total_sphincs_rotations(), 0);
    }

    #[test]
    fn test_sphincs_rotation_grace_period() {
        let mut registry = KeyRegistry::new();
        registry.register_sphincs_rotation("id1", SphincsKeyRotation {
            new_sphincs_pk: b"new_sphincs".to_vec(),
            rotated_at: 1000.0,
            reason: "upgrade".to_string(),
            record_id: "srot_1".to_string(),
        });

        // During grace period — both keys valid
        let during = 1000.0 + ROTATION_GRACE_SECS / 2.0;
        assert!(registry.is_sphincs_key_valid("id1", b"orig_sphincs", b"orig_sphincs", during));
        assert!(registry.is_sphincs_key_valid("id1", b"new_sphincs", b"orig_sphincs", during));
        assert!(!registry.is_sphincs_key_valid("id1", b"random", b"orig_sphincs", during));

        // After grace period — only new key valid
        let after = 1000.0 + ROTATION_GRACE_SECS + 1.0;
        assert!(!registry.is_sphincs_key_valid("id1", b"orig_sphincs", b"orig_sphincs", after));
        assert!(registry.is_sphincs_key_valid("id1", b"new_sphincs", b"orig_sphincs", after));
    }

    #[test]
    fn test_sphincs_active_key() {
        let mut registry = KeyRegistry::new();
        registry.register_sphincs_rotation("id1", SphincsKeyRotation {
            new_sphincs_pk: b"new_sphincs".to_vec(),
            rotated_at: 1000.0,
            reason: "test".to_string(),
            record_id: "srot_1".to_string(),
        });

        assert!(registry.active_sphincs_key("id1", 1000.0 + 100.0).is_none());
        assert_eq!(
            registry.active_sphincs_key("id1", 1000.0 + ROTATION_GRACE_SECS + 1.0),
            Some(b"new_sphincs".as_slice()),
        );
    }

    #[test]
    fn test_sphincs_history() {
        let mut registry = KeyRegistry::new();
        registry.register_sphincs_rotation("id1", SphincsKeyRotation {
            new_sphincs_pk: b"sph_v2".to_vec(),
            rotated_at: 100.0,
            reason: "first".to_string(),
            record_id: "sr1".to_string(),
        });
        registry.register_sphincs_rotation("id1", SphincsKeyRotation {
            new_sphincs_pk: b"sph_v3".to_vec(),
            rotated_at: 200.0,
            reason: "second".to_string(),
            record_id: "sr2".to_string(),
        });

        let history = registry.sphincs_history("id1");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].reason, "first");
        assert_eq!(history[1].reason, "second");
        assert_eq!(registry.total_sphincs_rotations(), 2);
    }

    #[test]
    fn test_extract_sphincs_rotation() {
        let meta = sphincs_rotation_metadata(b"new_sphincs_pk", "compromise");
        let record = ValidationRecord::create(
            b"test",
            vec![1, 2, 3],
            vec![],
            crate::record::Classification::Public,
            Some(meta),
        );
        let rotation = extract_sphincs_rotation(&record).unwrap();
        assert_eq!(rotation.new_sphincs_pk, b"new_sphincs_pk");
        assert_eq!(rotation.reason, "compromise");
    }

    #[test]
    fn test_sphincs_rotation_metadata_roundtrip() {
        let meta = sphincs_rotation_metadata(b"\x01\x02\x03", "upgrade");
        assert_eq!(meta.get(SPHINCS_ROTATION_KEY).unwrap(), &serde_json::json!(true));
        assert_eq!(meta.get("new_sphincs_public_key").unwrap(), &serde_json::json!("010203"));
        assert_eq!(meta.get("rotation_reason").unwrap(), &serde_json::json!("upgrade"));
    }

    // ─── Fixture-free pure-helper tests ───────────────────────────────────

    /// Strict-pin all 4 module constants with arithmetic cross-checks and
    /// cross-module disjointness. Locks the wire-format contract that defines
    /// what metadata flag string triggers which extractor.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_key_rotation_module_constants_strict_pin_and_cross_module_disjoint() {
        // ROTATION_GRACE_SECS == 24 hours expressed in seconds, multiple ways.
        assert_eq!(ROTATION_GRACE_SECS, 86400.0);
        assert_eq!(ROTATION_GRACE_SECS, 24.0 * 3600.0);
        assert_eq!(ROTATION_GRACE_SECS, 1440.0 * 60.0);
        assert!(ROTATION_GRACE_SECS > 0.0);
        assert!(ROTATION_GRACE_SECS.is_finite());
        // half-grace boundary used in tests (during_grace = rotated_at + GRACE/2)
        assert_eq!(ROTATION_GRACE_SECS / 2.0, 43200.0);

        // Three metadata flag strings — exact byte-pin.
        assert_eq!(KEY_ROTATION_KEY, "key_rotation");
        assert_eq!(REVOCATION_OP_KEY, "key_revocation");
        assert_eq!(SPHINCS_ROTATION_KEY, "sphincs_key_rotation");

        // ASCII lowercase snake_case (no spaces, no dashes, no uppercase).
        for s in [KEY_ROTATION_KEY, REVOCATION_OP_KEY, SPHINCS_ROTATION_KEY] {
            assert!(s.is_ascii(), "{s}");
            assert!(!s.is_empty(), "{s}");
            assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '_'), "{s}");
            assert!(!s.contains(' '), "{s}");
            assert!(!s.contains('-'), "{s}");
            assert!(!s.starts_with('_'), "{s}");
            assert!(!s.ends_with('_'), "{s}");
        }

        // The three flag strings are pairwise distinct.
        assert_ne!(KEY_ROTATION_KEY, REVOCATION_OP_KEY);
        assert_ne!(KEY_ROTATION_KEY, SPHINCS_ROTATION_KEY);
        assert_ne!(REVOCATION_OP_KEY, SPHINCS_ROTATION_KEY);

        // sphincs_key_rotation contains "key_rotation" as substring (suffix),
        // but the boolean-flag dispatch requires EXACT key match, so the
        // sphincs flag must NEVER be confused with the dilithium rotation
        // flag — even though their prefixes overlap nominally. This pins the
        // load-bearing property that extract_key_rotation looks up by
        // KEY_ROTATION_KEY (exact "key_rotation"), not by substring.
        assert!(SPHINCS_ROTATION_KEY.contains(KEY_ROTATION_KEY));
        assert!(SPHINCS_ROTATION_KEY.ends_with(KEY_ROTATION_KEY));
        assert_ne!(SPHINCS_ROTATION_KEY, KEY_ROTATION_KEY);

        // Boolean flags must be disjoint from payload keys in their builders
        // (flag keys are what extract_* checks; payload keys carry the hex pk
        // and the reason). Cross-confusion would route the wrong extractor.
        for payload in ["new_public_key", "new_sphincs_public_key", "revoked_public_key",
                        "rotation_reason", "revocation_reason"] {
            assert_ne!(KEY_ROTATION_KEY, payload);
            assert_ne!(REVOCATION_OP_KEY, payload);
            assert_ne!(SPHINCS_ROTATION_KEY, payload);
        }

        // Cross-module disjointness — wire-format keys must NEVER collide
        // with other subsystems' op-keys (would mis-dispatch records).
        assert_ne!(KEY_ROTATION_KEY, crate::seed_vault::SEED_VAULT_OP_KEY);
        assert_ne!(REVOCATION_OP_KEY, crate::seed_vault::SEED_VAULT_OP_KEY);
        assert_ne!(SPHINCS_ROTATION_KEY, crate::seed_vault::SEED_VAULT_OP_KEY);
        assert_ne!(KEY_ROTATION_KEY, crate::collaboration::COLLABORATION_OP_KEY);
        assert_ne!(REVOCATION_OP_KEY, crate::collaboration::COLLABORATION_OP_KEY);
        assert_ne!(SPHINCS_ROTATION_KEY, crate::collaboration::COLLABORATION_OP_KEY);

        // Length pin — accidental whitespace/null-byte append would break.
        assert_eq!(KEY_ROTATION_KEY.len(), "key_rotation".len());
        assert_eq!(REVOCATION_OP_KEY.len(), "key_revocation".len());
        assert_eq!(SPHINCS_ROTATION_KEY.len(), "sphincs_key_rotation".len());
        assert_eq!(KEY_ROTATION_KEY.len(), 12);
        assert_eq!(REVOCATION_OP_KEY.len(), 14);
        assert_eq!(SPHINCS_ROTATION_KEY.len(), 20);
    }

    /// KeyRegistry::new and Default are equivalent; all accessors return
    /// zero/empty/None on an empty registry; serde round-trip preserves
    /// the empty state.
    #[test]
    fn batch_b_key_registry_initial_state_default_equivalence_and_serde_roundtrip() {
        let r = KeyRegistry::new();
        // Counts all zero.
        assert_eq!(r.rotated_identities(), 0);
        assert_eq!(r.total_rotations(), 0);
        assert_eq!(r.total_sphincs_rotations(), 0);
        assert_eq!(r.revocation_count(), 0);
        assert!(r.revocations().is_empty());
        // Per-identity accessors None / 0 / empty for any string.
        for id in ["", "id1", "deadbeef", "missing"] {
            assert!(r.active_key(id, 0.0).is_none());
            assert!(r.active_key(id, f64::INFINITY).is_none());
            assert!(r.active_sphincs_key(id, 0.0).is_none());
            assert!(r.active_sphincs_key(id, f64::INFINITY).is_none());
            assert_eq!(r.rotations_for(id), 0);
            assert!(r.history(id).is_empty());
            assert!(r.sphincs_history(id).is_empty());
        }
        // is_revoked false for any key on empty registry.
        for k in [b"".as_slice(), b"k1", b"compromised", b"\x00\x01\x02"] {
            assert!(!r.is_revoked(k));
        }
        // is_revoked_hash false for any string.
        assert!(!r.is_revoked_hash(""));
        assert!(!r.is_revoked_hash("deadbeef"));
        assert!(!r.is_revoked_hash(&"a".repeat(64)));
        // is_key_valid on empty registry: only original key valid.
        assert!(r.is_key_valid("id1", b"orig", b"orig", 0.0));
        assert!(!r.is_key_valid("id1", b"other", b"orig", 0.0));
        assert!(r.is_sphincs_key_valid("id1", b"orig", b"orig", 0.0));
        assert!(!r.is_sphincs_key_valid("id1", b"other", b"orig", 0.0));

        // Default == new — initial state equivalence.
        let d: KeyRegistry = KeyRegistry::default();
        assert_eq!(d.rotated_identities(), r.rotated_identities());
        assert_eq!(d.total_rotations(), r.total_rotations());
        assert_eq!(d.total_sphincs_rotations(), r.total_sphincs_rotations());
        assert_eq!(d.revocation_count(), r.revocation_count());

        // Serde round-trip preserves empty state.
        let json = serde_json::to_string(&r).expect("serialize empty registry");
        let back: KeyRegistry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.rotated_identities(), 0);
        assert_eq!(back.total_rotations(), 0);
        assert_eq!(back.total_sphincs_rotations(), 0);
        assert_eq!(back.revocation_count(), 0);
        assert!(back.revocations().is_empty());
    }

    /// All three metadata builders emit exactly 3 keys with byte-exact key
    /// names, JSON value types (bool flag + string payloads), lowercase hex
    /// encoding (incl. empty bytes), and document the load-bearing fact that
    /// rotation/sphincs SHARE "rotation_reason" while revocation uses
    /// "revocation_reason" — flag-key discriminates which extractor fires.
    #[test]
    fn batch_b_metadata_builders_exact_3_key_shape_lowercase_hex_and_shared_reason_audit() {
        // rotation_metadata: 3 keys exactly.
        let rot = rotation_metadata(b"\x01\x02\x03", "periodic");
        assert_eq!(rot.len(), 3, "rotation metadata = exactly 3 keys");
        assert_eq!(rot.get(KEY_ROTATION_KEY), Some(&serde_json::json!(true)));
        assert_eq!(rot.get("new_public_key"), Some(&serde_json::json!("010203")));
        assert_eq!(rot.get("rotation_reason"), Some(&serde_json::json!("periodic")));
        // No leak keys.
        assert!(!rot.contains_key(REVOCATION_OP_KEY));
        assert!(!rot.contains_key(SPHINCS_ROTATION_KEY));
        assert!(!rot.contains_key("new_sphincs_public_key"));
        assert!(!rot.contains_key("revoked_public_key"));
        assert!(!rot.contains_key("revocation_reason"));

        // sphincs_rotation_metadata: 3 keys exactly.
        let sph = sphincs_rotation_metadata(b"\xAB\xCD", "upgrade");
        assert_eq!(sph.len(), 3);
        assert_eq!(sph.get(SPHINCS_ROTATION_KEY), Some(&serde_json::json!(true)));
        assert_eq!(sph.get("new_sphincs_public_key"), Some(&serde_json::json!("abcd")));
        assert_eq!(sph.get("rotation_reason"), Some(&serde_json::json!("upgrade")));
        assert!(!sph.contains_key(KEY_ROTATION_KEY));
        assert!(!sph.contains_key(REVOCATION_OP_KEY));

        // revocation_metadata: 3 keys exactly.
        let rev = revocation_metadata(b"\xFF\x00\xFF", "compromise");
        assert_eq!(rev.len(), 3);
        assert_eq!(rev.get(REVOCATION_OP_KEY), Some(&serde_json::json!(true)));
        assert_eq!(rev.get("revoked_public_key"), Some(&serde_json::json!("ff00ff")));
        assert_eq!(rev.get("revocation_reason"), Some(&serde_json::json!("compromise")));
        assert!(!rev.contains_key(KEY_ROTATION_KEY));
        assert!(!rev.contains_key(SPHINCS_ROTATION_KEY));

        // Empty input bytes → empty hex string (not absent, not null).
        let empty_rot = rotation_metadata(b"", "x");
        assert_eq!(empty_rot.get("new_public_key"), Some(&serde_json::json!("")));
        let empty_sph = sphincs_rotation_metadata(b"", "x");
        assert_eq!(empty_sph.get("new_sphincs_public_key"), Some(&serde_json::json!("")));
        let empty_rev = revocation_metadata(b"", "x");
        assert_eq!(empty_rev.get("revoked_public_key"), Some(&serde_json::json!("")));

        // Hex encoding is lowercase ASCII (per hex::encode).
        let high = rotation_metadata(b"\xFF\xFE\xFD\xFC", "x");
        let h = high.get("new_public_key").unwrap().as_str().unwrap();
        assert_eq!(h, "fffefdfc");
        assert!(h.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));

        // Boolean flag value MUST be JSON true (not "true" string / not 1).
        for meta in [&rot, &sph, &rev] {
            let flag_key = meta.keys().find(|k|
                k.as_str() == KEY_ROTATION_KEY
                || k.as_str() == REVOCATION_OP_KEY
                || k.as_str() == SPHINCS_ROTATION_KEY
            ).expect("flag key present");
            let v = meta.get(flag_key.as_str()).unwrap();
            assert_eq!(v.as_bool(), Some(true));
            assert_ne!(v, &serde_json::json!("true"));
            assert_ne!(v, &serde_json::json!(1));
        }

        // BTreeMap iteration order is ASCII-sorted keys — lock the order so
        // future readers know it's deterministic for canonical encoding.
        let keys: Vec<&str> = rot.keys().map(|s| s.as_str()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        // For rotation: ascending = "key_rotation" < "new_public_key" < "rotation_reason".
        assert_eq!(keys, vec!["key_rotation", "new_public_key", "rotation_reason"]);

        // Shared-reason audit: rotation and sphincs share "rotation_reason"
        // key (DAM convention); revocation uses "revocation_reason". The
        // boolean flag is what discriminates which extractor fires.
        let rot_keys: std::collections::HashSet<&str> = rot.keys().map(|s| s.as_str()).collect();
        let sph_keys: std::collections::HashSet<&str> = sph.keys().map(|s| s.as_str()).collect();
        let rev_keys: std::collections::HashSet<&str> = rev.keys().map(|s| s.as_str()).collect();
        let rot_sph_shared: Vec<&&str> = rot_keys.intersection(&sph_keys).collect();
        assert_eq!(rot_sph_shared.len(), 1);
        assert_eq!(**rot_sph_shared[0], *"rotation_reason");
        // rotation/revocation share nothing.
        assert!(rot_keys.is_disjoint(&rev_keys));
        // sphincs/revocation share nothing.
        assert!(sph_keys.is_disjoint(&rev_keys));
    }

    /// extract_key_rotation / extract_sphincs_rotation / extract_revocation
    /// are MUTUALLY EXCLUSIVE on the boolean flag key. A record built by one
    /// builder yields Some via its matching extractor and None via the other
    /// two. Plus a sweep of flag-mistype paths (string-"true" vs bool true,
    /// null, missing, bad-hex, missing-reason → "unspecified" default).
    #[test]
    fn batch_b_extract_mutual_exclusivity_flag_type_strictness_and_reason_default() {
        use crate::record::{ValidationRecord, Classification};

        fn rec_with(meta: std::collections::BTreeMap<String, serde_json::Value>) -> ValidationRecord {
            ValidationRecord::create(b"test", vec![1, 2, 3], vec![], Classification::Public, Some(meta))
        }
        fn rec_no_meta() -> ValidationRecord {
            ValidationRecord::create(b"test", vec![1, 2, 3], vec![], Classification::Public, None)
        }

        // Mutual exclusivity: a rotation record yields Some from key_rotation
        // and None from the other two extractors.
        let rot_rec = rec_with(rotation_metadata(b"\x01\x02", "periodic"));
        assert!(extract_key_rotation(&rot_rec).is_some());
        assert!(extract_revocation(&rot_rec).is_none());
        assert!(extract_sphincs_rotation(&rot_rec).is_none());

        let sph_rec = rec_with(sphincs_rotation_metadata(b"\x03\x04", "upgrade"));
        assert!(extract_key_rotation(&sph_rec).is_none());
        assert!(extract_revocation(&sph_rec).is_none());
        assert!(extract_sphincs_rotation(&sph_rec).is_some());

        let rev_rec = rec_with(revocation_metadata(b"\x05\x06", "compromise"));
        assert!(extract_key_rotation(&rev_rec).is_none());
        assert!(extract_revocation(&rev_rec).is_some());
        assert!(extract_sphincs_rotation(&rev_rec).is_none());

        // No metadata at all: all three return None.
        let bare = rec_no_meta();
        assert!(extract_key_rotation(&bare).is_none());
        assert!(extract_revocation(&bare).is_none());
        assert!(extract_sphincs_rotation(&bare).is_none());

        // Flag-as-string "true" (not JSON bool) → None (.as_bool() returns None).
        let mut m = std::collections::BTreeMap::new();
        m.insert(KEY_ROTATION_KEY.into(), serde_json::json!("true"));
        m.insert("new_public_key".into(), serde_json::json!("0102"));
        assert!(extract_key_rotation(&rec_with(m)).is_none());

        // Flag-as-number 1 (not bool) → None.
        let mut m = std::collections::BTreeMap::new();
        m.insert(KEY_ROTATION_KEY.into(), serde_json::json!(1));
        m.insert("new_public_key".into(), serde_json::json!("0102"));
        assert!(extract_key_rotation(&rec_with(m)).is_none());

        // Flag-as-null → None.
        let mut m = std::collections::BTreeMap::new();
        m.insert(KEY_ROTATION_KEY.into(), serde_json::json!(null));
        m.insert("new_public_key".into(), serde_json::json!("0102"));
        assert!(extract_key_rotation(&rec_with(m)).is_none());

        // Flag = false → None.
        let mut m = std::collections::BTreeMap::new();
        m.insert(KEY_ROTATION_KEY.into(), serde_json::json!(false));
        m.insert("new_public_key".into(), serde_json::json!("0102"));
        assert!(extract_key_rotation(&rec_with(m)).is_none());

        // Flag=true but missing payload "new_public_key" → None.
        let mut m = std::collections::BTreeMap::new();
        m.insert(KEY_ROTATION_KEY.into(), serde_json::json!(true));
        assert!(extract_key_rotation(&rec_with(m)).is_none());

        // Flag=true + payload as bool (not string) → None (as_str fails).
        let mut m = std::collections::BTreeMap::new();
        m.insert(KEY_ROTATION_KEY.into(), serde_json::json!(true));
        m.insert("new_public_key".into(), serde_json::json!(true));
        assert!(extract_key_rotation(&rec_with(m)).is_none());

        // Flag=true + payload not-hex string → None (hex::decode fails).
        let mut m = std::collections::BTreeMap::new();
        m.insert(KEY_ROTATION_KEY.into(), serde_json::json!(true));
        m.insert("new_public_key".into(), serde_json::json!("not hex here"));
        assert!(extract_key_rotation(&rec_with(m)).is_none());

        // Flag=true + empty hex string → Some(KeyRotation { new_public_key: empty Vec, .. }).
        let mut m = std::collections::BTreeMap::new();
        m.insert(KEY_ROTATION_KEY.into(), serde_json::json!(true));
        m.insert("new_public_key".into(), serde_json::json!(""));
        let extracted = extract_key_rotation(&rec_with(m)).expect("empty hex ok");
        assert!(extracted.new_public_key.is_empty());

        // Flag=true + missing rotation_reason → reason = "unspecified" default.
        let mut m = std::collections::BTreeMap::new();
        m.insert(KEY_ROTATION_KEY.into(), serde_json::json!(true));
        m.insert("new_public_key".into(), serde_json::json!("00"));
        let extracted = extract_key_rotation(&rec_with(m)).expect("ok");
        assert_eq!(extracted.reason, "unspecified");

        // Same default-fallback for sphincs.
        let mut m = std::collections::BTreeMap::new();
        m.insert(SPHINCS_ROTATION_KEY.into(), serde_json::json!(true));
        m.insert("new_sphincs_public_key".into(), serde_json::json!("00"));
        let extracted = extract_sphincs_rotation(&rec_with(m)).expect("ok");
        assert_eq!(extracted.reason, "unspecified");

        // Same default-fallback for revocation.
        let mut m = std::collections::BTreeMap::new();
        m.insert(REVOCATION_OP_KEY.into(), serde_json::json!(true));
        m.insert("revoked_public_key".into(), serde_json::json!("00"));
        let extracted = extract_revocation(&rec_with(m)).expect("ok");
        assert_eq!(extracted.reason, "unspecified");

        // Symmetric: revocation flag-as-string, sphincs flag-as-number → None.
        let mut m = std::collections::BTreeMap::new();
        m.insert(REVOCATION_OP_KEY.into(), serde_json::json!("true"));
        m.insert("revoked_public_key".into(), serde_json::json!("00"));
        assert!(extract_revocation(&rec_with(m)).is_none());
        let mut m = std::collections::BTreeMap::new();
        m.insert(SPHINCS_ROTATION_KEY.into(), serde_json::json!(0));
        m.insert("new_sphincs_public_key".into(), serde_json::json!("00"));
        assert!(extract_sphincs_rotation(&rec_with(m)).is_none());
    }

    /// KeyRotation / SphincsKeyRotation / RevocationEntry struct shape pins:
    /// field counts, Clone independence, serde round-trip (JSON) preserves
    /// every field, Debug non-empty + contains field names. RevocationEntry
    /// has 6 fields; KeyRotation and SphincsKeyRotation each have 4.
    #[test]
    fn batch_b_rotation_and_revocation_struct_shapes_clone_serde_and_debug() {
        // KeyRotation 4-field shape pin.
        let kr = KeyRotation {
            new_public_key: vec![0x01, 0x02, 0x03],
            rotated_at: 12345.5,
            reason: "periodic".to_string(),
            record_id: "rec-1".to_string(),
        };
        let kr_clone = kr.clone();
        assert_eq!(kr_clone.new_public_key, kr.new_public_key);
        assert_eq!(kr_clone.rotated_at, kr.rotated_at);
        assert_eq!(kr_clone.reason, kr.reason);
        assert_eq!(kr_clone.record_id, kr.record_id);
        // Independence: mutating clone does not touch original.
        let mut kr_clone = kr_clone;
        kr_clone.new_public_key.push(0xFF);
        assert_ne!(kr_clone.new_public_key, kr.new_public_key);
        assert_eq!(kr.new_public_key.len(), 3);
        // Serde JSON round-trip preserves all 4 fields.
        let json = serde_json::to_string(&kr).expect("ser");
        let back: KeyRotation = serde_json::from_str(&json).expect("de");
        assert_eq!(back.new_public_key, kr.new_public_key);
        assert_eq!(back.rotated_at, kr.rotated_at);
        assert_eq!(back.reason, kr.reason);
        assert_eq!(back.record_id, kr.record_id);
        // Debug non-empty + contains field names.
        let dbg = format!("{:?}", kr);
        assert!(!dbg.is_empty());
        assert!(dbg.contains("new_public_key"));
        assert!(dbg.contains("rotated_at"));
        assert!(dbg.contains("reason"));
        assert!(dbg.contains("record_id"));

        // SphincsKeyRotation 4-field shape pin (mirrors KeyRotation but field
        // named new_sphincs_pk to discriminate the algorithm at the type
        // level — important for serde JSON field collision rules).
        let sr = SphincsKeyRotation {
            new_sphincs_pk: vec![0x10, 0x11, 0x12, 0x13],
            rotated_at: 99.0,
            reason: "upgrade".to_string(),
            record_id: "srec-1".to_string(),
        };
        let sr_clone = sr.clone();
        assert_eq!(sr_clone.new_sphincs_pk, sr.new_sphincs_pk);
        assert_eq!(sr_clone.rotated_at, sr.rotated_at);
        assert_eq!(sr_clone.reason, sr.reason);
        assert_eq!(sr_clone.record_id, sr.record_id);
        let json = serde_json::to_string(&sr).expect("ser");
        let back: SphincsKeyRotation = serde_json::from_str(&json).expect("de");
        assert_eq!(back.new_sphincs_pk, sr.new_sphincs_pk);
        assert_eq!(back.rotated_at, sr.rotated_at);
        assert_eq!(back.reason, sr.reason);
        assert_eq!(back.record_id, sr.record_id);
        let dbg = format!("{:?}", sr);
        assert!(dbg.contains("new_sphincs_pk"));
        assert!(dbg.contains("rotated_at"));
        // Differs from KeyRotation: field name "new_sphincs_pk" not "new_public_key".
        assert!(!dbg.contains("new_public_key:"));

        // RevocationEntry 6-field shape pin.
        let re = RevocationEntry {
            revoked_key_hash: "deadbeef".to_string(),
            revoked_public_key: vec![0xDE, 0xAD, 0xBE, 0xEF],
            revoked_at: 5000.0,
            reason: "compromise".to_string(),
            record_id: "rev-1".to_string(),
            identity_hash: "id-1".to_string(),
        };
        let re_clone = re.clone();
        assert_eq!(re_clone.revoked_key_hash, re.revoked_key_hash);
        assert_eq!(re_clone.revoked_public_key, re.revoked_public_key);
        assert_eq!(re_clone.revoked_at, re.revoked_at);
        assert_eq!(re_clone.reason, re.reason);
        assert_eq!(re_clone.record_id, re.record_id);
        assert_eq!(re_clone.identity_hash, re.identity_hash);
        let json = serde_json::to_string(&re).expect("ser");
        let back: RevocationEntry = serde_json::from_str(&json).expect("de");
        assert_eq!(back.revoked_key_hash, re.revoked_key_hash);
        assert_eq!(back.revoked_public_key, re.revoked_public_key);
        assert_eq!(back.revoked_at, re.revoked_at);
        assert_eq!(back.reason, re.reason);
        assert_eq!(back.record_id, re.record_id);
        assert_eq!(back.identity_hash, re.identity_hash);
        let dbg = format!("{:?}", re);
        assert!(dbg.contains("revoked_key_hash"));
        assert!(dbg.contains("revoked_public_key"));
        assert!(dbg.contains("revoked_at"));
        assert!(dbg.contains("identity_hash"));
        assert!(dbg.contains("record_id"));
        assert!(dbg.contains("reason"));
    }
}
