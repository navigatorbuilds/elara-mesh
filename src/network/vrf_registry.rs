//! VRF key registry — per-anchor VRF public key registration via DAG records.
//!
//! Each anchor node generates a VRF keypair locally and submits a signed
//! `vrf_registration` record to the DAG. All nodes store the mapping
//! `identity_hash → VrfPublicKey` and use it to verify epoch seals.
//!
//! This replaces the single global VRF public key model. Genesis authority
//! is backwards-compatible — its key is auto-registered from the config.
//!
//! Registration records have metadata:
//! ```json
//! {
//!   "vrf_registration": true,
//!   "vrf_public_key": "<hex>",
//!   "node_type": "anchor"
//! }
//! ```
//!
//! Spec references:
//!   @spec Protocol §11.12 (Multi-anchor VRF sealing)

use std::collections::HashMap;

use crate::crypto::vrf::VrfPublicKey;
use crate::record::ValidationRecord;

/// Metadata key for VRF registration records.
pub const VRF_REGISTRATION_KEY: &str = "vrf_registration";

/// A single VRF key registration event.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VrfRegistration {
    /// The registered VRF public key hash (32 bytes, hex-encoded).
    pub vrf_public_key_hex: String,
    /// Full Dilithium3 VRF public key (1,952 bytes, hex-encoded).
    /// Needed for actual VRF proof verification. Empty for legacy registrations.
    #[serde(default)]
    pub vrf_full_public_key_hex: String,
    /// Timestamp when the registration record was created.
    pub registered_at: f64,
    /// Record ID of the registration record.
    pub record_id: String,
    /// Node type at registration time (should be "anchor").
    pub node_type: String,
}

/// Per-anchor VRF public key registry.
///
/// Maps `identity_hash → VrfRegistration` (latest wins — re-registration replaces).
/// Thread-safe when wrapped in RwLock (which NodeState does).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct VrfRegistry {
    /// identity_hash → latest VRF registration.
    registrations: HashMap<String, VrfRegistration>,
}

impl VrfRegistry {
    pub fn new() -> Self {
        Self {
            registrations: HashMap::new(),
        }
    }

    /// Register or update a VRF public key for an anchor identity.
    pub fn register(&mut self, identity_hash: &str, registration: VrfRegistration) {
        // Latest registration wins — allows key rotation.
        let existing = self.registrations.get(identity_hash);
        if existing.is_none_or(|e| registration.registered_at >= e.registered_at) {
            self.registrations
                .insert(identity_hash.to_string(), registration);
        }
    }

    /// Look up the VRF public key for an anchor identity.
    /// Returns `None` if the identity has no registered VRF key.
    /// Returns a full key (capable of VRF verification) if the full public key
    /// was stored. Otherwise returns a hash-only key (display/compare only).
    pub fn get_public_key(&self, identity_hash: &str) -> Option<VrfPublicKey> {
        let reg = self.registrations.get(identity_hash)?;

        // Try full key first (1,952 bytes — can verify VRF proofs)
        if !reg.vrf_full_public_key_hex.is_empty() {
            if let Ok(full_bytes) = hex::decode(&reg.vrf_full_public_key_hex) {
                if full_bytes.len() >= 1900 {
                    return Some(VrfPublicKey::from_full_bytes(&full_bytes));
                }
            }
        }

        // Fall back to hash-only (32 bytes — display/compare only, cannot verify)
        let bytes = hex::decode(&reg.vrf_public_key_hex).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(VrfPublicKey::from_bytes(arr))
    }

    /// Check if an identity has a registered VRF key.
    pub fn is_registered(&self, identity_hash: &str) -> bool {
        self.registrations.contains_key(identity_hash)
    }

    /// Number of registered anchors.
    pub fn count(&self) -> usize {
        self.registrations.len()
    }

    /// All registered identity hashes (for admin/status endpoints).
    pub fn registered_identities(&self) -> Vec<&str> {
        self.registrations.keys().map(|s| s.as_str()).collect()
    }

    /// Get registration details for an identity (for admin endpoint).
    pub fn get_registration(&self, identity_hash: &str) -> Option<&VrfRegistration> {
        self.registrations.get(identity_hash)
    }
}

/// Extract a VRF registration from a record's metadata, if present.
pub fn extract_vrf_registration(record: &ValidationRecord) -> Option<VrfRegistration> {
    let is_registration = record
        .metadata
        .get(VRF_REGISTRATION_KEY)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !is_registration {
        return None;
    }

    let vrf_pk_hex = record
        .metadata
        .get("vrf_public_key")
        .and_then(|v| v.as_str())?;

    // Validate hex decodes to 32 bytes
    let bytes = hex::decode(vrf_pk_hex).ok()?;
    if bytes.len() != 32 {
        return None;
    }

    let node_type = record
        .metadata
        .get("node_type")
        .and_then(|v| v.as_str())
        .unwrap_or("anchor")
        .to_string();

    // Only anchors can register VRF keys (Protocol §11.12).
    // At 1M nodes with 4KB VRF records each, allowing all node types
    // would produce 4GB of VRF data. Anchors are ~1% of nodes.
    if !crate::network::peer::NodeType::from_str(&node_type).can_seal_epochs() {
        return None;
    }

    // Extract full public key if present (new format)
    let vrf_full_pk_hex = record
        .metadata
        .get("vrf_full_public_key")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Some(VrfRegistration {
        vrf_public_key_hex: vrf_pk_hex.to_string(),
        vrf_full_public_key_hex: vrf_full_pk_hex,
        registered_at: record.timestamp,
        record_id: record.id.clone(),
        node_type,
    })
}

/// Persist a single registration to `CF_VRF_KEYS` so it survives restart.
///
/// Keyed by raw `identity_hash` bytes, value is the JSON-encoded
/// `VrfRegistration`. On restart, [`rehydrate_registry`] walks this CF
/// and repopulates the in-memory map.
///
/// Scale: at 10K anchors × ~2 KB per registration = ~20 MB. One row per
/// anchor identity, overwritten on re-registration (latest wins).
pub fn persist_registration(
    rocks: &crate::storage::rocks::StorageEngine,
    identity_hash: &str,
    reg: &VrfRegistration,
) -> crate::errors::Result<()> {
    let bytes = serde_json::to_vec(reg).map_err(|e| {
        crate::errors::ElaraError::Storage(format!("vrf reg serialize: {e}"))
    })?;
    rocks.put_cf_raw(
        crate::storage::rocks::CF_VRF_KEYS,
        identity_hash.as_bytes(),
        &bytes,
    )
}

/// Reconstruct a `VrfRegistry` from persisted rows in `CF_VRF_KEYS`.
///
/// Bounded scan — the CF holds one row per registered anchor identity,
/// not per record. At 10K anchors this is ~10K iterations on startup,
/// satisfies the O(active-population) scale rule. Malformed rows are
/// skipped with a debug log rather than failing startup.
pub fn rehydrate_registry(
    rocks: &crate::storage::rocks::StorageEngine,
) -> VrfRegistry {
    let mut reg = VrfRegistry::new();
    // Upper bound matches the documented 10K-anchor ceiling with 10× headroom.
    const MAX_ANCHOR_REHYDRATE: usize = 100_000;
    match rocks.list_cf_raw(crate::storage::rocks::CF_VRF_KEYS, MAX_ANCHOR_REHYDRATE) {
        Ok(rows) => {
            for (k, v) in rows {
                let Ok(identity_hash) = std::str::from_utf8(&k) else {
                    continue;
                };
                match serde_json::from_slice::<VrfRegistration>(&v) {
                    Ok(r) => reg.register(identity_hash, r),
                    Err(e) => {
                        tracing::debug!(
                            "VRF rehydrate: skipping malformed row id={} err={e}",
                            identity_hash
                        );
                    }
                }
            }
        }
        Err(e) => tracing::warn!("VRF rehydrate: CF scan failed: {e}"),
    }
    reg
}

/// Build metadata for a VRF registration record.
pub fn vrf_registration_metadata(
    vrf_public_key: &VrfPublicKey,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(VRF_REGISTRATION_KEY.into(), serde_json::json!(true));
    m.insert("node_type".into(), serde_json::json!("anchor"));
    m.insert(
        "vrf_public_key".into(),
        serde_json::json!(hex::encode(vrf_public_key.as_bytes())),
    );
    // Store full Dilithium3 public key (1,952 bytes) for VRF proof verification.
    // Legacy registrations only had the 32-byte hash which can't verify proofs.
    let full_pk = vrf_public_key.full_pk();
    if !full_pk.is_empty() {
        m.insert(
            "vrf_full_public_key".into(),
            serde_json::json!(hex::encode(full_pk)),
        );
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registration(identity: &str, pk_hex: &str, ts: f64) -> (String, VrfRegistration) {
        (
            identity.to_string(),
            VrfRegistration {
                vrf_public_key_hex: pk_hex.to_string(),
                vrf_full_public_key_hex: String::new(),
                registered_at: ts,
                record_id: format!("reg-{identity}"),
                node_type: "anchor".to_string(),
            },
        )
    }

    #[test]
    fn test_register_and_lookup() {
        let mut registry = VrfRegistry::new();
        let pk_hex = hex::encode([0xAAu8; 32]);
        let (id, reg) = make_registration("anchor1", &pk_hex, 1000.0);
        registry.register(&id, reg);

        assert!(registry.is_registered("anchor1"));
        assert!(!registry.is_registered("anchor2"));
        assert_eq!(registry.count(), 1);

        let pk = registry.get_public_key("anchor1");
        assert!(pk.is_some());
        assert_eq!(pk.unwrap().as_bytes(), &[0xAAu8; 32]);
    }

    #[test]
    fn test_re_registration_replaces() {
        let mut registry = VrfRegistry::new();
        let pk1 = hex::encode([0xAAu8; 32]);
        let pk2 = hex::encode([0xBBu8; 32]);

        let (id, reg1) = make_registration("anchor1", &pk1, 1000.0);
        registry.register(&id, reg1);

        let (id, reg2) = make_registration("anchor1", &pk2, 2000.0);
        registry.register(&id, reg2);

        let pk = registry.get_public_key("anchor1").unwrap();
        assert_eq!(pk.as_bytes(), &[0xBBu8; 32], "should be the newer key");
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_old_registration_ignored() {
        let mut registry = VrfRegistry::new();
        let pk1 = hex::encode([0xAAu8; 32]);
        let pk2 = hex::encode([0xBBu8; 32]);

        let (id, reg1) = make_registration("anchor1", &pk1, 2000.0);
        registry.register(&id, reg1);

        // Older registration should NOT replace
        let (id, reg2) = make_registration("anchor1", &pk2, 1000.0);
        registry.register(&id, reg2);

        let pk = registry.get_public_key("anchor1").unwrap();
        assert_eq!(pk.as_bytes(), &[0xAAu8; 32], "should keep the newer key");
    }

    #[test]
    fn test_multiple_anchors() {
        let mut registry = VrfRegistry::new();
        for i in 0..5 {
            let pk = hex::encode([i as u8; 32]);
            let (id, reg) = make_registration(&format!("anchor{i}"), &pk, 1000.0);
            registry.register(&id, reg);
        }
        assert_eq!(registry.count(), 5);
        assert_eq!(registry.registered_identities().len(), 5);
    }

    #[test]
    fn test_invalid_key_length_rejected() {
        let mut registry = VrfRegistry::new();
        let bad_pk = hex::encode([0xAAu8; 16]); // 16 bytes, not 32
        let (id, reg) = make_registration("anchor1", &bad_pk, 1000.0);
        registry.register(&id, reg);
        // Registration stored but lookup returns None (invalid key length)
        assert!(registry.get_public_key("anchor1").is_none());
    }

    #[test]
    fn test_extract_from_record() {
        let mut meta = std::collections::BTreeMap::new();
        meta.insert(VRF_REGISTRATION_KEY.into(), serde_json::json!(true));
        meta.insert("vrf_public_key".into(), serde_json::json!(hex::encode([0xCCu8; 32])));
        meta.insert("node_type".into(), serde_json::json!("anchor"));

        let record = ValidationRecord {
            id: "test-reg".to_string(),
            version: crate::wire::WIRE_VERSION,
            content_hash: vec![0u8; 32],
            creator_public_key: vec![0u8; 1952],
            timestamp: 1000.0,
            parents: vec![],
            classification: crate::record::Classification::Public,
            metadata: meta,
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };

        let reg = extract_vrf_registration(&record).unwrap();
        assert_eq!(reg.vrf_public_key_hex, hex::encode([0xCCu8; 32]));
        assert_eq!(reg.node_type, "anchor");
        assert_eq!(reg.record_id, "test-reg");
    }

    #[test]
    fn test_non_anchor_vrf_registration_rejected() {
        // Non-anchor node types must not be able to register VRF keys.
        // At 1M nodes, allowing all types would produce 4GB of VRF data.
        for node_type in &["leaf", "relay", "witness", "archive", "gateway"] {
            let mut meta = std::collections::BTreeMap::new();
            meta.insert(VRF_REGISTRATION_KEY.into(), serde_json::json!(true));
            meta.insert("vrf_public_key".into(), serde_json::json!(hex::encode([0xBBu8; 32])));
            meta.insert("node_type".into(), serde_json::json!(node_type));

            let record = ValidationRecord {
                id: format!("reg-{node_type}"),
                version: crate::wire::WIRE_VERSION,
                content_hash: vec![0u8; 32],
                creator_public_key: vec![0u8; 1952],
                timestamp: 2000.0,
                parents: vec![],
                classification: crate::record::Classification::Public,
                metadata: meta,
                signature: None,
                sphincs_signature: None,
                zk_proof: None,
                itc_stamp: None,
                zone_refs: Vec::new(),
                creator_sphincs_pk: None,
                sig_algorithm: 0x01,
                sphincs_algorithm: None,
                zone: None,
                identity_hash_wire: None,
                nonce: 0,
            };

            assert!(
                extract_vrf_registration(&record).is_none(),
                "node_type={node_type} should be rejected for VRF registration"
            );
        }
    }

    #[test]
    fn test_persist_and_rehydrate_roundtrip() {
        use crate::storage::rocks::StorageEngine;

        let tmp = tempfile::tempdir().expect("tempdir");
        let rocks = StorageEngine::open(tmp.path().join("rocksdb")).expect("open rocks");

        // Seed three registrations.
        let ids = ["anchor-a", "anchor-b", "anchor-c"];
        for (i, id) in ids.iter().enumerate() {
            let reg = VrfRegistration {
                vrf_public_key_hex: hex::encode([i as u8 + 1; 32]),
                vrf_full_public_key_hex: hex::encode(vec![0x11; 1952]),
                registered_at: 1000.0 + i as f64,
                record_id: format!("reg-{id}"),
                node_type: "anchor".into(),
            };
            persist_registration(&rocks, id, &reg).expect("persist");
        }

        // Fresh process: rehydrate from disk only.
        let rehydrated = rehydrate_registry(&rocks);
        assert_eq!(rehydrated.count(), 3);
        for (i, id) in ids.iter().enumerate() {
            let got = rehydrated.get_registration(id).expect(id);
            assert_eq!(got.vrf_public_key_hex, hex::encode([i as u8 + 1; 32]));
            assert_eq!(got.record_id, format!("reg-{id}"));
        }
    }

    #[test]
    fn test_rehydrate_empty_cf_yields_empty_registry() {
        use crate::storage::rocks::StorageEngine;
        let tmp = tempfile::tempdir().expect("tempdir");
        let rocks = StorageEngine::open(tmp.path().join("rocksdb")).expect("open rocks");
        let reg = rehydrate_registry(&rocks);
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn test_persist_overwrites_on_key_rotation() {
        use crate::storage::rocks::StorageEngine;
        let tmp = tempfile::tempdir().expect("tempdir");
        let rocks = StorageEngine::open(tmp.path().join("rocksdb")).expect("open rocks");

        let id = "anchor-1";
        let reg_old = VrfRegistration {
            vrf_public_key_hex: hex::encode([0xAAu8; 32]),
            vrf_full_public_key_hex: String::new(),
            registered_at: 1000.0,
            record_id: "reg-old".into(),
            node_type: "anchor".into(),
        };
        persist_registration(&rocks, id, &reg_old).unwrap();

        let reg_new = VrfRegistration {
            vrf_public_key_hex: hex::encode([0xBBu8; 32]),
            vrf_full_public_key_hex: String::new(),
            registered_at: 2000.0,
            record_id: "reg-new".into(),
            node_type: "anchor".into(),
        };
        persist_registration(&rocks, id, &reg_new).unwrap();

        let rehydrated = rehydrate_registry(&rocks);
        assert_eq!(rehydrated.count(), 1);
        let got = rehydrated.get_registration(id).unwrap();
        assert_eq!(got.record_id, "reg-new");
    }

    #[test]
    fn test_metadata_builder_includes_node_type() {
        let pk = VrfPublicKey::from_bytes([0xAAu8; 32]);
        let meta = vrf_registration_metadata(&pk);
        assert_eq!(
            meta.get("node_type").and_then(|v| v.as_str()),
            Some("anchor"),
            "metadata builder must include node_type=anchor"
        );
    }

    /// Pin the resident-set semantics for `count()` so the
    /// `elara_vrf_registry_identities` /metrics gauge reflects exactly the
    /// number of distinct identities — no inflation on re-registration,
    /// no shrinkage on older-timestamped re-registration, and `count()`
    /// always agrees with `registered_identities().len()`.
    ///
    /// Operator dashboard story: alongside `_consensus_committee_zones_below_target`,
    /// this gauge must report TRUE eligible-pool cardinality. If
    /// `count()` ever diverged from the underlying HashMap (e.g. via a bad
    /// refactor that started counting registration *records* instead of
    /// distinct identities), operators would see a phantom "VRF coverage
    /// healthy" while committees still couldn't form. Pin the invariant.
    #[test]
    fn ops_50_metric_invariants_pin_resident_set_cardinality() {
        let mut registry = VrfRegistry::new();

        // I1: fresh registry → count = 0, identities empty.
        assert_eq!(registry.count(), 0);
        assert_eq!(registry.registered_identities().len(), 0);

        // I2: registering N distinct identities → count = N.
        let n = 7;
        for i in 0..n {
            let pk = hex::encode([i as u8; 32]);
            let (id, reg) = make_registration(&format!("anchor{i}"), &pk, 1000.0);
            registry.register(&id, reg);
        }
        assert_eq!(registry.count(), n);
        assert_eq!(
            registry.registered_identities().len(),
            n,
            "count() and registered_identities().len() must agree"
        );

        // I3: re-registering the SAME identity with a NEWER timestamp must
        // replace in place — no count inflation. Critical: this is the
        // common case (key rotation) and the mainnet design assumes it.
        let pk_new = hex::encode([0xFFu8; 32]);
        let (id, reg_new) = make_registration("anchor0", &pk_new, 5000.0);
        registry.register(&id, reg_new);
        assert_eq!(
            registry.count(),
            n,
            "key rotation (newer ts, same identity) must NOT inflate count"
        );
        assert_eq!(registry.registered_identities().len(), n);

        // I4: re-registering with the SAME timestamp is also a HashMap
        // overwrite (>= comparison in `register`), so count stays put.
        let pk_same_ts = hex::encode([0xEEu8; 32]);
        let (id, reg_same_ts) = make_registration("anchor0", &pk_same_ts, 5000.0);
        registry.register(&id, reg_same_ts);
        assert_eq!(
            registry.count(),
            n,
            "same-timestamp re-registration must not change cardinality"
        );

        // I5: re-registering with an OLDER timestamp is rejected (no replace),
        // and obviously must not inflate count either.
        let pk_old = hex::encode([0xDDu8; 32]);
        let (id, reg_old) = make_registration("anchor0", &pk_old, 100.0);
        registry.register(&id, reg_old);
        assert_eq!(
            registry.count(),
            n,
            "older-timestamp re-registration must not change cardinality"
        );
        assert_eq!(registry.registered_identities().len(), n);

        // I6: registering NEW distinct identities continues to grow the set.
        for i in n..(n + 3) {
            let pk = hex::encode([i as u8; 32]);
            let (id, reg) = make_registration(&format!("anchor{i}"), &pk, 1000.0);
            registry.register(&id, reg);
        }
        assert_eq!(
            registry.count(),
            n + 3,
            "fresh distinct identities must each contribute +1"
        );
        assert_eq!(registry.registered_identities().len(), n + 3);
    }

    // ============================================================
    // Fixture-free tests (no storage/no NodeState)
    // ============================================================

    #[test]
    fn batch_b_vrf_registration_key_strict_pin_with_ascii_snake_case_and_cross_module_disjointness() {
        // Exact byte pin — drift changes the on-record metadata schema.
        assert_eq!(VRF_REGISTRATION_KEY, "vrf_registration");
        assert_eq!(VRF_REGISTRATION_KEY.len(), 16);
        // All ASCII, all lowercase or underscore.
        assert!(VRF_REGISTRATION_KEY.is_ascii());
        assert!(VRF_REGISTRATION_KEY
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '_'));
        // No leading/trailing underscore — keeps JSON-key shape canonical.
        assert!(!VRF_REGISTRATION_KEY.starts_with('_'));
        assert!(!VRF_REGISTRATION_KEY.ends_with('_'));
        // Exactly one underscore separator (snake_case shape: noun_noun).
        assert_eq!(VRF_REGISTRATION_KEY.matches('_').count(), 1);
        // Cross-module disjointness: must not collide with any other
        // metadata key the extractor or other modules read. A collision
        // would let one module's records be mis-extracted as another's.
        let other_keys: &[&str] = &[
            "vrf_public_key",
            "vrf_full_public_key",
            "node_type",
            "beat_op",
            "beat_to",
            "beat_record_id",
            "delegation",
            "witness_attestation",
            "geo_fraud",
            "fork_check",
        ];
        for k in other_keys {
            assert_ne!(
                VRF_REGISTRATION_KEY, *k,
                "VRF_REGISTRATION_KEY collides with metadata key {k}"
            );
        }
    }

    #[test]
    fn batch_b_vrf_registration_metadata_builder_shape_and_canonical_value_pin() {
        let pk = VrfPublicKey::from_bytes([0x5Au8; 32]);
        let meta = vrf_registration_metadata(&pk);
        // Key count: 3 (registration flag, node_type, hash) when full_pk is
        // empty, 4 when present (adds vrf_full_public_key).
        assert!(
            meta.len() == 3 || meta.len() == 4,
            "metadata key count must be 3 or 4, got {}",
            meta.len()
        );
        // VRF_REGISTRATION_KEY → bool true (NOT a string "true").
        assert_eq!(
            meta.get(VRF_REGISTRATION_KEY).and_then(|v| v.as_bool()),
            Some(true)
        );
        // node_type → "anchor" (NOT capitalized, NOT plural).
        assert_eq!(meta.get("node_type").and_then(|v| v.as_str()), Some("anchor"));
        // vrf_public_key → 64-char lowercase hex of the 32-byte hash.
        let pk_hex = meta
            .get("vrf_public_key")
            .and_then(|v| v.as_str())
            .expect("vrf_public_key present");
        assert_eq!(pk_hex.len(), 64);
        assert!(pk_hex
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        assert_eq!(pk_hex, hex::encode([0x5Au8; 32]));
        // BTreeMap iteration order is sorted — pin the canonical key order
        // since record-hashing depends on canonical metadata serialization.
        let keys: Vec<&str> = meta.keys().map(|s| s.as_str()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "BTreeMap must yield keys in sorted order");
        // The first key alphabetically is "node_type" (precedes "vrf_*").
        assert_eq!(keys[0], "node_type");
    }

    #[test]
    fn batch_b_vrf_registration_serde_roundtrip_and_legacy_default_for_full_pk() {
        let reg = VrfRegistration {
            vrf_public_key_hex: hex::encode([0x11u8; 32]),
            vrf_full_public_key_hex: hex::encode([0x22u8; 1952]),
            registered_at: 1_234_567.0,
            record_id: "rec-abc".into(),
            node_type: "anchor".into(),
        };
        // Roundtrip preserves all 5 fields bit-identically.
        let bytes = serde_json::to_vec(&reg).expect("serialize");
        let back: VrfRegistration = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(back.vrf_public_key_hex, reg.vrf_public_key_hex);
        assert_eq!(back.vrf_full_public_key_hex, reg.vrf_full_public_key_hex);
        assert_eq!(back.registered_at, reg.registered_at);
        assert_eq!(back.record_id, reg.record_id);
        assert_eq!(back.node_type, reg.node_type);
        // JSON shape: object with EXACTLY 5 snake_case keys.
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("parse");
        let obj = json.as_object().expect("top-level object");
        let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "node_type",
                "record_id",
                "registered_at",
                "vrf_full_public_key_hex",
                "vrf_public_key_hex"
            ]
        );
        // Legacy registrations (pre-full-PK) lack vrf_full_public_key_hex —
        // #[serde(default)] must let them deserialize cleanly. This is the
        // load-bearing field for backwards compatibility with pre-rotation
        // mainnet registrations.
        let legacy_json = serde_json::json!({
            "vrf_public_key_hex": hex::encode([0x33u8; 32]),
            "registered_at": 99.0,
            "record_id": "legacy",
            "node_type": "anchor"
            // vrf_full_public_key_hex deliberately omitted
        });
        let legacy: VrfRegistration =
            serde_json::from_value(legacy_json).expect("legacy deserialize");
        assert_eq!(legacy.vrf_full_public_key_hex, String::new());
        assert_eq!(legacy.record_id, "legacy");
        assert_eq!(legacy.vrf_public_key_hex, hex::encode([0x33u8; 32]));
    }

    #[test]
    fn batch_b_extract_vrf_registration_negative_paths_pre_node_type_gate() {
        let base_record =
            |meta: std::collections::BTreeMap<String, serde_json::Value>| ValidationRecord {
                id: "neg-test".into(),
                version: crate::wire::WIRE_VERSION,
                content_hash: vec![0u8; 32],
                creator_public_key: vec![0u8; 1952],
                timestamp: 1000.0,
                parents: vec![],
                classification: crate::record::Classification::Public,
                metadata: meta,
                signature: None,
                sphincs_signature: None,
                zk_proof: None,
                itc_stamp: None,
                zone_refs: Vec::new(),
                creator_sphincs_pk: None,
                sig_algorithm: 0x01,
                sphincs_algorithm: None,
                zone: None,
                identity_hash_wire: None,
                nonce: 0,
            };

        // (a) missing VRF_REGISTRATION_KEY → unwrap_or(false) → None.
        let m = std::collections::BTreeMap::new();
        assert!(extract_vrf_registration(&base_record(m)).is_none());

        // (b) VRF_REGISTRATION_KEY explicitly false → None.
        let mut m = std::collections::BTreeMap::new();
        m.insert(VRF_REGISTRATION_KEY.into(), serde_json::json!(false));
        m.insert(
            "vrf_public_key".into(),
            serde_json::json!(hex::encode([0xAAu8; 32])),
        );
        assert!(extract_vrf_registration(&base_record(m)).is_none());

        // (c) missing vrf_public_key → None on ?.
        let mut m = std::collections::BTreeMap::new();
        m.insert(VRF_REGISTRATION_KEY.into(), serde_json::json!(true));
        assert!(extract_vrf_registration(&base_record(m)).is_none());

        // (d) vrf_public_key non-hex (contains 'Z') → decode fails → None.
        let mut m = std::collections::BTreeMap::new();
        m.insert(VRF_REGISTRATION_KEY.into(), serde_json::json!(true));
        m.insert("vrf_public_key".into(), serde_json::json!("ZZZZ"));
        assert!(extract_vrf_registration(&base_record(m)).is_none());

        // (e) vrf_public_key hex valid but wrong length: 16, 31, 33, 64 bytes.
        for bad_len in [16usize, 31, 33, 64] {
            let mut m = std::collections::BTreeMap::new();
            m.insert(VRF_REGISTRATION_KEY.into(), serde_json::json!(true));
            m.insert(
                "vrf_public_key".into(),
                serde_json::json!(hex::encode(vec![0xAAu8; bad_len])),
            );
            assert!(
                extract_vrf_registration(&base_record(m)).is_none(),
                "{bad_len}-byte pk must be rejected"
            );
        }

        // POSITIVE control: 32-byte pk + anchor node_type → Some.
        let mut m = std::collections::BTreeMap::new();
        m.insert(VRF_REGISTRATION_KEY.into(), serde_json::json!(true));
        m.insert(
            "vrf_public_key".into(),
            serde_json::json!(hex::encode([0xAAu8; 32])),
        );
        m.insert("node_type".into(), serde_json::json!("anchor"));
        let ok = extract_vrf_registration(&base_record(m)).expect("positive control");
        assert_eq!(ok.vrf_public_key_hex, hex::encode([0xAAu8; 32]));
        assert_eq!(ok.node_type, "anchor");
    }

    #[test]
    fn batch_b_get_public_key_invalid_hash_length_sweep_and_full_pk_fallthrough_pin() {
        let mut registry = VrfRegistry::new();
        // (a) Identity registered with empty full_pk + invalid hash length →
        //     fallthrough to hash path → length check rejects → None.
        for bad_len in [0usize, 1, 16, 31, 33, 64] {
            let bad_hash_hex = hex::encode(vec![0xAAu8; bad_len]);
            let reg = VrfRegistration {
                vrf_public_key_hex: bad_hash_hex,
                vrf_full_public_key_hex: String::new(),
                registered_at: 1000.0,
                record_id: format!("bad-{bad_len}"),
                node_type: "anchor".into(),
            };
            let id = format!("anchor-bad-{bad_len}");
            registry.register(&id, reg);
            // Even though stored, get_public_key returns None.
            assert!(
                registry.get_public_key(&id).is_none(),
                "{bad_len}-byte hash must NOT resolve to a public key"
            );
            // But is_registered still reports true — the registration exists,
            // the LOOKUP just fails. This is the intended separation.
            assert!(registry.is_registered(&id));
        }

        // (b) Non-empty full_pk but too short (1899 bytes) + valid 32-byte
        //     hash backup → fallthrough to hash path → returns Some.
        // A drift accepting truncated full keys would let forged "full"
        // registrations spoof anchor VRFs.
        let reg = VrfRegistration {
            vrf_public_key_hex: hex::encode([0xCCu8; 32]),
            vrf_full_public_key_hex: hex::encode(vec![0x11u8; 1899]),
            registered_at: 2000.0,
            record_id: "fallthrough".into(),
            node_type: "anchor".into(),
        };
        registry.register("anchor-fall", reg);
        let pk = registry
            .get_public_key("anchor-fall")
            .expect("fallthrough must yield 32-byte hash key");
        assert_eq!(pk.as_bytes(), &[0xCCu8; 32]);

        // (c) Non-empty full_pk that's INVALID hex + valid 32-byte hash →
        //     fallthrough to hash path → returns Some.
        let reg = VrfRegistration {
            vrf_public_key_hex: hex::encode([0xDDu8; 32]),
            vrf_full_public_key_hex: "ZZZZ-not-hex".into(),
            registered_at: 3000.0,
            record_id: "bad-hex-fall".into(),
            node_type: "anchor".into(),
        };
        registry.register("anchor-bad-hex", reg);
        let pk = registry
            .get_public_key("anchor-bad-hex")
            .expect("invalid-hex full_pk must fall through to hash");
        assert_eq!(pk.as_bytes(), &[0xDDu8; 32]);

        // (d) Identity NEVER registered → get_public_key None (vs. registered-
        //     but-invalid which is also None — distinct semantics, same return).
        assert!(registry.get_public_key("never-registered").is_none());
        assert!(!registry.is_registered("never-registered"));
    }
}
