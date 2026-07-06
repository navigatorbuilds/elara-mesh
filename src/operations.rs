//! 9 DAM operations — the instruction set of the DVM.

//!
//! Spec references:
//!   @spec Protocol §3.3.4

use std::collections::BTreeMap;

use crate::crypto::hash::sha3_256;
use crate::crypto::pqc::dilithium3_verify;
use crate::dag::DagIndex;
use crate::errors::{ElaraError, Result};
use crate::identity::Identity;
use crate::record::{Classification, ValidationRecord};
use crate::storage::Storage;

/// DAM operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DamOp {
    Insert,
    Query,
    Witness,
    Merge,
    Classify,
    Analyze,
    Hash,
    Sign,
    Verify,
}

/// Configuration for the DVM.
#[derive(Debug, Clone)]
pub struct DvmConfig {
    pub verify_on_insert: bool,
    pub max_ancestors_depth: usize,
}

impl Default for DvmConfig {
    fn default() -> Self {
        Self {
            verify_on_insert: true,
            max_ancestors_depth: 100,
        }
    }
}

/// The DAM Virtual Machine — executes operations on a storage backend with an in-memory DAG index.
pub struct DamVm<S: Storage> {
    pub storage: S,
    pub dag: DagIndex,
    pub config: DvmConfig,
}

impl<S: Storage> DamVm<S> {
    pub fn new(storage: S, config: DvmConfig) -> Self {
        Self {
            storage,
            dag: DagIndex::new(),
            config,
        }
    }

    /// INSERT — Add a signed record to the DAG.
    pub fn insert(&mut self, record: &ValidationRecord) -> Result<String> {
        // Verify signature if configured
        if self.config.verify_on_insert {
            if let Some(sig) = &record.signature {
                let signable = record.signable_bytes();
                if !dilithium3_verify(&signable, sig, &record.creator_public_key)? {
                    return Err(ElaraError::InvalidSignature);
                }
                // Profile enforcement: SPHINCS+ pk and sig must be consistent
                if record.creator_sphincs_pk.is_some() && record.sphincs_signature.is_none() {
                    return Err(ElaraError::Wire(
                        "SPHINCS+ public key present but no SPHINCS+ signature".to_string()
                    ));
                }
                // Verify SPHINCS+ signature if present (Profile A dual-sig)
                if let Some(sphincs_sig) = &record.sphincs_signature {
                    let sphincs_pk = record.creator_sphincs_pk.as_ref()
                        .ok_or_else(|| ElaraError::Wire(
                            "SPHINCS+ signature present but no SPHINCS+ public key".to_string()
                        ))?;
                    if !crate::crypto::pqc::sphincs_verify(&signable, sphincs_sig, sphincs_pk)? {
                        return Err(ElaraError::InvalidSignature);
                    }
                }
            } else {
                return Err(ElaraError::InvalidSignature);
            }
        }

        // Insert into DAG index
        self.dag.insert(
            record.id.clone(),
            record.parents.clone(),
            record.timestamp,
        )?;

        // Insert into storage
        self.storage.insert(record)
    }

    /// QUERY — Retrieve records matching criteria.
    pub fn query(
        &self,
        classification: Option<Classification>,
        creator_key: Option<&[u8]>,
        since: Option<f64>,
        until: Option<f64>,
        limit: usize,
    ) -> Result<Vec<ValidationRecord>> {
        self.storage
            .query(classification, creator_key, since, until, limit)
    }

    /// WITNESS — Create a new record witnessing (referencing) current tip records.
    pub fn witness(
        &mut self,
        content: &[u8],
        identity: &Identity,
        classification: Classification,
        metadata: Option<BTreeMap<String, serde_json::Value>>,
    ) -> Result<String> {
        let tips = self.dag.tips();
        let mut record = ValidationRecord::create(
            content,
            identity.public_key.clone(),
            tips,
            classification,
            metadata,
        );

        // Sign (dual-sig for Profile A)
        identity.sign_record(&mut record)?;

        self.insert(&record)
    }

    /// WITNESS_PRIVATE — Create a PRIVATE record with a ZK proof (Protocol §5.3).
    ///
    /// Like `witness()` but always creates a PRIVATE record with the given ZK proof bytes
    /// attached. The proof must be pre-generated via `crypto::commitment::prove_*()`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn witness_private(
        &mut self,
        content: &[u8],
        identity: &Identity,
        zk_proof_bytes: Vec<u8>,
        metadata: Option<BTreeMap<String, serde_json::Value>>,
    ) -> Result<String> {
        let tips = self.dag.tips();
        let mut record = ValidationRecord::create(
            content,
            identity.public_key.clone(),
            tips,
            Classification::Private,
            metadata,
        );
        record.zk_proof = Some(zk_proof_bytes);

        // Sign (dual-sig for Profile A)
        identity.sign_record(&mut record)?;

        self.insert(&record)
    }

    /// MERGE — Create a merge record referencing multiple parents.
    pub fn merge(
        &mut self,
        parent_ids: Vec<String>,
        content: &[u8],
        identity: &Identity,
        classification: Classification,
    ) -> Result<String> {
        let mut record = ValidationRecord::create(
            content,
            identity.public_key.clone(),
            parent_ids,
            classification,
            None,
        );

        identity.sign_record(&mut record)?;

        self.insert(&record)
    }

    /// CLASSIFY — Get the classification of a record.
    pub fn classify(&self, record_id: &str) -> Result<Classification> {
        let record = self.storage.get(record_id)?;
        Ok(record.classification)
    }

    /// ANALYZE — Get DAG statistics around a record.
    pub fn analyze(&self, record_id: &str) -> Result<AnalysisResult> {
        if !self.dag.contains(record_id) {
            return Err(ElaraError::RecordNotFound(record_id.to_string()));
        }

        let ancestors = self
            .dag
            .ancestors(record_id, self.config.max_ancestors_depth);
        let descendants = self
            .dag
            .descendants(record_id, self.config.max_ancestors_depth);
        let parents = self.dag.parents(record_id);
        let children = self.dag.children(record_id);

        Ok(AnalysisResult {
            record_id: record_id.to_string(),
            ancestor_count: ancestors.len(),
            descendant_count: descendants.len(),
            parent_count: parents.len(),
            child_count: children.len(),
            is_tip: children.is_empty(),
            is_root: parents.is_empty(),
        })
    }

    /// HASH — Compute SHA3-256 of content.
    pub fn hash(&self, content: &[u8]) -> [u8; 32] {
        sha3_256(content)
    }

    /// SIGN — Sign a message with an identity.
    pub fn sign(&self, message: &[u8], identity: &Identity) -> Result<Vec<u8>> {
        identity.sign(message)
    }

    /// VERIFY — Verify a Dilithium3 signature.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool> {
        dilithium3_verify(message, signature, public_key)
    }

    /// Get current tips.
    pub fn tips(&self) -> Vec<String> {
        self.dag.tips()
    }

    /// Get roots.
    pub fn roots(&self) -> Vec<String> {
        self.dag.roots()
    }

    /// Total record count.
    pub fn len(&self) -> usize {
        self.dag.len()
    }

    pub fn is_empty(&self) -> bool {
        self.dag.is_empty()
    }

    /// Get a record by ID.
    pub fn get(&self, record_id: &str) -> Result<ValidationRecord> {
        self.storage.get(record_id)
    }
}

/// Result of the ANALYZE operation.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub record_id: String,
    pub ancestor_count: usize,
    pub descendant_count: usize,
    pub parent_count: usize,
    pub child_count: usize,
    pub is_tip: bool,
    pub is_root: bool,
}

#[cfg(all(test, feature = "node-core"))]
mod tests {
    use super::*;
    use crate::identity::{CryptoProfile, EntityType};
    use crate::storage::rocks::StorageEngine;

    fn setup_vm() -> (DamVm<StorageEngine>, Identity, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = StorageEngine::open(dir.path()).unwrap();
        let config = DvmConfig::default();
        let vm = DamVm::new(storage, config);
        let identity =
            Identity::generate(EntityType::Human, CryptoProfile::ProfileB).unwrap();
        (vm, identity, dir)
    }

    fn signed_record(
        identity: &Identity,
        parents: Vec<String>,
    ) -> ValidationRecord {
        let mut rec = ValidationRecord::create(
            b"test content",
            identity.public_key.clone(),
            parents,
            Classification::Public,
            None,
        );
        let signable = rec.signable_bytes();
        rec.signature = Some(identity.sign(&signable).unwrap());
        rec
    }

    #[test]
    fn test_insert_and_get() {
        let (mut vm, id, _dir) = setup_vm();
        let rec = signed_record(&id, vec![]);
        let rec_id = rec.id.clone();
        vm.insert(&rec).unwrap();

        let retrieved = vm.get(&rec_id).unwrap();
        assert_eq!(retrieved.id, rec_id);
    }

    #[test]
    fn test_insert_unsigned_rejected() {
        let (mut vm, id, _dir) = setup_vm();
        let rec = ValidationRecord::create(
            b"unsigned",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        assert!(vm.insert(&rec).is_err());
    }

    #[test]
    fn test_witness() {
        let (mut vm, id, _dir) = setup_vm();
        // Insert genesis
        let hash1 = vm.witness(b"genesis", &id, Classification::Public, None).unwrap();
        assert!(!hash1.is_empty());

        // Witness references tips
        let hash2 = vm.witness(b"second", &id, Classification::Public, None).unwrap();
        assert_ne!(hash1, hash2);
        assert_eq!(vm.len(), 2);
    }

    #[test]
    fn test_merge() {
        let (mut vm, id, _dir) = setup_vm();
        let r1 = signed_record(&id, vec![]);
        let r1_id = r1.id.clone();
        vm.insert(&r1).unwrap();

        let r2 = signed_record(&id, vec![]);
        let r2_id = r2.id.clone();
        vm.insert(&r2).unwrap();

        vm.merge(
            vec![r1_id, r2_id],
            b"merged",
            &id,
            Classification::Public,
        )
        .unwrap();
        assert_eq!(vm.len(), 3);
        assert_eq!(vm.tips().len(), 1);
    }

    #[test]
    fn test_analyze() {
        let (mut vm, id, _dir) = setup_vm();
        let r1 = signed_record(&id, vec![]);
        let r1_id = r1.id.clone();
        vm.insert(&r1).unwrap();

        let r2 = signed_record(&id, vec![r1_id.clone()]);
        let r2_id = r2.id.clone();
        vm.insert(&r2).unwrap();

        let analysis = vm.analyze(&r2_id).unwrap();
        assert_eq!(analysis.ancestor_count, 1);
        assert_eq!(analysis.parent_count, 1);
        assert!(analysis.is_tip);
        assert!(!analysis.is_root);

        let root_analysis = vm.analyze(&r1_id).unwrap();
        assert!(root_analysis.is_root);
    }

    #[test]
    fn test_hash_op() {
        let (vm, _, _dir) = setup_vm();
        let h1 = vm.hash(b"hello");
        let h2 = vm.hash(b"hello");
        assert_eq!(h1, h2);
        assert_ne!(vm.hash(b"hello"), vm.hash(b"world"));
    }

    #[test]
    fn test_sign_verify_ops() {
        let (vm, id, _dir) = setup_vm();
        let msg = b"test message";
        let sig = vm.sign(msg, &id).unwrap();
        assert!(vm.verify(msg, &sig, &id.public_key).unwrap());
        assert!(!vm.verify(b"wrong", &sig, &id.public_key).unwrap());
    }

    #[test]
    fn test_classify() {
        let (mut vm, id, _dir) = setup_vm();
        vm.witness(b"private data", &id, Classification::Private, None)
            .unwrap();
        let tips = vm.tips();
        let class = vm.classify(&tips[0]).unwrap();
        assert_eq!(class, Classification::Private);
    }

    // ─── Dual-Signature DamVm Tests ─────────────────────────────────────

    fn setup_vm_profile_a() -> (DamVm<StorageEngine>, Identity, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = StorageEngine::open(dir.path()).unwrap();
        let config = DvmConfig::default();
        let vm = DamVm::new(storage, config);
        let identity =
            Identity::generate(EntityType::Human, CryptoProfile::ProfileA).unwrap();
        (vm, identity, dir)
    }

    #[test]
    fn test_dual_sig_witness_profile_a() {
        let (mut vm, id, _dir) = setup_vm_profile_a();
        let _hash = vm.witness(b"dual-sig content", &id, Classification::Public, None).unwrap();
        assert_eq!(vm.len(), 1);

        // Retrieve the record via the tip
        let tips = vm.tips();
        assert_eq!(tips.len(), 1);
        let record = vm.get(&tips[0]).unwrap();

        // Profile A: both signatures present
        assert!(record.signature.is_some());
        assert!(record.sphincs_signature.is_some());
        assert!(record.creator_sphincs_pk.is_some());
    }

    #[test]
    fn test_dual_sig_insert_verifies_both() {
        let (mut vm, id, _dir) = setup_vm_profile_a();

        // Create and dual-sign a record
        let mut rec = ValidationRecord::create(
            b"test dual verify",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        id.sign_record(&mut rec).unwrap();

        // Should insert successfully — both signatures valid
        assert!(vm.insert(&rec).is_ok());
    }

    #[test]
    fn test_dual_sig_invalid_sphincs_rejected() {
        let (mut vm, id, _dir) = setup_vm_profile_a();

        let mut rec = ValidationRecord::create(
            b"test bad sphincs",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        id.sign_record(&mut rec).unwrap();

        // Corrupt the SPHINCS+ signature
        if let Some(ref mut sphincs_sig) = rec.sphincs_signature {
            sphincs_sig[0] ^= 0xFF;
        }

        // Should be rejected — SPHINCS+ signature invalid
        assert!(vm.insert(&rec).is_err());
    }

    #[test]
    fn test_sphincs_sig_without_pk_rejected() {
        let (mut vm, id, _dir) = setup_vm_profile_a();

        let mut rec = ValidationRecord::create(
            b"test missing pk",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        id.sign_record(&mut rec).unwrap();

        // Remove the SPHINCS+ public key but keep the signature
        rec.creator_sphincs_pk = None;

        // Should be rejected — signature present but no public key
        assert!(vm.insert(&rec).is_err());
    }

    #[test]
    fn test_sphincs_pk_without_sig_rejected() {
        let (mut vm, id, _dir) = setup_vm_profile_a();

        let mut rec = ValidationRecord::create(
            b"test pk without sig",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        id.sign_record(&mut rec).unwrap();

        // Keep the SPHINCS+ public key but remove the signature
        rec.sphincs_signature = None;

        // Should be rejected — pk present but no signature (incomplete Profile A)
        assert!(vm.insert(&rec).is_err());
    }

    #[test]
    fn test_sign_record_sets_algorithm_ids() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).unwrap();
        let mut rec = ValidationRecord::create(
            b"algo test",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        id.sign_record(&mut rec).unwrap();

        assert_eq!(rec.sig_algorithm, crate::crypto::ALG_DILITHIUM3);
        assert_eq!(rec.sphincs_algorithm, Some(crate::crypto::ALG_SPHINCS_SHA2_192F));
    }

    // ─── witness_private tests ──────────────────────────────────────────

    #[test]
    fn test_witness_private_creates_private_record_with_zk_proof() {
        let (mut vm, id, _dir) = setup_vm();
        let blinding = [42u8; 32];
        let proof = crate::crypto::commitment::prove_balance_range(1000, 500, &blinding).unwrap();
        let zk_bytes = proof.to_bytes();

        let _hash = vm.witness_private(b"private content", &id, zk_bytes, None).unwrap();
        assert!(!_hash.is_empty());

        // Get the record via tips (insert returns hash, not UUID)
        let tips = vm.tips();
        assert_eq!(tips.len(), 1);
        let record = vm.storage.get(&tips[0]).unwrap();
        assert_eq!(record.classification, Classification::Private);
        assert!(record.zk_proof.is_some());

        // Verify the attached proof is valid commitment
        let zk = record.zk_proof.as_ref().unwrap();
        assert!(crate::crypto::commitment::is_commitment_format(zk));
        assert!(crate::crypto::commitment::verify_commitment_proof(zk).unwrap());
    }

    #[test]
    fn test_witness_private_zk_proof_survives_wire_roundtrip() {
        let (mut vm, id, _dir) = setup_vm();
        let salt = crate::crypto::hash::sha3_256(b"salt");
        let proof = crate::crypto::commitment::prove_metadata_property(b"sensor", b"temp_ok", &salt).unwrap();
        let zk_bytes = proof.to_bytes();

        let _hash = vm.witness_private(b"sensor data", &id, zk_bytes, None).unwrap();
        let tips = vm.tips();
        let record = vm.storage.get(&tips[0]).unwrap();

        // Serialize to wire bytes and back
        let wire = record.to_bytes();
        let restored = ValidationRecord::from_bytes(&wire).unwrap();

        assert_eq!(restored.classification, Classification::Private);
        assert!(restored.zk_proof.is_some());
        let zk = restored.zk_proof.as_ref().unwrap();
        assert!(crate::crypto::commitment::is_commitment_format(zk));
        assert!(crate::crypto::commitment::verify_commitment_proof(zk).unwrap());
    }

    #[test]
    fn batch_b_dvm_config_default_pins_security_safe_verify_on_insert_and_dos_bounded_depth() {
        // Default config is security-load-bearing: a future "lazy" flip of
        // verify_on_insert to false would let any record bypass signature
        // verification on insert. max_ancestors_depth bounds ANALYZE
        // recursion to prevent DoS via crafted parent chains.
        let cfg = DvmConfig::default();
        assert!(cfg.verify_on_insert,
            "DvmConfig::default().verify_on_insert MUST be true — false would skip Dilithium3 verify on insert");
        assert_eq!(cfg.max_ancestors_depth, 100,
            "DvmConfig::default().max_ancestors_depth must be 100 (DoS bound on ANALYZE recursion)");

        // Defensive bounds: depth > 0 (zero disables ancestor traversal),
        // depth < usize::MAX (no silent unbounded recursion).
        assert!(cfg.max_ancestors_depth > 0, "depth=0 disables ANALYZE ancestor traversal");
        assert!(cfg.max_ancestors_depth < 1_000_000,
            "depth >= 1M would make ANALYZE unbounded on adversarial parent chains");
    }

    #[test]
    fn batch_b_dvm_config_clone_preserves_both_fields_and_debug_contains_field_names() {
        // Clone derive must produce an independent copy with identical fields.
        // A regression in derive(Clone) (e.g. someone manually impl'd Clone
        // and forgot a field) would silently lose state.
        let orig = DvmConfig { verify_on_insert: false, max_ancestors_depth: 42 };
        let cloned = orig.clone();
        assert_eq!(cloned.verify_on_insert, orig.verify_on_insert);
        assert_eq!(cloned.max_ancestors_depth, orig.max_ancestors_depth);

        // Mutation on the original must NOT affect the clone (deep-copy
        // semantics for value-type fields).
        let mut mut_orig = orig.clone();
        mut_orig.verify_on_insert = true;
        mut_orig.max_ancestors_depth = 999;
        // Confirm mutation actually applied — otherwise the independence
        // assertion below is vacuously true.
        assert!(mut_orig.verify_on_insert, "mutation must apply");
        assert_eq!(mut_orig.max_ancestors_depth, 999, "mutation must apply");
        assert!(!cloned.verify_on_insert, "clone must be independent of post-clone mutation");
        assert_eq!(cloned.max_ancestors_depth, 42);

        // Debug derive must emit BOTH field names — operator log readability.
        let dbg = format!("{:?}", orig);
        assert!(dbg.contains("verify_on_insert"),
            "Debug output must contain 'verify_on_insert' field name: {dbg}");
        assert!(dbg.contains("max_ancestors_depth"),
            "Debug output must contain 'max_ancestors_depth' field name: {dbg}");
        assert!(dbg.contains("DvmConfig"),
            "Debug output must contain struct name 'DvmConfig': {dbg}");
    }

    #[test]
    fn batch_b_dam_op_nine_variant_pairwise_distinctness_matrix() {
        // The DAM instruction set has exactly 9 ops (Insert, Query, Witness,
        // Merge, Classify, Analyze, Hash, Sign, Verify) per Protocol §3.3.4.
        // PartialEq must distinguish every pair — a regression that mapped
        // two variants to equal would silently break op-dispatch.
        let ops = [
            DamOp::Insert, DamOp::Query, DamOp::Witness, DamOp::Merge,
            DamOp::Classify, DamOp::Analyze, DamOp::Hash, DamOp::Sign, DamOp::Verify,
        ];
        assert_eq!(ops.len(), 9, "DAM operation set must have exactly 9 ops per Protocol §3.3.4");

        // Pairwise distinctness: 9 * 8 / 2 = 36 distinct unordered pairs.
        let mut distinct_pairs = 0;
        for i in 0..ops.len() {
            for j in (i + 1)..ops.len() {
                assert_ne!(ops[i], ops[j],
                    "DamOp variants must be pairwise distinct: ops[{i}]={:?} vs ops[{j}]={:?}",
                    ops[i], ops[j]);
                distinct_pairs += 1;
            }
        }
        assert_eq!(distinct_pairs, 36, "expected 9*8/2=36 pairwise distinctness checks");

        // Reflexivity: each variant equals itself.
        for op in &ops {
            assert_eq!(*op, *op, "DamOp::{:?} must equal itself", op);
        }
    }

    #[test]
    fn batch_b_dam_op_derive_matrix_clone_copy_debug_and_match_exhaustiveness() {
        // Copy derive: assignment doesn't move (compile-time check via
        // double-read pattern).
        let a = DamOp::Insert;
        let b = a;  // Copy, not move
        let c = a;  // a still usable
        assert_eq!(a, DamOp::Insert);
        assert_eq!(b, DamOp::Insert);
        assert_eq!(c, DamOp::Insert);

        // Clone derive (Copy implies Clone, but verify the trait).
        #[allow(clippy::clone_on_copy)] // intentional — pin Clone-derive presence
        let cloned = DamOp::Witness.clone();
        assert_eq!(cloned, DamOp::Witness);

        // Debug derive emits variant name verbatim — operator-log critical.
        assert_eq!(format!("{:?}", DamOp::Insert), "Insert");
        assert_eq!(format!("{:?}", DamOp::Query), "Query");
        assert_eq!(format!("{:?}", DamOp::Witness), "Witness");
        assert_eq!(format!("{:?}", DamOp::Merge), "Merge");
        assert_eq!(format!("{:?}", DamOp::Classify), "Classify");
        assert_eq!(format!("{:?}", DamOp::Analyze), "Analyze");
        assert_eq!(format!("{:?}", DamOp::Hash), "Hash");
        assert_eq!(format!("{:?}", DamOp::Sign), "Sign");
        assert_eq!(format!("{:?}", DamOp::Verify), "Verify");

        // Match-exhaustiveness compile-check: every variant must be reachable.
        // (A future addition that adds a variant without updating this test
        // surfaces in the resulting `non_exhaustive` compile warning when
        // ported to a match-based dispatcher.)
        let labels: Vec<&str> = [
            DamOp::Insert, DamOp::Query, DamOp::Witness, DamOp::Merge,
            DamOp::Classify, DamOp::Analyze, DamOp::Hash, DamOp::Sign, DamOp::Verify,
        ].iter().map(|op| match op {
            DamOp::Insert => "i",
            DamOp::Query => "q",
            DamOp::Witness => "w",
            DamOp::Merge => "m",
            DamOp::Classify => "c",
            DamOp::Analyze => "a",
            DamOp::Hash => "h",
            DamOp::Sign => "s",
            DamOp::Verify => "v",
        }).collect();
        assert_eq!(labels, vec!["i", "q", "w", "m", "c", "a", "h", "s", "v"]);
    }

    #[test]
    fn batch_b_analysis_result_seven_field_construction_and_clone_independence() {
        // AnalysisResult has 7 fields (record_id, ancestor_count,
        // descendant_count, parent_count, child_count, is_tip, is_root).
        // Pin construction order + each field is independently preserved
        // by Clone (a regression that swapped two fields in derive(Clone)
        // would only surface here).
        let orig = AnalysisResult {
            record_id: "abc123".to_string(),
            ancestor_count: 5,
            descendant_count: 11,
            parent_count: 2,
            child_count: 3,
            is_tip: false,
            is_root: true,
        };

        let cloned = orig.clone();
        assert_eq!(cloned.record_id, "abc123");
        assert_eq!(cloned.ancestor_count, 5);
        assert_eq!(cloned.descendant_count, 11);
        assert_eq!(cloned.parent_count, 2);
        assert_eq!(cloned.child_count, 3);
        assert!(!cloned.is_tip);
        assert!(cloned.is_root);

        // Counts use distinct sentinel values (5, 11, 2, 3) — a regression
        // that swapped two count fields would surface here as a value-mismatch.
        let counts = [
            cloned.ancestor_count, cloned.descendant_count,
            cloned.parent_count, cloned.child_count,
        ];
        let mut sorted_counts = counts.to_vec();
        sorted_counts.sort();
        sorted_counts.dedup();
        assert_eq!(sorted_counts.len(), 4, "all 4 count fields must use distinct sentinels");

        // Mutation on a second clone must not affect the first clone (deep
        // copy for String field).
        let mut mut_clone = orig.clone();
        mut_clone.record_id = "different".to_string();
        mut_clone.ancestor_count = 999;
        assert_eq!(cloned.record_id, "abc123", "first clone unaffected by second-clone mutation");
        assert_eq!(cloned.ancestor_count, 5);

        // Debug derive must emit struct name + at least one field name.
        let dbg = format!("{:?}", orig);
        assert!(dbg.contains("AnalysisResult"), "Debug must contain struct name: {dbg}");
        assert!(dbg.contains("record_id"), "Debug must contain record_id field name: {dbg}");
    }
}
