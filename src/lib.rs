#![recursion_limit = "256"]
//! Elara Runtime — Layer 1.5 DAM Virtual Machine.
//!
//! Rust implementation of the Elara Protocol with PyO3 bindings.
//! Provides a fast lane for crypto, wire format, and DAG operations
//! while maintaining byte-level compatibility with the Python Layer 1.

//!
//! Spec references:
//!   @spec Protocol §3.2

/// Zone identifier type — hierarchical paths for semantic zone addressing.
/// One real type for EVERY build config since the extraction: the shared
/// `elara_record::ZoneId(String)`. (The old `not(node-core)` u64 stub —
/// which collapsed hierarchical paths and rejected them at deserialize —
/// is retired; mobile/PyO3/wasm now speak the same zone paths as the node.)
pub use elara_record::ZoneId;

pub mod anchor_proof;
pub mod collaboration;
pub mod conformance;
pub mod content_safety;
pub mod continuity;
pub mod crypto;
pub mod dag;
pub mod errors;
pub mod emergency;
pub mod forgetting;
pub mod identity;
pub mod itc;
// Mandate evaluation + offline bundle verifier moved into `elara-verify`
// (extraction Step 4a) — same-path re-exports keep every consumer compiling
// unchanged. Signing-dependent bundle fixtures parked in mandate_bundle_tests.
pub use elara_verify::mandate;
pub use elara_verify::mandate_bundle;
#[cfg(test)]
mod mandate_bundle_tests;
// Query/read-side SDK for the mandate accountability layer. Offline bundle-verify
// + typed verdicts are always-on (wasm/default-safe, like `mandate_bundle`); the
// HTTP query client is `node-core`-gated (reqwest). Read-only — no issue/revoke.
pub mod mandate_sdk;
pub mod operations;
// `.elara-receipt` v1 envelope parsing for `elara-verify --receipt` — evidence
// transport only (trust roots stay CLI flags). Node-free and ungated, like
// `verify_core`, so the wasm build can grow receipt support without drift.
pub use elara_record::receipt;
pub use elara_record::record;
pub mod reincarnation;
pub mod seed_vault;
pub mod service_install;
// silence.rs REMOVED — pausing zones hurts availability with no benefit.
// Dormancy reclaim (5-year inactive → beats to pool) handles dead identities.
pub mod storage;
pub mod succession;
pub mod accounting;
pub use elara_record::uuid7;
pub mod versioning;
// Pure, node-free, wasm-portable verification LOGIC shared by the `elara-verify`
// CLI and the WASM/browser verifier (no drift). Extracted to the standalone
// `elara-verify` crate (MIT/Apache, Lane 3 Step 3); aliased so every
// `crate::verify_core::*` path resolves unchanged. Always-on (no feature gate);
// `verify_core::anchor`/`::grade` appear when the `verify-anchor` feature
// threads through to `elara-verify/verify-anchor`.
pub use elara_verify as verify_core;
pub use elara_record::wire;
// Build-config invariants (e.g. release panic strategy) asserted in the test gate.
#[cfg(test)]
mod build_invariants;
// Empirical fail-closed fuzz sweep over the attacker-reachable wire decoders —
// backs the §1059–§1063 by-inspection panic-hardening with random-input coverage.
#[cfg(test)]
mod decoder_fuzz;

#[cfg(feature = "node-core")]
pub mod network;

/// AUDIT-10 Milestone C: thin account-grade PQ client SDK on top of
/// `network::pq_client`. WASM + Python bindings are follow-up slices.
#[cfg(feature = "node-core")]
pub mod pq_client_sdk;


/// AUDIT-10 Milestone C #3: wasm-portable proof verification primitives.
/// Lives at the crate root (no feature gates) so browser / phone-tier
/// clients can call into it without pulling in tokio / rocksdb / etc.
pub mod light_verify;

// AUDIT-10 Milestone C exit #1 (Python half): PyO3 wrappers for the
// PQ client SDK. Gated on both `pyo3` and the SDK's own `node` feature.
#[cfg(all(
    not(target_arch = "wasm32"),
    feature = "pyo3",
    feature = "node-core"
))]
mod pyo3_sdk;

// ─── PyO3 Bindings (native only, requires pyo3 feature) ─────────────────────
#[cfg(all(not(target_arch = "wasm32"), feature = "pyo3"))]
mod pyo3_bindings {
    use std::collections::BTreeMap;

    use pyo3::prelude::*;
    use pyo3::types::{PyBytes, PyDict};

    use crate::{crypto, record, accounting};

    /// Generate a Dilithium3 keypair. Returns (public_key, secret_key) as bytes.
    #[pyfunction]
    pub fn py_dilithium3_keygen(py: Python) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
        let kp = crypto::pqc::dilithium3_keygen()?;
        Ok((
            PyBytes::new(py, &kp.public_key).into(),
            PyBytes::new(py, &kp.secret_key).into(),
        ))
    }

    /// Sign a message with Dilithium3. Returns signature bytes.
    /// ML-DSA-65 sign requires both secret and public key (FIPS 204).
    #[pyfunction]
    pub fn py_dilithium3_sign<'py>(
        py: Python<'py>,
        message: &[u8],
        secret_key: &[u8],
        public_key: &[u8],
    ) -> PyResult<Py<PyBytes>> {
        let sig = crypto::pqc::dilithium3_sign_with_pk(message, secret_key, public_key)?;
        Ok(PyBytes::new(py, &sig).into())
    }

    /// Verify a Dilithium3 signature. Returns bool.
    #[pyfunction]
    pub fn py_dilithium3_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> PyResult<bool> {
        // pqc verify returns elara_record::RecordError since the extraction —
        // foreign-foreign, so no direct PyErr bridge is possible (orphan rule);
        // route through ElaraError, which also keeps the pre-extraction
        // "Crypto error: …" message prefix on the Python side.
        Ok(crypto::pqc::dilithium3_verify(message, signature, public_key)
            .map_err(crate::errors::ElaraError::from)?)
    }

    /// Generate a SPHINCS+ keypair. Returns (public_key, secret_key) as bytes.
    #[pyfunction]
    pub fn py_sphincs_keygen(py: Python) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
        let kp = crypto::pqc::sphincs_keygen()?;
        Ok((
            PyBytes::new(py, &kp.public_key).into(),
            PyBytes::new(py, &kp.secret_key).into(),
        ))
    }

    /// Sign a message with SPHINCS+. Returns signature bytes.
    /// SLH-DSA sign requires both secret and public key.
    #[pyfunction]
    pub fn py_sphincs_sign<'py>(
        py: Python<'py>,
        message: &[u8],
        secret_key: &[u8],
        public_key: &[u8],
    ) -> PyResult<Py<PyBytes>> {
        let sig = crypto::pqc::sphincs_sign_with_pk(message, secret_key, public_key)?;
        Ok(PyBytes::new(py, &sig).into())
    }

    /// Verify a SPHINCS+ signature. Returns bool.
    #[pyfunction]
    pub fn py_sphincs_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> PyResult<bool> {
        // Same RecordError→ElaraError routing as py_dilithium3_verify above.
        Ok(crypto::pqc::sphincs_verify(message, signature, public_key)
            .map_err(crate::errors::ElaraError::from)?)
    }

    /// Dual-sign a message with both Dilithium3 and SPHINCS+ in a single Rust call.
    /// Returns (dilithium_sig, sphincs_sig) as bytes tuples.
    /// Both ML-DSA-65 and SLH-DSA require sk + pk pairs (FIPS 204 / pure-Rust impls).
    #[pyfunction]
    #[allow(clippy::too_many_arguments)]
    pub fn py_dual_sign<'py>(
        py: Python<'py>,
        message: &[u8],
        dilithium_sk: &[u8],
        dilithium_pk: &[u8],
        sphincs_sk: &[u8],
        sphincs_pk: &[u8],
    ) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
        let dil_sig = crypto::pqc::dilithium3_sign_with_pk(message, dilithium_sk, dilithium_pk)?;
        let sph_sig = crypto::pqc::sphincs_sign_with_pk(message, sphincs_sk, sphincs_pk)?;
        Ok((
            PyBytes::new(py, &dil_sig).into(),
            PyBytes::new(py, &sph_sig).into(),
        ))
    }

    /// Create a record, compute signable bytes, dual-sign, and return the complete record dict.
    /// Entire create+sign pipeline in one Rust call — zero Python↔Rust crossings.
    /// `creator_public_key` doubles as the Dilithium3 PK for FIPS 204 sign;
    /// SPHINCS+ requires its own PK alongside its SK (both optional but bundled).
    #[pyfunction]
    #[pyo3(signature = (content, creator_public_key, parents, classification, metadata, dilithium_sk, sphincs_sk=None, sphincs_pk=None))]
    #[allow(clippy::too_many_arguments)]
    pub fn py_create_sign_record<'py>(
        py: Python<'py>,
        content: &[u8],
        creator_public_key: &[u8],
        parents: Vec<String>,
        classification: u8,
        metadata: &Bound<'py, PyDict>,
        dilithium_sk: &[u8],
        sphincs_sk: Option<&[u8]>,
        sphincs_pk: Option<&[u8]>,
    ) -> PyResult<Py<PyAny>> {
        // Convert metadata from Python dict to BTreeMap
        let mut meta_map = BTreeMap::new();
        for (k, v) in metadata.iter() {
            let key: String = k.extract()?;
            let val = python_to_json_value(&v)?;
            meta_map.insert(key, val);
        }

        let cls = record::Classification::from_u8(classification)?;

        // Create unsigned record
        let mut rec = record::ValidationRecord::create(
            content,
            creator_public_key.to_vec(),
            parents,
            cls,
            Some(meta_map),
        );

        // Compute signable bytes and sign
        let signable = rec.signable_bytes();
        rec.signature = Some(crypto::pqc::dilithium3_sign_with_pk(
            &signable,
            dilithium_sk,
            creator_public_key,
        )?);
        if let (Some(sph_sk), Some(sph_pk)) = (sphincs_sk, sphincs_pk) {
            rec.sphincs_signature = Some(crypto::pqc::sphincs_sign_with_pk(
                &signable, sph_sk, sph_pk,
            )?);
        }

        // Return as Python dict
        record_to_dict(py, &rec)
    }

    /// Batch dual-sign multiple messages in parallel using rayon.
    /// Returns list of (dilithium_sig, sphincs_sig) byte tuples.
    #[pyfunction]
    #[allow(clippy::too_many_arguments)]
    pub fn py_batch_dual_sign<'py>(
        py: Python<'py>,
        messages: Vec<Vec<u8>>,
        dilithium_sk: &[u8],
        dilithium_pk: &[u8],
        sphincs_sk: &[u8],
        sphincs_pk: &[u8],
    ) -> PyResult<Vec<(Py<PyBytes>, Py<PyBytes>)>> {
        let results = crypto::batch::batch_dual_sign(
            &messages,
            dilithium_sk,
            dilithium_pk,
            sphincs_sk,
            sphincs_pk,
        );
        let mut out = Vec::with_capacity(results.len());
        for r in results {
            let (dil, sph) = r?;
            out.push((
                PyBytes::new(py, &dil).into(),
                PyBytes::new(py, &sph).into(),
            ));
        }
        Ok(out)
    }

    /// Compute SHA3-256 hash. Returns 32-byte hash.
    #[pyfunction]
    pub fn py_sha3_256<'py>(py: Python<'py>, data: &[u8]) -> Py<PyBytes> {
        let hash = crypto::hash::sha3_256(data);
        PyBytes::new(py, &hash).into()
    }

    /// Compute SHA3-256 hash. Returns hex string.
    #[pyfunction]
    pub fn py_sha3_256_hex(data: &[u8]) -> String {
        crypto::hash::sha3_256_hex(data)
    }

    /// Batch verify Dilithium3 signatures. Returns list of bools.
    #[pyfunction]
    pub fn py_batch_verify(jobs: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>) -> Vec<bool> {
        let verify_jobs: Vec<crypto::batch::VerifyJob> = jobs
            .iter()
            .map(|(msg, sig, pk)| crypto::batch::VerifyJob {
                message: msg,
                signature: sig,
                public_key: pk,
            })
            .collect();
        crypto::batch::batch_verify(&verify_jobs)
    }

    /// Generate a UUID v7 string.
    #[pyfunction]
    pub fn py_uuid7() -> String {
        crate::uuid7::uuid7()
    }

    /// Encode a ValidationRecord to wire format bytes.
    /// Takes a dict with record fields, returns bytes.
    #[pyfunction]
    pub fn py_record_to_bytes<'py>(py: Python<'py>, record_dict: &Bound<'py, PyDict>) -> PyResult<Py<PyBytes>> {
        let rec = dict_to_record(record_dict)?;
        let wire = rec.to_bytes();
        Ok(PyBytes::new(py, &wire).into())
    }

    /// Decode wire format bytes to a record dict.
    #[pyfunction]
    pub fn py_record_from_bytes<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Py<PyAny>> {
        let rec = record::ValidationRecord::from_bytes(data)?;
        record_to_dict(py, &rec)
    }

    /// Compute signable bytes for a record dict.
    #[pyfunction]
    pub fn py_signable_bytes<'py>(py: Python<'py>, record_dict: &Bound<'py, PyDict>) -> PyResult<Py<PyBytes>> {
        let rec = dict_to_record(record_dict)?;
        let signable = rec.signable_bytes();
        Ok(PyBytes::new(py, &signable).into())
    }

    /// Derive full ledger state from a list of record dicts.
    #[pyfunction]
    pub fn py_derive_ledger<'py>(
        py: Python<'py>,
        record_dicts: Vec<Bound<'py, PyDict>>,
        genesis_authority: &str,
    ) -> PyResult<Py<PyAny>> {
        let mut ledger_records = Vec::new();
        for rd in &record_dicts {
            let rec = dict_to_record(rd)?;
            match accounting::types::extract_ledger_op(&rec) {
                Ok(Some(op)) => ledger_records.push((rec, op)),
                Ok(None) => {}
                Err(_) => {}
            }
        }

        // Total-order replay so the SDK derives byte-identical ledger state to the node
        // (timestamp + record-ID tiebreak — mirrors ledger.rs derive_from_records_tolerant).
        ledger_records.sort_by(|a, b| {
            a.0.timestamp.total_cmp(&b.0.timestamp).then_with(|| a.0.id.cmp(&b.0.id))
        });

        let (state, skipped) = accounting::ledger::derive_ledger_tolerant(&ledger_records, genesis_authority);

        let result = PyDict::new(py);

        let accounts_dict = PyDict::new(py);
        for (identity, account) in &state.accounts {
            let acc = PyDict::new(py);
            acc.set_item("available", account.available)?;
            acc.set_item("staked", account.staked)?;
            acc.set_item("total_received", account.total_received)?;
            acc.set_item("total_sent", account.total_sent)?;
            acc.set_item("tx_count", account.tx_count)?;
            acc.set_item("last_active", account.last_active)?;
            accounts_dict.set_item(identity, acc)?;
        }
        result.set_item("accounts", accounts_dict)?;

        let stakes_dict = PyDict::new(py);
        for (record_id, entry) in &state.stakes {
            let stake = PyDict::new(py);
            stake.set_item("amount", entry.amount)?;
            stake.set_item("staker", &entry.staker)?;
            stake.set_item("purpose", entry.purpose.as_str())?;
            stake.set_item("active", entry.active)?;
            stake.set_item("timestamp", entry.timestamp)?;
            stakes_dict.set_item(record_id, stake)?;
        }
        result.set_item("stakes", stakes_dict)?;

        result.set_item("total_supply", state.total_supply)?;
        result.set_item("total_staked", state.total_staked)?;
        result.set_item("conservation_pool", state.conservation_pool)?;
        result.set_item("records_processed", state.records_processed)?;
        result.set_item("skipped", skipped)?;

        Ok(result.into())
    }

    /// Get staked amount for a specific identity from a list of record dicts.
    #[pyfunction]
    pub fn py_get_staked<'py>(
        _py: Python<'py>,
        record_dicts: Vec<Bound<'py, PyDict>>,
        genesis_authority: &str,
        identity_hash: &str,
    ) -> PyResult<u64> {
        let mut ledger_records = Vec::new();
        for rd in &record_dicts {
            let rec = dict_to_record(rd)?;
            if let Ok(Some(op)) = accounting::types::extract_ledger_op(&rec) { ledger_records.push((rec, op)) }
        }

        // Total-order replay so the SDK derives byte-identical ledger state to the node
        // (timestamp + record-ID tiebreak — mirrors ledger.rs derive_from_records_tolerant).
        ledger_records.sort_by(|a, b| {
            a.0.timestamp.total_cmp(&b.0.timestamp).then_with(|| a.0.id.cmp(&b.0.id))
        });

        let (state, _) = accounting::ledger::derive_ledger_tolerant(&ledger_records, genesis_authority);
        Ok(state.staked(identity_hash))
    }

    // ─── Ledger-op metadata builders (PyO3) ─────────────────────────────────────────

    #[pyfunction]
    pub fn py_mint_metadata<'py>(
        py: Python<'py>,
        amount: u64,
        to: &str,
        reason: &str,
    ) -> PyResult<Py<PyAny>> {
        let meta = accounting::types::mint_metadata(amount, to, reason);
        btree_to_pydict(py, &meta)
    }

    #[pyfunction]
    #[pyo3(signature = (amount, to, memo=None))]
    pub fn py_transfer_metadata<'py>(
        py: Python<'py>,
        amount: u64,
        to: &str,
        memo: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        let meta = accounting::types::transfer_metadata(amount, to, memo);
        btree_to_pydict(py, &meta)
    }

    #[pyfunction]
    pub fn py_stake_metadata<'py>(
        py: Python<'py>,
        amount: u64,
        purpose: &str,
    ) -> PyResult<Py<PyAny>> {
        let p = accounting::types::StakePurpose::from_str(purpose)?;
        let meta = accounting::types::stake_metadata(amount, &p);
        btree_to_pydict(py, &meta)
    }

    #[pyfunction]
    pub fn py_unstake_metadata<'py>(
        py: Python<'py>,
        stake_record_id: &str,
    ) -> PyResult<Py<PyAny>> {
        let meta = accounting::types::unstake_metadata(stake_record_id);
        btree_to_pydict(py, &meta)
    }

    #[pyfunction]
    #[pyo3(signature = (amount, memo=None))]
    pub fn py_burn_metadata<'py>(
        py: Python<'py>,
        amount: u64,
        memo: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        let meta = accounting::types::burn_metadata(amount, memo);
        btree_to_pydict(py, &meta)
    }

    #[pyfunction]
    pub fn py_witness_reward_metadata<'py>(
        py: Python<'py>,
        amount: u64,
        from: &str,
        to: &str,
        record_id: &str,
    ) -> PyResult<Py<PyAny>> {
        let meta = accounting::types::witness_reward_metadata(amount, from, to, record_id);
        btree_to_pydict(py, &meta)
    }

    #[pyfunction]
    pub fn py_slash_metadata<'py>(
        py: Python<'py>,
        amount: u64,
        offender: &str,
        challenger: &str,
        jury: Vec<String>,
        stake_record_id: &str,
        reason: &str,
    ) -> PyResult<Py<PyAny>> {
        let meta = accounting::types::slash_metadata(amount, offender, challenger, &jury, stake_record_id, reason);
        btree_to_pydict(py, &meta)
    }

    #[pyfunction]
    pub fn py_dormancy_reclaim_metadata<'py>(
        py: Python<'py>,
        amount: u64,
        dormant_identity: &str,
        last_activity: f64,
    ) -> PyResult<Py<PyAny>> {
        let meta = accounting::types::dormancy_reclaim_metadata(amount, dormant_identity, last_activity);
        btree_to_pydict(py, &meta)
    }

    /// Helper: convert BTreeMap<String, serde_json::Value> to Python dict.
    fn btree_to_pydict(py: Python, map: &BTreeMap<String, serde_json::Value>) -> PyResult<Py<PyAny>> {
        let dict = PyDict::new(py);
        for (k, v) in map {
            match v {
                serde_json::Value::Null => dict.set_item(k, py.None())?,
                serde_json::Value::Bool(b) => dict.set_item(k, *b)?,
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        dict.set_item(k, i)?;
                    } else if let Some(u) = n.as_u64() {
                        dict.set_item(k, u)?;
                    } else if let Some(f) = n.as_f64() {
                        dict.set_item(k, f)?;
                    }
                }
                serde_json::Value::String(s) => dict.set_item(k, s)?,
                other => dict.set_item(k, other.to_string())?,
            }
        }
        Ok(dict.into())
    }

    // ─── Helper conversions ───────────────────────────────────────────────────

    /// Convert a Python value to serde_json::Value, preserving types.
    pub fn python_to_json_value(obj: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
        if obj.is_none() {
            return Ok(serde_json::Value::Null);
        }
        if let Ok(b) = obj.extract::<bool>() {
            return Ok(serde_json::Value::Bool(b));
        }
        if let Ok(i) = obj.extract::<i64>() {
            return Ok(serde_json::json!(i));
        }
        if let Ok(f) = obj.extract::<f64>() {
            return Ok(serde_json::json!(f));
        }
        if let Ok(s) = obj.extract::<String>() {
            return Ok(serde_json::Value::String(s));
        }
        let s: String = obj.str()?.to_string();
        Ok(serde_json::Value::String(s))
    }

    pub fn dict_to_record(dict: &Bound<'_, PyDict>) -> PyResult<record::ValidationRecord> {
        let id: String = dict
            .get_item("id")?
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("id"))?
            .extract()?;

        let version: u16 = dict
            .get_item("version")?
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("version"))?
            .extract()?;

        let content_hash: Vec<u8> = dict
            .get_item("content_hash")?
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("content_hash"))?
            .extract()?;

        let creator_public_key: Vec<u8> = dict
            .get_item("creator_public_key")?
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("creator_public_key"))?
            .extract()?;

        let timestamp: f64 = dict
            .get_item("timestamp")?
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("timestamp"))?
            .extract()?;

        let parents: Vec<String> = dict
            .get_item("parents")?
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("parents"))?
            .extract()?;

        let classification_val: u8 = dict
            .get_item("classification")?
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("classification"))?
            .extract()?;
        let classification = record::Classification::from_u8(classification_val)?;

        let metadata: BTreeMap<String, serde_json::Value> =
            if let Some(meta_obj) = dict.get_item("metadata")? {
                if let Ok(meta_dict) = meta_obj.cast::<PyDict>() {
                    let mut map = BTreeMap::new();
                    for (k, v) in meta_dict.iter() {
                        let key: String = k.extract()?;
                        let val = python_to_json_value(&v)?;
                        map.insert(key, val);
                    }
                    map
                } else {
                    BTreeMap::new()
                }
            } else {
                BTreeMap::new()
            };

        let signature: Option<Vec<u8>> = dict
            .get_item("signature")?
            .and_then(|v| if v.is_none() { None } else { Some(v) })
            .map(|v| v.extract())
            .transpose()?;

        let sphincs_signature: Option<Vec<u8>> = dict
            .get_item("sphincs_signature")?
            .and_then(|v| if v.is_none() { None } else { Some(v) })
            .map(|v| v.extract())
            .transpose()?;

        let zk_proof: Option<Vec<u8>> = dict
            .get_item("zk_proof")?
            .and_then(|v| if v.is_none() { None } else { Some(v) })
            .map(|v| v.extract())
            .transpose()?;

        let itc_stamp: Option<Vec<u8>> = dict
            .get_item("itc_stamp")?
            .and_then(|v| if v.is_none() { None } else { Some(v) })
            .map(|v| v.extract())
            .transpose()?;

        let zone_refs: Vec<Vec<u8>> = dict
            .get_item("zone_refs")?
            .map(|v| v.extract())
            .transpose()?
            .unwrap_or_default();

        let creator_sphincs_pk: Option<Vec<u8>> = dict
            .get_item("creator_sphincs_pk")?
            .and_then(|v| if v.is_none() { None } else { Some(v) })
            .map(|v| v.extract())
            .transpose()?;

        let sphincs_algorithm = if sphincs_signature.is_some() {
            Some(crypto::ALG_SPHINCS_SHA2_192F)
        } else {
            None
        };

        Ok(record::ValidationRecord {
            id,
            version,
            content_hash,
            creator_public_key,
            timestamp,
            parents,
            classification,
            metadata,
            signature,
            sphincs_signature,
            zk_proof,
            itc_stamp,
            zone_refs,
            creator_sphincs_pk,
            sig_algorithm: crypto::ALG_DILITHIUM3,
            sphincs_algorithm,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        })
    }

    pub fn record_to_dict(py: Python, rec: &record::ValidationRecord) -> PyResult<Py<PyAny>> {
        let dict = PyDict::new(py);
        dict.set_item("id", &rec.id)?;
        dict.set_item("version", rec.version)?;
        dict.set_item("content_hash", PyBytes::new(py, &rec.content_hash))?;
        dict.set_item(
            "creator_public_key",
            PyBytes::new(py, &rec.creator_public_key),
        )?;
        dict.set_item("timestamp", rec.timestamp)?;
        dict.set_item("parents", &rec.parents)?;
        dict.set_item("classification", rec.classification as u8)?;

        let meta_dict = PyDict::new(py);
        for (k, v) in &rec.metadata {
            match v {
                serde_json::Value::Null => meta_dict.set_item(k, py.None())?,
                serde_json::Value::Bool(b) => meta_dict.set_item(k, *b)?,
                serde_json::Value::Number(n) => {
                    if let Some(i) = n.as_i64() {
                        meta_dict.set_item(k, i)?;
                    } else if let Some(f) = n.as_f64() {
                        meta_dict.set_item(k, f)?;
                    } else {
                        meta_dict.set_item(k, n.to_string())?;
                    }
                }
                serde_json::Value::String(s) => meta_dict.set_item(k, s)?,
                other => meta_dict.set_item(k, other.to_string())?,
            }
        }
        dict.set_item("metadata", meta_dict)?;

        match &rec.signature {
            Some(s) => dict.set_item("signature", PyBytes::new(py, s))?,
            None => dict.set_item("signature", py.None())?,
        }
        match &rec.sphincs_signature {
            Some(s) => dict.set_item("sphincs_signature", PyBytes::new(py, s))?,
            None => dict.set_item("sphincs_signature", py.None())?,
        }
        match &rec.zk_proof {
            Some(z) => dict.set_item("zk_proof", PyBytes::new(py, z))?,
            None => dict.set_item("zk_proof", py.None())?,
        }
        match &rec.itc_stamp {
            Some(s) => dict.set_item("itc_stamp", PyBytes::new(py, s))?,
            None => dict.set_item("itc_stamp", py.None())?,
        }
        if !rec.zone_refs.is_empty() {
            let refs: Vec<_> = rec.zone_refs.iter().map(|r| PyBytes::new(py, r)).collect();
            dict.set_item("zone_refs", refs)?;
        }
        match &rec.creator_sphincs_pk {
            Some(pk) => dict.set_item("creator_sphincs_pk", PyBytes::new(py, pk))?,
            None => dict.set_item("creator_sphincs_pk", py.None())?,
        }

        Ok(dict.into())
    }

    /// Elara Runtime — Rust-powered fast lane for the Elara Protocol.
    #[pymodule]
    pub fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
        // Crypto
        m.add_function(wrap_pyfunction!(py_dilithium3_keygen, m)?)?;
        m.add_function(wrap_pyfunction!(py_dilithium3_sign, m)?)?;
        m.add_function(wrap_pyfunction!(py_dilithium3_verify, m)?)?;
        m.add_function(wrap_pyfunction!(py_sphincs_keygen, m)?)?;
        m.add_function(wrap_pyfunction!(py_sphincs_sign, m)?)?;
        m.add_function(wrap_pyfunction!(py_sphincs_verify, m)?)?;
        m.add_function(wrap_pyfunction!(py_dual_sign, m)?)?;
        m.add_function(wrap_pyfunction!(py_create_sign_record, m)?)?;
        m.add_function(wrap_pyfunction!(py_batch_dual_sign, m)?)?;
        m.add_function(wrap_pyfunction!(py_sha3_256, m)?)?;
        m.add_function(wrap_pyfunction!(py_sha3_256_hex, m)?)?;
        m.add_function(wrap_pyfunction!(py_batch_verify, m)?)?;

        // UUID
        m.add_function(wrap_pyfunction!(py_uuid7, m)?)?;

        // Wire format
        m.add_function(wrap_pyfunction!(py_record_to_bytes, m)?)?;
        m.add_function(wrap_pyfunction!(py_record_from_bytes, m)?)?;
        m.add_function(wrap_pyfunction!(py_signable_bytes, m)?)?;

        // Beat ledger
        m.add_function(wrap_pyfunction!(py_derive_ledger, m)?)?;
        m.add_function(wrap_pyfunction!(py_get_staked, m)?)?;

        // PQ client SDK pyclasses (AccountClient, LightClient).
        // Gated on `node` because the SDK lives there.
        #[cfg(feature = "node-core")]
        super::pyo3_sdk::register(m)?;

        // Ledger-op metadata builders
        m.add_function(wrap_pyfunction!(py_mint_metadata, m)?)?;
        m.add_function(wrap_pyfunction!(py_transfer_metadata, m)?)?;
        m.add_function(wrap_pyfunction!(py_stake_metadata, m)?)?;
        m.add_function(wrap_pyfunction!(py_unstake_metadata, m)?)?;
        m.add_function(wrap_pyfunction!(py_burn_metadata, m)?)?;
        m.add_function(wrap_pyfunction!(py_witness_reward_metadata, m)?)?;
        m.add_function(wrap_pyfunction!(py_slash_metadata, m)?)?;
        m.add_function(wrap_pyfunction!(py_dormancy_reclaim_metadata, m)?)?;

        Ok(())
    }
}
