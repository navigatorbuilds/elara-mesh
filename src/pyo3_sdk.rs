//! Python bindings for [`crate::pq_client_sdk`].
//!
//! AUDIT-10 Milestone C exit criterion #1 (Python half). Wraps
//! [`AccountClient`] and [`LightClient`] as `#[pyclass]`es so accounts and
//! light-client scripts written in Python can talk to the PQ transport
//! without going through HTTPS.
//!
//! Design choices:
//!
//! - **Sync-blocking surface.** Every SDK method is `async fn` in Rust;
//!   the Python wrappers run them on a process-wide multi-thread Tokio
//!   runtime via `block_on`. Account UIs typically call SDK verbs from
//!   foreground threads where blocking is acceptable. Async-native
//!   bindings (`pyo3-async-runtimes`) are a follow-up slice.
//! - **GIL released during I/O.** Each verb wraps the `block_on` call in
//!   `Python::detach` so other Python threads keep running while the
//!   handshake + roundtrip happen.
//! - **JSON returned as Python dicts.** [`serde_json::Value`] is
//!   recursively converted to native Python types, no opaque handles.
//!
//! The `_native` extension only includes these classes when both the
//! `pyo3` feature *and* the `node` feature are active — the SDK depends
//! on the PQ transport, which is `node`-gated.

use std::sync::{Arc, OnceLock};

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use pyo3::IntoPyObjectExt;
use serde_json::{Number, Value};
use tokio::runtime::{Builder, Runtime};

use crate::network::pq_transport::PeerIdentityStore;
use crate::pq_client_sdk::{LightClient, VerifiedAccount, AccountClient};

/// Lazily-initialised Tokio runtime shared by every Python SDK call.
///
/// Two worker threads is enough — account UIs are not the bottleneck and
/// the runtime stays out of the way of PyO3's GIL accounting. The
/// runtime lives for the lifetime of the Python process (no shutdown
/// path); `OnceLock` prevents duplicate spawns under thread races.
fn rt_inner() -> Result<&'static Runtime, &'static str> {
    static RT: OnceLock<Result<Runtime, String>> = OnceLock::new();
    RT.get_or_init(|| {
        Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .thread_name("elara-sdk-py")
            .build()
            .map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|_| "failed to build SDK Tokio runtime")
}

fn rt() -> PyResult<&'static Runtime> {
    rt_inner().map_err(PyRuntimeError::new_err)
}

/// Recursively convert [`serde_json::Value`] into a native Python object.
fn json_to_py(py: Python<'_>, v: &Value) -> PyResult<Py<PyAny>> {
    match v {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => b.into_py_any(py),
        Value::Number(n) => number_to_py(py, n),
        Value::String(s) => s.as_str().into_py_any(py),
        Value::Array(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(json_to_py(py, item)?)?;
            }
            Ok(list.into_any().unbind())
        }
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, val) in map {
                dict.set_item(k, json_to_py(py, val)?)?;
            }
            Ok(dict.into_any().unbind())
        }
    }
}

fn number_to_py(py: Python<'_>, n: &Number) -> PyResult<Py<PyAny>> {
    if let Some(i) = n.as_i64() {
        i.into_py_any(py)
    } else if let Some(u) = n.as_u64() {
        u.into_py_any(py)
    } else if let Some(f) = n.as_f64() {
        f.into_py_any(py)
    } else {
        Err(PyRuntimeError::new_err(format!(
            "unrepresentable JSON number: {}",
            n
        )))
    }
}

fn map_err<E: std::fmt::Display>(e: E) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

// ─── AccountClient ──────────────────────────────────────────────────────

/// Python handle for [`crate::pq_client_sdk::AccountClient`].
///
/// Construct with `AccountClient()` for an ephemeral session keypair, or
/// `AccountClient.with_keypair(public_key, secret_key)` to reuse a
/// persisted Dilithium3 identity.
#[pyclass(name = "AccountClient", module = "elara_runtime._native")]
pub struct PyAccountClient {
    inner: AccountClient,
}

#[pymethods]
impl PyAccountClient {
    #[new]
    fn new() -> PyResult<Self> {
        let inner = AccountClient::ephemeral().map_err(map_err)?;
        Ok(Self { inner })
    }

    /// Build from a caller-supplied Dilithium3 keypair. Use this for
    /// accounts that retain identity across sessions.
    #[staticmethod]
    fn with_keypair(public_key: Vec<u8>, secret_key: Vec<u8>) -> PyResult<Self> {
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let inner = AccountClient::with_keypair(public_key, secret_key, pins);
        Ok(Self { inner })
    }

    /// Set the network id (realm) stamped on record submissions. Required
    /// when the target node runs a non-default `network_id` — without it,
    /// writes are rejected with `network_mismatch`. Applies to both the
    /// ephemeral and `with_keypair` constructors:
    /// `c = AccountClient(); c.set_network_id("my-realm")`.
    fn set_network_id(&mut self, network_id: String) {
        self.inner = self.inner.clone().with_network_id(network_id);
    }

    /// List of `(peer_addr, identity_hash_hex)` pairs the client has
    /// pinned via TOFU on first contact.
    fn pins(&self) -> Vec<(String, String)> {
        self.inner.pins().list()
    }

    /// Submit a wire-encoded record. Returns the JSON receipt as a dict.
    fn submit_record<'py>(
        &self,
        py: Python<'py>,
        peer_addr: String,
        wire_bytes: &Bound<'py, PyBytes>,
    ) -> PyResult<Py<PyAny>> {
        let inner = self.inner.clone();
        let bytes = wire_bytes.as_bytes().to_vec();
        let rt = rt()?;
        let value = py
            .detach(|| rt.block_on(async move { inner.submit_record(&peer_addr, &bytes).await }))
            .map_err(map_err)?;
        json_to_py(py, &value)
    }

    /// Fetch the account-state Merkle proof for a hex identity.
    fn account_proof<'py>(
        &self,
        py: Python<'py>,
        peer_addr: String,
        identity_hex: String,
    ) -> PyResult<Py<PyAny>> {
        let inner = self.inner.clone();
        let rt = rt()?;
        let value = py
            .detach(|| {
                rt.block_on(async move { inner.account_proof(&peer_addr, &identity_hex).await })
            })
            .map_err(map_err)?;
        json_to_py(py, &value)
    }

    /// Poll seal progress for a previously submitted record.
    fn seal_progress<'py>(
        &self,
        py: Python<'py>,
        peer_addr: String,
        record_id: String,
    ) -> PyResult<Py<PyAny>> {
        let inner = self.inner.clone();
        let rt = rt()?;
        let value = py
            .detach(|| {
                rt.block_on(async move { inner.seal_progress(&peer_addr, &record_id).await })
            })
            .map_err(map_err)?;
        json_to_py(py, &value)
    }

    /// Fetch the activity summary for a hex identity (Protocol §11.23).
    fn activity<'py>(
        &self,
        py: Python<'py>,
        peer_addr: String,
        identity_hex: String,
    ) -> PyResult<Py<PyAny>> {
        let inner = self.inner.clone();
        let rt = rt()?;
        let value = py
            .detach(|| {
                rt.block_on(async move { inner.activity(&peer_addr, &identity_hex).await })
            })
            .map_err(map_err)?;
        json_to_py(py, &value)
    }
}

// ─── LightClient ───────────────────────────────────────────────────────

/// Python handle for [`crate::pq_client_sdk::LightClient`].
///
/// Mirrors the Rust API: one call to `verify_account` fetches the latest
/// signed epoch header, fetches the account proof, runs the SMT
/// reconstruction, and returns the verified leaf.
#[pyclass(name = "LightClient", module = "elara_runtime._native")]
pub struct PyLightClient {
    inner: LightClient,
}

#[pymethods]
impl PyLightClient {
    #[new]
    fn new() -> PyResult<Self> {
        let inner = LightClient::ephemeral().map_err(map_err)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn with_keypair(public_key: Vec<u8>, secret_key: Vec<u8>) -> PyResult<Self> {
        let pins = Arc::new(PeerIdentityStore::in_memory());
        let inner = LightClient::with_keypair(public_key, secret_key, pins);
        Ok(Self { inner })
    }

    fn pins(&self) -> Vec<(String, String)> {
        self.inner.pins().list()
    }

    /// Verify an account against an epoch-anchored Merkle proof. Returns
    /// a dict: `{identity, exists, state_hash (hex|None), header: {...}}`.
    fn verify_account<'py>(
        &self,
        py: Python<'py>,
        header_peer: String,
        proof_peer: String,
        zone: String,
        identity_hex: String,
    ) -> PyResult<Py<PyAny>> {
        let inner = self.inner.clone();
        let rt = rt()?;
        let verified: VerifiedAccount = py
            .detach(|| {
                rt.block_on(async move {
                    inner
                        .verify_account(&header_peer, &proof_peer, &zone, &identity_hex)
                        .await
                })
            })
            .map_err(map_err)?;
        verified_account_to_dict(py, &verified)
    }
}

fn verified_account_to_dict(py: Python<'_>, v: &VerifiedAccount) -> PyResult<Py<PyAny>> {
    let dict = PyDict::new(py);
    dict.set_item("identity", &v.identity)?;
    dict.set_item("exists", v.exists)?;
    match v.state_hash {
        Some(h) => dict.set_item("state_hash", hex::encode(h))?,
        None => dict.set_item("state_hash", py.None())?,
    }

    let header = PyDict::new(py);
    header.set_item("zone", v.header.zone.to_string())?;
    header.set_item("epoch_number", v.header.epoch_number)?;
    header.set_item("merkle_root", hex::encode(v.header.merkle_root))?;
    header.set_item(
        "previous_seal_hash",
        hex::encode(v.header.previous_seal_hash),
    )?;
    header.set_item("record_count", v.header.record_count)?;
    header.set_item("start", v.header.start)?;
    header.set_item("end", v.header.end)?;
    match v.header.account_smt_root {
        Some(r) => header.set_item("account_smt_root", hex::encode(r))?,
        None => header.set_item("account_smt_root", py.None())?,
    }
    match v.header.seal_record_hash {
        Some(h) => header.set_item("seal_record_hash", hex::encode(h))?,
        None => header.set_item("seal_record_hash", py.None())?,
    }
    dict.set_item("header", header)?;

    Ok(dict.into_any().unbind())
}

/// Register the SDK pyclasses with the `_native` extension module. Called
/// from `pyo3_bindings::_native` when the `node` feature is active.
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyAccountClient>()?;
    m.add_class::<PyLightClient>()?;
    Ok(())
}

// Rust-side unit tests are deliberately omitted: pyo3 here is built as
// an `extension-module`, so `cargo test` cannot stand up a Python
// interpreter to attach a `Bound`/`Py` to. Constructor correctness is
// covered by the SDK's own unit tests in `pq_client_sdk/{account,light}.rs`,
// which already exercise `AccountClient::ephemeral()` and
// `LightClient::ephemeral()` against a real `PqListener`. The pyclass
// wrappers add only the `Py<PyAny>` packaging — verified at the Python
// layer by `tests/test_pq_sdk_bindings.py`.
