//! Protocol §11.23 Layer A slice 1 — HTTP-layer integration coverage for
//! `/records/by-hash/{content_hash}?relay=1`.
//!
//! Unit tests in `src/network/routes/explorer.rs:4906-5041` already exercise
//! `compute_record_by_hash_with_relay` directly (5 axes: relay=false hit,
//! relay=false miss, relay=true hit short-circuits, relay=true miss + no
//! peers, bad-input DoS guard). They bypass axum entirely.
//!
//! This file closes the integration gap flagged in an internal audit:
//! drives real HTTP requests through the axum router so the `?relay=`
//! query-string parser is on the call path. Catches regressions a refactor
//! of the `matches!(v.as_str(), "1" | "true" | "yes" | "TRUE" | "True")`
//! truthy-value table would silently introduce — the unit tests would still
//! pass because they pass `bool` directly.
//!
//! Axes covered (HTTP-layer surface only — every assertion is on
//! `Response::status()` + counter delta, no internal helper is called):
//!   1. No `?relay=` param + local hit  →  200 + record body, no relay counters.
//!   2. No `?relay=` param + local miss →  404, no relay counters.
//!   3. `?relay=1`   + local hit       →  200 + 0 relay counters (short-circuit).
//!   4. `?relay=1`   + local miss      →  404 + relay_attempts=1, relay_misses=1.
//!   5. `?relay=true`  + local miss    →  404 + relay_attempts=1, relay_misses=1.
//!   6. `?relay=yes`   + local miss    →  404 + relay_attempts=1, relay_misses=1.
//!   7. `?relay=TRUE`  + local miss    →  404 + relay_attempts=1, relay_misses=1.
//!   8. `?relay=True`  + local miss    →  404 + relay_attempts=1, relay_misses=1.
//!   9. `?relay=0`     + local miss    →  404 + 0 relay counters (truthy-only).
//!  10. `?relay=false` + local miss    →  404 + 0 relay counters (truthy-only).
//!  11. `?relay=garbage` + local miss  →  404 + 0 relay counters (truthy-only).
//!  12. `?relay=1` + non-hex input     →  400 + 0 relay counters (DoS guard).
//!  13. `?relay=1` + 63-char hex       →  400 + 0 relay counters (DoS guard).
//!
//! Why this matters: a future refactor that swapped the `matches!` for a
//! `to_lowercase() == "true"` would silently change the contract — `yes`
//! would stop relaying, `True`/`TRUE` would still work. The unit tests
//! `s1123_la1_*` call the helper with a `bool` arg and would not catch it.

#![cfg(feature = "node")]

use std::collections::BTreeMap;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::routing::get;
use axum::Router;
use tempfile::TempDir;
use tower::ServiceExt;

use elara_runtime::identity::{CryptoProfile, EntityType, Identity};
use elara_runtime::network::config::NodeConfig;
use elara_runtime::network::routes::explorer::record_by_hash;
use elara_runtime::network::state::NodeState;
use elara_runtime::network::witness::WitnessManager;
use elara_runtime::record::{Classification, ValidationRecord};
use elara_runtime::storage::rocks::StorageEngine;

/// Build a fresh `NodeState` with a real RocksDB tempdir, a fresh identity,
/// and no background tasks. Mirrors the in-module `test_state()` fixture in
/// `src/network/routes/explorer.rs:3887` — that helper isn't crate-visible
/// to the integration-test crate so we replicate the minimum surface here.
fn mk_state() -> (Arc<NodeState>, TempDir) {
    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let config = NodeConfig {
        data_dir: data_dir.clone(),
        identity_path: data_dir.join("identity.json"),
        db_path: data_dir.join("elara.db"),
        admin_token: "test-admin".into(),
        network_id: "relay-by-hash-integration-test".into(),
        mdns_enabled: false,
        health_check_interval_secs: 0,
        min_pow_difficulty: 0,
        ..Default::default()
    };
    let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
        .expect("generate identity");
    let rocks = Arc::new(
        StorageEngine::open(data_dir.join("rocksdb")).expect("open rocks"),
    );
    let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
    let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
    (state, tmp)
}

/// Build a stub v5 record whose `content_hash` is the supplied 32-byte array.
/// The handler under test reads only `content_hash` to populate the CF_IDX_HASH
/// index, so the other fields can be defaulted — but they must produce a record
/// that `put_record` accepts (non-empty creator_public_key + signature so the
/// downstream `compute_record_detail` projection has something to serialize).
fn stub_record_with_hash(id: &str, content_hash: [u8; 32]) -> ValidationRecord {
    ValidationRecord {
        id: id.to_string(),
        version: elara_runtime::wire::WIRE_VERSION,
        content_hash: content_hash.to_vec(),
        creator_public_key: vec![0xAA; 1952],
        timestamp: 1_700_000_000.0,
        parents: vec![],
        classification: Classification::Public,
        metadata: BTreeMap::new(),
        signature: Some(vec![0xBB; 3293]),
        sphincs_signature: None,
        zk_proof: None,
        itc_stamp: None,
        zone_refs: vec![],
        creator_sphincs_pk: None,
        sig_algorithm: 0x01,
        sphincs_algorithm: None,
        zone: None,
        identity_hash_wire: None,
        nonce: 0,
    }
}

/// Build an axum router with only the `/records/by-hash/{content_hash}` route
/// wired to the production `record_by_hash` handler. Mirrors the route shape
/// in `src/network/server.rs:9520` and `:9841` — the integration test does NOT
/// rebuild the whole router because the route under test is independent of
/// every other endpoint (the handler reads from `NodeState` directly).
fn mk_router(state: Arc<NodeState>) -> Router {
    Router::new()
        .route(
            "/records/by-hash/{content_hash}",
            get(record_by_hash),
        )
        .with_state(state)
}

/// Drive a GET request through the router and return the resulting status.
async fn get_status(router: Router, uri: &str) -> StatusCode {
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .expect("build request");
    let resp = router.oneshot(req).await.expect("oneshot");
    resp.status()
}

/// Drive a GET request and return `(status, body_json)`. Used when the test
/// also asserts the body shape (200-path tests).
async fn get_status_and_body(
    router: Router,
    uri: &str,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .expect("build request");
    let resp = router.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("collect body");
    let json: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Snapshot the five hit/miss/relay counters into one tuple so the
/// per-test assertion stays compact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counters {
    hits: u64,
    misses: u64,
    relay_attempts: u64,
    relay_hits: u64,
    relay_misses: u64,
}

fn snap(state: &Arc<NodeState>) -> Counters {
    Counters {
        hits: state.records_by_hash_hits_total.load(Relaxed),
        misses: state.records_by_hash_misses_total.load(Relaxed),
        relay_attempts: state
            .records_by_hash_peer_relay_attempts_total
            .load(Relaxed),
        relay_hits: state.records_by_hash_peer_relay_hits_total.load(Relaxed),
        relay_misses: state.records_by_hash_peer_relay_misses_total.load(Relaxed),
    }
}

// ── Axis 1: no `?relay=` param ────────────────────────────────────────────

#[tokio::test]
async fn no_relay_param_local_hit_returns_200_no_relay_counters() {
    let (state, _tmp) = mk_state();
    let hash = [0x11u8; 32];
    let rec = stub_record_with_hash("rec-no-relay-hit", hash);
    state.rocks.put_record(&rec.id, &rec).expect("put");

    let router = mk_router(state.clone());
    let (status, body) =
        get_status_and_body(router, &format!("/records/by-hash/{}", hex::encode(hash))).await;

    assert_eq!(status, StatusCode::OK, "local hit must return 200");
    assert_eq!(
        body["id"].as_str(),
        Some("rec-no-relay-hit"),
        "body must echo the resolved record id"
    );
    let c = snap(&state);
    assert_eq!(c.hits, 1, "local hit increments hits");
    assert_eq!(c.misses, 0);
    assert_eq!(
        c.relay_attempts, 0,
        "no `?relay=` param must never enter the fetcher"
    );
    assert_eq!(c.relay_hits, 0);
    assert_eq!(c.relay_misses, 0);
}

#[tokio::test]
async fn no_relay_param_local_miss_returns_404_no_relay_counters() {
    let (state, _tmp) = mk_state();
    let unknown = hex::encode([0x22u8; 32]);
    let router = mk_router(state.clone());
    let status = get_status(router, &format!("/records/by-hash/{unknown}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "local miss must return 404");
    let c = snap(&state);
    assert_eq!(c.hits, 0);
    assert_eq!(c.misses, 1, "local miss increments misses");
    assert_eq!(c.relay_attempts, 0, "default behaviour does not relay");
    assert_eq!(c.relay_hits, 0);
    assert_eq!(c.relay_misses, 0);
}

// ── Axis 2: `?relay=1` + local hit ────────────────────────────────────────

#[tokio::test]
async fn relay_1_local_hit_skips_fan_out_returns_200() {
    let (state, _tmp) = mk_state();
    let hash = [0x33u8; 32];
    let rec = stub_record_with_hash("rec-relay-1-hit", hash);
    state.rocks.put_record(&rec.id, &rec).expect("put");

    let router = mk_router(state.clone());
    let (status, body) = get_status_and_body(
        router,
        &format!("/records/by-hash/{}?relay=1", hex::encode(hash)),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "local hit short-circuits to 200");
    assert_eq!(body["id"].as_str(), Some("rec-relay-1-hit"));
    let c = snap(&state);
    assert_eq!(c.hits, 1);
    assert_eq!(
        c.relay_attempts, 0,
        "local hit MUST short-circuit before the fetcher even with ?relay=1"
    );
    assert_eq!(c.relay_hits, 0);
    assert_eq!(c.relay_misses, 0);
}

// ── Axis 3: `?relay=<truthy>` + local miss + no peers → relay counters ──

fn assert_relay_truthy_value_triggers_fan_out(value: &str) {
    let (state, _tmp) = mk_state();
    let unknown = hex::encode([0x44u8; 32]);
    let router = mk_router(state.clone());
    let uri = format!("/records/by-hash/{unknown}?relay={value}");
    // We tear down the future inside the function body so each test fn
    // can be a regular sync helper.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let status = rt.block_on(get_status(router, &uri));
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "relay=`{value}` + no peers must still return 404"
    );
    let c = snap(&state);
    assert_eq!(c.hits, 0);
    assert_eq!(c.misses, 1);
    assert_eq!(
        c.relay_attempts, 1,
        "relay=`{value}` must enter the fetcher exactly once"
    );
    assert_eq!(c.relay_hits, 0, "no peers configured → no relay hit");
    assert_eq!(
        c.relay_misses, 1,
        "fetcher exhaustion increments relay_misses per attempt"
    );
}

#[test]
fn relay_eq_1_triggers_fan_out() {
    assert_relay_truthy_value_triggers_fan_out("1");
}

#[test]
fn relay_eq_true_triggers_fan_out() {
    assert_relay_truthy_value_triggers_fan_out("true");
}

#[test]
fn relay_eq_yes_triggers_fan_out() {
    assert_relay_truthy_value_triggers_fan_out("yes");
}

#[test]
fn relay_eq_true_uppercase_triggers_fan_out() {
    assert_relay_truthy_value_triggers_fan_out("TRUE");
}

#[test]
fn relay_eq_true_capitalized_triggers_fan_out() {
    assert_relay_truthy_value_triggers_fan_out("True");
}

// ── Axis 4: non-truthy `?relay=` values must NOT relay ────────────────────

fn assert_relay_non_truthy_value_does_not_relay(value: &str) {
    let (state, _tmp) = mk_state();
    let unknown = hex::encode([0x55u8; 32]);
    let router = mk_router(state.clone());
    let uri = format!("/records/by-hash/{unknown}?relay={value}");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let status = rt.block_on(get_status(router, &uri));
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "non-truthy relay=`{value}` must still 404 the local miss"
    );
    let c = snap(&state);
    assert_eq!(c.hits, 0);
    assert_eq!(c.misses, 1, "local miss counter still ticks");
    assert_eq!(
        c.relay_attempts, 0,
        "non-truthy relay=`{value}` must NOT enter the fetcher"
    );
    assert_eq!(c.relay_hits, 0);
    assert_eq!(
        c.relay_misses, 0,
        "no fan-out → no relay-miss counter delta"
    );
}

#[test]
fn relay_eq_0_does_not_relay() {
    assert_relay_non_truthy_value_does_not_relay("0");
}

#[test]
fn relay_eq_false_does_not_relay() {
    assert_relay_non_truthy_value_does_not_relay("false");
}

#[test]
fn relay_eq_garbage_does_not_relay() {
    // Defensive: a account that ships `?relay=please` or `?relay=on` must
    // get default-no-relay behaviour, not silently turn on fan-out. Pin the
    // contract: ONLY the five-value truthy table relays. A future refactor
    // that swapped to `v != "0" && v != "false"` would silently break this.
    assert_relay_non_truthy_value_does_not_relay("garbage");
}

#[test]
fn relay_eq_empty_does_not_relay() {
    // `?relay=` (empty value) — present in the map with value "" — must NOT
    // relay. Catches a regression to `params.contains_key("relay")` which
    // would relay on every `?relay=...` regardless of value.
    assert_relay_non_truthy_value_does_not_relay("");
}

// ── Axis 5: bad-input DoS guard ───────────────────────────────────────────

#[tokio::test]
async fn relay_1_non_hex_input_returns_400_no_fan_out() {
    let (state, _tmp) = mk_state();
    // 64 chars but non-hex (contains 'z'). The local validator MUST reject
    // before the fetcher is reached, otherwise a account sending garbage
    // with ?relay=1 would amplify into 8 PQ round-trips per bad request.
    let bad = "z".repeat(64);
    let router = mk_router(state.clone());
    let status = get_status(router, &format!("/records/by-hash/{bad}?relay=1")).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "non-hex input must 400 at the local validator"
    );
    let c = snap(&state);
    assert_eq!(
        c.misses, 1,
        "bad input still counts as a local miss (operator signal)"
    );
    assert_eq!(
        c.relay_attempts, 0,
        "bad input must NEVER reach the fetcher — DoS amplification guard"
    );
    assert_eq!(c.relay_hits, 0);
    assert_eq!(c.relay_misses, 0);
}

#[tokio::test]
async fn relay_1_short_hex_returns_400_no_fan_out() {
    let (state, _tmp) = mk_state();
    // 63 chars (one short of the 64-hex contract). Same DoS-guard contract.
    let short = "a".repeat(63);
    let router = mk_router(state.clone());
    let status = get_status(router, &format!("/records/by-hash/{short}?relay=1")).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "short hash must 400 at the local validator"
    );
    let c = snap(&state);
    assert_eq!(c.misses, 1);
    assert_eq!(
        c.relay_attempts, 0,
        "short hash must NEVER reach the fetcher"
    );
}

#[tokio::test]
async fn relay_1_long_hex_returns_400_no_fan_out() {
    let (state, _tmp) = mk_state();
    // 65 chars (one over). Catches an off-by-one on the length check that
    // would mismatch the SMT-anchor's exact-64 contract — a 65-char prefix
    // of a real hash would otherwise silently match-and-truncate.
    let long = "b".repeat(65);
    let router = mk_router(state.clone());
    let status = get_status(router, &format!("/records/by-hash/{long}?relay=1")).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "long hash must 400 at the local validator"
    );
    let c = snap(&state);
    assert_eq!(c.misses, 1);
    assert_eq!(c.relay_attempts, 0);
}

// ── Axis 6: lookup is case-insensitive at the HTTP boundary ──────────────

#[tokio::test]
async fn uppercase_hash_resolves_same_as_lowercase() {
    // Pin that the trim+lowercase normalization runs at the HTTP boundary
    // BEFORE the CF_IDX_HASH probe — accounts that send uppercase hex (some
    // copy-paste flows from block explorers do) must hit, not 404. The
    // `compute_record_by_hash` body does `trimmed.to_ascii_lowercase()` so
    // this exercises the full HTTP→helper handoff with a non-canonical
    // path segment.
    let (state, _tmp) = mk_state();
    let hash = [0x77u8; 32];
    let rec = stub_record_with_hash("rec-upper", hash);
    state.rocks.put_record(&rec.id, &rec).expect("put");

    let router = mk_router(state.clone());
    let upper_hex = hex::encode_upper(hash);
    let (status, body) = get_status_and_body(
        router,
        &format!("/records/by-hash/{upper_hex}"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "uppercase hex must resolve via normalization");
    assert_eq!(body["id"].as_str(), Some("rec-upper"));
    let c = snap(&state);
    assert_eq!(c.hits, 1, "normalized lookup must count as a hit, not a miss");
    assert_eq!(c.relay_attempts, 0);
}
