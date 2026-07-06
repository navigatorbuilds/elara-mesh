//! Tests for the explorer route handlers (lifted verbatim from the
//! former inline `mod tests` in explorer.rs; logic unchanged).

use super::*;
use crate::identity::{CryptoProfile, EntityType, Identity};
use crate::network::config::NodeConfig;
use crate::network::witness::WitnessManager;
use crate::record::{Classification, ValidationRecord};
use crate::storage::rocks::StorageEngine;
use std::collections::BTreeMap;

/// Mirror of `state::test_node_state` — the crate-private helper isn't
/// re-exported to submodule tests, so we construct our own minimal
/// `NodeState` here (real RocksDB in tempdir, no background tasks).
fn test_state() -> Arc<NodeState> {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let config = NodeConfig {
        data_dir: data_dir.clone(),
        identity_path: data_dir.join("identity.json"),
        db_path: data_dir.join("elara.db"),
        admin_token: "test-admin".into(),
        network_id: "seal-progress-pruned-test".into(),
        mdns_enabled: false,
        health_check_interval_secs: 0,
        min_pow_difficulty: 0,
        ..Default::default()
    };

    let identity =
        Identity::generate(EntityType::Device, CryptoProfile::ProfileB).expect("generate identity");
    let rocks = Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
    let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
    let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
    std::mem::forget(tmp); // keep tempdir alive for the NodeState lifetime
    state
}

fn stub_record(id: &str) -> ValidationRecord {
    ValidationRecord {
        id: id.to_string(),
        version: crate::wire::WIRE_VERSION,
        content_hash: vec![0u8; 32],
        creator_public_key: vec![0xAA; 1952],
        timestamp: 1700000000.0,
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

/// Gap 8 pruned-fallback: when a record has been Finalized and its live
/// consensus/DAG entries have been GC'd, `compute_seal_progress` must
/// still return a terminal `settled:true, progress_pct:100, pruned:true`
/// payload so accounts stop polling instead of seeing a 404 race.
#[tokio::test]
async fn compute_seal_progress_pruned_fallback_returns_settled() {
    let state = test_state();
    let rid = "pruned-record-001".to_string();

    // Record exists in RocksDB but never entered consensus tracking
    // (simulates the "finalized long ago, then pruned from hot state" path).
    state
        .rocks
        .put_record(&rid, &stub_record(&rid))
        .expect("put_record");

    // Mark the record as finalized so `state.confirmation_level` reports
    // Finalized via the "Pending → finalized set" fallback.
    {
        let mut fin = state.finalized.write().await;
        fin.insert(rid.clone());
    }

    // DAG is empty, consensus has no seal for this record, but rocks
    // says it exists and finalized index confirms it — exactly the
    // pruned-race window compute_seal_progress has to handle.
    let body = compute_seal_progress(state.clone(), rid.clone())
        .await
        .expect("compute_seal_progress");

    assert_eq!(body["record_id"].as_str(), Some(rid.as_str()));
    assert_eq!(
        body["confirmation_level"].as_str(),
        Some("finalized"),
        "state.confirmation_level must project finalized index → Finalized"
    );
    let sp = body
        .get("seal_progress")
        .and_then(|v| v.as_object())
        .expect("seal_progress object");
    assert_eq!(sp.get("pruned").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(sp.get("settled").and_then(|v| v.as_bool()), Some(true));
    assert!(
        (sp.get("progress_pct")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0)
            - 100.0)
            .abs()
            < 0.01,
        "progress_pct must be 100 in pruned fallback so accounts stop polling"
    );

    // Gap 8: explicit Sealed-vs-Finalized surface must also be present
    // in the pruned-fallback path. A account that polls a record after
    // it's been GC'd from hot state still needs to render "Finalized"
    // without parsing the back-compat `settled` boolean.
    assert_eq!(
        sp.get("sealed").and_then(|v| v.as_bool()),
        Some(true),
        "pruned record was sealed at some point — must report sealed=true"
    );
    assert_eq!(
        sp.get("finalized").and_then(|v| v.as_bool()),
        Some(true),
        "pruned-fallback only fires when ConfirmationLevel ≥ Finalized"
    );
    assert_eq!(
        sp.get("state").and_then(|v| v.as_str()),
        Some("finalized"),
        "single-string state must be 'finalized' for the pruned-fallback path"
    );
    // sealed_at is unknown after prune (consensus state is gone).
    assert!(
        sp.get("sealed_at").map(|v| v.is_null()).unwrap_or(false),
        "sealed_at must be null in pruned fallback — registered_at was lost"
    );
}

// ── filter_canonical_chain regression tests (2026-04-26) ──────────
// Bug observed on Hillsboro: 259K seals on disk, /epochs/headers
// returned `{"headers":[],"total":0}`. Root cause: in-memory
// `latest_seal_hash` lagged behind disk after a restart (snapshot is
// taken every 15 epochs), so the filter dropped every header whose
// zone wasn't in the tip map. This blocks light-client cold sync.

fn stub_header(zone: &str, epoch: u64, prev: [u8; 32], hash: [u8; 32]) -> serde_json::Value {
    serde_json::json!({
        "zone": zone,
        "epoch_number": epoch,
        "previous_seal_hash": hex::encode(prev),
        "seal_record_hash": hex::encode(hash),
    })
}

#[test]
fn filter_canonical_chain_passes_through_zone_with_no_tip() {
    // Zone "1" has headers but no tip in the in-memory map (e.g.,
    // post-restart, snapshot not yet taken). Zone "0" has a tip.
    // Old behavior: both zones dropped. New behavior: zone-1
    // headers pass through, zone-0 filtered to canonical.
    let h0 = stub_header("0", 1, [0u8; 32], [0xA0; 32]);
    let h0b = stub_header("0", 2, [0xA0; 32], [0xA1; 32]);
    let h1 = stub_header("1", 5, [0u8; 32], [0xB0; 32]);
    let headers = vec![h0.clone(), h0b.clone(), h1.clone()];

    let mut tips: HashMap<ZoneId, [u8; 32]> = HashMap::new();
    tips.insert(ZoneId::new("0"), [0xA1; 32]); // canonical tip for zone 0

    let out = filter_canonical_chain(headers, &tips);
    assert_eq!(out.len(), 3, "zone-1 must pass through unfiltered");
    assert!(out.iter().any(|h| h["zone"] == "1"));
    assert!(out
        .iter()
        .any(|h| h["seal_record_hash"] == hex::encode([0xA0; 32])));
    assert!(out
        .iter()
        .any(|h| h["seal_record_hash"] == hex::encode([0xA1; 32])));
}

#[test]
fn filter_canonical_chain_drops_non_canonical_competing_seal() {
    // Zone "0" has two seal records claiming epoch 2. Tip points
    // at the canonical one. The competing entry must be dropped.
    let h_canon_a = stub_header("0", 1, [0u8; 32], [0xA0; 32]);
    let h_canon_b = stub_header("0", 2, [0xA0; 32], [0xA1; 32]);
    let h_competing = stub_header("0", 2, [0xA0; 32], [0xCC; 32]);
    let headers = vec![h_canon_a, h_canon_b, h_competing];

    let mut tips: HashMap<ZoneId, [u8; 32]> = HashMap::new();
    tips.insert(ZoneId::new("0"), [0xA1; 32]);

    let out = filter_canonical_chain(headers, &tips);
    assert_eq!(
        out.len(),
        2,
        "competing seal must be dropped, canonical kept"
    );
    assert!(out
        .iter()
        .all(|h| h["seal_record_hash"] != hex::encode([0xCC; 32])));
}

#[test]
fn filter_canonical_chain_treats_zero_tip_as_no_tip() {
    // Hillsboro post-restart 2026-04-26: `latest_seal_hash` for
    // zone "0" was [0u8; 32] (init sentinel) but the map entry
    // was present, so tip_zones contained "0" while canonical was
    // empty. Old filter dropped every header for that zone — light
    // client got `{"headers":[],"total":0}` despite 14k seals on
    // disk. A zero tip must behave the same as a missing tip.
    let h = stub_header("0", 1, [0u8; 32], [0xA0; 32]);
    let h2 = stub_header("0", 2, [0xA0; 32], [0xA1; 32]);
    let headers = vec![h, h2];

    let mut tips: HashMap<ZoneId, [u8; 32]> = HashMap::new();
    tips.insert(ZoneId::new("0"), [0u8; 32]); // zero sentinel — treat as no tip

    let out = filter_canonical_chain(headers, &tips);
    assert_eq!(out.len(), 2, "zero-tip zone must pass through");
}

#[test]
fn filter_canonical_chain_empty_tips_returns_all_unfiltered() {
    // Fresh node: no tips at all. Must pass everything through
    // (light client does its own chain check).
    let headers = vec![
        stub_header("0", 1, [0u8; 32], [0xA0; 32]),
        stub_header("1", 5, [0u8; 32], [0xB0; 32]),
    ];
    let tips: HashMap<ZoneId, [u8; 32]> = HashMap::new();
    let out = filter_canonical_chain(headers, &tips);
    assert_eq!(out.len(), 2);
}

#[test]
fn filter_canonical_chain_passes_through_when_tip_outside_window() {
    // Paginated `/headers/from/0?limit=K` returns
    // the *earliest* K seals.  The zone tip is at a much later epoch
    // and is NOT in by_hash.  Walkback from the tip breaks at the very
    // first lookup, `canonical` stays empty, and the old filter
    // dropped every returned header — `{"total":0,"headers":[]}` for
    // a node holding 20K+ seals.  Reproduced on testnet across
    // several nodes after the cache-poison hypothesis was ruled
    // out.  Fix: tip_zones excludes zones whose tip hash is not in
    // by_hash, so the headers pass through.
    let h0a = stub_header("0", 1, [0u8; 32], [0xA0; 32]);
    let h0b = stub_header("0", 2, [0xA0; 32], [0xA1; 32]);
    let headers = vec![h0a.clone(), h0b.clone()];
    // Tip at epoch 100 — its hash and the chain back to A1 are
    // outside the paginated window.
    let mut tips: HashMap<ZoneId, [u8; 32]> = HashMap::new();
    tips.insert(ZoneId::new("0"), [0xFF; 32]);

    let out = filter_canonical_chain(headers, &tips);
    assert_eq!(out.len(), 2, "tip outside window must pass through");
}

/// Negative case: record does not exist anywhere → RecordNotFound error.
/// Guards against the pruned-fallback swallowing genuine 404s.
#[tokio::test]
async fn compute_seal_progress_unknown_record_is_not_found() {
    let state = test_state();
    let err = compute_seal_progress(state, "does-not-exist".to_string())
        .await
        .expect_err("unknown record must 404");
    // ElaraError::RecordNotFound — exact variant irrelevant, just confirm
    // the error path fires instead of synthesizing a pruned payload.
    let msg = format!("{}", err);
    assert!(
        msg.to_lowercase().contains("not found") || msg.to_lowercase().contains("record"),
        "expected record-not-found error, got: {msg}"
    );
}

// ── ZSP Phase C: zone-scoped sync API ──────────────────────────────────
//
// The Phase B index (CF_RECORD_BY_ZONE) is wired through `query_records`
// when `?zone=` is set, and through `records_from_epoch` after the seal
// lookup. These tests pin the contract:
//   1. Zone-scoped fetch returns ONLY that zone's records.
//   2. `since` is honored on top of the zone scope.
//   3. The epoch endpoint refuses without `?zone=` (no global epoch).
//   4. The epoch endpoint maps `(zone, epoch)` → seal.start correctly.

fn zoned_record(id: &str, zone: ZoneId, ts: f64) -> ValidationRecord {
    let mut r = stub_record(id);
    r.zone = Some(zone);
    r.timestamp = ts;
    r
}

#[tokio::test]
async fn zsp_c_query_records_zone_scoped_returns_only_zone_records() {
    use crate::network::routes::core::{query_records, RecordQuery};
    use axum::extract::{Query, State};

    let state = test_state();
    let z_eu = ZoneId::new("medical/eu");
    let z_us = ZoneId::new("medical/us");

    // 3 records in EU, 3 records in US — interleaved timestamps so a naive
    // global scan would mix them. The zone-scoped path must pick only EU.
    for (i, (id, zone, ts)) in [
        ("eu-1", z_eu.clone(), 100.0),
        ("us-1", z_us.clone(), 110.0),
        ("eu-2", z_eu.clone(), 120.0),
        ("us-2", z_us.clone(), 130.0),
        ("eu-3", z_eu.clone(), 140.0),
        ("us-3", z_us.clone(), 150.0),
    ]
    .iter()
    .enumerate()
    {
        let _ = i;
        let rec = zoned_record(id, zone.clone(), *ts);
        state.rocks.put_record(id, &rec).expect("put_record");
    }

    let q = RecordQuery::__from_parts(Some(0.0), Some(100), None, Some("medical/eu".into()));
    let resp = query_records(State(state.clone()), Query(q))
        .await
        .map_err(|e| e.0)
        .expect("query_records");
    let hex_records = resp.0;
    let decoded: Vec<ValidationRecord> = hex_records
        .iter()
        .map(|h| ValidationRecord::from_bytes(&hex::decode(h).unwrap()).unwrap())
        .collect();
    let ids: Vec<&str> = decoded.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids.len(), 3, "expected 3 EU records, got {ids:?}");
    for id in &ids {
        assert!(
            id.starts_with("eu-"),
            "non-EU record leaked through zone filter: {id}"
        );
    }
}

#[tokio::test]
async fn zsp_c_query_records_zone_scoped_respects_since() {
    use crate::network::routes::core::{query_records, RecordQuery};
    use axum::extract::{Query, State};

    let state = test_state();
    let z = ZoneId::new("medical/eu");
    for (id, ts) in [("a", 100.0), ("b", 200.0), ("c", 300.0)].iter() {
        let rec = zoned_record(id, z.clone(), *ts);
        state.rocks.put_record(id, &rec).expect("put_record");
    }

    let q = RecordQuery::__from_parts(Some(150.0), Some(100), None, Some("medical/eu".into()));
    let resp = query_records(State(state.clone()), Query(q))
        .await
        .map_err(|e| e.0)
        .expect("query_records");
    let hex_records = resp.0;
    let ids: Vec<String> = hex_records
        .iter()
        .map(|h| {
            ValidationRecord::from_bytes(&hex::decode(h).unwrap())
                .unwrap()
                .id
        })
        .collect();
    assert_eq!(ids, vec!["b", "c"], "since=150 must drop ts=100 record");
}

#[tokio::test]
async fn zsp_c_query_records_no_zone_falls_back_to_global() {
    use crate::network::routes::core::{query_records, RecordQuery};
    use axum::extract::{Query, State};

    let state = test_state();
    let z_eu = ZoneId::new("medical/eu");
    let z_us = ZoneId::new("medical/us");
    for (id, zone, ts) in [("eu-1", z_eu.clone(), 100.0), ("us-1", z_us.clone(), 110.0)].iter() {
        let rec = zoned_record(id, zone.clone(), *ts);
        state.rocks.put_record(id, &rec).expect("put_record");
    }

    // No zone filter → both records returned via the legacy global scan.
    let q = RecordQuery::__from_parts(Some(0.0), Some(100), None, None);
    let resp = query_records(State(state.clone()), Query(q))
        .await
        .map_err(|e| e.0)
        .expect("query_records");
    assert_eq!(
        resp.0.len(),
        2,
        "zone-blind query must still return all records"
    );
}

#[tokio::test]
async fn zsp_c_records_from_epoch_requires_zone_param() {
    let state = test_state();
    let params: HashMap<String, String> = HashMap::new();
    let err = records_from_epoch(State(state.clone()), AxumPath(0u64), Query(params))
        .await
        .map_err(|e| e.0)
        .expect_err("must error without ?zone=");
    let msg = format!("{}", err);
    assert!(
        msg.contains("zone") || msg.to_lowercase().contains("requires"),
        "expected zone-required error, got: {msg}"
    );
    // The variant matters for HTTP status: Wire → 400, Network → 500.
    // Missing query param is a client bug (400), not a responder failure.
    assert!(
        matches!(err, ElaraError::Wire(_)),
        "missing-zone must map to ElaraError::Wire (→ 400), not {:?}",
        std::mem::discriminant(&err),
    );
}

#[tokio::test]
async fn zsp_c_records_from_epoch_zone_scope_filters_records() {
    // Seal lookup is exercised in compute_epoch_headers tests; here we
    // verify the zone-scoping half of the route works end-to-end. We
    // skip the seal — when no seal exists at (zone, epoch), the handler
    // falls back to since=0.0, so all zone records are returned.
    let state = test_state();
    let z_eu = ZoneId::new("medical/eu");
    let z_us = ZoneId::new("medical/us");
    for (id, zone, ts) in [
        ("eu-1", z_eu.clone(), 100.0),
        ("us-1", z_us.clone(), 110.0),
        ("eu-2", z_eu.clone(), 120.0),
    ]
    .iter()
    {
        let rec = zoned_record(id, zone.clone(), *ts);
        state.rocks.put_record(id, &rec).expect("put_record");
    }

    let mut params = HashMap::new();
    params.insert("zone".to_string(), "medical/eu".to_string());
    params.insert("limit".to_string(), "100".to_string());
    let resp = records_from_epoch(State(state.clone()), AxumPath(0u64), Query(params))
        .await
        .map_err(|e| e.0)
        .expect("records_from_epoch");
    let hex_records = resp.0;
    let ids: Vec<String> = hex_records
        .iter()
        .map(|h| {
            ValidationRecord::from_bytes(&hex::decode(h).unwrap())
                .unwrap()
                .id
        })
        .collect();
    assert_eq!(
        ids.len(),
        2,
        "EU-only fetch must skip US records, got {ids:?}"
    );
    for id in &ids {
        assert!(id.starts_with("eu-"), "US record leaked: {id}");
    }
}

#[tokio::test]
async fn zsp_c_records_from_epoch_uses_seal_start_ts() {
    use crate::network::epoch::{create_epoch_seal, disc5_index_key};

    let state = test_state();
    let z = ZoneId::new("medical/eu");
    // 3 records in zone, two before the seal.start, one after.
    for (id, ts) in [("pre-1", 50.0), ("pre-2", 90.0), ("post-1", 150.0)].iter() {
        let rec = zoned_record(id, z.clone(), *ts);
        state.rocks.put_record(id, &rec).expect("put_record");
    }

    // Build a real EpochSeal with start=100.0 in this zone.
    let epoch_state = state.epoch.read_recover().clone();
    let (seal_rec, parsed) = create_epoch_seal(
        &state.identity,
        state.rocks.as_ref(),
        &epoch_state,
        z.clone(),
        100.0,
        200.0,
        None,
        None,
    )
    .expect("create_epoch_seal");

    // Persist seal in CF_RECORDS so get_record can resolve it, and write
    // its CF_EPOCHS index entry so the records_from_epoch lookup finds it.
    state
        .rocks
        .put_record(&seal_rec.id, &seal_rec)
        .expect("put seal");
    let idx_key = disc5_index_key(parsed.epoch_number, z.path(), &seal_rec.id);
    state
        .rocks
        .put_cf_raw(crate::storage::rocks::CF_EPOCHS, &idx_key, &[])
        .expect("put_cf_raw");

    let mut params = HashMap::new();
    params.insert("zone".to_string(), "medical/eu".to_string());
    params.insert("limit".to_string(), "100".to_string());
    let resp = records_from_epoch(
        State(state.clone()),
        AxumPath(parsed.epoch_number),
        Query(params),
    )
    .await
    .map_err(|e| e.0)
    .expect("records_from_epoch");
    let ids: Vec<String> = resp
        .0
        .iter()
        .map(|h| {
            ValidationRecord::from_bytes(&hex::decode(h).unwrap())
                .unwrap()
                .id
        })
        .collect();
    // Records with ts >= 100 should be included: post-1 + the seal record
    // itself (timestamp set by create_epoch_seal). Pre-seal records (ts=50,90)
    // must be excluded.
    assert!(
        ids.contains(&"post-1".to_string()),
        "post-seal record missing: {ids:?}"
    );
    assert!(
        !ids.contains(&"pre-1".to_string()),
        "pre-seal record (ts=50) leaked through start_ts filter: {ids:?}"
    );
    assert!(
        !ids.contains(&"pre-2".to_string()),
        "pre-seal record (ts=90) leaked through start_ts filter: {ids:?}"
    );
}

// ── Gap 1 light-client invariants (2026-04-29) ─────────────────────────
//
// The fix is: `compute_account_proof` MUST NOT flush `smt_dirty`. If it
// does, the on-disk SMT root advances past the root signed by the most
// recent epoch seal, and `verify_account_proof_against_header` rejects
// every proof. These tests pin the post-fix invariants.

#[tokio::test]
async fn compute_account_proof_does_not_advance_smt_root() {
    // The handler MUST NOT call flush_dirty. After the call the
    // persistent SMT root must be unchanged from before — otherwise
    // proof.root races past the latest signed seal's account_smt_root
    // and light-client verification fails forever.
    use crate::network::account_merkle::AccountStateSMT;
    use crate::accounting::ledger::AccountState;

    let state = test_state();
    let identity = "11".repeat(32);

    // Capture the empty-tree root before any mutation.
    let root_before = {
        let tree = AccountStateSMT::new(&state.rocks);
        tree.root().expect("root")
    };

    // Add an account to the live ledger AND mark it dirty — this is
    // the exact state the production token::apply path leaves behind
    // between seals. The persistent SMT has no leaf for this account
    // yet (no flush has run), so the proof endpoint should report
    // "pending first seal" without flushing.
    {
        let mut ledger = state.ledger.write().await;
        ledger.accounts.insert(
            identity.clone(),
            AccountState {
                available: 12_345,
                ..Default::default()
            },
        );
        ledger.smt_dirty.insert(identity.clone());
    }

    let body = compute_account_proof(state.clone(), identity.clone())
        .await
        .expect("compute_account_proof");

    // Pending-first-seal branch: account exists in ledger, no leaf
    // in the SMT, no siblings returned (a phantom inclusion proof
    // would be a security bug — clients would accept "exists" with
    // a forgeable empty path).
    assert_eq!(body["exists"].as_bool(), Some(true));
    assert_eq!(body["pending_first_seal"].as_bool(), Some(true));
    assert!(
        body.get("siblings").is_none(),
        "pending_first_seal must not include siblings: {body}"
    );

    // Crucially: the on-disk root has NOT advanced. The smt_dirty
    // entry is still pending — only seal-time apply_snapshot may
    // touch the persistent tree.
    let root_after = {
        let tree = AccountStateSMT::new(&state.rocks);
        tree.root().expect("root")
    };
    assert_eq!(
        root_before,
        root_after,
        "compute_account_proof must NOT flush smt_dirty — \
             on-disk root advanced from {} to {}",
        hex::encode(root_before),
        hex::encode(root_after),
    );

    // The smt_dirty entry must also still be present (handler must
    // not consume it on read — that would lose the seal-time write).
    let still_dirty = state.ledger.read().await.smt_dirty.contains(&identity);
    assert!(
        still_dirty,
        "compute_account_proof must not drain smt_dirty"
    );
}

#[tokio::test]
async fn compute_account_proof_anchors_at_last_sealed_root_after_mutation() {
    // After a real seal flush has run, mutating the ledger again
    // (without a second flush) MUST leave proof.root == sealed root.
    // `live_state_matches_sealed` becomes false in that window so
    // accounts know they're seeing a between-seals view.
    use crate::network::account_merkle::{flush_dirty, AccountStateSMT};
    use crate::accounting::ledger::AccountState;

    let state = test_state();
    let identity = "22".repeat(32);

    // Step 1: seed the account, flush — this is the state right
    // after a normal seal commits.
    {
        let mut ledger = state.ledger.write().await;
        ledger.accounts.insert(
            identity.clone(),
            AccountState {
                available: 1_000,
                ..Default::default()
            },
        );
        ledger.smt_dirty.insert(identity.clone());
        let _ = flush_dirty(&state.rocks, &mut ledger).expect("flush");
    }
    let sealed_root = {
        let tree = AccountStateSMT::new(&state.rocks);
        tree.root().expect("root")
    };

    // Step 2: mutate (e.g. a new transfer applied between seals).
    {
        let mut ledger = state.ledger.write().await;
        ledger
            .accounts
            .get_mut(&identity)
            .expect("account present")
            .available = 9_999;
        ledger.smt_dirty.insert(identity.clone());
    }

    let body = compute_account_proof(state.clone(), identity.clone())
        .await
        .expect("compute_account_proof");

    let proof_root_hex = body["root"].as_str().expect("root").to_string();
    assert_eq!(
        proof_root_hex,
        hex::encode(sealed_root),
        "proof.root must equal the at-flush root (no in-handler advance)",
    );
    assert_eq!(
        body["live_state_matches_sealed"].as_bool(),
        Some(false),
        "live ledger advanced past sealed state — flag must reflect it",
    );

    // On-disk root unchanged by the second compute_account_proof call.
    let root_after = {
        let tree = AccountStateSMT::new(&state.rocks);
        tree.root().expect("root")
    };
    assert_eq!(
        root_after, sealed_root,
        "second proof read must not advance the SMT past flushed root"
    );
}

#[tokio::test]
async fn compute_account_proof_unseen_account_returns_exists_false() {
    // Identity nowhere in ledger or SMT → exists=false WITH a cryptographic
    // exclusion proof (present bitmap + siblings) that folds an empty leaf to the
    // sealed root — not the old trust-the-root bare assertion. Guards against the
    // pending_first_seal branch swallowing real 404s.
    let state = test_state();
    let identity = "ee".repeat(32);

    let body = compute_account_proof(state.clone(), identity.clone())
        .await
        .expect("compute_account_proof");

    assert_eq!(body["exists"].as_bool(), Some(false));
    assert!(
        body.get("pending_first_seal").is_none(),
        "non-existent account must not be flagged pending"
    );
    // Sound non-membership: a present bitmap + siblings + root the client folds.
    assert!(
        body.get("present").is_some(),
        "exclusion proof must carry a present bitmap"
    );
    assert!(
        body.get("siblings").is_some(),
        "exclusion proof must carry siblings"
    );
    let xp = crate::network::account_merkle::parse_wire_exclusion(&body)
        .expect("parse exclusion proof from non-existence response");
    assert!(
        crate::network::account_merkle::verify_exclusion_proof(&xp),
        "exclusion proof must fold an empty leaf to its declared root"
    );
    // Seal-routing parity with the present/pending branches: the absence
    // response must carry the advisory binding keys so a harvester knows WHICH
    // seal committed the witness's root (elara-verify --account-exclusion
    // --seal <that seal>). Values are environment-dependent (test_state has no
    // registered seal → null/false), but the KEYS must exist.
    assert!(
        body.get("bound_to_seal").is_some(),
        "absence response must carry bound_to_seal"
    );
    assert!(
        body.get("latest_sealed_account").is_some(),
        "absence response must carry latest_sealed_account (null when no seal yet)"
    );
}

#[tokio::test]
async fn record_wire_serves_canonical_decodable_bytes() {
    // /record/{id}/wire is the offline-verification read (receipts.html «3»):
    // the response must be the EXACT canonical wire bytes — decodable by
    // ValidationRecord::from_bytes and byte-identical to to_bytes(), because
    // the record's signature covers these bytes and nothing else.
    use axum::response::IntoResponse;
    let state = test_state();
    let rid = "0199-wire-test-record";
    let rec = stub_record(rid);
    state.rocks.put_record(rid, &rec).expect("put_record");

    let resp = match record_wire(State(state.clone()), AxumPath(rid.to_string())).await {
        Ok(r) => r.into_response(),
        Err(e) => panic!("wire route failed: {}", e.0),
    };
    assert_eq!(
        resp.headers().get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
        Some("application/octet-stream"),
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("body");
    assert_eq!(body.as_ref(), rec.to_bytes().as_slice(), "must be the exact canonical wire bytes");
    let decoded = ValidationRecord::from_bytes(&body).expect("round-trips through from_bytes");
    assert_eq!(decoded.id, rid);

    // Miss → typed error (404 at the HTTP layer), not a panic or empty 200.
    assert!(
        record_wire(State(state), AxumPath("no-such-record".into())).await.is_err(),
        "unknown id must be an error"
    );
}

#[tokio::test]
async fn compute_account_proof_malformed_identity_is_http_400_not_500() {
    // A malformed identity is a CLIENT error → HTTP 400, never 500. The handler
    // returns ElaraError::Wire (not Network), which AppError::into_response maps
    // to BAD_REQUEST. Regression guard: a public endpoint returning 500 on
    // trivially-bad input pollutes error-rate monitoring and reads as instability
    // to a first-contact reviewer (caught by the pre-flip error-surface probe,
    // 2026-06-27). Matches the sibling /records/by-hash hex guard.
    use axum::response::IntoResponse;
    let state = test_state();

    // (a) non-hex identity
    let err = compute_account_proof(state.clone(), "zzzz-not-hex".into())
        .await
        .expect_err("non-hex identity must be rejected");
    assert!(
        matches!(err, crate::errors::ElaraError::Wire(_)),
        "want Wire (→400), got {err:?}"
    );
    assert_eq!(
        crate::network::server::AppError(err).into_response().status(),
        axum::http::StatusCode::BAD_REQUEST,
    );

    // (b) valid hex, wrong length (16 bytes, not 32)
    let err = compute_account_proof(state, "ab".repeat(16))
        .await
        .expect_err("wrong-length identity must be rejected");
    assert!(
        matches!(err, crate::errors::ElaraError::Wire(_)),
        "want Wire (→400), got {err:?}"
    );
    assert_eq!(
        crate::network::server::AppError(err).into_response().status(),
        axum::http::StatusCode::BAD_REQUEST,
    );
}

#[tokio::test]
async fn compute_account_proof_post_seal_proof_round_trips() {
    // Happy path after a seal flush: the proof must verify against
    // the sealed root on its own (proof.state_hash + siblings →
    // recomputed root == proof.root). This is the cryptographic
    // contract light clients rely on.
    use crate::network::account_merkle::{flush_dirty, hash_account_state, AccountStateSMT};
    use crate::network::light::verify_account_proof_against_header;
    use crate::network::light::EpochHeader;
    use crate::accounting::ledger::AccountState;
    use crate::ZoneId;

    let state = test_state();
    let identity = "33".repeat(32);

    let acct = AccountState {
        available: 500_000,
        ..Default::default()
    };
    {
        let mut ledger = state.ledger.write().await;
        ledger.accounts.insert(identity.clone(), acct.clone());
        ledger.smt_dirty.insert(identity.clone());
        let _ = flush_dirty(&state.rocks, &mut ledger).expect("flush");
    }
    let sealed_root = {
        let tree = AccountStateSMT::new(&state.rocks);
        tree.root().expect("root")
    };

    let body = compute_account_proof(state.clone(), identity.clone())
        .await
        .expect("compute_account_proof");

    // Parse the SDK-side proof from the response (canonical compressed wire
    // shape) and run the same verifier the LightClient uses.
    let proof = crate::network::account_merkle::parse_wire_proof(&body)
        .expect("parse compressed account proof");
    let proof_root = proof.root;
    // Synthesize a header that signs the same root the proof anchors at.
    let header = EpochHeader {
        zone: ZoneId::new("0"),
        epoch_number: 1,
        merkle_root: [0u8; 32],
        previous_seal_hash: [0u8; 32],
        record_count: 1,
        start: 0.0,
        end: 1.0,
        account_smt_root: Some(proof_root),
        seal_record_hash: Some([0u8; 32]),
    };

    assert!(
        verify_account_proof_against_header(&proof, &header),
        "proof must verify against header signing the same root",
    );

    // The proof's state_hash must equal hash_account_state of the
    // ledger's view at flush time.
    assert_eq!(proof.state_hash, hash_account_state(&acct));
    assert_eq!(proof.root, sealed_root);
    assert_eq!(body["live_state_matches_sealed"].as_bool(), Some(true));
}

#[tokio::test]
async fn compute_account_proof_recovers_binding_from_disk_when_epoch_state_empty() {
    // Pin the boot-recovery path: EpochState::new() leaves
    // latest_sealed_account=None until the first post-restart seal
    // fires (state.rs:1478). Without the CF_EPOCHS fallback, every
    // /proof/account call between boot and the next seal returns
    // bound_to_seal=false, latest_sealed_account=null — a minutes-long
    // blind window for light clients on every restart.
    //
    // This test simulates that exact state: ledger flushed, on-disk
    // SMT populated, but EpochState in-memory state pristine. The
    // handler must reverse-scan CF_EPOCHS, find the seal whose root
    // matches the on-disk SMT, and return bound_to_seal=true.
    use crate::network::account_merkle::{flush_dirty, AccountStateSMT};
    use crate::network::epoch::{disc5_index_key, seal_metadata, SealMetadataParams};
    use crate::record::Classification;
    use crate::storage::rocks::CF_EPOCHS;
    use crate::accounting::ledger::AccountState;
    use crate::ZoneId;

    let state = test_state();
    let identity = "44".repeat(32);

    // Step 1: flush the SMT so the on-disk root matches what we'll
    // bake into the seal record.
    {
        let mut ledger = state.ledger.write().await;
        ledger.accounts.insert(
            identity.clone(),
            AccountState {
                available: 7_777,
                ..Default::default()
            },
        );
        ledger.smt_dirty.insert(identity.clone());
        let _ = flush_dirty(&state.rocks, &mut ledger).expect("flush");
    }
    let sealed_root = {
        let tree = AccountStateSMT::new(&state.rocks);
        tree.root().expect("root")
    };

    // Step 2: assert EpochState IS empty (the precondition we want
    // to test recovery from).
    assert!(
        state.epoch.read().unwrap().latest_sealed_account.is_none(),
        "test precondition: EpochState must start empty",
    );

    // Step 3: write a seal record + DISC-5 index entry that signs
    // the same root the SMT now stores. Anchor uses identity_hash
    // for creator verification, but for this test the seal's bytes
    // matter only insofar as extract_epoch_seal can parse them.
    let zone_path = "0";
    let epoch_n = 7u64;
    let meta = seal_metadata(SealMetadataParams {
        zone: ZoneId::new(zone_path),
        epoch_number: epoch_n,
        start: 1700000000.0,
        end: 1700000060.0,
        record_count: 1,
        merkle_root: &[0u8; 32],
        previous_seal_hash: &[0u8; 32],
        vrf_output: None,
        vrf_proof: None,
        sparse_merkle_root: None,
        record_hashes: None,
        zone_balance_total: None,
        zone_registry_root: None,
        zone_registry_delta: None,
        aggregator_rank: 0,
        account_smt_root: Some(&sealed_root),
        drand_pulse: None,
    });
    let mut seal_record = ValidationRecord::create(
        b"test-seal",
        state.identity.public_key.clone(),
        vec![],
        Classification::Public,
        Some(meta),
    );
    seal_record.zone = Some(ZoneId::new(zone_path));
    let signable = seal_record.signable_bytes();
    seal_record.signature = Some(state.identity.sign(&signable).unwrap());
    state
        .rocks
        .put_record(&seal_record.id, &seal_record)
        .expect("put seal");
    let key = disc5_index_key(epoch_n, zone_path, &seal_record.id);
    state
        .rocks
        .put_cf_raw(CF_EPOCHS, &key, &[])
        .expect("put disc5 idx");

    // Step 4: call compute_account_proof. With EpochState still
    // empty, the handler must fall back to CF_EPOCHS and surface
    // bound_to_seal=true + a populated latest_sealed_account.
    let body = compute_account_proof(state.clone(), identity.clone())
        .await
        .expect("compute_account_proof");

    assert_eq!(
        body["bound_to_seal"].as_bool(),
        Some(true),
        "fallback must restore bound_to_seal: {body}"
    );
    let bind = &body["latest_sealed_account"];
    assert!(
        !bind.is_null(),
        "latest_sealed_account must be populated by fallback"
    );
    assert_eq!(bind["epoch_number"].as_u64(), Some(epoch_n));
    assert_eq!(bind["zone"].as_str(), Some(zone_path));
    assert_eq!(bind["seal_id"].as_str(), Some(seal_record.id.as_str()));
    assert_eq!(
        bind["account_smt_root"].as_str(),
        Some(hex::encode(sealed_root).as_str())
    );
    assert_eq!(bind["matches_proof_root"].as_bool(), Some(true));

    // EpochState was never mutated — fallback must not write back.
    assert!(
        state.epoch.read().unwrap().latest_sealed_account.is_none(),
        "fallback is read-only; it must not poison EpochState",
    );
}

#[tokio::test]
async fn compute_account_proof_pending_branch_includes_seal_binding() {
    // Pin: when an account exists in the live ledger but has no leaf
    // in the on-disk SMT yet (witness has not flushed it through any
    // seal), the response must STILL surface the latest sealed
    // account-SMT binding. Without this, light clients can't tell
    // which seal their first-flushable proof will eventually anchor
    // to — they receive `pending_first_seal: true` with no epoch
    // number, no signed root, no retry signal.
    //
    // A cross-fleet probe showed a subset of nodes returning the
    // pending branch for active accounts immediately after restart;
    // light clients hitting those nodes had no way to find a node
    // that could serve a bound proof.
    use crate::network::account_merkle::{flush_dirty, AccountStateSMT};
    use crate::network::epoch::{disc5_index_key, seal_metadata, SealMetadataParams};
    use crate::record::Classification;
    use crate::storage::rocks::CF_EPOCHS;
    use crate::accounting::ledger::AccountState;
    use crate::ZoneId;

    let state = test_state();
    let pre_flushed = "55".repeat(32);
    let pending_id = "66".repeat(32);

    // Step 1: seed + flush a DIFFERENT account so the on-disk SMT
    // root advances to a non-empty value we can sign over. The seal
    // we forge below will bind THIS root.
    {
        let mut ledger = state.ledger.write().await;
        ledger.accounts.insert(
            pre_flushed.clone(),
            AccountState {
                available: 1,
                ..Default::default()
            },
        );
        ledger.smt_dirty.insert(pre_flushed.clone());
        let _ = flush_dirty(&state.rocks, &mut ledger).expect("flush");
    }
    let sealed_root = {
        let tree = AccountStateSMT::new(&state.rocks);
        tree.root().expect("root")
    };

    // Step 2: write a seal record + CF_EPOCHS index so the
    // fallback can recover the binding (mirrors the boot-recovery
    // test setup at compute_account_proof_recovers_binding_from_disk_…).
    let zone_path = "0";
    let epoch_n = 11u64;
    let meta = seal_metadata(SealMetadataParams {
        zone: ZoneId::new(zone_path),
        epoch_number: epoch_n,
        start: 1700000000.0,
        end: 1700000060.0,
        record_count: 0,
        merkle_root: &[0u8; 32],
        previous_seal_hash: &[0u8; 32],
        vrf_output: None,
        vrf_proof: None,
        sparse_merkle_root: None,
        record_hashes: None,
        zone_balance_total: None,
        zone_registry_root: None,
        zone_registry_delta: None,
        aggregator_rank: 0,
        account_smt_root: Some(&sealed_root),
        drand_pulse: None,
    });
    let mut seal_record = ValidationRecord::create(
        b"test-seal-pending",
        state.identity.public_key.clone(),
        vec![],
        Classification::Public,
        Some(meta),
    );
    seal_record.zone = Some(ZoneId::new(zone_path));
    let signable = seal_record.signable_bytes();
    seal_record.signature = Some(state.identity.sign(&signable).unwrap());
    state
        .rocks
        .put_record(&seal_record.id, &seal_record)
        .expect("put seal");
    state
        .rocks
        .put_cf_raw(
            CF_EPOCHS,
            &disc5_index_key(epoch_n, zone_path, &seal_record.id),
            &[],
        )
        .expect("put disc5 idx");

    // Step 3: insert a SECOND account into the live ledger and mark
    // it dirty WITHOUT flushing — this is the exact state a witness
    // is in between seals when a brand-new account is first observed.
    {
        let mut ledger = state.ledger.write().await;
        ledger.accounts.insert(
            pending_id.clone(),
            AccountState {
                available: 999,
                ..Default::default()
            },
        );
        ledger.smt_dirty.insert(pending_id.clone());
    }

    // Step 4: query the proof. Account exists in ledger but not in
    // SMT → pending_first_seal=true, but the binding must STILL be
    // surfaced so callers can poll for the next seal.
    let body = compute_account_proof(state.clone(), pending_id.clone())
        .await
        .expect("compute_account_proof");

    assert_eq!(body["exists"].as_bool(), Some(true));
    assert_eq!(body["pending_first_seal"].as_bool(), Some(true));
    assert_eq!(
        body["bound_to_seal"].as_bool(),
        Some(false),
        "pending account is not yet bound to any seal"
    );
    let bind = &body["latest_sealed_account"];
    assert!(
        !bind.is_null(),
        "pending response MUST include the binding so clients know which seal to wait for: {body}"
    );
    assert_eq!(bind["epoch_number"].as_u64(), Some(epoch_n));
    assert_eq!(
        bind["account_smt_root"].as_str(),
        Some(hex::encode(sealed_root).as_str())
    );
    assert_eq!(
        bind["matches_proof_root"].as_bool(),
        Some(false),
        "pending leaf cannot match the sealed root"
    );

    // No phantom inclusion proof: pending must NOT include siblings.
    assert!(
        body.get("siblings").is_none(),
        "pending_first_seal must not include siblings"
    );
}

// ── /records/by-hash/{content_hash} (Protocol §11.23 Layer A slice 0) ──
//
// Hit, miss, and bad-input paths. Verifies that:
//   1. The natural `hex::encode(record.content_hash)` resolves the record.
//   2. The hits / misses counters tick correctly.
//   3. Malformed input (wrong length, non-hex chars) returns Err and
//      counts toward misses, not hits.

fn record_with_hash(id: &str, content_hash: [u8; 32]) -> ValidationRecord {
    let mut rec = stub_record(id);
    rec.content_hash = content_hash.to_vec();
    rec
}

#[tokio::test]
async fn record_by_hash_hit_returns_record_and_increments_hits() {
    use std::sync::atomic::Ordering::Relaxed;
    let state = test_state();

    // Two records with distinct content hashes — the lookup MUST
    // resolve to exactly the matching one.
    let hash_a = [0x11u8; 32];
    let hash_b = [0x22u8; 32];
    let rec_a = record_with_hash("rec-a", hash_a);
    let rec_b = record_with_hash("rec-b", hash_b);
    state.rocks.put_record(&rec_a.id, &rec_a).expect("put A");
    state.rocks.put_record(&rec_b.id, &rec_b).expect("put B");

    let hits_before = state.records_by_hash_hits_total.load(Relaxed);
    let body = compute_record_by_hash(state.clone(), hex::encode(hash_a))
        .await
        .expect("hit must succeed")
        .expect("hit must produce Some");

    assert_eq!(body["id"].as_str(), Some("rec-a"));
    assert_eq!(
        state.records_by_hash_hits_total.load(Relaxed),
        hits_before + 1,
        "hit path must increment hits counter"
    );
    assert_eq!(
        state.records_by_hash_misses_total.load(Relaxed),
        0,
        "hit path must not touch the miss counter"
    );
}

#[tokio::test]
async fn record_by_hash_miss_returns_none_and_increments_misses() {
    use std::sync::atomic::Ordering::Relaxed;
    let state = test_state();
    // Don't put any record — every lookup is a miss.

    let unknown = hex::encode([0x33u8; 32]);
    let result = compute_record_by_hash(state.clone(), unknown)
        .await
        .expect("well-formed miss is Ok(None), not Err");
    assert!(result.is_none(), "unknown hash must produce None");
    assert_eq!(state.records_by_hash_misses_total.load(Relaxed), 1);
    assert_eq!(state.records_by_hash_hits_total.load(Relaxed), 0);
}

#[tokio::test]
async fn record_by_hash_rejects_non_hex_input() {
    use std::sync::atomic::Ordering::Relaxed;
    let state = test_state();

    // Wrong length (63 hex chars).
    let too_short = "a".repeat(63);
    let err = compute_record_by_hash(state.clone(), too_short)
        .await
        .expect_err("malformed input must Err, not silently miss");
    let msg = format!("{err}");
    assert!(
        msg.contains("64 hex"),
        "error must explain expected format: {msg}"
    );

    // Right length, non-hex character.
    let bad_char = format!("{}z", "a".repeat(63));
    let err = compute_record_by_hash(state.clone(), bad_char)
        .await
        .expect_err("non-hex must Err");
    let msg = format!("{err}");
    assert!(
        msg.contains("hex"),
        "error must explain expected format: {msg}"
    );

    // Both malformed inputs count as misses (operator signal that
    // accounts are sending garbage), never as hits.
    assert_eq!(state.records_by_hash_misses_total.load(Relaxed), 2);
    assert_eq!(state.records_by_hash_hits_total.load(Relaxed), 0);
}

// ── §11.23 Layer A slice 1: peer-relay opt-in ────────────────────────
//
// Three test axes for the new `compute_record_by_hash_with_relay` wrapper:
//   1. relay=false MUST be byte-identical to compute_record_by_hash
//      (both hit and miss paths).
//   2. relay=true + local hit MUST NOT touch the peer-relay counters
//      (relay is a fall-back, not always-fire).
//   3. relay=true + local miss + no viable peers MUST bump relay
//      attempts + misses, MUST NOT bump relay hits, MUST return None.

#[tokio::test]
async fn s1123_la1_with_relay_false_local_hit_matches_slice0() {
    use std::sync::atomic::Ordering::Relaxed;
    let state = test_state();
    let hash = [0xAAu8; 32];
    let rec = record_with_hash("rec-relay-hit", hash);
    state.rocks.put_record(&rec.id, &rec).expect("put");

    let body = compute_record_by_hash_with_relay(state.clone(), hex::encode(hash), false)
        .await
        .expect("hit ok")
        .expect("hit must produce Some");

    assert_eq!(body["id"].as_str(), Some("rec-relay-hit"));
    assert_eq!(state.records_by_hash_hits_total.load(Relaxed), 1);
    assert_eq!(state.records_by_hash_misses_total.load(Relaxed), 0);
    // Relay counters MUST be untouched on the local-hit path.
    assert_eq!(
        state
            .records_by_hash_peer_relay_attempts_total
            .load(Relaxed),
        0,
        "local hit must never enter the fetcher"
    );
    assert_eq!(state.records_by_hash_peer_relay_hits_total.load(Relaxed), 0);
    assert_eq!(
        state.records_by_hash_peer_relay_misses_total.load(Relaxed),
        0
    );
}

#[tokio::test]
async fn s1123_la1_with_relay_false_local_miss_does_not_fan_out() {
    use std::sync::atomic::Ordering::Relaxed;
    let state = test_state();
    let unknown = hex::encode([0xBBu8; 32]);
    // No records exist — miss path.

    let result = compute_record_by_hash_with_relay(state.clone(), unknown, false)
        .await
        .expect("well-formed miss is Ok(None)");

    assert!(
        result.is_none(),
        "local miss with relay=false must return None"
    );
    assert_eq!(state.records_by_hash_misses_total.load(Relaxed), 1);
    // relay=false: must NOT bump any relay counter.
    assert_eq!(
        state
            .records_by_hash_peer_relay_attempts_total
            .load(Relaxed),
        0
    );
    assert_eq!(state.records_by_hash_peer_relay_hits_total.load(Relaxed), 0);
    assert_eq!(
        state.records_by_hash_peer_relay_misses_total.load(Relaxed),
        0
    );
}

#[tokio::test]
async fn s1123_la1_with_relay_true_local_hit_skips_fan_out() {
    use std::sync::atomic::Ordering::Relaxed;
    let state = test_state();
    let hash = [0xCCu8; 32];
    let rec = record_with_hash("rec-relay-bypass", hash);
    state.rocks.put_record(&rec.id, &rec).expect("put");

    // relay=true but the record is local — fetcher MUST NOT be entered.
    let body = compute_record_by_hash_with_relay(state.clone(), hex::encode(hash), true)
        .await
        .expect("hit ok")
        .expect("must produce Some");

    assert_eq!(body["id"].as_str(), Some("rec-relay-bypass"));
    assert_eq!(state.records_by_hash_hits_total.load(Relaxed), 1);
    assert_eq!(
        state
            .records_by_hash_peer_relay_attempts_total
            .load(Relaxed),
        0,
        "local hit MUST short-circuit before the fetcher — relay is a fall-back, not always-fire"
    );
}

#[tokio::test]
async fn s1123_la1_with_relay_true_local_miss_no_peers_bumps_relay_attempts_and_misses() {
    use std::sync::atomic::Ordering::Relaxed;
    let state = test_state();
    let unknown = hex::encode([0xDDu8; 32]);

    let result = compute_record_by_hash_with_relay(state.clone(), unknown, true)
        .await
        .expect("relay-but-no-peers is Ok(None), never Err");

    assert!(
        result.is_none(),
        "no peers in the table → fetcher returns Miss → wrapper returns None"
    );
    assert_eq!(
        state.records_by_hash_misses_total.load(Relaxed),
        1,
        "local miss must still bump the local-tier miss counter"
    );
    assert_eq!(
        state
            .records_by_hash_peer_relay_attempts_total
            .load(Relaxed),
        1,
        "relay=true + local miss MUST enter the fetcher (1 attempt)"
    );
    assert_eq!(
        state.records_by_hash_peer_relay_hits_total.load(Relaxed),
        0,
        "no peers to query → no relay hit possible"
    );
    assert_eq!(
        state.records_by_hash_peer_relay_misses_total.load(Relaxed),
        1,
        "no viable peers → 1 relay miss (per-attempt, not per-peer)"
    );
}

#[tokio::test]
async fn s1123_la1_with_relay_propagates_validation_err_without_entering_fetcher() {
    use std::sync::atomic::Ordering::Relaxed;
    let state = test_state();
    // Malformed input MUST fail validation in the local pre-check,
    // never reach the relay path even when relay=true. Otherwise a
    // account sending garbage with ?relay=1 would amplify into 8 PQ
    // round-trips per bad request — DoS surface.

    let bad = "z".repeat(64);
    let err = compute_record_by_hash_with_relay(state.clone(), bad, true)
        .await
        .expect_err("non-hex must Err");
    let msg = format!("{err}");
    assert!(
        msg.contains("hex"),
        "error must explain expected format: {msg}"
    );

    assert_eq!(
        state.records_by_hash_misses_total.load(Relaxed),
        1,
        "bad input still counts as a local miss"
    );
    // CRITICAL: relay counters MUST NOT be bumped — fetcher is unreached.
    assert_eq!(
        state
            .records_by_hash_peer_relay_attempts_total
            .load(Relaxed),
        0,
        "bad input must NEVER reach the fetcher (DoS amplification guard)"
    );
    assert_eq!(state.records_by_hash_peer_relay_hits_total.load(Relaxed), 0);
    assert_eq!(
        state.records_by_hash_peer_relay_misses_total.load(Relaxed),
        0
    );
}

/// `compute_epoch_headers` used to cache the very
/// first computation indefinitely.  When that first computation ran
/// before any seals existed, the cache held `Some((t, vec![]))`, and
/// every subsequent `since=0` request short-circuited on the cache,
/// returning empty even after seals were written and the CF_EPOCHS
/// index was populated.  Light clients calling `/headers/from/0` got
/// `{"total":0,"headers":[]}` despite the node holding 20K+ seals.
/// The fix distrusts an empty cache when CF_EPOCHS is non-empty and
/// recomputes — this test pins that.
#[tokio::test]
async fn ops170_empty_cache_recomputes_when_index_has_seals() {
    use crate::network::epoch::{create_epoch_seal, disc5_index_key};

    let state = test_state();
    let z = ZoneId::new("ops170/zone");

    // Step 1 — CF_EPOCHS empty.  First call populates the cache with an
    // empty Vec: this mirrors a fresh node that warmed before its first
    // seal landed.
    let body = compute_epoch_headers(state.clone(), None, None, 100)
        .await
        .expect("first call ok");
    assert_eq!(body["total"].as_u64(), Some(0), "no seals yet");

    // Confirm the cache really is `Some((_, []))` so the test is not
    // accidentally exercising a None branch.
    {
        let guard = EPOCH_HEADERS_CACHE.lock().unwrap();
        let (_, ref cached) = guard.as_ref().expect("cache populated by first call");
        assert!(cached.is_empty(), "cache must hold empty vec to reproduce");
    }

    // Step 2 — write a real seal record + DISC-5 index entry.  This is
    // exactly what `register_epoch_seal` does on real ingest.
    let epoch_state = state.epoch.read_recover().clone();
    let (seal_rec, parsed) = create_epoch_seal(
        &state.identity,
        state.rocks.as_ref(),
        &epoch_state,
        z.clone(),
        100.0,
        200.0,
        None,
        None,
    )
    .expect("create_epoch_seal");
    state
        .rocks
        .put_record(&seal_rec.id, &seal_rec)
        .expect("put seal");
    let idx_key = disc5_index_key(parsed.epoch_number, z.path(), &seal_rec.id);
    state
        .rocks
        .put_cf_raw(crate::storage::rocks::CF_EPOCHS, &idx_key, &[])
        .expect("put_cf_raw");

    // Step 3 — call again with `since=0`.  Previously this returned 0
    // because the empty cache short-circuited the recompute path.  The
    // fix never trusts an empty cached vec, so it always recomputes —
    // picking up the new seal via the always-on CF_EPOCHS prefix scan.
    let body = compute_epoch_headers(state.clone(), None, None, 100)
        .await
        .expect("second call ok");
    let total = body["total"].as_u64().unwrap_or(0);
    assert!(
        total >= 1,
        "OPS-170: empty cache + seals in index must recompute (got total={total})"
    );
    // The recomputed list must reach the new seal — surface check.
    let headers = body["headers"].as_array().expect("headers array");
    assert!(
        headers
            .iter()
            .any(|h| h["seal_id"].as_str() == Some(seal_rec.id.as_str())),
        "newly-written seal not in recomputed list: {headers:?}"
    );
}

// ─── compute_epoch_headers wire-shape + filter pinning ──
//
// Gap 1 light-client endpoint /headers/from/{epoch} routes through
// `compute_epoch_headers`. Previously only the cache-poisoning
// path was pinned (`ops170_empty_cache_recomputes_when_index_has_seals`
// above) — the JSON envelope, post-canonical zone/since filters,
// limit truncation, and sort order were unpinned. A account/SDK
// consuming `header.account_smt_root` to verify an account proof
// would break silently on a `#[serde(skip_serializing_if = "Option::is_none")]`
// refactor; a light-client crawler stepping through `?since=N&limit=K`
// would break silently on a "drop limit cap" or "switch to descending sort"
// refactor. All five tests pin one wire-shape invariant on the
// bypass-cache path (since=Some(N>0)) so they sidestep the static
// EPOCH_HEADERS_CACHE (process-wide Mutex shared across parallel
// tests) and the canonical-chain filter (which only runs on
// !bypass_cache and requires EpochState.latest_seal_hash setup).
//
// Test-fixture pattern: reuses `seal_metadata` + `disc5_index_key`
// from `crate::network::epoch` (same path as the
// `compute_account_proof_recovers_binding_from_disk_…` tests at
// :4451 / :4559). Each test seeds 1-5 seal records via
// `put_record` + `put_cf_raw(CF_EPOCHS, …)`, then calls
// `compute_epoch_headers(state, zone_filter, Some(1), limit)` to
// exercise the bypass-cache path.

/// Build a seal record + DISC-5 index entry for a (zone, epoch).
/// Returns the seal's record id so tests can assert per-seal fields.
/// Optional `account_smt_root` mirrors legacy-vs-Gap-1 seals; `None`
/// leaves the field absent in metadata so `extract_epoch_seal`
/// surfaces a `None` on the wire (pinned by axis 2 below).
async fn seed_seal_at(
    state: &Arc<NodeState>,
    zone_path: &str,
    epoch_number: u64,
    account_smt_root: Option<[u8; 32]>,
) -> String {
    use crate::network::epoch::{disc5_index_key, seal_metadata, SealMetadataParams};
    use crate::storage::rocks::CF_EPOCHS;
    let zone = ZoneId::new(zone_path);
    let mut params = SealMetadataParams {
        zone: zone.clone(),
        epoch_number,
        start: 1700000000.0 + epoch_number as f64,
        end: 1700000060.0 + epoch_number as f64,
        record_count: epoch_number, // distinct per-seal so the wire field is not always identical
        merkle_root: &[(epoch_number as u8).wrapping_add(0x10); 32],
        previous_seal_hash: &[(epoch_number as u8).wrapping_add(0x20); 32],
        vrf_output: None,
        vrf_proof: None,
        sparse_merkle_root: None,
        record_hashes: None,
        zone_balance_total: None,
        zone_registry_root: None,
        zone_registry_delta: None,
        aggregator_rank: 0,
        account_smt_root: None,
        drand_pulse: None,
    };
    let _root_storage; // hold the borrow for `account_smt_root`
    if let Some(root) = account_smt_root {
        _root_storage = root;
        params.account_smt_root = Some(&_root_storage);
    }
    let meta = seal_metadata(params);
    // ValidationRecord::create uses uuid7() for the record id, so each
    // call gets a unique id even with identical content bytes — no need
    // to bake a UUID into the content here.
    let body = format!("seal-{}-{}", zone_path, epoch_number);
    let mut seal_record = ValidationRecord::create(
        body.as_bytes(),
        state.identity.public_key.clone(),
        vec![],
        Classification::Public,
        Some(meta),
    );
    seal_record.zone = Some(zone);
    let signable = seal_record.signable_bytes();
    seal_record.signature = Some(state.identity.sign(&signable).unwrap());
    state
        .rocks
        .put_record(&seal_record.id, &seal_record)
        .expect("put seal");
    let key = disc5_index_key(epoch_number, zone_path, &seal_record.id);
    state
        .rocks
        .put_cf_raw(CF_EPOCHS, &key, &[])
        .expect("put disc5 idx");
    seal_record.id
}

/// Axis 1 — populated-seal JSON envelope is exactly
/// `{total, headers}` at the top and exactly the 10 expected keys
/// per header. Defends against (a) a `serde_json::to_value(&header)`
/// swap that would either drop fields or introduce serde's own key
/// set (the manual `json!(…)` block at :2966 emits 10 keys
/// regardless of `EpochHeader.account_smt_root.is_none()` — a
/// `skip_serializing_if = "Option::is_none"` refactor on the struct
/// would silently drop `account_smt_root` and `seal_record_hash`
/// from the wire on legacy seals); (b) accidental top-level key
/// additions (e.g. paging cursor in `{next_since}`) that would
/// break account JSON-schema validators expecting exactly 2 keys.
/// Uses `since=Some(1)` to force the bypass-cache path so the
/// assertion is robust against concurrent tests poisoning the
/// process-global `EPOCH_HEADERS_CACHE`.
#[tokio::test]
async fn compute_epoch_headers_envelope_has_two_keys_and_each_header_ten_keys() {
    use std::collections::BTreeSet;
    let state = test_state();
    let smt_root = [0xCDu8; 32];
    let seal_id = seed_seal_at(&state, "ppp-envelope/a", 5, Some(smt_root)).await;

    let body = compute_epoch_headers(state.clone(), None, Some(1), 100)
        .await
        .expect("bypass-cache path must succeed");

    let top: BTreeSet<&str> = body
        .as_object()
        .expect("top-level must be JSON object")
        .keys()
        .map(|s| s.as_str())
        .collect();
    let expected_top: BTreeSet<&str> = ["total", "headers"].into_iter().collect();
    assert_eq!(
        top, expected_top,
        "top-level envelope must be exactly {{total, headers}}"
    );

    assert_eq!(
        body["total"].as_u64(),
        Some(1),
        "single planted seal must surface"
    );
    let headers = body["headers"].as_array().expect("headers must be array");
    assert_eq!(headers.len(), 1, "headers.len() must match total");

    let header_keys: BTreeSet<&str> = headers[0]
        .as_object()
        .expect("header must be JSON object")
        .keys()
        .map(|s| s.as_str())
        .collect();
    let expected_header: BTreeSet<&str> = [
        "zone",
        "epoch_number",
        "merkle_root",
        "previous_seal_hash",
        "record_count",
        "start",
        "end",
        "account_smt_root",
        "seal_record_hash",
        "seal_id",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        header_keys, expected_header,
        "header must have exactly the 10 wire keys (defends against skip_serializing_if drift)",
    );
    assert_eq!(headers[0]["seal_id"].as_str(), Some(seal_id.as_str()));
    assert_eq!(headers[0]["epoch_number"].as_u64(), Some(5));
    assert_eq!(
        headers[0]["account_smt_root"].as_str(),
        Some(hex::encode(smt_root).as_str())
    );
    // Wire-type purity: catches "harmonize numerics to strings" regression.
    assert!(
        headers[0]["record_count"].is_u64(),
        "record_count must be JSON Number"
    );
    assert!(
        headers[0]["start"].is_f64(),
        "start must be JSON Number (f64)"
    );
}

/// Axis 2 — legacy-seal compatibility: when a seal
/// record was produced before Gap-1 (no `epoch_account_smt_root`
/// in metadata), `EpochHeader.account_smt_root` is `None` and the
/// manual JSON emitter at :2974 renders it as `null` (NOT a
/// missing key). A account calling `header.account_smt_root` must
/// see the key as present-with-null so the proof-binding code can
/// branch on `is_null()` instead of `is_undefined()`. Defends
/// against a `serde_json::to_value(&EpochHeader)` swap where
/// `#[serde(default)]` on the field would NOT trigger
/// `skip_serializing_if` so the wire would stay correct, BUT a
/// follow-up "tighten up the wire shape" refactor adding
/// `skip_serializing_if = "Option::is_none"` would silently drop
/// the key on legacy seals — exactly the breaking change this
/// test pins out. Paired wire-type pin on `seal_record_hash`
/// (which IS populated by `header_from_seal_with_hash` from the
/// record's content hash) ensures the two `Option<[u8; 32]>`
/// fields with the same Rust shape diverge correctly on the wire.
#[tokio::test]
async fn compute_epoch_headers_legacy_seal_emits_null_account_smt_root_key() {
    let state = test_state();
    let seal_id = seed_seal_at(&state, "ppp-legacy/z", 3, None).await;

    let body = compute_epoch_headers(state.clone(), None, Some(1), 100)
        .await
        .expect("bypass-cache path must succeed");

    let headers = body["headers"].as_array().expect("headers array");
    let h = headers
        .iter()
        .find(|h| h["seal_id"].as_str() == Some(seal_id.as_str()))
        .expect("planted seal must appear");
    assert!(
        h.as_object().unwrap().contains_key("account_smt_root"),
        "account_smt_root key MUST be present (not missing) on legacy seals",
    );
    assert!(
        h["account_smt_root"].is_null(),
        "account_smt_root must be JSON null (not a missing key) when seal omitted root: {h}",
    );
    // seal_record_hash IS populated by header_from_seal_with_hash
    // from rec.record_hash() regardless of legacy/Gap-1 status, so
    // the wire field is Some(hex_string) here. Paired pin defends
    // against "treat both Option fields identically" refactor that
    // would either drop both keys or null out both keys.
    assert!(
            h["seal_record_hash"].is_string(),
            "seal_record_hash must be populated from rec.record_hash() regardless of legacy status: {h}",
        );
}

/// Axis 3 — `limit` truncates the returned headers Vec
/// AND `total` matches `headers.len()` after truncation. Previously
/// the limit was applied before the canonical-chain filter, so the
/// filter could shrink the response below `limit` and `total ==
/// headers.len()` was only true coincidentally; the modern shape
/// applies limit AFTER all filters at :3099 so `total ==
/// headers.len()` is a hard invariant. Defends against a refactor
/// that returns `{"total": pre_truncate_len, "headers": …}` where
/// the count would diverge from the array length — accounts paging
/// with `total` would over-/under-read. Also defends against
/// `limit=usize::MAX` removing the truncate call: the test plants
/// 5 seals and asks for 2 explicitly.
#[tokio::test]
async fn compute_epoch_headers_limit_truncates_and_total_matches_headers_len() {
    let state = test_state();
    for e in 1u64..=5 {
        seed_seal_at(&state, "ppp-limit/z", e, None).await;
    }

    let body = compute_epoch_headers(state.clone(), None, Some(1), 2)
        .await
        .expect("bypass-cache path must succeed");

    let headers = body["headers"].as_array().expect("headers array");
    assert_eq!(headers.len(), 2, "limit=2 must truncate the headers Vec");
    assert_eq!(
        body["total"].as_u64(),
        Some(2),
        "total must equal headers.len() AFTER truncation, not pre-truncation count",
    );
}

/// Axis 4 — sort order pins epoch-ascending across
/// insertion order. CF_EPOCHS keys are `(epoch_be, zone, record_id)`
/// so the RocksDB prefix scan already yields epoch-ascending order;
/// the post-scan `sort_by` at :3036 is defensive against that
/// invariant changing. Plants 4 seals in scrambled insertion order
/// (epochs 10, 3, 10, 3 across two zones) and asserts the final
/// `headers[*].epoch_number` sequence is monotonically non-
/// decreasing — the strongest pin available without depending on
/// per-zone tiebreak (modern ZoneId serializes as JSON String so
/// `h["zone"].as_u64()` returns None → unwrap_or(0) in the sort
/// comparator, making the primary key always 0 in the modern
/// path; the secondary epoch key drives the entire order).
/// Defends against a "switch to descending sort for fresh-first
/// display" refactor that would break light-client cold-sync (which
/// MUST walk forward from genesis epoch).
#[tokio::test]
async fn compute_epoch_headers_sorted_by_epoch_ascending() {
    let state = test_state();
    // Scrambled insertion order: 10, 3, 10, 3.
    seed_seal_at(&state, "ppp-sort/a", 10, None).await;
    seed_seal_at(&state, "ppp-sort/b", 3, None).await;
    seed_seal_at(&state, "ppp-sort/b", 10, None).await;
    seed_seal_at(&state, "ppp-sort/a", 3, None).await;

    let body = compute_epoch_headers(state.clone(), None, Some(1), 100)
        .await
        .expect("bypass-cache path must succeed");

    let headers = body["headers"].as_array().expect("headers array");
    assert_eq!(headers.len(), 4, "all 4 planted seals must surface");
    let epochs: Vec<u64> = headers
        .iter()
        .map(|h| {
            h["epoch_number"]
                .as_u64()
                .expect("epoch_number must be u64")
        })
        .collect();
    for w in epochs.windows(2) {
        assert!(
            w[0] <= w[1],
            "epochs must be monotonically non-decreasing: got {epochs:?}",
        );
    }
    // First-and-last sanity: with 4 seals at epochs {3, 3, 10, 10},
    // the sorted sequence MUST start at 3 and end at 10.
    assert_eq!(epochs.first().copied(), Some(3));
    assert_eq!(epochs.last().copied(), Some(10));
}

/// Axis 5 — `zone_filter` narrows the response to the
/// requested zone. Filter is applied at :3084 over the post-scan
/// vec (NOT pushed into the RocksDB prefix scan), so it must
/// correctly handle BOTH the modern string-zone JSON and the
/// legacy numeric-zone JSON via the `is_none_or` predicate pair.
/// Pre-filter the response holds seals from both zones; post-filter
/// only the matching zone's seals remain. Defends against (a) a
/// "lift the filter into the scan" refactor that would skip the
/// legacy-numeric-zone branch silently (no test fails because
/// CF_EPOCHS keys store the zone as bytes-of-the-path-string and
/// the legacy path would still match for "0"/"1" style zones),
/// and (b) a typo dropping the `&& h["zone"].as_u64()…` clause
/// that would keep modern-zone filter intact but break legacy
/// callers.
#[tokio::test]
async fn compute_epoch_headers_zone_filter_restricts_to_matching_zone() {
    let state = test_state();
    let alpha_id = seed_seal_at(&state, "ppp-zone/alpha", 5, None).await;
    let _beta_id = seed_seal_at(&state, "ppp-zone/beta", 5, None).await;
    let beta2_id = seed_seal_at(&state, "ppp-zone/beta", 7, None).await;

    // First call: no filter → both zones surface.
    let unfiltered = compute_epoch_headers(state.clone(), None, Some(1), 100)
        .await
        .expect("unfiltered call must succeed");
    let unfiltered_headers = unfiltered["headers"].as_array().expect("headers array");
    assert_eq!(
        unfiltered_headers.len(),
        3,
        "all 3 planted seals must surface unfiltered"
    );

    // Second call: zone="ppp-zone/alpha" → only alpha surfaces.
    let filtered = compute_epoch_headers(
        state.clone(),
        Some(ZoneId::new("ppp-zone/alpha")),
        Some(1),
        100,
    )
    .await
    .expect("zone-filtered call must succeed");
    let filtered_headers = filtered["headers"].as_array().expect("headers array");
    assert_eq!(
        filtered_headers.len(),
        1,
        "only the alpha seal must survive zone filter"
    );
    assert_eq!(
        filtered_headers[0]["seal_id"].as_str(),
        Some(alpha_id.as_str()),
        "the one surviving header must be the alpha seal",
    );
    assert_eq!(filtered_headers[0]["zone"].as_str(), Some("ppp-zone/alpha"));
    // Negative pin: beta_id must NOT appear in filtered response.
    assert!(
        !filtered_headers
            .iter()
            .any(|h| h["seal_id"].as_str() == Some(beta2_id.as_str())),
        "beta seal must NOT appear in alpha-filtered response: {filtered_headers:?}",
    );
    assert_eq!(
        filtered["total"].as_u64(),
        Some(1),
        "total must match filtered headers.len(), not pre-filter count",
    );
}

// ── compute_checkpoints_from tests ─────────
//
// /checkpoints/from/{epoch} is the Gap-3 super-seal cold-start path
// for light clients: at boot they pull the latest super-seal per
// zone, verify it against the trusted anchor key, then fast-forward
// to the next epoch via /headers/from/{epoch}. compute_checkpoints_
// from at :3305 is the pure handler — pre-slice has ZERO DIRECT
// tests (only one indirect end-to-end empty-state probe in
// pq_transport/router.rs:3957 via PqNodeClient::checkpoints_from)
// yet covers FIVE behaviour classes account/light-client traffic
// depends on: (i) populated-cache-miss path (latest_super_seal
// iterated, records fetched, extract_super_seal parsed, JSON
// envelope emitted with 9 per-checkpoint keys + 3 top-level keys);
// (ii) empty-state short-circuit (no latest_super_seal entries →
// return immediately with empty array AND cache the empty result,
// skipping the spawn_blocking entirely per the :3345-3356 branch);
// (iii) sort order across zones ((zone_str, end_epoch) ascending
// lexicographic at :3391-3399, defending against HashMap iter
// non-determinism); (iv) zone_filter post-cache narrowing at
// :3407-3417 (filter applied AFTER cache load, so a "lift the
// filter into the latest_super_seal iter" refactor would break
// cache reuse); (v) limit truncation at :3418 with total
// reflecting post-truncate count. The SUPER_SEALS_CACHE static
// is a process-global Mutex with no bypass-cache parameter (unlike
// compute_epoch_headers which has `since=Some(N)`), so a tokio
// gate Mutex serializes these 5 tests at the same level the
// function locks the cache — without it, a parallel test could
// poison the cache between our reset and our compute call, the
// cache-always-wins logic at :3315-3322 would feed the parallel
// test's super-seals to our filter+truncate at :3407-3418, and
// our assertions would fail flakily.

static QQQQ_CACHE_GATE: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Plant a super-seal record in rocks AND register it in
/// EpochState.latest_super_seal so compute_checkpoints_from finds
/// it via the O(active_zones) iter at :3336-3343.
async fn seed_super_seal_at(
    state: &Arc<NodeState>,
    zone_path: &str,
    start_epoch: u64,
    end_epoch: u64,
    seal_count: u64,
    committee_hash: [u8; 32],
) -> String {
    use crate::network::epoch::super_seal_metadata;
    let zone = ZoneId::new(zone_path);
    let merkle_root = [(end_epoch as u8).wrapping_add(0x40); 32];
    let prev_hash = [(end_epoch as u8).wrapping_add(0x50); 32];
    let meta = super_seal_metadata(
        zone.clone(),
        start_epoch,
        end_epoch,
        seal_count,
        &merkle_root,
        &prev_hash,
        &committee_hash,
    );
    let body = format!("super-seal-{}-{}-{}", zone_path, start_epoch, end_epoch);
    let mut rec = ValidationRecord::create(
        body.as_bytes(),
        state.identity.public_key.clone(),
        vec![],
        Classification::Public,
        Some(meta),
    );
    rec.zone = Some(zone.clone());
    let signable = rec.signable_bytes();
    rec.signature = Some(state.identity.sign(&signable).unwrap());
    state
        .rocks
        .put_record(&rec.id, &rec)
        .expect("put super-seal");
    let rec_hash = rec.record_hash();
    {
        use crate::network::RwLockRecover;
        let mut ep = state.epoch.write_recover();
        ep.register_super_seal(zone, end_epoch, rec.id.clone(), rec_hash, committee_hash);
    }
    rec.id
}

/// Reset the process-global SUPER_SEALS_CACHE so this test sees a
/// fresh state. Callers MUST hold `QQQQ_CACHE_GATE` to avoid a
/// parallel test poisoning the cache between this reset and the
/// compute_checkpoints_from call.
fn reset_super_seals_cache_qqqq() {
    let mut guard = SUPER_SEALS_CACHE.lock().expect("cache mutex");
    *guard = None;
}

/// Axis 1 — populated-state JSON envelope is exactly
/// `{total, super_seal_interval, checkpoints}` at the top and
/// exactly the 9 expected keys per checkpoint. Defends against
/// (a) a `serde_json::to_value(&parsed_super_seal)` swap that
/// would either drop fields or pick up `ParsedSuperSeal`'s serde
/// key set (`#[serde(default)] committee_hash` at epoch.rs:3268
/// means a serde-roundtrip refactor would silently emit the
/// default zero-hash on legacy super-seals where the metadata key
/// is absent, masking the operator-visible "no committee yet"
/// signal); (b) accidental top-level key additions (e.g. paging
/// cursor in `{next_zone}`) that would break account JSON-schema
/// validators expecting exactly 3 keys. Paired wire-type pin:
/// `start_epoch.is_u64()` + `total.is_u64()` +
/// `super_seal_interval.is_u64()` defends against a future
/// "harmonize all numerics to strings for JS BigInt safety"
/// regression that would render Number fields as Strings — light
/// clients parsing super_seal_interval as a plain integer would
/// silently parse the wrong cadence and over- or under-fetch
/// headers between checkpoints.
#[tokio::test]
async fn compute_checkpoints_from_envelope_has_three_keys_and_each_checkpoint_nine_keys() {
    use std::collections::BTreeSet;
    let _gate = QQQQ_CACHE_GATE.lock().await;
    reset_super_seals_cache_qqqq();
    let state = test_state();
    let committee_hash = [0xCD; 32];
    let _rec_id = seed_super_seal_at(&state, "qqq-envelope/a", 1, 64, 64, committee_hash).await;

    let body = compute_checkpoints_from(&state, 0, None, 100)
        .await
        .expect("populated cache-miss path must succeed");

    let top: BTreeSet<&str> = body
        .as_object()
        .expect("top-level must be JSON object")
        .keys()
        .map(|s| s.as_str())
        .collect();
    let expected_top: BTreeSet<&str> = ["total", "super_seal_interval", "checkpoints"]
        .into_iter()
        .collect();
    assert_eq!(
        top, expected_top,
        "top-level envelope must be exactly 3 keys: {{total, super_seal_interval, checkpoints}}"
    );

    // Wire-type pin: numerics MUST remain JSON Number not String.
    assert!(
        body["total"].is_u64(),
        "total must be JSON Number (u64), not String"
    );
    assert!(
        body["super_seal_interval"].is_u64(),
        "super_seal_interval must be JSON Number (u64)"
    );

    let checkpoints = body["checkpoints"].as_array().expect("checkpoints array");
    assert_eq!(
        checkpoints.len(),
        1,
        "single planted super-seal must surface"
    );
    let cp = &checkpoints[0];
    let cp_keys: BTreeSet<&str> = cp
        .as_object()
        .expect("checkpoint must be JSON object")
        .keys()
        .map(|s| s.as_str())
        .collect();
    let expected_cp: BTreeSet<&str> = [
        "zone",
        "start_epoch",
        "end_epoch",
        "seal_count",
        "merkle_root",
        "previous_super_seal_hash",
        "committee_hash",
        "record_id",
        "record_hash",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        cp_keys, expected_cp,
        "per-checkpoint envelope must be exactly 9 keys"
    );

    // Wire-type pin on start_epoch (JSON-Number).
    assert!(
        cp["start_epoch"].is_u64(),
        "start_epoch must be JSON Number (u64)"
    );
    assert_eq!(cp["zone"].as_str(), Some("qqq-envelope/a"));
    assert_eq!(cp["start_epoch"].as_u64(), Some(1));
    assert_eq!(cp["end_epoch"].as_u64(), Some(64));
    assert_eq!(cp["seal_count"].as_u64(), Some(64));
}

/// Axis 2 — empty-state short-circuit. When
/// EpochState.latest_super_seal is empty (fresh-genesis / bootstrap
/// / pre-first-super-seal), compute_checkpoints_from short-circuits
/// BEFORE the spawn_blocking call at :3358, returning
/// `{total: 0, super_seal_interval: 64, checkpoints: []}` with the
/// empty result cached at :3348-3350. Defends against (a) a
/// refactor that consolidates the empty-check into the post-spawn
/// loop — same JSON output but a wasted thread-pool slot per call,
/// matters at the 1M-zone target where the cold-start storm could
/// saturate `tokio::task::spawn_blocking`'s default 512-thread
/// limit; (b) regression that would skip caching the empty result,
/// causing every empty-state request to re-enter the same code
/// path. Pin asserts the JSON shape AND the SUPER_SEAL_INTERVAL
/// constant — light clients read super_seal_interval to know how
/// many epochs each checkpoint covers, so the value pinned here
/// MUST match the canonical 64-epoch constant from epoch.rs:159.
#[tokio::test]
async fn compute_checkpoints_from_empty_state_short_circuits_with_canonical_interval() {
    let _gate = QQQQ_CACHE_GATE.lock().await;
    reset_super_seals_cache_qqqq();
    let state = test_state();
    // Do NOT plant any super-seal — latest_super_seal stays empty.

    let body = compute_checkpoints_from(&state, 0, None, 100)
        .await
        .expect("empty-state path must succeed");

    assert_eq!(body["total"].as_u64(), Some(0), "no super-seals → total=0");
    assert_eq!(
        body["super_seal_interval"].as_u64(),
        Some(crate::network::epoch::SUPER_SEAL_INTERVAL),
        "super_seal_interval MUST surface the canonical 64-epoch constant — \
             light clients depend on this exact value"
    );
    let checkpoints = body["checkpoints"].as_array().expect("checkpoints array");
    assert!(
        checkpoints.is_empty(),
        "no super-seals → empty checkpoints array"
    );
}

/// Axis 3 — sort order pins (zone_str, end_epoch)
/// ascending lexicographic at the post-fetch sort at :3391-3399.
/// latest_super_seal is a `HashMap<ZoneId, ...>` so insertion
/// order is non-deterministic (HashMap iter is randomized per
/// process via RandomState seed); the explicit sort guarantees
/// stable JSON output for cache-friendly client diffing and for
/// the account UX that displays the checkpoint list in
/// alphabetic-by-zone order. Plants 2 super-seals across 2 zones
/// in REVERSE alphabetic order (zone "z-zone" first, then
/// "a-zone") and asserts the response surfaces "a-zone" at index
/// 0 — defending against a "drop the sort, latest_super_seal
/// iter is good enough" refactor that would yield non-
/// deterministic ordering across calls. Cross-axis: also pins
/// the unfiltered call surfaces BOTH planted super-seals
/// (defending against an over-aggressive filter that drops
/// either of them silently). Note: each zone holds only ONE
/// super-seal in latest_super_seal (newest wins per
/// register_super_seal at epoch.rs:1334-1340), so the cross-zone
/// sort is the only sort path exercised at the public surface;
/// the secondary `end_epoch` key in the sort comparator is
/// defensive against a future patch that changes latest_super_seal
/// to hold a Vec per zone.
#[tokio::test]
async fn compute_checkpoints_from_sorted_by_zone_ascending_lexicographic() {
    let _gate = QQQQ_CACHE_GATE.lock().await;
    reset_super_seals_cache_qqqq();
    let state = test_state();
    let committee_hash = [0; 32];
    // Insert "z-..." FIRST so HashMap insertion order is reverse-alphabetic.
    let _z_id = seed_super_seal_at(&state, "qqq-sort/z-zone", 1, 64, 64, committee_hash).await;
    let _a_id = seed_super_seal_at(&state, "qqq-sort/a-zone", 1, 64, 64, committee_hash).await;

    let body = compute_checkpoints_from(&state, 0, None, 100)
        .await
        .expect("populated path must succeed");

    let checkpoints = body["checkpoints"].as_array().expect("checkpoints array");
    // Cross-axis pin: BOTH planted super-seals surface unfiltered.
    assert_eq!(
        checkpoints.len(),
        2,
        "both planted super-seals must surface"
    );
    assert_eq!(
        body["total"].as_u64(),
        Some(2),
        "total must equal checkpoints.len()"
    );
    // Primary axis pin: alphabetic ordering despite reverse insertion.
    assert_eq!(
        checkpoints[0]["zone"].as_str(),
        Some("qqq-sort/a-zone"),
        "alphabetic-first zone must surface at index 0 despite being inserted SECOND",
    );
    assert_eq!(
        checkpoints[1]["zone"].as_str(),
        Some("qqq-sort/z-zone"),
        "alphabetic-last zone must surface at index 1 despite being inserted FIRST",
    );
}

/// Axis 4 — `zone_filter` narrows the response to the
/// requested zone at the post-cache filter at :3407-3417. Filter
/// is applied AFTER cache load, so a "lift the filter into the
/// latest_super_seal iter" refactor would break the cache reuse
/// pattern (filtered + unfiltered calls would clobber each other's
/// cache, since the cache is shared across all filter variants).
/// Plants 2 super-seals across 2 zones, calls with zone_filter
/// for one of them, asserts ONLY the matching zone surfaces.
/// Triple assertion: (a) positive — alpha-zone is present;
/// (b) total reflects filtered count (1), not pre-filter count
/// (2), so accounts paging on `total` don't over-read past the
/// array end; (c) negative pin — beta's `record_id` MUST NOT
/// appear in the filtered response (defending against an
/// inverted-predicate regression that would let both zones
/// through).
#[tokio::test]
async fn compute_checkpoints_from_zone_filter_narrows_to_matching_zone_only() {
    let _gate = QQQQ_CACHE_GATE.lock().await;
    reset_super_seals_cache_qqqq();
    let state = test_state();
    let committee_hash = [0; 32];
    let _alpha_id = seed_super_seal_at(&state, "qqq-zone/alpha", 1, 64, 64, committee_hash).await;
    let beta_id = seed_super_seal_at(&state, "qqq-zone/beta", 1, 64, 64, committee_hash).await;

    let body = compute_checkpoints_from(&state, 0, Some(ZoneId::new("qqq-zone/alpha")), 100)
        .await
        .expect("zone-filtered call must succeed");

    let checkpoints = body["checkpoints"].as_array().expect("checkpoints array");
    assert_eq!(
        checkpoints.len(),
        1,
        "only the alpha super-seal must survive zone filter, got: {checkpoints:?}",
    );
    assert_eq!(checkpoints[0]["zone"].as_str(), Some("qqq-zone/alpha"));
    assert_eq!(
        body["total"].as_u64(),
        Some(1),
        "total must reflect filtered checkpoints.len() (1), NOT pre-filter count (2)",
    );
    // Negative pin: beta's record_id must NOT appear in filtered response.
    assert!(
        !checkpoints
            .iter()
            .any(|c| c["record_id"].as_str() == Some(beta_id.as_str())),
        "beta super-seal must NOT appear in alpha-filtered response: {checkpoints:?}",
    );
}

/// Axis 5 — `limit` truncates AND `total` reflects
/// post-truncate count. Plants 3 super-seals across 3 zones,
/// calls with `limit=2`, asserts `checkpoints.len() == 2` AND
/// `total == 2`. Defends against (a) a refactor that returns
/// `{"total": pre_truncate_len, "checkpoints": …}` where the
/// count would diverge from the array length (accounts paging on
/// `total` would over-/under-read past the array boundary, and
/// in browsers that's a `undefined.zone` access on the JS side);
/// (b) `limit=usize::MAX` regression removing the truncate call
/// entirely (test plants 3 super-seals and asks for 2
/// explicitly, so a truncate(usize::MAX) no-op would surface all
/// 3 and fail the `checkpoints.len() == 2` assertion); (c) a
/// truncate-but-compute-total-pre-truncate refactor that would
/// pass the array-length assertion but fail the total
/// assertion. The 3-super-seals plant size is the minimum that
/// reliably distinguishes (3 > limit > 0) without relying on
/// `limit=0` edge cases (which are exercised elsewhere).
#[tokio::test]
async fn compute_checkpoints_from_limit_truncates_and_total_matches_array_len() {
    let _gate = QQQQ_CACHE_GATE.lock().await;
    reset_super_seals_cache_qqqq();
    let state = test_state();
    let committee_hash = [0; 32];
    for i in 0u64..3 {
        seed_super_seal_at(
            &state,
            &format!("qqq-limit/zone-{i}"),
            1,
            64,
            64,
            committee_hash,
        )
        .await;
    }

    let body = compute_checkpoints_from(&state, 0, None, 2)
        .await
        .expect("populated path must succeed");

    let checkpoints = body["checkpoints"].as_array().expect("checkpoints array");
    assert_eq!(
        checkpoints.len(),
        2,
        "limit=2 must truncate the checkpoints Vec"
    );
    assert_eq!(
        body["total"].as_u64(),
        Some(2),
        "total must equal checkpoints.len() AFTER truncation, not pre-truncation count",
    );
}

// ── compute_committees_snapshot tests ──────
//
// compute_committees_snapshot at :1659 is the /committees route handler
// — the gap-5 per-zone VRF witness committee surface that light clients
// hit to verify a seal's claimed committee_hash against the ground-
// truth draw per Protocol §11.5 + internal design notes. The
// helper delegates to state_committees_snapshot at zone_committee.rs:569
// for the per-zone resolver-cache draw, but the SHAPE of the JSON
// envelope at this route layer + the 4 query-param default-fallback
// semantics (epoch, k, from, limit) live ENTIRELY at :1666-1691 and
// have had ZERO direct coverage at the route layer — the 4
// existing tests at zone_committee.rs:1782/1793/1845/2144 cover the
// helper one layer below, but NOT this wrapper's envelope or default-
// unwrap behaviour. 5 axes natively orthogonal: (i) 6-key top-level
// envelope shape + wire-type pins; (ii) None-fallback semantics for
// epoch/k/limit pulling from state.dag.current_epoch() +
// DEFAULT_COMMITTEE_SIZE + DEFAULT_COMMITTEES_PAGE_SIZE constants;
// (iii) pagination — `next_from` reports the next zone past the page
// boundary, NOT the last zone IN the page; (iv) `from` is INCLUSIVE
// lower bound (partition_point uses `<`); (v) empty-state returns
// empty JSON object `{}` for committees (NOT JSON null), preserving
// account for-loop iteration semantics.
//
// Test-fixture pattern: ALL 5 tests use the existing test_state()
// helper at :3746 plus a new seed_committees_state(state, zones,
// anchors_with_stake) helper at :5557-5599 wrapping the three-step
// ZoneRegistry::with_genesis + VrfRegistry::register + ledger.accounts
// .insert ritual already proven at zone_committee.rs:1802-1844. No
// process-global cache here — NodeState's vrf_registry / zone_registry
// / ledger are per-instance — so no test gate Mutex needed (unlike
// the SUPER_SEALS_CACHE tests which had to serialize against that cache).

/// Seed a NodeState with active zones + VRF-registered anchors + per-
/// anchor stake in one call. Returns nothing — caller drives reads
/// via compute_committees_snapshot. Mirrors the proven shape at
/// zone_committee.rs:1802-1844.
async fn seed_committees_state(
    state: &Arc<NodeState>,
    zones: &[&str],
    anchors_with_stake: &[(&str, u64)],
) {
    use crate::network::vrf_registry::VrfRegistration;
    use crate::network::zone_registry::ZoneRegistry;
    use crate::ZoneId;
    {
        let mut reg = state.zone_registry.write().expect("zone registry");
        let zone_ids: Vec<ZoneId> = zones.iter().map(|z| ZoneId::new(z)).collect();
        *reg = ZoneRegistry::with_genesis(zone_ids);
    }
    {
        let mut vreg = state.vrf_registry.write().expect("vrf registry");
        for (i, (anchor, _)) in anchors_with_stake.iter().enumerate() {
            vreg.register(
                anchor,
                VrfRegistration {
                    vrf_public_key_hex: hex::encode([(0xA0 + i as u8); 32]),
                    vrf_full_public_key_hex: String::new(),
                    registered_at: 1.0,
                    record_id: format!("rec-{anchor}"),
                    node_type: "anchor".into(),
                },
            );
        }
    }
    {
        let mut ledger = state.ledger.write().await;
        for (anchor, stake) in anchors_with_stake {
            let acc = crate::accounting::ledger::AccountState {
                staked: *stake,
                ..Default::default()
            };
            ledger.accounts.insert(anchor.to_string(), acc);
        }
    }
}

/// Axis 1 — 6-key top-level envelope is exactly
/// `{epoch, committee_size, page_size, zone_count, next_from,
/// committees}` with wire-type pins. Plants 2 zones + 2 staked
/// anchors, calls with all params Some(_), asserts strict BTreeSet
/// symmetric-difference against the canonical key set. Defends
/// against (a) `serde_json::to_value(&snapshot_struct)` refactor
/// that would inherit the struct's serde key set (introducing
/// `#[serde(rename = "cursor")]` on `next_from` would silently
/// break accounts that grep for `next_from`), (b) a paging-cursor
/// rename to `cursor`/`next_zone` that would break the schema
/// validators, (c) a `#[serde(skip_serializing_if = "Option::is_none")]`
/// regression on `next_from` that would DROP the key entirely when
/// the page ends rather than emit JSON null (accounts parsing
/// `body.next_from === null` would crash on `undefined`). Wire-type
/// pins on `epoch.is_u64()` + `committee_size.is_u64()` +
/// `page_size.is_u64()` + `zone_count.is_u64()` defend against
/// the "harmonize numerics to strings for JS BigInt safety"
/// regression; pin on `committees.is_object()` (NOT array)
/// defends against a refactor that flattens the BTreeMap into
/// a `[{zone, members}]` list which would silently double the
/// wire size + break the account's `committees[zone]` access
/// pattern.
#[tokio::test]
async fn compute_committees_snapshot_envelope_has_six_keys_with_wire_type_pins() {
    use std::collections::BTreeSet;
    let state = test_state();
    seed_committees_state(
        &state,
        &["rrr-env/alpha", "rrr-env/beta"],
        &[("anchor-A", 1000), ("anchor-B", 500)],
    )
    .await;

    let body = compute_committees_snapshot(state.clone(), Some(7), Some(5), None, Some(1000)).await;

    let top: BTreeSet<&str> = body
        .as_object()
        .expect("top-level must be JSON object")
        .keys()
        .map(|s| s.as_str())
        .collect();
    let expected: BTreeSet<&str> = [
        "epoch",
        "committee_size",
        "page_size",
        "zone_count",
        "next_from",
        "committees",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        top, expected,
        "top-level envelope must be exactly 6 keys: \
             {{epoch, committee_size, page_size, zone_count, next_from, committees}}",
    );

    // Wire-type pins — numerics MUST stay JSON Number not String.
    assert!(body["epoch"].is_u64(), "epoch must be JSON Number (u64)");
    assert!(
        body["committee_size"].is_u64(),
        "committee_size must be JSON Number (u64)",
    );
    assert!(
        body["page_size"].is_u64(),
        "page_size must be JSON Number (u64)"
    );
    assert!(
        body["zone_count"].is_u64(),
        "zone_count must be JSON Number (u64)"
    );
    // `committees` MUST be JSON Object — accounts index by zone path,
    // a refactor to JSON Array would silently break that pattern.
    assert!(
        body["committees"].is_object(),
        "committees must be JSON Object keyed by zone path, NOT Array",
    );
    // `next_from` is JSON null when the page covers all zones (2
    // zones < page_size 1000 → no more to paginate). This MUST be
    // present-with-null (a skip_serializing_if would drop the key).
    assert!(
        body.as_object().unwrap().contains_key("next_from"),
        "next_from key must be PRESENT even when null (no skip_serializing_if)",
    );
    assert!(
        body["next_from"].is_null(),
        "next_from must be JSON null when no more pages exist",
    );

    assert_eq!(body["epoch"].as_u64(), Some(7));
    assert_eq!(body["committee_size"].as_u64(), Some(5));
    assert_eq!(body["page_size"].as_u64(), Some(1000));
    assert_eq!(body["zone_count"].as_u64(), Some(2));
}

/// Axis 2 — None-fallbacks pull from canonical constants
/// + state.dag.current_epoch(). When the caller passes `epoch=None,
/// k=None, limit=None`, the function MUST use
/// `state.dag.read().await.current_epoch()` (at :1668) +
/// `DEFAULT_COMMITTEE_SIZE` (=7, at :1670) +
/// `DEFAULT_COMMITTEES_PAGE_SIZE` (=1000, at :1672). Defends against
/// (a) a refactor that hardcodes `0`/`1`/`5` for k/limit (would
/// diverge from the operator-mental-model of "use the protocol
/// default unless overridden"), (b) a refactor that swaps
/// `current_epoch()` for `latest_finalized_epoch()` or
/// `latest_sealed_epoch()` — these are SEMANTICALLY DIFFERENT
/// (current_epoch is "now", finalized is "2/3-attested",
/// sealed is "anchor-signed") and a silent swap would render
/// committees that no longer match what an operator on the
/// current epoch sees, breaking the /committees → /seals
/// cross-reference UX. Pin uses the canonical constants directly
/// (NOT hardcoded 7/1000) so a future protocol-level cadence
/// change tracks here without a regression.
#[tokio::test]
async fn compute_committees_snapshot_none_fallbacks_use_canonical_constants() {
    let state = test_state();
    seed_committees_state(&state, &["rrr-defaults/zone"], &[("anchor-X", 1000)]).await;

    // Call with ALL params None — the function MUST unwrap to
    // canonical constants + dag.current_epoch().
    let body = compute_committees_snapshot(state.clone(), None, None, None, None).await;

    // dag.current_epoch() on a fresh DAG starts at 0.
    assert_eq!(
        body["epoch"].as_u64(),
        Some(0),
        "epoch=None MUST resolve via state.dag.current_epoch() — \
             fresh DAG starts at 0",
    );
    assert_eq!(
        body["committee_size"].as_u64(),
        Some(crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE as u64),
        "k=None MUST resolve to DEFAULT_COMMITTEE_SIZE (canonical \
             constant, currently 7) — pin tracks the constant not the literal",
    );
    assert_eq!(
        body["page_size"].as_u64(),
        Some(crate::network::zone_committee::DEFAULT_COMMITTEES_PAGE_SIZE as u64),
        "limit=None MUST resolve to DEFAULT_COMMITTEES_PAGE_SIZE \
             (canonical constant, currently 1000) — pin tracks the constant",
    );
}

/// Axis 3 — `limit` truncates AND `next_from` reports the
/// NEXT zone past the page boundary (NOT the last zone IN the page).
/// Plants 3 zones (`rrr-page/a`, `rrr-page/b`, `rrr-page/c`) in
/// `zone_registry`, calls with `limit=Some(2)`. The page covers zones
/// `a` + `b`; `next_from` MUST equal `"rrr-page/c"` — the FIRST zone
/// strictly past the page end. Defends against (a) off-by-one
/// refactor that emits `next_from = page.last()` (the last zone IN
/// the page), which would make pagination jump back-and-forth
/// (caller would paginate from `b` and re-fetch `b` itself); (b)
/// regression that emits `next_from = null` when the limit is hit
/// but more zones exist (caller would think pagination is done
/// despite 1 unfetched zone, silently truncating coverage at the
/// 1M-zone mainnet target); (c) regression where `zone_count`
/// reflects unfiltered total instead of `committees.len()` —
/// asserts `zone_count == 2` (matches page size, NOT 3 zones total),
/// triple-pinned against the partition_point + slice + len chain at
/// zone_committee.rs:610-636. Cross-axis assertion: zone-ordering is
/// lex-ascending across the BTreeMap iteration (BTreeMap's contract
/// at the JSON layer); planting in insertion order matches lex order
/// here so the pin is on `committees.keys()` containing exactly
/// `{a, b}` not on the insertion-order itself.
#[tokio::test]
async fn compute_committees_snapshot_limit_truncates_and_next_from_points_past_page() {
    let state = test_state();
    seed_committees_state(
        &state,
        &["rrr-page/a", "rrr-page/b", "rrr-page/c"],
        &[("anchor-A", 1000), ("anchor-B", 500)],
    )
    .await;

    let body = compute_committees_snapshot(state.clone(), Some(0), Some(2), None, Some(2)).await;

    let committees = body["committees"]
        .as_object()
        .expect("committees must be JSON Object");
    assert_eq!(
        committees.len(),
        2,
        "limit=2 must cap the page at 2 zones, got: {committees:?}",
    );
    assert_eq!(
        body["zone_count"].as_u64(),
        Some(2),
        "zone_count must reflect page size (2), NOT total zone count (3)",
    );
    assert!(
        committees.contains_key("rrr-page/a"),
        "alphabetic-first zone must be on the page",
    );
    assert!(
        committees.contains_key("rrr-page/b"),
        "alphabetic-second zone must be on the page",
    );
    assert!(
        !committees.contains_key("rrr-page/c"),
        "alphabetic-third zone must be OFF the page (past limit=2)",
    );

    // CRITICAL — next_from MUST point to the FIRST zone strictly past
    // the page end (c), NOT the LAST zone IN the page (b).
    assert_eq!(
        body["next_from"].as_str(),
        Some("rrr-page/c"),
        "next_from MUST point to the FIRST zone PAST the page boundary \
             (rrr-page/c), NOT the last zone IN the page (rrr-page/b) — \
             this is the load-bearing pin against the off-by-one pagination \
             refactor that would make callers re-fetch the boundary zone",
    );
}

/// Axis 4 — `from` is INCLUSIVE lower bound (lex). Plants
/// 3 zones (`rrr-from/a`, `rrr-from/b`, `rrr-from/c`), calls with
/// `from=Some("rrr-from/b")`. The partition_point at
/// zone_committee.rs:611 uses `z.as_str() < f` which skips zones
/// STRICTLY LESS than `f` — so `b` itself IS included. Asserts
/// `committees.keys() == {b, c}` (a is excluded, b is included).
/// Defends against (a) refactor that flips `<` to `<=` making
/// `from` exclusive (off-by-one in pagination — caller paginating
/// `from=next_from` would SKIP the boundary zone, silently losing
/// coverage at every page break); (b) refactor that filters the
/// full list BEFORE sort (would surface zones lex-before `from` if
/// the sort happens after the filter); (c) regression where
/// `next_from == None` is incorrectly emitted when no MORE pages
/// remain (asserts the page-end no-more-pages branch as well —
/// 2 zones in page = remaining zones, page_size default = 1000 > 2,
/// so next_from MUST be null here).
#[tokio::test]
async fn compute_committees_snapshot_from_param_is_inclusive_lower_bound() {
    use std::collections::BTreeSet;
    let state = test_state();
    seed_committees_state(
        &state,
        &["rrr-from/a", "rrr-from/b", "rrr-from/c"],
        &[("anchor-A", 1000)],
    )
    .await;

    let body = compute_committees_snapshot(
        state.clone(),
        Some(0),
        Some(2),
        Some("rrr-from/b".to_string()),
        Some(1000),
    )
    .await;

    let committees = body["committees"]
        .as_object()
        .expect("committees must be JSON Object");
    let actual: BTreeSet<&str> = committees.keys().map(|s| s.as_str()).collect();
    let expected: BTreeSet<&str> = ["rrr-from/b", "rrr-from/c"].into_iter().collect();
    assert_eq!(
        actual, expected,
        "from='rrr-from/b' is INCLUSIVE — page MUST contain {{b, c}} \
             and EXCLUDE a (partition_point uses `<` not `<=` per \
             zone_committee.rs:611). A refactor flipping `<` to `<=` \
             would silently skip the boundary zone, breaking pagination \
             at every page break.",
    );
    assert_eq!(
        body["zone_count"].as_u64(),
        Some(2),
        "zone_count must match committees.len() (2) — b included, c included, a excluded",
    );
    // page covers b+c, no more zones — next_from MUST be null.
    assert!(
        body["next_from"].is_null(),
        "next_from MUST be null when the page covers all remaining \
             zones — got: {:?}",
        body["next_from"],
    );
}

/// Axis 5 — empty registry returns canonical empty
/// envelope. Plants ZERO zones / anchors / stake. Calls. Asserts:
/// `zone_count == 0`, `committees == {}` (JSON object NOT null
/// NOT array), `next_from == null`, `epoch == 0`, `committee_size
/// == DEFAULT_COMMITTEE_SIZE`. Defends against (a) refactor that
/// returns JSON null or `[]` for empty `committees` — accounts
/// running `for (const [zone, members] of Object.entries(body.committees))`
/// would crash on null and silently skip on `[]`, both wrong; (b)
/// regression that omits one of the 6 envelope keys when the
/// registry is empty (`#[serde(skip_serializing_if = "BTreeMap::is_empty")]`
/// on `committees` would drop the key, breaking the schema
/// validators); (c) regression that surfaces a non-null `next_from`
/// on empty state (a refactor that emits `next_from = Some("")`
/// instead of None would make accounts paginate infinitely from
/// the empty cursor). The empty-state branch is the most-common
/// fresh-genesis / pre-onboarding production state — every new
/// node hits this path on first boot.
#[tokio::test]
async fn compute_committees_snapshot_empty_registry_emits_canonical_empty_envelope() {
    let state = test_state();
    // Do NOT call seed_committees_state — leave registries empty.

    let body = compute_committees_snapshot(state.clone(), None, None, None, None).await;

    // The 6 envelope keys MUST all be present even in empty state.
    let obj = body.as_object().expect("top-level must be JSON object");
    for key in &[
        "epoch",
        "committee_size",
        "page_size",
        "zone_count",
        "next_from",
        "committees",
    ] {
        assert!(
            obj.contains_key(*key),
            "envelope key '{key}' MUST be present even in empty-registry state",
        );
    }

    assert_eq!(body["zone_count"].as_u64(), Some(0), "zone_count must be 0");
    // committees MUST be an EMPTY JSON Object, NOT null, NOT array.
    let committees = body["committees"]
        .as_object()
        .expect("committees must be JSON Object in empty state (NOT null, NOT array)");
    assert!(
        committees.is_empty(),
        "committees object must be empty when no zones registered",
    );
    assert!(
        body["next_from"].is_null(),
        "next_from MUST be JSON null when no zones to paginate \
             (NOT empty-string, NOT missing key)",
    );
    // Defaults pin — empty registry still emits correct canonical
    // defaults so the account's schema validator passes.
    assert_eq!(body["epoch"].as_u64(), Some(0));
    assert_eq!(
        body["committee_size"].as_u64(),
        Some(crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE as u64),
    );
    assert_eq!(
        body["page_size"].as_u64(),
        Some(crate::network::zone_committee::DEFAULT_COMMITTEES_PAGE_SIZE as u64),
    );
}

// ── compute_consensus_record_detail tests ──
//
// compute_consensus_record_detail at :1270 is the /consensus/record/{id}
// route handler — the critical-path consensus-status lookup that every
// account hits to determine whether a transfer has settled / been
// finalized. Existing coverage is ONE indirect test at
// src/network/pq_transport/router.rs:5937
// (`router_consensus_record_detail_returns_attestation_array`) that
// pins 4 keys on the empty-record path: record_id echo, attestations
// is_array(), confirmation_level is_string(), settlement_threshold
// == "66.67%". That leaves the 15-key envelope shape, the wire-type
// pins on every numeric/boolean field, the is_settled-vs-is_finalized
// independence semantic, the beat precision-string formatting, the
// per-attestation sub-envelope, and the insertion-order semantic ALL
// unpinned. 5 axes orthogonal to the PQ indirect probe AND to each
// other: (i) strict 15-key top-level envelope + wire-type pins;
// (ii) settlement_threshold is the hardcoded "66.67%" string constant
// (NOT a number, NOT recomputed from 2/3); (iii) is_settled (from
// consensus.is_settled_diverse) and is_finalized (from
// state.finalized.contains) are independently sourced — opposite-
// quadrant test plants two records to falsify a "harmonize the two
// booleans" refactor; (iv) total_zone_stake_beat and
// attesting_stake_beat render via format_beat_precise — pin known
// micros values against their canonical beat string form (defends
// against an "always-2-decimal" or "scientific-notation" regression
// breaking beat-display precision); (v) per-attestation 4-key
// envelope {witness_hash, stake, independence, timestamp} +
// wire-type pins + insertion-order preservation (defends against a
// "sort by stake descending for prettier display" refactor that
// would break accounts relying on stable ordering AND against a
// serde-derive refactor on AttestationDetail that would rename fields
// via #[serde(rename)] or skip empty defaults).
//
// Test-fixture pattern: ALL 5 tests use the existing `test_state()`
// helper at :3746. No process-global cache constraint here — consensus
// / finalized / ledger are per-NodeState — so no test gate Mutex
// needed (unlike the EPOCH_HEADERS_CACHE /
// SUPER_SEALS_CACHE tests). Zone assignment is derived via
// `crate::network::consensus::zone_for_record(record_id)` at runtime
// so the tests track the live ZONE_COUNT atomic — pinning to a
// hardcoded `ZoneId::new("test_zone_alpha")` would diverge from
// record-routing under any future zone-split decision.

/// Axis 1 — 15-key top-level envelope is exactly
/// `{record_id, zone, is_settled, is_finalized, confirmation_level,
/// distinct_clusters, trust_score, total_zone_stake,
/// total_zone_stake_beat, attesting_stake, attesting_stake_beat,
/// threshold_pct, settlement_threshold, attestation_count,
/// attestations}` with wire-type pins on every numeric/boolean field.
/// Plants an unknown record_id (no zone_stake, no attestations, NOT
/// in finalized set). Asserts strict BTreeSet symmetric-difference
/// against the canonical key set. Defends against (a) a
/// `serde_json::to_value(&detail_struct)` refactor that would inherit
/// the RecordConsensusDetail serde key set (adding e.g.
/// `creator_stake` or `witness_set_size`) or drop existing keys via
/// `#[serde(skip_serializing_if)]`; (b) a paging-cursor or
/// nested-envelope refactor adding `{"data": {...}, "meta": {...}}`
/// wrapping; (c) silent type changes on `is_settled`/`is_finalized`
/// from JSON Bool to 0/1 integers for "JS-friendly" parsing
/// (existing accounts parse `body.is_settled === true` strictly);
/// (d) `confirmation_level` flipping from String to a numeric enum
/// discriminant (the account UI maps `"pending"`/`"sealed"`/
/// `"finalized"`/`"anchored"` strings to display strings); (e)
/// `settlement_threshold` flipping from String to Number 66.67
/// (loses the % sign + couples accounts to floating-point parse).
#[tokio::test]
async fn batch_ssss_compute_consensus_record_detail_unknown_record_emits_strict_fifteen_key_envelope(
) {
    let state = test_state();
    let v = compute_consensus_record_detail(state, "rec-ssss-axis1-unknown".into()).await;
    let obj = v
        .as_object()
        .expect("compute_consensus_record_detail MUST return a JSON Object");
    // Strict 15-key check via BTreeSet symmetric-difference. Any
    // extra key OR any missing key is a regression vs the
    // hand-coded `serde_json::json!()` envelope at explorer.rs:1299.
    let expected_keys: std::collections::BTreeSet<&str> = [
        "record_id",
        "zone",
        "is_settled",
        "is_finalized",
        "confirmation_level",
        "distinct_clusters",
        "trust_score",
        "total_zone_stake",
        "total_zone_stake_beat",
        "attesting_stake",
        "attesting_stake_beat",
        "threshold_pct",
        "settlement_threshold",
        "attestation_count",
        "attestations",
    ]
    .into_iter()
    .collect();
    let actual_keys: std::collections::BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
    assert_eq!(
        actual_keys,
        expected_keys,
        "compute_consensus_record_detail envelope MUST be EXACTLY \
             15 keys — hand-coded json!() at explorer.rs:1299 freeze. \
             Missing: {:?}, Extra: {:?}",
        expected_keys.difference(&actual_keys).collect::<Vec<_>>(),
        actual_keys.difference(&expected_keys).collect::<Vec<_>>(),
    );
    // Wire-type pins. Each is a defense against a silent shape flip
    // in the json!() macro or a serde refactor.
    assert_eq!(
        obj["record_id"].as_str(),
        Some("rec-ssss-axis1-unknown"),
        "record_id MUST echo back the input as a JSON String",
    );
    assert!(
        obj["zone"].is_string(),
        "zone MUST be JSON String (ZoneId serializes as path)"
    );
    assert_eq!(
        obj["is_settled"].as_bool(),
        Some(false),
        "is_settled MUST be JSON Bool false on unknown-record path \
             (NOT JSON null, NOT integer 0)",
    );
    assert_eq!(
        obj["is_finalized"].as_bool(),
        Some(false),
        "is_finalized MUST be JSON Bool false on unknown-record path",
    );
    assert_eq!(
        obj["confirmation_level"].as_str(),
        Some("pending"),
        "confirmation_level MUST be String \"pending\" on unknown-record \
             path (ConfirmationLevel::Pending.name() — NOT numeric \
             discriminant 0, NOT title-case \"Pending\")",
    );
    assert!(
        obj["distinct_clusters"].is_u64(),
        "distinct_clusters MUST be JSON Number-u64 — accounts strict-parse",
    );
    assert!(
        obj["trust_score"].is_f64() || obj["trust_score"].is_u64(),
        "trust_score MUST be JSON Number (f64 or 0.0 surfaced as 0 by serde_json)",
    );
    assert!(
        obj["total_zone_stake"].is_u64(),
        "total_zone_stake MUST be JSON Number-u64 (raw micros, NOT formatted string)",
    );
    assert!(
        obj["total_zone_stake_beat"].is_string(),
        "total_zone_stake_beat MUST be JSON String (beat precision-formatted, NOT raw micros)",
    );
    assert!(
        obj["attesting_stake"].is_u64(),
        "attesting_stake MUST be JSON Number-u64 (raw micros)",
    );
    assert!(
        obj["attesting_stake_beat"].is_string(),
        "attesting_stake_beat MUST be JSON String (beat precision-formatted)",
    );
    assert!(
        obj["threshold_pct"].is_f64() || obj["threshold_pct"].is_u64(),
        "threshold_pct MUST be JSON Number (0.0 surfaces as 0 on unknown path)",
    );
    assert_eq!(
        obj["settlement_threshold"].as_str(),
        Some("66.67%"),
        "settlement_threshold MUST be the hardcoded String \"66.67%\" \
             — pin reasserted in axis 2 for explicit constant-drift defense",
    );
    assert!(
        obj["attestation_count"].is_u64(),
        "attestation_count MUST be JSON Number-u64",
    );
    assert!(
        obj["attestations"].is_array(),
        "attestations MUST be JSON Array (empty `[]` on unknown record, NOT null)",
    );
}

/// Axis 2 — `settlement_threshold` is the HARDCODED
/// string `"66.67%"` constant, NOT a recomputed
/// `format!("{:.2}%", 2.0/3.0 * 100.0)` (which would emit "66.67%"
/// today but drift to "66.666666666666666%" or "66.67000000000001%"
/// under f64-printing-precision changes). Plants TWO records — one
/// unknown (zero attestations) and one with zone_stake + 2 distinct
/// attestations summing to settlement — and asserts BOTH emit the
/// byte-identical `"66.67%"` string. Defends against (a) a refactor
/// pulling the constant from a `consts::TWO_THIRDS_PCT_STR` that
/// drifts; (b) a refactor turning it into a Number 66.67 (loses %
/// sign, breaks account display); (c) a refactor that adapts the
/// threshold per-zone (e.g., 50%/66.67%/75% based on committee
/// size) — semantically that may be desirable but would NOT
/// surface here without breaking the account schema, so the test
/// forces the change to ALSO update the constant exposure.
#[tokio::test]
async fn batch_ssss_compute_consensus_record_detail_settlement_threshold_is_hardcoded_string_constant(
) {
    let state = test_state();
    // Record A: unknown, zero state.
    let v_a = compute_consensus_record_detail(state.clone(), "rec-ssss-axis2-empty".into()).await;
    // Record B: planted with zone_stake + 2 attestations.
    let rec_b = "rec-ssss-axis2-loaded";
    let zone_b = crate::network::consensus::zone_for_record(rec_b);
    {
        let mut consensus = state.consensus.lock_recover();
        consensus.register_zone_stake(zone_b, 1_500);
        consensus.add_attestation(crate::network::consensus::Attestation {
            record_id: rec_b.into(),
            witness_hash: "w-ssss-axis2-alpha".into(),
            stake: 500,
            timestamp: 1700000000.0,
        });
        consensus.add_attestation(crate::network::consensus::Attestation {
            record_id: rec_b.into(),
            witness_hash: "w-ssss-axis2-beta".into(),
            stake: 600,
            timestamp: 1700000001.0,
        });
    }
    let v_b = compute_consensus_record_detail(state, rec_b.into()).await;
    // Both records MUST emit the byte-identical "66.67%" string.
    assert_eq!(
        v_a["settlement_threshold"].as_str(),
        Some("66.67%"),
        "settlement_threshold MUST be \"66.67%\" on empty-state path",
    );
    assert_eq!(
        v_b["settlement_threshold"].as_str(),
        Some("66.67%"),
        "settlement_threshold MUST be \"66.67%\" on loaded-state path \
             — value MUST NOT vary with attestation count or zone_stake",
    );
    // Cross-axis byte-identity. If a refactor introduces a per-zone
    // adaptive threshold, the two records (one in default zone, one
    // in zone_for_record(rec_b)) would emit DIFFERENT strings — the
    // test would fail here.
    assert_eq!(
        v_a["settlement_threshold"].as_str(),
        v_b["settlement_threshold"].as_str(),
        "settlement_threshold MUST be the SAME byte-identical string \
             across all records — defends against a per-zone adaptive \
             threshold refactor that would silently fork the account UX",
    );
}

/// Axis 3 — `is_settled` (from `consensus.is_settled_diverse`
/// at consensus.rs:2204) and `is_finalized` (from
/// `state.finalized.read().contains` at explorer.rs:1279) are
/// independently sourced. Plants opposite-quadrant test records to
/// falsify a "harmonize the two booleans" refactor:
///   - Record-A: zone_stake registered + 2 attestations summing to
///     2/3 of eligible stake → `is_settled = true`. Record-A is NOT
///     in state.finalized → `is_finalized = false`.
///   - Record-B: ZERO zone_stake, ZERO attestations → `is_settled =
///     false`. Record-B IS inserted into state.finalized →
///     `is_finalized = true`.
/// Defends against (a) a "single-flag" refactor returning
/// `is_settled` from the finalized-set check (Record-A would then
/// flip to false on the wire); (b) the inverse refactor reading
/// `is_finalized` from `consensus.is_settled_diverse` (Record-B
/// would then flip to false); (c) a wire-renaming swap that
/// transposes the two field names (both records would test-fail).
/// The two booleans encode distinct lifecycle phases per Protocol
/// §7.5: `is_settled` = local 2/3 attestation threshold met;
/// `is_finalized` = record appears in the cross-zone finalized
/// index (epoch-anchored, observed by sealing).
#[tokio::test]
async fn batch_ssss_compute_consensus_record_detail_is_settled_and_is_finalized_are_independently_sourced(
) {
    let state = test_state();
    // ── Record-A: settled=true via consensus stake math, finalized=false.
    let rec_a = "rec-ssss-axis3-settled-not-finalized";
    let zone_a = crate::network::consensus::zone_for_record(rec_a);
    {
        let mut consensus = state.consensus.lock_recover();
        // eligible = 1500 (no creator_stake). 2 attestations at 500 +
        // 600 stake = 1100 attesting. 1100 * 3 = 3300 >= 1500 * 2 =
        // 3000 ✓ — passes is_settled threshold. With no profiles /
        // derived_geo registered, gamma_effective = 0 → independence
        // = 1.0 for both witnesses → effective_stake = 1100 →
        // is_settled_diverse also passes.
        consensus.register_zone_stake(zone_a, 1_500);
        consensus.add_attestation(crate::network::consensus::Attestation {
            record_id: rec_a.into(),
            witness_hash: "w-ssss-axis3-a-alpha".into(),
            stake: 500,
            timestamp: 1700000000.0,
        });
        consensus.add_attestation(crate::network::consensus::Attestation {
            record_id: rec_a.into(),
            witness_hash: "w-ssss-axis3-a-beta".into(),
            stake: 600,
            timestamp: 1700000001.0,
        });
    }
    // NOTE: Do NOT insert rec_a into state.finalized.
    let v_a = compute_consensus_record_detail(state.clone(), rec_a.into()).await;
    assert_eq!(
        v_a["is_settled"].as_bool(),
        Some(true),
        "Record-A MUST surface is_settled=true (consensus 2/3 threshold met)",
    );
    assert_eq!(
        v_a["is_finalized"].as_bool(),
        Some(false),
        "Record-A MUST surface is_finalized=false (NOT inserted into \
             state.finalized) — falsifies a refactor that derives \
             is_finalized from is_settled",
    );

    // ── Record-B: settled=false (no stake, no attestations),
    // finalized=true (inserted into state.finalized).
    let rec_b = "rec-ssss-axis3-finalized-not-settled";
    {
        let mut fin = state.finalized.write().await;
        fin.insert(rec_b.into());
    }
    let v_b = compute_consensus_record_detail(state, rec_b.into()).await;
    assert_eq!(
        v_b["is_settled"].as_bool(),
        Some(false),
        "Record-B MUST surface is_settled=false (no zone_stake, no \
             attestations) — falsifies a refactor that derives is_settled \
             from is_finalized",
    );
    assert_eq!(
        v_b["is_finalized"].as_bool(),
        Some(true),
        "Record-B MUST surface is_finalized=true (state.finalized.contains)",
    );
}

/// Axis 4 — `total_zone_stake_beat` and
/// `attesting_stake_beat` render via `format_beat_precise` (NOT a
/// `format!("{:.2}", micros as f64 / 1e9)` "always-2-decimal"
/// shortcut, NOT scientific notation, NOT raw micros). Plants
/// zone_stake = 12_345_000_000 micros (canonical "12.345" — 12
/// whole beat + 345_000_000 frac trimmed of trailing zeros) and one
/// attestation of stake = 1_000_000_000 micros (canonical "1.0" —
/// zero-frac shortcut path). Pins the exact canonical strings to
/// defend against (a) f64-precision-loss in a `as f64 / 1e9`
/// rewrite that would emit "12.344999999" instead of "12.345";
/// (b) loss of the zero-frac shortcut at micros == N×BASE_UNITS_PER_BEAT
/// (the explicit `if frac == 0 { format!("{whole}.0") }` branch at
/// validate.rs:866 — without it, "1.0" would become "1." which
/// breaks Decimal.js parsing); (c) a refactor moving to scientific
/// notation for large stakes (e.g. "1.234e10") which most account
/// big-number libraries can't parse; (d) byte-identity check —
/// total_zone_stake (u64) and total_zone_stake_beat (formatted
/// String) MUST encode the SAME amount, so the test asserts both
/// fields explicitly to catch a refactor that decouples them.
#[tokio::test]
async fn batch_ssss_compute_consensus_record_detail_beat_precision_strings_via_format_beat_precise()
{
    let state = test_state();
    let rec = "rec-ssss-axis4-beat-precision";
    let zone = crate::network::consensus::zone_for_record(rec);
    {
        let mut consensus = state.consensus.lock_recover();
        // 12.345 beat = 12_345_000_000 micros. After trimming
        // trailing zeros, format_beat_precise emits "12.345".
        consensus.register_zone_stake(zone, 12_345_000_000);
        // 1.0 beat = 1_000_000_000 micros. Hits the explicit
        // zero-frac shortcut path → "1.0".
        consensus.add_attestation(crate::network::consensus::Attestation {
            record_id: rec.into(),
            witness_hash: "w-ssss-axis4-alpha".into(),
            stake: 1_000_000_000,
            timestamp: 1700000000.0,
        });
    }
    let v = compute_consensus_record_detail(state, rec.into()).await;
    // Raw micros pins. These defend the u64 wire type and value
    // identity.
    assert_eq!(
        v["total_zone_stake"].as_u64(),
        Some(12_345_000_000),
        "total_zone_stake MUST equal the registered raw micros u64",
    );
    assert_eq!(
        v["attesting_stake"].as_u64(),
        Some(1_000_000_000),
        "attesting_stake MUST equal the attestation's raw micros u64",
    );
    // Canonical beat-formatted-string pins. These defend
    // format_beat_precise contract at validate.rs:863.
    assert_eq!(
        v["total_zone_stake_beat"].as_str(),
        Some("12.345"),
        "total_zone_stake_beat MUST be exactly \"12.345\" via \
             format_beat_precise — defends against f64 / 1e9 precision \
             loss, scientific notation, or always-2-decimal shortcuts",
    );
    assert_eq!(
        v["attesting_stake_beat"].as_str(),
        Some("1.0"),
        "attesting_stake_beat MUST be exactly \"1.0\" — defends the \
             explicit zero-frac shortcut branch at validate.rs:866 — \
             without it the result would be \"1.\" which breaks \
             Decimal.js parsing",
    );
}

/// Axis 5 — per-attestation 4-key envelope is exactly
/// `{witness_hash, stake, independence, timestamp}` with wire-type
/// pins AND attestations array preserves insertion order (NOT
/// sorted by stake / witness_hash / timestamp). Plants 2
/// attestations inserted in a NON-sort-stable order (alpha first
/// with HIGHER timestamp, beta second with LOWER timestamp) and
/// asserts: (i) attestation_count == attestations.len() == 2 —
/// cross-axis count invariant; (ii) attestations[0].witness_hash
/// == "w-ssss-axis5-alpha" (first inserted, NOT lexicographically
/// first OR timestamp-ascending first); (iii) each element is a
/// 4-key JSON object via BTreeSet symmetric-difference; (iv) wire
/// types match the JSON contract; (v) independence is a JSON
/// Number (the explorer.rs:1288 `(a.independence * 10000.0).round()
/// / 10000.0` rounding leaves the value as Number — pin defends
/// against a refactor that emits a string like `"1.0000"` for
/// "consistent display"). Defends against (a) a sort-by-stake
/// refactor (attestations[0].stake > attestations[1].stake would
/// reorder our test set since alpha=400 < beta=700); (b) a sort-
/// by-timestamp refactor (alpha.timestamp > beta.timestamp); (c)
/// a serde-derive on AttestationDetail with #[serde(rename)] or
/// skip_if regressions adding/dropping keys.
#[tokio::test]
async fn batch_ssss_compute_consensus_record_detail_per_attestation_envelope_preserves_insertion_order(
) {
    let state = test_state();
    let rec = "rec-ssss-axis5-per-attestation";
    let zone = crate::network::consensus::zone_for_record(rec);
    {
        let mut consensus = state.consensus.lock_recover();
        consensus.register_zone_stake(zone, 10_000);
        // alpha inserted FIRST with HIGHER timestamp + LOWER stake.
        // beta inserted SECOND with LOWER timestamp + HIGHER stake.
        // This insertion order is NON-stable under all three
        // candidate sort-key regressions (stake, timestamp,
        // witness_hash).
        consensus.add_attestation(crate::network::consensus::Attestation {
            record_id: rec.into(),
            witness_hash: "w-ssss-axis5-alpha".into(),
            stake: 400,
            timestamp: 1700000999.0,
        });
        consensus.add_attestation(crate::network::consensus::Attestation {
            record_id: rec.into(),
            witness_hash: "w-ssss-axis5-beta".into(),
            stake: 700,
            timestamp: 1700000100.0,
        });
    }
    let v = compute_consensus_record_detail(state, rec.into()).await;
    let attestations = v["attestations"]
        .as_array()
        .expect("attestations MUST be JSON Array");
    // Cross-axis count invariant — attestation_count == array length.
    assert_eq!(
        v["attestation_count"].as_u64(),
        Some(2),
        "attestation_count MUST equal the planted attestation count",
    );
    assert_eq!(
        attestations.len(),
        2,
        "attestations array length MUST match attestation_count — \
             cross-axis invariant defends against a refactor that filters \
             the array but not the count",
    );
    // Insertion order pin: alpha first (HIGHER timestamp + LOWER
    // stake), beta second. Falsifies any sort-by-X refactor.
    assert_eq!(
        attestations[0]["witness_hash"].as_str(),
        Some("w-ssss-axis5-alpha"),
        "attestations[0].witness_hash MUST be the FIRST inserted \
             ('w-ssss-axis5-alpha'), NOT the lexicographically-first OR \
             timestamp-ascending-first OR stake-descending-first witness — \
             insertion order is the wire contract",
    );
    assert_eq!(
        attestations[1]["witness_hash"].as_str(),
        Some("w-ssss-axis5-beta"),
        "attestations[1].witness_hash MUST be the SECOND inserted \
             ('w-ssss-axis5-beta')",
    );
    // Per-element strict 4-key envelope via BTreeSet symmetric
    // difference.
    let expected_keys: std::collections::BTreeSet<&str> =
        ["witness_hash", "stake", "independence", "timestamp"]
            .into_iter()
            .collect();
    for (i, elem) in attestations.iter().enumerate() {
        let obj = elem
            .as_object()
            .expect("attestation element MUST be JSON Object");
        let actual_keys: std::collections::BTreeSet<&str> =
            obj.keys().map(|s| s.as_str()).collect();
        assert_eq!(
            actual_keys,
            expected_keys,
            "attestations[{i}] envelope MUST be EXACTLY 4 keys — \
                 hand-coded json!() at explorer.rs:1285 freeze. \
                 Missing: {:?}, Extra: {:?}",
            expected_keys.difference(&actual_keys).collect::<Vec<_>>(),
            actual_keys.difference(&expected_keys).collect::<Vec<_>>(),
        );
        // Wire-type pins per element.
        assert!(
            obj["witness_hash"].is_string(),
            "attestations[{i}].witness_hash MUST be JSON String",
        );
        assert!(
            obj["stake"].is_u64(),
            "attestations[{i}].stake MUST be JSON Number-u64 (raw micros)",
        );
        assert!(
            obj["independence"].is_f64() || obj["independence"].is_u64(),
            "attestations[{i}].independence MUST be JSON Number (NOT \
                 String like \"1.0000\" — defends a stringification regression \
                 for 'consistent display'); 4-decimal rounding lives in \
                 explorer.rs:1288",
        );
        assert!(
            obj["timestamp"].is_f64(),
            "attestations[{i}].timestamp MUST be JSON Number-f64 \
                 (Unix-epoch seconds with sub-second precision)",
        );
    }
    // Cross-axis stake echo: insertion-order pin + planted values.
    assert_eq!(
        attestations[0]["stake"].as_u64(),
        Some(400),
        "attestations[0].stake MUST be the alpha-witness stake (400)",
    );
    assert_eq!(
        attestations[1]["stake"].as_u64(),
        Some(700),
        "attestations[1].stake MUST be the beta-witness stake (700)",
    );
}

#[tokio::test]
async fn record_by_hash_lookup_is_case_insensitive() {
    let state = test_state();
    let hash = [0xAB; 32];
    let rec = record_with_hash("rec-mixed", hash);
    state.rocks.put_record(&rec.id, &rec).expect("put");

    // Account may send the hash uppercase even though we store
    // lowercase; the route normalizes input before the index probe.
    let upper = hex::encode(hash).to_ascii_uppercase();
    let body = compute_record_by_hash(state.clone(), upper)
        .await
        .expect("uppercase must resolve")
        .expect("uppercase must produce Some");
    assert_eq!(body["id"].as_str(), Some("rec-mixed"));
}

// ── serialize_transfer JSON-shape contract ─────────────────────────────
//
// `serialize_transfer` is the stateless renderer behind
// `/xzone/transfers` and `/xzone/transfer/{id}`. Wallets and explorers
// parse a fixed JSON schema against it: a typo'd status string, a
// missing `has_proof` bit, or a renamed field would break the account
// claim flow at runtime. These tests pin the public surface so a
// refactor catches the contract drift here, not on a user device.

fn stub_pending_transfer(
    status: crate::accounting::cross_zone::TransferStatus,
) -> crate::accounting::cross_zone::PendingTransfer {
    crate::accounting::cross_zone::PendingTransfer {
        transfer_id: "lock-record-001".to_string(),
        sender: "sender-id-hex".to_string(),
        recipient: "recipient-id-hex".to_string(),
        amount: 1_000_000,
        source_zone: ZoneId::new("0"),
        dest_zone: ZoneId::new("1"),
        locked_at: 1_700_000_000.0,
        expires_at: 1_700_086_400.0,
        status,
        merkle_proof: Vec::new(),
        lock_record_hash: [0xAA; 32],
        source_merkle_root: [0xBB; 32],
        source_seal_signers: Vec::new(),
        source_committee_hash: [0u8; 32],
        source_seal_epoch: 0,
        source_committee_size: 0,
        dest_finality_committee: None,
        claim_record_id: None,
    }
}

#[test]
fn serialize_transfer_status_mapping_is_exhaustive_and_lowercase() {
    use crate::accounting::cross_zone::TransferStatus;
    // Every TransferStatus variant must serialize to a stable lowercase
    // string that accounts switch on. A label drift (Locked → "Locked")
    // silently mis-routes the account's pending/claimed/refunded UI.
    let cases = [
        (TransferStatus::Locked, "locked"),
        (TransferStatus::Claimed, "claimed"),
        (TransferStatus::Refunded, "refunded"),
        (TransferStatus::Aborted, "aborted"),
    ];
    for (variant, expected) in cases {
        let t = stub_pending_transfer(variant);
        let out = serialize_transfer(&t);
        assert_eq!(
            out["status"].as_str(),
            Some(expected),
            "TransferStatus serialization drift for {expected}",
        );
    }
}

#[test]
fn serialize_transfer_has_proof_reflects_merkle_proof_presence() {
    use crate::accounting::cross_zone::{ProofSibling, TransferStatus};
    // `has_proof: false` is the account's signal that a claim will be
    // rejected (M7 fix in cross_zone.rs). The bit must flip the moment
    // a sibling is appended so accounts don't render a "ready to claim"
    // CTA on a not-yet-sealed transfer.
    let mut t = stub_pending_transfer(TransferStatus::Locked);
    assert_eq!(
        serialize_transfer(&t)["has_proof"].as_bool(),
        Some(false),
        "empty merkle_proof must render has_proof=false",
    );

    t.merkle_proof.push(ProofSibling {
        hash: [0xCC; 32],
        is_right: true,
    });
    assert_eq!(
        serialize_transfer(&t)["has_proof"].as_bool(),
        Some(true),
        "non-empty merkle_proof must render has_proof=true",
    );
}

#[test]
fn serialize_transfer_renders_required_top_level_fields() {
    use crate::accounting::cross_zone::TransferStatus;
    // Wallets deserialize a fixed schema. A rename or removal of any
    // top-level key here is an outage on the account side; pin the
    // contract explicitly. Hex-encoded 32-byte arrays must produce
    // 64-char strings.
    let t = stub_pending_transfer(TransferStatus::Claimed);
    let out = serialize_transfer(&t);

    for k in [
        "transfer_id",
        "sender",
        "recipient",
        "amount",
        "source_zone",
        "dest_zone",
        "locked_at",
        "expires_at",
        "status",
        "has_proof",
        "lock_record_hash",
        "source_merkle_root",
        "claim_record_id",
    ] {
        assert!(
            out.get(k).is_some(),
            "missing top-level key `{k}` in serialize_transfer output",
        );
    }
    assert_eq!(out["amount"].as_u64(), Some(1_000_000));
    assert_eq!(out["source_zone"].as_str(), Some("0"));
    assert_eq!(out["dest_zone"].as_str(), Some("1"));
    assert_eq!(out["lock_record_hash"].as_str().map(str::len), Some(64));
    assert_eq!(out["source_merkle_root"].as_str().map(str::len), Some(64));
}

// ─── /validate_address/{address} format gate ─────────────────────────────
//
// Account integrations call this before ANY balance/transfer flow — bad
// formats must return `valid_format: false` without touching the ledger,
// valid-but-unseen hashes must return `valid_format: true, exists: false`.
// The branching at `compute_validate_address` (line 822) is the only gate
// protecting `ledger.accounts.contains_key` from arbitrary user input.

#[tokio::test]
async fn compute_validate_address_rejects_wrong_length() {
    let state = test_state();
    // 32-hex address (half the expected length) — must short-circuit and
    // NEVER acquire the ledger read lock.
    let short = "a".repeat(32);
    let out = compute_validate_address(state.clone(), short.clone()).await;
    assert_eq!(out["valid_format"], serde_json::Value::Bool(false));
    assert_eq!(out["exists"], serde_json::Value::Bool(false));
    assert_eq!(out["address"], serde_json::Value::String(short));
    assert_eq!(
        out["format"],
        serde_json::Value::String("sha3-256-hex".into())
    );
}

#[tokio::test]
async fn compute_validate_address_rejects_non_hex_chars() {
    let state = test_state();
    // 64-char string with a non-hex character at the end — passes length
    // gate but fails the `is_ascii_hexdigit` filter. Pins the early-out
    // boolean AND: a regression that drops one side of `&&` would expose
    // the ledger read to malformed input.
    let bad = format!("{}{}", "a".repeat(63), "z");
    let out = compute_validate_address(state, bad.clone()).await;
    assert_eq!(out["valid_format"], serde_json::Value::Bool(false));
    assert_eq!(out["exists"], serde_json::Value::Bool(false));
    assert_eq!(out["address"], serde_json::Value::String(bad));
}

#[tokio::test]
async fn compute_validate_address_valid_hex_not_in_ledger() {
    let state = test_state();
    // 64-char all-hex address but no account in the (empty) ledger:
    // valid_format=true, exists=false. The path that accounts hit when
    // they pre-check a recipient address before sending beat.
    let addr = "abcd1234".repeat(8);
    assert_eq!(addr.len(), 64);
    let out = compute_validate_address(state, addr.clone()).await;
    assert_eq!(out["valid_format"], serde_json::Value::Bool(true));
    assert_eq!(out["exists"], serde_json::Value::Bool(false));
    assert_eq!(out["address"], serde_json::Value::String(addr));
}

// ─── /identity/pk/{hash} soft-fail contract ──────────────────────────────
//
// Identity Partitioning Phase D — `compute_identity_pk` MUST return
// `pk: null, tier: null` for unseen hashes (NOT a 404, NOT an error).
// Callers in `network::identity_fetcher` rely on the soft-fail to fall
// through to the next peer per internal design notes §6.

#[tokio::test]
async fn compute_identity_pk_unknown_hash_returns_nulls() {
    let state = test_state();
    let hash = "f".repeat(64);
    let out = compute_identity_pk(state, hash.clone()).await;
    assert_eq!(out["identity_hash"], serde_json::Value::String(hash));
    assert!(
        out["pk"].is_null(),
        "pk must be null for unseen hash, got {}",
        out["pk"]
    );
    assert!(
        out["tier"].is_null(),
        "tier must be null for unseen hash, got {}",
        out["tier"]
    );
}

// ─── Gap-1 light-client header-sync E2E ─────────────────────────
//
// Confirms a
// light node bootstraps + verifies an account balance proof against a
// full node's /proof/account/{identity} without ever downloading records.
//
// These tests exercise the full Gap-1 cryptographic chain in-process:
//   1. Seed an account in the ledger.
//   2. Flush the on-disk account-state SMT (mimics seal-emission tree write).
//   3. Synthesize an EpochHeader anchored to the flushed root (what
//      /headers/from/{epoch} returns over the wire).
//   4. Call `compute_account_proof` (the in-process equivalent of
//      GET /proof/account/{identity}) — the same function the axum
//      handler wraps, so the JSON shape and proof construction are
//      byte-identical to the production HTTP path.
//   5. Parse the response back into typed SDK values (`AccountStateProof`,
//      `AccountState`) — exercises the wire contract a real account uses.
//   6. Run `verify_account_proof_against_header` — the Gap-1 SDK helper
//      that binds the proof to the signed seal root.
//   7. Assert the claimed AccountState hashes to `proof.state_hash`
//      (defends against a malicious node returning a fabricated balance
//      alongside a real proof).
//
// The test never touches CF_RECORDS or /records/* — proving a light client
// can derive a verified balance from header + proof alone, which is the
// contract Gap 1 of the MAINNET MANDATE 8-gap list promises.

fn light_client_test_account() -> (String, crate::accounting::ledger::AccountState) {
    let identity_hash = "ab".repeat(32); // 64-hex = 32-byte SHA3 identity
    let acct = crate::accounting::ledger::AccountState {
        available: 1_500_000_000, // 1.5 beat in base units (10^9/beat)
        staked: 500_000_000,
        total_received: 2_000_000_000,
        total_sent: 0,
        tx_count: 5,
        last_active: 1_700_000_000.0,
        vested_locked: 0,
        uptime_secs: 86_400,
        inactive_days: 0,
        witness_bonded: 0,
    };
    (identity_hash, acct)
}

fn parse_proof_from_response(
    response: &serde_json::Value,
    account_id: [u8; 32],
) -> crate::network::account_merkle::AccountStateProof {
    // Canonical compressed wire parse; override account_id with the caller's
    // expected identity (tests assert against a known account).
    let mut proof = crate::network::account_merkle::parse_wire_proof(response)
        .expect("parse compressed account proof");
    proof.account_id = account_id;
    proof
}

#[tokio::test]
async fn light_client_e2e_verifies_balance_against_header_proof_only() {
    use crate::network::account_merkle::{hash_account_state, AccountStateSMT};
    use crate::network::light::{verify_account_proof_against_header, EpochHeader};

    let state = test_state();
    let (identity_hash, seeded) = light_client_test_account();

    // 1. Seed the ledger.
    {
        let mut ledger = state.ledger.write().await;
        ledger
            .accounts
            .insert(identity_hash.clone(), seeded.clone());
    }

    // 2. Flush the SMT so the on-disk root reflects the seeded leaf —
    //    this is what apply_snapshot does at seal emission. We bypass
    //    the full seal-emission path (witnesses, attestations, consensus)
    //    because Gap-1 verification operates strictly on (header, proof);
    //    everything else is upstream of the light-client contract.
    let mut account_id = [0u8; 32];
    account_id.copy_from_slice(&hex::decode(&identity_hash).unwrap());
    let leaf_hash = hash_account_state(&seeded);
    {
        let mut tree = AccountStateSMT::new(&state.rocks);
        tree.update(&account_id, &leaf_hash).expect("smt update");
        tree.commit().expect("smt commit");
    }
    let sealed_root = AccountStateSMT::new(&state.rocks)
        .root()
        .expect("read sealed root");

    // 3. Synthesize the header a light client would receive from
    //    /headers/from/{epoch}.
    let header = EpochHeader {
        zone: crate::ZoneId::from_legacy(0),
        epoch_number: 1,
        merkle_root: [0u8; 32],
        previous_seal_hash: [0u8; 32],
        record_count: 0,
        start: 1_700_000_000.0,
        end: 1_700_000_060.0,
        account_smt_root: Some(sealed_root),
        seal_record_hash: Some([0xAB; 32]),
    };

    // 4. Light-client side: call the same compute_* the HTTP route wraps.
    let response = compute_account_proof(state.clone(), identity_hash.clone())
        .await
        .expect("compute_account_proof");

    // Sanity on the wire shape — server must report the account exists.
    assert_eq!(response["exists"].as_bool(), Some(true));
    assert_eq!(response["identity"].as_str(), Some(identity_hash.as_str()));

    // 5. Parse SDK-typed values from the JSON response.
    let proof = parse_proof_from_response(&response, account_id);
    let claimed: crate::accounting::ledger::AccountState =
        serde_json::from_value(response["account_state"].clone()).expect("parse account_state");

    // 6. Header-bound proof must verify under the signed account_smt_root.
    //    This is what a account calls after receiving (header, proof) over
    //    HTTP — passing this means the server cannot have fabricated a
    //    balance: the proof.root matches the signed seal root, and the
    //    siblings reconstruct that root from proof.state_hash.
    assert!(
        verify_account_proof_against_header(&proof, &header),
        "header-bound proof must verify under signed account_smt_root"
    );

    // 7. claimed AccountState must hash to proof.state_hash. Without this
    //    check, a malicious server could return a real proof for state H
    //    but a fabricated AccountState that doesn't hash to H — the account
    //    UI would display the wrong balance even though the proof verified.
    assert_eq!(
        hash_account_state(&claimed),
        proof.state_hash,
        "claimed account_state must hash to proof.state_hash"
    );

    // 8. Verified balance roundtrip — proves the light client derived
    //    the correct AccountState using only (header, proof). No
    //    /records/* call was needed.
    assert_eq!(claimed.available, seeded.available);
    assert_eq!(claimed.staked, seeded.staked);
    assert_eq!(claimed.tx_count, seeded.tx_count);
}

#[tokio::test]
async fn light_client_e2e_tampered_header_root_rejected() {
    // Negative path: if a (malicious or stale) full node returns a header
    // whose account_smt_root doesn't match the proof's root, the SDK
    // helper MUST reject. Otherwise a node could splice a real proof from
    // epoch N into a fabricated header for epoch N+1 to mislead light
    // clients about latest balance.
    use crate::network::account_merkle::{hash_account_state, AccountStateSMT};
    use crate::network::light::{verify_account_proof_against_header, EpochHeader};

    let state = test_state();
    let (identity_hash, seeded) = light_client_test_account();
    {
        let mut ledger = state.ledger.write().await;
        ledger
            .accounts
            .insert(identity_hash.clone(), seeded.clone());
    }
    let mut account_id = [0u8; 32];
    account_id.copy_from_slice(&hex::decode(&identity_hash).unwrap());
    let leaf_hash = hash_account_state(&seeded);
    {
        let mut tree = AccountStateSMT::new(&state.rocks);
        tree.update(&account_id, &leaf_hash).expect("smt update");
        tree.commit().expect("smt commit");
    }

    let response = compute_account_proof(state.clone(), identity_hash.clone())
        .await
        .expect("compute_account_proof");
    let proof = parse_proof_from_response(&response, account_id);

    // Tampered header: account_smt_root is a wrong root (flipped first byte).
    let mut tampered_root = proof.root;
    tampered_root[0] ^= 0xFF;
    let tampered_header = EpochHeader {
        zone: crate::ZoneId::from_legacy(0),
        epoch_number: 1,
        merkle_root: [0u8; 32],
        previous_seal_hash: [0u8; 32],
        record_count: 0,
        start: 1_700_000_000.0,
        end: 1_700_000_060.0,
        account_smt_root: Some(tampered_root),
        seal_record_hash: Some([0xAB; 32]),
    };

    assert!(
        !verify_account_proof_against_header(&proof, &tampered_header),
        "proof with root mismatching signed header root MUST be rejected"
    );
}

#[tokio::test]
async fn light_client_e2e_pre_gap1_header_rejected() {
    // Defense in depth: pre-Gap-1 seals don't carry account_smt_root
    // (the field is `None`). A light client receiving such a header MUST
    // refuse to verify any account proof against it — otherwise a node
    // running the old version could trick a fresh account into accepting
    // an unbound balance.
    use crate::network::account_merkle::{hash_account_state, AccountStateSMT};
    use crate::network::light::{verify_account_proof_against_header, EpochHeader};

    let state = test_state();
    let (identity_hash, seeded) = light_client_test_account();
    {
        let mut ledger = state.ledger.write().await;
        ledger
            .accounts
            .insert(identity_hash.clone(), seeded.clone());
    }
    let mut account_id = [0u8; 32];
    account_id.copy_from_slice(&hex::decode(&identity_hash).unwrap());
    let leaf_hash = hash_account_state(&seeded);
    {
        let mut tree = AccountStateSMT::new(&state.rocks);
        tree.update(&account_id, &leaf_hash).expect("smt update");
        tree.commit().expect("smt commit");
    }
    let response = compute_account_proof(state.clone(), identity_hash.clone())
        .await
        .expect("compute_account_proof");
    let proof = parse_proof_from_response(&response, account_id);

    // Legacy header — account_smt_root: None (pre-Gap-1 era).
    let legacy_header = EpochHeader {
        zone: crate::ZoneId::from_legacy(0),
        epoch_number: 1,
        merkle_root: [0u8; 32],
        previous_seal_hash: [0u8; 32],
        record_count: 0,
        start: 1_700_000_000.0,
        end: 1_700_000_060.0,
        account_smt_root: None,
        seal_record_hash: Some([0xAB; 32]),
    };

    assert!(
        !verify_account_proof_against_header(&proof, &legacy_header),
        "pre-Gap-1 header (account_smt_root=None) MUST not bind any proof"
    );
}

// ─── compute_* helper wire-shape pins ──
// Pivot from gossip.rs (all 5 sync helpers covered there) to
// explorer.rs.
// Three sync `compute_*` helpers are pinned here — each is the
// production-active source of explorer/account JSON the axum wrappers
// serve verbatim. Empty-state contracts are the most-likely-to-regress
// shape: a key rename or atomic reset in NodeState would silently break
// every account polling these endpoints.

#[test]
fn batch_l_compute_itc_status_fresh_state_returns_zero_events_and_joins() {
    let state = test_state();
    let v = compute_itc_status(state);
    assert!(v.get("itc").is_some(), "missing `itc` field");
    assert_eq!(
        v.get("events_total").and_then(|x| x.as_u64()),
        Some(0),
        "fresh state must report 0 itc_events_total",
    );
    assert_eq!(
        v.get("joins_total").and_then(|x| x.as_u64()),
        Some(0),
        "fresh state must report 0 itc_joins_total",
    );
}

#[test]
fn batch_l_compute_list_disputes_fresh_state_returns_zero_total_and_empty_array() {
    let state = test_state();
    let v = compute_list_disputes(state, None);
    assert_eq!(
        v.get("total").and_then(|x| x.as_u64()),
        Some(0),
        "fresh state must report 0 disputes total",
    );
    assert_eq!(
        v.get("disputes_opened_total").and_then(|x| x.as_u64()),
        Some(0),
        "fresh state must report 0 disputes_opened_total counter",
    );
    let arr = v
        .get("disputes")
        .and_then(|x| x.as_array())
        .expect("disputes field must be a JSON array");
    assert!(arr.is_empty(), "fresh-state disputes array must be empty");
}

#[test]
fn batch_l_compute_list_challenges_fresh_state_returns_zero_total_and_empty_array() {
    let state = test_state();
    let v = compute_list_challenges(state, None, None);
    assert_eq!(
        v.get("total").and_then(|x| x.as_u64()),
        Some(0),
        "fresh state must report 0 challenges total",
    );
    assert_eq!(
        v.get("filed_total").and_then(|x| x.as_u64()),
        Some(0),
        "fresh state must report 0 challenges_filed_total counter",
    );
    let arr = v
        .get("challenges")
        .and_then(|x| x.as_array())
        .expect("challenges field must be a JSON array");
    assert!(arr.is_empty(), "fresh-state challenges array must be empty");
}

// ─── compute_* helper wire-shape pins (continued) ──
// Three more sync `compute_*` helpers pinned. Each is the production
// source of explorer/account JSON the axum wrappers serve verbatim,
// and the empty-state contracts here lock in invariants that are
// not obvious from the call shape alone (the 0.8 unknown-profile
// correlation default IS the AUDIT-9 non-disclosure penalty; the
// 50.0/0.5 reputation default IS the new-witness baseline).

#[test]
fn batch_m_compute_witness_correlation_fresh_state_emits_default_correlation_without_profiles() {
    // Fresh consensus has zero registered profiles → unknown pair hits
    // the ALPHA+BETA=0.8 conservative-default branch at consensus.rs:2293.
    // This pins the AUDIT-9 non-disclosure penalty (sybils that skip
    // register_profile cannot diversity-settle records even with full
    // raw stake) — a regression that lowered 0.8 would silently re-open
    // the sybil window.
    let state = test_state();
    let v = compute_witness_correlation(state, "wA".into(), "wB".into());
    assert_eq!(v.get("witness_a").and_then(|x| x.as_str()), Some("wA"));
    assert_eq!(v.get("witness_b").and_then(|x| x.as_str()), Some("wB"));
    assert_eq!(
        v.get("correlation").and_then(|x| x.as_f64()),
        Some(0.8),
        "unknown-profile correlation must be ALPHA+BETA=0.8 (AUDIT-9)",
    );
    assert!(
        v.get("profile_a").is_none(),
        "no profile_a for unknown witness"
    );
    assert!(
        v.get("profile_b").is_none(),
        "no profile_b for unknown witness"
    );
}

#[test]
fn batch_m_compute_witness_reputation_unknown_witness_returns_default_with_note() {
    // Unknown witness in fresh reputation table → default-baseline
    // branch at explorer.rs:1473-1483. Score 50.0, trust 0.5, positive=0,
    // negative=0, last_event=null, note present. Wallets render this
    // exactly — a key rename here breaks every reputation view.
    let state = test_state();
    let v = compute_witness_reputation(state, Some("unknown_witness_hex".into()), None);
    assert_eq!(
        v.get("witness_hash").and_then(|x| x.as_str()),
        Some("unknown_witness_hex")
    );
    assert_eq!(v.get("score").and_then(|x| x.as_f64()), Some(50.0));
    assert_eq!(v.get("score_decayed").and_then(|x| x.as_f64()), Some(50.0));
    assert_eq!(
        v.get("trust_multiplier").and_then(|x| x.as_f64()),
        Some(0.5)
    );
    assert_eq!(v.get("positive_events").and_then(|x| x.as_u64()), Some(0));
    assert_eq!(v.get("negative_events").and_then(|x| x.as_u64()), Some(0));
    assert!(
        v.get("last_event").is_some_and(|x| x.is_null()),
        "last_event must be JSON null for never-seen witness",
    );
    assert!(
        v.get("note")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .contains("unknown"),
        "note must flag this as default reputation",
    );
}

#[test]
fn batch_m_compute_witness_reputation_no_filter_fresh_state_returns_zero_tracked_empty_array() {
    // No witness param → summary branch at explorer.rs:1486-1502.
    // Fresh state has zero tracked witnesses, empty witnesses array.
    // Pins keys `tracked_witnesses`/`witnesses` for the explorer
    // reputation-dashboard view.
    let state = test_state();
    let v = compute_witness_reputation(state, None, None);
    assert_eq!(
        v.get("tracked_witnesses").and_then(|x| x.as_u64()),
        Some(0),
        "fresh state must report 0 tracked_witnesses",
    );
    let arr = v
        .get("witnesses")
        .and_then(|x| x.as_array())
        .expect("witnesses field must be a JSON array");
    assert!(arr.is_empty(), "fresh-state witnesses array must be empty");
}

// ─── compute_* helper wire-shape pins (continued) ──
// Three more sync `compute_*` helpers pinned. This batch covers three
// distinct error-return contracts so a future refactor that unifies
// them can't silently change the wire shape: `compute_seal_debug` and
// `compute_dispute_detail` both return `Result<_, ElaraError>` and
// their unknown-id branches MUST emit `ElaraError::RecordNotFound`
// (mapped to HTTP 404 by the AppError wrapper at axum boundary),
// while `compute_routing_resolve` returns a plain JSON value whose
// `error` key is the only signal the account sees on a malformed
// query. Confusing the two breaks the explorer/account 404 vs 200
// distinction.
use std::sync::atomic::Ordering;

#[test]
fn batch_n_compute_seal_debug_unknown_id_returns_record_not_found_error() {
    // Unknown seal id in fresh consensus → RecordNotFound branch at
    // explorer.rs:666-668. The axum wrapper `seal_debug_route` turns
    // this into HTTP 404. A regression that swallowed the error and
    // returned `Ok(Json(null))` would surface as a 200 with empty body
    // and break the account's "no seal yet — keep polling" UX flow.
    let state = test_state();
    let err = compute_seal_debug(&state, "nonexistent-seal-id")
        .expect_err("fresh consensus has no seal — must return RecordNotFound error");
    match err {
        ElaraError::RecordNotFound(msg) => {
            assert!(
                msg.contains("nonexistent-seal-id"),
                "RecordNotFound message must echo the queried id, got: {msg}",
            );
            assert!(
                msg.contains("no attestations"),
                "RecordNotFound message must explain WHY (no attestations), got: {msg}",
            );
        }
        other => panic!("expected ElaraError::RecordNotFound, got: {other:?}"),
    }
}

#[test]
fn batch_n_compute_routing_resolve_missing_record_id_returns_error_json_no_counter_bump() {
    // Empty/missing record_id → guard branch at explorer.rs:1812-1819.
    // Returns JSON {"error": "..."} WITHOUT bumping the queries counter
    // (the increment at L1845-1847 sits AFTER the guard). Pins both
    // (a) the wire shape accounts parse on a bad request, and (b) the
    // "guard-before-meter" ordering — flipping that order would make
    // every malformed query inflate the resolve-rate metric and mask
    // real load spikes.
    let state = test_state();
    let queries_before = state
        .zone_routing_resolve_queries_total
        .load(Ordering::Relaxed);
    let v = compute_routing_resolve(&state, None, None);
    assert_eq!(
        v.get("error").and_then(|x| x.as_str()),
        Some("missing required query param: record_id"),
        "missing record_id must return the documented error message",
    );
    let queries_after = state
        .zone_routing_resolve_queries_total
        .load(Ordering::Relaxed);
    assert_eq!(
        queries_before, queries_after,
        "guard branch must NOT bump zone_routing_resolve_queries_total",
    );
}

#[test]
fn batch_n_compute_dispute_detail_unknown_id_returns_record_not_found_error() {
    // Unknown dispute id in fresh state → RecordNotFound branch at
    // explorer.rs:2325-2326. The axum wrapper `dispute_detail` turns
    // this into HTTP 404 via AppError. A regression that returned
    // `Ok(Json(null))` would surface as a 200 with empty body and
    // confuse account flows that distinguish "no such dispute" from
    // "dispute exists but no data yet".
    let state = test_state();
    let err = compute_dispute_detail(state, "nonexistent-dispute-id".into())
        .expect_err("fresh state has no disputes — must return RecordNotFound error");
    match err {
        ElaraError::RecordNotFound(msg) => {
            assert!(
                msg.contains("nonexistent-dispute-id"),
                "RecordNotFound message must echo the queried id, got: {msg}",
            );
            assert!(
                msg.contains("not found"),
                "RecordNotFound message must say 'not found', got: {msg}",
            );
        }
        other => panic!("expected ElaraError::RecordNotFound, got: {other:?}"),
    }
}

// ─── compute_* helper wire-shape pins (continued) ──
// Three final sync `compute_*` helpers pinned, closing the remaining
// explorer.rs helper-coverage slice. Each helper
// returns a DIFFERENT error/result wire shape and the assertions here
// pin the distinction so a future "unify error envelope" refactor can't
// silently merge them:
//   - `compute_register_witness_profile` returns `Result<_, ElaraError>`
//     with the `Wire` variant on missing fields (validation contract,
//     distinct from `RecordNotFound`); happy path mutates consensus.
//   - `compute_challenge_detail` returns plain JSON `{"error": "..."}`
//     in-band on unknown id (NOT a Result — different from
//     `compute_seal_debug`/`compute_dispute_detail` which DO return
//     `Result<_, RecordNotFound>`).
//   - `compute_activity` returns plain JSON `{"error": "...", "identity": ...}`
//     in-band with the identity echoed (accounts read the echo to confirm
//     they sent the right input).

#[test]
fn batch_o_compute_register_witness_profile_happy_path_registers_in_consensus() {
    // Happy path: non-empty witness_hash + organization → registers a
    // WitnessProfile in consensus and returns JSON with `registered:true`
    // plus all four input fields echoed verbatim. The PQ-transport router
    // surfaces this JSON unchanged, so the four echo keys are part of
    // the wire contract — a rename here breaks every operator script
    // that polls registration confirmations.
    let state = test_state();
    let body = WitnessProfileBody {
        witness_hash: "wA-hex-deadbeef".into(),
        organization: "OrgA".into(),
        subnet: "10.0.0.0/24".into(),
        geo_zone: "eu-north".into(),
    };
    let v = compute_register_witness_profile(&state, body)
        .expect("happy-path registration must succeed");
    assert_eq!(v.get("registered").and_then(|x| x.as_bool()), Some(true));
    assert_eq!(
        v.get("witness_hash").and_then(|x| x.as_str()),
        Some("wA-hex-deadbeef")
    );
    assert_eq!(v.get("organization").and_then(|x| x.as_str()), Some("OrgA"));
    assert_eq!(
        v.get("subnet").and_then(|x| x.as_str()),
        Some("10.0.0.0/24")
    );
    assert_eq!(v.get("geo_zone").and_then(|x| x.as_str()), Some("eu-north"));
    // Consensus state mutation: the new profile must be readable via
    // `consensus.profiles()` post-call. A regression where the helper
    // returned the success JSON without taking the consensus lock would
    // pass the wire-shape checks but silently drop the profile —
    // the lookup below catches that.
    let consensus = state.consensus.lock_recover();
    let found = consensus
        .profiles()
        .any(|(h, p)| h == "wA-hex-deadbeef" && p.organization == "OrgA");
    assert!(
        found,
        "registered profile must appear in consensus.profiles()"
    );
}

#[test]
fn batch_o_compute_challenge_detail_unknown_id_returns_in_band_error_json() {
    // Unknown challenge id in fresh state → in-band JSON envelope
    // `{"error": "challenge not found"}` at explorer.rs:3496. Note this
    // is DIFFERENT from `compute_dispute_detail` which returns
    // `Result<_, ElaraError::RecordNotFound>` (mapped to HTTP 404).
    // The challenge route serves the in-band envelope as HTTP 200 with
    // an `error` key — accounts distinguish the two cases by status code.
    // A regression that switched `compute_challenge_detail` to Result
    // would break every account that reads challenges via 200-only flow.
    let state = test_state();
    let v = compute_challenge_detail(state, "nonexistent-challenge-id".into());
    assert_eq!(
        v.get("error").and_then(|x| x.as_str()),
        Some("challenge not found"),
        "unknown challenge id must return the documented in-band error message",
    );
}

#[test]
fn batch_o_compute_activity_unknown_identity_returns_populated_envelope_via_reputation_default() {
    // Pins a surprising-to-readers contract: the `compute_activity`
    // not-found branch at explorer.rs:3700-3705 is structurally
    // UNREACHABLE on a fresh node because the reputation engine returns
    // `DEFAULT_REPUTATION=50.0` for unknown witnesses (reputation.rs:401),
    // and the helper sets `found=true` on any `reputation_score != 0.0`
    // (explorer.rs:3680-3681). So unknown identities get the populated
    // envelope, NOT the in-band error envelope. A account that special-cases
    // a 200-with-error-key response would be looking for a shape that
    // production never serves on fresh state. If someone changes
    // DEFAULT_REPUTATION to 0.0 or flips the `!= 0.0` check to `> 0.0`,
    // the unknown-identity path would suddenly hit the error envelope
    // and break this test — a signal that the wire-shape on /activity
    // changed and account UX needs to be re-audited.
    let state = test_state();
    let unknown = "ffffffff_unknown_identity_not_in_any_table";
    assert_ne!(
        unknown, state.config.genesis_authority,
        "test fixture must not collide with the configured genesis_authority",
    );
    let v = compute_activity(&state, unknown);
    assert!(
        v.get("error").is_none(),
        "fresh-state unknown identity must NOT take the in-band error branch \
             (reputation DEFAULT=50.0 flips found=true at explorer.rs:3681)",
    );
    assert_eq!(
        v.get("identity").and_then(|x| x.as_str()),
        Some(unknown),
        "identity field must echo the queried input for account UX",
    );
    assert_eq!(
        v.get("is_genesis_authority").and_then(|x| x.as_bool()),
        Some(false),
        "test fixture identity is NOT the genesis_authority",
    );
    assert_eq!(
        v.get("reputation_score").and_then(|x| x.as_f64()),
        Some(50.0),
        "fresh-state reputation_score must be DEFAULT_REPUTATION=50.0",
    );
}

// ─── Cache-freshness + constant pins ────────────────────────────
//
// Three sync pins on previously-uncovered surfaces:
//   1. EPOCH_HEADERS_TTL + SUPER_SEALS_TTL constants (cache-freshness)
//   2. compute_register_witness_profile required-field validation
//   3. compute_routing_resolve missing-record-id + invalid-hex branches

#[test]
fn batch_ah_explorer_cache_ttl_constants_pin_30_minute_uniform_freshness_window() {
    // Both caches share the same 30-min freshness window. If a future
    // change splits them (e.g., aggressive super-seal cache vs slow
    // header cache), it should land via a deliberate edit — not silently.
    assert_eq!(
        super::EPOCH_HEADERS_TTL,
        std::time::Duration::from_secs(1800),
        "EPOCH_HEADERS_TTL must remain 30 min (1800s) for /explorer/seals/headers cache",
    );
    assert_eq!(
        super::SUPER_SEALS_TTL,
        std::time::Duration::from_secs(1800),
        "SUPER_SEALS_TTL must remain 30 min (1800s) for /explorer/super_seals cache",
    );
    // Uniform-window invariant: both caches refresh at the same cadence.
    assert_eq!(
        super::EPOCH_HEADERS_TTL,
        super::SUPER_SEALS_TTL,
        "epoch-headers + super-seals caches must share TTL — operator runbooks assume one number",
    );
}

#[test]
fn batch_ah_compute_register_witness_profile_validates_required_fields_returns_wire_error() {
    let state = test_state();

    // Empty witness_hash → Wire error.
    let empty_hash = compute_register_witness_profile(
        &state,
        WitnessProfileBody {
            witness_hash: String::new(),
            organization: "OrgA".into(),
            subnet: "sub-1".into(),
            geo_zone: "EU".into(),
        },
    );
    let empty_hash_err = format!(
        "{:?}",
        empty_hash.expect_err("empty witness_hash must error")
    );
    assert!(
        empty_hash_err.contains("witness_hash and organization required"),
        "empty witness_hash must mention the required-fields message; got {empty_hash_err}"
    );

    // Empty organization → Wire error (same code path).
    let empty_org = compute_register_witness_profile(
        &state,
        WitnessProfileBody {
            witness_hash: "deadbeef".into(),
            organization: String::new(),
            subnet: "sub-1".into(),
            geo_zone: "EU".into(),
        },
    );
    let empty_org_err = format!(
        "{:?}",
        empty_org.expect_err("empty organization must error")
    );
    assert!(
        empty_org_err.contains("witness_hash and organization required"),
        "empty organization must mention the required-fields message; got {empty_org_err}"
    );

    // Happy path: both required fields present → Ok with the expected
    // JSON envelope. Subnet + geo_zone are allowed to be empty; only
    // witness_hash + organization are required.
    let ok = compute_register_witness_profile(
        &state,
        WitnessProfileBody {
            witness_hash: "feedface".into(),
            organization: "OrgB".into(),
            subnet: String::new(),
            geo_zone: String::new(),
        },
    )
    .expect("happy path must succeed");
    assert_eq!(ok.get("registered").and_then(|x| x.as_bool()), Some(true));
    assert_eq!(
        ok.get("witness_hash").and_then(|x| x.as_str()),
        Some("feedface")
    );
    assert_eq!(
        ok.get("organization").and_then(|x| x.as_str()),
        Some("OrgB")
    );
}

#[test]
fn batch_ah_compute_routing_resolve_missing_record_id_and_invalid_hex_return_error_json() {
    let state = test_state();

    // Missing record_id (None) → in-band JSON error envelope.
    let missing_none = compute_routing_resolve(&state, None, None);
    assert_eq!(
        missing_none.get("error").and_then(|x| x.as_str()),
        Some("missing required query param: record_id"),
        "None record_id must hit the missing-param branch",
    );

    // Empty-string record_id ALSO hits the missing branch (matches
    // `Some(r) if !r.is_empty()` guard rejecting "").
    let missing_empty = compute_routing_resolve(&state, Some(String::new()), None);
    assert_eq!(
        missing_empty.get("error").and_then(|x| x.as_str()),
        Some("missing required query param: record_id"),
        "empty-string record_id must hit the missing-param branch (guard rejects \"\")",
    );

    // Invalid hex for key_hex → in-band error envelope mentioning hex.
    let bad_hex = compute_routing_resolve(
        &state,
        Some("rec-123".to_string()),
        Some("not-hex-zz".to_string()),
    );
    let err_msg = bad_hex
        .get("error")
        .and_then(|x| x.as_str())
        .expect("invalid-hex branch must emit `error` field");
    assert!(
        err_msg.contains("invalid hex for key"),
        "invalid-hex error must mention 'invalid hex for key'; got {err_msg}",
    );
}

// ─── First direct unit tests on the
//     three top-level `compute_version_*` helpers (explorer.rs:3513,
//     3565, 3605). Previously all three were zero-coverage; the
//     PQ-transport routing + axum router both delegate to them and a
//     silent JSON-shape drift would fan out to every account that
//     renders version chains / fork views / dashboard stats.
//
//     Five orthogonal axes pinned:
//       (1) `compute_version_stats` on fresh state — all four counters
//           are strict u64 type with value 0, payload has EXACTLY
//           four keys (no silent extra field for a future schema add).
//       (2) `compute_version_stats` after registering two distinct
//           v1→v2 chains — chain_count=2 reflects distinct roots,
//           version_count=4, fork_count=0 (sequential, no branching).
//       (3) `compute_version_info` unknown id — error envelope shape
//           `{error, record_id}` echoes the queried id verbatim so
//           the account can distinguish "no version" from a transport
//           error (which lands as a top-level HTTP error, not this
//           in-band envelope).
//       (4) `compute_version_info` known mid-chain id — `chain_length`
//           equals the v1..=N count counting back from query, NOT
//           the full-chain length to the latest descendant. Catches
//           a regression that confuses "chain ending here" with
//           "all versions in the family".
//       (5) `compute_version_forks` known root with two v2 children —
//           `forks[]` reports parent=v1, branches=[v2a, v2b]; `tips[]`
//           includes both v2 children, ordered as DFS pops (we pin
//           the membership set rather than order — the stack-based
//           walk in `latest_versions` is not contract-stable order).
use crate::versioning::VersionRecord;

fn mk_version(
    record_id: &str,
    previous_version: Option<&str>,
    version_number: u64,
    creator: &str,
) -> VersionRecord {
    VersionRecord {
        record_id: record_id.into(),
        previous_version: previous_version.map(str::to_string),
        version_number,
        change_summary: None,
        creator: creator.into(),
        content_hash: format!("hash-{record_id}"),
    }
}

#[test]
fn batch_rr_compute_version_stats_fresh_state_all_zero_strict_u64_with_exactly_four_keys() {
    // Pins the dashboard wire contract: four keys, all u64, all zero.
    // A future "let's add a total_size_bytes field" PR would lift the
    // key count and surface here; a JSON-number → string regression on
    // any counter would also surface as `as_u64() ⇒ None`.
    let state = test_state();
    let v = compute_version_stats(state);
    let obj = v
        .as_object()
        .expect("compute_version_stats must return JSON object");
    assert_eq!(
        obj.len(),
        4,
        "fresh-state payload must have EXACTLY 4 keys (version_count, \
             chain_count, diff_count, fork_count); a future schema add \
             must update the dashboard renderer in lockstep",
    );
    assert_eq!(
        obj.get("version_count").and_then(|x| x.as_u64()),
        Some(0),
        "version_count must be strict u64 zero on fresh state",
    );
    assert_eq!(
        obj.get("chain_count").and_then(|x| x.as_u64()),
        Some(0),
        "chain_count must be strict u64 zero on fresh state",
    );
    assert_eq!(
        obj.get("diff_count").and_then(|x| x.as_u64()),
        Some(0),
        "diff_count must be strict u64 zero on fresh state",
    );
    assert_eq!(
        obj.get("fork_count").and_then(|x| x.as_u64()),
        Some(0),
        "fork_count must be strict u64 zero on fresh state (no children → no forks)",
    );
}

#[test]
fn batch_rr_compute_version_stats_two_distinct_chains_count_each_root_independently() {
    // Two v1 roots + two v2 sequels (one per chain) → 4 versions, 2
    // chains, 0 diffs, 0 forks. Pins that `chain_count` counts ROOTS
    // (length of the `roots: Vec<String>`), not "any v1 record" or
    // "any version with no previous_version" — those happen to coincide
    // today but the right invariant for the dashboard is "number of
    // independently-rooted version families".
    let state = test_state();
    {
        let mut vs = state.version_state.lock_recover();
        vs.register_version(mk_version("a1", None, 1, "alice"))
            .expect("register a1");
        vs.register_version(mk_version("a2", Some("a1"), 2, "alice"))
            .expect("register a2");
        vs.register_version(mk_version("b1", None, 1, "bob"))
            .expect("register b1");
        vs.register_version(mk_version("b2", Some("b1"), 2, "bob"))
            .expect("register b2");
    }
    let v = compute_version_stats(state);
    assert_eq!(
        v.get("version_count").and_then(|x| x.as_u64()),
        Some(4),
        "4 registered versions ⇒ version_count=4",
    );
    assert_eq!(
        v.get("chain_count").and_then(|x| x.as_u64()),
        Some(2),
        "2 distinct roots (a1, b1) ⇒ chain_count=2 (NOT 4 — a sequel \
             v2 is part of an existing chain, not a new one)",
    );
    assert_eq!(
        v.get("diff_count").and_then(|x| x.as_u64()),
        Some(0),
        "no diff records registered ⇒ diff_count=0",
    );
    assert_eq!(
        v.get("fork_count").and_then(|x| x.as_u64()),
        Some(0),
        "each parent has exactly ONE child ⇒ no forks; detect_forks \
             filters children.len() > 1",
    );
}

#[test]
fn batch_rr_compute_version_info_unknown_id_returns_error_envelope_echoing_record_id() {
    // Unknown record_id branch at explorer.rs:3546-3549. Wallets parse
    // this as "no version yet — render the empty state". The contract:
    //   - Top-level `error` field is a String.
    //   - Top-level `record_id` field echoes the queried id verbatim.
    //   - No `version` key (which would confuse account's
    //     "has version data?" check).
    // A regression that returned `{"version": null}` instead would
    // surface as a account rendering an empty version row instead of
    // the empty-state placeholder.
    let state = test_state();
    let v = compute_version_info(state, "nonexistent-version-id".into());
    let obj = v.as_object().expect("error envelope must be a JSON object");
    assert_eq!(
        obj.get("error").and_then(|x| x.as_str()),
        Some("version record not found"),
        "unknown id must emit the documented error message verbatim",
    );
    assert_eq!(
        obj.get("record_id").and_then(|x| x.as_str()),
        Some("nonexistent-version-id"),
        "record_id field must echo the queried id verbatim",
    );
    assert!(
        obj.get("version").is_none(),
        "error envelope must NOT carry a `version` key — a null version \
             field would confuse account's has-version-data? check",
    );
    assert!(
        obj.get("chain").is_none(),
        "error envelope must NOT carry a `chain` key",
    );
    assert!(
        obj.get("children").is_none(),
        "error envelope must NOT carry a `children` key",
    );
}

#[test]
fn batch_rr_compute_version_info_mid_chain_id_pins_chain_length_back_to_root_not_full_family() {
    // Chain: v1 → v2 → v3. Query mid-version v2.
    // `chain_to_root` walks BACKWARDS from queried id, so the chain
    // includes [v2, v1] (length 2), NOT [v1, v2, v3] (length 3).
    // This is the source of a real misread in account code that
    // assumed "chain_length = total versions in the family"; the
    // correct semantic is "ancestor depth of the queried version,
    // inclusive".
    // `children` lists DIRECT descendants of the queried id, so
    // querying v2 returns [v3], not [v3] + transitive future versions.
    let state = test_state();
    {
        let mut vs = state.version_state.lock_recover();
        vs.register_version(mk_version("v1", None, 1, "carol"))
            .expect("register v1");
        vs.register_version(mk_version("v2", Some("v1"), 2, "carol"))
            .expect("register v2");
        vs.register_version(mk_version("v3", Some("v2"), 3, "carol"))
            .expect("register v3");
    }
    let v = compute_version_info(state, "v2".into());

    // Top-level `version` echoes the queried record's fields.
    let ver = v
        .get("version")
        .expect("known id must carry `version` object");
    assert_eq!(
        ver.get("record_id").and_then(|x| x.as_str()),
        Some("v2"),
        "version.record_id must echo the queried id",
    );
    assert_eq!(
        ver.get("version_number").and_then(|x| x.as_u64()),
        Some(2),
        "version_number must be u64 (NOT f64 — accounts pattern-match \
             on integer types for version comparison)",
    );
    assert_eq!(
        ver.get("previous_version").and_then(|x| x.as_str()),
        Some("v1"),
        "previous_version must be Some(\"v1\") for v2",
    );

    // `chain_length` counts ancestors back from query, inclusive.
    assert_eq!(
        v.get("chain_length").and_then(|x| x.as_u64()),
        Some(2),
        "chain v2→v1 has length 2 (NOT 3 — chain_to_root walks \
             BACKWARDS, the future v3 is not in the chain back to root)",
    );
    let chain = v
        .get("chain")
        .and_then(|x| x.as_array())
        .expect("chain field must be a JSON array");
    assert_eq!(chain.len(), 2, "chain array length must match chain_length");
    assert_eq!(
        chain[0].get("record_id").and_then(|x| x.as_str()),
        Some("v2"),
        "chain[0] must be the queried version (chain_to_root inserts \
             current FIRST then walks back)",
    );
    assert_eq!(
        chain[1].get("record_id").and_then(|x| x.as_str()),
        Some("v1"),
        "chain[1] must be the root v1",
    );

    // `children` lists DIRECT descendants only.
    let children = v
        .get("children")
        .and_then(|x| x.as_array())
        .expect("children field must be a JSON array");
    assert_eq!(
        children.len(),
        1,
        "v2 has exactly one direct child (v3); the children field is \
             DIRECT descendants, NOT transitive",
    );
    assert_eq!(children[0].as_str(), Some("v3"), "v2's child must be v3",);
}

#[test]
fn batch_rr_compute_version_forks_two_v2_children_of_v1_emit_fork_at_parent_with_both_tips() {
    // Fork shape: v1 with two competing v2 children (v2a, v2b) — same
    // creator (the validation only allows same-creator chain continuity),
    // both legitimate v2 sequels racing the chain.
    // `forks[]` must report parent=v1, branches set = {v2a, v2b}.
    // `tips[]` must include BOTH leaves (neither has children).
    // `root` field must be v1 regardless of which leaf we queried.
    let state = test_state();
    {
        let mut vs = state.version_state.lock_recover();
        vs.register_version(mk_version("rv1", None, 1, "dave"))
            .expect("register rv1");
        vs.register_version(mk_version("rv2a", Some("rv1"), 2, "dave"))
            .expect("register rv2a");
        vs.register_version(mk_version("rv2b", Some("rv1"), 2, "dave"))
            .expect("register rv2b (fork at rv1)");
    }
    // Query via one of the leaves — root_for walks back to rv1 either way.
    let v = compute_version_forks(state, "rv2a".into());

    assert_eq!(
        v.get("root").and_then(|x| x.as_str()),
        Some("rv1"),
        "root field must be rv1 regardless of which leaf was queried \
             (root_for traverses chain_to_root.last())",
    );

    let forks = v
        .get("forks")
        .and_then(|x| x.as_array())
        .expect("forks field must be a JSON array");
    assert_eq!(
        forks.len(),
        1,
        "exactly ONE fork point (parent=rv1) — detect_forks filters \
             children.len() > 1; rv1 has 2 children, rv2a/rv2b each have 0",
    );
    let fork = &forks[0];
    assert_eq!(
        fork.get("parent").and_then(|x| x.as_str()),
        Some("rv1"),
        "fork parent must be rv1 (the divergence point)",
    );
    let branches = fork
        .get("branches")
        .and_then(|x| x.as_array())
        .expect("fork branches must be a JSON array");
    assert_eq!(branches.len(), 2, "fork has two branches");
    // Order is the children-vec push order, but pin as a SET so a future
    // shift to sorted-by-record-id (a reasonable hardening for
    // deterministic account diffing) wouldn't break this test.
    let branch_set: std::collections::HashSet<&str> =
        branches.iter().filter_map(|b| b.as_str()).collect();
    assert!(branch_set.contains("rv2a"), "branches must include rv2a");
    assert!(branch_set.contains("rv2b"), "branches must include rv2b");

    let tips = v
        .get("tips")
        .and_then(|x| x.as_array())
        .expect("tips field must be a JSON array");
    assert_eq!(
        tips.len(),
        2,
        "both rv2a and rv2b are leaves (no children) → both are tips",
    );
    let tip_ids: std::collections::HashSet<&str> = tips
        .iter()
        .filter_map(|t| t.get("record_id").and_then(|x| x.as_str()))
        .collect();
    assert!(tip_ids.contains("rv2a"), "tips must include rv2a (leaf)");
    assert!(tip_ids.contains("rv2b"), "tips must include rv2b (leaf)");
    // Pin tip projection shape: each tip carries record_id +
    // version_number + creator (per explorer.rs:3582-3585). A account
    // renders the per-tip row from these three fields; an accidental
    // omission of `version_number` would break the version-comparison
    // UI.
    for tip in tips {
        let obj = tip.as_object().expect("each tip must be a JSON object");
        assert!(obj.contains_key("record_id"), "tip must have record_id");
        assert_eq!(
            obj.get("version_number").and_then(|x| x.as_u64()),
            Some(2),
            "both tips are v2 sequels — version_number must be strict u64 2",
        );
        assert_eq!(
            obj.get("creator").and_then(|x| x.as_str()),
            Some("dave"),
            "tip creator must echo the registered creator string",
        );
    }
}

// ─── Five
//     orthogonal axes on the same three `compute_version_*` helpers
//     covering the gaps the prior batch left open:
//       (1) `diff_count` contract — the prior batch pinned `diff_count=0` on
//           fresh state and `diff_count=0` after registering versions,
//           but never with non-zero diffs. This batch registers N=3
//           diffs across two chains and asserts diff_count=3 with
//           version_count and fork_count unchanged — pins that the
//           dashboard's diff counter sources from `vs.diff_count()` =
//           `vs.diffs.len()` and not from any cross-attribute derivation.
//       (2) `fork_count` with MULTIPLE fork points — the prior batch pinned a
//           SINGLE fork point; this batch builds v1 → {v2a, v2b}, with
//           v2a → {v3a1, v3a2}, so detect_forks must return TWO entries.
//           Catches a regression where detect_forks short-circuits on
//           first match or returns only the SHALLOWEST fork.
//       (3) Deep-chain n=20 boundary — pins no implicit truncation in
//           `chain_to_root` (a future bounded-depth memoization would
//           surface here) AND the back-walking order is correct at
//           depth 20, not just at depth 2 (the prior mid-chain test).
//       (4) Root-query (v1) chain semantics — chain_to_root breaks
//           immediately when `previous_version.is_none()`, so the
//           returned chain is single-element [v1]. The prior batch only
//           tested mid-chain (v2 in v1→v2→v3); this pins the
//           degenerate root-query case which a refactor that
//           accidentally pre-incremented `current` to `previous_version`
//           before the None-check would silently fail (returning empty).
//       (5) Cross-route error envelope consistency — compute_version_forks
//           unknown-id branch (explorer.rs:3588-3591) MUST emit the
//           IDENTICAL envelope shape as compute_version_info's unknown-id
//           branch so accounts can use a single decoder branch for both
//           routes. The prior batch pinned only the compute_version_info side.

#[test]
fn batch_ss_compute_version_stats_diff_count_after_register_three_diffs_independent_of_version_count(
) {
    // Two v1→v2 chains (4 versions) + 3 diffs registered across them.
    // Two diffs flow on the alice chain (a1→a2 with distinct diff
    // record_ids d1, d3 — register_diff dedupes only on the diff's own
    // record_id, NOT on the (from, to) pair); one diff on bob's chain
    // (b1→b2 as d2). Pins:
    //   - diff_count == vs.diffs.len() == 3 (NOT version_count derivative)
    //   - version_count unchanged from baseline (4) — diffs don't touch
    //     the version index
    //   - fork_count=0 — diff registration must not create fork-graph entries
    let state = test_state();
    {
        let mut vs = state.version_state.lock_recover();
        vs.register_version(mk_version("a1", None, 1, "alice"))
            .expect("register a1");
        vs.register_version(mk_version("a2", Some("a1"), 2, "alice"))
            .expect("register a2");
        vs.register_version(mk_version("b1", None, 1, "bob"))
            .expect("register b1");
        vs.register_version(mk_version("b2", Some("b1"), 2, "bob"))
            .expect("register b2");
        vs.register_diff(crate::versioning::DiffRecord {
            record_id: "d1".into(),
            from_version: "a1".into(),
            to_version: "a2".into(),
            creator: "alice".into(),
        })
        .expect("register d1");
        vs.register_diff(crate::versioning::DiffRecord {
            record_id: "d2".into(),
            from_version: "b1".into(),
            to_version: "b2".into(),
            creator: "bob".into(),
        })
        .expect("register d2");
        vs.register_diff(crate::versioning::DiffRecord {
            record_id: "d3".into(),
            from_version: "a1".into(),
            to_version: "a2".into(),
            creator: "alice".into(),
        })
        .expect("register d3 — same (from,to) as d1, distinct record_id is allowed");
    }
    let v = compute_version_stats(state);
    assert_eq!(
        v.get("diff_count").and_then(|x| x.as_u64()),
        Some(3),
        "3 registered diffs ⇒ diff_count=3 (sourced from vs.diff_count() = \
             vs.diffs.len(), NOT from any version-cardinality derivation)",
    );
    assert_eq!(
        v.get("version_count").and_then(|x| x.as_u64()),
        Some(4),
        "diff registration must NOT touch the version index — \
             version_count stays at 4",
    );
    assert_eq!(
        v.get("chain_count").and_then(|x| x.as_u64()),
        Some(2),
        "diff registration must NOT touch the roots index — chain_count=2",
    );
    assert_eq!(
        v.get("fork_count").and_then(|x| x.as_u64()),
        Some(0),
        "diff registration must NOT touch the children/forks graph — \
             fork_count=0 even with 3 diffs",
    );
}

#[test]
fn batch_ss_compute_version_stats_fork_count_with_two_distinct_fork_points() {
    // Build a fork tree with TWO independent divergence points:
    //   rv1 → {rv2a, rv2b}                          (fork point #1: rv1)
    //   rv2a → {rv3a1, rv3a2}                       (fork point #2: rv2a)
    // Total: 5 versions, 1 root, 2 fork points.
    // detect_forks filters children.len() > 1, so:
    //   - rv1 (2 children) → fork
    //   - rv2a (2 children) → fork
    //   - rv2b (0 children), rv3a1 (0), rv3a2 (0) → no fork
    // ⇒ fork_count=2. Catches a regression where detect_forks short-
    // circuits on first match or returns only the shallowest fork.
    let state = test_state();
    {
        let mut vs = state.version_state.lock_recover();
        vs.register_version(mk_version("rv1", None, 1, "edith"))
            .expect("register rv1");
        vs.register_version(mk_version("rv2a", Some("rv1"), 2, "edith"))
            .expect("register rv2a (fork-point-1 child A)");
        vs.register_version(mk_version("rv2b", Some("rv1"), 2, "edith"))
            .expect("register rv2b (fork-point-1 child B)");
        vs.register_version(mk_version("rv3a1", Some("rv2a"), 3, "edith"))
            .expect("register rv3a1 (fork-point-2 child A)");
        vs.register_version(mk_version("rv3a2", Some("rv2a"), 3, "edith"))
            .expect("register rv3a2 (fork-point-2 child B)");
    }
    let v = compute_version_stats(state);
    assert_eq!(
        v.get("version_count").and_then(|x| x.as_u64()),
        Some(5),
        "5 registered versions ⇒ version_count=5",
    );
    assert_eq!(
        v.get("chain_count").and_then(|x| x.as_u64()),
        Some(1),
        "ONE root (rv1) ⇒ chain_count=1 even with two fork points",
    );
    assert_eq!(
        v.get("fork_count").and_then(|x| x.as_u64()),
        Some(2),
        "TWO fork points (rv1 + rv2a, both have children.len()=2) ⇒ \
             fork_count=2 — a regression that short-circuited detect_forks \
             after the first match or returned only the SHALLOWEST fork \
             would land here as fork_count=1",
    );
}

#[test]
fn batch_ss_compute_version_info_deep_chain_n20_no_implicit_truncation_full_back_order() {
    // Register a 20-deep chain v01→v02→…→v20 (single creator, sequential).
    // Query v20 (the tip). Pins:
    //   - chain_length=20 (NO implicit truncation in chain_to_root)
    //   - chain[0]=v20 (queried record FIRST per chain_to_root's insert-
    //     before-walk-back ordering)
    //   - chain[19]=v01 (the root, LAST in the back-walked array)
    //   - chain[i].record_id = format!("v{:02}", 20-i) — full back-order
    //     pin, not just endpoints; catches a regression that flipped the
    //     middle of the chain (e.g. an iterator that paired by-index
    //     against a sorted-ascending key, masking the bug at endpoints)
    let state = test_state();
    {
        let mut vs = state.version_state.lock_recover();
        // Register v01 (root), then v02..=v20 in sequence.
        vs.register_version(mk_version("v01", None, 1, "frank"))
            .expect("register v01 (root)");
        for n in 2..=20u64 {
            let id = format!("v{n:02}");
            let prev = format!("v{:02}", n - 1);
            vs.register_version(mk_version(&id, Some(&prev), n, "frank"))
                .unwrap_or_else(|e| panic!("register {id}: {e}"));
        }
    }
    let v = compute_version_info(state, "v20".into());

    assert_eq!(
        v.get("chain_length").and_then(|x| x.as_u64()),
        Some(20),
        "20-deep chain query at tip must return chain_length=20 — no \
             implicit truncation; a future bounded-depth memoization \
             (e.g. cap at MAX_CHAIN_DEPTH=10) would land here as chain_length<20",
    );

    let chain = v
        .get("chain")
        .and_then(|x| x.as_array())
        .expect("chain field must be a JSON array");
    assert_eq!(
        chain.len(),
        20,
        "chain array length must match chain_length=20"
    );

    // Full back-order pin: chain[i].record_id == format!("v{:02}", 20-i)
    // chain[0]=v20 (queried first), chain[1]=v19, ..., chain[19]=v01 (root)
    for (i, entry) in chain.iter().enumerate() {
        let expected = format!("v{:02}", 20 - i);
        assert_eq!(
            entry.get("record_id").and_then(|x| x.as_str()),
            Some(expected.as_str()),
            "chain[{i}] must be {expected} (chain_to_root inserts current \
                 FIRST then walks back, so index i carries the (20-i)th \
                 version)",
        );
    }
}

#[test]
fn batch_ss_compute_version_info_root_query_v1_chain_length_one_with_no_previous_walk() {
    // Single v1 root, no children registered.
    // chain_to_root walks backwards: pushes v1, then matches v.previous_version
    // == None → breaks immediately. Returned chain has length 1, NOT 0.
    // Pins:
    //   - chain_length=1 (NOT 0 — a refactor that pre-incremented `current`
    //     before the None-check would return an empty chain)
    //   - chain[0]=v1 (the root itself)
    //   - version.previous_version is None (JSON null) at root
    //   - children=[] (no descendants registered)
    let state = test_state();
    {
        let mut vs = state.version_state.lock_recover();
        vs.register_version(mk_version("root-v1", None, 1, "grace"))
            .expect("register root-v1");
    }
    let v = compute_version_info(state, "root-v1".into());

    // Top-level version field carries the root record's data.
    let ver = v
        .get("version")
        .expect("known id must carry `version` object");
    assert_eq!(
        ver.get("record_id").and_then(|x| x.as_str()),
        Some("root-v1"),
        "version.record_id must echo the queried root id",
    );
    assert_eq!(
        ver.get("version_number").and_then(|x| x.as_u64()),
        Some(1),
        "root version_number is 1",
    );
    assert!(
        ver.get("previous_version").is_some_and(|x| x.is_null()),
        "v1 (root) emits previous_version as JSON null (Option<String>::None \
             serializes to null), NOT omitted",
    );

    // Chain semantics at root: length=1, contains only the root itself.
    assert_eq!(
        v.get("chain_length").and_then(|x| x.as_u64()),
        Some(1),
        "root query returns chain_length=1 (the root itself), NOT 0 — \
             chain_to_root pushes current BEFORE checking previous_version, \
             so the v1 record is always in the chain",
    );
    let chain = v
        .get("chain")
        .and_then(|x| x.as_array())
        .expect("chain field must be a JSON array");
    assert_eq!(
        chain.len(),
        1,
        "chain array length must match chain_length=1"
    );
    assert_eq!(
        chain[0].get("record_id").and_then(|x| x.as_str()),
        Some("root-v1"),
        "chain[0] is the root itself",
    );

    // No children registered ⇒ children array is empty (not missing).
    let children = v
        .get("children")
        .and_then(|x| x.as_array())
        .expect("children field must be a JSON array even when empty");
    assert!(
        children.is_empty(),
        "no descendants registered ⇒ children=[] (empty array, NOT null \
             or missing — a account's `children.length` access must not panic)",
    );
}

#[test]
fn batch_ss_compute_version_forks_unknown_id_envelope_matches_compute_version_info_route() {
    // compute_version_forks unknown-id branch (explorer.rs:3588-3591) must
    // emit the IDENTICAL envelope shape as compute_version_info's unknown-id
    // branch so accounts can use a SINGLE decoder branch for
    // both `/versions/{id}` and `/versions/{id}/forks` failures.
    // Cross-route consistency contract:
    //   - Both emit `{"error": "version record not found", "record_id": <query>}`
    //   - Both keys are top-level Strings (NOT nested envelopes)
    //   - Both omit success-path keys (`root`/`forks`/`tips` for forks route;
    //     `version`/`chain`/`children` for info route)
    // A regression that diverged one route's error message verbatim
    // ("version not found" vs "version record not found", or
    // "record_id" vs "id") would silently break accounts that share a
    // single error decoder across both routes.
    let state = test_state();
    let v = compute_version_forks(state, "missing-fork-target".into());
    let obj = v
        .as_object()
        .expect("forks-route error envelope must be a JSON object");

    assert_eq!(
        obj.get("error").and_then(|x| x.as_str()),
        Some("version record not found"),
        "forks-route unknown-id error message must be byte-identical to \
             info-route's (\"version record not found\") so a shared account \
             decoder works for both",
    );
    assert_eq!(
        obj.get("record_id").and_then(|x| x.as_str()),
        Some("missing-fork-target"),
        "forks-route must echo the queried id verbatim in `record_id`, \
             matching info-route's contract",
    );
    // Cross-route shape pin: forks-route success keys MUST NOT leak into
    // the error envelope.
    assert!(
        obj.get("root").is_none(),
        "error envelope must NOT carry success-path `root` key",
    );
    assert!(
        obj.get("forks").is_none(),
        "error envelope must NOT carry success-path `forks` key",
    );
    assert!(
        obj.get("tips").is_none(),
        "error envelope must NOT carry success-path `tips` key",
    );
    // Top-level envelope is EXACTLY 2 keys (error + record_id) — guards
    // against a future "include suggested_id" or "include error_code"
    // field that would change wire size and break strict-shape decoders.
    assert_eq!(
        obj.len(),
        2,
        "forks-route error envelope must have EXACTLY 2 keys (error, \
             record_id), matching info-route's 2-key envelope contract",
    );
}

// ─── Five orthogonal axes on `compute_dispute_detail` (explorer.rs:2320)
//     covering the gaps an earlier batch left open.
//
//     Previously the helper had ONLY 1 unit test (an earlier unknown-id
//     RecordNotFound pin at line 5527). The HAPPY-PATH branch — which
//     serializes the full Dispute struct (9 fields, two Option fields,
//     one DisputeStatus enum, one nested DisputeResolution struct) via
//     `serde_json::to_value(dispute).unwrap_or_default()` — was 100%
//     unpinned. A regression in the Dispute struct (renamed field /
//     removed field / changed Option to T / changed enum variants) or
//     in DisputeStatus's `#[serde(rename_all = "snake_case")]` attribute
//     would silently break every account that polls `/disputes/{id}`.
//
//     Five axes pinned:
//       (1) Open-status full-shape round-trip — all 9 Dispute fields
//           present with strict types, status string == "open", both
//           Options serialize as JSON null (NOT omitted).
//       (2) EvidencePhase status after add_evidence — status transitions
//           to "evidence_phase", evidence_ids array carries the evidence
//           record id; pins the lifecycle step from the earlier unknown-id
//           test (which only exercises the empty registry).
//       (3) Resolved status + non-null resolution sub-object — resolve()
//           with "upheld" outcome promotes status to "resolved" AND
//           populates resolution = {resolved_at, resolver, outcome}
//           with the resolver string verbatim.
//       (4) Dismissed status disambiguated from Resolved via status
//           field — resolve() with "dismissed" outcome lands status as
//           "dismissed" (NOT "resolved"); resolution.outcome echoes
//           "dismissed" verbatim. Catches the snake_case attribute drop
//           regression (Resolved/Dismissed → "Resolved"/"Dismissed").
//       (5) Status field rename_all = snake_case wire contract — all
//           four reachable status strings (open / evidence_phase /
//           resolved / dismissed) are byte-distinct AND each lowercase,
//           pinning the attribute against an accidental drop or
//           switch to PascalCase that single-status tests miss.

#[test]
fn batch_tt_compute_dispute_detail_open_dispute_round_trips_all_nine_fields_strict_types() {
    // Insert an Open dispute via state.disputes.write_recover().open_dispute(),
    // query via compute_dispute_detail, verify the round-tripped JSON has
    // all 9 Dispute fields (id / contested_record_id / opener / reason /
    // opened_at / status / evidence_ids / governance_proposal_id /
    // resolution) with strict types:
    //   - id, contested_record_id, opener, reason: String
    //   - opened_at: JSON Number (f64) — accounts compare timestamps numerically
    //   - status: String "open" (snake_case)
    //   - evidence_ids: array (empty on Open status — no evidence submitted yet)
    //   - governance_proposal_id: JSON null (Option<String>::None serializes
    //     to null per serde default, NOT omitted)
    //   - resolution: JSON null (Option<DisputeResolution>::None)
    let state = test_state();
    {
        let mut ds = state.disputes.write_recover();
        ds.open_dispute(
            "d-open-1".into(),
            "contested-rec-A".into(),
            "alice-opener".into(),
            "alleged duplicate timestamp".into(),
            1000.0,
        )
        .expect("open_dispute must succeed in fresh state");
    }
    let v = compute_dispute_detail(state, "d-open-1".into())
        .expect("known dispute id must return Ok variant");
    let obj = v
        .as_object()
        .expect("compute_dispute_detail must return JSON Object");

    // Hard-pin EXACTLY 9 top-level keys — guards against schema bloat
    // (a future debug/diagnostic field added inside the Dispute struct
    // without a corresponding account-side renderer update) AND schema
    // drop (a refactor that elided an Option field via #[serde(skip_serializing_if)]).
    assert_eq!(
        obj.len(),
        9,
        "Dispute struct has 9 fields — round-trip JSON must have \
             EXACTLY 9 keys; got {} keys: {:?}",
        obj.len(),
        obj.keys().collect::<Vec<_>>(),
    );

    assert_eq!(
        obj.get("id").and_then(|x| x.as_str()),
        Some("d-open-1"),
        "id field echoes dispute id verbatim",
    );
    assert_eq!(
        obj.get("contested_record_id").and_then(|x| x.as_str()),
        Some("contested-rec-A"),
        "contested_record_id echoes input verbatim",
    );
    assert_eq!(
        obj.get("opener").and_then(|x| x.as_str()),
        Some("alice-opener"),
        "opener field echoes opener identity verbatim",
    );
    assert_eq!(
        obj.get("reason").and_then(|x| x.as_str()),
        Some("alleged duplicate timestamp"),
        "reason field echoes the dispute reason verbatim (catches an \
             accidental truncation / normalization of operator input)",
    );
    assert_eq!(
        obj.get("opened_at").and_then(|x| x.as_f64()),
        Some(1000.0),
        "opened_at is JSON Number (f64) — accounts order disputes by \
             timestamp numerically, a String regression would break sort",
    );
    assert_eq!(
        obj.get("status").and_then(|x| x.as_str()),
        Some("open"),
        "DisputeStatus::Open serializes as snake_case string \"open\"",
    );
    let evidence = obj
        .get("evidence_ids")
        .and_then(|x| x.as_array())
        .expect("evidence_ids is a JSON array even on Open status");
    assert!(
        evidence.is_empty(),
        "newly-opened dispute has no evidence — evidence_ids=[] (empty \
             array, NOT null or omitted)",
    );
    assert!(
        obj.get("governance_proposal_id")
            .is_some_and(|x| x.is_null()),
        "governance_proposal_id is Option<String>::None on a fresh \
             Open dispute → serializes as JSON null (NOT omitted — a \
             #[serde(skip_serializing_if = \"Option::is_none\")] regression \
             would break account decoders expecting the key to exist)",
    );
    assert!(
        obj.get("resolution").is_some_and(|x| x.is_null()),
        "resolution is Option<DisputeResolution>::None on a fresh Open \
             dispute → serializes as JSON null",
    );
}

#[test]
fn batch_tt_compute_dispute_detail_evidence_phase_status_after_add_evidence_round_trips_evidence_ids(
) {
    // Open a dispute, then call add_evidence to push it into the
    // EvidencePhase status. compute_dispute_detail must reflect:
    //   - status: "evidence_phase" (snake_case from EvidencePhase variant)
    //   - evidence_ids: ["evidence-rec-1"] (length 1, contains evidence record id)
    // Pins the lifecycle step from Open → EvidencePhase that the
    // unknown-id test (which only exercises empty-registry RecordNotFound)
    // cannot reach.
    let state = test_state();
    {
        let mut ds = state.disputes.write_recover();
        ds.open_dispute(
            "d-evidence-1".into(),
            "contested-rec-B".into(),
            "bob-opener".into(),
            "alleged double-spend".into(),
            2000.0,
        )
        .expect("open_dispute");
        ds.add_evidence(
            "d-evidence-1",
            "evidence-rec-1".into(),
            2100.0,  // within evidence window
            86400.0, // 24h window
        )
        .expect("add_evidence must succeed within window");
    }
    let v = compute_dispute_detail(state, "d-evidence-1".into())
        .expect("known dispute id must return Ok variant");

    assert_eq!(
        v.get("status").and_then(|x| x.as_str()),
        Some("evidence_phase"),
        "DisputeStatus::EvidencePhase serializes as snake_case string \
             \"evidence_phase\" (NOT \"EvidencePhase\" — the #[serde(rename_all)] \
             attribute is part of the wire contract)",
    );
    let evidence = v
        .get("evidence_ids")
        .and_then(|x| x.as_array())
        .expect("evidence_ids must be a JSON array");
    assert_eq!(
        evidence.len(),
        1,
        "one add_evidence call ⇒ evidence_ids.len() == 1",
    );
    assert_eq!(
        evidence[0].as_str(),
        Some("evidence-rec-1"),
        "evidence_ids[0] echoes the evidence record id verbatim",
    );
}

#[test]
fn batch_tt_compute_dispute_detail_resolved_emits_non_null_resolution_three_field_object() {
    // Open + resolve("upheld") promotes status to Resolved AND populates
    // the resolution Option with {resolved_at, resolver, outcome}.
    // Three orthogonal pins:
    //   - status == "resolved" (snake_case)
    //   - resolution sub-object is non-null (NOT JSON null)
    //   - resolution sub-object has EXACTLY 3 keys with strict types:
    //       resolved_at: f64, resolver: String, outcome: String
    let state = test_state();
    {
        let mut ds = state.disputes.write_recover();
        ds.open_dispute(
            "d-resolved-1".into(),
            "contested-rec-C".into(),
            "carol-opener".into(),
            "alleged invalid signature".into(),
            3000.0,
        )
        .expect("open_dispute");
        ds.resolve(
            "d-resolved-1",
            "consensus", // resolver string
            "upheld",    // outcome — NOT "dismissed", so status → Resolved
            3500.0,
        )
        .expect("resolve must succeed on Open dispute");
    }
    let v = compute_dispute_detail(state, "d-resolved-1".into())
        .expect("known dispute id must return Ok variant");

    assert_eq!(
        v.get("status").and_then(|x| x.as_str()),
        Some("resolved"),
        "non-\"dismissed\" outcome ⇒ DisputeStatus::Resolved → \
             snake_case string \"resolved\"",
    );

    let resolution = v
        .get("resolution")
        .expect("resolution key must exist post-resolve");
    assert!(
        resolution.is_object(),
        "post-resolve, resolution is a non-null Object (was JSON null \
             pre-resolve per Batch TT-(1) Open-status test)",
    );
    let r_obj = resolution.as_object().unwrap();
    assert_eq!(
        r_obj.len(),
        3,
        "DisputeResolution struct has 3 fields — JSON object must have \
             EXACTLY 3 keys; got {}: {:?}",
        r_obj.len(),
        r_obj.keys().collect::<Vec<_>>(),
    );
    assert_eq!(
        r_obj.get("resolved_at").and_then(|x| x.as_f64()),
        Some(3500.0),
        "resolved_at echoes the resolve timestamp as f64",
    );
    assert_eq!(
        r_obj.get("resolver").and_then(|x| x.as_str()),
        Some("consensus"),
        "resolver echoes the resolver identity string verbatim — \
             accounts render this as the audit trail",
    );
    assert_eq!(
        r_obj.get("outcome").and_then(|x| x.as_str()),
        Some("upheld"),
        "outcome echoes the resolve() outcome arg verbatim",
    );
}

#[test]
fn batch_tt_compute_dispute_detail_dismissed_status_distinguishable_from_resolved_via_status_string(
) {
    // Open + resolve("dismissed") lands status as Dismissed (NOT Resolved).
    // This is the discriminator branch in DisputeState::resolve at
    // dispute.rs:217-220:
    //   "dismissed" => DisputeStatus::Dismissed,
    //   _           => DisputeStatus::Resolved,
    // The "_" arm makes EVERY non-"dismissed" outcome land as Resolved,
    // so the "dismissed" string match is THE branch that produces a
    // distinct status. Pins:
    //   - status == "dismissed" (not "resolved" — discriminates the branch)
    //   - resolution.outcome == "dismissed" (the outcome string echoes
    //     even in the dismissed branch — both fields must agree)
    // A regression that lost the snake_case attribute would surface here
    // as status="Dismissed" (PascalCase from the variant name).
    let state = test_state();
    {
        let mut ds = state.disputes.write_recover();
        ds.open_dispute(
            "d-dismissed-1".into(),
            "contested-rec-D".into(),
            "dave-opener".into(),
            "frivolous claim".into(),
            4000.0,
        )
        .expect("open_dispute");
        ds.resolve("d-dismissed-1", "governance", "dismissed", 4500.0)
            .expect("resolve(dismissed) must succeed");
    }
    let v = compute_dispute_detail(state, "d-dismissed-1".into())
        .expect("known dispute id must return Ok variant");

    assert_eq!(
        v.get("status").and_then(|x| x.as_str()),
        Some("dismissed"),
        "outcome \"dismissed\" ⇒ DisputeStatus::Dismissed → snake_case \
             string \"dismissed\" (NOT \"resolved\" — pins the discriminator \
             branch in DisputeState::resolve at dispute.rs:217-220)",
    );
    let outcome = v
        .get("resolution")
        .and_then(|r| r.get("outcome"))
        .and_then(|o| o.as_str());
    assert_eq!(
        outcome,
        Some("dismissed"),
        "resolution.outcome echoes the dismissed outcome string verbatim — \
             the status field and resolution.outcome BOTH carry the dismissed \
             signal, and they must agree (catches a regression that mutated \
             one without the other)",
    );
}

#[test]
fn batch_tt_compute_dispute_detail_status_serde_rename_all_snake_case_all_four_variants_distinct() {
    // Cross-pin the #[serde(rename_all = "snake_case")] attribute on
    // DisputeStatus by exercising all four REACHABLE variants
    // (Open / EvidencePhase / Resolved / Dismissed; the fifth variant
    // CommunityReview requires escalate_to_governance which is a separate
    // helper) and verifying their rendered status strings are:
    //   - byte-distinct from each other (HashSet uniqueness check)
    //   - all lowercase (no uppercase character anywhere)
    //   - each at least one underscore-or-pure-letter (rule out
    //     accidental \" \" or punctuation contamination)
    // A regression that lost the #[serde(rename_all = "snake_case")]
    // attribute would emit "Open" / "EvidencePhase" / "Resolved" /
    // "Dismissed" — all distinct, all PascalCase. Single-status tests
    // miss this because each in isolation still differs from the others.
    // This pins the attribute itself as a wire contract.
    let state = test_state();
    {
        let mut ds = state.disputes.write_recover();
        // Open — d-status-a (just opened, no evidence, no resolve)
        ds.open_dispute(
            "d-status-a".into(),
            "rec-a".into(),
            "op-a".into(),
            "reason-a".into(),
            100.0,
        )
        .expect("open a");
        // EvidencePhase — d-status-b (open + add_evidence)
        ds.open_dispute(
            "d-status-b".into(),
            "rec-b".into(),
            "op-b".into(),
            "reason-b".into(),
            200.0,
        )
        .expect("open b");
        ds.add_evidence("d-status-b", "ev-b".into(), 250.0, 86400.0)
            .expect("evidence b");
        // Resolved — d-status-c (open + resolve("upheld"))
        ds.open_dispute(
            "d-status-c".into(),
            "rec-c".into(),
            "op-c".into(),
            "reason-c".into(),
            300.0,
        )
        .expect("open c");
        ds.resolve("d-status-c", "consensus", "upheld", 350.0)
            .expect("resolve c upheld");
        // Dismissed — d-status-d (open + resolve("dismissed"))
        ds.open_dispute(
            "d-status-d".into(),
            "rec-d".into(),
            "op-d".into(),
            "reason-d".into(),
            400.0,
        )
        .expect("open d");
        ds.resolve("d-status-d", "governance", "dismissed", 450.0)
            .expect("resolve d dismissed");
    }

    let mut statuses = std::collections::HashSet::new();
    for (id, expected) in [
        ("d-status-a", "open"),
        ("d-status-b", "evidence_phase"),
        ("d-status-c", "resolved"),
        ("d-status-d", "dismissed"),
    ] {
        let v = compute_dispute_detail(state.clone(), id.to_string())
            .unwrap_or_else(|e| panic!("compute_dispute_detail({id}): {e}"));
        let s = v
            .get("status")
            .and_then(|x| x.as_str())
            .unwrap_or_else(|| panic!("{id}: status field missing"))
            .to_string();
        assert_eq!(
            s, expected,
            "{id}: status must be \"{expected}\" (got \"{s}\") — pins \
                 #[serde(rename_all = \"snake_case\")] attribute on DisputeStatus",
        );
        // No uppercase character — pins lowercase contract.
        assert!(
            s.chars().all(|c| !c.is_ascii_uppercase()),
            "{id}: status \"{s}\" must contain NO uppercase character — \
                 a regression that lost #[serde(rename_all)] would emit \
                 PascalCase like \"Open\"",
        );
        statuses.insert(s);
    }

    // All four status strings must be distinct.
    assert_eq!(
        statuses.len(),
        4,
        "four reachable DisputeStatus variants must serialize to FOUR \
             byte-distinct strings; got {} distinct: {:?}",
        statuses.len(),
        statuses,
    );
}

// ─── Five orthogonal axes on `compute_dag_lifecycle` (explorer.rs:1990)
//     and `compute_dag_tips` (explorer.rs:2026) — TWO sibling DAG-summary
//     helpers that previously had ZERO direct unit tests.
//
//     Both helpers feed the explorer/account "DAG overview" dashboard
//     panel — wire-shape regressions break the dashboard silently
//     (empty arrays where there used to be data, or fields renamed under
//     a future refactor that touches the json! macro).
//
//     Five axes pinned (3 on compute_dag_lifecycle, 2 on compute_dag_tips):
//       (1) compute_dag_lifecycle fresh-state envelope — 7 keys present,
//           all counts at 0, avg_parents at literal 0.0 (zero-guard
//           branch at L2012 catches the div-by-zero refactor regression).
//       (2) compute_dag_lifecycle populated 3-node linear chain —
//           total=3, edges=2, tips=1 (only the head is a tip),
//           avg_parents=0.67 (the rounded-to-2dp expression at L2012).
//       (3) compute_dag_lifecycle pending derivation — manipulate the
//           finalized set externally, assert pending = total - finalized
//           - attested via saturating subtraction (saturates to 0 if
//           finalized > total, NOT panic on underflow).
//       (4) compute_dag_tips fresh-state empty-arrays-not-null contract
//           — 4 keys present, tips/roots are empty JSON arrays (NOT
//           null), tips_count=0, roots_count=0 strict-u64 types.
//       (5) compute_dag_tips populated state with TWO disjoint roots
//           plus TWO chain tips — tips set = {head-of-chain-a, root-b},
//           roots set = {root-a, root-b}; pin tips/roots semantics
//           (tips = childless nodes, roots = parentless nodes) so a
//           future swap of dag.tips()/dag.roots() at L2030-2031 surfaces.

#[tokio::test]
async fn batch_uu_compute_dag_lifecycle_fresh_state_emits_zero_counters_and_zero_avg_parents() {
    // Fresh NodeState has an empty DagIndex, empty finalized set, and
    // a fresh ConsensusEngine. All 4 derived counters MUST be 0, and
    // avg_parents MUST hit the `else 0.0` branch at L2012 (NOT a
    // div-by-zero panic — that branch is the contract being pinned).
    let state = test_state();
    let v = compute_dag_lifecycle(state).await;
    let obj = v
        .as_object()
        .expect("compute_dag_lifecycle must return JSON Object");
    assert_eq!(
        obj.len(),
        7,
        "lifecycle envelope must have EXACTLY 7 keys (total_records, \
             pending, attested, finalized, dag_tips, dag_edges, avg_parents); \
             got {} keys: {:?}",
        obj.len(),
        obj.keys().collect::<Vec<_>>(),
    );
    for k in [
        "total_records",
        "pending",
        "attested",
        "finalized",
        "dag_tips",
        "dag_edges",
        "avg_parents",
    ] {
        assert!(
            obj.contains_key(k),
            "lifecycle envelope must carry `{k}` field"
        );
    }
    for k in [
        "total_records",
        "pending",
        "attested",
        "finalized",
        "dag_tips",
        "dag_edges",
    ] {
        assert_eq!(
            obj.get(k).and_then(|x| x.as_u64()),
            Some(0),
            "fresh-state `{k}` must be u64 0",
        );
    }
    // Zero-guard branch at L2012: total==0 falls to literal 0.0, NOT
    // a div-by-zero panic. f64 type pin is the secondary contract —
    // dashboard renders this as "0.00" via printf-style formatting.
    let avg = obj
        .get("avg_parents")
        .and_then(|x| x.as_f64())
        .expect("avg_parents must be a JSON Number (f64)");
    assert_eq!(
        avg, 0.0,
        "fresh-state avg_parents must be literal 0.0 (zero-guard branch \
             at L2012 — total==0 returns 0.0 instead of dividing by zero)",
    );
}

#[tokio::test]
async fn batch_uu_compute_dag_lifecycle_three_node_chain_tips_one_avg_parents_two_thirds() {
    // Insert v1 <- v2 <- v3 linear chain into the DAG. Expected:
    //   total_records = 3
    //   dag_edges = 2 (one parent edge per non-root)
    //   dag_tips = 1 (only v3 has no children)
    //   avg_parents = (2 * 100.0 / 3.0).round() / 100.0 = 0.67
    // The 0.67 value pins the rounding contract at L2012 — a refactor
    // that dropped the *100.0 / .round() / 100.0 dance and emitted the
    // raw 0.6666… would silently break account decimal formatting.
    let state = test_state();
    {
        let mut dag_guard = state.dag.write().await;
        let dag = std::sync::Arc::make_mut(&mut *dag_guard);
        dag.insert("v1".into(), vec![], 100.0).expect("insert v1");
        dag.insert("v2".into(), vec!["v1".into()], 101.0)
            .expect("insert v2");
        dag.insert("v3".into(), vec!["v2".into()], 102.0)
            .expect("insert v3");
    }
    let v = compute_dag_lifecycle(state).await;
    assert_eq!(
        v.get("total_records").and_then(|x| x.as_u64()),
        Some(3),
        "3-node chain ⇒ total_records=3",
    );
    assert_eq!(
        v.get("dag_edges").and_then(|x| x.as_u64()),
        Some(2),
        "3-node chain has 2 parent-edges (v2→v1, v3→v2)",
    );
    assert_eq!(
        v.get("dag_tips").and_then(|x| x.as_u64()),
        Some(1),
        "3-node linear chain has exactly 1 tip (v3 — the head)",
    );
    // avg_parents rounding contract: (2 * 100 / 3).round() / 100 = 67.0 / 100 = 0.67
    // Floating-point comparison via f64::abs delta to absorb 1-ULP noise.
    let avg = v
        .get("avg_parents")
        .and_then(|x| x.as_f64())
        .expect("avg_parents is f64");
    assert!(
        (avg - 0.67).abs() < 1e-9,
        "3-node chain avg_parents must equal 0.67 (rounded to 2dp via \
             (edges * 100 / total).round() / 100 at L2012); got {avg}",
    );
}

#[tokio::test]
async fn batch_uu_compute_dag_lifecycle_pending_saturating_sub_when_finalized_exceeds_total() {
    // Pin the saturating-subtraction contract at L2000:
    //   pending = total.saturating_sub(finalized_count).saturating_sub(attested_count)
    // Insert 2 DAG records, then mark 5 records as finalized (more than
    // total — pathological but possible if finalized set is restored from
    // disk BEFORE the DAG is rebuilt). saturating_sub means pending=0,
    // NOT a usize-underflow panic. A regression to plain `-` would crash
    // the explorer endpoint on this corner case.
    let state = test_state();
    {
        let mut dag_guard = state.dag.write().await;
        let dag = std::sync::Arc::make_mut(&mut *dag_guard);
        dag.insert("r1".into(), vec![], 100.0).expect("insert r1");
        dag.insert("r2".into(), vec![], 101.0).expect("insert r2");
    }
    {
        let mut fin = state.finalized.write().await;
        // Insert 5 distinct finalized ids — more than dag.len()==2.
        for i in 0..5 {
            fin.insert(format!("finalized-r-{i}"));
        }
    }
    let v = compute_dag_lifecycle(state).await;
    assert_eq!(
        v.get("total_records").and_then(|x| x.as_u64()),
        Some(2),
        "dag holds 2 records",
    );
    assert_eq!(
        v.get("finalized").and_then(|x| x.as_u64()),
        Some(5),
        "finalized set holds 5 ids (pathological — more than total)",
    );
    // saturating_sub: 2.saturating_sub(5) == 0, then 0.saturating_sub(0) == 0
    assert_eq!(
        v.get("pending").and_then(|x| x.as_u64()),
        Some(0),
        "pending must saturate to 0 when finalized > total (NOT panic \
             on usize underflow — pins saturating_sub contract at L2000)",
    );
}

#[tokio::test]
async fn batch_uu_compute_dag_tips_fresh_state_emits_four_keys_with_empty_arrays_not_null() {
    // Fresh DAG → tips=[], roots=[]. Both MUST be JSON arrays (not null,
    // not missing) so the account's tips-list renderer can iterate without
    // an undefined-array NPE. Strict 4-key envelope pin guards against a
    // future "include zone-aware tips" schema bloat that would change
    // wire size for explorer decoders.
    let state = test_state();
    let v = compute_dag_tips(state, None).await;
    let obj = v
        .as_object()
        .expect("compute_dag_tips must return JSON Object");
    assert_eq!(
        obj.len(),
        4,
        "tips envelope must have EXACTLY 4 keys (tips, tips_count, roots, \
             roots_count); got {} keys: {:?}",
        obj.len(),
        obj.keys().collect::<Vec<_>>(),
    );
    let tips = obj
        .get("tips")
        .and_then(|x| x.as_array())
        .expect("tips MUST be a JSON array (not null)");
    assert!(tips.is_empty(), "fresh-state tips array is empty");
    let roots = obj
        .get("roots")
        .and_then(|x| x.as_array())
        .expect("roots MUST be a JSON array (not null)");
    assert!(roots.is_empty(), "fresh-state roots array is empty");
    assert_eq!(
        obj.get("tips_count").and_then(|x| x.as_u64()),
        Some(0),
        "fresh-state tips_count must be u64 0",
    );
    assert_eq!(
        obj.get("roots_count").and_then(|x| x.as_u64()),
        Some(0),
        "fresh-state roots_count must be u64 0",
    );
}

#[tokio::test]
async fn batch_uu_compute_dag_tips_two_disjoint_subtrees_tips_set_and_roots_set_semantically_distinct(
) {
    // Insert TWO disjoint subtrees so tips and roots are visibly distinct
    // sets (NOT trivially the same nodes on a single linear chain):
    //   subtree-a: root_a (parentless) ← chain_a (child of root_a)
    //   subtree-b: root_b (parentless, NO children)
    // Expected:
    //   roots = {root_a, root_b}  (2 parentless nodes)
    //   tips  = {chain_a, root_b} (2 childless nodes — root_b is BOTH
    //                              a root AND a tip because it has no
    //                              children)
    // Pins the DUAL membership of root_b (catches a regression where
    // tips() incorrectly excluded root nodes) AND distinguishes
    // tips/roots semantics (catches a regression where dag.tips() and
    // dag.roots() were swapped at L2030-2031).
    let state = test_state();
    {
        let mut dag_guard = state.dag.write().await;
        let dag = std::sync::Arc::make_mut(&mut *dag_guard);
        dag.insert("root_a".into(), vec![], 100.0)
            .expect("insert root_a");
        dag.insert("chain_a".into(), vec!["root_a".into()], 101.0)
            .expect("insert chain_a");
        dag.insert("root_b".into(), vec![], 102.0)
            .expect("insert root_b");
    }
    let v = compute_dag_tips(state, None).await;
    let tips: std::collections::HashSet<&str> = v
        .get("tips")
        .and_then(|x| x.as_array())
        .expect("tips array")
        .iter()
        .filter_map(|e| e.as_str())
        .collect();
    let roots: std::collections::HashSet<&str> = v
        .get("roots")
        .and_then(|x| x.as_array())
        .expect("roots array")
        .iter()
        .filter_map(|e| e.as_str())
        .collect();
    // tips = childless nodes = {chain_a, root_b}
    assert_eq!(
        tips,
        ["chain_a", "root_b"].iter().copied().collect(),
        "tips set must be {{chain_a, root_b}} — the two childless nodes",
    );
    // roots = parentless nodes = {root_a, root_b}
    assert_eq!(
        roots,
        ["root_a", "root_b"].iter().copied().collect(),
        "roots set must be {{root_a, root_b}} — the two parentless nodes",
    );
    // counts mirror lengths
    assert_eq!(v.get("tips_count").and_then(|x| x.as_u64()), Some(2));
    assert_eq!(v.get("roots_count").and_then(|x| x.as_u64()), Some(2));
    // root_b appears in BOTH sets — pins the dual-membership contract
    // (a tip-only filter that excluded roots would miss root_b in tips,
    // a root-only filter that excluded tips would miss root_b in roots).
    assert!(
        tips.contains("root_b") && roots.contains("root_b"),
        "root_b must appear in BOTH tips AND roots (childless AND parentless)",
    );
}

#[tokio::test]
async fn dag_tips_response_is_bounded_by_limit_while_counts_stay_true() {
    // `/dag/tips` is a PUBLIC, unauthenticated endpoint. A single GET must not
    // be able to pull the entire hot-tier frontier as one JSON payload (a
    // small-request → large-response amplification lever). Pin: the returned
    // tips/roots ARRAYS are capped at `limit`, while `tips_count`/`roots_count`
    // still report the TRUE frontier size (so a caller detects truncation via
    // `tips.len() < tips_count`). Five parentless, childless records are each
    // BOTH a root and a tip, so both frontiers have 5 entries.
    //
    // `compute_dag_tips` consumes the state `Arc`, so each query rebuilds a
    // fresh five-isolate DAG via this helper.
    async fn five_isolates_then_tips(limit: Option<usize>) -> serde_json::Value {
        let state = test_state();
        {
            let mut dag_guard = state.dag.write().await;
            let dag = std::sync::Arc::make_mut(&mut *dag_guard);
            for i in 0..5 {
                dag.insert(format!("isolate_{i}"), vec![], 100.0 + i as f64)
                    .expect("insert isolate");
            }
        }
        compute_dag_tips(state, limit).await
    }

    // limit=3 caps both arrays to 3 while the counts stay at the true 5.
    let v = five_isolates_then_tips(Some(3)).await;
    let tips = v.get("tips").and_then(|x| x.as_array()).expect("tips array");
    let roots = v
        .get("roots")
        .and_then(|x| x.as_array())
        .expect("roots array");
    assert_eq!(tips.len(), 3, "tips array MUST be capped at the limit (3)");
    assert_eq!(roots.len(), 3, "roots array MUST be capped at the limit (3)");
    assert_eq!(
        v.get("tips_count").and_then(|x| x.as_u64()),
        Some(5),
        "tips_count MUST report the TRUE frontier size (5), not the capped len",
    );
    assert_eq!(
        v.get("roots_count").and_then(|x| x.as_u64()),
        Some(5),
        "roots_count MUST report the TRUE frontier size (5), not the capped len",
    );

    // An over-large requested limit is clamped to the hard max, never honored
    // verbatim — usize::MAX must not panic or over-allocate; it returns at most
    // the true (small) frontier.
    let v2 = five_isolates_then_tips(Some(usize::MAX)).await;
    assert_eq!(
        v2.get("tips").and_then(|x| x.as_array()).map(|a| a.len()),
        Some(5),
        "an over-large limit is clamped to the hard max, returning the full small frontier",
    );
}

// ─── +5 unit tests on `compute_list_disputes` (explorer.rs:2286). ─────────────
//
// Previous coverage: ONE test
// (`batch_l_compute_list_disputes_fresh_state_returns_zero_total_and_empty_array`
// at L5345) — fresh-state envelope check only. The status-filter branch
// (`status.as_deref().is_none_or(|s| { let ds = format!("{:?}", d.status).to_lowercase(); ds == s.to_lowercase() })`)
// at L2294-L2298 was 100% unpinned, as was the `disputes_opened_total`
// atomic / `total` array-length orthogonality.
//
// Axes:
//   (1) Status filter SUBSETS results to matching status only — populate
//       state with 1 Open + 1 Resolved + 1 Dismissed dispute, filter
//       `Some("open")` returns exactly the 1 Open entry; total==1 not 3.
//       Pins that the filter actually filters (an earlier test covered the no-filter
//       branch only via `compute_list_disputes(state, None)`).
//   (2) Status filter case-insensitive on CALLER side — same setup,
//       filter `"OPEN"`/`"Open"`/`"oPeN"` all return same result as
//       `"open"`. Pins the `s.to_lowercase()` contract on the caller
//       argument — guards against a future "be strict on case" refactor
//       that would silently drop account queries arriving via URL params
//       (which preserve case).
//   (3) Multi-word Debug-form filter contract — pin that `EvidencePhase`
//       status matches filter `"evidencephase"` (Debug-form, NO underscore)
//       and does NOT match `"evidence_phase"` (snake_case JSON form). The
//       filter at L2296 derives the comparison key via `format!("{:?}",
//       d.status).to_lowercase()` which strips the snake_case rename. This
//       documents the existing latent contract: filters use Debug-derived
//       lowercase keys, NOT the snake_case JSON value of `d.status`. A
//       future refactor that wired the filter to `serde_json::to_string`
//       (the JSON-form) would be a BREAKING change and this test forces
//       it to be explicit. Distinct from an earlier test which pinned
//       snake_case in the JSON RESPONSE (which IS the wire contract).
//   (4) `disputes_opened_total` counter is sourced from the atomic
//       independently of `total` (= disputes.len()). Bump the atomic to
//       17 via `fetch_add`, populate 3 disputes, assert
//       `disputes_opened_total==17 AND total==3`. Catches a regression
//       that wired `total = opened_total` or vice versa (would pass at
//       fresh-state 0==0 but fail here at 17 != 3).
//   (5) Top-level envelope: EXACTLY 3-key Object {"total",
//       "disputes_opened_total", "disputes"} + strict u64 types on both
//       counter fields. Pin on BOTH empty AND populated branches —
//       catches a 4th-field bloat regression (e.g. a debug `cache_hit`
//       field added to the json! macro) AND a counter type-drift to
//       f64 (e.g. an accidental `.as_f64()` accumulator promotion).

#[test]
fn batch_vv_compute_list_disputes_status_filter_subsets_to_matching_status_only() {
    let state = test_state();
    {
        let mut ds = state.disputes.write_recover();
        ds.open_dispute(
            "d-open-vv".into(),
            "rec-open".into(),
            "alice".into(),
            "reason-open".into(),
            1000.0,
        )
        .expect("open_dispute");
        ds.open_dispute(
            "d-resolved-vv".into(),
            "rec-resolved".into(),
            "bob".into(),
            "reason-resolved".into(),
            1001.0,
        )
        .expect("open_dispute");
        ds.resolve("d-resolved-vv", "consensus", "upheld", 1100.0)
            .expect("resolve");
        ds.open_dispute(
            "d-dismissed-vv".into(),
            "rec-dismissed".into(),
            "carol".into(),
            "reason-dismissed".into(),
            1002.0,
        )
        .expect("open_dispute");
        ds.resolve("d-dismissed-vv", "consensus", "dismissed", 1200.0)
            .expect("resolve");
    }
    // No filter returns all 3 — baseline sanity that the populated state
    // is correctly built before exercising the filter branch.
    let v_all = compute_list_disputes(state.clone(), None);
    assert_eq!(
        v_all.get("total").and_then(|x| x.as_u64()),
        Some(3),
        "no-filter must return all 3 disputes — populated state baseline",
    );
    // Filter "open" returns ONLY the Open dispute.
    let v_open = compute_list_disputes(state.clone(), Some("open".into()));
    assert_eq!(
        v_open.get("total").and_then(|x| x.as_u64()),
        Some(1),
        "status=open filter must return exactly 1 dispute (the only Open one)",
    );
    let arr = v_open
        .get("disputes")
        .and_then(|x| x.as_array())
        .expect("disputes array");
    assert_eq!(arr.len(), 1, "disputes array length must mirror total");
    assert_eq!(
        arr[0].get("id").and_then(|x| x.as_str()),
        Some("d-open-vv"),
        "the single returned dispute MUST be the Open one (not a Resolved \
             or Dismissed entry that leaked through the filter)",
    );
    assert_eq!(
        arr[0].get("status").and_then(|x| x.as_str()),
        Some("open"),
        "returned dispute's status field is \"open\" (snake_case JSON form)",
    );
    // Filter "resolved" returns only the Resolved dispute.
    let v_resolved = compute_list_disputes(state.clone(), Some("resolved".into()));
    assert_eq!(
        v_resolved.get("total").and_then(|x| x.as_u64()),
        Some(1),
        "status=resolved must return exactly 1 dispute",
    );
    assert_eq!(
        v_resolved
            .get("disputes")
            .and_then(|x| x.as_array())
            .unwrap()[0]
            .get("id")
            .and_then(|x| x.as_str()),
        Some("d-resolved-vv"),
        "the single returned dispute MUST be the Resolved one",
    );
    // Filter "dismissed" returns only the Dismissed dispute.
    let v_dismissed = compute_list_disputes(state, Some("dismissed".into()));
    assert_eq!(
        v_dismissed.get("total").and_then(|x| x.as_u64()),
        Some(1),
        "status=dismissed must return exactly 1 dispute",
    );
    assert_eq!(
        v_dismissed
            .get("disputes")
            .and_then(|x| x.as_array())
            .unwrap()[0]
            .get("id")
            .and_then(|x| x.as_str()),
        Some("d-dismissed-vv"),
        "the single returned dispute MUST be the Dismissed one",
    );
}

#[test]
fn batch_vv_compute_list_disputes_status_filter_caller_side_case_insensitive() {
    // Populate state with one Open dispute, query with several casings of
    // "open" — all MUST match. The filter normalizes the caller input via
    // `s.to_lowercase()` at L2297; a regression to strict case-sensitive
    // match would silently drop account queries arriving via URL params
    // (which preserve the operator's typed case verbatim).
    let state = test_state();
    {
        let mut ds = state.disputes.write_recover();
        ds.open_dispute(
            "d-case-test".into(),
            "rec-A".into(),
            "alice".into(),
            "alleged".into(),
            3000.0,
        )
        .expect("open_dispute");
    }
    // Reference query — canonical lowercase "open".
    let baseline = compute_list_disputes(state.clone(), Some("open".into()));
    assert_eq!(
        baseline.get("total").and_then(|x| x.as_u64()),
        Some(1),
        "canonical \"open\" must match",
    );
    // Same-result for all casings of "open" — the comparator MUST be
    // case-insensitive on the caller-supplied string.
    for casing in ["OPEN", "Open", "oPeN", "OpEn", "open"] {
        let v = compute_list_disputes(state.clone(), Some(casing.to_string()));
        assert_eq!(
            v.get("total").and_then(|x| x.as_u64()),
            Some(1),
            "filter `{casing}` MUST return 1 dispute (case-insensitive \
                 caller-side normalization at L2297)",
        );
        // Pin that the SAME single dispute is returned in each casing —
        // catches a regression that returned 1 entry but a DIFFERENT one
        // per casing (which `total==1` alone would not detect).
        assert_eq!(
            v.get("disputes").and_then(|x| x.as_array()).unwrap()[0]
                .get("id")
                .and_then(|x| x.as_str()),
            Some("d-case-test"),
            "filter `{casing}` MUST return the same dispute as canonical \
                 \"open\" (case-fold preserves identity)",
        );
    }
}

#[test]
fn batch_vv_compute_list_disputes_multi_word_status_filter_uses_debug_form_not_snake_case() {
    // Open a dispute and add evidence to push it into EvidencePhase.
    // The filter at L2296 derives the comparison key via
    // `format!("{:?}", d.status).to_lowercase()` which produces
    // "evidencephase" (Debug form, no underscore) — NOT "evidence_phase"
    // (the snake_case JSON form bound by `#[serde(rename_all = "snake_case")]`).
    //
    // This test documents the existing latent mismatch as an INTENTIONAL
    // contract: a future refactor that switched the filter to use the
    // snake_case JSON form would be a BREAKING wire change (would alter
    // which `?status=...` URLs match) and this test forces that change
    // to be explicit.
    let state = test_state();
    {
        let mut ds = state.disputes.write_recover();
        ds.open_dispute(
            "d-evidence-vv".into(),
            "rec-evidence".into(),
            "alice".into(),
            "alleged".into(),
            4000.0,
        )
        .expect("open_dispute");
        ds.add_evidence(
            "d-evidence-vv",
            "ev-rec-1".into(),
            4100.0, // within 24h evidence window
            86400.0,
        )
        .expect("add_evidence");
    }
    // The JSON-form status is "evidence_phase" (snake_case) — sanity that
    // the serialization side IS snake_case (an earlier test pinned this; sanity
    // re-pinned here so the contrast is in-test).
    let v_no_filter = compute_list_disputes(state.clone(), None);
    let arr = v_no_filter
        .get("disputes")
        .and_then(|x| x.as_array())
        .unwrap();
    assert_eq!(
        arr[0].get("status").and_then(|x| x.as_str()),
        Some("evidence_phase"),
        "wire JSON form for EvidencePhase is snake_case \"evidence_phase\"",
    );
    // Filter `"evidencephase"` (Debug-form lowercase, NO underscore) MUST
    // match — pins the existing filter contract.
    let v_debug_form = compute_list_disputes(state.clone(), Some("evidencephase".into()));
    assert_eq!(
        v_debug_form.get("total").and_then(|x| x.as_u64()),
        Some(1),
        "filter `evidencephase` (Debug-form lowercase) MUST match the \
             EvidencePhase status — pins L2296 `format!(\"{{:?}}\", d.status)` \
             contract that strips the snake_case rename",
    );
    // Filter `"evidence_phase"` (snake_case JSON form, WITH underscore)
    // MUST NOT match — documents the existing mismatch as the active
    // contract. A future fix that aligns filter+JSON would need to
    // update this test (the regression-direction is captured here).
    let v_snake_form = compute_list_disputes(state, Some("evidence_phase".into()));
    assert_eq!(
        v_snake_form.get("total").and_then(|x| x.as_u64()),
        Some(0),
        "filter `evidence_phase` (snake_case JSON form) MUST NOT match \
             under the current filter contract — documents the latent \
             Debug-vs-JSON mismatch as an intentional pin",
    );
}

#[test]
fn batch_vv_compute_list_disputes_opened_total_counter_orthogonal_to_total_array_length() {
    // Bump `disputes_opened_total` atomic to 17 via `fetch_add` (simulates
    // historical opens whose disputes were since pruned/resolved-and-pruned).
    // Populate state with EXACTLY 3 active disputes.
    // Expected: `total=3` (array length) AND `disputes_opened_total=17`
    // (counter) — the two are SOURCED INDEPENDENTLY (counter from atomic,
    // total from disputes.len()) and a regression wiring `total =
    // opened_total` would surface here as `total==17` (or vice versa
    // `opened_total==3`). An existing fresh-state test (0==0)
    // cannot detect this aliasing.
    let state = test_state();
    state
        .disputes_opened_total
        .fetch_add(17, std::sync::atomic::Ordering::Relaxed);
    {
        let mut ds = state.disputes.write_recover();
        for i in 0..3 {
            ds.open_dispute(
                format!("d-orth-{i}"),
                format!("rec-orth-{i}"),
                format!("opener-{i}"),
                format!("reason-{i}"),
                5000.0 + i as f64,
            )
            .expect("open_dispute");
        }
    }
    let v = compute_list_disputes(state, None);
    assert_eq!(
        v.get("total").and_then(|x| x.as_u64()),
        Some(3),
        "total reflects the IN-MEMORY disputes.len() (3 active), NOT the \
             lifetime counter",
    );
    assert_eq!(
        v.get("disputes_opened_total").and_then(|x| x.as_u64()),
        Some(17),
        "disputes_opened_total reflects the LIFETIME atomic counter (17), \
             NOT the current in-memory array length",
    );
    assert_eq!(
        v.get("disputes")
            .and_then(|x| x.as_array())
            .map(|a| a.len()),
        Some(3),
        "disputes array length mirrors total (3), NOT opened_total (17)",
    );
}

#[test]
fn batch_vv_compute_list_disputes_envelope_exactly_three_keys_with_strict_u64_counters() {
    // Pin top-level envelope shape on BOTH empty AND populated branches:
    //   - Object with EXACTLY 3 keys: total / disputes_opened_total / disputes
    //   - total: strict u64 (catches f64 promotion from a downstream
    //     rate-per-sec accumulator)
    //   - disputes_opened_total: strict u64 (same)
    //   - disputes: JSON Array (empty array on fresh state, NOT null;
    //     populated array under load)
    //
    // Empty-branch sanity is covered by an earlier shape pin, but
    // re-pinned here in CONJUNCTION with the populated branch so a
    // regression that holds shape only on one branch (e.g. a `match` on
    // disputes.len() that emits a different envelope on empty vs
    // populated) is detectable.
    //
    // Empty branch.
    let state_empty = test_state();
    let v_empty = compute_list_disputes(state_empty, None);
    let obj_empty = v_empty
        .as_object()
        .expect("compute_list_disputes returns Object");
    assert_eq!(
        obj_empty.len(),
        3,
        "fresh-state envelope MUST have EXACTLY 3 top-level keys; got \
             {} keys: {:?}",
        obj_empty.len(),
        obj_empty.keys().collect::<Vec<_>>(),
    );
    let expected_keys: std::collections::HashSet<&str> =
        ["total", "disputes_opened_total", "disputes"]
            .iter()
            .copied()
            .collect();
    let actual_keys: std::collections::HashSet<&str> =
        obj_empty.keys().map(|k| k.as_str()).collect();
    assert_eq!(
        actual_keys, expected_keys,
        "fresh-state envelope key SET must equal {{total, \
             disputes_opened_total, disputes}}",
    );
    assert!(
        obj_empty.get("total").is_some_and(|x| x.is_u64()),
        "fresh-state total is strict u64 (not f64 / not String)",
    );
    assert!(
        obj_empty
            .get("disputes_opened_total")
            .is_some_and(|x| x.is_u64()),
        "fresh-state disputes_opened_total is strict u64",
    );
    assert!(
        obj_empty.get("disputes").is_some_and(|x| x.is_array()),
        "fresh-state disputes is JSON Array (NOT null, NOT missing)",
    );

    // Populated branch — re-pin SAME contract under load to catch a
    // branch-dependent envelope regression.
    let state_pop = test_state();
    state_pop
        .disputes_opened_total
        .fetch_add(42, std::sync::atomic::Ordering::Relaxed);
    {
        let mut ds = state_pop.disputes.write_recover();
        ds.open_dispute(
            "d-env-1".into(),
            "rec-env".into(),
            "alice".into(),
            "x".into(),
            6000.0,
        )
        .expect("open_dispute");
    }
    let v_pop = compute_list_disputes(state_pop, None);
    let obj_pop = v_pop
        .as_object()
        .expect("populated compute_list_disputes returns Object");
    assert_eq!(
        obj_pop.len(),
        3,
        "populated envelope MUST have EXACTLY 3 top-level keys (same \
             as fresh state — no branch-dependent shape drift)",
    );
    let actual_keys_pop: std::collections::HashSet<&str> =
        obj_pop.keys().map(|k| k.as_str()).collect();
    assert_eq!(
        actual_keys_pop, expected_keys,
        "populated envelope key SET must equal {{total, \
             disputes_opened_total, disputes}}",
    );
    assert!(
        obj_pop.get("total").is_some_and(|x| x.is_u64()),
        "populated total is strict u64",
    );
    assert_eq!(
        obj_pop.get("total").and_then(|x| x.as_u64()),
        Some(1),
        "populated total reflects the inserted dispute count (1)",
    );
    assert!(
        obj_pop
            .get("disputes_opened_total")
            .is_some_and(|x| x.is_u64()),
        "populated disputes_opened_total is strict u64",
    );
    assert_eq!(
        obj_pop
            .get("disputes_opened_total")
            .and_then(|x| x.as_u64()),
        Some(42),
        "populated disputes_opened_total reflects the atomic value (42)",
    );
    assert!(
        obj_pop.get("disputes").is_some_and(|x| x.is_array()),
        "populated disputes is JSON Array",
    );
}

// ─── Density-lift on
//     `compute_list_challenges` (explorer.rs:3428) — symmetric companion
//     to the `compute_list_disputes` work.
//
//     Previous coverage was only a fresh-state envelope (1 test);
//     the status-filter branch at L3436 AND the `filed_total`-vs-`total`
//     orthogonality were 100% unpinned. The five axes here cover
//     `compute_list_challenges`: this is the natural symmetric companion of
//     `compute_list_disputes`. SAME 5-axis design — adapted for the
//     DIFFERENT filter contract on this helper.
//
//   KEY DIFFERENCE FROM DISPUTES: this helper's filter is
//   `c.status.as_str() == sf` (STRICT BYTE EQUALITY against the
//   snake_case `as_str()` form), NOT `format!("{:?}", d.status)
//   .to_lowercase()` like disputes uses. So:
//     - filter IS case-SENSITIVE (axis 2, opposite of disputes axis 2)
//     - filter MATCHES the snake_case JSON form (axis 3, opposite of
//       disputes axis 3)
//
//   Documenting this divergence in-test is load-bearing for the
//   "align filter to JSON form" recommendation — this helper is
//   already on the right side of that recommendation; if a future
//   refactor "harmonized" both helpers to disputes' (currently latent
//   mismatch) contract it would BREAK this helper's wire-form behavior.
//   Pinning the contract here forces that decision to be explicit.

/// Build a stub Challenge with the given id + status. All other fields
/// take stub-friendly defaults. Bypasses `file_challenge`'s VRF jury
/// selection — these tests only exercise the helper's read path against
/// in-memory state, not the file-side jury machinery.
fn stub_challenge(
    id: &str,
    accused: &str,
    status: crate::network::fisherman::ChallengeStatus,
    filed_at: f64,
) -> crate::network::fisherman::Challenge {
    crate::network::fisherman::Challenge {
        id: id.to_string(),
        challenger: format!("challenger-{id}"),
        accused: accused.to_string(),
        challenge_type: crate::network::fisherman::ChallengeType::Spam,
        evidence: Vec::new(),
        structured_evidence: Vec::new(),
        filed_at,
        status,
        jury: Vec::new(),
        votes: Vec::new(),
        is_appeal: false,
        verdict: None,
        verdict_at: None,
        slash_amount: None,
    }
}

#[test]
fn batch_ww_compute_list_challenges_status_filter_subsets_to_matching_status_only() {
    // Populate state with 3 challenges in 3 DISTINCT statuses
    // (Filed / Verdict / Dismissed — three orthogonal terminal-ish
    // states), then sweep each filter form and verify exact subset.
    // Symmetric to the disputes status-filter pin.
    let state = test_state();
    {
        let mut chs = state.challenges.write_recover();
        chs.challenges.insert(
            "c-filed-ww".into(),
            stub_challenge(
                "c-filed-ww",
                "accused-a",
                crate::network::fisherman::ChallengeStatus::Filed,
                10_000.0,
            ),
        );
        chs.challenges.insert(
            "c-verdict-ww".into(),
            stub_challenge(
                "c-verdict-ww",
                "accused-b",
                crate::network::fisherman::ChallengeStatus::Verdict,
                10_001.0,
            ),
        );
        chs.challenges.insert(
            "c-dismissed-ww".into(),
            stub_challenge(
                "c-dismissed-ww",
                "accused-c",
                crate::network::fisherman::ChallengeStatus::Dismissed,
                10_002.0,
            ),
        );
    }
    // No filter — baseline 3-challenge populated state.
    let v_all = compute_list_challenges(state.clone(), None, None);
    assert_eq!(
        v_all.get("total").and_then(|x| x.as_u64()),
        Some(3),
        "no-filter must return all 3 challenges — populated baseline",
    );
    // Filter "filed" returns ONLY the Filed challenge.
    let v_filed = compute_list_challenges(state.clone(), Some("filed".into()), None);
    assert_eq!(
        v_filed.get("total").and_then(|x| x.as_u64()),
        Some(1),
        "status=filed filter must return exactly 1 challenge (only Filed)",
    );
    let arr = v_filed
        .get("challenges")
        .and_then(|x| x.as_array())
        .expect("challenges array");
    assert_eq!(arr.len(), 1, "challenges array length must mirror total");
    assert_eq!(
        arr[0].get("id").and_then(|x| x.as_str()),
        Some("c-filed-ww"),
        "the single returned challenge MUST be the Filed one (not a \
             Verdict or Dismissed entry that leaked through the filter)",
    );
    assert_eq!(
        arr[0].get("status").and_then(|x| x.as_str()),
        Some("filed"),
        "returned challenge's status field is \"filed\" (snake_case JSON)",
    );
    // Filter "verdict" — only the Verdict challenge.
    let v_verdict = compute_list_challenges(state.clone(), Some("verdict".into()), None);
    assert_eq!(
        v_verdict.get("total").and_then(|x| x.as_u64()),
        Some(1),
        "status=verdict must return exactly 1 challenge",
    );
    assert_eq!(
        v_verdict
            .get("challenges")
            .and_then(|x| x.as_array())
            .unwrap()[0]
            .get("id")
            .and_then(|x| x.as_str()),
        Some("c-verdict-ww"),
        "the single returned challenge MUST be the Verdict one",
    );
    // Filter "dismissed" — only the Dismissed challenge.
    let v_dismissed = compute_list_challenges(state, Some("dismissed".into()), None);
    assert_eq!(
        v_dismissed.get("total").and_then(|x| x.as_u64()),
        Some(1),
        "status=dismissed must return exactly 1 challenge",
    );
    assert_eq!(
        v_dismissed
            .get("challenges")
            .and_then(|x| x.as_array())
            .unwrap()[0]
            .get("id")
            .and_then(|x| x.as_str()),
        Some("c-dismissed-ww"),
        "the single returned challenge MUST be the Dismissed one",
    );
}

#[test]
fn batch_ww_compute_list_challenges_status_filter_is_case_sensitive_opposite_contract_from_disputes(
) {
    // OPPOSITE CONTRACT FROM DISPUTES. The filter at L3437 is
    // `c.status.as_str() == sf` — STRICT byte-equality, NO
    // `.to_lowercase()` on the caller string. So:
    //   - filter "filed" MATCHES the Filed status
    //   - filter "FILED" / "Filed" / "fIlEd" all DO NOT MATCH
    //
    // The disputes case-filter test pinned the OPPOSITE (case-INsensitive)
    // because compute_list_disputes uses `.to_lowercase()`. Pinning the
    // case-SENSITIVE contract here is load-bearing: a regression that
    // added `.to_lowercase()` "for symmetry with disputes" would silently
    // change which `?status=...` URLs match on this helper (any operator
    // typing `?status=Filed` would suddenly start matching where it
    // previously returned 0).
    let state = test_state();
    {
        let mut chs = state.challenges.write_recover();
        chs.challenges.insert(
            "c-case-test".into(),
            stub_challenge(
                "c-case-test",
                "accused-x",
                crate::network::fisherman::ChallengeStatus::Filed,
                11_000.0,
            ),
        );
    }
    // Sanity — canonical lowercase "filed" matches.
    let v_canonical = compute_list_challenges(state.clone(), Some("filed".into()), None);
    assert_eq!(
        v_canonical.get("total").and_then(|x| x.as_u64()),
        Some(1),
        "canonical \"filed\" MUST match the Filed challenge",
    );
    // Every other casing MUST return 0 — case-sensitive filter contract.
    for casing in ["FILED", "Filed", "fIlEd", "fileD", "FiLeD"] {
        let v = compute_list_challenges(state.clone(), Some(casing.to_string()), None);
        assert_eq!(
            v.get("total").and_then(|x| x.as_u64()),
            Some(0),
            "filter `{casing}` MUST return 0 challenges — pins the \
                 case-SENSITIVE contract at L3437 (`c.status.as_str() == sf`, \
                 NO caller-side `.to_lowercase()`); a regression to \
                 case-insensitive matching would surface here. Note: this \
                 is OPPOSITE the compute_list_disputes contract (Batch-VV \
                 axis 2 pinned that filter as case-INsensitive).",
        );
    }
}

#[test]
fn batch_ww_compute_list_challenges_multi_word_status_filter_uses_snake_case_not_debug_form() {
    // OPPOSITE CONTRACT FROM DISPUTES. Challenge's filter at L3437 uses
    // `c.status.as_str()` which returns snake_case ("jury_voting") via
    // the hand-written `ChallengeStatus::as_str` impl at
    // fisherman.rs:110. Dispute's filter at explorer.rs:2296 uses
    // `format!("{:?}", d.status).to_lowercase()` which produces
    // "evidencephase" (Debug-form, no underscore).
    //
    // So for challenges:
    //   - filter "jury_voting" (snake_case)        MATCHES JuryVoting
    //   - filter "juryvoting"  (Debug-form lower)  DOES NOT MATCH
    //
    // This is the contract a account would NATURALLY form from the JSON
    // response — `?status=jury_voting` works. The audit closure-note
    // recommended FIXING the disputes helper to behave like THIS helper
    // (via `serde_json::to_value(&d.status).as_str()`); pinning the
    // snake_case match here forces that direction to be the audit's
    // intent (NOT the other direction, i.e. NOT switching this helper
    // to Debug-form to match disputes).
    let state = test_state();
    {
        let mut chs = state.challenges.write_recover();
        chs.challenges.insert(
            "c-jury-voting".into(),
            stub_challenge(
                "c-jury-voting",
                "accused-y",
                crate::network::fisherman::ChallengeStatus::JuryVoting,
                12_000.0,
            ),
        );
    }
    // The wire JSON form for JuryVoting is "jury_voting" via the
    // hand-written `as_str()` impl at fisherman.rs:112-119.
    let v_no_filter = compute_list_challenges(state.clone(), None, None);
    let arr = v_no_filter
        .get("challenges")
        .and_then(|x| x.as_array())
        .unwrap();
    assert_eq!(
        arr[0].get("status").and_then(|x| x.as_str()),
        Some("jury_voting"),
        "wire JSON form for JuryVoting is snake_case \"jury_voting\" \
             (via ChallengeStatus::as_str at fisherman.rs:113)",
    );
    // Filter "jury_voting" (snake_case JSON form) MUST MATCH — pins
    // that this helper's filter uses the same JSON form as the wire,
    // unlike compute_list_disputes (which uses Debug form).
    let v_snake = compute_list_challenges(state.clone(), Some("jury_voting".into()), None);
    assert_eq!(
        v_snake.get("total").and_then(|x| x.as_u64()),
        Some(1),
        "filter `jury_voting` (snake_case JSON form) MUST match — pins \
             L3437 `c.status.as_str() == sf` contract; this is the \
             contract a account would naturally form from the JSON response. \
             OPPOSITE the compute_list_disputes Debug-form contract per \
             Batch-VV axis 3 (which is a latent mismatch the §465 closure \
             recommends fixing).",
    );
    // Filter "juryvoting" (Debug-form lowercase, NO underscore) MUST
    // NOT MATCH — distinguishes this helper's snake_case-form contract
    // from disputes' Debug-form contract. A future refactor that
    // "harmonized" this helper to use Debug form (e.g. by switching to
    // `format!("{:?}", c.status).to_lowercase()`) would surface as
    // this test flipping (total=1 → 0 inversion under the inverted form).
    let v_debug = compute_list_challenges(state, Some("juryvoting".into()), None);
    assert_eq!(
        v_debug.get("total").and_then(|x| x.as_u64()),
        Some(0),
        "filter `juryvoting` (Debug-form lowercase, no underscore) MUST \
             NOT match — pins that this helper uses snake_case form, NOT \
             the Debug form that compute_list_disputes uses. Documents the \
             contract divergence between the two helpers.",
    );
}

#[test]
fn batch_ww_compute_list_challenges_filed_total_counter_orthogonal_to_total_array_length() {
    // Bump `challenges_filed_total` atomic to 19 via `fetch_add` (simulates
    // historical files whose challenges were since finalized-and-pruned
    // or moved through the appeal lifecycle). Populate state with EXACTLY
    // 3 active challenges. Expected: `total=3` (array length) AND
    // `filed_total=19` (counter) — sourced INDEPENDENTLY: counter from
    // atomic, total from challenges.len(). The values 19/3 are coprime so
    // a regression aliasing `total = filed_total / k` for any small k
    // also surfaces here. An existing fresh-state test (0==0) cannot
    // detect this aliasing. Symmetric to the disputes counter-independence pin.
    let state = test_state();
    state
        .challenges_filed_total
        .fetch_add(19, std::sync::atomic::Ordering::Relaxed);
    {
        let mut chs = state.challenges.write_recover();
        for i in 0..3 {
            chs.challenges.insert(
                format!("c-orth-{i}"),
                stub_challenge(
                    &format!("c-orth-{i}"),
                    &format!("accused-orth-{i}"),
                    crate::network::fisherman::ChallengeStatus::Filed,
                    13_000.0 + i as f64,
                ),
            );
        }
    }
    let v = compute_list_challenges(state, None, None);
    assert_eq!(
        v.get("total").and_then(|x| x.as_u64()),
        Some(3),
        "total reflects the IN-MEMORY challenges.len() (3 active), NOT \
             the lifetime counter",
    );
    assert_eq!(
        v.get("filed_total").and_then(|x| x.as_u64()),
        Some(19),
        "filed_total reflects the LIFETIME atomic counter (19), NOT the \
             current in-memory array length",
    );
    assert_eq!(
        v.get("challenges")
            .and_then(|x| x.as_array())
            .map(|a| a.len()),
        Some(3),
        "challenges array length mirrors total (3), NOT filed_total (19)",
    );
}

#[test]
fn batch_ww_compute_list_challenges_envelope_exactly_three_keys_with_strict_u64_counters() {
    // Pin top-level envelope shape on BOTH empty AND populated branches:
    //   - Object with EXACTLY 3 keys: total / filed_total / challenges
    //   - total: strict u64 (catches f64 promotion from a downstream
    //     rate-per-sec accumulator)
    //   - filed_total: strict u64 (same)
    //   - challenges: JSON Array (empty array on fresh state, NOT null;
    //     populated array under load)
    //
    // Empty-branch shape is covered by an earlier pin; re-pinned here in
    // CONJUNCTION with the populated branch so a regression that holds
    // shape only on one branch (e.g. a `match` on challenges.len() that
    // emits a different envelope on empty vs populated) is detectable.
    // Symmetric to the disputes empty/populated shape pin.
    //
    // Empty branch.
    let state_empty = test_state();
    let v_empty = compute_list_challenges(state_empty, None, None);
    let obj_empty = v_empty
        .as_object()
        .expect("compute_list_challenges returns Object");
    assert_eq!(
        obj_empty.len(),
        3,
        "fresh-state envelope MUST have EXACTLY 3 top-level keys; got \
             {} keys: {:?}",
        obj_empty.len(),
        obj_empty.keys().collect::<Vec<_>>(),
    );
    let expected_keys: std::collections::HashSet<&str> = ["total", "filed_total", "challenges"]
        .iter()
        .copied()
        .collect();
    let actual_keys: std::collections::HashSet<&str> =
        obj_empty.keys().map(|k| k.as_str()).collect();
    assert_eq!(
        actual_keys, expected_keys,
        "fresh-state envelope key SET must equal {{total, filed_total, \
             challenges}}",
    );
    assert!(
        obj_empty.get("total").is_some_and(|x| x.is_u64()),
        "fresh-state total is strict u64 (not f64 / not String)",
    );
    assert!(
        obj_empty.get("filed_total").is_some_and(|x| x.is_u64()),
        "fresh-state filed_total is strict u64",
    );
    assert!(
        obj_empty.get("challenges").is_some_and(|x| x.is_array()),
        "fresh-state challenges is JSON Array (NOT null, NOT missing)",
    );

    // Populated branch — re-pin SAME contract under load to catch a
    // branch-dependent envelope regression.
    let state_pop = test_state();
    state_pop
        .challenges_filed_total
        .fetch_add(42, std::sync::atomic::Ordering::Relaxed);
    {
        let mut chs = state_pop.challenges.write_recover();
        chs.challenges.insert(
            "c-env-1".into(),
            stub_challenge(
                "c-env-1",
                "accused-env",
                crate::network::fisherman::ChallengeStatus::Filed,
                14_000.0,
            ),
        );
    }
    let v_pop = compute_list_challenges(state_pop, None, None);
    let obj_pop = v_pop
        .as_object()
        .expect("populated compute_list_challenges returns Object");
    assert_eq!(
        obj_pop.len(),
        3,
        "populated envelope MUST have EXACTLY 3 top-level keys (same \
             as fresh state — no branch-dependent shape drift)",
    );
    let actual_keys_pop: std::collections::HashSet<&str> =
        obj_pop.keys().map(|k| k.as_str()).collect();
    assert_eq!(
        actual_keys_pop, expected_keys,
        "populated envelope key SET must equal {{total, filed_total, \
             challenges}}",
    );
    assert!(
        obj_pop.get("total").is_some_and(|x| x.is_u64()),
        "populated total is strict u64",
    );
    assert_eq!(
        obj_pop.get("total").and_then(|x| x.as_u64()),
        Some(1),
        "populated total reflects the inserted challenge count (1)",
    );
    assert!(
        obj_pop.get("filed_total").is_some_and(|x| x.is_u64()),
        "populated filed_total is strict u64",
    );
    assert_eq!(
        obj_pop.get("filed_total").and_then(|x| x.as_u64()),
        Some(42),
        "populated filed_total reflects the atomic value (42)",
    );
    assert!(
        obj_pop.get("challenges").is_some_and(|x| x.is_array()),
        "populated challenges is JSON Array",
    );
}

#[test]
fn batch_ww_compute_list_challenges_bounds_returned_rows_while_total_reports_true_count() {
    // Public-surface response bound: the challenge map is reachable over the PQ
    // `list_challenges` verb by any handshaked peer and — unlike disputes
    // (capped at MAX_DISPUTES) — keeps active AND historical challenges with no
    // prune, so a single call must not dump the whole history. `limit` bounds
    // the returned `challenges` array while `total` reports the TRUE
    // (status-filtered) count so a caller detects truncation as
    // `challenges.len() < total`. Rows are ordered by id for a deterministic
    // page. Envelope stays {total, filed_total, challenges} — no new key.
    let state = test_state();
    {
        let mut chs = state.challenges.write_recover();
        for i in 0..5u8 {
            let id = format!("ch-{i:02}");
            chs.challenges.insert(
                id.clone(),
                stub_challenge(
                    &id,
                    &format!("accused-{i}"),
                    crate::network::fisherman::ChallengeStatus::Filed,
                    10_000.0 + i as f64,
                ),
            );
        }
    }
    // Request a page smaller than the challenge set.
    let v = compute_list_challenges(state, None, Some(2));
    let obj = v.as_object().expect("compute_list_challenges returns Object");
    let arr = obj["challenges"].as_array().expect("`challenges` MUST be a JSON Array");
    assert_eq!(
        arr.len(),
        2,
        "returned challenges MUST be bounded by the requested limit",
    );
    assert_eq!(
        obj.get("total").and_then(|x| x.as_u64()),
        Some(5),
        "`total` MUST report the TRUE challenge count regardless of the page cap",
    );
    // Deterministic ordering — lowest id first ("ch-00","ch-01").
    assert_eq!(
        arr[0].get("id").and_then(|x| x.as_str()),
        Some("ch-00"),
        "page MUST be ordered by id — first row is the lowest",
    );
    assert_eq!(
        arr[1].get("id").and_then(|x| x.as_str()),
        Some("ch-01"),
        "page MUST be ordered by id — second row is the next lowest",
    );
}

// ── +5 tests on `compute_challenge_detail` (explorer.rs:3469) ───────────────────────────────
//   — the companion to the `compute_dispute_detail` work and the
//   symmetric output-side pin to the filter-side `compute_list_
//   challenges` work. Previously only an unknown-id in-band
//   error envelope was pinned (1 test); the entire happy-path
//   serialization branch at L3480-3494 (13 keys) was 100% unpinned.
//   Covers the `compute_challenge_detail` happy-path continuation.
//
//   Axes orthogonal:
//     (1) Filed status — full 13-key envelope strict type pin
//     (2) votes inline 3-key Object contract (handcoded NOT serde-derive)
//     (3) Verdict status — non-null Option<bool>/Option<f64>/Option<u64>
//     (4) status as_str wire contract — all 6 ChallengeStatus variants
//     (5) challenge_type as_str wire contract — all 4 ChallengeType variants

#[test]
fn batch_xx_compute_challenge_detail_filed_full_thirteen_field_envelope_strict_types() {
    // Insert a Filed-status challenge with no votes / verdict / appeal,
    // query via compute_challenge_detail, verify the round-tripped JSON
    // has all 13 fields with strict types:
    //   id              → JSON String
    //   challenger      → JSON String
    //   accused         → JSON String
    //   challenge_type  → JSON String  (via ChallengeType::as_str())
    //   status          → JSON String  (via ChallengeStatus::as_str())
    //   filed_at        → JSON Number  (f64)
    //   evidence        → JSON Array
    //   jury            → JSON Array
    //   votes           → JSON Array
    //   verdict         → JSON Null    (Option::None → Value::Null)
    //   verdict_at      → JSON Null
    //   is_appeal       → JSON Bool    (false)
    //   slash_amount    → JSON Null
    // A missing key would silently break account decoding; an extra
    // key would silently bloat the challenge-detail wire shape.
    let state = test_state();
    {
        let mut chs = state.challenges.write_recover();
        chs.challenges.insert(
            "c-filed-xx".into(),
            stub_challenge(
                "c-filed-xx",
                "accused-x",
                crate::network::fisherman::ChallengeStatus::Filed,
                12_345.5,
            ),
        );
    }
    let v = compute_challenge_detail(state, "c-filed-xx".into());
    let obj = v
        .as_object()
        .expect("compute_challenge_detail must return JSON Object");
    let expected_keys: std::collections::HashSet<&str> = [
        "id",
        "challenger",
        "accused",
        "challenge_type",
        "status",
        "filed_at",
        "evidence",
        "jury",
        "votes",
        "verdict",
        "verdict_at",
        "is_appeal",
        "slash_amount",
    ]
    .iter()
    .copied()
    .collect();
    let actual_keys: std::collections::HashSet<&str> = obj.keys().map(|k| k.as_str()).collect();
    assert_eq!(
        actual_keys, expected_keys,
        "envelope key SET must equal the 13 documented fields — \
             a missing key would silently break account decoding, an extra \
             key would silently bloat 100K-record explorer feeds",
    );
    // Strict-type pin on every field
    assert_eq!(
        obj.get("id").and_then(|x| x.as_str()),
        Some("c-filed-xx"),
        "id is String + value-identity round-trip"
    );
    assert_eq!(
        obj.get("challenger").and_then(|x| x.as_str()),
        Some("challenger-c-filed-xx"),
        "challenger is String (stub helper formats as challenger-<id>)"
    );
    assert_eq!(
        obj.get("accused").and_then(|x| x.as_str()),
        Some("accused-x"),
        "accused is String"
    );
    assert_eq!(
        obj.get("challenge_type").and_then(|x| x.as_str()),
        Some("spam"),
        "challenge_type via ChallengeType::as_str() — Spam → \"spam\""
    );
    assert_eq!(
        obj.get("status").and_then(|x| x.as_str()),
        Some("filed"),
        "status via ChallengeStatus::as_str() — Filed → \"filed\""
    );
    assert_eq!(
        obj.get("filed_at").and_then(|x| x.as_f64()),
        Some(12_345.5),
        "filed_at is JSON Number (f64) — accounts order challenges \
             by timestamp numerically, a String regression would break sort"
    );
    assert!(
        obj.get("evidence").is_some_and(|x| x.is_array()),
        "evidence is JSON Array (empty on a fresh Filed challenge)"
    );
    assert_eq!(
        obj.get("evidence")
            .and_then(|x| x.as_array())
            .map(|a| a.len()),
        Some(0),
        "fresh Filed challenge has no evidence — array empty"
    );
    assert!(
        obj.get("jury").is_some_and(|x| x.is_array()),
        "jury is JSON Array (empty pre-JuryVoting status)"
    );
    assert_eq!(
        obj.get("jury").and_then(|x| x.as_array()).map(|a| a.len()),
        Some(0),
        "no jury selected yet — array empty"
    );
    assert!(
        obj.get("votes").is_some_and(|x| x.is_array()),
        "votes is JSON Array"
    );
    assert_eq!(
        obj.get("votes").and_then(|x| x.as_array()).map(|a| a.len()),
        Some(0),
        "no votes yet — array empty"
    );
    // Three Option fields all None → JSON Null (NOT omitted, NOT empty
    // string, NOT default zero — accounts distinguish "no verdict yet"
    // from "verdict = false" via this contract).
    assert!(
        obj.get("verdict").is_some_and(|x| x.is_null()),
        "verdict (Option::None) must serialize as JSON Null — \
             a #[serde(skip_serializing_if = \"Option::is_none\")] regression \
             would silently drop the key, breaking accounts that read it"
    );
    assert!(
        obj.get("verdict_at").is_some_and(|x| x.is_null()),
        "verdict_at (Option::None) must serialize as JSON Null"
    );
    assert!(
        obj.get("slash_amount").is_some_and(|x| x.is_null()),
        "slash_amount (Option::None) must serialize as JSON Null"
    );
    assert!(
        obj.get("is_appeal").is_some_and(|x| x.is_boolean()),
        "is_appeal is JSON Bool"
    );
    assert_eq!(
        obj.get("is_appeal").and_then(|x| x.as_bool()),
        Some(false),
        "stub challenge initialized is_appeal=false"
    );
}

#[test]
fn batch_xx_compute_challenge_detail_votes_inline_three_key_juror_guilty_timestamp_contract() {
    // The votes array is built INLINE at explorer.rs:3476-3478 via a
    // handcoded json!() 3-key object per vote, NOT via the auto-derived
    // Serialize impl on JuryVote (fisherman.rs:122-131). This means:
    //   (a) the wire shape is FROZEN at 3 keys (juror/guilty/timestamp)
    //       even if JuryVote gains a 4th field in fisherman.rs (a future
    //       `vote_weight` or `signature` would NOT leak through);
    //   (b) a account relying on JuryVote's #[derive(Serialize)] format
    //       would break if the derive ever switched to renamed/flattened
    //       form — but this helper's wire shape stays stable.
    // Pin the inline 3-key contract directly with three distinct votes.
    use crate::network::fisherman::JuryVote;
    let state = test_state();
    {
        let mut chs = state.challenges.write_recover();
        let mut ch = stub_challenge(
            "c-votes-xx",
            "accused-v",
            crate::network::fisherman::ChallengeStatus::JuryVoting,
            22_000.0,
        );
        // Three votes with distinct (juror, guilty, timestamp) triples
        // so position-dependent regressions surface (e.g. a regression
        // that emitted votes[i] = votes[0] for all i would pass any
        // single-vote test but fail this 3-vote element-wise check).
        ch.votes.push(JuryVote {
            juror: "juror-alice".into(),
            guilty: true,
            timestamp: 22_100.0,
        });
        ch.votes.push(JuryVote {
            juror: "juror-bob".into(),
            guilty: false,
            timestamp: 22_200.0,
        });
        ch.votes.push(JuryVote {
            juror: "juror-carol".into(),
            guilty: true,
            timestamp: 22_300.0,
        });
        chs.challenges.insert("c-votes-xx".into(), ch);
    }
    let v = compute_challenge_detail(state, "c-votes-xx".into());
    let votes_arr = v
        .get("votes")
        .and_then(|x| x.as_array())
        .expect("votes is JSON Array");
    assert_eq!(votes_arr.len(), 3, "all 3 inserted votes must round-trip");

    // Each vote element must be exactly 3 keys (frozen wire shape)
    let expected_vote_keys: std::collections::HashSet<&str> =
        ["juror", "guilty", "timestamp"].iter().copied().collect();
    for (i, vote) in votes_arr.iter().enumerate() {
        let vote_obj = vote
            .as_object()
            .expect("each vote element is a JSON Object");
        let actual_keys: std::collections::HashSet<&str> =
            vote_obj.keys().map(|k| k.as_str()).collect();
        assert_eq!(
            actual_keys, expected_vote_keys,
            "vote[{i}] keys must equal {{juror, guilty, timestamp}} — \
                 a 4th key would mean JuryVote's #[derive(Serialize)] leaked \
                 through, breaking the inline-mapping contract at L3477",
        );
        assert!(
            vote_obj.get("juror").is_some_and(|x| x.is_string()),
            "vote[{i}].juror is String"
        );
        assert!(
            vote_obj.get("guilty").is_some_and(|x| x.is_boolean()),
            "vote[{i}].guilty is JSON Bool (NOT 1/0 number, \
                 NOT \"true\"/\"false\" string)"
        );
        assert!(
            vote_obj
                .get("timestamp")
                .is_some_and(|x| x.is_f64() || x.is_i64() || x.is_u64()),
            "vote[{i}].timestamp is JSON Number"
        );
    }
    // Element-wise round-trip — guilty must be VALUE-correct per index
    assert_eq!(
        votes_arr[0].get("juror").and_then(|x| x.as_str()),
        Some("juror-alice")
    );
    assert_eq!(
        votes_arr[0].get("guilty").and_then(|x| x.as_bool()),
        Some(true)
    );
    assert_eq!(
        votes_arr[0].get("timestamp").and_then(|x| x.as_f64()),
        Some(22_100.0)
    );
    assert_eq!(
        votes_arr[1].get("juror").and_then(|x| x.as_str()),
        Some("juror-bob")
    );
    assert_eq!(
        votes_arr[1].get("guilty").and_then(|x| x.as_bool()),
        Some(false)
    );
    assert_eq!(
        votes_arr[1].get("timestamp").and_then(|x| x.as_f64()),
        Some(22_200.0)
    );
    assert_eq!(
        votes_arr[2].get("juror").and_then(|x| x.as_str()),
        Some("juror-carol")
    );
    assert_eq!(
        votes_arr[2].get("guilty").and_then(|x| x.as_bool()),
        Some(true)
    );
    assert_eq!(
        votes_arr[2].get("timestamp").and_then(|x| x.as_f64()),
        Some(22_300.0)
    );
}

#[test]
fn batch_xx_compute_challenge_detail_verdict_status_emits_non_null_verdict_verdict_at_slash_amount()
{
    // When a challenge reaches Verdict status, the three Option fields
    // (verdict / verdict_at / slash_amount) populate. Pin that:
    //   - Option::Some<bool> → JSON Bool  (NOT {"Some":true} object,
    //                                       NOT "true" string)
    //   - Option::Some<f64>  → JSON Number
    //   - Option::Some<u64>  → JSON Number with STRICT is_u64() contract
    // A regression to #[serde(tag="...")] on Option<T> would silently
    // flip all three field shapes. Companion to the disputes
    // Resolved-status non-null resolution sub-object pin.
    let state = test_state();
    {
        let mut chs = state.challenges.write_recover();
        let mut ch = stub_challenge(
            "c-verdict-xx",
            "accused-w",
            crate::network::fisherman::ChallengeStatus::Verdict,
            33_000.0,
        );
        ch.verdict = Some(true);
        ch.verdict_at = Some(33_500.0);
        ch.slash_amount = Some(1_000_000_u64);
        ch.is_appeal = false;
        chs.challenges.insert("c-verdict-xx".into(), ch);
    }
    let v = compute_challenge_detail(state, "c-verdict-xx".into());

    // verdict: Some(true) → JSON Bool true
    assert!(
        v.get("verdict").is_some_and(|x| x.is_boolean()),
        "verdict (Option::Some<bool>) must serialize as JSON Bool, \
             not a Some-wrapper object or a string"
    );
    assert_eq!(
        v.get("verdict").and_then(|x| x.as_bool()),
        Some(true),
        "verdict value round-trips Some(true) → JSON true"
    );

    // verdict_at: Some(33_500.0) → JSON Number
    assert!(
        v.get("verdict_at")
            .is_some_and(|x| x.is_f64() || x.is_i64() || x.is_u64()),
        "verdict_at (Option::Some<f64>) must serialize as JSON Number"
    );
    assert_eq!(
        v.get("verdict_at").and_then(|x| x.as_f64()),
        Some(33_500.0),
        "verdict_at value round-trips Some(33_500.0)"
    );

    // slash_amount: Some(1_000_000) → JSON Number with strict u64 contract
    assert!(
        v.get("slash_amount").is_some_and(|x| x.is_u64()),
        "slash_amount (Option::Some<u64>) must serialize with strict \
             is_u64() wire type, NOT f64 — silent floating-point precision \
             loss at >2^53 base units would corrupt slash accounting; \
             slash_percent at fisherman.rs:45 can produce slashes well above \
             2^53 at 1M-zone scale (50% of total staked supply caps in the \
             billions of base units for a single CartelFormation challenge)"
    );
    assert_eq!(
        v.get("slash_amount").and_then(|x| x.as_u64()),
        Some(1_000_000),
        "slash_amount value round-trips Some(1_000_000)"
    );

    // Status echoes Verdict as snake_case
    assert_eq!(
        v.get("status").and_then(|x| x.as_str()),
        Some("verdict"),
        "Verdict status echoes as snake_case \"verdict\""
    );
    // is_appeal still false on first verdict (Appeal status would set
    // is_appeal=true on the second-round challenge); pin the field
    // separation explicitly.
    assert_eq!(
        v.get("is_appeal").and_then(|x| x.as_bool()),
        Some(false),
        "first-round Verdict has is_appeal=false (Appeal is a distinct \
             ChallengeStatus, not a flag on the original Verdict)"
    );
}

#[test]
fn batch_xx_compute_challenge_detail_status_as_str_all_six_variants_distinct_wire_strings() {
    // ChallengeStatus has 6 variants (fisherman.rs:94-107):
    //   Filed / JuryVoting / Verdict / Appeal / Final / Dismissed
    // The helper emits c.status.as_str() at explorer.rs:3485, which
    // calls the hand-written as_str() method at fisherman.rs:110-119
    // (NOT serde). Pin all 6 wire strings:
    //   Filed       → "filed"
    //   JuryVoting  → "jury_voting"   (snake_case, NOT "juryvoting" Debug form)
    //   Verdict     → "verdict"
    //   Appeal      → "appeal"
    //   Final       → "final"
    //   Dismissed   → "dismissed"
    // Symmetric to the filter-side test which pins the FILTER side; this
    // pins the OUTPUT side. A future ChallengeStatus variant rename
    // would surface here AND at the filter site simultaneously,
    // making the impact-radius of the change visible from the test
    // failure log alone.
    use crate::network::fisherman::ChallengeStatus;
    let state = test_state();
    let cases = [
        ("c-status-filed", ChallengeStatus::Filed, "filed"),
        ("c-status-jury", ChallengeStatus::JuryVoting, "jury_voting"),
        ("c-status-verdict", ChallengeStatus::Verdict, "verdict"),
        ("c-status-appeal", ChallengeStatus::Appeal, "appeal"),
        ("c-status-final", ChallengeStatus::Final, "final"),
        (
            "c-status-dismissed",
            ChallengeStatus::Dismissed,
            "dismissed",
        ),
    ];
    {
        let mut chs = state.challenges.write_recover();
        for (id, status, _) in &cases {
            chs.challenges.insert(
                (*id).into(),
                stub_challenge(id, "accused-s", status.clone(), 44_000.0),
            );
        }
    }
    let mut outputs: Vec<String> = Vec::new();
    for (id, _, expected) in &cases {
        let v = compute_challenge_detail(state.clone(), (*id).to_string());
        let actual = v
            .get("status")
            .and_then(|x| x.as_str())
            .expect("status field is JSON String");
        assert_eq!(
            actual, *expected,
            "ChallengeStatus variant for {id} must serialize as \
                 \"{expected}\" — pins the hand-written as_str() table at \
                 fisherman.rs:110-119",
        );
        outputs.push(actual.to_string());
    }
    // Mutually distinct (6 variants → 6 distinct strings via HashSet)
    let unique: std::collections::HashSet<&String> = outputs.iter().collect();
    assert_eq!(
        unique.len(),
        6,
        "all 6 ChallengeStatus variants must produce DISTINCT wire \
             strings — a future regression aliasing two variants (e.g. both \
             Filed and JuryVoting returning \"filed\") would silently \
             collapse status reporting in operator dashboards, masking which \
             stage of the lifecycle a challenge is actually in",
    );
}

#[test]
fn batch_xx_compute_challenge_detail_challenge_type_as_str_all_four_variants_distinct_wire_strings()
{
    // ChallengeType has 4 variants (fisherman.rs:57-68):
    //   Spam / FalseWitnessing / DoubleSigning / CartelFormation
    // The helper emits c.challenge_type.as_str() at explorer.rs:3484,
    // which calls the hand-written as_str() method at fisherman.rs:
    // 81-88 (NOT serde). Pin all 4 wire strings:
    //   Spam            → "spam"
    //   FalseWitnessing → "false_witnessing"  (snake_case)
    //   DoubleSigning   → "double_signing"    (snake_case)
    //   CartelFormation → "cartel_formation"  (snake_case)
    // Wallets compute the displayed slash percentage by mapping
    // challenge_type to slash_percent (fisherman.rs:45-53). A wire-
    // string change would silently flip a 25% slash to 0% for the
    // affected type (the account's lookup table would no-op-default
    // on the unknown string), surfacing as misreported slashes in
    // user-facing UX without any runtime error to flag.
    use crate::network::fisherman::{ChallengeStatus, ChallengeType};
    let state = test_state();
    let cases = [
        ("c-type-spam", ChallengeType::Spam, "spam"),
        (
            "c-type-fw",
            ChallengeType::FalseWitnessing,
            "false_witnessing",
        ),
        ("c-type-ds", ChallengeType::DoubleSigning, "double_signing"),
        (
            "c-type-cf",
            ChallengeType::CartelFormation,
            "cartel_formation",
        ),
    ];
    {
        let mut chs = state.challenges.write_recover();
        for (id, ct, _) in &cases {
            let mut ch = stub_challenge(id, "accused-t", ChallengeStatus::Filed, 55_000.0);
            ch.challenge_type = ct.clone();
            chs.challenges.insert((*id).into(), ch);
        }
    }
    let mut outputs: Vec<String> = Vec::new();
    for (id, _, expected) in &cases {
        let v = compute_challenge_detail(state.clone(), (*id).to_string());
        let actual = v
            .get("challenge_type")
            .and_then(|x| x.as_str())
            .expect("challenge_type field is JSON String");
        assert_eq!(
            actual, *expected,
            "ChallengeType variant for {id} must serialize as \
                 \"{expected}\" — pins fisherman.rs:81-88 as_str() table",
        );
        outputs.push(actual.to_string());
    }
    // Mutually distinct (4 variants → 4 distinct strings)
    let unique: std::collections::HashSet<&String> = outputs.iter().collect();
    assert_eq!(
        unique.len(),
        4,
        "all 4 ChallengeType variants must produce DISTINCT wire \
             strings — a future regression aliasing two variants (e.g. both \
             DoubleSigning and CartelFormation returning the same string) \
             would silently flip the slash percentage applied to those \
             challenges in user-facing account UX",
    );
}

// ─── +6 on compute_vrf_registry ─────────
// Symmetric companion to the challenges list+detail
// pair, pivoting to the VRF-registry surface which was 100% unpinned
// previously. The helper at explorer.rs:1922 is consumed by the
// /admin/vrf_registry endpoint and surfaces the cluster's anchor
// registration table to operators. Five orthogonal axes pin the wire
// contract:
//   (1) fresh-state 4-key envelope strict-type pin
//   (2) lex-sort by identity_hash (HashMap iteration order would
//       scramble entries without the sort_by at L1946-1950)
//   (3) has_full_key boolean wire contract — both true/false branches
//   (4) per-entry 6-key Object strict-type contract (frozen by
//       handcoded json!() not #[derive(Serialize)])
//   (5) count == registrations.len() field-source pin across N sweep
//   (6) response bound — limit caps `registrations` while `count` stays the
//       TRUE total (anti-amplification on the PQ-reachable surface)

#[test]
fn batch_yy_compute_vrf_registry_fresh_state_four_key_envelope_strict_types() {
    // Fresh state with no registrations:
    //   - top-level Object has EXACTLY 4 keys {count, self_identity,
    //     genesis_authority, registrations}
    //   - count is strict u64 (NOT f64), value 0
    //   - registrations is empty Array (NOT null, NOT missing)
    //   - self_identity echoes state.identity.identity_hash byte-for-
    //     byte (one source)
    //   - genesis_authority echoes state.config.genesis_authority
    //     byte-for-byte (a DISTINCT source from self_identity)
    // Catches a regression that emitted `registrations: null` on
    // fresh state (would break operator dashboards that iterate the
    // array), or that swapped the two identity-string sources.
    let state = test_state();
    let v = compute_vrf_registry(state.clone(), None);
    let obj = v.as_object().expect("top-level must be JSON Object");
    let keys: std::collections::BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
    let expected: std::collections::BTreeSet<&str> = [
        "count",
        "self_identity",
        "genesis_authority",
        "registrations",
    ]
    .iter()
    .copied()
    .collect();
    assert_eq!(
        keys, expected,
        "fresh-state envelope must have EXACTLY 4 keys {{count, \
             self_identity, genesis_authority, registrations}} — drift \
             surfaces account-decoder mismatches across the fleet",
    );
    assert!(
        v.get("count").map(|c| c.is_u64()).unwrap_or(false),
        "count must be strict JSON u64 (not f64, not String) — a \
             silent f64-conversion regression at 2^53-anchor scale would \
             corrupt registry sizing",
    );
    assert_eq!(
        v.get("count").and_then(|c| c.as_u64()),
        Some(0),
        "fresh state must report count=0",
    );
    let regs = v.get("registrations").expect("registrations key present");
    assert!(
        regs.is_array(),
        "registrations must be JSON Array on fresh state (NOT null, \
             NOT missing) — a `null` regression would break operator \
             dashboards that iterate this field unconditionally",
    );
    assert_eq!(
        regs.as_array().expect("array").len(),
        0,
        "fresh state registrations must be empty Array",
    );
    assert_eq!(
        v.get("self_identity").and_then(|x| x.as_str()),
        Some(state.identity.identity_hash.as_str()),
        "self_identity must echo state.identity.identity_hash \
             byte-for-byte",
    );
    assert_eq!(
        v.get("genesis_authority").and_then(|x| x.as_str()),
        Some(state.config.genesis_authority.as_str()),
        "genesis_authority must echo state.config.genesis_authority \
             byte-for-byte — distinct source from self_identity; a swap \
             regression would silently break operator's 'am I genesis?' \
             distinction",
    );
    // self_identity and genesis_authority MUST be sourced from
    // different state fields. test_state() generates a fresh
    // identity, config.genesis_authority defaults to the
    // TESTNET_GENESIS_AUTHORITY constant — they will differ.
    assert_ne!(
        v.get("self_identity").and_then(|x| x.as_str()),
        v.get("genesis_authority").and_then(|x| x.as_str()),
        "self_identity and genesis_authority must be distinct in \
             this fixture (generated identity vs. \
             TESTNET_GENESIS_AUTHORITY constant) — equality means the \
             test fixture collapsed or the helper swapped field sources",
    );
}

#[test]
fn batch_yy_compute_vrf_registry_entries_sorted_lex_by_identity_hash() {
    // Register 3 entries in REVERSE-lex insertion order. Output must
    // be lex-sorted ascending. Pins explorer.rs:1946-1950 comparator.
    // HashMap iteration order is non-deterministic, so a regression
    // dropping the sort would silently scramble the list across runs
    // (operator dashboards would show entries in different orders on
    // every refresh, breaking visual diff-spotting against a peer).
    use crate::network::vrf_registry::VrfRegistration;
    let state = test_state();
    let ids = ["zeta-id-zzz", "mu-id-mmm", "alpha-id-aaa"];
    {
        let mut reg = state.vrf_registry.write().expect("registry lock");
        for id in &ids {
            reg.register(
                id,
                VrfRegistration {
                    vrf_public_key_hex: hex::encode([0xAAu8; 32]),
                    vrf_full_public_key_hex: String::new(),
                    registered_at: 1_000.0,
                    record_id: format!("rec-{id}"),
                    node_type: "anchor".into(),
                },
            );
        }
    }
    let v = compute_vrf_registry(state, None);
    let arr = v
        .get("registrations")
        .and_then(|x| x.as_array())
        .expect("registrations is JSON Array");
    assert_eq!(arr.len(), 3, "all 3 entries must surface");
    let actual: Vec<&str> = arr
        .iter()
        .map(|e| {
            e.get("identity_hash")
                .and_then(|x| x.as_str())
                .expect("identity_hash is String")
        })
        .collect();
    assert_eq!(
        actual,
        vec!["alpha-id-aaa", "mu-id-mmm", "zeta-id-zzz"],
        "entries must be lex-sorted ascending by identity_hash — a \
             regression dropping the sort_by at explorer.rs:1946-1950 \
             would surface as HashMap-iteration-order scrambling here \
             (inserted reverse-lex, must come out lex-ascending)",
    );
}

#[test]
fn batch_yy_compute_vrf_registry_has_full_key_boolean_both_branches() {
    // has_full_key at explorer.rs:1939 is
    // `!r.vrf_full_public_key_hex.is_empty()`. Pin both branches:
    //   - empty full_key string → has_full_key=false (JSON Bool)
    //   - non-empty full_key string → has_full_key=true (JSON Bool)
    // Pins the type as JSON Bool (NOT String "true"/"false", NOT
    // Number 1/0). A regression to `r.vrf_full_public_key_hex.len()`
    // would silently render non-empty as Number-truthy but break
    // account decoders that expect strict Bool.
    use crate::network::vrf_registry::VrfRegistration;
    let state = test_state();
    {
        let mut reg = state.vrf_registry.write().expect("registry lock");
        reg.register(
            "id-empty-full",
            VrfRegistration {
                vrf_public_key_hex: hex::encode([0xAAu8; 32]),
                vrf_full_public_key_hex: String::new(),
                registered_at: 1_000.0,
                record_id: "rec-empty-full".into(),
                node_type: "anchor".into(),
            },
        );
        reg.register(
            "id-with-full",
            VrfRegistration {
                vrf_public_key_hex: hex::encode([0xBBu8; 32]),
                vrf_full_public_key_hex: "deadbeef".into(),
                registered_at: 2_000.0,
                record_id: "rec-with-full".into(),
                node_type: "anchor".into(),
            },
        );
    }
    let v = compute_vrf_registry(state, None);
    let arr = v
        .get("registrations")
        .and_then(|x| x.as_array())
        .expect("registrations is JSON Array");
    assert_eq!(arr.len(), 2);
    // Lex-sorted: "id-empty-full" < "id-with-full"
    let empty_entry = &arr[0];
    let full_entry = &arr[1];
    assert_eq!(
        empty_entry.get("identity_hash").and_then(|x| x.as_str()),
        Some("id-empty-full"),
    );
    assert_eq!(
        full_entry.get("identity_hash").and_then(|x| x.as_str()),
        Some("id-with-full"),
    );
    // Type pin: has_full_key MUST be JSON Bool
    let has_full_empty = empty_entry
        .get("has_full_key")
        .expect("has_full_key key present");
    assert!(
        has_full_empty.is_boolean(),
        "has_full_key must be strict JSON Bool — got {:?}",
        has_full_empty,
    );
    assert_eq!(
        has_full_empty.as_bool(),
        Some(false),
        "empty vrf_full_public_key_hex must yield has_full_key=false",
    );
    let has_full_full = full_entry
        .get("has_full_key")
        .expect("has_full_key key present");
    assert!(
        has_full_full.is_boolean(),
        "has_full_key must be strict JSON Bool — got {:?}",
        has_full_full,
    );
    assert_eq!(
        has_full_full.as_bool(),
        Some(true),
        "non-empty vrf_full_public_key_hex must yield \
             has_full_key=true",
    );
}

#[test]
fn batch_yy_compute_vrf_registry_per_entry_six_key_object_strict_types() {
    // Each registration entry MUST be exactly 6 keys with strict
    // types: identity_hash=String, vrf_public_key_hex=String,
    // has_full_key=Bool, registered_at=Number, record_id=String,
    // node_type=String. Pins explorer.rs:1935-1944. Because this
    // helper uses HANDCODED json!() (NOT #[derive(Serialize)] on
    // VrfRegistration), the entry shape is FROZEN at 6 keys
    // irrespective of struct evolution — a 7th VrfRegistration
    // field added in vrf_registry.rs would NOT surface here, and
    // that is the intended decoupling pin.
    use crate::network::vrf_registry::VrfRegistration;
    let state = test_state();
    {
        let mut reg = state.vrf_registry.write().expect("registry lock");
        reg.register(
            "id-single",
            VrfRegistration {
                vrf_public_key_hex: hex::encode([0xCCu8; 32]),
                vrf_full_public_key_hex: "01ab".into(),
                registered_at: 3_141.5,
                record_id: "rec-single".into(),
                node_type: "anchor".into(),
            },
        );
    }
    let v = compute_vrf_registry(state, None);
    let arr = v
        .get("registrations")
        .and_then(|x| x.as_array())
        .expect("registrations is JSON Array");
    assert_eq!(arr.len(), 1);
    let entry = arr[0].as_object().expect("entry must be JSON Object");
    let keys: std::collections::BTreeSet<&str> = entry.keys().map(|s| s.as_str()).collect();
    let expected: std::collections::BTreeSet<&str> = [
        "identity_hash",
        "vrf_public_key_hex",
        "has_full_key",
        "registered_at",
        "record_id",
        "node_type",
    ]
    .iter()
    .copied()
    .collect();
    assert_eq!(
        keys, expected,
        "per-entry envelope MUST be exactly 6 keys — handcoded \
             json!() at explorer.rs:1935-1944 freezes wire shape \
             irrespective of VrfRegistration struct evolution",
    );
    // Strict-type pin for every key
    assert!(
        entry
            .get("identity_hash")
            .map(|v| v.is_string())
            .unwrap_or(false),
        "identity_hash must be JSON String",
    );
    assert!(
        entry
            .get("vrf_public_key_hex")
            .map(|v| v.is_string())
            .unwrap_or(false),
        "vrf_public_key_hex must be JSON String",
    );
    assert!(
        entry
            .get("has_full_key")
            .map(|v| v.is_boolean())
            .unwrap_or(false),
        "has_full_key must be JSON Bool",
    );
    assert!(
        entry
            .get("registered_at")
            .map(|v| v.is_number())
            .unwrap_or(false),
        "registered_at must be JSON Number",
    );
    assert!(
        entry
            .get("record_id")
            .map(|v| v.is_string())
            .unwrap_or(false),
        "record_id must be JSON String",
    );
    assert!(
        entry
            .get("node_type")
            .map(|v| v.is_string())
            .unwrap_or(false),
        "node_type must be JSON String",
    );
    // Pin VALUES too — each field round-trips byte-for-byte from the
    // registered VrfRegistration to the JSON output.
    assert_eq!(
        entry.get("identity_hash").and_then(|x| x.as_str()),
        Some("id-single"),
    );
    assert_eq!(
        entry.get("vrf_public_key_hex").and_then(|x| x.as_str()),
        Some(hex::encode([0xCCu8; 32]).as_str()),
    );
    assert_eq!(
        entry.get("has_full_key").and_then(|x| x.as_bool()),
        Some(true),
        "vrf_full_public_key_hex='01ab' is non-empty → \
             has_full_key=true",
    );
    assert_eq!(
        entry.get("registered_at").and_then(|x| x.as_f64()),
        Some(3_141.5),
    );
    assert_eq!(
        entry.get("record_id").and_then(|x| x.as_str()),
        Some("rec-single"),
    );
    assert_eq!(
        entry.get("node_type").and_then(|x| x.as_str()),
        Some("anchor"),
    );
}

#[test]
fn batch_yy_compute_vrf_registry_count_equals_registrations_len_across_n_sweep() {
    // count at explorer.rs:1953 is sourced from `entries.len()` (the
    // post-filter_map Vec of valid registrations), NOT from
    // `reg.count()` (the registry's internal HashMap len). Both
    // happen to agree when every registered_identity has a valid
    // get_registration result — but the filter_map at
    // explorer.rs:1932-1934 silently drops any identity for which
    // get_registration returns None. So a regression that sourced
    // count from `reg.count()` would surface count > registrations
    // .len() in any state where the registry's internal HashMap and
    // the helper's serialized entries diverge.
    //
    // Pin the same algebraic invariant across N ∈ {0, 1, 3, 5} so
    // a future field-source swap (count ← reg.count()) is caught
    // at every population level. Both happen to agree in the unit-
    // test environment, so this pins the CONTRACT not the failure
    // mode — a `count` re-wired to a different source would have to
    // maintain agreement at every N or fail at least one N here.
    use crate::network::vrf_registry::VrfRegistration;
    for &n in &[0usize, 1, 3, 5] {
        let state = test_state();
        {
            let mut reg = state.vrf_registry.write().expect("registry lock");
            for i in 0..n {
                reg.register(
                    &format!("id-{i:02}"),
                    VrfRegistration {
                        vrf_public_key_hex: hex::encode([i as u8; 32]),
                        vrf_full_public_key_hex: String::new(),
                        registered_at: 1_000.0 + (i as f64),
                        record_id: format!("rec-{i:02}"),
                        node_type: "anchor".into(),
                    },
                );
            }
        }
        let v = compute_vrf_registry(state, None);
        let count = v
            .get("count")
            .and_then(|x| x.as_u64())
            .expect("count is u64");
        let regs_len = v
            .get("registrations")
            .and_then(|x| x.as_array())
            .map(|a| a.len())
            .expect("registrations is Array");
        assert_eq!(
            count as usize, regs_len,
            "count MUST equal registrations.len() at N={n} — field \
                 sourced from entries.len() at explorer.rs:1953, NOT \
                 from reg.count()",
        );
        assert_eq!(
            count as usize, n,
            "count MUST equal the inserted N={n} (sanity check on \
                 register() not deduping by identity_hash collision)",
        );
    }
}

#[test]
fn batch_yy_compute_vrf_registry_bounds_returned_rows_while_count_reports_true_total() {
    // Public-surface response bound: `/vrf/registry` is reachable over the PQ
    // verb by any handshaked peer and grows with the anchor/witness set, so a
    // single call must not dump the whole registry. `limit` bounds the returned
    // `registrations` array while `count` still reports the TRUE total so a
    // caller detects truncation as `registrations.len() < count`. Rows are
    // ordered by identity_hash so the page is a deterministic lowest-first slice.
    use crate::network::vrf_registry::VrfRegistration;
    let state = test_state();
    {
        let mut reg = state.vrf_registry.write().expect("registry lock");
        for i in 0..5usize {
            reg.register(
                &format!("id-{i:02}"),
                VrfRegistration {
                    vrf_public_key_hex: hex::encode([i as u8; 32]),
                    vrf_full_public_key_hex: String::new(),
                    registered_at: 1_000.0 + (i as f64),
                    record_id: format!("rec-{i:02}"),
                    node_type: "anchor".into(),
                },
            );
        }
    }
    // Request a page smaller than the registry.
    let v = compute_vrf_registry(state, Some(2));
    let regs = v
        .get("registrations")
        .and_then(|x| x.as_array())
        .expect("registrations is JSON Array");
    assert_eq!(
        regs.len(),
        2,
        "returned registrations MUST be bounded by the requested limit",
    );
    assert_eq!(
        v.get("count").and_then(|x| x.as_u64()),
        Some(5),
        "`count` MUST report the TRUE registration total regardless of the page cap",
    );
    // Deterministic ordering — lowest identity_hash first ("id-00","id-01").
    assert_eq!(
        regs[0].get("identity_hash").and_then(|x| x.as_str()),
        Some("id-00"),
        "page MUST be ordered by identity_hash — first row is the lowest id",
    );
    assert_eq!(
        regs[1].get("identity_hash").and_then(|x| x.as_str()),
        Some("id-01"),
        "page MUST be ordered by identity_hash — second row is the next lowest",
    );
}

// ─── +5 on compute_witness_correlation ──
// Previously only a fresh-state envelope was pinned (1 test):
// both witnesses unknown → 3-key envelope, correlation=0.8 (ALPHA+BETA
// conservative-default). The asymmetric / one-side-registered branches,
// the both-registered overlap arithmetic (consensus.rs:2316-2338), and
// the WitnessProfile sub-object 3-key wire shape were 100% unpinned.
//
// Pivot from the `compute_vrf_registry` test — that pinned a discrete
// registry table, this pins the SCALAR correlation derived from it,
// covering the unknown-profile counter-bump branch (consensus.rs:2310)
// separately from the both-known weighted-sum branch
// (consensus.rs:2316-2338).
//
// Five orthogonal axes:
//   (1) profile_a only — 4-key envelope w/ profile_a sub-object, NO
//       profile_b key. Correlation STILL 0.8 (unknown-profile branch
//       fires because the lookup requires BOTH profiles to be Some).
//   (2) profile_b only — symmetric counterpart, profile_b populated
//       and profile_a absent; pins the asymmetric output direction.
//   (3) both profiles, fully overlapping (same org/subnet/geo_zone)
//       → 5-key envelope, correlation=1.0 (ALPHA 0.5 + BETA 0.3 +
//       GAMMA 0.2). Pins both sub-objects' strict 3-key shape.
//   (4) both profiles, fully disjoint (no field matches) →
//       correlation=0.0. Pins the min-correlation contract for
//       registered pairs (vs. the 0.8 default for unregistered).
//   (5) both profiles, same org only → correlation=ALPHA=0.5. Pins
//       per-field weight contribution (org alone) AND the sub-object
//       3-key strict-shape contract via key-set enumeration — a
//       regression that #[derive(Serialize)]'d WitnessProfile would
//       leak any new field (e.g. an internal `pq_pubkey` byte blob)
//       into wire output; this axis catches that by enumerating the
//       sub-object keys.
//
// The unknown-profile counter at consensus.rs:2310 bumps only in
// branches 1, 2 (and an existing test) — not in 3, 4, 5.
// None of these tests inspect that counter directly (it's a process-
// wide atomic; concurrent test interleave could race the value), but
// they collectively exercise both sides of the partition.

#[test]
fn batch_zz_compute_witness_correlation_profile_a_only_emits_4_key_envelope_with_profile_a_branch()
{
    // Register a profile for witness_a only. witness_b has no profile.
    // The correlation function's pair-lookup at consensus.rs:2294-2313
    // requires BOTH profiles to be Some — one-sided registration still
    // falls into the unknown-profile branch with conservative default
    // ALPHA + BETA = 0.8.
    //
    // The JSON helper's profile-presence branches (explorer.rs:1423,
    // 1430) are INDEPENDENT of the correlation-function branch: the
    // helper looks up each witness's profile separately and emits a
    // sub-object whenever the registration table has the witness, even
    // if the correlation arithmetic took the unknown-profile shortcut.
    // So the wire shape is 4 keys (envelope + profile_a) while the
    // correlation is still 0.8.
    let state = test_state();
    let body = WitnessProfileBody {
        witness_hash: "wA-only-deadbeef".into(),
        organization: "OrgA".into(),
        subnet: "10.1.0.0/24".into(),
        geo_zone: "eu-north".into(),
    };
    compute_register_witness_profile(&state, body)
        .expect("witness_a profile registration must succeed");

    let v = compute_witness_correlation(
        Arc::clone(&state),
        "wA-only-deadbeef".into(),
        "wB-unregistered".into(),
    );

    assert_eq!(
        v.get("witness_a").and_then(|x| x.as_str()),
        Some("wA-only-deadbeef")
    );
    assert_eq!(
        v.get("witness_b").and_then(|x| x.as_str()),
        Some("wB-unregistered")
    );
    assert_eq!(
        v.get("correlation").and_then(|x| x.as_f64()),
        Some(0.8),
        "one-sided registration must still hit ALPHA+BETA=0.8 (unknown-profile branch)",
    );
    let profile_a = v
        .get("profile_a")
        .expect("profile_a sub-object must be present");
    assert!(
        profile_a.is_object(),
        "profile_a must be a JSON Object, not null"
    );
    assert_eq!(
        profile_a.get("organization").and_then(|x| x.as_str()),
        Some("OrgA"),
    );
    assert_eq!(
        profile_a.get("subnet").and_then(|x| x.as_str()),
        Some("10.1.0.0/24"),
    );
    assert_eq!(
        profile_a.get("geo_zone").and_then(|x| x.as_str()),
        Some("eu-north"),
    );
    assert!(
        v.get("profile_b").is_none(),
        "profile_b key MUST be absent when witness_b has no registration — \
             a regression that emitted `profile_b: null` would inflate the wire \
             shape from 4 keys to 5 and break operator dashboards that key off \
             `.has(profile_b)` to detect registration",
    );
}

#[test]
fn batch_zz_compute_witness_correlation_profile_b_only_emits_4_key_envelope_with_profile_b_branch()
{
    // Symmetric counterpart to axis (1): register only witness_b.
    // Pins the OPPOSITE asymmetric output direction — confirms the
    // helper's two independent presence checks at L1423 and L1430
    // fire in BOTH directions (a regression that accidentally tied
    // profile_b's emission to profile_a's presence would pass axis 1
    // but fail this).
    let state = test_state();
    let body = WitnessProfileBody {
        witness_hash: "wB-only-feedface".into(),
        organization: "OrgB".into(),
        subnet: "10.2.0.0/24".into(),
        geo_zone: "us-east".into(),
    };
    compute_register_witness_profile(&state, body)
        .expect("witness_b profile registration must succeed");

    let v = compute_witness_correlation(
        Arc::clone(&state),
        "wA-unregistered".into(),
        "wB-only-feedface".into(),
    );

    assert_eq!(
        v.get("witness_a").and_then(|x| x.as_str()),
        Some("wA-unregistered")
    );
    assert_eq!(
        v.get("witness_b").and_then(|x| x.as_str()),
        Some("wB-only-feedface")
    );
    assert_eq!(
        v.get("correlation").and_then(|x| x.as_f64()),
        Some(0.8),
        "one-sided registration (b only) must still hit ALPHA+BETA=0.8",
    );
    assert!(
        v.get("profile_a").is_none(),
        "profile_a key MUST be absent when witness_a has no registration — \
             symmetric counterpart to axis (1)",
    );
    let profile_b = v
        .get("profile_b")
        .expect("profile_b sub-object must be present");
    assert!(profile_b.is_object(), "profile_b must be a JSON Object");
    assert_eq!(
        profile_b.get("organization").and_then(|x| x.as_str()),
        Some("OrgB"),
    );
    assert_eq!(
        profile_b.get("subnet").and_then(|x| x.as_str()),
        Some("10.2.0.0/24"),
    );
    assert_eq!(
        profile_b.get("geo_zone").and_then(|x| x.as_str()),
        Some("us-east"),
    );
}

#[test]
fn batch_zz_compute_witness_correlation_fully_overlapping_profiles_emit_max_correlation_one() {
    // Both witnesses registered with IDENTICAL profile fields. Hits
    // the both-known branch at consensus.rs:2316-2338:
    //   same_org    = 1.0 → ALPHA  * 1.0 = 0.5
    //   same_subnet = 1.0 → BETA   * 1.0 = 0.3  (self-reported match)
    //   same_zone   = 1.0 → GAMMA  * 1.0 = 0.2  (self-reported match)
    //   sum = 1.0 — the MAXIMUM correlation for registered pairs.
    // Wire envelope is 5 keys; both profile sub-objects are full
    // 3-key Objects. A regression that lowered any of ALPHA/BETA/
    // GAMMA would surface here as a non-1.0 value.
    let state = test_state();
    compute_register_witness_profile(
        &state,
        WitnessProfileBody {
            witness_hash: "wA-overlap-aa".into(),
            organization: "SharedOrg".into(),
            subnet: "192.168.1.0/24".into(),
            geo_zone: "eu-west".into(),
        },
    )
    .expect("wA registration must succeed");
    compute_register_witness_profile(
        &state,
        WitnessProfileBody {
            witness_hash: "wB-overlap-bb".into(),
            organization: "SharedOrg".into(),
            subnet: "192.168.1.0/24".into(),
            geo_zone: "eu-west".into(),
        },
    )
    .expect("wB registration must succeed");

    let v = compute_witness_correlation(
        Arc::clone(&state),
        "wA-overlap-aa".into(),
        "wB-overlap-bb".into(),
    );

    assert_eq!(
        v.get("correlation").and_then(|x| x.as_f64()),
        Some(1.0),
        "ALPHA+BETA+GAMMA = 0.5+0.3+0.2 = 1.0 must be reachable when all \
             three self-reported fields match — a regression that lowered any \
             of the weights would surface as a non-1.0 value here",
    );
    let profile_a = v.get("profile_a").expect("profile_a must be present");
    assert_eq!(
        profile_a.get("organization").and_then(|x| x.as_str()),
        Some("SharedOrg")
    );
    assert_eq!(
        profile_a.get("subnet").and_then(|x| x.as_str()),
        Some("192.168.1.0/24")
    );
    assert_eq!(
        profile_a.get("geo_zone").and_then(|x| x.as_str()),
        Some("eu-west")
    );
    let profile_b = v.get("profile_b").expect("profile_b must be present");
    assert_eq!(
        profile_b.get("organization").and_then(|x| x.as_str()),
        Some("SharedOrg")
    );
    assert_eq!(
        profile_b.get("subnet").and_then(|x| x.as_str()),
        Some("192.168.1.0/24")
    );
    assert_eq!(
        profile_b.get("geo_zone").and_then(|x| x.as_str()),
        Some("eu-west")
    );
}

#[test]
fn batch_zz_compute_witness_correlation_fully_disjoint_profiles_emit_zero_correlation() {
    // Both witnesses registered, NO field matches → correlation = 0.0.
    // Pins the MIN-correlation contract for the registered-pair branch:
    // the conservative-default 0.8 (unregistered) is HIGHER than the
    // honest-disjoint 0.0 (fully registered + diverse). A regression
    // that defaulted to ALPHA when same_org=0.0 (e.g. an off-by-one in
    // the boolean→float coercion) would surface here as 0.5 instead
    // of 0.0. This is also the operational target state — diverse
    // mainnet witnesses SHOULD trend toward 0.0, with non-zero values
    // indicating accidental co-location or colluding sybil clusters.
    let state = test_state();
    compute_register_witness_profile(
        &state,
        WitnessProfileBody {
            witness_hash: "wA-disjoint-cc".into(),
            organization: "OrgAlpha".into(),
            subnet: "10.0.0.0/24".into(),
            geo_zone: "eu-north".into(),
        },
    )
    .expect("wA registration must succeed");
    compute_register_witness_profile(
        &state,
        WitnessProfileBody {
            witness_hash: "wB-disjoint-dd".into(),
            organization: "OrgOmega".into(),
            subnet: "172.16.0.0/24".into(),
            geo_zone: "us-west".into(),
        },
    )
    .expect("wB registration must succeed");

    let v = compute_witness_correlation(
        Arc::clone(&state),
        "wA-disjoint-cc".into(),
        "wB-disjoint-dd".into(),
    );

    assert_eq!(
        v.get("correlation").and_then(|x| x.as_f64()),
        Some(0.0),
        "fully disjoint profiles must emit correlation=0.0 — registered \
             honest-diverse pair, NOT the 0.8 unknown-profile default",
    );
    assert!(
        v.get("profile_a").is_some(),
        "profile_a present (registered)"
    );
    assert!(
        v.get("profile_b").is_some(),
        "profile_b present (registered)"
    );
}

#[test]
fn batch_zz_compute_witness_correlation_same_org_only_pins_alpha_weight_and_sub_object_strict_three_key_shape(
) {
    // Both registered, ONLY organization matches → correlation = ALPHA
    // = 0.5. Pins the per-field additivity contract (org alone
    // contributes exactly 0.5, no spillover from BETA or GAMMA) AND
    // the WitnessProfile sub-object's strict 3-key shape — enumerates
    // the key set on profile_a to lock {organization, subnet, geo_zone}
    // with NO extras. A regression that swapped the handcoded
    // json!({"organization", "subnet", "geo_zone"}) for a
    // #[derive(Serialize)] on the WitnessProfile struct would leak any
    // newly-added field (e.g. an internal handshake-state byte blob)
    // into the wire output — this axis catches that.
    let state = test_state();
    compute_register_witness_profile(
        &state,
        WitnessProfileBody {
            witness_hash: "wA-org-only-ee".into(),
            organization: "SameOrg".into(),
            subnet: "10.0.0.0/24".into(),
            geo_zone: "eu-north".into(),
        },
    )
    .expect("wA registration must succeed");
    compute_register_witness_profile(
        &state,
        WitnessProfileBody {
            witness_hash: "wB-org-only-ff".into(),
            organization: "SameOrg".into(),
            subnet: "172.16.0.0/24".into(),
            geo_zone: "us-west".into(),
        },
    )
    .expect("wB registration must succeed");

    let v = compute_witness_correlation(
        Arc::clone(&state),
        "wA-org-only-ee".into(),
        "wB-org-only-ff".into(),
    );

    assert_eq!(
        v.get("correlation").and_then(|x| x.as_f64()),
        Some(0.5),
        "same_org only → ALPHA*1.0 + BETA*0.0 + GAMMA*0.0 = 0.5; pins \
             the per-field weight contribution and rules out any spillover \
             between fields",
    );

    // Enumerate the profile_a sub-object's key set to lock the strict
    // 3-key shape. A regression that derived Serialize on WitnessProfile
    // would leak any new field added to the struct into wire output.
    let profile_a = v
        .get("profile_a")
        .and_then(|x| x.as_object())
        .expect("profile_a must be a JSON Object");
    let mut keys_a: Vec<&str> = profile_a.keys().map(|s| s.as_str()).collect();
    keys_a.sort();
    assert_eq!(
        keys_a,
        vec!["geo_zone", "organization", "subnet"],
        "profile_a MUST emit EXACTLY 3 keys (organization, subnet, geo_zone) \
             — a regression that derived Serialize on WitnessProfile would leak \
             additional struct fields into wire output",
    );

    // Symmetric enumeration for profile_b.
    let profile_b = v
        .get("profile_b")
        .and_then(|x| x.as_object())
        .expect("profile_b must be a JSON Object");
    let mut keys_b: Vec<&str> = profile_b.keys().map(|s| s.as_str()).collect();
    keys_b.sort();
    assert_eq!(
        keys_b,
        vec!["geo_zone", "organization", "subnet"],
        "profile_b MUST emit EXACTLY 3 keys; symmetric pin to keys_a",
    );
}

// ─── compute_itc_status (explorer.rs:1969) ────────────────────
// Existing coverage was a
// single fresh-state envelope test (events_total=0, joins_total=0, `itc`
// field present). Both counters' INDEPENDENCE, strict-u64 type contract,
// top-level 3-key envelope key-set, and `itc` sub-object 2-key shape were
// 100% unpinned. Wallets/dashboards polling /itc/status need these stable.
#[test]
fn batch_aaa_compute_itc_status_events_total_bumps_independently_of_joins_total() {
    let state = test_state();
    state
        .itc_events_total
        .fetch_add(7, std::sync::atomic::Ordering::Relaxed);
    let v = compute_itc_status(state);
    assert_eq!(
        v.get("events_total").and_then(|x| x.as_u64()),
        Some(7),
        "events_total must reflect the fetch_add to 7",
    );
    assert_eq!(
        v.get("joins_total").and_then(|x| x.as_u64()),
        Some(0),
        "joins_total must remain 0 — bumping events_total must NOT spill into joins_total",
    );
}

#[test]
fn batch_aaa_compute_itc_status_joins_total_bumps_independently_of_events_total() {
    let state = test_state();
    state
        .itc_joins_total
        .fetch_add(11, std::sync::atomic::Ordering::Relaxed);
    let v = compute_itc_status(state);
    assert_eq!(
        v.get("joins_total").and_then(|x| x.as_u64()),
        Some(11),
        "joins_total must reflect the fetch_add to 11",
    );
    assert_eq!(
        v.get("events_total").and_then(|x| x.as_u64()),
        Some(0),
        "events_total must remain 0 — symmetric independence pin to the events-bumps test",
    );
}

#[test]
fn batch_aaa_compute_itc_status_counters_emit_strict_u64_not_f64_or_string() {
    let state = test_state();
    // Coprime non-trivial values defeat any cross-aliasing (events==joins or
    // events==2*joins) and any default-fallback that returns the same scalar.
    state
        .itc_events_total
        .fetch_add(7, std::sync::atomic::Ordering::Relaxed);
    state
        .itc_joins_total
        .fetch_add(11, std::sync::atomic::Ordering::Relaxed);
    let v = compute_itc_status(state);
    let ev = v.get("events_total").expect("events_total key must exist");
    assert!(
        ev.is_u64(),
        "events_total MUST be JSON Number-u64 (not f64, not String) — accounts strict-parse u64",
    );
    assert_eq!(ev.as_u64(), Some(7));
    let jn = v.get("joins_total").expect("joins_total key must exist");
    assert!(
            jn.is_u64(),
            "joins_total MUST be JSON Number-u64 (not f64, not String) — symmetric type pin to events_total",
        );
    assert_eq!(jn.as_u64(), Some(11));
}

#[test]
fn batch_aaa_compute_itc_status_top_level_envelope_is_strict_three_key_object() {
    let state = test_state();
    let v = compute_itc_status(state);
    let obj = v
        .as_object()
        .expect("compute_itc_status MUST return a top-level JSON Object");
    let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    keys.sort();
    // Strict key-set enumeration catches any future silent field addition
    // (e.g. a `peers_total` 4th key) that would inflate operator dashboards
    // or break strict-parsing accounts. Hand-coded json!() at line 1975
    // freezes the wire shape at 3 keys.
    assert_eq!(
        keys,
        vec!["events_total", "itc", "joins_total"],
        "top-level envelope MUST emit EXACTLY 3 keys {{itc, events_total, joins_total}}",
    );
}

#[test]
fn batch_aaa_compute_itc_status_itc_sub_object_emits_two_key_shape_with_details_array() {
    let state = test_state();
    let v = compute_itc_status(state);
    let itc = v
        .get("itc")
        .and_then(|x| x.as_object())
        .expect("`itc` sub-field MUST be a JSON Object");
    let mut keys: Vec<&str> = itc.keys().map(|s| s.as_str()).collect();
    keys.sort();
    // Pins the wire shape of itc::ZoneClockManager::summary() — a future
    // addition (e.g. `last_join_at` ts) would surface here BEFORE
    // dashboards inflate. The 2-key contract is intentionally tighter than
    // the source struct so any drift is forced through this gate.
    assert_eq!(
        keys,
        vec!["details", "zones"],
        "`itc` sub-object MUST emit EXACTLY 2 keys {{zones, details}}",
    );
    // `details` on a fresh state MUST be a JSON Array (NOT null, NOT Object).
    // A `#[serde(skip_serializing_if = \"Vec::is_empty\")]` regression would
    // silently drop the field; this assertion fails on absence AND on type
    // drift.
    let details = itc
        .get("details")
        .and_then(|x| x.as_array())
        .expect("`details` on fresh state MUST be a JSON Array (empty), NOT null/Object");
    assert!(
        details.is_empty(),
        "fresh-state `details` array MUST be empty (no zone clocks tracked yet)",
    );
    // `zones` is a u64 count, MUST be 0 on fresh state, MUST be Number-u64.
    let zones = itc.get("zones").expect("`zones` key must exist");
    assert!(
            zones.is_u64(),
            "`zones` MUST be JSON Number-u64 on fresh state — operator dashboards aggregate cluster-wide",
        );
    assert_eq!(zones.as_u64(), Some(0));
}

// ─── compute_committees_is_member (explorer.rs:1717) ──────────
// The `compute_committees_is_member` helper
// had ZERO direct test coverage previously. Pairs with the
// `compute_vrf_registry` coverage at the committee-membership-derivation
// step — the registry table feeds the committee selection that this
// helper queries. Two error-envelope branches (missing zone, missing id)
// AND the Option<u64>/Option<usize> default-resolution branches (default
// epoch = dag.current_epoch(), default k = DEFAULT_COMMITTEE_SIZE) AND
// the 6-key happy-path envelope were 100% unpinned.
#[tokio::test]
async fn batch_bbb_compute_committees_is_member_missing_zone_returns_error_envelope() {
    let state = test_state();
    let v =
        compute_committees_is_member(state, None, Some("aabbccdd".to_string()), None, None).await;
    let obj = v
        .as_object()
        .expect("missing-zone branch MUST return a JSON Object");
    let keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    assert_eq!(
        keys,
        vec!["error"],
        "missing-zone error envelope MUST be EXACTLY 1 key {{error}} — no leaked happy-path keys",
    );
    assert_eq!(
        obj.get("error").and_then(|x| x.as_str()),
        Some("missing required query param: zone"),
        "error text must match exactly the hand-coded literal at L1728",
    );
}

#[tokio::test]
async fn batch_bbb_compute_committees_is_member_missing_id_returns_distinct_error_envelope() {
    let state = test_state();
    let v = compute_committees_is_member(state, Some("0".to_string()), None, None, None).await;
    let obj = v
        .as_object()
        .expect("missing-id branch MUST return a JSON Object");
    let keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    assert_eq!(
            keys,
            vec!["error"],
            "missing-id error envelope MUST be EXACTLY 1 key {{error}} — symmetric to missing-zone branch",
        );
    // Distinct from missing-zone branch — pins that the two early-returns
    // emit DIFFERENT diagnostic text (a copy-paste regression returning
    // "zone" for the id branch would surface here).
    assert_eq!(
        obj.get("error").and_then(|x| x.as_str()),
        Some("missing required query param: id"),
        "error text MUST distinguish missing-id from missing-zone branch",
    );
}

#[tokio::test]
async fn batch_bbb_compute_committees_is_member_default_epoch_resolves_to_dag_current_epoch() {
    let state = test_state();
    // Fresh dag → current_epoch() = 0. Pass None for epoch; assert
    // helper's resolved `epoch` field equals dag.current_epoch().
    // A regression that defaulted to e.g. 1 or u64::MAX (e.g. a swapped
    // `unwrap_or(1)`) would surface here.
    let v = compute_committees_is_member(
        state.clone(),
        Some("0".to_string()),
        Some("aabbccddeeff0011".to_string()),
        None,
        None,
    )
    .await;
    assert_eq!(
        v.get("epoch").and_then(|x| x.as_u64()),
        Some(0),
        "fresh-state dag.current_epoch() default MUST resolve to 0",
    );
    // Strict-u64 type pin: epoch MUST be JSON Number-u64 (NOT String, NOT
    // f64). A regression that serialized epoch as String would break
    // account-side strict u64 parsers.
    let ep = v.get("epoch").expect("epoch key must exist");
    assert!(
        ep.is_u64(),
        "epoch MUST be JSON Number-u64 — accounts strict-parse against fork detection",
    );
}

#[tokio::test]
async fn batch_bbb_compute_committees_is_member_default_k_resolves_to_default_committee_size() {
    let state = test_state();
    // Pass None for k; assert resolved committee_size equals
    // DEFAULT_COMMITTEE_SIZE = 7 (per zone_committee.rs:63). A regression
    // changing the default to e.g. 5 or 11 would surface here AND in the
    // wire shape simultaneously.
    let v = compute_committees_is_member(
        state,
        Some("0".to_string()),
        Some("aabbccddeeff0011".to_string()),
        None,
        None,
    )
    .await;
    assert_eq!(
        v.get("committee_size").and_then(|x| x.as_u64()),
        Some(crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE as u64),
        "missing-k branch MUST default to DEFAULT_COMMITTEE_SIZE (=7)",
    );
    let cs = v
        .get("committee_size")
        .expect("committee_size key must exist");
    assert!(cs.is_u64(), "committee_size MUST be JSON Number-u64",);
}

#[tokio::test]
async fn batch_bbb_compute_committees_is_member_happy_path_emits_strict_six_key_envelope() {
    let state = test_state();
    let v = compute_committees_is_member(
        state,
        Some("0".to_string()),
        Some("aabbccddeeff0011".to_string()),
        Some(13),
        Some(5),
    )
    .await;
    let obj = v.as_object().expect("happy-path MUST return a JSON Object");
    let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    keys.sort();
    // Strict 6-key envelope catches any future field addition (e.g. a
    // future `selection_seed` or `vrf_proof` key) BEFORE it inflates
    // operator dashboards.
    assert_eq!(
        keys,
        vec![
            "committee_size",
            "epoch",
            "identity",
            "is_member",
            "selection_rank",
            "zone",
        ],
        "happy-path envelope MUST be EXACTLY 6 keys — handcoded json!() freeze",
    );
    // Per-field type pins:
    assert_eq!(
        obj.get("zone").and_then(|x| x.as_str()),
        Some("0"),
        "zone field must echo input string verbatim",
    );
    assert_eq!(
        obj.get("epoch").and_then(|x| x.as_u64()),
        Some(13),
        "epoch field must echo input (Some-branch) verbatim",
    );
    assert_eq!(
        obj.get("committee_size").and_then(|x| x.as_u64()),
        Some(5),
        "committee_size field must echo input (Some-branch) verbatim",
    );
    assert_eq!(
        obj.get("identity").and_then(|x| x.as_str()),
        Some("aabbccddeeff0011"),
        "identity field must echo input verbatim",
    );
    // is_member MUST be a JSON Bool (NOT a {Some:bool} wrapper from
    // accidental Serde-derive on a custom enum), and on a fresh-state
    // node with no anchor stakes the helper returns is_member=false.
    let im = v.get("is_member").expect("is_member key must exist");
    assert!(
        im.is_boolean(),
        "is_member MUST be JSON Bool (NOT String, NOT Object wrapper)",
    );
    assert_eq!(im.as_bool(), Some(false));
    // selection_rank is an Option<usize>; on a fresh-state non-member
    // node it MUST be JSON Null (NOT absent — strict 6-key contract
    // includes this key) and NOT a {None: null} wrapper.
    let sr = v
        .get("selection_rank")
        .expect("selection_rank key must exist");
    assert!(
            sr.is_null(),
            "selection_rank on non-member fresh-state MUST be JSON Null (the strict 6-key envelope keeps the key present)",
        );
}

// ─── compute_zone_health (explorer.rs:1582) ───────────────────
// Previously ZERO direct test coverage for `compute_zone_health`. The
// helper assembles a strict 5-key envelope from TWO distinct data
// sources: (a) `consensus.zone_health()` drives the `zones` array via
// attestations/zone_stakes; (b) `zone_state.coverage_summary()` +
// `under_witnessed_zones()` drive the `coverage` array + the
// `under_witnessed_zones` list. Pins five axes: (1) fresh-state strict
// 5-key envelope + empty-array contract + min_witnesses_required strict
// u64; (2) `zones` array per-element 5-key shape (zone/total_stake/
// active_records/settled_records/unique_witnesses) with strict types;
// (3) `coverage` array per-element 4-key shape (zone/record_count/
// unique_witnesses/has_coverage) + has_coverage IS-Bool; (4) total_zones
// invariant — MUST equal `zones.len()` (NOT `coverage.len()`); (5)
// `under_witnessed_zones` array emits zone IDs as JSON Strings.
#[tokio::test]
async fn batch_ccc_compute_zone_health_fresh_state_strict_five_key_envelope_empty_arrays_min_witnesses_one(
) {
    let state = test_state();
    let v = compute_zone_health(state).await;
    let obj = v
        .as_object()
        .expect("fresh-state response MUST be a JSON Object");
    let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    keys.sort();
    // Strict 5-key envelope catches any future field addition (e.g. a
    // `last_seal_at` or `zone_count_by_status` key) BEFORE it inflates
    // operator dashboards or breaks account strict-shape parsers.
    assert_eq!(
        keys,
        vec![
            "coverage",
            "min_witnesses_required",
            "total_zones",
            "under_witnessed_zones",
            "zones",
        ],
        "fresh-state envelope MUST be EXACTLY 5 keys — handcoded json!() freeze",
    );
    // All three arrays MUST be empty Arrays (NOT null). A
    // `#[serde(skip_serializing_if = "Vec::is_empty")]` regression on any
    // of the three would surface as missing-key OR null-instead-of-array.
    let zones = obj
        .get("zones")
        .and_then(|x| x.as_array())
        .expect("`zones` MUST be a JSON Array on fresh state, NOT null/Object");
    assert!(zones.is_empty(), "fresh-state `zones` MUST be empty");
    let coverage = obj
        .get("coverage")
        .and_then(|x| x.as_array())
        .expect("`coverage` MUST be a JSON Array on fresh state, NOT null/Object");
    assert!(coverage.is_empty(), "fresh-state `coverage` MUST be empty");
    let uwz = obj
        .get("under_witnessed_zones")
        .and_then(|x| x.as_array())
        .expect("`under_witnessed_zones` MUST be a JSON Array on fresh state, NOT null/Object");
    assert!(
        uwz.is_empty(),
        "fresh-state `under_witnessed_zones` MUST be empty"
    );
    // total_zones is a Vec::len() projection, MUST be u64-typed Number.
    let tz = obj
        .get("total_zones")
        .expect("`total_zones` key must exist");
    assert!(
        tz.is_u64(),
        "`total_zones` MUST be JSON Number-u64 — operator dashboards strict-parse",
    );
    assert_eq!(tz.as_u64(), Some(0), "fresh-state `total_zones` MUST be 0");
    // min_witnesses_required mirrors NodeConfig::zone_min_witnesses (default 1).
    // A regression that pulled from a different config field would surface as
    // a different value here.
    let mwr = obj
        .get("min_witnesses_required")
        .expect("`min_witnesses_required` key must exist");
    assert!(
        mwr.is_u64(),
        "`min_witnesses_required` MUST be JSON Number-u64",
    );
    assert_eq!(
        mwr.as_u64(),
        Some(1),
        "NodeConfig::default().zone_min_witnesses == 1; helper must surface that value",
    );
}

#[tokio::test]
async fn batch_ccc_compute_zone_health_consensus_stake_only_zones_element_strict_five_key_envelope()
{
    let state = test_state();
    // Register a non-zero zone stake into consensus WITHOUT touching
    // zone_state — this exercises the `zone_health()` "include zones with
    // stake but no active records" branch (consensus.rs:2710) and leaves
    // coverage empty so axis 4 (total_zones vs coverage.len()) can pin the
    // invariant independently.
    {
        let mut consensus = state.consensus.lock_recover();
        consensus.register_zone_stake(crate::ZoneId::new("test_zone_alpha"), 12345);
    }
    let v = compute_zone_health(state).await;
    let zones = v
        .get("zones")
        .and_then(|x| x.as_array())
        .expect("`zones` MUST be a JSON Array");
    assert_eq!(
        zones.len(),
        1,
        "single registered stake MUST surface as 1 zone element"
    );
    let z0 = zones[0]
        .as_object()
        .expect("zone element MUST be a JSON Object");
    let mut keys: Vec<&str> = z0.keys().map(|s| s.as_str()).collect();
    keys.sort();
    // Strict 5-key per-element envelope catches any future field addition
    // (e.g. a `geo_zone` or `last_seal_at` key) BEFORE it breaks operator
    // dashboards or doubles the per-zone payload size.
    assert_eq!(
        keys,
        vec![
            "active_records",
            "settled_records",
            "total_stake",
            "unique_witnesses",
            "zone",
        ],
        "zones[i] envelope MUST be EXACTLY 5 keys — handcoded json!() at explorer.rs:1588 freeze",
    );
    // Per-field type pins. A serde-derive on a typed wrapper would surface
    // as e.g. `{"Stake": 12345}` instead of bare Number.
    assert_eq!(
        z0.get("zone").and_then(|x| x.as_str()),
        Some("test_zone_alpha"),
        "zone field MUST be String (ZoneId serializes as inner path)",
    );
    let ts = z0.get("total_stake").expect("total_stake key must exist");
    assert!(
        ts.is_u64(),
        "total_stake MUST be JSON Number-u64 — accounts strict-parse against fork detection",
    );
    assert_eq!(ts.as_u64(), Some(12345));
    // active/settled/unique_witnesses on "stake-only" branch MUST all be 0
    // (u64-typed). A regression that loaded these from a different source
    // would surface as non-zero on a no-attestation state.
    let ar = z0
        .get("active_records")
        .expect("active_records key must exist");
    assert!(ar.is_u64(), "active_records MUST be JSON Number-u64");
    assert_eq!(ar.as_u64(), Some(0));
    let sr = z0
        .get("settled_records")
        .expect("settled_records key must exist");
    assert!(sr.is_u64(), "settled_records MUST be JSON Number-u64");
    assert_eq!(sr.as_u64(), Some(0));
    let uw = z0
        .get("unique_witnesses")
        .expect("unique_witnesses key must exist");
    assert!(uw.is_u64(), "unique_witnesses MUST be JSON Number-u64");
    assert_eq!(uw.as_u64(), Some(0));
}

#[tokio::test]
async fn batch_ccc_compute_zone_health_zone_state_insert_coverage_element_strict_four_key_envelope_has_coverage_is_bool(
) {
    let state = test_state();
    // Insert a record into zone_state WITHOUT registering any witnesses.
    // With min_witnesses=1 (NodeConfig default) and 0 witnesses, the zone
    // is UNDER-witnessed (has_coverage=false). This exercises the "Bool
    // wire shape" of has_coverage (NOT Option<bool> JSON Null and NOT a
    // {Some: bool} wrapper) AND the per-element 4-key envelope.
    {
        let mut zs = state.zone_state.lock_recover();
        zs.record_inserted("axis3_probe_record");
    }
    // Compute expected zone path — record_inserted() routes via
    // zone_for_record() under the live ZONE_COUNT atomic. Don't predict
    // the exact zone path here (it depends on ZONE_COUNT state); just
    // verify the shape of the single emitted coverage element.
    let v = compute_zone_health(state).await;
    let coverage = v
        .get("coverage")
        .and_then(|x| x.as_array())
        .expect("`coverage` MUST be a JSON Array");
    assert_eq!(
        coverage.len(),
        1,
        "single record_inserted MUST surface as 1 coverage element",
    );
    let c0 = coverage[0]
        .as_object()
        .expect("coverage element MUST be a JSON Object");
    let mut keys: Vec<&str> = c0.keys().map(|s| s.as_str()).collect();
    keys.sort();
    // Strict 4-key per-element envelope at explorer.rs:1607-1612.
    assert_eq!(
        keys,
        vec!["has_coverage", "record_count", "unique_witnesses", "zone"],
        "coverage[i] envelope MUST be EXACTLY 4 keys — handcoded json!() freeze",
    );
    // zone is a String (ZoneId serializes as path).
    assert!(
        c0.get("zone").and_then(|x| x.as_str()).is_some(),
        "coverage[i].zone MUST be JSON String (ZoneId path)",
    );
    // record_count is u64. With one record_inserted, value MUST be 1.
    let rc = c0.get("record_count").expect("record_count key must exist");
    assert!(rc.is_u64(), "record_count MUST be JSON Number-u64");
    assert_eq!(rc.as_u64(), Some(1));
    let uw = c0
        .get("unique_witnesses")
        .expect("unique_witnesses key must exist");
    assert!(uw.is_u64(), "unique_witnesses MUST be JSON Number-u64");
    assert_eq!(
        uw.as_u64(),
        Some(0),
        "no witnesses attached MUST surface as 0"
    );
    // has_coverage CRITICAL pin: MUST be JSON Bool (NOT String, NOT Object
    // {Some: bool}). With min_witnesses_required=1 and unique_witnesses=0,
    // the zone has insufficient coverage → has_coverage=false.
    let hc = c0.get("has_coverage").expect("has_coverage key must exist");
    assert!(
        hc.is_boolean(),
        "has_coverage MUST be JSON Bool (NOT String, NOT Object wrapper)",
    );
    assert_eq!(
        hc.as_bool(),
        Some(false),
        "0 witnesses < min_witnesses_required=1 MUST emit has_coverage=false",
    );
}

#[tokio::test]
async fn batch_ccc_compute_zone_health_total_zones_equals_zones_array_length_not_coverage() {
    let state = test_state();
    // Register a consensus stake but DO NOT touch zone_state. This sets
    // up an asymmetric state where zones.len()=1 and coverage.len()=0 —
    // a regression that copy-pasted `coverage.len()` into the
    // `total_zones` projection would surface here.
    {
        let mut consensus = state.consensus.lock_recover();
        consensus.register_zone_stake(crate::ZoneId::new("axis4_probe_zone"), 999);
    }
    let v = compute_zone_health(state).await;
    let zones_len = v
        .get("zones")
        .and_then(|x| x.as_array())
        .map(|a| a.len())
        .expect("zones MUST be a JSON Array");
    let coverage_len = v
        .get("coverage")
        .and_then(|x| x.as_array())
        .map(|a| a.len())
        .expect("coverage MUST be a JSON Array");
    let total_zones = v
        .get("total_zones")
        .and_then(|x| x.as_u64())
        .expect("total_zones MUST be JSON Number-u64");
    // The two array sources are deliberately asymmetric here (1 vs 0).
    assert_eq!(
        zones_len, 1,
        "consensus-stake-only setup MUST surface 1 zone element"
    );
    assert_eq!(
        coverage_len, 0,
        "no record_inserted MUST leave coverage empty"
    );
    // Invariant: total_zones MUST be the `zones.len()` projection.
    assert_eq!(
            total_zones,
            zones_len as u64,
            "total_zones MUST equal zones.len() — a regression projecting from coverage.len() would surface here (got total_zones={total_zones}, zones.len()={zones_len}, coverage.len()={coverage_len})",
        );
    // Belt-and-braces — explicit numeric pin in case zones_len became 0
    // (which would silently make the equality vacuous).
    assert_eq!(
        total_zones, 1,
        "total_zones MUST be 1 (NOT 0 if it incorrectly projected from coverage.len())",
    );
}

#[tokio::test]
async fn batch_ccc_compute_zone_health_under_witnessed_array_emits_zone_id_strings() {
    let state = test_state();
    // Insert a record into zone_state. With min_witnesses=1 and 0
    // attached witnesses, the zone IS under-witnessed and MUST appear in
    // the `under_witnessed_zones` array — as a JSON String, NOT an Object
    // or per-zone struct. A `#[derive(Serialize)] struct UnderWitnessed`
    // wrapper or accidental switch to `Vec<ZoneHealth>` would surface
    // here as element-type drift.
    {
        let mut zs = state.zone_state.lock_recover();
        zs.record_inserted("axis5_probe_record");
    }
    let v = compute_zone_health(state).await;
    let uwz = v
        .get("under_witnessed_zones")
        .and_then(|x| x.as_array())
        .expect("under_witnessed_zones MUST be a JSON Array");
    assert_eq!(
        uwz.len(),
        1,
        "1 inserted record with 0 witnesses (min=1) MUST surface as 1 under-witnessed zone",
    );
    let e0 = &uwz[0];
    // Wire-shape pin: each element MUST be a JSON String (ZoneId path).
    assert!(
            e0.is_string(),
            "under_witnessed_zones[i] MUST be JSON String (NOT Object, NOT Array) — drift here breaks operator dashboards that index by string",
        );
    // The string MUST correspond to the same zone the coverage entry
    // surfaces — cross-source consistency pin.
    let coverage = v
        .get("coverage")
        .and_then(|x| x.as_array())
        .expect("coverage MUST be a JSON Array");
    let coverage_zone = coverage
        .first()
        .and_then(|c| c.get("zone"))
        .and_then(|z| z.as_str())
        .expect("coverage[0].zone MUST exist and be a String");
    assert_eq!(
        e0.as_str(),
        Some(coverage_zone),
        "under_witnessed_zones[0] MUST match coverage[0].zone — cross-source consistency invariant",
    );
}

// ─── compute_validate_address (explorer.rs:822) ───────────────
// Covers the
// account-facing public address-validation endpoint at L822. Previously
// ZERO direct test coverage despite this being the helper a account
// calls before sending beat to an entered string: a regression here
// routes user funds to the wrong destination (silent loss). The pure-fn
// gate at L826 (`len == 64 && all is_ascii_hexdigit`), the
// short-circuit at L827-L832 (exists=false when invalid), and the
// 4-key envelope at L834-L839 (`address`/`valid_format`/`exists`/
// `format`) with literal `"sha3-256-hex"` format string were all 100%
// unpinned.
//
// Axes:
//  (1) Wrong-length addresses (0/63/65/100 chars, all-hex content) return
//      valid_format=false AND exists=false — the len==64 guard is the
//      FIRST term of && so it short-circuits the hex-digit walk; pins
//      that a regression flipping the gate to `>=64` or `<=64` surfaces.
//  (2) Non-hex characters in a 64-length string ('g' just past 'f',
//      uppercase 'G' just past 'F', a space, a literal '!') return
//      valid_format=false — pins the .all(is_ascii_hexdigit) AND-fold
//      that the SECOND term enforces over EVERY character; the
//      adjacent-to-f/F probes catch off-by-one in the range check.
//  (3) Uppercase A-F AND mixed-case hex BOTH return valid_format=true —
//      pins that the gate is CASE-INSENSITIVE (is_ascii_hexdigit accepts
//      0-9, a-f, AND A-F). A account copying a hash from a block-explorer
//      that emits uppercase MUST NOT be rejected.
//  (4) `exists` reflects ledger.accounts membership when valid_format=true
//      (insert-then-query → exists=true; query-without-insert → false)
//      AND the format-gate short-circuits BEFORE ledger access — a
//      malformed key inserted into ledger.accounts is NOT observable
//      via this endpoint (security pin: prevents probing malformed
//      lookalike keys that may exist for migration reasons by tunneling
//      a non-64 byte string through the validation endpoint).
//  (5) Top-level envelope is EXACTLY 4 keys {address, valid_format,
//      exists, format} on BOTH valid and invalid branches; `format`
//      is the LITERAL "sha3-256-hex" (a account may switch parsing
//      rules on this token when ed25519 addresses ship the same
//      envelope with `format: "ed25519-pk-hex"`); valid_format AND
//      exists are strict JSON Bool (NOT String "true"/"false" — the
//      JS `if (resp.valid_format)` truthy-check would accept any
//      string); address is JSON String AND echoed VERBATIM (no case
//      normalization, no truncation — accounts render the typed
//      input back to the user unchanged).
#[tokio::test]
async fn batch_ddd_compute_validate_address_wrong_length_returns_invalid_format_and_exists_false() {
    let state = test_state();
    // Four wrong-length cases sweep both sides of the `len == 64` boundary
    // plus the empty-string degenerate case plus a far-off length. All
    // strings are otherwise all-hex so the FIRST term of && (length
    // gate) is the sole reason for the false. A regression flipping the
    // gate to `len >= 64` or `len <= 64` would surface here.
    for addr in [
        String::new(),   // empty
        "a".repeat(63),  // off-by-one short
        "a".repeat(65),  // off-by-one long
        "a".repeat(100), // far-too-long
    ] {
        let v = compute_validate_address(state.clone(), addr.clone()).await;
        assert_eq!(
            v.get("valid_format").and_then(|x| x.as_bool()),
            Some(false),
            "addr len={} must yield valid_format=false (length gate fires)",
            addr.len(),
        );
        assert_eq!(
                v.get("exists").and_then(|x| x.as_bool()),
                Some(false),
                "addr len={} must yield exists=false (format-gate short-circuit suppresses ledger lookup)",
                addr.len(),
            );
        // Address echoed verbatim regardless of length validity.
        assert_eq!(
            v.get("address").and_then(|x| x.as_str()),
            Some(addr.as_str()),
            "address field must echo input verbatim even when length is invalid",
        );
    }
}

#[tokio::test]
async fn batch_ddd_compute_validate_address_non_hex_char_in_64_length_returns_invalid_format() {
    let state = test_state();
    // Each case is a 64-character string with exactly ONE non-hex byte
    // somewhere in the body, so only the .all(is_ascii_hexdigit) walk
    // can fire. Chars chosen sweep distinct rejection reasons:
    //   'g' — adjacent to 'f' in ASCII, defeats any off-by-one in the
    //         lowercase hex range check (Rust's is_ascii_hexdigit
    //         enforces 'a'..='f' exactly, not 'a'..='g').
    //   'G' — adjacent to 'F' in ASCII, symmetric uppercase pin.
    //   ' ' — whitespace byte 0x20; common copy-paste mistake (trailing
    //         space from a clipboard) and the helper MUST reject rather
    //         than trim, or two distinct user inputs map to the same
    //         address class.
    //   '!' — byte 0x21; rejection of arbitrary punctuation.
    let prefix = "a".repeat(63);
    for bad_char in ['g', 'G', ' ', '!'] {
        let addr = format!("{prefix}{bad_char}");
        assert_eq!(addr.len(), 64, "test setup: addr must be exactly 64 bytes");
        let v = compute_validate_address(state.clone(), addr.clone()).await;
        assert_eq!(
                v.get("valid_format").and_then(|x| x.as_bool()),
                Some(false),
                "addr with bad_char={:?} must yield valid_format=false (.all(is_ascii_hexdigit) AND-fold rejects)",
                bad_char,
            );
        assert_eq!(
            v.get("exists").and_then(|x| x.as_bool()),
            Some(false),
            "bad-hex addr must yield exists=false (format gate short-circuits ledger)",
        );
    }
    // Sanity twin: a 64-char all-lowercase-hex string IS valid_format=true,
    // proving the negatives above are due to the bad char and not any
    // unrelated bug in the helper.
    let mut sanity = prefix.clone();
    sanity.push('a');
    assert_eq!(sanity.len(), 64);
    let v = compute_validate_address(state.clone(), sanity.clone()).await;
    assert_eq!(
        v.get("valid_format").and_then(|x| x.as_bool()),
        Some(true),
        "sanity twin: 64-char all-hex addr MUST yield valid_format=true",
    );
}

#[tokio::test]
async fn batch_ddd_compute_validate_address_uppercase_and_mixed_case_hex_are_both_valid_format() {
    let state = test_state();
    // Uppercase-only sweep — Rust's is_ascii_hexdigit accepts 'A'..='F'
    // identically to 'a'..='f'. A account copying a hash from a
    // block-explorer that emits uppercase MUST NOT be rejected here.
    let upper = "ABCDEF0123456789".repeat(4);
    assert_eq!(upper.len(), 64);
    let v = compute_validate_address(state.clone(), upper.clone()).await;
    assert_eq!(
        v.get("valid_format").and_then(|x| x.as_bool()),
        Some(true),
        "uppercase A-F address MUST be valid_format=true (case-insensitive hex gate)",
    );
    assert_eq!(
        v.get("address").and_then(|x| x.as_str()),
        Some(upper.as_str()),
        "uppercase address echoed verbatim — no lowercasing normalization",
    );

    // Mixed-case sweep — pins that the gate accepts ANY mixture and
    // that the echoed `address` preserves the mixture exactly.
    let mixed = "aBcDeF0123456789".repeat(4);
    assert_eq!(mixed.len(), 64);
    let v2 = compute_validate_address(state.clone(), mixed.clone()).await;
    assert_eq!(
        v2.get("valid_format").and_then(|x| x.as_bool()),
        Some(true),
        "mixed-case address MUST be valid_format=true (case-insensitive hex gate)",
    );
    assert_eq!(
        v2.get("address").and_then(|x| x.as_str()),
        Some(mixed.as_str()),
        "mixed-case address echoed verbatim — case mixture preserved (no normalization)",
    );
}

#[tokio::test]
async fn batch_ddd_compute_validate_address_exists_reflects_ledger_membership_and_format_gate_short_circuits(
) {
    use crate::accounting::ledger::AccountState;
    let state = test_state();
    // Address A: 64-char all-hex, populated in ledger → exists=true.
    let addr_a = "a".repeat(64);
    // Address B: 64-char all-hex (different from A), NOT populated → exists=false.
    let addr_b = "b".repeat(64);
    // Address C: malformed (length != 64), populated in ledger — proves
    // the format gate short-circuits BEFORE the ledger lookup, so a
    // malformed key that happens to exist is NOT observable through
    // this endpoint. Security pin: prevents probing legacy / migration
    // keys with non-64 hex strings via the account-facing validation
    // endpoint.
    let addr_c = "short_key_not_64_chars".to_string();
    {
        let mut ledger = state.ledger.write().await;
        ledger
            .accounts
            .insert(addr_a.clone(), AccountState::default());
        ledger
            .accounts
            .insert(addr_c.clone(), AccountState::default());
    }
    // A: valid_format=true AND in-ledger → exists=true
    let va = compute_validate_address(state.clone(), addr_a.clone()).await;
    assert_eq!(
        va.get("valid_format").and_then(|x| x.as_bool()),
        Some(true),
        "addr_a is 64-char all-hex → valid_format=true",
    );
    assert_eq!(
        va.get("exists").and_then(|x| x.as_bool()),
        Some(true),
        "addr_a populated in ledger.accounts → exists=true",
    );
    // B: valid_format=true AND NOT in-ledger → exists=false
    let vb = compute_validate_address(state.clone(), addr_b.clone()).await;
    assert_eq!(
        vb.get("valid_format").and_then(|x| x.as_bool()),
        Some(true),
        "addr_b is 64-char all-hex → valid_format=true",
    );
    assert_eq!(
            vb.get("exists").and_then(|x| x.as_bool()),
            Some(false),
            "addr_b NOT in ledger.accounts → exists=false (lookup is read-only and reflects membership)",
        );
    // C: malformed length, IS in ledger.accounts → exists=false (gate short-circuits)
    let vc = compute_validate_address(state.clone(), addr_c.clone()).await;
    assert_eq!(
        vc.get("valid_format").and_then(|x| x.as_bool()),
        Some(false),
        "addr_c length != 64 → valid_format=false (length gate fires before ledger)",
    );
    assert_eq!(
            vc.get("exists").and_then(|x| x.as_bool()),
            Some(false),
            "addr_c IS in ledger.accounts but valid_format=false short-circuits exists to false — security gate against probing malformed keys",
        );
}

#[tokio::test]
async fn batch_ddd_compute_validate_address_envelope_is_strict_four_keys_with_literal_format_string(
) {
    let state = test_state();
    // Strict 4-key envelope must hold on BOTH the valid-format branch
    // AND the invalid-format branch — any future addition (e.g. a
    // checksum_hex field for ed25519-style addresses) MUST surface here
    // BEFORE accounts inflate their parsers. Also pins:
    //   - `format` is the LITERAL "sha3-256-hex" string (accounts may
    //     switch parsing rules on this token when other profiles ship);
    //   - `valid_format` and `exists` are strict JSON Bool (NOT String
    //     "true"/"false" — a JS `if (resp.valid_format)` truthy-check
    //     would silently accept any malformed address);
    //   - `address` is JSON String (NOT a Number even for a numeric-
    //     looking digit-only 64-char input).
    for addr in [
        "a".repeat(64),
        "F".repeat(64),
        "short".to_string(),
        String::new(),
    ] {
        let v = compute_validate_address(state.clone(), addr.clone()).await;
        let obj = v
            .as_object()
            .expect("compute_validate_address MUST return a top-level JSON Object");
        let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
        keys.sort();
        assert_eq!(
                keys,
                vec!["address", "exists", "format", "valid_format"],
                "top-level envelope MUST emit EXACTLY 4 keys {{address, valid_format, exists, format}} regardless of branch — input addr={:?}",
                addr,
            );
        // Literal format string pin — accounts parse this token to
        // determine which checksum / prefix rules apply.
        assert_eq!(
            obj.get("format").and_then(|x| x.as_str()),
            Some("sha3-256-hex"),
            "`format` field MUST be the LITERAL string 'sha3-256-hex'",
        );
        // Strict Bool type for valid_format + exists.
        let vf = obj
            .get("valid_format")
            .expect("valid_format key must exist");
        assert!(
            vf.is_boolean(),
            "valid_format MUST be JSON Bool (NOT String, NOT Number)",
        );
        let ex = obj.get("exists").expect("exists key must exist");
        assert!(
                ex.is_boolean(),
                "exists MUST be JSON Bool (NOT String, NOT Number) — symmetric type pin to valid_format",
            );
        // Address is JSON String type AND echoed verbatim.
        let ad = obj.get("address").expect("address key must exist");
        assert!(
            ad.is_string(),
            "address MUST be JSON String (NOT Number, NOT Null even for empty input)",
        );
        assert_eq!(
            ad.as_str(),
            Some(addr.as_str()),
            "address echoed VERBATIM (no normalization, no truncation)",
        );
    }
}

// ─── compute_identity_pk (5 tests) ─────────────────────────────
//
// A fresh account-facing helper
// with only 1 unit test (the None-branch sentinel at L5036). Previously
// unpinned axes: ALL FOUR Some-tier branches (anchor / witness / user /
// legacy CF_IDENTITIES); the literal tier-string values returned by
// `get_public_key_with_tier`; `pk` hex-encoding round-trip (callers MUST
// be able to decode the returned hex back to the original bytes); the
// CF-walk PRECEDENCE order on parallel inserts (anchor outranks
// witness/user/legacy even if the Phase-C tombstone cascade is bypassed —
// e.g. legacy snapshot import predating the cascade). Identity Partitioning
// Phase D contract: this endpoint is the source of truth for "which tier
// holds this PK", so the literal tier string and the precedence ordering
// are the wire contract for the network::identity_fetcher soft-fail path.
//
// Axes: (1) ANCHOR-tier `store_public_key_anchor` write → tier =
// "identities_anchor" with pk hex-round-trip; (2) WITNESS-tier
// `store_public_key_witness` write → tier = "identities_witness"; (3)
// USER-tier `store_public_key_user` write → tier = "identities_user";
// (4) LEGACY CF_IDENTITIES via `store_public_key` → tier = "identities"
// (back-compat for nodes never re-keyed post Phase B; pins the 4th
// branch of the CF walk); (5) tier PRECEDENCE on parallel raw-puts
// (anchor + user populated for the same hash via `put_cf_raw` bypassing
// the Phase-C cascade) → anchor's pk wins, strict 3-key envelope on
// BOTH Some-branch AND None-branch (key-set equality test), `identity_hash`
// echoed verbatim on every branch.

#[tokio::test]
async fn batch_eee_compute_identity_pk_anchor_tier_hex_roundtrip_and_tier_string() {
    let state = test_state();
    let hash = "a".repeat(64);
    // Choose a PK byte vector that exercises hex-encoding across the
    // 0x00..=0xFF range — a regression that truncated the hex or
    // swapped endianness in `hex::encode` would surface here.
    let pk_bytes: Vec<u8> = (0u8..=15).cycle().take(64).collect();
    state
        .rocks
        .store_public_key_anchor(&hash, &pk_bytes)
        .expect("store anchor pk");

    let v = compute_identity_pk(state, hash.clone()).await;
    assert_eq!(
        v.get("identity_hash").and_then(|x| x.as_str()),
        Some(hash.as_str()),
        "identity_hash echoed verbatim on Some-branch",
    );
    assert_eq!(
            v.get("tier").and_then(|x| x.as_str()),
            Some("identities_anchor"),
            "anchor-tier write MUST surface tier='identities_anchor' (literal CF name from get_public_key_with_tier)",
        );
    // Hex round-trip — accounts / identity_fetcher decode this back to
    // raw bytes before signature verification, so the encoding contract
    // is load-bearing.
    let hex_str = v
        .get("pk")
        .and_then(|x| x.as_str())
        .expect("pk MUST be JSON String on Some-branch (NOT null)");
    let decoded = hex::decode(hex_str).expect("pk hex MUST decode back to original bytes");
    assert_eq!(
            decoded, pk_bytes,
            "pk hex round-trip MUST be byte-identical to the original (no truncation, no endianness swap)",
        );
}

#[tokio::test]
async fn batch_eee_compute_identity_pk_witness_tier_emits_identities_witness_label() {
    let state = test_state();
    let hash = "b".repeat(64);
    // No prior anchor entry — the witness-tier demotion guard at
    // store_public_key_witness:1739 short-circuits if an anchor entry
    // already exists, so we test the clean fresh-witness path here.
    let pk_bytes = vec![0xDDu8; 32];
    state
        .rocks
        .store_public_key_witness(&hash, &pk_bytes)
        .expect("store witness pk");

    let v = compute_identity_pk(state, hash.clone()).await;
    assert_eq!(
        v.get("tier").and_then(|x| x.as_str()),
        Some("identities_witness"),
        "witness-tier write MUST surface tier='identities_witness' (literal CF name)",
    );
    assert_eq!(
        v.get("identity_hash").and_then(|x| x.as_str()),
        Some(hash.as_str()),
        "identity_hash echoed verbatim",
    );
    assert_eq!(
        v.get("pk").and_then(|x| x.as_str()),
        Some(hex::encode(&pk_bytes).as_str()),
        "pk hex round-trip on witness branch",
    );
}

#[tokio::test]
async fn batch_eee_compute_identity_pk_user_tier_emits_identities_user_label() {
    let state = test_state();
    let hash = "c".repeat(64);
    // User-tier path — no prior anchor or witness entry, so the Phase-C
    // demotion guards at store_public_key_user_at:1807 and :1811 don't
    // fire and we land cleanly in CF_IDENTITIES_USER.
    let pk_bytes = vec![0xEEu8; 48];
    state
        .rocks
        .store_public_key_user(&hash, &pk_bytes)
        .expect("store user pk");

    let v = compute_identity_pk(state, hash.clone()).await;
    assert_eq!(
        v.get("tier").and_then(|x| x.as_str()),
        Some("identities_user"),
        "user-tier write MUST surface tier='identities_user' (literal CF name)",
    );
    assert_eq!(
        v.get("identity_hash").and_then(|x| x.as_str()),
        Some(hash.as_str()),
        "identity_hash echoed verbatim",
    );
    assert_eq!(
        v.get("pk").and_then(|x| x.as_str()),
        Some(hex::encode(&pk_bytes).as_str()),
        "pk hex round-trip on user branch",
    );
}

#[tokio::test]
async fn batch_eee_compute_identity_pk_legacy_identities_cf_fallback() {
    let state = test_state();
    let hash = "d".repeat(64);
    // Legacy `store_public_key` writes to CF_IDENTITIES (the
    // pre-Phase-B unpartitioned bucket). `get_public_key_with_tier`
    // walks anchor → witness → user → identities (legacy), so a node
    // that imported a pre-Phase-B snapshot and never re-keyed will
    // fall through to this branch. Pinning ensures the 4th term of
    // the CF walk remains observable through the helper (a regression
    // dropping CF_IDENTITIES from the walk array would silently brick
    // back-compat for legacy operators).
    let pk_bytes = vec![0xCCu8; 16];
    state
        .rocks
        .store_public_key(&hash, &pk_bytes)
        .expect("store legacy pk");

    let v = compute_identity_pk(state, hash.clone()).await;
    assert_eq!(
            v.get("tier").and_then(|x| x.as_str()),
            Some("identities"),
            "legacy CF_IDENTITIES write MUST surface tier='identities' (4th CF in get_public_key_with_tier walk — back-compat for pre-Phase-B snapshots)",
        );
    assert_eq!(
        v.get("pk").and_then(|x| x.as_str()),
        Some(hex::encode(&pk_bytes).as_str()),
        "pk hex round-trip on legacy branch",
    );
}

#[tokio::test]
async fn batch_eee_compute_identity_pk_tier_precedence_and_strict_three_key_envelope_both_branches()
{
    let state = test_state();
    // ── Axis 5a: ANCHOR outranks USER on parallel raw-puts ──
    // We bypass the Phase-C tombstone cascade in `store_public_key_anchor`
    // by writing both CFs directly via `put_cf_raw`. This models the
    // "legacy snapshot import predates the cascade" scenario where the
    // same identity_hash physically exists in two CFs. The walk order in
    // `get_public_key_with_tier` is the canonical precedence — ANCHOR
    // first → ANCHOR wins. If a future refactor flips the walk to
    // USER-first, identity_fetcher would surface a user-tier PK while
    // the same identity has an authoritative anchor PK on disk, breaking
    // the trust hierarchy.
    let hash = "e".repeat(64);
    let anchor_pk = vec![0x11u8; 32];
    let user_pk = vec![0x22u8; 32];
    assert_ne!(anchor_pk, user_pk, "test setup: PKs must differ");
    state
        .rocks
        .put_cf_raw("identities_anchor", hash.as_bytes(), &anchor_pk)
        .expect("raw put anchor");
    state
        .rocks
        .put_cf_raw("identities_user", hash.as_bytes(), &user_pk)
        .expect("raw put user");

    let v = compute_identity_pk(state.clone(), hash.clone()).await;
    assert_eq!(
            v.get("tier").and_then(|x| x.as_str()),
            Some("identities_anchor"),
            "tier MUST be 'identities_anchor' when both anchor and user CFs hold the same hash (CF-walk order is the canonical precedence)",
        );
    assert_eq!(
            v.get("pk").and_then(|x| x.as_str()),
            Some(hex::encode(&anchor_pk).as_str()),
            "pk MUST be the ANCHOR bytes, NOT the user bytes — proves the walk returns the FIRST hit and does not silently merge or fall through",
        );

    // ── Axis 5b: strict 3-key envelope on the Some branch ──
    let some_obj = v
        .as_object()
        .expect("compute_identity_pk Some branch MUST return a top-level JSON Object");
    let mut some_keys: Vec<&str> = some_obj.keys().map(|s| s.as_str()).collect();
    some_keys.sort();
    assert_eq!(
            some_keys,
            vec!["identity_hash", "pk", "tier"],
            "Some branch envelope MUST emit EXACTLY 3 keys {{identity_hash, pk, tier}} — any future addition (e.g. expires_at) MUST surface here before SDKs inflate parsers",
        );

    // ── Axis 5c: strict 3-key envelope on the None branch with key-set equality to Some-branch ──
    // Critical wire contract: the None branch ships the SAME 3-key shape
    // as the Some branch with `pk` and `tier` set to JSON Null, NOT a
    // 1-key {error:…} envelope. Callers in network::identity_fetcher do
    // `resp.pk.is_null()` to detect soft-fail — a 1-key error envelope
    // would crash the deserializer (per internal design notes §6).
    let missing_hash = "0".repeat(64);
    let none_v = compute_identity_pk(state, missing_hash.clone()).await;
    let none_obj = none_v
        .as_object()
        .expect("compute_identity_pk None branch MUST also return a top-level JSON Object");
    let mut none_keys: Vec<&str> = none_obj.keys().map(|s| s.as_str()).collect();
    none_keys.sort();
    assert_eq!(
            none_keys, some_keys,
            "None-branch key-set MUST EQUAL Some-branch key-set — wire contract for the identity_fetcher soft-fail path (pk.is_null() detect, NOT a 1-key error envelope)",
        );
    assert!(
            none_obj.get("pk").map(|x| x.is_null()).unwrap_or(false),
            "None branch: pk MUST be JSON Null (NOT empty-string, NOT missing key) — identity_fetcher relies on .is_null() for soft-fail detection",
        );
    assert!(
            none_obj.get("tier").map(|x| x.is_null()).unwrap_or(false),
            "None branch: tier MUST be JSON Null (NOT empty-string, NOT missing key) — symmetric Null-type pin to pk",
        );
    assert_eq!(
            none_obj.get("identity_hash").and_then(|x| x.as_str()),
            Some(missing_hash.as_str()),
            "None branch: identity_hash echoed verbatim even on miss (so caller can correlate response with request)",
        );
}

// ─── compute_epoch_status (explorer.rs:885) ──────────────────
// A fresh operator-facing
// endpoint with ZERO direct test coverage. `compute_epoch_status` is the
// /epoch/status wire contract: a single top-level `epochs` array of
// per-zone {zone, epoch_number, latest_seal_id, latest_seal_hash} objects
// sourced from `EpochState.latest_epoch` keys. Previously unpinned axes:
// (a) fresh-state empty-epochs branch (the `.iter().map().collect()`
// on an empty HashMap MUST produce `[]` not null nor missing key);
// (b) per-entry 4-key envelope (any silent addition like `vrf_output`
// would inflate operator dashboards);
// (c) hex-encoding round-trip of `latest_seal_hash` (a regression to
// base64 or uppercase or `.to_string()` of bytes would silently break
// light clients verifying against seal hashes);
// (d) defensive defaults — `latest_seal_id.get().unwrap_or(&String::new())`
// AND `latest_seal_hash.get().map(hex::encode).unwrap_or_default()` mean
// a zone with `latest_epoch` populated but no seal_id/seal_hash row
// MUST emit empty-string (NOT null, NOT missing key — accounts strict-
// parse `latest_seal_id: String`);
// (e) array-length contract — entries.len() == latest_epoch.len() even
// when the seal_id/seal_hash maps are sparse (the iteration walks
// `latest_epoch`, NOT the sealed maps).
//
// Axes: (1) fresh-state strict 2-key envelope {epochs: [], total: 0};
// (2) single-zone happy-path full 4-key entry with all fields populated;
// (3) hex round-trip — `hex::decode(latest_seal_hash) == original [u8;32]`;
// (4) missing seal_id + seal_hash → empty-string defaults (NOT null);
// (5) multi-zone count + per-entry shape contract across N=3 zones.

#[tokio::test]
async fn batch_fff_compute_epoch_status_fresh_state_emits_empty_epochs_array_with_total_count_envelope(
) {
    let state = test_state();
    let v = compute_epoch_status(&state, None).await;
    let obj = v
        .as_object()
        .expect("compute_epoch_status MUST return a top-level JSON Object");
    let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    keys.sort();
    // Strict 2-key envelope {epochs, total} catches any future silent field
    // addition. `total` was added with the public-surface response bound so a
    // caller can detect truncation (epochs.len() < total) — pinned here so a
    // later edit can't drop it (light clients depend on the true count).
    assert_eq!(
        keys,
        vec!["epochs", "total"],
        "top-level envelope MUST emit EXACTLY 2 keys {{epochs, total}} — no silent inflation",
    );
    let epochs = obj
        .get("epochs")
        .and_then(|x| x.as_array())
        .expect("`epochs` MUST be a JSON Array on fresh state (NOT null, NOT Object)");
    assert!(
        epochs.is_empty(),
        "fresh-state `epochs` array MUST be empty — no zones registered yet",
    );
    assert_eq!(
        obj.get("total").and_then(|x| x.as_u64()),
        Some(0),
        "fresh-state `total` MUST be 0 — no zones tracked yet",
    );
}

#[tokio::test]
async fn batch_fff_compute_epoch_status_single_zone_happy_path_emits_four_key_entry_with_all_fields_populated(
) {
    let state = test_state();
    let zone = crate::network::zone::ZoneId::from_legacy(7);
    let seal_id = "fffeeeddccbbaa9988776655443322110011223344556677889900aabbccddee";
    let seal_hash: [u8; 32] = [0xAB; 32];
    {
        let mut epoch = state.epoch.write_recover();
        epoch.latest_epoch.insert(zone.clone(), 42);
        epoch
            .latest_seal_id
            .insert(zone.clone(), seal_id.to_string());
        epoch.latest_seal_hash.insert(zone.clone(), seal_hash);
    }
    let v = compute_epoch_status(&state, None).await;
    let epochs = v
        .get("epochs")
        .and_then(|x| x.as_array())
        .expect("`epochs` MUST be a JSON Array");
    assert_eq!(epochs.len(), 1, "exactly one entry — one zone inserted",);
    let entry = epochs[0]
        .as_object()
        .expect("per-entry MUST be a JSON Object");
    let mut entry_keys: Vec<&str> = entry.keys().map(|s| s.as_str()).collect();
    entry_keys.sort();
    // Strict 4-key envelope per entry — a future addition (e.g. `vrf_output`
    // or `sealed_at_ts`) would silently inflate operator dashboards and
    // surface here BEFORE production. Hand-coded json!() at L891 freezes
    // the per-entry wire shape.
    assert_eq!(
            entry_keys,
            vec!["epoch_number", "latest_seal_hash", "latest_seal_id", "zone"],
            "per-entry envelope MUST emit EXACTLY 4 keys {{zone, epoch_number, latest_seal_id, latest_seal_hash}}",
        );
    // ZoneId newtype tuple-struct serializes transparently as its inner
    // String. A regression to a tuple-serialized form `["7"]` or an
    // Object form `{"path":"7"}` would surface here.
    assert_eq!(
        entry.get("zone").and_then(|x| x.as_str()),
        Some("7"),
        "zone field MUST be the legacy numeric ZoneId string `7`",
    );
    let ep = entry
        .get("epoch_number")
        .expect("epoch_number key must exist");
    assert!(
        ep.is_u64(),
        "epoch_number MUST be JSON Number-u64 (NOT String, NOT f64) — light clients strict-parse",
    );
    assert_eq!(ep.as_u64(), Some(42));
    assert_eq!(
        entry.get("latest_seal_id").and_then(|x| x.as_str()),
        Some(seal_id),
        "latest_seal_id MUST echo the inserted record_id verbatim",
    );
    let hash_str = entry
        .get("latest_seal_hash")
        .and_then(|x| x.as_str())
        .expect("latest_seal_hash MUST be JSON String on populated branch");
    // Pin lowercase hex (`hex::encode` default) — a regression to
    // `hex::encode_upper` or `format!("{:X}", _)` would surface here.
    assert_eq!(
            hash_str,
            "abababababababababababababababababababababababababababababababab",
            "latest_seal_hash MUST be the lowercase-hex encoding of the 32-byte content hash (64 chars for 32 bytes)",
        );
}

#[tokio::test]
async fn batch_fff_compute_epoch_status_seal_hash_hex_round_trips_via_hex_decode_to_original_bytes()
{
    let state = test_state();
    let zone = crate::network::zone::ZoneId::from_legacy(0);
    // Cycle 0x00..=0x0F across 32 bytes — exercises both nibbles of every
    // hex digit pair. Catches regressions to truncated encoding (`{:x}`
    // on `&[u8]` is NOT defined), uppercase (`hex::encode_upper`), or
    // a string-debug `format!("{:?}", bytes)` which would yield
    // `[0, 1, 2, …]` and trivially fail `hex::decode`.
    let seal_hash: [u8; 32] = std::array::from_fn(|i| (i as u8) & 0x0F);
    {
        let mut epoch = state.epoch.write_recover();
        epoch.latest_epoch.insert(zone.clone(), 1);
        epoch
            .latest_seal_id
            .insert(zone.clone(), "dummy".to_string());
        epoch.latest_seal_hash.insert(zone.clone(), seal_hash);
    }
    let v = compute_epoch_status(&state, None).await;
    let epochs = v
        .get("epochs")
        .and_then(|x| x.as_array())
        .expect("`epochs` array must exist");
    assert_eq!(epochs.len(), 1);
    let hash_str = epochs[0]
        .get("latest_seal_hash")
        .and_then(|x| x.as_str())
        .expect("latest_seal_hash MUST be JSON String");
    // The wire contract: callers (light clients, explorers) MUST be able
    // to `hex::decode(latest_seal_hash)` and get back exactly the 32 bytes
    // that were stored. Any byte-identity break (truncation, leading zero
    // strip, endian swap) surfaces here.
    let decoded = hex::decode(hash_str).expect("latest_seal_hash MUST be valid hex");
    assert_eq!(
            decoded.as_slice(),
            seal_hash.as_slice(),
            "hex::decode(latest_seal_hash) MUST round-trip byte-identical to the original [u8; 32] content hash — wire contract for light-client seal verification",
        );
    assert_eq!(
        decoded.len(),
        32,
        "decoded byte length MUST equal 32 — pins the content-hash size invariant",
    );
}

#[tokio::test]
async fn batch_fff_compute_epoch_status_missing_seal_id_and_hash_default_to_empty_string_not_null()
{
    let state = test_state();
    let zone = crate::network::zone::ZoneId::from_legacy(99);
    // Populate ONLY `latest_epoch` — leave `latest_seal_id` and
    // `latest_seal_hash` un-inserted for this zone. The iteration in
    // compute_epoch_status walks `latest_epoch`, so this zone MUST
    // appear in the output; the missing entries MUST surface as the
    // documented defensive defaults: empty-string for `latest_seal_id`
    // (via `.unwrap_or(&String::new())` at L894) AND empty-string for
    // `latest_seal_hash` (via `.unwrap_or_default()` on the
    // hex-encoded Option<String> at L895). NOT JSON Null. NOT missing
    // keys. Wallets strict-parse both fields as `String`, so emitting
    // null would crash deserialization.
    {
        let mut epoch = state.epoch.write_recover();
        epoch.latest_epoch.insert(zone.clone(), 5);
    }
    let v = compute_epoch_status(&state, None).await;
    let epochs = v
        .get("epochs")
        .and_then(|x| x.as_array())
        .expect("`epochs` array must exist");
    assert_eq!(
            epochs.len(),
            1,
            "entry count tracks latest_epoch.len() — sparse seal_id/seal_hash maps MUST NOT suppress the entry",
        );
    let entry = epochs[0].as_object().expect("entry must be Object");
    // Both fields MUST be present as keys (not omitted via a
    // `#[serde(skip_serializing_if = "String::is_empty")]` regression
    // on the source map) AND MUST be JSON String type (not Null).
    let seal_id = entry
        .get("latest_seal_id")
        .expect("latest_seal_id key MUST be present even on missing-row branch");
    assert!(
            seal_id.is_string(),
            "latest_seal_id on missing-row branch MUST be JSON String (empty), NOT Null — accounts strict-parse as String",
        );
    assert_eq!(
        seal_id.as_str(),
        Some(""),
        "latest_seal_id default MUST be empty-string per `.unwrap_or(&String::new())` at L894",
    );
    let seal_hash = entry
        .get("latest_seal_hash")
        .expect("latest_seal_hash key MUST be present even on missing-row branch");
    assert!(
            seal_hash.is_string(),
            "latest_seal_hash on missing-row branch MUST be JSON String (empty), NOT Null — symmetric to latest_seal_id",
        );
    assert_eq!(
            seal_hash.as_str(),
            Some(""),
            "latest_seal_hash default MUST be empty-string per `.unwrap_or_default()` on the hex-encoded Option<String> at L895",
        );
    // Sanity-check that epoch_number IS populated (so we can't have a
    // false-positive where the entry is just empty everywhere).
    assert_eq!(
            entry.get("epoch_number").and_then(|x| x.as_u64()),
            Some(5),
            "epoch_number MUST still reflect the inserted value — pins that latest_epoch IS the iteration root",
        );
}

#[tokio::test]
async fn batch_fff_compute_epoch_status_multi_zone_enumeration_emits_n_entries_with_strict_four_key_shape(
) {
    let state = test_state();
    // Three distinct zones with coprime epoch numbers — any aliasing
    // (e.g. iter.dedup, hash collision in serialization) would surface
    // as a missing entry or duplicate epoch_number value. Use
    // hierarchical paths AND legacy numeric to exercise both
    // construction branches.
    let zones = vec![
        (crate::network::zone::ZoneId::new("medical/eu"), 11u64),
        (crate::network::zone::ZoneId::from_legacy(13), 17u64),
        (crate::network::zone::ZoneId::new("iot/sensors"), 23u64),
    ];
    {
        let mut epoch = state.epoch.write_recover();
        for (z, e) in &zones {
            epoch.latest_epoch.insert(z.clone(), *e);
        }
    }
    let v = compute_epoch_status(&state, None).await;
    let epochs = v
        .get("epochs")
        .and_then(|x| x.as_array())
        .expect("`epochs` array must exist");
    assert_eq!(
        epochs.len(),
        3,
        "entry count MUST equal latest_epoch.len() — N=3 zones inserted",
    );
    // Every entry MUST satisfy the strict 4-key shape. HashMap iteration
    // order is non-deterministic, so we look up by zone path rather than
    // assert positional order. Also verify the (zone → epoch_number)
    // mapping round-trips for each inserted pair — pins that the
    // helper's `(zone, epoch_number)` tuple destructure carries the
    // correct value (not e.g. a constant default leaked from somewhere).
    let mut seen_epochs: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for entry in epochs {
        let entry_obj = entry.as_object().expect("entry must be Object");
        let mut entry_keys: Vec<&str> = entry_obj.keys().map(|s| s.as_str()).collect();
        entry_keys.sort();
        assert_eq!(
            entry_keys,
            vec!["epoch_number", "latest_seal_hash", "latest_seal_id", "zone"],
            "every per-entry envelope MUST emit EXACTLY 4 keys — strict shape across all N entries",
        );
        let z = entry_obj
            .get("zone")
            .and_then(|x| x.as_str())
            .expect("zone field MUST be JSON String")
            .to_string();
        let e = entry_obj
            .get("epoch_number")
            .and_then(|x| x.as_u64())
            .expect("epoch_number MUST be JSON Number-u64");
        seen_epochs.insert(z, e);
    }
    // Cross-check every inserted (zone, epoch) pair survived the
    // serialization round-trip. A regression that swapped `epoch_number`
    // for a constant or dropped a zone entry would surface here.
    for (z, e) in &zones {
        assert_eq!(
                seen_epochs.get(z.path()).copied(),
                Some(*e),
                "zone `{}` MUST emit epoch_number={} — each inserted (zone, epoch) pair survives the serialization",
                z.path(),
                e,
            );
    }
}

// Public-surface response bound: `/epochs` is anonymous + unauthenticated, so
// a single GET must not be able to dump one row per zone for the whole zone
// set (1M-zone design target). `limit` bounds the returned `epochs` array while
// `total` still reports the TRUE zone count so a caller detects truncation as
// `epochs.len() < total`. Rows are ordered by zone id so the returned page is
// a deterministic lowest-ids-first slice, not an arbitrary HashMap sample.
#[tokio::test]
async fn batch_fff_compute_epoch_status_bounds_returned_rows_while_total_reports_true_zone_count() {
    let state = test_state();
    {
        let mut epoch = state.epoch.write_recover();
        for n in 0..5u64 {
            epoch
                .latest_epoch
                .insert(crate::network::zone::ZoneId::from_legacy(n), n);
        }
    }
    // Request a page smaller than the zone set.
    let v = compute_epoch_status(&state, Some(2)).await;
    let epochs = v
        .get("epochs")
        .and_then(|x| x.as_array())
        .expect("`epochs` MUST be a JSON Array");
    assert_eq!(
        epochs.len(),
        2,
        "returned rows MUST be bounded by the requested limit",
    );
    assert_eq!(
        v.get("total").and_then(|x| x.as_u64()),
        Some(5),
        "`total` MUST report the TRUE zone count regardless of the page cap",
    );
    // Deterministic ordering — lowest zone ids first (string order "0","1").
    assert_eq!(
        epochs[0].get("zone").and_then(|x| x.as_str()),
        Some("0"),
        "page MUST be ordered by zone id — first row is the lowest id",
    );
    assert_eq!(
        epochs[1].get("zone").and_then(|x| x.as_str()),
        Some("1"),
        "page MUST be ordered by zone id — second row is the next lowest id",
    );
}

// ── compute_list_witness_profiles (explorer.rs:1374) ──────
// Wire contract for /witnesses/profiles: returns the strict 2-key envelope
// {profiles: [...], count: N} where each profile entry is a strict 4-key
// object {witness_hash, organization, subnet, geo_zone}. Previously this
// helper had ZERO direct test coverage — the only adjacent coverage was
// the `register_witness_profile` happy-path which asserts a profile
// is readable via `consensus.profiles()` but does NOT pin the JSON wire
// shape returned by this endpoint. Operator dashboards that list all
// registered witnesses rely on the strict 4-key entry envelope; a silent
// serde rename or skip_serializing_if would surface here.

#[tokio::test]
async fn batch_ggg_compute_list_witness_profiles_fresh_state_emits_empty_array_and_zero_count() {
    // Fresh-state contract: no profiles have been registered, so the
    // helper MUST emit `profiles: []` (NOT JSON Null, NOT missing key)
    // and `count: 0` as strict JSON Number-u64. A regression to
    // `.map().collect()` panicking on empty input, or `count` becoming
    // a String, would surface here. The fresh-state envelope is the
    // load-bearing shape for dashboards' empty-state UI.
    let state = test_state();
    let v = compute_list_witness_profiles(state, None).await;

    let obj = v.as_object().expect("top-level MUST be JSON Object");
    let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["count", "profiles"],
        "top-level envelope MUST emit EXACTLY 2 keys — strict shape, no `total` or `error` leakage",
    );

    let profiles = v
        .get("profiles")
        .and_then(|x| x.as_array())
        .expect("`profiles` MUST be a JSON Array (NOT null) on fresh state");
    assert!(
        profiles.is_empty(),
        "fresh state MUST emit an empty `profiles` array, not null and not missing key",
    );

    assert_eq!(
        v.get("count").and_then(|x| x.as_u64()),
        Some(0),
        "fresh-state `count` MUST be JSON Number-u64 zero (NOT String, NOT Null)",
    );
}

#[tokio::test]
async fn batch_ggg_compute_list_witness_profiles_single_profile_happy_path_emits_strict_four_key_entry(
) {
    // Single-profile happy path: register one witness via
    // consensus.register_profile (bypassing compute_register_witness_profile
    // so we directly exercise the read path under test), then assert the
    // emitted JSON entry mirrors all 4 fields verbatim. A regression that
    // renamed `witness_hash` → `hash`, or dropped `geo_zone` from the
    // entry, would break operator UIs (dashboards build per-zone heatmaps
    // off `geo_zone`; AML tooling builds per-org clusters off
    // `organization`). Pins the wire contract end-to-end.
    let state = test_state();
    {
        let mut consensus = state.consensus.lock_recover();
        consensus.register_profile(
            "wA-hex-deadbeef",
            crate::network::consensus::WitnessProfile {
                organization: "navigatorbuilds".into(),
                subnet: "10.0.0.0/24".into(),
                geo_zone: "eu-north".into(),
            },
        );
    }
    let v = compute_list_witness_profiles(state, None).await;

    let profiles = v
        .get("profiles")
        .and_then(|x| x.as_array())
        .expect("`profiles` array must exist");
    assert_eq!(profiles.len(), 1, "exactly 1 profile was registered");
    assert_eq!(
        v.get("count").and_then(|x| x.as_u64()),
        Some(1),
        "`count` MUST mirror profiles.len() for a 1-entry registry",
    );

    let entry = profiles[0]
        .as_object()
        .expect("profile entry MUST be JSON Object");
    let mut entry_keys: Vec<&str> = entry.keys().map(|s| s.as_str()).collect();
    entry_keys.sort();
    assert_eq!(
        entry_keys,
        vec!["geo_zone", "organization", "subnet", "witness_hash"],
        "per-entry envelope MUST emit EXACTLY 4 keys — pins wire shape for dashboards",
    );

    assert_eq!(
        entry.get("witness_hash").and_then(|x| x.as_str()),
        Some("wA-hex-deadbeef"),
        "`witness_hash` MUST be echoed verbatim — account lookups join on this string",
    );
    assert_eq!(
        entry.get("organization").and_then(|x| x.as_str()),
        Some("navigatorbuilds"),
        "`organization` MUST be echoed verbatim — AML cluster tooling joins on this",
    );
    assert_eq!(
        entry.get("subnet").and_then(|x| x.as_str()),
        Some("10.0.0.0/24"),
        "`subnet` MUST be echoed verbatim — locality grouping reads CIDR strings",
    );
    assert_eq!(
        entry.get("geo_zone").and_then(|x| x.as_str()),
        Some("eu-north"),
        "`geo_zone` MUST be echoed verbatim — per-zone heatmaps read this",
    );
}

#[tokio::test]
async fn batch_ggg_compute_list_witness_profiles_multi_profile_n3_enumeration_round_trips_all_triples(
) {
    // Multi-profile enumeration: register N=3 witnesses with mutually
    // distinct triples (3 orgs × 3 subnets × 3 geo_zones, all coprime so
    // any aliasing surfaces). HashMap iteration order is non-deterministic
    // (the backing store is a std HashMap inside AWCConsensus), so the
    // test looks up each entry by `witness_hash` rather than asserting
    // positional order. Cross-checks the `count == profiles.len()`
    // invariant — a regression that hand-counted `count` separately
    // from the array would surface as a count mismatch.
    let state = test_state();
    let expected: Vec<(&str, &str, &str, &str)> = vec![
        ("w1-hex", "org-a", "10.0.1", "earth-us"),
        ("w2-hex", "org-b", "10.0.2", "earth-eu"),
        ("w3-hex", "org-c", "10.0.3", "mars-olympus"),
    ];
    {
        let mut consensus = state.consensus.lock_recover();
        for (h, org, subnet, geo) in &expected {
            consensus.register_profile(
                h,
                crate::network::consensus::WitnessProfile {
                    organization: (*org).into(),
                    subnet: (*subnet).into(),
                    geo_zone: (*geo).into(),
                },
            );
        }
    }
    let v = compute_list_witness_profiles(state, None).await;

    let profiles = v
        .get("profiles")
        .and_then(|x| x.as_array())
        .expect("`profiles` array must exist");
    assert_eq!(
        profiles.len(),
        3,
        "exactly 3 profiles were registered — entry count MUST equal registry size",
    );
    assert_eq!(
        v.get("count").and_then(|x| x.as_u64()),
        Some(3),
        "`count` MUST equal profiles.len() — invariant across all N",
    );

    let mut seen: std::collections::HashMap<String, (String, String, String)> =
        std::collections::HashMap::new();
    for entry in profiles {
        let obj = entry.as_object().expect("entry MUST be Object");
        let mut entry_keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
        entry_keys.sort();
        assert_eq!(
            entry_keys,
            vec!["geo_zone", "organization", "subnet", "witness_hash"],
            "every per-entry envelope MUST emit EXACTLY 4 keys — strict shape across all N",
        );
        let h = obj
            .get("witness_hash")
            .and_then(|x| x.as_str())
            .expect("witness_hash MUST be String")
            .to_string();
        let org = obj
            .get("organization")
            .and_then(|x| x.as_str())
            .expect("organization MUST be String")
            .to_string();
        let subnet = obj
            .get("subnet")
            .and_then(|x| x.as_str())
            .expect("subnet MUST be String")
            .to_string();
        let geo = obj
            .get("geo_zone")
            .and_then(|x| x.as_str())
            .expect("geo_zone MUST be String")
            .to_string();
        seen.insert(h, (org, subnet, geo));
    }
    // Cross-check every inserted triple survived the serialization
    // round-trip. A regression that swapped `organization` for `subnet`
    // (or vice versa) would surface here even though both fields are
    // String-typed and would pass type checks.
    for (h, org, subnet, geo) in &expected {
        let (got_org, got_subnet, got_geo) = seen
            .get(*h)
            .unwrap_or_else(|| panic!("witness_hash `{}` MUST appear in the emitted array", h));
        assert_eq!(got_org, org, "organization MUST round-trip for `{}`", h);
        assert_eq!(got_subnet, subnet, "subnet MUST round-trip for `{}`", h);
        assert_eq!(got_geo, geo, "geo_zone MUST round-trip for `{}`", h);
    }
}

#[tokio::test]
async fn batch_ggg_compute_list_witness_profiles_empty_string_subnet_and_geo_emit_as_empty_string_not_null(
) {
    // Defensive default contract: the WitnessProfile struct permits
    // empty strings on `subnet` and `geo_zone` (consensus.rs:168;
    // production tests at consensus.rs:4427/4437 register profiles with
    // empty subnet AND empty geo_zone). The wire envelope MUST emit
    // those fields as JSON empty-string ("") — NOT JSON Null, NOT a
    // missing key. A regression that added
    // `#[serde(skip_serializing_if = "String::is_empty")]` to
    // WitnessProfile would silently drop the keys, breaking strict
    // 4-key account parsers that expect Value::String on both fields.
    // Note: `organization` cannot be tested empty via
    // compute_register_witness_profile (guarded at explorer.rs:1341),
    // but the registry path under test (consensus.register_profile)
    // has no such guard — so we exercise the unguarded path directly.
    let state = test_state();
    {
        let mut consensus = state.consensus.lock_recover();
        consensus.register_profile(
            "edge-case-witness",
            crate::network::consensus::WitnessProfile {
                organization: "org-x".into(),
                subnet: String::new(),
                geo_zone: String::new(),
            },
        );
    }
    let v = compute_list_witness_profiles(state, None).await;

    let entry = v
        .get("profiles")
        .and_then(|x| x.as_array())
        .and_then(|arr| arr.first())
        .and_then(|x| x.as_object())
        .expect("the single registered profile must emit a JSON Object entry");

    // Strict 4-key shape preserved even with empty values — defends
    // against the skip_serializing_if regression.
    let mut entry_keys: Vec<&str> = entry.keys().map(|s| s.as_str()).collect();
    entry_keys.sort();
    assert_eq!(
        entry_keys,
        vec!["geo_zone", "organization", "subnet", "witness_hash"],
        "strict 4-key envelope MUST hold even when subnet/geo_zone are empty strings",
    );

    // Type pin: both fields MUST be JSON String (NOT null) — strict
    // account parsers expecting `String` would break on Null.
    assert!(
        entry.get("subnet").map(|v| v.is_string()).unwrap_or(false),
        "`subnet` MUST be JSON String (not Null) for an empty-subnet profile",
    );
    assert!(
        entry
            .get("geo_zone")
            .map(|v| v.is_string())
            .unwrap_or(false),
        "`geo_zone` MUST be JSON String (not Null) for an empty-geo_zone profile",
    );

    // Value pin: empty string content.
    assert_eq!(
        entry.get("subnet").and_then(|x| x.as_str()),
        Some(""),
        "empty `subnet` MUST emit as JSON empty-string \"\" not Null and not missing",
    );
    assert_eq!(
        entry.get("geo_zone").and_then(|x| x.as_str()),
        Some(""),
        "empty `geo_zone` MUST emit as JSON empty-string \"\" not Null and not missing",
    );
}

#[tokio::test]
async fn batch_ggg_compute_list_witness_profiles_duplicate_witness_hash_overwrites_not_appends() {
    // Backing-store semantic pin: the WitnessProfile registry is a
    // HashMap<String, WitnessProfile> (consensus.rs:1724
    // `self.profiles.insert(...)`). Re-registering the same
    // witness_hash with different fields MUST overwrite (HashMap
    // semantics), NOT append a second entry (Vec semantics). The
    // emitted profiles array therefore has length 1 (not 2) and the
    // LATEST `(organization, subnet, geo_zone)` triple — pins the
    // map-not-vec choice against a refactor that switched the backing
    // store to a Vec for ordering guarantees. Such a regression would
    // double-count witnesses, breaking reputation aggregation that
    // sums per-witness scores. Also pins `count == profiles.len()`
    // invariant under the overwrite case.
    let state = test_state();
    {
        let mut consensus = state.consensus.lock_recover();
        // First registration.
        consensus.register_profile(
            "shared-hash",
            crate::network::consensus::WitnessProfile {
                organization: "old-org".into(),
                subnet: "10.0.0".into(),
                geo_zone: "earth-us".into(),
            },
        );
        // Re-registration with same hash, different triple.
        consensus.register_profile(
            "shared-hash",
            crate::network::consensus::WitnessProfile {
                organization: "new-org".into(),
                subnet: "172.16.0".into(),
                geo_zone: "mars-olympus".into(),
            },
        );
    }
    let v = compute_list_witness_profiles(state, None).await;

    let profiles = v
        .get("profiles")
        .and_then(|x| x.as_array())
        .expect("`profiles` array must exist");
    assert_eq!(
            profiles.len(),
            1,
            "duplicate witness_hash MUST overwrite NOT append (HashMap semantics, not Vec) — len=1 after two registrations of the same key",
        );
    assert_eq!(
        v.get("count").and_then(|x| x.as_u64()),
        Some(1),
        "`count == profiles.len()` invariant holds under the overwrite case",
    );

    // Latest-wins pin: the second registration's triple MUST be the
    // one emitted. A regression that preferred the first write (insert
    // semantics changed to `.or_insert(...)`) would surface here.
    let entry = profiles[0].as_object().expect("entry MUST be Object");
    assert_eq!(
        entry.get("witness_hash").and_then(|x| x.as_str()),
        Some("shared-hash"),
        "witness_hash MUST echo the shared key",
    );
    assert_eq!(
        entry.get("organization").and_then(|x| x.as_str()),
        Some("new-org"),
        "organization MUST be the LATEST write (HashMap last-insert-wins on key collision)",
    );
    assert_eq!(
        entry.get("subnet").and_then(|x| x.as_str()),
        Some("172.16.0"),
        "subnet MUST be the LATEST write — pins overwrite, not merge",
    );
    assert_eq!(
        entry.get("geo_zone").and_then(|x| x.as_str()),
        Some("mars-olympus"),
        "geo_zone MUST be the LATEST write — pins overwrite, not merge",
    );
}

#[tokio::test]
async fn batch_ggg_compute_list_witness_profiles_bounds_returned_rows_while_count_reports_true_total(
) {
    // Public-surface response bound: `/witnesses/profiles` is reachable over the
    // PQ verb by any handshaked peer and grows with the witness set, so a single
    // call must not dump every profile. `limit` bounds the returned `profiles`
    // array while `count` still reports the TRUE total so a caller detects
    // truncation as `profiles.len() < count`. Rows are ordered by witness_hash so
    // the page is a deterministic lowest-first slice. Envelope stays {profiles,
    // count} — no new key; `count` already played the total role.
    let state = test_state();
    {
        let mut consensus = state.consensus.lock_recover();
        for i in 0..5u8 {
            consensus.register_profile(
                &format!("wh-{i:02}"),
                crate::network::consensus::WitnessProfile {
                    organization: format!("org-{i}"),
                    subnet: "10.0.0.0/24".into(),
                    geo_zone: "eu-north".into(),
                },
            );
        }
    }
    // Request a page smaller than the profile set.
    let v = compute_list_witness_profiles(state, Some(2)).await;
    let profiles = v
        .get("profiles")
        .and_then(|x| x.as_array())
        .expect("`profiles` MUST be a JSON Array");
    assert_eq!(
        profiles.len(),
        2,
        "returned profiles MUST be bounded by the requested limit",
    );
    assert_eq!(
        v.get("count").and_then(|x| x.as_u64()),
        Some(5),
        "`count` MUST report the TRUE profile total regardless of the page cap",
    );
    // Deterministic ordering — lowest witness_hash first ("wh-00","wh-01").
    assert_eq!(
        profiles[0].get("witness_hash").and_then(|x| x.as_str()),
        Some("wh-00"),
        "page MUST be ordered by witness_hash — first row is the lowest",
    );
    assert_eq!(
        profiles[1].get("witness_hash").and_then(|x| x.as_str()),
        Some("wh-01"),
        "page MUST be ordered by witness_hash — second row is the next lowest",
    );
}

// ─── `compute_witness_reputation` orthogonal
// pins. explorer.rs:1448 had only 2
// earlier tests (unknown-witness default-baseline + no-filter fresh
// state). Missing axes: (1) KNOWN-witness happy-path strict 9-key
// envelope incl. trust_multiplier_effective + first_seen + the
// CRITICAL "note-must-be-absent" pin (catches a refactor that unified
// known/unknown branches into one shape); (2) multi-event score
// arithmetic via positive/negative deltas + post-event invariant
// score == DEFAULT_REPUTATION + Σdeltas; (3) unknown-witness STRICT
// 8-key envelope with `note` PRESENT and `first_seen` +
// `trust_multiplier_effective` ABSENT — orthogonal to (1), pins
// structural divergence; (4) None-branch summary multi-witness N=3
// strict 5-key per-entry shape (5-key NOT 9-key — summary entries
// intentionally omit score_decayed/trust_multiplier_effective/
// last_event/first_seen to bound JSON payload under heavy tracked-
// witnesses growth); (5) summary sort order descending by score —
// a regression to backing-HashMap iteration order would non-deterministic-
// ally break the explorer's "top-N most trusted" dashboard.
//
// Timestamp strategy: apply_event(_, _, 0.0) creates the witness with
// first_seen=0.0 and last_event=0.0 (the `timestamp > entry.last_event`
// guard is false since 0.0 > 0.0 is false). decay_score special-cases
// last_event==0.0 to return score UNCHANGED (reputation.rs:59);
// age_factor special-cases first_seen==0.0 to return AGE_FACTOR_FULL=1.0
// (reputation.rs:104). This makes score == score_decayed AND
// trust_multiplier == trust_multiplier_effective numerically, which
// makes the tests deterministic without needing to control
// SystemTime::now() inside compute_witness_reputation.

#[test]
fn batch_hhh_compute_witness_reputation_known_witness_emits_strict_nine_key_envelope_no_note() {
    // Known-witness Some(witness) branch at explorer.rs:1460-1471 emits
    // a 9-key envelope: witness_hash, score, score_decayed,
    // trust_multiplier, trust_multiplier_effective, positive_events,
    // negative_events, last_event, first_seen. The CRITICAL pin here
    // is the ABSENCE of the `note` key — that's the unknown-branch's
    // marker (line 1481). A refactor that unified the two branches
    // into one envelope would silently leak "unknown witness — default
    // reputation" into a real witness's reputation panel, breaking
    // accounts that key UX off the `note`-present-or-absent signal.
    let state = test_state();
    {
        let mut rep = state.reputation.lock_recover();
        // Legacy timestamp 0.0 → first_seen=last_event=0.0 → decay+age
        // both no-op, so score == score_decayed and trust_multiplier
        // == trust_multiplier_effective deterministically.
        rep.apply_event(
            "wA-hex-cafef00d",
            crate::network::reputation::ReputationEvent::Undisputed,
            0.0,
        );
    }
    let v = compute_witness_reputation(state, Some("wA-hex-cafef00d".into()), None);

    let obj = v.as_object().expect("top-level MUST be JSON Object");
    let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    keys.sort();
    assert_eq!(
            keys,
            vec![
                "first_seen",
                "last_event",
                "negative_events",
                "positive_events",
                "score",
                "score_decayed",
                "trust_multiplier",
                "trust_multiplier_effective",
                "witness_hash",
            ],
            "known-witness envelope MUST emit EXACTLY 9 keys — pins wire shape for /peers/reputation?witness=…",
        );

    assert_eq!(
        v.get("witness_hash").and_then(|x| x.as_str()),
        Some("wA-hex-cafef00d"),
        "witness_hash MUST echo the queried hash verbatim",
    );
    assert_eq!(
        v.get("score").and_then(|x| x.as_f64()),
        Some(51.0),
        "score = DEFAULT_REPUTATION(50) + DELTA_UNDISPUTED(+1) = 51.0",
    );
    assert_eq!(
            v.get("score_decayed").and_then(|x| x.as_f64()),
            Some(51.0),
            "legacy last_event=0.0 → decay_score returns score unchanged (reputation.rs:59 special case)",
        );
    assert_eq!(
        v.get("trust_multiplier").and_then(|x| x.as_f64()),
        Some(0.51),
        "trust_multiplier = score_to_multiplier(51.0) = 51/100 = 0.51",
    );
    assert_eq!(
        v.get("trust_multiplier_effective").and_then(|x| x.as_f64()),
        Some(0.51),
        "legacy first_seen=0.0 → AGE_FACTOR_FULL=1.0 → effective == raw trust_multiplier",
    );
    assert_eq!(
        v.get("positive_events").and_then(|x| x.as_u64()),
        Some(1),
        "Undisputed (delta>0) bumps positive_events to 1",
    );
    assert_eq!(
        v.get("negative_events").and_then(|x| x.as_u64()),
        Some(0),
        "no DisputeLost/Spam events → negative_events stays 0",
    );
    assert_eq!(
        v.get("last_event").and_then(|x| x.as_f64()),
        Some(0.0),
        "last_event = applied timestamp = 0.0 (legacy)",
    );
    assert_eq!(
        v.get("first_seen").and_then(|x| x.as_f64()),
        Some(0.0),
        "first_seen = first apply_event timestamp = 0.0",
    );

    assert!(
            v.get("note").is_none(),
            "known-witness branch MUST NOT include `note` — that's the unknown branch's marker; a regression that unified the two branches would surface here",
        );
}

#[test]
fn batch_hhh_compute_witness_reputation_mixed_events_score_arithmetic_with_positive_negative_split()
{
    // Multi-event accumulation pin: apply_event clamps each step
    // (reputation.rs:319) and tracks positive/negative independently.
    // 2× Undisputed (delta=+1) + 1× DisputeLost (delta=-5) → final
    // score = 50 + 1 + 1 - 5 = 47, positive=2 (incremented by every
    // delta>0), negative=1 (incremented by every delta<=0). A
    // regression that collapsed positive/negative into a single
    // signed counter would surface as either of these counts being
    // wrong. trust_multiplier = score/100 = 0.47.
    let state = test_state();
    {
        let mut rep = state.reputation.lock_recover();
        rep.apply_event(
            "wB-mixed",
            crate::network::reputation::ReputationEvent::Undisputed,
            0.0,
        );
        rep.apply_event(
            "wB-mixed",
            crate::network::reputation::ReputationEvent::Undisputed,
            0.0,
        );
        rep.apply_event(
            "wB-mixed",
            crate::network::reputation::ReputationEvent::DisputeLost,
            0.0,
        );
    }
    let v = compute_witness_reputation(state, Some("wB-mixed".into()), None);

    assert_eq!(
        v.get("score").and_then(|x| x.as_f64()),
        Some(47.0),
        "score = DEFAULT(50) + 2×Undisputed(+1) + 1×DisputeLost(-5) = 47.0",
    );
    assert_eq!(
            v.get("positive_events").and_then(|x| x.as_u64()),
            Some(2),
            "Undisputed events bump positive_events INDEPENDENT of net score sign — 2 positive events even though score dropped below 50",
        );
    assert_eq!(
        v.get("negative_events").and_then(|x| x.as_u64()),
        Some(1),
        "DisputeLost bumps negative_events to 1",
    );
    assert_eq!(
        v.get("trust_multiplier").and_then(|x| x.as_f64()),
        Some(0.47),
        "trust_multiplier = 47/100 = 0.47 (score_to_multiplier)",
    );
}

#[test]
fn batch_hhh_compute_witness_reputation_unknown_witness_emits_strict_eight_key_envelope_with_note()
{
    // Unknown-witness Some(witness) branch at explorer.rs:1473-1483 emits
    // an 8-key envelope: witness_hash, score, score_decayed,
    // trust_multiplier, positive_events, negative_events, last_event,
    // note. CRITICAL pin: `note` PRESENT, AND `first_seen` /
    // `trust_multiplier_effective` ABSENT. Orthogonal to the known-
    // witness 9-key pin in test 1. A regression that aligned the two
    // branches (e.g. always including `first_seen=0.0` for unknown)
    // would silently break accounts that render "never seen" UI off
    // the `note`-present + `first_seen`-absent signature.
    let state = test_state();
    let v = compute_witness_reputation(state, Some("unknown-hex-deadbeef".into()), None);

    let obj = v.as_object().expect("top-level MUST be JSON Object");
    let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    keys.sort();
    assert_eq!(
            keys,
            vec![
                "last_event",
                "negative_events",
                "note",
                "positive_events",
                "score",
                "score_decayed",
                "trust_multiplier",
                "witness_hash",
            ],
            "unknown-witness envelope MUST emit EXACTLY 8 keys (incl. `note`, excl. `first_seen` + `trust_multiplier_effective`)",
        );

    assert!(
            v.get("first_seen").is_none(),
            "unknown branch MUST NOT include `first_seen` — that's the known branch's identity-tracking marker",
        );
    assert!(
            v.get("trust_multiplier_effective").is_none(),
            "unknown branch MUST NOT include `trust_multiplier_effective` — known-branch-only field (no decay/age for default witness)",
        );
    assert!(
            v.get("note").is_some_and(|x| x.is_string()),
            "unknown branch MUST carry `note` as JSON-String (account renders 'unknown witness — default reputation')",
        );
    assert!(
            v.get("last_event").is_some_and(|x| x.is_null()),
            "unknown-witness last_event MUST be JSON null (NOT 0.0 sentinel) — distinguishes 'never seen' from 'seen at epoch 0'",
        );
}

#[test]
fn batch_hhh_compute_witness_reputation_no_filter_multi_witness_entries_emit_strict_five_keys() {
    // None-branch summary view at explorer.rs:1486-1502: when N
    // witnesses are tracked, the emitted `witnesses` array MUST have
    // N entries, each with EXACTLY 5 keys (witness_hash, score,
    // trust_multiplier, positive_events, negative_events). Unlike
    // the known-witness branch (9 keys), summary entries
    // INTENTIONALLY omit score_decayed / trust_multiplier_effective /
    // last_event / first_seen — the per-entry footprint is smaller
    // so the JSON payload stays bounded under heavy tracked-witnesses
    // growth (10K+ witnesses × 9 keys would blow past the account
    // strict-parse buffer). A regression that aligned summary
    // entries to the 9-key known-witness shape would silently
    // 2-3× the response payload.
    let state = test_state();
    {
        let mut rep = state.reputation.lock_recover();
        rep.apply_event(
            "wC-1",
            crate::network::reputation::ReputationEvent::Undisputed,
            0.0,
        );
        rep.apply_event(
            "wC-2",
            crate::network::reputation::ReputationEvent::Undisputed,
            0.0,
        );
        rep.apply_event(
            "wC-3",
            crate::network::reputation::ReputationEvent::Undisputed,
            0.0,
        );
    }
    let v = compute_witness_reputation(state, None, None);

    let obj = v.as_object().expect("top-level MUST be JSON Object");
    let mut top_keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    top_keys.sort();
    assert_eq!(
        top_keys,
        vec!["tracked_witnesses", "witnesses"],
        "None-branch top-level envelope MUST be EXACTLY 2 keys",
    );
    assert_eq!(
        v.get("tracked_witnesses").and_then(|x| x.as_u64()),
        Some(3),
        "3 distinct witnesses applied → tracked_count() == 3",
    );
    let witnesses = v
        .get("witnesses")
        .and_then(|x| x.as_array())
        .expect("witnesses MUST be a JSON Array");
    assert_eq!(
        witnesses.len(),
        3,
        "3 apply_event calls on distinct hashes → 3 array entries",
    );

    for entry in witnesses {
        let obj = entry.as_object().expect("each entry MUST be Object");
        let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
        keys.sort();
        assert_eq!(
                keys,
                vec![
                    "negative_events",
                    "positive_events",
                    "score",
                    "trust_multiplier",
                    "witness_hash",
                ],
                "summary-entry envelope MUST be EXACTLY 5 keys — no score_decayed/trust_multiplier_effective/last_event/first_seen leakage from the known-witness branch",
            );
    }
}

#[test]
fn batch_hhh_compute_witness_reputation_no_filter_witnesses_sorted_descending_by_score() {
    // summary_at(now) sorts by decayed_score DESCENDING
    // (reputation.rs:546). With three distinct deltas DisputeWon(+2)
    // / Undisputed(+1) / DisputeLost(-5) producing scores 52 > 51 >
    // 45, the emitted witnesses array MUST be sorted in that order.
    // A regression to insertion-order would produce non-deterministic
    // JSON because the backing HashMap<String, WitnessReputation>
    // iterates in unspecified order — breaking explorer "top-N most
    // trusted" dashboards that consume the array directly without
    // re-sorting on the account side.
    let state = test_state();
    {
        let mut rep = state.reputation.lock_recover();
        rep.apply_event(
            "wD-top",
            crate::network::reputation::ReputationEvent::DisputeWon,
            0.0,
        ); // score 50+2 = 52
        rep.apply_event(
            "wD-mid",
            crate::network::reputation::ReputationEvent::Undisputed,
            0.0,
        ); // score 50+1 = 51
        rep.apply_event(
            "wD-bot",
            crate::network::reputation::ReputationEvent::DisputeLost,
            0.0,
        ); // score 50-5 = 45
    }
    let v = compute_witness_reputation(state, None, None);

    let witnesses = v
        .get("witnesses")
        .and_then(|x| x.as_array())
        .expect("witnesses array");
    assert_eq!(witnesses.len(), 3);

    let scores: Vec<f64> = witnesses
        .iter()
        .map(|e| {
            e.get("score")
                .and_then(|x| x.as_f64())
                .expect("score must be Number-f64")
        })
        .collect();

    assert_eq!(
        scores[0], 52.0,
        "highest score (DisputeWon witness, +2) MUST be first — summary_at sorts desc",
    );
    assert_eq!(
        scores[1], 51.0,
        "middle score (Undisputed witness, +1) MUST be second",
    );
    assert_eq!(
        scores[2], 45.0,
        "lowest score (DisputeLost witness, -5) MUST be third",
    );

    // Cross-check positional witness_hash alignment to score order.
    assert_eq!(
        witnesses[0].get("witness_hash").and_then(|x| x.as_str()),
        Some("wD-top"),
        "top-score witness_hash MUST be wD-top — pins sort key (score) to identity (witness_hash)",
    );
    assert_eq!(
        witnesses[2].get("witness_hash").and_then(|x| x.as_str()),
        Some("wD-bot"),
        "bottom-score witness_hash MUST be wD-bot",
    );
}

#[test]
fn batch_hhh_compute_witness_reputation_explicit_limit_truncates_to_top_n_by_score_count_true() {
    // SCALE-RULE page bound on the no-filter summary: an explicit limit caps the
    // `witnesses` array to the top-N by decayed score while `tracked_witnesses`
    // stays the TRUE count. Plant 3 witnesses with scores 52 > 51 > 45, request
    // limit=2 → array is [52, 51] (top 2 by score) and tracked_witnesses=3.
    let state = test_state();
    {
        let mut rep = state.reputation.lock_recover();
        rep.apply_event("wL-top", crate::network::reputation::ReputationEvent::DisputeWon, 0.0); // 52
        rep.apply_event("wL-mid", crate::network::reputation::ReputationEvent::Undisputed, 0.0); // 51
        rep.apply_event("wL-bot", crate::network::reputation::ReputationEvent::DisputeLost, 0.0); // 45
    }
    let v = compute_witness_reputation(state, None, Some(2));

    assert_eq!(
        v.get("tracked_witnesses").and_then(|x| x.as_u64()),
        Some(3),
        "tracked_witnesses MUST stay the TRUE count (3), NOT the page length (2)",
    );
    let witnesses = v.get("witnesses").and_then(|x| x.as_array()).expect("witnesses array");
    assert_eq!(witnesses.len(), 2, "explicit limit=2 MUST cap the array to 2 entries");
    let scores: Vec<f64> = witnesses
        .iter()
        .map(|e| e.get("score").and_then(|x| x.as_f64()).unwrap_or(0.0))
        .collect();
    assert_eq!(
        scores,
        vec![52.0, 51.0],
        "bounded page MUST be the TOP 2 witnesses by score (52, 51) — not an arbitrary slice",
    );
}

// ─── `compute_peer_reputation` orthogonal
// pins. explorer.rs:1514 was
// zero-baseline (no `compute_peer_reputation` matches in the existing
// test mod). Same-shape sibling of `compute_list_witness_profiles`
// — both emit a `{<array>, count: N}` envelope over
// a HashMap-backed registry (PeerTable.peers : HashMap<String, PeerInfo>
// here vs WitnessRegistry.profiles : HashMap<String, WitnessProfile>
// for the profiles helper) — so the 5-axis template re-applies verbatim, with two
// pivots: per-entry shape grows from 4 keys (profiles) to 9 keys
// (peers), and the reputation field carries a 4-decimal rounding
// contract that profiles lacked.
//
// Previously unpinned axes: (1) fresh-state empty envelope (`peers.all()`
// on empty HashMap MUST yield `[]` not null nor missing), (2) per-entry
// strict 9-key envelope {identity_hash, host, node_type, reputation,
// successes, failures, valid_records, invalid_records, state} (any
// silent addition would inflate operator dashboards by ~30% at 100+
// peers), (3) multi-peer set-equality enumeration (peers.all() is
// `self.peers.values().collect()` over a HashMap → iteration order is
// non-deterministic across runs; positional asserts would non-det-
// erministically break the explorer's /peers/reputation table), (4)
// PeerState enum → JSON string mapping for ALL 3 variants (Connected
// → "connected", Offline → "offline", Stale → "stale") at the route
// boundary (the `match p.state {…}` arms at explorer.rs:1529-1532 are
// the load-bearing wire contract — a regression to `format!("{:?}", _)`
// debug-format would emit "Connected"/"Offline"/"Stale" PascalCase
// and silently brick accounts that strict-parse the lowercase literals),
// and (5) reputation 4-decimal rounding contract via `(x * 10000.0)
// .round() / 10000.0` at explorer.rs:1524 — the 1/3 ratio case
// produces 0.3333333... raw → 0.3333 rounded; a regression dropping
// the rounding would emit 0.3333333333333333 (16-decimal IEEE 754),
// a regression to `.trunc()` would also emit 0.3333 (false-pass), so
// the test pairs the rounded-to-0.3333 assertion with a NodeType::
// Anchor → "anchor" snake_case pin (`serde(rename_all = "snake_case")`
// on the NodeType enum at peer.rs:39) to lock the wire contract on
// both axes simultaneously.

fn make_test_peer(
    id: &str,
    st: crate::network::peer::PeerState,
    node_type: crate::network::peer::NodeType,
) -> crate::network::peer::PeerInfo {
    crate::network::peer::PeerInfo {
        identity_hash: id.to_string(),
        host: "127.0.0.1".to_string(),
        port: 9473,
        node_type,
        last_seen: 1000.0,
        state: st,
        failures: 0,
        successes: 0,
        valid_records: 0,
        invalid_records: 0,
        backoff_until: 0.0,
        pow_nonce: 0,
        pow_difficulty: 0,
        public_key_hex: String::new(),
        provenance: crate::network::peer::PeerProvenance::Outbound,
        subscribed_zones: Vec::new(),
        att_watermark: 0.0,
        pull_failures: 0,
        pull_backoff_until: 0.0,
        reachable: true,
        protocol_version: 0,
        att_pull_invalid_sig: 0,
        att_pull_invalid_powas: 0,
        att_push_low_stake_deferred: 0,
        recent_bad_sig_record_ids: std::collections::VecDeque::new(),
    }
}

#[tokio::test]
async fn batch_iii_compute_peer_reputation_fresh_state_emits_strict_two_key_envelope_with_empty_array(
) {
    // Fresh test_state() has a PeerTable with local_identity set but
    // ZERO inserted peers. compute_peer_reputation MUST emit
    // {peers: [], count: 0} — pins the empty-HashMap → empty-Array
    // contract (NOT null, NOT missing key). A regression to
    // `#[serde(skip_serializing_if = "Vec::is_empty")]` on the peers
    // field would silently drop the key and break accounts that
    // pattern-match `{peers, count}` for routing-table dashboards.
    let state = test_state();
    let v = compute_peer_reputation(state, None).await;

    let obj = v.as_object().expect("top-level MUST be JSON Object");
    let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["count", "peers"],
        "envelope MUST emit EXACTLY 2 keys [count, peers] — pins wire shape for /peers/reputation",
    );

    let peers = v
        .get("peers")
        .and_then(|x| x.as_array())
        .expect("peers MUST be a JSON Array");
    assert!(
        peers.is_empty(),
        "fresh-state peers MUST be empty array, got {} entries",
        peers.len()
    );

    assert_eq!(
        v.get("count").and_then(|x| x.as_u64()),
        Some(0),
        "fresh-state count MUST be u64 zero (NOT null, NOT i64-typed)",
    );
}

#[tokio::test]
async fn batch_iii_compute_peer_reputation_explicit_limit_truncates_array_but_count_stays_true() {
    // SCALE-RULE page bound: with an explicit small limit the `peers` array is
    // capped to `limit` while `count` reports the TRUE peer-table size, so a
    // caller detects truncation via `peers.len() < count`. Insert 3 peers,
    // request limit=2 → 2 entries returned, count=3. Pins the bound that keeps
    // /peers/reputation from dumping the whole table at the 10K+ node target.
    let state = test_state();
    for id in ["plimit-a", "plimit-b", "plimit-c"] {
        assert!(state.peers.write().await.insert(make_test_peer(
            id,
            crate::network::peer::PeerState::Connected,
            crate::network::peer::NodeType::Leaf,
        )));
    }
    let v = compute_peer_reputation(state, Some(2)).await;

    let peers = v.get("peers").and_then(|x| x.as_array()).expect("peers array");
    assert_eq!(peers.len(), 2, "explicit limit=2 MUST cap the array to 2 entries");
    assert_eq!(
        v.get("count").and_then(|x| x.as_u64()),
        Some(3),
        "count MUST stay the TRUE peer-table size (3), NOT the page length (2)",
    );
}

#[tokio::test]
async fn batch_iii_compute_peer_reputation_single_peer_emits_strict_nine_key_entry() {
    // Single-peer happy-path. Pins all 9 entry keys + literal values
    // for a baseline Leaf/Connected/zero-counters peer. The CRITICAL
    // pin is the strict 9-key set — any silent addition (e.g. exposing
    // `pow_difficulty` or `att_watermark` on the explorer surface)
    // would inflate operator dashboards by ~10% per added field at
    // 100+ peers AND surface PoW/anti-Sybil internal state to the
    // public /peers/reputation endpoint.
    let state = test_state();
    let inserted = state.peers.write().await.insert(make_test_peer(
        "peer-A-baseline",
        crate::network::peer::PeerState::Connected,
        crate::network::peer::NodeType::Leaf,
    ));
    assert!(
        inserted,
        "insert MUST succeed — peer is not self and PoW disabled"
    );
    let v = compute_peer_reputation(state, None).await;

    let peers = v
        .get("peers")
        .and_then(|x| x.as_array())
        .expect("peers MUST be a JSON Array");
    assert_eq!(peers.len(), 1, "MUST have exactly 1 peer");
    assert_eq!(
        v.get("count").and_then(|x| x.as_u64()),
        Some(1),
        "count MUST equal peers.len() = 1",
    );

    let entry = peers[0].as_object().expect("entry MUST be a JSON Object");
    let mut entry_keys: Vec<&str> = entry.keys().map(|s| s.as_str()).collect();
    entry_keys.sort();
    assert_eq!(
            entry_keys,
            vec![
                "failures",
                "host",
                "identity_hash",
                "invalid_records",
                "node_type",
                "reputation",
                "state",
                "successes",
                "valid_records",
            ],
            "entry MUST emit EXACTLY 9 keys — pins wire shape against silent additions (pow_*, att_*, provenance leak)",
        );

    assert_eq!(
        entry.get("identity_hash").and_then(|x| x.as_str()),
        Some("peer-A-baseline"),
        "identity_hash MUST echo the inserted hash verbatim",
    );
    assert_eq!(
        entry.get("host").and_then(|x| x.as_str()),
        Some("127.0.0.1:9473"),
        "host MUST be format!(\"{{}}:{{}}\", host, port) — '127.0.0.1:9473'",
    );
    assert_eq!(
            entry.get("node_type").and_then(|x| x.as_str()),
            Some("leaf"),
            "NodeType::Leaf MUST serialize as snake_case 'leaf' (pins #[serde(rename_all)] at peer.rs:39)",
        );
    assert_eq!(
        entry.get("reputation").and_then(|x| x.as_f64()),
        Some(0.5),
        "fresh peer with no events → reputation() returns 0.5 neutral (peer.rs:737)",
    );
    assert_eq!(
        entry.get("successes").and_then(|x| x.as_u64()),
        Some(0),
        "successes MUST be u64 zero"
    );
    assert_eq!(
        entry.get("failures").and_then(|x| x.as_u64()),
        Some(0),
        "failures MUST be u64 zero"
    );
    assert_eq!(
        entry.get("valid_records").and_then(|x| x.as_u64()),
        Some(0),
        "valid_records MUST be u64 zero"
    );
    assert_eq!(
        entry.get("invalid_records").and_then(|x| x.as_u64()),
        Some(0),
        "invalid_records MUST be u64 zero"
    );
    assert_eq!(
            entry.get("state").and_then(|x| x.as_str()),
            Some("connected"),
            "PeerState::Connected MUST map to literal 'connected' (NOT 'Connected' PascalCase nor enum tag)",
        );
}

#[tokio::test]
async fn batch_iii_compute_peer_reputation_multi_peer_n_three_emits_set_equality_no_positional() {
    // Multi-peer N=3 set-equality enumeration. peers.all() at
    // peer.rs:529 is `self.peers.values().collect()` over a HashMap —
    // iteration order is non-deterministic across runs. A positional
    // assertion (`peers[0].identity_hash == "peer-1"`) would non-
    // deterministically break the /peers/reputation table contract.
    // This test pins the COUNT and SET membership across 3 distinct
    // peers without asserting positional order — exactly mirrors
    // the `compute_list_witness_profiles` axis-3 pin.
    let state = test_state();
    for id in ["peer-X-001", "peer-Y-002", "peer-Z-003"] {
        assert!(state.peers.write().await.insert(make_test_peer(
            id,
            crate::network::peer::PeerState::Connected,
            crate::network::peer::NodeType::Leaf,
        )));
    }
    let v = compute_peer_reputation(state, None).await;

    let peers = v
        .get("peers")
        .and_then(|x| x.as_array())
        .expect("peers MUST be Array");
    assert_eq!(peers.len(), 3, "peers array MUST have exactly 3 entries");
    assert_eq!(
        v.get("count").and_then(|x| x.as_u64()),
        Some(3),
        "count MUST equal peers.len() = 3 (incremental counter contract)",
    );

    // Set-equality on identity_hashes — positional order is non-deterministic.
    let mut hashes: Vec<&str> = peers
        .iter()
        .filter_map(|e| e.get("identity_hash").and_then(|x| x.as_str()))
        .collect();
    hashes.sort();
    assert_eq!(
            hashes,
            vec!["peer-X-001", "peer-Y-002", "peer-Z-003"],
            "all 3 identity_hashes MUST appear via set-equality (HashMap iteration is non-deterministic)",
        );
}

#[tokio::test]
async fn batch_iii_compute_peer_reputation_state_enum_all_three_variants_emit_lowercase_literals() {
    // PeerState enum → JSON string mapping for ALL 3 variants:
    // Connected → "connected", Offline → "offline", Stale → "stale".
    // The match at explorer.rs:1529-1532 is the load-bearing wire
    // contract — a regression to `format!("{:?}", p.state)` would
    // emit "Connected"/"Offline"/"Stale" PascalCase and silently
    // brick accounts that strict-parse the lowercase literals.
    let state = test_state();
    assert!(state.peers.write().await.insert(make_test_peer(
        "peer-conn",
        crate::network::peer::PeerState::Connected,
        crate::network::peer::NodeType::Leaf,
    )));
    assert!(state.peers.write().await.insert(make_test_peer(
        "peer-offl",
        crate::network::peer::PeerState::Offline,
        crate::network::peer::NodeType::Leaf,
    )));
    assert!(state.peers.write().await.insert(make_test_peer(
        "peer-stal",
        crate::network::peer::PeerState::Stale,
        crate::network::peer::NodeType::Leaf,
    )));
    let v = compute_peer_reputation(state, None).await;

    let peers = v
        .get("peers")
        .and_then(|x| x.as_array())
        .expect("peers MUST be Array");
    assert_eq!(
        peers.len(),
        3,
        "MUST have 3 peers (one per PeerState variant)"
    );

    // Map identity_hash → state for set-style lookup (HashMap order is non-deterministic).
    let state_by_id: std::collections::HashMap<&str, &str> = peers
        .iter()
        .filter_map(|e| {
            let id = e.get("identity_hash").and_then(|x| x.as_str())?;
            let st = e.get("state").and_then(|x| x.as_str())?;
            Some((id, st))
        })
        .collect();
    assert_eq!(
        state_by_id.get("peer-conn"),
        Some(&"connected"),
        "PeerState::Connected MUST map to lowercase 'connected'",
    );
    assert_eq!(
        state_by_id.get("peer-offl"),
        Some(&"offline"),
        "PeerState::Offline MUST map to lowercase 'offline'",
    );
    assert_eq!(
        state_by_id.get("peer-stal"),
        Some(&"stale"),
        "PeerState::Stale MUST map to lowercase 'stale'",
    );
}

#[tokio::test]
async fn batch_iii_compute_peer_reputation_reputation_rounded_four_decimals_and_node_type_anchor_snake_case(
) {
    // Reputation 4-decimal rounding contract. Construct a peer with
    // successes=1, valid_records=2 (good=3), failures=4,
    // invalid_records=2 (bad=6), total=9, ratio = 3/9 = 0.3333333...
    // The route applies `(x * 10000.0).round() / 10000.0` at
    // explorer.rs:1524, which yields exactly 0.3333. A regression
    // dropping the rounding would emit 0.3333333333333333 (16-decimal
    // IEEE 754 raw) — NOT equal to JSON-serialized 0.3333. Pin BOTH
    // the rounded reputation AND NodeType::Anchor → "anchor"
    // snake_case mapping (peer.rs:39) in the same test to lock two
    // wire contracts orthogonally.
    let state = test_state();
    let mut peer = make_test_peer(
        "peer-anchor-rep",
        crate::network::peer::PeerState::Connected,
        crate::network::peer::NodeType::Anchor,
    );
    peer.successes = 1;
    peer.valid_records = 2;
    peer.failures = 4;
    peer.invalid_records = 2;
    // good = 1+2 = 3, bad = 4+2 = 6, total = 9, ratio = 3/9 ≈ 0.3333333...
    assert!(state.peers.write().await.insert(peer));
    let v = compute_peer_reputation(state, None).await;

    let peers = v
        .get("peers")
        .and_then(|x| x.as_array())
        .expect("peers MUST be Array");
    assert_eq!(peers.len(), 1, "MUST have 1 peer");
    let entry = &peers[0];

    assert_eq!(
            entry.get("reputation").and_then(|x| x.as_f64()),
            Some(0.3333),
            "reputation MUST be (3/9).round()-to-4-decimals = 0.3333 (pins rounding contract at explorer.rs:1524)",
        );
    assert_eq!(
        entry.get("node_type").and_then(|x| x.as_str()),
        Some("anchor"),
        "NodeType::Anchor MUST serialize as snake_case 'anchor' (NOT 'Anchor' PascalCase)",
    );
    // Cross-check counter fields preserve numeric type + value through serde.
    assert_eq!(
        entry.get("successes").and_then(|x| x.as_u64()),
        Some(1),
        "successes MUST be u64 1"
    );
    assert_eq!(
        entry.get("valid_records").and_then(|x| x.as_u64()),
        Some(2),
        "valid_records MUST be u64 2"
    );
    assert_eq!(
        entry.get("failures").and_then(|x| x.as_u64()),
        Some(4),
        "failures MUST be u64 4"
    );
    assert_eq!(
        entry.get("invalid_records").and_then(|x| x.as_u64()),
        Some(2),
        "invalid_records MUST be u64 2"
    );
}

// ─── compute_reward_stats ──────────────────
//
// Previous baseline: ZERO direct tests on compute_reward_stats
// (explorer.rs:1552). The /rewards/stats endpoint exposes a 10-key
// operator-facing envelope that accounts and dashboards strict-parse for
// (a) auto-reward emission counts/amounts (b) per-attestation reward
// pricing, (c) conservation-pool balance/cap/headroom, and (d) whether
// the local node is the genesis authority. Five orthogonal axes pin the
// wire contract: (1) fresh-state strict 10-key envelope + zero baseline
// on all counters, (2) micros/beat dual-unit conversion contract across
// 3 paired fields (auto_rewards_amount / conservation_pool /
// reward_per_attestation) — pins the `/ BASE_UNITS_PER_BEAT as f64` formula
// at explorer.rs:1560/1562/1564, (3) auto_rewards counter INDEPENDENCE
// (events vs amount counters carry independent state; coprime fetch_add
// 13 vs 19_000_000_000 defeats aliasing), (4) conservation_pool cap +
// headroom math contract — pins CONSERVATION_POOL_MAX_FRACTION=0.10
// (accounting/types.rs:70) and pool_headroom = pool_cap - conservation_pool
// (accounting/ledger.rs:345 saturating_sub), (5) is_genesis_authority TRUE
// branch via inline NodeState with `config.genesis_authority =
// identity.identity_hash` AND pool_headroom saturating-to-zero edge when
// conservation_pool > pool_cap (defeats unsigned-underflow regression).
//
// Out of scope: the axum `reward_stats` handler wrapping (already
// covered indirectly by the compute_*-direct pattern — wrapping is a
// 1-line `Json(...)` invocation with no logic), and the conservation
// pool's `pool_monthly_remaining` window logic (different endpoint).

#[tokio::test]
async fn batch_jjj_compute_reward_stats_fresh_state_emits_strict_ten_key_envelope_with_zero_counters(
) {
    // Fresh test_state(): all atomics at zero, default LedgerState
    // (total_supply=0, conservation_pool=0), default config
    // (witness_reward_micros=1_000_000_000, genesis_authority=TESTNET_GENESIS_AUTHORITY
    // which a randomly-generated test identity will NOT match). MUST emit
    // EXACTLY 10 keys with the expected zero-baseline values. A regression
    // adding a new field (e.g. `auto_reward_cap_per_window`) would silently
    // inflate operator dashboards; a regression dropping conservation_pool_cap
    // or conservation_pool_headroom would break treasury monitoring.
    let state = test_state();
    let v = compute_reward_stats(state.clone()).await;

    let obj = v.as_object().expect("top-level MUST be JSON Object");
    let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    keys.sort();
    assert_eq!(
            keys,
            vec![
                "auto_rewards_amount_beat",
                "auto_rewards_amount_micros",
                "auto_rewards_total",
                "conservation_pool_beat",
                "conservation_pool_cap_micros",
                "conservation_pool_headroom_micros",
                "conservation_pool_micros",
                "is_genesis_authority",
                "reward_per_attestation_beat",
                "reward_per_attestation_micros",
            ],
            "envelope MUST emit EXACTLY 10 keys — pins wire shape against silent additions/removals on /rewards/stats",
        );

    // Counters all start at zero.
    assert_eq!(
        v.get("auto_rewards_total").and_then(|x| x.as_u64()),
        Some(0),
        "fresh-state auto_rewards_total MUST be u64 0"
    );
    assert_eq!(
        v.get("auto_rewards_amount_micros").and_then(|x| x.as_u64()),
        Some(0),
        "fresh-state auto_rewards_amount_micros MUST be u64 0"
    );
    assert_eq!(
        v.get("auto_rewards_amount_beat").and_then(|x| x.as_f64()),
        Some(0.0),
        "fresh-state auto_rewards_amount_beat MUST be f64 0.0 (0 micros / 1e9 = 0.0 exact)"
    );

    // Default LedgerState: total_supply=0 → pool_cap=0, conservation_pool=0 → pool_headroom=0.
    assert_eq!(
        v.get("conservation_pool_micros").and_then(|x| x.as_u64()),
        Some(0),
        "fresh-state conservation_pool_micros MUST be u64 0"
    );
    assert_eq!(
        v.get("conservation_pool_beat").and_then(|x| x.as_f64()),
        Some(0.0),
        "fresh-state conservation_pool_beat MUST be f64 0.0"
    );
    assert_eq!(
        v.get("conservation_pool_cap_micros")
            .and_then(|x| x.as_u64()),
        Some(0),
        "fresh-state conservation_pool_cap_micros MUST be u64 0 (total_supply=0 → cap=0)"
    );
    assert_eq!(
        v.get("conservation_pool_headroom_micros")
            .and_then(|x| x.as_u64()),
        Some(0),
        "fresh-state conservation_pool_headroom_micros MUST be u64 0 (cap=0 → headroom=0)"
    );

    // Default config.witness_reward_micros = 1_000_000_000 (1 beat, base units).
    assert_eq!(
            v.get("reward_per_attestation_micros").and_then(|x| x.as_u64()),
            Some(state.config.witness_reward_micros),
            "reward_per_attestation_micros MUST echo config.witness_reward_micros (default 1_000_000_000)",
        );
    assert_eq!(
            v.get("reward_per_attestation_beat").and_then(|x| x.as_f64()),
            Some(state.config.witness_reward_micros as f64 / crate::accounting::types::BASE_UNITS_PER_BEAT as f64),
            "reward_per_attestation_beat MUST equal micros/BASE_UNITS_PER_BEAT via same f64 division as explorer.rs:1562",
        );

    // Test-fixture identity is randomly generated → NOT the TESTNET_GENESIS_AUTHORITY.
    assert_ne!(
        state.identity.identity_hash, state.config.genesis_authority,
        "test fixture identity must not collide with the configured genesis_authority",
    );
    assert_eq!(
            v.get("is_genesis_authority").and_then(|x| x.as_bool()),
            Some(false),
            "fresh-state test fixture identity is NOT the genesis_authority — pins the != branch of the equality at explorer.rs:1567",
        );
}

#[tokio::test]
async fn batch_jjj_compute_reward_stats_micros_to_beat_dual_unit_conversion_three_fields() {
    // Pins the `micros as f64 / BASE_UNITS_PER_BEAT as f64` dual-unit
    // conversion contract on THREE distinct fields with THREE distinct
    // exact-representable f64 magnitudes — defeats copy-paste aliasing
    // and regression to integer-division-truncation. Critical: a
    // regression to `(micros / BASE_UNITS_PER_BEAT) as f64` would emit 3.0
    // → 0.0 (integer truncation on micros < 1e9) and silently zero out
    // account displays.
    //
    // Magnitudes chosen as integer-multiples of BASE_UNITS_PER_BEAT so the
    // f64 conversion is byte-exact (no recurring-binary-fraction noise):
    //   auto_rewards_amount = 25 * BASE_UNITS_PER_BEAT = 25.0 beat
    //   conservation_pool   = 17 * BASE_UNITS_PER_BEAT = 17.0 beat
    //   (witness_reward_micros stays at default 1_000_000_000 = 1.0 beat;
    //    we re-use the same `micros as f64 / BASE_UNITS_PER_BEAT as f64`
    //    arithmetic in the expected value so the test tracks the config
    //    default rather than hard-coding a magic float.)
    let state = test_state();
    state.auto_rewards_amount_total.store(
        25 * crate::accounting::types::BASE_UNITS_PER_BEAT,
        std::sync::atomic::Ordering::Relaxed,
    );
    {
        let mut ledger = state.ledger.write().await;
        ledger.conservation_pool = 17 * crate::accounting::types::BASE_UNITS_PER_BEAT;
    }
    let v = compute_reward_stats(state.clone()).await;

    // Field 1: auto_rewards_amount.
    assert_eq!(
        v.get("auto_rewards_amount_micros").and_then(|x| x.as_u64()),
        Some(25 * crate::accounting::types::BASE_UNITS_PER_BEAT),
        "auto_rewards_amount_micros MUST echo the atomic verbatim as u64",
    );
    assert_eq!(
            v.get("auto_rewards_amount_beat").and_then(|x| x.as_f64()),
            Some(25.0),
            "25 * BASE_UNITS_PER_BEAT / BASE_UNITS_PER_BEAT = 25.0 beat (exact f64) — pins explorer.rs:1560",
        );

    // Field 2: conservation_pool.
    assert_eq!(
        v.get("conservation_pool_micros").and_then(|x| x.as_u64()),
        Some(17 * crate::accounting::types::BASE_UNITS_PER_BEAT),
        "conservation_pool_micros MUST echo ledger.conservation_pool verbatim as u64",
    );
    assert_eq!(
            v.get("conservation_pool_beat").and_then(|x| x.as_f64()),
            Some(17.0),
            "17 * BASE_UNITS_PER_BEAT / BASE_UNITS_PER_BEAT = 17.0 beat (exact f64) — pins explorer.rs:1564",
        );

    // Field 3: reward_per_attestation (default value, same conversion
    // arithmetic). 1_000_000_000 / 1_000_000_000 = 1.0 with f64 division.
    let expected_reward_beat =
        state.config.witness_reward_micros as f64 / crate::accounting::types::BASE_UNITS_PER_BEAT as f64;
    assert_eq!(
            v.get("reward_per_attestation_beat").and_then(|x| x.as_f64()),
            Some(expected_reward_beat),
            "reward_per_attestation_beat MUST equal witness_reward_micros / BASE_UNITS_PER_BEAT via SAME f64 division (pins explorer.rs:1562)",
        );

    // Sanity cross-check: the three beat fields are DISTINCT — defeats
    // any regression that conflates them via copy-paste.
    let a = v
        .get("auto_rewards_amount_beat")
        .and_then(|x| x.as_f64())
        .unwrap();
    let c = v
        .get("conservation_pool_beat")
        .and_then(|x| x.as_f64())
        .unwrap();
    let r = v
        .get("reward_per_attestation_beat")
        .and_then(|x| x.as_f64())
        .unwrap();
    assert!(
        a != c && c != r && a != r,
        "the three _beat fields MUST be distinct (a={a} c={c} r={r}); aliasing regression detected"
    );
}

#[tokio::test]
async fn batch_jjj_compute_reward_stats_counter_independence_events_vs_amount() {
    // Pins counter independence: auto_rewards_total (events count) is
    // a SEPARATE atomic from auto_rewards_amount_total (cumulative
    // base units). A regression that aliases them (e.g. accidentally
    // emits auto_rewards_amount_total in both fields) would surface
    // here. Coprime magnitudes 13 (events) and 19 * BASE_UNITS_PER_BEAT
    // (amount, 19.0 beat) defeat any aliasing-via-coincidence trick.
    let state = test_state();
    state
        .auto_rewards_total
        .store(13, std::sync::atomic::Ordering::Relaxed);
    state.auto_rewards_amount_total.store(
        19 * crate::accounting::types::BASE_UNITS_PER_BEAT,
        std::sync::atomic::Ordering::Relaxed,
    );
    let v = compute_reward_stats(state).await;

    assert_eq!(
        v.get("auto_rewards_total").and_then(|x| x.as_u64()),
        Some(13),
        "auto_rewards_total MUST echo the events-counter atomic (NOT the amount atomic)",
    );
    assert_eq!(
        v.get("auto_rewards_amount_micros").and_then(|x| x.as_u64()),
        Some(19 * crate::accounting::types::BASE_UNITS_PER_BEAT),
        "auto_rewards_amount_micros MUST echo the amount-counter atomic (NOT the events atomic)",
    );
    assert_eq!(
            v.get("auto_rewards_amount_beat").and_then(|x| x.as_f64()),
            Some(19.0),
            "auto_rewards_amount_beat = 19 * BASE_UNITS_PER_BEAT / BASE_UNITS_PER_BEAT = 19.0 beat exact",
        );
    // 13 ≠ 19_000_000_000, so the assertions above failing would
    // diagnose aliasing — but pin it explicitly with a value-distinct
    // sanity check as well.
    let events = v
        .get("auto_rewards_total")
        .and_then(|x| x.as_u64())
        .unwrap();
    let amount = v
        .get("auto_rewards_amount_micros")
        .and_then(|x| x.as_u64())
        .unwrap();
    assert_ne!(
        events, amount,
        "events ({events}) MUST NOT equal amount ({amount}) — independent atomics"
    );
}

#[tokio::test]
async fn batch_jjj_compute_reward_stats_conservation_pool_cap_and_headroom_math() {
    // Pins the Conservation Pool hard-cap formula at accounting/ledger.rs:340
    // and the headroom = cap - pool saturating_sub at accounting/ledger.rs:345.
    // Underlying constant CONSERVATION_POOL_MAX_FRACTION = 0.10 lives at
    // accounting/types.rs:70. With total_supply = 1_000_000 * BASE_UNITS_PER_BEAT
    // (1M beat) and conservation_pool = 30_000 * BASE_UNITS_PER_BEAT (30K beat):
    //   pool_cap = (1M * 0.10) * BASE_UNITS_PER_BEAT = 100_000 * BASE_UNITS_PER_BEAT
    //   pool_headroom = 100_000 - 30_000 = 70_000 * BASE_UNITS_PER_BEAT
    // A regression dropping CONSERVATION_POOL_MAX_FRACTION from 0.10 to
    // a different fraction (e.g. 0.05 or 0.25) would be caught here.
    let state = test_state();
    let one_beat = crate::accounting::types::BASE_UNITS_PER_BEAT;
    {
        let mut ledger = state.ledger.write().await;
        ledger.total_supply = 1_000_000 * one_beat; // 1M beat
        ledger.conservation_pool = 30_000 * one_beat; // 30K beat
    }
    let v = compute_reward_stats(state).await;

    assert_eq!(
        v.get("conservation_pool_micros").and_then(|x| x.as_u64()),
        Some(30_000 * one_beat),
        "conservation_pool_micros echoes ledger.conservation_pool",
    );
    assert_eq!(
            v.get("conservation_pool_cap_micros").and_then(|x| x.as_u64()),
            Some(100_000 * one_beat),
            "pool_cap = (1M beat * 0.10) = 100K beat in base units (pins CONSERVATION_POOL_MAX_FRACTION=0.10)",
        );
    assert_eq!(
        v.get("conservation_pool_headroom_micros")
            .and_then(|x| x.as_u64()),
        Some(70_000 * one_beat),
        "pool_headroom = pool_cap (100K beat) - conservation_pool (30K beat) = 70K beat in base units",
    );
    // Cross-check the headroom is STRICTLY positive (pool < cap branch).
    let headroom = v
        .get("conservation_pool_headroom_micros")
        .and_then(|x| x.as_u64())
        .unwrap();
    let cap = v
        .get("conservation_pool_cap_micros")
        .and_then(|x| x.as_u64())
        .unwrap();
    let pool = v
        .get("conservation_pool_micros")
        .and_then(|x| x.as_u64())
        .unwrap();
    assert_eq!(
        headroom,
        cap - pool,
        "headroom invariant: cap - pool == headroom when pool ≤ cap (NOT saturating branch)"
    );
}

#[tokio::test]
async fn batch_jjj_compute_reward_stats_is_genesis_authority_true_and_headroom_saturating_zero() {
    // Two-axis composite test:
    // (a) is_genesis_authority TRUE branch — inline-construct a NodeState
    //     where config.genesis_authority is forcibly aligned with the
    //     generated identity.identity_hash. This is the ONLY way the
    //     equality at explorer.rs:1567 can evaluate to true; the default
    //     test_state() uses TESTNET_GENESIS_AUTHORITY which a random
    //     identity will never match (covered by axis 1 false-branch).
    // (b) pool_headroom = 0 saturating edge — set conservation_pool >
    //     pool_cap (which can happen in some legacy/migration scenarios
    //     or during a supply-shrink event). saturating_sub at
    //     accounting/ledger.rs:345 MUST yield 0 (NOT u64::MAX from underflow).
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let identity =
        Identity::generate(EntityType::Device, CryptoProfile::ProfileB).expect("generate identity");
    let mut config = NodeConfig {
        data_dir: data_dir.clone(),
        identity_path: data_dir.join("identity.json"),
        db_path: data_dir.join("elara.db"),
        admin_token: "test-admin".into(),
        network_id: "reward-stats-genesis-test".into(),
        mdns_enabled: false,
        health_check_interval_secs: 0,
        min_pow_difficulty: 0,
        ..Default::default()
    };
    // Align genesis_authority with this node's identity_hash to force
    // is_genesis_authority=true.
    config.genesis_authority = identity.identity_hash.clone();
    let rocks = Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
    let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
    let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
    std::mem::forget(tmp);

    // Force pool > cap via small total_supply and large conservation_pool.
    // total_supply = 100 * BASE_UNITS_PER_BEAT → pool_cap = 10 * BASE_UNITS_PER_BEAT
    // conservation_pool = 50 * BASE_UNITS_PER_BEAT → pool > cap by 40 beat
    let one_beat = crate::accounting::types::BASE_UNITS_PER_BEAT;
    {
        let mut ledger = state.ledger.write().await;
        ledger.total_supply = 100 * one_beat;
        ledger.conservation_pool = 50 * one_beat;
    }
    let v = compute_reward_stats(state.clone()).await;

    // Axis (a): is_genesis_authority TRUE.
    assert_eq!(
        state.identity.identity_hash, state.config.genesis_authority,
        "test prerequisite: identity_hash MUST equal genesis_authority for the TRUE branch",
    );
    assert_eq!(
            v.get("is_genesis_authority").and_then(|x| x.as_bool()),
            Some(true),
            "is_genesis_authority MUST be true when identity_hash == genesis_authority (pins explorer.rs:1567 == branch)",
        );

    // Axis (b): pool_headroom saturating-to-zero when pool > cap.
    assert_eq!(
        v.get("conservation_pool_micros").and_then(|x| x.as_u64()),
        Some(50 * one_beat),
        "conservation_pool_micros echoes 50 beat in base units (field name historical)",
    );
    assert_eq!(
        v.get("conservation_pool_cap_micros")
            .and_then(|x| x.as_u64()),
        Some(10 * one_beat),
        "pool_cap = 100 beat * 0.10 = 10 beat in base units",
    );
    // CRITICAL: saturating_sub MUST yield 0, NOT u64::MAX from underflow.
    assert_eq!(
            v.get("conservation_pool_headroom_micros").and_then(|x| x.as_u64()),
            Some(0),
            "pool_headroom MUST saturate to 0 when conservation_pool (50 beat) > pool_cap (10 beat) — \
             pins accounting/ledger.rs:345 saturating_sub against a regression to unchecked u64 subtraction",
        );
}

// ─── compute_governance_proposals ─────────────────────
//
// /governance/proposals is the operator-facing list view of all governance
// proposals — the account UX that surfaces "what is the network voting on
// right now". The pure compute_* helper at explorer.rs:915 had ZERO direct
// test coverage previously.
//
// Previously-unpinned axes:
//   • Top-level envelope shape: strict 4 keys {proposals, total, limit,
//     offset}. Any silent addition (e.g. `next_offset` HATEOAS link) or
//     drop (e.g. `total` removed because "clients can count") would break
//     account pagination. Defaults: limit=50, offset=0 (explorer.rs:922-923).
//   • Per-entry envelope shape: strict 9 keys {id, proposer, category,
//     title, status, created_at, voting_deadline, vote_count, tally} —
//     plus the strict 6-key nested `tally` object {for, against, abstain,
//     voters, raw_participating_stake, raw_participating_stake_beat}. The
//     `category` field uses `p.category.as_str()` (snake_case literal) NOT
//     the enum's serde-derived rename — regression to `format!("{:?}", ..)`
//     would emit "Parameter" (capitalized) and break governance-explorer
//     case-sensitive parsers. The `status` field uses
//     `format!("{:?}", p.status).to_lowercase()` — pairs with the
//     case-insensitive filter contract.
//   • Status filter contract: `format!("{:?}", p.status).to_lowercase() ==
//     s.to_lowercase()` (explorer.rs:935-940) — case-insensitive on BOTH
//     sides. Regression to `to_lowercase` only on the rhs OR strict
//     equality would lose the upper-case-from-URL traffic that mobile
//     accounts emit.
//   • Sort contract: `b.created_at.partial_cmp(&a.created_at)` — DESCENDING
//     (newest first). Regression to ascending would break "Activity"
//     surfaces in the explorer UI.
//   • Pagination: skip(offset).take(limit), with `total` reflecting the
//     POST-FILTER count (so a `status=active&limit=2` request shows the
//     correct active count, not the all-proposals count). Limit clamps to
//     200 via `.min(200)` at explorer.rs:922 — pins the un-paginated DoS
//     vector at 1M-proposal mainnet scale.
//   • vote_count = p.votes.len(), tally fields driven by tally_votes() —
//     for a 0-vote proposal, all tally numerics MUST be 0/0.0.
//
// Out of scope: the axum `governance_proposals` handler wrapping (already
// covered indirectly — wrapping is a 1-line `Json(...)` invocation with no
// logic), the per-proposal detail endpoint `compute_governance_proposal_detail`
// (separate slice), and tally arithmetic correctness across
// multiple voters (covered by governance.rs `test_tally_*` unit tests).
//
// Strategy: insert proposals directly into `ledger.governance.proposals`
// via the write-lock pattern (used throughout this test module — no
// `propose()` invocation needed since we're testing the read-projection).

/// Helper: construct a minimal `Proposal` for test fixtures. Centralizing
/// the field-set avoids per-test drift when the `Proposal` struct gains
/// new fields (and forces a recompile here so the new field is consciously
/// considered in the envelope-shape assertions).
fn batch_kkk_mk_proposal(
    id: &str,
    proposer: &str,
    category: crate::accounting::governance::ProposalCategory,
    status: crate::accounting::governance::ProposalStatus,
    title: &str,
    created_at: f64,
    votes: Vec<crate::accounting::governance::Vote>,
) -> crate::accounting::governance::Proposal {
    crate::accounting::governance::Proposal {
        id: id.into(),
        proposer: proposer.into(),
        category,
        title: title.into(),
        description: format!("desc for {id}"),
        created_at,
        voting_deadline: created_at + 7.0 * 24.0 * 3600.0,
        status,
        passed_at: None,
        votes,
        committee: None,
    }
}

#[tokio::test]
async fn batch_kkk_compute_governance_proposals_fresh_state_emits_strict_four_key_envelope_with_empty_array(
) {
    // Fresh state: no proposals inserted, no filter, no limit/offset.
    // MUST emit the strict 4-key envelope with `proposals: []`, total=0,
    // and the explicit defaults limit=50 + offset=0. A regression that
    // changes defaults (e.g. limit=100) or drops the keys for empty
    // payloads would break account pagination assumptions.
    let state = test_state();
    let v = compute_governance_proposals(state.clone(), None, None, None).await;

    let obj = v.as_object().expect("top-level MUST be JSON Object");
    let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    keys.sort();
    assert_eq!(
            keys,
            vec!["limit", "offset", "proposals", "total"],
            "envelope MUST emit EXACTLY 4 keys — pins wire shape against silent additions/removals on /governance/proposals",
        );

    let proposals = v
        .get("proposals")
        .and_then(|x| x.as_array())
        .expect("proposals MUST be JSON Array");
    assert!(
        proposals.is_empty(),
        "fresh-state proposals array MUST be empty (no proposals inserted)"
    );
    assert_eq!(
        v.get("total").and_then(|x| x.as_u64()),
        Some(0),
        "fresh-state total MUST be u64 0"
    );
    assert_eq!(
        v.get("limit").and_then(|x| x.as_u64()),
        Some(50),
        "default limit MUST be 50 (explorer.rs:922: limit.unwrap_or(50).min(200))"
    );
    assert_eq!(
        v.get("offset").and_then(|x| x.as_u64()),
        Some(0),
        "default offset MUST be 0 (explorer.rs:923: offset.unwrap_or(0))"
    );
}

#[tokio::test]
async fn batch_kkk_compute_governance_proposals_single_proposal_emits_strict_nine_key_entry_with_six_key_tally(
) {
    // Insert ONE Active Parameter proposal with zero votes. Pins:
    //   • Per-entry strict 9-key envelope.
    //   • Strict 6-key nested `tally` object.
    //   • `category` value = "parameter" (snake_case via .as_str(), NOT
    //     "Parameter" from enum debug-format) — regression-guard against
    //     a refactor that swaps the as_str() call for `format!("{:?}",..)`.
    //   • `status` value = "active" (lowercase via Debug+to_lowercase) —
    //     pairs with the case-insensitive filter contract tested below.
    //   • `vote_count` = 0 (no votes).
    //   • All tally numerics = 0/0.0 (zero-vote tally early-exit at
    //     governance.rs:1288).
    //   • `raw_participating_stake_beat` = "0.0" (format_beat_precise(0)
    //     yields "0.0" not "0").
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        ledger.governance.proposals.insert(
            "prop-active-001".into(),
            batch_kkk_mk_proposal(
                "prop-active-001",
                "alice-hash",
                crate::accounting::governance::ProposalCategory::Parameter,
                crate::accounting::governance::ProposalStatus::Active,
                "raise witness reward",
                1700000000.0,
                vec![],
            ),
        );
    }
    let v = compute_governance_proposals(state.clone(), None, None, None).await;

    assert_eq!(v.get("total").and_then(|x| x.as_u64()), Some(1));
    let arr = v
        .get("proposals")
        .and_then(|x| x.as_array())
        .expect("proposals MUST be array");
    assert_eq!(arr.len(), 1);

    let p = arr[0].as_object().expect("proposal entry MUST be Object");
    let mut keys: Vec<&str> = p.keys().map(|s| s.as_str()).collect();
    keys.sort();
    assert_eq!(
            keys,
            vec![
                "category",
                "created_at",
                "id",
                "proposer",
                "status",
                "tally",
                "title",
                "vote_count",
                "voting_deadline",
            ],
            "per-entry envelope MUST emit EXACTLY 9 keys — pins wire shape against silent additions/removals",
        );

    assert_eq!(
        p.get("id").and_then(|x| x.as_str()),
        Some("prop-active-001")
    );
    assert_eq!(
        p.get("proposer").and_then(|x| x.as_str()),
        Some("alice-hash")
    );
    assert_eq!(
            p.get("category").and_then(|x| x.as_str()),
            Some("parameter"),
            "category MUST emit `as_str()` snake_case literal NOT enum debug-format — pins explorer.rs:946",
        );
    assert_eq!(
        p.get("status").and_then(|x| x.as_str()),
        Some("active"),
        "status MUST emit lowercase via Debug+to_lowercase — pins explorer.rs:948",
    );
    assert_eq!(
        p.get("title").and_then(|x| x.as_str()),
        Some("raise witness reward")
    );
    assert_eq!(
        p.get("created_at").and_then(|x| x.as_f64()),
        Some(1700000000.0)
    );
    assert_eq!(
        p.get("voting_deadline").and_then(|x| x.as_f64()),
        Some(1700000000.0 + 7.0 * 24.0 * 3600.0),
        "voting_deadline MUST echo Proposal.voting_deadline verbatim",
    );
    assert_eq!(
        p.get("vote_count").and_then(|x| x.as_u64()),
        Some(0),
        "vote_count MUST equal p.votes.len() = 0 for an unvoted proposal",
    );

    // Strict 6-key tally envelope.
    let tally = p
        .get("tally")
        .and_then(|x| x.as_object())
        .expect("tally MUST be JSON Object");
    let mut tkeys: Vec<&str> = tally.keys().map(|s| s.as_str()).collect();
    tkeys.sort();
    assert_eq!(
            tkeys,
            vec![
                "abstain",
                "against",
                "for",
                "raw_participating_stake",
                "raw_participating_stake_beat",
                "voters",
            ],
            "tally envelope MUST emit EXACTLY 6 keys — pins wire shape against silent additions/removals",
        );

    // Zero-vote tally early-exit at governance.rs:1288 → all numerics 0/0.0.
    assert_eq!(tally.get("for").and_then(|x| x.as_f64()), Some(0.0));
    assert_eq!(tally.get("against").and_then(|x| x.as_f64()), Some(0.0));
    assert_eq!(tally.get("abstain").and_then(|x| x.as_f64()), Some(0.0));
    assert_eq!(tally.get("voters").and_then(|x| x.as_u64()), Some(0));
    assert_eq!(
        tally
            .get("raw_participating_stake")
            .and_then(|x| x.as_u64()),
        Some(0)
    );
    assert_eq!(
        tally
            .get("raw_participating_stake_beat")
            .and_then(|x| x.as_str()),
        Some("0.0"),
        "format_beat_precise(0) yields \"0.0\" (accounting/validate.rs:867) — pins the STRING type \
             (clients strict-parse this as String, not as f64-via-JSON-Number)",
    );
}

#[tokio::test]
async fn batch_kkk_compute_governance_proposals_status_filter_case_insensitive_both_sides() {
    // Insert 3 proposals (Active, Passed, Rejected). Verify:
    //   • status=None → returns all 3.
    //   • status=Some("active") → returns 1.
    //   • status=Some("ACTIVE") (uppercase from URL) → returns 1.
    //   • status=Some("PaSSeD") (mixed-case) → returns 1.
    //   • status=Some("vetoed") → returns 0 (no match — proves the filter
    //     actually excludes non-matching proposals, not just no-ops).
    //   • Verify `total` reflects the POST-FILTER count, not the
    //     unfiltered count.
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        ledger.governance.proposals.insert(
            "p-act".into(),
            batch_kkk_mk_proposal(
                "p-act",
                "alice",
                crate::accounting::governance::ProposalCategory::Parameter,
                crate::accounting::governance::ProposalStatus::Active,
                "active prop",
                100.0,
                vec![],
            ),
        );
        ledger.governance.proposals.insert(
            "p-pass".into(),
            batch_kkk_mk_proposal(
                "p-pass",
                "bob",
                crate::accounting::governance::ProposalCategory::Parameter,
                crate::accounting::governance::ProposalStatus::Passed,
                "passed prop",
                200.0,
                vec![],
            ),
        );
        ledger.governance.proposals.insert(
            "p-rej".into(),
            batch_kkk_mk_proposal(
                "p-rej",
                "carol",
                crate::accounting::governance::ProposalCategory::Parameter,
                crate::accounting::governance::ProposalStatus::Rejected,
                "rejected prop",
                300.0,
                vec![],
            ),
        );
    }

    // No filter → all 3.
    let all = compute_governance_proposals(state.clone(), None, None, None).await;
    assert_eq!(
        all.get("total").and_then(|x| x.as_u64()),
        Some(3),
        "no filter MUST return total=3 (all proposals)"
    );
    assert_eq!(
        all.get("proposals")
            .and_then(|x| x.as_array())
            .map(|a| a.len()),
        Some(3)
    );

    // status="active" (already lowercase) → 1.
    let active_lower =
        compute_governance_proposals(state.clone(), Some("active".into()), None, None).await;
    assert_eq!(
        active_lower.get("total").and_then(|x| x.as_u64()),
        Some(1),
        "filter status=\"active\" MUST match the 1 Active proposal"
    );
    assert_eq!(
        active_lower
            .get("proposals")
            .and_then(|x| x.as_array())
            .and_then(|a| a.first())
            .and_then(|p| p.get("id"))
            .and_then(|x| x.as_str()),
        Some("p-act"),
        "lowercase filter MUST select p-act",
    );

    // status="ACTIVE" (uppercase from URL) → 1. THIS is the
    // case-insensitive lhs.to_lowercase() == rhs.to_lowercase() contract.
    let active_upper =
        compute_governance_proposals(state.clone(), Some("ACTIVE".into()), None, None).await;
    assert_eq!(
            active_upper.get("total").and_then(|x| x.as_u64()), Some(1),
            "filter status=\"ACTIVE\" (uppercase) MUST still match Active — pins case-insensitive contract at explorer.rs:936",
        );

    // status="PaSSeD" (mixed-case) → 1.
    let passed_mixed =
        compute_governance_proposals(state.clone(), Some("PaSSeD".into()), None, None).await;
    assert_eq!(
        passed_mixed.get("total").and_then(|x| x.as_u64()),
        Some(1),
        "filter status=\"PaSSeD\" (mixed-case) MUST match Passed — case-insensitive both sides"
    );
    assert_eq!(
        passed_mixed
            .get("proposals")
            .and_then(|x| x.as_array())
            .and_then(|a| a.first())
            .and_then(|p| p.get("status"))
            .and_then(|x| x.as_str()),
        Some("passed"),
        "matched proposal MUST be p-pass (status=\"passed\" in output)",
    );

    // status="vetoed" → 0 (no proposal has this status).
    let vetoed =
        compute_governance_proposals(state.clone(), Some("vetoed".into()), None, None).await;
    assert_eq!(vetoed.get("total").and_then(|x| x.as_u64()), Some(0),
            "filter status=\"vetoed\" MUST exclude all 3 proposals (none Vetoed) — proves the filter actually excludes");
    assert!(
        vetoed
            .get("proposals")
            .and_then(|x| x.as_array())
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "filter status=\"vetoed\" MUST yield empty proposals array",
    );
}

#[tokio::test]
async fn batch_kkk_compute_governance_proposals_sort_descending_by_created_at_with_pagination() {
    // Insert 5 proposals at created_at = 1.0, 2.0, 3.0, 4.0, 5.0 (all
    // Active, same category). Verify:
    //   • No pagination → all 5 returned, sorted DESC by created_at:
    //     [5.0, 4.0, 3.0, 2.0, 1.0]. Pins explorer.rs:964-970 sort.
    //   • offset=1, limit=2 → returns [4.0, 3.0] (skip newest, take next
    //     two). Pins explorer.rs:973 skip().take() composition.
    //   • total=5 always (offset/limit do NOT shrink total — operators
    //     need the unfiltered post-filter count to compute "page X of Y").
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        for ts in [1.0, 2.0, 3.0, 4.0, 5.0_f64] {
            let id = format!("p-{}", ts as u64);
            ledger.governance.proposals.insert(
                id.clone(),
                batch_kkk_mk_proposal(
                    &id,
                    "p",
                    crate::accounting::governance::ProposalCategory::Parameter,
                    crate::accounting::governance::ProposalStatus::Active,
                    "t",
                    ts,
                    vec![],
                ),
            );
        }
    }

    // No pagination → all 5, sorted DESC.
    let all = compute_governance_proposals(state.clone(), None, None, None).await;
    let arr = all
        .get("proposals")
        .and_then(|x| x.as_array())
        .expect("array");
    assert_eq!(arr.len(), 5, "all 5 proposals MUST be returned");
    let ts_seq: Vec<f64> = arr
        .iter()
        .map(|p| p.get("created_at").and_then(|x| x.as_f64()).unwrap_or(0.0))
        .collect();
    assert_eq!(
            ts_seq,
            vec![5.0, 4.0, 3.0, 2.0, 1.0],
            "proposals MUST be sorted DESC by created_at (newest first) — pins explorer.rs:964 b.cmp(&a)",
        );

    // offset=1, limit=2 → [4.0, 3.0].
    let page = compute_governance_proposals(state.clone(), None, Some(2), Some(1)).await;
    assert_eq!(
        page.get("total").and_then(|x| x.as_u64()),
        Some(5),
        "total MUST reflect post-filter count (5), NOT post-pagination count (2)"
    );
    assert_eq!(page.get("limit").and_then(|x| x.as_u64()), Some(2));
    assert_eq!(page.get("offset").and_then(|x| x.as_u64()), Some(1));
    let page_arr = page
        .get("proposals")
        .and_then(|x| x.as_array())
        .expect("array");
    let page_ts: Vec<f64> = page_arr
        .iter()
        .map(|p| p.get("created_at").and_then(|x| x.as_f64()).unwrap_or(0.0))
        .collect();
    assert_eq!(
            page_ts,
            vec![4.0, 3.0],
            "offset=1 limit=2 from DESC-sorted [5,4,3,2,1] MUST yield [4.0, 3.0] — pins skip(1).take(2) composition",
        );
}

#[tokio::test]
async fn batch_kkk_compute_governance_proposals_limit_clamped_at_200_and_tally_reflects_one_vote() {
    // Two-axis test:
    //   (a) Limit clamp: limit=10_000 → effective limit=200 (clamped at
    //       explorer.rs:922 via .min(200)). Pins the un-paginated DoS
    //       vector at 1M-proposal mainnet scale.
    //   (b) Tally non-zero: insert ONE proposal with ONE For vote at
    //       stake=1_000_000 micros. Verify:
    //         • tally.for > 0.0 (conviction(1_000_000, 0_duration) > 0).
    //         • tally.voters = 1.
    //         • tally.raw_participating_stake = 1_000_000 (sum of stakes
    //           pre-dampening).
    //         • tally.raw_participating_stake_beat = format_beat_precise(
    //           1_000_000) = "0.001" (0 whole + 9-pad-then-trim "001000000"
    //           → "001").
    //         • vote_count = 1.
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        // Insert a single proposal with one For vote.
        let one_vote = crate::accounting::governance::Vote {
            voter: "voter-1".into(),
            stake: 1_000_000,
            direction: crate::accounting::governance::VoteDirection::For,
            voted_at: 1700000000.0,
            own_stake: None,
        };
        ledger.governance.proposals.insert(
            "p-vote".into(),
            batch_kkk_mk_proposal(
                "p-vote",
                "alice",
                crate::accounting::governance::ProposalCategory::Parameter,
                crate::accounting::governance::ProposalStatus::Active,
                "with one vote",
                1700000000.0,
                vec![one_vote],
            ),
        );
    }

    // Axis (a): limit clamp.
    let clamped = compute_governance_proposals(state.clone(), None, Some(10_000), None).await;
    assert_eq!(
        clamped.get("limit").and_then(|x| x.as_u64()),
        Some(200),
        "limit=10_000 MUST clamp to 200 — pins explorer.rs:922 .min(200) DoS guard",
    );

    // Axis (b): tally non-zero on the single voted proposal.
    let v = compute_governance_proposals(state.clone(), None, None, None).await;
    let p = v
        .get("proposals")
        .and_then(|x| x.as_array())
        .and_then(|a| a.first())
        .expect("one proposal");
    assert_eq!(
        p.get("vote_count").and_then(|x| x.as_u64()),
        Some(1),
        "vote_count MUST be 1 after inserting one Vote"
    );

    let tally = p.get("tally").and_then(|x| x.as_object()).expect("tally");
    let for_conv = tally
        .get("for")
        .and_then(|x| x.as_f64())
        .expect("for_conviction MUST be f64");
    assert!(for_conv > 0.0,
            "tally.for MUST be > 0.0 for one For vote with stake=1_000_000 — pins tally_votes wiring at explorer.rs:942");
    assert_eq!(
        tally.get("voters").and_then(|x| x.as_u64()),
        Some(1),
        "tally.voters MUST equal voter_count = 1"
    );
    assert_eq!(
        tally.get("against").and_then(|x| x.as_f64()),
        Some(0.0),
        "tally.against MUST be 0.0 (no Against votes)"
    );
    assert_eq!(
        tally.get("abstain").and_then(|x| x.as_f64()),
        Some(0.0),
        "tally.abstain MUST be 0.0 (no Abstain votes)"
    );
    assert_eq!(
        tally
            .get("raw_participating_stake")
            .and_then(|x| x.as_u64()),
        Some(1_000_000),
        "raw_participating_stake MUST be u64 sum of stakes (1_000_000) — pre-dampening",
    );
    assert_eq!(
            tally.get("raw_participating_stake_beat").and_then(|x| x.as_str()),
            Some("0.001"),
            "format_beat_precise(1_000_000) MUST yield \"0.001\" (whole=0, frac=1_000_000 → \"001000000\" → trim → \"001\") — \
             pins accounting/validate.rs:863-873 trailing-zero-trim contract",
        );
}

// ─── compute_governance_proposal_detail (explorer.rs:990) ──
//
// Sibling endpoint to /governance/proposals. The /governance/proposal/{id}
// detail endpoint emits a DIFFERENT envelope shape than the list
// endpoint:
//   • 13-key top-level (vs 9-key per-list-entry): adds description,
//     passed_at, can_execute, total_governance_staked, full votes array.
//   • 8-key tally (vs 6-key in list): adds for_fraction +
//     supermajority_met (computed at the route boundary, not in
//     tally_votes itself).
//   • Per-vote 6-key entry (NEW — not present in list endpoint at all):
//     voter, direction, stake, voted_at, conviction, dampened_power.
//     Wallets render the vote list from this exact shape.
//
// Reuses `batch_kkk_mk_proposal` helper (no new helper needed —
// Proposal/Vote structs are identical between list and detail).

#[tokio::test]
async fn batch_lll_compute_governance_proposal_detail_not_found_returns_governance_error() {
    // Not-found path: requesting an id that doesn't exist in
    // ledger.governance.proposals MUST return ElaraError::Governance
    // with the message "proposal not found: {id}". This is the ONLY
    // non-Ok path through compute_governance_proposal_detail (the rest
    // of the function is infallible after the get()). Pins the error
    // chain through the `?` operator at explorer.rs:1000.
    let state = test_state();
    let res = compute_governance_proposal_detail(state.clone(), "does-not-exist".into()).await;
    let err = res.expect_err("MUST be Err for unknown proposal id");
    match err {
        crate::errors::ElaraError::Governance(msg) => {
            assert!(
                    msg.contains("proposal not found"),
                    "error message MUST contain \"proposal not found\" — pins explorer.rs:1000 format string; actual: {msg}",
                );
            assert!(
                    msg.contains("does-not-exist"),
                    "error message MUST echo the requested id — pins format!() interpolation; actual: {msg}",
                );
        }
        other => panic!("expected ElaraError::Governance, got {other:?}"),
    }
}

#[tokio::test]
async fn batch_lll_compute_governance_proposal_detail_strict_thirteen_key_envelope_with_zero_votes()
{
    // Insert ONE Parameter/Active proposal with NO votes. Pins:
    //   • Top-level strict 13-key envelope: id, proposer, category,
    //     title, description, status, created_at, voting_deadline,
    //     passed_at, can_execute, votes, tally, total_governance_staked.
    //   • description = "desc for prop-detail-001" (from helper's
    //     format!() — proves description is wired through, not dropped).
    //   • passed_at = JSON null (Proposal.passed_at = None, serde
    //     serializes None as null).
    //   • can_execute = false (Active ≠ Passed → can_execute() early
    //     returns false at governance.rs:428).
    //   • votes = [] (empty array, not absent key — pins the always-emit
    //     contract).
    //   • tally numerics all zero (no votes → tally_votes early-exit).
    //   • for_fraction = 0.0 (decisive=0 → else-branch at
    //     explorer.rs:1029-1033).
    //   • supermajority_met = false (0.0 < 0.67 SUPERMAJORITY_THRESHOLD).
    //   • total_governance_staked = 0 (fresh state has no stakes).
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        ledger.governance.proposals.insert(
            "prop-detail-001".into(),
            batch_kkk_mk_proposal(
                "prop-detail-001",
                "alice-detail-hash",
                crate::accounting::governance::ProposalCategory::Parameter,
                crate::accounting::governance::ProposalStatus::Active,
                "lower epoch floor",
                1700000000.0,
                vec![],
            ),
        );
    }
    let v = compute_governance_proposal_detail(state.clone(), "prop-detail-001".into())
        .await
        .expect("Ok for inserted proposal");

    let obj = v.as_object().expect("top-level MUST be JSON Object");
    let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    keys.sort();
    assert_eq!(
            keys,
            vec![
                "can_execute",
                "category",
                "created_at",
                "description",
                "id",
                "passed_at",
                "proposer",
                "status",
                "tally",
                "title",
                "total_governance_staked",
                "votes",
                "voting_deadline",
            ],
            "detail envelope MUST emit EXACTLY 13 keys — pins wire shape against silent additions/removals on /governance/proposal/{{id}}",
        );

    assert_eq!(
        v.get("id").and_then(|x| x.as_str()),
        Some("prop-detail-001")
    );
    assert_eq!(
        v.get("proposer").and_then(|x| x.as_str()),
        Some("alice-detail-hash")
    );
    assert_eq!(
        v.get("category").and_then(|x| x.as_str()),
        Some("parameter")
    );
    assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("active"));
    assert_eq!(
        v.get("title").and_then(|x| x.as_str()),
        Some("lower epoch floor")
    );
    assert_eq!(
            v.get("description").and_then(|x| x.as_str()),
            Some("desc for prop-detail-001"),
            "description MUST be the helper-generated `desc for {{id}}` string — proves description is wired through to detail envelope (the list endpoint omits this field)",
        );
    assert_eq!(
        v.get("created_at").and_then(|x| x.as_f64()),
        Some(1700000000.0)
    );
    assert_eq!(
        v.get("voting_deadline").and_then(|x| x.as_f64()),
        Some(1700000000.0 + 7.0 * 24.0 * 3600.0),
    );
    assert!(
            v.get("passed_at").map(|x| x.is_null()).unwrap_or(false),
            "passed_at MUST be JSON null when Proposal.passed_at = None — pins serde Option<f64> ↔ null serialization",
        );
    assert_eq!(
        v.get("can_execute").and_then(|x| x.as_bool()),
        Some(false),
        "can_execute MUST be false for Active proposal (governance.rs:428: not Passed → false)",
    );
    assert!(
        v.get("votes")
            .and_then(|x| x.as_array())
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "votes MUST be an empty JSON array (not missing key) when no votes cast",
    );
    assert_eq!(
        v.get("total_governance_staked").and_then(|x| x.as_u64()),
        Some(0),
        "total_governance_staked MUST be 0 in a fresh ledger (no stakes inserted)",
    );

    // Verify tally arithmetic on zero-vote path.
    let tally = v
        .get("tally")
        .and_then(|x| x.as_object())
        .expect("tally Object");
    assert_eq!(
        tally.get("for_conviction").and_then(|x| x.as_f64()),
        Some(0.0)
    );
    assert_eq!(
        tally.get("against_conviction").and_then(|x| x.as_f64()),
        Some(0.0)
    );
    assert_eq!(
        tally.get("abstain_conviction").and_then(|x| x.as_f64()),
        Some(0.0)
    );
    assert_eq!(tally.get("voters").and_then(|x| x.as_u64()), Some(0));
    assert_eq!(
        tally.get("for_fraction").and_then(|x| x.as_f64()),
        Some(0.0),
        "for_fraction MUST be 0.0 when decisive=0 (explorer.rs:1029-1033 else-branch)",
    );
    assert_eq!(
        tally.get("supermajority_met").and_then(|x| x.as_bool()),
        Some(false),
        "supermajority_met MUST be false when for_fraction (0.0) < SUPERMAJORITY_THRESHOLD (0.67)",
    );
}

#[tokio::test]
async fn batch_lll_compute_governance_proposal_detail_single_for_vote_emits_strict_six_key_vote_entry(
) {
    // Insert a proposal with ONE For vote (stake=4_000_000 base units,
    // voted_at=0.0 so duration since vote = SystemTime::now() ≫ 0).
    // Pins:
    //   • votes array has EXACTLY 1 entry.
    //   • Per-vote entry has EXACTLY 6 keys: voter, direction, stake,
    //     voted_at, conviction, dampened_power. This entry shape is the
    //     PRIMARY new surface introduced by detail (list endpoint omits
    //     per-vote breakdown entirely).
    //   • direction value = "for" (snake_case via VoteDirection::as_str()
    //     at explorer.rs:1019 — NOT enum debug "For").
    //   • stake echoes the input verbatim.
    //   • voted_at echoes the input verbatim (0.0).
    //   • conviction > 0.0 (positive duration × positive stake →
    //     conviction(stake, t) = stake × (1 - e^(-t/τ)) > 0).
    //   • dampened_power = sqrt(conviction), so dampened > 0 and
    //     dampened < conviction (because conviction ≫ 1 ⇒ sqrt smaller).
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        ledger.governance.proposals.insert(
            "prop-one-vote".into(),
            batch_kkk_mk_proposal(
                "prop-one-vote",
                "alice",
                crate::accounting::governance::ProposalCategory::Parameter,
                crate::accounting::governance::ProposalStatus::Active,
                "t",
                1700000000.0,
                vec![crate::accounting::governance::Vote {
                    voter: "voter-A-hash".into(),
                    stake: 4_000_000,
                    direction: crate::accounting::governance::VoteDirection::For,
                    voted_at: 0.0,
                    own_stake: None,
                }],
            ),
        );
    }
    let v = compute_governance_proposal_detail(state.clone(), "prop-one-vote".into())
        .await
        .expect("Ok");

    let votes = v
        .get("votes")
        .and_then(|x| x.as_array())
        .expect("votes Array");
    assert_eq!(votes.len(), 1, "MUST have exactly 1 vote entry");

    let entry = votes[0].as_object().expect("vote entry MUST be Object");
    let mut vkeys: Vec<&str> = entry.keys().map(|s| s.as_str()).collect();
    vkeys.sort();
    assert_eq!(
            vkeys,
            vec![
                "conviction",
                "dampened_power",
                "direction",
                "stake",
                "voted_at",
                "voter",
            ],
            "per-vote entry MUST emit EXACTLY 6 keys — pins the per-vote envelope shape that accounts render from",
        );

    assert_eq!(
        entry.get("voter").and_then(|x| x.as_str()),
        Some("voter-A-hash")
    );
    assert_eq!(
            entry.get("direction").and_then(|x| x.as_str()),
            Some("for"),
            "direction MUST be `for` (snake_case via VoteDirection::as_str) NOT \"For\" (Debug fmt) — pins explorer.rs:1019",
        );
    assert_eq!(entry.get("stake").and_then(|x| x.as_u64()), Some(4_000_000));
    assert_eq!(entry.get("voted_at").and_then(|x| x.as_f64()), Some(0.0));

    let conv = entry
        .get("conviction")
        .and_then(|x| x.as_f64())
        .expect("conviction MUST be f64");
    assert!(
            conv > 0.0,
            "conviction MUST be > 0.0 for stake=4M with duration ≫ 0 (current time - voted_at=0); got {conv}",
        );
    let damp = entry
        .get("dampened_power")
        .and_then(|x| x.as_f64())
        .expect("dampened_power MUST be f64");
    assert!(
            damp > 0.0 && damp < conv,
            "dampened_power = sqrt(conviction); for conv≫1 MUST satisfy 0 < damp < conv; got damp={damp} conv={conv}",
        );
    // Tighter bound: dampened_power MUST equal sqrt(conviction) within f64 precision.
    let expected_damp = conv.sqrt();
    let rel_err = (damp - expected_damp).abs() / expected_damp.max(1.0);
    assert!(
            rel_err < 1e-12,
            "dampened_power MUST equal sqrt(conviction) — pins governance.rs:1209 sqrt(); rel_err={rel_err}",
        );
}

#[tokio::test]
async fn batch_lll_compute_governance_proposal_detail_strict_eight_key_tally_with_for_fraction_arithmetic(
) {
    // Insert a proposal with TWO votes: 1 For (stake=8M) + 1 Against
    // (stake=2M), both with voted_at=0.0. Pins:
    //   • Tally strict 8-key envelope: for_conviction, against_conviction,
    //     abstain_conviction, voters, raw_participating_stake,
    //     raw_participating_stake_beat, for_fraction, supermajority_met.
    //   • voters = 2.
    //   • raw_participating_stake = 8M + 2M = 10M.
    //   • raw_participating_stake_beat = format_beat_precise(10_000_000)
    //     = "0.01" (whole=0, frac=10_000_000 → trim → "01").
    //   • for_conviction > against_conviction.
    //   • for_fraction = 2/3 (NOT 0.8). tally_votes (governance.rs:1283)
    //     stores DAMPENED powers (sqrt of raw conviction), so the ratio
    //     is sqrt(8M)/sqrt(2M) = sqrt(4) = 2, giving for_fraction =
    //     2/(2+1) = 2/3. This is the load-bearing wire-shape detail
    //     accounts must respect: the tally fields are SQRT-DAMPENED.
    //   • supermajority_met = false (2/3 ≈ 0.6667 < 0.67
    //     SUPERMAJORITY_THRESHOLD). The strict-less-than gap between
    //     2/3 and 0.67 is intentional — supermajority should require a
    //     genuine super-majority, not bare two-thirds.
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        ledger.governance.proposals.insert(
            "prop-tally".into(),
            batch_kkk_mk_proposal(
                "prop-tally",
                "alice",
                crate::accounting::governance::ProposalCategory::Parameter,
                crate::accounting::governance::ProposalStatus::Active,
                "t",
                1700000000.0,
                vec![
                    crate::accounting::governance::Vote {
                        voter: "v-for".into(),
                        stake: 8_000_000,
                        direction: crate::accounting::governance::VoteDirection::For,
                        voted_at: 0.0,
                        own_stake: None,
                    },
                    crate::accounting::governance::Vote {
                        voter: "v-against".into(),
                        stake: 2_000_000,
                        direction: crate::accounting::governance::VoteDirection::Against,
                        voted_at: 0.0,
                        own_stake: None,
                    },
                ],
            ),
        );
    }
    let v = compute_governance_proposal_detail(state.clone(), "prop-tally".into())
        .await
        .expect("Ok");

    let tally = v
        .get("tally")
        .and_then(|x| x.as_object())
        .expect("tally Object");
    let mut tkeys: Vec<&str> = tally.keys().map(|s| s.as_str()).collect();
    tkeys.sort();
    assert_eq!(
            tkeys,
            vec![
                "abstain_conviction",
                "against_conviction",
                "for_conviction",
                "for_fraction",
                "raw_participating_stake",
                "raw_participating_stake_beat",
                "supermajority_met",
                "voters",
            ],
            "detail tally envelope MUST emit EXACTLY 8 keys — pins wire shape (list tally uses different keys: for/against/abstain + 3 raw + voters = 6)",
        );

    assert_eq!(tally.get("voters").and_then(|x| x.as_u64()), Some(2));
    assert_eq!(
        tally
            .get("raw_participating_stake")
            .and_then(|x| x.as_u64()),
        Some(10_000_000),
        "raw_participating_stake MUST be 8M + 2M = 10M",
    );
    assert_eq!(
        tally
            .get("raw_participating_stake_beat")
            .and_then(|x| x.as_str()),
        Some("0.01"),
        "format_beat_precise(10_000_000) MUST yield \"0.01\" (10M micro = 0.01 beat)",
    );

    let for_conv = tally
        .get("for_conviction")
        .and_then(|x| x.as_f64())
        .expect("for_conviction f64");
    let against_conv = tally
        .get("against_conviction")
        .and_then(|x| x.as_f64())
        .expect("against_conviction f64");
    let abstain_conv = tally
        .get("abstain_conviction")
        .and_then(|x| x.as_f64())
        .expect("abstain_conviction f64");
    assert!(for_conv > against_conv, "8M stake For > 2M stake Against");
    assert_eq!(abstain_conv, 0.0, "no Abstain votes");

    let for_fraction = tally
        .get("for_fraction")
        .and_then(|x| x.as_f64())
        .expect("for_fraction f64");
    // tally.for_conviction and tally.against_conviction are DAMPENED
    // (sqrt) per governance.rs:1305. So for fixed duration t:
    //   for_dampened    = sqrt(conv(8M, t)) ∝ sqrt(8M)
    //   against_dampened = sqrt(conv(2M, t)) ∝ sqrt(2M)
    // ratio = sqrt(8M)/sqrt(2M) = sqrt(4) = 2
    // for_fraction = 2/(2+1) = 2/3 ≈ 0.6666666666666667.
    let expected_fraction = 2.0_f64 / 3.0_f64;
    let rel_err = (for_fraction - expected_fraction).abs();
    assert!(
            rel_err < 1e-12,
            "for_fraction MUST equal sqrt(8M)/(sqrt(8M)+sqrt(2M)) = 2/3 because tally stores sqrt-dampened powers (governance.rs:1305); got {for_fraction}",
        );
    // 2/3 ≈ 0.6667 vs 0.67 threshold: 0.6667 < 0.67, so supermajority
    // is NOT met. Pins the strict-less-than gap between 2/3 and 0.67.
    assert!(
            for_fraction < crate::accounting::governance::SUPERMAJORITY_THRESHOLD,
            "premise check: for_fraction (2/3) MUST be < SUPERMAJORITY_THRESHOLD (0.67); got fraction={for_fraction} threshold={}",
            crate::accounting::governance::SUPERMAJORITY_THRESHOLD,
        );
    assert_eq!(
        tally.get("supermajority_met").and_then(|x| x.as_bool()),
        Some(false),
        "supermajority_met MUST be false (2/3 ≈ 0.6667 < 0.67 SUPERMAJORITY_THRESHOLD)",
    );
}

#[tokio::test]
async fn batch_lll_compute_governance_proposal_detail_passed_with_passed_at_yields_can_execute_true(
) {
    // Insert a Passed proposal with passed_at = Some(0.0) (epoch 1970).
    // SystemTime::now() at test time is ≫ 1970 + 30·24·3600 (the
    // EXECUTION_DELAY_SECS = 30 days), so can_execute MUST return true.
    // Pins:
    //   • passed_at serializes as Some(0.0) → JSON Number 0.0, NOT null.
    //     This is the OTHER serde branch from the Active test above (None → null).
    //   • can_execute = true (Passed status + passed_at + now ≫ passed_at
    //     + EXECUTION_DELAY_SECS).
    //   • status string = "passed" (lowercase via Debug+to_lowercase).
    //
    // Together with batch_lll_..._strict_thirteen_key_envelope_with_zero_votes
    // (which pins None → null + false can_execute), this test pins BOTH
    // branches of passed_at's Option<f64> ↔ JSON serialization AND BOTH
    // branches of can_execute's status/timing predicate.
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        let mut prop = batch_kkk_mk_proposal(
            "prop-passed",
            "alice",
            crate::accounting::governance::ProposalCategory::Parameter,
            crate::accounting::governance::ProposalStatus::Passed,
            "executed prop",
            1700000000.0,
            vec![],
        );
        prop.passed_at = Some(0.0); // 1970-01-01 — now() ≫ this + 30d
        ledger
            .governance
            .proposals
            .insert("prop-passed".into(), prop);
    }
    let v = compute_governance_proposal_detail(state.clone(), "prop-passed".into())
        .await
        .expect("Ok");

    assert_eq!(
        v.get("status").and_then(|x| x.as_str()),
        Some("passed"),
        "status MUST be lowercase \"passed\" (Debug+to_lowercase)",
    );
    assert_eq!(
            v.get("passed_at").and_then(|x| x.as_f64()),
            Some(0.0),
            "passed_at MUST serialize as JSON Number 0.0 (NOT null) when Proposal.passed_at = Some(0.0) — pins serde Option<f64>::Some ↔ Number",
        );
    assert_eq!(
            v.get("can_execute").and_then(|x| x.as_bool()),
            Some(true),
            "can_execute MUST be true: status=Passed AND now({}) > passed_at(0.0) + EXECUTION_DELAY_SECS(30d) — pins governance.rs:427-435 happy-path",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0),
        );
}

// ─── compute_governance_summary (explorer.rs:1071) ──────────
//
// Continues
// the governance-subsystem sweep that opened with
// compute_governance_proposals and compute_governance_proposal_detail.
// Pins compute_governance_summary — the
// aggregate counters + constants surface served by `/governance/summary`,
// which is the wire contract accounts read for governance-mode UX
// (proposal totals, voting params, delegation count).
//
// Five axis-distinct surfaces this batch pins:
//   1. Strict 16-key envelope on fresh state + zero-counter baseline.
//   2. proposal_counts wiring across all 7 ProposalStatus variants
//      (Active, Passed, Rejected, Expired, Executed, Cancelled, Vetoed)
//      via recount_proposal_statuses bridge.
//   3. total_governance_staked filter contract: counted iff
//      (active=true AND purpose=Governance). Witness, Storage, and
//      inactive entries MUST be excluded.
//   4. active_delegations surfaces the incremental counter field (NOT
//      delegations.len()) — inactive entries don't count, the counter
//      is the load-bearing scrape-path value.
//   5. Constants (MIN_PROPOSAL_STAKE, MAX_ACTIVE_PROPOSALS_PER_IDENTITY,
//      VOTING_PERIOD_SECS, EXECUTION_DELAY_SECS, SUPERMAJORITY_THRESHOLD,
//      MIN_PARTICIPATION_FRACTION) surface verbatim with the library's
//      exact f64/u64/usize values — pins the wire contract against silent
//      constant drift.
//
// Strategy: insert proposals / stakes / delegations directly into the
// ledger via the write-lock pattern, then read back via
// `compute_governance_summary`. Bridge-helpers (`recount_proposal_statuses`,
// `recount_active_delegations`) sync the incremental counters after
// direct-map insertion, which is the same pattern snapshot-restore uses.

#[tokio::test]
async fn batch_mmm_compute_governance_summary_fresh_state_emits_strict_sixteen_key_envelope_with_zero_counters(
) {
    // Fresh state: no proposals, no stakes, no delegations. MUST emit
    // the strict 16-key envelope with all 10 counter-style fields at
    // zero (total_proposals, active, passed, rejected, expired, executed,
    // cancelled, vetoed, active_delegations, total_governance_staked)
    // and the 6 constant-style fields populated from library values.
    // This pins the wire shape against silent additions/removals on
    // `/governance/summary` — a regression that drops a key would break
    // account governance-mode rendering.
    let state = test_state();
    let v = compute_governance_summary(state.clone()).await;

    let obj = v.as_object().expect("top-level MUST be JSON Object");
    let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    keys.sort();
    assert_eq!(
            keys,
            vec![
                "active",
                "active_delegations",
                "cancelled",
                "executed",
                "execution_delay_secs",
                "expired",
                "max_active_proposals_per_identity",
                "min_participation_fraction",
                "min_proposal_stake",
                "passed",
                "rejected",
                "supermajority_threshold",
                "total_governance_staked",
                "total_proposals",
                "vetoed",
                "voting_period_secs",
            ],
            "summary envelope MUST emit EXACTLY 16 keys — pins wire shape against silent additions/removals on /governance/summary",
        );

    // All 10 counter-style fields are zero on fresh state.
    assert_eq!(v.get("total_proposals").and_then(|x| x.as_u64()), Some(0));
    assert_eq!(v.get("active").and_then(|x| x.as_u64()), Some(0));
    assert_eq!(v.get("passed").and_then(|x| x.as_u64()), Some(0));
    assert_eq!(v.get("rejected").and_then(|x| x.as_u64()), Some(0));
    assert_eq!(v.get("expired").and_then(|x| x.as_u64()), Some(0));
    assert_eq!(v.get("executed").and_then(|x| x.as_u64()), Some(0));
    assert_eq!(v.get("cancelled").and_then(|x| x.as_u64()), Some(0));
    assert_eq!(v.get("vetoed").and_then(|x| x.as_u64()), Some(0));
    assert_eq!(
        v.get("active_delegations").and_then(|x| x.as_u64()),
        Some(0)
    );
    assert_eq!(
        v.get("total_governance_staked").and_then(|x| x.as_u64()),
        Some(0)
    );
}

#[tokio::test]
async fn batch_mmm_compute_governance_summary_proposal_counts_match_all_seven_status_variants() {
    // Insert 8 proposals across all 7 ProposalStatus variants:
    //   2× Active + 1× each of {Passed, Rejected, Expired, Executed,
    //   Cancelled, Vetoed} = 8 total.
    // After `recount_proposal_statuses` (snapshot-restore bridge), the
    // status counters MUST match exactly. Pins compute_governance_summary's
    // `proposal_counts()` tuple-destructure at explorer.rs:1073 against
    // a tuple-ordering bug (the 7 fields are positional). The 2× Active
    // case proves the counter increments (not a boolean flag).
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        use crate::accounting::governance::{ProposalCategory, ProposalStatus};
        let inserts = [
            ("p-active-1", ProposalStatus::Active),
            ("p-active-2", ProposalStatus::Active),
            ("p-passed", ProposalStatus::Passed),
            ("p-rejected", ProposalStatus::Rejected),
            ("p-expired", ProposalStatus::Expired),
            ("p-executed", ProposalStatus::Executed),
            ("p-cancelled", ProposalStatus::Cancelled),
            ("p-vetoed", ProposalStatus::Vetoed),
        ];
        for (id, status) in inserts {
            ledger.governance.proposals.insert(
                id.into(),
                batch_kkk_mk_proposal(
                    id,
                    "alice",
                    ProposalCategory::Parameter,
                    status,
                    "t",
                    1700000000.0,
                    vec![],
                ),
            );
        }
        // Bridge: direct-map insertion bypasses inc/dec; reseed counters.
        ledger.governance.recount_proposal_statuses();
    }

    let v = compute_governance_summary(state.clone()).await;
    assert_eq!(
        v.get("total_proposals").and_then(|x| x.as_u64()),
        Some(8),
        "total_proposals MUST equal proposals.len() = 8",
    );
    assert_eq!(
        v.get("active").and_then(|x| x.as_u64()),
        Some(2),
        "active MUST be 2 (counter, not flag — pins explorer.rs:1073 tuple position 0)",
    );
    assert_eq!(
        v.get("passed").and_then(|x| x.as_u64()),
        Some(1),
        "passed MUST be 1 — pins explorer.rs:1073 tuple position 1",
    );
    assert_eq!(
        v.get("rejected").and_then(|x| x.as_u64()),
        Some(1),
        "rejected MUST be 1 — pins explorer.rs:1073 tuple position 2",
    );
    assert_eq!(
        v.get("expired").and_then(|x| x.as_u64()),
        Some(1),
        "expired MUST be 1 — pins explorer.rs:1073 tuple position 3",
    );
    assert_eq!(
        v.get("executed").and_then(|x| x.as_u64()),
        Some(1),
        "executed MUST be 1 — pins explorer.rs:1073 tuple position 4",
    );
    assert_eq!(
        v.get("cancelled").and_then(|x| x.as_u64()),
        Some(1),
        "cancelled MUST be 1 — pins explorer.rs:1073 tuple position 5",
    );
    assert_eq!(
        v.get("vetoed").and_then(|x| x.as_u64()),
        Some(1),
        "vetoed MUST be 1 — pins explorer.rs:1073 tuple position 6",
    );
}

#[tokio::test]
async fn batch_mmm_compute_governance_summary_total_governance_staked_excludes_witness_storage_inactive(
) {
    // total_governance_staked sums StakeEntry.amount IFF
    //   active == true AND purpose == StakePurpose::Governance
    // Insert 4 entries with the cross-product of mismatches; only ONE
    // qualifies. Pins the filter contract at governance.rs:1568
    //   `.filter(|s| s.active && s.purpose == StakePurpose::Governance)`
    // — a regression that drops either predicate would inflate the
    // total and break economics-page accounting.
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        use crate::accounting::ledger::StakeEntry;
        use crate::accounting::types::StakePurpose;
        // Counted: active + governance.
        ledger.stakes.insert(
            "alice-gov-active".into(),
            StakeEntry {
                record_id: "alice-gov-active".into(),
                amount: 10_000_000,
                purpose: StakePurpose::Governance,
                staker: "alice".into(),
                timestamp: 1700000000.0,
                active: true,
            },
        );
        // NOT counted: active + witness.
        ledger.stakes.insert(
            "bob-witness-active".into(),
            StakeEntry {
                record_id: "bob-witness-active".into(),
                amount: 5_000_000,
                purpose: StakePurpose::Witness,
                staker: "bob".into(),
                timestamp: 1700000001.0,
                active: true,
            },
        );
        // NOT counted: inactive + governance.
        ledger.stakes.insert(
            "carol-gov-inactive".into(),
            StakeEntry {
                record_id: "carol-gov-inactive".into(),
                amount: 7_000_000,
                purpose: StakePurpose::Governance,
                staker: "carol".into(),
                timestamp: 1700000002.0,
                active: false,
            },
        );
        // NOT counted: active + storage.
        ledger.stakes.insert(
            "dave-storage-active".into(),
            StakeEntry {
                record_id: "dave-storage-active".into(),
                amount: 3_000_000,
                purpose: StakePurpose::Storage,
                staker: "dave".into(),
                timestamp: 1700000003.0,
                active: true,
            },
        );
    }
    let v = compute_governance_summary(state.clone()).await;
    assert_eq!(
            v.get("total_governance_staked").and_then(|x| x.as_u64()),
            Some(10_000_000),
            "total_governance_staked MUST be 10M (alice only) — proves both (active=true) AND (purpose=Governance) gates are wired. Witness (5M), inactive-gov (7M), and storage (3M) MUST be excluded.",
        );
}

#[tokio::test]
async fn batch_mmm_compute_governance_summary_active_delegations_reflects_counter_not_map_size() {
    // active_delegations surfaces ledger.governance.active_delegations_count
    // (the incremental u64 counter), NOT delegations.len(). Insert
    // 3 DelegationEntry rows — 2 active + 1 inactive — and verify after
    // recount_active_delegations() the surfaced count is 2, NOT 3.
    //
    // This pins the load-bearing distinction: delegations is a HashMap
    // that keeps inactive entries (history-preserving), but the incremental
    // scrape-path counter is the source of truth for the active-only
    // count. A regression that swapped to `.len()` would inflate the
    // count and break governance-mode UX showing "active delegations".
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        use crate::accounting::governance::DelegationEntry;
        ledger.governance.delegations.insert(
            "alice".into(),
            DelegationEntry {
                delegator: "alice".into(),
                delegate: "bob".into(),
                created_at: 1700000000.0,
                active: true,
            },
        );
        ledger.governance.delegations.insert(
            "carol".into(),
            DelegationEntry {
                delegator: "carol".into(),
                delegate: "bob".into(),
                created_at: 1700000001.0,
                active: true,
            },
        );
        ledger.governance.delegations.insert(
            "dave".into(),
            DelegationEntry {
                delegator: "dave".into(),
                delegate: "eve".into(),
                created_at: 1700000002.0,
                active: false,
            },
        );
        // Bridge the active-delegations counter from direct-map insertion.
        ledger.governance.recount_active_delegations();
        // Premise check: HashMap.len() is 3, counter is 2.
        assert_eq!(ledger.governance.delegations.len(), 3);
        assert_eq!(ledger.governance.active_delegations_count, 2);
    }

    let v = compute_governance_summary(state.clone()).await;
    assert_eq!(
            v.get("active_delegations").and_then(|x| x.as_u64()),
            Some(2),
            "active_delegations MUST surface the OPS-155 counter (=2), NOT delegations.len() (=3). Inactive entries are history-preserved in the map but excluded from the active count.",
        );
}

#[tokio::test]
async fn batch_mmm_compute_governance_summary_constants_match_library_exports_verbatim() {
    // The 6 constant-style fields (min_proposal_stake,
    // max_active_proposals_per_identity, voting_period_secs,
    // execution_delay_secs, supermajority_threshold,
    // min_participation_fraction) MUST surface the library's exact
    // values verbatim — these are the wire contract that anchors the
    // economics rendering on the account's governance-mode panel. A
    // silent drift in these constants would mean accounts compute the
    // wrong "needs N beat to propose" gate or the wrong "X days left
    // to vote" countdown.
    //
    // Pin specific numeric values rather than just `assert_eq!(expr,
    // const)` — that catches both the case where the const moves AND
    // the case where the surface-helper switches to a different const
    // (e.g. accidentally serializing the wrong field).
    let state = test_state();
    let v = compute_governance_summary(state.clone()).await;

    // min_proposal_stake = MIN_PROPOSAL_STAKE = 1_000 × BASE_UNITS_PER_BEAT
    //                                        = 1_000 × 1_000_000_000
    //                                        = 1_000_000_000_000 base units
    //                                        = 1_000 beat.
    // Note: despite the "micro" name, BASE_UNITS_PER_BEAT is 10^9 (i.e., nano-
    // scale internally) — see accounting/types.rs:25. The wire shape is what
    // accounts read, so pin the raw u64 here.
    assert_eq!(
            v.get("min_proposal_stake").and_then(|x| x.as_u64()),
            Some(1_000_000_000_000),
            "min_proposal_stake MUST equal MIN_PROPOSAL_STAKE = 1_000 × BASE_UNITS_PER_BEAT (1e9) = 1e12 raw units",
        );
    assert_eq!(
        v.get("min_proposal_stake").and_then(|x| x.as_u64()),
        Some(crate::accounting::governance::MIN_PROPOSAL_STAKE),
        "min_proposal_stake MUST equal the live library const value",
    );

    // max_active_proposals_per_identity = 3.
    assert_eq!(
        v.get("max_active_proposals_per_identity")
            .and_then(|x| x.as_u64()),
        Some(3),
        "max_active_proposals_per_identity MUST equal MAX_ACTIVE_PROPOSALS_PER_IDENTITY = 3",
    );
    assert_eq!(
        v.get("max_active_proposals_per_identity")
            .and_then(|x| x.as_u64())
            .map(|u| u as usize),
        Some(crate::accounting::governance::MAX_ACTIVE_PROPOSALS_PER_IDENTITY),
    );

    // voting_period_secs = 14 days = 14 × 24 × 3600 = 1_209_600.0.
    assert_eq!(
        v.get("voting_period_secs").and_then(|x| x.as_f64()),
        Some(14.0 * 24.0 * 3600.0),
        "voting_period_secs MUST equal VOTING_PERIOD_SECS = 14 days in seconds",
    );
    assert_eq!(
        v.get("voting_period_secs").and_then(|x| x.as_f64()),
        Some(crate::accounting::governance::VOTING_PERIOD_SECS),
    );

    // execution_delay_secs = 30 days = 30 × 24 × 3600 = 2_592_000.0.
    assert_eq!(
        v.get("execution_delay_secs").and_then(|x| x.as_f64()),
        Some(30.0 * 24.0 * 3600.0),
        "execution_delay_secs MUST equal EXECUTION_DELAY_SECS = 30 days in seconds",
    );
    assert_eq!(
        v.get("execution_delay_secs").and_then(|x| x.as_f64()),
        Some(crate::accounting::governance::EXECUTION_DELAY_SECS),
    );

    // supermajority_threshold = 0.67 (super-2/3, strict-greater than
    // bare 2/3 to require a genuine super-majority).
    assert_eq!(
        v.get("supermajority_threshold").and_then(|x| x.as_f64()),
        Some(0.67),
        "supermajority_threshold MUST equal SUPERMAJORITY_THRESHOLD = 0.67",
    );
    assert_eq!(
        v.get("supermajority_threshold").and_then(|x| x.as_f64()),
        Some(crate::accounting::governance::SUPERMAJORITY_THRESHOLD),
    );

    // min_participation_fraction = 0.25.
    assert_eq!(
        v.get("min_participation_fraction").and_then(|x| x.as_f64()),
        Some(0.25),
        "min_participation_fraction MUST equal MIN_PARTICIPATION_FRACTION = 0.25",
    );
    assert_eq!(
        v.get("min_participation_fraction").and_then(|x| x.as_f64()),
        Some(crate::accounting::governance::MIN_PARTICIPATION_FRACTION),
    );
}

// ─── compute_dag_record_graph / compute_dag_stats ────────
//
// The DAG-subsystem
// pivot — the lowest-coverage subsystem after
// the governance-triplet sweep closes. Two helpers in one batch:
//
//   compute_dag_record_graph (explorer.rs:2054, 12-key envelope) — the
//   account's "explore around this record" surface: parents+children
//   neighbourhood plus BFS-bounded ancestors/descendants. Wire shape
//   contains 4 paired array+count fields (parents, children, ancestors,
//   descendants) PLUS 4 scalar context fields (record_id, exists,
//   depth, direction). Previous direct coverage = ZERO.
//
//   compute_dag_stats (explorer.rs:2269, 7-key envelope) — the
//   explorer landing-page header card (total records + classification
//   pie + operation pie + earliest/latest time-range). This is now an
//   O(1) atomic-load over the prior O(all_records) for_each scan;
//   the test pins the wire shape end-to-end against
//   `record_stats_snapshot_json` and locks the
//   atomic-counters → JSON-keys mapping contract.
//
// Five tests structured as: (1)+(2)+(3)+(4) on record_graph (fresh
// state, linear chain, diamond DAG, direction filter), (5) on stats
// (atomic-counter wire-shape pin).

#[tokio::test]
async fn batch_nnn_compute_dag_record_graph_fresh_state_emits_strict_twelve_key_envelope_with_empty_arrays(
) {
    // Fresh-state probe: query a record_id that does NOT exist in the
    // DAG. The 12-key envelope MUST still surface fully populated with
    // `exists=false`, `parents/children/ancestors/descendants` as
    // empty JSON arrays (NOT null, NOT missing), and all `_count`
    // siblings as 0. This is the safe-default contract the account's
    // "record not found" branch relies on — a regression that returned
    // `null` for any array field would break the account's iteration
    // logic with an undefined-array NPE.
    let state = test_state();
    let v =
        compute_dag_record_graph(state.clone(), "non-existent-record-id".into(), None, None).await;

    let obj = v
        .as_object()
        .expect("compute_dag_record_graph returns an object");
    assert_eq!(
        obj.len(),
        13,
        "compute_dag_record_graph MUST emit a strict 13-key envelope \
             (record_id, exists, depth, direction, parents/_count × 4 \
             paired arrays, truncated); got {} keys: {:?}",
        obj.len(),
        obj.keys().collect::<Vec<_>>(),
    );
    for key in [
        "record_id",
        "exists",
        "depth",
        "direction",
        "parents",
        "parents_count",
        "children",
        "children_count",
        "ancestors",
        "ancestors_count",
        "descendants",
        "descendants_count",
        "truncated",
    ] {
        assert!(obj.contains_key(key), "envelope MUST contain key '{key}'");
    }
    // Fresh state → nothing to walk → not truncated.
    assert_eq!(
        v["truncated"].as_bool(),
        Some(false),
        "empty-DAG graph walk is complete, not truncated",
    );

    assert_eq!(v["record_id"].as_str(), Some("non-existent-record-id"));
    assert_eq!(v["exists"].as_bool(), Some(false));
    // Default depth = 5 (depth.unwrap_or(5).min(20)); default direction
    // = "both" — both pinned here as part of the wire contract.
    assert_eq!(v["depth"].as_u64(), Some(5));
    assert_eq!(v["direction"].as_str(), Some("both"));

    // All four paired (array, count) surfaces MUST be empty array +
    // count=0. Pin BOTH halves to catch a regression that emitted
    // null or omitted the count.
    for key in ["parents", "children", "ancestors", "descendants"] {
        assert!(
            v[key].is_array(),
            "{key} MUST be a JSON array (NOT null/missing) so accounts \
                 can iterate without an undefined-array NPE",
        );
        assert_eq!(
            v[key].as_array().map(|a| a.len()),
            Some(0),
            "{key} MUST be empty on fresh state",
        );
        assert_eq!(
            v[format!("{key}_count").as_str()].as_u64(),
            Some(0),
            "{key}_count MUST equal 0 on fresh state",
        );
    }
}

#[tokio::test]
async fn compute_causal_proof_carries_capped_flags_and_counts_on_small_dag() {
    // 5-node linear chain c1→…→c5; query the middle node c3. The walks are
    // far below MAX_DAG_WALK_NODES, so the response MUST carry the bounded-walk
    // signal keys with value `false` (the wire contract a client uses to know
    // the counts are exact, not a floor). A regression that dropped the flags
    // would silently turn a bounded count back into an unbounded-looking one.
    let state = test_state();
    {
        let mut dag_guard = state.dag.write().await;
        let dag = std::sync::Arc::make_mut(&mut *dag_guard);
        dag.insert("c1".into(), vec![], 100.0).expect("insert c1");
        dag.insert("c2".into(), vec!["c1".into()], 101.0).expect("insert c2");
        dag.insert("c3".into(), vec!["c2".into()], 102.0).expect("insert c3");
        dag.insert("c4".into(), vec!["c3".into()], 103.0).expect("insert c4");
        dag.insert("c5".into(), vec!["c4".into()], 104.0).expect("insert c5");
    }
    let v = compute_causal_proof(state, "c3".into())
        .await
        .expect("causal proof for an existing record");

    assert_eq!(v["ancestor_count"].as_u64(), Some(2), "c3 ancestors = {{c1,c2}}");
    assert_eq!(v["descendant_count"].as_u64(), Some(2), "c3 descendants = {{c4,c5}}");
    assert_eq!(
        v["ancestor_count_capped"].as_bool(),
        Some(false),
        "small-DAG walk is complete — count is exact, not capped",
    );
    assert_eq!(
        v["descendant_count_capped"].as_bool(),
        Some(false),
        "small-DAG walk is complete — count is exact, not capped",
    );
}

#[tokio::test]
async fn batch_nnn_compute_dag_record_graph_linear_chain_emits_sorted_parents_children_ancestors_descendants(
) {
    // 5-node linear chain c1→c2→c3→c4→c5 (each child has prior as
    // parent). Query the MIDDLE node c3. Expected surface:
    //   parents = [c2], parents_count = 1
    //   children = [c4], children_count = 1
    //   ancestors = {c1, c2} (sorted → [c1, c2]), ancestors_count = 2
    //   descendants = {c4, c5} (sorted → [c4, c5]), descendants_count = 2
    // The `v.sort()` calls at explorer.rs:2070 / 2078 are load-bearing
    // for stable JSON serialization order — accounts cache the response
    // and diff it, an unstable order would generate spurious cache
    // misses. Pin the exact sorted ordering.
    let state = test_state();
    {
        let mut dag_guard = state.dag.write().await;
        let dag = std::sync::Arc::make_mut(&mut *dag_guard);
        dag.insert("c1".into(), vec![], 100.0).expect("insert c1");
        dag.insert("c2".into(), vec!["c1".into()], 101.0)
            .expect("insert c2");
        dag.insert("c3".into(), vec!["c2".into()], 102.0)
            .expect("insert c3");
        dag.insert("c4".into(), vec!["c3".into()], 103.0)
            .expect("insert c4");
        dag.insert("c5".into(), vec!["c4".into()], 104.0)
            .expect("insert c5");
    }
    let v = compute_dag_record_graph(state, "c3".into(), None, None).await;

    assert_eq!(
        v["exists"].as_bool(),
        Some(true),
        "c3 MUST exist in the DAG"
    );

    let parents = v["parents"].as_array().expect("parents array");
    assert_eq!(
        parents
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["c2"],
        "direct parent of c3 MUST be c2",
    );
    assert_eq!(v["parents_count"].as_u64(), Some(1));

    let children = v["children"].as_array().expect("children array");
    assert_eq!(
        children
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["c4"],
        "direct child of c3 MUST be c4",
    );
    assert_eq!(v["children_count"].as_u64(), Some(1));

    // ancestors are sorted lex — c1 < c2 lexicographically.
    let ancestors = v["ancestors"].as_array().expect("ancestors array");
    assert_eq!(
        ancestors
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["c1", "c2"],
        "ancestors MUST be lex-sorted (pins the v.sort() call at explorer.rs:2070)",
    );
    assert_eq!(v["ancestors_count"].as_u64(), Some(2));

    // descendants are sorted lex — c4 < c5.
    let descendants = v["descendants"].as_array().expect("descendants array");
    assert_eq!(
        descendants
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["c4", "c5"],
        "descendants MUST be lex-sorted (pins the v.sort() call at explorer.rs:2078)",
    );
    assert_eq!(v["descendants_count"].as_u64(), Some(2));
}

#[tokio::test]
async fn batch_nnn_compute_dag_record_graph_diamond_dag_ancestors_deduplicated_via_hashset() {
    // Diamond DAG:
    //          d_top
    //         /     \
    //       d_lef   d_rig
    //         \     /
    //          d_bot
    // Query d_bot. Expected:
    //   parents = [d_lef, d_rig] (sorted lex), parents_count = 2
    //   ancestors = {d_top, d_lef, d_rig} via HashSet dedup (NOT 4 with
    //                a duplicate d_top from the two BFS paths) → sorted
    //                yields [d_lef, d_rig, d_top], ancestors_count = 3
    // The `HashSet<String>` return type at dag.rs:629 is load-bearing
    // for the diamond case — a regression to Vec<String> with
    // append-on-visit would emit duplicates and inflate the count.
    let state = test_state();
    {
        let mut dag_guard = state.dag.write().await;
        let dag = std::sync::Arc::make_mut(&mut *dag_guard);
        dag.insert("d_top".into(), vec![], 100.0)
            .expect("insert d_top");
        dag.insert("d_lef".into(), vec!["d_top".into()], 101.0)
            .expect("insert d_lef");
        dag.insert("d_rig".into(), vec!["d_top".into()], 102.0)
            .expect("insert d_rig");
        dag.insert("d_bot".into(), vec!["d_lef".into(), "d_rig".into()], 103.0)
            .expect("insert d_bot");
    }
    let v = compute_dag_record_graph(state, "d_bot".into(), None, None).await;

    let parents = v["parents"].as_array().expect("parents array");
    // dag.parents() iterates a BTreeSet (or HashSet → collect to Vec
    // without sort), so the response sort comes from neither parents
    // nor children — only ancestors/descendants are explicitly sorted.
    // Pin parents_count=2 and lex-membership without ordering.
    assert_eq!(v["parents_count"].as_u64(), Some(2));
    let parents_set: std::collections::HashSet<&str> =
        parents.iter().map(|x| x.as_str().unwrap()).collect();
    assert_eq!(
        parents_set,
        ["d_lef", "d_rig"].iter().copied().collect(),
        "d_bot's direct parents MUST be exactly {{d_lef, d_rig}}",
    );

    // Ancestors: HashSet dedup MUST collapse d_top down to one entry.
    // sorted lex → [d_lef, d_rig, d_top].
    let ancestors = v["ancestors"].as_array().expect("ancestors array");
    assert_eq!(
        ancestors
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["d_lef", "d_rig", "d_top"],
        "diamond DAG ancestors MUST be deduplicated by HashSet \
             (pins dag.rs:629 return type) and lex-sorted",
    );
    assert_eq!(
        v["ancestors_count"].as_u64(),
        Some(3),
        "diamond DAG ancestor count MUST be 3 (NOT 4 with duplicate d_top)",
    );
}

#[tokio::test]
async fn batch_nnn_compute_dag_record_graph_direction_filter_excludes_opposite_traversal_set() {
    // The `direction` query param at explorer.rs:2062 has three valid
    // values: "both" (default), "ancestors", "descendants". When the
    // filter is "ancestors" the descendants array MUST be empty (count
    // 0); when "descendants" the ancestors array MUST be empty (count
    // 0). Direct parents/children are ALWAYS populated regardless of
    // direction (they're computed unconditionally at explorer.rs:2065).
    //
    // Build a 3-node chain a→b→c, query the middle b under each of
    // the three direction modes.
    let state = test_state();
    {
        let mut dag_guard = state.dag.write().await;
        let dag = std::sync::Arc::make_mut(&mut *dag_guard);
        dag.insert("a".into(), vec![], 100.0).expect("insert a");
        dag.insert("b".into(), vec!["a".into()], 101.0)
            .expect("insert b");
        dag.insert("c".into(), vec!["b".into()], 102.0)
            .expect("insert c");
    }

    // direction = "ancestors" → ancestors populated, descendants empty.
    let v_anc =
        compute_dag_record_graph(state.clone(), "b".into(), None, Some("ancestors".into())).await;
    assert_eq!(v_anc["direction"].as_str(), Some("ancestors"));
    assert_eq!(v_anc["parents_count"].as_u64(), Some(1));
    assert_eq!(v_anc["children_count"].as_u64(), Some(1));
    assert_eq!(
        v_anc["ancestors_count"].as_u64(),
        Some(1),
        "ancestors direction MUST populate ancestors (b's ancestor=a, count=1)",
    );
    assert_eq!(
        v_anc["descendants_count"].as_u64(),
        Some(0),
        "ancestors direction MUST zero out the descendants traversal",
    );
    assert_eq!(
        v_anc["descendants"].as_array().map(|a| a.len()),
        Some(0),
        "ancestors direction MUST emit empty descendants array",
    );

    // direction = "descendants" → descendants populated, ancestors empty.
    let v_des =
        compute_dag_record_graph(state.clone(), "b".into(), None, Some("descendants".into())).await;
    assert_eq!(v_des["direction"].as_str(), Some("descendants"));
    assert_eq!(
        v_des["ancestors_count"].as_u64(),
        Some(0),
        "descendants direction MUST zero out the ancestors traversal",
    );
    assert_eq!(
        v_des["descendants_count"].as_u64(),
        Some(1),
        "descendants direction MUST populate descendants (b's descendant=c, count=1)",
    );

    // direction = "both" → both populated. Sanity-pin to bound the
    // matrix and prove the asymmetric filter above isn't a side effect
    // of the default branch.
    let v_both = compute_dag_record_graph(state, "b".into(), None, Some("both".into())).await;
    assert_eq!(v_both["direction"].as_str(), Some("both"));
    assert_eq!(v_both["ancestors_count"].as_u64(), Some(1));
    assert_eq!(v_both["descendants_count"].as_u64(), Some(1));
}

#[tokio::test]
async fn batch_nnn_compute_dag_stats_reflects_atomic_counters_with_strict_seven_key_top_level_envelope(
) {
    // compute_dag_stats is the O(1) wire-projection of NodeState's
    // record-stats atomic counters. The wire shape is a
    // strict 7-key top-level envelope:
    //   total_records, unique_creators, creators_indexed, stats_partial,
    //   time_range{earliest,latest}, by_classification{public,private,
    //   restricted,sovereign}, by_operation{mint,transfer,stake,unstake,
    //   burn,slash,witness_reward,dormancy_reclaim,pool_fund,
    //   epoch_seal,non_token}
    // Pin BOTH the 7-key top-level skeleton AND the atomic-counter →
    // JSON field mapping. A regression that re-ordered the atomic
    // loads in record_stats_snapshot_json would silently swap counter
    // labels in the explorer landing page.
    use std::sync::atomic::Ordering::Relaxed;
    let state = test_state();

    // Seed the atomic counters with distinguishable per-field values
    // so any mis-wiring will surface as a label swap.
    state.record_stats_total.store(42, Relaxed);
    state.record_stats_class_public.store(20, Relaxed);
    state.record_stats_class_private.store(10, Relaxed);
    state.record_stats_class_restricted.store(8, Relaxed);
    state.record_stats_class_sovereign.store(4, Relaxed);
    state.record_stats_op_mint.store(11, Relaxed);
    state.record_stats_op_transfer.store(12, Relaxed);
    state.record_stats_op_stake.store(13, Relaxed);
    state.record_stats_op_unstake.store(14, Relaxed);
    state.record_stats_op_burn.store(15, Relaxed);
    state.record_stats_op_slash.store(16, Relaxed);
    state.record_stats_op_witness_reward.store(17, Relaxed);
    state.record_stats_op_dormancy_reclaim.store(18, Relaxed);
    state.record_stats_op_pool_fund.store(19, Relaxed);
    state.record_stats_epoch_seals.store(21, Relaxed);
    state.record_stats_non_token.store(22, Relaxed);
    // f64-bits storage: earliest=1700000000.0, latest=1700001000.0.
    state
        .record_stats_earliest_ts_bits
        .store(1700000000.0_f64.to_bits(), Relaxed);
    state
        .record_stats_latest_ts_bits
        .store(1700001000.0_f64.to_bits(), Relaxed);
    state.record_stats_seed_bounded.store(true, Relaxed);

    let v = compute_dag_stats(state)
        .await
        .expect("compute_dag_stats ok");

    let obj = v.as_object().expect("compute_dag_stats returns an object");
    assert_eq!(
        obj.len(),
        7,
        "compute_dag_stats MUST emit a strict 7-key envelope (total_records, \
             unique_creators, creators_indexed, stats_partial, time_range, \
             by_classification, by_operation); got {} keys: {:?}",
        obj.len(),
        obj.keys().collect::<Vec<_>>(),
    );

    // Top-level scalars: pin total/unique_creators (null until HLL
    // ships)/creators_indexed (false until HLL ships)/stats_partial.
    assert_eq!(v["total_records"].as_u64(), Some(42));
    assert!(
        v["unique_creators"].is_null(),
        "unique_creators MUST be null until the HLL follow-up lands \
             (per record_stats_snapshot_json contract at state.rs:4522)",
    );
    assert_eq!(v["creators_indexed"].as_bool(), Some(false));
    assert_eq!(v["stats_partial"].as_bool(), Some(true));

    // time_range — 2-key sub-envelope with earliest/latest f64.
    let tr = v["time_range"].as_object().expect("time_range object");
    assert_eq!(tr.len(), 2, "time_range MUST be 2-key {{earliest, latest}}");
    assert_eq!(tr["earliest"].as_f64(), Some(1700000000.0));
    assert_eq!(tr["latest"].as_f64(), Some(1700001000.0));

    // by_classification — 4-key sub-envelope. Distinguishable per-field
    // values catch any label-swap regression.
    let bc = v["by_classification"]
        .as_object()
        .expect("by_classification object");
    assert_eq!(bc.len(), 4);
    assert_eq!(bc["public"].as_u64(), Some(20));
    assert_eq!(bc["private"].as_u64(), Some(10));
    assert_eq!(bc["restricted"].as_u64(), Some(8));
    assert_eq!(bc["sovereign"].as_u64(), Some(4));

    // by_operation — 11-key sub-envelope (matches the 10 ledger ops +
    // epoch_seal + non_token = 11 distinct buckets). Pin label→atomic
    // mapping.
    let bo = v["by_operation"].as_object().expect("by_operation object");
    assert_eq!(
        bo.len(),
        11,
        "by_operation MUST be 11-key (mint,transfer,stake,unstake,burn,\
             slash,witness_reward,dormancy_reclaim,pool_fund,epoch_seal,non_token); \
             got {} keys: {:?}",
        bo.len(),
        bo.keys().collect::<Vec<_>>(),
    );
    assert_eq!(bo["mint"].as_u64(), Some(11));
    assert_eq!(bo["transfer"].as_u64(), Some(12));
    assert_eq!(bo["stake"].as_u64(), Some(13));
    assert_eq!(bo["unstake"].as_u64(), Some(14));
    assert_eq!(bo["burn"].as_u64(), Some(15));
    assert_eq!(bo["slash"].as_u64(), Some(16));
    assert_eq!(bo["witness_reward"].as_u64(), Some(17));
    assert_eq!(bo["dormancy_reclaim"].as_u64(), Some(18));
    assert_eq!(bo["pool_fund"].as_u64(), Some(19));
    assert_eq!(bo["epoch_seal"].as_u64(), Some(21));
    assert_eq!(bo["non_token"].as_u64(), Some(22));
}

// ─── compute_xzone_stats (explorer.rs:2503) ──────────────
//
// The cross-zone-subsystem pivot — the lowest-coverage account-render surface
// after the governance triplet and DAG pair closed.
// Previous direct-pin count: ZERO. Adjacent indirect coverage exists
// in `cross_zone::tests::ops152_status_counters_invariant_under_random_ops`
// which pins the per-status state-machine invariant on CrossZoneState
// mutations — those tests guard the counter machinery, but NOT the
// wire-shape projection that accounts actually render.
//
// The /xzone/stats wire surface is a strict 4-key top envelope:
//   counters:                6-key sub {locks_total, claims_total,
//                             refunds_total, aborts_total, cancels_total,
//                             rejects_total} — each backed by a NodeState
//                             AtomicU64 at state.rs:1687-1704.
//   pending:                 5-key sub {total, locked, claimed, refunded,
//                             aborted} — `total` reflects HashMap len,
//                             the other 4 are per-status counters on
//                             CrossZoneState (cross_zone.rs:209-212).
//   currently_locked_micros: u64 from LedgerState.pending_xzone_locked
//                             (ledger.rs:182).
//   claim_timeout_secs:      f64 const CLAIM_TIMEOUT_SECS (= 24 * 3600
//                             = 86400.0) from cross_zone.rs:29.
//
// Five axes pin the wire contract end-to-end against the source-of-truth
// surfaces above. Any silent re-wiring (atomic→JSON label swap, per-status
// counter→HashMap-len fallback, constant rename) surfaces at the CI gate.

#[tokio::test]
async fn batch_ooo_compute_xzone_stats_fresh_state_emits_strict_four_key_envelope_with_zero_counters(
) {
    // Fresh state — zero atomic counters, zero per-status counters, empty
    // pending HashMap, zero pending_xzone_locked. The 4-key top envelope
    // MUST surface in full with `claim_timeout_secs` carrying the live
    // CLAIM_TIMEOUT_SECS const (NOT 0.0 — the const is independent of
    // node state, so the fresh-state branch is exactly where a "default
    // 0 on missing field" regression would surface).
    let state = test_state();
    let v = compute_xzone_stats(state).await;

    let obj = v
        .as_object()
        .expect("compute_xzone_stats returns an object");
    assert_eq!(
        obj.len(),
        4,
        "compute_xzone_stats MUST emit a strict 4-key top envelope \
             (counters, pending, currently_locked_micros, claim_timeout_secs); \
             got {} keys: {:?}",
        obj.len(),
        obj.keys().collect::<Vec<_>>(),
    );
    for key in [
        "counters",
        "pending",
        "currently_locked_micros",
        "claim_timeout_secs",
    ] {
        assert!(
            obj.contains_key(key),
            "top envelope MUST contain key '{key}'"
        );
    }

    // counters sub-envelope: strict 6 keys, all zero on fresh state.
    let counters = v["counters"]
        .as_object()
        .expect("counters MUST be an object");
    assert_eq!(
        counters.len(),
        6,
        "counters sub-envelope MUST be strict 6-key (locks/claims/refunds/\
             aborts/cancels/rejects _total); got {} keys: {:?}",
        counters.len(),
        counters.keys().collect::<Vec<_>>(),
    );
    for key in [
        "locks_total",
        "claims_total",
        "refunds_total",
        "aborts_total",
        "cancels_total",
        "rejects_total",
    ] {
        assert_eq!(
            counters.get(key).and_then(|x| x.as_u64()),
            Some(0),
            "fresh-state counters.{key} MUST be u64 0",
        );
    }

    // pending sub-envelope: strict 5 keys, all zero on fresh state.
    let pending = v["pending"].as_object().expect("pending MUST be an object");
    assert_eq!(
        pending.len(),
        5,
        "pending sub-envelope MUST be strict 5-key (total, locked, claimed, \
             refunded, aborted); got {} keys: {:?}",
        pending.len(),
        pending.keys().collect::<Vec<_>>(),
    );
    for key in ["total", "locked", "claimed", "refunded", "aborted"] {
        assert_eq!(
            pending.get(key).and_then(|x| x.as_u64()),
            Some(0),
            "fresh-state pending.{key} MUST be u64 0",
        );
    }

    // Top-level scalars.
    assert_eq!(v["currently_locked_micros"].as_u64(), Some(0));
    // CLAIM_TIMEOUT_SECS is f64 = 24.0 * 3600.0 = 86400.0 — the const at
    // cross_zone.rs:29. Pin BOTH the literal value AND the live const so
    // a future rename surfaces at the CI gate.
    assert_eq!(
        v["claim_timeout_secs"].as_f64(),
        Some(86400.0),
        "claim_timeout_secs MUST equal CLAIM_TIMEOUT_SECS = 24h = 86400.0 \
             (NOT 0.0 — the const is independent of node state and the \
             fresh-state branch is exactly where 'default-0-on-missing-field' \
             regressions would land)",
    );
    assert_eq!(
        v["claim_timeout_secs"].as_f64(),
        Some(crate::accounting::cross_zone::CLAIM_TIMEOUT_SECS),
        "claim_timeout_secs MUST equal the live CLAIM_TIMEOUT_SECS const \
             (catches future const-rename or value-drift regressions)",
    );
}

#[tokio::test]
async fn batch_ooo_compute_xzone_stats_six_atomic_counters_independence_via_coprime_seeds() {
    // The 6 atomic counters on NodeState (xzone_locks_total .. xzone_rejects_total
    // at state.rs:1687-1704) MUST surface under their EXACT JSON keys in
    // counters.{*_total}. Use coprime distinguishable seeds (7/11/13/17/
    // 19/23) so any label-swap regression in the json! macro at
    // explorer.rs:2528-2535 surfaces as a value mismatch on a specific
    // key. Coprime values defeat any `total = locks + claims + ...`
    // aliasing or accidental cross-wiring.
    use std::sync::atomic::Ordering::Relaxed;
    let state = test_state();
    state.xzone_locks_total.store(7, Relaxed);
    state.xzone_claims_total.store(11, Relaxed);
    state.xzone_refunds_total.store(13, Relaxed);
    state.xzone_aborts_total.store(17, Relaxed);
    state.xzone_cancels_total.store(19, Relaxed);
    state.xzone_rejects_total.store(23, Relaxed);

    let v = compute_xzone_stats(state).await;
    let counters = v["counters"].as_object().expect("counters object");
    // Exact label→atomic mapping. Any silent permutation surfaces here.
    assert_eq!(counters["locks_total"].as_u64(), Some(7));
    assert_eq!(counters["claims_total"].as_u64(), Some(11));
    assert_eq!(counters["refunds_total"].as_u64(), Some(13));
    assert_eq!(counters["aborts_total"].as_u64(), Some(17));
    assert_eq!(counters["cancels_total"].as_u64(), Some(19));
    assert_eq!(counters["rejects_total"].as_u64(), Some(23));
}

#[tokio::test]
async fn batch_ooo_compute_xzone_stats_ops152_status_counters_wire_through_not_via_hashmap_scan() {
    // Per-status
    // counts in pending.{locked,claimed,refunded,aborted} MUST be
    // sourced from CrossZoneState's incrementally-maintained u64 fields
    // (cross_zone.rs:209-212) — NOT from a `pending.values().filter(...)
    // .count()` scan. Set the 4 CrossZoneState counters to coprime
    // distinguishable values (3/5/7/11) WITH AN EMPTY pending HashMap;
    // if the helper were falling back to a HashMap scan, all 4 fields
    // would surface as 0. Coprime defeats accidental cross-wiring.
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        // Mutate the 4 per-status counters directly. Pending HashMap stays
        // EMPTY — the divergence between counters and HashMap len IS the
        // axis being pinned.
        ledger.cross_zone.locked_count = 3;
        ledger.cross_zone.claimed_count = 5;
        ledger.cross_zone.refunded_count = 7;
        ledger.cross_zone.aborted_count = 11;
    }

    let v = compute_xzone_stats(state).await;
    let pending = v["pending"].as_object().expect("pending object");
    // Counters surface verbatim despite the empty HashMap — proves the
    // O(1) counter path at explorer.rs:2519-2522 is wired correctly and
    // hasn't regressed to an O(n) `pending.values()` scan.
    assert_eq!(
        pending["locked"].as_u64(),
        Some(3),
        "pending.locked MUST equal CrossZoneState.locked_count (NOT a \
             HashMap scan — OPS-152 invariant)",
    );
    assert_eq!(pending["claimed"].as_u64(), Some(5));
    assert_eq!(pending["refunded"].as_u64(), Some(7));
    assert_eq!(pending["aborted"].as_u64(), Some(11));
    // pending.total still reflects HashMap len (zero here) — pinned for
    // contrast against the 4 per-status counters above. Demonstrates that
    // pending.total is DERIVED differently from the 4 status fields.
    assert_eq!(
        pending["total"].as_u64(),
        Some(0),
        "pending.total reflects HashMap len (empty here), NOT the sum of \
             the 4 OPS-152 status counters above",
    );
}

#[tokio::test]
async fn batch_ooo_compute_xzone_stats_pending_total_reflects_hashmap_len_and_currently_locked_micros_reflects_ledger_field(
) {
    // Two orthogonal axes in one test:
    //   (a) pending.total reflects `ledger.cross_zone.pending.len() as u64`
    //       at explorer.rs:2523. Insert 3 PendingTransfer entries with
    //       distinct transfer_ids; assert pending.total=3 regardless of
    //       the per-status counter values (which are 0 here, NOT 3).
    //   (b) currently_locked_micros surfaces `ledger.pending_xzone_locked`
    //       u64 verbatim at explorer.rs:2524. Distinct large value
    //       (12_345_678_999) defeats any cross-wiring to the 4 status
    //       counters above.
    use crate::accounting::cross_zone::{PendingTransfer, TransferStatus};
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        // (a) — insert 3 PendingTransfer entries. The per-status counters
        // stay at 0 to prove pending.total is sourced from HashMap len,
        // NOT counter sum.
        for i in 0..3 {
            let tid = format!("tx-{i}");
            ledger.cross_zone.pending.insert(
                tid.clone(),
                PendingTransfer {
                    transfer_id: tid.clone(),
                    sender: "sender".into(),
                    recipient: "recipient".into(),
                    amount: 100,
                    source_zone: crate::ZoneId::new("a"),
                    dest_zone: crate::ZoneId::new("b"),
                    locked_at: 0.0,
                    expires_at: 1.0,
                    status: TransferStatus::Locked,
                    merkle_proof: vec![],
                    lock_record_hash: [0u8; 32],
                    source_merkle_root: [0u8; 32],
                    source_seal_signers: vec![],
                    source_committee_hash: [0u8; 32],
                    source_seal_epoch: 0,
                    source_committee_size: 0,
                    dest_finality_committee: None,
                    claim_record_id: None,
                },
            );
        }
        // (b) — set pending_xzone_locked to a distinct large value. NOT
        // equal to (a)'s 3 entries × 100 amount = 300; NOT equal to the
        // sum of any other counter. Pure isolation test.
        ledger.pending_xzone_locked = 12_345_678_999;
    }

    let v = compute_xzone_stats(state).await;
    assert_eq!(
        v["pending"]["total"].as_u64(),
        Some(3),
        "pending.total MUST equal ledger.cross_zone.pending.len() = 3 \
             (sourced from HashMap len at explorer.rs:2523)",
    );
    // The per-status counters were NOT touched here, so they MUST still be 0 —
    // proves pending.total is independently derived.
    assert_eq!(v["pending"]["locked"].as_u64(), Some(0));
    assert_eq!(v["pending"]["claimed"].as_u64(), Some(0));
    // currently_locked_micros surfaces the LedgerState field verbatim.
    assert_eq!(
        v["currently_locked_micros"].as_u64(),
        Some(12_345_678_999),
        "currently_locked_micros MUST equal ledger.pending_xzone_locked = \
             12_345_678_999 (sourced verbatim at explorer.rs:2524 — distinct \
             from the 3 PendingTransfer × 100 amount sum, proves the field is \
             read independently from HashMap content)",
    );
}

#[tokio::test]
async fn batch_ooo_compute_xzone_stats_counters_pending_and_micros_axes_cross_independent_under_simultaneous_seed(
) {
    // Cross-independence test: seed ALL three axes (atomic counters,
    // per-status counters, ledger micros) with DISTINCT coprime values and
    // verify each surfaces independently — defeats any aliasing or
    // accidental field-reuse regression in the json! macro.
    //
    // Seed values chosen to be mutually coprime AND distinct from any
    // sum/product/diff of each other to maximize divergence detection:
    //   atomic: 31/37/41/43/47/53        (6 primes)
    //   status: 59/61/67/71              (4 primes; pending HashMap empty)
    //   micros: 12_345_678_999            (distinct large u64)
    // Any silent re-wiring (e.g. swapping locks_total → claims_total in
    // the json! macro, or sourcing pending.locked from the atomic instead
    // of the per-status counter) surfaces as a specific value mismatch.
    use std::sync::atomic::Ordering::Relaxed;
    let state = test_state();
    // Atomic counters.
    state.xzone_locks_total.store(31, Relaxed);
    state.xzone_claims_total.store(37, Relaxed);
    state.xzone_refunds_total.store(41, Relaxed);
    state.xzone_aborts_total.store(43, Relaxed);
    state.xzone_cancels_total.store(47, Relaxed);
    state.xzone_rejects_total.store(53, Relaxed);
    // Per-status counters + micros.
    {
        let mut ledger = state.ledger.write().await;
        ledger.cross_zone.locked_count = 59;
        ledger.cross_zone.claimed_count = 61;
        ledger.cross_zone.refunded_count = 67;
        ledger.cross_zone.aborted_count = 71;
        ledger.pending_xzone_locked = 12_345_678_999;
    }

    let v = compute_xzone_stats(state).await;

    // Atomic counters: 31/37/41/43/47/53.
    assert_eq!(v["counters"]["locks_total"].as_u64(), Some(31));
    assert_eq!(v["counters"]["claims_total"].as_u64(), Some(37));
    assert_eq!(v["counters"]["refunds_total"].as_u64(), Some(41));
    assert_eq!(v["counters"]["aborts_total"].as_u64(), Some(43));
    assert_eq!(v["counters"]["cancels_total"].as_u64(), Some(47));
    assert_eq!(v["counters"]["rejects_total"].as_u64(), Some(53));

    // Per-status counters: 59/61/67/71 surface in pending.{locked,claimed,
    // refunded,aborted} — NOT swapped with the atomic counters above
    // (which start at 31). The coprime gap between atomic seeds (31-53)
    // and per-status seeds (59-71) means any cross-wiring would land on a
    // value out of expected range.
    assert_eq!(v["pending"]["locked"].as_u64(), Some(59));
    assert_eq!(v["pending"]["claimed"].as_u64(), Some(61));
    assert_eq!(v["pending"]["refunded"].as_u64(), Some(67));
    assert_eq!(v["pending"]["aborted"].as_u64(), Some(71));
    // pending.total still 0 (empty HashMap).
    assert_eq!(v["pending"]["total"].as_u64(), Some(0));

    // currently_locked_micros: 12_345_678_999 — distinct from every
    // counter value above so cross-wiring surfaces immediately.
    assert_eq!(v["currently_locked_micros"].as_u64(), Some(12_345_678_999));

    // claim_timeout_secs unchanged (independent of node state).
    assert_eq!(
        v["claim_timeout_secs"].as_f64(),
        Some(crate::accounting::cross_zone::CLAIM_TIMEOUT_SECS),
    );
}

// ─── compute_xzone_transfers (explorer.rs:2584) ──────────
//
// The matched-sibling of `compute_xzone_stats`
// in the cross-zone-subsystem sweep. Previous direct-pin count: ZERO.
//
// The /xzone/transfers wire surface is a strict 3-key envelope:
//   total:     u64 = pre-truncate filtered count
//   returned:  u64 = post-truncate array length (== transfers.len())
//   transfers: Array of serialize_transfer() objects, sorted by locked_at
//              DESC (newest first) so accounts see recent activity up top
//
// Filter axes (applied conjunctively inside `pending.values().filter(...)`):
//   status=locked|claimed|refunded|aborted  — exact TransferStatus match;
//                                              any other string parses to
//                                              None (= no status filter)
//   sender=<identity>                       — exact String match
//   recipient=<identity>                    — exact String match
//   limit=N (default 100, cap 1000)         — post-sort truncation
//
// Five axes pin the wire contract end-to-end against the filter/sort/cap
// pipeline at explorer.rs:2584-2643. Any silent re-wiring (filter inversion,
// sort direction flip, total/returned swap, cap removal) surfaces at CI.
//
// Helper: tests below build PendingTransfer entries via this stub to keep
// each test focused on the wire-contract axis being pinned. Default values
// are picked so that filter axes can be tested by overriding only the
// relevant field.
fn ppp_stub_pending_transfer(
    transfer_id: &str,
    sender: &str,
    recipient: &str,
    status: crate::accounting::cross_zone::TransferStatus,
    locked_at: f64,
) -> crate::accounting::cross_zone::PendingTransfer {
    crate::accounting::cross_zone::PendingTransfer {
        transfer_id: transfer_id.into(),
        sender: sender.into(),
        recipient: recipient.into(),
        amount: 100,
        source_zone: crate::ZoneId::new("a"),
        dest_zone: crate::ZoneId::new("b"),
        locked_at,
        expires_at: locked_at + 86400.0,
        status,
        merkle_proof: vec![],
        lock_record_hash: [0u8; 32],
        source_merkle_root: [0u8; 32],
        source_seal_signers: vec![],
        source_committee_hash: [0u8; 32],
        source_seal_epoch: 0,
        source_committee_size: 0,
        dest_finality_committee: None,
        claim_record_id: None,
    }
}

#[tokio::test]
async fn batch_ppp_compute_xzone_transfers_fresh_state_emits_strict_three_key_envelope_with_empty_array(
) {
    // Fresh state — no pending transfers. The 3-key top envelope MUST
    // surface in full with `transfers` as an empty JSON Array (NOT null,
    // NOT absent — accounts iterate the array unconditionally, so a
    // serialize-as-null regression would crash callers). `total` and
    // `returned` MUST both be u64 0. No filters applied.
    let state = test_state();
    let v = compute_xzone_transfers(state, None, None, None, None).await;

    let obj = v
        .as_object()
        .expect("compute_xzone_transfers returns an object");
    assert_eq!(
        obj.len(),
        3,
        "compute_xzone_transfers MUST emit a strict 3-key top envelope \
             (total, returned, transfers); got {} keys: {:?}",
        obj.len(),
        obj.keys().collect::<Vec<_>>(),
    );
    for key in ["total", "returned", "transfers"] {
        assert!(
            obj.contains_key(key),
            "top envelope MUST contain key '{key}'"
        );
    }
    assert_eq!(v["total"].as_u64(), Some(0));
    assert_eq!(v["returned"].as_u64(), Some(0));
    let transfers = v["transfers"]
        .as_array()
        .expect("transfers MUST be a JSON Array (NOT null, NOT absent)");
    assert!(transfers.is_empty(), "fresh-state transfers MUST be empty");
}

#[tokio::test]
async fn batch_ppp_compute_xzone_transfers_status_filter_exact_match_across_all_four_variants_plus_invalid_passthrough(
) {
    // Seed 4 PendingTransfers with DISTINCT statuses (Locked, Claimed,
    // Refunded, Aborted). Apply status filter to each variant and assert
    // the helper returns exactly the matching transfer. Also test that
    // an invalid status string ("xyz") falls through to None (= no
    // filter), returning all 4 transfers. Pins the 4-variant match arm
    // at explorer.rs:2593-2599 against any silent label swap.
    use crate::accounting::cross_zone::TransferStatus;
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        ledger.cross_zone.pending.insert(
            "tx-locked".into(),
            ppp_stub_pending_transfer("tx-locked", "s", "r", TransferStatus::Locked, 1.0),
        );
        ledger.cross_zone.pending.insert(
            "tx-claimed".into(),
            ppp_stub_pending_transfer("tx-claimed", "s", "r", TransferStatus::Claimed, 2.0),
        );
        ledger.cross_zone.pending.insert(
            "tx-refunded".into(),
            ppp_stub_pending_transfer("tx-refunded", "s", "r", TransferStatus::Refunded, 3.0),
        );
        ledger.cross_zone.pending.insert(
            "tx-aborted".into(),
            ppp_stub_pending_transfer("tx-aborted", "s", "r", TransferStatus::Aborted, 4.0),
        );
    }

    for (status_str, expected_id) in &[
        ("locked", "tx-locked"),
        ("claimed", "tx-claimed"),
        ("refunded", "tx-refunded"),
        ("aborted", "tx-aborted"),
    ] {
        let v = compute_xzone_transfers(
            state.clone(),
            Some((*status_str).to_string()),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(
            v["total"].as_u64(),
            Some(1),
            "status={status_str} MUST match exactly 1 transfer",
        );
        assert_eq!(v["returned"].as_u64(), Some(1));
        let transfers = v["transfers"].as_array().expect("array");
        assert_eq!(transfers.len(), 1);
        assert_eq!(
            transfers[0]["transfer_id"].as_str(),
            Some(*expected_id),
            "status={status_str} MUST return transfer_id={expected_id}",
        );
        assert_eq!(transfers[0]["status"].as_str(), Some(*status_str));
    }

    // Invalid status string "xyz" parses to None (no filter), returning
    // ALL 4 transfers. Pins the fall-through arm at explorer.rs:2598.
    let v = compute_xzone_transfers(state.clone(), Some("xyz".to_string()), None, None, None).await;
    assert_eq!(
        v["total"].as_u64(),
        Some(4),
        "invalid status string MUST parse to None (no filter) and return \
             all 4 transfers; got total={}",
        v["total"],
    );
    assert_eq!(v["returned"].as_u64(), Some(4));
}

#[tokio::test]
async fn batch_ppp_compute_xzone_transfers_sender_recipient_filters_exact_match_and_conjunctive_composition(
) {
    // Three axes in one test:
    //   (a) sender filter exact match — case-sensitive, excludes mismatches
    //   (b) recipient filter exact match — same semantics
    //   (c) conjunctive composition (sender AND recipient AND status)
    //       — pins the `&&` semantics at explorer.rs:2607-2622
    //
    // Seed 4 transfers covering the (sender, recipient) cross-product
    // {alice, bob} × {carol, dave}. Each filter axis isolates a subset;
    // conjunctive composition isolates exactly one transfer.
    use crate::accounting::cross_zone::TransferStatus;
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        ledger.cross_zone.pending.insert(
            "tx-ac".into(),
            ppp_stub_pending_transfer("tx-ac", "alice", "carol", TransferStatus::Locked, 1.0),
        );
        ledger.cross_zone.pending.insert(
            "tx-ad".into(),
            ppp_stub_pending_transfer("tx-ad", "alice", "dave", TransferStatus::Claimed, 2.0),
        );
        ledger.cross_zone.pending.insert(
            "tx-bc".into(),
            ppp_stub_pending_transfer("tx-bc", "bob", "carol", TransferStatus::Locked, 3.0),
        );
        ledger.cross_zone.pending.insert(
            "tx-bd".into(),
            ppp_stub_pending_transfer("tx-bd", "bob", "dave", TransferStatus::Refunded, 4.0),
        );
    }

    // (a) sender=alice → 2 transfers (tx-ac, tx-ad).
    let v =
        compute_xzone_transfers(state.clone(), None, Some("alice".to_string()), None, None).await;
    assert_eq!(v["total"].as_u64(), Some(2));
    assert_eq!(v["returned"].as_u64(), Some(2));
    let ids: Vec<&str> = v["transfers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["transfer_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"tx-ac"));
    assert!(ids.contains(&"tx-ad"));
    assert!(
        !ids.contains(&"tx-bc"),
        "bob MUST be excluded by sender=alice"
    );
    assert!(!ids.contains(&"tx-bd"));

    // (b) recipient=carol → 2 transfers (tx-ac, tx-bc).
    let v =
        compute_xzone_transfers(state.clone(), None, None, Some("carol".to_string()), None).await;
    assert_eq!(v["total"].as_u64(), Some(2));
    let ids: Vec<&str> = v["transfers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["transfer_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"tx-ac"));
    assert!(ids.contains(&"tx-bc"));
    assert!(
        !ids.contains(&"tx-ad"),
        "dave MUST be excluded by recipient=carol"
    );
    assert!(!ids.contains(&"tx-bd"));

    // (c) Conjunctive — sender=alice AND recipient=carol AND status=locked
    // → exactly 1 transfer (tx-ac). Pins the `&&` semantics of the three
    // filter clauses at explorer.rs:2607-2622: any single mismatch must
    // exclude the entire row (not just a subset of clauses).
    let v = compute_xzone_transfers(
        state.clone(),
        Some("locked".to_string()),
        Some("alice".to_string()),
        Some("carol".to_string()),
        None,
    )
    .await;
    assert_eq!(
        v["total"].as_u64(),
        Some(1),
        "conjunctive sender=alice AND recipient=carol AND status=locked \
             MUST match exactly 1 transfer (tx-ac)",
    );
    assert_eq!(v["transfers"][0]["transfer_id"].as_str(), Some("tx-ac"),);

    // Conjunctive with a mismatched sender — must return empty (NOT
    // fall back to a single-filter pass).
    let v = compute_xzone_transfers(
        state.clone(),
        None,
        Some("alice".to_string()),
        Some("dave".to_string()),
        None,
    )
    .await;
    assert_eq!(
        v["total"].as_u64(),
        Some(1),
        "sender=alice AND recipient=dave MUST match exactly tx-ad",
    );
    assert_eq!(v["transfers"][0]["transfer_id"].as_str(), Some("tx-ad"));
}

#[tokio::test]
async fn batch_ppp_compute_xzone_transfers_limit_clamp_default_100_and_hard_cap_1000() {
    // Limit clamp pipeline at explorer.rs:2600 = `limit.unwrap_or(100)
    // .min(1000)`. Two distinct axes:
    //   (a) None → 100 (default)
    //   (b) Some(5000) → 1000 (hard cap — DoS guard)
    //
    // Seed N=1500 PendingTransfers (between default 100 and cap 1000)
    // so we can observe BOTH clamp points distinctly:
    //   - None     → returned=100, total=1500
    //   - Some(50) → returned=50,  total=1500    (pass-through under cap)
    //   - Some(5000) → returned=1000, total=1500 (hard cap engaged)
    //
    // Coprime locked_at values keep the sort deterministic for the
    // sibling test (this test only pins `total`/`returned`).
    use crate::accounting::cross_zone::TransferStatus;
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        for i in 0..1500u64 {
            let tid = format!("tx-{i:05}");
            ledger.cross_zone.pending.insert(
                tid.clone(),
                ppp_stub_pending_transfer(
                    &tid,
                    "s",
                    "r",
                    TransferStatus::Locked,
                    // Each transfer gets a distinct locked_at so the
                    // newest-first sort is total-ordering-deterministic.
                    i as f64,
                ),
            );
        }
    }

    // (a) Default — None → 100.
    let v = compute_xzone_transfers(state.clone(), None, None, None, None).await;
    assert_eq!(
        v["total"].as_u64(),
        Some(1500),
        "total MUST reflect pre-truncate filtered count (1500)",
    );
    assert_eq!(
        v["returned"].as_u64(),
        Some(100),
        "default limit MUST clamp to 100 (limit.unwrap_or(100) at \
             explorer.rs:2600)",
    );
    assert_eq!(v["transfers"].as_array().unwrap().len(), 100);

    // (b) Under-cap pass-through — Some(50) → 50.
    let v = compute_xzone_transfers(state.clone(), None, None, None, Some(50)).await;
    assert_eq!(v["total"].as_u64(), Some(1500));
    assert_eq!(v["returned"].as_u64(), Some(50));
    assert_eq!(v["transfers"].as_array().unwrap().len(), 50);

    // (c) Hard cap — Some(5000) → 1000.
    let v = compute_xzone_transfers(state.clone(), None, None, None, Some(5000)).await;
    assert_eq!(v["total"].as_u64(), Some(1500));
    assert_eq!(
        v["returned"].as_u64(),
        Some(1000),
        "limit=5000 MUST clamp to 1000 (`.min(1000)` hard cap at \
             explorer.rs:2600 — DoS guard against unbounded account queries)",
    );
    assert_eq!(v["transfers"].as_array().unwrap().len(), 1000);

    // (d) Exact cap — Some(1000) → 1000.
    let v = compute_xzone_transfers(state.clone(), None, None, None, Some(1000)).await;
    assert_eq!(v["returned"].as_u64(), Some(1000));
}

#[tokio::test]
async fn batch_ppp_compute_xzone_transfers_sort_desc_by_locked_at_and_total_vs_returned_pagination_contract(
) {
    // Two orthogonal contract pins in one test:
    //   (a) Sort order is DESC by locked_at (newest first at array[0])
    //       — pins explorer.rs:2630-2634. Wallets render "recent activity
    //       up top" semantics that an ASC regression would silently
    //       reverse.
    //   (b) total vs returned divergence under truncation — `total` is
    //       the pre-truncate filtered count; `returned` is the
    //       post-truncate array length (which equals transfers.len()).
    //       A regression that conflates these (e.g. `total = returned`
    //       after `.truncate(limit)`) would surface here.
    //
    // Seed 5 transfers with locked_at values {10.0, 30.0, 20.0, 50.0,
    // 40.0} (deliberately unsorted in insertion order so the helper's
    // sort step is the only source of ordering). Apply limit=3 to force
    // truncation and observe both axes.
    use crate::accounting::cross_zone::TransferStatus;
    let state = test_state();
    let locks_at_values = [10.0_f64, 30.0, 20.0, 50.0, 40.0];
    {
        let mut ledger = state.ledger.write().await;
        for (i, &locked_at) in locks_at_values.iter().enumerate() {
            let tid = format!("tx-{i}");
            ledger.cross_zone.pending.insert(
                tid.clone(),
                ppp_stub_pending_transfer(&tid, "s", "r", TransferStatus::Locked, locked_at),
            );
        }
    }

    // (b) total vs returned under limit=3 truncation.
    let v = compute_xzone_transfers(state.clone(), None, None, None, Some(3)).await;
    assert_eq!(
        v["total"].as_u64(),
        Some(5),
        "total MUST reflect pre-truncate filtered count (5), NOT \
             post-truncate (which would be 3 — would indicate the truncation \
             ran BEFORE total was captured at explorer.rs:2635)",
    );
    assert_eq!(
        v["returned"].as_u64(),
        Some(3),
        "returned MUST reflect post-truncate array length (3)",
    );
    let transfers = v["transfers"].as_array().expect("array");
    assert_eq!(
        transfers.len(),
        3,
        "transfers.len() MUST equal returned (3) — pins the \
             returned=transfers.len() invariant at explorer.rs:2640",
    );

    // (a) Sort DESC — newest (largest locked_at) at array[0]. From the
    // seeded {10, 30, 20, 50, 40} the top-3 newest are {50, 40, 30} in
    // order. Pins the partial_cmp(&la) direction at explorer.rs:2633:
    // any ASC regression (la.partial_cmp(&lb)) would land {10, 20, 30}.
    let locked_at_seq: Vec<f64> = transfers
        .iter()
        .map(|t| t["locked_at"].as_f64().unwrap())
        .collect();
    assert_eq!(
        locked_at_seq,
        vec![50.0, 40.0, 30.0],
        "sort MUST be DESC by locked_at (newest first); ASC would give \
             [10.0, 20.0, 30.0]",
    );
    // Verify the corresponding transfer_ids — seeded order in
    // locks_at_values: tx-0=10.0, tx-1=30.0, tx-2=20.0, tx-3=50.0,
    // tx-4=40.0. So newest-first should be tx-3 (50), tx-4 (40), tx-1
    // (30). HashMap iteration order is non-deterministic, so the helper
    // MUST source its ordering ONLY from the sort step — not from
    // insertion or HashMap traversal order.
    let id_seq: Vec<&str> = transfers
        .iter()
        .map(|t| t["transfer_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        id_seq,
        vec!["tx-3", "tx-4", "tx-1"],
        "transfer_id sequence MUST follow locked_at DESC sort",
    );

    // Sub-axis: limit=None default 100 with N=5 entries returns all 5,
    // total == returned == 5 (no truncation engaged). Pins the
    // returned <= total invariant under no-truncate.
    let v = compute_xzone_transfers(state.clone(), None, None, None, None).await;
    assert_eq!(v["total"].as_u64(), Some(5));
    assert_eq!(
        v["returned"].as_u64(),
        Some(5),
        "with N=5 < limit=100, returned MUST equal total (5)",
    );
    assert_eq!(v["transfers"].as_array().unwrap().len(), 5);
}

// ─── compute_dag_search (explorer.rs:2124) ───────────────
//
// DAG-subsystem triplet completion
// (lifecycle+tips + record_graph+stats + search). Previous
// direct-pin count: ZERO. Adjacent indirect coverage: `query_records`
// tests at explorer.rs:4009+ pin the underlying rocks-storage
// timestamp-indexed query primitive, but NOT the post-fetch filter
// pipeline (op/creator/to/from/has_key conjunctive AND + classification
// enum mapping + limit clamp + filters echo) that compute_dag_search
// wraps around it.
//
// The /dag/search wire surface is a strict 4-key envelope:
//   results: Array of entries (id, timestamp, classification,
//            creator_hash, parents, content_hash, has_signature)
//   count:   u64 = post-filter array length
//   limit:   u64 = post-clamp limit echo (raw input clamped to 500)
//   filters: 8-key sub-envelope echoing every input filter param
//            (op, creator, to, from, since, until, classification,
//            has_key) — accounts cache+diff on this envelope so a
//            regression that drops a filter key would invalidate
//            their diff and force a full re-fetch every poll.
//
// Five orthogonal axes pinned (one per branch in the filter pipeline):
//   (1) Fresh-state envelope on empty storage — 4-key top + 8-key
//       filters sub-envelope contract; default limit=50 echoed when
//       params.limit=None at explorer.rs:2128.
//   (2) Limit clamp pipeline = `params.limit.unwrap_or(50).min(500)`.
//       Three axes: None→50 (default), Some(17)→17 (pass-through),
//       Some(999)→500 (hard cap). The clamped value (NOT raw input)
//       echoes into envelope.limit — protects accounts that paginate
//       against the echo.
//   (3) Classification enum mapping at explorer.rs:2132-2140 —
//       lowercase-normalize + 4-variant match {public, private,
//       restricted, sovereign}; ANY other string collapses to None
//       (no filter, all classifications returned). Pins both the
//       case-insensitive normalization AND the fallthrough arm
//       against silent label swap.
//   (4) beat_op filter at explorer.rs:2178-2183 — PURE string-compare
//       on record.metadata["beat_op"], decoupled from LedgerOp::from_str
//       parse. A sentinel string that is NOT a valid LedgerOp must
//       still filter correctly (proves the filter branch doesn't
//       call extract_ledger_op first).
//   (5) Composite creator + has_key conjunctive AND filter at
//       explorer.rs:2171-2203 — full 2×2 cross-product (creator-match
//       × key-match) with only ONE record passing both filters. OR
//       regression would yield 3; swapped-order regression would yield
//       2. Pins the AND-composition semantics AND the filters-echo
//       sub-envelope shape (every input field echoed verbatim).

#[tokio::test]
async fn batch_qqq_compute_dag_search_fresh_state_emits_strict_four_key_envelope_with_eight_filter_subkeys(
) {
    // Fresh-state probe: empty rocks DB. The 4-key envelope MUST
    // surface with `results=[]` (empty Array, NOT null), `count=0`,
    // `limit=50` (the unwrap_or default echoed back), and the
    // `filters` sub-object MUST contain all 8 keys with null values.
    // Wallets diff on this envelope shape — a regression that
    // omitted a filter key would invalidate their diff and force a
    // full re-fetch on every poll.
    let state = test_state();
    let params = DagSearchQuery {
        op: None,
        creator: None,
        to: None,
        from: None,
        since: None,
        until: None,
        limit: None,
        classification: None,
        has_key: None,
    };
    let v = compute_dag_search(state.clone(), params)
        .await
        .expect("compute_dag_search succeeds on empty rocks");

    let obj = v.as_object().expect("compute_dag_search returns an object");
    assert_eq!(
        obj.len(),
        4,
        "compute_dag_search MUST emit a strict 4-key envelope \
             (results, count, limit, filters); got {} keys: {:?}",
        obj.len(),
        obj.keys().collect::<Vec<_>>(),
    );
    for key in ["results", "count", "limit", "filters"] {
        assert!(obj.contains_key(key), "envelope MUST contain key '{key}'");
    }

    // results MUST be empty Array (NOT null/missing) — accounts iterate
    // unconditionally so an as-null regression would crash callers.
    assert!(
        v["results"].is_array(),
        "results MUST be a JSON Array so accounts can iterate without an undefined-array NPE",
    );
    assert_eq!(v["results"].as_array().map(|a| a.len()), Some(0));
    assert_eq!(v["count"].as_u64(), Some(0));

    // Default limit = 50 (params.limit.unwrap_or(50).min(500)) — the
    // 50 echoes back into envelope.limit when input is None. Pins the
    // unwrap_or branch independently of the .min(500) clamp.
    assert_eq!(
        v["limit"].as_u64(),
        Some(50),
        "envelope.limit MUST echo the default 50 when params.limit=None",
    );

    // filters sub-envelope: 8 keys MUST be present even when all are
    // None (serde_json emits `null` for None — so the keys ARE in
    // the JSON object).
    let filters = v["filters"]
        .as_object()
        .expect("filters MUST be a JSON object");
    assert_eq!(
        filters.len(),
        8,
        "filters MUST contain exactly 8 keys; got {} keys: {:?}",
        filters.len(),
        filters.keys().collect::<Vec<_>>(),
    );
    for key in [
        "op",
        "creator",
        "to",
        "from",
        "since",
        "until",
        "classification",
        "has_key",
    ] {
        assert!(
            filters.contains_key(key),
            "filters sub-envelope MUST contain key '{key}' (got: {:?})",
            filters.keys().collect::<Vec<_>>(),
        );
        assert!(
            filters[key].is_null(),
            "filters.{key} MUST be null when input is None (got {:?})",
            filters[key],
        );
    }
}

#[tokio::test]
async fn batch_qqq_compute_dag_search_limit_clamp_default_fifty_pass_through_and_hard_cap_five_hundred(
) {
    // Limit clamp pipeline at explorer.rs:2128 = `params.limit
    // .unwrap_or(50).min(500)`. Three axes:
    //   (a) None        → 50   (default)
    //   (b) Some(17)    → 17   (sub-cap pass-through)
    //   (c) Some(999)   → 500  (hard cap engaged — DoS guard)
    // The clamped value (NOT raw input) echoes into envelope.limit —
    // protects accounts that paginate against the echo (if a regression
    // returned 999 in the echo, the account would over-paginate on the
    // next page and hit the same 500-row cap silently, breaking its
    // "expected page size" accounting).
    let state = test_state();

    // (a) None → 50.
    let v = compute_dag_search(
        state.clone(),
        DagSearchQuery {
            op: None,
            creator: None,
            to: None,
            from: None,
            since: None,
            until: None,
            limit: None,
            classification: None,
            has_key: None,
        },
    )
    .await
    .expect("None limit");
    assert_eq!(
        v["limit"].as_u64(),
        Some(50),
        "None limit MUST default to 50 via unwrap_or(50)",
    );

    // (b) Some(17) → 17 (sub-cap pass-through).
    let v = compute_dag_search(
        state.clone(),
        DagSearchQuery {
            op: None,
            creator: None,
            to: None,
            from: None,
            since: None,
            until: None,
            limit: Some(17),
            classification: None,
            has_key: None,
        },
    )
    .await
    .expect("sub-cap limit");
    assert_eq!(
        v["limit"].as_u64(),
        Some(17),
        "sub-cap limit MUST echo verbatim (17 in, 17 out)",
    );

    // (c) Some(999) → 500 (hard cap engaged).
    let v = compute_dag_search(
        state.clone(),
        DagSearchQuery {
            op: None,
            creator: None,
            to: None,
            from: None,
            since: None,
            until: None,
            limit: Some(999),
            classification: None,
            has_key: None,
        },
    )
    .await
    .expect("over-cap limit");
    assert_eq!(
        v["limit"].as_u64(),
        Some(500),
        "envelope.limit MUST echo the CLAMPED value 500 (NOT the raw input 999); \
             accounts paginate against this echo so an unclamped echo would break \
             their page-size accounting",
    );
}

#[tokio::test]
async fn batch_qqq_compute_dag_search_classification_enum_mapping_invalid_string_falls_through_to_none(
) {
    // Insert 2 Public + 1 Private records. Query each classification
    // variant + one invalid string. The invalid string MUST collapse
    // to None (no filter — three results returned) NOT propagate as
    // a 4xx-style error or crash. The lowercase normalization at
    // explorer.rs:2133 ALSO needs to match — "Public" (capital P)
    // normalizes to "public" pre-match.
    let state = test_state();
    for (id, classification, ts) in [
        ("pub-a", Classification::Public, 100.0),
        ("pub-b", Classification::Public, 110.0),
        ("priv-a", Classification::Private, 120.0),
    ] {
        let mut rec = stub_record(id);
        rec.classification = classification;
        rec.timestamp = ts;
        state.rocks.put_record(id, &rec).expect("put_record");
    }

    // (a) classification="public" — only the 2 Public records.
    let v = compute_dag_search(
        state.clone(),
        DagSearchQuery {
            op: None,
            creator: None,
            to: None,
            from: None,
            since: None,
            until: None,
            limit: None,
            classification: Some("public".into()),
            has_key: None,
        },
    )
    .await
    .expect("public filter");
    assert_eq!(v["count"].as_u64(), Some(2), "public filter MUST yield 2");
    let ids: Vec<&str> = v["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    for id in &ids {
        assert!(
            id.starts_with("pub-"),
            "Private record leaked into public filter: {id}",
        );
    }

    // (b) classification="Public" (capital P) — lowercase normalization
    // at explorer.rs:2133 MUST hit, yielding the same 2 records.
    let v = compute_dag_search(
        state.clone(),
        DagSearchQuery {
            op: None,
            creator: None,
            to: None,
            from: None,
            since: None,
            until: None,
            limit: None,
            classification: Some("Public".into()),
            has_key: None,
        },
    )
    .await
    .expect("Public (capital P) filter");
    assert_eq!(
        v["count"].as_u64(),
        Some(2),
        "case-insensitive lowercase normalization MUST yield 2 for 'Public'",
    );

    // (c) classification="not-a-real-class" — invalid string collapses
    // to None (no filter) → all 3 records returned. Pins the
    // fallthrough arm `_ => None` at explorer.rs:2138 against any
    // future regression that might surface invalid strings as errors.
    let v = compute_dag_search(
        state.clone(),
        DagSearchQuery {
            op: None,
            creator: None,
            to: None,
            from: None,
            since: None,
            until: None,
            limit: None,
            classification: Some("not-a-real-class".into()),
            has_key: None,
        },
    )
    .await
    .expect("invalid classification");
    assert_eq!(
        v["count"].as_u64(),
        Some(3),
        "invalid classification string MUST collapse to None (no filter) → 3 records, \
             NOT 0 (would be a silent UX cliff) or error",
    );
    // Echo carries the raw input verbatim (NOT the parsed enum).
    assert_eq!(
        v["filters"]["classification"].as_str(),
        Some("not-a-real-class"),
        "filters.classification echoes the raw input string verbatim",
    );
}

#[tokio::test]
async fn batch_qqq_compute_dag_search_beat_op_filter_is_pure_string_compare_decoupled_from_ledger_op_parse(
) {
    // The op_filter branch at explorer.rs:2178-2183 does a PURE
    // string compare on record.metadata["beat_op"] — it MUST NOT
    // call LedgerOp::from_str. Pin this by using a sentinel
    // beat_op string ("vanish") that is NOT a valid LedgerOp.
    // If the filter accidentally called extract_ledger_op first,
    // it would error on the unknown op and `vanish` would never
    // match — the test would yield count=0 instead of count=2.
    //
    // The fetch_limit*10 multiplier at explorer.rs:2142-2148 also
    // engages here (filter set → fetch 10× the limit pre-filter),
    // so this test implicitly verifies the multiplier path is
    // still bounded by the post-filter `if results.len() >= limit
    // { break; }` cap at explorer.rs:2167.
    let state = test_state();
    for (id, op, ts) in [
        ("v-1", "vanish", 100.0),
        ("v-2", "vanish", 110.0),
        ("k-1", "kindle", 120.0),
        ("k-2", "kindle", 130.0),
    ] {
        let mut rec = stub_record(id);
        rec.timestamp = ts;
        rec.metadata.insert(
            "beat_op".to_string(),
            serde_json::Value::String(op.to_string()),
        );
        state.rocks.put_record(id, &rec).expect("put_record");
    }

    let v = compute_dag_search(
        state.clone(),
        DagSearchQuery {
            op: Some("vanish".into()),
            creator: None,
            to: None,
            from: None,
            since: None,
            until: None,
            limit: None,
            classification: None,
            has_key: None,
        },
    )
    .await
    .expect("op=vanish filter");

    assert_eq!(
        v["count"].as_u64(),
        Some(2),
        "op=vanish MUST match the 2 v-* records (pure string-compare, decoupled from \
             LedgerOp::from_str which would have errored on 'vanish')",
    );
    let ids: Vec<&str> = v["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    for id in &ids {
        assert!(
            id.starts_with("v-"),
            "kindle record leaked through op=vanish filter: {id}",
        );
    }
    // Echo carries the raw filter input.
    assert_eq!(v["filters"]["op"].as_str(), Some("vanish"));

    // Sanity: filtering on a NON-matching op yields zero — the filter
    // IS being applied (rules out a "filter silently ignored" bug).
    let v = compute_dag_search(
        state.clone(),
        DagSearchQuery {
            op: Some("nonexistent-op".into()),
            creator: None,
            to: None,
            from: None,
            since: None,
            until: None,
            limit: None,
            classification: None,
            has_key: None,
        },
    )
    .await
    .expect("op=nonexistent-op filter");
    assert_eq!(
        v["count"].as_u64(),
        Some(0),
        "non-matching op filter MUST yield 0 (the filter is in fact applied)",
    );
}

#[tokio::test]
async fn batch_qqq_compute_dag_search_creator_and_has_key_filters_and_compose_with_filters_echo() {
    // AND-composition: a record passes only if BOTH creator AND
    // has_key match. Insert four records across the 2×2 cross-
    // product (two creators × with/without 'tag' metadata key):
    //
    //   id | creator_pk             | has 'tag'?
    //   ---+------------------------+-----------
    //   A  | [0xAA; 1952]           | yes
    //   B  | [0xAA; 1952]           | no
    //   C  | [0xCC; 1952]           | yes
    //   D  | [0xCC; 1952]           | no
    //
    // Filter creator=hash(0xAA-pk) AND has_key=tag → only A matches.
    // Each of the four records exists on the orthogonal axis pair
    // (creator-match × key-match), so:
    //   - AND-composition (correct) → 1 (A)
    //   - OR-composition regression → 3 (A+B+C — anyone matching
    //     either filter)
    //   - "first filter wins" regression → 2 (A+B by creator OR
    //     A+C by key, depending on order)
    // Distinct error signatures defeat any silent re-wiring.
    use crate::crypto::hash::sha3_256_hex;

    let state = test_state();
    let pk_aa = vec![0xAA; 1952];
    let pk_cc = vec![0xCC; 1952];
    let hash_aa = sha3_256_hex(&pk_aa);

    for (id, pk, has_tag, ts) in [
        ("A", &pk_aa, true, 100.0),
        ("B", &pk_aa, false, 110.0),
        ("C", &pk_cc, true, 120.0),
        ("D", &pk_cc, false, 130.0),
    ] {
        let mut rec = stub_record(id);
        rec.creator_public_key = pk.clone();
        rec.timestamp = ts;
        if has_tag {
            rec.metadata.insert(
                "tag".to_string(),
                serde_json::Value::String("present".into()),
            );
        }
        state.rocks.put_record(id, &rec).expect("put_record");
    }

    let v = compute_dag_search(
        state.clone(),
        DagSearchQuery {
            op: None,
            creator: Some(hash_aa.clone()),
            to: None,
            from: None,
            since: None,
            until: None,
            limit: Some(100),
            classification: None,
            has_key: Some("tag".into()),
        },
    )
    .await
    .expect("creator+has_key composite filter");

    assert_eq!(
        v["count"].as_u64(),
        Some(1),
        "creator=hash(0xAA) AND has_key=tag MUST yield exactly 1 (record A); \
             OR-composition would yield 3 (A+B by creator OR A+C by tag); \
             first-filter-wins regression would yield 2",
    );
    assert_eq!(
        v["results"][0]["id"].as_str(),
        Some("A"),
        "the surviving record MUST be A (creator=0xAA × has tag)",
    );

    // creator_hash on the surfaced entry MUST equal the filter input —
    // pin the entry-level creator_hash field which accounts diff to
    // detect cross-creator contamination.
    assert_eq!(
        v["results"][0]["creator_hash"].as_str(),
        Some(hash_aa.as_str()),
    );

    // Filters echo carries BOTH inputs verbatim. Pin the full echo
    // shape to catch any future refactor that drops a filter key
    // from the JSON.
    let filters = v["filters"].as_object().expect("filters object");
    assert_eq!(filters["creator"].as_str(), Some(hash_aa.as_str()));
    assert_eq!(filters["has_key"].as_str(), Some("tag"));
    assert!(filters["op"].is_null());
    assert!(filters["to"].is_null());
    assert!(filters["from"].is_null());
    assert!(filters["since"].is_null());
    assert!(filters["until"].is_null());
    assert!(filters["classification"].is_null());
    assert_eq!(
        v["limit"].as_u64(),
        Some(100),
        "limit echo is 100 (sub-clamp); the pre-clamp value passed through",
    );
}

// ─── compute_xzone_transfer (explorer.rs:2661) ─────────────
//
// Cross-zone subsystem triplet completion
// (stats + transfers-list + transfer-detail). Previous direct-pin count: ZERO.
// Adjacent indirect
// coverage: the list-path test pins the LIST-path serialize_transfer over the same
// 13-key envelope, but on the ARRAY traversal path; this pins the
// SINGLE-fetch path that exercises ledger.cross_zone.get(&id) lookup
// semantics + the 404-on-miss branch accounts rely on to stop polling.
//
// The /xzone/transfer/{id} wire surface is a strict 13-key envelope
// (serialize_transfer at explorer.rs:2554-2575):
//   transfer_id: String   — caller-supplied id, echoed verbatim
//   sender: String        — identity hash, echoed verbatim
//   recipient: String     — identity hash, echoed verbatim
//   amount: u64           — base units
//   source_zone: String   — ZoneId.to_string()
//   dest_zone: String     — ZoneId.to_string()
//   locked_at: f64        — unix epoch seconds
//   expires_at: f64       — locked_at + CLAIM_TIMEOUT_SECS (24 h)
//   status: String        — lowercase 4-variant {locked|claimed|refunded|aborted}
//   has_proof: bool       — !merkle_proof.is_empty() — accounts gate UI on this
//   lock_record_hash: String        — hex::encode of [u8;32]
//   source_merkle_root: String      — hex::encode of [u8;32]
//   claim_record_id: Option<String> — null until destination zone seals the claim
//
// Five orthogonal axes pinned (one per branch in the helper):
//   (1) Not-found path — empty pending map, lookup by any id returns
//       Err(ElaraError::RecordNotFound) which the route layer maps to
//       HTTP 404. Pins the .ok_or_else branch at explorer.rs:2666-2670.
//       Wallets STOP polling on 404 (vs continue on 409/transient); a
//       silent Ok(null) regression would loop them forever.
//   (2) Strict 13-key envelope on a happy-path single insert — verifies
//       the entire serialize_transfer wire contract surfaces in full
//       with the correct types. Pins explorer.rs:2554-2575 against any
//       key drop or type swap (e.g. amount as String regression).
//   (3) Status enum mapping (4 variants) — Locked/Claimed/Refunded/
//       Aborted → exact lowercase strings. Pins the 4-arm match at
//       explorer.rs:2564-2569 against silent label swap (e.g. "lock"
//       vs "locked" → accounts compare status strings exactly).
//   (4) ID-based selection isolation — three transfers in the pending
//       map, fetch each by id, verify return is exactly that transfer
//       (not a sibling). Pins ledger.cross_zone.get(&id) as a true
//       indexed lookup (NOT a `pending.values().find(|t| t.id == id)`
//       linear-scan regression which would scale O(N) at 1M-pending
//       mainnet target).
//   (5) has_proof boolean + hex encoding round-trip — empty merkle_proof
//       gives has_proof=false; populated proof gives has_proof=true.
//       lock_record_hash + source_merkle_root populated with distinct
//       non-zero bytes round-trip through hex::encode to the expected
//       64-char lowercase hex strings. Pins explorer.rs:2570-2572 —
//       accounts use lock_record_hash to look up the LOCK record and a
//       hex-encoding regression (e.g. base64) would break that fetch.

#[tokio::test]
async fn batch_rrr_compute_xzone_transfer_not_found_returns_record_not_found_error() {
    // Empty pending map. Lookup by ANY id MUST return
    // Err(ElaraError::RecordNotFound) — the 404-path accounts hinge their
    // "stop polling, transfer never existed or was pruned" UX on. A
    // silent Ok(null) or Ok({}) regression would loop accounts forever.
    // Pins the .ok_or_else branch at explorer.rs:2666-2670.
    use crate::errors::ElaraError;

    let state = test_state();
    let result = compute_xzone_transfer(state, "tx-does-not-exist".to_string()).await;

    assert!(
        result.is_err(),
        "lookup on empty pending map MUST return Err — a silent \
             Ok(null) or Ok({{}}) regression would loop accounts forever"
    );
    match result {
        Err(ElaraError::RecordNotFound(msg)) => {
            assert!(
                msg.contains("tx-does-not-exist"),
                "RecordNotFound message MUST contain the transfer_id for \
                     operator debugging; got: {msg:?}"
            );
            assert!(
                msg.starts_with("xzone transfer "),
                "RecordNotFound message MUST start with 'xzone transfer ' \
                     to disambiguate from /records/{{id}} 404s in logs; got: {msg:?}"
            );
        }
        Err(other) => panic!(
            "expected ElaraError::RecordNotFound, got: {other:?} — \
                 a regression to a different error variant would break the \
                 route layer's 404 mapping at error→HTTP translation"
        ),
        Ok(v) => panic!(
            "expected Err on empty pending map, got Ok({v:?}) — silent \
                 success regression"
        ),
    }
}

#[tokio::test]
async fn batch_rrr_compute_xzone_transfer_happy_path_emits_strict_thirteen_key_envelope() {
    // Insert ONE transfer, fetch by exact id. The 13-key envelope MUST
    // surface in full with the correct types. Pins serialize_transfer at
    // explorer.rs:2554-2575 against any key drop or type swap.
    use crate::accounting::cross_zone::TransferStatus;

    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        ledger.cross_zone.pending.insert(
            "tx-happy".into(),
            ppp_stub_pending_transfer("tx-happy", "alice", "bob", TransferStatus::Locked, 1234.5),
        );
    }

    let v = compute_xzone_transfer(state, "tx-happy".to_string())
        .await
        .expect("happy-path fetch by exact id MUST succeed");

    let obj = v
        .as_object()
        .expect("compute_xzone_transfer returns an object");
    assert_eq!(
        obj.len(),
        13,
        "compute_xzone_transfer MUST emit a strict 13-key envelope \
             (transfer_id, sender, recipient, amount, source_zone, dest_zone, \
             locked_at, expires_at, status, has_proof, lock_record_hash, \
             source_merkle_root, claim_record_id); got {} keys: {:?}",
        obj.len(),
        obj.keys().collect::<Vec<_>>(),
    );
    for key in [
        "transfer_id",
        "sender",
        "recipient",
        "amount",
        "source_zone",
        "dest_zone",
        "locked_at",
        "expires_at",
        "status",
        "has_proof",
        "lock_record_hash",
        "source_merkle_root",
        "claim_record_id",
    ] {
        assert!(obj.contains_key(key), "envelope MUST contain key '{key}'");
    }

    // Per-field type + value pins.
    assert_eq!(v["transfer_id"].as_str(), Some("tx-happy"));
    assert_eq!(v["sender"].as_str(), Some("alice"));
    assert_eq!(v["recipient"].as_str(), Some("bob"));
    assert_eq!(
        v["amount"].as_u64(),
        Some(100),
        "amount MUST be a JSON Number (u64), NOT String — accounts parse \
             as u64 unconditionally; a String regression would crash callers",
    );
    assert_eq!(v["source_zone"].as_str(), Some("a"));
    assert_eq!(v["dest_zone"].as_str(), Some("b"));
    assert_eq!(v["locked_at"].as_f64(), Some(1234.5));
    assert_eq!(
        v["expires_at"].as_f64(),
        Some(1234.5 + 86400.0),
        "expires_at MUST equal locked_at + 86400.0 (CLAIM_TIMEOUT_SECS)",
    );
    assert_eq!(v["status"].as_str(), Some("locked"));
    assert_eq!(
        v["has_proof"].as_bool(),
        Some(false),
        "stub merkle_proof is empty → has_proof MUST be false; a true \
             regression would gate account UI on a non-existent proof",
    );
    assert_eq!(
        v["lock_record_hash"].as_str(),
        Some("0000000000000000000000000000000000000000000000000000000000000000"),
        "lock_record_hash MUST be hex::encode of [u8;32] all-zeros",
    );
    assert_eq!(
        v["source_merkle_root"].as_str(),
        Some("0000000000000000000000000000000000000000000000000000000000000000"),
    );
    assert!(
        v["claim_record_id"].is_null(),
        "claim_record_id MUST be JSON null when None (NOT absent, NOT \
             empty-string) — accounts use null-check to gate destination-zone \
             claim-record lookup",
    );
}

#[tokio::test]
async fn batch_rrr_compute_xzone_transfer_status_enum_all_four_variants_emit_lowercase_literals() {
    // Seed four transfers, one per TransferStatus variant. Fetch each
    // by id and verify the lowercase string emitted on the wire matches
    // the variant exactly. Pins the 4-arm match at explorer.rs:2564-2569
    // against any silent label swap (e.g. "lock" vs "locked", or
    // CamelCase serde regression that would break account status compare).
    use crate::accounting::cross_zone::TransferStatus;

    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        ledger.cross_zone.pending.insert(
            "tx-l".into(),
            ppp_stub_pending_transfer("tx-l", "s", "r", TransferStatus::Locked, 1.0),
        );
        ledger.cross_zone.pending.insert(
            "tx-c".into(),
            ppp_stub_pending_transfer("tx-c", "s", "r", TransferStatus::Claimed, 2.0),
        );
        ledger.cross_zone.pending.insert(
            "tx-r".into(),
            ppp_stub_pending_transfer("tx-r", "s", "r", TransferStatus::Refunded, 3.0),
        );
        ledger.cross_zone.pending.insert(
            "tx-a".into(),
            ppp_stub_pending_transfer("tx-a", "s", "r", TransferStatus::Aborted, 4.0),
        );
    }

    for (transfer_id, expected_status) in &[
        ("tx-l", "locked"),
        ("tx-c", "claimed"),
        ("tx-r", "refunded"),
        ("tx-a", "aborted"),
    ] {
        let v = compute_xzone_transfer(state.clone(), (*transfer_id).to_string())
            .await
            .unwrap_or_else(|e| panic!("transfer_id={transfer_id} MUST be findable: {e:?}"));
        assert_eq!(
            v["status"].as_str(),
            Some(*expected_status),
            "transfer_id={transfer_id} MUST serialize status as \
                 '{expected_status}' (exact lowercase, NOT 'Locked', \
                 NOT 'LOCKED', NOT 'lock')",
        );
        assert_eq!(
            v["transfer_id"].as_str(),
            Some(*transfer_id),
            "transfer_id field MUST echo the id we fetched — proves \
                 the helper returned THIS transfer, not a sibling",
        );
    }
}

#[tokio::test]
async fn batch_rrr_compute_xzone_transfer_id_based_selection_returns_isolated_match_from_multi_entry_map(
) {
    // Three distinct transfers in the pending map. Fetch each by id
    // and assert the returned envelope reflects ONLY that transfer's
    // fields (sender/recipient/amount/locked_at — all distinct per
    // entry). Pins ledger.cross_zone.get(&id) as a true HashMap-indexed
    // lookup against any regression to a linear `pending.values().find()`
    // (which would scale O(N) at 1M-pending mainnet) or worse — a
    // first-entry-wins HashMap iteration regression that would silently
    // return the wrong transfer.
    use crate::accounting::cross_zone::TransferStatus;

    let state = test_state();
    // Distinct (sender, recipient, locked_at) per id so an
    // index-mismatch regression would surface in multiple fields.
    let seed = [
        ("tx-alpha", "alice", "x", TransferStatus::Locked, 100.0_f64),
        ("tx-beta", "bob", "y", TransferStatus::Claimed, 200.0),
        ("tx-gamma", "carol", "z", TransferStatus::Refunded, 300.0),
    ];
    {
        let mut ledger = state.ledger.write().await;
        for (id, sender, recipient, status, locked_at) in &seed {
            ledger.cross_zone.pending.insert(
                (*id).into(),
                ppp_stub_pending_transfer(id, sender, recipient, status.clone(), *locked_at),
            );
        }
    }

    for (id, expected_sender, expected_recipient, expected_status, expected_locked_at) in &seed {
        let v = compute_xzone_transfer(state.clone(), (*id).to_string())
            .await
            .unwrap_or_else(|e| panic!("id={id} MUST be findable in 3-entry map: {e:?}"));
        assert_eq!(
            v["transfer_id"].as_str(),
            Some(*id),
            "lookup by id={id} MUST return the transfer with that id, \
                 NOT a sibling — pins HashMap-indexed get() at \
                 cross_zone.rs:833 against linear-scan or wrong-entry regression",
        );
        assert_eq!(v["sender"].as_str(), Some(*expected_sender));
        assert_eq!(v["recipient"].as_str(), Some(*expected_recipient));
        assert_eq!(
            v["status"].as_str(),
            Some(match expected_status {
                TransferStatus::Locked => "locked",
                TransferStatus::Claimed => "claimed",
                TransferStatus::Refunded => "refunded",
                TransferStatus::Aborted => "aborted",
            }),
        );
        assert_eq!(v["locked_at"].as_f64(), Some(*expected_locked_at));
    }

    // Non-existent id on a populated map MUST still return RecordNotFound
    // (NOT a stale-cache regression that surfaces a previously-fetched
    // transfer for an unknown id).
    let result = compute_xzone_transfer(state, "tx-not-in-map".to_string()).await;
    assert!(
        result.is_err(),
        "unknown id on populated map MUST return Err — a silent \
             stale-cache surface of a previously-fetched transfer would \
             corrupt account polling"
    );
}

#[tokio::test]
async fn batch_rrr_compute_xzone_transfer_has_proof_toggle_and_hex_encoding_round_trip() {
    // Two-axis test in one body:
    //   (a) has_proof: bool — derived from !merkle_proof.is_empty(). An
    //       empty proof MUST emit false; a populated proof MUST emit true.
    //       Pins the boolean derivation at explorer.rs:2570.
    //   (b) lock_record_hash + source_merkle_root MUST round-trip
    //       through hex::encode to the expected 64-char lowercase hex
    //       strings. Pins explorer.rs:2571-2572 against any regression
    //       to base64, base58, or raw-byte JSON arrays.
    use crate::accounting::cross_zone::{PendingTransfer, ProofSibling, TransferStatus};

    let state = test_state();

    // Distinct non-zero byte patterns for the two hash fields so a
    // swap regression (e.g. emitting source_merkle_root under
    // lock_record_hash) would surface as wrong hex.
    let lock_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let root_bytes: [u8; 32] = [0xab; 32];

    {
        let mut ledger = state.ledger.write().await;

        // (a-empty) merkle_proof=[] → has_proof MUST be false.
        ledger.cross_zone.pending.insert(
            "tx-empty-proof".into(),
            ppp_stub_pending_transfer("tx-empty-proof", "s", "r", TransferStatus::Locked, 10.0),
        );

        // (a-populated + b) Build a transfer with a non-empty merkle
        // proof and non-zero hash fields. Override the stub's empty/
        // zero defaults.
        let mut populated =
            ppp_stub_pending_transfer("tx-populated", "s", "r", TransferStatus::Claimed, 20.0);
        populated.merkle_proof = vec![
            ProofSibling {
                hash: [0u8; 32],
                is_right: true,
            },
            ProofSibling {
                hash: [1u8; 32],
                is_right: false,
            },
        ];
        populated.lock_record_hash = lock_bytes;
        populated.source_merkle_root = root_bytes;
        populated.claim_record_id = Some("claim-001".to_string());
        // Coerce the type so the override path mirrors the canonical
        // PendingTransfer construction site (insurance against any
        // future field-order refactor in the struct).
        let _coerced: PendingTransfer = populated.clone();
        ledger
            .cross_zone
            .pending
            .insert("tx-populated".into(), populated);
    }

    // (a-empty) has_proof=false on empty merkle_proof.
    let v_empty = compute_xzone_transfer(state.clone(), "tx-empty-proof".to_string())
        .await
        .expect("tx-empty-proof");
    assert_eq!(
        v_empty["has_proof"].as_bool(),
        Some(false),
        "empty merkle_proof MUST emit has_proof=false — accounts gate \
             the destination-zone claim-eligibility UI on this boolean",
    );
    assert!(
        v_empty["claim_record_id"].is_null(),
        "tx-empty-proof claim_record_id MUST be null (stub default)",
    );

    // (a-populated + b) has_proof=true + hex round-trip.
    let v_pop = compute_xzone_transfer(state, "tx-populated".to_string())
        .await
        .expect("tx-populated");
    assert_eq!(
        v_pop["has_proof"].as_bool(),
        Some(true),
        "populated merkle_proof MUST emit has_proof=true — pins the \
             !is_empty() derivation at explorer.rs:2570",
    );

    // Hex round-trip — independent encoding via hex::encode of the same
    // bytes acts as the oracle. Pin the EXACT expected hex string so a
    // base64/base58 regression would diverge visibly.
    let expected_lock_hex = hex::encode(lock_bytes);
    let expected_root_hex = hex::encode(root_bytes);
    assert_eq!(
        v_pop["lock_record_hash"].as_str(),
        Some(expected_lock_hex.as_str()),
        "lock_record_hash MUST be hex::encode of the [u8;32] field; \
             a base64/base58 regression would emit '{expected_lock_hex}' \
             differently",
    );
    assert_eq!(
        v_pop["source_merkle_root"].as_str(),
        Some(expected_root_hex.as_str()),
    );
    // Cross-pin: the two hex strings MUST differ (lock_bytes vs
    // root_bytes are seeded distinct). A field-swap regression that
    // emits source_merkle_root under lock_record_hash would collapse
    // them to the same value here.
    assert_ne!(
        v_pop["lock_record_hash"].as_str(),
        v_pop["source_merkle_root"].as_str(),
        "lock_record_hash and source_merkle_root MUST emit DIFFERENT \
             hex (seeded distinct) — a field-swap regression collapses them",
    );

    // claim_record_id non-null path — populated transfer carries Some.
    assert_eq!(
        v_pop["claim_record_id"].as_str(),
        Some("claim-001"),
        "claim_record_id MUST serialize Some(String) as a JSON String \
             (NOT as {{\"Some\": \"…\"}} — that would be a serde-derive \
             regression on the Option wrapper)",
    );
}

// ─── compute_xzone_bundle (explorer.rs:2698) ──────────────────
//
// Closes the cross-zone QUARTET (stats + transfers-list +
// transfer-detail + bundle) — the four read-side surfaces a account
// or destination-zone verifier needs to (a) discover, (b) inspect, and (c)
// re-verify a pending xzone transfer end-to-end. This slice pins the bundle path
// (`/xzone/bundle/{transfer_id}` per `xzone_bundle` at explorer.rs:2718)
// which assembles a self-contained `XZoneTransferBundle` and serializes
// it for the wire.
//
// Three branches to lock:
//   (1) ledger.cross_zone.get(&id) returns None → RecordNotFound
//       (explorer.rs:2707 `.ok_or_else`).
//   (2) PendingTransfer present but pre-seal/pre-finality
//       (`merkle_proof.is_empty() || source_committee_size == 0`) →
//       Wire error "not yet sealed-and-finalized" surfaced via
//       XZoneTransferBundle::from_pending → None (cross_zone.rs:1344).
//   (3) Fully Phase-2c-populated PendingTransfer → 13-field bundle
//       JSON envelope (explorer.rs:2715 serde_json::to_value).

/// Build a fully-populated PendingTransfer that XZoneTransferBundle::from_pending
/// will accept — i.e. `!merkle_proof.is_empty() && source_committee_size > 0`.
fn sss_seeded_pending_transfer(transfer_id: &str) -> crate::accounting::cross_zone::PendingTransfer {
    use crate::accounting::cross_zone::{
        PendingTransfer, ProofSibling, SealFinalityWitness, TransferStatus,
    };
    PendingTransfer {
        transfer_id: transfer_id.into(),
        sender: "alice".into(),
        recipient: "bob".into(),
        amount: 4242,
        source_zone: crate::ZoneId::new("src-zone"),
        dest_zone: crate::ZoneId::new("dst-zone"),
        locked_at: 1234.5,
        expires_at: 1234.5 + 86400.0,
        status: TransferStatus::Locked,
        merkle_proof: vec![
            ProofSibling {
                hash: [0x11; 32],
                is_right: false,
            },
            ProofSibling {
                hash: [0x22; 32],
                is_right: true,
            },
        ],
        lock_record_hash: [0xaa; 32],
        source_merkle_root: [0xbb; 32],
        source_seal_signers: vec![SealFinalityWitness {
            witness_pk: vec![0xcc; 1952],
            signature: vec![0xdd; 3293],
            committee_proof: vec![ProofSibling {
                hash: [0xee; 32],
                is_right: false,
            }],
        }],
        source_committee_hash: [0xff; 32],
        source_seal_epoch: 7,
        source_committee_size: 5,
        dest_finality_committee: None,
        claim_record_id: None,
    }
}

#[tokio::test]
async fn batch_sss_compute_xzone_bundle_not_found_returns_record_not_found_error() {
    // Empty pending map. Lookup by ANY id MUST return
    // Err(ElaraError::RecordNotFound) with the same prefix shape as
    // compute_xzone_transfer. Wallets/SDKs reuse the
    // same 404→stop-polling UX across `/xzone/transfer/{id}` and
    // `/xzone/bundle/{id}`; a silent Ok regression here would loop
    // verifier code forever waiting for a bundle that never existed.
    // Pins explorer.rs:2707 `.ok_or_else`.
    use crate::errors::ElaraError;

    let state = test_state();
    let result = compute_xzone_bundle(state, "tx-does-not-exist".to_string()).await;

    assert!(
        result.is_err(),
        "lookup on empty pending map MUST return Err — silent Ok would \
             loop verifier code forever"
    );
    match result {
        Err(ElaraError::RecordNotFound(msg)) => {
            assert!(
                msg.contains("tx-does-not-exist"),
                "RecordNotFound message MUST contain the transfer_id for \
                     operator debugging; got: {msg:?}"
            );
            assert!(
                msg.starts_with("xzone transfer "),
                "RecordNotFound message MUST start with 'xzone transfer ' \
                     to disambiguate from /records/{{id}} 404s in logs; got: {msg:?}"
            );
        }
        Err(other) => panic!(
            "expected ElaraError::RecordNotFound, got: {other:?} — a \
                 regression to Wire / different variant would break the route \
                 layer's 404 HTTP mapping"
        ),
        Ok(v) => panic!(
            "expected Err on empty pending map, got Ok({v:?}) — silent \
                 success regression"
        ),
    }
}

#[tokio::test]
async fn batch_sss_compute_xzone_bundle_empty_merkle_proof_returns_wire_error_not_yet_sealed() {
    // Insert a freshly-locked transfer (default stub leaves merkle_proof
    // empty and source_committee_size == 0 — the canonical pre-seal
    // state right after `lock_transfer`). XZoneTransferBundle::from_pending
    // MUST return None and compute_xzone_bundle MUST surface that as
    // Wire("not yet sealed-and-finalized — retry after next epoch boundary").
    //
    // This is the distinguished failure mode accounts use to decide
    // "back off and retry" vs "404, give up" — a silent fallthrough to
    // RecordNotFound here would conflate the two and stall settlement.
    // Pins cross_zone.rs:1344 `merkle_proof.is_empty()` branch +
    // explorer.rs:2710-2714 ElaraError::Wire message wrapping.
    use crate::errors::ElaraError;
    use crate::accounting::cross_zone::TransferStatus;

    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        ledger.cross_zone.pending.insert(
            "tx-pre-seal".into(),
            ppp_stub_pending_transfer("tx-pre-seal", "alice", "bob", TransferStatus::Locked, 100.0),
        );
    }

    let result = compute_xzone_bundle(state, "tx-pre-seal".to_string()).await;
    match result {
        Err(ElaraError::Wire(msg)) => {
            assert!(
                msg.contains("tx-pre-seal"),
                "Wire message MUST contain the transfer_id; got: {msg:?}"
            );
            assert!(
                msg.contains("not yet sealed-and-finalized"),
                "Wire message MUST carry the canonical 'not yet sealed-and-\
                     finalized' phrase — accounts parse-match on this to gate \
                     retry-vs-give-up UX; got: {msg:?}"
            );
            assert!(
                msg.contains("retry after next epoch boundary"),
                "Wire message MUST include the retry hint so operators \
                     debugging via logs see the account-facing remediation; \
                     got: {msg:?}"
            );
        }
        Err(other) => panic!(
            "expected ElaraError::Wire (not-yet-sealed), got: {other:?} \
                 — RecordNotFound regression here would conflate 'retry later' \
                 with '404 give up'"
        ),
        Ok(v) => panic!(
            "expected Err on pre-seal transfer, got Ok({v:?}) — silent \
                 success would emit a half-built bundle that fails .verify() \
                 in the destination zone"
        ),
    }
}

#[tokio::test]
async fn batch_sss_compute_xzone_bundle_zero_committee_size_returns_wire_error_even_with_populated_proof(
) {
    // The OTHER pre-finality path: merkle_proof IS populated (set_proof
    // ran) but source_committee_size is still 0 (set_finality_witnesses
    // hasn't run yet — the gap window between epoch seal and committee
    // attestation). XZoneTransferBundle::from_pending checks BOTH
    // conditions and MUST refuse — a half-built bundle with no committee
    // would fail verify_finality_quorum on the destination side.
    // Pins the SECOND clause of cross_zone.rs:1344
    // `pt.source_committee_size == 0`.
    use crate::errors::ElaraError;
    use crate::accounting::cross_zone::{PendingTransfer, ProofSibling, TransferStatus};

    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        let mut t: PendingTransfer = ppp_stub_pending_transfer(
            "tx-half-built",
            "alice",
            "bob",
            TransferStatus::Locked,
            200.0,
        );
        // set_proof ran — merkle_proof non-empty, lock_record_hash +
        // source_merkle_root populated.
        t.merkle_proof = vec![ProofSibling {
            hash: [0x33; 32],
            is_right: true,
        }];
        t.lock_record_hash = [0x44; 32];
        t.source_merkle_root = [0x55; 32];
        // set_finality_witnesses did NOT run — source_committee_size still 0.
        assert_eq!(t.source_committee_size, 0, "test precondition");
        ledger.cross_zone.pending.insert("tx-half-built".into(), t);
    }

    let result = compute_xzone_bundle(state, "tx-half-built".to_string()).await;
    match result {
        Err(ElaraError::Wire(msg)) => {
            assert!(
                msg.contains("tx-half-built") && msg.contains("not yet sealed-and-finalized"),
                "Wire message MUST flag 'not yet sealed-and-finalized' \
                     even when merkle_proof is populated — committee_size==0 \
                     half-built bundles MUST be refused; got: {msg:?}"
            );
        }
        Err(other) => panic!("expected ElaraError::Wire on committee_size==0, got: {other:?}"),
        Ok(v) => panic!(
            "expected Err on committee_size==0, got Ok({v:?}) — emitting \
                 a half-built bundle would fail verify_finality_quorum at the \
                 destination, blocking a real claim"
        ),
    }
}

#[tokio::test]
async fn batch_sss_compute_xzone_bundle_happy_path_serializes_all_thirteen_bundle_fields() {
    // Fully Phase-2c-populated PendingTransfer (merkle_proof non-empty
    // AND source_committee_size > 0) → XZoneTransferBundle::from_pending
    // returns Some → the wire JSON MUST carry all 13 fields with the
    // correct types. A key drop or rename here would silently break
    // destination-zone verifiers whose XZoneTransferBundle::deserialize
    // demands the full set. Pins the bundle envelope at cross_zone.rs:1307
    // + the serde_json::to_value pipeline at explorer.rs:2715.

    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        ledger
            .cross_zone
            .pending
            .insert("tx-good".into(), sss_seeded_pending_transfer("tx-good"));
    }

    let v = compute_xzone_bundle(state, "tx-good".to_string())
        .await
        .expect("fully-seeded transfer MUST yield a bundle");

    let obj = v
        .as_object()
        .expect("compute_xzone_bundle MUST return a JSON Object");
    for key in [
        "transfer_id",
        "sender",
        "recipient",
        "amount",
        "source_zone",
        "dest_zone",
        "lock_record_hash",
        "merkle_proof",
        "source_merkle_root",
        "source_seal_epoch",
        "source_committee_hash",
        "source_committee_size",
        "source_seal_signers",
    ] {
        assert!(
            obj.contains_key(key),
            "bundle MUST contain key '{key}' — a deserializer on the \
                 destination side rejects bundles missing any of the 13 \
                 finality-proof fields"
        );
    }
    assert_eq!(
        obj.len(),
        13,
        "bundle MUST be EXACTLY 13 keys (no leak of stub fields like \
             locked_at/expires_at/status/claim_record_id — those live on \
             PendingTransfer, NOT the wire bundle); got {} keys: {:?}",
        obj.len(),
        obj.keys().collect::<Vec<_>>(),
    );

    // Type + value pins.
    assert_eq!(v["transfer_id"].as_str(), Some("tx-good"));
    assert_eq!(v["sender"].as_str(), Some("alice"));
    assert_eq!(v["recipient"].as_str(), Some("bob"));
    assert_eq!(
        v["amount"].as_u64(),
        Some(4242),
        "amount MUST be a JSON Number (u64), NOT String — accounts parse \
             unconditionally as u64",
    );
    assert_eq!(
        v["source_zone"].as_str(),
        Some("src-zone"),
        "source_zone MUST be a JSON String (ZoneId Serialize) — a regression \
             to Object/Array would break light-client bundle ingestion",
    );
    assert_eq!(v["dest_zone"].as_str(), Some("dst-zone"));
    assert_eq!(
        v["source_seal_epoch"].as_u64(),
        Some(7),
        "source_seal_epoch MUST be u64 — replay-protection pins it in \
             the signed bytes",
    );
    assert_eq!(
        v["source_committee_size"].as_u64(),
        Some(5),
        "source_committee_size MUST be u64 in JSON (Rust u32 → JSON \
             Number) and MUST be non-zero (gate condition for from_pending)",
    );
    // merkle_proof + source_seal_signers MUST be JSON Arrays (NOT null).
    let proof_arr = v["merkle_proof"]
        .as_array()
        .expect("merkle_proof MUST be a JSON Array (Vec<ProofSibling>)");
    assert_eq!(
        proof_arr.len(),
        2,
        "merkle_proof MUST carry both seeded ProofSiblings — a Vec drop \
             regression would silently halve the inclusion proof"
    );
    let signers_arr = v["source_seal_signers"]
        .as_array()
        .expect("source_seal_signers MUST be a JSON Array (Vec<SealFinalityWitness>)");
    assert_eq!(
        signers_arr.len(),
        1,
        "source_seal_signers MUST carry the seeded witness"
    );
    // The hash fields ([u8; 32]) serialize as JSON Arrays of 32 numbers
    // by default-serde — cross_zone.rs has NO custom hex codec on the
    // bundle wire form (unlike serialize_transfer at explorer.rs:2571).
    // Pin BOTH the length and a discriminating element so a hex-string
    // regression on either side would surface visibly.
    let lock_hash_arr = v["lock_record_hash"].as_array().expect(
        "lock_record_hash MUST be a JSON Array of u8 (default serde \
                     on [u8;32]) — NOT a hex string (that's serialize_transfer)",
    );
    assert_eq!(lock_hash_arr.len(), 32, "lock_record_hash MUST be 32 bytes");
    assert_eq!(
        lock_hash_arr[0].as_u64(),
        Some(0xaa),
        "lock_record_hash bytes MUST round-trip 0xaa pattern"
    );
    let root_arr = v["source_merkle_root"]
        .as_array()
        .expect("source_merkle_root MUST be a JSON Array of u8");
    assert_eq!(root_arr.len(), 32);
    assert_eq!(root_arr[0].as_u64(), Some(0xbb));
    let committee_arr = v["source_committee_hash"]
        .as_array()
        .expect("source_committee_hash MUST be a JSON Array of u8");
    assert_eq!(committee_arr.len(), 32);
    assert_eq!(committee_arr[0].as_u64(), Some(0xff));
}

#[tokio::test]
async fn batch_sss_compute_xzone_bundle_id_based_selection_returns_isolated_match_from_multi_entry_map(
) {
    // Three distinct transfers in the pending map — only ONE fully
    // sealed-and-finalized, one half-built, one fresh. Each fetch MUST
    // return EXACTLY that transfer's state, not a sibling. Pins the
    // ledger.cross_zone.get(&id) HashMap-indexed lookup at
    // cross_zone.rs:833 against any first-entry-wins iteration regression
    // (which would silently return wrong data for two of three callers).
    use crate::errors::ElaraError;
    use crate::accounting::cross_zone::TransferStatus;

    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        // (good) Fully seeded — bundle MUST succeed.
        ledger
            .cross_zone
            .pending
            .insert("tx-good".into(), sss_seeded_pending_transfer("tx-good"));
        // (fresh) Empty merkle_proof — bundle MUST surface Wire error.
        ledger.cross_zone.pending.insert(
            "tx-fresh".into(),
            ppp_stub_pending_transfer("tx-fresh", "carol", "dan", TransferStatus::Locked, 500.0),
        );
        // (orphan) A second seeded transfer with different field values
        // — if get() returned the wrong entry by id, the bundle's
        // sender/amount would visibly mismatch what we asked for.
        let mut other = sss_seeded_pending_transfer("tx-other");
        other.sender = "eve".into();
        other.recipient = "frank".into();
        other.amount = 9999;
        other.source_zone = crate::ZoneId::new("other-src");
        other.dest_zone = crate::ZoneId::new("other-dst");
        ledger.cross_zone.pending.insert("tx-other".into(), other);
    }

    // (good) → bundle for tx-good with sender=alice, amount=4242.
    let v_good = compute_xzone_bundle(state.clone(), "tx-good".to_string())
        .await
        .expect("tx-good MUST yield a bundle");
    assert_eq!(v_good["transfer_id"].as_str(), Some("tx-good"));
    assert_eq!(v_good["sender"].as_str(), Some("alice"));
    assert_eq!(v_good["amount"].as_u64(), Some(4242));

    // (other) → bundle for tx-other with sender=eve, amount=9999, distinct zone.
    // This is the cross-pin: the SAME helper that returned tx-good's
    // data MUST return tx-other's distinct data — proving get() is
    // index-keyed, not iterator-position-keyed.
    let v_other = compute_xzone_bundle(state.clone(), "tx-other".to_string())
        .await
        .expect("tx-other MUST yield a bundle");
    assert_eq!(v_other["transfer_id"].as_str(), Some("tx-other"));
    assert_eq!(v_other["sender"].as_str(), Some("eve"));
    assert_eq!(v_other["amount"].as_u64(), Some(9999));
    assert_eq!(v_other["source_zone"].as_str(), Some("other-src"));

    // (fresh) → Wire error (NOT a stale-cache surface of tx-good or tx-other).
    let r_fresh = compute_xzone_bundle(state.clone(), "tx-fresh".to_string()).await;
    match r_fresh {
        Err(ElaraError::Wire(msg)) => {
            assert!(
                msg.contains("tx-fresh"),
                "Wire error MUST name the requested id (tx-fresh), proving \
                     get() found THIS entry and not a sibling; got: {msg:?}"
            );
        }
        other => panic!(
            "expected Wire error on fresh transfer, got: {other:?} — a \
                 stale-cache regression here would return tx-good or \
                 tx-other's bundle"
        ),
    }

    // Unknown id on a populated map MUST still return RecordNotFound.
    let r_missing = compute_xzone_bundle(state, "tx-not-in-map".to_string()).await;
    assert!(matches!(r_missing, Err(ElaraError::RecordNotFound(_))));
}

// ─── `compute_routing_resolve` tests ──
// Prior coverage on `compute_routing_resolve` (explorer.rs:1807) was just
// two error-branch tests (`batch_n_*` for guard-before-meter ordering and
// `batch_ah_*` for None/empty/invalid-hex). The HAPPY-path branches plus
// four orthogonal contract details were unpinned. This batch closes that
// gap with five pins, each isolating a distinct invariant a refactor could
// silently break:
//
//   (1) `key_hex=None` path defaults to `[0u8; 32]` and emits a 64-char
//       all-zeros routing_key hex. Pins the documented "default key is
//       all-zeros" contract at explorer.rs:1842 — a regression that
//       changed the sentinel to random bytes would silently re-route
//       every keyless request to a different leaf under multi-zone splits.
//   (2) Wrong-byte-length `key_hex` (valid hex, wrong byte count) → the
//       documented "key must decode to 32 bytes, got N" error with the
//       ACTUAL byte count echoed. Pins explorer.rs:1831-1837 and the
//       distinction from the "invalid hex" branch (different error text,
//       different debugging path for operators).
//   (3) Happy path on fresh state — six-key top-level envelope with a
//       two-key `registry` sub-object. Pins the wire shape accounts parse
//       (record_id / routing_key / naive_zone / resolved_zone / redirected
//       / registry.{active_count, highest_effective_epoch}). A future
//       "let's add a hop_count field" PR would lift the key count and
//       surface here.
//   (4) Counter-bump ordering on the happy path: the queries counter
//       increments EXACTLY ONCE per successful call (sits AFTER the
//       guards at explorer.rs:1845-1847), and the redirected counter
//       stays at 0 on fresh state (no rewrites possible with empty
//       registry). Complements batch_n which pinned NO bump on guard
//       failure; this pin completes the meter-once-per-success contract.
//   (5) `routing_key` echo preserves the input hex string verbatim — the
//       helper stores `hex_str` (the user's input) rather than
//       `hex::encode(decoded)`. Uppercase input round-trips uppercase.
//       A regression that switched to re-encoding would silently
//       lowercase account-side echo comparisons.

#[test]
fn batch_ttt_compute_routing_resolve_no_key_defaults_to_all_zeros_with_64_char_hex() {
    // `key_hex=None` → routing_key = [0u8; 32], routing_key_hex = "0"*64.
    // Pins the default-key sentinel at explorer.rs:1842. A regression
    // that changed `[0u8; 32]` to e.g. `[0xFF; 32]` would silently route
    // every keyless request through a different leaf and break alignment
    // with `routing_key_for_record(record_id)` (the documented "use the
    // record hash as default key" contract). The 64-char width also
    // catches a regression that switched `hex::encode([0u8; 32])` to
    // `hex::encode([0u8; 16])` or `format!("{:x}", 0)` (which would
    // produce a single "0").
    let state = test_state();
    let v = compute_routing_resolve(&state, Some("rec-default-key".into()), None);
    let routing_key_hex = v
        .get("routing_key")
        .and_then(|x| x.as_str())
        .expect("happy path with None key must produce a routing_key string field");
    assert_eq!(
        routing_key_hex.len(),
        64,
        "default routing_key hex MUST be 64 chars (32 bytes); got len={}",
        routing_key_hex.len(),
    );
    assert!(
        routing_key_hex.chars().all(|c| c == '0'),
        "default routing_key hex MUST be all zeros; got '{routing_key_hex}'",
    );
}

#[test]
fn batch_ttt_compute_routing_resolve_wrong_byte_length_emits_documented_byte_count_error() {
    // Valid hex but decoded length != 32 → in-band JSON error envelope
    // at explorer.rs:1831-1837 with the ACTUAL byte count echoed.
    // Pins both (a) the distinction from the invalid-hex branch
    // (different error text — "key must decode to 32 bytes, got N"
    // vs "invalid hex for key: ..."), and (b) the byte-count echo so
    // operators debugging "wrong key length" requests can see N at a
    // glance instead of having to count hex chars.
    let state = test_state();

    // 16-byte (32-char hex) — short.
    let short = compute_routing_resolve(
        &state,
        Some("rec-short-key".into()),
        Some("00112233445566778899aabbccddeeff".into()),
    );
    let short_err = short
        .get("error")
        .and_then(|x| x.as_str())
        .expect("16-byte hex MUST hit the length-mismatch branch with `error` field");
    assert!(
        short_err.contains("key must decode to 32 bytes"),
        "length-mismatch error MUST mention 'key must decode to 32 bytes'; got '{short_err}'",
    );
    assert!(
        short_err.contains("got 16"),
        "length-mismatch error MUST echo the actual byte count (16); got '{short_err}'",
    );

    // 64-byte (128-char hex) — long.
    let long_hex = "00".repeat(64); // 64 bytes encoded as 128 hex chars
    let long = compute_routing_resolve(&state, Some("rec-long-key".into()), Some(long_hex));
    let long_err = long
        .get("error")
        .and_then(|x| x.as_str())
        .expect("64-byte hex MUST hit the length-mismatch branch with `error` field");
    assert!(
        long_err.contains("got 64"),
        "length-mismatch error MUST echo the actual byte count (64); got '{long_err}'",
    );
}

#[test]
fn batch_ttt_compute_routing_resolve_happy_path_six_key_envelope_with_two_key_registry_subobject() {
    // Pins the success-path wire shape: top-level has EXACTLY six keys
    // (record_id, routing_key, naive_zone, resolved_zone, redirected,
    // registry) and `registry` has EXACTLY two keys (active_count,
    // highest_effective_epoch). On a fresh `ZoneRegistry::new()` (which
    // `test_state` produces), naive_zone == resolved_zone and redirected
    // is false because no transition seals have been applied. A future
    // schema-additive change would surface here as a key-count drift.
    let state = test_state();
    let v = compute_routing_resolve(&state, Some("rec-shape-pin".into()), None);

    let top = v
        .as_object()
        .expect("compute_routing_resolve must return a JSON object");
    assert_eq!(
        top.len(),
        6,
        "happy-path envelope MUST have EXACTLY 6 top-level keys; got {} ({:?})",
        top.len(),
        top.keys().collect::<Vec<_>>(),
    );
    for key in [
        "record_id",
        "routing_key",
        "naive_zone",
        "resolved_zone",
        "redirected",
        "registry",
    ] {
        assert!(
            top.contains_key(key),
            "happy-path envelope MUST contain key '{key}'",
        );
    }

    let registry = top
        .get("registry")
        .and_then(|x| x.as_object())
        .expect("registry sub-object MUST be a JSON object");
    assert_eq!(
        registry.len(),
        2,
        "registry sub-object MUST have EXACTLY 2 keys; got {} ({:?})",
        registry.len(),
        registry.keys().collect::<Vec<_>>(),
    );
    assert!(registry.contains_key("active_count"));
    assert!(registry.contains_key("highest_effective_epoch"));

    // On fresh `ZoneRegistry::new()`: `resolve` is identity (no rewrites
    // possible) ⇒ naive == resolved ⇒ redirected = false. Pin the
    // no-rewrite invariant.
    assert_eq!(
        top.get("naive_zone").and_then(|x| x.as_str()),
        top.get("resolved_zone").and_then(|x| x.as_str()),
        "fresh-registry resolve MUST be identity (naive == resolved)",
    );
    assert_eq!(
        top.get("redirected").and_then(|x| x.as_bool()),
        Some(false),
        "fresh-registry resolve MUST set redirected=false",
    );

    // Active_count=0, highest_effective_epoch=0 on a brand new registry.
    assert_eq!(
        registry.get("active_count").and_then(|x| x.as_u64()),
        Some(0),
        "fresh registry has 0 active zones",
    );
    assert_eq!(
        registry
            .get("highest_effective_epoch")
            .and_then(|x| x.as_u64()),
        Some(0),
        "fresh registry has highest_effective_epoch=0",
    );
}

#[test]
fn batch_ttt_compute_routing_resolve_happy_path_bumps_queries_counter_exactly_once_no_redirected_bump(
) {
    // Complements `batch_n_*_no_counter_bump` (which pinned that the
    // guard branch does NOT bump the queries counter). This test pins
    // the dual invariant: a happy-path call bumps the queries counter
    // by EXACTLY ONE, and the redirected counter stays at zero on
    // fresh state (no rewrites possible, so resolution.redirected is
    // always false at explorer.rs:1859 and the redirected counter
    // bump at L1860-1862 never fires). Together the two tests pin
    // the meter-on-success-only ordering.
    let state = test_state();
    let queries_before = state
        .zone_routing_resolve_queries_total
        .load(Ordering::Relaxed);
    let redirected_before = state
        .zone_routing_resolve_redirected_total
        .load(Ordering::Relaxed);

    let _ = compute_routing_resolve(&state, Some("rec-counter-once".into()), None);

    let queries_after = state
        .zone_routing_resolve_queries_total
        .load(Ordering::Relaxed);
    let redirected_after = state
        .zone_routing_resolve_redirected_total
        .load(Ordering::Relaxed);

    assert_eq!(
        queries_after - queries_before,
        1,
        "happy-path MUST bump zone_routing_resolve_queries_total by EXACTLY 1; delta={}",
        queries_after - queries_before,
    );
    assert_eq!(
        redirected_after, redirected_before,
        "fresh-registry resolve has redirected=false; redirected counter MUST NOT bump",
    );

    // Multi-call accumulation: three more calls bump the queries counter
    // by exactly three more, redirected stays put.
    for _ in 0..3 {
        let _ = compute_routing_resolve(&state, Some("rec-counter-once".into()), None);
    }
    assert_eq!(
        state
            .zone_routing_resolve_queries_total
            .load(Ordering::Relaxed)
            - queries_before,
        4,
        "four happy-path calls total MUST bump queries counter by 4",
    );
    assert_eq!(
        state
            .zone_routing_resolve_redirected_total
            .load(Ordering::Relaxed),
        redirected_before,
        "no rewrites possible ⇒ redirected counter stays unchanged across N calls",
    );
}

#[test]
fn batch_ttt_compute_routing_resolve_routing_key_echo_preserves_input_hex_casing() {
    // The helper stores the user's literal `hex_str` (line 1840)
    // rather than re-encoding the decoded bytes via `hex::encode`. So
    // uppercase input echoes uppercase, lowercase echoes lowercase,
    // mixed echoes mixed. A regression that switched to
    // `hex::encode(&bytes)` would silently lowercase everything and
    // break any account-side echo comparison that uses the raw input
    // string (e.g. `assert_eq!(resp.routing_key, my_uppercase_key)`).
    let state = test_state();

    let upper = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
    let lower = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    let mixed = "AaBbCcDdEeFf00112233445566778899aAbBcCdDeEfF00112233445566778899";

    for input in [upper, lower, mixed] {
        let v =
            compute_routing_resolve(&state, Some("rec-case-pin".into()), Some(input.to_string()));
        assert_eq!(
            v.get("routing_key").and_then(|x| x.as_str()),
            Some(input),
            "routing_key echo MUST preserve input casing verbatim; \
                 expected '{input}' got '{:?}'",
            v.get("routing_key"),
        );
    }
}

// ─── compute_activity orthogonal pins ────────────────────────────
//
// Five orthogonal pins on `compute_activity` (explorer.rs:3629). Prior
// coverage at `batch_o_compute_activity_unknown_identity_returns_*`
// exercised only the "unknown identity routes through reputation default
// and populates the envelope" surface — the genesis-branch flip, the
// five-key schema lock, the key_info always-populated shape, the
// ledger balance-and-staked echo with beat arithmetic, and the
// identity-echo case preservation were all unpinned:
//
//   (1) Genesis identity flips both `is_genesis_authority:true` and
//       `found=true` independent of all other subsystems
//       (explorer.rs:3697-3698). Distinct from the reputation-default
//       path — if reputation were ever moved to a lazy-init that doesn't
//       set found=true on first read, the genesis path must still
//       resolve to the populated envelope.
//   (2) Populated envelope carries all five mandatory subsystem keys
//       (trust / ledger / continuity_score / reputation_score / keys)
//       at explorer.rs:3707-3715. Wallets that key into the JSON
//       without optionality guards break if a regression drops a key
//       on `None` rather than emitting JSON null.
//   (3) `keys` sub-object is ALWAYS `Some(json!({key_rotations: N}))`
//       on a fresh identity (rotations=0), NOT `None`. Distinct from
//       `trust_info` / `ledger_info` which short-circuit to `None`
//       when their subsystem has no data. The `key_info` block at
//       explorer.rs:3687-3695 unconditionally emits the JSON regardless
//       of rotation count.
//   (4) Ledger balance>0 flips `found=true` and emits four sub-keys
//       (`balance_micros`, `balance_beat`, `staked_micros`,
//       `staked_beat`) with the documented beat conversion
//       (`BASE_UNITS_PER_BEAT = 1_000_000_000`). A regression that changed
//       the constant or dropped a sub-key would surface here before
//       account UX divergence.
//   (5) The `identity` echo at explorer.rs:3708 is the raw input
//       string — NOT normalized (no lowercase / no truncation). Mixed
//       and uppercase hex identities echo verbatim. Wallets that
//       compare `resp.identity == requested_identity` rely on this.

#[test]
fn batch_uuu_compute_activity_genesis_authority_flips_is_genesis_and_found_independent_of_reputation(
) {
    // The genesis branch at explorer.rs:3697-3698 sets BOTH
    // `is_genesis_authority:true` in the wire envelope AND
    // `found=true` (so the populated envelope is returned, NOT the
    // in-band error branch). This is a separate code path from the
    // reputation-default-flips-found surface pinned in batch_o —
    // a regression that moved reputation to lazy-init (rep.score_at
    // returns 0.0 for unknown until first writes) would NOT mask the
    // genesis path. This test exists so that hardening reputation
    // semantics doesn't silently change the wire shape of /activity
    // for the genesis authority identity.
    let state = test_state();
    let genesis = state.config.genesis_authority.clone();
    let v = compute_activity(&state, &genesis);
    assert!(
        v.get("error").is_none(),
        "genesis identity must NOT hit the in-band error envelope; got {v:?}",
    );
    assert_eq!(
        v.get("is_genesis_authority").and_then(|x| x.as_bool()),
        Some(true),
        "is_genesis_authority MUST be true when identity == config.genesis_authority",
    );
    assert_eq!(
        v.get("identity").and_then(|x| x.as_str()),
        Some(genesis.as_str()),
        "identity echo MUST match the queried genesis identity verbatim",
    );
}

#[test]
fn batch_uuu_compute_activity_populated_envelope_carries_five_mandatory_subsystem_keys() {
    // Schema lock at explorer.rs:3707-3715: any populated envelope
    // (i.e. found=true branch) MUST include all five subsystem keys
    // (`trust`, `ledger`, `continuity_score`, `reputation_score`,
    // `keys`) as top-level fields. The serde_json::json! macro emits
    // every key listed, even when the value is JSON null (from a
    // None/Option). A regression that switched to a conditional
    // builder (only inserting keys when the value is Some) would
    // break accounts that key into `body["trust"]["tier"]` without
    // pre-checking for key presence — they'd hit `KeyError` instead
    // of getting null. The five-key shape is wire contract.
    let state = test_state();
    let unknown = "ffffffff_uuu_envelope_schema_lock";
    let v = compute_activity(&state, unknown);
    let obj = v
        .as_object()
        .expect("populated envelope must be a JSON object");
    for key in [
        "trust",
        "ledger",
        "continuity_score",
        "reputation_score",
        "keys",
    ] {
        assert!(
            obj.contains_key(key),
            "populated envelope MUST carry top-level key '{key}'; full body: {v:?}",
        );
    }
    // Top-level envelope additionally has identity + is_genesis_authority,
    // so the total surface is exactly 7 keys.
    assert!(
        obj.contains_key("identity"),
        "envelope MUST carry top-level 'identity' field",
    );
    assert!(
        obj.contains_key("is_genesis_authority"),
        "envelope MUST carry top-level 'is_genesis_authority' field",
    );
}

#[test]
fn batch_uuu_compute_activity_keys_subobject_always_populated_on_fresh_identity_with_zero_rotations(
) {
    // The `key_info` block at explorer.rs:3687-3695 unconditionally
    // emits `Some(json!({"key_rotations": rotations}))` even when
    // `rotations == 0`. This is structurally DIFFERENT from
    // `trust_info` / `ledger_info` which return None when the
    // subsystem has no data for the identity. A regression that
    // added a `if rotations > 0` short-circuit (to align with the
    // trust/ledger pattern) would emit `keys: null` for every
    // fresh identity — breaking accounts that read
    // `body["keys"]["key_rotations"]` and getting `None / KeyError`
    // instead of `0`. Pin the always-Some shape.
    let state = test_state();
    let fresh = "ffffffff_uuu_fresh_identity_zero_rotations";
    let v = compute_activity(&state, fresh);
    let keys = v
        .get("keys")
        .expect("keys field MUST be present on every populated envelope");
    assert!(
        !keys.is_null(),
        "keys sub-object MUST be a populated JSON object on fresh identity, NOT null; got {keys:?}",
    );
    assert_eq!(
        keys.get("key_rotations").and_then(|x| x.as_u64()),
        Some(0),
        "fresh identity MUST have key_rotations=0 (no rotations registered); got {keys:?}",
    );
}

#[tokio::test]
async fn batch_uuu_compute_activity_ledger_balance_flips_found_and_emits_four_subkeys_with_beat_arithmetic(
) {
    // When ledger.balance(identity) > 0, the `ledger_info` block at
    // explorer.rs:3653-3669 emits a four-key sub-object with the
    // documented beat conversion arithmetic. Pin:
    //   - All four sub-keys present (`balance_micros`, `balance_beat`,
    //     `staked_micros`, `staked_beat`).
    //   - `balance_beat = balance_micros / BASE_UNITS_PER_BEAT` exactly
    //     (using a power-of-ten balance that exercises no FP
    //     precision loss — 3_000_000_000 micros = 3.0 beat).
    //   - `staked_beat = staked_micros / BASE_UNITS_PER_BEAT`.
    //
    // A regression that:
    //   (a) changed `BASE_UNITS_PER_BEAT` from 1_000_000_000 to e.g.
    //       1_000_000 (the literal "micro" interpretation) would
    //       silently shift account displays by 1000x.
    //   (b) dropped any of the four sub-keys (e.g. forgot to echo
    //       `staked_micros` after a refactor) would break delegation
    //       UX in every account that polls /activity.
    let state = test_state();
    let identity = "ffffffff_uuu_ledger_balance_pin".to_string();

    // Seed both balance + staked with non-zero values to exercise
    // all four sub-keys at once. 3_000_000_000 = 3.0 beat exactly,
    // 2_000_000_000 = 2.0 beat exactly — both representable in f64.
    {
        let mut ledger = state.ledger.write().await;
        ledger.accounts.insert(
            identity.clone(),
            crate::accounting::ledger::AccountState {
                available: 3_000_000_000,
                staked: 2_000_000_000,
                ..Default::default()
            },
        );
    }

    let v = compute_activity(&state, &identity);
    assert!(
        v.get("error").is_none(),
        "balance>0 MUST flip found=true and return populated envelope; got {v:?}",
    );
    let ledger_obj = v
        .get("ledger")
        .and_then(|x| x.as_object())
        .expect("ledger sub-object MUST be populated when balance > 0");

    // Four sub-keys all present.
    for key in [
        "balance_micros",
        "balance_beat",
        "staked_micros",
        "staked_beat",
    ] {
        assert!(
            ledger_obj.contains_key(key),
            "ledger sub-object MUST carry '{key}'; full: {ledger_obj:?}",
        );
    }

    // Micros echo verbatim from u64 storage.
    assert_eq!(
        ledger_obj.get("balance_micros").and_then(|x| x.as_u64()),
        Some(3_000_000_000),
        "balance_micros MUST echo ledger.balance() verbatim",
    );
    assert_eq!(
        ledger_obj.get("staked_micros").and_then(|x| x.as_u64()),
        Some(2_000_000_000),
        "staked_micros MUST echo ledger.staked() verbatim",
    );

    // beat conversion: micros / BASE_UNITS_PER_BEAT (= 1_000_000_000).
    // Use exact f64 comparisons since both values are powers of ten
    // representable in IEEE-754 binary64 without rounding.
    assert_eq!(
        ledger_obj.get("balance_beat").and_then(|x| x.as_f64()),
        Some(3.0),
        "balance_beat MUST equal balance_micros / BASE_UNITS_PER_BEAT \
             (3_000_000_000 / 1_000_000_000 = 3.0)",
    );
    assert_eq!(
        ledger_obj.get("staked_beat").and_then(|x| x.as_f64()),
        Some(2.0),
        "staked_beat MUST equal staked_micros / BASE_UNITS_PER_BEAT \
             (2_000_000_000 / 1_000_000_000 = 2.0)",
    );

    // Constant pin: a regression that bumped BASE_UNITS_PER_BEAT by
    // even one zero would surface here as a math mismatch above,
    // but the explicit constant check makes the root cause clear
    // when the test fails.
    assert_eq!(
        crate::accounting::types::BASE_UNITS_PER_BEAT,
        1_000_000_000,
        "BASE_UNITS_PER_BEAT MUST remain 1_000_000_000 (nano-precision \
             despite the historical 'micro' name); a change here breaks \
             every account's beat display by a power-of-ten factor",
    );
}

#[test]
fn batch_uuu_compute_activity_identity_echo_preserves_input_casing_verbatim() {
    // The identity field at explorer.rs:3708 is the raw input,
    // NOT normalized. Mixed-case and uppercase identities echo
    // verbatim. Wallets that compare `resp.identity ==
    // requested_identity` rely on this — a regression that
    // lowercased the input (e.g. for "canonical" identity matching)
    // would silently break that compare even though the underlying
    // subsystem lookups already happen with the raw string. Pin
    // the three casings to cover regression patterns:
    //   - Pure uppercase (e.g. accounts normalizing to UPPER).
    //   - Pure lowercase (the conventional canonical form).
    //   - Mixed-case (catches a regression that called
    //     to_uppercase() / to_lowercase() asymmetrically).
    let state = test_state();
    let inputs = [
        "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        "AaBbCcDdEeFf00112233445566778899aAbBcCdDeEfF00112233445566778899",
    ];
    for input in inputs {
        let v = compute_activity(&state, input);
        assert_eq!(
            v.get("identity").and_then(|x| x.as_str()),
            Some(input),
            "identity echo MUST preserve input casing verbatim; \
                 expected '{input}' got '{:?}'",
            v.get("identity"),
        );
    }
}

// ─── compute_checkpoint_latest orthogonal pins ────
//
// The pure helper at routes/explorer.rs:3241 is the read-side of the
// Gap-3 super-seal wire surface served at GET /checkpoints/latest/{zone}.
// Two callers: (1) `checkpoint_latest` axum adapter at :3271, (2) the
// PQ-transport /checkpoints route. Previously the helper was 100%
// un-pinned despite serving light-client cold-sync paths (PQ account
// bootstrap reads the latest super-seal to anchor its trust chain
// against `record_hash` + `committee_hash`). Five orthogonal axes
// below pin the two-branch envelope (None/no-seal vs Some/found),
// constant-derived `seal_count`, `saturating_sub` underflow safety
// on `start_epoch`, and lowercase-hex encoding contract on both
// 32-byte hash fields.

#[tokio::test]
async fn batch_zzz_compute_checkpoint_latest_no_super_seal_returns_two_key_error_envelope() {
    // Fresh state, no super-seal registered: the None branch must
    // surface a 2-key in-band `{error, zone}` envelope (NOT panic,
    // NOT 404). The helper is "infallible-by-design" at the no-seal
    // boundary per the doc comment at routes/explorer.rs:3236 — both
    // PQ and HTTPS surface the same body byte-for-byte. A regression
    // that bubbled an `ElaraError::NotFound` from the None branch
    // would break the PQ transport's same-body contract.
    let state = test_state();
    let v = compute_checkpoint_latest(state, "alpha/beta".into())
        .await
        .expect("compute_checkpoint_latest must succeed on missing super-seal");
    let obj = v.as_object().expect("top-level must be Object");
    assert_eq!(
        obj.len(),
        2,
        "no-seal branch must emit EXACTLY 2 keys (error, zone); got {} keys",
        obj.len()
    );
    assert_eq!(
        obj.get("error").and_then(|x| x.as_str()),
        Some("no super-seal yet for this zone"),
        "error message MUST be the documented operator-facing literal"
    );
    assert_eq!(
        obj.get("zone").and_then(|x| x.as_str()),
        Some("alpha/beta"),
        "zone field MUST echo the normalized zone path (lowercase, slash-preserved)"
    );
}

#[tokio::test]
async fn batch_zzz_compute_checkpoint_latest_seven_key_envelope_contract() {
    // Some-branch wire envelope MUST carry exactly 7 keys:
    //   {zone, start_epoch, end_epoch, seal_count, record_id,
    //    record_hash, committee_hash}.
    // A silent 6th-key bloat (e.g., adding `produced_at` for ops
    // dashboards) AND a missing key (e.g., dropping `seal_count`
    // after a refactor) both surface here via strict set-equality.
    let state = test_state();
    let zone = crate::ZoneId::new("payments/eu");
    let record_id = "ff".repeat(32);
    let record_hash: [u8; 32] = [0xAB; 32];
    let committee_hash: [u8; 32] = [0xCD; 32];
    {
        let mut epoch = state.epoch.write_recover();
        epoch.latest_super_seal.insert(
            zone.clone(),
            (1024, record_id.clone(), record_hash, committee_hash),
        );
    }
    let v = compute_checkpoint_latest(state.clone(), zone.to_string())
        .await
        .expect("compute ok");
    let obj = v.as_object().expect("top-level must be Object");
    let got: std::collections::BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
    let want: std::collections::BTreeSet<&str> = [
        "zone",
        "start_epoch",
        "end_epoch",
        "seal_count",
        "record_id",
        "record_hash",
        "committee_hash",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        got, want,
        "Some-branch top-level key set MUST match exactly (no addition, no removal)"
    );
    // Sanity pin: record_id echoes the inserted value verbatim (no
    // re-hash, no canonicalization).
    assert_eq!(
        obj.get("record_id").and_then(|x| x.as_str()),
        Some(record_id.as_str()),
        "record_id MUST echo the inserted value verbatim"
    );
}

#[tokio::test]
async fn batch_zzz_compute_checkpoint_latest_seal_count_pins_super_seal_interval_constant() {
    // `seal_count` is sourced from `SUPER_SEAL_INTERVAL = 64`
    // (epoch.rs:159) — NOT from runtime config, NOT from a per-zone
    // seal count, NOT from the populated buffer length. A regression
    // that wired this to a config field (e.g., `super_seal_interval`)
    // or to `epoch.seal_buffer.len()` would surface here. Pin both
    // (a) value equals the constant symbolic reference, AND (b) the
    // literal 64 — a const bump from 64 → 128 surfaces here as a
    // deliberate prompt to update the test, never as silent drift.
    let state = test_state();
    let zone = crate::ZoneId::new("zone-a");
    {
        let mut epoch = state.epoch.write_recover();
        epoch
            .latest_super_seal
            .insert(zone.clone(), (100, "x".repeat(64), [0u8; 32], [0u8; 32]));
    }
    let v = compute_checkpoint_latest(state, zone.to_string())
        .await
        .expect("compute ok");
    assert_eq!(
        v.get("seal_count").and_then(|x| x.as_u64()),
        Some(crate::network::epoch::SUPER_SEAL_INTERVAL),
        "seal_count MUST equal SUPER_SEAL_INTERVAL constant (symbolic pin)"
    );
    assert_eq!(
            v.get("seal_count").and_then(|x| x.as_u64()),
            Some(64u64),
            "literal pin: SUPER_SEAL_INTERVAL is currently 64 — a bump surfaces here as a deliberate prompt to update this test"
        );
}

#[tokio::test]
async fn batch_zzz_compute_checkpoint_latest_start_epoch_uses_saturating_sub_no_underflow() {
    // `start_epoch = end_epoch.saturating_sub(SUPER_SEAL_INTERVAL - 1)`
    // at routes/explorer.rs:3252 floors at 0 for any end_epoch <
    // SUPER_SEAL_INTERVAL. Pin (a) small end_epoch (5) → start = 0,
    // (b) zero end_epoch → start = 0 (boundary), (c) large end_epoch
    // (1024) → start = 1024 - 63 = 961 (off-by-one pin against the
    // SUPER_SEAL_INTERVAL vs SUPER_SEAL_INTERVAL-1 confusion).
    //
    // Regression caught: a refactor to plain `end_epoch -
    // (SUPER_SEAL_INTERVAL - 1)` would panic in debug mode and
    // wrap to ~u64::MAX in release mode for small end_epoch — tanking
    // light-client cold-sync at fresh-fleet boot (epoch < 64 is the
    // first ~2h of a new chain).
    let state = test_state();
    let zone_small = crate::ZoneId::new("zone-small");
    let zone_zero = crate::ZoneId::new("zone-zero");
    let zone_big = crate::ZoneId::new("zone-big");
    {
        let mut epoch = state.epoch.write_recover();
        epoch.latest_super_seal.insert(
            zone_small.clone(),
            (5, "a".repeat(64), [0u8; 32], [0u8; 32]),
        );
        epoch
            .latest_super_seal
            .insert(zone_zero.clone(), (0, "b".repeat(64), [0u8; 32], [0u8; 32]));
        epoch.latest_super_seal.insert(
            zone_big.clone(),
            (1024, "c".repeat(64), [0u8; 32], [0u8; 32]),
        );
    }
    let v_small = compute_checkpoint_latest(state.clone(), zone_small.to_string())
        .await
        .expect("ok");
    assert_eq!(
        v_small.get("start_epoch").and_then(|x| x.as_u64()),
        Some(0u64),
        "end=5 → saturating_sub MUST floor at 0 (no debug-panic, no release-wrap)"
    );
    assert_eq!(
        v_small.get("end_epoch").and_then(|x| x.as_u64()),
        Some(5u64),
        "end_epoch echoes the inserted value verbatim"
    );

    let v_zero = compute_checkpoint_latest(state.clone(), zone_zero.to_string())
        .await
        .expect("ok");
    assert_eq!(
        v_zero.get("start_epoch").and_then(|x| x.as_u64()),
        Some(0u64),
        "end=0 (boundary) → start=0 (no underflow)"
    );
    assert_eq!(v_zero.get("end_epoch").and_then(|x| x.as_u64()), Some(0u64));

    let v_big = compute_checkpoint_latest(state, zone_big.to_string())
        .await
        .expect("ok");
    assert_eq!(
            v_big.get("start_epoch").and_then(|x| x.as_u64()),
            Some(961u64),
            "end=1024 → start = 1024 - 63 = 961 (off-by-one pin: SUPER_SEAL_INTERVAL-1, NOT SUPER_SEAL_INTERVAL)"
        );
    assert_eq!(
        v_big.get("end_epoch").and_then(|x| x.as_u64()),
        Some(1024u64)
    );
}

#[tokio::test]
async fn batch_zzz_compute_checkpoint_latest_hex_encoding_lowercase_round_trips_for_both_hashes() {
    // `record_hash` and `committee_hash` are encoded via `hex::encode()`
    // at routes/explorer.rs:3259-3260 — lowercase, 64 hex chars for
    // 32 bytes, no `0x` prefix. Pin (a) lowercase contract (a
    // regression to `hex::encode_upper` surfaces here), (b) round-trip
    // via `hex::decode` reproduces the original bytes (catches a
    // regression that emitted `format!("{:?}", &bytes)` Debug output
    // instead of hex), (c) both fields are independent (asymmetric
    // input pattern catches a regression that accidentally re-used
    // `record_hash` bytes for the `committee_hash` field via a
    // copy-paste bug in the json!() body).
    let state = test_state();
    let zone = crate::ZoneId::new("zone-hex");
    // Asymmetric byte patterns: record_hash uses low nibble 0..0xF
    // cycled; committee_hash uses 0xF0|(0..0xF) so high nibble is
    // always 0xF. Wire output for record_hash will be
    // "000102…0f00010…0f…" and committee_hash "f0f1f2…ffF0…" — both
    // exercise every hex digit pair AND are byte-distinct.
    let record_hash: [u8; 32] = std::array::from_fn(|i| (i as u8) & 0x0F);
    let committee_hash: [u8; 32] = std::array::from_fn(|i| 0xF0u8 | ((i as u8) & 0x0F));
    assert_ne!(
        record_hash, committee_hash,
        "sanity: hashes MUST differ for the asymmetry pin to be meaningful"
    );
    {
        let mut epoch = state.epoch.write_recover();
        epoch.latest_super_seal.insert(
            zone.clone(),
            (
                256,
                "0123456789abcdef".repeat(4),
                record_hash,
                committee_hash,
            ),
        );
    }
    let v = compute_checkpoint_latest(state, zone.to_string())
        .await
        .expect("compute ok");
    let rh = v
        .get("record_hash")
        .and_then(|x| x.as_str())
        .expect("record_hash MUST be JSON String");
    let ch = v
        .get("committee_hash")
        .and_then(|x| x.as_str())
        .expect("committee_hash MUST be JSON String");
    assert_eq!(rh.len(), 64, "32 bytes → 64 hex chars (no `0x` prefix)");
    assert_eq!(ch.len(), 64, "32 bytes → 64 hex chars");
    assert_eq!(
        rh,
        rh.to_lowercase(),
        "record_hash MUST be lowercase hex (`hex::encode`, NOT `hex::encode_upper`)"
    );
    assert_eq!(
        ch,
        ch.to_lowercase(),
        "committee_hash MUST be lowercase hex"
    );
    let rh_bytes: Vec<u8> =
        hex::decode(rh).expect("record_hash MUST hex-decode (no Debug-format leak)");
    let ch_bytes: Vec<u8> = hex::decode(ch).expect("committee_hash MUST hex-decode");
    assert_eq!(
        &rh_bytes[..],
        &record_hash[..],
        "record_hash round-trips to the original 32 bytes"
    );
    assert_eq!(
        &ch_bytes[..],
        &committee_hash[..],
        "committee_hash round-trips to the original 32 bytes"
    );
    assert_ne!(
        rh, ch,
        "wire fields MUST be distinct (catches a copy-paste bug that aliased one hash for both)"
    );
}

// ─── compute_seal_debug happy-path ───────
// `compute_seal_debug` (explorer.rs:654) was tested ONLY on the
// error-path branch (`batch_n_..._unknown_id_returns_record_not_found_error`
// at L5473) prior to this slice. The happy-path serialization is the
// operator's primary diagnostic surface for "why isn't this seal
// settling?" — accounts / dashboards pull `/explorer/seal/{id}/debug`
// to read the per-attestor diversity-weighted effective_stake AND the
// 2/3 threshold the seal needs to cross. Five orthogonal axes:
//   (1) 15-field envelope contract — every field on `SealDebug`
//       (consensus.rs:4139) must surface on the wire with the
//       documented type. A future #[derive(Serialize)] field added
//       upstream would leak through here; a #[serde(skip)] mistake
//       would silently drop a diagnostic from operator views.
//   (2) settlement_denominator picks committee_stake when nonzero
//       and falls back to zone_stake when not — the helper at
//       consensus.rs:1706 IS the load-bearing branch for MAINNET
//       gap #5 (per-zone committees). A regression that flipped the
//       fallback direction would inflate the denominator on bootstrap
//       zones where `register_epoch_committee` hasn't run yet.
//   (3) stake_threshold = (2/3) × settlement_denominator exactly —
//       crossing this flips `is_settled` per consensus.rs:3580
//       (`effective_stake * 3.0 >= eligible_stake as f64 * 2.0`).
//       Float-tolerant compare guards against a literal-2-becomes-3
//       refactor.
//   (4) committee_members emitted sorted lexicographically — the
//       HashSet iteration at consensus.rs:3827-3829 is sorted before
//       serialization. Cross-node hash-stability of the wire payload
//       depends on this; an `iter().collect::<Vec<_>>()` regression
//       (drop the `.sort()`) would yield nondeterministic ordering.
//   (5) per-attestor `effective_stake == stake * independence` — the
//       per-entry wire contract at consensus.rs:3807-3815. A
//       regression that emitted just `stake` (dropping the
//       diversity-weighting) would surface here, and would silently
//       inflate effective_stake for colluding witness sets.

#[test]
fn batch_aaaa_compute_seal_debug_happy_path_emits_fifteen_field_envelope() {
    // Register one zone-stake + one attestation under a known seal_id.
    // Verify the JSON envelope returned by `compute_seal_debug` exactly
    // covers the 15 documented `SealDebug` fields with the documented
    // types — a regression that added a new diagnostic field upstream
    // (via #[derive(Serialize)]) would surface as len() > 15 here, and
    // a #[serde(skip_serializing_if = "Option::is_none")] mistake on
    // registered_at/finalized_at would surface as len() < 15.
    let state = test_state();
    let zone = crate::ZoneId::from_legacy(0);
    {
        let mut consensus = state.consensus.lock_recover();
        consensus.register_zone_stake(zone.clone(), 1000);
        consensus.register_seal_records("seal-aaaa-envelope", vec!["rec-aaaa-1".to_string()]);
        consensus.add_seal_attestation(crate::network::consensus::SealAttestation {
            seal_id: "seal-aaaa-envelope".to_string(),
            zone: zone.clone(),
            epoch_number: 42,
            witness_hash: "w1-aaaa".to_string(),
            stake: 250,
            timestamp: 1700000001.0,
        });
    }
    let v = compute_seal_debug(&state, "seal-aaaa-envelope")
        .expect("happy path with one attestation MUST return Ok(_)");
    let obj = v
        .as_object()
        .expect("compute_seal_debug happy path MUST return a JSON Object");
    let expected_keys: std::collections::BTreeSet<&str> = [
        "seal_id",
        "zone",
        "epoch_number",
        "attestation_count",
        "attestors",
        "effective_stake",
        "committee_stake",
        "zone_stake",
        "settlement_denominator",
        "stake_threshold",
        "is_settled",
        "is_global_seal",
        "registered_at",
        "finalized_at",
        "committee_members",
    ]
    .iter()
    .copied()
    .collect();
    let actual_keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
    assert_eq!(
        actual_keys, expected_keys,
        "SealDebug wire envelope MUST be exactly these 15 keys — a regression \
             that added a new diagnostic upstream via #[derive(Serialize)] would \
             surface as a key-set delta here"
    );
    assert_eq!(
        obj.get("seal_id").and_then(|x| x.as_str()),
        Some("seal-aaaa-envelope"),
        "seal_id MUST echo input verbatim (no normalization)"
    );
    assert_eq!(
        obj.get("zone").and_then(|x| x.as_str()),
        Some("0"),
        "zone serializes as plain string (ZoneId::from_legacy(0))"
    );
    assert_eq!(
        obj.get("epoch_number").and_then(|x| x.as_u64()),
        Some(42),
        "epoch_number must round-trip the attestation's epoch_number field as u64"
    );
    assert_eq!(
        obj.get("attestation_count").and_then(|x| x.as_u64()),
        Some(1),
        "single attestation → count == 1 (not the variable-bumped seal_attestation_add_total)"
    );
    assert!(
        obj.get("attestors").map(|x| x.is_array()).unwrap_or(false),
        "attestors MUST be a JSON Array (not Object, not omitted)"
    );
    assert!(
        obj.get("registered_at")
            .map(|x| x.is_f64())
            .unwrap_or(false),
        "register_seal_records was called → registered_at is Some(f64), NOT null"
    );
    assert!(
        obj.get("finalized_at")
            .map(|x| x.is_null())
            .unwrap_or(false),
        "below 2/3 threshold → finalized_at MUST be null (Option::None serializes as null)"
    );
    assert_eq!(
        obj.get("is_settled").and_then(|x| x.as_bool()),
        Some(false),
        "one attestation w/ stake 250 vs threshold ~667 → NOT settled"
    );
    assert_eq!(
        obj.get("is_global_seal").and_then(|x| x.as_bool()),
        Some(false),
        "no register_global_seal call → is_global_seal == false"
    );
}

#[test]
fn batch_aaaa_compute_seal_debug_settlement_denominator_picks_committee_when_nonzero_else_zone() {
    // Pins the fallback at consensus.rs:1706 (`settlement_denominator`):
    //   * committee_stakes[zone] > 0  → committee_stake
    //   * else                         → zone_stakes[zone]
    // Two seals under DIFFERENT zones in the same test isolate the two
    // branches without cross-contamination — flipping the fallback
    // direction at consensus.rs:1707-1709 would fail BOTH assertions
    // simultaneously (cross-zone confirmation that this is the active
    // branch, not a coincidence).
    let state = test_state();
    let zone_no_committee = crate::ZoneId::from_legacy(1);
    let zone_with_committee = crate::ZoneId::from_legacy(2);
    {
        let mut consensus = state.consensus.lock_recover();
        // Branch A: only zone-stake registered → fallback to zone_stake.
        consensus.register_zone_stake(zone_no_committee.clone(), 900);
        consensus.register_seal_records("seal-aaaa-fallback-zone", vec!["rec-fb-z".to_string()]);
        consensus.add_seal_attestation(crate::network::consensus::SealAttestation {
            seal_id: "seal-aaaa-fallback-zone".to_string(),
            zone: zone_no_committee.clone(),
            epoch_number: 1,
            witness_hash: "wZ".to_string(),
            stake: 10,
            timestamp: 1.0,
        });
        // Branch B: zone-stake AND committee — committee wins.
        consensus.register_zone_stake(zone_with_committee.clone(), 5000);
        consensus.register_epoch_committee(
            &zone_with_committee,
            &[("c1".to_string(), 120), ("c2".to_string(), 180)],
        );
        consensus.register_seal_records("seal-aaaa-committee-wins", vec!["rec-cw".to_string()]);
        consensus.add_seal_attestation(crate::network::consensus::SealAttestation {
            seal_id: "seal-aaaa-committee-wins".to_string(),
            zone: zone_with_committee.clone(),
            epoch_number: 2,
            witness_hash: "c1".to_string(),
            stake: 120,
            timestamp: 2.0,
        });
    }
    let fb = compute_seal_debug(&state, "seal-aaaa-fallback-zone").expect("branch A: ok");
    assert_eq!(
        fb.get("zone_stake").and_then(|x| x.as_u64()),
        Some(900),
        "zone_stake reflects register_zone_stake(900)"
    );
    assert_eq!(
        fb.get("committee_stake").and_then(|x| x.as_u64()),
        Some(0),
        "no committee registered → committee_stake reads 0"
    );
    assert_eq!(
        fb.get("settlement_denominator").and_then(|x| x.as_u64()),
        Some(900),
        "branch A: no committee → fallback to zone_stake (consensus.rs:1709)"
    );
    let cw = compute_seal_debug(&state, "seal-aaaa-committee-wins").expect("branch B: ok");
    assert_eq!(
        cw.get("zone_stake").and_then(|x| x.as_u64()),
        Some(5000),
        "zone_stake unchanged: register_zone_stake(5000) on this zone"
    );
    assert_eq!(
        cw.get("committee_stake").and_then(|x| x.as_u64()),
        Some(300),
        "committee_stake = sum of member stakes (120 + 180)"
    );
    assert_eq!(
            cw.get("settlement_denominator").and_then(|x| x.as_u64()),
            Some(300),
            "branch B: committee_stake > 0 → consensus.rs:1707-1708 picks committee, NOT zone_stake=5000"
        );
}

#[test]
fn batch_aaaa_compute_seal_debug_stake_threshold_is_exactly_two_thirds_of_settlement_denominator() {
    // `stake_threshold = settlement_denominator * 2.0 / 3.0`
    // (consensus.rs:3821). Pin the arithmetic with a literal that has
    // a clean rational representation (900 / 3 = 300, × 2 = 600.0).
    // A regression to a different fraction (e.g. 3/5, or hardcoded 0.5)
    // would surface here as a float mismatch. Float-tolerant compare
    // guards against any future refactor that introduces an imprecise
    // intermediate (e.g. `* 0.6666...`).
    let state = test_state();
    let zone = crate::ZoneId::from_legacy(3);
    {
        let mut consensus = state.consensus.lock_recover();
        consensus.register_zone_stake(zone.clone(), 900);
        consensus.register_seal_records("seal-aaaa-threshold", vec!["rec-thr".to_string()]);
        consensus.add_seal_attestation(crate::network::consensus::SealAttestation {
            seal_id: "seal-aaaa-threshold".to_string(),
            zone: zone.clone(),
            epoch_number: 7,
            witness_hash: "wT".to_string(),
            stake: 100,
            timestamp: 9.0,
        });
    }
    let v = compute_seal_debug(&state, "seal-aaaa-threshold").expect("happy path: ok");
    let denom = v
        .get("settlement_denominator")
        .and_then(|x| x.as_u64())
        .expect("settlement_denominator must be u64");
    let threshold = v
        .get("stake_threshold")
        .and_then(|x| x.as_f64())
        .expect("stake_threshold must be f64");
    let expected = (denom as f64) * 2.0 / 3.0;
    assert!(
        (threshold - expected).abs() < 1e-9,
        "stake_threshold MUST equal (2/3) × settlement_denominator exactly — \
             got threshold={threshold}, expected={expected} (denom={denom})"
    );
    assert!(
        (threshold - 600.0).abs() < 1e-9,
        "literal pin: denom=900 → threshold=600.0, got {threshold}"
    );
}

#[test]
fn batch_aaaa_compute_seal_debug_committee_members_emitted_sorted_lexicographically() {
    // Wire-payload determinism: register an epoch committee with
    // deliberately-unsorted member identities (z, m, a, x, c). The
    // serialization at consensus.rs:3823-3831 sorts the HashSet
    // contents before emitting — without this sort, parallel-node
    // wire payloads would diverge under HashSet iteration nondeterminism
    // and break content-addressed checkpoint hashes that include the
    // SealDebug payload.
    let state = test_state();
    let zone = crate::ZoneId::from_legacy(4);
    let unsorted = ["z-id", "m-id", "a-id", "x-id", "c-id"];
    let sorted_expected = ["a-id", "c-id", "m-id", "x-id", "z-id"];
    {
        let mut consensus = state.consensus.lock_recover();
        // Each member with stake 10 — committee_stake = 50.
        let members: Vec<(String, u64)> =
            unsorted.iter().map(|s| ((*s).to_string(), 10u64)).collect();
        consensus.register_epoch_committee(&zone, &members);
        consensus.register_seal_records("seal-aaaa-committee-sort", vec!["rec-cs".to_string()]);
        consensus.add_seal_attestation(crate::network::consensus::SealAttestation {
            seal_id: "seal-aaaa-committee-sort".to_string(),
            zone: zone.clone(),
            epoch_number: 11,
            witness_hash: "a-id".to_string(),
            stake: 10,
            timestamp: 11.0,
        });
    }
    let v = compute_seal_debug(&state, "seal-aaaa-committee-sort").expect("happy path: ok");
    let arr = v
        .get("committee_members")
        .and_then(|x| x.as_array())
        .expect("committee_members MUST be a JSON Array");
    let actual: Vec<&str> = arr.iter().filter_map(|x| x.as_str()).collect();
    assert_eq!(
        actual,
        sorted_expected.to_vec(),
        "committee_members MUST emit lexicographically sorted (consensus.rs:3828) — \
             a regression that dropped the `.sort()` would yield nondeterministic \
             order from HashSet iteration and break cross-node hash-stability"
    );
    assert_eq!(
        arr.len(),
        5,
        "all five registered members surface — no dedup, no truncation"
    );
}

#[test]
fn batch_aaaa_compute_seal_debug_attestors_carry_effective_stake_equals_stake_times_independence() {
    // Per-attestor wire contract at consensus.rs:3807-3815:
    //   SealAttestorDetail { witness_hash, stake, independence,
    //                        effective_stake, timestamp }
    // The invariant `effective_stake == stake as f64 * independence`
    // is load-bearing for the diversity-weighted settlement math.
    // A regression that emitted just `stake` (dropping the
    // diversity-weighting) would inflate effective_stake by 1/independence
    // for colluding witness sets, breaking the MESH-BFT 2/3 guarantee.
    //
    // Without WitnessProfile registration, `correlation_weighted` falls
    // into the unknown-profile branch (ALPHA+BETA=0.8), so with 2
    // witnesses each:
    //   independence = 1 / (1 + 0.8) = 0.555...
    //   effective_stake = stake * 0.555...
    // The test asserts the WIRE INVARIANT (stake×independence), NOT
    // the specific numerical value of independence — that decouples
    // this axis from any future tuning of ALPHA/BETA.
    let state = test_state();
    let zone = crate::ZoneId::from_legacy(5);
    {
        let mut consensus = state.consensus.lock_recover();
        consensus.register_zone_stake(zone.clone(), 1000);
        consensus.register_seal_records("seal-aaaa-attestor-math", vec!["rec-am".to_string()]);
        // Two attestations with different stakes so a copy-paste bug
        // (one attestor's effective_stake echoing the other's) would
        // also surface.
        consensus.add_seal_attestation(crate::network::consensus::SealAttestation {
            seal_id: "seal-aaaa-attestor-math".to_string(),
            zone: zone.clone(),
            epoch_number: 17,
            witness_hash: "w-am-1".to_string(),
            stake: 200,
            timestamp: 17.0,
        });
        consensus.add_seal_attestation(crate::network::consensus::SealAttestation {
            seal_id: "seal-aaaa-attestor-math".to_string(),
            zone: zone.clone(),
            epoch_number: 17,
            witness_hash: "w-am-2".to_string(),
            stake: 350,
            timestamp: 18.0,
        });
    }
    let v = compute_seal_debug(&state, "seal-aaaa-attestor-math").expect("happy path: ok");
    let attestors = v
        .get("attestors")
        .and_then(|x| x.as_array())
        .expect("attestors MUST be a JSON Array");
    assert_eq!(
        attestors.len(),
        2,
        "two add_seal_attestation calls → two attestor entries"
    );
    let mut sum_effective = 0.0_f64;
    for att in attestors {
        let obj = att
            .as_object()
            .expect("each attestor entry MUST be a JSON Object");
        let actual_keys: std::collections::BTreeSet<&str> =
            obj.keys().map(|k| k.as_str()).collect();
        let expected_keys: std::collections::BTreeSet<&str> = [
            "witness_hash",
            "stake",
            "independence",
            "effective_stake",
            "timestamp",
        ]
        .iter()
        .copied()
        .collect();
        assert_eq!(
            actual_keys, expected_keys,
            "SealAttestorDetail MUST emit exactly 5 keys"
        );
        let stake = obj
            .get("stake")
            .and_then(|x| x.as_u64())
            .expect("stake MUST be u64");
        let independence = obj
            .get("independence")
            .and_then(|x| x.as_f64())
            .expect("independence MUST be f64");
        let effective_stake = obj
            .get("effective_stake")
            .and_then(|x| x.as_f64())
            .expect("effective_stake MUST be f64");
        let expected = stake as f64 * independence;
        assert!(
            (effective_stake - expected).abs() < 1e-6,
            "effective_stake MUST equal stake × independence — \
                 got effective_stake={effective_stake}, expected={expected} \
                 (stake={stake}, independence={independence}) — \
                 a regression that emitted plain `stake` would surface here"
        );
        // Independence is in (0, 1] for any honest computation:
        // 1 / (1 + non-negative-correlation-sum) is at most 1.0 and
        // strictly > 0 for finite correlation. Catches a regression
        // that emitted `1.0 - independence` or negated the value.
        assert!(
            independence > 0.0 && independence <= 1.0,
            "independence MUST be in (0, 1] — got {independence}"
        );
        sum_effective += effective_stake;
    }
    let envelope_effective = v
        .get("effective_stake")
        .and_then(|x| x.as_f64())
        .expect("top-level effective_stake MUST be f64");
    assert!(
        (envelope_effective - sum_effective).abs() < 1e-6,
        "top-level effective_stake MUST equal sum of per-attestor effective_stake — \
             got envelope={envelope_effective}, per-attestor sum={sum_effective}"
    );
}

// ─── compute_seal_debug is_global_seal=true branch ───────
// The prior batch pinned the WHOLE `compute_seal_debug` happy path
// assuming `is_global_seal=false` (no `register_global_seal` call in
// any of the 5 setups). The complementary is_global_seal=true branch
// (gated by `consensus.global_seal_stuck_zone` membership at
// `consensus.rs:3820`) carries the Stage 3c.1 global-quorum-seal
// wire surface — the operator-facing diagnostic for "is this stuck-zone
// escalation actually settling under the cross-zone quorum, or is the
// captured stuck zone trying to rubber-stamp itself?". Three axes pin
// the three observable differences this branch introduces:
//   (1) `is_global_seal` wire field flips true after register_global_seal
//       (covers the boolean output AND the registration ordering
//       invariance — register before OR after attestations).
//   (2) `is_settled` reflects `is_global_seal_settled` math, NOT the
//       per-zone math. The KEY safety property at consensus.rs:3617-3656:
//       attestations from the stuck zone are silently dropped from the
//       numerator, so a captured stuck zone with massive stake cannot
//       rubber-stamp its own escalation. A regression that ran per-zone
//       math for global seals would surface as `is_settled: true` on a
//       stuck-zone-only attestation set.
//   (3) Wire `settlement_denominator` for a global seal reflects the
//       FIRST attestation's zone's local denominator (consensus.rs:3804
//       uses `self.settlement_denominator(&zone)` with `zone =
//       atts.first().zone`), NOT the cross-zone `max` over non-stuck
//       zones that `is_global_seal_settled` actually uses
//       (consensus.rs:3624-3630). This is a wire/math asymmetry — pin
//       it so any future "fix" (aligning the wire denominator with
//       the cross-zone max) surfaces as a deliberate prompt to update
//       this test and the operator-dashboard docs, rather than silent
//       drift breaking dashboards that compare `effective_stake` to
//       `stake_threshold`.

#[test]
fn batch_bbbb_compute_seal_debug_global_seal_flips_is_global_seal_wire_field_with_ordering_invariance(
) {
    // Two parallel seals exercise the registration ordering: one
    // registers global BEFORE any attestation lands, the other registers
    // global AFTER the attestation. Both MUST emit is_global_seal=true.
    // A regression that gated `is_global_seal` on "register-after-attest"
    // ordering (e.g., copy-paste from finalized_at which only gets set
    // post-settlement) would fail axis (a). A regression that gated on
    // "register-before-attest" (e.g., a one-shot HashMap clear in
    // add_seal_attestation) would fail axis (b).
    let state = test_state();
    let stuck_zone = crate::ZoneId::from_legacy(7);
    let non_stuck_zone = crate::ZoneId::from_legacy(8);
    {
        let mut consensus = state.consensus.lock_recover();
        consensus.register_zone_stake(non_stuck_zone.clone(), 100);
        // Axis (a): register_global_seal FIRST, then add attestation.
        consensus.register_global_seal("seal-bbbb-pre-register", stuck_zone.clone());
        consensus.register_seal_records("seal-bbbb-pre-register", vec!["rec-bbbb-pre".to_string()]);
        consensus.add_seal_attestation(crate::network::consensus::SealAttestation {
            seal_id: "seal-bbbb-pre-register".to_string(),
            zone: non_stuck_zone.clone(),
            epoch_number: 1,
            witness_hash: "w-bbbb-pre".to_string(),
            stake: 10,
            timestamp: 1.0,
        });
        // Axis (b): add attestation FIRST, then register_global_seal.
        consensus
            .register_seal_records("seal-bbbb-post-register", vec!["rec-bbbb-post".to_string()]);
        consensus.add_seal_attestation(crate::network::consensus::SealAttestation {
            seal_id: "seal-bbbb-post-register".to_string(),
            zone: non_stuck_zone.clone(),
            epoch_number: 2,
            witness_hash: "w-bbbb-post".to_string(),
            stake: 10,
            timestamp: 2.0,
        });
        consensus.register_global_seal("seal-bbbb-post-register", stuck_zone.clone());
    }
    let pre =
        compute_seal_debug(&state, "seal-bbbb-pre-register").expect("pre-register happy path: ok");
    assert_eq!(
        pre.get("is_global_seal").and_then(|x| x.as_bool()),
        Some(true),
        "register_global_seal BEFORE attestation MUST surface is_global_seal: true"
    );
    let post = compute_seal_debug(&state, "seal-bbbb-post-register")
        .expect("post-register happy path: ok");
    assert_eq!(
        post.get("is_global_seal").and_then(|x| x.as_bool()),
        Some(true),
        "register_global_seal AFTER attestation MUST surface is_global_seal: true \
             (consensus.rs:3820 reads global_seal_stuck_zone.contains_key at debug time, \
              ordering-invariant)"
    );
    // Sanity: cross-check against the consensus-layer trait at
    // consensus.rs:3596 to confirm the wire field tracks the same map.
    let consensus = state.consensus.lock_recover();
    assert!(consensus.is_global_seal("seal-bbbb-pre-register"));
    assert!(consensus.is_global_seal("seal-bbbb-post-register"));
}

#[test]
fn batch_bbbb_compute_seal_debug_global_seal_is_settled_excludes_stuck_zone_attestations() {
    // Construct a case where per-zone math WOULD settle but global-seal
    // math MUST NOT — proves `is_settled` for a registered global seal
    // routes through `is_global_seal_settled` (consensus.rs:3617), NOT
    // the per-zone `is_seal_settled` path. The MESH-BFT safety property:
    // a captured stuck zone cannot rubber-stamp its own escalation by
    // packing its own stake into self-attestations.
    //
    // Setup:
    //   * stuck_zone (zone 9) has zone_stake = 1_000_000 (captured-large).
    //   * non_stuck_zone (zone 10) has zone_stake = 100 (small honest set).
    //   * Single attestation FROM the stuck zone with stake 999_999.
    //
    // Per-zone math (if it were running): denom = settlement_denominator(
    //   stuck_zone) = 1_000_000; threshold = 666_666.67; effective_stake
    //   = 999_999 × independence ≈ 999_999 ≥ threshold → settled.
    //
    // Global math (CORRECT): denom = max(zone_stakes[z], z != stuck) =
    //   100; threshold = 66.67; numerator filters to non-stuck-zone
    //   attestations only → 0 attestations remaining → is_global_seal_
    //   settled returns false at the `non_stuck_atts.is_empty()` guard
    //   (consensus.rs:3640-3642).
    //
    // A regression that ran per-zone math for global seals (e.g., a
    // refactor that dropped the `if let Some(stuck_zone) = ...` branch
    // at consensus.rs:3551) would flip is_settled: false → true here.
    let state = test_state();
    let stuck_zone = crate::ZoneId::from_legacy(9);
    let non_stuck_zone = crate::ZoneId::from_legacy(10);
    {
        let mut consensus = state.consensus.lock_recover();
        consensus.register_zone_stake(stuck_zone.clone(), 1_000_000);
        consensus.register_zone_stake(non_stuck_zone.clone(), 100);
        consensus.register_global_seal("seal-bbbb-safety", stuck_zone.clone());
        consensus.register_seal_records("seal-bbbb-safety", vec!["rec-bbbb-safety".to_string()]);
        // Single attestation FROM the stuck zone with massive stake.
        // Under global-seal math this attestation is DROPPED from the
        // numerator at consensus.rs:3636-3639.
        consensus.add_seal_attestation(crate::network::consensus::SealAttestation {
            seal_id: "seal-bbbb-safety".to_string(),
            zone: stuck_zone.clone(),
            epoch_number: 3,
            witness_hash: "w-stuck-attacker".to_string(),
            stake: 999_999,
            timestamp: 3.0,
        });
    }
    let v = compute_seal_debug(&state, "seal-bbbb-safety").expect("happy path: ok");
    assert_eq!(
        v.get("is_global_seal").and_then(|x| x.as_bool()),
        Some(true),
        "registered as global seal → is_global_seal: true"
    );
    assert_eq!(
        v.get("is_settled").and_then(|x| x.as_bool()),
        Some(false),
        "stuck-zone-only attestations MUST NOT settle a global seal — \
             captured stuck zone with stake 999_999 against non-stuck zone_stake \
             of 100 → global math drops the stuck attestation, leaves 0 in \
             numerator, returns false at the empty-non-stuck-atts guard \
             (consensus.rs:3640-3642). A regression that ran per-zone math \
             would surface is_settled: true here."
    );
    // Cross-check: under per-zone math this WOULD have settled, so the
    // assertion above is meaningful (not a tautology where global math
    // and per-zone math agree).
    assert_eq!(
        v.get("attestation_count").and_then(|x| x.as_u64()),
        Some(1),
        "attestation_count surfaces the stored attestation (1) — the \
             stuck-zone filter applies to settlement math, NOT to the count \
             of stored attestations on the wire."
    );
}

#[test]
fn batch_bbbb_compute_seal_debug_global_seal_wire_denominator_reflects_first_attestation_zone_not_cross_zone_max(
) {
    // Wire/math asymmetry pin: for a registered global seal,
    // `compute_seal_debug` emits `settlement_denominator` =
    // `self.settlement_denominator(&zone)` where `zone = atts.first()
    // .zone` (consensus.rs:3804). This is the per-zone denominator for
    // the FIRST attestation's zone, NOT the cross-zone `max` over
    // non-stuck zones that `is_global_seal_settled` uses
    // (consensus.rs:3624-3630).
    //
    // Setup engineered so the wire denominator ≠ the math denominator:
    //   * stuck_zone (zone 11): zone_stake = 999 (won't appear in wire
    //     denominator because first att is NOT from this zone, and
    //     won't appear in global-math denominator because it's the
    //     stuck zone — excluded).
    //   * non_stuck_A (zone 12): zone_stake = 300 (LARGEST non-stuck).
    //   * non_stuck_B (zone 13): zone_stake = 100 (SMALLEST non-stuck).
    //   * First attestation FROM non_stuck_B (zone 13).
    //
    // Wire: settlement_denominator = settlement_denominator(non_stuck_B)
    //       = 100 (B's own zone_stake; no committee registered).
    //       stake_threshold = 2/3 × 100 = 66.67.
    // Math: is_global_seal_settled denominator = max(300, 100) = 300.
    //       Actual math threshold = 2/3 × 300 = 200.0.
    //
    // The wire shows threshold = 66.67, but the actual settlement math
    // runs against 200.0. A regression that "fixed" the wire to align
    // with the math (i.e., emitted max(non_stuck zone_stakes) for
    // global seals) would surface here as wire denominator 300 instead
    // of 100 — a DELIBERATE prompt to update operator dashboards that
    // currently rely on the per-zone wire denominator.
    let state = test_state();
    let stuck_zone = crate::ZoneId::from_legacy(11);
    let non_stuck_a = crate::ZoneId::from_legacy(12);
    let non_stuck_b = crate::ZoneId::from_legacy(13);
    {
        let mut consensus = state.consensus.lock_recover();
        consensus.register_zone_stake(stuck_zone.clone(), 999);
        consensus.register_zone_stake(non_stuck_a.clone(), 300);
        consensus.register_zone_stake(non_stuck_b.clone(), 100);
        consensus.register_global_seal("seal-bbbb-wire-asymmetry", stuck_zone.clone());
        consensus.register_seal_records(
            "seal-bbbb-wire-asymmetry",
            vec!["rec-bbbb-asym".to_string()],
        );
        consensus.add_seal_attestation(crate::network::consensus::SealAttestation {
            seal_id: "seal-bbbb-wire-asymmetry".to_string(),
            zone: non_stuck_b.clone(),
            epoch_number: 4,
            witness_hash: "w-from-B".to_string(),
            stake: 50,
            timestamp: 4.0,
        });
    }
    let v = compute_seal_debug(&state, "seal-bbbb-wire-asymmetry").expect("happy path: ok");
    assert_eq!(
        v.get("is_global_seal").and_then(|x| x.as_bool()),
        Some(true),
        "registered as global seal → is_global_seal: true"
    );
    // Pin the WIRE denominator: 100 (non_stuck_B's zone_stake), NOT 300
    // (max non-stuck), NOT 999 (stuck zone).
    assert_eq!(
        v.get("settlement_denominator").and_then(|x| x.as_u64()),
        Some(100),
        "WIRE settlement_denominator MUST reflect first attestation's zone \
             (non_stuck_B = 100) per consensus.rs:3804 — NOT the cross-zone max \
             non-stuck value (300) used by is_global_seal_settled. A future \
             refactor that 'fixed' this asymmetry must deliberately update \
             this test."
    );
    // Pin the WIRE threshold: 2/3 × 100 = 66.67, NOT 2/3 × 300 = 200.0.
    let threshold = v
        .get("stake_threshold")
        .and_then(|x| x.as_f64())
        .expect("stake_threshold must be f64");
    let expected_wire_threshold = 100.0 * 2.0 / 3.0;
    assert!(
        (threshold - expected_wire_threshold).abs() < 1e-9,
        "WIRE stake_threshold MUST be 2/3 × WIRE denominator (66.67), \
             NOT 2/3 × math denominator (200.0). Got threshold={threshold}, \
             expected={expected_wire_threshold}."
    );
    // Pin the cross-zone exclusion at zone_stake granularity: the
    // stuck_zone's zone_stake of 999 MUST NOT appear in the wire
    // denominator (would only appear if first att were FROM stuck zone,
    // which it isn't here). This guards a regression that flipped the
    // wire to use stuck-zone's local denom.
    assert_ne!(
        v.get("settlement_denominator").and_then(|x| x.as_u64()),
        Some(999),
        "settlement_denominator MUST NOT reflect stuck_zone's stake (999) \
             when the first attestation is FROM a non-stuck zone."
    );
    // Cross-check independent of is_settled-flip ambiguity: the wire
    // committee_stake is 0 (no committee registered) for this zone.
    assert_eq!(
        v.get("committee_stake").and_then(|x| x.as_u64()),
        Some(0),
        "no register_epoch_committee call → committee_stake reads 0"
    );
}

// ─── compute_itc_status orthogonal pins ──────────────
//
// `compute_itc_status` (routes/explorer.rs:1969) is the read-only wire
// surface for the per-zone Interval Tree Clock (ITC) state served at
// `/itc`. It is the shared compute helper feeding both the axum handler
// at line 1982 AND any future PQ-native verb that wires through (per the
// shared-compute pattern). Previously the helper had ZERO
// dedicated tests despite touching three independent runtime axes:
//   (a) the `state.zone_clocks` Mutex<ZoneClockManager> snapshot via
//       `ZoneClockManager::summary()` at `src/itc.rs:666-683`
//   (b) the `state.itc_events_total` AtomicU64 counter bumped at
//       `src/network/ingest.rs:1618` on local record creation
//   (c) the `state.itc_joins_total` AtomicU64 counter bumped at
//       `src/network/ingest.rs:1612` on remote stamp receipt
//
// The 4 axes pinned below correspond to the load-bearing wire contracts:
//   (1) strict 3-key top-level envelope `{itc, events_total,
//       joins_total}` via BTreeSet set-equality — a silent 4th-key bloat
//       (`zone_count`, `last_event_at` for ops dashboards) AND a
//       missing-key regression (dropping `joins_total` after a refactor)
//       both surface here as a key-set delta. Account/explorer clients
//       running with serde `deny_unknown_fields` would otherwise break
//       on a silent wire addition; this is the same pattern as the
//       envelope pin on `compute_get_epoch_snapshot`.
//   (2) fresh-state ZERO baseline — `itc.zones == 0` (HashMap len),
//       `itc.details == []` (empty array, NOT null), and BOTH atomic
//       counters serialize as u64 zero (NOT string "0", NOT null).
//       Account UIs iterate `body.itc.details.map(...)` and a null/missing
//       `details` crashes the iterator on first-load.
//   (3) atomic counter wire-through with orthogonal seed values
//       (events=7, joins=3, coprime to avoid accidental swap-symmetry).
//       A regression that wired `events_total` and `joins_total` to the
//       same counter (copy-paste bug) would surface here as wire (7,7)
//       or (3,3) instead of (7,3); a regression that off-by-one'd one
//       counter would surface as (8,3) or (7,4).
//   (4) ZoneClockManager.summary() pass-through — `record_event()` on 3
//       distinct zones produces `itc.zones == 3` AND
//       `itc.details.len() == 3`. The cardinality equality between the
//       `zones` count field and the `details` array length is a load-
//       bearing wire invariant (operator dashboards read `zones` as a
//       fast scalar; explorer UIs render `details[]`) — a refactor that
//       paginated `details` while keeping `zones` at the total would
//       surface here as inequality. The 3rd zone's `path()` ("alpha/eu")
//       is also pinned to surface in `details` to verify the
//       lowercase-normalized path is the wire serialization, not the
//       internal numeric hash or a re-canonicalized form.

#[test]
fn batch_ffff_compute_itc_status_strict_three_key_top_level_envelope() {
    // Wire-shape pin via strict BTreeSet equality on top-level keys.
    // Compute helper returns exactly `{itc, events_total, joins_total}` —
    // any addition (e.g., `zone_count`, `last_event_at`) or removal
    // (e.g., dropping `joins_total` post-refactor) surfaces here as a
    // set-mismatch failure with a deliberate prompt to update the test.
    let state = test_state();
    let v = compute_itc_status(state);
    let obj = v
        .as_object()
        .expect("compute_itc_status MUST return a JSON Object at top level");
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
    let expected: std::collections::BTreeSet<&str> =
        ["itc", "events_total", "joins_total"].into_iter().collect();
    assert_eq!(
        actual, expected,
        "compute_itc_status top-level wire envelope MUST be exactly these 3 keys \
             (itc, events_total, joins_total) — a silent 4th-key bloat for ops dashboards \
             AND a missing-key regression both surface here"
    );
}

#[test]
fn batch_ffff_compute_itc_status_fresh_state_zero_baseline_no_null_fields() {
    // Empty NodeState: ZoneClockManager has no stamps, no events/joins
    // have been recorded. Pin the EXACT serialization for each field:
    //   - itc.zones == 0 (u64, NOT null, NOT string)
    //   - itc.details is [] (Array, NOT null, NOT missing)
    //   - events_total == 0 (u64, NOT string "0", NOT null)
    //   - joins_total == 0 (u64, NOT string "0", NOT null)
    // Account/explorer clients iterate `body.itc.details.map(...)` — a
    // null `details` would crash on first-load. A `String("0")` for the
    // counters would silently break `body.events_total as int` casts.
    let state = test_state();
    let v = compute_itc_status(state);

    let itc = v.get("itc").expect("itc subobject present");
    assert!(
        itc.is_object(),
        "itc MUST be a JSON Object (not null, not array)"
    );
    assert_eq!(
        itc.get("zones").and_then(|x| x.as_u64()),
        Some(0),
        "fresh-state ZoneClockManager has empty stamps HashMap → zones == 0"
    );
    let details = itc.get("details").expect("itc.details present");
    assert!(
        details.is_array(),
        "itc.details MUST be a JSON Array (empty, NOT null, NOT missing) — \
             account iteration `body.itc.details.map(...)` crashes on null"
    );
    assert_eq!(
        details.as_array().expect("array").len(),
        0,
        "fresh-state empty stamps HashMap → details is empty array"
    );

    // Pin counter type-AND-value for both atomics.
    assert!(
        v.get("events_total").map(|x| x.is_u64()).unwrap_or(false),
        "events_total MUST be JSON u64 (NOT String, NOT null) — `as int` casts break otherwise"
    );
    assert_eq!(
        v.get("events_total").and_then(|x| x.as_u64()),
        Some(0),
        "fresh-state AtomicU64::new(0) → events_total == 0"
    );
    assert!(
        v.get("joins_total").map(|x| x.is_u64()).unwrap_or(false),
        "joins_total MUST be JSON u64 (NOT String, NOT null)"
    );
    assert_eq!(
        v.get("joins_total").and_then(|x| x.as_u64()),
        Some(0),
        "fresh-state AtomicU64::new(0) → joins_total == 0"
    );
}

#[test]
fn batch_ffff_compute_itc_status_atomic_counter_orthogonal_wire_through() {
    // Bump events_total and joins_total to coprime values (7, 3) so a
    // regression that wired BOTH wire fields to the same counter
    // (copy-paste bug at `routes/explorer.rs:1977-1978` reading
    // `events_total` for both) would surface as (7, 7) or (3, 3) instead
    // of the orthogonal (7, 3). Coprime seeds also rule out an
    // accidental-swap regression (would give (3, 7) instead of (7, 3)).
    let state = test_state();
    state
        .itc_events_total
        .store(7, std::sync::atomic::Ordering::Relaxed);
    state
        .itc_joins_total
        .store(3, std::sync::atomic::Ordering::Relaxed);

    let v = compute_itc_status(state);
    assert_eq!(
        v.get("events_total").and_then(|x| x.as_u64()),
        Some(7),
        "events_total wire field MUST read the local events counter (not joins)"
    );
    assert_eq!(
        v.get("joins_total").and_then(|x| x.as_u64()),
        Some(3),
        "joins_total wire field MUST read the joins counter (not events) — \
             coprime seeds (7, 3) rule out copy-paste-same-counter regression"
    );
}

#[test]
fn batch_ffff_compute_itc_status_zone_clock_summary_pass_through_with_path_echo() {
    // Record events on 3 distinct zones via ZoneClockManager::record_event.
    // Verify that compute_itc_status passes the summary() through:
    //   (a) itc.zones == 3 (HashMap len)
    //   (b) itc.details.len() == 3 (Array length matches scalar)
    //   (c) the lowercase-normalized path of one zone ("alpha/eu") shows
    //       up verbatim in some entry's `zone` field — pins that the
    //       wire serialization uses `ZoneId::path()` (the internal
    //       String) NOT the legacy numeric hash NOR any re-canonicalized
    //       form. ZoneId::new normalizes to lowercase + strips trailing
    //       slashes (zone.rs:40-51), so "ALPHA/EU/" → "alpha/eu".
    let state = test_state();
    let z1 = crate::ZoneId::from_legacy(0);
    let z2 = crate::ZoneId::from_legacy(1);
    let z3 = crate::ZoneId::new("ALPHA/EU/"); // normalizes to "alpha/eu"
    {
        let mut clocks = state.zone_clocks.lock_recover();
        let _ = clocks.record_event(z1.clone());
        let _ = clocks.record_event(z2.clone());
        let _ = clocks.record_event(z3.clone());
    }
    let v = compute_itc_status(state);
    let itc = v.get("itc").expect("itc subobject present");

    assert_eq!(
        itc.get("zones").and_then(|x| x.as_u64()),
        Some(3),
        "ZoneClockManager.stamps HashMap has 3 entries → itc.zones == 3"
    );
    let details = itc
        .get("details")
        .and_then(|x| x.as_array())
        .expect("itc.details present and is Array");
    assert_eq!(
        details.len(),
        3,
        "itc.details.len() MUST equal itc.zones — a refactor that paginated \
             details while keeping zones at the total would surface here"
    );

    // Pin the path-echo on the normalized-input zone. Collect all
    // emitted `zone` strings, then assert the normalized form is
    // present; this is order-independent (HashMap iteration order is
    // unstable but the set equality is stable).
    let emitted_paths: std::collections::BTreeSet<String> = details
        .iter()
        .filter_map(|entry| {
            entry
                .get("zone")
                .and_then(|p| p.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    assert!(
        emitted_paths.contains("alpha/eu"),
        "summary() MUST serialize ZoneId via path() (lowercased, slash-preserved) — \
             the normalized form 'alpha/eu' MUST appear (NOT 'ALPHA/EU/', NOT a numeric hash). \
             Got emitted paths: {emitted_paths:?}"
    );
    assert!(
        emitted_paths.contains("0") && emitted_paths.contains("1"),
        "ZoneId::from_legacy(0/1) MUST serialize as '0'/'1' strings (not 0/1 numbers, \
             not re-canonicalized). Got: {emitted_paths:?}"
    );
}

// ─── compute_governance_params orthogonal pins ──────
//
// Density slice on `src/network/routes/explorer.rs::compute_governance_params`
// (lines 1153-1164). Pre-slice the function had ZERO unit tests despite
// being the `/governance/params` wire surface that accounts, dashboards
// and governance UIs read to display current network parameters. The
// slice also CLOSES a 2-month-old wire-surface gap: `stake_throughput_ratio`
// was added to `GovernableParams` and to `GOVERNABLE_PARAMS` on 2026-03-10
// (commit d7155fc8 — initial protocol spec) AND has a backing
// `apply()`/`get()` branch in src/accounting/governance.rs:512 + :530 +
// internal design notes:61 — but was missing from the
// `compute_governance_params` JSON object. Governance could change it
// and clients had no way to query it back. This slice ships the fix
// (one wire field added, line 1161) and pins the new 6-key wire-shape
// invariant against future drift.
//
// The 5 axes are mutually orthogonal — no test subsumes another:
//   1. Strict 6-key envelope (top-level wire-shape pin against silent
//      additions/removals).
//   2. Default-state value equality (all 5 GovernableParams::default()
//      fields match the JSON output verbatim + total_changes == 0).
//   3. GOVERNABLE_PARAMS ↔ wire-surface bijection (every name in the
//      const appears as a wire key, NO unrecognised wire key exists).
//   4. JSON type-purity (each field is exactly the expected scalar
//      type — no String coercion, no null fallback).
//   5. total_changes counter wire-through (vector len → u64; 3-entry
//      seed pins Vec::len() arithmetic against an off-by-one regression).
//
// Why the GOVERNABLE_PARAMS ↔ wire-surface bijection (axis 3) is
// load-bearing: without it, the *next* governance param added to
// `GovernableParams` (say `min_stake_secs`) would drift the same way
// `stake_throughput_ratio` did — present in governance.rs::apply(),
// present in the const, but invisible on the wire. Axis 3 will fail
// the moment GOVERNABLE_PARAMS grows past the wire surface, forcing
// the wire keeper to either add the new key or remove it from the const.

#[tokio::test]
async fn batch_hhhh_compute_governance_params_emits_strict_six_key_envelope() {
    // Wire-shape pin via strict BTreeSet equality. The 6 keys are:
    //   - 5 GovernableParams scalars (propagation_rate_limit_per_hour,
    //     epoch_seal_interval_secs, witness_reward_micros,
    //     record_retention_secs, stake_throughput_ratio)
    //   - total_changes (Vec::len() exposed as u64)
    // A 7th key (e.g., "version") OR a missing key (e.g., dropping
    // stake_throughput_ratio in a future refactor — exactly the regression
    // class this slice closes) BOTH surface here as set-mismatch failure.
    let state = test_state();
    let v = compute_governance_params(state).await;
    let obj = v
        .as_object()
        .expect("compute_governance_params MUST return a JSON Object at top level");
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
    let expected: std::collections::BTreeSet<&str> = [
        "propagation_rate_limit_per_hour",
        "epoch_seal_interval_secs",
        "witness_reward_micros",
        "record_retention_secs",
        "stake_throughput_ratio",
        "total_changes",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        actual, expected,
        "compute_governance_params top-level wire envelope MUST be EXACTLY these 6 keys — \
             silent additions (e.g., 'version', 'last_change_at') OR missing keys \
             (e.g., dropping stake_throughput_ratio post-refactor) BOTH surface here"
    );
}

#[tokio::test]
async fn batch_hhhh_compute_governance_params_default_state_values_match_governable_params_default()
{
    // Fresh NodeState: `ledger.governance.params` is `GovernableParams::default()`.
    // Pin every scalar against the literal default value:
    //   - propagation_rate_limit_per_hour: u64 = 120
    //   - epoch_seal_interval_secs: f64 = 300.0
    //   - witness_reward_micros: u64 = 1_000_000_000  (1 beat, base units 10^9/beat)
    //   - record_retention_secs: f64 = 0.0  (infinite)
    //   - stake_throughput_ratio: u64 = 100_000_000  (economics §9.4 default, base units)
    //   - total_changes: u64 = 0 (empty Vec)
    // A regression that swapped any of these defaults (e.g., bumped
    // witness_reward to 10 beat without doc update, or zeroed
    // stake_throughput_ratio defeating fee-market gating) would fail here
    // before reaching the testnet. Pinned against literal values, not
    // GovernableParams::default(), so a coordinated change to BOTH the
    // default constructor AND this test (e.g., a stealth value bump
    // landing both edits in the same commit) is rejected by the unit
    // tests in governance.rs that ALSO pin these literals.
    let state = test_state();
    let v = compute_governance_params(state).await;
    assert_eq!(
        v.get("propagation_rate_limit_per_hour")
            .and_then(|x| x.as_u64()),
        Some(120),
        "propagation_rate_limit_per_hour default MUST be 120 — pinned against \
             governance.rs:482 literal"
    );
    // f64 comparison via to_string round-trip avoids epsilon issues for
    // small integer-valued floats — 300.0 serializes as "300.0" reliably
    // in serde_json.
    assert_eq!(
        v.get("epoch_seal_interval_secs").and_then(|x| x.as_f64()),
        Some(300.0),
        "epoch_seal_interval_secs default MUST be 300.0 — pinned against \
             governance.rs:483 literal"
    );
    assert_eq!(
        v.get("witness_reward_micros").and_then(|x| x.as_u64()),
        Some(1_000_000_000),
        "witness_reward_micros default MUST be 1_000_000_000 (1 beat in base units, 10^9/beat) — \
             pinned against governance.rs:484 literal"
    );
    assert_eq!(
        v.get("record_retention_secs").and_then(|x| x.as_f64()),
        Some(0.0),
        "record_retention_secs default MUST be 0.0 (sentinel = infinite retention) — \
             pinned against governance.rs:485 literal; a regression flipping this to a \
             finite value would silently enable GC on all retention-unaware nodes"
    );
    assert_eq!(
        v.get("stake_throughput_ratio").and_then(|x| x.as_u64()),
        Some(100_000_000),
        "stake_throughput_ratio default MUST be 100_000_000 (economics §9.4 default — \
             10^8 base units per daily record, so 100 beat stake = 1000 rec/day budget). This \
             field was added 2026-03-10 (commit d7155fc8) but missing from the wire \
             surface until Batch-HHHH on 2026-05-23 — this pin closes the wire-shape gap"
    );
    assert_eq!(
        v.get("total_changes").and_then(|x| x.as_u64()),
        Some(0),
        "total_changes on fresh state MUST be 0 (empty Vec::len())"
    );
}

#[tokio::test]
async fn batch_hhhh_compute_governance_params_governable_params_const_to_wire_surface_bijection() {
    // Pin the invariant: every name in `GOVERNABLE_PARAMS` const MUST
    // appear as a wire key. This is the load-bearing test for future
    // governance param additions — if a new field (e.g., "min_stake_secs")
    // is added to `GovernableParams` AND to `GOVERNABLE_PARAMS` const
    // AND to the `apply()` match arm, but the wire keeper forgets to
    // expose it here, THIS TEST FAILS with a clear error message
    // identifying the missing field. Without this axis, the wire surface
    // silently drifts (exactly how stake_throughput_ratio drifted for
    // 2 months between its 2026-03-10 addition and the 2026-05-23 fix).
    //
    // The bijection is enforced in BOTH directions:
    //   (a) every GOVERNABLE_PARAMS name MUST appear in wire keys (no
    //       silently-unqueryable governance param)
    //   (b) every wire key (excluding the meta-key `total_changes`) MUST
    //       appear in GOVERNABLE_PARAMS (no wire key that isn't actually
    //       governable — which would mislead account operators)
    use crate::accounting::governance::GOVERNABLE_PARAMS;
    let state = test_state();
    let v = compute_governance_params(state).await;
    let obj = v.as_object().expect("top-level Object");
    let wire_keys: std::collections::BTreeSet<&str> = obj.keys().map(|k| k.as_str()).collect();
    let const_names: std::collections::BTreeSet<&str> = GOVERNABLE_PARAMS.iter().copied().collect();

    // Direction (a): every GOVERNABLE_PARAMS name MUST be on the wire.
    for name in &const_names {
        assert!(
            wire_keys.contains(name),
            "GOVERNABLE_PARAMS entry '{name}' is governable but NOT exposed on \
                 /governance/params — account operators have no way to read the current \
                 value. Either add `\"{name}\": params.{name}` to compute_governance_params \
                 OR remove '{name}' from the GOVERNABLE_PARAMS const."
        );
    }

    // Direction (b): every wire key (minus the meta `total_changes`) MUST
    // be in GOVERNABLE_PARAMS.
    for key in &wire_keys {
        if *key == "total_changes" {
            continue;
        }
        assert!(
            const_names.contains(key),
            "Wire key '{key}' is exposed on /governance/params but NOT in \
                 GOVERNABLE_PARAMS — account operators see it as queryable, but \
                 governance proposals to change it would fail at the apply() match arm. \
                 Either add '{key}' to GOVERNABLE_PARAMS + apply()/get() in governance.rs \
                 OR remove the wire field from compute_governance_params."
        );
    }
}

#[tokio::test]
async fn batch_hhhh_compute_governance_params_per_field_json_type_purity() {
    // Pin the JSON scalar type for each wire field. A regression that
    // accidentally coerced a u64 to a String via `.to_string()` (e.g.,
    // for a "human readable" formatting bug) would silently break account
    // `body.witness_reward_micros as i64` parses. Likewise an `f64` that
    // landed as a JSON null on NaN (which `serde_json` does by default
    // for non-finite floats) would crash account `.toFixed()` calls.
    //
    // GovernableParams fields by Rust type:
    //   - propagation_rate_limit_per_hour: u64  → JSON u64
    //   - epoch_seal_interval_secs: f64         → JSON f64 (finite)
    //   - witness_reward_micros: u64            → JSON u64
    //   - record_retention_secs: f64            → JSON f64 (finite)
    //   - stake_throughput_ratio: u64           → JSON u64
    //   - total_changes (Vec::len() as usize)   → JSON u64
    let state = test_state();
    let v = compute_governance_params(state).await;

    // u64 fields: pin is_u64() AND !is_string() AND !is_null()
    for name in [
        "propagation_rate_limit_per_hour",
        "witness_reward_micros",
        "stake_throughput_ratio",
        "total_changes",
    ] {
        let val = v
            .get(name)
            .unwrap_or_else(|| panic!("wire field '{name}' MUST be present"));
        assert!(
            val.is_u64(),
            "{name} MUST be JSON u64 (NOT String, NOT null) — account `as i64` casts \
                 break on String coercion; got: {val:?}"
        );
        assert!(!val.is_string(), "{name} MUST NOT be String");
        assert!(!val.is_null(), "{name} MUST NOT be null");
    }

    // f64 fields: pin is_f64() AND .is_finite() AND !is_null()
    for name in ["epoch_seal_interval_secs", "record_retention_secs"] {
        let val = v
            .get(name)
            .unwrap_or_else(|| panic!("wire field '{name}' MUST be present"));
        assert!(
            val.is_f64() || val.is_u64(),
            "{name} MUST be JSON Number (f64 or u64) — got: {val:?}"
        );
        let f = val
            .as_f64()
            .unwrap_or_else(|| panic!("{name} MUST be convertible to f64"));
        assert!(
            f.is_finite(),
            "{name} MUST be IEEE-754 finite (NOT NaN, NOT ±Inf) — got: {f}"
        );
        assert!(!val.is_null(), "{name} MUST NOT be null");
        assert!(!val.is_string(), "{name} MUST NOT be String");
    }
}

#[tokio::test]
async fn batch_hhhh_compute_governance_params_total_changes_wires_param_change_vec_len() {
    // Pin the `total_changes` ↔ `param_changes.len()` invariant. Seed 3
    // ParamChange entries via direct write (bypasses the apply() side
    // effects — we only want to test the wire arithmetic). Verify wire
    // total_changes == 3. The values themselves don't matter for this
    // axis; what matters is the counter equals Vec::len(), not (len-1),
    // not (len+1), not the highest-numbered proposal_id.
    use crate::accounting::governance::ParamChange;
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        let entries = [
            (
                "propagation_rate_limit_per_hour",
                "120",
                "240",
                "p-001",
                1700000000.0_f64,
            ),
            (
                "witness_reward_micros",
                "1000000",
                "2000000",
                "p-002",
                1700001000.0,
            ),
            (
                "stake_throughput_ratio",
                "100000",
                "200000",
                "p-003",
                1700002000.0,
            ),
        ];
        for (name, old, new, pid, ts) in entries {
            ledger.governance.param_changes.push(ParamChange {
                name: name.into(),
                old_value: old.into(),
                new_value: new.into(),
                proposal_id: pid.into(),
                applied_at: ts,
            });
        }
        // Sanity: the direct push leaves the params themselves unchanged
        // — total_changes wire field should reflect history len, NOT
        // the param values. (Future "did params actually change" axis is
        // a separate slice.)
    }

    let v = compute_governance_params(state).await;
    assert_eq!(
        v.get("total_changes").and_then(|x| x.as_u64()),
        Some(3),
        "total_changes MUST equal param_changes.len() = 3 — pins the Vec::len() \
             wire arithmetic against an off-by-one regression (e.g., a 'cached count' \
             that drifts from the actual vector)"
    );

    // Cross-axis check: the params themselves did NOT change (we only
    // pushed history records, not applied them). So the wire scalars
    // remain at defaults. This pins that `total_changes` is decoupled
    // from the parameter values — a regression that wired `total_changes`
    // to `params.propagation_rate_limit_per_hour` (or some other scalar)
    // would emit `120`, not `3`.
    assert_eq!(
        v.get("propagation_rate_limit_per_hour")
            .and_then(|x| x.as_u64()),
        Some(120),
        "propagation_rate_limit_per_hour MUST remain at default 120 — direct \
             param_changes.push() does NOT apply the change, so params stay at default. \
             This decouples the total_changes counter from the param scalars."
    );
    assert_eq!(
        v.get("stake_throughput_ratio").and_then(|x| x.as_u64()),
        Some(100_000_000),
        "stake_throughput_ratio MUST remain at default 100_000_000 — same decoupling \
             pin as propagation_rate_limit_per_hour above"
    );
}

// ─── compute_challenge_detail happy-path 13-key envelope ───
//
// Prior coverage of `compute_challenge_detail` (explorer.rs:3470):
//   - `batch_o_compute_challenge_detail_unknown_id_returns_in_band_error_json`
//     (explorer.rs:5606) — ONLY the None-branch (id not found) error
//     envelope is pinned.
//
// The Some-branch (happy path, 13-key full Challenge wire envelope at
// explorer.rs:3481-3495) is 100% UNPINNED. A regression that drops a
// key via `#[serde(skip_serializing_if)]`, mis-renders an enum, sorts
// the votes Vec, or hides Option fields on None would compile cleanly
// and silently break the explorer's challenge-detail page + account
// jury-voting flow. These 5 axes pin each regression class separately.
//
// All 5 tests reuse the existing `test_state()` + `stub_challenge()`
// helpers shared with the sibling challenge tests. The Option-fields axis (5) needs a
// custom inline Challenge construction (stub_challenge fixes the
// three Option fields to None) — kept inline rather than extending
// stub_challenge to preserve the existing test-fixture contract.

#[test]
fn batch_mmmm_compute_challenge_detail_happy_path_strict_thirteen_key_envelope_no_skip_if_regressions(
) {
    // Insert a stub challenge with stub-friendly defaults (all Option
    // fields = None, all Vec fields = empty). Assert that ALL 13 keys
    // are present in the JSON object — empty Vec + None Option emit as
    // present keys, NOT missing. Defends against a future regression
    // that adds `#[serde(skip_serializing_if = "Vec::is_empty")]` to
    // evidence/jury/votes OR `#[serde(skip_serializing_if = "Option::is_none")]`
    // to verdict/verdict_at/slash_amount. Note the helper builds JSON
    // MANUALLY via `serde_json::json!()` (NOT serde derive on Challenge),
    // so the skip_if directives wouldn't actually fire today — but a
    // refactor swapping to `serde_json::to_value(&challenge)` would
    // pick up the derive's skip_if attrs (e.g., the existing
    // `#[serde(default, skip_serializing_if = "Vec::is_empty")]` on
    // `structured_evidence` at fisherman.rs:148 — though structured_evidence
    // is NOT one of the 13 helper keys, the precedent shows skip_if is
    // already in the type's derive surface).
    let state = test_state();
    {
        let mut chs = state.challenges.write_recover();
        chs.challenges.insert(
            "c-mmmm-envelope".into(),
            stub_challenge(
                "c-mmmm-envelope",
                "accused-mmmm",
                crate::network::fisherman::ChallengeStatus::Filed,
                1700000000.0,
            ),
        );
    }
    let v = compute_challenge_detail(state, "c-mmmm-envelope".into());
    let obj = v
        .as_object()
        .expect("happy-path payload must be a JSON object, not an error envelope");
    // Strict 13-key check. Any extra key OR any missing key is a
    // regression vs the documented contract at explorer.rs:3481-3495.
    let expected_keys: std::collections::BTreeSet<&str> = [
        "id",
        "challenger",
        "accused",
        "challenge_type",
        "status",
        "filed_at",
        "evidence",
        "jury",
        "votes",
        "verdict",
        "verdict_at",
        "is_appeal",
        "slash_amount",
    ]
    .into_iter()
    .collect();
    let actual_keys: std::collections::BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
    assert_eq!(
        actual_keys, expected_keys,
        "compute_challenge_detail happy-path MUST emit exactly the 13 documented \
             keys — extra keys break account schema validators, missing keys break \
             dashboards reading e.g. `challenge.verdict === null` to detect pending state"
    );
    // Explicit shape check on the values that take defaults — these
    // would silently change shape under a `serde(skip_serializing_if)`
    // regression even if the key was preserved (e.g., turning the Vec
    // into an Option<Vec> with the empty value becoming null).
    assert!(
        obj["evidence"].is_array(),
        "evidence MUST be a JSON Array (defaults to empty `[]`), NOT null"
    );
    assert!(
        obj["jury"].is_array(),
        "jury MUST be a JSON Array (defaults to empty `[]`), NOT null"
    );
    assert!(
        obj["votes"].is_array(),
        "votes MUST be a JSON Array (defaults to empty `[]`), NOT null"
    );
}

#[test]
fn batch_mmmm_compute_challenge_detail_challenge_type_renders_snake_case_for_all_four_variants() {
    // The helper at explorer.rs:3485 calls `c.challenge_type.as_str()`
    // — the hand-written impl at fisherman.rs:81-88 maps each of the
    // 4 ChallengeType variants to a snake_case string:
    //   Spam              → "spam"
    //   FalseWitnessing   → "false_witnessing"
    //   DoubleSigning     → "double_signing"
    //   CartelFormation   → "cartel_formation"
    //
    // The ChallengeType enum does NOT carry `#[serde(rename_all = "snake_case")]`
    // (see fisherman.rs:55-68) — the wire form is ONLY produced via
    // `as_str()`, not serde. A regression that switched to
    // `serde_json::to_value(&c.challenge_type)` would emit Debug-form
    // PascalCase ("Spam", "FalseWitnessing", ...) on the FalseWitnessing /
    // DoubleSigning / CartelFormation cases — the Spam case alone
    // happens to be a single word that's PascalCase-lower-equivalent
    // to snake_case, so a single-variant test would silently miss the
    // multi-word regression. Pinning all 4 variants here forces every
    // case to surface.
    use crate::network::fisherman::ChallengeType;
    let cases = [
        (ChallengeType::Spam, "spam"),
        (ChallengeType::FalseWitnessing, "false_witnessing"),
        (ChallengeType::DoubleSigning, "double_signing"),
        (ChallengeType::CartelFormation, "cartel_formation"),
    ];
    let state = test_state();
    for (variant, expected) in cases.iter() {
        let id = format!("c-mmmm-ct-{expected}");
        {
            let mut chs = state.challenges.write_recover();
            chs.challenges.insert(
                id.clone(),
                crate::network::fisherman::Challenge {
                    id: id.clone(),
                    challenger: "ch-x".into(),
                    accused: "acc-x".into(),
                    challenge_type: variant.clone(),
                    evidence: Vec::new(),
                    structured_evidence: Vec::new(),
                    filed_at: 1700000000.0,
                    status: crate::network::fisherman::ChallengeStatus::Filed,
                    jury: Vec::new(),
                    votes: Vec::new(),
                    is_appeal: false,
                    verdict: None,
                    verdict_at: None,
                    slash_amount: None,
                },
            );
        }
        let v = compute_challenge_detail(state.clone(), id.clone());
        assert_eq!(
            v.get("challenge_type").and_then(|x| x.as_str()),
            Some(*expected),
            "challenge_type for {variant:?} MUST render as snake_case `{expected}` — \
                 a refactor to serde_json::to_value would emit Debug-form `{variant:?}` and \
                 break every operator script filtering by ?challenge_type=double_signing"
        );
    }
}

#[test]
fn batch_mmmm_compute_challenge_detail_status_renders_snake_case_for_all_six_variants() {
    // Mirror of axis 2 but on `ChallengeStatus` (6 variants vs 4).
    // The helper at explorer.rs:3486 calls `c.status.as_str()` — the
    // hand-written impl at fisherman.rs:110-119 maps:
    //   Filed       → "filed"
    //   JuryVoting  → "jury_voting"
    //   Verdict     → "verdict"
    //   Appeal      → "appeal"
    //   Final       → "final"
    //   Dismissed   → "dismissed"
    //
    // Unlike ChallengeType, ChallengeStatus DOES carry
    // `#[serde(rename_all = "snake_case")]` at fisherman.rs:92-94, so
    // a switch to serde-derived serialization would produce the same
    // wire form for these 6 variants. BUT a regression that swapped
    // to `format!("{:?}", c.status).to_lowercase()` (the OLD dispute
    // pattern, see compute_list_disputes at explorer.rs:2296) would
    // produce "juryvoting" (no underscore) — distinct from the
    // documented "jury_voting" form. Pinning the 6 wire-form strings
    // here defends against both regression directions on the same
    // helper.
    use crate::network::fisherman::ChallengeStatus;
    let cases = [
        (ChallengeStatus::Filed, "filed"),
        (ChallengeStatus::JuryVoting, "jury_voting"),
        (ChallengeStatus::Verdict, "verdict"),
        (ChallengeStatus::Appeal, "appeal"),
        (ChallengeStatus::Final, "final"),
        (ChallengeStatus::Dismissed, "dismissed"),
    ];
    let state = test_state();
    for (variant, expected) in cases.iter() {
        let id = format!("c-mmmm-st-{expected}");
        {
            let mut chs = state.challenges.write_recover();
            chs.challenges.insert(
                id.clone(),
                stub_challenge(&id, "acc-y", variant.clone(), 1700000001.0),
            );
        }
        let v = compute_challenge_detail(state.clone(), id.clone());
        assert_eq!(
            v.get("status").and_then(|x| x.as_str()),
            Some(*expected),
            "status for {variant:?} MUST render as snake_case `{expected}` — \
                 a refactor to `format!(\"{{:?}}\", ...).to_lowercase()` (the OLD \
                 dispute pattern) would silently drop the underscore on `JuryVoting`"
        );
    }
}

#[test]
fn batch_mmmm_compute_challenge_detail_votes_array_preserves_insertion_order_not_sorted() {
    // The helper at explorer.rs:3477-3479 builds the votes array via
    // `c.votes.iter().map(|v| ...)` — preserves Vec insertion order,
    // NO sort. Plant 3 JuryVotes with DELIBERATELY non-monotonic
    // timestamps and non-alphabetic juror IDs:
    //   votes[0]: juror="j-c", guilty=true,  timestamp=200.0  (latest)
    //   votes[1]: juror="j-a", guilty=false, timestamp=150.0  (middle)
    //   votes[2]: juror="j-b", guilty=true,  timestamp=100.0  (earliest)
    //
    // Insertion order: j-c (t=200), j-a (t=150), j-b (t=100).
    // Timestamp-asc order would be: j-b, j-a, j-c.
    // Timestamp-desc order would be: j-c, j-a, j-b.
    // Alphabetic-asc order would be: j-a, j-b, j-c.
    //
    // The expected wire order (insertion) is: j-c, j-a, j-b. A regression
    // that added `.sort_by_key(|v| v.timestamp)` would emit j-b first;
    // a regression that added `.sort_by_key(|v| v.juror.clone())` would
    // emit j-a first. Both are distinct from the insertion order, so
    // either regression class surfaces here. The jury-voting UI iterates
    // this Vec in submission order to render "vote #1 by j-c was guilty,
    // vote #2 by j-a was not guilty, vote #3 by j-b was guilty" — a
    // sort would scramble that chronological narrative AND silently
    // change which votes are highlighted as "the deciding ones."
    use crate::network::fisherman::{Challenge, ChallengeStatus, ChallengeType, JuryVote};
    let state = test_state();
    {
        let mut chs = state.challenges.write_recover();
        chs.challenges.insert(
            "c-mmmm-votes-order".into(),
            Challenge {
                id: "c-mmmm-votes-order".into(),
                challenger: "ch-z".into(),
                accused: "acc-z".into(),
                challenge_type: ChallengeType::DoubleSigning,
                evidence: Vec::new(),
                structured_evidence: Vec::new(),
                filed_at: 1700000000.0,
                status: ChallengeStatus::JuryVoting,
                jury: vec!["j-c".into(), "j-a".into(), "j-b".into()],
                votes: vec![
                    JuryVote {
                        juror: "j-c".into(),
                        guilty: true,
                        timestamp: 200.0,
                    },
                    JuryVote {
                        juror: "j-a".into(),
                        guilty: false,
                        timestamp: 150.0,
                    },
                    JuryVote {
                        juror: "j-b".into(),
                        guilty: true,
                        timestamp: 100.0,
                    },
                ],
                is_appeal: false,
                verdict: None,
                verdict_at: None,
                slash_amount: None,
            },
        );
    }
    let v = compute_challenge_detail(state, "c-mmmm-votes-order".into());
    let votes = v
        .get("votes")
        .and_then(|x| x.as_array())
        .expect("votes MUST be a JSON Array");
    assert_eq!(
        votes.len(),
        3,
        "all 3 inserted votes MUST appear in the wire"
    );
    // Insertion order: j-c (latest timestamp), j-a (middle), j-b (earliest).
    // Position 0 = j-c. A timestamp-asc sort would put j-b at [0]; an
    // alphabetic sort would put j-a at [0]; either regression fails here.
    assert_eq!(
        votes[0].get("juror").and_then(|x| x.as_str()),
        Some("j-c"),
        "votes[0].juror MUST be `j-c` (first INSERTED) — NOT `j-b` (timestamp-asc \
             regression) NOR `j-a` (alphabetic-asc regression)"
    );
    assert_eq!(
        votes[1].get("juror").and_then(|x| x.as_str()),
        Some("j-a"),
        "votes[1].juror MUST be `j-a` (second INSERTED)"
    );
    assert_eq!(
        votes[2].get("juror").and_then(|x| x.as_str()),
        Some("j-b"),
        "votes[2].juror MUST be `j-b` (third INSERTED, earliest timestamp)"
    );
    // Wire shape per vote: 3 keys exactly (juror, guilty, timestamp).
    // Pins that the JuryVote serialization at explorer.rs:3478 (via
    // `json!({ "juror": v.juror, "guilty": v.guilty, "timestamp": v.timestamp })`)
    // doesn't accidentally inherit additional fields from the JuryVote
    // struct (which has only 3 fields today at fisherman.rs:124-131,
    // but a future addition like `signature: Option<Vec<u8>>` would
    // silently appear in the wire unless this helper explicitly named
    // its 3 keys — which it does). Pin the boolean+number wire types
    // on votes[0] to defend against the "harmonize all bools to 0/1"
    // refactor regression on the same payload.
    assert!(
        votes[0].get("guilty").and_then(|x| x.as_bool()) == Some(true),
        "votes[0].guilty MUST be JSON Bool true (NOT 1/0)"
    );
    assert_eq!(
        votes[0].get("timestamp").and_then(|x| x.as_f64()),
        Some(200.0),
        "votes[0].timestamp MUST be JSON Number 200.0"
    );
}

#[test]
fn batch_mmmm_compute_challenge_detail_option_fields_emit_json_null_on_none_and_correct_types_on_some(
) {
    // Three fields are `Option<T>` on Challenge:
    //   verdict      : Option<bool>
    //   verdict_at   : Option<f64>
    //   slash_amount : Option<u64>
    //
    // The helper at explorer.rs:3491-3494 emits them via the
    // `serde_json::json!()` macro WITHOUT a `skip_serializing_if`
    // guard — so None becomes JSON `null`, Some(v) becomes the
    // underlying scalar.
    //
    // **None leg (Filed status)**: all three MUST be JSON Null, NOT
    // missing keys. A regression that wrapped them in
    // `if let Some(v) = c.verdict { result["verdict"] = json!(v); }`
    // would compile cleanly but silently drop the keys — breaking
    // every dashboard that reads `challenge.verdict === null` to
    // detect pending state (the absence-of-key form `'verdict' in
    // challenge` would still pass but the strict-equality JS check
    // would fail).
    //
    // **Some leg (Final status with verdict)**: paired wire-type pin.
    //   verdict      → JSON Bool      (NOT string "guilty"/"not_guilty")
    //   verdict_at   → JSON Number    (NOT ISO timestamp string)
    //   slash_amount → JSON u64       (NOT string for JS BigInt safety)
    //
    // A "harmonize all numbers to strings for JS BigInt safety" or
    // "verdict-as-enum-string" refactor regression surfaces here.
    use crate::network::fisherman::{Challenge, ChallengeStatus, ChallengeType};
    let state = test_state();

    // ── None leg ────────────────────────────────────────────────────
    {
        let mut chs = state.challenges.write_recover();
        chs.challenges.insert(
            "c-mmmm-none".into(),
            Challenge {
                id: "c-mmmm-none".into(),
                challenger: "ch-n".into(),
                accused: "acc-n".into(),
                challenge_type: ChallengeType::Spam,
                evidence: Vec::new(),
                structured_evidence: Vec::new(),
                filed_at: 1700000000.0,
                status: ChallengeStatus::Filed,
                jury: Vec::new(),
                votes: Vec::new(),
                is_appeal: false,
                verdict: None,
                verdict_at: None,
                slash_amount: None,
            },
        );
    }
    let v_none = compute_challenge_detail(state.clone(), "c-mmmm-none".into());
    let obj_none = v_none.as_object().expect("must be object");
    // Critical: the three keys MUST be PRESENT in the object with
    // JSON Null values, NOT missing keys. `contains_key` MUST return
    // true AND `is_null()` MUST return true.
    for k in ["verdict", "verdict_at", "slash_amount"].iter() {
        assert!(
            obj_none.contains_key(*k),
            "key `{k}` MUST be present in the object on the None leg — \
                 dropping the key on None would break dashboards reading the \
                 `=== null` form"
        );
        assert!(
            obj_none[*k].is_null(),
            "key `{k}` MUST be JSON Null on the None leg (NOT empty string, \
                 NOT zero, NOT missing)"
        );
    }

    // ── Some leg ────────────────────────────────────────────────────
    {
        let mut chs = state.challenges.write_recover();
        chs.challenges.insert(
            "c-mmmm-some".into(),
            Challenge {
                id: "c-mmmm-some".into(),
                challenger: "ch-s".into(),
                accused: "acc-s".into(),
                challenge_type: ChallengeType::CartelFormation,
                evidence: Vec::new(),
                structured_evidence: Vec::new(),
                filed_at: 1700000000.0,
                status: ChallengeStatus::Final,
                jury: Vec::new(),
                votes: Vec::new(),
                is_appeal: false,
                verdict: Some(true),
                verdict_at: Some(1700000123.5),
                slash_amount: Some(50_000_000_u64),
            },
        );
    }
    let v_some = compute_challenge_detail(state, "c-mmmm-some".into());
    // Paired wire-type pin on the Some leg.
    assert_eq!(
        v_some.get("verdict").and_then(|x| x.as_bool()),
        Some(true),
        "verdict MUST be JSON Bool on Some — NOT a string like \"guilty\""
    );
    assert_eq!(
        v_some.get("verdict_at").and_then(|x| x.as_f64()),
        Some(1700000123.5),
        "verdict_at MUST be JSON Number (f64) on Some — NOT an ISO timestamp string"
    );
    assert_eq!(
        v_some.get("slash_amount").and_then(|x| x.as_u64()),
        Some(50_000_000_u64),
        "slash_amount MUST be JSON Number (u64) on Some — NOT a string for JS \
             BigInt safety; a `harmonize-large-numbers-to-strings` refactor would surface here"
    );
    // Cross-axis: is_appeal stays JSON Bool on the same payload (defends
    // against a paired "all bools to 0/1" regression that would silently
    // flip is_appeal AND verdict together).
    assert!(
        v_some.get("is_appeal").and_then(|x| x.as_bool()) == Some(false),
        "is_appeal MUST remain JSON Bool on the Some leg payload"
    );
}

// ─── compute_governance_delegations tests ──
//
// 5 axes orthogonal to the existing PQ-router empty-state probe at
// src/network/pq_transport/router.rs:4817 (4 keys pinned, no stake or
// delegator semantics) AND orthogonal to each other:
//   (1) 5-key top-level envelope + wire-type pins on every field
//       — present-with-null pin on delegated_from_me Option key
//   (2) delegated_from_me Option<{delegate, created_at}> JSON-null vs
//       2-key Object semantics
//   (3) delegated_to_me 3-key sub-envelope + per-DELEGATOR stake lookup
//       (NOT per-identity-being-queried)
//   (4) total_effective_stake = own + Σ delegators-gov-stakes; witness-
//       purpose stake on a delegator contributes 0; non-delegator
//       governance stakes excluded
//   (5) inactive delegations excluded from BOTH directions (delegators_
//       for active-filter at governance.rs:1163 + delegation_of active-
//       filter at governance.rs:1168)
//
// Test-fixture pattern: all 5 use existing test_state() helper at :3746.
// No process-global cache constraint — ledger.governance/ledger.stakes
// are per-NodeState — no test-gate Mutex needed.

#[tokio::test]
async fn batch_tttt_compute_governance_delegations_empty_state_envelope_shape_and_wire_types() {
    // Axis 1: 5-key top-level envelope {identity, own_governance_stake,
    // delegated_to_me, delegated_from_me, total_effective_stake} +
    // wire-type pins on EVERY field — BTreeSet symmetric-difference
    // makes a key-add or key-remove a hard fail. Defends:
    // (a) skip_serializing_if on the Option<delegated_from_me> field
    //     turning JSON null into a dropped key (accounts calling
    //     `body.delegated_from_me === null` would crash on undefined);
    // (b) refactor renaming the cursor to e.g. `delegate_outgoing` for
    //     "schema modernization";
    // (c) numeric-to-string flip on the two stake-sum u64 surfaces
    //     (own_governance_stake + total_effective_stake).
    let state = test_state();
    let v = compute_governance_delegations(state, "tttt-axis-1-identity".to_string(), None).await;

    let obj = v.as_object().expect("envelope MUST be a JSON object");
    let actual_keys: std::collections::BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
    let expected_keys: std::collections::BTreeSet<&str> = [
        "identity",
        "own_governance_stake",
        "delegated_to_me",
        "delegated_to_me_count",
        "delegated_from_me",
        "total_effective_stake",
    ]
    .iter()
    .copied()
    .collect();
    let missing: Vec<&&str> = expected_keys.difference(&actual_keys).collect();
    let extra: Vec<&&str> = actual_keys.difference(&expected_keys).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "envelope key mismatch: missing={missing:?}, extra={extra:?}",
    );

    assert!(v["identity"].is_string(), "identity MUST be JSON string");
    assert_eq!(v["identity"].as_str(), Some("tttt-axis-1-identity"));
    assert!(
        v["own_governance_stake"].is_u64(),
        "own_governance_stake MUST be JSON u64"
    );
    assert_eq!(
        v["own_governance_stake"].as_u64(),
        Some(0),
        "empty state → 0 own stake"
    );
    assert!(
        v["delegated_to_me"].is_array(),
        "delegated_to_me MUST be JSON Array (NOT object, NOT null)"
    );
    assert_eq!(
        v["delegated_to_me"].as_array().map(|a| a.len()),
        Some(0),
        "empty state → 0 incoming delegations"
    );
    assert!(
        v["delegated_to_me_count"].is_u64(),
        "delegated_to_me_count MUST be JSON u64 (TRUE incoming count for truncation detection)"
    );
    assert_eq!(
        v["delegated_to_me_count"].as_u64(),
        Some(0),
        "empty state → 0 incoming delegation count"
    );
    assert!(
        v["delegated_from_me"].is_null(),
        "delegated_from_me MUST be JSON null on no-outgoing — defends against \
             skip_serializing_if dropping the key (accounts reading body \
             .delegated_from_me === null would crash on undefined)"
    );
    assert!(
        obj.contains_key("delegated_from_me"),
        "delegated_from_me key MUST be PRESENT-with-null on empty state"
    );
    assert!(
        v["total_effective_stake"].is_u64(),
        "total_effective_stake MUST be JSON u64"
    );
    assert_eq!(
        v["total_effective_stake"].as_u64(),
        Some(0),
        "empty state → 0 effective stake"
    );
}

#[tokio::test]
async fn batch_tttt_compute_governance_delegations_limit_truncates_array_count_and_sum_over_all() {
    // SCALE-RULE page bound: with 3 inbound delegators and limit=2 the
    // `delegated_to_me` array caps to 2, but `delegated_to_me_count` reports the
    // TRUE 3 AND `total_effective_stake` sums over ALL 3 delegators (+ own) —
    // NOT just the serialized page. A naive truncate-then-sum would under-count
    // voting power; this pins sum-and-count BEFORE truncate.
    let state = test_state();
    let judge = "tttt-limit-judge";
    {
        let mut ledger = state.ledger.write().await;
        use crate::accounting::governance::DelegationEntry;
        use crate::accounting::ledger::StakeEntry;
        use crate::accounting::types::StakePurpose;
        for (i, amount) in [("a", 1000u64), ("b", 2000), ("c", 3000)] {
            let who = format!("tttt-limit-{i}");
            ledger.governance.delegations.insert(
                who.clone(),
                DelegationEntry {
                    delegator: who.clone(),
                    delegate: judge.into(),
                    created_at: 1_700_000_000.0,
                    active: true,
                },
            );
            ledger.stakes.insert(
                format!("{who}-gov"),
                StakeEntry {
                    record_id: format!("{who}-gov"),
                    amount,
                    purpose: StakePurpose::Governance,
                    staker: who,
                    timestamp: 1_700_000_000.0,
                    active: true,
                },
            );
        }
    }
    let v = compute_governance_delegations(state, judge.to_string(), Some(2)).await;

    let incoming = v["delegated_to_me"].as_array().expect("delegated_to_me array");
    assert_eq!(incoming.len(), 2, "limit=2 MUST cap delegated_to_me to 2 entries");
    assert_eq!(
        v["delegated_to_me_count"].as_u64(),
        Some(3),
        "delegated_to_me_count MUST be the TRUE inbound count (3), not the page length (2)",
    );
    assert_eq!(
        v["total_effective_stake"].as_u64(),
        Some(6000),
        "total_effective_stake MUST sum ALL 3 delegators (1000+2000+3000), not just the 2-entry page (judge own stake = 0)",
    );
}

#[tokio::test]
async fn batch_tttt_compute_governance_delegations_delegated_from_me_option_some_vs_none_branch_diverges(
) {
    // Axis 2: delegated_from_me carries Option<{delegate, created_at}>
    // serde semantics — JSON null when None, 2-key Object when Some.
    // The two branches diverge in JSON SHAPE, not just value. Defends
    // a refactor to `.unwrap_or_else(|| serde_json::json!({}))` that
    // would silently flip JSON null → {} on the None leg (a account
    // checking `body.delegated_from_me === null` would crash on a
    // truthy {} object).
    let state = test_state();
    let identity = "tttt-axis-2-identity";
    // Plant one OUTGOING delegation: identity → judge with a fractional
    // created_at (1_700_000_777.25) so the f64 wire-type pin can't be
    // satisfied by an integer-coercion serializer fallback.
    {
        let mut ledger = state.ledger.write().await;
        use crate::accounting::governance::DelegationEntry;
        ledger.governance.delegations.insert(
            identity.into(),
            DelegationEntry {
                delegator: identity.into(),
                delegate: "tttt-axis-2-judge".into(),
                created_at: 1_700_000_777.25,
                active: true,
            },
        );
    }
    let v = compute_governance_delegations(state.clone(), identity.to_string(), None).await;

    // Some-leg shape: MUST be a 2-key Object {delegate, created_at}.
    assert!(
        v["delegated_from_me"].is_object(),
        "delegated_from_me MUST be JSON Object on Some leg"
    );
    let outgoing = v["delegated_from_me"]
        .as_object()
        .expect("outgoing MUST be object");
    let outgoing_keys: std::collections::BTreeSet<&str> =
        outgoing.keys().map(|s| s.as_str()).collect();
    let expected_outgoing: std::collections::BTreeSet<&str> =
        ["delegate", "created_at"].iter().copied().collect();
    let missing: Vec<&&str> = expected_outgoing.difference(&outgoing_keys).collect();
    let extra: Vec<&&str> = outgoing_keys.difference(&expected_outgoing).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "outgoing sub-envelope key mismatch: missing={missing:?}, extra={extra:?} \
             — a refactor that re-emitted the delegator field, or stripped \
             created_at to save bytes, would surface here",
    );
    assert_eq!(
        v["delegated_from_me"]["delegate"].as_str(),
        Some("tttt-axis-2-judge")
    );
    assert!(
        v["delegated_from_me"]["created_at"].is_number(),
        "created_at MUST be JSON Number (NOT ISO-string)"
    );
    assert_eq!(
        v["delegated_from_me"]["created_at"].as_f64(),
        Some(1_700_000_777.25),
        "created_at MUST round-trip the source f64 value byte-faithfully"
    );

    // None-leg shape on a DIFFERENT identity (one with NO outgoing
    // delegation) MUST be JSON null — this is the load-bearing pin for
    // the Option<Value> serde branch divergence.
    let v_none =
        compute_governance_delegations(state.clone(), "tttt-axis-2-noone".to_string(), None).await;
    assert!(
        v_none["delegated_from_me"].is_null(),
        "delegated_from_me MUST be JSON null when no outgoing delegation \
             exists — NOT empty {{}}, NOT empty array, NOT absent key"
    );
}

#[tokio::test]
async fn batch_tttt_compute_governance_delegations_delegated_to_me_per_delegator_stake_lookup() {
    // Axis 3: 3-key per-incoming sub-envelope {delegator, stake,
    // created_at} pin + stake is looked up PER-DELEGATOR (NOT per-
    // identity-being-queried). Plant 2 delegators with DIFFERENT
    // governance stakes both delegating to judge; each element's stake
    // field MUST reflect its OWN delegator's stake, NOT the judge's
    // stake. A regression swapping `&d.delegator` for `&identity` at
    // explorer.rs:1121 would conflate all rows to the judge's stake
    // and silently break the "delegator X is granting you Y beat of
    // voting power" UX.
    let state = test_state();
    let judge = "tttt-axis-3-judge";
    {
        let mut ledger = state.ledger.write().await;
        use crate::accounting::governance::DelegationEntry;
        use crate::accounting::ledger::StakeEntry;
        use crate::accounting::types::StakePurpose;
        // alice → judge, gov-stake = 1000.
        ledger.governance.delegations.insert(
            "tttt-axis-3-alice".into(),
            DelegationEntry {
                delegator: "tttt-axis-3-alice".into(),
                delegate: judge.into(),
                created_at: 1_700_000_001.0,
                active: true,
            },
        );
        ledger.stakes.insert(
            "tttt-axis-3-alice-gov".into(),
            StakeEntry {
                record_id: "tttt-axis-3-alice-gov".into(),
                amount: 1000,
                purpose: StakePurpose::Governance,
                staker: "tttt-axis-3-alice".into(),
                timestamp: 1_700_000_000.0,
                active: true,
            },
        );
        // bob → judge, gov-stake = 2000.
        ledger.governance.delegations.insert(
            "tttt-axis-3-bob".into(),
            DelegationEntry {
                delegator: "tttt-axis-3-bob".into(),
                delegate: judge.into(),
                created_at: 1_700_000_002.0,
                active: true,
            },
        );
        ledger.stakes.insert(
            "tttt-axis-3-bob-gov".into(),
            StakeEntry {
                record_id: "tttt-axis-3-bob-gov".into(),
                amount: 2000,
                purpose: StakePurpose::Governance,
                staker: "tttt-axis-3-bob".into(),
                timestamp: 1_700_000_000.0,
                active: true,
            },
        );
        // judge own gov-stake = 9_999_999 — markedly different from
        // either delegator's stake so the per-identity regression
        // surfaces as 9_999_999 leaking into both rows.
        ledger.stakes.insert(
            "tttt-axis-3-judge-gov".into(),
            StakeEntry {
                record_id: "tttt-axis-3-judge-gov".into(),
                amount: 9_999_999,
                purpose: StakePurpose::Governance,
                staker: judge.into(),
                timestamp: 1_700_000_000.0,
                active: true,
            },
        );
    }
    let v = compute_governance_delegations(state, judge.to_string(), None).await;
    let incoming = v["delegated_to_me"]
        .as_array()
        .expect("delegated_to_me is array");
    assert_eq!(
        incoming.len(),
        2,
        "MUST surface both active delegators (alice + bob)"
    );

    // 3-key sub-envelope pin on each element via BTreeSet equality.
    let expected_in: std::collections::BTreeSet<&str> = ["delegator", "stake", "created_at"]
        .iter()
        .copied()
        .collect();
    for entry in incoming {
        let entry_keys: std::collections::BTreeSet<&str> = entry
            .as_object()
            .expect("entry MUST be object")
            .keys()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(
            entry_keys, expected_in,
            "incoming sub-envelope MUST be exactly {{delegator, stake, created_at}}"
        );
    }
    // Find alice's row by delegator-name and pin stake = 1000.
    let alice_row = incoming
        .iter()
        .find(|e| e["delegator"].as_str() == Some("tttt-axis-3-alice"))
        .expect("alice row MUST surface");
    assert_eq!(
        alice_row["stake"].as_u64(),
        Some(1000),
        "alice's row MUST carry alice's governance stake (1000), \
             NOT judge's (9_999_999) — a regression swapping per-delegator \
             lookup for per-identity would surface here as 9_999_999"
    );
    // Find bob's row and pin stake = 2000.
    let bob_row = incoming
        .iter()
        .find(|e| e["delegator"].as_str() == Some("tttt-axis-3-bob"))
        .expect("bob row MUST surface");
    assert_eq!(
        bob_row["stake"].as_u64(),
        Some(2000),
        "bob's row MUST carry bob's governance stake (2000), \
             NOT judge's (9_999_999)"
    );
    // Cross-axis: per-row created_at values are insertion-faithful (NOT
    // a single 0.0 default leaking through, NOT swapped to the
    // queried-identity's row).
    assert_eq!(alice_row["created_at"].as_f64(), Some(1_700_000_001.0));
    assert_eq!(bob_row["created_at"].as_f64(), Some(1_700_000_002.0));
}

#[tokio::test]
async fn batch_tttt_compute_governance_delegations_total_effective_stake_excludes_witness_purpose_and_non_delegators(
) {
    // Axis 4: total_effective_stake = own_governance_stake + Σ
    // delegators' governance stakes. Pin the arithmetic AND two
    // distinct filtering predicates:
    //  (i) delegator's stake lookup goes through governance_stake_for
    //      which filters by `purpose == StakePurpose::Governance` —
    //      witness-purpose stake on a delegator MUST contribute 0;
    //  (ii) only delegators-to-judge contribute — a non-delegator's
    //       governance stake MUST NOT leak.
    //
    // The bug-class this pins: a refactor at explorer.rs:1131 swapping
    // the `incoming.iter().filter_map(|d| d["stake"].as_u64()).sum()`
    // to a raw `ledger.stakes.values().filter(...).sum()` would let
    // both witness-purpose stake AND non-delegator governance stake
    // leak into the effective-power total.
    let state = test_state();
    let judge = "tttt-axis-4-judge";
    {
        let mut ledger = state.ledger.write().await;
        use crate::accounting::governance::DelegationEntry;
        use crate::accounting::ledger::StakeEntry;
        use crate::accounting::types::StakePurpose;
        // judge own governance stake = 5000.
        ledger.stakes.insert(
            "tttt-axis-4-judge-gov".into(),
            StakeEntry {
                record_id: "tttt-axis-4-judge-gov".into(),
                amount: 5000,
                purpose: StakePurpose::Governance,
                staker: judge.into(),
                timestamp: 1_700_000_000.0,
                active: true,
            },
        );
        // alice → judge, gov-stake = 1000 → contributes 1000.
        ledger.governance.delegations.insert(
            "tttt-axis-4-alice".into(),
            DelegationEntry {
                delegator: "tttt-axis-4-alice".into(),
                delegate: judge.into(),
                created_at: 1_700_000_001.0,
                active: true,
            },
        );
        ledger.stakes.insert(
            "tttt-axis-4-alice-gov".into(),
            StakeEntry {
                record_id: "tttt-axis-4-alice-gov".into(),
                amount: 1000,
                purpose: StakePurpose::Governance,
                staker: "tttt-axis-4-alice".into(),
                timestamp: 1_700_000_000.0,
                active: true,
            },
        );
        // bob → judge, gov-stake = 2000 → contributes 2000.
        ledger.governance.delegations.insert(
            "tttt-axis-4-bob".into(),
            DelegationEntry {
                delegator: "tttt-axis-4-bob".into(),
                delegate: judge.into(),
                created_at: 1_700_000_002.0,
                active: true,
            },
        );
        ledger.stakes.insert(
            "tttt-axis-4-bob-gov".into(),
            StakeEntry {
                record_id: "tttt-axis-4-bob-gov".into(),
                amount: 2000,
                purpose: StakePurpose::Governance,
                staker: "tttt-axis-4-bob".into(),
                timestamp: 1_700_000_000.0,
                active: true,
            },
        );
        // dave → judge, but dave's stake is WITNESS-purpose, NOT
        // governance → contributes 0, NOT 8888.
        ledger.governance.delegations.insert(
            "tttt-axis-4-dave".into(),
            DelegationEntry {
                delegator: "tttt-axis-4-dave".into(),
                delegate: judge.into(),
                created_at: 1_700_000_003.0,
                active: true,
            },
        );
        ledger.stakes.insert(
            "tttt-axis-4-dave-witness".into(),
            StakeEntry {
                record_id: "tttt-axis-4-dave-witness".into(),
                amount: 8888,
                purpose: StakePurpose::Witness,
                staker: "tttt-axis-4-dave".into(),
                timestamp: 1_700_000_000.0,
                active: true,
            },
        );
        // charlie has governance stake but does NOT delegate to judge
        // → MUST NOT contribute (cross-axis pin against a regression
        // summing ALL governance stakes instead of only delegators-to-
        // judge).
        ledger.stakes.insert(
            "tttt-axis-4-charlie-gov".into(),
            StakeEntry {
                record_id: "tttt-axis-4-charlie-gov".into(),
                amount: 999,
                purpose: StakePurpose::Governance,
                staker: "tttt-axis-4-charlie".into(),
                timestamp: 1_700_000_000.0,
                active: true,
            },
        );
    }
    let v = compute_governance_delegations(state, judge.to_string(), None).await;
    assert_eq!(
        v["own_governance_stake"].as_u64(),
        Some(5000),
        "own_governance_stake MUST surface judge's gov-stake (5000)"
    );
    // All 3 active delegators surface (alice, bob, dave) even though
    // dave's stake contribution is 0.
    assert_eq!(
        v["delegated_to_me"].as_array().map(|a| a.len()),
        Some(3),
        "delegated_to_me MUST surface ALL 3 active delegators even when \
             dave's contribution is 0 (delegation existence ≠ stake gating)"
    );
    // total = 5000 + 1000 + 2000 + 0 = 8000. NOT 16888 (would include
    // dave's 8888 witness-stake), NOT 8999 (would include charlie's
    // 999 non-delegator gov-stake), NOT 5000 (would mean delegator
    // stakes weren't summed at all).
    assert_eq!(
            v["total_effective_stake"].as_u64(),
            Some(8000),
            "total_effective_stake MUST equal 5000(judge)+1000(alice)+2000(bob)+0(dave-witness) = 8000. \
             dave's 8888 witness-stake MUST be excluded (governance_stake_for \
             filters by purpose); charlie's 999 MUST be excluded (not a \
             delegator-to-judge)"
        );
    // Cross-axis pin: dave's stake field in delegated_to_me is 0 (not
    // 8888) — surfaces the per-delegator filtering at the per-row
    // level (axis 3 pins per-delegator lookup; this pins the witness-
    // exclusion within that lookup).
    let dave_row = v["delegated_to_me"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["delegator"].as_str() == Some("tttt-axis-4-dave"))
        .expect("dave row MUST surface even with 0 stake");
    assert_eq!(
        dave_row["stake"].as_u64(),
        Some(0),
        "dave's row stake MUST be 0 (witness-purpose excluded), NOT 8888"
    );
}

#[tokio::test]
async fn batch_tttt_compute_governance_delegations_inactive_excluded_both_directions() {
    // Axis 5: inactive delegations are excluded from BOTH directions —
    // delegators_for() filters `.active && .delegate == X` (incoming),
    // and delegation_of() filters `.active` (outgoing). Plant ALL
    // THREE: an active incoming, an inactive incoming, and an inactive
    // outgoing.
    //
    // Expected:
    //  (a) delegated_to_me has EXACTLY 1 entry (active alice→judge);
    //      bob→judge is inactive and MUST NOT surface;
    //  (b) delegated_from_me is JSON null (judge→eve is inactive —
    //      would surface as Some(...) if delegation_of leaked inactive
    //      entries);
    //  (c) total_effective_stake = judge_own + alice_stake ONLY; bob's
    //      stake (would be 2000) MUST NOT contribute.
    //
    // The bug-class this pins: a refactor at governance.rs:1163
    // flipping `.filter(|d| d.active && d.delegate == delegate)` to
    // `.filter(|d| d.delegate == delegate)` would surface bob's
    // inactive row — silently re-enable revoked voting power.
    let state = test_state();
    let judge = "tttt-axis-5-judge";
    {
        let mut ledger = state.ledger.write().await;
        use crate::accounting::governance::DelegationEntry;
        use crate::accounting::ledger::StakeEntry;
        use crate::accounting::types::StakePurpose;
        // judge own gov-stake = 5000.
        ledger.stakes.insert(
            "tttt-axis-5-judge-gov".into(),
            StakeEntry {
                record_id: "tttt-axis-5-judge-gov".into(),
                amount: 5000,
                purpose: StakePurpose::Governance,
                staker: judge.into(),
                timestamp: 1_700_000_000.0,
                active: true,
            },
        );
        // alice → judge (ACTIVE) — MUST surface; stake = 1000.
        ledger.governance.delegations.insert(
            "tttt-axis-5-alice".into(),
            DelegationEntry {
                delegator: "tttt-axis-5-alice".into(),
                delegate: judge.into(),
                created_at: 1_700_000_001.0,
                active: true,
            },
        );
        ledger.stakes.insert(
            "tttt-axis-5-alice-gov".into(),
            StakeEntry {
                record_id: "tttt-axis-5-alice-gov".into(),
                amount: 1000,
                purpose: StakePurpose::Governance,
                staker: "tttt-axis-5-alice".into(),
                timestamp: 1_700_000_000.0,
                active: true,
            },
        );
        // bob → judge (INACTIVE) — MUST NOT surface; bob's 2000 stake
        // MUST NOT contribute to total.
        ledger.governance.delegations.insert(
            "tttt-axis-5-bob".into(),
            DelegationEntry {
                delegator: "tttt-axis-5-bob".into(),
                delegate: judge.into(),
                created_at: 1_700_000_002.0,
                active: false,
            },
        );
        ledger.stakes.insert(
            "tttt-axis-5-bob-gov".into(),
            StakeEntry {
                record_id: "tttt-axis-5-bob-gov".into(),
                amount: 2000,
                purpose: StakePurpose::Governance,
                staker: "tttt-axis-5-bob".into(),
                timestamp: 1_700_000_000.0,
                active: true,
            },
        );
        // judge → eve (INACTIVE) — delegation_of(judge) MUST return
        // None, so delegated_from_me MUST be JSON null.
        ledger.governance.delegations.insert(
            judge.into(),
            DelegationEntry {
                delegator: judge.into(),
                delegate: "tttt-axis-5-eve".into(),
                created_at: 1_700_000_003.0,
                active: false,
            },
        );
    }
    let v = compute_governance_delegations(state, judge.to_string(), None).await;
    // (a) Only alice's active delegation surfaces in delegated_to_me.
    let incoming = v["delegated_to_me"]
        .as_array()
        .expect("delegated_to_me is array");
    assert_eq!(
        incoming.len(),
        1,
        "MUST exclude bob's inactive delegation from delegated_to_me"
    );
    assert_eq!(
        incoming[0]["delegator"].as_str(),
        Some("tttt-axis-5-alice"),
        "the sole surviving row MUST be alice (the ACTIVE delegator)"
    );
    // (b) delegated_from_me is JSON null even though delegations[judge]
    // exists in the HashMap — delegation_of's active-filter is the
    // load-bearing predicate.
    assert!(
        v["delegated_from_me"].is_null(),
        "delegated_from_me MUST be JSON null when judge's outgoing \
             delegation is inactive — delegation_of MUST filter `.active`. \
             A regression dropping the active-filter at governance.rs:1169 \
             would surface judge→eve here"
    );
    // (c) total = 5000 (own) + 1000 (alice) ONLY. bob's 2000 MUST be
    // excluded since his delegation is inactive.
    assert_eq!(
        v["total_effective_stake"].as_u64(),
        Some(6000),
        "total_effective_stake MUST equal 5000(judge)+1000(alice) = 6000. \
             bob's 2000 MUST NOT contribute (inactive delegation \
             excluded from delegators_for)"
    );
}

// ─── §11.18 Slice 3 — compute_upgrade_outcomes
// and compute_upgrade_outcome_detail orthogonal pins
//
// Slice 3 surfaces the Slice-2-shipped `GovernanceState.upgrade_outcomes`
// HashMap via two GET routes. Axes that distinguish a correct
// implementation from a regression:
//
//   (1) Empty state — list endpoint MUST emit the strict 4-key envelope
//       {outcomes, total, limit, offset} with outcomes=[], total=0,
//       limit=50, offset=0. A regression that drops `total` (clients
//       can count) or adds HATEOAS links would break account pagination.
//   (2) Single outcome — list contains the record with all 8 fields
//       (proposal_id, kind, reference_impl_hash, proposed_at_epoch,
//       outcome, for_ratio, transition_deadline_secs, recorded_at_ts).
//       Pins the wire shape against silent field renames/drops in
//       UpgradeOutcomeRecord (which has snake_case wire names — a
//       refactor swapping to camelCase via #[serde(rename_all=…)] would
//       break the explorer + any Slice-4 indexer reading this).
//   (3) Multi-outcome sort — DESCENDING by recorded_at_ts (newest
//       first). Regression to ascending would surface stale outcomes
//       at the top of operator dashboards.
//   (4) Pagination — limit/offset both honored; total reflects
//       UNFILTERED count (no filter in this endpoint, but the total
//       must NOT be the post-slice count).
//   (5) Detail by proposal_id — returns the record JSON when present.
//   (6) Detail missing → ElaraError::Governance with the proposal_id
//       NAMED in the error message so operators can correlate to the
//       UI's "no outcome recorded" empty-state.

fn batch_iiiii_mk_outcome(
    proposal_id: &str,
    recorded_at_ts: f64,
    outcome: &str,
    for_ratio: Option<f64>,
    transition_deadline_secs: Option<u64>,
) -> crate::accounting::governance::UpgradeOutcomeRecord {
    crate::accounting::governance::UpgradeOutcomeRecord {
        proposal_id: proposal_id.into(),
        kind: "soft_fork".into(),
        reference_impl_hash: format!("hash-for-{proposal_id}"),
        proposed_at_epoch: 100,
        outcome: outcome.into(),
        for_ratio,
        transition_deadline_secs,
        recorded_at_ts,
    }
}

#[tokio::test]
async fn batch_iiiii_compute_upgrade_outcomes_empty_state_emits_strict_four_key_envelope() {
    let state = test_state();
    let v = compute_upgrade_outcomes(state, None, None).await;

    let obj = v.as_object().expect("top-level MUST be JSON Object");
    let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["limit", "offset", "outcomes", "total"],
        "envelope MUST emit EXACTLY 4 keys — pins wire shape against \
             silent additions on /governance/upgrade_outcomes",
    );
    assert!(
        v["outcomes"].as_array().expect("outcomes array").is_empty(),
        "fresh-state outcomes array MUST be empty"
    );
    assert_eq!(v["total"].as_u64(), Some(0), "total MUST be 0");
    assert_eq!(v["limit"].as_u64(), Some(50), "default limit MUST be 50");
    assert_eq!(v["offset"].as_u64(), Some(0), "default offset MUST be 0");
}

#[tokio::test]
async fn batch_iiiii_compute_upgrade_outcomes_single_record_serializes_all_eight_fields() {
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        ledger.governance.upgrade_outcomes.insert(
            "prop-1".into(),
            batch_iiiii_mk_outcome("prop-1", 1_700_000_000.0, "passed", None, Some(7 * 86400)),
        );
    }
    let v = compute_upgrade_outcomes(state, None, None).await;
    assert_eq!(v["total"].as_u64(), Some(1));
    let outcomes = v["outcomes"].as_array().expect("outcomes array");
    assert_eq!(outcomes.len(), 1, "single record MUST surface in list");

    // Pin the strict 8-field wire shape — any serde rename or field
    // drop in UpgradeOutcomeRecord would surface here.
    let entry = &outcomes[0];
    let obj = entry.as_object().expect("entry MUST be JSON Object");
    let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "for_ratio",
            "kind",
            "outcome",
            "proposal_id",
            "proposed_at_epoch",
            "recorded_at_ts",
            "reference_impl_hash",
            "transition_deadline_secs",
        ],
        "per-record envelope MUST emit EXACTLY 8 snake_case fields"
    );
    assert_eq!(entry["proposal_id"].as_str(), Some("prop-1"));
    assert_eq!(entry["kind"].as_str(), Some("soft_fork"));
    assert_eq!(entry["outcome"].as_str(), Some("passed"));
    assert_eq!(entry["proposed_at_epoch"].as_u64(), Some(100));
    assert_eq!(entry["transition_deadline_secs"].as_u64(), Some(7 * 86400));
    assert!(
        entry["for_ratio"].is_null(),
        "Passed outcome has no for_ratio"
    );
}

#[tokio::test]
async fn batch_iiiii_compute_upgrade_outcomes_multi_record_sorts_newest_first() {
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        // Insert in arbitrary order; the sort must reorder newest-first.
        ledger.governance.upgrade_outcomes.insert(
            "old".into(),
            batch_iiiii_mk_outcome("old", 100.0, "passed", None, Some(86400)),
        );
        ledger.governance.upgrade_outcomes.insert(
            "newest".into(),
            batch_iiiii_mk_outcome("newest", 300.0, "active", None, None),
        );
        ledger.governance.upgrade_outcomes.insert(
            "middle".into(),
            batch_iiiii_mk_outcome("middle", 200.0, "failed", Some(0.4), None),
        );
    }
    let v = compute_upgrade_outcomes(state, None, None).await;
    let outcomes = v["outcomes"].as_array().expect("outcomes array");
    assert_eq!(outcomes.len(), 3);
    assert_eq!(
        outcomes[0]["proposal_id"].as_str(),
        Some("newest"),
        "newest by recorded_at_ts MUST come first"
    );
    assert_eq!(outcomes[1]["proposal_id"].as_str(), Some("middle"));
    assert_eq!(
        outcomes[2]["proposal_id"].as_str(),
        Some("old"),
        "oldest MUST come last"
    );
    // Failed-outcome pin: for_ratio is Some, transition_deadline is None.
    assert_eq!(outcomes[1]["for_ratio"].as_f64(), Some(0.4));
    assert!(outcomes[1]["transition_deadline_secs"].is_null());
}

#[tokio::test]
async fn batch_iiiii_compute_upgrade_outcomes_pagination_respects_limit_and_offset() {
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        for i in 0..5 {
            let id = format!("p-{i}");
            ledger.governance.upgrade_outcomes.insert(
                id.clone(),
                batch_iiiii_mk_outcome(&id, i as f64, "passed", None, Some(86400)),
            );
        }
    }
    // limit=2, offset=1 — skip newest, return next 2.
    let v = compute_upgrade_outcomes(state, Some(2), Some(1)).await;
    assert_eq!(
        v["total"].as_u64(),
        Some(5),
        "total MUST reflect FULL count, not page size"
    );
    assert_eq!(v["limit"].as_u64(), Some(2));
    assert_eq!(v["offset"].as_u64(), Some(1));
    let outcomes = v["outcomes"].as_array().expect("outcomes array");
    assert_eq!(outcomes.len(), 2, "page size MUST honor limit");
    // Newest-first order with offset=1 means we skip p-4 (recorded_at_ts=4)
    // and surface p-3 (ts=3), p-2 (ts=2).
    assert_eq!(outcomes[0]["proposal_id"].as_str(), Some("p-3"));
    assert_eq!(outcomes[1]["proposal_id"].as_str(), Some("p-2"));
}

#[tokio::test]
async fn batch_iiiii_compute_upgrade_outcome_detail_existing_proposal_returns_record_json() {
    let state = test_state();
    {
        let mut ledger = state.ledger.write().await;
        ledger.governance.upgrade_outcomes.insert(
            "found-id".into(),
            batch_iiiii_mk_outcome("found-id", 1234.5, "passed", None, Some(14 * 86400)),
        );
    }
    let v = compute_upgrade_outcome_detail(state, "found-id".into())
        .await
        .expect("found-id MUST return Ok");
    assert_eq!(v["proposal_id"].as_str(), Some("found-id"));
    assert_eq!(v["outcome"].as_str(), Some("passed"));
    assert_eq!(v["transition_deadline_secs"].as_u64(), Some(14 * 86400));
    assert_eq!(v["recorded_at_ts"].as_f64(), Some(1234.5));
}

#[tokio::test]
async fn batch_iiiii_compute_upgrade_outcome_detail_missing_proposal_returns_governance_error_with_id_in_message(
) {
    let state = test_state();
    let result = compute_upgrade_outcome_detail(state, "missing-prop".into()).await;
    match result {
        Ok(_) => panic!("missing proposal_id MUST return Err"),
        Err(ElaraError::Governance(msg)) => {
            assert!(
                msg.contains("missing-prop"),
                "error message MUST name the missing proposal_id \
                     (got: {msg}) — operators correlate this to the UI's \
                     'no outcome recorded' empty-state"
            );
        }
        Err(other) => panic!("expected ElaraError::Governance, got {:?}", other),
    }
}

/// `/mandate/{id}/acts` must surface `authoritative_complete` so a snapshot-
/// bootstrapped follower's `{mandate_found:true, count:0}` is never misread as
/// "this agent never acted": act indexes are live-ingest-only, never snapshot-
/// carried, so a follower omits pre-baseline acts. Coverage-honesty for the C16
/// accountability query — without it the dogfood mandate's acts look absent on a
/// freshly-joined node (e.g. the first external joiner) that bootstrapped past their seal.
#[tokio::test]
async fn mandate_acts_coverage_authoritative_complete_tracks_snapshot_bootstrap() {
    let state = test_state();
    let mid = "a".repeat(64);

    // Fresh node = replayed-from-genesis = full history → authoritative.
    let v = mandate_acts(
        State(state.clone()),
        AxumPath(mid.clone()),
        Query(std::collections::HashMap::new()),
    )
    .await
    .0;
    assert_eq!(v["count"], serde_json::json!(0));
    assert_eq!(
        v["authoritative_complete"],
        serde_json::json!(true),
        "a genesis-replay node has full act history"
    );

    // Simulate a snapshot bootstrap: enumeration may omit pre-baseline acts, so
    // {count:0, authoritative_complete:false} must NOT be read as "no acts exist".
    state
        .ledger_loaded_from_snapshot
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let v2 = mandate_acts(
        State(state.clone()),
        AxumPath(mid),
        Query(std::collections::HashMap::new()),
    )
    .await
    .0;
    assert_eq!(
        v2["authoritative_complete"],
        serde_json::json!(false),
        "a snapshot-bootstrapped follower is NOT authoritative for act enumeration"
    );
}

/// `/mandate/status/{record_id}` must mark its `is_mandate_act:false` answer as
/// node-local on a snapshot-bootstrapped follower: act entries (CF_MANDATE_ACT)
/// are live-ingest-only, never snapshot-carried, so a "false" there can be a
/// pre-baseline false negative — NOT a definitive "this record is not a mandate
/// act". Sibling of the `/mandate/{id}/acts` coverage field; without it a freshly-
/// joined node (e.g. the first external joiner) silently disavows a real act it bootstrapped past.
#[tokio::test]
async fn mandate_status_not_found_authoritative_complete_tracks_snapshot_bootstrap() {
    let state = test_state();
    let rec = "b".repeat(64); // no act entry exists → the not-found path

    // Genesis-replay node = full act history → a not-found answer is definitive.
    let v = mandate_status(State(state.clone()), AxumPath(rec.clone())).await.0;
    assert_eq!(v["is_mandate_act"], serde_json::json!(false));
    assert_eq!(
        v["authoritative_complete"],
        serde_json::json!(true),
        "a genesis-replay node definitively has no such act"
    );

    // Snapshot-bootstrapped follower: is_mandate_act:false may be a pre-baseline
    // false negative, so the answer must NOT be presented as authoritative.
    state
        .ledger_loaded_from_snapshot
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let v2 = mandate_status(State(state.clone()), AxumPath(rec)).await.0;
    assert_eq!(
        v2["authoritative_complete"],
        serde_json::json!(false),
        "a snapshot-bootstrapped follower may have bootstrapped past the act"
    );
}
