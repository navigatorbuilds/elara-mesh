//! Tests for the zone-transition route handlers (lifted verbatim from
//! the former inline `mod tests` in transitions.rs; logic unchanged).

use super::*;
use crate::crypto::hash::sha3_256;
use crate::crypto::pqc::{dilithium3_keygen, dilithium3_sign_with_pk, DilithiumKeypair};
use crate::identity::{CryptoProfile, EntityType, Identity};
use crate::network::config::NodeConfig;
use crate::network::transition_store::PendingTransition;
use crate::network::witness::WitnessManager;
use crate::network::zone::ZoneId;
use crate::network::zone_transition_seal::{
    TransitionKind, ZoneSnapshot, TRANSITION_DISPUTE_WINDOW_EPOCHS,
};
use crate::storage::rocks::StorageEngine;

/// Spin up a minimal `NodeState` backed by a real RocksDB tempdir,
/// same shape as the helper in explorer's test module.
fn test_state() -> Arc<NodeState> {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let config = NodeConfig {
        data_dir: data_dir.clone(),
        identity_path: data_dir.join("identity.json"),
        db_path: data_dir.join("elara.db"),
        admin_token: "test-admin".into(),
        network_id: "transitions-route-test".into(),
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
    std::mem::forget(tmp);
    state
}

/// Register an anchor: store its Dilithium3 pubkey in `CF_IDENTITIES`
/// under `hex(sha3_256(pubkey))`. Returns `(identity_hash, keypair)`
/// for use when signing test seals.
fn register_anchor(state: &NodeState) -> ([u8; 32], DilithiumKeypair) {
    let kp = dilithium3_keygen().expect("keygen");
    let ident = sha3_256(&kp.public_key);
    state
        .rocks
        .store_public_key(&hex::encode(ident), &kp.public_key)
        .expect("store pubkey");
    (ident, kp)
}

/// Transitions-F1: put an identity into the staked-anchor trust set the way
/// production does — a real ledger `StakeEntry` at the witness floor (the
/// same shape `apply_genesis_validators` writes). Handler-level tests go
/// through the real `NodeState::transition_trust_view()`, which sources
/// membership from `staker_index` + `staked >= MIN_WITNESS_STAKE_BASE_UNITS`
/// — a registered-but-unstaked signer is rejected before pubkey lookup.
/// Bumps `stake_mutation_seq` so a previously-memoized view invalidates.
async fn stake_anchor(state: &NodeState, ident: [u8; 32]) {
    use crate::accounting::types::{StakePurpose, MIN_WITNESS_STAKE_BASE_UNITS};
    let hex_id = hex::encode(ident);
    let rid = format!("test-stake:{hex_id}");
    let mut ledger = state.ledger.write().await;
    ledger.accounts.entry(hex_id.clone()).or_default().staked +=
        MIN_WITNESS_STAKE_BASE_UNITS;
    ledger.stakes.insert(
        rid.clone(),
        crate::accounting::ledger::StakeEntry {
            record_id: rid.clone(),
            amount: MIN_WITNESS_STAKE_BASE_UNITS,
            purpose: StakePurpose::Witness,
            staker: hex_id.clone(),
            timestamp: 0.0,
            active: true,
        },
    );
    ledger.staker_index.entry(hex_id).or_default().push(rid);
    ledger.stake_mutation_seq += 1;
}

fn split_seal_at(proposed_at: u64) -> TransitionSeal {
    TransitionSeal {
        kind: TransitionKind::Split,
        proposed_at_epoch: proposed_at,
        effective_epoch: proposed_at + TRANSITION_DISPUTE_WINDOW_EPOCHS,
        parents: vec![ZoneSnapshot {
            zone_id: ZoneId::new("test/parent"),
            state_root: [1; 32],
            last_seal_record_id: "parent".into(),
            record_count: 10,
            committee_hash: [2; 32],
        }],
        children: vec![
            ZoneSnapshot {
                zone_id: ZoneId::new("test/child-a"),
                state_root: [0; 32],
                last_seal_record_id: String::new(),
                record_count: 0,
                committee_hash: [3; 32],
            },
            ZoneSnapshot {
                zone_id: ZoneId::new("test/child-b"),
                state_root: [0; 32],
                last_seal_record_id: String::new(),
                record_count: 0,
                committee_hash: [4; 32],
            },
        ],
        split_key: Some([0x80; 32]),
        proposer_sigs: vec![],
    }
}

fn merge_seal_at(proposed_at: u64) -> TransitionSeal {
    TransitionSeal {
        kind: TransitionKind::Merge,
        proposed_at_epoch: proposed_at,
        effective_epoch: proposed_at + TRANSITION_DISPUTE_WINDOW_EPOCHS,
        parents: vec![
            ZoneSnapshot {
                zone_id: ZoneId::new("test/parent-a"),
                state_root: [5; 32],
                last_seal_record_id: "pa".into(),
                record_count: 10,
                committee_hash: [6; 32],
            },
            ZoneSnapshot {
                zone_id: ZoneId::new("test/parent-b"),
                state_root: [7; 32],
                last_seal_record_id: "pb".into(),
                record_count: 10,
                committee_hash: [8; 32],
            },
        ],
        children: vec![ZoneSnapshot {
            zone_id: ZoneId::new("test/merged"),
            state_root: [0; 32],
            last_seal_record_id: String::new(),
            record_count: 0,
            committee_hash: [9; 32],
        }],
        split_key: None,
        proposer_sigs: vec![],
    }
}

/// Helper — unwrap a handler Result<Json<T>, AppError> into Json<T>
/// without relying on Debug for the error variant (AppError is
/// opaque by design). Panics with a captured message on the Err path.
fn ok_or_panic<T>(r: Result<Json<T>, AppError>, label: &str) -> Json<T> {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{label}: handler returned AppError({})", e.0),
    }
}

/// Helper — assert handler Result is Err and return the underlying
/// ElaraError's string for content assertions.
fn err_msg<T>(r: Result<Json<T>, AppError>, label: &str) -> String {
    match r {
        Ok(_) => panic!("{label}: expected Err, got Ok"),
        Err(e) => e.0.to_string(),
    }
}

/// Forgery fuzz: proposing with a sig whose identity isn't in
/// `CF_IDENTITIES` must 400 out — not quietly count against the
/// threshold.
#[tokio::test]
async fn propose_rejects_unregistered_anchor() {
    let state = test_state();
    // F1: stake the phantom so the stake gate passes and the
    // pubkey-registration branch under test is the one that fires.
    stake_anchor(&state, [0x99; 32]).await;
    let mut seal = split_seal_at(100);
    seal.proposer_sigs.push(AnchorSig {
        anchor_identity_hash: [0x99; 32],
        dilithium3_sig: vec![0xaa; 3309],
    });
    let msg = err_msg(
        propose_transition(State(state), Json(seal)).await,
        "propose",
    );
    assert!(
        msg.contains("pubkey not registered"),
        "expected unregistered-anchor error, got {msg}"
    );
}

/// Happy path for `submit_sig`: register one anchor, propose empty
/// seal, submit the anchor's sig → store accepts, sigs_collected=1.
#[tokio::test]
async fn submit_sig_round_trip_registered_anchor() {
    let state = test_state();
    let (ident, kp) = register_anchor(&state);
    stake_anchor(&state, ident).await;

    let seal = split_seal_at(100);
    let seal_hash = seal.seal_hash_for_sig().expect("hash");

    let propose_resp = ok_or_panic(
        propose_transition(State(state.clone()), Json(seal)).await,
        "propose",
    );
    assert_eq!(propose_resp.0.status, "AwaitingSigs");
    let id_hex = propose_resp.0.id.clone();

    let sig_bytes =
        dilithium3_sign_with_pk(&seal_hash, &kp.secret_key, &kp.public_key).expect("sign");
    let sig = AnchorSig {
        anchor_identity_hash: ident,
        dilithium3_sig: sig_bytes,
    };
    let sig_resp = ok_or_panic(
        submit_sig(State(state), Path(id_hex), Json(sig)).await,
        "submit_sig",
    );
    assert_eq!(sig_resp.0.sigs_collected, 1);
}

/// Submitting a sig from an unregistered anchor must fail. This is
/// the same surface as `propose_rejects_unregistered_anchor` but at
/// the `/sig` handler.
#[tokio::test]
async fn submit_sig_rejects_unregistered_anchor() {
    let state = test_state();
    // F1: stake the phantom so the pubkey-registration branch fires.
    stake_anchor(&state, [0x77; 32]).await;
    let seal = split_seal_at(100);
    let propose_resp = ok_or_panic(
        propose_transition(State(state.clone()), Json(seal)).await,
        "propose",
    );
    let id_hex = propose_resp.0.id;

    let forged = AnchorSig {
        anchor_identity_hash: [0x77; 32],
        dilithium3_sig: vec![0xaa; 3309],
    };
    let msg = err_msg(
        submit_sig(State(state), Path(id_hex), Json(forged)).await,
        "submit_sig",
    );
    assert!(
        msg.contains("pubkey not registered"),
        "expected unregistered-anchor error, got {msg}"
    );
}

/// Correctness guard: a sig arriving at `submit_sig` AFTER
/// `effective_epoch` must 400. Otherwise a late sig could flip
/// AwaitingSigs → DisputeWindow, and the next `tick()` would mark
/// the seal Finalized instead of Expired — mutating the outcome
/// after the dispute window closed. Mirrors add_veto's
/// `current_epoch >= effective_epoch` guard so sigs and vetoes
/// share the same temporal semantics.
#[tokio::test]
async fn submit_sig_rejects_after_effective_epoch() {
    let state = test_state();
    let (ident, kp) = register_anchor(&state);

    // Propose first (no state_core — temporal guard in propose
    // only fires when state_core is set). effective_epoch = 103.
    let seal = split_seal_at(100);
    let seal_hash = seal.seal_hash_for_sig().expect("hash");
    let effective_epoch = seal.effective_epoch;
    let propose_resp = ok_or_panic(
        propose_transition(State(state.clone()), Json(seal)).await,
        "propose",
    );
    let id_hex = propose_resp.0.id;

    // Now install state_core AT effective_epoch — exactly at the
    // boundary: current_epoch >= effective_epoch must reject.
    install_state_core_at_epoch(&state, effective_epoch);

    // Build a valid sig over the real seal_hash. The sig itself
    // is fine — only the temporal guard should fire.
    let sig_bytes =
        dilithium3_sign_with_pk(&seal_hash, &kp.secret_key, &kp.public_key).expect("sign");
    let sig = AnchorSig {
        anchor_identity_hash: ident,
        dilithium3_sig: sig_bytes,
    };
    let msg = err_msg(
        submit_sig(State(state), Path(id_hex), Json(sig)).await,
        "submit_sig",
    );
    assert!(
        msg.contains("dispute window closed"),
        "expected temporal-guard error, got: {msg}"
    );
}

/// `resolve_account` routes an account hash below `split_key` to
/// `children[0]` and above to `children[1]`, matching
/// `TransitionSeal::account_belongs_to_child`.
#[tokio::test]
async fn resolve_account_routes_by_split_key() {
    let state = test_state();
    let seal = split_seal_at(100);
    // split_key is [0x80; 32] per helper.
    let propose_resp = ok_or_panic(
        propose_transition(State(state.clone()), Json(seal)).await,
        "propose",
    );
    let id_hex = propose_resp.0.id;

    let low_account = hex::encode([0x10u8; 32]);
    let low_resp = ok_or_panic(
        resolve_account(State(state.clone()), Path((id_hex.clone(), low_account))).await,
        "resolve low",
    );
    assert_eq!(low_resp.0.post_transition_zone, "test/child-a");
    assert!(!low_resp.0.final_binding); // status is AwaitingSigs

    let high_account = hex::encode([0xF0u8; 32]);
    let high_resp = ok_or_panic(
        resolve_account(State(state), Path((id_hex, high_account))).await,
        "resolve high",
    );
    assert_eq!(high_resp.0.post_transition_zone, "test/child-b");
}

/// Install a `StateCoreHandle` with the given `current_epoch` into
/// the test node state. Uses dummy channels that no one reads —
/// temporal validation only consults the snapshot, not the
/// channels, so these never fire. Returns silently on double-init
/// (state_core is a OnceCell, but the test flow calls this at most
/// once per `test_state`).
fn install_state_core_at_epoch(state: &NodeState, current_epoch: u64) {
    use arc_swap::ArcSwap;
    use tokio::sync::mpsc;

    let snap = crate::network::state_core::StateSnapshot {
        current_epoch,
        ..Default::default()
    };
    let snapshot = Arc::new(ArcSwap::from_pointee(snap));
    let (tx, _rx) = mpsc::channel(1);
    let (ptx, _prx) = mpsc::channel(1);
    let handle = crate::network::state_core::StateCoreHandle::new(tx, ptx, snapshot);
    let _ = state.state_core.set(handle);
}

/// `/transitions/propose` rejects proposals whose `proposed_at_epoch`
/// is too far ahead of the node's current_epoch — a DoS vector
/// otherwise: an attacker parks proposals centuries in the future
/// that fill `MAX_PENDING_TRANSITIONS` and evict honest proposals
/// without ever hitting their dispute window. Slack of
/// `PROPOSAL_MAX_LEAD_EPOCHS` covers normal anchor clock skew.
#[tokio::test]
async fn propose_rejects_proposal_too_far_future() {
    let state = test_state();
    install_state_core_at_epoch(&state, 100);

    // proposed_at = 100 + PROPOSAL_MAX_LEAD_EPOCHS (boundary: still OK).
    let mut ok_seal = split_seal_at(100 + super::PROPOSAL_MAX_LEAD_EPOCHS);
    ok_seal.effective_epoch = ok_seal.proposed_at_epoch + TRANSITION_DISPUTE_WINDOW_EPOCHS;
    let _ = ok_or_panic(
        propose_transition(State(state.clone()), Json(ok_seal)).await,
        "boundary ok",
    );

    // proposed_at = 100 + PROPOSAL_MAX_LEAD_EPOCHS + 1 (one past the
    // boundary — must 400).
    let bad_seal = split_seal_at(100 + super::PROPOSAL_MAX_LEAD_EPOCHS + 1);
    let err = err_msg(
        propose_transition(State(state), Json(bad_seal)).await,
        "too far future",
    );
    assert!(
        err.contains("ahead of current_epoch"),
        "got unexpected error: {err}"
    );
}

/// A proposal whose `effective_epoch` is already at or behind the
/// current_epoch is meaningless — the dispute window has closed
/// before the store ever sees it. Reject upfront; otherwise tick()
/// silently expires it after gossip already burned CPU on verify.
#[tokio::test]
async fn propose_rejects_past_effective_epoch() {
    let state = test_state();
    // current_epoch = 200, so any seal whose effective_epoch <= 200
    // must 400. split_seal_at(100) sets effective_epoch = 103.
    install_state_core_at_epoch(&state, 200);

    let stale = split_seal_at(100);
    let err = err_msg(propose_transition(State(state), Json(stale)).await, "stale");
    assert!(
        err.contains("not in the future"),
        "got unexpected error: {err}"
    );
}

/// `/transitions/{id}/resolve/{account}` falls back to
/// `CF_TRANSITIONS_FINAL` when the seal has been pruned from the
/// in-memory store. Wallets holding an old transition id must
/// still resolve "which zone does my account route to?" long
/// after the hot-store retention window closes — otherwise the
/// endpoint silently 404s on anything older than the pending cap.
#[tokio::test]
async fn resolve_account_falls_back_to_finalized_cf() {
    let state = test_state();

    // Persist the seal directly to CF only — no hot-store entry.
    // Mirrors the "long-after-prune" state for any finalized seal.
    let seal = split_seal_at(100);
    let id = seal.seal_hash_for_sig().expect("hash");
    let bytes = serde_json::to_vec(&seal).expect("serialize");
    state
        .rocks
        .put_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id, &bytes)
        .expect("persist");

    // Confirm the hot store really doesn't have it — we're
    // exercising the fallback path, not duplicate resolution.
    {
        let store = state.transitions.read().unwrap();
        assert!(store.get(&id).is_none());
    }

    let id_hex = hex::encode(id);

    // split_key = [0x80; 32], so 0x10-prefixed account routes to
    // child-a (the "below the split point" half of the hashspace).
    let low_account = hex::encode([0x10u8; 32]);
    let low_resp = ok_or_panic(
        resolve_account(State(state.clone()), Path((id_hex.clone(), low_account))).await,
        "resolve low (cf-fallback)",
    );
    assert_eq!(low_resp.0.post_transition_zone, "test/child-a");
    assert!(
        low_resp.0.final_binding,
        "CF-persisted seals are Finalized by construction"
    );
    assert_eq!(low_resp.0.status, "Finalized");

    // Symmetric high-side account routes to child-b.
    let high_account = hex::encode([0xF0u8; 32]);
    let high_resp = ok_or_panic(
        resolve_account(State(state.clone()), Path((id_hex.clone(), high_account))).await,
        "resolve high (cf-fallback)",
    );
    assert_eq!(high_resp.0.post_transition_zone, "test/child-b");
    assert!(high_resp.0.final_binding);

    // Unknown id in BOTH hot and CF → 404 Path stays intact.
    let unknown_id = hex::encode([0xEFu8; 32]);
    let unknown_account = hex::encode([0x00u8; 32]);
    let err = resolve_account(State(state), Path((unknown_id.clone(), unknown_account))).await;
    assert!(err.is_err(), "unknown id must still 404");
}

/// `list_finalized_transitions` surfaces every seal persisted in
/// CF_TRANSITIONS_FINAL by `run_transition_tick`. Here we write two
/// seals directly via `put_cf_raw` (bypassing the tick, which needs a
/// live state_core) and verify the endpoint enumerates both with
/// status="Finalized" and effective-epoch-descending ordering.
#[tokio::test]
async fn list_finalized_returns_cf_contents_sorted() {
    let state = test_state();

    let early = split_seal_at(100); // effective_epoch = 103
    let late = split_seal_at(200); // effective_epoch = 203
    for seal in [&early, &late] {
        let id = seal.seal_hash_for_sig().expect("hash");
        let bytes = serde_json::to_vec(seal).expect("serialize");
        state
            .rocks
            .put_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id, &bytes)
            .expect("persist");
    }

    let resp = ok_or_panic(
        list_finalized_transitions(State(state), Query(ListFinalizedParams::default())).await,
        "list_finalized",
    );
    assert_eq!(resp.0.count, 2);
    assert_eq!(resp.0.total, Some(2));
    assert_eq!(resp.0.offset, Some(0));
    // Newest-effective-first: late (203) before early (103).
    assert_eq!(resp.0.transitions[0].effective_epoch, 203);
    assert_eq!(resp.0.transitions[1].effective_epoch, 103);
    assert_eq!(resp.0.transitions[0].status, "Finalized");
}

/// Empty CF returns an empty list, not an error.
#[tokio::test]
async fn list_finalized_empty_cf() {
    let state = test_state();
    let resp = ok_or_panic(
        list_finalized_transitions(State(state), Query(ListFinalizedParams::default())).await,
        "list_finalized_empty",
    );
    assert_eq!(resp.0.count, 0);
    assert_eq!(resp.0.total, Some(0));
    assert!(resp.0.transitions.is_empty());
}

/// Pagination: `?offset=1&limit=1` on a two-entry CF returns just the
/// older of the two (because default sort is effective-epoch-descending,
/// so offset 1 lands on the second-newest). `total` still reports 2.
#[tokio::test]
async fn list_finalized_pagination_offset_and_limit() {
    let state = test_state();
    for base in [100u64, 200, 300] {
        let seal = split_seal_at(base);
        let id = seal.seal_hash_for_sig().expect("hash");
        let bytes = serde_json::to_vec(&seal).expect("serialize");
        state
            .rocks
            .put_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id, &bytes)
            .expect("persist");
    }

    // Page 1: first two, newest-first.
    let page1 = ok_or_panic(
        list_finalized_transitions(
            State(state.clone()),
            Query(ListFinalizedParams {
                offset: Some(0),
                limit: Some(2),
                kind: None,
                since_epoch: None,
                until_epoch: None,
                zone: None,
            }),
        )
        .await,
        "page1",
    );
    assert_eq!(page1.0.count, 2);
    assert_eq!(page1.0.total, Some(3));
    assert_eq!(page1.0.offset, Some(0));
    assert_eq!(page1.0.limit, Some(2));
    assert_eq!(page1.0.transitions[0].effective_epoch, 303);
    assert_eq!(page1.0.transitions[1].effective_epoch, 203);

    // Page 2: remaining entry.
    let page2 = ok_or_panic(
        list_finalized_transitions(
            State(state.clone()),
            Query(ListFinalizedParams {
                offset: Some(2),
                limit: Some(2),
                kind: None,
                since_epoch: None,
                until_epoch: None,
                zone: None,
            }),
        )
        .await,
        "page2",
    );
    assert_eq!(page2.0.count, 1);
    assert_eq!(page2.0.total, Some(3));
    assert_eq!(page2.0.offset, Some(2));
    assert_eq!(page2.0.transitions[0].effective_epoch, 103);

    // Offset past end → empty page, total still intact.
    let empty = ok_or_panic(
        list_finalized_transitions(
            State(state),
            Query(ListFinalizedParams {
                offset: Some(10),
                limit: Some(2),
                kind: None,
                since_epoch: None,
                until_epoch: None,
                zone: None,
            }),
        )
        .await,
        "past-end",
    );
    assert_eq!(empty.0.count, 0);
    assert_eq!(empty.0.total, Some(3));
    assert!(empty.0.transitions.is_empty());
}

/// `/transitions/stats` reports in-memory status counts and the durable
/// CF_TRANSITIONS_FINAL count together. Empty store + empty CF → all
/// zeroes.
#[tokio::test]
async fn stats_empty_state_zeroes() {
    let state = test_state();
    let resp = ok_or_panic(transition_stats(State(state)).await, "stats-empty");
    assert_eq!(resp.0.pending_total, 0);
    assert_eq!(resp.0.finalized_durable, 0);
    assert_eq!(resp.0.pending.awaiting_sigs, 0);
    assert_eq!(resp.0.pending.dispute_window, 0);
    assert_eq!(resp.0.pending_by_kind.split, 0);
    assert_eq!(resp.0.pending_by_kind.merge, 0);
    assert_eq!(resp.0.pending_by_kind.total(), 0);
    // No pending entries → no vetoes attached.
    assert_eq!(resp.0.pending_vetoes_by_reason.total(), 0);
    // Fresh state: boot-replay never ran, counter defaults to zero.
    assert_eq!(resp.0.boot_replayed_total, 0);
    // Empty store → no active window to watch.
    assert_eq!(resp.0.nearest_effective_epoch, None);
    // Empty CF → no durable finalized epoch to report.
    assert_eq!(resp.0.finalized_durable_latest_epoch, None);
}

/// `/transitions/stats.finalized_durable_latest_epoch` returns the
/// max `effective_epoch` across the durable CF. Gives operators a
/// "how recent was our most recent applied transition?" signal
/// without paging through /transitions/finalized.
#[tokio::test]
async fn stats_reports_finalized_durable_latest_epoch() {
    let state = test_state();

    // Persist three splits with distinct effective_epochs (100+W,
    // 300+W, 200+W). The max is 300+W regardless of insertion order.
    for proposed in [100u64, 300, 200] {
        let seal = split_seal_at(proposed);
        let id = seal.seal_hash_for_sig().expect("hash");
        let bytes = serde_json::to_vec(&seal).expect("serialize");
        state
            .rocks
            .put_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id, &bytes)
            .expect("persist");
    }

    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(resp.0.finalized_durable, 3);
    let expected_max = 300 + crate::network::zone_transition_seal::TRANSITION_DISPUTE_WINDOW_EPOCHS;
    let expected_min = 100 + crate::network::zone_transition_seal::TRANSITION_DISPUTE_WINDOW_EPOCHS;
    assert_eq!(resp.0.finalized_durable_latest_epoch, Some(expected_max));
    assert_eq!(
        resp.0.finalized_durable_oldest_epoch,
        Some(expected_min),
        "oldest must be the smallest effective_epoch in the CF page"
    );
}

/// Empty CF: oldest epoch is None and must be skipped from the
/// serialized output — same shape contract as `latest_epoch`.
#[tokio::test]
async fn stats_omits_finalized_durable_oldest_epoch_when_empty() {
    let state = test_state();
    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(resp.0.finalized_durable_oldest_epoch, None);
    let body = serde_json::to_string(&resp.0).expect("ser");
    assert!(
        !body.contains("finalized_durable_oldest_epoch"),
        "None field must be skipped in serialized output, got: {body}"
    );
}

/// `/transitions/stats` reports the Split/Merge breakdown of the
/// durable finalized CF page. Aggregated from the same scan that
/// produces the count — total must equal `finalized_durable` when
/// every row decodes cleanly.
#[tokio::test]
async fn stats_reports_finalized_durable_by_kind() {
    let state = test_state();

    // Persist 3 splits + 2 merges.
    for proposed in [100u64, 150, 200] {
        let seal = split_seal_at(proposed);
        let id = seal.seal_hash_for_sig().expect("hash");
        let bytes = serde_json::to_vec(&seal).expect("serialize");
        state
            .rocks
            .put_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id, &bytes)
            .expect("persist split");
    }
    for proposed in [250u64, 300] {
        let seal = merge_seal_at(proposed);
        let id = seal.seal_hash_for_sig().expect("hash");
        let bytes = serde_json::to_vec(&seal).expect("serialize");
        state
            .rocks
            .put_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id, &bytes)
            .expect("persist merge");
    }

    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(resp.0.finalized_durable, 5);
    assert_eq!(resp.0.finalized_durable_by_kind.split, 3);
    assert_eq!(resp.0.finalized_durable_by_kind.merge, 2);
    assert_eq!(
        resp.0.finalized_durable_by_kind.total(),
        resp.0.finalized_durable,
        "by_kind.total() must reconcile with finalized_durable"
    );
}

/// Empty CF: by-kind counts are all zero and total()==0==finalized_durable.
#[tokio::test]
async fn stats_finalized_durable_by_kind_zero_on_empty_cf() {
    let state = test_state();
    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(resp.0.finalized_durable, 0);
    assert_eq!(resp.0.finalized_durable_by_kind.split, 0);
    assert_eq!(resp.0.finalized_durable_by_kind.merge, 0);
    assert_eq!(resp.0.finalized_durable_by_kind.total(), 0);
}

/// `/transitions/stats` exposes the soonest `effective_epoch` across
/// active pending proposals. Operators diff this against
/// `current_epoch` to get a "window closes in N epochs" glance.
#[tokio::test]
async fn stats_reports_nearest_effective_epoch() {
    let state = test_state();

    // Two splits. The earlier proposed_at yields the smaller
    // effective_epoch (proposed_at + TRANSITION_DISPUTE_WINDOW_EPOCHS).
    let early = split_seal_at(100);
    let late = split_seal_at(500);
    let _ = ok_or_panic(
        propose_transition(State(state.clone()), Json(late)).await,
        "propose late",
    );
    let _ = ok_or_panic(
        propose_transition(State(state.clone()), Json(early.clone())).await,
        "propose early",
    );

    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(
        resp.0.nearest_effective_epoch,
        Some(early.effective_epoch),
        "nearest must be the earliest active window"
    );
}

/// `/transitions/stats` exposes the oldest `proposed_at_epoch`
/// across active pending proposals — the companion to
/// `nearest_effective_epoch`. Operators diff against
/// `current_epoch` to flag stuck-in-flight proposals.
#[tokio::test]
async fn stats_reports_oldest_active_proposed_at_epoch() {
    let state = test_state();

    // Two splits proposed at different epochs. The smaller
    // proposed_at_epoch wins regardless of insertion order.
    let early = split_seal_at(100);
    let late = split_seal_at(500);
    let _ = ok_or_panic(
        propose_transition(State(state.clone()), Json(late)).await,
        "propose late",
    );
    let _ = ok_or_panic(
        propose_transition(State(state.clone()), Json(early.clone())).await,
        "propose early",
    );

    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(
        resp.0.oldest_active_proposed_at_epoch,
        Some(early.proposed_at_epoch),
        "oldest must be the longest-waiting active proposal"
    );
}

/// `/transitions/stats` surfaces the store's monotone eviction
/// counter. Zero in steady state; must track the store-level
/// counter verbatim when the store is under capacity pressure.
#[tokio::test]
async fn stats_reports_evictions_total_zero_in_steady_state() {
    let state = test_state();
    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(resp.0.evictions_total, 0, "no inserts yet → no evictions");
    assert_eq!(
        resp.0.proposals_accepted_total, 0,
        "no inserts yet → no accepted proposals"
    );
}

/// `/transitions/stats` surfaces the mirror-write-failure counter.
/// Zero in steady state. Bumping the NodeState AtomicU64 directly
/// (bypassing the error paths, which are hard to trigger in a test)
/// confirms the wiring from NodeState → /stats response.
#[tokio::test]
async fn stats_reports_mirror_write_failures_total() {
    let state = test_state();
    let resp = ok_or_panic(transition_stats(State(state.clone())).await, "stats");
    assert_eq!(resp.0.mirror_write_failures_total, 0);

    // Simulate two mirror-write failures.
    state
        .transitions_mirror_write_failures_total
        .fetch_add(2, std::sync::atomic::Ordering::Relaxed);

    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(
        resp.0.mirror_write_failures_total, 2,
        "stats must surface the NodeState counter verbatim"
    );
}

/// After a handful of fresh proposals, `proposals_accepted_total`
/// must track the actual insert count. Confirms the wiring from
/// `TransitionStore::proposals_accepted_total()` through
/// `/transitions/stats`.
#[tokio::test]
async fn stats_reports_proposals_accepted_total_tracks_inserts() {
    let state = test_state();
    for proposed in [100u64, 200, 300] {
        let seal = split_seal_at(proposed);
        let _ = ok_or_panic(
            propose_transition(State(state.clone()), Json(seal)).await,
            "propose",
        );
    }
    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(
        resp.0.proposals_accepted_total, 3,
        "three fresh proposals → counter = 3"
    );
    assert_eq!(resp.0.evictions_total, 0, "well under cap → no evictions");
}

/// `/transitions/stats` echoes back `MAX_PENDING_TRANSITIONS` so
/// dashboards can render `pending_total / pending_capacity`
/// saturation without hardcoding the constant. Lets operators
/// notice store-pressure conditions (DoS via full store, honest
/// proposals getting rejected) from a single metrics poll.
#[tokio::test]
async fn stats_echoes_pending_capacity_constant() {
    let state = test_state();
    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(
        resp.0.pending_capacity,
        crate::network::transition_store::MAX_PENDING_TRANSITIONS,
        "stats must echo the store capacity cap"
    );
    assert!(
        resp.0.pending_total <= resp.0.pending_capacity,
        "pending_total must never exceed capacity"
    );
}

/// `/transitions/stats` echoes back the protocol's
/// `TRANSITION_DISPUTE_WINDOW_EPOCHS` so client tooling can render
/// "dispute window closes in N" without hardcoding the constant
/// (and without fetching the full seal).
#[tokio::test]
async fn stats_echoes_dispute_window_constant() {
    let state = test_state();
    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(
        resp.0.dispute_window_epochs,
        crate::network::zone_transition_seal::TRANSITION_DISPUTE_WINDOW_EPOCHS,
        "stats must echo the protocol constant"
    );
}

/// On an empty store, `oldest_active_proposed_at_epoch` is None
/// and must be omitted from the serialized response — same
/// shape contract as `nearest_effective_epoch`.
#[tokio::test]
async fn stats_omits_oldest_when_no_active_proposals() {
    let state = test_state();
    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(resp.0.oldest_active_proposed_at_epoch, None);
    let body = serde_json::to_string(&resp.0).expect("ser");
    assert!(
        !body.contains("oldest_active_proposed_at_epoch"),
        "None field must be skipped in serialized output, got: {body}"
    );
}

/// With one pending proposal in the in-memory store AND one finalized
/// seal persisted to CF, stats reports both counts independently.
#[tokio::test]
async fn stats_reports_pending_and_durable() {
    let state = test_state();

    // Pending (in-memory only).
    let seal = split_seal_at(100);
    let propose_resp = ok_or_panic(
        propose_transition(State(state.clone()), Json(seal)).await,
        "propose",
    );
    assert_eq!(propose_resp.0.status, "AwaitingSigs");

    // Durable (CF only).
    let finalized = split_seal_at(200);
    let id = finalized.seal_hash_for_sig().expect("hash");
    let bytes = serde_json::to_vec(&finalized).expect("serialize");
    state
        .rocks
        .put_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id, &bytes)
        .expect("persist");

    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(resp.0.pending_total, 1);
    assert_eq!(resp.0.pending.awaiting_sigs, 1);
    assert_eq!(resp.0.finalized_durable, 1);
    // The one pending entry is a Split (test helper), so pending_by_kind
    // must reflect that and totals must agree.
    assert_eq!(resp.0.pending_by_kind.split, 1);
    assert_eq!(resp.0.pending_by_kind.merge, 0);
    assert_eq!(resp.0.pending_by_kind.total(), resp.0.pending_total);
}

/// `/transitions/stats` surfaces the boot-replay count set by
/// `boot_replay_pending_transitions`. Simulates the boot path by
/// writing a pending entry to the CF, then calling the replay hook,
/// then asserting the counter landed in the stats JSON.
#[tokio::test]
async fn stats_reports_boot_replay_counter() {
    let state = test_state();
    // Write one live pending entry to CF_TRANSITIONS_PENDING as if we
    // were recovering from a prior process. Serialization matches
    // `persist_pending_entry` on the write path.
    let seal = split_seal_at(100);
    let pending =
        crate::network::transition_store::PendingTransition::from_seal(seal).expect("pending");
    state
        .rocks
        .put_cf_raw(
            crate::storage::rocks::CF_TRANSITIONS_PENDING,
            &pending.id,
            &serde_json::to_vec(&pending).expect("serialize"),
        )
        .expect("persist");

    // Drive the boot hook. It reads from the CF, populates the store,
    // and bumps `transitions_boot_replayed_total`.
    let replayed = crate::network::health::boot_replay_pending_transitions(&state);
    assert_eq!(replayed, 1, "one CF row → one replay");

    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(resp.0.boot_replayed_total, 1);
    // And the replay put it back into the in-memory store.
    assert_eq!(resp.0.pending_total, 1);
    assert_eq!(resp.0.pending.awaiting_sigs, 1);
}

/// `/transitions/stats` surfaces the two gossip counters
/// (`gossip_pushed_total`, `gossip_dedup_total`) maintained by
/// `push_transition_seal_to_peers`. Semantics pinned by this test:
///   * `gossip_pushed_total` counts pushes that actually reached ≥1
///     peer. With no connected peers in the test harness it stays 0
///     — NOT a bug, the dedup SeenSet is still primed on the
///     first call.
///   * `gossip_dedup_total` counts pushes short-circuited by the
///     SeenSet. A second push of the same seal = +1 dedup.
#[tokio::test]
async fn gossip_counters_dedupe_duplicate_proposals() {
    let state = test_state();
    let seal = split_seal_at(100);

    // First propose. No connected peers in test harness → pushed=0,
    // but the SeenSet records the seal id.
    let _ = ok_or_panic(
        propose_transition(State(state.clone()), Json(seal.clone())).await,
        "propose-first",
    );
    let resp = ok_or_panic(
        transition_stats(State(state.clone())).await,
        "stats-after-first",
    );
    assert_eq!(
        resp.0.gossip_pushed_total, 0,
        "no peers → no successful push"
    );
    assert_eq!(resp.0.gossip_dedup_total, 0);

    // Push the SAME seal again via the gossip fn — must trip
    // SeenSet dedup (the handler would 409 at the store, bypassing
    // the push, so we exercise the push fn directly).
    super::super::super::gossip::push_transition_seal_to_peers(&state, &seal).await;
    let resp = ok_or_panic(
        transition_stats(State(state.clone())).await,
        "stats-after-dedup",
    );
    assert_eq!(resp.0.gossip_pushed_total, 0);
    assert_eq!(
        resp.0.gossip_dedup_total, 1,
        "re-push of same seal hits dedup"
    );

    // Push a DIFFERENT seal — new id, not in SeenSet, dedup stays
    // at 1 and pushed stays 0 (still no peers).
    let other = split_seal_at(101);
    super::super::super::gossip::push_transition_seal_to_peers(&state, &other).await;
    let resp = ok_or_panic(transition_stats(State(state)).await, "stats-after-other");
    assert_eq!(resp.0.gossip_pushed_total, 0);
    assert_eq!(resp.0.gossip_dedup_total, 1);
}

/// `/transitions/stats` surfaces the four lifecycle counters
/// (`finalized_total`, `finalized_split_total`, `finalized_merge_total`,
/// `expired_total`) maintained by `run_transition_tick` when seals
/// cross `effective_epoch`. Operators use these to answer "did this
/// node actually finalize any Gap 4 transitions, and in what mix?"
/// Pokes the atomics directly — same pattern as the orchestrator
/// counter test — so the stats-surface contract is the thing under
/// test, not the tick that increments them.
#[tokio::test]
async fn stats_reports_finalize_expire_counters() {
    let state = test_state();
    let resp = ok_or_panic(transition_stats(State(state.clone())).await, "stats");
    assert_eq!(resp.0.finalized_total, 0);
    assert_eq!(resp.0.finalized_split_total, 0);
    assert_eq!(resp.0.finalized_merge_total, 0);
    assert_eq!(resp.0.expired_total, 0);

    // Simulate run_transition_tick flipping 2 Splits + 1 Merge to
    // Finalized, plus 1 AwaitingSigs to Expired.
    state
        .transitions_finalized_total
        .fetch_add(3, std::sync::atomic::Ordering::Relaxed);
    state
        .transitions_finalized_split_total
        .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
    state
        .transitions_finalized_merge_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    state
        .transitions_expired_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(resp.0.finalized_total, 3);
    assert_eq!(resp.0.finalized_split_total, 2);
    assert_eq!(resp.0.finalized_merge_total, 1);
    assert_eq!(resp.0.expired_total, 1);
    // Kind invariant: split + merge == total after any tick.
    assert_eq!(
        resp.0.finalized_split_total + resp.0.finalized_merge_total,
        resp.0.finalized_total,
        "finalized split/merge subtotals must sum to total",
    );
}

/// `/transitions/stats` surfaces the two orchestrator counters
/// (`orchestrator_proposed_total`, `orchestrator_insert_rejected_total`)
/// maintained by `run_auto_scale_tick`'s Gap 4 path. Without operator
/// visibility the orchestrator is a black box — "did my auto-scale
/// tick just emit a TransitionSeal or not?" is exactly the question
/// a fleet dashboard has to answer. Simulates the health-loop bump
/// by poking the atomics directly (the full tick is integration-tested
/// elsewhere; here we pin the stats contract).
#[tokio::test]
async fn stats_reports_orchestrator_counters() {
    let state = test_state();
    // Baseline: both zero on a fresh store.
    let resp = ok_or_panic(transition_stats(State(state.clone())).await, "stats");
    assert_eq!(resp.0.orchestrator_proposed_total, 0);
    assert_eq!(resp.0.orchestrator_insert_rejected_total, 0);

    // Simulate run_auto_scale_tick emitting 3 seals and tripping 1
    // insert-rejection (duplicate-in-flight or store-full).
    state
        .transitions_proposed_by_orchestrator_total
        .fetch_add(3, std::sync::atomic::Ordering::Relaxed);
    state
        .transitions_orchestrator_insert_rejected_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(resp.0.orchestrator_proposed_total, 3);
    assert_eq!(resp.0.orchestrator_insert_rejected_total, 1);

    // Both fields are always present in the JSON — they're plain
    // u64 with no skip_serializing_if, so operators can poll
    // unconditionally.
    let body = serde_json::to_string(&resp.0).expect("ser");
    assert!(body.contains("orchestrator_proposed_total"));
    assert!(body.contains("orchestrator_insert_rejected_total"));
}

/// After a successful `/transitions/propose`, the entry is mirrored
/// to `CF_TRANSITIONS_PENDING`. The CF row is byte-equal to the
/// serialized PendingTransition held in memory.
#[tokio::test]
async fn propose_mirrors_to_pending_cf() {
    let state = test_state();
    let seal = split_seal_at(100);
    let propose_resp = ok_or_panic(
        propose_transition(State(state.clone()), Json(seal.clone())).await,
        "propose",
    );
    let id = hex::decode(&propose_resp.0.id).expect("hex");
    let id: [u8; 32] = id.try_into().expect("32 bytes");

    let bytes = state
        .rocks
        .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_PENDING, &id)
        .expect("cf read")
        .expect("row present");
    let recovered: crate::network::transition_store::PendingTransition =
        serde_json::from_slice(&bytes).expect("deserialize");
    assert_eq!(recovered.seal.proposed_at_epoch, seal.proposed_at_epoch);
    assert_eq!(recovered.status, PendingStatus::AwaitingSigs);
}

/// When a synchronous veto flips status to `Vetoed` (requires 2
/// vetoes per MIN_VETOES_TO_HALT), the pending CF row is deleted —
/// a restart must not rehydrate a dead proposal.
#[tokio::test]
async fn veto_halt_deletes_pending_cf_row() {
    use crate::network::transition_store::{VetoReason, MIN_VETOES_TO_HALT};
    let state = test_state();

    // Propose (mirrors to CF).
    let seal = split_seal_at(100);
    let propose_resp = ok_or_panic(
        propose_transition(State(state.clone()), Json(seal)).await,
        "propose",
    );
    let id_hex = propose_resp.0.id.clone();
    let id_bytes: [u8; 32] = hex::decode(&id_hex)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    assert!(
        state
            .rocks
            .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_PENDING, &id_bytes)
            .unwrap()
            .is_some(),
        "CF should have the mirrored row after propose"
    );

    // Synthetically push the store past the veto threshold. We go
    // through the store directly (not HTTP) because the test state
    // doesn't have registered vetoer pubkeys — and the behaviour
    // under test is the CF cleanup, not the verify path.
    {
        let mut store = state.transitions.write().unwrap();
        for i in 0..MIN_VETOES_TO_HALT {
            let v = crate::network::transition_store::TransitionVeto {
                seal_hash: id_bytes,
                reason: VetoReason::BadBoundary,
                evidence: vec![i as u8],
                submitted_at_epoch: 101,
                vetoer_identity_hash: [i as u8 + 1; 32],
                dilithium3_sig: vec![0xaa; 32],
            };
            store.add_veto(&id_bytes, v, 101).expect("add_veto");
        }
        assert_eq!(store.get(&id_bytes).unwrap().status, PendingStatus::Vetoed);
    }

    // Now drive the persist-pending helper as the HTTP handler would
    // after its final successful veto. The Vetoed status must cause
    // a CF delete, not a re-write.
    persist_pending_entry(&state, &id_bytes);
    assert!(
        state
            .rocks
            .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_PENDING, &id_bytes)
            .unwrap()
            .is_none(),
        "CF row must be deleted after status flips to Vetoed"
    );
}

/// Client requesting limit > FINALIZED_PAGE_MAX is silently clamped.
/// The response's `limit` field reflects the effective cap so clients
/// can detect and adjust their paging stride.
#[tokio::test]
async fn list_finalized_limit_clamped_to_max() {
    let state = test_state();
    let resp = ok_or_panic(
        list_finalized_transitions(
            State(state),
            Query(ListFinalizedParams {
                offset: None,
                limit: Some(99_999),
                kind: None,
                since_epoch: None,
                until_epoch: None,
                zone: None,
            }),
        )
        .await,
        "clamp",
    );
    assert_eq!(resp.0.limit, Some(FINALIZED_PAGE_MAX));
}

/// DoS-resistance check: submitting a sig to an unknown transition id
/// must fail fast with `record not found`, *before* Dilithium3 verify
/// burns CPU. Bogus sig bytes here would be slow to verify; if we hit
/// the verify path, this test would surface a different error string.
#[tokio::test]
async fn submit_sig_unknown_id_rejected_before_verify() {
    let state = test_state();
    let unknown_id = hex::encode([0x42u8; 32]);
    let bogus_sig = AnchorSig {
        anchor_identity_hash: [0x99; 32],
        dilithium3_sig: vec![0; 3309],
    };
    let msg = err_msg(
        submit_sig(State(state), Path(unknown_id), Json(bogus_sig)).await,
        "submit_sig",
    );
    assert!(
        msg.contains("transition"),
        "expected not-found error for unknown id, got {msg}"
    );
}

/// DoS-resistance check: same behaviour for `/veto` — unknown id must
/// reject before the veto-sig verify runs.
#[tokio::test]
async fn submit_veto_unknown_id_rejected_before_verify() {
    use crate::network::transition_store::VetoReason;
    let state = test_state();
    let unknown_id = hex::encode([0x42u8; 32]);
    let bogus_veto = TransitionVeto {
        seal_hash: [0x42u8; 32],
        reason: VetoReason::BadBoundary,
        evidence: b"x".to_vec(),
        submitted_at_epoch: 101,
        vetoer_identity_hash: [0x99; 32],
        dilithium3_sig: vec![0; 3309],
    };
    let msg = err_msg(
        submit_veto(State(state), Path(unknown_id), Json(bogus_veto)).await,
        "submit_veto",
    );
    assert!(
        msg.contains("transition"),
        "expected not-found error for unknown id, got {msg}"
    );
}

/// `list_transitions` returns entries sorted by effective_epoch ASC
/// so near-window proposals surface first.
#[tokio::test]
async fn list_transitions_sorted_by_effective_epoch() {
    let state = test_state();

    let late = split_seal_at(200);
    let early = split_seal_at(100); // effective_epoch 103 < 203

    let _ = ok_or_panic(
        propose_transition(State(state.clone()), Json(late)).await,
        "propose late",
    );
    let _ = ok_or_panic(
        propose_transition(State(state.clone()), Json(early)).await,
        "propose early",
    );

    let list = ok_or_panic(
        list_transitions(State(state), Query(ListPendingParams::default())).await,
        "list",
    );
    assert_eq!(list.0.count, 2);
    assert!(list.0.transitions[0].effective_epoch <= list.0.transitions[1].effective_epoch);
    assert_eq!(list.0.transitions[0].effective_epoch, 103);
}

/// `/transitions?kind=split` returns only Split proposals. `?kind=merge`
/// returns only Merge. Bare request returns both. Unknown kind is 400.
#[tokio::test]
async fn list_transitions_kind_filter() {
    let state = test_state();

    // Propose 1 split + 1 merge, distinct epochs so ids differ.
    let split = split_seal_at(100);
    let merge = merge_seal_at(200);
    let _ = ok_or_panic(
        propose_transition(State(state.clone()), Json(split)).await,
        "propose split",
    );
    let _ = ok_or_panic(
        propose_transition(State(state.clone()), Json(merge)).await,
        "propose merge",
    );

    // No filter → both.
    let all = ok_or_panic(
        list_transitions(State(state.clone()), Query(ListPendingParams::default())).await,
        "all",
    );
    assert_eq!(all.0.count, 2);

    // kind=split → only split.
    let splits = ok_or_panic(
        list_transitions(
            State(state.clone()),
            Query(ListPendingParams {
                kind: Some("split".into()),
                status: None,
                zone: None,
            }),
        )
        .await,
        "splits",
    );
    assert_eq!(splits.0.count, 1);
    assert_eq!(splits.0.transitions[0].kind, "Split");

    // Case-insensitive — "MERGE" same as "merge".
    let merges = ok_or_panic(
        list_transitions(
            State(state.clone()),
            Query(ListPendingParams {
                kind: Some("MERGE".into()),
                status: None,
                zone: None,
            }),
        )
        .await,
        "merges",
    );
    assert_eq!(merges.0.count, 1);
    assert_eq!(merges.0.transitions[0].kind, "Merge");

    // Unknown kind → AppError (400 at HTTP layer), not silent empty.
    let err = err_msg(
        list_transitions(
            State(state),
            Query(ListPendingParams {
                kind: Some("schism".into()),
                status: None,
                zone: None,
            }),
        )
        .await,
        "unknown kind",
    );
    assert!(err.contains("schism"), "got {err}");
}

/// `/transitions?status=vetoed|awaitingsigs` narrows the list to
/// entries at a specific lifecycle stage. Symmetric to `?kind=`,
/// combinable with it (AND), case-insensitive, 400 on unknown.
#[tokio::test]
async fn list_transitions_status_filter() {
    use crate::network::transition_store::{VetoReason, MIN_VETOES_TO_HALT};
    let state = test_state();

    // Two splits proposed. Both start AwaitingSigs.
    let a = split_seal_at(100);
    let b = split_seal_at(200);
    let resp_a = ok_or_panic(
        propose_transition(State(state.clone()), Json(a)).await,
        "propose a",
    );
    let _ = ok_or_panic(
        propose_transition(State(state.clone()), Json(b)).await,
        "propose b",
    );

    // Push proposal A past the veto threshold directly through the
    // store (test state has no registered vetoer pubkeys, and the
    // behaviour under test is list filtering, not veto verify).
    let a_id: [u8; 32] = hex::decode(&resp_a.0.id)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    {
        let mut store = state.transitions.write().unwrap();
        for i in 0..MIN_VETOES_TO_HALT {
            let v = crate::network::transition_store::TransitionVeto {
                seal_hash: a_id,
                reason: VetoReason::BadBoundary,
                evidence: vec![i as u8],
                submitted_at_epoch: 101,
                vetoer_identity_hash: [i as u8 + 1; 32],
                dilithium3_sig: vec![0xaa; 32],
            };
            store.add_veto(&a_id, v, 101).expect("add_veto");
        }
        assert_eq!(store.get(&a_id).unwrap().status, PendingStatus::Vetoed);
    }

    // status=vetoed → only A.
    let vetoed = ok_or_panic(
        list_transitions(
            State(state.clone()),
            Query(ListPendingParams {
                kind: None,
                status: Some("vetoed".into()),
                zone: None,
            }),
        )
        .await,
        "vetoed",
    );
    assert_eq!(vetoed.0.count, 1);
    assert_eq!(vetoed.0.transitions[0].status, "Vetoed");

    // status=AwaitingSigs (case-insensitive) → only B.
    let awaiting = ok_or_panic(
        list_transitions(
            State(state.clone()),
            Query(ListPendingParams {
                kind: None,
                status: Some("AwaitingSigs".into()),
                zone: None,
            }),
        )
        .await,
        "awaiting",
    );
    assert_eq!(awaiting.0.count, 1);
    assert_eq!(awaiting.0.transitions[0].status, "AwaitingSigs");

    // kind=split AND status=vetoed → still only A (both predicates match).
    let both = ok_or_panic(
        list_transitions(
            State(state.clone()),
            Query(ListPendingParams {
                kind: Some("split".into()),
                status: Some("vetoed".into()),
                zone: None,
            }),
        )
        .await,
        "kind+status",
    );
    assert_eq!(both.0.count, 1);

    // kind=merge AND status=vetoed → empty (both splits, nothing
    // matches kind=merge).
    let none = ok_or_panic(
        list_transitions(
            State(state.clone()),
            Query(ListPendingParams {
                kind: Some("merge".into()),
                status: Some("vetoed".into()),
                zone: None,
            }),
        )
        .await,
        "no intersection",
    );
    assert_eq!(none.0.count, 0);

    // Unknown status → 400.
    let err = err_msg(
        list_transitions(
            State(state),
            Query(ListPendingParams {
                kind: None,
                status: Some("zombie".into()),
                zone: None,
            }),
        )
        .await,
        "unknown status",
    );
    assert!(err.contains("zombie"), "got {err}");
}

/// `/transitions/finalized?kind=split|merge` filters the CF scan
/// and drives `total` off the filtered set so paging stays coherent.
#[tokio::test]
async fn list_finalized_kind_filter() {
    let state = test_state();

    // Persist 2 split + 1 merge finalized seals.
    for proposed in [100u64, 200] {
        let seal = split_seal_at(proposed);
        let id = seal.seal_hash_for_sig().expect("hash");
        let bytes = serde_json::to_vec(&seal).expect("serialize");
        state
            .rocks
            .put_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id, &bytes)
            .expect("persist split");
    }
    let merge = merge_seal_at(300);
    let mid = merge.seal_hash_for_sig().expect("hash");
    let mbytes = serde_json::to_vec(&merge).expect("serialize");
    state
        .rocks
        .put_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &mid, &mbytes)
        .expect("persist merge");

    // No filter → all 3.
    let all = ok_or_panic(
        list_finalized_transitions(State(state.clone()), Query(ListFinalizedParams::default()))
            .await,
        "all",
    );
    assert_eq!(all.0.total, Some(3));
    assert_eq!(all.0.count, 3);

    // kind=split → 2.
    let splits = ok_or_panic(
        list_finalized_transitions(
            State(state.clone()),
            Query(ListFinalizedParams {
                offset: None,
                limit: None,
                kind: Some("split".into()),
                since_epoch: None,
                until_epoch: None,
                zone: None,
            }),
        )
        .await,
        "splits",
    );
    assert_eq!(splits.0.total, Some(2));
    assert!(splits.0.transitions.iter().all(|t| t.kind == "Split"));

    // kind=merge → 1.
    let merges = ok_or_panic(
        list_finalized_transitions(
            State(state.clone()),
            Query(ListFinalizedParams {
                offset: None,
                limit: None,
                kind: Some("merge".into()),
                since_epoch: None,
                until_epoch: None,
                zone: None,
            }),
        )
        .await,
        "merges",
    );
    assert_eq!(merges.0.total, Some(1));
    assert_eq!(merges.0.transitions[0].kind, "Merge");

    // Unknown kind → 400.
    let err = err_msg(
        list_finalized_transitions(
            State(state),
            Query(ListFinalizedParams {
                offset: None,
                limit: None,
                kind: Some("schism".into()),
                since_epoch: None,
                until_epoch: None,
                zone: None,
            }),
        )
        .await,
        "unknown",
    );
    assert!(err.contains("schism"), "got {err}");
}

/// `/transitions/finalized?since_epoch=<n>` filters out seals whose
/// `effective_epoch < n`. Clients polling for "anything new since
/// last pull" set since_epoch to their last-seen effective_epoch+1
/// and get the delta without re-scanning history.
#[tokio::test]
async fn list_finalized_since_epoch_filter() {
    let state = test_state();

    // Persist 3 splits with distinct effective_epochs: 103, 203, 303.
    for proposed in [100u64, 200, 300] {
        let seal = split_seal_at(proposed);
        let id = seal.seal_hash_for_sig().expect("hash");
        let bytes = serde_json::to_vec(&seal).expect("serialize");
        state
            .rocks
            .put_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id, &bytes)
            .expect("persist");
    }

    // since_epoch=0 → all 3 (inclusive lower bound).
    let all = ok_or_panic(
        list_finalized_transitions(
            State(state.clone()),
            Query(ListFinalizedParams {
                offset: None,
                limit: None,
                kind: None,
                since_epoch: Some(0),
                until_epoch: None,
                zone: None,
            }),
        )
        .await,
        "all",
    );
    assert_eq!(all.0.total, Some(3));

    // since_epoch=200 → only 203 and 303 survive (>= 200).
    let delta = ok_or_panic(
        list_finalized_transitions(
            State(state.clone()),
            Query(ListFinalizedParams {
                offset: None,
                limit: None,
                kind: None,
                since_epoch: Some(200),
                until_epoch: None,
                zone: None,
            }),
        )
        .await,
        "since=200",
    );
    assert_eq!(delta.0.total, Some(2));
    assert!(delta.0.transitions.iter().all(|t| t.effective_epoch >= 200));

    // since_epoch=304 → nothing (strict post-newest).
    let empty = ok_or_panic(
        list_finalized_transitions(
            State(state.clone()),
            Query(ListFinalizedParams {
                offset: None,
                limit: None,
                kind: None,
                since_epoch: Some(304),
                until_epoch: None,
                zone: None,
            }),
        )
        .await,
        "past-newest",
    );
    assert_eq!(empty.0.total, Some(0));

    // kind=split AND since_epoch=200 → still 2 (both late entries
    // are splits). AND-semantics preserved.
    let both = ok_or_panic(
        list_finalized_transitions(
            State(state),
            Query(ListFinalizedParams {
                offset: None,
                limit: None,
                kind: Some("split".into()),
                since_epoch: Some(200),
                until_epoch: None,
                zone: None,
            }),
        )
        .await,
        "kind+since",
    );
    assert_eq!(both.0.total, Some(2));
}

/// `/transitions/finalized?until_epoch=<n>` filters out seals
/// whose `effective_epoch > n`. Combined with `since_epoch` this
/// gives clients arbitrary epoch-range queries for timeline views.
#[tokio::test]
async fn list_finalized_until_epoch_filter() {
    let state = test_state();

    // Persist 3 splits with effective_epochs 103, 203, 303.
    for proposed in [100u64, 200, 300] {
        let seal = split_seal_at(proposed);
        let id = seal.seal_hash_for_sig().expect("hash");
        let bytes = serde_json::to_vec(&seal).expect("serialize");
        state
            .rocks
            .put_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id, &bytes)
            .expect("persist");
    }

    // until_epoch=203 → keeps 103 and 203 (inclusive upper bound),
    // drops 303.
    let early_half = ok_or_panic(
        list_finalized_transitions(
            State(state.clone()),
            Query(ListFinalizedParams {
                offset: None,
                limit: None,
                kind: None,
                since_epoch: None,
                until_epoch: Some(203),
                zone: None,
            }),
        )
        .await,
        "until=203",
    );
    assert_eq!(early_half.0.total, Some(2));
    assert!(early_half
        .0
        .transitions
        .iter()
        .all(|t| t.effective_epoch <= 203));

    // until_epoch=102 → strictly before the oldest entry → 0 hits.
    let empty = ok_or_panic(
        list_finalized_transitions(
            State(state.clone()),
            Query(ListFinalizedParams {
                offset: None,
                limit: None,
                kind: None,
                since_epoch: None,
                until_epoch: Some(102),
                zone: None,
            }),
        )
        .await,
        "pre-oldest",
    );
    assert_eq!(empty.0.total, Some(0));

    // since_epoch=200 AND until_epoch=250 → window isolates 203.
    // AND-composition across both epoch bounds.
    let window = ok_or_panic(
        list_finalized_transitions(
            State(state.clone()),
            Query(ListFinalizedParams {
                offset: None,
                limit: None,
                kind: None,
                since_epoch: Some(200),
                until_epoch: Some(250),
                zone: None,
            }),
        )
        .await,
        "range",
    );
    assert_eq!(window.0.total, Some(1));
    assert_eq!(window.0.transitions[0].effective_epoch, 203);

    // since > until → empty set (client asked for a zero-width window).
    let inverted = ok_or_panic(
        list_finalized_transitions(
            State(state),
            Query(ListFinalizedParams {
                offset: None,
                limit: None,
                kind: None,
                since_epoch: Some(300),
                until_epoch: Some(200),
                zone: None,
            }),
        )
        .await,
        "inverted",
    );
    assert_eq!(inverted.0.total, Some(0));
}

/// `/transitions/finalized?zone=<zone_id>` filters to seals that
/// reference the zone in either parents or children. Zone-operators
/// use this to scope history to "transitions that affected MY zone"
/// — the split that produced it and any merges that consumed it.
#[tokio::test]
async fn list_finalized_zone_filter() {
    let state = test_state();

    // Split seal references "test/parent" in parents and
    // "test/child-a" / "test/child-b" in children (see test helper).
    let split = split_seal_at(100);
    let sid = split.seal_hash_for_sig().expect("hash");
    let sbytes = serde_json::to_vec(&split).expect("ser");
    state
        .rocks
        .put_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &sid, &sbytes)
        .expect("persist split");

    // Merge seal references "test/parent-a" / "test/parent-b" as
    // parents and "test/merged" as child — no overlap with the split.
    let merge = merge_seal_at(200);
    let mid = merge.seal_hash_for_sig().expect("hash");
    let mbytes = serde_json::to_vec(&merge).expect("ser");
    state
        .rocks
        .put_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &mid, &mbytes)
        .expect("persist merge");

    // zone=test/child-a → matches the split's child, only 1 hit.
    let child = ok_or_panic(
        list_finalized_transitions(
            State(state.clone()),
            Query(ListFinalizedParams {
                offset: None,
                limit: None,
                kind: None,
                since_epoch: None,
                until_epoch: None,
                zone: Some("test/child-a".into()),
            }),
        )
        .await,
        "child",
    );
    assert_eq!(child.0.total, Some(1));
    assert_eq!(child.0.transitions[0].kind, "Split");

    // zone=test/merged → matches the merge's child, only 1 hit.
    let merged = ok_or_panic(
        list_finalized_transitions(
            State(state.clone()),
            Query(ListFinalizedParams {
                offset: None,
                limit: None,
                kind: None,
                since_epoch: None,
                until_epoch: None,
                zone: Some("test/merged".into()),
            }),
        )
        .await,
        "merged",
    );
    assert_eq!(merged.0.total, Some(1));
    assert_eq!(merged.0.transitions[0].kind, "Merge");

    // Normalization: "TEST/CHILD-A" must match the lower-case
    // normalized zone_id. ZoneId::new handles that.
    let upcased = ok_or_panic(
        list_finalized_transitions(
            State(state.clone()),
            Query(ListFinalizedParams {
                offset: None,
                limit: None,
                kind: None,
                since_epoch: None,
                until_epoch: None,
                zone: Some("TEST/CHILD-A".into()),
            }),
        )
        .await,
        "upcased",
    );
    assert_eq!(upcased.0.total, Some(1));

    // zone=does/not/exist → 0 hits.
    let nope = ok_or_panic(
        list_finalized_transitions(
            State(state),
            Query(ListFinalizedParams {
                offset: None,
                limit: None,
                kind: None,
                since_epoch: None,
                until_epoch: None,
                zone: Some("does/not/exist".into()),
            }),
        )
        .await,
        "nope",
    );
    assert_eq!(nope.0.total, Some(0));
}

/// `/transitions?zone=<zone_id>` filters pending entries to seals
/// that reference the zone in either parents or children. Symmetric
/// to `/transitions/finalized?zone=` — zone-operators watch "is a
/// split/merge affecting MY zone currently in-flight?" without
/// scanning the whole pending set.
#[tokio::test]
async fn list_transitions_zone_filter() {
    let state = test_state();

    // Two proposals: a split (parents=test/parent, children=test/child-a,
    // test/child-b) and a merge (parents=test/parent-a, test/parent-b,
    // children=test/merged) — no zone overlap between the two.
    let split = split_seal_at(100);
    let merge = merge_seal_at(200);
    let _ = ok_or_panic(
        propose_transition(State(state.clone()), Json(split)).await,
        "propose split",
    );
    let _ = ok_or_panic(
        propose_transition(State(state.clone()), Json(merge)).await,
        "propose merge",
    );

    // zone=test/parent → split's parent, 1 hit.
    let parent = ok_or_panic(
        list_transitions(
            State(state.clone()),
            Query(ListPendingParams {
                kind: None,
                status: None,
                zone: Some("test/parent".into()),
            }),
        )
        .await,
        "parent",
    );
    assert_eq!(parent.0.count, 1);
    assert_eq!(parent.0.transitions[0].kind, "Split");

    // zone=test/child-b → split's child, 1 hit.
    let child_b = ok_or_panic(
        list_transitions(
            State(state.clone()),
            Query(ListPendingParams {
                kind: None,
                status: None,
                zone: Some("test/child-b".into()),
            }),
        )
        .await,
        "child-b",
    );
    assert_eq!(child_b.0.count, 1);
    assert_eq!(child_b.0.transitions[0].kind, "Split");

    // zone=test/merged → merge's child, 1 hit.
    let merged = ok_or_panic(
        list_transitions(
            State(state.clone()),
            Query(ListPendingParams {
                kind: None,
                status: None,
                zone: Some("test/merged".into()),
            }),
        )
        .await,
        "merged",
    );
    assert_eq!(merged.0.count, 1);
    assert_eq!(merged.0.transitions[0].kind, "Merge");

    // Normalization: uppercase + trailing slash must still match
    // the lower-case normalized zone_id. ZoneId::new handles that.
    let upcased = ok_or_panic(
        list_transitions(
            State(state.clone()),
            Query(ListPendingParams {
                kind: None,
                status: None,
                zone: Some("TEST/PARENT-A/".into()),
            }),
        )
        .await,
        "upcased",
    );
    assert_eq!(upcased.0.count, 1);
    assert_eq!(upcased.0.transitions[0].kind, "Merge");

    // zone filter combines with kind filter (AND): kind=split &
    // zone=test/parent-a → 0 hits (parent-a only appears in merge).
    let cross = ok_or_panic(
        list_transitions(
            State(state.clone()),
            Query(ListPendingParams {
                kind: Some("split".into()),
                status: None,
                zone: Some("test/parent-a".into()),
            }),
        )
        .await,
        "cross",
    );
    assert_eq!(cross.0.count, 0);

    // No match.
    let nope = ok_or_panic(
        list_transitions(
            State(state),
            Query(ListPendingParams {
                kind: None,
                status: None,
                zone: Some("does/not/exist".into()),
            }),
        )
        .await,
        "nope",
    );
    assert_eq!(nope.0.count, 0);
}

/// `/transitions/{id}` falls back to `CF_TRANSITIONS_FINAL` when the
/// entry has been pruned from the in-memory store. Clients can
/// deep-link by id long after the dispute window closed.
#[tokio::test]
async fn fetch_transition_falls_back_to_finalized_cf() {
    let state = test_state();

    // Persist a seal directly to CF_TRANSITIONS_FINAL as if it had
    // been finalized and then pruned from the hot store.
    let seal = split_seal_at(500);
    let id = seal.seal_hash_for_sig().expect("hash");
    let bytes = serde_json::to_vec(&seal).expect("serialize");
    state
        .rocks
        .put_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id, &bytes)
        .expect("persist");

    // No entry in the in-memory store — sanity check.
    {
        let store = state.transitions.read().expect("store");
        assert!(store.get(&id).is_none());
    }

    // Fetch by id hex — handler must hit the CF fallback.
    let resp = ok_or_panic(
        fetch_transition(State(state), Path(hex::encode(id))).await,
        "finalized-fetch",
    );
    assert_eq!(resp.0.status, "Finalized");
    assert_eq!(resp.0.seal.proposed_at_epoch, 500);
    assert!(!resp.0.window_open);
    assert!(
        resp.0.vetoes.is_empty(),
        "finalized CF rows carry no vetoes"
    );
}

/// `/transitions/{id}` still 404s for ids that aren't in EITHER the
/// hot store OR CF_TRANSITIONS_FINAL — the fallback must not mask
/// genuinely unknown ids.
#[tokio::test]
async fn fetch_transition_unknown_id_still_404s() {
    let state = test_state();
    let unknown_id = [0xee; 32];
    let err = err_msg(
        fetch_transition(State(state), Path(hex::encode(unknown_id))).await,
        "unknown",
    );
    assert!(
        err.contains("transition"),
        "expected not-found for unknown id, got {err}"
    );
}

/// Build a NodeState whose identity is configured as an Anchor AND
/// whose own pubkey is registered in `CF_IDENTITIES` — the two
/// conditions `maybe_cosign_transition` checks before auto-signing
/// a pending proposal.
fn test_state_as_anchor() -> Arc<NodeState> {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let config = NodeConfig {
        data_dir: data_dir.clone(),
        identity_path: data_dir.join("identity.json"),
        db_path: data_dir.join("elara.db"),
        admin_token: "test-admin".into(),
        network_id: "transitions-cosign-test".into(),
        mdns_enabled: false,
        health_check_interval_secs: 0,
        min_pow_difficulty: 0,
        node_type: "anchor".into(),
        ..Default::default()
    };

    let identity =
        Identity::generate(EntityType::Device, CryptoProfile::ProfileB).expect("generate identity");
    let rocks = Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
    // Register this node's own pubkey under its identity_hash so
    // verify_anchor_sig can resolve the cosign's key on any peer
    // (here modelled by the same local CF_IDENTITIES read).
    rocks
        .store_public_key(&identity.identity_hash, &identity.public_key)
        .expect("store own pubkey");
    let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
    let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
    std::mem::forget(tmp);
    state
}

/// Anchor-cosign end-to-end: an anchor node receiving an unsigned
/// proposal via `/transitions/propose` must auto-append its own
/// Dilithium3 signature to the pending store and bump
/// `cosigns_total`. Without this path, orchestrator-originated
/// proposals land 1-of-N on every anchor and expire at the window
/// boundary.
#[tokio::test]
async fn propose_triggers_anchor_cosign() {
    let state = test_state_as_anchor();

    // Baseline: cosigns_total must start at 0.
    let before = ok_or_panic(transition_stats(State(state.clone())).await, "before");
    assert_eq!(before.0.cosigns_total, 0);

    // Propose an unsigned seal. The handler should accept it (empty
    // proposer_sigs is legal at AwaitingSigs) and our cosign path
    // must auto-sign after the insert.
    let seal = split_seal_at(200);
    let propose_resp = ok_or_panic(
        propose_transition(State(state.clone()), Json(seal.clone())).await,
        "propose",
    );
    assert_eq!(
        propose_resp.0.sigs_collected, 0,
        "handler response reports the pre-cosign count (cosign runs after the insert ack)"
    );

    // The store entry must now carry exactly one sig — ours.
    let id_bytes: [u8; 32] = hex::decode(&propose_resp.0.id)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let stored_sigs = {
        let store = state.transitions.read().unwrap();
        let pending = store.get(&id_bytes).expect("pending entry");
        pending.seal.proposer_sigs.clone()
    };
    assert_eq!(stored_sigs.len(), 1, "exactly one cosign (ours)");

    // And the sig's anchor_identity_hash must match this node's
    // identity — no phantom cosigns.
    let own_hash: [u8; 32] = hex::decode(&state.identity.identity_hash)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    assert_eq!(stored_sigs[0].anchor_identity_hash, own_hash);

    // Counter reflects the increment.
    let after = ok_or_panic(transition_stats(State(state.clone())).await, "after");
    assert_eq!(after.0.cosigns_total, 1);
}

/// A non-anchor node must NOT auto-cosign. `maybe_cosign_transition`
/// short-circuits at the `can_seal_epochs()` check; this test pins
/// that contract so a later refactor can't accidentally broaden
/// who's allowed to inject sigs.
#[tokio::test]
async fn propose_skips_cosign_on_non_anchor() {
    let state = test_state(); // default node_type = "witness"
    let seal = split_seal_at(300);
    let propose_resp = ok_or_panic(
        propose_transition(State(state.clone()), Json(seal)).await,
        "propose",
    );
    let id_bytes: [u8; 32] = hex::decode(&propose_resp.0.id)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let sigs_len = {
        let store = state.transitions.read().unwrap();
        store
            .get(&id_bytes)
            .expect("pending")
            .seal
            .proposer_sigs
            .len()
    };
    assert_eq!(sigs_len, 0, "non-anchor must not cosign");

    let resp = ok_or_panic(transition_stats(State(state)).await, "stats");
    assert_eq!(resp.0.cosigns_total, 0);
}

/// Sig-level gossip dedup: `push_transition_sig_to_peers` uses a
/// per-(seal, anchor) SeenSet. A re-broadcast of the same
/// (seal_id, anchor_identity_hash) must increment
/// `sig_gossip_dedup_total` instead of re-forwarding.
#[tokio::test]
async fn sig_gossip_dedupes_same_seal_same_anchor() {
    use crate::network::zone_transition_seal::AnchorSig;
    let state = test_state();
    let seal_id = [0xa5u8; 32];
    let sig = AnchorSig {
        anchor_identity_hash: [0x11u8; 32],
        dilithium3_sig: vec![0xcc; 64],
    };

    // First push: no peers → pushed stays 0, but SeenSet records
    // the (seal, anchor) key.
    super::super::super::gossip::push_transition_sig_to_peers(&state, seal_id, &sig).await;
    let resp = ok_or_panic(transition_stats(State(state.clone())).await, "first");
    assert_eq!(resp.0.sig_gossip_pushed_total, 0);
    assert_eq!(resp.0.sig_gossip_dedup_total, 0);

    // Same (seal, anchor) again → dedup++.
    super::super::super::gossip::push_transition_sig_to_peers(&state, seal_id, &sig).await;
    let resp = ok_or_panic(transition_stats(State(state.clone())).await, "dup");
    assert_eq!(
        resp.0.sig_gossip_dedup_total, 1,
        "re-broadcast of same (seal, anchor) must hit dedup"
    );

    // Different anchor on same seal → not deduped (each anchor's
    // sig gets its own gossip slot).
    let other_sig = AnchorSig {
        anchor_identity_hash: [0x22u8; 32],
        dilithium3_sig: vec![0xdd; 64],
    };
    super::super::super::gossip::push_transition_sig_to_peers(&state, seal_id, &other_sig).await;
    let resp = ok_or_panic(transition_stats(State(state)).await, "other-anchor");
    assert_eq!(
        resp.0.sig_gossip_dedup_total, 1,
        "different anchor on same seal must not hit dedup"
    );
}

/// Register a vetoer: store a fresh Dilithium3 pubkey in
/// `CF_IDENTITIES` and return the (identity_hash, keypair) so the
/// caller can sign vetoes with a key the handler can verify.
/// Symmetric to `register_anchor` — different semantic slot, same
/// storage shape.
fn register_vetoer(state: &NodeState) -> ([u8; 32], DilithiumKeypair) {
    let kp = dilithium3_keygen().expect("keygen");
    let ident = sha3_256(&kp.public_key);
    state
        .rocks
        .store_public_key(&hex::encode(ident), &kp.public_key)
        .expect("store vetoer pubkey");
    (ident, kp)
}

/// Build a Dilithium3-signed `TransitionVeto` targeting `seal_hash`.
/// Signs the canonical veto bytes with `kp` so `submit_veto`'s
/// `verify_sig` path will accept it against the registered pubkey.
fn signed_veto(
    seal_hash: [u8; 32],
    vetoer_identity: [u8; 32],
    kp: &DilithiumKeypair,
    submitted_at_epoch: u64,
    evidence: Vec<u8>,
) -> TransitionVeto {
    use crate::network::transition_store::VetoReason;
    let mut v = TransitionVeto {
        seal_hash,
        reason: VetoReason::BadBoundary,
        evidence,
        submitted_at_epoch,
        vetoer_identity_hash: vetoer_identity,
        dilithium3_sig: vec![],
    };
    // Sign canonical-for-sig bytes (signature field cleared).
    let msg = v.canonical_encode_for_sig().expect("canonical encode");
    let hash = sha3_256(&msg);
    v.dilithium3_sig =
        dilithium3_sign_with_pk(&hash, &kp.secret_key, &kp.public_key).expect("sign veto");
    v
}

/// Gap 4 dispute veto — end-to-end integration through the HTTP
/// handlers: propose a seal, let it enter DisputeWindow (threshold
/// of cosigned-anchor sigs attached), then submit two independent
/// vetoes via `POST /transitions/{id}/veto`. The second veto must
/// flip status to `Vetoed` and the persisted CF row must be deleted
/// (a Vetoed proposal must NOT rehydrate on restart — that's what
/// `persist_pending_entry`'s delete-on-Vetoed branch is for).
///
/// This complements `veto_halt_deletes_pending_cf_row` which pokes
/// the store directly. The missing piece was the full HTTP path:
/// Dilithium3 sig verify on each veto, handler-driven status flip,
/// handler-driven CF cleanup.
#[tokio::test]
async fn submit_veto_halts_and_deletes_pending_via_http() {
    use crate::network::zone_transition_seal::SPLIT_ANCHOR_THRESHOLD;
    let state = test_state();

    // Build a Split seal and sign it with SPLIT_ANCHOR_THRESHOLD
    // registered anchors so it enters DisputeWindow on insert —
    // vetoes only apply once the window is open.
    // proposed_at_epoch=0 because the test NodeState has no state_core,
    // so best_effort_current_epoch returns 0 and add_veto's clock-skew
    // guard requires current_epoch >= proposed_at_epoch. effective_epoch
    // is 0 + TRANSITION_DISPUTE_WINDOW_EPOCHS = 3 — window stays open.
    let mut seal = split_seal_at(0);
    let seal_hash = seal.seal_hash_for_sig().expect("seal hash");
    let mut anchor_keys = Vec::new();
    for _ in 0..SPLIT_ANCHOR_THRESHOLD {
        let (ident, kp) = register_anchor(&state);
        stake_anchor(&state, ident).await;
        let sig_bytes =
            dilithium3_sign_with_pk(&seal_hash, &kp.secret_key, &kp.public_key).expect("sign seal");
        seal.proposer_sigs.push(AnchorSig {
            anchor_identity_hash: ident,
            dilithium3_sig: sig_bytes,
        });
        anchor_keys.push((ident, kp));
    }
    // Keep proposer_sigs in the canonical sorted order the seal
    // enforces on persist; the handler would re-sort anyway but
    // matching up-front avoids a spurious byte-diff in assertions.
    seal.proposer_sigs.sort_by_key(|s| s.anchor_identity_hash);

    let propose_resp = ok_or_panic(
        propose_transition(State(state.clone()), Json(seal)).await,
        "propose",
    );
    assert_eq!(
        propose_resp.0.status, "DisputeWindow",
        "seal with threshold sigs must enter DisputeWindow immediately"
    );
    let id_hex = propose_resp.0.id.clone();
    let id_bytes: [u8; 32] = hex::decode(&id_hex)
        .expect("hex")
        .try_into()
        .expect("32 bytes");

    // Pending CF row should exist — persist_pending_entry ran on insert.
    assert!(
        state
            .rocks
            .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_PENDING, &id_bytes)
            .unwrap()
            .is_some(),
        "pending CF row present after propose",
    );

    // First veto: handler accepts, status stays DisputeWindow (only
    // 1 veto, MIN_VETOES_TO_HALT=2). CF row still present.
    let (v1_ident, v1_kp) = register_vetoer(&state);
    let veto1 = signed_veto(id_bytes, v1_ident, &v1_kp, 1, vec![0xee]);
    let resp1 = ok_or_panic(
        submit_veto(State(state.clone()), Path(id_hex.clone()), Json(veto1)).await,
        "veto 1",
    );
    assert_eq!(
        resp1.0.status, "DisputeWindow",
        "single veto below MIN_VETOES_TO_HALT must not flip status"
    );
    assert_eq!(resp1.0.vetoes_count, 1);
    assert!(
        state
            .rocks
            .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_PENDING, &id_bytes)
            .unwrap()
            .is_some(),
        "CF row must still be present after a single veto",
    );

    // Second veto from a DIFFERENT identity: flips to Vetoed and
    // triggers the persist_pending delete-on-Vetoed branch.
    let (v2_ident, v2_kp) = register_vetoer(&state);
    let veto2 = signed_veto(id_bytes, v2_ident, &v2_kp, 1, vec![0xff]);
    let resp2 = ok_or_panic(
        submit_veto(State(state.clone()), Path(id_hex.clone()), Json(veto2)).await,
        "veto 2",
    );
    assert_eq!(
        resp2.0.status, "Vetoed",
        "second independent veto must flip status to Vetoed"
    );
    assert_eq!(resp2.0.vetoes_count, 2);
    assert!(
        state
            .rocks
            .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_PENDING, &id_bytes)
            .unwrap()
            .is_none(),
        "CF row must be deleted once status reaches Vetoed (restart must not rehydrate)",
    );

    // In-memory store still holds the Vetoed entry so /transitions/{id}
    // can serve the terminal status to clients/gossip that race the
    // tick's eviction.
    let store = state.transitions.read().unwrap();
    assert_eq!(store.get(&id_bytes).unwrap().status, PendingStatus::Vetoed);
}

/// Two vetoes from the SAME vetoer_identity must NOT halt — the
/// MIN_VETOES_TO_HALT threshold is on distinct identities, not on
/// veto count. Without this guard a single rogue peer could kill any
/// transition at fleet scale. Drives the second submit through the
/// HTTP handler the same way the halt test does.
#[tokio::test]
async fn submit_veto_duplicate_identity_does_not_halt() {
    use crate::network::zone_transition_seal::SPLIT_ANCHOR_THRESHOLD;
    let state = test_state();

    let mut seal = split_seal_at(0);
    let seal_hash = seal.seal_hash_for_sig().expect("seal hash");
    for _ in 0..SPLIT_ANCHOR_THRESHOLD {
        let (ident, kp) = register_anchor(&state);
        stake_anchor(&state, ident).await;
        let sig_bytes =
            dilithium3_sign_with_pk(&seal_hash, &kp.secret_key, &kp.public_key).expect("sign seal");
        seal.proposer_sigs.push(AnchorSig {
            anchor_identity_hash: ident,
            dilithium3_sig: sig_bytes,
        });
    }
    seal.proposer_sigs.sort_by_key(|s| s.anchor_identity_hash);
    let propose_resp = ok_or_panic(
        propose_transition(State(state.clone()), Json(seal)).await,
        "propose",
    );
    let id_hex = propose_resp.0.id.clone();
    let id_bytes: [u8; 32] = hex::decode(&id_hex)
        .expect("hex")
        .try_into()
        .expect("32 bytes");

    // Single vetoer submits two structurally-distinct vetoes (the
    // evidence bytes differ so veto_hash differs — otherwise the
    // store would dedup by veto_hash). The store's
    // "one-veto-per-vetoer" guard must still reject the second one.
    let (vid, vkp) = register_vetoer(&state);
    let veto_a = signed_veto(id_bytes, vid, &vkp, 1, vec![0x01]);
    let veto_b = signed_veto(id_bytes, vid, &vkp, 1, vec![0x02]);

    let _ = ok_or_panic(
        submit_veto(State(state.clone()), Path(id_hex.clone()), Json(veto_a)).await,
        "veto a",
    );
    let err = err_msg(
        submit_veto(State(state.clone()), Path(id_hex.clone()), Json(veto_b)).await,
        "veto b (same identity)",
    );
    // The store rejects with something identifying duplicate-vetoer;
    // handler surfaces the error string unchanged. Don't pin the
    // exact wording — just that we got an error AND the status stays
    // DisputeWindow.
    assert!(
        !err.is_empty(),
        "duplicate-vetoer veto must be rejected by the handler",
    );
    let store = state.transitions.read().unwrap();
    let pending = store.get(&id_bytes).unwrap();
    assert_eq!(
        pending.status,
        PendingStatus::DisputeWindow,
        "single-identity repeat veto must not reach MIN_VETOES_TO_HALT",
    );
    assert_eq!(
        pending.vetoes.len(),
        1,
        "only the first veto from this identity was recorded"
    );
}

/// Pull backstop gating — non-anchor nodes must no-op.
///
/// Rationale: pulling is a recovery path for anchors that missed a
/// seal via gossip. A light / witness node running the pull tick
/// would spend bandwidth and accomplish nothing (no cosign to
/// contribute). Make sure the gate catches the non-anchor case
/// before touching the network.
#[tokio::test]
async fn pull_tick_noop_on_non_anchor() {
    let state = test_state(); // non-anchor by default
    let before = ok_or_panic(transition_stats(State(state.clone())).await, "before");
    assert_eq!(before.0.pulled_total, 0);
    assert_eq!(before.0.pull_errors_total, 0);

    run_transition_pull_tick(&state).await;

    let after = ok_or_panic(transition_stats(State(state)).await, "after");
    assert_eq!(after.0.pulled_total, 0, "non-anchor must not pull");
    assert_eq!(
        after.0.pull_errors_total, 0,
        "non-anchor must exit before any fetch could fail"
    );
}

/// Pull backstop gating — anchor with no peers must no-op cleanly.
///
/// An anchor that's not yet connected to any relay peers has
/// nowhere to pull from. The tick must early-return without
/// incrementing the error counter (no fetch was attempted, so
/// there's no failure to record).
#[tokio::test]
async fn pull_tick_noop_without_peers() {
    let state = test_state_as_anchor();
    let before = ok_or_panic(transition_stats(State(state.clone())).await, "before");
    assert_eq!(before.0.pulled_total, 0);
    assert_eq!(before.0.pull_errors_total, 0);

    run_transition_pull_tick(&state).await;

    let after = ok_or_panic(transition_stats(State(state)).await, "after");
    assert_eq!(after.0.pulled_total, 0);
    assert_eq!(
        after.0.pull_errors_total, 0,
        "no peers to hit ⇒ no fetch ⇒ no error counter bump"
    );
}

// ─── decode_id / pagination / cold-boot pins ────────────────────────────
//
// Three sync pins on previously-uncovered surfaces in this module:
//   1. `decode_id` happy path + invalid-hex + wrong-length branches
//   2. Pagination + lead-epoch constants with cross-constraints
//   3. `best_effort_current_epoch` cold-boot fallback (state_core unset)

#[test]
fn batch_af_decode_id_happy_path_and_two_error_branches_pin_32_byte_invariant() {
    // Happy path: 64 hex chars → exactly 32 bytes.
    let all_zero = "0".repeat(64);
    let decoded = decode_id(&all_zero).expect("64-zero-hex decodes");
    assert_eq!(decoded, [0u8; 32], "zeroes pass through verbatim");

    // Happy path: non-trivial bytes round-trip.
    let mixed = hex::encode([0x01u8, 0xab, 0xcd, 0xef].repeat(8));
    assert_eq!(mixed.len(), 64);
    let decoded_mixed = decode_id(&mixed).expect("32-byte mixed hex decodes");
    assert_eq!(decoded_mixed[0], 0x01);
    assert_eq!(decoded_mixed[3], 0xef);
    assert_eq!(decoded_mixed[31], 0xef);

    // Error: not-hex string.
    let bad = decode_id("this-is-not-hex-at-all-zzzzzzzz");
    let bad_msg = format!("{:?}", bad.expect_err("non-hex must error"));
    assert!(
        bad_msg.contains("invalid id hex"),
        "non-hex error must mention 'invalid id hex'; got {bad_msg}"
    );

    // Error: wrong length — 31 bytes (62 hex chars).
    let short = "0".repeat(62);
    let short_err = format!("{:?}", decode_id(&short).expect_err("31 bytes must error"));
    assert!(
        short_err.contains("got 31 bytes"),
        "31-byte error must report 'got 31 bytes'; got {short_err}"
    );

    // Error: wrong length — 33 bytes (66 hex chars).
    let long = "0".repeat(66);
    let long_err = format!("{:?}", decode_id(&long).expect_err("33 bytes must error"));
    assert!(
        long_err.contains("got 33 bytes"),
        "33-byte error must report 'got 33 bytes'; got {long_err}"
    );
}

#[test]
fn batch_af_pagination_constants_pin_default_le_max_le_list_invariant() {
    // Pin literal values so a silent bump trips this exact-name test.
    assert_eq!(super::PROPOSAL_MAX_LEAD_EPOCHS, 2);
    assert_eq!(super::FINALIZED_LIST_MAX, 4096);
    assert_eq!(super::FINALIZED_PAGE_DEFAULT, 128);
    assert_eq!(super::FINALIZED_PAGE_MAX, 1024);

    // Cross-constraints page-default ≤ page-max ≤ list-max pinned
    // at compile time via the `const _: () = assert!(..)` block
    // next to the const declarations (routes/transitions.rs ~L1010).
    // A regression now fails at `cargo build`, not at `cargo test`.
    // Runtime asserts removed (clippy::assertions_on_constants —
    // both operands const-eval).
}

#[test]
fn batch_af_best_effort_current_epoch_cold_boot_falls_back_to_zero_when_state_core_not_set() {
    // `test_state()` builds a NodeState without installing state_core —
    // mimicking the cold-boot window before bootstrap completes. The
    // doc-comment on `best_effort_current_epoch` documents that this
    // returns 0 in that window (so `current_epoch < proposed_at` flips
    // the clock-skew-reject default on the safe side).
    let state = test_state();
    assert!(
        state.state_core.get().is_none(),
        "precondition: cold-boot state has no state_core installed"
    );
    assert_eq!(
            best_effort_current_epoch(&state),
            0,
            "cold-boot fallback MUST be 0 — anchors propose >0 epochs, so clock-skew gate rejects safely"
        );
}

// ─── Pin the residual fixture-free surface that
// the decode_id / pagination-const / cold-boot-fallback tests and the
// 50-odd full-fixture tests above leave uncovered. These are the wire
// contracts on the public response + query-param structs plus the
// pure status-label mapping that the PQ router and the axum route both
// serialize through compute_list_transitions. A silent drop or rename
// here is the kind of regression the type-checker waves past but that
// breaks every PQ + REST client downstream.
// ────────────────────────────────────────────────────────────────────

#[test]
fn batch_b_status_label_pins_pascal_case_round_trip_for_all_five_variants() {
    // PIN: routes/transitions.rs:1818 — status_label is the wire-string
    // mapping for the 5 PendingStatus variants. Consumed by both the
    // axum routes (TransitionView.status, TransitionSummary.status,
    // ProposeResponse.status, VetoResponse.status, SigResponse.status)
    // AND the PQ router via compute_list_transitions. Both transports
    // MUST serialize byte-identical strings — a silent rename to
    // snake_case here would split the PQ + REST clients into two
    // different parse paths. Pin all 5 variants with exact strings.
    assert_eq!(
        status_label(PendingStatus::AwaitingSigs),
        "AwaitingSigs",
        "PendingStatus::AwaitingSigs MUST serialize as PascalCase 'AwaitingSigs'",
    );
    assert_eq!(
        status_label(PendingStatus::DisputeWindow),
        "DisputeWindow",
        "PendingStatus::DisputeWindow MUST serialize as PascalCase 'DisputeWindow'",
    );
    assert_eq!(
        status_label(PendingStatus::Vetoed),
        "Vetoed",
        "PendingStatus::Vetoed MUST serialize as PascalCase 'Vetoed'",
    );
    assert_eq!(
        status_label(PendingStatus::Finalized),
        "Finalized",
        "PendingStatus::Finalized MUST serialize as PascalCase 'Finalized'",
    );
    assert_eq!(
        status_label(PendingStatus::Expired),
        "Expired",
        "PendingStatus::Expired MUST serialize as PascalCase 'Expired'",
    );

    // Round-trip pin: status filter case-insensitive parse (lowercase
    // accepted via compute_list_transitions) ⇄ PascalCase emit
    // (status_label). A regression that swaps either direction breaks
    // GET /transitions?status=finalized vs the response's
    // status:"Finalized" symmetry, which is the convention every
    // explorer + ops script relies on.
    for variant in [
        PendingStatus::AwaitingSigs,
        PendingStatus::DisputeWindow,
        PendingStatus::Vetoed,
        PendingStatus::Finalized,
        PendingStatus::Expired,
    ] {
        let label = status_label(variant);
        // Property pin: every label is a non-empty ASCII string whose
        // first char is uppercase (PascalCase invariant).
        assert!(!label.is_empty(), "no variant may produce empty label");
        assert!(
            label.chars().next().unwrap().is_ascii_uppercase(),
            "every label must start with ASCII uppercase (PascalCase); got {label:?}",
        );
    }
}

#[test]
fn batch_b_list_finalized_params_serde_defaults_pin_six_optional_fields() {
    // PIN: ListFinalizedParams at routes/transitions.rs:807 — every
    // field carries `#[serde(default)]` so a bare query string
    // (`GET /transitions/finalized`) deserializes to all-None defaults.
    // If a future refactor drops `#[serde(default)]` from ANY field,
    // the bare-query path fails at axum's extractor with a 422 — a
    // silent breakage that the existing happy-path tests with
    // explicit fields don't catch.
    //
    // The six fields are: offset, limit, kind, since_epoch,
    // until_epoch, zone. Pin them all.
    let empty: ListFinalizedParams = serde_json::from_value(serde_json::json!({})).expect(
        "ListFinalizedParams MUST deserialize from empty object — all fields are #[serde(default)]",
    );
    assert!(empty.offset.is_none(), "empty → offset=None");
    assert!(empty.limit.is_none(), "empty → limit=None");
    assert!(empty.kind.is_none(), "empty → kind=None");
    assert!(empty.since_epoch.is_none(), "empty → since_epoch=None");
    assert!(empty.until_epoch.is_none(), "empty → until_epoch=None");
    assert!(empty.zone.is_none(), "empty → zone=None");

    // Field-name pin: rename catches. A silent rename of `since_epoch`
    // → `from_epoch` would silently let the explorer-poll loop send
    // queries that no longer narrow the response.
    let full: ListFinalizedParams = serde_json::from_value(serde_json::json!({
        "offset": 100,
        "limit": 50,
        "kind": "Split",
        "since_epoch": 42,
        "until_epoch": 99,
        "zone": "medical/eu",
    }))
    .expect("ListFinalizedParams MUST accept all 6 named fields");
    assert_eq!(
        full.offset,
        Some(100),
        "field name 'offset' must round-trip"
    );
    assert_eq!(full.limit, Some(50), "field name 'limit' must round-trip");
    assert_eq!(full.kind.as_deref(), Some("Split"));
    assert_eq!(full.since_epoch, Some(42));
    assert_eq!(full.until_epoch, Some(99));
    assert_eq!(full.zone.as_deref(), Some("medical/eu"));
}

#[test]
fn batch_b_list_pending_params_three_filter_fields_distinct_from_finalized_pagination() {
    // PIN: ListPendingParams at routes/transitions.rs:842 is a
    // 3-field DELTA from ListFinalizedParams — it carries only
    // filters (kind, status, zone) with NO pagination (offset,
    // limit, since_epoch, until_epoch are absent). This asymmetry
    // is load-bearing: /transitions/finalized supports paginated
    // history walks, /transitions returns the (small, bounded)
    // pending set in full. If a future refactor accidentally
    // generalizes both routes to the same param struct, the
    // pending-list response loses its always-complete invariant
    // (count == total).
    let empty: ListPendingParams = serde_json::from_value(serde_json::json!({})).expect(
        "ListPendingParams MUST deserialize from empty object — all 3 fields are #[serde(default)]",
    );
    assert!(empty.kind.is_none(), "empty → kind=None");
    assert!(empty.status.is_none(), "empty → status=None");
    assert!(empty.zone.is_none(), "empty → zone=None");

    // Round-trip the three actual filter names.
    let full: ListPendingParams = serde_json::from_value(serde_json::json!({
        "kind": "Merge",
        "status": "awaitingsigs",
        "zone": "research/ml",
    }))
    .expect("ListPendingParams MUST accept all 3 filter fields");
    assert_eq!(full.kind.as_deref(), Some("Merge"));
    assert_eq!(full.status.as_deref(), Some("awaitingsigs"));
    assert_eq!(full.zone.as_deref(), Some("research/ml"));

    // Extras-ignored invariant: serde without `deny_unknown_fields`
    // tolerates extra wire keys, which is the right semantic for a
    // forward-compatible HTTP route. Pin that behavior — a regression
    // that adds `deny_unknown_fields` would break older clients that
    // send a richer query.
    let extras: ListPendingParams = serde_json::from_value(serde_json::json!({
        "kind": "Split",
        "offset": 100,    // belongs on ListFinalizedParams, not here
        "limit": 50,      // same
    }))
    .expect("extras must be tolerated for forward compat");
    assert_eq!(extras.kind.as_deref(), Some("Split"));
    assert!(
        extras.status.is_none(),
        "status must NOT silently default from any extra"
    );
    assert!(
        extras.zone.is_none(),
        "zone must NOT silently default from any extra"
    );
}

#[test]
fn batch_b_transition_list_response_skip_if_none_pins_pagination_metadata_optionality() {
    // PIN: TransitionListResponse at routes/transitions.rs:766 emits
    // `total`, `offset`, `limit` via
    // `#[serde(skip_serializing_if = "Option::is_none")]`. The
    // pending-list endpoint (no pagination) sets all three to None
    // → wire shape MUST be the 3-key core (count, current_epoch,
    // transitions). The finalized-list endpoint sets all three to
    // Some → wire shape MUST grow to 6 keys. If a refactor drops
    // the skip_if attribute, the pending-list response would emit
    // `"total":null,"offset":null,"limit":null` — older clients
    // assuming a present-key-means-paginated heuristic would
    // mis-classify the response and double-fetch.
    let bare = TransitionListResponse {
        count: 5,
        current_epoch: 100,
        transitions: vec![],
        total: None,
        offset: None,
        limit: None,
    };
    let bare_json = serde_json::to_value(&bare).expect("serialize bare response");
    let bare_map = bare_json.as_object().expect("response is an object");
    assert_eq!(
            bare_map.len(),
            3,
            "pending-list TransitionListResponse MUST emit exactly 3 keys (count, current_epoch, transitions) — got {} ({:?}). Drift means skip_serializing_if_none was dropped on pagination fields.",
            bare_map.len(),
            bare_map.keys().collect::<Vec<_>>(),
        );
    assert!(bare_map.contains_key("count"), "count is required");
    assert!(
        bare_map.contains_key("current_epoch"),
        "current_epoch is required"
    );
    assert!(
        bare_map.contains_key("transitions"),
        "transitions is required"
    );
    assert!(
        !bare_map.contains_key("total"),
        "total MUST be omitted when None"
    );
    assert!(
        !bare_map.contains_key("offset"),
        "offset MUST be omitted when None"
    );
    assert!(
        !bare_map.contains_key("limit"),
        "limit MUST be omitted when None"
    );

    // Paginated case: all 3 Some → wire shape has all 6 keys.
    let paged = TransitionListResponse {
        count: 5,
        current_epoch: 100,
        transitions: vec![],
        total: Some(42),
        offset: Some(10),
        limit: Some(5),
    };
    let paged_json = serde_json::to_value(&paged).expect("serialize paged response");
    let paged_map = paged_json.as_object().expect("response is an object");
    assert_eq!(
            paged_map.len(),
            6,
            "paginated TransitionListResponse MUST emit all 6 keys when total/offset/limit are Some — got {} ({:?})",
            paged_map.len(),
            paged_map.keys().collect::<Vec<_>>(),
        );
    assert_eq!(paged_map.get("total").and_then(|x| x.as_u64()), Some(42));
    assert_eq!(paged_map.get("offset").and_then(|x| x.as_u64()), Some(10));
    assert_eq!(paged_map.get("limit").and_then(|x| x.as_u64()), Some(5));
}

#[test]
fn batch_b_decode_id_uppercase_hex_accepted_pins_case_insensitive_invariant() {
    // PIN: routes/transitions.rs:1985 — decode_id delegates to
    // hex::decode which is case-insensitive per the standard.
    // The existing decode_id test covers all-zero (case-trivial)
    // and invalid-non-hex; this pins that uppercase A-F is also
    // accepted. Operator tooling (cURL invocations, ops scripts
    // pasting hashes from logs) commonly mixes case — a silent
    // tightening to lowercase-only would break them.
    let lower = "deadbeef".repeat(8);
    let upper = "DEADBEEF".repeat(8);
    let mixed = "DeAdBeEf".repeat(8);

    assert_eq!(lower.len(), 64);
    assert_eq!(upper.len(), 64);
    assert_eq!(mixed.len(), 64);

    let decoded_lower = decode_id(&lower).expect("lowercase 64-hex must decode");
    let decoded_upper = decode_id(&upper).expect("uppercase 64-hex must decode");
    let decoded_mixed = decode_id(&mixed).expect("mixed-case 64-hex must decode");

    // Case-insensitive invariant: all three byte arrays are equal.
    assert_eq!(
            decoded_lower, decoded_upper,
            "lowercase and uppercase hex MUST decode to the same byte array (case-insensitive invariant)",
        );
    // Byte content is `deadbeef…` repeated → first byte 0xde, second 0xad, etc.
    assert_eq!(decoded_lower[0], 0xde);
    assert_eq!(decoded_lower[1], 0xad);
    assert_eq!(decoded_lower[2], 0xbe);
    assert_eq!(decoded_lower[3], 0xef);
    // Mixed-case is the practical operator scenario (copy-paste from
    // a heterogeneous log).
    assert_eq!(
        decoded_lower, decoded_mixed,
        "mixed-case hex MUST also decode identically",
    );

    // Negative pin: a SINGLE non-hex char inside an otherwise-valid
    // 64-char string still rejects. Catches a regression that
    // relaxes the hex check to "ignore garbage chars".
    let mut tainted = "0".repeat(63);
    tainted.push('Z');
    assert_eq!(tainted.len(), 64);
    assert!(
            decode_id(&tainted).is_err(),
            "single non-hex char in a 64-len string MUST still reject — case-insensitivity does NOT extend to non-hex tolerance",
        );
}

// ─── Pin the un-covered response-struct
// surface that the decode_id / pagination-const / cold-boot-fallback tests
// and the status_label / TransitionListResponse / params-default /
// decode_id-uppercase tests leave untouched. ProposeResponse, TransitionSummary,
// ResolveResponse, VetoResponse, SigResponse, TransitionStatsResponse are
// all on the wire — every PQ + REST client downstream parses these shapes.
// A silent rename / type drift / lost `#[serde(skip_serializing_if)]`
// attribute here is exactly the regression class that compiles cleanly but
// breaks every operator dashboard + light-client follower at runtime.
// ────────────────────────────────────────────────────────────────────────

#[test]
fn batch_vvv_propose_response_strict_four_key_envelope_pins_serialize_only_wire_contract() {
    // PIN: ProposeResponse at routes/transitions.rs:548 — derives ONLY
    // `serde::Serialize` (no Deserialize). Pin the exact 4 keys + their
    // JSON types. A silent add of e.g. `accepted: bool` (the kind of
    // refactor that mirrors ProposeBody.accepted-flag) would inflate
    // every cURL-scraping ops script's parse path with a phantom field.
    let resp = ProposeResponse {
        id: "deadbeef".repeat(8),
        status: "AwaitingSigs".to_string(),
        threshold: 4,
        sigs_collected: 1,
    };
    let v = serde_json::to_value(&resp).expect("ProposeResponse must serialize");
    let map = v.as_object().expect("ProposeResponse is a JSON object");

    // Strict 4-key set — no extras, no missing.
    assert_eq!(
            map.len(),
            4,
            "ProposeResponse MUST emit exactly 4 keys (id, status, threshold, sigs_collected) — got {} ({:?})",
            map.len(),
            map.keys().collect::<Vec<_>>(),
        );
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    assert_eq!(
        keys.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        vec!["id", "sigs_collected", "status", "threshold"],
        "ProposeResponse key-set drift — wire contract broken",
    );
    // Type pins: id+status are JSON Strings; threshold+sigs_collected are
    // JSON Numbers (usize → u64 on the wire).
    assert!(map["id"].is_string(), "id MUST be JSON String");
    assert!(map["status"].is_string(), "status MUST be JSON String");
    assert!(
        map["threshold"].is_u64(),
        "threshold MUST be JSON Number (usize→u64), got {:?}",
        map["threshold"],
    );
    assert!(
        map["sigs_collected"].is_u64(),
        "sigs_collected MUST be JSON Number (usize→u64), got {:?}",
        map["sigs_collected"],
    );
    // Verbatim echo: id round-trips lowercase hex (a regression to
    // uppercase-normalization would surface here).
    assert_eq!(map["id"].as_str(), Some("deadbeef".repeat(8).as_str()));
    // status string passes through verbatim from `status_label` —
    // PascalCase preserved (NOT lowercased).
    assert_eq!(map["status"].as_str(), Some("AwaitingSigs"));
}

#[test]
fn batch_vvv_transition_summary_eleven_field_round_trip_with_kind_debug_and_window_open_bool() {
    // PIN: TransitionSummary at routes/transitions.rs:748 — derives BOTH
    // Serialize+Deserialize so the round-trip is part of the wire
    // contract (PQ peers re-emit list items they received). 11 fields —
    // any silent drop on either side splits the PQ and REST clients
    // into divergent parse paths.
    let summary = TransitionSummary {
        id: "abc".repeat(21) + "d", // 64-char hex-ish
        status: "DisputeWindow".to_string(),
        kind: "Split".to_string(),
        proposed_at_epoch: 1_000,
        effective_epoch: 1_003,
        threshold: 4,
        sigs_collected: 3,
        vetoes_count: 1,
        parents: vec!["zone-A".into(), "zone-B".into()],
        children: vec!["zone-C".into()],
        window_open: true,
    };
    let json = serde_json::to_string(&summary).expect("serialize");
    let parsed: TransitionSummary = serde_json::from_str(&json).expect("deserialize round-trip");

    // Field-by-field preservation (no PartialEq derive, manual compare).
    assert_eq!(parsed.id, summary.id, "id MUST round-trip byte-identical");
    assert_eq!(parsed.status, summary.status);
    assert_eq!(parsed.kind, summary.kind, "kind 'Split'/'Merge' wire string MUST round-trip — regression to TransitionKind Debug-rename surfaces here");
    assert_eq!(parsed.proposed_at_epoch, summary.proposed_at_epoch);
    assert_eq!(parsed.effective_epoch, summary.effective_epoch);
    assert_eq!(parsed.threshold, summary.threshold);
    assert_eq!(parsed.sigs_collected, summary.sigs_collected);
    assert_eq!(parsed.vetoes_count, summary.vetoes_count);
    assert_eq!(parsed.parents, summary.parents);
    assert_eq!(parsed.children, summary.children);
    assert_eq!(
        parsed.window_open, summary.window_open,
        "window_open MUST round-trip as Bool — a regression to u8/usize would surface here"
    );

    // Wire-shape pins on the serialized form.
    let v: serde_json::Value = serde_json::from_str(&json).expect("re-parse as Value");
    let map = v.as_object().expect("Object");
    assert_eq!(
        map.len(),
        11,
        "TransitionSummary MUST emit exactly 11 keys — got {} ({:?})",
        map.len(),
        map.keys().collect::<Vec<_>>(),
    );
    // Bool window_open serializes as JSON Bool, not Number 0/1.
    assert!(
        map["window_open"].is_boolean(),
        "window_open MUST serialize as JSON Bool, got {:?}",
        map["window_open"],
    );
    // kind comes through verbatim PascalCase.
    assert_eq!(map["kind"].as_str(), Some("Split"));
    // Vec<String> parents/children are JSON Arrays.
    assert!(map["parents"].is_array(), "parents MUST be JSON Array");
    assert!(map["children"].is_array(), "children MUST be JSON Array");
    assert_eq!(map["parents"].as_array().unwrap().len(), 2);
    assert_eq!(map["children"].as_array().unwrap().len(), 1);
}

#[test]
fn batch_vvv_resolve_response_strict_seven_key_with_final_binding_bool_and_account_hash_echo() {
    // PIN: ResolveResponse at routes/transitions.rs:1541 — the wire
    // shape emitted by GET /transitions/{id}/resolve/{account_hash}.
    // Wallets call this to find out "where does my account live AFTER
    // this transition takes effect?". The 7-key envelope + bool
    // final_binding is the contract every account depends on. A silent
    // refactor that changes final_binding from JSON Bool to JSON Number
    // (e.g. 0/1) would silently break every strict-type account parser.
    let resp = ResolveResponse {
        id: "1".repeat(64),
        status: "Finalized".to_string(),
        account_hash: "AbCdEf".repeat(10) + "1234", // mixed-case 64-char to pin echo
        post_transition_zone: "child-zone-7".to_string(),
        final_binding: true,
        effective_epoch: 1_500,
        current_epoch: 1_600,
    };
    let v = serde_json::to_value(&resp).expect("serialize");
    let map = v.as_object().expect("Object");

    assert_eq!(
        map.len(),
        7,
        "ResolveResponse MUST emit exactly 7 keys — got {} ({:?})",
        map.len(),
        map.keys().collect::<Vec<_>>(),
    );
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    assert_eq!(
        keys.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        vec![
            "account_hash",
            "current_epoch",
            "effective_epoch",
            "final_binding",
            "id",
            "post_transition_zone",
            "status",
        ],
        "ResolveResponse key-set drift — wire contract broken",
    );
    // final_binding MUST be JSON Bool (NOT Number 0/1).
    assert!(
        map["final_binding"].is_boolean(),
        "final_binding MUST serialize as JSON Bool, got {:?}",
        map["final_binding"],
    );
    assert_eq!(map["final_binding"].as_bool(), Some(true));
    // account_hash echoed byte-exact (no normalization — mixed-case
    // input survives the round-trip; defends silent lowercasing).
    assert_eq!(
        map["account_hash"].as_str(),
        Some(("AbCdEf".repeat(10) + "1234").as_str()),
        "account_hash MUST echo verbatim — no case normalization",
    );
    // Numeric epochs are u64 on the wire.
    assert!(map["effective_epoch"].is_u64());
    assert!(map["current_epoch"].is_u64());
}

#[test]
fn batch_vvv_veto_response_three_key_disjoint_from_sig_response_four_key_no_field_aliasing() {
    // PIN: VetoResponse (routes/transitions.rs:1642) and SigResponse
    // (routes/transitions.rs:1725) share `id` and `status` BUT differ
    // on the remaining fields — VetoResponse adds vetoes_count;
    // SigResponse adds sigs_collected + threshold. A silent rename
    // (vetoes_count → sigs_collected, or merging the two responses
    // into a single shape) would break the explorer + account flows
    // that special-case the two endpoint responses by field-set.
    let veto = VetoResponse {
        id: "feed".repeat(16),
        status: "DisputeWindow".to_string(),
        vetoes_count: 3,
    };
    let sig = SigResponse {
        id: "feed".repeat(16),
        status: "AwaitingSigs".to_string(),
        sigs_collected: 2,
        threshold: 4,
    };

    let veto_v = serde_json::to_value(&veto).expect("VetoResponse serialize");
    let sig_v = serde_json::to_value(&sig).expect("SigResponse serialize");
    let veto_map = veto_v.as_object().expect("Object");
    let sig_map = sig_v.as_object().expect("Object");

    // Distinct key counts: 3 vs 4.
    assert_eq!(
        veto_map.len(),
        3,
        "VetoResponse MUST emit exactly 3 keys — got {} ({:?})",
        veto_map.len(),
        veto_map.keys().collect::<Vec<_>>(),
    );
    assert_eq!(
        sig_map.len(),
        4,
        "SigResponse MUST emit exactly 4 keys — got {} ({:?})",
        sig_map.len(),
        sig_map.keys().collect::<Vec<_>>(),
    );

    // Asymmetry pins: vetoes_count ONLY on VetoResponse; sigs_collected
    // + threshold ONLY on SigResponse. A merge of the two structs
    // (e.g. shared ActionResponse) would surface here.
    assert!(
        veto_map.contains_key("vetoes_count"),
        "vetoes_count MUST appear on VetoResponse",
    );
    assert!(
        !veto_map.contains_key("sigs_collected"),
        "sigs_collected MUST NOT appear on VetoResponse (would alias with SigResponse)",
    );
    assert!(
        !veto_map.contains_key("threshold"),
        "threshold MUST NOT appear on VetoResponse",
    );
    assert!(
        sig_map.contains_key("sigs_collected"),
        "sigs_collected MUST appear on SigResponse",
    );
    assert!(
        sig_map.contains_key("threshold"),
        "threshold MUST appear on SigResponse",
    );
    assert!(
        !sig_map.contains_key("vetoes_count"),
        "vetoes_count MUST NOT appear on SigResponse (would alias with VetoResponse)",
    );

    // Shared keys: id + status. Both responses must carry them.
    for key in ["id", "status"] {
        assert!(
            veto_map.contains_key(key),
            "shared key {key:?} MUST appear on VetoResponse",
        );
        assert!(
            sig_map.contains_key(key),
            "shared key {key:?} MUST appear on SigResponse",
        );
    }

    // Numeric types: usize → u64 on the wire across both responses.
    assert!(veto_map["vetoes_count"].is_u64());
    assert!(sig_map["sigs_collected"].is_u64());
    assert!(sig_map["threshold"].is_u64());
}

#[test]
fn batch_vvv_transition_stats_response_four_optional_epoch_fields_skip_when_none_appear_when_some()
{
    // PIN: TransitionStatsResponse at routes/transitions.rs:1173 carries
    // FOUR Option<u64> fields gated by `#[serde(skip_serializing_if =
    // "Option::is_none")]`:
    //   - nearest_effective_epoch        (:1251)
    //   - oldest_active_proposed_at_epoch (:1261)
    //   - finalized_durable_latest_epoch  (:1269)
    //   - finalized_durable_oldest_epoch  (:1277)
    // A regression that drops the skip_if attribute on ANY of them
    // would emit `"field":null` on a fresh node (no active proposals,
    // empty CF) and break strict-Option clients that expect
    // present-key-means-Some semantics. Pin both legs: all-None →
    // none-of-those-4-keys; all-Some → all-4-keys-appear with u64
    // values.
    use crate::network::transition_store::{KindCounts, StatusCounts, VetoReasonCounts};

    // Helper: build a minimal TransitionStatsResponse with the four
    // Option<u64> epochs configurable, all other fields zeroed.
    fn mk(
        nearest_eff: Option<u64>,
        oldest_active: Option<u64>,
        fin_latest: Option<u64>,
        fin_oldest: Option<u64>,
    ) -> TransitionStatsResponse {
        TransitionStatsResponse {
            current_epoch: 0,
            dispute_window_epochs: 0,
            pending_capacity: 0,
            evictions_total: 0,
            proposals_accepted_total: 0,
            pending: StatusCounts::default(),
            pending_total: 0,
            pending_by_kind: KindCounts::default(),
            pending_vetoes_by_reason: VetoReasonCounts::default(),
            proposals_with_vetoes: 0,
            finalized_durable: 0,
            boot_replayed_total: 0,
            mirror_write_failures_total: 0,
            nearest_effective_epoch: nearest_eff,
            oldest_active_proposed_at_epoch: oldest_active,
            finalized_durable_latest_epoch: fin_latest,
            finalized_durable_oldest_epoch: fin_oldest,
            finalized_durable_by_kind: KindCounts::default(),
            orchestrator_proposed_total: 0,
            orchestrator_insert_rejected_total: 0,
            orchestrator_skipped_undersized_pool_total: 0,
            finalized_total: 0,
            finalized_split_total: 0,
            finalized_merge_total: 0,
            expired_total: 0,
            gossip_pushed_total: 0,
            gossip_dedup_total: 0,
            sig_gossip_pushed_total: 0,
            sig_gossip_dedup_total: 0,
            cosigns_total: 0,
            pulled_total: 0,
            pull_errors_total: 0,
        }
    }

    // All-None leg: none of the 4 keys appear.
    let bare = mk(None, None, None, None);
    let bare_v = serde_json::to_value(&bare).expect("serialize bare stats");
    let bare_map = bare_v.as_object().expect("Object");
    for key in [
        "nearest_effective_epoch",
        "oldest_active_proposed_at_epoch",
        "finalized_durable_latest_epoch",
        "finalized_durable_oldest_epoch",
    ] {
        assert!(
            !bare_map.contains_key(key),
            "{key:?} MUST be omitted when None — got {} keys, with {key:?} present. \
                 Drift means #[serde(skip_serializing_if = \"Option::is_none\")] was dropped \
                 from {key:?}.",
            bare_map.len(),
        );
    }

    // All-Some leg: distinct, coprime values so a future refactor that
    // accidentally aliases two of the 4 fields (e.g. copy-paste bug
    // assigning the same source to two destinations) surfaces here.
    let populated = mk(Some(101), Some(202), Some(303), Some(404));
    let pop_v = serde_json::to_value(&populated).expect("serialize populated stats");
    let pop_map = pop_v.as_object().expect("Object");
    assert_eq!(
        pop_map
            .get("nearest_effective_epoch")
            .and_then(|v| v.as_u64()),
        Some(101),
        "nearest_effective_epoch MUST appear with the Some(101) value",
    );
    assert_eq!(
        pop_map
            .get("oldest_active_proposed_at_epoch")
            .and_then(|v| v.as_u64()),
        Some(202),
        "oldest_active_proposed_at_epoch MUST appear with the Some(202) value",
    );
    assert_eq!(
        pop_map
            .get("finalized_durable_latest_epoch")
            .and_then(|v| v.as_u64()),
        Some(303),
        "finalized_durable_latest_epoch MUST appear with the Some(303) value",
    );
    assert_eq!(
        pop_map
            .get("finalized_durable_oldest_epoch")
            .and_then(|v| v.as_u64()),
        Some(404),
        "finalized_durable_oldest_epoch MUST appear with the Some(404) value",
    );

    // Sub-object presence: non-skipped aggregate counters (pending,
    // pending_by_kind, pending_vetoes_by_reason, finalized_durable_by_kind)
    // MUST appear on BOTH legs — they don't carry skip_serializing_if
    // and emit as zero objects when empty.
    for key in [
        "pending",
        "pending_by_kind",
        "pending_vetoes_by_reason",
        "finalized_durable_by_kind",
    ] {
        assert!(
            bare_map.contains_key(key),
            "{key:?} MUST appear on bare TransitionStatsResponse (no skip_serializing_if)",
        );
        assert!(
            pop_map.contains_key(key),
            "{key:?} MUST appear on populated TransitionStatsResponse",
        );
    }
}

// ─── Pin the TransitionView wire
// shape (routes/transitions.rs:665 — response of GET /transitions/{id}).
// An earlier slice covered ProposeResponse / TransitionSummary /
// ResolveResponse / VetoResponse vs SigResponse / TransitionStatsResponse
// but left TransitionView un-pinned despite it being the FULL view of
// a single transition — every explorer "drill into proposal" + light-
// client "fetch this seal by id" path returns this shape. A silent
// refactor that flattens seal → summary, drops vetoes, or renames a
// field would compile cleanly but break every follower at runtime.
// 5 axes, each catches a regression class that earlier slices survive:
//   (1) strict 8-key envelope with NO skip_if — every field always
//       present (View ≠ Stats which gated 4 epoch fields on None);
//   (2) nested seal is the FULL TransitionSeal (7 fields) not a
//       Summary projection — defends the seal-hash-chain wire path;
//   (3) vetoes is Vec<TransitionVeto> preserving insertion order and
//       full 6-field veto shape — defends dispute-window UI;
//   (4) disjoint-field invariant vs TransitionSummary — View has
//       {seal, vetoes, current_epoch}; Summary has {kind,
//       proposed_at_epoch, effective_epoch, parents, children,
//       vetoes_count}; merging the two responses would break accounts;
//   (5) window_open is JSON Bool + current_epoch is JSON Number —
//       both wire-type purity pins, paired in one test to make the
//       orthogonality explicit (a regression to a tristate u8
//       window_open would fail here even if other tests pass).
// ────────────────────────────────────────────────────────────────────────

#[test]
fn batch_llll_transition_view_strict_eight_key_envelope_pins_no_optional_serde_skip_attrs() {
    // PIN: TransitionView at routes/transitions.rs:665 — derives
    // Serialize+Deserialize with NO `#[serde(skip_serializing_if)]`
    // attributes on ANY of its 8 fields. A regression that gates
    // `current_epoch` or `window_open` on Option-skip semantics
    // (the kind of refactor that mirrors TransitionStatsResponse's
    // four optional epoch fields) would silently break every client
    // expecting present-key-always semantics.
    let seal = split_seal_at(100);
    let view = TransitionView {
        id: "1".repeat(64),
        status: "AwaitingSigs".to_string(),
        seal: seal.clone(),
        vetoes: vec![],
        threshold: seal.required_threshold(),
        sigs_collected: 0,
        window_open: true,
        current_epoch: 100,
    };
    let v = serde_json::to_value(&view).expect("TransitionView must serialize");
    let map = v.as_object().expect("TransitionView is a JSON object");

    // Strict 8-key set — no extras, no missing.
    assert_eq!(
        map.len(),
        8,
        "TransitionView MUST emit exactly 8 keys — got {} ({:?})",
        map.len(),
        map.keys().collect::<Vec<_>>(),
    );
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    assert_eq!(
        keys.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        vec![
            "current_epoch",
            "id",
            "seal",
            "sigs_collected",
            "status",
            "threshold",
            "vetoes",
            "window_open",
        ],
        "TransitionView key-set drift — wire contract broken",
    );

    // Zero-veto leg: `vetoes: []` MUST still emit as a present empty
    // array, NOT be omitted. A future `#[serde(skip_serializing_if =
    // "Vec::is_empty")]` attribute would break this assertion — and
    // every dashboard that does `view.vetoes.length` would NPE on
    // the now-undefined key.
    assert!(
        map["vetoes"].is_array(),
        "vetoes MUST emit as JSON Array even when empty, got {:?}",
        map["vetoes"],
    );
    assert_eq!(
        map["vetoes"].as_array().unwrap().len(),
        0,
        "empty-vetoes leg: array MUST have len=0",
    );

    // current_epoch=0 leg: a fresh node with no epoch progress
    // returns current_epoch=0 from best_effort_current_epoch — that
    // value MUST still serialize as JSON Number 0 (NOT be omitted by
    // a future `skip_if = "u64::is_zero"` attribute, which is the
    // exact regression that the cold-boot helper tests pin
    // against on the helper side).
    let view_zero = TransitionView {
        id: "2".repeat(64),
        status: "AwaitingSigs".to_string(),
        seal: split_seal_at(0),
        vetoes: vec![],
        threshold: 0,
        sigs_collected: 0,
        window_open: false,
        current_epoch: 0,
    };
    let z = serde_json::to_value(&view_zero).expect("serialize zero-epoch View");
    let z_map = z.as_object().expect("Object");
    assert!(
        z_map.contains_key("current_epoch"),
        "current_epoch=0 MUST still appear as a key — no skip_if on u64",
    );
    assert_eq!(z_map["current_epoch"].as_u64(), Some(0));
    assert!(
        z_map.contains_key("threshold"),
        "threshold=0 MUST still appear — no skip_if on usize",
    );
    assert!(
        z_map.contains_key("sigs_collected"),
        "sigs_collected=0 MUST still appear — no skip_if on usize",
    );
}

#[test]
fn batch_llll_transition_view_nested_seal_round_trips_full_transition_seal_shape_not_summary() {
    // PIN: TransitionView.seal at routes/transitions.rs:668 is the
    // FULL `TransitionSeal` struct (7 fields), NOT a Summary
    // projection. A refactor that swaps `seal: TransitionSeal` for
    // `seal: TransitionSummary` (the kind of "save bytes by reusing
    // the list view shape") would compile cleanly but silently
    // break every light-client follower that parses the seal hash
    // chain — TransitionSeal carries proposer_sigs (which carry
    // dilithium3 signatures) but TransitionSummary does NOT.
    let mut seal = split_seal_at(100);
    // Plant a distinctive proposer_sigs entry so a Summary swap
    // (which would drop proposer_sigs) is visible. Use a non-empty
    // Vec to exercise the nested-Vec-of-AnchorSig serde path.
    seal.proposer_sigs.push(AnchorSig {
        anchor_identity_hash: [0xAB; 32],
        dilithium3_sig: vec![0xCD; 3309],
    });
    let view = TransitionView {
        id: "3".repeat(64),
        status: "AwaitingSigs".to_string(),
        seal: seal.clone(),
        vetoes: vec![],
        threshold: seal.required_threshold(),
        sigs_collected: 1,
        window_open: true,
        current_epoch: 100,
    };

    // Round-trip — TransitionView derives BOTH Serialize+Deserialize,
    // so peers re-emit views they received. The round-trip MUST
    // preserve every TransitionSeal sub-field byte-identical.
    let json = serde_json::to_string(&view).expect("serialize View");
    let parsed: TransitionView = serde_json::from_str(&json).expect("deserialize round-trip");

    // Top-level seal field round-trips ALL 7 TransitionSeal fields:
    assert_eq!(parsed.seal.kind, seal.kind, "seal.kind MUST round-trip");
    assert_eq!(parsed.seal.effective_epoch, seal.effective_epoch);
    assert_eq!(parsed.seal.proposed_at_epoch, seal.proposed_at_epoch);
    assert_eq!(parsed.seal.parents.len(), 1, "Split has exactly 1 parent");
    assert_eq!(
        parsed.seal.children.len(),
        2,
        "Split has exactly 2 children"
    );
    assert_eq!(
        parsed.seal.split_key, seal.split_key,
        "split_key Option<[u8;32]> MUST round-trip exact bytes",
    );
    assert_eq!(
        parsed.seal.proposer_sigs.len(),
        1,
        "proposer_sigs MUST round-trip — regression to seal=Summary projection would lose this",
    );
    assert_eq!(
        parsed.seal.proposer_sigs[0].anchor_identity_hash, [0xAB; 32],
        "AnchorSig.anchor_identity_hash MUST round-trip byte-identical",
    );
    assert_eq!(
        parsed.seal.proposer_sigs[0].dilithium3_sig.len(),
        3309,
        "AnchorSig.dilithium3_sig MUST preserve full Dilithium3 byte count",
    );

    // Wire-shape pin on the serialized form: seal MUST be a JSON
    // Object containing the 7 TransitionSeal keys, NOT a flattened
    // string-hash (the kind of regression where someone "compacts"
    // the view to embed seal as a sealing-hash hex string).
    let v: serde_json::Value = serde_json::from_str(&json).expect("re-parse as Value");
    let seal_obj = v["seal"]
        .as_object()
        .expect("seal MUST be JSON Object, not a hex String — TransitionSeal projection drift");
    // The 7 TransitionSeal fields must all be present on the wire.
    for key in [
        "kind",
        "effective_epoch",
        "proposed_at_epoch",
        "parents",
        "children",
        "split_key",
        "proposer_sigs",
    ] {
        assert!(
            seal_obj.contains_key(key),
            "seal.{key:?} MUST appear in the wire shape — TransitionSeal projection drift",
        );
    }
}

#[test]
fn batch_llll_transition_view_vetoes_array_preserves_insertion_order_and_full_veto_shape() {
    // PIN: TransitionView.vetoes at routes/transitions.rs:669 is
    // `Vec<TransitionVeto>` — NOT `Vec<String>` (hashes only) and
    // NOT `BTreeMap<reason, Vec<TransitionVeto>>` (which would
    // reorder by reason key). The dispute-window UI iterates this
    // Vec in submission order to show "veto #1 was BadBoundary @
    // epoch X, veto #2 was StateRootMismatch @ epoch Y" — a sort or
    // dedupe in the wire-shape would silently break that flow.
    use crate::network::transition_store::{TransitionVeto, VetoReason};

    // Plant 3 vetoes in a deliberate REVERSE-sorted order on
    // submitted_at_epoch so any sort-by-epoch regression flips the
    // order visibly. Use distinct reasons so a sort-by-reason
    // regression ALSO surfaces.
    let veto_c = TransitionVeto {
        seal_hash: [0xCC; 32],
        reason: VetoReason::BadBoundary,
        evidence: vec![1, 2, 3],
        submitted_at_epoch: 110, // submitted FIRST in this Vec
        vetoer_identity_hash: [0x11; 32],
        dilithium3_sig: vec![0xAA; 3309],
    };
    let veto_b = TransitionVeto {
        seal_hash: [0xCC; 32],
        reason: VetoReason::StateRootMismatch,
        evidence: vec![4, 5, 6],
        submitted_at_epoch: 105, // EARLIER epoch but LATER in Vec
        vetoer_identity_hash: [0x22; 32],
        dilithium3_sig: vec![0xBB; 3309],
    };
    let veto_a = TransitionVeto {
        seal_hash: [0xCC; 32],
        reason: VetoReason::CommitteeDiversity,
        evidence: vec![7, 8, 9],
        submitted_at_epoch: 102, // EARLIEST epoch, LAST in Vec
        vetoer_identity_hash: [0x33; 32],
        dilithium3_sig: vec![0xCC; 3309],
    };

    let view = TransitionView {
        id: "4".repeat(64),
        status: "DisputeWindow".to_string(),
        seal: split_seal_at(100),
        vetoes: vec![veto_c.clone(), veto_b.clone(), veto_a.clone()],
        threshold: 1,
        sigs_collected: 1,
        window_open: true,
        current_epoch: 115,
    };

    let json = serde_json::to_string(&view).expect("serialize View with vetoes");
    let parsed: TransitionView = serde_json::from_str(&json).expect("deserialize");

    // Order preserved byte-identical to insertion (NOT sorted by
    // submitted_at_epoch ascending). A regression to
    // `BTreeSet<TransitionVeto>` or `sort_by_key(submitted_at)`
    // would surface here as the first element flipping from
    // veto_c (110) to veto_a (102).
    assert_eq!(parsed.vetoes.len(), 3, "all 3 vetoes round-trip");
    assert_eq!(
        parsed.vetoes[0].submitted_at_epoch, 110,
        "Vec<TransitionVeto> MUST preserve insertion order — got reorder",
    );
    assert_eq!(
        parsed.vetoes[1].submitted_at_epoch, 105,
        "veto_b at index 1 MUST preserve position",
    );
    assert_eq!(
        parsed.vetoes[2].submitted_at_epoch, 102,
        "veto_a at index 2 MUST preserve position",
    );

    // Full 6-field veto shape preserved (NOT compacted to e.g.
    // just `{hash, reason}`):
    let v: serde_json::Value = serde_json::from_str(&json).expect("re-parse");
    let vetoes_arr = v["vetoes"].as_array().expect("vetoes is JSON Array");
    assert_eq!(vetoes_arr.len(), 3);
    let veto0 = vetoes_arr[0].as_object().expect("veto entry is Object");
    for key in [
        "seal_hash",
        "reason",
        "evidence",
        "submitted_at_epoch",
        "vetoer_identity_hash",
        "dilithium3_sig",
    ] {
        assert!(
            veto0.contains_key(key),
            "TransitionVeto.{key:?} MUST appear on the wire — compacted-veto regression",
        );
    }
    // dilithium3_sig length pin: a regression to truncated/empty
    // sig (the kind of "we don't need the sig in the View, only at
    // ingest" optimisation) would surface here.
    assert_eq!(
        veto0["dilithium3_sig"].as_array().unwrap().len(),
        3309,
        "veto[0].dilithium3_sig MUST preserve full ML-DSA-65 byte count",
    );
}

#[test]
fn batch_llll_transition_view_disjoint_from_summary_no_field_aliasing_between_get_and_list() {
    // PIN: TransitionView (8 keys, routes/transitions.rs:665) and
    // TransitionSummary (11 keys, routes/transitions.rs:749) are
    // DIFFERENT shapes — they're returned by different endpoints
    // (GET /transitions/{id} vs GET /transitions). A merge into a
    // single "TransitionResponse" shape would break the explorer
    // (which renders list-row UI vs detail-page UI from these two
    // distinct payloads) and account flows that special-case the
    // two endpoints by field-set. Pin the asymmetry explicitly:
    //   - View-only: {seal, vetoes, current_epoch}
    //   - Summary-only: {kind, proposed_at_epoch, effective_epoch,
    //                    parents, children, vetoes_count}
    //   - Shared: {id, status, threshold, sigs_collected,
    //             window_open}  (5 fields)
    let seal = split_seal_at(100);
    let view = TransitionView {
        id: "5".repeat(64),
        status: "AwaitingSigs".to_string(),
        seal: seal.clone(),
        vetoes: vec![],
        threshold: 4,
        sigs_collected: 2,
        window_open: true,
        current_epoch: 100,
    };
    let summary = TransitionSummary {
        id: "5".repeat(64),
        status: "AwaitingSigs".to_string(),
        kind: "Split".to_string(),
        proposed_at_epoch: 100,
        effective_epoch: 103,
        threshold: 4,
        sigs_collected: 2,
        vetoes_count: 0,
        parents: vec!["test/parent".into()],
        children: vec!["test/child-a".into(), "test/child-b".into()],
        window_open: true,
    };

    let view_v = serde_json::to_value(&view).expect("View serialize");
    let summary_v = serde_json::to_value(&summary).expect("Summary serialize");
    let view_map = view_v.as_object().expect("Object");
    let summary_map = summary_v.as_object().expect("Object");

    // View-only fields MUST NOT appear on Summary:
    for view_only in ["seal", "vetoes", "current_epoch"] {
        assert!(
            view_map.contains_key(view_only),
            "{view_only:?} MUST appear on TransitionView",
        );
        assert!(
            !summary_map.contains_key(view_only),
            "{view_only:?} MUST NOT appear on TransitionSummary — would alias View",
        );
    }

    // Summary-only fields MUST NOT appear on View:
    for summary_only in [
        "kind",
        "proposed_at_epoch",
        "effective_epoch",
        "parents",
        "children",
        "vetoes_count",
    ] {
        assert!(
            summary_map.contains_key(summary_only),
            "{summary_only:?} MUST appear on TransitionSummary",
        );
        assert!(
            !view_map.contains_key(summary_only),
            "{summary_only:?} MUST NOT appear on TransitionView — would alias Summary",
        );
    }

    // Shared fields MUST appear on BOTH (5 fields exactly):
    let shared = ["id", "status", "threshold", "sigs_collected", "window_open"];
    for key in shared {
        assert!(
            view_map.contains_key(key),
            "shared key {key:?} MUST appear on TransitionView",
        );
        assert!(
            summary_map.contains_key(key),
            "shared key {key:?} MUST appear on TransitionSummary",
        );
    }

    // Cross-check key counts pin the asymmetry from the other side:
    // View has 8 keys = 5 shared + 3 view-only.
    // Summary has 11 keys = 5 shared + 6 summary-only.
    // (vetoes_count is summary-only despite View carrying full
    // Vec<TransitionVeto> in `vetoes` — different field name +
    // different shape, NOT an aliasing.)
    assert_eq!(view_map.len(), 8, "View key count = 5 shared + 3 view-only");
    assert_eq!(
        summary_map.len(),
        11,
        "Summary key count = 5 shared + 6 summary-only",
    );
    // The Vec<TransitionVeto> on View vs the usize vetoes_count on
    // Summary is the canonical example of "same concept, different
    // shape": catches a merge regression that would unify them.
    assert!(
        view_map["vetoes"].is_array(),
        "View.vetoes is JSON Array of full veto objects",
    );
    assert!(
        summary_map["vetoes_count"].is_u64(),
        "Summary.vetoes_count is JSON Number (just the count)",
    );
}

#[test]
fn batch_llll_transition_view_window_open_is_json_bool_and_current_epoch_is_json_number_paired() {
    // PIN: TransitionView.window_open (bool, line 672) and
    // TransitionView.current_epoch (u64, line 673) — paired wire-
    // type purity pin. A regression to a tristate `window_open: u8`
    // (the kind of refactor where someone adds "0=closed,
    // 1=open, 2=expiring-soon") would compile cleanly but break
    // every strict-typed account parser that expects JSON Bool.
    // Symmetrically, a regression to `current_epoch: String` (the
    // kind of "big-int safe" refactor that flips u64s to strings to
    // dodge JavaScript's 53-bit ceiling) would break every numeric-
    // comparison path. Pin both axes in ONE test to make the
    // orthogonality explicit and catch the pair-wise regression
    // class where a refactor "harmonizes" all numeric/bool wire
    // types into a single shape.
    let view_open = TransitionView {
        id: "6".repeat(64),
        status: "AwaitingSigs".to_string(),
        seal: split_seal_at(100),
        vetoes: vec![],
        threshold: 4,
        sigs_collected: 0,
        window_open: true,
        current_epoch: 100,
    };
    let view_closed = TransitionView {
        id: "7".repeat(64),
        status: "Finalized".to_string(),
        seal: split_seal_at(100),
        vetoes: vec![],
        threshold: 4,
        sigs_collected: 4,
        window_open: false,
        current_epoch: 1_000_000_000_001, // > u32::MAX to defend
                                          // the "fits in JS Number"
                                          // regression where someone
                                          // truncates to i32.
    };

    let open_v = serde_json::to_value(&view_open).expect("serialize open");
    let closed_v = serde_json::to_value(&view_closed).expect("serialize closed");

    // window_open is JSON Bool on BOTH legs (no implicit 1/0).
    assert!(
        open_v["window_open"].is_boolean(),
        "window_open=true MUST serialize as JSON Bool, got {:?}",
        open_v["window_open"],
    );
    assert_eq!(open_v["window_open"].as_bool(), Some(true));
    assert!(
        closed_v["window_open"].is_boolean(),
        "window_open=false MUST serialize as JSON Bool (NOT omitted, NOT 0), got {:?}",
        closed_v["window_open"],
    );
    assert_eq!(closed_v["window_open"].as_bool(), Some(false));

    // current_epoch is JSON Number (NOT String) on BOTH legs.
    // The closed-leg deliberately exercises a value > u32::MAX
    // (10^12 + 1) to defend the "fits in i32" regression — JSON
    // Number serde accommodates u64 just fine; a String wrapper
    // would silently break.
    assert!(
        open_v["current_epoch"].is_u64(),
        "current_epoch (100) MUST serialize as JSON Number, got {:?}",
        open_v["current_epoch"],
    );
    assert_eq!(open_v["current_epoch"].as_u64(), Some(100));
    assert!(
        closed_v["current_epoch"].is_u64(),
        "current_epoch (>u32::MAX) MUST serialize as JSON Number, got {:?}",
        closed_v["current_epoch"],
    );
    assert_eq!(
        closed_v["current_epoch"].as_u64(),
        Some(1_000_000_000_001),
        "current_epoch MUST preserve full u64 precision past u32::MAX",
    );

    // Cross-axis pin: a future refactor that "harmonizes" wire
    // types (e.g. "all numbers become strings for big-int safety")
    // would silently flip BOTH current_epoch AND threshold/
    // sigs_collected to strings. Check the other numeric pair on
    // the same payload — threshold (usize→u64) and sigs_collected
    // (usize→u64) ALSO survive as JSON Numbers.
    assert!(open_v["threshold"].is_u64());
    assert!(open_v["sigs_collected"].is_u64());
}

// ─── verify_anchor_sig orthogonal pins ──────────────
//
// PIN: routes/transitions.rs:78 — verify_anchor_sig is the gossip-side
// anchor-sig verifier on the transition pull/push hot path. Returns
// Ok(()) iff (F1) the signer is in the staked-anchor trust set AND
// (a) the anchor's pubkey is in CF_IDENTITIES AND (b) the
// Dilithium3 sig verifies against `seal_hash`. The 4 error modes (not
// staked / no pubkey / Ok(false) / Err-from-verify) MUST map to 4
// DISTINCT `ElaraError::Wire` strings so operators can attribute a 400
// to the right root cause. The stake gate fires FIRST (before any
// Dilithium3 CPU), so the axis-2..5 pins below pass a trust set that
// CONTAINS their signer — trust membership (ledger stake) and pubkey
// registration (CF_IDENTITIES) are independent axes; a staked identity
// whose pubkey never propagated is exactly what axis 2 covers.

/// Build an explicit trust set for direct verify_anchor_sig pins —
/// the unit-level stand-in for `NodeState::transition_trust_view()`.
fn trust_with(ids: &[[u8; 32]]) -> std::collections::HashSet<[u8; 32]> {
    ids.iter().copied().collect()
}

/// Axis 0 / Transitions-F1 stake gate: a signer ABSENT from the trust
/// set is rejected with the distinct "anchor not in staked trust set"
/// message BEFORE pubkey resolution or Dilithium3 verify run — even
/// when the pubkey IS registered and the sig IS valid (everything
/// downstream would pass). Also pins the distinct stake-reject
/// counter so operators can tell unstaked-signer from forged-bytes.
#[test]
fn f1_verify_anchor_sig_unstaked_signer_rejected_before_crypto() {
    let state = test_state();
    let (ident, kp) = register_anchor(&state);
    let seal_hash: [u8; 32] = sha3_256(b"f1-axis0-stake-gate-seal");
    let sig_bytes = dilithium3_sign_with_pk(&seal_hash, &kp.secret_key, &kp.public_key)
        .expect("axis0: sign");
    let sig = AnchorSig {
        anchor_identity_hash: ident,
        dilithium3_sig: sig_bytes,
    };
    let before = state
        .transition_sig_stake_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    // Empty trust set — registered + cryptographically valid is NOT enough.
    let err = verify_anchor_sig(&state, &sig, &seal_hash, &trust_with(&[]))
        .expect_err("axis0: unstaked signer MUST fail despite valid sig");
    assert!(
        matches!(err, ElaraError::Wire(_)),
        "axis0: variant MUST be ElaraError::Wire, got {err:?}",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("anchor not in staked trust set"),
        "axis0: error MUST carry the distinct stake-gate phrase; got {msg}",
    );
    assert!(
        msg.contains(&hex::encode(ident)),
        "axis0: error MUST include the hex identity for traceability; got {msg}",
    );
    let after = state
        .transition_sig_stake_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        after,
        before + 1,
        "axis0: stake-gate rejection MUST bump transition_sig_stake_rejected_total",
    );
    // Same call WITH trust membership succeeds — the gate is the only
    // thing that was failing.
    verify_anchor_sig(&state, &sig, &seal_hash, &trust_with(&[ident]))
        .expect("axis0: staked signer with valid sig MUST verify");
}

/// Transitions-F1: `test_state` variant with an explicit genesis authority
/// (the default `TESTNET_GENESIS_AUTHORITY` is the empty string, which the
/// trust view's 32-byte decode guard correctly skips).
fn test_state_with_genesis(genesis_hex: &str) -> Arc<NodeState> {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let config = NodeConfig {
        data_dir: data_dir.clone(),
        identity_path: data_dir.join("identity.json"),
        db_path: data_dir.join("elara.db"),
        admin_token: "test-admin".into(),
        network_id: "transitions-f1-trust-test".into(),
        mdns_enabled: false,
        health_check_interval_secs: 0,
        min_pow_difficulty: 0,
        genesis_authority: genesis_hex.into(),
        ..Default::default()
    };
    let identity =
        Identity::generate(EntityType::Device, CryptoProfile::ProfileB).expect("generate identity");
    let rocks = Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("rocks"));
    let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
    let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
    std::mem::forget(tmp);
    state
}

/// Transitions-F1: `transition_trust_view` membership semantics —
/// genesis-authority-always-in (even with an empty staker set), the
/// witness-stake floor boundary (at-floor in, below-floor out,
/// registered-but-unstaked out), and refresh on stake mutation (an
/// unstake drops the member on the next view read; memoization must
/// not serve the stale set once `stake_mutation_seq` moves).
#[tokio::test]
async fn f1_trust_view_genesis_floor_boundary_and_refresh() {
    use crate::accounting::types::MIN_WITNESS_STAKE_BASE_UNITS;

    let genesis: [u8; 32] = sha3_256(b"f1-view-genesis-authority");
    let state = test_state_with_genesis(&hex::encode(genesis));

    // Empty ledger: the view is exactly {genesis}.
    let view = state.transition_trust_view().await;
    assert!(
        view.contains(&genesis),
        "genesis authority MUST be in the trust set with an empty staker set",
    );
    assert_eq!(
        view.len(),
        1,
        "empty-ledger trust set MUST be exactly {{genesis}}",
    );

    // at_floor is staked exactly AT the witness floor → in.
    let at_floor: [u8; 32] = sha3_256(b"f1-view-at-floor");
    stake_anchor(&state, at_floor).await;
    // below_floor has a staker_index entry but staked = floor - 1 → out.
    let below_floor: [u8; 32] = sha3_256(b"f1-view-below-floor");
    {
        let hex_id = hex::encode(below_floor);
        let rid = format!("test-stake:{hex_id}");
        let mut ledger = state.ledger.write().await;
        ledger.accounts.entry(hex_id.clone()).or_default().staked =
            MIN_WITNESS_STAKE_BASE_UNITS - 1;
        ledger.staker_index.entry(hex_id).or_default().push(rid);
        ledger.stake_mutation_seq += 1;
    }
    // registered_only has a pubkey in CF_IDENTITIES but no ledger stake → out.
    let (registered_only, _kp) = register_anchor(&state);

    let view = state.transition_trust_view().await;
    assert!(view.contains(&genesis), "genesis stays in");
    assert!(
        view.contains(&at_floor),
        "staked-at-floor identity MUST be in the trust set",
    );
    assert!(
        !view.contains(&below_floor),
        "below-floor stake MUST NOT pass the witness-floor gate",
    );
    assert!(
        !view.contains(&registered_only),
        "CF_IDENTITIES registration without ledger stake MUST NOT grant trust",
    );

    // Unstake at_floor → the NEXT view read (seq moved) drops it.
    {
        let hex_id = hex::encode(at_floor);
        let mut ledger = state.ledger.write().await;
        if let Some(acct) = ledger.accounts.get_mut(&hex_id) {
            acct.staked = 0;
        }
        ledger.stake_mutation_seq += 1;
    }
    let view = state.transition_trust_view().await;
    assert!(
        !view.contains(&at_floor),
        "unstaked identity MUST drop out of the trust set on refresh",
    );
    assert!(view.contains(&genesis), "genesis survives every refresh");
}

/// Transitions-F1: the finalize-tick stake pre-filter — the apply-site
/// gate. A seal that reached sig-COUNT threshold in the store (gossip
/// race / direct insert never crosses an ingest handler) but whose
/// signers are not in the trust set MUST be sig-rejected at the tick:
/// not persisted to CF_TRANSITIONS_FINAL, stake-reject counter bumped.
/// The identical seal with trusted signers MUST persist. This pins the
/// invariant the boot path relies on: CF_TRANSITIONS_FINAL presence ⇒
/// passed the stake gate at finalize time (boot replay deliberately
/// re-checks crypto but NOT live stake — see rebuild_from_finalized).
#[tokio::test]
async fn f1_tick_stake_prefilter_blocks_untrusted_finalize_and_persist() {
    use crate::network::health::run_transition_tick;
    use crate::network::zone_transition_seal::SPLIT_ANCHOR_THRESHOLD;

    // Threshold-signed seal, signers registered in CF_IDENTITIES.
    // proposed_at=0 → effective=3; state_core at 5 puts the tick past
    // the dispute window so `tick()` reports it newly-finalized.
    let build = |state: &Arc<NodeState>| -> ([u8; 32], Vec<[u8; 32]>) {
        let mut seal = split_seal_at(0);
        let seal_hash = seal.seal_hash_for_sig().expect("hash");
        let mut signers = Vec::new();
        for _ in 0..SPLIT_ANCHOR_THRESHOLD {
            let (ident, kp) = register_anchor(state);
            let sig_bytes = dilithium3_sign_with_pk(&seal_hash, &kp.secret_key, &kp.public_key)
                .expect("sign");
            seal.proposer_sigs.push(AnchorSig {
                anchor_identity_hash: ident,
                dilithium3_sig: sig_bytes,
            });
            signers.push(ident);
        }
        seal.proposer_sigs.sort_by_key(|s| s.anchor_identity_hash);
        let id = {
            let mut store = state.transitions.write().expect("store lock");
            store.insert(seal).expect("insert threshold-signed seal")
        };
        (id, signers)
    };

    // Case 1: signers NOT in the trust set → rejected at the tick.
    let state = test_state();
    install_state_core_at_epoch(&state, 5);
    let (id, _signers) = build(&state);
    let rejected_before = state
        .transition_sig_stake_rejected_total
        .load(std::sync::atomic::Ordering::Relaxed);
    run_transition_tick(&state, &trust_with(&[])).expect("tick");
    assert!(
        state
            .rocks
            .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id)
            .expect("cf read")
            .is_none(),
        "untrusted-signer seal MUST NOT reach CF_TRANSITIONS_FINAL",
    );
    assert_eq!(
        state
            .transition_sig_stake_rejected_total
            .load(std::sync::atomic::Ordering::Relaxed),
        rejected_before + SPLIT_ANCHOR_THRESHOLD as u64,
        "every filtered sig MUST bump the stake-reject counter",
    );
    assert_eq!(
        state
            .zone_registry_tick_sig_verify_failures_total
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the seal itself MUST be counted sig-rejected at the tick",
    );

    // Case 2: same shape, signers IN the trust set → persists.
    let state = test_state();
    install_state_core_at_epoch(&state, 5);
    let (id, signers) = build(&state);
    run_transition_tick(&state, &trust_with(&signers)).expect("tick");
    assert!(
        state
            .rocks
            .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id)
            .expect("cf read")
            .is_some(),
        "trusted-signer seal MUST persist to CF_TRANSITIONS_FINAL",
    );
}

/// Transitions-F1 end-to-end through the real handler + real view: a
/// CF_IDENTITIES-registered anchor with a cryptographically valid sig
/// but NO ledger stake is rejected by `propose_transition` — the exact
/// pre-F1 gap (any registered identity could contribute threshold
/// weight) closed at the outermost ingest surface.
#[tokio::test]
async fn f1_propose_rejects_registered_but_unstaked_anchor() {
    let state = test_state();
    let (ident, kp) = register_anchor(&state);
    let mut seal = split_seal_at(100);
    let seal_hash = seal.seal_hash_for_sig().expect("hash");
    let sig_bytes =
        dilithium3_sign_with_pk(&seal_hash, &kp.secret_key, &kp.public_key).expect("sign");
    seal.proposer_sigs.push(AnchorSig {
        anchor_identity_hash: ident,
        dilithium3_sig: sig_bytes,
    });
    let msg = err_msg(
        propose_transition(State(state), Json(seal)).await,
        "propose",
    );
    assert!(
        msg.contains("anchor not in staked trust set"),
        "registered-but-unstaked signer MUST hit the F1 stake gate, got {msg}",
    );
}

/// Axis 1 / happy path: registered anchor + valid Dilithium3 sig over
/// `seal_hash` → `Ok(())`. This is the only path that should ever
/// return Ok — every other branch in the match is an error.
#[test]
fn batch_nnnn_verify_anchor_sig_happy_path_registered_anchor_valid_sig_returns_ok() {
    let state = test_state();
    let (ident, kp) = register_anchor(&state);
    let seal_hash: [u8; 32] = sha3_256(b"batch-nnnn-axis1-happy-seal");
    let sig_bytes =
        dilithium3_sign_with_pk(&seal_hash, &kp.secret_key, &kp.public_key).expect("axis1: sign");
    let sig = AnchorSig {
        anchor_identity_hash: ident,
        dilithium3_sig: sig_bytes,
    };
    verify_anchor_sig(&state, &sig, &seal_hash, &trust_with(&[ident]))
        .expect("axis1: valid sig from registered anchor MUST verify");
}

/// Axis 2 / unregistered anchor: identity_hash absent from CF_IDENTITIES
/// → `ElaraError::Wire("anchor pubkey not registered: <hex>")`. The hex
/// form of the identity_hash MUST be in the message so operators can
/// trace which anchor announce never landed. Pins the early-return
/// path BEFORE pqc::dilithium3_verify is called.
#[test]
fn batch_nnnn_verify_anchor_sig_unregistered_anchor_returns_pubkey_not_registered_with_hex_identity(
) {
    let state = test_state();
    // NOTE: do NOT call register_anchor — the lookup MUST miss.
    let phantom_ident: [u8; 32] = sha3_256(b"batch-nnnn-axis2-phantom-anchor");
    let phantom_ident_hex = hex::encode(phantom_ident);
    let sig = AnchorSig {
        anchor_identity_hash: phantom_ident,
        dilithium3_sig: vec![0xaa; 3309],
    };
    let seal_hash: [u8; 32] = sha3_256(b"batch-nnnn-axis2-seal");
    let err = verify_anchor_sig(&state, &sig, &seal_hash, &trust_with(&[phantom_ident]))
        .expect_err("axis2: unregistered anchor MUST fail");
    assert!(
        matches!(err, ElaraError::Wire(_)),
        "axis2: variant MUST be ElaraError::Wire (handler maps to 400), got {err:?}",
    );
    let msg = err.to_string();
    assert!(
            msg.contains("anchor pubkey not registered"),
            "axis2: error MUST mention 'anchor pubkey not registered' so ops can grep for it; got {msg}",
        );
    assert!(
            msg.contains(&phantom_ident_hex),
            "axis2: error MUST include hex({phantom_ident_hex}) of the missing identity for traceability; got {msg}",
        );
}

/// Axis 3 / valid sig over the WRONG message: registered anchor, valid
/// Dilithium3 sig over hash A, but verify_anchor_sig called with hash B
/// → `ElaraError::Wire("anchor sig invalid")`. Distinguishes the
/// `Ok(false)` branch (cryptographic mismatch — sig is well-formed but
/// doesn't verify) from the `Err` branch (verifier itself errored).
/// The exact string "anchor sig invalid" MUST appear AND
/// "verify failed" MUST NOT — collapsing these into a single message
/// would erase the structural-vs-cryptographic distinction.
#[test]
fn batch_nnnn_verify_anchor_sig_registered_anchor_wrong_message_returns_anchor_sig_invalid() {
    let state = test_state();
    let (ident, kp) = register_anchor(&state);
    let hash_a: [u8; 32] = sha3_256(b"batch-nnnn-axis3-hash-A");
    let hash_b: [u8; 32] = sha3_256(b"batch-nnnn-axis3-hash-B");
    assert_ne!(hash_a, hash_b, "axis3: setup — A and B MUST differ");
    // Sig is over A but we'll verify against B → Ok(false).
    let sig_over_a = dilithium3_sign_with_pk(&hash_a, &kp.secret_key, &kp.public_key)
        .expect("axis3: sign over A");
    assert_eq!(
        sig_over_a.len(),
        3309,
        "axis3: sig length MUST be 3309 to hit Ok(false), not the wrong-length Err branch"
    );
    let sig = AnchorSig {
        anchor_identity_hash: ident,
        dilithium3_sig: sig_over_a,
    };
    let err = verify_anchor_sig(&state, &sig, &hash_b, &trust_with(&[ident]))
        .expect_err("axis3: sig-over-A vs verify-against-B MUST fail");
    assert!(
        matches!(err, ElaraError::Wire(_)),
        "axis3: variant MUST be ElaraError::Wire, got {err:?}",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("anchor sig invalid"),
        "axis3: error MUST be 'anchor sig invalid' (Ok(false) branch); got {msg}",
    );
    assert!(
            !msg.contains("verify failed"),
            "axis3: error MUST NOT contain 'verify failed' (that's the Err branch — collapsing the two breaks operator triage); got {msg}",
        );
}

/// Axis 4 / wrong-length sig bytes: registered anchor, but the sig is
/// not 3309 bytes (FIPS 204 ML-DSA-65 size). `pqc::dilithium3_verify`
/// returns `Err(ElaraError::Crypto(...))`, which maps to
/// `ElaraError::Wire("anchor sig verify failed: ...")`. Distinguishes
/// the `Err` branch from the `Ok(false)` branch — the prefix "verify
/// failed:" MUST appear and the standalone "anchor sig invalid" MUST
/// NOT (the substring "invalid" still appears via "invalid ML-DSA-65
/// signature length"; we pin the more-specific "anchor sig invalid"
/// phrase).
#[test]
fn batch_nnnn_verify_anchor_sig_registered_anchor_wrong_length_sig_returns_verify_failed() {
    let state = test_state();
    let (ident, _kp) = register_anchor(&state);
    // 100 bytes is NOT 3309 — pqc::dilithium3_verify will early-return
    // Err(ElaraError::Crypto("invalid ML-DSA-65 signature length: 100 ...")).
    let bogus_sig = vec![0xee; 100];
    let sig = AnchorSig {
        anchor_identity_hash: ident,
        dilithium3_sig: bogus_sig,
    };
    let seal_hash: [u8; 32] = sha3_256(b"batch-nnnn-axis4-seal");
    let err = verify_anchor_sig(&state, &sig, &seal_hash, &trust_with(&[ident]))
        .expect_err("axis4: wrong-length sig MUST fail");
    assert!(
            matches!(err, ElaraError::Wire(_)),
            "axis4: variant MUST be ElaraError::Wire (NOT Crypto — verify_anchor_sig wraps), got {err:?}",
        );
    let msg = err.to_string();
    assert!(
        msg.contains("anchor sig verify failed"),
        "axis4: error MUST start with 'anchor sig verify failed' (Err branch); got {msg}",
    );
    // The standalone "anchor sig invalid" phrase MUST NOT appear —
    // that's the Ok(false) branch. The substring "invalid" may appear
    // inside "invalid ML-DSA-65 signature length" (pqc wrapper); the
    // assertion is on the EXACT outer-message phrase.
    assert!(
            !msg.contains("anchor sig invalid"),
            "axis4: error MUST NOT contain 'anchor sig invalid' (that's the Ok(false) branch); got {msg}",
        );
}

/// Axis 5 / disjointness pin: trigger all 3 error paths sequentially,
/// capture the 3 error strings, and assert they're pairwise distinct.
/// Defends against a future refactor that collapses the 3 messages
/// into a single "anchor sig error" — that would compile cleanly but
/// destroy the operator triage signal documented in the doc-comment
/// at routes/transitions.rs:70-77. Each message MUST also start with
/// the `ElaraError::Wire` Display prefix "Wire format error: ".
#[test]
fn batch_nnnn_verify_anchor_sig_three_error_messages_are_pairwise_distinct_strings() {
    let state = test_state();
    let (ident, kp) = register_anchor(&state);
    let seal_hash: [u8; 32] = sha3_256(b"batch-nnnn-axis5-seal");

    // Path 2: unregistered anchor — use a phantom identity NOT in CF.
    let phantom_ident: [u8; 32] = sha3_256(b"batch-nnnn-axis5-phantom");
    let path_unregistered = AnchorSig {
        anchor_identity_hash: phantom_ident,
        dilithium3_sig: vec![0x11; 3309],
    };
    let trust = trust_with(&[ident, phantom_ident]);
    let msg_unregistered = verify_anchor_sig(&state, &path_unregistered, &seal_hash, &trust)
        .expect_err("axis5: unregistered MUST err")
        .to_string();

    // Path 3: Ok(false) — sig over a different message.
    let hash_other: [u8; 32] = sha3_256(b"batch-nnnn-axis5-other-message");
    let sig_over_other = dilithium3_sign_with_pk(&hash_other, &kp.secret_key, &kp.public_key)
        .expect("axis5: sign over other");
    let path_invalid = AnchorSig {
        anchor_identity_hash: ident,
        dilithium3_sig: sig_over_other,
    };
    let msg_invalid = verify_anchor_sig(&state, &path_invalid, &seal_hash, &trust)
        .expect_err("axis5: bad sig MUST err")
        .to_string();

    // Path 4: verify Err — wrong-length sig bytes.
    let path_verify_err = AnchorSig {
        anchor_identity_hash: ident,
        dilithium3_sig: vec![0x22; 50],
    };
    let msg_verify_err = verify_anchor_sig(&state, &path_verify_err, &seal_hash, &trust)
        .expect_err("axis5: wrong-length MUST err")
        .to_string();

    // All 3 start with the Wire Display prefix.
    for (label, m) in [
        ("unregistered", &msg_unregistered),
        ("invalid", &msg_invalid),
        ("verify_err", &msg_verify_err),
    ] {
        assert!(
                m.starts_with("Wire format error: "),
                "axis5/{label}: MUST start with 'Wire format error: ' (ElaraError::Wire Display prefix); got {m}",
            );
    }

    // Pairwise disjointness — none of the 3 strings is equal to or a
    // prefix of any other. (Substring containment is too weak; equality
    // is too narrow — equal-prefix would be a regression that adds
    // identical generic text and then appends details.)
    assert_ne!(
        msg_unregistered, msg_invalid,
        "axis5: unregistered == invalid"
    );
    assert_ne!(
        msg_unregistered, msg_verify_err,
        "axis5: unregistered == verify_err"
    );
    assert_ne!(msg_invalid, msg_verify_err, "axis5: invalid == verify_err");
    // Stricter: no message is a prefix of another. A regression that
    // appends extra detail to a generic prefix (e.g. all-errors prefixed
    // "anchor sig failed: ...") would fail equality above but not the
    // prefix check. Asserts none of them is the prefix of another.
    assert!(
            !msg_invalid.starts_with(&msg_unregistered),
            "axis5: msg_invalid prefix-collides with msg_unregistered ({msg_invalid} vs {msg_unregistered})",
        );
    assert!(
            !msg_verify_err.starts_with(&msg_unregistered),
            "axis5: msg_verify_err prefix-collides with msg_unregistered ({msg_verify_err} vs {msg_unregistered})",
        );
    assert!(
        !msg_unregistered.starts_with(&msg_invalid),
        "axis5: msg_unregistered prefix-collides with msg_invalid",
    );
    assert!(
        !msg_verify_err.starts_with(&msg_invalid),
        "axis5: msg_verify_err prefix-collides with msg_invalid",
    );
    assert!(
        !msg_unregistered.starts_with(&msg_verify_err),
        "axis5: msg_unregistered prefix-collides with msg_verify_err",
    );
    assert!(
        !msg_invalid.starts_with(&msg_verify_err),
        "axis5: msg_invalid prefix-collides with msg_verify_err",
    );
}

// ─── persist_pending_entry orthogonal pins ──────────
//
// PIN: routes/transitions.rs:112 — persist_pending_entry mirrors a
// `PendingTransition` from the in-memory store to
// `CF_TRANSITIONS_PENDING` on every mutation handler (propose / sig /
// veto). It branches on the entry's `status`:
//   - Vetoed → DELETE the CF row (terminal-on-restart MUST NOT replay)
//   - any other status → PUT the serialized PendingTransition bytes
//   - entry absent from store → silent no-op (eviction-race safe)
// Failures on the put/delete path bump
// `transitions_mirror_write_failures_total`; happy paths MUST NOT.
//
// Existing direct coverage: zero. One end-to-end test
// (`veto_halt_deletes_pending_cf_row` at :3107) asserts CF state after
// a full propose→add_veto→persist chain, pinning the composite Vetoed-
// delete outcome, but does NOT isolate `persist_pending_entry`'s
// contract per branch — a refactor that inverted the status predicate
// (`!= Vetoed` instead of `== Vetoed`) would still pass the end-to-end
// test if the test's propose path happened to land in Vetoed too, but
// would silently break the AwaitingSigs/DisputeWindow put path. The 5
// axes below pin each direct branch + the failure-counter invariant.

/// Axis 1 / AwaitingSigs path writes round-trippable bytes: insert a
/// fresh entry (status starts AwaitingSigs since no proposer_sigs are
/// planted), call `persist_pending_entry`, read the CF row back,
/// deserialize via `serde_json::from_slice::<PendingTransition>`, and
/// assert {id, status, seal.kind, proposer_sigs.len(), vetoes.len()}
/// all round-trip identically. The failure counter
/// `transitions_mirror_write_failures_total` MUST remain 0. This pins
/// the most common path (every propose call hits this) and that the
/// serialization wire-shape survives the put.
#[test]
fn batch_oooo_persist_pending_entry_awaiting_sigs_writes_round_trippable_bytes() {
    let state = test_state();
    let seal = split_seal_at(100);
    let id = {
        let mut store = state.transitions.write().expect("axis1: write lock");
        store.insert(seal.clone()).expect("axis1: insert")
    };
    let baseline_failures = state
        .transitions_mirror_write_failures_total
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        baseline_failures, 0,
        "axis1: precondition — failure counter starts at 0",
    );

    persist_pending_entry(&state, &id);

    let bytes = state
        .rocks
        .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_PENDING, &id)
        .expect("axis1: cf read")
        .expect("axis1: CF row MUST exist after persist on AwaitingSigs");
    let round_trip: crate::network::transition_store::PendingTransition =
        serde_json::from_slice(&bytes)
            .expect("axis1: persisted bytes MUST deserialize back to PendingTransition");
    assert_eq!(round_trip.id, id, "axis1: id MUST round-trip");
    assert_eq!(
        round_trip.status,
        PendingStatus::AwaitingSigs,
        "axis1: status MUST round-trip as AwaitingSigs",
    );
    assert_eq!(
        round_trip.seal.kind,
        TransitionKind::Split,
        "axis1: seal.kind MUST round-trip as Split",
    );
    assert_eq!(
        round_trip.seal.proposer_sigs.len(),
        0,
        "axis1: zero proposer_sigs MUST round-trip (no add_sig was called)",
    );
    assert_eq!(
        round_trip.vetoes.len(),
        0,
        "axis1: zero vetoes MUST round-trip (no add_veto was called)",
    );

    let post_failures = state
        .transitions_mirror_write_failures_total
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        post_failures, 0,
        "axis1: failure counter MUST remain 0 on happy AwaitingSigs put",
    );
}

/// Axis 2 / DisputeWindow path PUTS, does NOT delete: the delete
/// branch is keyed EXCLUSIVELY off `status == Vetoed`, so any other
/// non-AwaitingSigs status (DisputeWindow specifically) MUST take the
/// put path. Defends against an inverted-predicate refactor (e.g.
/// "delete if status is terminal" lumping DisputeWindow with Vetoed)
/// that would silently drop the CF row before the dispute window
/// closes — letting a restart mid-dispute lose the pending entry.
/// Plants SPLIT_ANCHOR_THRESHOLD sigs via add_sig so the store flips
/// AwaitingSigs → DisputeWindow on the 4th, persists, asserts the CF
/// row exists AND its status round-trips as DisputeWindow.
#[test]
fn batch_oooo_persist_pending_entry_dispute_window_writes_not_deletes() {
    use crate::network::zone_transition_seal::SPLIT_ANCHOR_THRESHOLD;
    let state = test_state();
    let seal = split_seal_at(100);
    let id = {
        let mut store = state.transitions.write().expect("axis2: write lock");
        let inserted_id = store.insert(seal.clone()).expect("axis2: insert");
        // add_sig validates length+dedup but does NOT cryptographically
        // verify — we plant 4 disjoint anchors with bogus 3309-byte
        // sigs (length matters for verify path; not exercised here).
        for i in 0..SPLIT_ANCHOR_THRESHOLD {
            let sig = AnchorSig {
                anchor_identity_hash: [i as u8 + 1; 32],
                dilithium3_sig: vec![0xbb; 3309],
            };
            store
                .add_sig(&inserted_id, sig)
                .expect("axis2: add_sig under threshold");
        }
        let pending = store.get(&inserted_id).expect("axis2: entry present");
        assert_eq!(
            pending.status,
            PendingStatus::DisputeWindow,
            "axis2: precondition — store entry MUST flip to DisputeWindow at threshold",
        );
        inserted_id
    };

    persist_pending_entry(&state, &id);

    let bytes = state
        .rocks
        .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_PENDING, &id)
        .expect("axis2: cf read");
    assert!(
            bytes.is_some(),
            "axis2: DisputeWindow MUST take the put branch (CF row MUST exist), NOT the Vetoed delete branch",
        );
    let round_trip: crate::network::transition_store::PendingTransition =
        serde_json::from_slice(&bytes.unwrap()).expect("axis2: persisted bytes MUST deserialize");
    assert_eq!(
        round_trip.status,
        PendingStatus::DisputeWindow,
        "axis2: persisted status MUST match in-store DisputeWindow",
    );

    let failures = state
        .transitions_mirror_write_failures_total
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        failures, 0,
        "axis2: failure counter MUST remain 0 on happy DisputeWindow put",
    );
}

/// Axis 3 / Vetoed path DELETES from CF: pre-plant the CF row via an
/// AwaitingSigs persist, then flip the entry to Vetoed by adding
/// MIN_VETOES_TO_HALT vetoes through `add_veto`, then persist again.
/// Asserts (a) the CF row is gone after the second persist and (b)
/// the in-memory store entry survives (delete is CF-only — the
/// orchestrator's tick path prunes the in-memory entry, not
/// `persist_pending_entry`). Failure counter MUST remain 0.
/// This pins the exact restart-safety invariant: a Vetoed proposal
/// MUST NOT rehydrate on boot even if it was previously mirrored.
#[test]
fn batch_oooo_persist_pending_entry_vetoed_deletes_cf_row_preserves_in_memory_entry() {
    use crate::network::transition_store::{TransitionVeto, VetoReason, MIN_VETOES_TO_HALT};
    let state = test_state();
    let seal = split_seal_at(100);
    let id = {
        let mut store = state.transitions.write().expect("axis3: write lock");
        store.insert(seal.clone()).expect("axis3: insert")
    };

    // First persist plants the CF row via the AwaitingSigs put branch.
    persist_pending_entry(&state, &id);
    assert!(
        state
            .rocks
            .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_PENDING, &id)
            .expect("axis3: cf read pre-veto")
            .is_some(),
        "axis3: precondition — CF row MUST exist after AwaitingSigs persist",
    );

    // Flip status to Vetoed via MIN_VETOES_TO_HALT independent vetoes.
    // `add_veto` does NOT cryptographically verify the dilithium3_sig
    // bytes — that happens at the HTTP handler — so we can plant
    // bogus 32-byte sigs here.
    {
        let mut store = state.transitions.write().expect("axis3: write lock");
        for i in 0..MIN_VETOES_TO_HALT {
            let v = TransitionVeto {
                seal_hash: id,
                reason: VetoReason::BadBoundary,
                evidence: vec![i as u8],
                submitted_at_epoch: 101,
                vetoer_identity_hash: [i as u8 + 10; 32],
                dilithium3_sig: vec![0xcc; 32],
            };
            store.add_veto(&id, v, 101).expect("axis3: add_veto");
        }
        assert_eq!(
            store.get(&id).expect("axis3: entry present").status,
            PendingStatus::Vetoed,
            "axis3: precondition — status MUST be Vetoed after MIN_VETOES_TO_HALT",
        );
    }

    // Second persist takes the Vetoed delete branch.
    persist_pending_entry(&state, &id);
    assert!(
        state
            .rocks
            .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_PENDING, &id)
            .expect("axis3: cf read post-persist")
            .is_none(),
        "axis3: CF row MUST be deleted after persist on Vetoed",
    );

    // In-memory store entry survives the CF delete — `persist_pending_entry`
    // ONLY mirrors to CF; the tick path is what prunes the in-memory entry.
    let store = state.transitions.read().expect("axis3: read lock");
    assert!(
            store.get(&id).is_some(),
            "axis3: in-memory entry MUST persist (persist_pending_entry only mirrors to CF, never mutates store)",
        );

    let failures = state
        .transitions_mirror_write_failures_total
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        failures, 0,
        "axis3: failure counter MUST remain 0 on happy Vetoed delete",
    );
}

/// Axis 4 / Entry absent from store → silent no-op: persist for an id
/// that was never inserted (simulates the eviction race documented in
/// the routes/transitions.rs:121-125 comment — entry evicted between
/// mutation and mirror). Asserts (a) no CF row is created, (b) the
/// failure counter stays 0 (race-not-failure), and (c) the in-memory
/// store remains empty. This pins the "evict-then-persist" race as a
/// silent shape, distinct from a counter-bumping failure shape.
#[test]
fn batch_oooo_persist_pending_entry_missing_store_entry_is_silent_noop() {
    let state = test_state();
    let phantom_id: [u8; 32] = sha3_256(b"batch-oooo-axis4-phantom-id-never-inserted");
    {
        let store = state.transitions.read().expect("axis4: read lock");
        assert!(
            store.get(&phantom_id).is_none(),
            "axis4: precondition — store MUST NOT contain the phantom id",
        );
    }
    assert!(
        state
            .rocks
            .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_PENDING, &phantom_id)
            .expect("axis4: cf read pre-persist")
            .is_none(),
        "axis4: precondition — CF MUST NOT have a row for the phantom id",
    );

    persist_pending_entry(&state, &phantom_id);

    assert!(
        state
            .rocks
            .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_PENDING, &phantom_id)
            .expect("axis4: cf read post-persist")
            .is_none(),
        "axis4: no CF row MUST be created — missing-store-entry race is a silent no-op, NOT a put",
    );

    let failures = state
        .transitions_mirror_write_failures_total
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        failures, 0,
        "axis4: failure counter MUST remain 0 — eviction race is not a failure shape",
    );
}

/// Axis 5 / Vetoed delete on MISSING CF row is silent: flip an entry
/// straight to Vetoed (MIN_VETOES_TO_HALT add_veto calls) WITHOUT a
/// prior persist call, so the CF row never existed. Then call persist.
/// `state.rocks.delete_cf_raw` on a missing key is a no-op (RocksDB
/// semantics) — `persist_pending_entry` MUST NOT bump the failure
/// counter on this path. Distinct from axis 3 (which pre-plants the
/// CF row before flipping to Vetoed): axis 5 covers the "first persist
/// after veto flip" path with no prior mirror, defending against a
/// regression that treated "delete returned no rocksdb error but
/// nothing was deleted" as a failure-counter event.
#[test]
fn batch_oooo_persist_pending_entry_vetoed_with_no_prior_cf_row_is_silent_no_counter_bump() {
    use crate::network::transition_store::{TransitionVeto, VetoReason, MIN_VETOES_TO_HALT};
    let state = test_state();
    let seal = split_seal_at(100);
    let id = {
        let mut store = state.transitions.write().expect("axis5: write lock");
        let inserted_id = store.insert(seal.clone()).expect("axis5: insert");
        // Flip directly to Vetoed WITHOUT calling persist between
        // insert and add_veto — so no CF row gets pre-planted.
        for i in 0..MIN_VETOES_TO_HALT {
            let v = TransitionVeto {
                seal_hash: inserted_id,
                reason: VetoReason::BadBoundary,
                evidence: vec![i as u8],
                submitted_at_epoch: 101,
                vetoer_identity_hash: [i as u8 + 50; 32],
                dilithium3_sig: vec![0xdd; 32],
            };
            store
                .add_veto(&inserted_id, v, 101)
                .expect("axis5: add_veto");
        }
        assert_eq!(
            store
                .get(&inserted_id)
                .expect("axis5: entry present")
                .status,
            PendingStatus::Vetoed,
            "axis5: precondition — Vetoed status after MIN_VETOES_TO_HALT",
        );
        inserted_id
    };

    // Confirm precondition: no CF row exists yet (no prior persist).
    assert!(
        state
            .rocks
            .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_PENDING, &id)
            .expect("axis5: cf read pre-persist")
            .is_none(),
        "axis5: precondition — CF row MUST NOT exist before first persist",
    );

    // Persist with Vetoed status + no prior CF row → delete branch on
    // a missing key (RocksDB delete on missing key is OK).
    persist_pending_entry(&state, &id);

    assert!(
        state
            .rocks
            .get_cf_raw(crate::storage::rocks::CF_TRANSITIONS_PENDING, &id)
            .expect("axis5: cf read post-persist")
            .is_none(),
        "axis5: CF row MUST remain absent — delete on missing key is a no-op (not a put)",
    );

    let failures = state
        .transitions_mirror_write_failures_total
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
            failures, 0,
            "axis5: failure counter MUST remain 0 — delete_cf_raw on missing key is a no-op, NOT a failure",
        );
}

// ─── resolve_account orthogonal pins ─
//
// `resolve_account` (transitions.rs:1558) is the per-account "which zone do
// I route to post-transition?" query. Wallets call it after observing a
// split/merge seal to learn whether their account moves to a new zone.
// Before this batch it had ZERO direct unit coverage despite fanning into
// 6 independent decision axes any zero-coverage state hides:
//
//   (1) decode_id(transition_id) failure — bad-hex on the URL's first segment
//   (2) decode_id(account_hex) failure  — bad-hex on the URL's second segment
//   (3) Hot-store hit + Finalized      — final_binding=true, status=Finalized
//   (4) Hot-store hit + AwaitingSigs   — final_binding=false (non-Finalized)
//   (5) Split lex-compare low half     — account < split_key → children[0]
//   (5b) Split lex-compare high half   — account >= split_key → children[1]
//   (6) Hot-miss + CF fallback hit     — status hardcoded "Finalized" + final_binding=true
//   (7) Hot-miss + CF miss             — RecordNotFound (404 path)
//
// Account UX depends on these distinctions. A regression that flipped axis 5
// (low vs high half) would route every account to the wrong child zone post-
// split — undetectable until users start getting "account not found" on
// their previously-correct zone. A regression on axis 6 (CF fallback) would
// 404 every account holding an old transition id once the hot store pruned
// the entry, even though the answer is trivially derivable from CF storage.

/// Build a Split TransitionSeal with a caller-chosen split_key. Lets tests
/// pin BOTH halves of the lex-compare branch (axis 5 vs 5b) deterministically.
fn batch_ggggg_split_seal_with_split_key(split_key: [u8; 32]) -> TransitionSeal {
    TransitionSeal {
        kind: TransitionKind::Split,
        proposed_at_epoch: 100,
        effective_epoch: 100 + TRANSITION_DISPUTE_WINDOW_EPOCHS,
        parents: vec![ZoneSnapshot {
            zone_id: ZoneId::new("test/parent"),
            state_root: [1; 32],
            last_seal_record_id: "parent".into(),
            record_count: 10,
            committee_hash: [2; 32],
        }],
        children: vec![
            ZoneSnapshot {
                zone_id: ZoneId::new("test/child-low"),
                state_root: [0; 32],
                last_seal_record_id: String::new(),
                record_count: 0,
                committee_hash: [3; 32],
            },
            ZoneSnapshot {
                zone_id: ZoneId::new("test/child-high"),
                state_root: [0; 32],
                last_seal_record_id: String::new(),
                record_count: 0,
                committee_hash: [4; 32],
            },
        ],
        split_key: Some(split_key),
        proposer_sigs: vec![],
    }
}

/// Inject a PendingTransition directly into the hot store with a chosen
/// status. Uses `replay_insert` to bypass the seal-validation path so
/// tests can pin status-dependent branches (Finalized vs AwaitingSigs)
/// without running the full sig-collection lifecycle.
fn batch_ggggg_inject_pending(
    state: &Arc<NodeState>,
    seal: TransitionSeal,
    status: PendingStatus,
) -> [u8; 32] {
    let id = seal.seal_hash_for_sig().expect("seal_hash_for_sig");
    let pending = PendingTransition {
        seal,
        vetoes: vec![],
        status,
        id,
    };
    let mut store = state.transitions.write().expect("transitions write lock");
    store.replay_insert(pending);
    id
}

#[tokio::test]
async fn batch_ggggg_resolve_account_decode_id_failure_on_transition_id_returns_wire_error() {
    // Axis (1): URL's first hex segment is malformed — the first decode_id
    // call fails before any state lookup. Pin that this error path is
    // distinct from axis 2 (account-hex failure) so a refactor that
    // swapped the call order surfaces here.
    let state = test_state();
    let bad_id = "not-valid-hex-at-all".to_string();
    let good_account = hex::encode([0u8; 32]);
    let result = super::resolve_account(
        axum::extract::State(state.clone()),
        axum::extract::Path((bad_id, good_account)),
    )
    .await;
    match result {
        Ok(_) => panic!("bad transition-id hex MUST reject"),
        Err(app) => match app.0 {
            ElaraError::Wire(_) => { /* expected */ }
            other => panic!("expected Wire error, got {:?}", other),
        },
    }
}

#[tokio::test]
async fn batch_ggggg_resolve_account_decode_id_failure_on_account_returns_wire_error() {
    // Axis (2): URL's second hex segment is malformed. The first call
    // (transition_id) succeeds because the hex is well-formed even
    // though no entry exists at that id — the second call (account)
    // is where it fails. This pins call-order: a refactor that
    // resolved the account first (and 404'd before decoding it) would
    // surface the wrong error class here.
    let state = test_state();
    let good_id = hex::encode([0u8; 32]);
    let bad_account = "not-hex-either".to_string();
    let result = super::resolve_account(
        axum::extract::State(state.clone()),
        axum::extract::Path((good_id, bad_account)),
    )
    .await;
    match result {
        Ok(_) => panic!("bad account hex MUST reject"),
        Err(app) => match app.0 {
            ElaraError::Wire(_) => { /* expected */ }
            other => panic!("expected Wire error, got {:?}", other),
        },
    }
}

#[tokio::test]
async fn batch_ggggg_resolve_account_hot_finalized_returns_final_binding_true_with_finalized_label()
{
    // Axis (3): hot-store hit + status=Finalized. final_binding MUST
    // be true and status label MUST be "Finalized". This is the
    // most common account flow — observe the seal in the hot store
    // after sigs are collected and the dispute window has closed.
    let state = test_state();
    // split_key = [0xFF; 32] so any account_hash < that → children[0].
    let seal = batch_ggggg_split_seal_with_split_key([0xFFu8; 32]);
    let id = batch_ggggg_inject_pending(&state, seal, PendingStatus::Finalized);

    let account_hex = hex::encode([0x10u8; 32]); // 0x10 < 0xFF → low half
    let result = super::resolve_account(
        axum::extract::State(state.clone()),
        axum::extract::Path((hex::encode(id), account_hex.clone())),
    )
    .await;
    let response = match result {
        Ok(json) => json.0,
        Err(e) => panic!("well-formed Finalized hot-hit MUST succeed, got {:?}", e.0),
    };
    assert_eq!(response.status, "Finalized");
    assert!(
        response.final_binding,
        "Finalized status MUST set final_binding=true"
    );
    assert_eq!(
        response.post_transition_zone, "test/child-low",
        "split_key=0xFF…FF means account=0x10…10 routes to low child"
    );
    assert_eq!(
        response.account_hash, account_hex,
        "account_hash field MUST echo the input verbatim"
    );
}

#[tokio::test]
async fn batch_ggggg_resolve_account_hot_awaiting_sigs_returns_final_binding_false() {
    // Axis (4): hot-store hit + status=AwaitingSigs. final_binding MUST
    // be false — the proposal hasn't crossed the sig threshold so
    // accounts MUST NOT route to the new zone yet. A regression that
    // returned final_binding=true on non-Finalized status would let
    // accounts prematurely move their state to a zone the cluster has
    // not yet committed to.
    let state = test_state();
    let seal = batch_ggggg_split_seal_with_split_key([0xFFu8; 32]);
    let id = batch_ggggg_inject_pending(&state, seal, PendingStatus::AwaitingSigs);
    let account_hex = hex::encode([0x10u8; 32]);
    let result = super::resolve_account(
        axum::extract::State(state.clone()),
        axum::extract::Path((hex::encode(id), account_hex)),
    )
    .await;
    let response = match result {
        Ok(json) => json.0,
        Err(e) => panic!(
            "well-formed AwaitingSigs hot-hit MUST succeed, got {:?}",
            e.0
        ),
    };
    assert_eq!(response.status, "AwaitingSigs");
    assert!(
        !response.final_binding,
        "AwaitingSigs MUST set final_binding=false — proposal has not crossed sig threshold"
    );
}

#[tokio::test]
async fn batch_ggggg_resolve_account_split_lex_compare_high_half_routes_to_second_child() {
    // Axis (5b): account_hash >= split_key → children[1]. Paired with
    // axis 3 (which pinned the low-half route) to lock both sides of
    // the lex-compare branch. A regression that swapped the compare
    // direction would silently route every account to the wrong child.
    let state = test_state();
    // split_key = [0x80; 32]; account_hash = [0x90; 32] is GREATER → high half.
    let seal = batch_ggggg_split_seal_with_split_key([0x80u8; 32]);
    let id = batch_ggggg_inject_pending(&state, seal, PendingStatus::Finalized);

    let account_hex = hex::encode([0x90u8; 32]);
    let result = super::resolve_account(
        axum::extract::State(state.clone()),
        axum::extract::Path((hex::encode(id), account_hex)),
    )
    .await;
    let response = match result {
        Ok(json) => json.0,
        Err(e) => panic!("well-formed high-half query MUST succeed, got {:?}", e.0),
    };
    assert_eq!(
        response.post_transition_zone, "test/child-high",
        "split_key=0x80…80 + account=0x90…90 MUST route to high child"
    );
}

#[tokio::test]
async fn batch_ggggg_resolve_account_cf_fallback_after_hot_miss_returns_finalized_label_hardcoded()
{
    // Axis (6): hot-store MISS + CF_TRANSITIONS_FINAL HIT. The seal
    // is reconstructed from durable storage; the handler hardcodes
    // status="Finalized" + final_binding=true because seals are
    // written to CF_TRANSITIONS_FINAL ONLY after the orchestrator
    // confirms Finalization. A regression that read status from
    // some other source (or defaulted to "Expired") would break
    // account long-tail queries past the hot-store eviction window.
    let state = test_state();
    let seal = batch_ggggg_split_seal_with_split_key([0xFFu8; 32]);
    let id = seal.seal_hash_for_sig().expect("seal_hash_for_sig");
    // Write directly to CF (no hot-store insert) — simulates a
    // long-since-pruned hot entry whose seal persists in durable storage.
    let bytes = serde_json::to_vec(&seal).expect("serialize seal");
    state
        .rocks
        .put_cf_raw(crate::storage::rocks::CF_TRANSITIONS_FINAL, &id, &bytes)
        .expect("put CF row");

    // Precondition: hot store does not contain the entry.
    {
        let store = state.transitions.read().expect("transitions read");
        assert!(
            store.get(&id).is_none(),
            "hot store must be empty for axis 6"
        );
    }

    let account_hex = hex::encode([0x10u8; 32]);
    let result = super::resolve_account(
        axum::extract::State(state.clone()),
        axum::extract::Path((hex::encode(id), account_hex)),
    )
    .await;
    let response = match result {
        Ok(json) => json.0,
        Err(e) => panic!(
            "CF fallback MUST succeed on hot-miss + CF-hit, got {:?}",
            e.0
        ),
    };
    assert_eq!(
        response.status, "Finalized",
        "CF fallback hardcodes status='Finalized' — entries here are Finalized by construction"
    );
    assert!(
        response.final_binding,
        "CF fallback hardcodes final_binding=true"
    );
    assert_eq!(response.post_transition_zone, "test/child-low");
}

#[tokio::test]
async fn batch_ggggg_resolve_account_double_miss_returns_record_not_found_with_id_in_message() {
    // Axis (7): hot MISS + CF MISS → RecordNotFound. Pin that the
    // error message names the missing id so operators (and the
    // account's "transition expired" UI flow) can correlate.
    let state = test_state();
    let id_bytes = [0xAAu8; 32];
    let id_hex = hex::encode(id_bytes);
    let account_hex = hex::encode([0u8; 32]);
    let result = super::resolve_account(
        axum::extract::State(state.clone()),
        axum::extract::Path((id_hex.clone(), account_hex)),
    )
    .await;
    match result {
        Ok(_) => panic!("double-miss MUST return RecordNotFound"),
        Err(app) => match app.0 {
            ElaraError::RecordNotFound(msg) => {
                assert!(
                    msg.contains(&id_hex),
                    "RecordNotFound message MUST name the missing id (got: {msg})"
                );
            }
            other => panic!("expected RecordNotFound, got {:?}", other),
        },
    }
}

// ─── submit_sig orthogonal pins ─────────────────────
//
// Four existing tests already pin the load-bearing branches of
// submit_sig: round_trip_registered_anchor (success), rejects_
// unregistered_anchor (verify_anchor_sig failure), rejects_after_
// effective_epoch (state_core set + past-window), unknown_id_rejected_
// before_verify (hot-miss). This slice adds the FIVE remaining
// orthogonal axes that those tests don't cover:
//
//   (1) decode_id failure on URL hex — distinct from "valid hex but
//       unknown id" (existing unknown_id test uses well-formed hex).
//   (2) state_core UNSET + past-effective sig → succeeds. Negative
//       complement of rejects_after_effective_epoch: proves the
//       window-check is conditional on state_core being installed
//       (the `if let Some(core) = state.state_core.get()` guard).
//   (3) state_core SET + current_epoch == effective_epoch - 1 → sig
//       accepted. Boundary pin for the `>=` comparison: the immediate
//       sub-effective epoch must NOT trip the guard. A refactor that
//       flipped to `>` (off-by-one in the safe direction) would still
//       pass this; a flip to `<=` would fail it.
//   (4) Hot-miss RecordNotFound message contains the id_hex. Existing
//       unknown_id_rejected_before_verify only checks msg.contains
//       ("transition") — too weak. The operator playbook (account UX
//       "transition expired" path) reads the actual id back.
//   (5) Dispute-window error msg names BOTH current_epoch and
//       effective_epoch VALUES. Pins the operator-info contract: a
//       refactor that dropped one of the two epoch numbers would
//       break ops correlation but pass a content-blind test.

#[tokio::test]
async fn batch_hhhhh_submit_sig_decode_id_failure_on_url_hex_returns_wire_error() {
    // Axis (1): URL hex segment is malformed (odd length / non-hex
    // char). decode_id MUST fail at the top of submit_sig BEFORE any
    // store lookup. Pin: the error path is Wire (not RecordNotFound).
    let state = test_state();
    let bad_id = "zz".to_string();
    let bogus_sig = AnchorSig {
        anchor_identity_hash: [0x11; 32],
        dilithium3_sig: vec![0; 3309],
    };
    let result = submit_sig(
        axum::extract::State(state),
        axum::extract::Path(bad_id),
        axum::extract::Json(bogus_sig),
    )
    .await;
    match result {
        Ok(_) => panic!("malformed URL hex MUST fail at decode_id"),
        Err(app) => match app.0 {
            ElaraError::Wire(_) => { /* expected */ }
            other => panic!("expected Wire from decode_id failure, got {:?}", other),
        },
    }
}

#[tokio::test]
async fn batch_hhhhh_submit_sig_state_core_unset_bypasses_window_check_and_succeeds() {
    // Axis (2): with state_core NOT installed, the
    // `if let Some(core) = state.state_core.get()` guard falls
    // through and the request proceeds to verify_anchor_sig regardless
    // of effective_epoch. Construct a seal with a low proposed_at_epoch
    // (window already closed in wall-clock terms) and submit a valid
    // sig from a registered anchor — must succeed. Negative complement
    // of `submit_sig_rejects_after_effective_epoch`, which differs ONLY
    // in whether state_core is installed.
    let state = test_state();
    let (ident, kp) = register_anchor(&state);
    stake_anchor(&state, ident).await;

    // proposed_at_epoch = 0, effective_epoch = 3 — "past" in the sense
    // that a node at any current_epoch >= 3 would reject. With no
    // state_core, current_epoch is undefined and the guard skips.
    let seal = split_seal_at(0);
    let seal_hash = seal.seal_hash_for_sig().expect("seal_hash_for_sig");
    let propose_resp = ok_or_panic(
        propose_transition(
            axum::extract::State(state.clone()),
            axum::extract::Json(seal),
        )
        .await,
        "propose",
    );
    let id_hex = propose_resp.0.id;

    let sig_bytes =
        dilithium3_sign_with_pk(&seal_hash, &kp.secret_key, &kp.public_key).expect("sign");
    let sig = AnchorSig {
        anchor_identity_hash: ident,
        dilithium3_sig: sig_bytes,
    };
    let resp = ok_or_panic(
        submit_sig(
            axum::extract::State(state),
            axum::extract::Path(id_hex),
            axum::extract::Json(sig),
        )
        .await,
        "submit_sig",
    );
    assert_eq!(
        resp.0.sigs_collected, 1,
        "state_core unset MUST bypass window-check — sig must be accepted"
    );
}

#[tokio::test]
async fn batch_hhhhh_submit_sig_boundary_current_epoch_just_below_effective_accepts() {
    // Axis (3): state_core SET with current_epoch = effective_epoch - 1.
    // The guard's predicate is `current_epoch >= effective_epoch`, so
    // the immediate sub-effective epoch must NOT fire it. Pin: at
    // exactly `effective_epoch - 1` the sig is accepted (the `<` side
    // of `>=`). Mirror-axis of `submit_sig_rejects_after_effective_epoch`
    // (which pins the `==` side at the boundary itself).
    let state = test_state();
    let (ident, kp) = register_anchor(&state);
    stake_anchor(&state, ident).await;

    let seal = split_seal_at(100);
    let seal_hash = seal.seal_hash_for_sig().expect("seal_hash_for_sig");
    let effective_epoch = seal.effective_epoch;
    let propose_resp = ok_or_panic(
        propose_transition(
            axum::extract::State(state.clone()),
            axum::extract::Json(seal),
        )
        .await,
        "propose",
    );
    let id_hex = propose_resp.0.id;

    // Install state_core at effective_epoch - 1 — exactly one epoch
    // below the guard boundary. current_epoch (= effective-1) < effective
    // must NOT trip the guard.
    install_state_core_at_epoch(&state, effective_epoch - 1);

    let sig_bytes =
        dilithium3_sign_with_pk(&seal_hash, &kp.secret_key, &kp.public_key).expect("sign");
    let sig = AnchorSig {
        anchor_identity_hash: ident,
        dilithium3_sig: sig_bytes,
    };
    let resp = ok_or_panic(
        submit_sig(
            axum::extract::State(state),
            axum::extract::Path(id_hex),
            axum::extract::Json(sig),
        )
        .await,
        "submit_sig",
    );
    assert_eq!(
        resp.0.sigs_collected, 1,
        "current_epoch = effective_epoch - 1 MUST be inside the window — sig must be accepted"
    );
}

#[tokio::test]
async fn batch_hhhhh_submit_sig_hot_miss_record_not_found_contains_id_hex() {
    // Axis (4): hot-store miss → RecordNotFound. Pin that the error
    // message names the actual id_hex (not just "transition"), so the
    // operator/account flow can correlate the rejected sig back to the
    // expired/unknown proposal id. Strengthens the existing
    // `submit_sig_unknown_id_rejected_before_verify` test which only
    // checks msg.contains("transition").
    let state = test_state();
    let unknown_id_hex = hex::encode([0x42u8; 32]);
    let bogus_sig = AnchorSig {
        anchor_identity_hash: [0x99; 32],
        dilithium3_sig: vec![0; 3309],
    };
    let result = submit_sig(
        axum::extract::State(state),
        axum::extract::Path(unknown_id_hex.clone()),
        axum::extract::Json(bogus_sig),
    )
    .await;
    match result {
        Ok(_) => panic!("hot-miss MUST return RecordNotFound"),
        Err(app) => match app.0 {
            ElaraError::RecordNotFound(msg) => {
                assert!(
                    msg.contains(&unknown_id_hex),
                    "RecordNotFound message MUST name the missing id_hex \
                         (got: {msg}, expected to contain {unknown_id_hex})"
                );
            }
            other => panic!("expected RecordNotFound, got {:?}", other),
        },
    }
}

#[tokio::test]
async fn batch_hhhhh_submit_sig_window_closed_error_names_both_epoch_values() {
    // Axis (5): state_core set, current_epoch >= effective_epoch.
    // Pin: the Wire error message contains BOTH epoch values as
    // numeric strings, so operators reading logs can correlate the
    // rejected sig to a specific seal. A refactor that dropped one of
    // the two numbers (e.g. logged only the gap) would break ops
    // correlation but pass a content-blind test. Distinct from
    // `submit_sig_rejects_after_effective_epoch` which only checks
    // that an error occurred at all.
    let state = test_state();
    let (ident, kp) = register_anchor(&state);

    let seal = split_seal_at(100);
    let seal_hash = seal.seal_hash_for_sig().expect("seal_hash_for_sig");
    let effective_epoch = seal.effective_epoch;
    let propose_resp = ok_or_panic(
        propose_transition(
            axum::extract::State(state.clone()),
            axum::extract::Json(seal),
        )
        .await,
        "propose",
    );
    let id_hex = propose_resp.0.id;

    // Install state_core PAST effective — guard must fire, error
    // message must contain both numbers.
    let current_epoch = effective_epoch + 5;
    install_state_core_at_epoch(&state, current_epoch);

    let sig_bytes =
        dilithium3_sign_with_pk(&seal_hash, &kp.secret_key, &kp.public_key).expect("sign");
    let sig = AnchorSig {
        anchor_identity_hash: ident,
        dilithium3_sig: sig_bytes,
    };
    let msg = err_msg(
        submit_sig(
            axum::extract::State(state),
            axum::extract::Path(id_hex),
            axum::extract::Json(sig),
        )
        .await,
        "submit_sig",
    );
    let current_str = current_epoch.to_string();
    let effective_str = effective_epoch.to_string();
    assert!(
        msg.contains(&current_str),
        "dispute-window error MUST name current_epoch={current_str} (got: {msg})"
    );
    assert!(
        msg.contains(&effective_str),
        "dispute-window error MUST name effective_epoch={effective_str} (got: {msg})"
    );
}

// ─── compute_get_transition orthogonal pins ─
//
// Pivot from the `submit_sig` and `resolve_account` slices — both
// covered the production axum-extractor
// handlers. This slice drills the un-tested PQ-router twin
// `compute_get_transition` at lines 1916-1983, whose FIVE branches
// are not covered by the existing slices:
//
//   (1) `hex::decode` failure on the input id returns
//       `ElaraError::Wire("invalid id hex: <hex error>")` — distinct
//       from `decode_id`'s `"invalid id hex: {id_hex}"` form, since
//       this helper echoes the parser's error, not the input string.
//       The `decode_id` test does NOT cover this.
//   (2) Well-formed hex but byte-length != 32 returns
//       `Wire("id must be 32 bytes, got {N}")` where N MUST be the
//       actual byte length so light clients can tell a 16-byte CID
//       from a 32-byte id without re-running their own decode.
//   (3) Hot-store HIT with `status=AwaitingSigs` and `state_core`
//       epoch strictly between proposed_at and effective:
//       `window_open=true`, `id == pending.id_hex()`, and
//       `sigs_collected/threshold` reflect the seal — pins the
//       happy-path emit shape for split/merge observers.
//   (4) Hot-store HIT with `status=Finalized` but `state_core` epoch
//       INSIDE [proposed_at, effective): `window_open=false`. The
//       status-overrides-epoch invariant — a refactor that dropped
//       the `!matches!(... Finalized | Vetoed | Expired)` guard
//       would mis-flag a finalized seal as still-open.
//   (5) Pending-store MISS + CF_TRANSITIONS_FINAL HIT echoes the
//       INPUT `id_hex` (NOT `pending.id_hex()`), status is the
//       hardcoded literal "Finalized" (not `status_label`), vetoes
//       are empty, window_open is false. This is the post-prune
//       cold-tier path where a GC'd seal lives on the CF only.

#[test]
fn batch_iiiii_compute_get_transition_invalid_hex_returns_wire_with_decoder_error_inlined() {
    // Axis (1): odd-length string ("z") is not even valid hex; the
    // `hex::decode` call fails before the byte-length check. The
    // returned error MUST be Wire and MUST embed the hex crate's
    // error description so callers can distinguish "you sent
    // garbage" from "you sent valid hex of the wrong length"
    // (axis 2). Distinct from `decode_id` — that helper formats
    // `"invalid id hex: {id_hex}"`; this helper formats
    // `"invalid id hex: {e}"` where `e` is the parser error.
    let state = test_state();
    let result = super::compute_get_transition(&state, "z");
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("invalid hex MUST reject — got Ok"),
    };
    match err {
        ElaraError::Wire(msg) => {
            assert!(
                msg.starts_with("invalid id hex:"),
                "expected 'invalid id hex:' prefix, got: {msg}"
            );
            // Pin that the message embeds the parser's error and
            // NOT the literal input (the input-echo form is
            // `decode_id`'s contract, not ours).
            assert!(
                !msg.contains("invalid id hex: z"),
                "MUST NOT echo input verbatim (that's decode_id's form); got: {msg}"
            );
        }
        other => panic!("expected Wire error, got: {:?}", other),
    }
}

#[test]
fn batch_iiiii_compute_get_transition_wrong_byte_length_names_actual_count_in_error() {
    // Axis (2): 32-char hex decodes to 16 bytes — valid hex,
    // wrong length. The error MUST be Wire and MUST literally
    // contain "got 16" so operators can read the byte count
    // off a log line without re-decoding the input. Pin the
    // exact format string used at line 1925-1928.
    let state = test_state();
    // 32 hex chars → 16 bytes (not 32).
    let id_hex_16 = hex::encode([0xAAu8; 16]);
    assert_eq!(id_hex_16.len(), 32, "fixture must be 32 hex chars");
    let result = super::compute_get_transition(&state, &id_hex_16);
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("16-byte id MUST reject — got Ok"),
    };
    match err {
        ElaraError::Wire(msg) => {
            assert!(
                msg.contains("id must be 32 bytes"),
                "expected canonical length error prefix, got: {msg}"
            );
            assert!(
                msg.contains("got 16"),
                "length error MUST name actual byte count 16, got: {msg}"
            );
            // Also pin that this is distinct from `decode_id`'s
            // form which has the suffix "(64 hex chars)" — this
            // helper's message MUST NOT have that suffix.
            assert!(
                !msg.contains("64 hex chars"),
                "compute_get_transition MUST NOT use decode_id's 'X hex chars' suffix; got: {msg}"
            );
        }
        other => panic!("expected Wire error, got: {:?}", other),
    }
}

#[test]
fn batch_iiiii_compute_get_transition_pending_awaiting_sigs_window_open_true_with_seal_threshold_echoed(
) {
    // Axis (3): pending store HIT, status=AwaitingSigs, current
    // epoch strictly inside [proposed_at, effective). All three
    // window_open conditions hold: current < effective, current >=
    // proposed_at, status is NOT in {Vetoed, Expired, Finalized}.
    // The returned view MUST echo `pending.id_hex()` (the bytes
    // round-tripped — equal to the input hex in this fixture),
    // `status_label(AwaitingSigs) == "AwaitingSigs"`, and the
    // threshold/sigs_collected fields from the underlying seal.
    let state = test_state();
    let seal = split_seal_at(100); // proposed_at=100, effective=103
    let effective = seal.effective_epoch;
    let threshold = seal.required_threshold();
    let proposer_sigs_len = seal.proposer_sigs.len();
    let id = batch_ggggg_inject_pending(&state, seal, PendingStatus::AwaitingSigs);
    // current_epoch=101 is strictly between proposed_at=100 and
    // effective=103 — window MUST be open.
    install_state_core_at_epoch(&state, 101);

    let view = match super::compute_get_transition(&state, &hex::encode(id)) {
        Ok(v) => v,
        Err(e) => panic!("expected Ok, got Err({:?})", e),
    };
    assert!(
        view.window_open,
        "window_open MUST be true when current_epoch=101 is inside [100, {effective})"
    );
    assert_eq!(
        view.status, "AwaitingSigs",
        "status label must be AwaitingSigs"
    );
    assert_eq!(
        view.id,
        hex::encode(id),
        "id MUST round-trip the injected hex"
    );
    assert_eq!(
        view.threshold, threshold,
        "threshold MUST mirror seal.required_threshold()"
    );
    assert_eq!(
        view.sigs_collected, proposer_sigs_len,
        "sigs_collected MUST mirror seal.proposer_sigs.len()"
    );
    assert_eq!(
        view.current_epoch, 101,
        "current_epoch echo must be the state_core value"
    );
    assert!(view.vetoes.is_empty(), "fresh pending entry has no vetoes");
}

#[test]
fn batch_iiiii_compute_get_transition_pending_finalized_in_epoch_window_returns_window_open_false_status_overrides_epoch(
) {
    // Axis (4): pending store HIT, status=Finalized, current epoch
    // still inside [proposed_at, effective). The epoch math alone
    // would yield window_open=true, but the status guard at line
    // 1942-1947 (the `!matches!(status, Vetoed | Expired |
    // Finalized)` clause) MUST fire and force window_open=false.
    // This pins the status-overrides-epoch invariant that
    // distinguishes a finalized seal from a still-in-dispute one
    // — a refactor that dropped the guard would silently flag
    // finalized seals as still-open and break account UX.
    let state = test_state();
    let seal = split_seal_at(100); // proposed_at=100, effective=103
    let id = batch_ggggg_inject_pending(&state, seal, PendingStatus::Finalized);
    // current_epoch=101 inside [100, 103) — would be open if
    // status were AwaitingSigs/DisputeWindow (see axis 3).
    install_state_core_at_epoch(&state, 101);

    let view = match super::compute_get_transition(&state, &hex::encode(id)) {
        Ok(v) => v,
        Err(e) => panic!("expected Ok, got Err({:?})", e),
    };
    assert!(
            !view.window_open,
            "Finalized status MUST force window_open=false even when current_epoch is inside the epoch window"
        );
    assert_eq!(
        view.status, "Finalized",
        "status_label(Finalized) MUST equal 'Finalized'"
    );
    assert_eq!(
        view.current_epoch, 101,
        "current_epoch echo unchanged by status"
    );
}

#[test]
fn batch_iiiii_compute_get_transition_cf_fallback_returns_hardcoded_finalized_with_input_id_echoed()
{
    // Axis (5): pending store MISS, CF_TRANSITIONS_FINAL HIT.
    // Two pins unique to the CF branch that axes 3/4 do not
    // touch: (a) the returned `id` field is the INPUT `id_hex`
    // echoed back (line 1971: `id: id_hex.to_string()`), NOT
    // `pending.id_hex()` — the test fixture deliberately uses a
    // 32-byte key whose seal-hash-for-sig differs from the CF
    // key so a refactor that swapped to `seal.id_hex()` would
    // surface here. (b) the status string is the hardcoded
    // literal "Finalized" at line 1972, NOT the result of
    // `status_label(...)` — there is no PendingStatus involved
    // on the CF path. Also pin vetoes=empty and window_open=false.
    let state = test_state();
    // Use a chosen 32-byte CF key that is deliberately UNRELATED
    // to the seal's own hash, so we can verify id-echo behaviour.
    let cf_key = [0x77u8; 32];
    let cf_key_hex = hex::encode(cf_key);
    // Build a seal whose `seal_hash_for_sig()` would yield a
    // different 32-byte hash (any non-trivial seal does — that
    // hash depends on all the seal fields, not on a fixed [0x77]).
    let seal = split_seal_at(50);
    let seal_bytes = serde_json::to_vec(&seal).expect("seal serialize");
    state
        .rocks
        .put_cf_raw(
            crate::storage::rocks::CF_TRANSITIONS_FINAL,
            &cf_key,
            &seal_bytes,
        )
        .expect("put CF finalized seal");
    // Make sure NO pending entry exists at this key (default empty
    // store after `test_state()` — explicit sanity check).
    {
        let store = state.transitions.read().expect("read lock");
        assert!(
            store.get(&cf_key).is_none(),
            "fixture invariant: pending store must miss to take CF branch"
        );
    }

    let view = match super::compute_get_transition(&state, &cf_key_hex) {
        Ok(v) => v,
        Err(e) => panic!("expected Ok on CF hit, got Err({:?})", e),
    };
    assert_eq!(
        view.id, cf_key_hex,
        "CF branch MUST echo the INPUT id_hex, not the seal's own hash"
    );
    assert_eq!(
        view.status, "Finalized",
        "CF branch MUST set status to the hardcoded literal 'Finalized'"
    );
    assert!(
        view.vetoes.is_empty(),
        "CF branch always emits empty vetoes"
    );
    assert!(
            !view.window_open,
            "CF branch hardcodes window_open=false (the dispute window is closed for finalized-and-pruned seals)"
        );
    // Pin that seal.proposer_sigs.len() flows into sigs_collected
    // on the CF path too (line 1969).
    assert_eq!(
        view.sigs_collected,
        seal.proposer_sigs.len(),
        "sigs_collected MUST come from the deserialized CF seal"
    );
}

// ─── compute_list_transitions orthogonal pins ─
//
// Sibling of the `compute_get_transition` slice — same file,
// adjacent PQ-router helper at line 1839. compute_list_transitions
// covers the PULL side of the transition pipeline (orchestrators +
// light clients enumerating pending seals), where compute_get_transition
// covers the GET side (single-id lookup). Five branches uncovered by
// the existing tests, which all hit axum extractors or response structs — none
// drilled the helper's status-filter parser or its iteration ordering:
//
//   (1) status_filter_raw=None returns ALL pending entries; the
//       TransitionListResponse `total` field is None (pending count is
//       already total, no pagination on this endpoint) and current_epoch
//       echoes state_core.
//   (2) status_filter_raw=Some("AWAITINGSIGS") (uppercase) MUST match
//       AwaitingSigs entries — pins the `to_ascii_lowercase()` call at
//       line 1847. A refactor that dropped the lowercase normalization
//       would silently turn case-insensitive filters into a 400 wall
//       for any account that uses canonical CamelCase in its query.
//   (3) status_filter_raw=Some("FooBar") → Err(Wire("unknown status
//       filter 'foobar'")) — the embedded filter name MUST be the
//       LOWERCASED form (the `other` bound at line 1853 is the
//       lowercased &str, not the raw input). A refactor that echoed
//       the raw input would surface here.
//   (4) Multi-entry sort by (effective_epoch, id) lex-secondary —
//       two seals at same effective_epoch (split + merge both at
//       proposed_at=100, effective=103) sort deterministically by id
//       lex. A refactor that dropped the `.then_with(|| a.id.cmp(...))`
//       secondary key at line 1903 would surface as a flaky-looking
//       ordering that depends on HashMap iteration order.
//   (5) window_open per-entry follows the same status-override
//       invariant pinned for compute_get_transition
//       axis 4 — but in list context. Inject 1 AwaitingSigs + 1
//       Finalized at proposed_at=100/effective=103, install
//       state_core at epoch=101 (inside the window). The AwaitingSigs
//       entry has window_open=true; the Finalized entry has
//       window_open=false. Pins that the status-override fires
//       per-entry inside the iterator (not just on the singleton
//       lookup path).

#[test]
fn batch_jjjjj_compute_list_transitions_no_filter_returns_all_entries_with_total_none() {
    // Axis (1): default filter (None) returns every pending entry.
    // The TransitionListResponse `total` field MUST be None — the
    // pending endpoint is un-paginated, so `count` is already total.
    // The `current_epoch` field MUST echo the state_core value
    // (default 0 if state_core is not installed — but we install at
    // 50 here to pin the echo path).
    let state = test_state();
    install_state_core_at_epoch(&state, 50);
    let split = split_seal_at(100);
    let merge = merge_seal_at(200);
    let _ = batch_ggggg_inject_pending(&state, split, PendingStatus::Finalized);
    let _ = batch_ggggg_inject_pending(&state, merge, PendingStatus::AwaitingSigs);

    let resp = match super::compute_list_transitions(&state, None) {
        Ok(r) => r,
        Err(e) => panic!("default filter MUST succeed, got Err({:?})", e),
    };
    assert_eq!(resp.count, 2, "both injected entries MUST be returned");
    assert_eq!(
        resp.transitions.len(),
        2,
        "transitions vec length matches count"
    );
    assert!(
            resp.total.is_none(),
            "pending list endpoint MUST emit total=None — count is already total (no pagination here, distinct from /transitions/finalized which DOES paginate)"
        );
    assert!(resp.offset.is_none(), "no pagination → offset=None");
    assert!(resp.limit.is_none(), "no pagination → limit=None");
    assert_eq!(
        resp.current_epoch, 50,
        "current_epoch field MUST echo the state_core value"
    );
}

#[test]
fn batch_jjjjj_compute_list_transitions_uppercase_filter_matches_case_insensitive_via_lowercase_normalization(
) {
    // Axis (2): the raw filter "AWAITINGSIGS" is uppercase; the
    // `to_ascii_lowercase()` call at line 1847 normalizes it to
    // "awaitingsigs" before matching the static arms. The match MUST
    // succeed and return ONLY the AwaitingSigs entry. A regression
    // that dropped the lowercase normalization would route through
    // the `other` arm and 400 on this query. Pins ALSO that the
    // status_label echo on the matched entry is the canonical
    // CamelCase "AwaitingSigs" (not the lowercased raw) — the
    // filter and the response label come from different sources.
    let state = test_state();
    let split = split_seal_at(100);
    let merge = merge_seal_at(200);
    let _ = batch_ggggg_inject_pending(&state, split, PendingStatus::AwaitingSigs);
    let _ = batch_ggggg_inject_pending(&state, merge, PendingStatus::Finalized);

    let resp = match super::compute_list_transitions(&state, Some("AWAITINGSIGS".to_string())) {
        Ok(r) => r,
        Err(e) => panic!(
            "uppercase filter MUST be normalized to lowercase, got Err({:?})",
            e
        ),
    };
    assert_eq!(
        resp.count, 1,
        "only the AwaitingSigs entry matches — Finalized is filtered out"
    );
    assert_eq!(
            resp.transitions[0].status, "AwaitingSigs",
            "response label MUST be canonical CamelCase (status_label output), not the lowercased filter raw"
        );
}

#[test]
fn batch_jjjjj_compute_list_transitions_unknown_status_filter_returns_wire_error_with_lowercased_name_embedded(
) {
    // Axis (3): an unknown filter value "FooBar" routes through
    // the `other` arm at line 1853, which formats the error as
    // `unknown status filter '{other}'`. The `other` bound at the
    // match arm is the LOWERCASED &str (because the match
    // expression is `raw.to_ascii_lowercase().as_str()`), NOT the
    // raw input. So the error message MUST contain "foobar"
    // (lowercased) and MUST NOT contain "FooBar" (raw input).
    // This pins the lowercase normalization at the error-path
    // level: a refactor that moved `to_ascii_lowercase()` after
    // the match (echoing raw on error but lowercased on match)
    // would silently introduce that inconsistency.
    let state = test_state();
    let result = super::compute_list_transitions(&state, Some("FooBar".to_string()));
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("unknown status filter MUST reject — got Ok"),
    };
    match err {
        ElaraError::Wire(msg) => {
            assert!(
                msg.starts_with("unknown status filter"),
                "error prefix MUST be 'unknown status filter', got: {msg}"
            );
            assert!(
                msg.contains("'foobar'"),
                "error MUST embed the LOWERCASED filter name 'foobar', got: {msg}"
            );
            assert!(
                    !msg.contains("FooBar"),
                    "error MUST NOT echo the raw mixed-case input (the match arm binds the lowercased form), got: {msg}"
                );
        }
        other => panic!("expected Wire error, got: {:?}", other),
    }
}

#[test]
fn batch_jjjjj_compute_list_transitions_sort_by_effective_epoch_then_id_lex_secondary() {
    // Axis (4): three entries — two with identical effective_epoch
    // (split + merge both at proposed_at=100 → effective=103) and
    // one with later effective_epoch (split at proposed_at=200 →
    // effective=203). The sort at line 1900-1904 MUST place the
    // two effective=103 entries before the effective=203 one
    // (primary key) AND MUST order the two effective=103 entries
    // by id lex (secondary key). A refactor that dropped the
    // `.then_with(|| a.id.cmp(&b.id))` secondary would surface
    // as non-deterministic ordering of same-epoch entries, which
    // looks fine in CI most of the time but breaks light-client
    // diff-based polling that assumes a stable list order.
    let state = test_state();
    // split + merge at SAME proposed_at=100 produce two distinct
    // seals (different kind + parents/children) with the SAME
    // effective_epoch=103 but DIFFERENT ids — perfect for pinning
    // the lex-secondary tiebreak.
    let split_103 = split_seal_at(100);
    let merge_103 = merge_seal_at(100);
    let split_203 = split_seal_at(200);
    let id_split_103 = batch_ggggg_inject_pending(&state, split_103, PendingStatus::AwaitingSigs);
    let id_merge_103 = batch_ggggg_inject_pending(&state, merge_103, PendingStatus::AwaitingSigs);
    let _ = batch_ggggg_inject_pending(&state, split_203, PendingStatus::AwaitingSigs);
    // Fixture invariant: the two effective=103 ids MUST differ
    // (otherwise replay_insert would overwrite and we'd have only
    // 2 entries instead of 3, defeating the sort-pin).
    assert_ne!(
        id_split_103, id_merge_103,
        "split + merge at same proposed_at MUST yield different ids"
    );

    let resp = match super::compute_list_transitions(&state, None) {
        Ok(r) => r,
        Err(e) => panic!("expected Ok, got Err({:?})", e),
    };
    assert_eq!(resp.count, 3, "all 3 entries MUST be present");
    // Primary sort key: effective_epoch ascending.
    assert_eq!(
        resp.transitions[0].effective_epoch, 103,
        "transitions[0] MUST have effective_epoch=103 (lower primary key)"
    );
    assert_eq!(
        resp.transitions[1].effective_epoch, 103,
        "transitions[1] MUST have effective_epoch=103 (other entry at same epoch)"
    );
    assert_eq!(
        resp.transitions[2].effective_epoch, 203,
        "transitions[2] MUST have effective_epoch=203 (higher primary key)"
    );
    // Secondary sort key: id lex ascending. Pin that the two
    // effective=103 entries are ordered by their id strings.
    assert!(
        resp.transitions[0].id < resp.transitions[1].id,
        "transitions[0].id ({}) MUST be lex-less than transitions[1].id ({}) — secondary sort key",
        resp.transitions[0].id,
        resp.transitions[1].id
    );
}

#[test]
fn batch_jjjjj_compute_list_transitions_window_open_per_entry_respects_status_override_finalized_forces_false(
) {
    // Axis (5): same status-override invariant as the
    // compute_get_transition axis 4, but in LIST context — the per-entry window_open at lines
    // 1876-1883 carries the `!matches!(... Vetoed | Expired |
    // Finalized)` guard. Inject 1 AwaitingSigs + 1 Finalized at
    // proposed_at=100 / effective=103, install state_core at
    // epoch=101 (strictly inside [100, 103) for BOTH entries).
    // The epoch math alone yields window_open=true for both, but
    // the status guard MUST fire on the Finalized entry and force
    // its window_open=false. The AwaitingSigs entry retains
    // window_open=true. A regression that dropped the guard
    // inside the iterator (but kept it on the singleton lookup)
    // would silently flag every finalized seal in the list as
    // still-open — accounts polling /transitions to see what's
    // pending would offer veto buttons for already-finalized
    // seals.
    let state = test_state();
    let split_aw = split_seal_at(100); // effective=103
    let merge_fin = merge_seal_at(100); // effective=103
    let _ = batch_ggggg_inject_pending(&state, split_aw, PendingStatus::AwaitingSigs);
    let _ = batch_ggggg_inject_pending(&state, merge_fin, PendingStatus::Finalized);
    // current_epoch=101 inside [100, 103) for BOTH entries.
    install_state_core_at_epoch(&state, 101);

    let resp = match super::compute_list_transitions(&state, None) {
        Ok(r) => r,
        Err(e) => panic!("expected Ok, got Err({:?})", e),
    };
    assert_eq!(resp.count, 2, "both entries MUST be returned");

    let awaiting = resp
        .transitions
        .iter()
        .find(|t| t.status == "AwaitingSigs")
        .expect("MUST contain the AwaitingSigs entry");
    let finalized = resp
        .transitions
        .iter()
        .find(|t| t.status == "Finalized")
        .expect("MUST contain the Finalized entry");

    assert!(
        awaiting.window_open,
        "AwaitingSigs entry at current_epoch=101 inside [100, 103) MUST have window_open=true"
    );
    assert!(
            !finalized.window_open,
            "Finalized entry MUST have window_open=false even though current_epoch=101 is inside [100, 103) — status-override invariant fires per-entry in the iterator"
        );
    // Pin that current_epoch echoes state_core (101 from install).
    assert_eq!(
        resp.current_epoch, 101,
        "current_epoch field MUST echo the state_core value"
    );
}
