#![cfg(feature = "node")]
//! §11.23 Layer A slice 1 — `?relay=1` peer-relay integration tests.
//!
//! Unit tests in `src/network/record_hash_fetcher.rs` cover the pure
//! `select_candidates` filter chain (self / unreachable / backoff /
//! cap-at-8 / FIFO / mixed-filter composition). This file exercises the
//! NEXT layer up: the `fetch_record_from_peers` orchestrator on a real
//! `NodeState`, asserting that the three peer-relay counters
//! (`attempts`, `hits`, `misses`) bookkeep correctly across the
//! empty-pool fast-paths AND that the counter-domain isolation
//! between the LOCAL hit/miss family (`records_by_hash_{hits,misses}_total`)
//! and the RELAY-tier family (`records_by_hash_peer_relay_*`) is preserved.
//!
//! Why this layer matters: the empty-post-filter path is the dominant
//! production path on a fresh node (no peers yet) AND on any node where
//! the local peer table happens to contain only skip-class entries
//! (all unreachable, all in backoff, all self). The counter bookkeeping
//! in that path drives the operator-facing dashboards that decide
//! whether peer-relay is doing useful work at all — a regression that
//! double-counts or under-counts attempts/misses here silently distorts
//! the alerting signal at fleet scale.
//!
//! §720-(a) closure: tests/ was empty for `?relay=1` despite impl
//! shipped since §617 and 17 unit tests in `record_hash_fetcher.rs`.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use elara_runtime::identity::{CryptoProfile, EntityType, Identity};
use elara_runtime::network::config::NodeConfig;
use elara_runtime::network::peer::{NodeType, PeerInfo, PeerProvenance, PeerState};
use elara_runtime::network::record_hash_fetcher::{fetch_record_from_peers, FetchOutcome};
use elara_runtime::network::state::NodeState;
use elara_runtime::network::witness::WitnessManager;
use elara_runtime::storage::rocks::StorageEngine;

/// 64-hex content-hash fixture. Doesn't need to map to anything real —
/// the empty-pool fast-paths never touch the storage layer.
const FIXTURE_HASH: &str =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

/// Construct a fresh NodeState with an isolated tempdir and `min_pow_difficulty=0`
/// so test-only PeerInfo records (which carry no PoW) can be inserted.
/// `std::mem::forget(tmp)` is intentional — the test process exits before
/// the tempdir matters, and dropping it mid-test races against rocks lock
/// release on some kernels.
fn fresh_state() -> Arc<NodeState> {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let config = NodeConfig {
        data_dir: data_dir.clone(),
        identity_path: data_dir.join("identity.json"),
        db_path: data_dir.join("elara.db"),
        admin_token: "test-admin".into(),
        network_id: "relay-v1-test".into(),
        mdns_enabled: false,
        health_check_interval_secs: 0,
        min_pow_difficulty: 0,
        ..Default::default()
    };
    let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
        .expect("generate identity");
    let rocks = Arc::new(
        StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"),
    );
    let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
    let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
    std::mem::forget(tmp);
    state
}

/// Construct a PeerInfo with explicit `reachable` + `backoff_until` knobs.
/// The other fields are zeroed defaults — none of them affect the
/// `select_candidates` filter chain (`failures` is read indirectly via
/// `in_backoff(now)`, which the explicit `backoff_until` value overrides).
fn mk_peer(id: &str, host: &str, reachable: bool, in_backoff: bool) -> PeerInfo {
    PeerInfo {
        identity_hash: id.to_string(),
        host: host.to_string(),
        port: 9473,
        node_type: NodeType::Leaf,
        last_seen: 0.0,
        state: PeerState::Connected,
        failures: if in_backoff { 5 } else { 0 },
        successes: 0,
        valid_records: 0,
        invalid_records: 0,
        // f64::MAX / 2.0 keeps the test stable past 2038 without
        // overflowing the duration_since arithmetic in `in_backoff`.
        backoff_until: if in_backoff { f64::MAX / 2.0 } else { 0.0 },
        pow_nonce: 0,
        pow_difficulty: 0,
        public_key_hex: String::new(),
        provenance: PeerProvenance::Outbound,
        subscribed_zones: Default::default(),
        att_watermark: 0.0,
        pull_failures: 0,
        pull_backoff_until: 0.0,
        reachable,
        protocol_version: 0,
        att_pull_invalid_sig: 0,
        att_pull_invalid_powas: 0,
        att_push_low_stake_deferred: 0,
        recent_bad_sig_record_ids: std::collections::VecDeque::new(),
    }
}

/// Snapshot the three peer-relay counters atomically (well, Relaxed —
/// the test thread is the only writer so observation-order races are
/// not in scope). Returned tuple is `(attempts, hits, misses)`.
fn peer_relay_counters(state: &NodeState) -> (u64, u64, u64) {
    (
        state.records_by_hash_peer_relay_attempts_total.load(Ordering::Relaxed),
        state.records_by_hash_peer_relay_hits_total.load(Ordering::Relaxed),
        state.records_by_hash_peer_relay_misses_total.load(Ordering::Relaxed),
    )
}

/// Snapshot the LOCAL hit/miss counters — distinct from the relay-tier
/// counters above. The relay fetcher path must NOT touch these.
fn local_hits_misses(state: &NodeState) -> (u64, u64) {
    (
        state.records_by_hash_hits_total.load(Ordering::Relaxed),
        state.records_by_hash_misses_total.load(Ordering::Relaxed),
    )
}

// ── Test 1: fresh-state counter sanity ──────────────────────────────────

#[tokio::test]
async fn s1123_la1_int_fresh_state_initializes_all_three_relay_counters_to_zero() {
    // Regression-pin against a refactor that initializes any of the three
    // peer-relay counters non-zero (e.g., via Default impl drift). At
    // fleet scale, a non-zero baseline would silently shift the
    // `rate()` graphs in the operator dashboards by a constant offset.
    let state = fresh_state();
    let (attempts, hits, misses) = peer_relay_counters(&state);
    assert_eq!(attempts, 0, "fresh node must have attempts=0");
    assert_eq!(hits, 0, "fresh node must have hits=0");
    assert_eq!(misses, 0, "fresh node must have misses=0");
}

// ── Test 2: empty peer table is the canonical fast-path ─────────────────

#[tokio::test]
async fn s1123_la1_int_empty_peer_table_yields_miss_and_bumps_attempts_plus_misses() {
    // Empty peer table — `select_candidates` returns Vec::new(), the
    // fetcher takes the early-return branch at `record_hash_fetcher.rs:84`,
    // bumps misses and returns. Pins the most common production path
    // (fresh node, no peers discovered yet) end-to-end.
    let state = fresh_state();
    let before = peer_relay_counters(&state);
    assert_eq!(before, (0, 0, 0));

    let outcome = fetch_record_from_peers(&state, FIXTURE_HASH).await;
    assert_eq!(outcome, FetchOutcome::Miss,
        "empty peer table must yield Miss, not Hit");

    let (attempts, hits, misses) = peer_relay_counters(&state);
    assert_eq!(attempts, 1, "single call must bump attempts by exactly 1");
    assert_eq!(hits, 0, "no peer to hit — hits must stay at 0");
    assert_eq!(misses, 1, "empty-pool early-return must bump misses by 1");
}

// ── Test 3: unreachable-only pool routes to miss via filter chain ───────

#[tokio::test]
async fn s1123_la1_int_unreachable_only_pool_yields_miss() {
    // Pool of 3 reachable=false peers. `select_candidates` filters all
    // of them out via the `.filter(|p| p.reachable)` predicate, the
    // post-filter Vec is empty, the fetcher takes the empty-pool branch.
    // Pins that the filter chain — when EVERY input falls into the
    // unreachable skip class — collapses to the same fast-path the
    // truly-empty pool takes, with identical counter deltas.
    let state = fresh_state();
    {
        let mut peers = state.peers.write().await;
        for i in 0..3 {
            let p = mk_peer(&format!("unreach{i}"), "10.0.0.1", false, false);
            assert!(peers.insert(p), "unreachable peer insert must succeed");
        }
    }

    let before = peer_relay_counters(&state);
    let outcome = fetch_record_from_peers(&state, FIXTURE_HASH).await;
    assert_eq!(outcome, FetchOutcome::Miss);

    let after = peer_relay_counters(&state);
    assert_eq!(after.0 - before.0, 1, "attempts +1");
    assert_eq!(after.1 - before.1, 0, "hits unchanged");
    assert_eq!(after.2 - before.2, 1, "misses +1");
}

// ── Test 4: backoff-only pool routes to miss ────────────────────────────

#[tokio::test]
async fn s1123_la1_int_backoff_only_pool_yields_miss() {
    // Pool of 3 in-backoff peers (failures>=5, backoff_until=far_future).
    // `select_candidates` filters them out via the `.filter(|p| !p.in_backoff(now))`
    // predicate. Distinct from Test 3 because backoff is a *temporal*
    // skip (recoverable when backoff_until <= now), unreachable is a
    // *structural* skip (only flips via the peer's own re-advertise).
    // The filter chain handles both via the same `.collect::<Vec>()`
    // empty-result branch.
    let state = fresh_state();
    {
        let mut peers = state.peers.write().await;
        for i in 0..3 {
            let p = mk_peer(&format!("backoff{i}"), "10.0.0.1", true, true);
            assert!(peers.insert(p), "backoff peer insert must succeed");
        }
    }

    let outcome = fetch_record_from_peers(&state, FIXTURE_HASH).await;
    assert_eq!(outcome, FetchOutcome::Miss);

    let (attempts, hits, misses) = peer_relay_counters(&state);
    assert_eq!(attempts, 1);
    assert_eq!(hits, 0);
    assert_eq!(misses, 1);
}

// ── Test 5: mixed skip-class pool composes through filter chain ─────────

#[tokio::test]
async fn s1123_la1_int_mixed_skip_pool_yields_miss() {
    // 1 unreachable + 2 in-backoff peers. None survive the filter chain.
    // Distinct from Tests 3 + 4: those exercise a UNIFORM skip class,
    // this one exercises COMPOSITION — the chain
    // `filter(reachable).filter(!in_backoff)` must hold its empty
    // result when the skip reasons differ across the input.
    let state = fresh_state();
    {
        let mut peers = state.peers.write().await;
        assert!(peers.insert(mk_peer("u1", "10.0.0.1", false, false)));
        assert!(peers.insert(mk_peer("b1", "10.0.0.2", true, true)));
        assert!(peers.insert(mk_peer("b2", "10.0.0.3", true, true)));
    }

    let outcome = fetch_record_from_peers(&state, FIXTURE_HASH).await;
    assert_eq!(outcome, FetchOutcome::Miss);

    let (attempts, hits, misses) = peer_relay_counters(&state);
    assert_eq!(attempts, 1);
    assert_eq!(hits, 0);
    assert_eq!(misses, 1);
}

// ── Test 6: counters are strictly monotonic over N back-to-back calls ───

#[tokio::test]
async fn s1123_la1_int_relay_counters_strictly_monotonic_over_n_calls() {
    // 5 sequential calls on an empty pool. Pins:
    //   * attempts MUST equal N — the bump at line 76 is on entry, no
    //     early return skips it
    //   * misses MUST equal N — the empty-pool branch is the SOLE bump
    //     site on this path, so it must fire exactly once per call
    //   * hits stays 0 — no candidates, no hit ever
    // Catches a regression that conditionally skipped the entry-bump
    // (e.g. `if !candidates.is_empty() { attempts.fetch_add(1, …) }`)
    // which would pass Test 2's "+1" assertion but under-count here.
    let state = fresh_state();
    const N: u64 = 5;
    for _ in 0..N {
        let outcome = fetch_record_from_peers(&state, FIXTURE_HASH).await;
        assert_eq!(outcome, FetchOutcome::Miss);
    }
    let (attempts, hits, misses) = peer_relay_counters(&state);
    assert_eq!(attempts, N,
        "attempts must increment exactly once per call (got {attempts}, expected {N})");
    assert_eq!(hits, 0, "no candidates means no hit ever");
    assert_eq!(misses, N,
        "empty-pool early-return must bump misses exactly once per call (got {misses}, expected {N})");
}

// ── Test 7: counter-domain isolation — relay fetcher leaves local untouched

#[tokio::test]
async fn s1123_la1_int_relay_fetcher_does_not_touch_local_hits_misses() {
    // `fetch_record_from_peers` MUST only bump the peer-relay-tier
    // counters (`records_by_hash_peer_relay_*`), never the LOCAL-tier
    // counters (`records_by_hash_{hits,misses}_total`). The local-tier
    // counters are owned by `compute_record_by_hash` exclusively —
    // a regression that bumped them from inside the fetcher would
    // silently double-count local misses on every `?relay=1` request
    // (the axum handler chain bumps local-miss, THEN enters fetcher;
    // a duplicate bump inside fetcher would 2× the local-miss rate).
    let state = fresh_state();
    let (local_h_before, local_m_before) = local_hits_misses(&state);
    assert_eq!((local_h_before, local_m_before), (0, 0));

    for _ in 0..3 {
        let _ = fetch_record_from_peers(&state, FIXTURE_HASH).await;
    }

    let (local_h_after, local_m_after) = local_hits_misses(&state);
    assert_eq!(local_h_after, 0,
        "local-tier hits must not bump from inside the relay fetcher");
    assert_eq!(local_m_after, 0,
        "local-tier misses must not bump from inside the relay fetcher — counter-domain isolation regression");

    // And the relay-tier counters DID bump — sanity check that the
    // test actually exercised the path.
    let (attempts, _, misses) = peer_relay_counters(&state);
    assert_eq!(attempts, 3);
    assert_eq!(misses, 3);
}

// ── Test 8: hits counter is strictly write-once-per-success-path ────────

#[tokio::test]
async fn s1123_la1_int_hits_counter_stays_zero_when_no_candidates_resolve() {
    // The `hits` bump is only reachable via the success branch at
    // `record_hash_fetcher.rs:104-106` (`pq_client.get_record_by_hash(...) =>
    // Ok(Some(body))`). Empty-pool, unreachable-only, and backoff-only
    // pools all bypass the loop entirely — `hits` must stay 0 across all
    // three. This test pins that NONE of the three skip-class fast-paths
    // accidentally bumps `hits` (e.g., via a stray `fetch_add` in the
    // empty-pool branch that should have been on `misses`).
    let state = fresh_state();

    // Path 1: empty pool.
    let _ = fetch_record_from_peers(&state, FIXTURE_HASH).await;
    assert_eq!(
        state.records_by_hash_peer_relay_hits_total.load(Ordering::Relaxed),
        0,
        "empty-pool path must NOT bump hits",
    );

    // Path 2: unreachable-only pool.
    {
        let mut peers = state.peers.write().await;
        assert!(peers.insert(mk_peer("u", "10.0.0.1", false, false)));
    }
    let _ = fetch_record_from_peers(&state, FIXTURE_HASH).await;
    assert_eq!(
        state.records_by_hash_peer_relay_hits_total.load(Ordering::Relaxed),
        0,
        "unreachable-only path must NOT bump hits",
    );

    // Path 3: add an in-backoff peer alongside (still all-skip).
    {
        let mut peers = state.peers.write().await;
        assert!(peers.insert(mk_peer("b", "10.0.0.2", true, true)));
    }
    let _ = fetch_record_from_peers(&state, FIXTURE_HASH).await;
    assert_eq!(
        state.records_by_hash_peer_relay_hits_total.load(Ordering::Relaxed),
        0,
        "mixed-all-skip path must NOT bump hits",
    );
}
