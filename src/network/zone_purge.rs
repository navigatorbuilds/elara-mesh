//! ZSP Phase D — subscription-change purge job.
//!
//! When a node calls `NodeState::unsubscribe_zone(zone)`, the storage layer
//! (RocksDB CFs, search index, DAG hot tier, consensus attestations) still
//! holds every record this node ever ingested for that zone. Without active
//! cleanup, disk grows without bound across subscription churn.
//!
//! This module drains those records in bounded slices: `pending_drain_loop`
//! ticks every 250ms; each tick pops one zone off the queue and deletes up to
//! `MAX_PURGE_PER_TICK` records. If more remain, the zone is re-pushed to the
//! tail. If the user re-subscribes mid-purge (race), the tick aborts and
//! drops the zone — `is_subscribed` is checked on entry.
//!
//! ## Why "exact zone match" only
//!
//! `ZoneId::to_key_bytes()` SHA3-truncates the zone path, so ancestors and
//! descendants share NO prefix in `CF_RECORD_BY_ZONE`. Phase D Slice 1 only
//! purges records tagged with the exact unsubscribed zone. Descendant purge
//! (auto-scale split aftermath) is out of scope and tracked separately —
//! see internal design notes §5.
//!
//! ## Scale
//!
//! `iter_zone` is prefix-bounded so the per-tick cost is O(MAX_PURGE_PER_TICK)
//! not O(zone_size). At 5000 records / 250 ms = 20 K records / sec / zone,
//! a 1M-record zone drains in ~50 s with no disk-IO spike.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::state::NodeState;
use super::zone::ZoneId;

/// Hard ceiling on records deleted per zone per tick. Bounds the WriteBatch
/// size in `delete_record` and keeps tick latency predictable. A 250 ms drain
/// loop × 5000 = 20 K rec/s purge throughput — fast enough to drain a 1M-
/// record zone in under a minute, slow enough not to starve other writers.
pub const MAX_PURGE_PER_TICK: usize = 5_000;

/// Push a zone onto the purge queue. Idempotent at the queue level — a zone
/// can sit in the queue multiple times (re-enqueued on partial drain), and
/// each entry is processed independently. Wrapped helper so `unsubscribe_zone`
/// doesn't have to know the timestamp encoding.
pub fn enqueue_purge_zone(state: &Arc<NodeState>, zone: ZoneId) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    if let Ok(mut q) = state.zone_purge_queue.lock() {
        q.push_back((zone, now));
    }
}

/// Age in seconds of the oldest queued purge (head of queue). 0 when queue
/// is empty. Surfaced on /metrics as `elara_zone_purge_lag_seconds_oldest`.
/// Distinguishes healthy churn (queue empties between ticks, lag <1 s) from
/// stuck purges (queue head age grows past tick cadence).
pub fn oldest_lag_secs(state: &NodeState) -> f64 {
    let q = match state.zone_purge_queue.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let head_ts = match q.front() {
        Some((_, ts)) => *ts,
        None => return 0.0,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    (now - head_ts).max(0.0)
}

/// Current queue depth (pending zones not yet drained). Note: a zone can
/// occupy multiple entries during partial drain, so this is a load gauge,
/// not a distinct-zone count.
pub fn queue_depth(state: &NodeState) -> usize {
    match state.zone_purge_queue.lock() {
        Ok(g) => g.len(),
        Err(p) => p.into_inner().len(),
    }
}

/// One purge tick. Pops the head zone, checks subscription state, and
/// deletes up to `MAX_PURGE_PER_TICK` records belonging to that zone. If
/// the zone still has records after the tick, it's re-enqueued at the tail.
///
/// Returns the number of records actually deleted this tick (0 if the queue
/// was empty, the zone was re-subscribed, or storage returned no records).
///
/// Lock discipline: holds `zone_purge_queue` only during the pop/push,
/// and acquires `dag.write()` ONCE for the whole batch (single
/// `Arc::make_mut`) instead of once per record. Storage and consensus
/// locks are still taken per-record so a long batch doesn't block other
/// writers indefinitely.
pub async fn run_purge_tick(state: &Arc<NodeState>) -> usize {
    // Pop one zone off the head.
    let (zone, _enqueued_at) = {
        let mut q = match state.zone_purge_queue.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        match q.pop_front() {
            Some(entry) => entry,
            None => return 0,
        }
    };

    // Re-subscribe race: bail out without touching storage. The user's
    // current subscription set takes precedence over the queue's snapshot.
    let still_subscribed = match state.zone_manager.lock() {
        Ok(g) => g.is_subscribed(&zone),
        Err(p) => p.into_inner().is_subscribed(&zone),
    };
    if still_subscribed {
        return 0;
    }

    let zone_key = zone.to_key_bytes();
    let record_ids =
        state.rocks.iter_zone(&zone_key, None, None, MAX_PURGE_PER_TICK);

    if record_ids.is_empty() {
        // Zone fully drained — drop without re-enqueue.
        return 0;
    }

    // DAG hot tier: take the write lock once and apply all removals in a
    // single critical section.
    {
        let mut dag_guard = state.dag.write().await;
        let dag = std::sync::Arc::make_mut(&mut *dag_guard);
        for rid in &record_ids {
            dag.remove(rid);
        }
    }

    let mut deleted = 0usize;
    for rid in &record_ids {
        // Storage: clears CF_RECORDS, secondary indexes, CF_RECORD_BY_ZONE,
        // finalized index, decrements __record_count__.
        if let Err(e) = state.rocks.delete_record(rid) {
            tracing::warn!("ZSP Phase D: delete_record({rid}) failed: {e}");
            continue;
        }
        // Consensus: clears attestations + confirmation_levels +
        // creator_stakes + cross_zone_parents + record_to_seal pointer.
        match state.consensus.lock() {
            Ok(mut cons) => cons.forget_record(rid),
            Err(p) => p.into_inner().forget_record(rid),
        }
        deleted += 1;
    }

    state
        .zone_purge_records_purged_total
        .fetch_add(deleted as u64, Ordering::Relaxed);

    // If we hit the per-tick ceiling, more records likely remain — re-queue
    // for the next tick. If we deleted fewer than the ceiling, this zone is
    // (probably) drained; one more tick with empty iter would confirm, but
    // that's the next caller's concern.
    if record_ids.len() == MAX_PURGE_PER_TICK {
        enqueue_purge_zone(state, zone);
    }

    deleted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::consensus::Attestation;
    use crate::network::state::NodeState;
    use crate::network::witness::WitnessManager;
    use crate::network::zone::ZoneId;
    use crate::record::{Classification, ValidationRecord};
    use crate::storage::rocks::StorageEngine;
    use std::sync::Arc;

    fn temp_state() -> Arc<NodeState> {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "zone-purge-test".into(),
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

    fn record_in(zone: &ZoneId, id: &str, ts_secs: f64) -> ValidationRecord {
        let mut r = ValidationRecord::create(
            id.as_bytes(),
            vec![1, 2, 3],
            vec![],
            Classification::Public,
            None,
        );
        r.id = id.to_string();
        r.timestamp = ts_secs;
        r.zone = Some(zone.clone());
        r
    }

    #[tokio::test]
    async fn purge_drains_unsubscribed_zone() {
        let state = temp_state();
        // Single-segment zone has no parent, so subscribe()/unsubscribe()
        // are exact-match symmetric — no implicit ancestor coverage to
        // confuse `is_subscribed` after unsubscribe.
        let zone = ZoneId::new("zptest");

        state.zone_manager.lock().unwrap().subscribe(&zone);
        let zone_key = zone.to_key_bytes();
        for i in 0..3u32 {
            let rec = record_in(&zone, &format!("rec-{i}"), 100.0 + i as f64);
            state.rocks.put_record(&rec.id, &rec).unwrap();
        }
        assert_eq!(state.rocks.iter_zone(&zone_key, None, None, 100).len(), 3);

        state.unsubscribe_zone(&zone);
        let n = run_purge_tick(&state).await;
        assert_eq!(n, 3);
        assert!(state.rocks.iter_zone(&zone_key, None, None, 100).is_empty());
        assert_eq!(
            state.zone_purge_records_purged_total.load(Ordering::Relaxed),
            3
        );
    }

    #[tokio::test]
    async fn re_subscribe_aborts_purge() {
        let state = temp_state();
        let zone = ZoneId::new("zprace");

        state.zone_manager.lock().unwrap().subscribe(&zone);
        let zone_key = zone.to_key_bytes();
        let rec = record_in(&zone, "rec-keep", 100.0);
        state.rocks.put_record(&rec.id, &rec).unwrap();

        // Enqueue purge directly without unsubscribing — simulates the race
        // where unsubscribe + re-subscribe both fire before the tick runs.
        enqueue_purge_zone(&state, zone.clone());
        let n = run_purge_tick(&state).await;
        assert_eq!(n, 0);
        assert_eq!(
            state.rocks.iter_zone(&zone_key, None, None, 100).len(),
            1,
            "record should survive re-subscribe race"
        );
    }

    #[tokio::test]
    async fn empty_queue_is_noop() {
        let state = temp_state();
        assert_eq!(run_purge_tick(&state).await, 0);
        assert_eq!(queue_depth(&state), 0);
        assert_eq!(oldest_lag_secs(&state), 0.0);
    }

    #[tokio::test]
    async fn forget_record_clears_consensus_state() {
        let state = temp_state();
        let zone = ZoneId::new("zpcons");

        state.zone_manager.lock().unwrap().subscribe(&zone);
        let rec = record_in(&zone, "rec-cons", 100.0);
        state.rocks.put_record(&rec.id, &rec).unwrap();

        // Seed consensus state so forget_record has something to clear.
        {
            let mut cons = state.consensus.lock().unwrap();
            cons.add_attestation(Attestation {
                record_id: "rec-cons".to_string(),
                witness_hash: "w1".to_string(),
                stake: 1000,
                timestamp: 100.0,
            });
        }
        assert_eq!(state.consensus.lock().unwrap().attestation_count("rec-cons"), 1);

        state.unsubscribe_zone(&zone);
        run_purge_tick(&state).await;

        assert_eq!(
            state.consensus.lock().unwrap().attestation_count("rec-cons"),
            0,
            "purge tick should clear consensus attestations via forget_record"
        );
    }

    // ── ZSP Phase E /admin/zones/scope coverage ───────────────────────────────

    #[tokio::test]
    async fn scope_default_behavior_is_accept_all() {
        let state = temp_state();
        let scope = crate::network::routes::admin::compute_zones_scope(&state);
        assert_eq!(scope["default_behavior"], "accept_all");
        assert_eq!(scope["subscribed_zones"], serde_json::json!([]));
        assert_eq!(scope["pending_purge"]["queue_depth"], 0);
        assert_eq!(scope["pending_purge"]["records_purged_total"], 0);
    }

    #[tokio::test]
    async fn scope_reports_subscribed_zones_and_per_zone_counts() {
        let state = temp_state();
        let zone_a = ZoneId::new("zpscope-a");
        let zone_b = ZoneId::new("zpscope-b");
        state.zone_manager.lock().unwrap().subscribe(&zone_a);
        state.zone_manager.lock().unwrap().subscribe(&zone_b);

        for i in 0..2u32 {
            let r = record_in(&zone_a, &format!("rec-a-{i}"), 100.0 + i as f64);
            state.rocks.put_record(&r.id, &r).unwrap();
        }
        let r = record_in(&zone_b, "rec-b-0", 100.0);
        state.rocks.put_record(&r.id, &r).unwrap();

        let scope = crate::network::routes::admin::compute_zones_scope(&state);
        assert_eq!(scope["default_behavior"], "scoped");
        let zones = scope["subscribed_zones"].as_array().unwrap();
        assert_eq!(zones.len(), 2);
        assert!(zones.iter().any(|z| z == "zpscope-a"));
        assert!(zones.iter().any(|z| z == "zpscope-b"));

        let per_zone = scope["per_zone_storage"].as_array().unwrap();
        let counts: std::collections::HashMap<&str, u64> = per_zone
            .iter()
            .map(|v| {
                (
                    v["zone"].as_str().unwrap(),
                    v["record_count"].as_u64().unwrap(),
                )
            })
            .collect();
        assert_eq!(counts["zpscope-a"], 2);
        assert_eq!(counts["zpscope-b"], 1);
    }

    #[tokio::test]
    async fn scope_surfaces_pending_purge_after_unsubscribe() {
        let state = temp_state();
        let zone = ZoneId::new("zpscope-purge");
        state.zone_manager.lock().unwrap().subscribe(&zone);
        let rec = record_in(&zone, "rec-only", 100.0);
        state.rocks.put_record(&rec.id, &rec).unwrap();

        // Pre-unsubscribe: queue empty.
        let pre = crate::network::routes::admin::compute_zones_scope(&state);
        assert_eq!(pre["pending_purge"]["queue_depth"], 0);

        state.unsubscribe_zone(&zone);

        // Post-unsubscribe but pre-tick: zone is queued, scope reflects it.
        let mid = crate::network::routes::admin::compute_zones_scope(&state);
        assert_eq!(mid["default_behavior"], "accept_all");
        assert_eq!(mid["pending_purge"]["queue_depth"], 1);

        // Drain.
        let purged = run_purge_tick(&state).await;
        assert_eq!(purged, 1);

        // Post-tick: queue empty, counter incremented.
        let post = crate::network::routes::admin::compute_zones_scope(&state);
        assert_eq!(post["pending_purge"]["queue_depth"], 0);
        assert_eq!(post["pending_purge"]["records_purged_total"], 1);
    }

    // ─── Phase E Slice 3: subscription persistence across restart ─────────

    #[tokio::test]
    async fn subscribe_zone_writes_persistence_file() {
        let state = temp_state();
        let z = ZoneId::new("persist/eu");
        state.subscribe_zone(&z);

        let path = crate::network::zone_persist::subscriptions_path(&state.config.data_dir);
        assert!(path.exists(), "subscribe_zone must write JSON sidecar");

        let on_disk = crate::network::zone_persist::load_subscriptions(&state.config.data_dir);
        assert!(on_disk.contains(&z), "persisted set must contain new zone");
    }

    #[tokio::test]
    async fn unsubscribe_zone_persists_removal() {
        let state = temp_state();
        let z = ZoneId::new("persist/dropme");
        state.subscribe_zone(&z);
        assert!(crate::network::zone_persist::load_subscriptions(&state.config.data_dir)
            .contains(&z));

        state.unsubscribe_zone(&z);
        let on_disk = crate::network::zone_persist::load_subscriptions(&state.config.data_dir);
        assert!(
            !on_disk.contains(&z),
            "unsubscribe must persist the removal, not just mutate in-memory"
        );
    }

    #[tokio::test]
    async fn subscribe_zone_persists_auto_pinned_ancestors() {
        // ZoneManager::subscribe() auto-pins ancestors (zone.rs:331-339).
        // Persistence must capture the full set, not just the operator's
        // named zone — otherwise restart would silently drop the ancestor
        // pin and re-flip the node to a partial-coverage state.
        let state = temp_state();
        let leaf = ZoneId::new("medical/eu/west");
        state.subscribe_zone(&leaf);

        let on_disk = crate::network::zone_persist::load_subscriptions(&state.config.data_dir);
        assert!(on_disk.contains(&leaf));
        assert!(on_disk.contains(&ZoneId::new("medical/eu")));
        assert!(on_disk.contains(&ZoneId::new("medical")));
    }

    #[tokio::test]
    async fn restore_on_boot_repopulates_zone_manager() {
        // Simulate a previous lifecycle: write a subscriptions JSON file,
        // build a NEW NodeState pointing at that data_dir, and confirm the
        // zone_manager comes up pre-populated.
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();

        let mut want = std::collections::HashSet::new();
        want.insert(ZoneId::new("retail/us"));
        want.insert(ZoneId::new("medical/eu"));
        crate::network::zone_persist::save_subscriptions(&data_dir, &want)
            .expect("seed persistence file");

        let config = crate::network::config::NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "zone-restore-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            ..Default::default()
        };
        let identity = crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        )
        .expect("generate identity");
        let rocks = std::sync::Arc::new(
            crate::storage::rocks::StorageEngine::open(data_dir.join("rocksdb"))
                .expect("open rocksdb"),
        );
        let wmgr =
            std::sync::Arc::new(crate::network::witness::WitnessManager::new(rocks.clone()));
        let state =
            std::sync::Arc::new(crate::network::state::NodeState::new(config, identity, rocks, wmgr));
        std::mem::forget(tmp);

        let mgr = state.zone_manager.lock().unwrap();
        assert!(mgr.subscribed_zones().contains(&ZoneId::new("retail/us")));
        assert!(mgr.subscribed_zones().contains(&ZoneId::new("medical/eu")));
    }

    #[tokio::test]
    async fn missing_persistence_file_yields_empty_subscriptions() {
        // Default behavior (= "accept all zones") preserved when the file
        // doesn't exist — fresh data_dir behaves as pre-Slice-3.
        let state = temp_state();
        let mgr = state.zone_manager.lock().unwrap();
        assert!(
            mgr.subscribed_zones().is_empty(),
            "fresh data_dir must have empty subscription set"
        );
    }

    // ─── public-surface invariant tests (purge throughput + gauges) ───────
    //
    // Five orthogonal axes pinning the public-surface invariants used by
    // ZSP Phase D operator dashboards (queue_depth, oldest_lag_secs gauges)
    // and the MAX_PURGE_PER_TICK throughput-math claim cited in the module
    // doc ("5000 / 250 ms = 20 K rec/s; 1 M-record zone drains in ~50 s").

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_max_purge_per_tick_literal_pin_with_throughput_math_cross_check() {
        // Pin the literal first so a future bump is intentional + audited.
        assert_eq!(MAX_PURGE_PER_TICK, 5_000);

        // Throughput at the documented 250 ms tick cadence:
        // 5_000 records / 0.250 s = 20_000 records/s.
        let tick_period_secs = 0.250f64;
        let throughput_per_sec = MAX_PURGE_PER_TICK as f64 / tick_period_secs;
        assert_eq!(throughput_per_sec, 20_000.0,
            "MAX_PURGE_PER_TICK / 250 ms must yield exactly 20 K rec/s");

        // 1 M-record drain time at 20 K rec/s = 50 s ("under a minute").
        let drain_secs_1m = 1_000_000.0 / throughput_per_sec;
        assert_eq!(drain_secs_1m, 50.0);
        assert!(drain_secs_1m < 60.0,
            "1 M-record drain must complete in <60 s at MAX_PURGE_PER_TICK");

        // Lower bound: >= 1 (zero would deadlock the queue, never drain).
        // Upper bound: <= 50_000 — a single WriteBatch this large would
        // exceed RocksDB's recommended ~32 MB batch ceiling at typical
        // 50 KB record sizes.
        assert!(MAX_PURGE_PER_TICK >= 1);
        assert!(MAX_PURGE_PER_TICK <= 50_000);
    }

    #[tokio::test]
    async fn batch_b_queue_depth_and_oldest_lag_zero_state_are_paired_on_empty() {
        // Both read helpers must report a zero-state when the queue is
        // empty, and the zero-state must agree (a regression that surfaced
        // 0.0 lag but positive depth would silently break the operator
        // dashboards' "queue idle" condition).
        let state = temp_state();
        assert_eq!(queue_depth(&state), 0);
        assert_eq!(oldest_lag_secs(&state), 0.0);

        // Readers are pure — repeated calls do not mutate.
        for _ in 0..3 {
            assert_eq!(queue_depth(&state), 0);
            assert_eq!(oldest_lag_secs(&state), 0.0);
        }
    }

    #[tokio::test]
    async fn batch_b_enqueue_same_zone_repeated_is_not_deduped_per_docstring() {
        // Docstring contract on `enqueue_purge_zone`:
        // "Idempotent at the queue level — a zone can sit in the queue
        //  multiple times (re-enqueued on partial drain), and each entry
        //  is processed independently."
        //
        // 5 enqueues of the SAME zone must yield depth = 5, not depth = 1.
        // A future dedup that broke this would silently change the
        // re-queue-on-partial-drain semantics in `run_purge_tick`.
        let state = temp_state();
        let zone = ZoneId::new("dup-pin");
        for i in 1..=5 {
            enqueue_purge_zone(&state, zone.clone());
            assert_eq!(queue_depth(&state), i,
                "queue must grow linearly even when re-enqueueing the same zone");
        }
    }

    #[tokio::test]
    async fn batch_b_enqueue_distinct_zones_grows_queue_depth_by_one_per_call() {
        // Five distinct zones, one enqueue per zone — depth must equal the
        // enqueue count exactly. Verifies that distinct zones do NOT
        // collapse and that `enqueue_purge_zone` is a strict +1 operation
        // on `queue_depth`.
        let state = temp_state();
        let zones: Vec<ZoneId> = (0..5)
            .map(|i| ZoneId::new(&format!("distinct-{i}")))
            .collect();

        for (i, z) in zones.iter().enumerate() {
            enqueue_purge_zone(&state, z.clone());
            assert_eq!(queue_depth(&state), i + 1,
                "enqueue #{i} must increment depth by exactly 1");
        }
        assert_eq!(queue_depth(&state), 5);

        // `oldest_lag_secs` must remain non-negative + finite for the
        // earliest-enqueued zone (FIFO head).
        let lag = oldest_lag_secs(&state);
        assert!(lag >= 0.0, "lag must be non-negative");
        assert!(lag.is_finite(), "lag must be finite");
        assert!(!lag.is_nan(), "lag must not be NaN");
    }

    #[tokio::test]
    async fn batch_b_oldest_lag_secs_finite_non_negative_after_enqueue_clock_skew_clamp() {
        // Source-code clamp: `(now - head_ts).max(0.0)`. Pin the clamp +
        // finite-math invariants used by the Prometheus gauge
        // `elara_zone_purge_lag_seconds_oldest`. Prometheus rejects
        // non-finite floats — a NaN/Inf escape would silently break the
        // scrape and hide a stuck purge.
        let state = temp_state();
        let zone = ZoneId::new("lag-clamp-pin");
        enqueue_purge_zone(&state, zone);

        let lag = oldest_lag_secs(&state);
        assert!(lag >= 0.0, "lag clamped to ≥ 0 (clock-skew defense)");
        assert!(lag.is_finite(), "lag is finite (Prometheus rejects NaN/Inf)");
        assert!(!lag.is_nan(), "lag is not NaN");
        // Within a fresh process the lag must be very small — well under
        // 60 s (the typical Prometheus scrape interval).
        assert!(lag < 60.0,
            "fresh-enqueue lag must be << 60 s, got {lag}");
    }

    #[tokio::test]
    async fn full_lifecycle_subscribe_drop_rebuild_restores() {
        // End-to-end: subscribe through the canonical helper, drop the state,
        // rebuild a new NodeState on the same data_dir, verify the
        // subscription is back in the manager.
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();

        let make_state = |dir: &std::path::Path| -> std::sync::Arc<crate::network::state::NodeState> {
            let config = crate::network::config::NodeConfig {
                data_dir: dir.to_path_buf(),
                identity_path: dir.join("identity.json"),
                db_path: dir.join("elara.db"),
                admin_token: "test-admin".into(),
                network_id: "zone-lifecycle-test".into(),
                mdns_enabled: false,
                health_check_interval_secs: 0,
                min_pow_difficulty: 0,
                ..Default::default()
            };
            let identity = crate::identity::Identity::generate(
                crate::identity::EntityType::Device,
                crate::identity::CryptoProfile::ProfileB,
            )
            .expect("generate identity");
            let rocks = std::sync::Arc::new(
                crate::storage::rocks::StorageEngine::open(dir.join("rocksdb"))
                    .expect("open rocksdb"),
            );
            let wmgr = std::sync::Arc::new(
                crate::network::witness::WitnessManager::new(rocks.clone()),
            );
            std::sync::Arc::new(crate::network::state::NodeState::new(
                config, identity, rocks, wmgr,
            ))
        };

        // Single-segment zone has no ancestor, so subscribe()/unsubscribe()
        // are exact-symmetric — `is_subscribed` won't return true via the
        // ancestor-coverage rule (zone.rs:347-353) after the unsubscribe
        // step. (Same trick as `re_subscribe_aborts_purge`.)
        let z = ZoneId::new("lifecyclezone");

        // Run 1: subscribe through state helper.
        {
            let s1 = make_state(&data_dir);
            s1.subscribe_zone(&z);
            assert!(s1.zone_manager.lock().unwrap().is_subscribed(&z));
        }

        // Run 2: rebuild on the same data_dir, expect restored.
        {
            let s2 = make_state(&data_dir);
            assert!(
                s2.zone_manager.lock().unwrap().is_subscribed(&z),
                "subscription must survive state drop + rebuild"
            );
        }

        // Run 3: unsubscribe, rebuild, expect empty.
        {
            let s3 = make_state(&data_dir);
            s3.unsubscribe_zone(&z);
        }
        {
            let s4 = make_state(&data_dir);
            assert!(
                !s4.zone_manager.lock().unwrap().is_subscribed(&z),
                "unsubscribe must also survive state drop + rebuild"
            );
        }

        std::mem::forget(tmp);
    }
}
