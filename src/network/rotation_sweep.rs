//! KR-3 S2 — W2 durable-marker catch-up sweep (IO gather+apply shell, §3-3).
//!
//! The W1 finalize-drain hook ([`crate::network::pending_drain`]) writes a
//! rotation-CF entry on the finalize tick from *fresh in-memory* seal state.
//! Two races leave a rotation finalized with no W1 write:
//! - the **Layer-1-first race** — a record reaches consensus-Finalized via pure
//!   attestation *before* any seal covers it, so `covering_seal_finality` is
//!   `None` at drain time; and
//! - a **crash / boot-replay corner** — the node dies (or replays on boot via
//!   `recompute_confirmation(suppress_events=true)`) between the fast-track
//!   finalize and the drain, so the enqueue that drives W1 never fires.
//!
//! This module is the durable BACKSTOP for both. At seal ingest, W2-A arms a
//! durable `rotation_seal_pending:{zone}:{epoch}` marker inside the seal's own
//! Phase-2 `WriteBatch` (crash-atomic). This sweep scans those markers and, per
//! marker slot, re-derives the covering seal's finality from **durable evidence
//! only — never the 24 h-evicted attestation trackers** (the round-2 R-1
//! lesson): the durable scheme-(i) `att:{seal_rid}:{witness}` rows (Leg A) and
//! the zone's canonical `previous_seal_hash` burial walk (Leg B). It hands those
//! inputs to the pure per-slot planner
//! ([`rotation_finality::plan_marker_slot_sweep`], W2-B2a), then persists the
//! entries the planner returns and discharges the marker once every hop
//! obligation is written.
//!
//! **Layering.** The decision core is pure and exhaustively unit-tested in
//! [`rotation_finality`]; this file is only the IO shell — gather the durable
//! inputs, call the planner, apply the plan. Keeping the two apart means the
//! fork-bearing finality logic is testable without a live node and cannot drift
//! from the threshold the live settlement path uses.
//!
//! **Zero runtime effect this slice.** The sweep has NO production caller yet —
//! the periodic (`spawn_pending_sweep_loop`) + boot wiring is the W2-C slice.
//! It is also self-gated on `s2_rotation_ordering_enabled`, so even once wired
//! it is a byte-identical no-op until the flag flips. Both properties are
//! proven by the tests below (flag-OFF no-op; every write path exercised only
//! with the flag ON).

use std::sync::atomic::Ordering;
use std::sync::Arc;

use tracing::warn;

use crate::network::rotation_finality as rf;
use crate::network::state::NodeState;
use crate::network::zone::ZoneId;
use crate::network::LockRecover;
use crate::storage::rocks::StorageEngine;

/// Hard ceiling on the canonical `previous_seal_hash` burial walk (SCALE
/// backstop). The walk is naturally bounded to `tip_epoch − marker_epoch` (it
/// stops the moment it reaches the marker's epoch — see
/// [`build_canonical_prefix`]), so in steady state it is 1–3 steps: a marker
/// only survives while its seal is still shallow, and once buried it is
/// discharged and gone. This ceiling only binds in the degenerate case of an
/// off-canonical / orphaned target the epoch-stop never reaches, or a boot after
/// pathological (thousands-of-epochs) downtime with an un-discharged marker; in
/// both the extra work is a bounded one-off and the conservative outcome
/// ("not buried → keep the marker") is safe.
const MAX_CANONICAL_SEAL_WALK: u64 = 4096;

/// Per-run outcome of the durable-marker sweep, for the W2-C loop's logging and
/// the cross-module tests. All counters are per-invocation (not cumulative — the
/// cumulative view is the `elara_rotation_cf_write_total{writer="sweep"}` and
/// `_failed_total` metrics the apply path bumps).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RotationSweepStats {
    /// Armed markers examined this run.
    pub markers_scanned: u64,
    /// Rotation-CF entries persisted this run (`writer=sweep`). One per finalized
    /// member hop of a winning seal; a hop deferred by same-slot lineage or a
    /// pulse-less seal is NOT counted (it writes nothing this tick).
    pub entries_written: u64,
    /// Markers discharged (deleted) this run — a final seal was chosen AND every
    /// hop obligation was written, so the slot is fully swept.
    pub markers_discharged: u64,
    /// Rotation-CF writes that failed to persist (RocksDB error). The marker is
    /// then kept for the next tick regardless of the plan's discharge verdict, so
    /// a transient fault self-heals rather than losing the entry.
    pub write_failures: u64,
    /// Markers whose `(zone, epoch)` slot held no stored seal (an orphaned
    /// marker). Kept, never written — nothing to finalize there.
    pub orphan_markers: u64,
}

/// Run one durable-marker catch-up sweep (§3-3 W2). Scans every armed
/// `rotation_seal_pending:{zone}:{epoch}` marker and sweeps its slot.
///
/// Self-gated: a byte-identical no-op while `s2_rotation_ordering_enabled` is
/// OFF (returns default stats without even scanning). The W2-C caller gates too,
/// mirroring the W1 hook; the redundant self-gate keeps the entry point safe to
/// call unconditionally from any future loop.
pub async fn run_rotation_marker_sweep(state: &Arc<NodeState>) -> RotationSweepStats {
    let mut stats = RotationSweepStats::default();
    if !state.config.s2_rotation_ordering_enabled {
        return stats;
    }
    // Ascending epoch within each zone (§3-3 sweep order) — the scan is a
    // prefix-bounded seek, never a full-CF walk (SCALE).
    for (zone, epoch) in state.rocks.scan_rotation_seal_markers() {
        sweep_one_marker(state, &zone, epoch, &mut stats).await;
    }

    // W2-D observability: fold this run's per-invocation stats into the cumulative
    // metrics. Only reached when the flag is ON (the OFF path early-returned
    // above), so every W2-D metric stays 0 under flag-OFF — byte-identical.
    // `entries_written`/`write_failures` are already bumped inline by the apply
    // path (`writer=sweep` + `_failed_total`); folding them here would double-count.
    state.rotation_sweep_runs_total.fetch_add(1, Ordering::Relaxed);
    state
        .rotation_sweep_markers_scanned_total
        .fetch_add(stats.markers_scanned, Ordering::Relaxed);
    state
        .rotation_sweep_markers_discharged_total
        .fetch_add(stats.markers_discharged, Ordering::Relaxed);
    state
        .rotation_sweep_orphan_markers_total
        .fetch_add(stats.orphan_markers, Ordering::Relaxed);
    // Gauge (not a counter): armed markers still pending after this run.
    state.rotation_sweep_pending_markers.store(
        stats.markers_scanned.saturating_sub(stats.markers_discharged),
        Ordering::Relaxed,
    );

    stats
}

/// Sweep one marker slot: gather the DISC-5 rival candidates + their durable
/// evidence inputs, plan with the pure per-slot planner, apply the plan.
async fn sweep_one_marker(
    state: &Arc<NodeState>,
    zone: &str,
    epoch: u64,
    stats: &mut RotationSweepStats,
) {
    stats.markers_scanned += 1;

    // DISC-5 rival set: every seal stored at this slot (Phase-2 writes every
    // parsed seal before the canonicality decision, so a slot can hold >1).
    let rids = state.rocks.seal_record_ids_at_zone_epoch(epoch, zone);
    if rids.is_empty() {
        // Orphaned marker — no seal stored here. Keep it, never a write.
        stats.orphan_markers += 1;
        return;
    }

    // Build the candidate set + capture the authoritative ZoneId (all rivals in
    // a DISC-5 slot share it) and each candidate's seal-creator identity for the
    // denominator exclusion.
    let mut candidates: Vec<rf::SlotSealCandidate> = Vec::with_capacity(rids.len());
    let mut creator_hashes: Vec<String> = Vec::with_capacity(rids.len());
    let mut zone_id: Option<ZoneId> = None;
    for rid in &rids {
        let Ok(Some(seal_rec)) = state.rocks.get_record(rid) else {
            continue;
        };
        let Ok(Some(parsed)) = crate::network::epoch::extract_epoch_seal(&seal_rec) else {
            continue;
        };
        // A seal with no beacon pulse at all cannot contribute a coordinate-
        // bearing entry (§4 fail-closed). Skipping it is outcome-identical to
        // including it: it could only "win" its slot and then fail to build,
        // keeping the marker — never a wrong write — while avoiding a fabricated
        // placeholder pulse. (A pulse that is present but carries no `chain_hash`
        // is a different case: it flows through as a real candidate whose
        // `seal_chain_hash = None` triggers the planner's fail-closed path.)
        let Some(pulse) = parsed.drand_pulse.clone() else {
            continue;
        };

        // Member records already filtered to rotation *hops* (revocations and
        // non-rotation records excluded — their entry shape is the §6.3
        // resolver's). Each `record_hashes` entry is a member `record.record_hash()`.
        let mut member_hops: Vec<crate::record::ValidationRecord> = Vec::new();
        for mh in &parsed.record_hashes {
            let Some(mid) = state.rocks.record_id_by_record_hash(&hex::encode(mh)) else {
                continue;
            };
            let Ok(Some(mrec)) = state.rocks.get_record(&mid) else {
                continue;
            };
            if rf::rotation_hop_fields(&mrec).is_some() {
                member_hops.push(mrec);
            }
        }

        // Leg-A input: the witness hash of every durable scheme-(i)
        // `att:{seal_rid}:{witness}` row on the SEAL record (deduped in the
        // recount). Never the ephemeral consensus attestation map.
        let attesting_witnesses: Vec<String> = state
            .witness_mgr
            .get_attestations(rid)
            .map(|rows| rows.into_iter().map(|a| a.witness_hash).collect())
            .unwrap_or_default();

        if zone_id.is_none() {
            zone_id = Some(parsed.zone.clone());
        }
        creator_hashes.push(crate::accounting::types::creator_identity_hash(&seal_rec));
        candidates.push(rf::SlotSealCandidate {
            seal_record_id: rid.clone(),
            seal_hash: seal_rec.record_hash(),
            seal_chain_hash: pulse.chain_hash.clone(),
            seal_round: pulse.round,
            seal_zone_path: parsed.zone.path().to_string(),
            seal_epoch: parsed.epoch_number,
            pulse,
            attesting_witnesses,
            member_hops,
        });
    }

    let Some(zone_id) = zone_id else {
        // No parsable pulse-bearing seal at the slot → nothing to finalize yet.
        // Keep the marker (it is not orphaned — a seal is stored, just not
        // coordinate-eligible this tick).
        return;
    };

    // Settlement denominator for the slot's zone (committee stake when active,
    // else liveness-adjusted full zone stake) — the SAME value the live
    // `is_seal_settled` path divides by. Scoped so the std consensus mutex is
    // never held across an `.await`.
    let denominator = {
        state
            .consensus
            .lock_recover()
            .settlement_denominator_for_zone(&zone_id)
    };

    // Canonical chain tip for the burial walk. Scoped for the same lock-discipline
    // reason (std RwLock). A poisoned lock degrades to "no canonical chain" —
    // Leg-B then finds nothing, Leg-A is unaffected, and the marker simply waits.
    let tip_hash = match state.epoch.read() {
        Ok(g) => g.previous_seal_hash(&zone_id),
        Err(_) => [0u8; 32],
    };
    let canonical_prefix = build_canonical_prefix(state.rocks.as_ref(), tip_hash, epoch);

    // Plan the slot. The ledger read guard is held ONLY across the pure planner
    // call (which borrows the `staked` view) and the creator-exclusion min; it is
    // dropped before any write, so no lock crosses the apply `.await`s.
    let plan = {
        let ledger = state.ledger.read().await;
        // Exclude the seal creator's stake from the denominator: a creator cannot
        // self-attest, so their stake is unreachable and must not inflate it.
        // Re-derived from the DURABLE ledger (never the in-memory `creator_stakes`
        // map, which is empty on the boot sweep). The planner takes ONE denominator
        // for the slot; excluding the MINIMUM creator stake across rivals yields
        // the largest (hardest) denominator, so a wrong-creator guess can only make
        // the 2/3 bar harder — never over-finalize. In the common single-seal slot
        // it is the exact `is_seal_settled` value.
        let min_creator_stake = creator_hashes
            .iter()
            .map(|h| ledger.staked(h))
            .min()
            .unwrap_or(0);
        let eligible_stake = denominator.saturating_sub(min_creator_stake);
        rf::plan_marker_slot_sweep(
            &candidates,
            eligible_stake,
            |w| ledger.staked(w),
            &canonical_prefix,
            canonical_prefix.len() as u64,
            |k| state.rocks.get_rotation_newkey_index(k),
        )
    };

    // Apply: persist each planned entry, then discharge the marker ONLY if the
    // plan says to AND every write actually landed (a write failure keeps the
    // marker for the next tick, so nothing is silently lost).
    let mut all_written = true;
    for entry in &plan.entries {
        // W2-D canonicality-mismatch detection: a durable entry already exists for
        // this (lineage, hop) but under a DIFFERENT covering seal — the canonical
        // winner of the slot flipped between ticks (a Burial-evidence reorg, or a
        // W1-optimistic write that lost canonicality). The put below rewrites it to
        // the current canonical winner; count the flip. Cheap O(1) point lookup;
        // the common re-sweep of an un-flipped hop reads back the SAME
        // seal_record_id and does not count. A Quorum winner is BFT-unique per slot
        // so it should never legitimately flip — such a flip is a louder alarm and
        // is still counted here.
        if let Some(existing) = state
            .rocks
            .get_rotation_entry(&entry.lineage_id, entry.hop_index)
        {
            if existing.seal_record_id != entry.seal_record_id {
                state
                    .rotation_cf_canonicality_mismatch_total
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        match state.rocks.put_rotation_entry(entry) {
            Ok(()) => {
                state
                    .rotation_cf_write_sweep_total
                    .fetch_add(1, Ordering::Relaxed);
                // FIN-1 display parity: surface the rotation as finalized in the
                // API. Explicitly NOT the effect predicate — the CF entry is.
                state.finalized.write().await.insert(entry.record_id.clone());
                stats.entries_written += 1;
            }
            Err(e) => {
                warn!(
                    "W2 sweep rotation-CF write failed for {}: {e}",
                    &entry.record_id[..entry.record_id.len().min(16)]
                );
                state
                    .rotation_cf_write_failed_total
                    .fetch_add(1, Ordering::Relaxed);
                stats.write_failures += 1;
                all_written = false;
            }
        }
    }

    if plan.delete_marker && all_written {
        match state.rocks.delete_rotation_seal_marker(zone, epoch) {
            Ok(()) => stats.markers_discharged += 1,
            Err(e) => warn!("W2 sweep marker delete failed for {zone}:{epoch}: {e}"),
        }
    }
}

/// Build the zone's canonical chain seal-hash prefix, tip first, for Leg-B
/// ([`rotation_finality::leg_b_canonical_burial`]). Walks `previous_seal_hash`
/// backward from `tip_hash`, resolving each seal via the record-hash index, and
/// stops the moment it reaches (or passes) `marker_epoch` — below the marker's
/// epoch a canonical target at a HIGHER epoch cannot exist, so the walk is
/// bounded to `tip_epoch − marker_epoch` in the common case. [`MAX_CANONICAL_SEAL_WALK`]
/// is the hard SCALE ceiling for the degenerate off-canonical/orphan case.
///
/// Position in the returned vec IS the successor count (tip = 0), exactly as
/// Leg-B counts burial. A hash that resolves to no stored seal (or a non-seal
/// record) ends the walk — a broken link cannot be a valid canonical chain
/// beyond that point.
fn build_canonical_prefix(
    rocks: &StorageEngine,
    tip_hash: [u8; 32],
    marker_epoch: u64,
) -> Vec<[u8; 32]> {
    let mut prefix: Vec<[u8; 32]> = Vec::new();
    let mut cur = tip_hash;
    while cur != [0u8; 32] && (prefix.len() as u64) < MAX_CANONICAL_SEAL_WALK {
        prefix.push(cur);
        let Some(rid) = rocks.record_id_by_record_hash(&hex::encode(cur)) else {
            break;
        };
        let Ok(Some(rec)) = rocks.get_record(&rid) else {
            break;
        };
        let Ok(Some(parsed)) = crate::network::epoch::extract_epoch_seal(&rec) else {
            break;
        };
        // Reached the marker's slot depth — the target (if canonical) is already
        // in `prefix`; walking below it cannot find a higher-epoch canonical
        // target, so stop.
        if parsed.epoch_number <= marker_epoch {
            break;
        }
        cur = parsed.previous_seal_hash;
    }
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::sha3_256_hex;
    use crate::identity::{CryptoProfile, EntityType, Identity};
    use crate::network::config::NodeConfig;
    use crate::network::epoch::extract_epoch_seal;
    use crate::network::rotation_finality::FinalityEvidence;
    use crate::network::state::NodeState;
    use crate::network::time_bracket::DrandPulse;
    use crate::network::witness::WitnessManager;
    use crate::record::{Classification, ValidationRecord};
    use crate::storage::rocks::StorageEngine;
    use std::collections::BTreeMap;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// NodeState with `s2_rotation_ordering_enabled = flag_on`. Mirrors the W1
    /// drain tests' `rotation_state`.
    fn sweep_state(flag_on: bool) -> (Arc<NodeState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        let config = NodeConfig {
            data_dir: data_dir.clone(),
            identity_path: data_dir.join("identity.json"),
            db_path: data_dir.join("elara.db"),
            admin_token: "test-admin".into(),
            network_id: "kr3-s2-w2-test".into(),
            mdns_enabled: false,
            health_check_interval_secs: 0,
            min_pow_difficulty: 0,
            genesis_authority: sha3_256_hex(&key(0x01)),
            s2_rotation_ordering_enabled: flag_on,
            ..Default::default()
        };
        let identity = Identity::generate(EntityType::Device, CryptoProfile::ProfileB)
            .expect("generate identity");
        let rocks = Arc::new(StorageEngine::open(data_dir.join("rocksdb")).expect("open rocksdb"));
        let wmgr = Arc::new(WitnessManager::new(rocks.clone()));
        let state = Arc::new(NodeState::new(config, identity, rocks, wmgr));
        (state, tmp)
    }

    fn pulse(round: u64) -> DrandPulse {
        DrandPulse {
            round,
            randomness: "beef".into(),
            genesis_unix: 1,
            period_secs: 30,
            chain_hash: Some("cA".into()),
            signature: None,
            previous_signature: None,
        }
    }

    /// Store a key-rotation record (creator_pk = old key `old`, metadata new key
    /// `new`); return its id. Root-hop coordinate keyed `(sha3(old), 0)`.
    fn store_rotation(state: &Arc<NodeState>, old: &[u8], new: &[u8]) -> String {
        let rec = ValidationRecord::create(
            b"rot",
            old.to_vec(),
            vec![],
            Classification::Public,
            Some(crate::network::key_rotation::rotation_metadata(new, "periodic")),
        );
        state.rocks.put_record(&rec.id, &rec).expect("put rotation");
        rec.id
    }

    fn record_hash_of(state: &Arc<NodeState>, rid: &str) -> [u8; 32] {
        state
            .rocks
            .get_record(rid)
            .unwrap()
            .unwrap()
            .record_hash()
    }

    /// Build + store an epoch-seal record chaining onto `prev_seal`, optionally
    /// carrying a pulse and rotation member hashes. Returns `(seal_id, seal_hash)`.
    fn store_seal(
        state: &Arc<NodeState>,
        zone: &str,
        epoch: u64,
        prev_seal: [u8; 32],
        pulse: Option<&DrandPulse>,
        member_hashes: &[[u8; 32]],
    ) -> (String, [u8; 32]) {
        let mut m: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        m.insert("epoch_op".into(), serde_json::json!("seal"));
        m.insert("epoch_zone".into(), serde_json::json!(zone));
        m.insert("epoch_number".into(), serde_json::json!(epoch));
        m.insert("epoch_start".into(), serde_json::json!(1.0));
        m.insert("epoch_end".into(), serde_json::json!(2.0));
        m.insert(
            "epoch_record_count".into(),
            serde_json::json!(member_hashes.len() as u64),
        );
        // The R3-8 parse-time root gate (`extract_epoch_seal`, epoch.rs:2155)
        // DROPS the inline `epoch_record_hashes` enumeration to empty unless it
        // recomputes to this signed `epoch_merkle_root`. A bogus (e.g. zero) root
        // therefore yields `parsed.record_hashes == []`, so the sweep sees a seal
        // with no member hops and writes nothing. The helper must set the REAL
        // Merkle root of the members it enumerates — exactly as a producer does.
        // Empty members → empty-tree root; the gate is skipped when the inline
        // enumeration is absent, so the value is irrelevant there.
        m.insert(
            "epoch_merkle_root".into(),
            serde_json::json!(hex::encode(
                crate::network::sync::MerkleTree::root(member_hashes)
            )),
        );
        m.insert(
            "epoch_previous_seal".into(),
            serde_json::json!(hex::encode(prev_seal)),
        );
        if !member_hashes.is_empty() {
            let hs: Vec<String> = member_hashes.iter().map(hex::encode).collect();
            m.insert("epoch_record_hashes".into(), serde_json::json!(hs));
        }
        if let Some(p) = pulse {
            p.write_metadata(&mut m);
        }
        let rec = ValidationRecord::create(
            b"seal",
            key(0x55).to_vec(),
            vec![],
            Classification::Public,
            Some(m),
        );
        state.rocks.put_record(&rec.id, &rec).expect("put seal");
        // Mirror the production Phase-2 seal store: `put_record` writes the seal
        // payload and the record-hash reverse index, but NOT the CF_EPOCHS DISC-5
        // slot index (`epoch_be ‖ zone ‖ 0x00 ‖ rid`) — production writes that
        // separately (`epoch.rs:13926`, `put_record_with_pk_zone(.., Some(key))`).
        // It is the index `seal_record_ids_at_zone_epoch` scans to build the W2
        // rival set, so without it every marker slot reads as orphaned and the
        // sweep never sees a candidate. Empty value: the reader parses the rid out
        // of the key. `zone` here equals the seal's `zone.path()` (the marker is
        // armed with the same literal), so the key lines up with the reader prefix.
        let disc5_key = crate::network::epoch::disc5_index_key(epoch, zone, &rec.id);
        state
            .rocks
            .put_cf_raw(crate::storage::rocks::CF_EPOCHS, &disc5_key, &[])
            .expect("put seal CF_EPOCHS DISC-5 index");
        let h = rec.record_hash();
        (rec.id, h)
    }

    /// Set the zone's canonical tip so the burial walk can reach it.
    fn set_tip(state: &Arc<NodeState>, seal_id: &str, tip_hash: [u8; 32]) {
        let zone = extract_epoch_seal(&state.rocks.get_record(seal_id).unwrap().unwrap())
            .unwrap()
            .unwrap()
            .zone;
        state
            .epoch
            .write()
            .unwrap()
            .latest_seal_hash
            .insert(zone, tip_hash);
    }

    /// Register zone stake + seed staked witness accounts + store their durable
    /// `att:` rows on the seal — enough for a Leg-A quorum recount.
    async fn seed_quorum(state: &Arc<NodeState>, seal_id: &str, witnesses: &[(&str, u64)], denom: u64) {
        let zone = extract_epoch_seal(&state.rocks.get_record(seal_id).unwrap().unwrap())
            .unwrap()
            .unwrap()
            .zone;
        state.consensus.lock_recover().register_zone_stake(zone, denom);
        {
            let mut ledger = state.ledger.write().await;
            for (w, s) in witnesses {
                ledger.accounts.entry((*w).into()).or_default().staked = *s;
            }
        }
        for (w, _) in witnesses {
            state
                .witness_mgr
                .store_attestation(seal_id, w, b"sig", 1.0, None)
                .unwrap();
        }
    }

    /// FLAG OFF ⇒ the sweep is a byte-identical no-op even with a fully armed,
    /// finalizable slot present: nothing scanned, nothing written, marker kept.
    #[tokio::test]
    async fn sweep_flag_off_is_byte_identical_noop() {
        let (state, _t) = sweep_state(false);
        let rot = store_rotation(&state, &key(0x10), &key(0x11));
        let rh = record_hash_of(&state, &rot);
        let _ = store_seal(&state, "default", 5, [0; 32], Some(&pulse(100)), &[rh]);
        state.rocks.arm_rotation_seal_marker_for_test("default", 5).unwrap();

        let stats = run_rotation_marker_sweep(&state).await;

        assert_eq!(stats, RotationSweepStats::default(), "flag OFF → no-op");
        assert!(state.rocks.get_rotation_entry(&sha3_256_hex(&key(0x10)), 0).is_none());
        assert_eq!(state.rotation_cf_write_sweep_total.load(Ordering::Relaxed), 0);
        assert_eq!(
            state.rocks.scan_rotation_seal_markers(),
            vec![("default".to_string(), 5)],
            "marker untouched while flag OFF"
        );
    }

    /// An armed marker whose slot holds no stored seal is orphaned — kept, never
    /// written.
    #[tokio::test]
    async fn sweep_orphan_marker_is_kept_without_write() {
        let (state, _t) = sweep_state(true);
        state.rocks.arm_rotation_seal_marker_for_test("default", 9).unwrap();

        let stats = run_rotation_marker_sweep(&state).await;

        assert_eq!(stats.markers_scanned, 1);
        assert_eq!(stats.orphan_markers, 1);
        assert_eq!(stats.entries_written, 0);
        assert_eq!(stats.markers_discharged, 0);
        assert_eq!(
            state.rocks.scan_rotation_seal_markers(),
            vec![("default".to_string(), 9)],
            "orphan marker kept"
        );
    }

    /// Leg-B burial path: the covering seal sits on the canonical chain with two
    /// successors → buried → the sweep writes the CF entry (evidence=Burial),
    /// coordinate taken from the seal, and discharges the marker. No stake or
    /// attestations needed — this is the boot-replay backstop (no W1 involvement).
    #[tokio::test]
    async fn sweep_burial_winner_writes_entry_and_discharges_marker() {
        let (state, _t) = sweep_state(true);
        let (old, new) = (key(0x20), key(0x21));
        let rot = store_rotation(&state, &old, &new);
        let rh = record_hash_of(&state, &rot);
        // Target seal @5 with the rotation as a member; two canonical successors.
        let (tgt_id, tgt_hash) = store_seal(&state, "default", 5, [0; 32], Some(&pulse(200)), &[rh]);
        let (_s1, s1_hash) = store_seal(&state, "default", 6, tgt_hash, Some(&pulse(201)), &[]);
        let (_s2, s2_hash) = store_seal(&state, "default", 7, s1_hash, Some(&pulse(202)), &[]);
        set_tip(&state, &tgt_id, s2_hash);
        state.rocks.arm_rotation_seal_marker_for_test("default", 5).unwrap();

        let stats = run_rotation_marker_sweep(&state).await;

        let lineage = format!("d:{}", sha3_256_hex(&old));
        let entry = state
            .rocks
            .get_rotation_entry(&lineage, 0)
            .expect("sweep wrote the CF entry via canonical burial");
        assert_eq!(entry.evidence, FinalityEvidence::Burial);
        assert_eq!(entry.record_id, rot);
        assert_eq!(entry.new_key_hash, sha3_256_hex(&new));
        // Coordinate assigned by the covering seal (@5, round 200), never the record.
        assert_eq!(entry.coord.epoch, 5);
        assert_eq!(entry.coord.round, 200);
        assert_eq!(entry.coord.chain_hash, "cA");

        assert_eq!(stats.entries_written, 1);
        assert_eq!(stats.markers_discharged, 1);
        assert_eq!(state.rotation_cf_write_sweep_total.load(Ordering::Relaxed), 1);
        assert!(state.finalized.read().await.contains(&rot), "FIN-1 display parity");
        assert!(
            state.rocks.scan_rotation_seal_markers().is_empty(),
            "marker discharged once buried"
        );
    }

    /// Leg-A quorum path: durable `att:` rows + staked witnesses cross 2/3 → the
    /// sweep writes the CF entry (evidence=Quorum) with no canonical burial. Proves
    /// the attestation + stake + denominator gather wiring end-to-end.
    #[tokio::test]
    async fn sweep_quorum_winner_writes_entry_via_leg_a() {
        let (state, _t) = sweep_state(true);
        let (old, new) = (key(0x30), key(0x31));
        let rot = store_rotation(&state, &old, &new);
        let rh = record_hash_of(&state, &rot);
        let (seal_id, _h) = store_seal(&state, "default", 5, [0; 32], Some(&pulse(300)), &[rh]);
        // Denominator 300; two witnesses staked 100 each → 200*3 >= 300*2.
        seed_quorum(&state, &seal_id, &[("wit-a", 100), ("wit-b", 100)], 300).await;
        state.rocks.arm_rotation_seal_marker_for_test("default", 5).unwrap();

        let stats = run_rotation_marker_sweep(&state).await;

        let entry = state
            .rocks
            .get_rotation_entry(&format!("d:{}", sha3_256_hex(&old)), 0)
            .expect("quorum recount → CF entry");
        assert_eq!(entry.evidence, FinalityEvidence::Quorum);
        assert_eq!(entry.record_id, rot);
        assert_eq!(stats.entries_written, 1);
        assert_eq!(stats.markers_discharged, 1);
        assert!(state.rocks.scan_rotation_seal_markers().is_empty());
    }

    /// A seal with a witness stake just under 2/3 and no canonical burial is NOT
    /// final → the sweep writes nothing and keeps the marker (the load-bearing
    /// "never over-finalize" property).
    #[tokio::test]
    async fn sweep_sub_quorum_not_final_keeps_marker() {
        let (state, _t) = sweep_state(true);
        let (old, new) = (key(0x50), key(0x51));
        let rot = store_rotation(&state, &old, &new);
        let rh = record_hash_of(&state, &rot);
        let (seal_id, _h) = store_seal(&state, "default", 5, [0; 32], Some(&pulse(400)), &[rh]);
        // 100/300 stake attesting = 33% → 100*3 < 300*2. No tip set → no burial.
        seed_quorum(&state, &seal_id, &[("wit-a", 100)], 300).await;
        let _ = new;
        state.rocks.arm_rotation_seal_marker_for_test("default", 5).unwrap();

        let stats = run_rotation_marker_sweep(&state).await;

        assert_eq!(stats.entries_written, 0);
        assert_eq!(stats.markers_discharged, 0);
        assert!(state.rocks.get_rotation_entry(&sha3_256_hex(&old), 0).is_none());
        assert_eq!(
            state.rocks.scan_rotation_seal_markers(),
            vec![("default".to_string(), 5)],
            "sub-quorum → marker kept"
        );
    }

    /// A covering seal with NO pulse is skipped as a candidate → the slot yields
    /// no coordinate-eligible seal → marker kept, nothing written (§4 fail-closed).
    #[tokio::test]
    async fn sweep_pulseless_seal_keeps_marker() {
        let (state, _t) = sweep_state(true);
        let (old, new) = (key(0x40), key(0x41));
        let rot = store_rotation(&state, &old, &new);
        let rh = record_hash_of(&state, &rot);
        let _ = new;
        let _ = store_seal(&state, "default", 5, [0; 32], None, &[rh]);
        state.rocks.arm_rotation_seal_marker_for_test("default", 5).unwrap();

        let stats = run_rotation_marker_sweep(&state).await;

        assert_eq!(stats.markers_scanned, 1);
        assert_eq!(stats.orphan_markers, 0, "a seal is stored — not orphaned, just pulse-less");
        assert_eq!(stats.entries_written, 0);
        assert_eq!(stats.markers_discharged, 0);
        assert!(state.rocks.get_rotation_entry(&sha3_256_hex(&old), 0).is_none());
        assert_eq!(
            state.rocks.scan_rotation_seal_markers(),
            vec![("default".to_string(), 5)],
            "pulse-less seal → marker kept"
        );
    }

    /// Same-slot lineage self-heal across two ticks (§9 convergence): two hops of
    /// ONE lineage in one quorum seal. Tick 1 writes only the root hop and keeps
    /// the marker (the dependent hop's predecessor isn't durable yet); tick 2 finds
    /// the predecessor in the durable index, writes the dependent hop, and
    /// discharges the marker. No spurious-root entry is ever persisted.
    #[tokio::test]
    async fn sweep_same_lineage_defers_then_converges_over_two_ticks() {
        let (state, _t) = sweep_state(true);
        let (k0, k1, k2) = (key(0x60), key(0x61), key(0x62));
        let rot1 = store_rotation(&state, &k0, &k1);
        let rot2 = store_rotation(&state, &k1, &k2);
        let h1 = record_hash_of(&state, &rot1);
        let h2 = record_hash_of(&state, &rot2);
        let (seal_id, _h) = store_seal(&state, "default", 5, [0; 32], Some(&pulse(500)), &[h1, h2]);
        seed_quorum(&state, &seal_id, &[("wq", 300)], 300).await;
        state.rocks.arm_rotation_seal_marker_for_test("default", 5).unwrap();

        // Tick 1: root hop only; dependent hop deferred, marker kept.
        let s1 = run_rotation_marker_sweep(&state).await;
        assert_eq!(s1.entries_written, 1, "tick 1 writes the root hop only");
        assert_eq!(s1.markers_discharged, 0, "dependent hop deferred → marker kept");
        assert!(
            state.rocks.get_rotation_entry(&format!("d:{}", sha3_256_hex(&k0)), 0).is_some(),
            "root hop (k0->k1) written"
        );

        // Tick 2: predecessor now durable → dependent hop writes; marker discharged.
        let s2 = run_rotation_marker_sweep(&state).await;
        assert_eq!(s2.markers_discharged, 1, "marker discharged after both hops written");
        // The dependent hop chains at index 1 under the same lineage root.
        let dependent = state
            .rocks
            .get_rotation_entry(&format!("d:{}", sha3_256_hex(&k0)), 1)
            .expect("dependent hop (k1->k2) written on tick 2");
        assert_eq!(dependent.new_key_hash, sha3_256_hex(&k2));
        assert_eq!(dependent.record_id, rot2);
        assert!(state.rocks.scan_rotation_seal_markers().is_empty());
    }

    /// §9 boot-replay corner (the 2nd named-race test): a rotation reaches
    /// consensus-Finalized during boot via `recompute_confirmation(
    /// suppress_events=true)`, so `enqueue_finalized` never fires and the W1
    /// drain hook writes NOTHING — yet the durable `rotation_seal_pending`
    /// marker armed at the original seal ingest survived the crash/boot. The W2
    /// sweep is the sole backstop: it must backfill the rotation-CF entry from
    /// durable evidence alone.
    ///
    /// This case is exercised with ZERO in-memory consensus state (no
    /// `register_zone_stake`, no attestation map) — exactly the fresh-boot
    /// condition where the sweep's first (immediate) periodic tick can run
    /// before the async consensus stake-rebuild completes. Leg-B canonical
    /// burial needs no stake, so the backstop still finalizes; a quorum-only
    /// seal would instead defer (zero denominator → not-final) and self-heal on
    /// a later tick. Proves the boot sweep is W1-independent AND safe pre-rebuild.
    #[tokio::test]
    async fn sweep_boot_replay_corner_backfills_before_stake_rebuild() {
        let (state, _t) = sweep_state(true);
        let (old, new) = (key(0x70), key(0x71));
        let rot = store_rotation(&state, &old, &new);
        let rh = record_hash_of(&state, &rot);
        // Covering seal @5 with two canonical successors → buried (Leg-B).
        let (tgt_id, tgt_hash) = store_seal(&state, "default", 5, [0; 32], Some(&pulse(700)), &[rh]);
        let (_s1, s1_hash) = store_seal(&state, "default", 6, tgt_hash, Some(&pulse(701)), &[]);
        let (_s2, s2_hash) = store_seal(&state, "default", 7, s1_hash, Some(&pulse(702)), &[]);
        set_tip(&state, &tgt_id, s2_hash);
        // The durable marker survived boot; W1 never ran (enqueue-miss) so no
        // CF entry exists yet — the sweep is the only path that can finalize it.
        state.rocks.arm_rotation_seal_marker_for_test("default", 5).unwrap();
        let lineage = format!("d:{}", sha3_256_hex(&old));
        assert!(
            state.rocks.get_rotation_entry(&lineage, 0).is_none(),
            "precondition: W1 wrote nothing (boot-replay enqueue-miss)"
        );

        // First boot sweep — NO consensus stake registered (pre-rebuild).
        let stats = run_rotation_marker_sweep(&state).await;

        let entry = state
            .rocks
            .get_rotation_entry(&lineage, 0)
            .expect("boot sweep backfilled the W1-missed rotation via Leg-B burial");
        assert_eq!(entry.evidence, FinalityEvidence::Burial);
        assert_eq!(entry.record_id, rot);
        assert_eq!(entry.coord.epoch, 5, "coordinate from the covering seal, not the record");
        assert_eq!(stats.entries_written, 1);
        assert_eq!(stats.markers_discharged, 1);
        assert!(state.finalized.read().await.contains(&rot), "FIN-1 display parity");
        assert!(
            state.rocks.scan_rotation_seal_markers().is_empty(),
            "marker discharged once the boot backstop finalized the hop"
        );
    }

    /// §9 boot-safety self-heal for the QUORUM path — the Leg-A analog of the
    /// burial boot test above, and the direct defence of the W2-C wiring's
    /// "quorum-only cases self-heal on a later tick once the rebuild lands"
    /// claim (state_core.rs). Durable evidence — the `att:` rows and the
    /// witnesses' ledger stake — survives a crash, but the consensus
    /// `zone_stakes` denominator is rebuilt from the ledger only at boot
    /// (`register_stakes_from_ledger`, elara_node.rs:1507, which runs BEFORE
    /// `spawn_state_core`). Should the sweep's immediate first tick ever run
    /// before that registration, the denominator is 0 →
    /// `two_thirds_stake_met` returns false → Leg-A defers and the marker is
    /// KEPT (never over-finalized against a zero denominator). No canonical
    /// tip is set, so Leg-B burial is unavailable and Leg-A is the SOLE
    /// finalization path — isolating the denominator dependence. Once the
    /// rebuild lands, the next tick meets quorum and writes.
    #[tokio::test]
    async fn sweep_quorum_zero_denominator_defers_then_heals_after_rebuild() {
        let (state, _t) = sweep_state(true);
        let (old, new) = (key(0x80), key(0x81));
        let rot = store_rotation(&state, &old, &new);
        let rh = record_hash_of(&state, &rot);
        let (seal_id, _h) = store_seal(&state, "default", 5, [0; 32], Some(&pulse(800)), &[rh]);

        // Durable evidence that survived the crash: the witnesses' ledger stake
        // and their `att:` rows on the seal. Deliberately NOT `seed_quorum` — we
        // withhold `register_zone_stake` so the consensus denominator is still 0
        // (the pre-boot-registration state). No `set_tip` → no Leg-B burial.
        {
            let mut ledger = state.ledger.write().await;
            ledger.accounts.entry("wit-a".into()).or_default().staked = 100;
            ledger.accounts.entry("wit-b".into()).or_default().staked = 100;
        }
        state.witness_mgr.store_attestation(&seal_id, "wit-a", b"sig", 1.0, None).unwrap();
        state.witness_mgr.store_attestation(&seal_id, "wit-b", b"sig", 1.0, None).unwrap();
        state.rocks.arm_rotation_seal_marker_for_test("default", 5).unwrap();

        // Tick 1 — denominator 0 (rebuild has not run): Leg-A cannot settle
        // (`eligible_stake == 0`), Leg-B has no tip → defer, marker kept.
        let s1 = run_rotation_marker_sweep(&state).await;
        assert_eq!(s1.entries_written, 0, "zero denominator → quorum unmeetable → defer");
        assert_eq!(s1.markers_discharged, 0);
        assert!(state.rocks.get_rotation_entry(&format!("d:{}", sha3_256_hex(&old)), 0).is_none());
        assert_eq!(
            state.rocks.scan_rotation_seal_markers(),
            vec![("default".to_string(), 5)],
            "marker kept — never over-finalized against a zero denominator",
        );

        // The consensus stake rebuild lands (elara_node.rs:1507
        // `register_stakes_from_ledger`), populating the zone denominator.
        let zone = extract_epoch_seal(&state.rocks.get_record(&seal_id).unwrap().unwrap())
            .unwrap()
            .unwrap()
            .zone;
        state.consensus.lock_recover().register_zone_stake(zone, 300);

        // Tick 2 — denominator 300, attesting 200 → 200*3 >= 300*2 → quorum →
        // write + discharge. The catch-up self-healed with no lost entry.
        let s2 = run_rotation_marker_sweep(&state).await;
        assert_eq!(s2.entries_written, 1, "post-rebuild quorum → CF entry written");
        assert_eq!(s2.markers_discharged, 1);
        let entry = state
            .rocks
            .get_rotation_entry(&format!("d:{}", sha3_256_hex(&old)), 0)
            .expect("self-healed via Leg-A quorum after the denominator rebuild");
        assert_eq!(entry.evidence, FinalityEvidence::Quorum);
        assert_eq!(entry.record_id, rot);
        assert!(state.rocks.scan_rotation_seal_markers().is_empty());
        let _ = new;
    }

    /// W2-D observability: flag OFF ⇒ NONE of the new W2-D metrics move (the sweep
    /// early-returns before folding them in). Extends the flag-OFF byte-identical
    /// no-op guarantee to the observability surface.
    #[tokio::test]
    async fn sweep_flag_off_leaves_w2d_metrics_zero() {
        let (state, _t) = sweep_state(false);
        let rot = store_rotation(&state, &key(0x10), &key(0x11));
        let rh = record_hash_of(&state, &rot);
        let _ = store_seal(&state, "default", 5, [0; 32], Some(&pulse(100)), &[rh]);
        state.rocks.arm_rotation_seal_marker_for_test("default", 5).unwrap();

        let _ = run_rotation_marker_sweep(&state).await;

        assert_eq!(state.rotation_sweep_runs_total.load(Ordering::Relaxed), 0);
        assert_eq!(state.rotation_sweep_markers_scanned_total.load(Ordering::Relaxed), 0);
        assert_eq!(state.rotation_sweep_markers_discharged_total.load(Ordering::Relaxed), 0);
        assert_eq!(state.rotation_sweep_orphan_markers_total.load(Ordering::Relaxed), 0);
        assert_eq!(state.rotation_sweep_pending_markers.load(Ordering::Relaxed), 0);
        assert_eq!(state.rotation_cf_canonicality_mismatch_total.load(Ordering::Relaxed), 0);
    }

    /// W2-D observability: a discharging burial run folds its per-invocation stats
    /// into the cumulative metrics; a SECOND run over the (now empty) marker set
    /// still bumps the runs heartbeat but leaves scanned/discharged flat and the
    /// pending gauge at 0.
    #[tokio::test]
    async fn sweep_run_folds_observability_counters() {
        let (state, _t) = sweep_state(true);
        let (old, new) = (key(0x60), key(0x61));
        let rot = store_rotation(&state, &old, &new);
        let rh = record_hash_of(&state, &rot);
        let (tgt_id, tgt_hash) = store_seal(&state, "default", 5, [0; 32], Some(&pulse(200)), &[rh]);
        let (_s1, s1_hash) = store_seal(&state, "default", 6, tgt_hash, Some(&pulse(201)), &[]);
        let (_s2, s2_hash) = store_seal(&state, "default", 7, s1_hash, Some(&pulse(202)), &[]);
        set_tip(&state, &tgt_id, s2_hash);
        state.rocks.arm_rotation_seal_marker_for_test("default", 5).unwrap();
        let _ = rot;

        let _ = run_rotation_marker_sweep(&state).await;

        assert_eq!(state.rotation_sweep_runs_total.load(Ordering::Relaxed), 1);
        assert_eq!(state.rotation_sweep_markers_scanned_total.load(Ordering::Relaxed), 1);
        assert_eq!(state.rotation_sweep_markers_discharged_total.load(Ordering::Relaxed), 1);
        assert_eq!(state.rotation_sweep_orphan_markers_total.load(Ordering::Relaxed), 0);
        // scanned 1 − discharged 1 → pending gauge 0.
        assert_eq!(state.rotation_sweep_pending_markers.load(Ordering::Relaxed), 0);

        // Second run: marker already discharged, nothing to scan, but the runs
        // heartbeat still advances (liveness even on an empty sweep).
        let _ = run_rotation_marker_sweep(&state).await;
        assert_eq!(state.rotation_sweep_runs_total.load(Ordering::Relaxed), 2);
        assert_eq!(state.rotation_sweep_markers_scanned_total.load(Ordering::Relaxed), 1);
        assert_eq!(state.rotation_sweep_markers_discharged_total.load(Ordering::Relaxed), 1);
        assert_eq!(state.rotation_sweep_pending_markers.load(Ordering::Relaxed), 0);
    }

    /// W2-D observability: an orphan marker (armed slot, no stored seal) folds into
    /// the orphan counter and holds the pending gauge at 1 (scanned, never
    /// discharged) — the "armed without its seal landing" alarm surface.
    #[tokio::test]
    async fn sweep_orphan_marker_folds_pending_gauge() {
        let (state, _t) = sweep_state(true);
        state.rocks.arm_rotation_seal_marker_for_test("default", 9).unwrap();

        let _ = run_rotation_marker_sweep(&state).await;

        assert_eq!(state.rotation_sweep_runs_total.load(Ordering::Relaxed), 1);
        assert_eq!(state.rotation_sweep_markers_scanned_total.load(Ordering::Relaxed), 1);
        assert_eq!(state.rotation_sweep_orphan_markers_total.load(Ordering::Relaxed), 1);
        assert_eq!(state.rotation_sweep_markers_discharged_total.load(Ordering::Relaxed), 0);
        // scanned 1 − discharged 0 → still pending.
        assert_eq!(state.rotation_sweep_pending_markers.load(Ordering::Relaxed), 1);
        assert_eq!(state.rotation_cf_canonicality_mismatch_total.load(Ordering::Relaxed), 0);
    }

    /// W2-D canonicality-mismatch: re-sweeping a slot whose canonical winner is
    /// UNCHANGED never bumps the counter (same seal_record_id read back); a reorg
    /// that moves the canonical chain to a rival seal at the same (zone, epoch)
    /// rewrites the entry under the new seal and bumps the counter exactly once.
    #[tokio::test]
    async fn sweep_canonicality_mismatch_only_on_seal_flip() {
        let (state, _t) = sweep_state(true);
        let (old, new) = (key(0x70), key(0x71));
        let rot = store_rotation(&state, &old, &new);
        let rh = record_hash_of(&state, &rot);
        let lineage = format!("d:{}", sha3_256_hex(&old));
        let _ = new;

        // Chain A: seal @5 (member rot) buried under two successors → canonical.
        let (a_id, a_hash) = store_seal(&state, "default", 5, [0; 32], Some(&pulse(500)), &[rh]);
        let (_a1, a1_hash) = store_seal(&state, "default", 6, a_hash, Some(&pulse(501)), &[]);
        let (_a2, a2_hash) = store_seal(&state, "default", 7, a1_hash, Some(&pulse(502)), &[]);
        set_tip(&state, &a_id, a2_hash);
        state.rocks.arm_rotation_seal_marker_for_test("default", 5).unwrap();

        // Tick 1: first write, no prior entry → no mismatch.
        let _ = run_rotation_marker_sweep(&state).await;
        let e1 = state.rocks.get_rotation_entry(&lineage, 0).expect("entry under A");
        assert_eq!(e1.seal_record_id, a_id);
        assert_eq!(state.rotation_cf_canonicality_mismatch_total.load(Ordering::Relaxed), 0);

        // Re-sweep with A still canonical → same seal read back → no spurious count.
        state.rocks.arm_rotation_seal_marker_for_test("default", 5).unwrap();
        let _ = run_rotation_marker_sweep(&state).await;
        assert_eq!(
            state.rotation_cf_canonicality_mismatch_total.load(Ordering::Relaxed),
            0,
            "unchanged re-sweep must not count a mismatch"
        );

        // Reorg: rival chain B at the SAME (default, 5) slot (member rot), buried
        // under its own two successors; move the tip to B → A is now off-canonical.
        let (b_id, b_hash) = store_seal(&state, "default", 5, [0; 32], Some(&pulse(600)), &[rh]);
        let (_b1, b1_hash) = store_seal(&state, "default", 6, b_hash, Some(&pulse(601)), &[]);
        let (_b2, b2_hash) = store_seal(&state, "default", 7, b1_hash, Some(&pulse(602)), &[]);
        set_tip(&state, &b_id, b2_hash);
        state.rocks.arm_rotation_seal_marker_for_test("default", 5).unwrap();

        // Tick 2: canonical winner flipped A→B → entry rewritten under B, mismatch++.
        let _ = run_rotation_marker_sweep(&state).await;
        let e2 = state.rocks.get_rotation_entry(&lineage, 0).expect("entry rewritten under B");
        assert_ne!(a_id, b_id);
        assert_eq!(e2.seal_record_id, b_id, "seal_record_id corrected to the new canonical seal");
        assert_eq!(e2.coord.round, 600, "coordinate follows the new canonical seal's pulse");
        assert_eq!(
            state.rotation_cf_canonicality_mismatch_total.load(Ordering::Relaxed),
            1,
            "exactly one canonicality flip counted"
        );
    }
}
