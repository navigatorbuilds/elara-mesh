//! Gap 4: Zone auto-scaling — node-side orchestration.
//!
//! The pure decision engine — constants, [`ScalingDecision`], [`AutoScaler`],
//! [`recommend_zone_count`], [`pick_transition_target`], [`TransitionTarget`] —
//! lives in the standalone `elara-zone-autoscaler` crate (MIT/Apache) and is
//! re-exported here so existing `crate::network::auto_scale::*` paths keep
//! resolving. This module keeps [`propose_transition_from_decision`], which is
//! node-coupled: it reads live state via `StorageEngine`, draws the per-zone
//! committee via the VRF path, and signs a [`TransitionSeal`] with the local
//! [`Identity`].
//!
//! [`TransitionSeal`]: crate::network::zone_transition_seal::TransitionSeal
//! [`Identity`]: crate::identity::Identity
//!
//! Decision → emit `zone_transition` announcement record (handled by
//! `epoch::zone_transition_metadata`, signed by genesis authority). The
//! transition takes effect at `target_epoch` when all nodes flip `ZONE_COUNT`
//! atomically. Records created at or after target_epoch route via
//! `for_record_dynamic(_, new)`; older records stay pinned to their original
//! zone (their seals don't change retroactively).
//!
//! @spec Protocol §7.5 (zone model), §11.12 (scale mandate).

use std::collections::HashMap;

// Pure decision engine extracted to the standalone `elara-zone-autoscaler`
// crate (MIT/Apache). Re-exported so existing `crate::network::auto_scale::*`
// paths keep resolving. The crate is generic over the zone-id type; the node
// always uses it with `ZoneId`.
pub use elara_zone_autoscaler::*;

use crate::network::zone::ZoneId;

/// Compose the per-zone primitives into a signed, ready-to-store
/// [`TransitionSeal`] from a scaling decision.
///
/// Pipeline:
/// 1. Narrow the global [`ScalingDecision`] to a concrete
///    [`TransitionTarget`] via [`pick_transition_target`].
/// 2. Read live state for the parent zone(s) via `build_zone_snapshot`.
/// 3. Derive deterministic child zone_ids:
///    - Split `X` → children `X/L`, `X/R`, split at
///      [`SPLIT_KEY_MIDPOINT`].
///    - Merge `(A, B)` with `A ≤ B` lex → child named
///      `format!("{A}+{B}")`. Lex-sorting the parents before naming
///      guarantees two honest anchors compute the same child name.
/// 4. Build the seal with `proposed_at_epoch = current_epoch`,
///    `effective_epoch = current_epoch + TRANSITION_DISPUTE_WINDOW_EPOCHS`.
/// 5. Sign as the local anchor via
///    [`super::zone_transition_seal::TransitionSeal::sign_as_anchor`] —
///    gives the seal 1-of-N sigs; the remaining M-1 come over gossip.
///
/// Returns `Ok(None)` on NoChange decisions or when the target cannot
/// be picked (empty activity map / merge with <2 zones). Any other
/// failure — storage read, snapshot build, structural validate, sign —
/// propagates as `Err`.
///
/// Committee hashes are computed from `candidates` using the same
/// stake-weighted VRF draw as the live committee selection path. Parent
/// zone snapshots carry the committee that was sealing the zone at
/// `current_epoch`; child zones get a freshly-drawn committee for the
/// same epoch. All-zeros if `candidates` is empty (no staked anchors).
pub fn propose_transition_from_decision(
    storage: &crate::storage::rocks::StorageEngine,
    identity: &crate::identity::Identity,
    decision: &ScalingDecision,
    per_zone_activity: &HashMap<ZoneId, f64>,
    current_epoch: u64,
    candidates: &[super::zone_committee::Candidate],
    committee_size: usize,
) -> crate::errors::Result<Option<crate::network::zone_transition_seal::TransitionSeal>> {
    use crate::network::zone_committee::{committee_hash_from_members, select_zone_committee};
    use crate::network::zone_transition_seal::{
        build_zone_snapshot, newborn_child_snapshot, TransitionKind, TransitionSeal,
        TRANSITION_DISPUTE_WINDOW_EPOCHS,
    };

    let Some(target) = pick_transition_target(decision, per_zone_activity) else {
        return Ok(None);
    };

    let effective_epoch = current_epoch.saturating_add(TRANSITION_DISPUTE_WINDOW_EPOCHS);

    // Compute committee_hash for a zone: select members via VRF, then hash.
    let zone_committee_hash = |zone: &ZoneId| -> [u8; 32] {
        let members = select_zone_committee(zone.path(), current_epoch, candidates, committee_size);
        if members.is_empty() {
            tracing::warn!(
                "propose_transition: no staked anchors for zone {} at epoch {} — committee_hash=zeros",
                zone.path(), current_epoch
            );
        }
        committee_hash_from_members(&members, current_epoch)
    };

    let mut seal = match target {
        TransitionTarget::Split { parent } => {
            let parent_ch = zone_committee_hash(&parent);
            let parent_snap = build_zone_snapshot(storage, parent.clone(), parent_ch)?;
            let left_zone = ZoneId::new(&format!("{}/L", parent.path()));
            let right_zone = ZoneId::new(&format!("{}/R", parent.path()));
            let left_ch = zone_committee_hash(&left_zone);
            let right_ch = zone_committee_hash(&right_zone);
            let left = newborn_child_snapshot(left_zone, left_ch);
            let right = newborn_child_snapshot(right_zone, right_ch);
            TransitionSeal {
                kind: TransitionKind::Split,
                effective_epoch,
                proposed_at_epoch: current_epoch,
                parents: vec![parent_snap],
                children: vec![left, right],
                split_key: Some(SPLIT_KEY_MIDPOINT),
                proposer_sigs: vec![],
            }
        }
        TransitionTarget::Merge { a, b } => {
            // pick_transition_target already emits (a, b) lex-sorted, but
            // re-assert locally so the child-name derivation is obviously
            // deterministic at this site.
            debug_assert!(a <= b, "pick_transition_target must return lex-sorted pair");
            let a_ch = zone_committee_hash(&a);
            let b_ch = zone_committee_hash(&b);
            let a_snap = build_zone_snapshot(storage, a.clone(), a_ch)?;
            let b_snap = build_zone_snapshot(storage, b.clone(), b_ch)?;
            let child_zone = ZoneId::new(&format!("{}+{}", a.path(), b.path()));
            let child_ch = zone_committee_hash(&child_zone);
            let child = newborn_child_snapshot(child_zone, child_ch);
            TransitionSeal {
                kind: TransitionKind::Merge,
                effective_epoch,
                proposed_at_epoch: current_epoch,
                parents: vec![a_snap, b_snap],
                children: vec![child],
                split_key: None,
                proposer_sigs: vec![],
            }
        }
    };

    // Validate before signing so we fail fast on any structural error
    // (would be caught by the store's insert path later, but catching it
    // here keeps the local orchestrator honest).
    seal.validate_structure()?;
    seal.sign_as_anchor(identity)?;

    Ok(Some(seal))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Epoch constants live in the node; the autoscaler crate bakes
    // TARGET_ZONE_RATE. The drift-guard test below pins them together.
    use crate::network::epoch::{MIN_ADAPTIVE_EPOCH_SECS, TARGET_RECORDS_PER_EPOCH};

    fn zid(n: u64) -> ZoneId {
        ZoneId::from_legacy(n)
    }

    fn activity(entries: &[(u64, f64)]) -> HashMap<ZoneId, f64> {
        entries.iter().map(|(z, r)| (zid(*z), *r)).collect()
    }

    // ── drift guard ─────────────────────────────────────────────────
    //
    // `elara_zone_autoscaler::TARGET_ZONE_RATE` is baked at 20.0 to keep the
    // crate dependency-free. This pins it to the node's source-of-truth epoch
    // constants so a future retune of either constant fails the build instead
    // of silently desyncing the autoscaler band from the actual seal cadence.
    #[test]
    fn target_zone_rate_matches_node_epoch_constants() {
        let expected = TARGET_RECORDS_PER_EPOCH / MIN_ADAPTIVE_EPOCH_SECS;
        assert!(
            (TARGET_ZONE_RATE - expected).abs() < f64::EPSILON,
            "elara_zone_autoscaler::TARGET_ZONE_RATE ({TARGET_ZONE_RATE}) drifted from \
             node TARGET_RECORDS_PER_EPOCH / MIN_ADAPTIVE_EPOCH_SECS ({expected}) — \
             rebake the crate constant or reconcile the epoch constants",
        );
        const _: () = assert!(TARGET_ZONE_RATE > 0.0, "TARGET_ZONE_RATE MUST be positive");
    }

    // ── propose_transition_from_decision ────────────────────────────

    fn tmp_storage() -> (crate::storage::rocks::StorageEngine, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let eng = crate::storage::rocks::StorageEngine::open(dir.path()).expect("open");
        (eng, dir)
    }

    fn test_identity() -> crate::identity::Identity {
        crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        )
        .expect("identity")
    }

    #[test]
    fn propose_nochange_returns_none() {
        let (storage, _dir) = tmp_storage();
        let id = test_identity();
        let act = activity(&[(0, 1.0)]);
        let dec = ScalingDecision::NoChange {
            avg_rate: 1.0,
            reason: ScalingReason::Balanced,
        };
        let out = propose_transition_from_decision(&storage, &id, &dec, &act, 100, &[], crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn propose_split_builds_signed_seal() {
        use crate::network::zone_transition_seal::{TransitionKind, TRANSITION_DISPUTE_WINDOW_EPOCHS};

        let (storage, _dir) = tmp_storage();
        let id = test_identity();
        // Hot activity with zone 1 hottest.
        let act = activity(&[(0, 1.0), (1, 5.0)]);
        let dec = ScalingDecision::Split { new_count: 4, avg_rate: 3.0 };

        let seal = propose_transition_from_decision(&storage, &id, &dec, &act, 1000, &[], crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE)
            .expect("propose")
            .expect("some seal");

        assert_eq!(seal.kind, TransitionKind::Split);
        assert_eq!(seal.proposed_at_epoch, 1000);
        assert_eq!(seal.effective_epoch, 1000 + TRANSITION_DISPUTE_WINDOW_EPOCHS);
        assert_eq!(seal.parents.len(), 1);
        assert_eq!(seal.parents[0].zone_id, zid(1));
        assert_eq!(seal.children.len(), 2);
        assert_eq!(seal.children[0].zone_id.path(), "1/l");
        assert_eq!(seal.children[1].zone_id.path(), "1/r");
        assert_eq!(seal.split_key, Some(SPLIT_KEY_MIDPOINT));
        assert_eq!(seal.proposer_sigs.len(), 1, "seal must be 1-of-N signed");

        // Signature verifies.
        seal.validate_structure().expect("structure");
        let hash = seal.seal_hash_for_sig().expect("hash");
        let ok = crate::crypto::pqc::dilithium3_verify(
            &hash,
            &seal.proposer_sigs[0].dilithium3_sig,
            &id.public_key,
        )
        .expect("verify");
        assert!(ok);
    }

    #[test]
    fn propose_merge_builds_signed_seal() {
        use crate::network::zone_transition_seal::TransitionKind;

        let (storage, _dir) = tmp_storage();
        let id = test_identity();
        // Four zones, two coldest are 1 and 2.
        let act = activity(&[(0, 10.0), (1, 0.1), (2, 0.2), (3, 20.0)]);
        let dec = ScalingDecision::Merge { new_count: 2, avg_rate: 7.0 };

        let seal = propose_transition_from_decision(&storage, &id, &dec, &act, 500, &[], crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE)
            .expect("propose")
            .expect("some seal");

        assert_eq!(seal.kind, TransitionKind::Merge);
        assert_eq!(seal.parents.len(), 2);
        // Lex-sorted: "1" < "2".
        assert_eq!(seal.parents[0].zone_id, zid(1));
        assert_eq!(seal.parents[1].zone_id, zid(2));
        assert_eq!(seal.children.len(), 1);
        assert_eq!(seal.children[0].zone_id.path(), "1+2");
        assert_eq!(seal.split_key, None);
        assert_eq!(seal.proposer_sigs.len(), 1);
        seal.validate_structure().expect("structure");
    }

    /// Two anchors observing the same decision + activity snapshot must
    /// produce seals with the SAME canonical hash (so their sigs merge
    /// into one proposal in TransitionStore instead of forking).
    /// This is the convergence guarantee that makes M-of-N reachable.
    #[test]
    fn propose_is_canonical_across_anchors() {
        let (storage_a, _a) = tmp_storage();
        let (storage_b, _b) = tmp_storage();
        let id_a = test_identity();
        let id_b = test_identity();
        // Identical observed state:
        let act = activity(&[(7, 2.0), (3, 5.0), (11, 2.0)]);
        let dec = ScalingDecision::Split { new_count: 6, avg_rate: 3.0 };

        let seal_a = propose_transition_from_decision(&storage_a, &id_a, &dec, &act, 200, &[], crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE)
            .unwrap()
            .unwrap();
        let seal_b = propose_transition_from_decision(&storage_b, &id_b, &dec, &act, 200, &[], crate::network::zone_committee::DEFAULT_COMMITTEE_SIZE)
            .unwrap()
            .unwrap();

        // seal_hash_for_sig excludes proposer_sigs, so two anchors that
        // saw the same inputs (and signed with different keys) MUST
        // produce the same canonical hash — otherwise their sigs accrue
        // to separate store entries and neither reaches threshold.
        let h_a = seal_a.seal_hash_for_sig().expect("hash a");
        let h_b = seal_b.seal_hash_for_sig().expect("hash b");
        assert_eq!(h_a, h_b, "canonical hash must be anchor-independent");
    }

    // ── Gap 4 split-then-route invariant ──────────────────────────────────
    //
    // The finding for Gap 4 was: code-complete but no
    // "split-then-route-records-via-`for_record_dynamic`-and-verify-no-record-loss"
    // integration test. These tests pin down the load-bearing invariant: when
    // `zone_count` flips at a transition, existing records' stored zones are
    // immutable, no record is lost or duplicated, and aggregate zone-idx scans
    // recover every inserted record exactly once.

    fn make_record(content: &[u8], creator_pk: Vec<u8>, zone: ZoneId) -> crate::record::ValidationRecord {
        let mut rec = crate::record::ValidationRecord::create(
            content,
            creator_pk,
            vec![],
            crate::record::Classification::Public,
            None,
        );
        rec.zone = Some(zone);
        rec
    }

    #[test]
    fn split_then_route_no_record_loss() {
        // Insert under zone_count=2, transition to count=4, insert again.
        // Verify (a) every record is findable by id, (b) every record appears
        // in exactly one zone-idx entry, (c) the aggregate zone-idx scan
        // covers all inserts.
        let (storage, _dir) = tmp_storage();
        let id = test_identity();

        // Phase 1: 50 records with zone field set under zone_count=2.
        let mut old_records: Vec<(String, ZoneId)> = Vec::with_capacity(50);
        for i in 0..50 {
            let mut rec = make_record(
                format!("old-{i}").as_bytes(),
                id.public_key.clone(),
                ZoneId::from_legacy(0), // placeholder; rewritten below
            );
            let zone = ZoneId::for_record_dynamic(&rec.id, 2);
            rec.zone = Some(zone.clone());
            storage.put_record(&rec.id, &rec).expect("put old");
            old_records.push((rec.id.clone(), zone));
        }

        // Old records distribute across exactly the count=2 zones.
        for (_, z) in &old_records {
            let n = z.legacy_value().expect("legacy zone");
            assert!(n < 2, "old record landed outside count=2 range: {z:?}");
        }

        // Phase 2: simulate the zone_transition firing — set ZONE_COUNT=4.
        // (Production path: `epoch.rs:3239-3251` reads state.zone_transition
        // and calls `consensus::set_zone_count(t.new_count)`.) We don't need
        // to drive the full epoch tick here — the contract under test is
        // storage-side: stored zones are immutable and the index follows them.

        // Phase 3: 50 more records with zone field set under zone_count=4.
        let mut new_records: Vec<(String, ZoneId)> = Vec::with_capacity(50);
        for i in 0..50 {
            let placeholder = make_record(
                format!("new-{i}").as_bytes(),
                id.public_key.clone(),
                ZoneId::from_legacy(0),
            );
            let zone = ZoneId::for_record_dynamic(&placeholder.id, 4);
            let mut rec = placeholder;
            rec.zone = Some(zone.clone());
            storage.put_record(&rec.id, &rec).expect("put new");
            new_records.push((rec.id.clone(), zone));
        }

        // Phase 4: every record findable by id (no loss across the transition).
        for (rid, _) in old_records.iter().chain(new_records.iter()) {
            let got = storage.get_record(rid).expect("get").expect("Some");
            assert_eq!(got.id, *rid);
        }

        // Phase 5: zone-idx aggregate covers every record exactly once.
        // Iterate zones {0, 1, 2, 3} — old records live in {0, 1}, new live
        // in {0, 1, 2, 3}. Sum must equal total inserts; no record may appear
        // under two different zone keys.
        let mut seen: HashMap<String, ZoneId> = HashMap::new();
        for n in 0..4u64 {
            let zone = ZoneId::from_legacy(n);
            let zone_key = zone.to_key_bytes();
            for rid in storage.iter_zone(&zone_key, None, None, usize::MAX) {
                if let Some(prev) = seen.insert(rid.clone(), zone.clone()) {
                    panic!(
                        "record {rid} appears in both {prev:?} and {zone:?} — \
                         zone-idx must store each record under exactly one zone"
                    );
                }
            }
        }
        assert_eq!(
            seen.len(),
            100,
            "expected 100 records across all zones, found {}",
            seen.len()
        );

        // Phase 6: old records are still in their pre-transition zones.
        for (rid, original_zone) in &old_records {
            let observed = seen.get(rid).expect("old record dropped from zone-idx");
            assert_eq!(
                observed, original_zone,
                "old record {rid} drifted from {original_zone:?} to {observed:?} \
                 — stored zones must be immutable across a zone_transition"
            );
        }

        // Phase 7: new records live in their assigned count=4 zones.
        for (rid, expected) in &new_records {
            let observed = seen.get(rid).expect("new record missing from zone-idx");
            assert_eq!(
                observed, expected,
                "new record {rid} routed to {observed:?}, expected {expected:?}"
            );
        }
    }

    #[test]
    fn zone_transition_does_not_relocate_existing_records() {
        // Tighter invariant: a single record whose stored zone was set under
        // count=N must NOT appear in the count=M-recomputed zone after a
        // transition. The CF_RECORD_BY_ZONE index is keyed by stored zone,
        // not by recomputed-on-read zone.
        let (storage, _dir) = tmp_storage();
        let id = test_identity();

        // Build a record with a known id, pin zone under count=2.
        let placeholder = make_record(
            b"some content",
            id.public_key.clone(),
            ZoneId::from_legacy(0),
        );
        let original_zone = ZoneId::for_record_dynamic(&placeholder.id, 2);
        let recomputed_under_4 = ZoneId::for_record_dynamic(&placeholder.id, 4);
        let mut rec = placeholder;
        rec.zone = Some(original_zone.clone());
        let rid = rec.id.clone();
        storage.put_record(&rid, &rec).expect("put");

        // Stored zone holds the record.
        let original_key = original_zone.to_key_bytes();
        let ids_in_original = storage.iter_zone(&original_key, None, None, 100);
        assert!(
            ids_in_original.contains(&rid),
            "record vanished from its stored zone"
        );

        // If count=4 routing maps the same id to a different zone path, the
        // index MUST NOT have a phantom entry there.
        if recomputed_under_4 != original_zone {
            let other_key = recomputed_under_4.to_key_bytes();
            let ids_in_other = storage.iter_zone(&other_key, None, None, 100);
            assert!(
                !ids_in_other.contains(&rid),
                "record incorrectly indexed under count=4 zone {recomputed_under_4:?} — \
                 zone-idx is keyed by stored zone, not recomputed zone"
            );
        }
    }

    #[test]
    fn merge_then_route_no_record_loss() {
        // Symmetric to split_then_route_no_record_loss but in the merge
        // direction (count=4 → count=2). Same invariant: stored zones are
        // immutable across a transition, so records inserted under count=4
        // (zones {0..3}) must remain at their stored zone after the network
        // shrinks to count=2 — the count=2 routing only applies to NEW
        // records, never relocates existing ones.
        let (storage, _dir) = tmp_storage();
        let id = test_identity();

        // Phase 1: 50 records under zone_count=4. Distribute across zones {0..3}.
        let mut old_records: Vec<(String, ZoneId)> = Vec::with_capacity(50);
        for i in 0..50 {
            let placeholder = make_record(
                format!("pre-merge-{i}").as_bytes(),
                id.public_key.clone(),
                ZoneId::from_legacy(0),
            );
            let zone = ZoneId::for_record_dynamic(&placeholder.id, 4);
            let mut rec = placeholder;
            rec.zone = Some(zone.clone());
            storage.put_record(&rec.id, &rec).expect("put pre-merge");
            old_records.push((rec.id.clone(), zone));
        }

        // Old records distribute across the count=4 zones {0..3}.
        for (_, z) in &old_records {
            let n = z.legacy_value().expect("legacy zone");
            assert!(n < 4, "pre-merge record landed outside count=4 range: {z:?}");
        }

        // Phase 2: simulate a Merge transition — set ZONE_COUNT=2.
        // (Production path: epoch.rs:3239-3251 calls consensus::set_zone_count
        // on the zone_transition record. The storage-side contract under test
        // is independent: stored zones don't move; new records route via
        // for_record_dynamic(_, 2).)

        // Phase 3: 50 more records under zone_count=2. Must land in {0,1} only.
        let mut new_records: Vec<(String, ZoneId)> = Vec::with_capacity(50);
        for i in 0..50 {
            let placeholder = make_record(
                format!("post-merge-{i}").as_bytes(),
                id.public_key.clone(),
                ZoneId::from_legacy(0),
            );
            let zone = ZoneId::for_record_dynamic(&placeholder.id, 2);
            let mut rec = placeholder;
            rec.zone = Some(zone.clone());
            storage.put_record(&rec.id, &rec).expect("put post-merge");
            new_records.push((rec.id.clone(), zone));
        }
        for (_, z) in &new_records {
            let n = z.legacy_value().expect("legacy zone");
            assert!(n < 2, "post-merge record landed outside count=2 range: {z:?}");
        }

        // Phase 4: every record findable by id (no loss across the transition).
        for (rid, _) in old_records.iter().chain(new_records.iter()) {
            let got = storage.get_record(rid).expect("get").expect("Some");
            assert_eq!(got.id, *rid);
        }

        // Phase 5: zone-idx aggregate covers every record exactly once across
        // zones {0..3} — pre-merge records can still live at zones {2, 3}
        // after the merge because their stored zone was set under count=4.
        let mut seen: HashMap<String, ZoneId> = HashMap::new();
        for n in 0..4u64 {
            let zone = ZoneId::from_legacy(n);
            let zone_key = zone.to_key_bytes();
            for rid in storage.iter_zone(&zone_key, None, None, usize::MAX) {
                if let Some(prev) = seen.insert(rid.clone(), zone.clone()) {
                    panic!(
                        "record {rid} appears in both {prev:?} and {zone:?} — \
                         zone-idx must store each record under exactly one zone, \
                         even after a merge transition"
                    );
                }
            }
        }
        assert_eq!(
            seen.len(),
            100,
            "expected 100 records across all zones after merge, found {}",
            seen.len()
        );

        // Phase 6: pre-merge records are still in their original count=4 zones.
        // This is the merge-direction immutability check — stored zones do not
        // move because the network shrunk.
        for (rid, original_zone) in &old_records {
            let observed = seen.get(rid).expect("pre-merge record dropped from zone-idx");
            assert_eq!(
                observed, original_zone,
                "pre-merge record {rid} drifted from {original_zone:?} to {observed:?} \
                 — stored zones must be immutable across a Merge zone_transition"
            );
        }

        // Phase 7: post-merge records live in their assigned count=2 zones {0,1}.
        for (rid, expected) in &new_records {
            let observed = seen.get(rid).expect("post-merge record missing from zone-idx");
            assert_eq!(
                observed, expected,
                "post-merge record {rid} routed to {observed:?}, expected {expected:?}"
            );
        }
    }

    #[test]
    fn split_then_route_aggregate_count_matches_inserts() {
        // Cross-check Gap 4 invariant against `count_zone` (O(zone)) — the
        // path used at `/admin/zone_autoscale` and zone-balance metrics. Sum
        // across {0..max_observed} zones must equal total inserts, regardless
        // of whether records were inserted under count=2 or count=4.
        let (storage, _dir) = tmp_storage();
        let id = test_identity();

        for i in 0..30 {
            let placeholder = make_record(
                format!("a-{i}").as_bytes(),
                id.public_key.clone(),
                ZoneId::from_legacy(0),
            );
            let zone = ZoneId::for_record_dynamic(&placeholder.id, 2);
            let mut rec = placeholder;
            rec.zone = Some(zone);
            storage.put_record(&rec.id, &rec).expect("put a");
        }
        for i in 0..30 {
            let placeholder = make_record(
                format!("b-{i}").as_bytes(),
                id.public_key.clone(),
                ZoneId::from_legacy(0),
            );
            let zone = ZoneId::for_record_dynamic(&placeholder.id, 4);
            let mut rec = placeholder;
            rec.zone = Some(zone);
            storage.put_record(&rec.id, &rec).expect("put b");
        }

        let mut total = 0usize;
        for n in 0..4u64 {
            let zone = ZoneId::from_legacy(n);
            total += storage.count_zone(&zone.to_key_bytes());
        }
        assert_eq!(total, 60, "aggregate zone-count must match total inserts (no loss, no double-count)");
    }

    /// `TransitionTarget<ZoneId>` PartialEq with the real node zone type —
    /// the crate's own test exercises the generic with `String`; this pins the
    /// integration with `ZoneId` (lex-ordered paths) the node actually uses.
    #[test]
    fn transition_target_partial_eq_with_real_zone_id() {
        let z0 = ZoneId::from_legacy(0);
        let z1 = ZoneId::from_legacy(1);
        let z2 = ZoneId::from_legacy(2);
        let split_z0 = TransitionTarget::Split { parent: z0.clone() };
        let split_z1 = TransitionTarget::Split { parent: z1.clone() };
        let merge_01 = TransitionTarget::Merge { a: z0.clone(), b: z1.clone() };

        assert_eq!(split_z0, TransitionTarget::Split { parent: z0.clone() });
        assert_ne!(split_z0, split_z1, "Split(z0) vs Split(z1) MUST disambiguate");
        assert_ne!(split_z0, merge_01, "Split vs Merge MUST disambiguate");
        let merge_12 = TransitionTarget::Merge { a: z1.clone(), b: z2.clone() };
        assert_ne!(merge_01, merge_12, "Merge(z0,z1) vs Merge(z1,z2) MUST disambiguate");
    }
}
