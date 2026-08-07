//! PARTITION-MERGE conservation trip-wire.
//!
//! Detects when a same-epoch seal DEMOTION demotes a seal that covered an
//! `XZoneLock` whose cross-zone transfer is already `Claimed` — the precondition
//! that would make an `XZoneRevert` clawback necessary (internal design notes
//! Gap D; spec/tla/Conservation.tla TAIL 1 `ResolveSealDemotion`).
//!
//! ## Why this is a trip-wire, NOT the revert itself
//!
//! Fusion audit 2026-06-28 (3 Sonnet + 1 Opus read-only panels → synth →
//! final-verify), verdict SLICE. The conservation break the Phase-D TLA+ model
//! proves guard-necessary is **not reachable in the current architecture**:
//!
//! 1. The ledger is a pure **append-only fold over records, independent of seal
//!    canonicality**. Seal demotion (`record_orphan_sibling` /
//!    `apply_canonical_seal`) touches ONLY `EpochState` metadata, never the
//!    ledger. So `Lock → Seal → Claim → Demote` leaves sender −Amt, recipient
//!    +Amt, pending 0 → conservation holds. The model's `bal[Sender] += Amt`
//!    lock-reversion has no code equivalent (it models a hypothetical
//!    rollback-on-demotion / sharded-per-zone-ledger architecture).
//! 2. The claim gate (`verify_finality_quorum`) freezes the source committee at
//!    lock-seal time, so a demotion cannot retroactively invalidate a claim
//!    without a ≥2/3 source-committee Byzantine equivocation (slashing
//!    territory), not the honest partition the model assumes.
//! 3. A naive revert would itself break conservation: clawing `bal[Recipient]`
//!    without re-crediting `bal[Sender]` (which was never reverted, append-only)
//!    DESTROYS Amt; porting the TLA `bal[Sender] += Amt` term verbatim INFLATES
//!    by Amt. A correct revert must be a sum-neutral Recipient→Sender move.
//!
//! Building the full revert now would be machinery for an unreachable failure
//! mode. So we ship the cheap, zero-risk detector: if
//! `elara_xzone_demoted_seal_covers_claimed_lock_total` ever goes non-zero in
//! soak, that is the empirical signal to promote SLICE → build the
//! (sum-neutral) revert.
//!
//! ## Design
//!
//! Capture is **outcome-based** at the sole production seal-registration call
//! site (`ingest.rs`): read the canonical `(epoch, seal_id)` for the zone before
//! vs. after registration. This covers BOTH `register_seal` (the default lex-min
//! path, which does NOT orphan-track demotions) and `register_seal_with_reconcile`
//! (the weight path) without duplicating the canonicalization decision logic.
//! Captured demotions go on a bounded `NodeState` queue (cheap — built under the
//! epoch write lock already held, pushed once it is released). A periodic
//! health-loop tick drains them and does the storage/ledger I/O — resolve the
//! demoted seal's `record_hashes` → `record_id`s → look up `cross_zone.pending`
//! (since `transfer_id == lock record.id`) — OUTSIDE any consensus lock.
//!
//! Scale: capture O(1); scan O(records-in-demoted-seal) bounded per tick; queue
//! bounded. No O(all_records) anywhere.

use std::collections::VecDeque;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use tracing::warn;

use super::epoch::extract_epoch_seal;
use super::ingest::resolve_seal_record_ids;
use super::state::NodeState;
use super::LockRecover;
use crate::accounting::cross_zone::TransferStatus;

/// Max demotion events buffered for the cross-zone coverage scan. A same-epoch
/// demotion is rare (partition-merge / dual-proposer race only); 1024 covers a
/// large merge burst before drop-oldest fires. ≈ 1024 × ~120 B ≈ 120 KB worst case.
pub const DEMOTED_SEAL_SCAN_QUEUE_CAP: usize = 1024;

/// Max demotion events scanned per health-loop tick — bounds the per-tick
/// storage I/O (each `None`-`record_hashes` entry re-fetches the demoted seal).
pub const DEMOTED_SEAL_SCAN_PER_TICK: usize = 64;

/// One buffered same-epoch seal demotion awaiting a cross-zone coverage scan.
#[derive(Clone, Debug)]
pub struct DemotedSealScan {
    /// Zone of the demoted seal (display form — used only for the operator log).
    pub zone: String,
    /// Epoch of the demoted seal.
    pub epoch: u64,
    /// record_id of the demoted seal (a seal's id == its record id).
    pub seal_id: String,
    /// Covered `record_hashes` if known at capture (the incoming-demoted case,
    /// where the seal object was in hand). `None` for the prev-demoted case →
    /// the scan re-fetches the demoted seal record by `seal_id` and parses it.
    pub record_hashes: Option<Vec<[u8; 32]>>,
}

/// Classify a same-epoch seal-registration outcome into a demotion.
///
/// Given the canonical seal_id for the zone *before* registration (`prev`), the
/// canonical seal_id *after* (`new`), and the incoming seal's id (`incoming`),
/// returns `Some((demoted_seal_id, incoming_was_demoted))` or `None` when no
/// demotion occurred (idempotent re-register, or the incoming simply became the
/// first/advancing canonical). Pure — unit-tested independently of `NodeState`.
///
/// - incoming became canonical, replacing a *different* prev → prev demoted.
/// - canonical unchanged but incoming was a *different* same-epoch challenger →
///   incoming demoted (it lost the lex-min / weight race).
pub fn classify_demotion(
    prev: &str,
    new: Option<&str>,
    incoming: &str,
) -> Option<(String, bool)> {
    if new == Some(incoming) && prev != incoming {
        Some((prev.to_string(), false))
    } else if new == Some(prev) && prev != incoming {
        Some((incoming.to_string(), true))
    } else {
        None
    }
}

/// Bounded enqueue (drop-oldest at `cap`). Returns `true` if an entry was
/// dropped. Pure — testable without a `NodeState`.
fn enqueue_bounded(q: &mut VecDeque<DemotedSealScan>, entry: DemotedSealScan, cap: usize) -> bool {
    let dropped = q.len() >= cap;
    if dropped {
        q.pop_front();
    }
    q.push_back(entry);
    dropped
}

/// Enqueue a captured demotion for the async coverage scan. Bounded (drop-oldest
/// on overflow, bumping `demoted_seal_scan_queue_dropped_total`). Cheap enough to
/// call right after releasing the epoch write lock — no I/O, just a `VecDeque`
/// push under a dedicated mutex.
pub fn push_demoted_seal_scan(state: &NodeState, entry: DemotedSealScan) {
    state.same_epoch_seal_demotions_total.fetch_add(1, Relaxed);
    let dropped = {
        let mut q = state.demoted_seal_scan_queue.lock_recover();
        enqueue_bounded(&mut q, entry, DEMOTED_SEAL_SCAN_QUEUE_CAP)
    };
    if dropped {
        state
            .demoted_seal_scan_queue_dropped_total
            .fetch_add(1, Relaxed);
    }
}

/// One tick: drain up to [`DEMOTED_SEAL_SCAN_PER_TICK`] captured demotions and
/// check each against `cross_zone.pending`. Runs on every node in the health
/// loop; O(1) and allocation-free when the queue is empty (the common case).
pub async fn run_demoted_seal_xzone_scan_tick(state: &Arc<NodeState>) {
    let batch: Vec<DemotedSealScan> = {
        let mut q = state.demoted_seal_scan_queue.lock_recover();
        let n = q.len().min(DEMOTED_SEAL_SCAN_PER_TICK);
        q.drain(..n).collect()
    };
    if batch.is_empty() {
        return;
    }

    for entry in batch {
        // Resolve the demoted seal's covered record_hashes (re-fetch the seal
        // record for the prev-demoted case where we did not have it in hand).
        let record_hashes = match entry.record_hashes {
            Some(rh) => rh,
            None => match state.rocks.get_record(&entry.seal_id) {
                Ok(Some(rec)) => match extract_epoch_seal(&rec) {
                    // R3-8 slice 4: a re-fetched demoted seal may carry no
                    // inline enumeration (bounded emission / root gate).
                    // Derive from the local window (root-verified) so the
                    // conservation trip-wire keeps working above the inline
                    // cap; on None fall through to the empty-skip below.
                    Ok(Some(parsed)) => {
                        if parsed.record_hashes.is_empty() && parsed.record_count > 0 {
                            match crate::network::epoch::derive_seal_enumeration(
                                &*state.rocks,
                                &parsed,
                            ) {
                                Some(crate::network::epoch::DeriveOutcome::Derived(d)) => d,
                                _ => parsed.record_hashes,
                            }
                        } else {
                            parsed.record_hashes
                        }
                    }
                    _ => continue, // not a parseable seal record (evicted/cold) — skip
                },
                _ => continue, // seal record not found locally — skip
            },
        };
        if record_hashes.is_empty() {
            continue;
        }

        // Map record_hashes → record_ids (storage point-reads, no lock held).
        let record_ids = resolve_seal_record_ids(state, &record_hashes);
        if record_ids.is_empty() {
            continue;
        }

        // Cross-reference against in-flight cross-zone transfers. transfer_id ==
        // the XZoneLock record's id, so a covered record_id is a direct key into
        // `cross_zone.pending`. In-memory lookups only; lock released promptly.
        let (covered, claimed_ids) = {
            let ledger = state.ledger.read().await;
            let mut covered = false;
            let mut claimed_ids: Vec<String> = Vec::new();
            for rid in &record_ids {
                if let Some(t) = ledger.cross_zone.pending.get(rid) {
                    covered = true;
                    if t.status == TransferStatus::Claimed {
                        claimed_ids.push(rid.clone());
                    }
                }
            }
            (covered, claimed_ids)
        };

        if covered {
            state
                .xzone_demoted_seal_covers_lock_total
                .fetch_add(1, Relaxed);
        }
        if !claimed_ids.is_empty() {
            state
                .xzone_demoted_seal_covers_claimed_lock_total
                .fetch_add(1, Relaxed);
            let short: Vec<&str> = claimed_ids
                .iter()
                .map(|s| &s[..s.len().min(16)])
                .collect();
            warn!(
                "PARTITION-MERGE conservation trip-wire: demoted seal {} (zone {} epoch {}) \
                 covers {} CLAIMED cross-zone transfer(s) {:?} — XZoneRevert precondition \
                 (internal design notes Gap D). Conservation is still held by the append-only \
                 ledger + frozen-committee claim gate; if this is non-transient, investigate a \
                 >=2/3 source-committee equivocation and consider building the (sum-neutral) revert.",
                &entry.seal_id[..entry.seal_id.len().min(16)],
                entry.zone,
                entry.epoch,
                claimed_ids.len(),
                short,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(id: &str) -> DemotedSealScan {
        DemotedSealScan {
            zone: "0".to_string(),
            epoch: 7,
            seal_id: id.to_string(),
            record_hashes: None,
        }
    }

    #[test]
    fn classify_incoming_wins_demotes_prev() {
        // incoming "B" became canonical, replacing a different prev "A".
        let got = classify_demotion("A", Some("B"), "B");
        assert_eq!(got, Some(("A".to_string(), false)));
    }

    #[test]
    fn classify_incoming_loses_demotes_incoming() {
        // canonical unchanged ("A"), incoming "B" was a different challenger.
        let got = classify_demotion("A", Some("A"), "B");
        assert_eq!(got, Some(("B".to_string(), true)));
    }

    #[test]
    fn classify_idempotent_reregister_is_no_demotion() {
        // incoming == prev == new: re-registering the same canonical seal.
        assert_eq!(classify_demotion("A", Some("A"), "A"), None);
    }

    #[test]
    fn classify_first_seal_is_no_demotion() {
        // prev == incoming and that became canonical → not a demotion of a
        // *different* seal (guarded by prev != incoming).
        assert_eq!(classify_demotion("A", Some("A"), "A"), None);
        // new is None (no canonical recorded) → never a demotion.
        assert_eq!(classify_demotion("A", None, "B"), None);
    }

    #[test]
    fn enqueue_bounded_under_cap_keeps_all_fifo() {
        let mut q: VecDeque<DemotedSealScan> = VecDeque::new();
        assert!(!enqueue_bounded(&mut q, scan("a"), 3));
        assert!(!enqueue_bounded(&mut q, scan("b"), 3));
        assert!(!enqueue_bounded(&mut q, scan("c"), 3));
        assert_eq!(q.len(), 3);
        assert_eq!(q.front().unwrap().seal_id, "a");
        assert_eq!(q.back().unwrap().seal_id, "c");
    }

    #[test]
    fn enqueue_bounded_at_cap_drops_oldest() {
        let mut q: VecDeque<DemotedSealScan> = VecDeque::new();
        enqueue_bounded(&mut q, scan("a"), 2);
        enqueue_bounded(&mut q, scan("b"), 2);
        // At cap: pushing "c" drops oldest "a", keeps FIFO [b, c].
        assert!(enqueue_bounded(&mut q, scan("c"), 2));
        assert_eq!(q.len(), 2);
        assert_eq!(q.front().unwrap().seal_id, "b");
        assert_eq!(q.back().unwrap().seal_id, "c");
    }
}
