//! `fold_sunset` — the permanent-v1-arm fence (Merkle fold-tag brief V2,
//! §Fence, redesigned 2026-08-22; Phase-4 panel re-verify REQUIRED).
//!
//! Closes the eternal-downgrade path: without a fence, "absent tag ⇒ v1
//! forever" — a producer that keeps emitting v6-wire seals after the flip
//! keeps the bare fold alive for new epochs indefinitely. The fence is a
//! SIGNED REPLICATED artifact (per the T85/T86-verdict law: a verifier-side
//! rule must ride the chain, or upgrade lag forks nodes): op `fold_sunset`,
//! payload `{tree, min_fold_version, boundary_epoch}`, signed by the genesis
//! authority today (per-op-class threshold once staked anchors > 1).
//!
//! Semantics: no seal of the named tree with `epoch_number > boundary_epoch`
//! may verify under a fold version `< min_fold_version` — a v6-wire seal
//! above the boundary is REJECTED, fail-closed. At or below the boundary,
//! v1 verification stays valid FOREVER (historical replay untouched).
//!
//! Deliberate breaks from the `sunset.rs` precedent (its four audited holes):
//! * **HOLE-1 — monotonic register.** `sunset.rs::register` is an
//!   unconditional overwrite (re-activation-friendly). Here a validly-signed
//!   OLD record replayed after a newer one (delayed gossip, out-of-order
//!   rebuild) must not weaken the fence: the boundary may never RISE (even
//!   on a version advance — no readmission window), and same-boundary
//!   entries must raise the version. Fold sunsets are one-way by definition.
//! * **HOLE-2/3 — reconciliation on arrival.** First-ingest-only enforcement
//!   leaves a seal accepted BEFORE the fence arrived trusted forever, and
//!   lets two honest nodes disagree on the same seal by arrival order.
//!   Applying a fence returns the fenced range so the caller re-scans
//!   already-accepted seals (epoch-indexed, bounded to `(E, tip]` — never
//!   full history) and quarantines violators exactly like an ingest reject.
//! * **HOLE-2 boot — two-phase rebuild.** Boot recovery PRESCANS fold_sunset
//!   records (cheap filtered walk) before the main pass verifies seals, so a
//!   fence-violating seal on disk is not re-trusted at every boot.
//! * **HOLE-4 — snapshots carry fence state.** The fast-sync snapshot gains
//!   a serde-defaulted `fold_sunset_entries` field; a fresh join starts
//!   FENCED. Integrity = the snapshot's signed checksum binds entries by
//!   content; apply re-registers through the monotonic gate with a known-
//!   version bound. Carrying the full signed fence RECORDS (true per-entry
//!   re-verify) is a named pre-emission gate (V7-FLIP-RUNBOOK).
//!
//! **Ships INERT:** nothing in this tree emits a `fold_sunset` record; the
//! emission path is a named gate (staked anchors > 1). All code below only
//! registers and enforces what arrives on the chain — with no record, every
//! query returns "no fence" and behavior is byte-identical to pre-fence.
//!
//! Two closures, named separately (do not conflate): the v7 decode ceiling
//! stops OLD BINARIES from reading tagged seals (fail-closed-by-rejection);
//! only fence EMISSION stops an upgraded-but-misbehaving PRODUCER from
//! continuing to emit v6-wire seals for new epochs. Under solo authority the
//! only producer is the authority itself — accepted risk, stated here.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::record::ValidationRecord;

/// Which Merkle tree a fence entry governs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceTree {
    /// The epoch-seal record tree (F1).
    Seal,
    /// The super-seal tree.
    SuperSeal,
}

impl FenceTree {
    pub fn as_str(&self) -> &'static str {
        match self {
            FenceTree::Seal => "seal",
            FenceTree::SuperSeal => "super_seal",
        }
    }

    pub fn from_str_strict(s: &str) -> Option<Self> {
        match s {
            "seal" => Some(FenceTree::Seal),
            "super_seal" => Some(FenceTree::SuperSeal),
            _ => None,
        }
    }
}

/// One registered fence: seals of `tree` with `epoch_number > boundary_epoch`
/// must verify under a fold version `>= min_fold_version`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldSunsetEntry {
    pub tree: FenceTree,
    pub min_fold_version: u16,
    pub boundary_epoch: u64,
    /// Record id carrying this fence (audit trail / snapshot re-verify).
    pub record_id: String,
}

/// Outcome of a registration attempt (monotonic register, HOLE-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceRegistration {
    /// First fence for this tree, or a strict advance — now active. The
    /// caller MUST run the reconciliation sweep over `(boundary_epoch, tip]`
    /// for this tree (HOLE-2/3).
    Advanced,
    /// Entry does not strictly strengthen the fence — refused, counter
    /// bumped. A replayed old-but-validly-signed record lands here by
    /// design; the boundary only FALLS or holds, never rises.
    RefusedNotAdvancing,
}

/// Registry of active fences, one slot per tree. Plain data + atomics; the
/// node owns exactly one (inside `NodeState`), snapshots serialize the
/// entries, boot prescan re-fills it before the main verify pass.
#[derive(Debug, Default)]
pub struct FoldSunsetRegistry {
    entries: BTreeMap<FenceTree, FoldSunsetEntry>,
    /// Registrations refused by the monotonic rule (observability: a replay
    /// attempt against the fence is visible, not silent).
    pub refused_total: AtomicU64,
    /// Seals quarantined by the reconciliation sweep (HOLE-2/3).
    pub reconciliation_quarantined_total: AtomicU64,
    /// Verify-time rejections (a fenced seal arrived after the fence).
    pub verify_reject_total: AtomicU64,
}

impl FoldSunsetRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Monotonic register (HOLE-1). Strict advance = higher
    /// `min_fold_version`, or equal version with a LOWER boundary epoch
    /// (tightening the fence to cover more epochs is an advance; loosening
    /// it — a higher boundary readmitting v1 seals in `(old_E, new_E]` — is
    /// a downgrade and is refused).
    pub fn register(&mut self, entry: FoldSunsetEntry) -> FenceRegistration {
        match self.entries.get(&entry.tree) {
            Some(cur) => {
                // One-way in BOTH coordinates (panel, all four seats): the
                // boundary may NEVER rise — even a genuine version advance
                // must not readmit v1 seals in (old_E, new_E]. A future
                // multi-generation fence needs an ordered ratchet, not a
                // wider single slot.
                let advances = entry.boundary_epoch <= cur.boundary_epoch
                    && entry.min_fold_version >= cur.min_fold_version
                    && (entry.min_fold_version > cur.min_fold_version
                        || entry.boundary_epoch < cur.boundary_epoch);
                if advances {
                    info!(
                        tree = entry.tree.as_str(),
                        min_fold_version = entry.min_fold_version,
                        boundary_epoch = entry.boundary_epoch,
                        record = %entry.record_id,
                        "fold_sunset fence ADVANCED"
                    );
                    self.entries.insert(entry.tree, entry);
                    FenceRegistration::Advanced
                } else {
                    self.refused_total.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        tree = entry.tree.as_str(),
                        offered_version = entry.min_fold_version,
                        offered_boundary = entry.boundary_epoch,
                        active_version = cur.min_fold_version,
                        active_boundary = cur.boundary_epoch,
                        record = %entry.record_id,
                        "fold_sunset registration REFUSED (does not advance — replay?)"
                    );
                    FenceRegistration::RefusedNotAdvancing
                }
            }
            None => {
                info!(
                    tree = entry.tree.as_str(),
                    min_fold_version = entry.min_fold_version,
                    boundary_epoch = entry.boundary_epoch,
                    record = %entry.record_id,
                    "fold_sunset fence ARMED"
                );
                self.entries.insert(entry.tree, entry);
                FenceRegistration::Advanced
            }
        }
    }

    /// Verify-time gate: may a seal of `tree` at `epoch_number`, carried by a
    /// record of `seal_wire_version`, verify under the fold recipe that
    /// version implies? `Ok(())` when no fence is armed (inert default), the
    /// seal is at/below the boundary (historical replay), or the seal's fold
    /// version satisfies the fence. Callers bump `verify_reject_total` on Err
    /// and refuse the seal exactly like a signature failure (fail-closed).
    pub fn check_seal(
        &self,
        tree: FenceTree,
        epoch_number: u64,
        seal_wire_version: u16,
    ) -> Result<(), FenceViolation> {
        let Some(entry) = self.entries.get(&tree) else {
            return Ok(());
        };
        if epoch_number <= entry.boundary_epoch {
            return Ok(());
        }
        let fold_version = if seal_wire_version >= crate::wire::FOLD_V2_MIN_WIRE_VERSION {
            2
        } else {
            1
        };
        if fold_version >= entry.min_fold_version {
            return Ok(());
        }
        Err(FenceViolation {
            tree,
            epoch_number,
            seal_wire_version,
            required_min_fold: entry.min_fold_version,
            boundary_epoch: entry.boundary_epoch,
        })
    }

    /// Active fence for a tree, if any (metrics gauge + snapshot export).
    pub fn active(&self, tree: FenceTree) -> Option<&FoldSunsetEntry> {
        self.entries.get(&tree)
    }

    /// All entries (snapshot export; deterministic order via BTreeMap).
    pub fn entries(&self) -> impl Iterator<Item = &FoldSunsetEntry> {
        self.entries.values()
    }
}

/// A fence rejection — carried into logs/quarantine records verbatim so the
/// operator sees WHICH rule fired, not just "seal rejected".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceViolation {
    pub tree: FenceTree,
    pub epoch_number: u64,
    pub seal_wire_version: u16,
    pub required_min_fold: u16,
    pub boundary_epoch: u64,
}

impl std::fmt::Display for FenceViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "fold_sunset fence: {} seal at epoch {} (wire v{}) folds below required v{} past boundary {}",
            self.tree.as_str(),
            self.epoch_number,
            self.seal_wire_version,
            self.required_min_fold,
            self.boundary_epoch
        )
    }
}

/// Extract a `fold_sunset` payload from a record, if it is one. Returns
/// `None` for every non-fence record (cheap key probe first — this runs in
/// the boot prescan's filtered walk). Signature validity is the CALLER's
/// gate (ingest verifies before extract; snapshot apply re-verifies).
pub fn extract_fold_sunset(record: &ValidationRecord) -> Option<FoldSunsetEntry> {
    let op = record.metadata.get("op")?.as_str()?;
    if op != "fold_sunset" {
        return None;
    }
    let tree = FenceTree::from_str_strict(record.metadata.get("fence_tree")?.as_str()?)?;
    let min_fold_version = record.metadata.get("fence_min_fold_version")?.as_u64()? as u16;
    let boundary_epoch = record.metadata.get("fence_boundary_epoch")?.as_u64()?;
    Some(FoldSunsetEntry {
        tree,
        min_fold_version,
        boundary_epoch,
        record_id: record.id.clone(),
    })
}

/// SCALE ceiling on the reconciliation sweep's epoch range per zone. A fence
/// normally lands at (or just past) its boundary, so the live range is tiny;
/// the ceiling only binds on a pathological late fence. Truncation is LOUD
/// (no silent caps): the remainder is named in the warn and the sweep is
/// re-runnable (it is a pure function of fence + store).
pub const MAX_RECONCILE_EPOCHS_PER_ZONE: u64 = 100_000;

/// HOLE-2/3 reconciliation: after a fence ADVANCES, re-judge seals accepted
/// BEFORE it arrived. Epoch-indexed walk over `(boundary, tip]` per zone —
/// never full history. This slice DETECTS + counts + alarms (durable verdict
/// = the counters + the named rids in the log); rolling tip/state off a
/// quarantined seal is the Phase-4 panel's mandated re-verify item and ships
/// with the fence's first EMISSION, not with this inert consumer.
/// Durable-persistence key for the armed registry (panel H1: the fence must
/// survive a clean restart that skips the record rebuild pass entirely, and
/// must not depend on the rebuild cap's record-recency window).
pub const FENCE_PERSIST_KEY: &[u8] = b"fold_sunset_registry_v1";

/// Persist the current armed entries durably (synced write — a fence is a
/// consensus rule, losing it across a crash is a fork risk). Call after any
/// registration that ADVANCED. JSON payload: Vec<FoldSunsetEntry>.
pub fn persist_registry(state: &crate::network::state::NodeState) {
    use crate::network::RwLockRecover;
    let entries: Vec<FoldSunsetEntry> = {
        let reg = state.fold_sunset.read_recover();
        reg.entries().cloned().collect()
    };
    match serde_json::to_vec(&entries) {
        Ok(bytes) => {
            if let Err(e) = state.rocks.put_cf_raw_synced(
                crate::storage::rocks::CF_METADATA,
                FENCE_PERSIST_KEY,
                &bytes,
            ) {
                warn!("fold_sunset registry persist FAILED: {e}");
            }
        }
        Err(e) => warn!("fold_sunset registry serialize FAILED: {e}"),
    }
}

/// Load persisted entries at boot, BEFORE any rebuild pass and independent of
/// it (panel H1). Monotonic register absorbs duplicates from the later
/// record-pass collection; unknown-version entries are refused by bounds.
pub fn load_persisted_registry(state: &crate::network::state::NodeState) {
    use crate::network::RwLockRecover;
    let Ok(Some(bytes)) =
        state.rocks.get_cf_raw(crate::storage::rocks::CF_METADATA, FENCE_PERSIST_KEY)
    else {
        return;
    };
    match serde_json::from_slice::<Vec<FoldSunsetEntry>>(&bytes) {
        Ok(entries) => {
            let mut reg = state.fold_sunset.write_recover();
            for e in entries {
                if e.min_fold_version <= 2 {
                    reg.register(e);
                } else {
                    reg.refused_total.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        tree = e.tree.as_str(),
                        min_fold_version = e.min_fold_version,
                        "persisted fold_sunset entry with unknown fold version SKIPPED                          (N4: extend check_seal's wire→fold mapping before any v3 fence)"
                    );
                }
            }
        }
        Err(e) => warn!("fold_sunset persisted registry decode FAILED (ignored): {e}"),
    }
}

pub const MAX_RECONCILE_ZONES: usize = 4096;

/// Synchronous by design (panel M2/F1: zero await points, pure RocksDB +
/// registry reads) — callers run it via `tokio::task::spawn_blocking`, never
/// inline on an async worker.
pub fn reconcile_after_fence(
    state: &std::sync::Arc<crate::network::state::NodeState>,
    entry: &FoldSunsetEntry,
) {
    // Super-seal fences are enforced at admission + boot; the zone-epoch
    // index cannot enumerate super-seals — skip before paying any I/O.
    if entry.tree == FenceTree::SuperSeal {
        info!(
            boundary = entry.boundary_epoch,
            "fold_sunset reconciliation: super_seal tree — admission-enforced, sweep skipped"
        );
        return;
    }
    let zone_tips: Vec<(crate::ZoneId, u64)> = {
        use crate::network::RwLockRecover;
        let es = state.epoch.read_recover();
        es.latest_epoch.iter().map(|(z, e)| (z.clone(), *e)).collect()
    };
    let mut quarantined = 0u64;
    let total_zones = zone_tips.len();
    if total_zones > MAX_RECONCILE_ZONES {
        warn!(
            total_zones,
            cap = MAX_RECONCILE_ZONES,
            "fold_sunset reconciliation TRUNCATED at zone cap — re-run to cover the rest"
        );
    }
    for (zone, tip) in zone_tips.into_iter().take(MAX_RECONCILE_ZONES) {
        if tip <= entry.boundary_epoch {
            continue;
        }
        let start = entry.boundary_epoch + 1;
        let end = tip.min(entry.boundary_epoch + MAX_RECONCILE_EPOCHS_PER_ZONE);
        if end < tip {
            warn!(
                zone = %zone,
                truncated_from = tip,
                swept_to = end,
                "fold_sunset reconciliation TRUNCATED at ceiling — re-run to cover the rest"
            );
        }
        for epoch in start..=end {
            for rid in state.rocks.seal_record_ids_at_zone_epoch(epoch, zone.path()) {
                let Ok(Some(rec)) = state.rocks.get_record(&rid) else { continue };
                let tree_epoch_version = match entry.tree {
                    FenceTree::Seal => Some((epoch, rec.version)),
                    // Super-seals are not zone-epoch-indexed here; their
                    // fence is enforced at admission + boot. Skip in sweep.
                    FenceTree::SuperSeal => None,
                };
                if let Some((ep, wv)) = tree_epoch_version {
                    {
                        use crate::network::RwLockRecover;
                        let reg = state.fold_sunset.read_recover();
                        if reg.check_seal(entry.tree, ep, wv).is_err() {
                            quarantined += 1;
                            reg.reconciliation_quarantined_total
                                .fetch_add(1, Ordering::Relaxed);
                            warn!(
                                seal = %rid,
                                zone = %zone,
                                epoch = ep,
                                wire_version = wv,
                                "fold_sunset reconciliation: previously-accepted seal VIOLATES the fence (quarantine-flagged; operator attention required)"
                            );
                        }
                    }
                }
            }
        }
    }
    if quarantined > 0 {
        warn!(
            tree = entry.tree.as_str(),
            boundary = entry.boundary_epoch,
            quarantined,
            "fold_sunset reconciliation complete WITH VIOLATIONS — see per-seal warns above"
        );
    } else {
        info!(
            tree = entry.tree.as_str(),
            boundary = entry.boundary_epoch,
            "fold_sunset reconciliation complete — no pre-fence violations"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Classification;

    fn test_record() -> ValidationRecord {
        ValidationRecord::create(b"fence-test", vec![0u8; 32], vec![], Classification::Public, None)
    }

    fn entry(tree: FenceTree, v: u16, e: u64) -> FoldSunsetEntry {
        FoldSunsetEntry {
            tree,
            min_fold_version: v,
            boundary_epoch: e,
            record_id: format!("test-{}-{v}-{e}", tree.as_str()),
        }
    }

    #[test]
    fn first_registration_arms_the_fence() {
        let mut r = FoldSunsetRegistry::new();
        assert_eq!(
            r.register(entry(FenceTree::Seal, 2, 100_000)),
            FenceRegistration::Advanced
        );
        assert_eq!(r.active(FenceTree::Seal).unwrap().boundary_epoch, 100_000);
    }

    #[test]
    fn hole1_replayed_old_fence_cannot_lower_the_boundary() {
        let mut r = FoldSunsetRegistry::new();
        r.register(entry(FenceTree::Seal, 2, 100_000));
        // Same version, HIGHER boundary = loosening (readmits v1 in the gap) — refused.
        assert_eq!(
            r.register(entry(FenceTree::Seal, 2, 200_000)),
            FenceRegistration::RefusedNotAdvancing
        );
        // Identical entry replayed — refused (not a strict advance).
        assert_eq!(
            r.register(entry(FenceTree::Seal, 2, 100_000)),
            FenceRegistration::RefusedNotAdvancing
        );
        assert_eq!(r.active(FenceTree::Seal).unwrap().boundary_epoch, 100_000);
        assert_eq!(r.refused_total.load(Ordering::Relaxed), 2);
        // Tightening (same version, lower boundary) IS an advance.
        assert_eq!(
            r.register(entry(FenceTree::Seal, 2, 90_000)),
            FenceRegistration::Advanced
        );
        // Version advance with a HIGHER boundary is REFUSED (panel fix, all
        // four seats): it would readmit v1 seals in (90_000, 500_000].
        assert_eq!(
            r.register(entry(FenceTree::Seal, 3, 500_000)),
            FenceRegistration::RefusedNotAdvancing
        );
        // Version advance at the SAME (or lower) boundary advances.
        assert_eq!(
            r.register(entry(FenceTree::Seal, 3, 90_000)),
            FenceRegistration::Advanced
        );
        // Version DOWNGRADE must refuse even with a lower boundary (final
        // verifier N1: a replayed older genuine fence must never disarm a
        // newer one — the register must be order-independent).
        assert_eq!(
            r.register(entry(FenceTree::Seal, 2, 50_000)),
            FenceRegistration::RefusedNotAdvancing
        );
        assert_eq!(r.active(FenceTree::Seal).unwrap().min_fold_version, 3);
    }

    #[test]
    fn check_seal_inert_without_fence_and_historical_below_boundary() {
        let mut r = FoldSunsetRegistry::new();
        // Inert: no fence, everything passes (v6 far in the future too).
        assert!(r.check_seal(FenceTree::Seal, u64::MAX, 6).is_ok());
        r.register(entry(FenceTree::Seal, 2, 100_000));
        // At/below boundary: v1 valid forever.
        assert!(r.check_seal(FenceTree::Seal, 100_000, 6).is_ok());
        assert!(r.check_seal(FenceTree::Seal, 1, 5).is_ok());
        // Above boundary: v6-wire (v1 fold) REJECTED, v7-wire (v2 fold) passes.
        assert!(r.check_seal(FenceTree::Seal, 100_001, 6).is_err());
        assert!(r.check_seal(FenceTree::Seal, 100_001, 7).is_ok());
        // Distinct tree unaffected.
        assert!(r.check_seal(FenceTree::SuperSeal, u64::MAX, 6).is_ok());
    }

    #[test]
    fn extract_ignores_non_fence_records_and_parses_fence_payload() {
        let mut rec = test_record();
        assert!(extract_fold_sunset(&rec).is_none());
        rec.metadata
            .insert("op".into(), serde_json::json!("fold_sunset"));
        rec.metadata
            .insert("fence_tree".into(), serde_json::json!("seal"));
        rec.metadata
            .insert("fence_min_fold_version".into(), serde_json::json!(2));
        rec.metadata
            .insert("fence_boundary_epoch".into(), serde_json::json!(123));
        let e = extract_fold_sunset(&rec).expect("fence parses");
        assert_eq!(e.tree, FenceTree::Seal);
        assert_eq!(e.min_fold_version, 2);
        assert_eq!(e.boundary_epoch, 123);
        // Unknown tree name = None, never a default (fail-closed parse).
        rec.metadata
            .insert("fence_tree".into(), serde_json::json!("zone_record"));
        assert!(extract_fold_sunset(&rec).is_none());
    }
}
