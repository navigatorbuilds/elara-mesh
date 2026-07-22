//! ARCH-1 in-memory store of unfinalized ledger deltas.
//!
//! See internal design notes for the full design. At a glance:
//!
//! - Every ingested ledger op mirrors into this store at phase 4 of ingest
//!   instead of mutating `CF_LEDGER` directly.
//! - Entries leave the store on one of two triggers:
//!   - `commit(record_id)` — consensus reached `Finalized`. The caller
//!     pulls the delta, applies it to the committed ledger, and deletes
//!     it from `CF_PENDING_DELTAS`.
//!   - `discard(record_id)` — epoch timeout, explicit rejection, or
//!     conflict resolution. Delta dropped with no ledger mutation.
//!
//! The store is structurally bounded:
//!   - `MAX_PENDING_PER_IDENTITY` = 4096 live deltas per creator identity.
//!   - `MAX_TOTAL_PENDING` = 1_048_576 live deltas globally.
//!
//! Over-quota inserts are rejected, not silently dropped — the caller
//! (ingest path) must surface the error so the record can be re-queued
//! or NACKed.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::errors::{ElaraError, Result};
use crate::accounting::pending_delta::PendingLedgerDelta;

/// Per-identity in-flight cap. Prevents a single creator from flooding
/// pending state faster than the finality loop can drain it.
///
/// Sized for `peak_rec/s × observed_finality_secs × 1.3 headroom`.
/// History:
///   - 64 (initial sizing): telemetry showed cap-pinch fallbacks vastly
///     outnumbering finality-gated commits — too tight.
///   - 256: held briefly but saturated under sustained load; per-record
///     finality measured at ~220s (not the 75s in-zone target), so the
///     cap drained far slower than issuance — too tight.
///   - 1024: with measured 220s finality and ~3 rec/s peak issuance, the
///     sizing rule yielded `3 × 220 × 1.5 = 990`, rounded to the next power
///     of two. Held during steady-state but proved too tight under
///     bootstrap/catch-up conditions.
///   - **4096** (current): catch-up telemetry showed sustained issuance of
///     ~14 rec/s with cap-pinch firing well above the 1024 ceiling. Sizing
///     rule: `14 × 220 × 1.3 = 4004` → round to the next power of two = 4096.
///     Memory: 4096 × ~200 B/entry = ~800 KB per identity worst-case;
///     global ceiling unchanged at `MAX_TOTAL_PENDING = 1M` (≈200 MB).
///     The cap-pinch fallback bypasses the conservation invariant
///     (direct-apply, no consensus gate), so under-sizing the cap is a
///     correctness regression during catch-up; oversizing only costs RAM.
///
/// Sustained non-zero `elara_pending_ledger_fallback_direct_apply_total`
/// after this sizing means finality is genuinely too slow, not the cap.
pub const MAX_PENDING_PER_IDENTITY: usize = 4096;

/// Global in-flight cap. At ~64 bytes/entry worst case this is ~64 MB —
/// fits comfortably on a 2 GB node, and the store is O(active), not
/// O(history), so it never grows beyond this.
pub const MAX_TOTAL_PENDING: usize = 1_048_576;

/// Why `insert` refused a delta. Surfaced by the ingest path so the caller
/// can decide whether to drop, retry, or NACK to the sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertRejection {
    /// The store already has a delta for this `record_id`.
    DuplicateRecord,
    /// The originating identity has hit `MAX_PENDING_PER_IDENTITY`
    /// in-flight deltas.
    PerIdentityQuotaExceeded { identity: String, current: usize },
    /// The global `MAX_TOTAL_PENDING` cap was hit.
    GlobalQuotaExceeded { current: usize },
}

impl std::fmt::Display for InsertRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateRecord => {
                f.write_str("pending delta already exists for this record")
            }
            Self::PerIdentityQuotaExceeded { identity, current } => write!(
                f,
                "identity {identity} at pending cap ({current} / {MAX_PENDING_PER_IDENTITY})"
            ),
            Self::GlobalQuotaExceeded { current } => write!(
                f,
                "pending store at global cap ({current} / {MAX_TOTAL_PENDING})"
            ),
        }
    }
}

impl From<InsertRejection> for ElaraError {
    fn from(r: InsertRejection) -> Self {
        ElaraError::Ledger(r.to_string())
    }
}

/// In-memory reversible-delta store. `NodeState` wraps this in a
/// `tokio::sync::RwLock` because reads (balance RPC, ingest validation)
/// dominate writes (one per ingest + one per finalization).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PendingLedger {
    /// Primary index: record_id → delta.
    by_record: HashMap<String, PendingLedgerDelta>,
    /// Secondary index: creator identity → [record_id]. Bounded per
    /// identity by `MAX_PENDING_PER_IDENTITY`.
    by_identity: HashMap<String, Vec<String>>,
}

impl PendingLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.by_record.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_record.len()
    }

    pub fn contains(&self, record_id: &str) -> bool {
        self.by_record.contains_key(record_id)
    }

    pub fn get(&self, record_id: &str) -> Option<&PendingLedgerDelta> {
        self.by_record.get(record_id)
    }

    /// Number of in-flight deltas whose creator is `identity`.
    pub fn pending_count_for(&self, identity: &str) -> usize {
        self.by_identity
            .get(identity)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Sum of debits each in-flight delta would apply to `identity`.
    /// Used by `effective_available` at ingest validation to prevent a
    /// sender from pipelining multiple pending Transfers that would each
    /// pass in isolation but together exceed balance.
    ///
    /// O(k) where k = `pending_count_for(identity)` ≤ 64.
    pub fn locked_by_identity(&self, identity: &str) -> u64 {
        let Some(rids) = self.by_identity.get(identity) else {
            return 0;
        };
        let mut total: u64 = 0;
        for rid in rids {
            if let Some(d) = self.by_record.get(rid) {
                total = total.saturating_add(d.op.debit_amount_for(identity));
            }
        }
        total
    }

    /// Add a delta to the store. Returns `InsertRejection` on:
    /// - duplicate record_id,
    /// - creator over `MAX_PENDING_PER_IDENTITY`,
    /// - store over `MAX_TOTAL_PENDING`.
    ///
    /// The persistence layer (CF_PENDING_DELTAS) is NOT touched here —
    /// the caller owns the write-to-disk side so insert + disk-write can
    /// be sequenced in either order without this store knowing about
    /// RocksDB.
    pub fn insert(
        &mut self,
        delta: PendingLedgerDelta,
    ) -> std::result::Result<(), InsertRejection> {
        if self.by_record.contains_key(&delta.record_id) {
            return Err(InsertRejection::DuplicateRecord);
        }
        if self.by_record.len() >= MAX_TOTAL_PENDING {
            return Err(InsertRejection::GlobalQuotaExceeded {
                current: self.by_record.len(),
            });
        }
        let per_identity = self
            .by_identity
            .get(&delta.creator)
            .map(|v| v.len())
            .unwrap_or(0);
        if per_identity >= MAX_PENDING_PER_IDENTITY {
            return Err(InsertRejection::PerIdentityQuotaExceeded {
                identity: delta.creator.clone(),
                current: per_identity,
            });
        }
        self.by_identity
            .entry(delta.creator.clone())
            .or_default()
            .push(delta.record_id.clone());
        self.by_record.insert(delta.record_id.clone(), delta);
        Ok(())
    }

    /// Remove the delta for `record_id` from the store and return it.
    /// Called by both the commit path (finality reached) and the discard
    /// path (timeout / rejection). Idempotent: returns `None` if the
    /// record was already absent.
    pub fn take(&mut self, record_id: &str) -> Option<PendingLedgerDelta> {
        let delta = self.by_record.remove(record_id)?;
        if let Some(rids) = self.by_identity.get_mut(&delta.creator) {
            rids.retain(|r| r != record_id);
            if rids.is_empty() {
                self.by_identity.remove(&delta.creator);
            }
        }
        Some(delta)
    }

    /// Iterate over every live delta. Bounded by `MAX_TOTAL_PENDING`, so
    /// safe to call from the epoch-timeout sweep. Order is unspecified.
    pub fn iter(&self) -> impl Iterator<Item = &PendingLedgerDelta> {
        self.by_record.values()
    }

    /// Largest per-identity bucket depth across all creators. O(k) over
    /// distinct creators (≤ MAX_TOTAL_PENDING / 1 in the worst case).
    /// Surfaced as `elara_pending_ledger_max_identity_depth` so ops can
    /// see when a single creator is approaching `MAX_PENDING_PER_IDENTITY`
    /// and triggering cap-pinch fallback (ARCH-1).
    pub fn max_per_identity_depth(&self) -> usize {
        self.by_identity.values().map(Vec::len).max().unwrap_or(0)
    }

    /// Count of distinct creator identities with at least one live pending
    /// delta. Surfaced as `elara_pending_ledger_distinct_identities` so ops
    /// can distinguish *single-hot-creator* from *broad-base* pending
    /// growth — both can saturate `MAX_TOTAL_PENDING` but they need
    /// different responses (hot creator → rate-limit upstream; broad base
    /// → suspect finality stall). Combine with `max_per_identity_depth`:
    /// `distinct=1, max=cap` is cap-pinch fallback territory; `distinct=N,
    /// max=cap/N` is even distribution under finality lag.
    pub fn distinct_identities(&self) -> usize {
        self.by_identity.len()
    }

    /// Smallest `applied_at` across all live deltas (i.e. the oldest
    /// entry's wall-clock seconds-since-epoch). Returns `None` when the
    /// store is empty. Surfaced as `elara_pending_ledger_oldest_age_seconds`
    /// (computed at scrape time as `now - oldest_applied_at`) so ops can
    /// distinguish:
    ///
    /// * **Healthy churn:** depth at cap but oldest stays <60s → drain
    ///   keeps up; cap is correct, traffic is real.
    /// * **Stuck pending:** depth at cap and oldest grows past
    ///   `PENDING_DISCARD_TIMEOUT_SECS` (600s) → drain isn't moving
    ///   records to commit (consensus stall, sweep skipping Sealed
    ///   entries, or finality bottleneck).
    pub fn oldest_applied_at(&self) -> Option<f64> {
        self.by_record
            .values()
            .map(|d| d.applied_at)
            .reduce(f64::min)
    }

    /// Bulk load — used by the boot path to rehydrate from
    /// `CF_PENDING_DELTAS`. Skips duplicates and quota-violating entries
    /// silently (the restored state is assumed sane because the store
    /// enforced bounds when it wrote the CF; a violation here would
    /// indicate CF corruption, which the caller must surface).
    pub fn boot_replay(
        &mut self,
        deltas: impl IntoIterator<Item = PendingLedgerDelta>,
    ) -> Result<()> {
        for d in deltas {
            if let Err(e) = self.insert(d) {
                return Err(ElaraError::Storage(format!(
                    "pending_ledger boot replay: {e}"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::pending_delta::PendingOp;

    fn mk(record_id: &str, creator: &str, amount: u64) -> PendingLedgerDelta {
        PendingLedgerDelta::new(
            record_id.to_string(),
            creator.to_string(),
            1.0,
            2.0,
            PendingOp::Transfer {
                from: creator.to_string(),
                to: "bob".to_string(),
                amount,
                memo: None,
            },
        )
    }

    #[test]
    fn insert_then_get() {
        let mut p = PendingLedger::new();
        p.insert(mk("rec-1", "alice", 10)).unwrap();
        assert_eq!(p.len(), 1);
        assert!(p.contains("rec-1"));
        let d = p.get("rec-1").unwrap();
        assert_eq!(d.creator, "alice");
    }

    #[test]
    fn take_removes_from_both_indexes() {
        let mut p = PendingLedger::new();
        p.insert(mk("rec-1", "alice", 10)).unwrap();
        p.insert(mk("rec-2", "alice", 20)).unwrap();
        assert_eq!(p.pending_count_for("alice"), 2);

        let taken = p.take("rec-1").unwrap();
        assert_eq!(taken.record_id, "rec-1");
        assert_eq!(p.len(), 1);
        assert_eq!(p.pending_count_for("alice"), 1);

        // Idempotent: second take is a None
        assert!(p.take("rec-1").is_none());
    }

    #[test]
    fn take_last_for_identity_drops_secondary_entry() {
        let mut p = PendingLedger::new();
        p.insert(mk("rec-1", "alice", 10)).unwrap();
        p.take("rec-1").unwrap();
        assert_eq!(p.pending_count_for("alice"), 0);
        // by_identity should have dropped the "alice" key entirely
        assert!(!p.by_identity.contains_key("alice"));
    }

    #[test]
    fn duplicate_record_rejected() {
        let mut p = PendingLedger::new();
        p.insert(mk("rec-1", "alice", 10)).unwrap();
        let err = p.insert(mk("rec-1", "alice", 20)).unwrap_err();
        assert_eq!(err, InsertRejection::DuplicateRecord);
    }

    #[test]
    fn per_identity_quota_enforced() {
        let mut p = PendingLedger::new();
        for i in 0..MAX_PENDING_PER_IDENTITY {
            p.insert(mk(&format!("rec-{i}"), "alice", 1)).unwrap();
        }
        let err = p.insert(mk("rec-overflow", "alice", 1)).unwrap_err();
        assert!(matches!(
            err,
            InsertRejection::PerIdentityQuotaExceeded { .. }
        ));
        // A different identity is unaffected
        p.insert(mk("rec-bob-1", "bob", 1)).unwrap();
    }

    #[test]
    fn max_per_identity_depth_tracks_largest_bucket() {
        let mut p = PendingLedger::new();
        assert_eq!(p.max_per_identity_depth(), 0);
        p.insert(mk("a-1", "alice", 1)).unwrap();
        p.insert(mk("a-2", "alice", 1)).unwrap();
        p.insert(mk("a-3", "alice", 1)).unwrap();
        p.insert(mk("b-1", "bob", 1)).unwrap();
        assert_eq!(p.max_per_identity_depth(), 3, "alice has the deepest bucket");
        // Drain alice down — bob now has the deepest.
        p.take("a-1").unwrap();
        p.take("a-2").unwrap();
        p.take("a-3").unwrap();
        assert_eq!(p.max_per_identity_depth(), 1, "bob is the only creator left");
        p.take("b-1").unwrap();
        assert_eq!(p.max_per_identity_depth(), 0, "store empty");
    }

    #[test]
    fn distinct_identities_counts_unique_creators() {
        let mut p = PendingLedger::new();
        assert_eq!(p.distinct_identities(), 0, "empty store → 0");
        p.insert(mk("a-1", "alice", 1)).unwrap();
        assert_eq!(p.distinct_identities(), 1);
        p.insert(mk("a-2", "alice", 1)).unwrap();
        p.insert(mk("a-3", "alice", 1)).unwrap();
        assert_eq!(p.distinct_identities(), 1, "still one identity (alice)");
        p.insert(mk("b-1", "bob", 1)).unwrap();
        p.insert(mk("c-1", "charlie", 1)).unwrap();
        assert_eq!(p.distinct_identities(), 3);
        // Drain bob entirely — distinct count drops.
        p.take("b-1").unwrap();
        assert_eq!(p.distinct_identities(), 2, "bob's bucket is gone");
        // Drain alice partially — distinct count stays.
        p.take("a-1").unwrap();
        assert_eq!(p.distinct_identities(), 2, "alice still has 2 pending");
        // Drain alice fully — distinct count drops.
        p.take("a-2").unwrap();
        p.take("a-3").unwrap();
        assert_eq!(p.distinct_identities(), 1, "only charlie left");
        p.take("c-1").unwrap();
        assert_eq!(p.distinct_identities(), 0, "store empty");
    }

    #[test]
    fn oldest_applied_at_returns_min_across_deltas() {
        let mut p = PendingLedger::new();
        assert!(p.oldest_applied_at().is_none(), "empty store → None");
        let mk_at = |rid: &str, applied_at: f64| {
            PendingLedgerDelta::new(
                rid.to_string(),
                "alice".to_string(),
                1.0,
                applied_at,
                PendingOp::Transfer {
                    from: "alice".to_string(),
                    to: "bob".to_string(),
                    amount: 1,
                    memo: None,
                },
            )
        };
        p.insert(mk_at("rec-newest", 300.0)).unwrap();
        p.insert(mk_at("rec-oldest", 100.0)).unwrap();
        p.insert(mk_at("rec-middle", 200.0)).unwrap();
        assert_eq!(p.oldest_applied_at(), Some(100.0));
        // After draining the oldest, the second-oldest takes over.
        p.take("rec-oldest").unwrap();
        assert_eq!(p.oldest_applied_at(), Some(200.0));
        p.take("rec-middle").unwrap();
        p.take("rec-newest").unwrap();
        assert!(p.oldest_applied_at().is_none(), "drained → None");
    }

    #[test]
    fn locked_by_identity_sums_transfer_debits() {
        let mut p = PendingLedger::new();
        p.insert(mk("rec-1", "alice", 10)).unwrap();
        p.insert(mk("rec-2", "alice", 25)).unwrap();
        p.insert(mk("rec-3", "bob", 100)).unwrap();
        assert_eq!(p.locked_by_identity("alice"), 35);
        assert_eq!(p.locked_by_identity("bob"), 100);
        assert_eq!(p.locked_by_identity("charlie"), 0);
    }

    #[test]
    fn boot_replay_populates_store() {
        let deltas = vec![
            mk("rec-1", "alice", 10),
            mk("rec-2", "bob", 20),
            mk("rec-3", "alice", 30),
        ];
        let mut p = PendingLedger::new();
        p.boot_replay(deltas).unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(p.pending_count_for("alice"), 2);
        assert_eq!(p.pending_count_for("bob"), 1);
        assert_eq!(p.locked_by_identity("alice"), 40);
    }

    #[test]
    fn json_roundtrip_whole_store() {
        // Defensive: whole-store serialization is NOT the persistence
        // path (CF_PENDING_DELTAS serializes per-delta), but it validates
        // that the type is serde-clean end to end.
        let mut p = PendingLedger::new();
        p.insert(mk("rec-1", "alice", 10)).unwrap();
        p.insert(mk("rec-2", "bob", 20)).unwrap();
        let json = serde_json::to_vec(&p).unwrap();
        let back: PendingLedger = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.len(), 2);
        assert!(back.contains("rec-1"));
        assert!(back.contains("rec-2"));
    }

    // ──────────────── pending-cap + rejection Display tests ─────────────────
    // Fixture-free constant + empty-store + display pins. No record ingest —
    // these defend the cap values (per-identity 4096, global 2^20), the
    // rejection enum Display strings (operator-readable error messages),
    // and the empty-store invariants of new/default.

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_per_identity_and_global_pending_caps_strict_value_pin_power_of_two() {
        // MAX_PENDING_PER_IDENTITY = 4096 — Gap 2.1 diagnostic chain (see
        // doc on const). MAX_TOTAL_PENDING = 1_048_576 = 2^20 — picked so
        // worst-case ~64 MB fits on a 2 GB node.
        assert_eq!(MAX_PENDING_PER_IDENTITY, 4096);
        assert_eq!(MAX_TOTAL_PENDING, 1_048_576);
        // Both are powers of two (cleaner hex math + lets the operator
        // recognise either limit on sight). 4096 = 2^12, 1_048_576 = 2^20.
        assert!(MAX_PENDING_PER_IDENTITY.is_power_of_two());
        assert!(MAX_TOTAL_PENDING.is_power_of_two());
        assert_eq!(MAX_PENDING_PER_IDENTITY.trailing_zeros(), 12);
        assert_eq!(MAX_TOTAL_PENDING.trailing_zeros(), 20);
        // Global cap is at least 256x the per-identity cap — sanity that
        // a single identity can't (legitimately) own the whole store.
        assert!(MAX_TOTAL_PENDING >= 256 * MAX_PENDING_PER_IDENTITY);
        // Type pins.
        let _: usize = MAX_PENDING_PER_IDENTITY;
        let _: usize = MAX_TOTAL_PENDING;
    }

    #[test]
    fn batch_b_insert_rejection_display_three_variants_pin_operator_messages() {
        // Operator-facing Display strings — pin each variant's format so a
        // log-parsing playbook stays valid. Numeric formatting matters
        // (no thousands separator on `current`, slash-separated capacity).
        let dup = InsertRejection::DuplicateRecord;
        assert_eq!(
            format!("{dup}"),
            "pending delta already exists for this record",
        );

        let per = InsertRejection::PerIdentityQuotaExceeded {
            identity: "alice-hash".into(),
            current: 4096,
        };
        let per_msg = format!("{per}");
        assert!(per_msg.starts_with("identity alice-hash at pending cap"));
        assert!(per_msg.contains("4096 / 4096"));
        assert!(per_msg.contains(&MAX_PENDING_PER_IDENTITY.to_string()));

        let glob = InsertRejection::GlobalQuotaExceeded { current: 1_048_576 };
        let glob_msg = format!("{glob}");
        assert!(glob_msg.starts_with("pending store at global cap"));
        assert!(glob_msg.contains("1048576 / 1048576"));
        assert!(glob_msg.contains(&MAX_TOTAL_PENDING.to_string()));
    }

    #[test]
    fn batch_b_insert_rejection_into_elara_error_token_preserves_display_payload() {
        // The `?` operator in the ingest hot path lifts InsertRejection
        // into ElaraError. Pin that the conversion is via Display (not
        // Debug) so log messages stay human-readable.
        let r = InsertRejection::PerIdentityQuotaExceeded {
            identity: "carol".into(),
            current: 4096,
        };
        let display = format!("{r}");
        let err: ElaraError = r.into();
        match err {
            ElaraError::Ledger(s) => {
                assert_eq!(s, display, "conversion must preserve Display string");
                assert!(s.contains("carol"));
            }
            other => panic!("expected ElaraError::Ledger, got {other:?}"),
        }
    }

    #[test]
    fn batch_b_pending_ledger_new_equals_default_empty_store_invariants() {
        // new() == Self::default(); both produce an empty store. Pin the
        // five empty-store getter values so a refactor that drops one of
        // the indices fails this test loudly.
        let p_new = PendingLedger::new();
        let p_def = PendingLedger::default();
        // Both report empty.
        assert!(p_new.is_empty());
        assert!(p_def.is_empty());
        assert_eq!(p_new.len(), 0);
        assert_eq!(p_def.len(), 0);
        // Unknown-id getters all return None / false / 0.
        assert!(!p_new.contains("anything"));
        assert!(p_new.get("anything").is_none());
        // serde round-trip on empty store is shape-stable.
        let json = serde_json::to_vec(&p_new).unwrap();
        let back: PendingLedger = serde_json::from_slice(&json).unwrap();
        assert!(back.is_empty());
        assert_eq!(back.len(), 0);
    }

    #[test]
    fn batch_b_pending_count_and_locked_unknown_identity_return_zero_no_panic() {
        // No record for `identity` → pending_count_for and locked_by_identity
        // must return 0 (not panic, not Option::None). This is the hot-path
        // invariant the balance-RPC uses to decide whether to call further.
        let p = PendingLedger::new();
        assert_eq!(p.pending_count_for("absent-identity"), 0);
        assert_eq!(p.locked_by_identity("absent-identity"), 0);
        // Empty string is a valid (if absurd) identity — still 0, no panic.
        assert_eq!(p.pending_count_for(""), 0);
        assert_eq!(p.locked_by_identity(""), 0);
        // Very long identity (no panic on hash lookup).
        let long = "x".repeat(10_000);
        assert_eq!(p.pending_count_for(&long), 0);
        assert_eq!(p.locked_by_identity(&long), 0);
    }
}
