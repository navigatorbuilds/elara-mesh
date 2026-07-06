//! Acquisition velocity limits — per-identity inflow throttling + large-mint vesting.
//!
//! economics v0.4.1 Section 13.2:
//! - Max acquisition rate: 0.5% of circulating supply per 30 days per identity
//! - Large mint vesting: mint > 0.1% of supply → 365-day linear vesting
//!
//! These prevent rapid accumulation and ensure large mints unlock gradually.
//! Genesis authority is exempt from acquisition limits (but vesting still applies).

//!
//! Spec references:
//!   @spec economics §13.2

use std::collections::HashMap;

use crate::errors::{ElaraError, Result};

// ─── Constants (economics v0.4.1 Section 13.2) ─────────────────────────────

/// Acquisition window: 30 days in seconds.
pub const ACQUISITION_WINDOW_SECS: f64 = 30.0 * 24.0 * 3600.0;

/// Max acquisition rate: 0.5% of circulating supply per 30-day window.
pub const MAX_ACQUISITION_RATE: f64 = 0.005;

/// Large mint threshold: > 0.1% of total supply triggers vesting.
pub const LARGE_MINT_THRESHOLD: f64 = 0.001;

/// Vesting duration: 365 days in seconds.
pub const VESTING_DURATION_SECS: f64 = 365.0 * 24.0 * 3600.0;

// ── Fixed-point gate constants (consensus determinism) ───────────────────────
// These thresholds gate transfer/mint accept-reject inside `apply_op` on EVERY
// node, so the rate constants above must NOT be applied in f64 (`supply as f64 *
// 0.005` is non-portable across libm and loses integer precision once supply
// exceeds 2^53). The exact rationals below drive the integer gate instead.
// See internal design notes.

/// 0.5% acquisition rate as the exact rational 5/1000.
pub const MAX_ACQUISITION_RATE_NUM: u128 = 5;
pub const MAX_ACQUISITION_RATE_DEN: u128 = 1000;
/// 0.1% large-mint threshold as the exact rational 1/1000.
pub const LARGE_MINT_THRESHOLD_NUM: u128 = 1;
pub const LARGE_MINT_THRESHOLD_DEN: u128 = 1000;
/// Vesting duration in whole seconds (365 d) for the integer linear-release path.
pub const VESTING_DURATION_SECS_INT: u128 = 365 * 24 * 3600;

/// Minimum circulating supply for acquisition limits to activate.
/// Below this, the economy is too young for rate limits to be meaningful.
pub const ACQUISITION_LIMIT_ACTIVATION: u64 = 1_000_000 * crate::accounting::types::BASE_UNITS_PER_BEAT;

// ─── Acquisition Tracker ─────────────────────────────────────────────────────

/// Per-identity inflow tracking for acquisition velocity limits.
#[derive(Debug, Clone, Default)]
pub struct AcquisitionTracker {
    /// Per-identity inflow records: (timestamp, amount).
    inflows: HashMap<String, Vec<(f64, u64)>>,
}

impl AcquisitionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an inflow (transfer received or mint received).
    pub fn record_inflow(&mut self, identity: &str, amount: u64, timestamp: f64) {
        let entry = self.inflows.entry(identity.to_string()).or_default();
        entry.push((timestamp, amount));
    }

    /// Sum inflows in the last 30 days from the given timestamp.
    pub fn inflow_in_window(&self, identity: &str, now: f64) -> u64 {
        let cutoff = now - ACQUISITION_WINDOW_SECS;
        match self.inflows.get(identity) {
            Some(v) => v
                .iter()
                .filter(|(ts, _)| *ts > cutoff)
                .map(|(_, amt)| *amt)
                .fold(0u64, |acc, x| acc.saturating_add(x)),
            None => 0,
        }
    }

    /// Check if receiving `amount` would exceed the acquisition velocity limit.
    ///
    /// Returns Ok(()) if allowed, Err if limit would be exceeded.
    /// Genesis authority as recipient is exempt.
    pub fn check_acquisition(
        &self,
        recipient: &str,
        amount: u64,
        circulating_supply: u64,
        timestamp: f64,
        genesis_authority: &str,
    ) -> Result<()> {
        // Genesis authority exempt
        if recipient == genesis_authority {
            return Ok(());
        }

        // No limit if circulating supply is below activation threshold
        if circulating_supply < ACQUISITION_LIMIT_ACTIVATION {
            return Ok(());
        }

        let limit = ((circulating_supply as u128).saturating_mul(MAX_ACQUISITION_RATE_NUM)
            / MAX_ACQUISITION_RATE_DEN) as u64;
        let already_received = self.inflow_in_window(recipient, timestamp);
        let total_inflow = already_received.saturating_add(amount);

        if total_inflow > limit {
            let remaining = limit.saturating_sub(already_received);
            return Err(ElaraError::Ledger(format!(
                "acquisition velocity exceeded: max {:.1}% of circulating supply per 30 days. \
                 already received {} in window, proposed {}, limit {}, remaining {}",
                MAX_ACQUISITION_RATE * 100.0,
                already_received,
                amount,
                limit,
                remaining,
            )));
        }

        Ok(())
    }

    /// Prune entries older than the window to prevent unbounded growth.
    pub fn prune(&mut self, now: f64) {
        let cutoff = now - ACQUISITION_WINDOW_SECS;
        for entry in self.inflows.values_mut() {
            entry.retain(|(ts, _)| *ts > cutoff);
        }
        self.inflows.retain(|_, v| !v.is_empty());
    }

    /// Number of tracked identities.
    pub fn tracked_identities(&self) -> usize {
        self.inflows.len()
    }
}

// ─── Vesting Manager ─────────────────────────────────────────────────────────

/// A single vesting entry for a large mint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VestingEntry {
    /// Record ID of the mint that created this vesting.
    pub record_id: String,
    /// Total amount being vested (base units).
    pub total_amount: u64,
    /// Timestamp when vesting starts.
    pub start_time: f64,
    /// Timestamp when vesting fully unlocks.
    pub end_time: f64,
}

impl VestingEntry {
    /// Create a new 365-day linear vesting entry.
    pub fn new(record_id: String, amount: u64, start_time: f64) -> Self {
        Self {
            record_id,
            total_amount: amount,
            start_time,
            end_time: start_time + VESTING_DURATION_SECS,
        }
    }

    /// Amount unlocked at the given timestamp (linear release).
    pub fn unlocked(&self, now: f64) -> u64 {
        if now >= self.end_time {
            self.total_amount
        } else if now <= self.start_time {
            0
        } else {
            // Integer linear release: unlocked = total × elapsed_secs / duration,
            // floored to whole seconds. `now`/`start_time` are deterministic record
            // timestamps and their difference is < 2^53, so the f64 subtract is
            // correctly-rounded (bit-portable); the value path is pure u128 so a
            // balance the ledger writes never depends on non-portable f64 multiply.
            let elapsed_secs = (now - self.start_time).floor().max(0.0) as u128;
            ((self.total_amount as u128).saturating_mul(elapsed_secs)
                / VESTING_DURATION_SECS_INT) as u64
        }
    }

    /// Amount still locked at the given timestamp.
    pub fn locked(&self, now: f64) -> u64 {
        self.total_amount.saturating_sub(self.unlocked(now))
    }

    /// Whether this entry is fully vested.
    pub fn is_fully_vested(&self, now: f64) -> bool {
        now >= self.end_time
    }
}

/// Manages vesting schedules for large mints.
///
/// Tracks both individual and cumulative mints to prevent split-mint bypass
/// (economics §13.4): multiple sub-threshold mints that collectively exceed
/// 0.1% of supply still trigger vesting.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct VestingManager {
    /// Per-identity vesting entries.
    schedules: HashMap<String, Vec<VestingEntry>>,
    /// Per-identity cumulative mint tracking: (timestamp, amount) pairs.
    /// Used to detect split-mint bypass within a 30-day window.
    cumulative_mints: HashMap<String, Vec<(f64, u64)>>,
}

impl VestingManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a single mint amount triggers vesting (> 0.1% of total supply).
    pub fn requires_vesting(amount: u64, total_supply: u64) -> bool {
        if total_supply == 0 {
            return false;
        }
        let threshold = ((total_supply as u128).saturating_mul(LARGE_MINT_THRESHOLD_NUM)
            / LARGE_MINT_THRESHOLD_DEN) as u64;
        amount > threshold
    }

    /// Check if cumulative mints within 30 days exceed the vesting threshold.
    /// Prevents split-mint bypass: multiple sub-threshold mints that collectively
    /// exceed 0.1% of supply still trigger vesting (economics §13.4).
    pub fn cumulative_exceeds_threshold(
        &self,
        identity: &str,
        new_amount: u64,
        total_supply: u64,
        timestamp: f64,
    ) -> bool {
        if total_supply == 0 {
            return false;
        }
        let threshold = ((total_supply as u128).saturating_mul(LARGE_MINT_THRESHOLD_NUM)
            / LARGE_MINT_THRESHOLD_DEN) as u64;
        let cutoff = timestamp - ACQUISITION_WINDOW_SECS;
        let prior_mints: u64 = self
            .cumulative_mints
            .get(identity)
            .map(|mints| {
                mints
                    .iter()
                    .filter(|(ts, _)| *ts > cutoff)
                    .map(|(_, amt)| *amt)
                    .fold(0u64, |acc, x| acc.saturating_add(x))
            })
            .unwrap_or(0);
        prior_mints.saturating_add(new_amount) > threshold
    }

    /// Record a mint for cumulative tracking.
    pub fn record_mint(&mut self, identity: &str, amount: u64, timestamp: f64) {
        let entry = self.cumulative_mints.entry(identity.to_string()).or_default();
        entry.push((timestamp, amount));
        // Bound the window: `cumulative_exceeds_threshold` only ever reads mints
        // within ACQUISITION_WINDOW_SECS, so older entries are dead weight. This
        // map is now serialized into the state snapshot (see LedgerState.vesting
        // `#[serde(default)]`), so prune on insert — deterministic w.r.t. the
        // canonical timestamp-sorted apply order — to keep it O(mints-in-window)
        // per identity, not O(all-time). Closes the SCALE violation alongside the
        // determinism fix; the re-filtered read keeps it consensus-transparent.
        let cutoff = timestamp - ACQUISITION_WINDOW_SECS;
        entry.retain(|(ts, _)| *ts > cutoff);
    }

    /// Add a vesting schedule for a large mint.
    pub fn add_vesting(&mut self, identity: &str, record_id: String, amount: u64, timestamp: f64) {
        let entry = VestingEntry::new(record_id, amount, timestamp);
        self.schedules
            .entry(identity.to_string())
            .or_default()
            .push(entry);
    }

    /// Total unvested (locked) balance for an identity at the given time.
    pub fn locked_balance(&self, identity: &str, now: f64) -> u64 {
        match self.schedules.get(identity) {
            Some(entries) => entries.iter().map(|e| e.locked(now)).sum(),
            None => 0,
        }
    }

    /// Available (transferable) balance = available - locked.
    pub fn transferable_balance(&self, identity: &str, available: u64, now: f64) -> u64 {
        available.saturating_sub(self.locked_balance(identity, now))
    }

    /// Prune fully vested entries and old cumulative mint records.
    pub fn prune(&mut self, now: f64) {
        for entries in self.schedules.values_mut() {
            entries.retain(|e| !e.is_fully_vested(now));
        }
        self.schedules.retain(|_, v| !v.is_empty());

        // Prune cumulative mint records older than 30 days
        let cutoff = now - ACQUISITION_WINDOW_SECS;
        for mints in self.cumulative_mints.values_mut() {
            mints.retain(|(ts, _)| *ts > cutoff);
        }
        self.cumulative_mints.retain(|_, v| !v.is_empty());
    }

    /// Number of identities with active vesting.
    pub fn active_vestings(&self) -> usize {
        self.schedules.len()
    }

    /// Total number of vesting entries across all identities.
    pub fn total_entries(&self) -> usize {
        self.schedules.values().map(|v| v.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::types::BASE_UNITS_PER_BEAT;

    const BEAT: u64 = BASE_UNITS_PER_BEAT;

    #[test]
    fn acquisition_and_vesting_gates_are_exact_integers_above_2pow53() {
        // Supply 21B beat = 2.1e19 base units > 2^53: f64 paths lose precision.
        let supply = 21_000_000_000u64.saturating_mul(BEAT);
        assert!(supply as u128 > (1u128 << 53));
        // 0.5% acquisition limit must equal supply/200 exactly.
        let tracker = AcquisitionTracker::new();
        let exact_limit = (supply as u128 / 200) as u64;
        assert!(tracker
            .check_acquisition("e", exact_limit, supply, 1000.0, "genesis")
            .is_ok());
        assert!(tracker
            .check_acquisition("e", exact_limit + 1, supply, 1000.0, "genesis")
            .is_err());
        // 0.1% large-mint threshold must equal supply/1000 exactly.
        let exact_thresh = (supply as u128 / 1000) as u64;
        assert!(!VestingManager::requires_vesting(exact_thresh, supply));
        assert!(VestingManager::requires_vesting(exact_thresh + 1, supply));
        // Linear vesting of a >2^53 grant: at exactly half the duration the
        // integer release is total/2 (no f64 precision loss).
        let grant = 5_000_000_000u64.saturating_mul(BEAT);
        let entry = VestingEntry::new("r".into(), grant, 1000.0);
        let half_secs = (VESTING_DURATION_SECS_INT / 2) as f64;
        assert_eq!(
            entry.unlocked(1000.0 + half_secs),
            (grant as u128 / 2) as u64
        );
    }

    // ─── Acquisition Tracker Tests ───────────────────────────────────────

    #[test]
    fn test_acquisition_within_limit() {
        let tracker = AcquisitionTracker::new();
        // Circulating = 1B beat. Limit = 0.5% = 5M beat per 30 days.
        let circulating = 1_000_000_000 * BEAT;
        let result =
            tracker.check_acquisition("alice", 4_000_000 * BEAT, circulating, 1000.0, "genesis");
        assert!(result.is_ok());
    }

    #[test]
    fn test_acquisition_exceeds_limit() {
        let tracker = AcquisitionTracker::new();
        // Circulating = 1B beat. Limit = 5M beat. Try 6M.
        let circulating = 1_000_000_000 * BEAT;
        let result =
            tracker.check_acquisition("alice", 6_000_000 * BEAT, circulating, 1000.0, "genesis");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("acquisition velocity exceeded"));
    }

    #[test]
    fn test_acquisition_cumulative_in_window() {
        let mut tracker = AcquisitionTracker::new();
        let circulating = 1_000_000_000 * BEAT; // limit = 5M

        // Alice received 3M at t=1000
        tracker.record_inflow("alice", 3_000_000 * BEAT, 1000.0);

        // Try another 3M at t=2000 → 6M > 5M limit
        let result =
            tracker.check_acquisition("alice", 3_000_000 * BEAT, circulating, 2000.0, "genesis");
        assert!(result.is_err());

        // But 1.5M should work → 4.5M < 5M
        let result =
            tracker.check_acquisition("alice", 1_500_000 * BEAT, circulating, 2000.0, "genesis");
        assert!(result.is_ok());
    }

    #[test]
    fn test_acquisition_window_expiry() {
        let mut tracker = AcquisitionTracker::new();
        let circulating = 1_000_000_000 * BEAT;

        // Alice received 4.5M at t=1000
        tracker.record_inflow("alice", 4_500_000 * BEAT, 1000.0);

        // 31 days later, window expired
        let future = 1000.0 + ACQUISITION_WINDOW_SECS + 1.0;
        let result =
            tracker.check_acquisition("alice", 4_500_000 * BEAT, circulating, future, "genesis");
        assert!(result.is_ok());
    }

    #[test]
    fn test_acquisition_genesis_exempt() {
        let mut tracker = AcquisitionTracker::new();
        let circulating = 1_000_000_000 * BEAT;

        // Even with massive prior inflows, genesis is exempt
        tracker.record_inflow("genesis", 500_000_000 * BEAT, 1000.0);
        let result = tracker.check_acquisition(
            "genesis",
            500_000_000 * BEAT,
            circulating,
            2000.0,
            "genesis",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_acquisition_below_activation_threshold() {
        let tracker = AcquisitionTracker::new();
        // Below 1M beat circulating — no limit (too early)
        let circulating = 500_000 * BEAT;
        let result = tracker.check_acquisition("alice", 400_000 * BEAT, circulating, 1000.0, "genesis");
        assert!(result.is_ok());
    }

    #[test]
    fn test_acquisition_independent_identities() {
        let mut tracker = AcquisitionTracker::new();
        let circulating = 1_000_000_000 * BEAT; // limit = 5M each

        tracker.record_inflow("alice", 4_500_000 * BEAT, 1000.0);

        // Alice near limit
        let result =
            tracker.check_acquisition("alice", 1_000_000 * BEAT, circulating, 2000.0, "genesis");
        assert!(result.is_err());

        // Bob has no inflows
        let result =
            tracker.check_acquisition("bob", 4_000_000 * BEAT, circulating, 2000.0, "genesis");
        assert!(result.is_ok());
    }

    #[test]
    fn test_acquisition_prune() {
        let mut tracker = AcquisitionTracker::new();
        tracker.record_inflow("alice", 1000 * BEAT, 100.0);
        tracker.record_inflow("bob", 2000 * BEAT, 200.0);

        assert_eq!(tracker.tracked_identities(), 2);

        let future = 200.0 + ACQUISITION_WINDOW_SECS + 1.0;
        tracker.prune(future);
        assert_eq!(tracker.tracked_identities(), 0);
    }

    // ─── Vesting Tests ───────────────────────────────────────────────────

    #[test]
    fn test_vesting_requires_large_mint() {
        let supply = 1_000_000_000 * BEAT; // 1B
        // 0.1% of 1B = 1M. Amounts > 1M trigger vesting.
        assert!(!VestingManager::requires_vesting(1_000_000 * BEAT, supply)); // exactly at threshold
        assert!(VestingManager::requires_vesting(1_000_001 * BEAT, supply)); // 1 micro over
        assert!(!VestingManager::requires_vesting(500_000 * BEAT, supply));
    }

    #[test]
    fn test_vesting_zero_supply() {
        // First mint: no vesting required regardless of amount
        assert!(!VestingManager::requires_vesting(1_000_000 * BEAT, 0));
    }

    #[test]
    fn test_vesting_linear_unlock() {
        let entry = VestingEntry::new("mint-1".into(), 365_000 * BEAT, 0.0);

        // t=0: nothing unlocked
        assert_eq!(entry.unlocked(0.0), 0);
        assert_eq!(entry.locked(0.0), 365_000 * BEAT);

        // Halfway (182.5 days)
        let half = VESTING_DURATION_SECS / 2.0;
        let unlocked_half = entry.unlocked(half);
        // Should be ~182,500 beat (half of 365K)
        assert!(unlocked_half > 182_000 * BEAT);
        assert!(unlocked_half < 183_000 * BEAT);

        // Fully vested (365 days)
        assert_eq!(entry.unlocked(VESTING_DURATION_SECS), 365_000 * BEAT);
        assert_eq!(entry.locked(VESTING_DURATION_SECS), 0);

        // Past vesting
        assert_eq!(entry.unlocked(VESTING_DURATION_SECS + 1000.0), 365_000 * BEAT);
        assert!(entry.is_fully_vested(VESTING_DURATION_SECS));
    }

    #[test]
    fn test_vesting_manager_locked_balance() {
        let mut mgr = VestingManager::new();
        mgr.add_vesting("alice", "mint-1".into(), 1_000_000 * BEAT, 0.0);
        mgr.add_vesting("alice", "mint-2".into(), 500_000 * BEAT, 0.0);

        // At t=0, all locked
        assert_eq!(mgr.locked_balance("alice", 0.0), 1_500_000 * BEAT);

        // After full vesting, nothing locked
        let after = VESTING_DURATION_SECS + 1.0;
        assert_eq!(mgr.locked_balance("alice", after), 0);
    }

    #[test]
    fn test_vesting_transferable_balance() {
        let mut mgr = VestingManager::new();
        mgr.add_vesting("alice", "mint-1".into(), 1_000_000 * BEAT, 0.0);

        // Alice has 1.5M available, 1M locked → 500K transferable
        let transferable = mgr.transferable_balance("alice", 1_500_000 * BEAT, 0.0);
        assert_eq!(transferable, 500_000 * BEAT);

        // After full vesting, all 1.5M transferable
        let after = VESTING_DURATION_SECS + 1.0;
        let transferable = mgr.transferable_balance("alice", 1_500_000 * BEAT, after);
        assert_eq!(transferable, 1_500_000 * BEAT);
    }

    #[test]
    fn test_vesting_prune_completed() {
        let mut mgr = VestingManager::new();
        mgr.add_vesting("alice", "mint-1".into(), 1_000_000 * BEAT, 0.0);
        assert_eq!(mgr.active_vestings(), 1);

        // After full vesting, prune removes it
        mgr.prune(VESTING_DURATION_SECS + 1.0);
        assert_eq!(mgr.active_vestings(), 0);
    }

    #[test]
    fn test_vesting_no_identity() {
        let mgr = VestingManager::new();
        // Unknown identity has no locked balance
        assert_eq!(mgr.locked_balance("unknown", 1000.0), 0);
        assert_eq!(mgr.transferable_balance("unknown", 100 * BEAT, 1000.0), 100 * BEAT);
    }

    #[test]
    fn test_vesting_partial_unlock_transferable() {
        let mut mgr = VestingManager::new();
        // 365K beat vested at t=0 → unlocks ~1K/day
        mgr.add_vesting("alice", "mint-1".into(), 365_000 * BEAT, 0.0);

        // At day 100: ~100K unlocked, ~265K locked
        let day_100 = 100.0 * 24.0 * 3600.0;
        let locked = mgr.locked_balance("alice", day_100);
        assert!(locked > 264_000 * BEAT);
        assert!(locked < 266_000 * BEAT);

        // With 400K available: transferable = 400K - ~265K = ~135K
        let transferable = mgr.transferable_balance("alice", 400_000 * BEAT, day_100);
        assert!(transferable > 134_000 * BEAT);
        assert!(transferable < 136_000 * BEAT);
    }

    // ─── Split-Mint Bypass Prevention Tests (§13.4) ───────────────────────

    #[test]
    fn test_cumulative_split_mint_detection() {
        let mut mgr = VestingManager::new();
        let supply = 1_000_000_000 * BEAT; // 1B beat, threshold = 1M beat

        // First mint: 500K (below 0.1% threshold individually)
        mgr.record_mint("alice", 500_000 * BEAT, 1000.0);
        assert!(!mgr.cumulative_exceeds_threshold("alice", 400_000 * BEAT, supply, 2000.0));

        // Cumulative: 500K + 600K = 1.1M > 1M threshold → should trigger
        assert!(mgr.cumulative_exceeds_threshold("alice", 600_000 * BEAT, supply, 2000.0));
    }

    #[test]
    fn test_cumulative_window_expiry() {
        let mut mgr = VestingManager::new();
        let supply = 1_000_000_000 * BEAT;

        // Mint 900K at t=1000
        mgr.record_mint("alice", 900_000 * BEAT, 1000.0);

        // Within 30 days: 900K + 200K = 1.1M > 1M → triggers
        assert!(mgr.cumulative_exceeds_threshold("alice", 200_000 * BEAT, supply, 2000.0));

        // After 30 days: old mint expired, 200K alone < 1M → doesn't trigger
        let after = 1000.0 + ACQUISITION_WINDOW_SECS + 1.0;
        assert!(!mgr.cumulative_exceeds_threshold("alice", 200_000 * BEAT, supply, after));
    }

    #[test]
    fn test_cumulative_independent_identities() {
        let mut mgr = VestingManager::new();
        let supply = 1_000_000_000 * BEAT;

        // Alice mints 800K
        mgr.record_mint("alice", 800_000 * BEAT, 1000.0);

        // Bob's cumulative is independent — 300K doesn't trigger for Bob
        assert!(!mgr.cumulative_exceeds_threshold("bob", 300_000 * BEAT, supply, 2000.0));
        // But it does trigger for Alice (800K + 300K = 1.1M)
        assert!(mgr.cumulative_exceeds_threshold("alice", 300_000 * BEAT, supply, 2000.0));
    }

    #[test]
    fn test_cumulative_prune() {
        let mut mgr = VestingManager::new();
        mgr.record_mint("alice", 500_000 * BEAT, 100.0);
        mgr.record_mint("alice", 300_000 * BEAT, 200.0);

        // Prune after 30 days — both records gone
        let after = 200.0 + ACQUISITION_WINDOW_SECS + 1.0;
        mgr.prune(after);
        assert!(mgr.cumulative_mints.is_empty());
    }

    #[test]
    fn test_cumulative_zero_supply() {
        let mgr = VestingManager::new();
        // Zero supply → no threshold → cumulative never triggers
        assert!(!mgr.cumulative_exceeds_threshold("alice", 1_000_000 * BEAT, 0, 1000.0));
    }

    // ── acquisition + vesting constant tests (economics §13.2) ──────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_acquisition_vesting_constants_strict_pin_with_structural_relations() {
        // Strict const values.
        assert_eq!(ACQUISITION_WINDOW_SECS, 30.0 * 24.0 * 3600.0);
        assert_eq!(MAX_ACQUISITION_RATE, 0.005);
        assert_eq!(LARGE_MINT_THRESHOLD, 0.001);
        assert_eq!(VESTING_DURATION_SECS, 365.0 * 24.0 * 3600.0);
        assert_eq!(ACQUISITION_LIMIT_ACTIVATION, 1_000_000 * crate::accounting::types::BASE_UNITS_PER_BEAT);
        // Arithmetic-literal cross-check (3600s/hr * 24 hr/day).
        assert_eq!(ACQUISITION_WINDOW_SECS, 2_592_000.0);
        assert_eq!(VESTING_DURATION_SECS, 31_536_000.0);
        // Structural: MAX_RATE = 5 * LARGE_MINT (acquisition velocity 5x stricter than mint
        // threshold — sustained inflow caps must dwarf single-mint thresholds).
        assert!((MAX_ACQUISITION_RATE - 5.0 * LARGE_MINT_THRESHOLD).abs() < 1e-12);
        // VESTING is ~12.17 windows long (365/30).
        let ratio = VESTING_DURATION_SECS / ACQUISITION_WINDOW_SECS;
        assert!((ratio - (365.0 / 30.0)).abs() < 1e-9);
        // Both fractions in (0, 1).
        assert!(MAX_ACQUISITION_RATE > 0.0 && MAX_ACQUISITION_RATE < 1.0);
        assert!(LARGE_MINT_THRESHOLD > 0.0 && LARGE_MINT_THRESHOLD < 1.0);
    }

    #[test]
    fn batch_b_acquisition_tracker_new_equals_default_with_empty_state_and_inflow_tracking() {
        let t_new = AcquisitionTracker::new();
        let t_def = AcquisitionTracker::default();
        // Both empty at construction.
        assert_eq!(t_new.tracked_identities(), 0);
        assert_eq!(t_def.tracked_identities(), 0);
        // inflow_in_window on unknown identity returns 0 (not a panic).
        assert_eq!(t_new.inflow_in_window("ghost", 1_000_000.0), 0);
        assert_eq!(t_def.inflow_in_window("ghost", 0.0), 0);
        // Recording an inflow increments tracked_identities by 1 per new identity.
        let mut t = AcquisitionTracker::new();
        t.record_inflow("alice", 100, 1.0);
        assert_eq!(t.tracked_identities(), 1);
        t.record_inflow("alice", 200, 2.0); // same identity → no new tracker
        assert_eq!(t.tracked_identities(), 1);
        t.record_inflow("bob", 50, 3.0);
        assert_eq!(t.tracked_identities(), 2);
        // Inflows in window sum across multiple entries.
        assert_eq!(t.inflow_in_window("alice", 4.0), 300);
    }

    #[test]
    fn batch_b_vesting_entry_new_pins_end_time_with_unlocked_plus_locked_invariant() {
        let entry = VestingEntry::new("mint_42".to_string(), 1_000_000, 1000.0);
        // Pin end_time = start + VESTING_DURATION_SECS.
        assert_eq!(entry.start_time, 1000.0);
        assert_eq!(entry.end_time, 1000.0 + VESTING_DURATION_SECS);
        assert_eq!(entry.total_amount, 1_000_000);
        assert_eq!(entry.record_id, "mint_42");
        // Mathematical invariant: unlocked(t) + locked(t) == total_amount, for any t.
        let timestamps = [
            0.0,                                            // before start
            1000.0,                                         // exactly start
            1000.0 + VESTING_DURATION_SECS / 4.0,            // 25%
            1000.0 + VESTING_DURATION_SECS / 2.0,            // 50% midpoint
            1000.0 + VESTING_DURATION_SECS * 3.0 / 4.0,      // 75%
            1000.0 + VESTING_DURATION_SECS,                  // exactly end
            1000.0 + VESTING_DURATION_SECS * 2.0,            // far future
        ];
        for t in timestamps {
            let u = entry.unlocked(t);
            let l = entry.locked(t);
            // ±1 tolerance for floor() rounding in (amount * fraction) as u64.
            let sum = u.saturating_add(l);
            assert!(
                sum == entry.total_amount || sum + 1 == entry.total_amount,
                "unlocked+locked invariant broken at t={t}: u={u} l={l} sum={sum}"
            );
        }
        // is_fully_vested true at end_time, false strictly before.
        assert!(entry.is_fully_vested(entry.end_time));
        assert!(entry.is_fully_vested(entry.end_time + 1.0));
        assert!(!entry.is_fully_vested(entry.end_time - 1.0));
        // unlocked(before_start) == 0.
        assert_eq!(entry.unlocked(0.0), 0);
        assert_eq!(entry.unlocked(500.0), 0);
        // unlocked(at_or_after_end) == total.
        assert_eq!(entry.unlocked(entry.end_time), 1_000_000);
        assert_eq!(entry.unlocked(entry.end_time + 100.0), 1_000_000);
    }

    #[test]
    fn batch_b_vesting_manager_requires_vesting_strict_greater_than_boundary() {
        let supply = 1_000_000_000u64 * BEAT;
        let threshold = (supply as f64 * LARGE_MINT_THRESHOLD) as u64;
        // STRICT GREATER-THAN: at exactly threshold, requires_vesting returns FALSE.
        // (The function uses `amount > threshold`, not `>=`.) This is load-bearing for
        // mint-sizing UX — operators want to hit threshold exactly without triggering vesting.
        assert!(!VestingManager::requires_vesting(threshold, supply));
        // At threshold+1 → TRUE.
        assert!(VestingManager::requires_vesting(threshold + 1, supply));
        // Far above threshold → TRUE.
        assert!(VestingManager::requires_vesting(threshold * 10, supply));
        // Far below threshold → FALSE.
        assert!(!VestingManager::requires_vesting(threshold / 2, supply));
        assert!(!VestingManager::requires_vesting(1, supply));
        // Zero amount → FALSE (0 > anything is false).
        assert!(!VestingManager::requires_vesting(0, supply));
        // Zero supply → FALSE regardless of amount (early-return guard).
        assert!(!VestingManager::requires_vesting(threshold + 1, 0));
        assert!(!VestingManager::requires_vesting(u64::MAX, 0));
    }

    #[test]
    fn batch_b_vesting_manager_new_equals_default_with_clone_independence() {
        let m_new = VestingManager::new();
        let m_def = VestingManager::default();
        assert!(m_new.schedules.is_empty());
        assert!(m_def.schedules.is_empty());
        assert!(m_new.cumulative_mints.is_empty());
        assert!(m_def.cumulative_mints.is_empty());
        // Locked balance on empty manager returns 0 for any identity/time.
        assert_eq!(m_new.locked_balance("ghost", 1_000_000.0), 0);
        assert_eq!(m_def.locked_balance("ghost", 0.0), 0);
        // Clone independence: mutating a clone doesn't bleed back to original.
        let mut original = VestingManager::new();
        original.record_mint("alice", 100, 1.0);
        let mut cloned = original.clone();
        cloned.record_mint("alice", 999, 2.0);
        // Original still has only 1 mint for alice; clone has 2.
        let supply = 1_000_000u64 * BEAT;
        assert!(original.cumulative_exceeds_threshold("alice", 0, supply, 2.5)
            != cloned.cumulative_exceeds_threshold("alice", 0, supply, 2.5)
            || original.cumulative_mints.get("alice").unwrap().len()
                != cloned.cumulative_mints.get("alice").unwrap().len());
    }
}
