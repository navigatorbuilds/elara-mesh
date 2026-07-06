//! Transfer velocity limits — per-identity outflow throttling.
//!
//! economics v0.4.1 Section 13.3 — 5 velocity tiers:
//! - Balance < 100K beat: 100% (no limit, instant liquidation)
//! - Balance 100K-1M beat: 50% per day (2 days to liquidate)
//! - Balance 1M-10M beat: 10% per day (10 days to liquidate)
//! - Balance 10M-100M beat: 3% per day (34 days to liquidate)
//! - Balance 100M+ beat: 1% per day (100 days to liquidate)
//!
//! Basis: max(current_balance, peak_balance_30d) — prevents Sybil-split bypass.
//! Multi-hop laundering defense (§13.6): velocity follows money, not current balance.
//! Each hop is throttled at the receiving amount's tier via peak-balance tracking.

//!
//! Spec references:
//!   @spec economics §13.3

use std::collections::HashMap;

use crate::errors::{ElaraError, Result};
use crate::accounting::types::BASE_UNITS_PER_BEAT;

// ─── Constants (economics v0.4.1 Section 13.3) ─────────────────────────────

/// Velocity window: 24 hours in seconds.
pub const VELOCITY_WINDOW_SECS: f64 = 24.0 * 3600.0;

/// Peak balance lookback: 30 days in seconds.
pub const PEAK_BALANCE_WINDOW_SECS: f64 = 30.0 * 24.0 * 3600.0;

/// Tier boundaries (inclusive lower bound).
/// < 100K beat: no velocity limit.
pub const TIER_FREE_CEILING: u64 = 100_000 * BASE_UNITS_PER_BEAT;
/// 100K-1M beat: 50% per day (2 days to liquidate).
pub const TIER_LOW_CEILING: u64 = 1_000_000 * BASE_UNITS_PER_BEAT;
/// 1M-10M beat: 10% per day (10 days to liquidate).
pub const TIER_MID_CEILING: u64 = 10_000_000 * BASE_UNITS_PER_BEAT;
/// 10M-100M beat: 3% per day (34 days to liquidate).
pub const TIER_HIGH_CEILING: u64 = 100_000_000 * BASE_UNITS_PER_BEAT;
// 100M+ beat: 1% per day (100 days to liquidate) — no upper ceiling constant needed.

/// Per-tier daily outbound rate.
pub const RATE_FREE: f64 = 1.0;       // <100K: no limit
pub const RATE_LOW: f64 = 0.50;       // 100K-1M: 50%/day
pub const RATE_MID: f64 = 0.10;       // 1M-10M: 10%/day
pub const RATE_HIGH: f64 = 0.03;      // 10M-100M: 3%/day
pub const RATE_MEGA: f64 = 0.01;      // 100M+: 1%/day

// ── Fixed-point rates (consensus gate) ───────────────────────────────────────
// The accept/reject gate runs inside `apply_op` on EVERY node, so it must be
// bit-identical across architectures. `effective_balance as f64 * rate` is NOT:
// the rate constants 0.10/0.03/0.01 are not exactly representable in IEEE-754,
// and `balance as f64` loses integer precision once balance > 2^53 (reachable
// at ≥100M-beat holders). The `_Q` integer twins below remove both hazards,
// sharing the 1e9 discipline of SETTLEMENT_Q / CONVICTION_Q / IDLE_DECAY_Q.
// See internal design notes.

/// Fixed-point scale: a `_q` value of `VELOCITY_Q` represents the fraction 1.0.
pub const VELOCITY_Q: u128 = 1_000_000_000;
pub const RATE_LOW_Q: u128 = 500_000_000; // 0.50
pub const RATE_MID_Q: u128 = 100_000_000; // 0.10
pub const RATE_HIGH_Q: u128 = 30_000_000; // 0.03
pub const RATE_MEGA_Q: u128 = 10_000_000; // 0.01

// ── Backwards-compatible aliases (used by external code) ─────────────────────
#[deprecated(note = "use TIER_FREE_CEILING")]
pub const TIER_1_THRESHOLD: u64 = TIER_FREE_CEILING;
#[deprecated(note = "use TIER_MID_CEILING")]
pub const TIER_2_THRESHOLD: u64 = TIER_MID_CEILING;
#[deprecated(note = "use TIER_HIGH_CEILING")]
pub const TIER_3_THRESHOLD: u64 = TIER_HIGH_CEILING;
#[deprecated(note = "use RATE_MID")]
pub const TIER_1_RATE: f64 = RATE_MID;
#[deprecated(note = "use RATE_HIGH")]
pub const TIER_2_RATE: f64 = RATE_HIGH;
#[deprecated(note = "use RATE_MEGA")]
pub const TIER_3_RATE: f64 = RATE_MEGA;

// ─── Types ───────────────────────────────────────────────────────────────────

/// Per-identity velocity tracking state.
#[derive(Debug, Clone, Default)]
struct IdentityVelocity {
    /// Recent outflows: (timestamp, amount) pairs.
    outflows: Vec<(f64, u64)>,
    /// Balance observations for peak tracking: (timestamp, total_balance).
    balance_history: Vec<(f64, u64)>,
}

/// Network-wide velocity tracker.
///
/// Tracks per-identity outflows and peak balances to enforce
/// transfer velocity limits from economics v0.4.1.
#[derive(Debug, Clone, Default)]
pub struct VelocityTracker {
    identities: HashMap<String, IdentityVelocity>,
}

impl VelocityTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an outflow (transfer send).
    pub fn record_outflow(&mut self, identity: &str, amount: u64, timestamp: f64) {
        let entry = self.identities.entry(identity.to_string()).or_default();
        entry.outflows.push((timestamp, amount));
    }

    /// Record a balance observation (call after any balance change).
    /// `total_balance` = available + staked.
    pub fn record_balance(&mut self, identity: &str, total_balance: u64, timestamp: f64) {
        let entry = self.identities.entry(identity.to_string()).or_default();
        entry.balance_history.push((timestamp, total_balance));
    }

    /// Sum outflows in the last 24h from the given timestamp.
    pub fn outflow_in_window(&self, identity: &str, now: f64) -> u64 {
        let cutoff = now - VELOCITY_WINDOW_SECS;
        match self.identities.get(identity) {
            Some(v) => v
                .outflows
                .iter()
                .filter(|(ts, _)| *ts > cutoff)
                .map(|(_, amt)| *amt)
                .fold(0u64, |acc, x| acc.saturating_add(x)),
            None => 0,
        }
    }

    /// Peak total balance in the last 30 days.
    pub fn peak_balance(&self, identity: &str, now: f64) -> u64 {
        let cutoff = now - PEAK_BALANCE_WINDOW_SECS;
        match self.identities.get(identity) {
            Some(v) => v
                .balance_history
                .iter()
                .filter(|(ts, _)| *ts > cutoff)
                .map(|(_, bal)| *bal)
                .max()
                .unwrap_or(0),
            None => 0,
        }
    }

    /// Sum outflows in a custom window (for governance decay: 30 days).
    pub fn outflow_in_custom_window(&self, identity: &str, now: f64, window_secs: f64) -> u64 {
        let cutoff = now - window_secs;
        match self.identities.get(identity) {
            Some(v) => v
                .outflows
                .iter()
                .filter(|(ts, _)| *ts > cutoff)
                .map(|(_, amt)| *amt)
                .fold(0u64, |acc, x| acc.saturating_add(x)),
            None => 0,
        }
    }

    /// Peak total balance in a custom window (for governance decay: 90 days).
    pub fn peak_balance_in_window(&self, identity: &str, now: f64, window_secs: f64) -> u64 {
        let cutoff = now - window_secs;
        match self.identities.get(identity) {
            Some(v) => v
                .balance_history
                .iter()
                .filter(|(ts, _)| *ts > cutoff)
                .map(|(_, bal)| *bal)
                .max()
                .unwrap_or(0),
            None => 0,
        }
    }

    /// Check if a proposed outflow would exceed velocity limits.
    ///
    /// `current_total` = available + staked (before this transfer).
    /// `velocity_multiplier` = scaling factor from circuit breaker (1.0 normal, 0.5 at L1/L2).
    /// Returns Ok(()) if allowed, Err if velocity limit exceeded.
    pub fn check_velocity(
        &self,
        identity: &str,
        amount: u64,
        current_total: u64,
        timestamp: f64,
        velocity_multiplier: f64,
    ) -> Result<()> {
        let peak = self.peak_balance(identity, timestamp);
        let effective_balance = current_total.max(peak);

        // Below 100K beat: no velocity limit
        if effective_balance < TIER_FREE_CEILING {
            return Ok(());
        }

        // Integer gate (see VELOCITY_Q note above): base_limit = balance × rate,
        // computed in u128 fixed-point so it is bit-identical on every arch.
        let rate_q = velocity_rate_q(effective_balance);
        let base_limit = (effective_balance as u128).saturating_mul(rate_q) / VELOCITY_Q;
        // The circuit-breaker × exchange multiplier is always an exact dyadic
        // fraction in {0, 0.25, 0.5, 1.0}; `× VELOCITY_Q` (=1e9, < 2^53) is exact
        // and bit-identical across IEEE-754 platforms, so converting it here keeps
        // the gate deterministic without threading an integer through every caller.
        debug_assert!(
            (0.0..=1.0).contains(&velocity_multiplier)
                && (velocity_multiplier * VELOCITY_Q as f64).fract() == 0.0,
            "velocity_multiplier must be an exact dyadic fraction in [0,1]"
        );
        let mult_q = (velocity_multiplier * VELOCITY_Q as f64) as u128;
        let limit = base_limit.saturating_mul(mult_q) / VELOCITY_Q;
        let already_sent = self.outflow_in_window(identity, timestamp) as u128;
        let total_outflow = already_sent.saturating_add(amount as u128);

        if total_outflow > limit {
            let remaining = limit.saturating_sub(already_sent);
            let base_units = BASE_UNITS_PER_BEAT as u128;
            return Err(ElaraError::Ledger(format!(
                "velocity limit exceeded: {:.0}% daily cap for balance tier{}. \
                 already sent {} beat in 24h, proposed {} beat, limit {} beat, \
                 remaining allowance {} beat",
                velocity_rate(effective_balance) * 100.0 * velocity_multiplier,
                if velocity_multiplier < 1.0 { " (circuit breaker active)" } else { "" },
                already_sent / base_units,
                amount as u128 / base_units,
                limit / base_units,
                remaining / base_units,
            )));
        }

        Ok(())
    }

    /// Prune entries older than their respective windows.
    /// Call periodically to prevent unbounded memory growth.
    pub fn prune(&mut self, now: f64) {
        let outflow_cutoff = now - VELOCITY_WINDOW_SECS;
        let balance_cutoff = now - PEAK_BALANCE_WINDOW_SECS;

        for entry in self.identities.values_mut() {
            entry.outflows.retain(|(ts, _)| *ts > outflow_cutoff);
            entry
                .balance_history
                .retain(|(ts, _)| *ts > balance_cutoff);
        }

        self.identities
            .retain(|_, v| !v.outflows.is_empty() || !v.balance_history.is_empty());
    }

    /// Number of tracked identities (for diagnostics).
    pub fn tracked_identities(&self) -> usize {
        self.identities.len()
    }
}

/// Compute the velocity rate for a given effective balance.
/// Returns the fraction of balance allowed to be transferred per 24h.
///
/// economics v0.4.1 §13.3 — 5 tiers:
/// - <100K: 100%, 100K-1M: 50%, 1M-10M: 10%, 10M-100M: 3%, 100M+: 1%
pub fn velocity_rate(balance: u64) -> f64 {
    if balance >= TIER_HIGH_CEILING {
        RATE_MEGA       // 100M+: 1%/day
    } else if balance >= TIER_MID_CEILING {
        RATE_HIGH       // 10M-100M: 3%/day
    } else if balance >= TIER_LOW_CEILING {
        RATE_MID        // 1M-10M: 10%/day
    } else if balance >= TIER_FREE_CEILING {
        RATE_LOW        // 100K-1M: 50%/day
    } else {
        RATE_FREE       // <100K: no limit
    }
}

/// Fixed-point per-tier daily rate (fraction × [`VELOCITY_Q`]). Integer twin of
/// [`velocity_rate`], used by the consensus accept/reject gate in `check_velocity`
/// so the decision is bit-identical across architectures.
pub fn velocity_rate_q(balance: u64) -> u128 {
    if balance >= TIER_HIGH_CEILING {
        RATE_MEGA_Q // 100M+: 1%/day
    } else if balance >= TIER_MID_CEILING {
        RATE_HIGH_Q // 10M-100M: 3%/day
    } else if balance >= TIER_LOW_CEILING {
        RATE_MID_Q // 1M-10M: 10%/day
    } else if balance >= TIER_FREE_CEILING {
        RATE_LOW_Q // 100K-1M: 50%/day
    } else {
        VELOCITY_Q // <100K: 1.0 (caller early-returns before reaching here)
    }
}

/// Compute the daily outflow limit in base units for a given balance.
pub fn daily_limit(balance: u64) -> u64 {
    if balance < TIER_FREE_CEILING {
        balance // no limit — can send everything
    } else {
        (balance as f64 * velocity_rate(balance)) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BEAT: u64 = BASE_UNITS_PER_BEAT;

    #[test]
    fn velocity_gate_is_exact_integer_above_2pow53() {
        // 200M beat = 2e17 base units > 2^53 — the regime where `balance as f64`
        // loses integer precision and the old f64 gate could fork across arch.
        // The integer gate must land on the exact rational boundary: MEGA tier
        // (≥100M beat) is 1%/day, so limit = balance / 100 exactly, multiplier 1.0.
        let bal = 200_000_000u64 * BEAT;
        assert!(bal as u128 > (1u128 << 53), "test balance must exceed 2^53");
        let exact_limit = (bal as u128 / 100) as u64;
        let tracker = VelocityTracker::new();
        // Exactly at the limit is allowed (gate is strict `>`).
        assert!(tracker
            .check_velocity("whale", exact_limit, bal, 1000.0, 1.0)
            .is_ok());
        // One base-unit over the exact integer limit is rejected.
        assert!(tracker
            .check_velocity("whale", exact_limit + 1, bal, 1000.0, 1.0)
            .is_err());
        // Half multiplier (circuit breaker / exchange) halves the limit exactly.
        assert!(tracker
            .check_velocity("whale", exact_limit / 2, bal, 1000.0, 0.5)
            .is_ok());
        assert!(tracker
            .check_velocity("whale", exact_limit / 2 + 1, bal, 1000.0, 0.5)
            .is_err());
    }

    // ── Free tier (<100K): no limit ──────────────────────────────────────────

    #[test]
    fn test_free_tier_no_limit() {
        let tracker = VelocityTracker::new();
        // 50K beat — below 100K threshold, can send everything
        let result = tracker.check_velocity("alice", 50_000 * BEAT, 50_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_free_tier_send_everything() {
        let tracker = VelocityTracker::new();
        // 99,999 beat — just below threshold, can send all
        let result = tracker.check_velocity("alice", 99_999 * BEAT, 99_999 * BEAT, 1000.0, 1.0);
        assert!(result.is_ok());
    }

    // ── Low tier (100K-1M): 50%/day ─────────────────────────────────────────

    #[test]
    fn test_low_tier_within_limit() {
        let tracker = VelocityTracker::new();
        // 500K beat balance, 50% = 250K max/day
        let result = tracker.check_velocity("alice", 240_000 * BEAT, 500_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_low_tier_exceeds_limit() {
        let tracker = VelocityTracker::new();
        // 500K beat balance, 50% = 250K max, try 260K
        let result = tracker.check_velocity("alice", 260_000 * BEAT, 500_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("velocity limit exceeded"));
    }

    #[test]
    fn test_low_tier_boundary_100k() {
        let tracker = VelocityTracker::new();
        // Exactly 100K beat — enters low tier, 50% = 50K max
        let result = tracker.check_velocity("alice", 50_000 * BEAT, 100_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_ok());

        let result = tracker.check_velocity("alice", 50_001 * BEAT, 100_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_low_tier_liquidation_2_days() {
        // 500K beat, 50%/day → day 1: send 250K, day 2: send remaining
        let mut tracker = VelocityTracker::new();
        let balance = 500_000 * BEAT;

        // Day 1: send 250K
        let result = tracker.check_velocity("alice", 250_000 * BEAT, balance, 1000.0, 1.0);
        assert!(result.is_ok());
        tracker.record_outflow("alice", 250_000 * BEAT, 1000.0);
        tracker.record_balance("alice", balance, 1000.0);

        // Day 1: can't send more
        let result = tracker.check_velocity("alice", BEAT, balance, 1001.0, 1.0);
        assert!(result.is_err());

        // Day 2: window expired, can send again (balance still counts from peak)
        let day2 = 1000.0 + VELOCITY_WINDOW_SECS + 1.0;
        let result = tracker.check_velocity("alice", 250_000 * BEAT, 250_000 * BEAT, day2, 1.0);
        assert!(result.is_ok());
    }

    // ── Mid tier (1M-10M): 10%/day ──────────────────────────────────────────

    #[test]
    fn test_mid_tier_within_limit() {
        let tracker = VelocityTracker::new();
        // 5M beat balance, 10% = 500K max/day
        let result =
            tracker.check_velocity("alice", 490_000 * BEAT, 5_000_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_mid_tier_exceeds_limit() {
        let tracker = VelocityTracker::new();
        // 5M beat balance, 10% = 500K max, try 600K
        let result =
            tracker.check_velocity("alice", 600_000 * BEAT, 5_000_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_mid_tier_boundary_1m() {
        let tracker = VelocityTracker::new();
        // Exactly 1M beat — enters mid tier, 10% = 100K max
        let result =
            tracker.check_velocity("alice", 100_000 * BEAT, 1_000_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_ok());

        let result =
            tracker.check_velocity("alice", 100_001 * BEAT, 1_000_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_err());
    }

    // ── High tier (10M-100M): 3%/day ────────────────────────────────────────

    #[test]
    fn test_high_tier_within_limit() {
        let tracker = VelocityTracker::new();
        // 50M beat balance, 3% = 1.5M max
        let result =
            tracker.check_velocity("alice", 1_400_000 * BEAT, 50_000_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_high_tier_exceeds_limit() {
        let tracker = VelocityTracker::new();
        // 50M beat balance, 3% = 1.5M max, try 2M
        let result =
            tracker.check_velocity("alice", 2_000_000 * BEAT, 50_000_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_err());
    }

    // ── Mega tier (100M+): 1%/day ───────────────────────────────────────────

    #[test]
    fn test_mega_tier_within_limit() {
        let tracker = VelocityTracker::new();
        // 200M beat balance, 1% = 2M max
        let result =
            tracker.check_velocity("alice", 1_900_000 * BEAT, 200_000_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_mega_tier_exceeds_limit() {
        let tracker = VelocityTracker::new();
        // 200M beat balance, 1% = 2M max, try 3M
        let result =
            tracker.check_velocity("alice", 3_000_000 * BEAT, 200_000_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_err());
    }

    // ── Cumulative & window tests ───────────────────────────────────────────

    #[test]
    fn test_cumulative_outflows_in_window() {
        let mut tracker = VelocityTracker::new();
        let balance = 500_000 * BEAT; // 500K, low tier, 50% = 250K/day

        // Send 200K at t=1000
        tracker.record_outflow("alice", 200_000 * BEAT, 1000.0);

        // Try to send another 60K at t=2000 (same 24h window)
        // 200K + 60K = 260K > 250K limit
        let result = tracker.check_velocity("alice", 60_000 * BEAT, balance, 2000.0, 1.0);
        assert!(result.is_err());

        // But 40K should be fine (200K + 40K = 240K < 250K)
        let result = tracker.check_velocity("alice", 40_000 * BEAT, balance, 2000.0, 1.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_window_expiry() {
        let mut tracker = VelocityTracker::new();
        let balance = 500_000 * BEAT; // 50%/day = 250K

        // Send 240K at t=1000
        tracker.record_outflow("alice", 240_000 * BEAT, 1000.0);

        // At t=1000+86401 (just past 24h), the old outflow expired
        let future = 1000.0 + VELOCITY_WINDOW_SECS + 1.0;
        let result = tracker.check_velocity("alice", 240_000 * BEAT, balance, future, 1.0);
        assert!(result.is_ok());
    }

    // ── Peak-balance anti-splitting (§13.6 multi-hop defense) ───────────────

    #[test]
    fn test_peak_balance_prevents_splitting() {
        let mut tracker = VelocityTracker::new();

        // Alice had 200M beat at t=1000 (mega tier, 1% = 2M/day)
        tracker.record_balance("alice", 200_000_000 * BEAT, 1000.0);

        // Now at t=2000 she split down to 50K (below free tier normally)
        // But peak_30d is still 200M, so mega tier applies
        let result = tracker.check_velocity("alice", 3_000_000 * BEAT, 50_000 * BEAT, 2000.0, 1.0);
        assert!(result.is_err());

        // 2M should work (within 1% of 200M peak)
        let result = tracker.check_velocity("alice", 1_900_000 * BEAT, 50_000 * BEAT, 2000.0, 1.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_peak_balance_window_expiry() {
        let mut tracker = VelocityTracker::new();

        // Alice had 200M at t=1000
        tracker.record_balance("alice", 200_000_000 * BEAT, 1000.0);

        // 31 days later, peak has expired. Current balance 50K = no limit
        let future = 1000.0 + PEAK_BALANCE_WINDOW_SECS + 1.0;
        let result = tracker.check_velocity("alice", 50_000 * BEAT, 50_000 * BEAT, future, 1.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_multihop_laundering_defense() {
        // §13.6: velocity follows money. Intermediate identity that received 50M
        // cannot relay faster than 3%/day = 1.5M/day, even if current balance is low.
        let mut tracker = VelocityTracker::new();

        // Bob is intermediate — received 50M from Alice
        tracker.record_balance("bob", 50_000_000 * BEAT, 1000.0);

        // Bob forwards most to Carol, now has only 100K. But peak is 50M.
        // High tier (10M-100M) → 3%/day of 50M = 1.5M/day max
        let result =
            tracker.check_velocity("bob", 2_000_000 * BEAT, 100_000 * BEAT, 2000.0, 1.0);
        assert!(result.is_err()); // 2M > 1.5M

        let result =
            tracker.check_velocity("bob", 1_400_000 * BEAT, 100_000 * BEAT, 2000.0, 1.0);
        assert!(result.is_ok()); // 1.4M < 1.5M
    }

    // ── Utility functions ───────────────────────────────────────────────────

    #[test]
    fn test_daily_limit_function() {
        assert_eq!(daily_limit(50_000 * BEAT), 50_000 * BEAT);      // free tier: full
        assert_eq!(daily_limit(100_000 * BEAT), 50_000 * BEAT);     // low tier: 50% of 100K
        assert_eq!(daily_limit(500_000 * BEAT), 250_000 * BEAT);    // low tier: 50% of 500K
        assert_eq!(daily_limit(1_000_000 * BEAT), 100_000 * BEAT);  // mid tier: 10% of 1M
        assert_eq!(daily_limit(5_000_000 * BEAT), 500_000 * BEAT);  // mid tier: 10% of 5M
        assert_eq!(daily_limit(50_000_000 * BEAT), 1_500_000 * BEAT); // high tier: 3% of 50M
        assert_eq!(daily_limit(200_000_000 * BEAT), 2_000_000 * BEAT); // mega tier: 1% of 200M
    }

    #[test]
    fn test_velocity_rate_function() {
        // Free tier
        assert_eq!(velocity_rate(50_000 * BEAT), RATE_FREE);
        assert_eq!(velocity_rate(99_999 * BEAT), RATE_FREE);
        // Low tier (100K-1M)
        assert_eq!(velocity_rate(100_000 * BEAT), RATE_LOW);
        assert_eq!(velocity_rate(500_000 * BEAT), RATE_LOW);
        assert_eq!(velocity_rate(999_999 * BEAT), RATE_LOW);
        // Mid tier (1M-10M)
        assert_eq!(velocity_rate(1_000_000 * BEAT), RATE_MID);
        assert_eq!(velocity_rate(5_000_000 * BEAT), RATE_MID);
        assert_eq!(velocity_rate(9_999_999 * BEAT), RATE_MID);
        // High tier (10M-100M)
        assert_eq!(velocity_rate(10_000_000 * BEAT), RATE_HIGH);
        assert_eq!(velocity_rate(50_000_000 * BEAT), RATE_HIGH);
        assert_eq!(velocity_rate(99_999_999 * BEAT), RATE_HIGH);
        // Mega tier (100M+)
        assert_eq!(velocity_rate(100_000_000 * BEAT), RATE_MEGA);
        assert_eq!(velocity_rate(500_000_000 * BEAT), RATE_MEGA);
    }

    // ── Pruning ─────────────────────────────────────────────────────────────

    #[test]
    fn test_prune_removes_old_entries() {
        let mut tracker = VelocityTracker::new();
        tracker.record_outflow("alice", 1000, 100.0);
        tracker.record_balance("alice", 5000, 100.0);
        tracker.record_outflow("alice", 2000, 200.0);

        assert_eq!(tracker.tracked_identities(), 1);

        // Prune at t=100 + 30d + 1 — everything should be gone
        let future = 100.0 + PEAK_BALANCE_WINDOW_SECS + 1.0;
        tracker.prune(future);
        assert_eq!(tracker.tracked_identities(), 0);
    }

    #[test]
    fn test_prune_keeps_recent() {
        let mut tracker = VelocityTracker::new();
        tracker.record_outflow("alice", 1000, 100.0);
        tracker.record_outflow("alice", 2000, 100_000.0);

        tracker.prune(100_001.0);
        assert_eq!(tracker.tracked_identities(), 1);
        assert_eq!(tracker.outflow_in_window("alice", 100_001.0), 2000);
    }

    // ── Multi-identity independence ─────────────────────────────────────────

    #[test]
    fn test_independent_identities() {
        let mut tracker = VelocityTracker::new();
        let balance = 500_000 * BEAT; // low tier, 50% = 250K/day

        tracker.record_outflow("alice", 240_000 * BEAT, 1000.0);
        tracker.record_outflow("bob", 10_000 * BEAT, 1000.0);

        // Alice near limit (240K of 250K used)
        let result = tracker.check_velocity("alice", 20_000 * BEAT, balance, 1001.0, 1.0);
        assert!(result.is_err());

        // Bob has plenty of room
        let result = tracker.check_velocity("bob", 200_000 * BEAT, balance, 1001.0, 1.0);
        assert!(result.is_ok());
    }

    // ── Exact boundary tests ────────────────────────────────────────────────

    #[test]
    fn test_exact_limit_allowed() {
        let tracker = VelocityTracker::new();
        // 100K beat at low tier boundary, 50% = 50K limit
        let result = tracker.check_velocity("alice", 50_000 * BEAT, 100_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_one_over_limit_rejected() {
        let tracker = VelocityTracker::new();
        // 100K beat, 50% = 50K limit, try 50K + 1 micro
        let result =
            tracker.check_velocity("alice", 50_000 * BEAT + 1, 100_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_err());
    }

    // ── Circuit breaker multiplier ──────────────────────────────────────────

    #[test]
    fn test_velocity_multiplier_halves_limit() {
        let tracker = VelocityTracker::new();
        // 500K beat, low tier, 50% = 250K/day. With 0.5 multiplier → 125K/day
        let result =
            tracker.check_velocity("alice", 120_000 * BEAT, 500_000 * BEAT, 1000.0, 0.5);
        assert!(result.is_ok());

        let result =
            tracker.check_velocity("alice", 130_000 * BEAT, 500_000 * BEAT, 1000.0, 0.5);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("circuit breaker active"));
    }

    #[test]
    fn test_velocity_multiplier_zero_blocks_all() {
        let tracker = VelocityTracker::new();
        // With multiplier 0.0, even 1 micro should be blocked
        let result =
            tracker.check_velocity("alice", 1, 500_000 * BEAT, 1000.0, 0.0);
        assert!(result.is_err());
    }

    // ── Cross-tier transition ───────────────────────────────────────────────

    #[test]
    fn test_tier_transition_as_balance_grows() {
        // Verify rates change correctly as balance crosses tier boundaries
        let tracker = VelocityTracker::new();

        // 999,999 beat → low tier (50%)
        let limit_low = daily_limit(999_999 * BEAT);
        assert_eq!(limit_low, ((999_999 * BEAT) as f64 * 0.50) as u64);

        // 1,000,000 beat → mid tier (10%)
        let limit_mid = daily_limit(1_000_000 * BEAT);
        assert_eq!(limit_mid, 100_000 * BEAT);

        // Verify the cliff: mid-tier limit is smaller than low-tier limit
        // at the boundary (500K vs 100K). This is intended — larger balances
        // face proportionally stricter limits.
        assert!(limit_low > limit_mid);

        // Check velocity still works at boundary
        let result =
            tracker.check_velocity("alice", 100_000 * BEAT, 1_000_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_ok());

        let result =
            tracker.check_velocity("alice", 100_001 * BEAT, 1_000_000 * BEAT, 1000.0, 1.0);
        assert!(result.is_err());
    }

    // ─── fixture-free tests ─────────────────────────────────

    #[test]
    fn batch_b_velocity_constants_strict_pin_with_arithmetic_cross_checks() {
        // Window constants — both literal seconds AND structural day-multiples
        assert_eq!(VELOCITY_WINDOW_SECS, 86_400.0);
        assert_eq!(VELOCITY_WINDOW_SECS, 24.0 * 3600.0);
        assert_eq!(PEAK_BALANCE_WINDOW_SECS, 2_592_000.0);
        assert_eq!(PEAK_BALANCE_WINDOW_SECS, 30.0 * 24.0 * 3600.0);
        assert!(
            (PEAK_BALANCE_WINDOW_SECS - 30.0 * VELOCITY_WINDOW_SECS).abs() < 1e-9,
            "peak-balance window must be exactly 30 × velocity window"
        );

        // Tier ceilings — strict literal pin in base units
        assert_eq!(TIER_FREE_CEILING, 100_000 * BASE_UNITS_PER_BEAT);
        assert_eq!(TIER_LOW_CEILING, 1_000_000 * BASE_UNITS_PER_BEAT);
        assert_eq!(TIER_MID_CEILING, 10_000_000 * BASE_UNITS_PER_BEAT);
        assert_eq!(TIER_HIGH_CEILING, 100_000_000 * BASE_UNITS_PER_BEAT);
        assert_eq!(TIER_FREE_CEILING, 100_000_000_000_000_u64);

        // Rate constants — strict literal pin
        assert_eq!(RATE_FREE, 1.0);
        assert_eq!(RATE_LOW, 0.50);
        assert_eq!(RATE_MID, 0.10);
        assert_eq!(RATE_HIGH, 0.03);
        assert_eq!(RATE_MEGA, 0.01);
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_tier_ladder_structural_ten_x_progression_with_rate_strict_ordering() {
        // Ceiling ladder: 100K → 1M → 10M → 100M each step is exactly 10×
        assert_eq!(TIER_LOW_CEILING, 10 * TIER_FREE_CEILING);
        assert_eq!(TIER_MID_CEILING, 10 * TIER_LOW_CEILING);
        assert_eq!(TIER_HIGH_CEILING, 10 * TIER_MID_CEILING);
        // Two-step composition pins
        assert_eq!(TIER_MID_CEILING, 100 * TIER_FREE_CEILING);
        assert_eq!(TIER_HIGH_CEILING, 1_000 * TIER_FREE_CEILING);

        // Rate ladder STRICTLY descending — higher balance, lower rate
        assert!(RATE_FREE > RATE_LOW);
        assert!(RATE_LOW > RATE_MID);
        assert!(RATE_MID > RATE_HIGH);
        assert!(RATE_HIGH > RATE_MEGA);
        // Rate ratios — LOW:MID = 5:1, MID:HIGH ≈ 3.33:1
        assert!((RATE_LOW / RATE_MID - 5.0).abs() < 1e-9, "RATE_LOW must be 5× RATE_MID");
        assert!((RATE_MID / RATE_MEGA - 10.0).abs() < 1e-9, "RATE_MID must be 10× RATE_MEGA");
        assert!((RATE_HIGH / RATE_MEGA - 3.0).abs() < 1e-9, "RATE_HIGH must be 3× RATE_MEGA");
    }

    #[test]
    fn batch_b_velocity_rate_at_exact_tier_boundaries_with_one_below() {
        // velocity_rate at-or-above each ceiling moves to the next tier
        // (inclusive lower-bound semantics in the implementation).
        // At each boundary, rate jumps DOWN to the next tier's rate.

        // <100K boundary
        assert_eq!(velocity_rate(TIER_FREE_CEILING - 1), RATE_FREE);
        assert_eq!(velocity_rate(TIER_FREE_CEILING), RATE_LOW);

        // 100K-1M boundary
        assert_eq!(velocity_rate(TIER_LOW_CEILING - 1), RATE_LOW);
        assert_eq!(velocity_rate(TIER_LOW_CEILING), RATE_MID);

        // 1M-10M boundary
        assert_eq!(velocity_rate(TIER_MID_CEILING - 1), RATE_MID);
        assert_eq!(velocity_rate(TIER_MID_CEILING), RATE_HIGH);

        // 10M-100M boundary
        assert_eq!(velocity_rate(TIER_HIGH_CEILING - 1), RATE_HIGH);
        assert_eq!(velocity_rate(TIER_HIGH_CEILING), RATE_MEGA);

        // Zero balance → free tier rate (degenerate but well-defined)
        assert_eq!(velocity_rate(0), RATE_FREE);
        // u64::MAX → mega rate (no overflow)
        assert_eq!(velocity_rate(u64::MAX), RATE_MEGA);
    }

    #[test]
    fn batch_b_daily_limit_identity_balance_times_rate_at_tier_boundaries() {
        // For balances ≥ TIER_FREE_CEILING: limit = balance × velocity_rate(balance)
        // For balances < TIER_FREE_CEILING: limit = balance (no throttle)

        // Below free ceiling — pass-through
        assert_eq!(daily_limit(0), 0);
        assert_eq!(daily_limit(TIER_FREE_CEILING - 1), TIER_FREE_CEILING - 1);

        // At low tier boundary: 100K beat × 50% = 50K beat
        let low_at_ceiling = daily_limit(TIER_FREE_CEILING);
        let expected_low = (TIER_FREE_CEILING as f64 * RATE_LOW) as u64;
        assert_eq!(low_at_ceiling, expected_low);
        assert_eq!(low_at_ceiling, 50_000 * BASE_UNITS_PER_BEAT);

        // At mid tier boundary: 1M × 10% = 100K
        let mid_at_ceiling = daily_limit(TIER_LOW_CEILING);
        assert_eq!(mid_at_ceiling, (TIER_LOW_CEILING as f64 * RATE_MID) as u64);
        assert_eq!(mid_at_ceiling, 100_000 * BASE_UNITS_PER_BEAT);

        // At high tier boundary: 10M × 3% = 300K
        let high_at_ceiling = daily_limit(TIER_MID_CEILING);
        assert_eq!(high_at_ceiling, (TIER_MID_CEILING as f64 * RATE_HIGH) as u64);
        assert_eq!(high_at_ceiling, 300_000 * BASE_UNITS_PER_BEAT);

        // At mega tier boundary: 100M × 1% = 1M
        let mega_at_ceiling = daily_limit(TIER_HIGH_CEILING);
        assert_eq!(mega_at_ceiling, (TIER_HIGH_CEILING as f64 * RATE_MEGA) as u64);
        assert_eq!(mega_at_ceiling, 1_000_000 * BASE_UNITS_PER_BEAT);
    }

    #[test]
    fn batch_b_velocity_tracker_new_equals_default_with_empty_window_zeros() {
        // ::new must produce the same observable state as ::default()
        let t1 = VelocityTracker::new();
        let t2 = VelocityTracker::default();

        assert_eq!(t1.tracked_identities(), 0);
        assert_eq!(t2.tracked_identities(), 0);

        // Empty tracker — all window queries return 0 for any identity
        assert_eq!(t1.outflow_in_window("nobody", 1000.0), 0);
        assert_eq!(t1.peak_balance("nobody", 1000.0), 0);
        assert_eq!(t1.outflow_in_custom_window("nobody", 1000.0, 60.0), 0);
        assert_eq!(t1.peak_balance_in_window("nobody", 1000.0, 60.0), 0);

        // Recording an outflow increments tracked_identities exactly once
        // (idempotent on the same identity)
        let mut t3 = VelocityTracker::new();
        t3.record_outflow("alice", 100, 1000.0);
        assert_eq!(t3.tracked_identities(), 1);
        t3.record_outflow("alice", 200, 2000.0);
        assert_eq!(t3.tracked_identities(), 1, "same identity must NOT bump count");
        t3.record_outflow("bob", 50, 1000.0);
        assert_eq!(t3.tracked_identities(), 2);

        // Sum semantics: 100 + 200 within window
        assert_eq!(t3.outflow_in_window("alice", 2000.0), 300);
        // Cutoff (strict > now-window) excludes the boundary point
        // at exactly now-VELOCITY_WINDOW_SECS
        let just_inside = 2000.0 + 1.0;
        let inside_sum = t3.outflow_in_window("alice", just_inside);
        assert_eq!(inside_sum, 300);
    }
}
