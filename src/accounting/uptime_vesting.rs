//! Uptime vesting — the genesis bootstrap allocation, earned through participation.
//!
//! The 30% Network Bootstrap pool (`genesis.rs`) is earned, not given away: an
//! operator's grant vests by accumulated node uptime (actual hours online, not
//! calendar days), so credits accrue to nodes that actually do the work. Vesting-
//! locked credits are not spendable until uptime milestones unlock them.
//!
//! NOTE (not-a-coin pivot 2026-06-09): beat is internal protocol plumbing, not a
//! cryptocurrency — no sale, listing, or transfer market (see `genesis.rs`: "No
//! ICO. No pre-sale. No airdrop."). This grant path is NOT wired in production
//! (see internal design notes, economics §12); the `vested_locked` / `uptime_secs`
//! / `inactive_days` account fields are retained for account-SMT wire-compat and
//! are inert until a future epoch-gated activation.
//!
//! Vesting schedule:
//!   24h   (~1 day 24/7):     1% unlocked
//!   72h   (~3 days 24/7):    5% unlocked
//!   168h  (~7 days 24/7):   10% unlocked
//!   720h  (~30 days 24/7):  20% unlocked
//!   2,160h (~90 days 24/7): 30% unlocked
//!   4,320h (~180 days 24/7): 50% unlocked
//!   8,760h (~1 year 24/7):  100% unlocked — fully vested
//!
//! Inactivity drain: 15 consecutive days inactive → small daily drain
//! back to the bootstrap pool for new joiners.
//!
//! Active = online ≥1 hour within 7 days → inactivity counter resets.

//!
//! Spec references:
//!   @spec economics §12

use super::ledger::AccountState;

// ─── Vesting Milestones ─────────────────────────────────────────────────────

/// Vesting milestones: (accumulated_uptime_hours, cumulative_unlock_percent).
/// Each milestone unlocks up to that cumulative percentage of the original grant.
const VESTING_MILESTONES: &[(u64, u64)] = &[
    (24,      1),   // 1 day 24/7
    (72,      5),   // 3 days 24/7
    (168,    10),   // 7 days 24/7, ~84 days at 2h/day
    (720,    20),   // 30 days 24/7, ~90 days at 8h/day
    (2_160,  30),   // 90 days 24/7
    (4_320,  50),   // 180 days 24/7
    (8_760, 100),   // 1 year 24/7 — fully vested
];

/// Maximum nodes eligible for the genesis bootstrap allocation.
pub const MAX_VESTING_NODES: usize = 10_000;

/// Bootstrap grant amount per node in base units (configurable).
/// Default: 1,000 beat = 1,000,000,000 base units.
pub const DEFAULT_VESTING_GRANT: u64 = 1_000_000_000;

/// Days of inactivity before drain starts.
pub const INACTIVITY_THRESHOLD_DAYS: u32 = 15;

/// Daily drain rate as percentage of remaining vested_locked.
/// 1% per day — gentle but meaningful. 100 days of full inactivity = ~63% drained.
pub const DAILY_DRAIN_PERCENT: f64 = 1.0;

/// Minimum hours online within 7 days to be considered "active".
pub const ACTIVE_MIN_HOURS: u64 = 1;

// ─── Vesting Logic ──────────────────────────────────────────────────────────

/// Compute what percentage of the original grant should be unlocked
/// based on accumulated uptime hours.
pub fn vesting_percent(uptime_hours: u64) -> u64 {
    let mut pct = 0u64;
    for &(threshold_hours, cumulative_pct) in VESTING_MILESTONES {
        if uptime_hours >= threshold_hours {
            pct = cumulative_pct;
        } else {
            break;
        }
    }
    pct
}

/// Compute the next vesting milestone (hours needed, percent unlocked).
/// Returns None if fully vested.
pub fn next_milestone(uptime_hours: u64) -> Option<(u64, u64)> {
    for &(threshold_hours, cumulative_pct) in VESTING_MILESTONES {
        if uptime_hours < threshold_hours {
            return Some((threshold_hours, cumulative_pct));
        }
    }
    None // fully vested
}

/// Process vesting for an account. Moves unlocked beats from vested_locked to available.
///
/// Call this periodically (e.g., every epoch seal or every hour).
/// Returns the amount newly unlocked (0 if no change).
pub fn process_vesting(account: &mut AccountState, original_grant: u64) -> u64 {
    if account.vested_locked == 0 {
        return 0;
    }

    let uptime_hours = account.uptime_secs / 3600;
    let pct = vesting_percent(uptime_hours);

    // How much should be unlocked cumulatively (integer: pct is whole-percent).
    let should_be_unlocked = ((original_grant as u128) * pct as u128 / 100) as u64;

    // How much has already been unlocked (original - remaining locked)
    let already_unlocked = original_grant.saturating_sub(account.vested_locked);

    // New amount to unlock
    let to_unlock = should_be_unlocked.saturating_sub(already_unlocked);
    let to_unlock = to_unlock.min(account.vested_locked); // can't unlock more than locked

    if to_unlock > 0 {
        account.vested_locked -= to_unlock;
        account.available += to_unlock;
    }

    to_unlock
}

/// Process inactivity drain. Drains a percentage of vested_locked back to the pool.
///
/// Returns the amount drained (0 if account is active or no locked beats).
pub fn process_inactivity_drain(account: &mut AccountState) -> u64 {
    if account.vested_locked == 0 || account.inactive_days < INACTIVITY_THRESHOLD_DAYS {
        return 0;
    }

    // Drain 1% of remaining vested_locked per day (integer: DAILY_DRAIN_PERCENT = 1).
    let drain = ((account.vested_locked as u128) / 100) as u64;
    let drain = drain.max(1); // minimum 1 base unit to ensure progress

    let drain = drain.min(account.vested_locked);
    account.vested_locked -= drain;

    drain
}

/// Record uptime for an account. Call with the session duration in seconds.
///
/// Also resets inactivity counter if the session was ≥1 hour.
pub fn record_uptime(account: &mut AccountState, session_secs: u64) {
    account.uptime_secs += session_secs;

    // Active = online ≥1 hour → reset inactivity counter
    if session_secs >= ACTIVE_MIN_HOURS * 3600 {
        account.inactive_days = 0;
    }
}

/// Increment inactivity counter by one day.
/// Call this once per day for accounts that haven't been seen.
pub fn tick_inactive_day(account: &mut AccountState) {
    account.inactive_days += 1;
}

/// Summary of an account's vesting status.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CustodyStatus {
    /// Currently locked vesting credits.
    pub vested_locked: u64,
    /// Available (liquid) balance.
    pub available: u64,
    /// Total accumulated uptime in hours.
    pub uptime_hours: u64,
    /// Current vesting percentage unlocked.
    pub vesting_percent: u64,
    /// Next milestone: (hours_needed, percent_at_milestone). None if fully vested.
    pub next_milestone: Option<(u64, u64)>,
    /// Hours until next milestone (0 if fully vested).
    pub hours_to_next: u64,
    /// Consecutive inactive days.
    pub inactive_days: u32,
    /// Whether inactivity drain is active.
    pub drain_active: bool,
}

/// Get the custody status for an account.
pub fn custody_status(account: &AccountState) -> CustodyStatus {
    let uptime_hours = account.uptime_secs / 3600;
    let pct = vesting_percent(uptime_hours);
    let next = next_milestone(uptime_hours);
    let hours_to_next = next.map_or(0, |(h, _)| h.saturating_sub(uptime_hours));

    CustodyStatus {
        vested_locked: account.vested_locked,
        available: account.available,
        uptime_hours,
        vesting_percent: pct,
        next_milestone: next,
        hours_to_next,
        inactive_days: account.inactive_days,
        drain_active: account.inactive_days >= INACTIVITY_THRESHOLD_DAYS && account.vested_locked > 0,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn vesting_account(amount: u64) -> AccountState {
        AccountState {
            vested_locked: amount,
            ..Default::default()
        }
    }

    #[test]
    fn test_vesting_percent_milestones() {
        assert_eq!(vesting_percent(0), 0);
        assert_eq!(vesting_percent(23), 0);
        assert_eq!(vesting_percent(24), 1);     // 1 day 24/7
        assert_eq!(vesting_percent(71), 1);
        assert_eq!(vesting_percent(72), 5);     // 3 days 24/7
        assert_eq!(vesting_percent(100), 5);
        assert_eq!(vesting_percent(168), 10);   // 7 days 24/7
        assert_eq!(vesting_percent(500), 10);
        assert_eq!(vesting_percent(720), 20);   // 30 days 24/7
        assert_eq!(vesting_percent(1000), 20);
        assert_eq!(vesting_percent(2160), 30);  // 90 days 24/7
        assert_eq!(vesting_percent(4320), 50);  // 180 days 24/7
        assert_eq!(vesting_percent(8760), 100); // 1 year 24/7
        assert_eq!(vesting_percent(99999), 100);
    }

    #[test]
    fn test_next_milestone() {
        assert_eq!(next_milestone(0), Some((24, 1)));
        assert_eq!(next_milestone(24), Some((72, 5)));
        assert_eq!(next_milestone(72), Some((168, 10)));
        assert_eq!(next_milestone(168), Some((720, 20)));
        assert_eq!(next_milestone(720), Some((2160, 30)));
        assert_eq!(next_milestone(4320), Some((8760, 100)));
        assert_eq!(next_milestone(8760), None); // fully vested
        assert_eq!(next_milestone(99999), None);
    }

    #[test]
    fn test_process_vesting_first_milestone() {
        let original = 1_000_000_000u64; // 1000 beat
        let mut account = vesting_account(original);
        account.uptime_secs = 24 * 3600; // exactly 24 hours (1 day)

        let unlocked = process_vesting(&mut account, original);
        assert_eq!(unlocked, 10_000_000); // 1% of 1000 beat
        assert_eq!(account.available, 10_000_000);
        assert_eq!(account.vested_locked, 990_000_000);
    }

    #[test]
    fn test_process_vesting_progressive() {
        let original = 1_000_000_000u64;
        let mut account = vesting_account(original);

        // First milestone: 72h → 5%
        account.uptime_secs = 72 * 3600;
        process_vesting(&mut account, original);
        assert_eq!(account.available, 50_000_000);

        // Second milestone: 168h → 10% total (5% more)
        account.uptime_secs = 168 * 3600;
        let unlocked = process_vesting(&mut account, original);
        assert_eq!(unlocked, 50_000_000); // additional 5%
        assert_eq!(account.available, 100_000_000); // 10% total
        assert_eq!(account.vested_locked, 900_000_000);

        // Third milestone: 720h → 20% total (10% more)
        account.uptime_secs = 720 * 3600;
        let unlocked = process_vesting(&mut account, original);
        assert_eq!(unlocked, 100_000_000);
        assert_eq!(account.available, 200_000_000); // 20% total
        assert_eq!(account.vested_locked, 800_000_000);
    }

    #[test]
    fn test_process_vesting_full() {
        let original = 1_000_000_000u64;
        let mut account = vesting_account(original);
        account.uptime_secs = 8760 * 3600; // 1 year — fully vested

        let unlocked = process_vesting(&mut account, original);
        assert_eq!(unlocked, original);
        assert_eq!(account.available, original);
        assert_eq!(account.vested_locked, 0);
    }

    #[test]
    fn test_process_vesting_no_change_between_milestones() {
        let original = 1_000_000_000u64;
        let mut account = vesting_account(original);
        account.uptime_secs = 168 * 3600; // at 10% milestone
        process_vesting(&mut account, original);

        // Add 100 more hours (still below 720h milestone)
        account.uptime_secs = 268 * 3600;
        let unlocked = process_vesting(&mut account, original);
        assert_eq!(unlocked, 0); // no new milestone reached
    }

    #[test]
    fn test_inactivity_drain_before_threshold() {
        let mut account = vesting_account(1_000_000_000);
        account.inactive_days = 14; // below threshold
        let drained = process_inactivity_drain(&mut account);
        assert_eq!(drained, 0);
    }

    #[test]
    fn test_inactivity_drain_at_threshold() {
        let mut account = vesting_account(1_000_000_000);
        account.inactive_days = 15; // at threshold
        let drained = process_inactivity_drain(&mut account);
        assert_eq!(drained, 10_000_000); // 1% of 1B
        assert_eq!(account.vested_locked, 990_000_000);
    }

    #[test]
    fn test_inactivity_drain_no_locked_tokens() {
        let mut account = AccountState { inactive_days: 30, ..Default::default() };
        let drained = process_inactivity_drain(&mut account);
        assert_eq!(drained, 0); // nothing to drain
    }

    #[test]
    fn test_record_uptime_resets_inactivity() {
        let mut account = AccountState { inactive_days: 20, ..Default::default() };

        // Short session (30 min) — doesn't reset
        record_uptime(&mut account, 1800);
        assert_eq!(account.inactive_days, 20);
        assert_eq!(account.uptime_secs, 1800);

        // Long session (2 hours) — resets inactivity
        record_uptime(&mut account, 7200);
        assert_eq!(account.inactive_days, 0);
        assert_eq!(account.uptime_secs, 9000);
    }

    #[test]
    fn test_tick_inactive_day() {
        let mut account = AccountState::default();
        assert_eq!(account.inactive_days, 0);
        tick_inactive_day(&mut account);
        assert_eq!(account.inactive_days, 1);
        tick_inactive_day(&mut account);
        assert_eq!(account.inactive_days, 2);
    }

    #[test]
    fn test_custody_status() {
        let mut account = vesting_account(1_000_000_000);
        account.uptime_secs = 1000 * 3600; // past 720h milestone

        // Process vesting first
        process_vesting(&mut account, 1_000_000_000);

        let status = custody_status(&account);
        assert_eq!(status.vesting_percent, 20);
        assert_eq!(status.next_milestone, Some((2160, 30)));
        assert_eq!(status.hours_to_next, 1160); // 2160 - 1000
        assert!(!status.drain_active);
    }

    #[test]
    fn test_custody_status_drain_active() {
        let mut account = vesting_account(1_000_000_000);
        account.inactive_days = 15;

        let status = custody_status(&account);
        assert!(status.drain_active);
    }

    #[test]
    fn test_24_7_node_vests_12x_faster() {
        let original = 1_000_000_000u64;

        // 24/7 node: 720 hours in 30 days
        let mut full_time = vesting_account(original);
        full_time.uptime_secs = 30 * 24 * 3600; // 720 hours
        assert_eq!(vesting_percent(full_time.uptime_secs / 3600), 20);

        // 2h/day node: 720 hours in 360 days
        let mut part_time = vesting_account(original);
        part_time.uptime_secs = 360 * 2 * 3600; // also 720 hours
        assert_eq!(vesting_percent(part_time.uptime_secs / 3600), 20);

        // Same uptime = same vesting. But 24/7 gets there 12× faster in wall time.
    }

    // ── uptime-vesting constant tests (economics §14.3) ─────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_uptime_vesting_constants_strict_pin_with_ranges() {
        assert_eq!(MAX_VESTING_NODES, 10_000);
        // DEFAULT_VESTING_GRANT = 1B base units. With BASE_UNITS_PER_BEAT = 1B,
        // that's exactly 1 beat per genesis node.
        assert_eq!(DEFAULT_VESTING_GRANT, 1_000_000_000);
        assert_eq!(DEFAULT_VESTING_GRANT, crate::accounting::types::BASE_UNITS_PER_BEAT);
        assert_eq!(INACTIVITY_THRESHOLD_DAYS, 15);
        assert_eq!(DAILY_DRAIN_PERCENT, 1.0);
        assert_eq!(ACTIVE_MIN_HOURS, 1);
        // Each in expected range.
        assert!(MAX_VESTING_NODES > 0 && MAX_VESTING_NODES <= 1_000_000); // bounded
        assert!(DAILY_DRAIN_PERCENT > 0.0 && DAILY_DRAIN_PERCENT < 100.0);
        assert!(INACTIVITY_THRESHOLD_DAYS > 0 && INACTIVITY_THRESHOLD_DAYS < 365);
    }

    #[test]
    fn batch_b_vesting_milestones_seven_step_ladder_with_monotonic_ascending_pairs() {
        // 7 milestones: (24h→1%, 72h→5%, 168h→10%, 720h→20%, 2160h→30%, 4320h→50%, 8760h→100%).
        // VESTING_MILESTONES is a private const, but we can verify the structural invariants
        // through vesting_percent at each boundary + monotonicity across the range.
        let boundaries = [
            (0u64, 0u64),          // pre-first milestone
            (24, 1), (72, 5), (168, 10), (720, 20),
            (2_160, 30), (4_320, 50), (8_760, 100),
        ];
        for &(hours, expected_pct) in &boundaries {
            assert_eq!(
                vesting_percent(hours),
                expected_pct,
                "vesting_percent({hours}h) expected {expected_pct}%"
            );
        }
        // One hour BEFORE each milestone returns previous tier's percent.
        assert_eq!(vesting_percent(23), 0);   // before 24h
        assert_eq!(vesting_percent(71), 1);   // before 72h
        assert_eq!(vesting_percent(167), 5);  // before 168h
        assert_eq!(vesting_percent(8_759), 50); // before final milestone
        // Monotonic non-decreasing across full range — sample broadly.
        let samples = [0u64, 24, 50, 72, 100, 168, 500, 720, 1500, 2_160, 3500, 4_320, 6500, 8_760, 100_000];
        let mut prev = vesting_percent(samples[0]);
        for &h in &samples[1..] {
            let cur = vesting_percent(h);
            assert!(cur >= prev, "vesting_percent must be non-decreasing: m({h})={cur} prev={prev}");
            prev = cur;
        }
        // Cap at 100% — vesting_percent(u64::MAX) doesn't overflow or exceed 100.
        assert_eq!(vesting_percent(u64::MAX), 100);
    }

    #[test]
    fn batch_b_next_milestone_returns_none_fully_vested_with_first_for_zero_uptime() {
        // Zero uptime → first milestone (24h, 1%).
        let m0 = next_milestone(0).unwrap();
        assert_eq!(m0, (24, 1));
        // 1 hour → still pointing at first milestone (haven't crossed 24h).
        let m1 = next_milestone(1).unwrap();
        assert_eq!(m1, (24, 1));
        // Exactly at 24h → next is 72h, 5%.
        let m24 = next_milestone(24).unwrap();
        assert_eq!(m24, (72, 5));
        // Right before final (8759h) → next is (8760, 100).
        let m_final = next_milestone(8_759).unwrap();
        assert_eq!(m_final, (8_760, 100));
        // Fully vested at exactly 8760h → None.
        assert!(next_milestone(8_760).is_none());
        // Way past fully vested → None.
        assert!(next_milestone(100_000).is_none());
        assert!(next_milestone(u64::MAX).is_none());
    }

    #[test]
    fn batch_b_process_inactivity_drain_min_one_micro_floor_for_tiny_balances() {
        use crate::accounting::ledger::AccountState;
        // Tiny vested_locked balance: 1% of 50 = 0.5 → floors to 0, but min(1) floor kicks in.
        let mut acc = AccountState {
            vested_locked: 50,
            inactive_days: INACTIVITY_THRESHOLD_DAYS,
            ..AccountState::default()
        };
        let drained = process_inactivity_drain(&mut acc);
        assert_eq!(drained, 1, "min-1-micro floor must ensure progress on tiny balances");
        assert_eq!(acc.vested_locked, 49);
        // Even at vested_locked=1, drain returns 1 (and balance goes to 0).
        let mut acc2 = AccountState {
            vested_locked: 1,
            inactive_days: INACTIVITY_THRESHOLD_DAYS + 100,
            ..AccountState::default()
        };
        let drained2 = process_inactivity_drain(&mut acc2);
        assert_eq!(drained2, 1);
        assert_eq!(acc2.vested_locked, 0);
        // Once vested_locked=0, further calls return 0.
        let drained3 = process_inactivity_drain(&mut acc2);
        assert_eq!(drained3, 0);
        // Below INACTIVITY_THRESHOLD_DAYS → no drain even if vested_locked is huge.
        let mut acc3 = AccountState {
            vested_locked: 1_000_000_000,
            inactive_days: INACTIVITY_THRESHOLD_DAYS - 1,
            ..AccountState::default()
        };
        assert_eq!(process_inactivity_drain(&mut acc3), 0);
        assert_eq!(acc3.vested_locked, 1_000_000_000); // unchanged
    }

    #[test]
    fn batch_b_inactivity_drain_rate_matches_daily_drain_percent_constant() {
        use crate::accounting::ledger::AccountState;
        // process_inactivity_drain drains 1% of vested_locked per call (matching DAILY_DRAIN_PERCENT).
        // Pin: large vested_locked → drain = vested_locked * DAILY_DRAIN_PERCENT / 100
        let mut acc = AccountState::default();
        let initial = 10_000_000_000u64; // 10B micros
        acc.vested_locked = initial;
        acc.inactive_days = INACTIVITY_THRESHOLD_DAYS;
        let drained = process_inactivity_drain(&mut acc);
        let expected = (initial as f64 * DAILY_DRAIN_PERCENT / 100.0) as u64;
        assert_eq!(drained, expected);
        assert_eq!(acc.vested_locked, initial - expected);
        // Conservative invariant: drain is always ≥1 (min floor) when triggered.
        assert!(drained >= 1);
        // Drain cannot exceed remaining vested_locked.
        let mut acc2 = AccountState {
            vested_locked: 1_000_000_000,
            inactive_days: 365,
            ..AccountState::default()
        };
        let d = process_inactivity_drain(&mut acc2);
        assert!(d <= 1_000_000_000);
    }
}
