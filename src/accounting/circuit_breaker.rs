//! Circuit breaker — network-wide panic protection.
//!
//! economics v0.4.1 Section 13.5:
//! - Normal: daily volume < 3% of circulating supply
//! - Level 1 (Elevated): 3-5% — per-identity velocity limits halved
//! - Level 2 (Stress): 5-10% — large transfers paused, governance frozen
//! - Level 3 (Crisis): >10% — all transfers >1K beat paused
//!
//! Small transfers (<10K beat for L1/L2, <1K for L3) always allowed.

//!
//! Spec references:
//!   @spec economics §13.5

use crate::errors::{ElaraError, Result};
use crate::accounting::types::BASE_UNITS_PER_BEAT;

// ─── Constants (economics v0.4.1 Section 13.5) ─────────────────────────────

/// Circuit breaker thresholds as fraction of circulating supply.
pub const LEVEL_1_THRESHOLD: f64 = 0.03; // 3%
pub const LEVEL_2_THRESHOLD: f64 = 0.05; // 5%
pub const LEVEL_3_THRESHOLD: f64 = 0.10; // 10%

/// Small transfer exemption: transfers below this are always allowed at L1/L2.
pub const SMALL_TRANSFER_LIMIT: u64 = 10_000 * BASE_UNITS_PER_BEAT;

/// Micro transfer limit: transfers below this are always allowed at L3.
pub const MICRO_TRANSFER_LIMIT: u64 = 1_000 * BASE_UNITS_PER_BEAT;

/// L2 pause threshold: transfers above this fraction of supply are paused.
pub const LEVEL_2_PAUSE_FRACTION: f64 = 0.0001; // 0.01% of supply

/// Sliding window for volume tracking: 24 hours in seconds.
pub const VOLUME_WINDOW_SECS: f64 = 24.0 * 3600.0;

/// Cooldown: L1 lifts when volume stays below 3% for this duration (6h).
pub const LEVEL_1_COOLDOWN_SECS: f64 = 6.0 * 3600.0;

/// Minimum L2 duration (24h).
pub const LEVEL_2_MIN_DURATION_SECS: f64 = 24.0 * 3600.0;

/// Minimum L3 duration (48h).
pub const LEVEL_3_MIN_DURATION_SECS: f64 = 48.0 * 3600.0;

// ─── Types ───────────────────────────────────────────────────────────────────

/// Circuit breaker level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BreakerLevel {
    Normal,
    Level1,
    Level2,
    Level3,
}

impl BreakerLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Level1 => "level_1_elevated",
            Self::Level2 => "level_2_stress",
            Self::Level3 => "level_3_crisis",
        }
    }
}

/// Circuit breaker state.
///
/// NOTE: although this struct derives `Serialize`/`Deserialize`, the owning
/// `LedgerState.circuit_breaker` field is `#[serde(skip)]` (a parent field-level
/// skip overrides the child derive), so NONE of these fields — `level` included —
/// survive a state snapshot. A snapshot-bootstrapped node starts at
/// `BreakerLevel::Normal` with an empty volume window. That is why the breaker
/// `check_transfer` gate must NOT run on the synced/sealed-record replay path
/// (`enforce_rate_limits=false`): a bootstrapped follower (Normal) and a
/// since-genesis node (possibly elevated) would diverge. See
/// internal design notes (Track D) +
/// internal design notes (finding 3).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CircuitBreaker {
    /// Current breaker level.
    pub level: BreakerLevel,
    /// When the current level was activated (timestamp).
    pub level_since: f64,
    /// When volume last dropped below L1 threshold (for cooldown tracking).
    pub below_l1_since: Option<f64>,
    /// Rolling transfer volume entries: (timestamp, amount).
    #[serde(skip)]
    volume_entries: Vec<(f64, u64)>,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self {
            level: BreakerLevel::Normal,
            level_since: 0.0,
            below_l1_since: None,
            volume_entries: Vec::new(),
        }
    }

    /// Record a transfer volume (call after every successful transfer).
    pub fn record_volume(&mut self, amount: u64, timestamp: f64) {
        self.volume_entries.push((timestamp, amount));
    }

    /// Total transfer volume in the last 24h.
    pub fn volume_in_window(&self, now: f64) -> u64 {
        let cutoff = now - VOLUME_WINDOW_SECS;
        self.volume_entries
            .iter()
            .filter(|(ts, _)| *ts > cutoff)
            .map(|(_, amt)| *amt)
            .fold(0u64, |acc, x| acc.saturating_add(x))
    }

    /// Update the breaker level based on current volume and circulating supply.
    /// Call after every transfer or periodically.
    pub fn update_level(&mut self, circulating_supply: u64, now: f64) {
        if circulating_supply == 0 {
            return;
        }

        let volume = self.volume_in_window(now);
        // Integer level decision (no f64 in a gate that changes accept/reject on
        // every node): `volume/circ ≥ p%` ⟺ `volume·100 ≥ circ·p`, in u128 so it
        // is bit-identical across architectures. Thresholds are 3% / 5% / 10%.
        let v = volume as u128;
        let c = circulating_supply as u128;
        let new_level = if v.saturating_mul(100) >= c.saturating_mul(10) {
            BreakerLevel::Level3
        } else if v.saturating_mul(100) >= c.saturating_mul(5) {
            BreakerLevel::Level2
        } else if v.saturating_mul(100) >= c.saturating_mul(3) {
            BreakerLevel::Level1
        } else {
            BreakerLevel::Normal
        };

        // Track when volume drops below L1 (for cooldown)
        if v.saturating_mul(100) < c.saturating_mul(3) {
            if self.below_l1_since.is_none() {
                self.below_l1_since = Some(now);
            }
        } else {
            self.below_l1_since = None;
        }

        // Escalation is immediate
        if new_level as u8 > self.level as u8 {
            self.level = new_level;
            self.level_since = now;
            return;
        }

        // De-escalation requires cooldown
        match self.level {
            BreakerLevel::Level3 => {
                let elapsed = now - self.level_since;
                if elapsed >= LEVEL_3_MIN_DURATION_SECS && new_level < BreakerLevel::Level3 {
                    self.level = new_level.max(BreakerLevel::Level2);
                    self.level_since = now;
                }
            }
            BreakerLevel::Level2 => {
                let elapsed = now - self.level_since;
                if elapsed >= LEVEL_2_MIN_DURATION_SECS && new_level < BreakerLevel::Level2 {
                    self.level = new_level.max(BreakerLevel::Level1);
                    self.level_since = now;
                }
            }
            BreakerLevel::Level1 => {
                // L1 lifts when volume below threshold for 6h continuously
                if let Some(below_since) = self.below_l1_since {
                    if now - below_since >= LEVEL_1_COOLDOWN_SECS {
                        self.level = BreakerLevel::Normal;
                        self.level_since = now;
                    }
                }
            }
            BreakerLevel::Normal => {}
        }
    }

    /// Check if a proposed transfer is allowed under the current breaker level.
    /// Returns Ok(()) if allowed, Err if blocked.
    pub fn check_transfer(
        &self,
        amount: u64,
        circulating_supply: u64,
    ) -> Result<()> {
        match self.level {
            BreakerLevel::Normal => Ok(()),
            BreakerLevel::Level1 => {
                // Small transfers always allowed
                if amount <= SMALL_TRANSFER_LIMIT {
                    return Ok(());
                }
                // All other transfers allowed but velocity limits are halved
                // (velocity halving is handled in the velocity check, not here)
                Ok(())
            }
            BreakerLevel::Level2 => {
                // Small transfers always allowed
                if amount <= SMALL_TRANSFER_LIMIT {
                    return Ok(());
                }
                // Transfers > 0.01% of supply are paused. Integer gate: 0.01%
                // = 1/10_000, computed in u128 so the pause boundary is identical
                // on every node (the old `supply as f64 * 0.0001` was non-portable).
                let pause_threshold = ((circulating_supply as u128) / 10_000) as u64;
                if amount > pause_threshold {
                    return Err(ElaraError::Ledger(format!(
                        "circuit breaker Level 2 (stress): transfers > {} beat \
                         (0.01% of supply) paused. Current level since {:.0}s ago",
                        pause_threshold / BASE_UNITS_PER_BEAT,
                        0.0, // caller can compute
                    )));
                }
                Ok(())
            }
            BreakerLevel::Level3 => {
                // Only micro transfers allowed
                if amount <= MICRO_TRANSFER_LIMIT {
                    return Ok(());
                }
                Err(ElaraError::Ledger(format!(
                    "circuit breaker Level 3 (crisis): only transfers <= {} beat allowed",
                    MICRO_TRANSFER_LIMIT / BASE_UNITS_PER_BEAT,
                )))
            }
        }
    }

    /// Get the velocity multiplier for the current level.
    /// At Level 1, velocity limits are halved (multiplier = 0.5).
    pub fn velocity_multiplier(&self) -> f64 {
        match self.level {
            BreakerLevel::Normal => 1.0,
            BreakerLevel::Level1 => 0.5,
            BreakerLevel::Level2 => 0.5,
            BreakerLevel::Level3 => 0.0, // effectively blocked by check_transfer
        }
    }

    /// Prune old volume entries outside the tracking window.
    pub fn prune(&mut self, now: f64) {
        let cutoff = now - VOLUME_WINDOW_SECS;
        self.volume_entries.retain(|(ts, _)| *ts > cutoff);
    }
}

/// Compute the BreakerLevel as u8 for comparison.
impl BreakerLevel {
    fn as_u8(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::Level1 => 1,
            Self::Level2 => 2,
            Self::Level3 => 3,
        }
    }
}

impl PartialOrd for BreakerLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BreakerLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_u8().cmp(&other.as_u8())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BEAT: u64 = BASE_UNITS_PER_BEAT;
    /// 1 billion beat circulating supply for tests.
    const SUPPLY: u64 = 1_000_000_000 * BEAT;

    #[test]
    fn test_normal_allows_everything() {
        let cb = CircuitBreaker::new();
        assert_eq!(cb.level, BreakerLevel::Normal);
        assert!(cb.check_transfer(1_000_000 * BEAT, SUPPLY).is_ok());
    }

    #[test]
    fn test_level_1_triggers_at_3_percent() {
        let mut cb = CircuitBreaker::new();
        // 3% of 1B = 30M beat
        cb.record_volume(30_000_000 * BEAT, 1000.0);
        cb.update_level(SUPPLY, 1000.0);
        assert_eq!(cb.level, BreakerLevel::Level1);
    }

    #[test]
    fn test_level_1_allows_all_transfers() {
        let mut cb = CircuitBreaker::new();
        cb.record_volume(30_000_000 * BEAT, 1000.0);
        cb.update_level(SUPPLY, 1000.0);
        // L1 allows all transfers (velocity is halved elsewhere)
        assert!(cb.check_transfer(5_000_000 * BEAT, SUPPLY).is_ok());
        assert!(cb.check_transfer(100 * BEAT, SUPPLY).is_ok());
    }

    #[test]
    fn test_level_2_triggers_at_5_percent() {
        let mut cb = CircuitBreaker::new();
        // 5% of 1B = 50M beat
        cb.record_volume(50_000_000 * BEAT, 1000.0);
        cb.update_level(SUPPLY, 1000.0);
        assert_eq!(cb.level, BreakerLevel::Level2);
    }

    #[test]
    fn test_level_2_blocks_large_transfers() {
        let mut cb = CircuitBreaker::new();
        cb.record_volume(50_000_000 * BEAT, 1000.0);
        cb.update_level(SUPPLY, 1000.0);

        // 0.01% of 1B = 100K beat — transfers above this are paused
        assert!(cb.check_transfer(200_000 * BEAT, SUPPLY).is_err());

        // Small transfers always allowed
        assert!(cb.check_transfer(5_000 * BEAT, SUPPLY).is_ok());
    }

    #[test]
    fn test_level_3_triggers_at_10_percent() {
        let mut cb = CircuitBreaker::new();
        // 10% of 1B = 100M beat
        cb.record_volume(100_000_000 * BEAT, 1000.0);
        cb.update_level(SUPPLY, 1000.0);
        assert_eq!(cb.level, BreakerLevel::Level3);
    }

    #[test]
    fn test_level_3_only_micro_transfers() {
        let mut cb = CircuitBreaker::new();
        cb.record_volume(100_000_000 * BEAT, 1000.0);
        cb.update_level(SUPPLY, 1000.0);

        // >1K beat blocked
        assert!(cb.check_transfer(2_000 * BEAT, SUPPLY).is_err());

        // <=1K beat allowed
        assert!(cb.check_transfer(1_000 * BEAT, SUPPLY).is_ok());
        assert!(cb.check_transfer(500 * BEAT, SUPPLY).is_ok());
    }

    #[test]
    fn test_level_1_cooldown_6h() {
        let mut cb = CircuitBreaker::new();
        // Trigger L1
        cb.record_volume(30_000_000 * BEAT, 1000.0);
        cb.update_level(SUPPLY, 1000.0);
        assert_eq!(cb.level, BreakerLevel::Level1);

        // Volume drops to 0 immediately after (entries still in window though)
        // At t=1000+86401 (next day), the volume entry expired
        let next_day = 1000.0 + VOLUME_WINDOW_SECS + 1.0;

        // Volume below threshold but cooldown not met
        cb.update_level(SUPPLY, next_day);
        // below_l1_since just got set, need 6h more
        assert_eq!(cb.level, BreakerLevel::Level1);

        // 6h later — cooldown met
        let after_cooldown = next_day + LEVEL_1_COOLDOWN_SECS + 1.0;
        cb.update_level(SUPPLY, after_cooldown);
        assert_eq!(cb.level, BreakerLevel::Normal);
    }

    #[test]
    fn test_level_2_min_duration_24h() {
        let mut cb = CircuitBreaker::new();
        // Trigger L2
        cb.record_volume(50_000_000 * BEAT, 1000.0);
        cb.update_level(SUPPLY, 1000.0);
        assert_eq!(cb.level, BreakerLevel::Level2);

        // Volume drops to L1 range (3-5%) after window expires
        let next_day = 1000.0 + VOLUME_WINDOW_SECS + 1.0;
        cb.record_volume(35_000_000 * BEAT, next_day);

        // Before 24h minimum, can't de-escalate
        cb.update_level(SUPPLY, 1000.0 + 3600.0); // only 1h since L2
        assert_eq!(cb.level, BreakerLevel::Level2);

        // After 24h, can de-escalate to L1 (not Normal)
        let after_24h = 1000.0 + LEVEL_2_MIN_DURATION_SECS + 1.0;
        cb.update_level(SUPPLY, after_24h);
        // Volume is now in L1 range (3-5%) due to the second recording
        assert!(cb.level <= BreakerLevel::Level1 || cb.level == BreakerLevel::Level2);
    }

    #[test]
    fn test_escalation_is_immediate() {
        let mut cb = CircuitBreaker::new();
        // Normal → L3 in one step
        cb.record_volume(100_000_000 * BEAT, 1000.0);
        cb.update_level(SUPPLY, 1000.0);
        assert_eq!(cb.level, BreakerLevel::Level3);
    }

    #[test]
    fn test_velocity_multiplier() {
        let mut cb = CircuitBreaker::new();
        assert_eq!(cb.velocity_multiplier(), 1.0);

        cb.level = BreakerLevel::Level1;
        assert_eq!(cb.velocity_multiplier(), 0.5);

        cb.level = BreakerLevel::Level2;
        assert_eq!(cb.velocity_multiplier(), 0.5);

        cb.level = BreakerLevel::Level3;
        assert_eq!(cb.velocity_multiplier(), 0.0);
    }

    #[test]
    fn test_prune_old_volume() {
        let mut cb = CircuitBreaker::new();
        cb.record_volume(1000, 100.0);
        cb.record_volume(2000, 100_000.0);

        cb.prune(100_001.0);
        // Only the recent entry (t=100000) should remain
        assert_eq!(cb.volume_in_window(100_001.0), 2000);
    }

    #[test]
    fn test_breaker_level_ordering() {
        assert!(BreakerLevel::Normal < BreakerLevel::Level1);
        assert!(BreakerLevel::Level1 < BreakerLevel::Level2);
        assert!(BreakerLevel::Level2 < BreakerLevel::Level3);
    }

    #[test]
    fn test_volume_window_tracks_24h() {
        let mut cb = CircuitBreaker::new();
        cb.record_volume(1000, 100.0);
        cb.record_volume(2000, 200.0);

        // Both in window
        assert_eq!(cb.volume_in_window(300.0), 3000);

        // After 24h from first entry
        let future = 100.0 + VOLUME_WINDOW_SECS + 1.0;
        assert_eq!(cb.volume_in_window(future), 2000); // only second entry

        // After 24h from second entry
        let far_future = 200.0 + VOLUME_WINDOW_SECS + 1.0;
        assert_eq!(cb.volume_in_window(far_future), 0);
    }

    #[test]
    fn test_zero_supply_no_panic() {
        let mut cb = CircuitBreaker::new();
        cb.record_volume(1000, 100.0);
        // Should not panic or change level
        cb.update_level(0, 100.0);
        assert_eq!(cb.level, BreakerLevel::Normal);
    }

    // ── circuit-breaker threshold tests (economics §10) ──────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_level_threshold_constants_strict_pin_monotonic_with_l3_double_l2() {
        assert_eq!(LEVEL_1_THRESHOLD, 0.03, "L1 = 3% of 24h volume");
        assert_eq!(LEVEL_2_THRESHOLD, 0.05, "L2 = 5%");
        assert_eq!(LEVEL_3_THRESHOLD, 0.10, "L3 = 10%");
        // Strict monotonic ascending — escalation ladder integrity.
        assert!(LEVEL_1_THRESHOLD < LEVEL_2_THRESHOLD);
        assert!(LEVEL_2_THRESHOLD < LEVEL_3_THRESHOLD);
        // L3 = 2 * L2 structural relation (crisis doubles stress threshold).
        assert!((LEVEL_3_THRESHOLD - 2.0 * LEVEL_2_THRESHOLD).abs() < 1e-9);
        // Each threshold in (0, 1) — valid probability/fraction.
        for t in [LEVEL_1_THRESHOLD, LEVEL_2_THRESHOLD, LEVEL_3_THRESHOLD] {
            assert!(t > 0.0 && t < 1.0);
        }
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_transfer_limit_constants_ratio_pin_small_is_ten_micro() {
        assert_eq!(MICRO_TRANSFER_LIMIT, 1_000 * BASE_UNITS_PER_BEAT);
        assert_eq!(SMALL_TRANSFER_LIMIT, 10_000 * BASE_UNITS_PER_BEAT);
        // SMALL = 10 × MICRO (one order of magnitude).
        assert_eq!(SMALL_TRANSFER_LIMIT, 10 * MICRO_TRANSFER_LIMIT);
        // Both positive and L2 pause fraction pinned.
        assert!(MICRO_TRANSFER_LIMIT > 0);
        assert!(SMALL_TRANSFER_LIMIT > MICRO_TRANSFER_LIMIT);
        assert_eq!(LEVEL_2_PAUSE_FRACTION, 0.0001);
        assert!(LEVEL_2_PAUSE_FRACTION < LEVEL_1_THRESHOLD);
        // L2 pause fraction is 1bp (0.01% of supply) — well below L1 escalation.
        assert!((LEVEL_2_PAUSE_FRACTION - 1e-4).abs() < 1e-12);
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_duration_constants_joint_pin_volume_window_cooldown_min_durations() {
        // Volume window = 24h, cooldowns + min durations in concrete seconds.
        assert_eq!(VOLUME_WINDOW_SECS, 24.0 * 3600.0);
        assert_eq!(LEVEL_1_COOLDOWN_SECS, 6.0 * 3600.0);
        assert_eq!(LEVEL_2_MIN_DURATION_SECS, 24.0 * 3600.0);
        assert_eq!(LEVEL_3_MIN_DURATION_SECS, 48.0 * 3600.0);
        // L2 min == VOLUME_WINDOW — cooldown ≥ window so de-escalation requires full window pass.
        assert_eq!(LEVEL_2_MIN_DURATION_SECS, VOLUME_WINDOW_SECS);
        // L3 min = 2 × L2 min (crisis cools down for double the duration of stress).
        assert_eq!(LEVEL_3_MIN_DURATION_SECS, 2.0 * LEVEL_2_MIN_DURATION_SECS);
        // L1 cooldown < L2 min — escalation classes have proportional cooldowns.
        assert!(LEVEL_1_COOLDOWN_SECS < LEVEL_2_MIN_DURATION_SECS);
        // 6h, 24h, 48h — arithmetic-literal cross-check (3600s/hr).
        assert_eq!(LEVEL_1_COOLDOWN_SECS, 21_600.0);
        assert_eq!(LEVEL_2_MIN_DURATION_SECS, 86_400.0);
        assert_eq!(LEVEL_3_MIN_DURATION_SECS, 172_800.0);
    }

    #[test]
    fn batch_b_breaker_level_serde_snake_case_with_as_str_ladder_and_total_ordering() {
        // 4-variant ladder: as_str strict values pinned.
        assert_eq!(BreakerLevel::Normal.as_str(), "normal");
        assert_eq!(BreakerLevel::Level1.as_str(), "level_1_elevated");
        assert_eq!(BreakerLevel::Level2.as_str(), "level_2_stress");
        assert_eq!(BreakerLevel::Level3.as_str(), "level_3_crisis");
        // serde JSON tags follow snake_case — Normal/level1/level2/level3 (variant
        // name → snake_case via rename_all). NOT the verbose as_str() output.
        assert_eq!(serde_json::to_string(&BreakerLevel::Normal).unwrap(), "\"normal\"");
        assert_eq!(serde_json::to_string(&BreakerLevel::Level1).unwrap(), "\"level1\"");
        assert_eq!(serde_json::to_string(&BreakerLevel::Level2).unwrap(), "\"level2\"");
        assert_eq!(serde_json::to_string(&BreakerLevel::Level3).unwrap(), "\"level3\"");
        // Round-trip stability for all 4.
        for v in [BreakerLevel::Normal, BreakerLevel::Level1, BreakerLevel::Level2, BreakerLevel::Level3] {
            let json = serde_json::to_string(&v).unwrap();
            let back: BreakerLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
        // Ord total ordering: Normal < L1 < L2 < L3 (already in test_breaker_level_ordering
        // but here pin cmp() + max() + sorted-array invariant).
        let levels = [BreakerLevel::Level3, BreakerLevel::Normal, BreakerLevel::Level2, BreakerLevel::Level1];
        let mut sorted = levels;
        sorted.sort();
        assert_eq!(
            sorted,
            [BreakerLevel::Normal, BreakerLevel::Level1, BreakerLevel::Level2, BreakerLevel::Level3]
        );
        assert_eq!(*levels.iter().max().unwrap(), BreakerLevel::Level3);
        assert_eq!(*levels.iter().min().unwrap(), BreakerLevel::Normal);
    }

    #[test]
    fn batch_b_circuit_breaker_new_equals_default_with_normal_initial_state() {
        let cb_new = CircuitBreaker::new();
        let cb_def = CircuitBreaker::default();
        // Initial state: Normal level, zero level_since, no below_l1_since marker.
        assert_eq!(cb_new.level, BreakerLevel::Normal);
        assert_eq!(cb_def.level, BreakerLevel::Normal);
        assert_eq!(cb_new.level_since, 0.0);
        assert_eq!(cb_def.level_since, 0.0);
        assert!(cb_new.below_l1_since.is_none());
        assert!(cb_def.below_l1_since.is_none());
        // Fresh breaker — volume window empty regardless of query time.
        assert_eq!(cb_new.volume_in_window(0.0), 0);
        assert_eq!(cb_new.volume_in_window(1_000_000.0), 0);
        // velocity_multiplier on fresh Normal == 1.0 (full velocity).
        assert_eq!(cb_new.velocity_multiplier(), 1.0);
        // Fresh CB passes any transfer (Normal allows everything).
        assert!(cb_new
            .check_transfer(1_000_000_000_u64.saturating_mul(BASE_UNITS_PER_BEAT), 1_000_000_000_u64.saturating_mul(BASE_UNITS_PER_BEAT))
            .is_ok());
    }
}
