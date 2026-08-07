//! Phased Bootstrap Detection — economics v0.4.1 Section 14.2.
//!
//! Auto-detects network phase from connected peer count:
//! - Genesis (1-10 nodes): founding team, no rewards
//! - Early Growth (10-1K nodes): 3-5x elevated rewards from 30% bootstrap pool
//! - Decentralization Threshold (1K-10K nodes): normalize to base rewards
//! - Critical Mass (10K+ nodes): self-sustaining from organic fees
//!
//! Phase transitions are automatic based on unique identity count.
//! Reward multiplier scales linearly within Early Growth phase.

//!
//! Spec references:
//!   @spec economics §14.2

use serde::{Deserialize, Serialize};

// ─── Constants (economics v0.4.1 Section 14.2) ─────────────────────────────

/// Phase boundary: Genesis → Early Growth (mainnet).
pub const GENESIS_CEILING: u64 = 10;
/// Phase boundary: Early Growth → Decentralization (mainnet).
pub const EARLY_GROWTH_CEILING: u64 = 1_000;
/// Phase boundary: Decentralization → Critical Mass (mainnet).
pub const DECENTRALIZATION_CEILING: u64 = 10_000;

/// Testnet thresholds — lowered so small networks can test reward flow.
pub const TESTNET_GENESIS_CEILING: u64 = 2;
pub const TESTNET_EARLY_GROWTH_CEILING: u64 = 10;
pub const TESTNET_DECENTRALIZATION_CEILING: u64 = 50;

/// Mainnet phase boundaries as a `(genesis, early, decentralization)` tuple —
/// what `phase_boundaries()` returns when ELARA_TESTNET is unset.
pub const MAINNET_BOUNDARIES: (u64, u64, u64) =
    (GENESIS_CEILING, EARLY_GROWTH_CEILING, DECENTRALIZATION_CEILING);
/// Testnet phase boundaries (lowered ceilings) in the same tuple shape.
pub const TESTNET_BOUNDARIES: (u64, u64, u64) =
    (TESTNET_GENESIS_CEILING, TESTNET_EARLY_GROWTH_CEILING, TESTNET_DECENTRALIZATION_CEILING);

/// Returns true if ELARA_TESTNET=true is set.
pub fn is_testnet() -> bool {
    std::env::var("ELARA_TESTNET").unwrap_or_default() == "true"
}

/// Active phase boundaries (testnet-aware). The `*_with` core functions take a
/// boundaries tuple explicitly so they can be unit-tested deterministically,
/// independent of the ambient ELARA_TESTNET value.
pub fn phase_boundaries() -> (u64, u64, u64) {
    if is_testnet() { TESTNET_BOUNDARIES } else { MAINNET_BOUNDARIES }
}

/// Reward multiplier during Genesis phase (no bootstrap rewards).
pub const GENESIS_MULTIPLIER: f64 = 0.0;
/// Maximum reward multiplier during Early Growth (at 10 nodes).
pub const EARLY_GROWTH_MAX_MULTIPLIER: f64 = 5.0;
/// Minimum reward multiplier during Early Growth (at 1K nodes, tapering).
pub const EARLY_GROWTH_MIN_MULTIPLIER: f64 = 3.0;
/// Reward multiplier during Decentralization phase (normalizing to base).
/// Linearly decays from 3.0 at 1K nodes to 1.0 at 10K nodes.
pub const DECENTRALIZATION_MAX_MULTIPLIER: f64 = 3.0;
/// Base reward multiplier (Critical Mass — self-sustaining).
pub const BASE_MULTIPLIER: f64 = 1.0;

// ─── Types ─────────────────────────────────────────────────────────────────

/// Network bootstrap phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapPhase {
    /// 1-10 nodes. Founding team. No bootstrap rewards.
    Genesis,
    /// 10-1K nodes. Elevated rewards (3-5x) from bootstrap pool.
    EarlyGrowth,
    /// 1K-10K nodes. Rewards normalize toward base rate.
    Decentralization,
    /// 10K+ nodes. Self-sustaining from organic fees.
    CriticalMass,
}

impl BootstrapPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Genesis => "genesis",
            Self::EarlyGrowth => "early_growth",
            Self::Decentralization => "decentralization",
            Self::CriticalMass => "critical_mass",
        }
    }
}

impl std::fmt::Display for BootstrapPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Detect the current bootstrap phase from the number of unique active identities.
///
/// Uses lowered thresholds when `ELARA_TESTNET=true` is set.
pub fn detect_phase(node_count: u64) -> BootstrapPhase {
    detect_phase_with(node_count, phase_boundaries())
}

/// Env-independent phase detection against explicit boundaries — the testable
/// core. `detect_phase` is the testnet-aware wrapper that reads the live env.
pub fn detect_phase_with(node_count: u64, boundaries: (u64, u64, u64)) -> BootstrapPhase {
    let (genesis, early, decentral) = boundaries;
    if node_count >= decentral {
        BootstrapPhase::CriticalMass
    } else if node_count >= early {
        BootstrapPhase::Decentralization
    } else if node_count >= genesis {
        BootstrapPhase::EarlyGrowth
    } else {
        BootstrapPhase::Genesis
    }
}

/// Compute the reward multiplier for the current node count.
///
/// - Genesis (< genesis_ceiling): 0.0 (no rewards)
/// - Early Growth: linear interpolation 5.0 → 3.0
/// - Decentralization: linear interpolation 3.0 → 1.0
/// - Critical Mass: 1.0 (base rate)
///
/// Uses lowered thresholds when `ELARA_TESTNET=true` is set.
pub fn reward_multiplier(node_count: u64) -> f64 {
    reward_multiplier_with(node_count, phase_boundaries())
}

/// Env-independent reward multiplier against explicit boundaries — the testable
/// core. `reward_multiplier` is the testnet-aware wrapper.
pub fn reward_multiplier_with(node_count: u64, boundaries: (u64, u64, u64)) -> f64 {
    let (genesis, early, decentral) = boundaries;
    match detect_phase_with(node_count, boundaries) {
        BootstrapPhase::Genesis => GENESIS_MULTIPLIER,
        BootstrapPhase::EarlyGrowth => {
            let range = early - genesis;
            let progress = node_count - genesis;
            let fraction = progress as f64 / range as f64;
            EARLY_GROWTH_MAX_MULTIPLIER
                - fraction * (EARLY_GROWTH_MAX_MULTIPLIER - EARLY_GROWTH_MIN_MULTIPLIER)
        }
        BootstrapPhase::Decentralization => {
            let range = decentral - early;
            let progress = node_count - early;
            let fraction = progress as f64 / range as f64;
            DECENTRALIZATION_MAX_MULTIPLIER
                - fraction * (DECENTRALIZATION_MAX_MULTIPLIER - BASE_MULTIPLIER)
        }
        BootstrapPhase::CriticalMass => BASE_MULTIPLIER,
    }
}

// ─── State ─────────────────────────────────────────────────────────────────

/// Tracks bootstrap phase transitions over time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapState {
    /// Current phase.
    pub current_phase: BootstrapPhase,
    /// Current unique node count.
    pub node_count: u64,
    /// Current reward multiplier.
    pub multiplier: f64,
    /// History of phase transitions: (timestamp, phase, node_count).
    pub transitions: Vec<(f64, BootstrapPhase, u64)>,
}

impl Default for BootstrapState {
    fn default() -> Self {
        Self {
            current_phase: BootstrapPhase::Genesis,
            node_count: 0,
            multiplier: GENESIS_MULTIPLIER,
            transitions: Vec::new(),
        }
    }
}

impl BootstrapState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the node count and detect phase transitions.
    /// Returns true if the phase changed.
    pub fn update(&mut self, node_count: u64, timestamp: f64) -> bool {
        self.update_with(node_count, timestamp, phase_boundaries())
    }

    /// Env-independent state update against explicit boundaries — the testable
    /// core. `update` is the testnet-aware wrapper.
    pub fn update_with(
        &mut self,
        node_count: u64,
        timestamp: f64,
        boundaries: (u64, u64, u64),
    ) -> bool {
        let new_phase = detect_phase_with(node_count, boundaries);
        self.node_count = node_count;
        self.multiplier = reward_multiplier_with(node_count, boundaries);

        if new_phase != self.current_phase {
            self.transitions
                .push((timestamp, new_phase, node_count));
            self.current_phase = new_phase;
            true
        } else {
            false
        }
    }

    /// Get the reward multiplier to apply to witness rewards.
    pub fn current_multiplier(&self) -> f64 {
        self.multiplier
    }

    /// Apply the bootstrap multiplier to a base reward amount.
    pub fn apply_multiplier(&self, base_reward: u64) -> u64 {
        (base_reward as f64 * self.multiplier) as u64
    }

    /// Number of phase transitions that have occurred.
    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }

    /// Summary for API endpoints.
    pub fn summary(&self) -> serde_json::Value {
        let (genesis, early, decentral) = phase_boundaries();
        serde_json::json!({
            "phase": self.current_phase.as_str(),
            "node_count": self.node_count,
            "multiplier": self.multiplier,
            "transitions": self.transitions.len(),
            "testnet": is_testnet(),
            "phase_boundaries": {
                "genesis": format!("1-{}", genesis),
                "early_growth": format!("{}-{}", genesis, early),
                "decentralization": format!("{}-{}", early, decentral),
                "critical_mass": format!("{}+", decentral),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::types::BASE_UNITS_PER_BEAT;

    // ── Deterministic mainnet test cores ─────────────────────────────────────
    // CI runs the whole suite with ELARA_TESTNET=true (faucet + bootstrap
    // testnet mode), which makes the env-reading `detect_phase`/`reward_multiplier`
    // return *testnet* phases. The unit tests below pin MAINNET behavior, so they
    // resolve to these env-independent `*_with(.., MAINNET_BOUNDARIES)` shadows
    // instead of the ambient-env wrappers — assertions stay terse and pass under
    // any ELARA_TESTNET value. (The testnet path is pinned separately, below.)
    fn detect_phase(node_count: u64) -> BootstrapPhase {
        super::detect_phase_with(node_count, MAINNET_BOUNDARIES)
    }
    fn reward_multiplier(node_count: u64) -> f64 {
        super::reward_multiplier_with(node_count, MAINNET_BOUNDARIES)
    }

    // ── Phase detection ─────────────────────────────────────────────────────

    #[test]
    fn test_phase_detection() {
        assert_eq!(detect_phase(0), BootstrapPhase::Genesis);
        assert_eq!(detect_phase(1), BootstrapPhase::Genesis);
        assert_eq!(detect_phase(9), BootstrapPhase::Genesis);
        assert_eq!(detect_phase(10), BootstrapPhase::EarlyGrowth);
        assert_eq!(detect_phase(500), BootstrapPhase::EarlyGrowth);
        assert_eq!(detect_phase(999), BootstrapPhase::EarlyGrowth);
        assert_eq!(detect_phase(1_000), BootstrapPhase::Decentralization);
        assert_eq!(detect_phase(5_000), BootstrapPhase::Decentralization);
        assert_eq!(detect_phase(9_999), BootstrapPhase::Decentralization);
        assert_eq!(detect_phase(10_000), BootstrapPhase::CriticalMass);
        assert_eq!(detect_phase(100_000), BootstrapPhase::CriticalMass);
    }

    // ── Reward multiplier ───────────────────────────────────────────────────

    #[test]
    fn test_genesis_no_rewards() {
        assert_eq!(reward_multiplier(0), 0.0);
        assert_eq!(reward_multiplier(5), 0.0);
        assert_eq!(reward_multiplier(9), 0.0);
    }

    #[test]
    fn test_early_growth_multiplier_range() {
        // At 10 nodes: 5.0x
        let m10 = reward_multiplier(10);
        assert!((m10 - 5.0).abs() < 0.01, "at 10 nodes: {m10}");

        // At 999 nodes: ~3.0x
        let m999 = reward_multiplier(999);
        assert!(m999 > 2.99 && m999 < 3.02, "at 999 nodes: {m999}");

        // Monotonically decreasing within phase
        assert!(reward_multiplier(10) > reward_multiplier(500));
        assert!(reward_multiplier(500) > reward_multiplier(999));
    }

    #[test]
    fn test_early_growth_midpoint() {
        // At ~505 nodes (midpoint): should be ~4.0
        let m = reward_multiplier(505);
        assert!(m > 3.9 && m < 4.1, "at 505 nodes: {m}");
    }

    #[test]
    fn test_decentralization_multiplier_range() {
        // At 1000 nodes: 3.0x
        let m1k = reward_multiplier(1_000);
        assert!((m1k - 3.0).abs() < 0.01, "at 1000 nodes: {m1k}");

        // At 9999 nodes: ~1.0x
        let m10k = reward_multiplier(9_999);
        assert!(m10k > 0.99 && m10k < 1.02, "at 9999 nodes: {m10k}");

        // Monotonically decreasing
        assert!(reward_multiplier(1_000) > reward_multiplier(5_000));
        assert!(reward_multiplier(5_000) > reward_multiplier(9_999));
    }

    #[test]
    fn test_critical_mass_base_rate() {
        assert_eq!(reward_multiplier(10_000), 1.0);
        assert_eq!(reward_multiplier(50_000), 1.0);
        assert_eq!(reward_multiplier(1_000_000), 1.0);
    }

    // ── State tracking ──────────────────────────────────────────────────────

    #[test]
    fn test_bootstrap_state_transitions() {
        let mut state = BootstrapState::new();
        assert_eq!(state.current_phase, BootstrapPhase::Genesis);
        assert_eq!(state.multiplier, 0.0);

        // Grow to 10 → EarlyGrowth
        assert!(state.update_with(10, 1000.0, MAINNET_BOUNDARIES));
        assert_eq!(state.current_phase, BootstrapPhase::EarlyGrowth);
        assert!((state.multiplier - 5.0).abs() < 0.01);

        // Grow to 1000 → Decentralization
        assert!(state.update_with(1_000, 2000.0, MAINNET_BOUNDARIES));
        assert_eq!(state.current_phase, BootstrapPhase::Decentralization);

        // Grow to 10000 → CriticalMass
        assert!(state.update_with(10_000, 3000.0, MAINNET_BOUNDARIES));
        assert_eq!(state.current_phase, BootstrapPhase::CriticalMass);
        assert_eq!(state.multiplier, 1.0);

        assert_eq!(state.transition_count(), 3);
    }

    #[test]
    fn test_no_transition_same_phase() {
        let mut state = BootstrapState::new();
        state.update_with(10, 1000.0, MAINNET_BOUNDARIES);
        // Still in EarlyGrowth at 50 nodes — no transition
        assert!(!state.update_with(50, 2000.0, MAINNET_BOUNDARIES));
        assert_eq!(state.transition_count(), 1);
    }

    #[test]
    fn test_apply_multiplier() {
        let mut state = BootstrapState::new();
        state.update_with(10, 1000.0, MAINNET_BOUNDARIES); // 5x multiplier

        let base = 100 * BASE_UNITS_PER_BEAT; // 100 beat base reward
        let boosted = state.apply_multiplier(base);
        assert_eq!(boosted, 500 * BASE_UNITS_PER_BEAT); // 500 beat
    }

    #[test]
    fn test_apply_multiplier_genesis_zero() {
        let state = BootstrapState::new(); // Genesis phase
        let base = 100 * BASE_UNITS_PER_BEAT;
        assert_eq!(state.apply_multiplier(base), 0); // No rewards in genesis
    }

    #[test]
    fn test_summary_json() {
        let mut state = BootstrapState::new();
        state.update_with(500, 1000.0, MAINNET_BOUNDARIES);
        let s = state.summary();
        assert_eq!(s["phase"], "early_growth");
        assert_eq!(s["node_count"], 500);
        assert!(s["multiplier"].as_f64().unwrap() > 3.0);
    }

    // ── Edge cases ──────────────────────────────────────────────────────────

    #[test]
    fn test_multiplier_continuity_at_boundaries() {
        // At each boundary, multiplier should be continuous (no jumps)
        let m_eg_end = reward_multiplier(999);
        let m_dec_start = reward_multiplier(1_000);
        // Both should be ~3.0
        assert!((m_eg_end - m_dec_start).abs() < 0.02,
            "discontinuity at EarlyGrowth→Decentralization: {m_eg_end} vs {m_dec_start}");

        let m_dec_end = reward_multiplier(9_999);
        let m_cm_start = reward_multiplier(10_000);
        // Both should be ~1.0
        assert!((m_dec_end - m_cm_start).abs() < 0.01,
            "discontinuity at Decentralization→CriticalMass: {m_dec_end} vs {m_cm_start}");
    }

    // ── phased-bootstrap ceiling tests (economics §14.2) ───────────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_phase_ceiling_constants_strict_pin_with_monotonic_and_testnet_ratio() {
        // Mainnet ceilings — strict values + 100× ratio between consecutive thresholds.
        assert_eq!(GENESIS_CEILING, 10);
        assert_eq!(EARLY_GROWTH_CEILING, 1_000);
        assert_eq!(DECENTRALIZATION_CEILING, 10_000);
        assert!(GENESIS_CEILING < EARLY_GROWTH_CEILING);
        assert!(EARLY_GROWTH_CEILING < DECENTRALIZATION_CEILING);
        assert_eq!(EARLY_GROWTH_CEILING, GENESIS_CEILING * 100);
        assert_eq!(DECENTRALIZATION_CEILING, EARLY_GROWTH_CEILING * 10);
        // Testnet ceilings — strict values + monotonic + lower than mainnet.
        assert_eq!(TESTNET_GENESIS_CEILING, 2);
        assert_eq!(TESTNET_EARLY_GROWTH_CEILING, 10);
        assert_eq!(TESTNET_DECENTRALIZATION_CEILING, 50);
        assert!(TESTNET_GENESIS_CEILING < TESTNET_EARLY_GROWTH_CEILING);
        assert!(TESTNET_EARLY_GROWTH_CEILING < TESTNET_DECENTRALIZATION_CEILING);
        assert!(TESTNET_GENESIS_CEILING < GENESIS_CEILING);
        assert!(TESTNET_DECENTRALIZATION_CEILING < DECENTRALIZATION_CEILING);
    }

    #[test]
    fn testnet_boundaries_shift_phase_thresholds_deterministically() {
        // The testnet path is what CI exercises with ELARA_TESTNET=true. Pin it
        // explicitly via the env-independent core so coverage no longer depends on
        // the ambient env (the mainnet shadows above intentionally bypass it).
        assert_eq!(detect_phase_with(1, TESTNET_BOUNDARIES), BootstrapPhase::Genesis);
        assert_eq!(detect_phase_with(2, TESTNET_BOUNDARIES), BootstrapPhase::EarlyGrowth);
        assert_eq!(detect_phase_with(10, TESTNET_BOUNDARIES), BootstrapPhase::Decentralization);
        assert_eq!(detect_phase_with(50, TESTNET_BOUNDARIES), BootstrapPhase::CriticalMass);
        // Genesis pays nothing on either network; testnet reaches EarlyGrowth far
        // earlier, so the same count diverges between the two boundary sets.
        assert_eq!(reward_multiplier_with(1, TESTNET_BOUNDARIES), 0.0);
        assert!(reward_multiplier_with(2, TESTNET_BOUNDARIES) > 4.99);
        assert_ne!(
            detect_phase_with(9, TESTNET_BOUNDARIES),
            detect_phase_with(9, MAINNET_BOUNDARIES),
        );
    }

    #[test]
    fn batch_b_bootstrap_phase_serde_snake_case_matches_as_str_with_distinctness() {
        let variants = [
            BootstrapPhase::Genesis,
            BootstrapPhase::EarlyGrowth,
            BootstrapPhase::Decentralization,
            BootstrapPhase::CriticalMass,
        ];
        // serde JSON tags must match as_str() output (load-bearing for /status RPC).
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let trimmed = json.trim_matches('"');
            assert_eq!(
                trimmed,
                v.as_str(),
                "serde tag must agree with as_str() for {v:?}"
            );
        }
        // Strict as_str() values pin.
        assert_eq!(BootstrapPhase::Genesis.as_str(), "genesis");
        assert_eq!(BootstrapPhase::EarlyGrowth.as_str(), "early_growth");
        assert_eq!(BootstrapPhase::Decentralization.as_str(), "decentralization");
        assert_eq!(BootstrapPhase::CriticalMass.as_str(), "critical_mass");
        // All 4 distinct under PartialEq.
        for i in 0..variants.len() {
            for j in 0..variants.len() {
                if i == j { assert_eq!(variants[i], variants[j]); }
                else { assert_ne!(variants[i], variants[j]); }
            }
        }
        // Display impl produces same as as_str().
        assert_eq!(format!("{}", BootstrapPhase::EarlyGrowth), "early_growth");
    }

    #[test]
    fn batch_b_bootstrap_state_new_equals_default_genesis_phase_invariant() {
        let s_new = BootstrapState::new();
        let s_def = BootstrapState::default();
        assert_eq!(s_new.current_phase, BootstrapPhase::Genesis);
        assert_eq!(s_def.current_phase, BootstrapPhase::Genesis);
        assert_eq!(s_new.node_count, 0);
        assert_eq!(s_def.node_count, 0);
        assert_eq!(s_new.multiplier, GENESIS_MULTIPLIER);
        assert_eq!(s_def.multiplier, GENESIS_MULTIPLIER);
        assert_eq!(s_new.multiplier, 0.0);
        assert!(s_new.transitions.is_empty());
        assert!(s_def.transitions.is_empty());
        assert_eq!(s_new.transition_count(), 0);
        assert_eq!(s_new.current_multiplier(), 0.0);
        // apply_multiplier on fresh Genesis state always zero.
        assert_eq!(s_new.apply_multiplier(1_000_000), 0);
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_multiplier_constants_pin_with_early_min_equals_decen_max_continuity() {
        // Individual strict pin for each multiplier constant.
        assert_eq!(GENESIS_MULTIPLIER, 0.0);
        assert_eq!(EARLY_GROWTH_MAX_MULTIPLIER, 5.0);
        assert_eq!(EARLY_GROWTH_MIN_MULTIPLIER, 3.0);
        assert_eq!(DECENTRALIZATION_MAX_MULTIPLIER, 3.0);
        assert_eq!(BASE_MULTIPLIER, 1.0);
        // Critical structural invariant: EarlyGrowth-end == Decentralization-start.
        // This is what makes `test_multiplier_continuity_at_boundaries` pass — pin it
        // here at the constant level so refactors can't drift the constants without
        // failing this test.
        assert_eq!(
            EARLY_GROWTH_MIN_MULTIPLIER, DECENTRALIZATION_MAX_MULTIPLIER,
            "EarlyGrowth→Decentralization boundary continuity requires these to match"
        );
        // Strict ordering: 0 < 1 < 3 < 5 — pins the multiplier ladder.
        assert!(GENESIS_MULTIPLIER < BASE_MULTIPLIER);
        assert!(BASE_MULTIPLIER < EARLY_GROWTH_MIN_MULTIPLIER);
        assert!(EARLY_GROWTH_MIN_MULTIPLIER < EARLY_GROWTH_MAX_MULTIPLIER);
        assert_eq!(EARLY_GROWTH_MAX_MULTIPLIER, BASE_MULTIPLIER * 5.0);
    }

    #[test]
    fn batch_b_detect_phase_u64_max_no_panic_with_post_genesis_monotonic_non_increasing() {
        // Large node count → CriticalMass (no panic, no overflow in interpolation).
        assert_eq!(detect_phase(u64::MAX), BootstrapPhase::CriticalMass);
        assert_eq!(reward_multiplier(u64::MAX), 1.0);
        // STRUCTURAL DESIGN: reward_multiplier intentionally JUMPS at the
        // Genesis→EarlyGrowth boundary (0 → 5) to bootstrap rewards. Pin
        // this discontinuity so a refactor can't accidentally smooth it.
        assert_eq!(reward_multiplier(9), 0.0);
        assert!(reward_multiplier(10) > 4.99);
        assert!(reward_multiplier(10) > reward_multiplier(9),
            "Genesis→EarlyGrowth must be an UPWARD jump by design");
        // POST-Genesis (node_count ≥ GENESIS_CEILING) monotonic non-increasing.
        let post_genesis = [10u64, 100, 500, 999, 1_000, 5_000, 9_999, 10_000, 100_000, 1_000_000];
        let mut prev = reward_multiplier(post_genesis[0]);
        for &n in &post_genesis[1..] {
            let cur = reward_multiplier(n);
            assert!(
                cur <= prev + 1e-9,
                "post-Genesis monotonic non-increasing violated: m({n})={cur} > prev={prev}"
            );
            prev = cur;
        }
        // Genesis range (0-9) all zero, CriticalMass range all 1.0 — invariant tails.
        assert_eq!(reward_multiplier(0), reward_multiplier(9));
        assert_eq!(reward_multiplier(10_000), reward_multiplier(1_000_000));
        // Global maximum is exactly EARLY_GROWTH_MAX at n=GENESIS_CEILING.
        let max_seen = post_genesis.iter().map(|&n| reward_multiplier(n)).fold(0.0_f64, f64::max);
        assert!((max_seen - EARLY_GROWTH_MAX_MULTIPLIER).abs() < 0.01);
    }
}
