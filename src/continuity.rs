//! Continuity Scoring (Protocol §11.33).
//!
//! Trust component measuring unbroken network presence.
//! Tracks consecutive days of activity, gaps, and recovery.
//!
//! Score ranges:
//! - New identity (< 24 hours):          continuity = 0.0
//! - Young identity (1-30 days):         continuity = 0.1 – 0.4
//! - Established identity (30-365 days): continuity = 0.4 – 0.8
//! - Veteran identity (1+ years):        continuity = 0.8 – 1.0
//!
//! Gaps in activity reduce the score. Recovery after gaps is penalized.

//!
//! Spec references:
//!   @spec Protocol §11.35

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─── Constants ─────────────────────────────────────────────────────────────

const SECS_PER_DAY: f64 = 86400.0;

/// Phase boundaries in days.
const YOUNG_THRESHOLD_DAYS: f64 = 1.0;
const ESTABLISHED_THRESHOLD_DAYS: f64 = 30.0;
const VETERAN_THRESHOLD_DAYS: f64 = 365.0;

/// Score ranges per phase.
const YOUNG_MIN: f64 = 0.1;
const YOUNG_MAX: f64 = 0.4;
const ESTABLISHED_MIN: f64 = 0.4;
const ESTABLISHED_MAX: f64 = 0.8;
const VETERAN_MIN: f64 = 0.8;
const VETERAN_MAX: f64 = 1.0;

/// Gap penalty: each day of inactivity reduces score by this fraction.
const GAP_PENALTY_PER_DAY: f64 = 0.02;

/// Minimum continuity score (never goes below this after first activity).
const MIN_SCORE: f64 = 0.05;

/// Maximum gap before score resets to near-zero (30 days).
const MAX_GAP_DAYS: f64 = 30.0;

// ─── Types ─────────────────────────────────────────────────────────────────

/// Continuity tracker for a single identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuityTracker {
    /// Identity hash.
    pub identity: String,
    /// First activity timestamp.
    pub first_seen: f64,
    /// Most recent activity timestamp.
    pub last_seen: f64,
    /// Total consecutive active days (resets on gaps > MAX_GAP_DAYS).
    pub consecutive_days: u64,
    /// Total active days (unique days with activity).
    pub total_active_days: u64,
    /// Number of gaps (periods of inactivity > 1 day).
    pub gap_count: u64,
    /// Longest gap in days.
    pub longest_gap_days: f64,
    /// Current computed score.
    pub score: f64,
}

impl ContinuityTracker {
    /// Create a new tracker on first activity.
    pub fn new(identity: &str, first_seen: f64) -> Self {
        Self {
            identity: identity.to_string(),
            first_seen,
            last_seen: first_seen,
            consecutive_days: 0,
            total_active_days: 1,
            gap_count: 0,
            longest_gap_days: 0.0,
            score: 0.0,
        }
    }

    /// Record activity at a given timestamp.
    pub fn record_activity(&mut self, timestamp: f64) {
        if timestamp <= self.last_seen {
            return; // No backwards time
        }

        let gap_days = (timestamp - self.last_seen) / SECS_PER_DAY;

        if gap_days > 1.0 {
            // Gap detected
            self.gap_count += 1;
            if gap_days > self.longest_gap_days {
                self.longest_gap_days = gap_days;
            }

            if gap_days > MAX_GAP_DAYS {
                // Major gap: reset consecutive days
                self.consecutive_days = 1;
            } else {
                // Minor gap: penalize but don't reset
                self.consecutive_days += 1;
            }
        } else {
            self.consecutive_days += 1;
        }

        self.total_active_days += 1;
        self.last_seen = timestamp;
        self.score = self.compute_score(timestamp);
    }

    /// Compute the continuity score at a given time.
    pub fn compute_score(&self, now: f64) -> f64 {
        let age_days = (now - self.first_seen) / SECS_PER_DAY;

        // Brand new identity: always 0.0
        if age_days < YOUNG_THRESHOLD_DAYS {
            return 0.0;
        }

        // Base score from age
        let base = if age_days < ESTABLISHED_THRESHOLD_DAYS {
            // Linear interpolation: 1d→0.1, 30d→0.4
            let t = (age_days - YOUNG_THRESHOLD_DAYS)
                / (ESTABLISHED_THRESHOLD_DAYS - YOUNG_THRESHOLD_DAYS);
            YOUNG_MIN + t * (YOUNG_MAX - YOUNG_MIN)
        } else if age_days < VETERAN_THRESHOLD_DAYS {
            // Linear interpolation: 30d→0.4, 365d→0.8
            let t = (age_days - ESTABLISHED_THRESHOLD_DAYS)
                / (VETERAN_THRESHOLD_DAYS - ESTABLISHED_THRESHOLD_DAYS);
            ESTABLISHED_MIN + t * (ESTABLISHED_MAX - ESTABLISHED_MIN)
        } else {
            // Asymptotic approach to 1.0
            let years_past = (age_days - VETERAN_THRESHOLD_DAYS) / 365.25;
            VETERAN_MIN + (VETERAN_MAX - VETERAN_MIN) * (1.0 - (-years_past * 0.5).exp())
        };

        // Gap penalty
        let current_gap = (now - self.last_seen) / SECS_PER_DAY;
        let penalty = if current_gap > 1.0 {
            (current_gap * GAP_PENALTY_PER_DAY).min(base - MIN_SCORE)
        } else {
            0.0
        };

        // Activity ratio bonus/penalty
        let expected_days = age_days.max(1.0);
        let activity_ratio = self.total_active_days as f64 / expected_days;
        let activity_factor = activity_ratio.min(1.0); // Cap at 1.0

        let adjusted = (base - penalty) * activity_factor;
        adjusted.max(if self.total_active_days > 0 {
            MIN_SCORE
        } else {
            0.0
        })
    }

    /// Age of this identity in days.
    pub fn age_days(&self, now: f64) -> f64 {
        (now - self.first_seen) / SECS_PER_DAY
    }

    /// Current gap in days (time since last activity).
    pub fn current_gap_days(&self, now: f64) -> f64 {
        (now - self.last_seen) / SECS_PER_DAY
    }
}

// ─── State ─────────────────────────────────────────────────────────────────

/// Tracks continuity scores for all identities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContinuityState {
    trackers: HashMap<String, ContinuityTracker>,
}

impl ContinuityState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record activity for an identity.
    pub fn record_activity(&mut self, identity: &str, timestamp: f64) {
        self.trackers
            .entry(identity.to_string())
            .and_modify(|t| t.record_activity(timestamp))
            .or_insert_with(|| ContinuityTracker::new(identity, timestamp));
    }

    /// Get the continuity score for an identity at a given time.
    pub fn score(&self, identity: &str, now: f64) -> f64 {
        self.trackers
            .get(identity)
            .map_or(0.0, |t| t.compute_score(now))
    }

    /// Get the tracker for an identity.
    pub fn tracker(&self, identity: &str) -> Option<&ContinuityTracker> {
        self.trackers.get(identity)
    }

    /// Number of tracked identities.
    pub fn identity_count(&self) -> usize {
        self.trackers.len()
    }

    /// Identities with score below a threshold at a given time.
    pub fn low_continuity(&self, threshold: f64, now: f64) -> Vec<&ContinuityTracker> {
        self.trackers
            .values()
            .filter(|t| t.compute_score(now) < threshold)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_identity_zero_score() {
        let t = ContinuityTracker::new("alice", 1000.0);
        // Brand new — score is 0 (< 24 hours)
        assert_eq!(t.compute_score(1000.0), 0.0);
    }

    #[test]
    fn test_young_identity_score() {
        let mut t = ContinuityTracker::new("alice", 0.0);
        // 15 days of daily activity
        for day in 1..=15 {
            t.record_activity(day as f64 * SECS_PER_DAY);
        }
        let score = t.compute_score(15.0 * SECS_PER_DAY);
        // Should be in young range (0.1-0.4)
        assert!((0.1..=0.4).contains(&score), "score={score}");
    }

    #[test]
    fn test_established_identity_score() {
        let mut t = ContinuityTracker::new("alice", 0.0);
        // 60 days of daily activity
        for day in 1..=60 {
            t.record_activity(day as f64 * SECS_PER_DAY);
        }
        let score = t.compute_score(60.0 * SECS_PER_DAY);
        // Should be in established range (0.4-0.8)
        assert!((0.4..=0.8).contains(&score), "score={score}");
    }

    #[test]
    fn test_veteran_identity_score() {
        let mut t = ContinuityTracker::new("alice", 0.0);
        // 400 days of daily activity
        for day in 1..=400 {
            t.record_activity(day as f64 * SECS_PER_DAY);
        }
        let score = t.compute_score(400.0 * SECS_PER_DAY);
        // Should be in veteran range (0.8-1.0)
        assert!((0.8..=1.0).contains(&score), "score={score}");
    }

    #[test]
    fn test_gap_reduces_score() {
        let mut t = ContinuityTracker::new("alice", 0.0);
        // 30 days active
        for day in 1..=30 {
            t.record_activity(day as f64 * SECS_PER_DAY);
        }
        let score_active = t.compute_score(30.0 * SECS_PER_DAY);

        // 10-day gap
        let score_gap = t.compute_score(40.0 * SECS_PER_DAY);
        assert!(score_gap < score_active, "gap should reduce score");
    }

    #[test]
    fn test_major_gap_resets_consecutive() {
        let mut t = ContinuityTracker::new("alice", 0.0);
        for day in 1..=10 {
            t.record_activity(day as f64 * SECS_PER_DAY);
        }
        assert_eq!(t.consecutive_days, 10);

        // 31-day gap (> MAX_GAP_DAYS)
        t.record_activity(41.0 * SECS_PER_DAY);
        assert_eq!(t.consecutive_days, 1);
        assert_eq!(t.gap_count, 1);
    }

    #[test]
    fn test_score_never_negative() {
        let t = ContinuityTracker::new("alice", 0.0);
        // Check score way in the future with no activity
        let score = t.compute_score(10000.0 * SECS_PER_DAY);
        assert!(score >= 0.0);
    }

    #[test]
    fn test_state_record_activity() {
        let mut state = ContinuityState::new();
        state.record_activity("alice", 0.0);
        state.record_activity("alice", SECS_PER_DAY);

        assert_eq!(state.identity_count(), 1);
        let tracker = state.tracker("alice").unwrap();
        assert_eq!(tracker.total_active_days, 2);
    }

    #[test]
    fn test_state_multiple_identities() {
        let mut state = ContinuityState::new();
        state.record_activity("alice", 0.0);
        state.record_activity("bob", 0.0);
        assert_eq!(state.identity_count(), 2);
    }

    #[test]
    fn test_state_unknown_identity_score() {
        let state = ContinuityState::new();
        assert_eq!(state.score("unknown", 1000.0), 0.0);
    }

    #[test]
    fn test_low_continuity_filter() {
        let mut state = ContinuityState::new();
        // Active identity
        state.record_activity("alice", 0.0);
        for day in 1..=60 {
            state.record_activity("alice", day as f64 * SECS_PER_DAY);
        }
        // New identity
        state.record_activity("bob", 59.0 * SECS_PER_DAY);

        let low = state.low_continuity(0.3, 60.0 * SECS_PER_DAY);
        // Bob should be low, Alice should be established
        assert!(low.iter().any(|t| t.identity == "bob"));
    }

    #[test]
    fn test_backwards_time_ignored() {
        let mut t = ContinuityTracker::new("alice", 100.0);
        t.record_activity(200.0);
        t.record_activity(50.0); // Should be ignored
        assert_eq!(t.last_seen, 200.0);
        assert_eq!(t.total_active_days, 2);
    }

    // ─── fixture-free ────────────────────────────────────
    //
    // Five axes covering surface NOT covered by existing semantic tests:
    //   1. Phase boundary constants strict-pin + cross-relations
    //      (YOUNG_MAX == ESTABLISHED_MIN, ESTABLISHED_MAX == VETERAN_MIN,
    //       VETERAN_MAX == 1.0, SECS_PER_DAY == 86400)
    //   2. ContinuityTracker::new() 8-field initial-state strict-pin
    //      + Clone + serde_json roundtrip preservation
    //   3. age_days + current_gap_days pure-formula sweep across
    //      positive/zero/negative time deltas
    //   4. compute_score AT-boundary behavior: age == 1.0/30.0/365.0
    //      exact day with no current gap, no inactivity gap
    //   5. record_activity boundary matrix: timestamp == last_seen
    //      idempotent reject, longest_gap_days max-tracking across
    //      multiple gaps, MAX_GAP_DAYS=30 vs 31-day boundary

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_continuity_constants_strict_pin_and_phase_boundary_cross_relations() {
        // SECS_PER_DAY pin — drift here silently rescales every age computation.
        assert_eq!(SECS_PER_DAY, 86400.0,
            "SECS_PER_DAY must be exactly 86400.0 (24*60*60)");
        assert_eq!(SECS_PER_DAY, 24.0 * 60.0 * 60.0,
            "SECS_PER_DAY must equal 24h × 60m × 60s");

        // Phase boundary days — used in compute_score interpolation.
        assert_eq!(YOUNG_THRESHOLD_DAYS, 1.0,
            "YOUNG_THRESHOLD_DAYS pins the new→young transition at 1 day");
        assert_eq!(ESTABLISHED_THRESHOLD_DAYS, 30.0,
            "ESTABLISHED_THRESHOLD_DAYS pins the young→established transition at 30 days");
        assert_eq!(VETERAN_THRESHOLD_DAYS, 365.0,
            "VETERAN_THRESHOLD_DAYS pins the established→veteran transition at 365 days");

        // Score range pins per phase.
        assert_eq!(YOUNG_MIN, 0.1);
        assert_eq!(YOUNG_MAX, 0.4);
        assert_eq!(ESTABLISHED_MIN, 0.4);
        assert_eq!(ESTABLISHED_MAX, 0.8);
        assert_eq!(VETERAN_MIN, 0.8);
        assert_eq!(VETERAN_MAX, 1.0);

        // Cross-relation: phase ranges must be CONTIGUOUS so a continuous
        // age sweep produces a continuous score sweep (no jumps).
        assert_eq!(YOUNG_MAX, ESTABLISHED_MIN,
            "phase-boundary continuity broken: YOUNG_MAX must equal ESTABLISHED_MIN");
        assert_eq!(ESTABLISHED_MAX, VETERAN_MIN,
            "phase-boundary continuity broken: ESTABLISHED_MAX must equal VETERAN_MIN");
        assert_eq!(VETERAN_MAX, 1.0,
            "VETERAN_MAX must reach the protocol's score ceiling of 1.0");

        // Other constants.
        assert_eq!(GAP_PENALTY_PER_DAY, 0.02,
            "gap penalty rate pin (2% score per day of inactivity)");
        assert_eq!(MIN_SCORE, 0.05,
            "MIN_SCORE floor pin — score never drops below 0.05 after first activity");
        assert_eq!(MAX_GAP_DAYS, 30.0,
            "MAX_GAP_DAYS pin — 30-day inactivity resets consecutive counter");

        // MIN_SCORE must lie strictly below YOUNG_MIN (otherwise a brand-new
        // identity with one record would land in the young range immediately).
        assert!(MIN_SCORE < YOUNG_MIN,
            "MIN_SCORE ({MIN_SCORE}) must be strictly below YOUNG_MIN ({YOUNG_MIN})");

        // Phase thresholds must be strictly ascending.
        assert!(YOUNG_THRESHOLD_DAYS < ESTABLISHED_THRESHOLD_DAYS);
        assert!(ESTABLISHED_THRESHOLD_DAYS < VETERAN_THRESHOLD_DAYS);
    }

    #[test]
    fn batch_b_tracker_new_initial_state_strict_pin_clone_and_serde_roundtrip() {
        // Strict initial-state pin on every field after ContinuityTracker::new.
        let t = ContinuityTracker::new("alice", 1234.5);
        assert_eq!(t.identity, "alice", "identity must be cloned from input");
        assert_eq!(t.first_seen, 1234.5,
            "first_seen must equal constructor timestamp argument");
        assert_eq!(t.last_seen, 1234.5,
            "last_seen must equal first_seen at construction (no activity yet)");
        assert_eq!(t.consecutive_days, 0,
            "consecutive_days must start at 0 (first call to record_activity counts day 1)");
        assert_eq!(t.total_active_days, 1,
            "total_active_days starts at 1 because constructor marks day-0 as active");
        assert_eq!(t.gap_count, 0,
            "gap_count must start at 0 — no activity history yet");
        assert_eq!(t.longest_gap_days, 0.0,
            "longest_gap_days must start at 0.0");
        assert_eq!(t.score, 0.0,
            "initial score is 0.0 — explicit compute_score required to populate");

        // Clone preserves every field byte-equal.
        let c = t.clone();
        assert_eq!(c.identity, t.identity);
        assert_eq!(c.first_seen, t.first_seen);
        assert_eq!(c.last_seen, t.last_seen);
        assert_eq!(c.consecutive_days, t.consecutive_days);
        assert_eq!(c.total_active_days, t.total_active_days);
        assert_eq!(c.gap_count, t.gap_count);
        assert_eq!(c.longest_gap_days, t.longest_gap_days);
        assert_eq!(c.score, t.score);

        // serde_json wire-format roundtrip preserves all 8 fields.
        let json = serde_json::to_string(&t).expect("ContinuityTracker must serialize");
        let back: ContinuityTracker = serde_json::from_str(&json)
            .expect("ContinuityTracker must deserialize");
        assert_eq!(back.identity, t.identity);
        assert_eq!(back.first_seen, t.first_seen);
        assert_eq!(back.last_seen, t.last_seen);
        assert_eq!(back.consecutive_days, t.consecutive_days);
        assert_eq!(back.total_active_days, t.total_active_days);
        assert_eq!(back.gap_count, t.gap_count);
        assert_eq!(back.longest_gap_days, t.longest_gap_days);
        assert_eq!(back.score, t.score);

        // Wire form contains all 8 snake_case field names.
        for field in &["identity", "first_seen", "last_seen", "consecutive_days",
                       "total_active_days", "gap_count", "longest_gap_days", "score"] {
            assert!(json.contains(field),
                "JSON wire form must contain `{field}` field name; got: {json}");
        }
    }

    #[test]
    fn batch_b_age_days_and_current_gap_days_pure_formula_sweep() {
        // age_days(now) = (now - first_seen) / SECS_PER_DAY
        // current_gap_days(now) = (now - last_seen) / SECS_PER_DAY
        // Both are pure (now - <fixed point>) / 86400 formulas.
        let t = ContinuityTracker::new("alice", 0.0);

        // Zero delta: age_days(0) == 0.0, current_gap_days(0) == 0.0.
        assert_eq!(t.age_days(0.0), 0.0,
            "age_days at constructor time must be 0.0");
        assert_eq!(t.current_gap_days(0.0), 0.0,
            "current_gap_days at constructor time must be 0.0");

        // Exact 1-day delta: must equal 1.0 (SECS_PER_DAY conversion).
        assert!((t.age_days(SECS_PER_DAY) - 1.0).abs() < f64::EPSILON,
            "age_days(SECS_PER_DAY) must equal 1.0");
        assert!((t.current_gap_days(SECS_PER_DAY) - 1.0).abs() < f64::EPSILON,
            "current_gap_days(SECS_PER_DAY) must equal 1.0");

        // Multi-day sweep: 7, 30, 365 days.
        for &expected_days in &[7.0_f64, 30.0, 365.0, 1000.0] {
            let now = expected_days * SECS_PER_DAY;
            assert!((t.age_days(now) - expected_days).abs() < 1e-9,
                "age_days({now}) drifted from {expected_days}");
            assert!((t.current_gap_days(now) - expected_days).abs() < 1e-9,
                "current_gap_days({now}) drifted from {expected_days}");
        }

        // Negative-time semantics: now < first_seen produces negative output.
        // This is a NON-PANIC contract — callers must handle it but the
        // helper itself must not error.
        let t2 = ContinuityTracker::new("bob", 1000.0 * SECS_PER_DAY);
        let neg_age = t2.age_days(0.0);
        assert!(neg_age < 0.0,
            "age_days BEFORE first_seen must produce negative output (non-panic): {neg_age}");
        assert!((neg_age + 1000.0).abs() < 1e-9,
            "negative age_days formula: (0 - 1000d) / 86400 = -1000.0; got {neg_age}");

        // Divergence between age_days and current_gap_days:
        // age = (now - first), gap = (now - last). When last_seen advances
        // beyond first_seen, gap < age.
        let mut t3 = ContinuityTracker::new("carol", 0.0);
        t3.record_activity(5.0 * SECS_PER_DAY);
        assert!((t3.age_days(10.0 * SECS_PER_DAY) - 10.0).abs() < 1e-9);
        assert!((t3.current_gap_days(10.0 * SECS_PER_DAY) - 5.0).abs() < 1e-9,
            "current_gap_days uses last_seen (5d), not first_seen (0d)");
    }

    #[test]
    fn batch_b_compute_score_phase_boundary_strict_below_above_and_continuity_at_exact_edges() {
        // BELOW YOUNG threshold (age < 1.0 day) → ALWAYS 0.0 regardless
        // of activity. This is the "brand-new" floor.
        let t = ContinuityTracker::new("alice", 0.0);
        assert_eq!(t.compute_score(0.0), 0.0,
            "age = 0 days must produce score 0.0");
        assert_eq!(t.compute_score(0.5 * SECS_PER_DAY), 0.0,
            "age = 0.5 days (< YOUNG threshold) must produce score 0.0");
        // Just-below-1-day boundary.
        assert_eq!(t.compute_score(0.999 * SECS_PER_DAY), 0.0,
            "age = 0.999 days (just below YOUNG threshold) must still produce 0.0");

        // EXACT YOUNG threshold (age == 1.0 day): falls through the
        // `< YOUNG_THRESHOLD_DAYS` gate → enters young-range interpolation.
        // With t=0 in the young interpolation: base = YOUNG_MIN = 0.1.
        // BUT the activity_factor reduces it: total_active_days=1, age=1.0,
        // expected=1.0 → ratio=1.0 → factor=1.0. So score = 0.1 * 1.0 = 0.1.
        let s_1d = t.compute_score(1.0 * SECS_PER_DAY);
        assert!((s_1d - YOUNG_MIN).abs() < 1e-9,
            "age = 1.0 day with 1 active day must score exactly YOUNG_MIN (0.1); got {s_1d}");

        // BUILD a fully-active identity (one activity per day) for boundary tests.
        let mut full = ContinuityTracker::new("bob", 0.0);
        for day in 1..=30 {
            full.record_activity(day as f64 * SECS_PER_DAY);
        }
        // Age = 30 days with 31 total_active_days (init + 30 records).
        // At exact ESTABLISHED boundary: falls through `< ESTABLISHED_THRESHOLD_DAYS`
        // gate → enters established-range with t=0 → base = ESTABLISHED_MIN = 0.4.
        // activity_factor = 31/30 capped to 1.0.
        let s_30d = full.compute_score(30.0 * SECS_PER_DAY);
        assert!((s_30d - ESTABLISHED_MIN).abs() < 1e-9,
            "age = 30 days (exact established boundary) with full activity must score \
             exactly ESTABLISHED_MIN (0.4); got {s_30d}");

        // 1-day past established boundary: tiny step into established interpolation.
        // t = (31 - 30) / (365 - 30) = 1/335 ≈ 0.002985
        // base = 0.4 + 0.002985 * 0.4 ≈ 0.40119
        let mut full2 = ContinuityTracker::new("carol", 0.0);
        for day in 1..=31 {
            full2.record_activity(day as f64 * SECS_PER_DAY);
        }
        let s_31d = full2.compute_score(31.0 * SECS_PER_DAY);
        assert!(s_31d > ESTABLISHED_MIN,
            "age = 31 days must score STRICTLY above ESTABLISHED_MIN; got {s_31d}");
        assert!(s_31d < ESTABLISHED_MAX,
            "age = 31 days must score below ESTABLISHED_MAX (0.8); got {s_31d}");
    }

    #[test]
    fn batch_b_record_activity_boundary_matrix_idempotent_and_longest_gap_and_30_vs_31_day_cutoff() {
        // Boundary 1: timestamp == last_seen is IDEMPOTENT (no-op).
        // The check is `if timestamp <= self.last_seen { return }` — note the
        // <=, so exact-equal timestamps are also rejected.
        let mut t = ContinuityTracker::new("alice", 100.0);
        let initial_total = t.total_active_days;
        let initial_consec = t.consecutive_days;
        t.record_activity(100.0); // SAME as first_seen / last_seen
        assert_eq!(t.last_seen, 100.0,
            "same-timestamp record must NOT advance last_seen");
        assert_eq!(t.total_active_days, initial_total,
            "same-timestamp record must NOT increment total_active_days");
        assert_eq!(t.consecutive_days, initial_consec,
            "same-timestamp record must NOT increment consecutive_days");

        // Boundary 2: longest_gap_days TRACKS THE MAX across multiple gaps.
        let mut t = ContinuityTracker::new("bob", 0.0);
        // First gap: 5 days.
        t.record_activity(6.0 * SECS_PER_DAY);
        assert!((t.longest_gap_days - 6.0).abs() < 1e-9,
            "first gap of 6 days must set longest_gap_days to 6.0; got {}", t.longest_gap_days);
        // Smaller second gap: 3 days — must NOT overwrite the longer one.
        t.record_activity(9.0 * SECS_PER_DAY);
        assert!((t.longest_gap_days - 6.0).abs() < 1e-9,
            "shorter subsequent gap (3 d) must NOT reduce longest_gap_days from 6.0; got {}",
            t.longest_gap_days);
        // Larger third gap: 10 days — must update longest.
        t.record_activity(19.0 * SECS_PER_DAY);
        assert!((t.longest_gap_days - 10.0).abs() < 1e-9,
            "longer subsequent gap (10 d) must update longest_gap_days; got {}",
            t.longest_gap_days);
        assert_eq!(t.gap_count, 3, "three gaps must increment gap_count to 3");

        // Boundary 3: MAX_GAP_DAYS = 30. At exactly 30 days gap (NOT > 30),
        // consecutive_days increments. At 30.001 (> 30), consecutive_days resets to 1.
        let mut t1 = ContinuityTracker::new("carol", 0.0);
        t1.record_activity(SECS_PER_DAY); // day 1
        assert_eq!(t1.consecutive_days, 1);

        // Exactly 30 days later (i.e., 31 days total from start).
        // gap_days from last_seen=86400 to now=86400+30*86400 = 30.0 days.
        // 30.0 > 1.0 → enters gap branch. 30.0 > 30.0 is FALSE → minor gap path.
        t1.record_activity(SECS_PER_DAY + 30.0 * SECS_PER_DAY);
        assert_eq!(t1.consecutive_days, 2,
            "exactly 30-day gap (NOT > MAX_GAP_DAYS) takes minor-gap branch, increments consecutive");

        // Now 30.001 days from last_seen → > MAX_GAP_DAYS → major gap → resets.
        let mut t2 = ContinuityTracker::new("dave", 0.0);
        t2.record_activity(SECS_PER_DAY);
        t2.record_activity(SECS_PER_DAY + 30.001 * SECS_PER_DAY);
        assert_eq!(t2.consecutive_days, 1,
            "gap > MAX_GAP_DAYS (30.001 d) must take major-gap branch and RESET consecutive to 1");
    }
}
