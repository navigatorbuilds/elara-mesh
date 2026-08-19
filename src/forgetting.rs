//! Real Forgetting — embedding weight decay and node retirement (EMERGENT-MIND §3).
//!
//! "A brain that remembers everything can't function. A network that stores
//! everything gets slower every day."
//!
//! Records nobody references, nobody predicts about, nobody witnesses —
//! gradually lose relevance. They don't disappear. They sink. Like memories
//! you can't access but would recognize if shown.
//!
//! Nodes that burn through their stake, lose all trust, and make too many
//! wrong predictions — their identity is retired. A new node takes its place.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─── Relevance Decay ─────────────────────────────────────────────────────────

/// Exponential decay half-life: 30 days in seconds.
/// After 30 days without a reference, a record's relevance halves.
pub const DECAY_HALF_LIFE_SECS: f64 = 30.0 * 24.0 * 3600.0;

/// Minimum relevance before a record is considered "sunken" (eligible for early GC).
pub const SUNKEN_THRESHOLD: f64 = 0.05;

/// Per-record relevance tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordRelevance {
    /// Number of times this record has been referenced as a DAG parent.
    pub reference_count: u32,
    /// Number of predictions targeting this record's zone+epoch.
    pub prediction_count: u32,
    /// Number of witness attestations on this record.
    pub witness_count: u32,
    /// Timestamp of the most recent reference (parent, prediction, or witness).
    pub last_referenced: f64,
    /// Timestamp when relevance tracking started for this record.
    pub created: f64,
}

impl RecordRelevance {
    pub fn new(created: f64) -> Self {
        Self {
            reference_count: 0,
            prediction_count: 0,
            witness_count: 0,
            last_referenced: created,
            created,
        }
    }

    /// Compute current relevance score [0.0, 1.0].
    ///
    /// Base relevance from activity (references, predictions, witnesses),
    /// multiplied by time decay since last reference.
    pub fn relevance(&self, now: f64) -> f64 {
        // Base: how much attention has this record received?
        // Each type of reference contributes diminishingly.
        let base = 1.0_f64
            .min(0.3 + 0.1 * self.reference_count as f64)
            .min(1.0)
            + 0.05 * self.prediction_count.min(10) as f64
            + 0.05 * self.witness_count.min(10) as f64;
        let base = base.min(1.0);

        // Time decay: exponential decay from last reference
        let elapsed = (now - self.last_referenced).max(0.0);
        let decay = (-elapsed * (2.0_f64.ln()) / DECAY_HALF_LIFE_SECS).exp();

        base * decay
    }

    /// Is this record "sunken" — below the threshold for early GC?
    pub fn is_sunken(&self, now: f64) -> bool {
        self.relevance(now) < SUNKEN_THRESHOLD
    }

    /// Record a new reference (DAG parent link).
    pub fn record_reference(&mut self, now: f64) {
        self.reference_count += 1;
        self.last_referenced = now;
    }

    /// Record a prediction targeting this record's context.
    pub fn record_prediction(&mut self, now: f64) {
        self.prediction_count += 1;
        self.last_referenced = now;
    }

    /// Record a witness attestation.
    pub fn record_witness(&mut self, now: f64) {
        self.witness_count += 1;
        self.last_referenced = now;
    }
}

/// Tracks relevance for all records in the network.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelevanceTracker {
    /// Record ID → relevance data.
    pub records: HashMap<String, RecordRelevance>,
}

impl RelevanceTracker {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    /// Start tracking a new record.
    pub fn track(&mut self, record_id: &str, created: f64) {
        self.records
            .entry(record_id.to_string())
            .or_insert_with(|| RecordRelevance::new(created));
    }

    /// Record a DAG parent reference.
    pub fn reference(&mut self, record_id: &str, now: f64) {
        if let Some(r) = self.records.get_mut(record_id) {
            r.record_reference(now);
        }
    }

    /// Record a prediction targeting a record's context.
    pub fn prediction_ref(&mut self, record_id: &str, now: f64) {
        if let Some(r) = self.records.get_mut(record_id) {
            r.record_prediction(now);
        }
    }

    /// Record a witness attestation.
    pub fn witness_ref(&mut self, record_id: &str, now: f64) {
        if let Some(r) = self.records.get_mut(record_id) {
            r.record_witness(now);
        }
    }

    /// Get all sunken record IDs (below relevance threshold).
    pub fn sunken_records(&self, now: f64) -> Vec<String> {
        self.records
            .iter()
            .filter(|(_, r)| r.is_sunken(now))
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Remove tracking data for pruned records.
    pub fn remove(&mut self, record_id: &str) {
        self.records.remove(record_id);
    }

    /// Total tracked records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

// ─── Node Health Monitoring ──────────────────────────────────────────────────
//
// Tracks prediction accuracy and health signals per identity.
// This is MONITORING ONLY — it does NOT force nodes offline.
// Economic incentives (lose stake on wrong predictions, lose reputation)
// already handle underperforming nodes. Dormancy reclaim (5-year inactive
// → beats to conservation pool) handles truly dead identities.

/// Criteria thresholds for health warnings.
pub const RETIREMENT_MIN_WRONG_PREDICTIONS: u32 = 10;
pub const RETIREMENT_MAX_ENTROPY: f64 = 0.2;
pub const RETIREMENT_MAX_REPUTATION: f64 = 20.0;

/// Assessment of whether a node should retire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetirementStatus {
    /// Node is healthy, no retirement needed.
    Healthy,
    /// Node is struggling but may recover.
    Warning {
        reasons: Vec<String>,
    },
    /// Node should retire — identity is burned out.
    ShouldRetire {
        reasons: Vec<String>,
    },
}

/// Per-identity retirement tracking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeHealth {
    /// Consecutive wrong predictions (resets on correct prediction).
    pub consecutive_wrong: u32,
    /// Total wrong predictions (lifetime).
    pub total_wrong: u32,
    /// Total correct predictions (lifetime).
    pub total_correct: u32,
    /// Current stake (base units).
    pub current_stake: u64,
    /// Current entropy score from trust engine.
    pub entropy: f64,
    /// Current reputation score [0, 100].
    pub reputation: f64,
}

impl NodeHealth {
    /// Record a correct prediction.
    pub fn prediction_correct(&mut self) {
        self.consecutive_wrong = 0;
        self.total_correct += 1;
    }

    /// Record a wrong prediction.
    pub fn prediction_wrong(&mut self) {
        self.consecutive_wrong += 1;
        self.total_wrong += 1;
    }

    /// Prediction accuracy (0.0 - 1.0).
    pub fn accuracy(&self) -> f64 {
        let total = self.total_correct + self.total_wrong;
        if total == 0 {
            return 0.5; // neutral for new nodes
        }
        self.total_correct as f64 / total as f64
    }

    /// Update external signals.
    pub fn update(&mut self, stake: u64, entropy: f64, reputation: f64) {
        self.current_stake = stake;
        self.entropy = entropy;
        self.reputation = reputation;
    }

    /// Assess retirement status.
    pub fn assess(&self) -> RetirementStatus {
        let mut reasons = Vec::new();

        if self.current_stake == 0 {
            reasons.push("zero stake".to_string());
        }
        if self.entropy < RETIREMENT_MAX_ENTROPY {
            reasons.push(format!("entropy {:.2} < {:.2}", self.entropy, RETIREMENT_MAX_ENTROPY));
        }
        if self.reputation < RETIREMENT_MAX_REPUTATION {
            reasons.push(format!("reputation {:.0} < {:.0}", self.reputation, RETIREMENT_MAX_REPUTATION));
        }
        if self.consecutive_wrong >= RETIREMENT_MIN_WRONG_PREDICTIONS {
            reasons.push(format!("{} consecutive wrong predictions", self.consecutive_wrong));
        }

        if reasons.len() >= 3 {
            RetirementStatus::ShouldRetire { reasons }
        } else if !reasons.is_empty() {
            RetirementStatus::Warning { reasons }
        } else {
            RetirementStatus::Healthy
        }
    }
}

/// Tracks health for all known node identities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetirementTracker {
    pub nodes: HashMap<String, NodeHealth>,
}

impl RetirementTracker {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    /// Get or create health tracking for an identity.
    pub fn health(&mut self, identity_hash: &str) -> &mut NodeHealth {
        self.nodes.entry(identity_hash.to_string()).or_default()
    }

    /// Get all identities that should retire.
    pub fn candidates_for_retirement(&self) -> Vec<(String, Vec<String>)> {
        self.nodes
            .iter()
            .filter_map(|(id, health)| match health.assess() {
                RetirementStatus::ShouldRetire { reasons } => {
                    Some((id.clone(), reasons))
                }
                _ => None,
            })
            .collect()
    }

    /// Remove tracking for a retired identity.
    pub fn remove(&mut self, identity_hash: &str) {
        self.nodes.remove(identity_hash);
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Relevance Decay ──

    #[test]
    fn test_new_record_relevance() {
        let r = RecordRelevance::new(1000.0);
        // Fresh record: base relevance from creation
        let rel = r.relevance(1000.0);
        assert!(rel > 0.0 && rel <= 1.0, "fresh record: {rel}");
    }

    #[test]
    fn test_relevance_decays_over_time() {
        let r = RecordRelevance::new(0.0);
        let r1 = r.relevance(0.0);
        let r2 = r.relevance(DECAY_HALF_LIFE_SECS); // 30 days
        let r3 = r.relevance(DECAY_HALF_LIFE_SECS * 2.0); // 60 days
        assert!(r2 < r1, "should decay: {r2} < {r1}");
        assert!(r3 < r2, "should decay further: {r3} < {r2}");
        // After one half-life, should be roughly half
        assert!((r2 / r1 - 0.5).abs() < 0.05, "half-life: {}/{} = {}", r2, r1, r2 / r1);
    }

    #[test]
    fn test_references_boost_relevance() {
        let mut r = RecordRelevance::new(0.0);
        let base = r.relevance(100.0);
        r.record_reference(100.0);
        r.record_reference(100.0);
        let boosted = r.relevance(100.0);
        assert!(boosted > base, "references should boost: {boosted} > {base}");
    }

    #[test]
    fn test_sunken_after_long_neglect() {
        let r = RecordRelevance::new(0.0);
        // After 6 months with no references
        let six_months = 180.0 * 24.0 * 3600.0;
        assert!(r.is_sunken(six_months), "should be sunken after 6 months neglect");
    }

    #[test]
    fn test_active_record_not_sunken() {
        let mut r = RecordRelevance::new(0.0);
        // Heavily referenced
        for i in 0..10 {
            r.record_reference(i as f64 * 1000.0);
        }
        assert!(!r.is_sunken(10000.0), "active record should not be sunken");
    }

    #[test]
    fn test_tracker_sunken_records() {
        let mut tracker = RelevanceTracker::new();
        tracker.track("old", 0.0);
        tracker.track("new", 100.0);

        let six_months = 180.0 * 24.0 * 3600.0;
        // Reference "new" recently
        tracker.reference("new", six_months - 100.0);

        let sunken = tracker.sunken_records(six_months);
        assert!(sunken.contains(&"old".to_string()));
        assert!(!sunken.contains(&"new".to_string()));
    }

    // ── Node Retirement ──

    #[test]
    fn test_healthy_node() {
        let health = NodeHealth {
            current_stake: 1000,
            entropy: 0.8,
            reputation: 75.0,
            consecutive_wrong: 0,
            total_correct: 50,
            total_wrong: 5,
        };
        assert_eq!(health.assess(), RetirementStatus::Healthy);
    }

    #[test]
    fn test_warning_node() {
        let health = NodeHealth {
            current_stake: 0, // one problem
            entropy: 0.8,
            reputation: 75.0,
            consecutive_wrong: 2,
            total_correct: 50,
            total_wrong: 5,
        };
        match health.assess() {
            RetirementStatus::Warning { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert!(reasons[0].contains("zero stake"));
            }
            other => panic!("expected Warning, got {:?}", other),
        }
    }

    #[test]
    fn test_should_retire() {
        let health = NodeHealth {
            current_stake: 0,         // problem 1
            entropy: 0.1,             // problem 2
            reputation: 10.0,         // problem 3
            consecutive_wrong: 15,    // problem 4
            total_correct: 2,
            total_wrong: 50,
        };
        match health.assess() {
            RetirementStatus::ShouldRetire { reasons } => {
                assert!(reasons.len() >= 3);
            }
            other => panic!("expected ShouldRetire, got {:?}", other),
        }
    }

    #[test]
    fn test_prediction_tracking() {
        let mut health = NodeHealth::default();
        health.prediction_correct();
        health.prediction_correct();
        health.prediction_wrong();
        assert_eq!(health.total_correct, 2);
        assert_eq!(health.total_wrong, 1);
        assert_eq!(health.consecutive_wrong, 1);

        health.prediction_correct();
        assert_eq!(health.consecutive_wrong, 0); // reset on correct
    }

    #[test]
    fn test_accuracy() {
        let health = NodeHealth {
            total_correct: 80,
            total_wrong: 20,
            ..Default::default()
        };
        assert!((health.accuracy() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_accuracy_new_node() {
        let health = NodeHealth::default();
        assert!((health.accuracy() - 0.5).abs() < 0.001); // neutral
    }

    #[test]
    fn test_retirement_candidates() {
        let mut tracker = RetirementTracker::new();
        // Healthy node
        tracker.health("good").update(1000, 0.8, 75.0);
        // Burned-out node
        let bad = tracker.health("bad");
        bad.update(0, 0.1, 10.0);
        bad.consecutive_wrong = 15;

        let candidates = tracker.candidates_for_retirement();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, "bad");
    }

    // ─── fixture-free, pure helpers ─────────────────────

    /// All 5 module constants strict-pin + arithmetic cross-checks (half-life
    /// expressed multiple ways, threshold magnitudes, cross-relations).
    /// Locks the policy contract for relevance decay + retirement thresholds.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_forgetting_module_constants_strict_pin_and_arithmetic_relations() {
        // DECAY_HALF_LIFE_SECS = 30 days, multiple arithmetic forms.
        assert_eq!(DECAY_HALF_LIFE_SECS, 30.0 * 24.0 * 3600.0);
        assert_eq!(DECAY_HALF_LIFE_SECS, 30.0 * 86400.0);
        assert_eq!(DECAY_HALF_LIFE_SECS, 2_592_000.0);
        assert!(DECAY_HALF_LIFE_SECS > 0.0);
        assert!(DECAY_HALF_LIFE_SECS.is_finite());
        // 30 days in minutes/hours cross-check.
        assert_eq!(DECAY_HALF_LIFE_SECS / 60.0, 43_200.0);   // minutes in 30d
        assert_eq!(DECAY_HALF_LIFE_SECS / 3600.0, 720.0);    // hours in 30d
        assert_eq!(DECAY_HALF_LIFE_SECS / 86400.0, 30.0);    // days

        // SUNKEN_THRESHOLD strict-pin.
        assert_eq!(SUNKEN_THRESHOLD, 0.05);
        assert!(SUNKEN_THRESHOLD > 0.0);
        assert!(SUNKEN_THRESHOLD < 1.0);
        assert!(SUNKEN_THRESHOLD < 0.5,
            "must be far below mid-relevance else healthy records sink");

        // Retirement criteria thresholds.
        assert_eq!(RETIREMENT_MIN_WRONG_PREDICTIONS, 10);
        assert_eq!(RETIREMENT_MAX_ENTROPY, 0.2);
        assert_eq!(RETIREMENT_MAX_REPUTATION, 20.0);
        assert!(RETIREMENT_MIN_WRONG_PREDICTIONS > 0);
        assert!(RETIREMENT_MAX_ENTROPY > 0.0);
        assert!(RETIREMENT_MAX_ENTROPY < 1.0);
        assert!(RETIREMENT_MAX_REPUTATION > 0.0);
        assert!(RETIREMENT_MAX_REPUTATION <= 100.0,
            "reputation is on [0,100] scale per NodeHealth doc");

        // Reputation threshold below mid-scale (50) — only severely degraded
        // nodes trigger.
        assert!(RETIREMENT_MAX_REPUTATION < 50.0);
        // Entropy threshold below mid-scale (0.5) — only severely degraded
        // identities trigger.
        assert!(RETIREMENT_MAX_ENTROPY < 0.5);

        // Numeric types pin (u32 / f64).
        let _: u32 = RETIREMENT_MIN_WRONG_PREDICTIONS;
        let _: f64 = RETIREMENT_MAX_ENTROPY;
        let _: f64 = RETIREMENT_MAX_REPUTATION;
        let _: f64 = DECAY_HALF_LIFE_SECS;
        let _: f64 = SUNKEN_THRESHOLD;
    }

    /// RecordRelevance::new initial-state shape pin + 5-field struct pin +
    /// Clone independence + serde JSON round-trip + counter monotonicity
    /// (record_reference/prediction/witness each advance exactly one counter
    /// and update last_referenced without touching the others).
    #[test]
    fn batch_b_record_relevance_initial_state_clone_serde_and_counter_monotonicity() {
        let r = RecordRelevance::new(1234.5);
        // 5-field initial state.
        assert_eq!(r.reference_count, 0);
        assert_eq!(r.prediction_count, 0);
        assert_eq!(r.witness_count, 0);
        assert_eq!(r.last_referenced, 1234.5);
        assert_eq!(r.created, 1234.5);
        // last_referenced == created at construction (load-bearing — relevance
        // computed at now=created gets zero elapsed → decay multiplier 1.0).
        assert_eq!(r.last_referenced, r.created);

        // Clone independence.
        let mut clone = r.clone();
        clone.record_reference(5000.0);
        assert_eq!(r.reference_count, 0, "original untouched");
        assert_eq!(r.last_referenced, 1234.5);
        assert_eq!(clone.reference_count, 1);
        assert_eq!(clone.last_referenced, 5000.0);

        // Serde JSON round-trip preserves all 5 fields.
        let mut r = RecordRelevance::new(100.0);
        r.record_reference(200.0);
        r.record_prediction(300.0);
        r.record_witness(400.0);
        let json = serde_json::to_string(&r).expect("ser");
        let back: RecordRelevance = serde_json::from_str(&json).expect("de");
        assert_eq!(back.reference_count, r.reference_count);
        assert_eq!(back.prediction_count, r.prediction_count);
        assert_eq!(back.witness_count, r.witness_count);
        assert_eq!(back.last_referenced, r.last_referenced);
        assert_eq!(back.created, r.created);

        // Counter monotonicity — each method touches its OWN counter + last_ref.
        let mut r = RecordRelevance::new(0.0);
        r.record_reference(10.0);
        assert_eq!(r.reference_count, 1);
        assert_eq!(r.prediction_count, 0);
        assert_eq!(r.witness_count, 0);
        assert_eq!(r.last_referenced, 10.0);
        assert_eq!(r.created, 0.0, "created never changes");

        r.record_prediction(20.0);
        assert_eq!(r.reference_count, 1, "reference unchanged");
        assert_eq!(r.prediction_count, 1);
        assert_eq!(r.witness_count, 0);
        assert_eq!(r.last_referenced, 20.0);

        r.record_witness(30.0);
        assert_eq!(r.reference_count, 1);
        assert_eq!(r.prediction_count, 1);
        assert_eq!(r.witness_count, 1, "witness incremented");
        assert_eq!(r.last_referenced, 30.0);

        // Repeated calls increment without bound until u32::MAX (not pinned
        // here, but document the type).
        for _ in 0..100 {
            r.record_reference(40.0);
        }
        assert_eq!(r.reference_count, 101);
        assert_eq!(r.last_referenced, 40.0);

        // Debug non-empty + contains all 5 field names.
        let dbg = format!("{:?}", r);
        for field in ["reference_count", "prediction_count", "witness_count",
                      "last_referenced", "created"] {
            assert!(dbg.contains(field), "Debug missing {field}");
        }
    }

    /// relevance(t) saturation behavior: capped at 1.0 even at 10^6
    /// references, exact decay at half-life boundary, sunken-after-many-
    /// half-lives, time-decay monotonic (t1 < t2 ⟹ relevance(t1) >=
    /// relevance(t2) when nothing else changes), now < last_referenced is
    /// clamped (elapsed = max(0, now-last_ref) so relevance doesn't grow
    /// backwards), all values lie in [0,1].
    #[test]
    fn batch_b_relevance_saturation_decay_monotonicity_and_clock_skew_clamp() {
        // Saturation: huge reference_count doesn't exceed 1.0.
        let mut r = RecordRelevance::new(0.0);
        for _ in 0..1_000_000 {
            r.record_reference(0.0);
        }
        let rel = r.relevance(0.0);
        assert!(rel <= 1.0, "saturation: {rel}");
        assert!(rel > 0.0);

        // Same saturation for prediction + witness (the .min(10) cap in
        // base formula ensures even 1M of either doesn't blow it up).
        let mut r = RecordRelevance::new(0.0);
        for _ in 0..1_000_000 {
            r.record_prediction(0.0);
        }
        for _ in 0..1_000_000 {
            r.record_witness(0.0);
        }
        let rel = r.relevance(0.0);
        assert!(rel <= 1.0);

        // All relevance values in [0, 1] for sweep of inputs.
        let r = RecordRelevance::new(0.0);
        for t in [0.0, 1.0, 100.0, 86400.0, DECAY_HALF_LIFE_SECS,
                  DECAY_HALF_LIFE_SECS * 2.0, DECAY_HALF_LIFE_SECS * 10.0,
                  1e9, 1e12] {
            let rel = r.relevance(t);
            assert!((0.0..=1.0).contains(&rel), "rel({t}) = {rel} out of [0,1]");
        }

        // Half-life exactness: relevance at t=half-life ≈ 50% of t=0.
        let r = RecordRelevance::new(0.0);
        let r0 = r.relevance(0.0);
        let r_half = r.relevance(DECAY_HALF_LIFE_SECS);
        let r_two_half = r.relevance(DECAY_HALF_LIFE_SECS * 2.0);
        assert!((r_half / r0 - 0.5).abs() < 0.01,
            "half-life ≈ 50%: {}/{} = {}", r_half, r0, r_half / r0);
        assert!((r_two_half / r0 - 0.25).abs() < 0.01,
            "two half-lives ≈ 25%: {}/{} = {}", r_two_half, r0, r_two_half / r0);

        // Time-decay monotonicity over a sweep (no references in between).
        let mut prev = f64::INFINITY;
        for t in [0.0, 100.0, 86400.0, DECAY_HALF_LIFE_SECS,
                  DECAY_HALF_LIFE_SECS * 2.0, DECAY_HALF_LIFE_SECS * 5.0,
                  DECAY_HALF_LIFE_SECS * 10.0] {
            let rel = r.relevance(t);
            assert!(rel <= prev + 1e-9,
                "rel({t})={rel} not <= prev={prev}");
            prev = rel;
        }

        // Clock skew clamp: now < last_referenced shouldn't blow up; elapsed
        // is max(0, ...) so decay = exp(0) = 1 → relevance returns BASE,
        // matching the now==last_referenced case (load-bearing for clock-skew
        // resilience — peers with skewed clocks must not report higher
        // relevance from earlier timestamps).
        let mut r = RecordRelevance::new(1000.0);
        r.record_reference(1000.0);
        let at_create = r.relevance(1000.0);
        let in_past = r.relevance(0.0);
        assert!((at_create - in_past).abs() < 1e-9,
            "past time clamped: at={at_create} past={in_past}");

        // is_sunken cross-check: relevance below threshold ⟹ is_sunken.
        let r = RecordRelevance::new(0.0);
        let very_late = DECAY_HALF_LIFE_SECS * 20.0; // ~600 days
        let rel = r.relevance(very_late);
        assert!(rel < SUNKEN_THRESHOLD, "must be below threshold");
        assert!(r.is_sunken(very_late));
        // And not sunken at creation.
        assert!(!r.is_sunken(0.0));
    }

    /// RetirementStatus 3-variant enum + assess() bucketing rule:
    /// reasons.len() == 0 → Healthy, 1..=2 → Warning, >=3 → ShouldRetire.
    /// PartialEq across variants. accuracy() boundaries: 0-total → 0.5
    /// (neutral), all-correct → 1.0, all-wrong → 0.0. consecutive_wrong
    /// resets on prediction_correct().
    #[test]
    fn batch_b_retirement_status_buckets_assess_thresholds_and_accuracy_boundaries() {
        // Healthy: 0 reasons → Healthy.
        let h = NodeHealth {
            current_stake: 1000,
            entropy: 0.8,
            reputation: 75.0,
            consecutive_wrong: 0,
            total_correct: 10,
            total_wrong: 1,
        };
        assert_eq!(h.assess(), RetirementStatus::Healthy);

        // PartialEq: Healthy == Healthy.
        assert_eq!(RetirementStatus::Healthy, RetirementStatus::Healthy);
        // Warning != Healthy.
        assert_ne!(RetirementStatus::Warning { reasons: vec!["x".into()] },
                   RetirementStatus::Healthy);
        // Warning with same reasons == Warning with same reasons.
        let w1 = RetirementStatus::Warning { reasons: vec!["a".into(), "b".into()] };
        let w2 = RetirementStatus::Warning { reasons: vec!["a".into(), "b".into()] };
        assert_eq!(w1, w2);
        // Different reasons → not equal.
        let w3 = RetirementStatus::Warning { reasons: vec!["a".into()] };
        assert_ne!(w1, w3);
        // Warning != ShouldRetire even with same reasons.
        let s = RetirementStatus::ShouldRetire { reasons: vec!["a".into(), "b".into()] };
        assert_ne!(w1, s);

        // Boundary 0 → Healthy.
        // Boundary 1 → Warning (low-stake only).
        let h = NodeHealth {
            current_stake: 0,
            entropy: 0.8,
            reputation: 75.0,
            consecutive_wrong: 0,
            total_correct: 10,
            total_wrong: 1,
        };
        match h.assess() {
            RetirementStatus::Warning { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert!(reasons[0].contains("zero stake"));
            }
            other => panic!("expected Warning, got {:?}", other),
        }

        // Boundary 2 → Warning.
        let h = NodeHealth {
            current_stake: 0,
            entropy: 0.1,
            reputation: 75.0,
            consecutive_wrong: 0,
            total_correct: 10,
            total_wrong: 1,
        };
        match h.assess() {
            RetirementStatus::Warning { reasons } => assert_eq!(reasons.len(), 2),
            other => panic!("expected Warning(2), got {:?}", other),
        }

        // Boundary 3 → ShouldRetire (exact cutoff).
        let h = NodeHealth {
            current_stake: 0,
            entropy: 0.1,
            reputation: 10.0,
            consecutive_wrong: 0,
            total_correct: 10,
            total_wrong: 1,
        };
        match h.assess() {
            RetirementStatus::ShouldRetire { reasons } => assert_eq!(reasons.len(), 3),
            other => panic!("expected ShouldRetire(3), got {:?}", other),
        }

        // Consecutive-wrong threshold: < RETIREMENT_MIN_WRONG_PREDICTIONS
        // does NOT contribute a reason; >= does.
        let h = NodeHealth {
            current_stake: 1000,
            entropy: 0.8,
            reputation: 75.0,
            consecutive_wrong: RETIREMENT_MIN_WRONG_PREDICTIONS - 1,
            total_correct: 0,
            total_wrong: 0,
        };
        assert_eq!(h.assess(), RetirementStatus::Healthy);

        let h = NodeHealth {
            current_stake: 1000,
            entropy: 0.8,
            reputation: 75.0,
            consecutive_wrong: RETIREMENT_MIN_WRONG_PREDICTIONS,
            total_correct: 0,
            total_wrong: 0,
        };
        match h.assess() {
            RetirementStatus::Warning { reasons } => {
                assert!(reasons[0].contains("consecutive wrong"));
            }
            other => panic!("expected Warning, got {:?}", other),
        }

        // Entropy boundary: AT threshold = NOT triggered (entropy < threshold).
        let h = NodeHealth {
            current_stake: 1000,
            entropy: RETIREMENT_MAX_ENTROPY,
            reputation: 75.0,
            consecutive_wrong: 0,
            total_correct: 0,
            total_wrong: 0,
        };
        assert_eq!(h.assess(), RetirementStatus::Healthy);

        // Reputation boundary: AT threshold = NOT triggered (reputation < threshold).
        let h = NodeHealth {
            current_stake: 1000,
            entropy: 0.8,
            reputation: RETIREMENT_MAX_REPUTATION,
            consecutive_wrong: 0,
            total_correct: 0,
            total_wrong: 0,
        };
        assert_eq!(h.assess(), RetirementStatus::Healthy);

        // accuracy() boundaries.
        let h0 = NodeHealth::default();
        assert_eq!(h0.accuracy(), 0.5, "zero-total → neutral 0.5");
        let all_right = NodeHealth { total_correct: 100, total_wrong: 0, ..Default::default() };
        assert_eq!(all_right.accuracy(), 1.0);
        let all_wrong = NodeHealth { total_correct: 0, total_wrong: 100, ..Default::default() };
        assert_eq!(all_wrong.accuracy(), 0.0);
        // 80/20 split = 0.8.
        let mixed = NodeHealth { total_correct: 80, total_wrong: 20, ..Default::default() };
        assert!((mixed.accuracy() - 0.8).abs() < 1e-9);
        // Single sample: 1/0 = 1.0; 0/1 = 0.0.
        let one_right = NodeHealth { total_correct: 1, total_wrong: 0, ..Default::default() };
        assert_eq!(one_right.accuracy(), 1.0);
        let one_wrong = NodeHealth { total_correct: 0, total_wrong: 1, ..Default::default() };
        assert_eq!(one_wrong.accuracy(), 0.0);

        // prediction_correct resets consecutive_wrong but does NOT reduce total_wrong.
        let mut h = NodeHealth::default();
        for _ in 0..5 {
            h.prediction_wrong();
        }
        assert_eq!(h.consecutive_wrong, 5);
        assert_eq!(h.total_wrong, 5);
        h.prediction_correct();
        assert_eq!(h.consecutive_wrong, 0, "reset on correct");
        assert_eq!(h.total_wrong, 5, "total_wrong NOT reset");
        assert_eq!(h.total_correct, 1);
    }

    /// RelevanceTracker and RetirementTracker initial-state pins + new ==
    /// default + idempotent track (registering same id twice keeps original
    /// created, doesn't reset counters) + remove() handles missing id
    /// silently + sunken_records / candidates_for_retirement on empty
    /// tracker return empty Vec + reference/prediction/witness on
    /// untracked id is silent no-op (no panic, no insert).
    #[test]
    fn batch_b_trackers_initial_state_idempotent_track_and_silent_no_op_paths() {
        // RelevanceTracker::new == default.
        let n = RelevanceTracker::new();
        let d: RelevanceTracker = RelevanceTracker::default();
        assert_eq!(n.len(), 0);
        assert!(n.is_empty());
        assert_eq!(d.len(), 0);
        assert!(d.is_empty());
        assert!(n.sunken_records(0.0).is_empty());
        assert!(n.sunken_records(1e12).is_empty());

        // Reference on untracked id: silent no-op (HashMap::get_mut returns None).
        let mut t = RelevanceTracker::new();
        t.reference("never_tracked", 100.0);
        t.prediction_ref("never_tracked", 100.0);
        t.witness_ref("never_tracked", 100.0);
        assert!(t.is_empty(), "no insert side-effect");

        // Track creates entry on first call.
        t.track("r1", 50.0);
        assert_eq!(t.len(), 1);
        let r1 = t.records.get("r1").unwrap();
        assert_eq!(r1.created, 50.0);
        assert_eq!(r1.reference_count, 0);

        // Idempotent track: second call with same id does NOT reset
        // created or any counter (or_insert_with is no-op when key exists).
        // First mutate r1 via reference, then re-track and verify state preserved.
        t.reference("r1", 100.0);
        assert_eq!(t.records.get("r1").unwrap().reference_count, 1);
        t.track("r1", 999.0); // would-be re-init with different created
        let r1 = t.records.get("r1").unwrap();
        assert_eq!(r1.created, 50.0, "original created preserved");
        assert_eq!(r1.reference_count, 1, "counter preserved");
        assert_eq!(t.len(), 1, "still 1 entry");

        // reference now mutates existing entry.
        t.reference("r1", 200.0);
        assert_eq!(t.records.get("r1").unwrap().reference_count, 2);
        assert_eq!(t.records.get("r1").unwrap().last_referenced, 200.0);

        // remove existing id.
        t.remove("r1");
        assert!(t.is_empty());
        // remove missing id is silent.
        t.remove("ghost");
        assert!(t.is_empty());

        // sunken_records collects all sunken ids; respects creation time.
        let mut t = RelevanceTracker::new();
        t.track("ancient", 0.0);
        t.track("recent", 1e9 - 100.0);
        let now = 1e9;
        let sunken: std::collections::HashSet<String> = t.sunken_records(now).into_iter().collect();
        assert!(sunken.contains("ancient"), "ancient should sink");
        assert!(!sunken.contains("recent"), "recent should not");

        // RetirementTracker::new == default.
        let n = RetirementTracker::new();
        let d: RetirementTracker = RetirementTracker::default();
        assert_eq!(n.nodes.len(), 0);
        assert_eq!(d.nodes.len(), 0);
        assert!(n.candidates_for_retirement().is_empty());
        assert!(d.candidates_for_retirement().is_empty());

        // health() auto-creates entry with Default values.
        let mut r = RetirementTracker::new();
        let h = r.health("new_id");
        assert_eq!(h.current_stake, 0);
        assert_eq!(h.entropy, 0.0);
        assert_eq!(h.reputation, 0.0);
        assert_eq!(h.consecutive_wrong, 0);
        assert_eq!(h.total_correct, 0);
        assert_eq!(h.total_wrong, 0);
        assert_eq!(r.nodes.len(), 1);

        // health() on existing id returns the SAME entry (not a fresh one).
        // Mutate via first reference, then re-fetch and verify state.
        r.health("new_id").update(500, 0.7, 60.0);
        let h2 = r.health("new_id");
        assert_eq!(h2.current_stake, 500, "preserved across re-fetch");
        assert_eq!(h2.entropy, 0.7);
        assert_eq!(h2.reputation, 60.0);
        assert_eq!(r.nodes.len(), 1, "no duplicate entry");

        // remove() works + handles missing silently.
        r.remove("new_id");
        assert_eq!(r.nodes.len(), 0);
        r.remove("missing");
        assert_eq!(r.nodes.len(), 0);

        // candidates_for_retirement only returns ShouldRetire (not Warning).
        let mut r = RetirementTracker::new();
        r.health("warning_only").update(0, 0.8, 75.0); // 1 reason → Warning
        let h = r.health("retire_now");
        h.update(0, 0.1, 10.0);
        h.consecutive_wrong = 20; // 4 reasons → ShouldRetire
        let cands = r.candidates_for_retirement();
        assert_eq!(cands.len(), 1, "only retire-status node listed");
        assert_eq!(cands[0].0, "retire_now");
        assert!(cands[0].1.len() >= 3, "reasons attached");
    }
}
