//! Reincarnation Detection (Protocol §11.33).
//!
//! Behavioral fingerprinting to detect identity resets from the same
//! physical device or operator. When an identity is abandoned (slashed,
//! reputation destroyed) and a "new" identity appears with suspiciously
//! similar characteristics, this module flags it.
//!
//! Signals used for detection:
//! 1. Timing patterns — activity hour distribution, submission intervals
//! 2. Network origin — IP range / geographic proximity (hashed for privacy)
//! 3. Content fingerprints — metadata patterns, record size distribution
//! 4. Hardware attestation — same device hardware profile
//!
//! Suspected reincarnations get reduced initial trust.

//!
//! Spec references:
//!   @spec Protocol §6.4

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Number of hourly buckets for timing fingerprint.
const TIMING_BUCKETS: usize = 24;

/// Similarity threshold for flagging (0.0-1.0). Above this = suspected reincarnation.
const REINCARNATION_THRESHOLD: f64 = 0.75;

/// Trust reduction factor for suspected reincarnations.
const REINCARNATION_TRUST_PENALTY: f64 = 0.3;

/// Minimum observations before fingerprint is meaningful.
const MIN_OBSERVATIONS: usize = 10;

// ─── Types ─────────────────────────────────────────────────────────────────

/// Behavioral fingerprint for an identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFingerprint {
    /// Identity hash.
    pub identity: String,
    /// Activity distribution across 24 hours (normalized).
    pub timing_distribution: [f64; TIMING_BUCKETS],
    /// Network origin hash (privacy-preserving).
    pub network_origin_hash: Option<String>,
    /// Average record size (bytes).
    pub avg_record_size: f64,
    /// Average metadata key count per record.
    pub avg_metadata_keys: f64,
    /// Hardware attestation fingerprint (if available).
    pub hardware_fingerprint: Option<String>,
    /// Total observations used to build this fingerprint.
    pub observation_count: usize,
    /// Whether this identity has been abandoned/slashed.
    pub abandoned: bool,
}

impl BehavioralFingerprint {
    pub fn new(identity: &str) -> Self {
        Self {
            identity: identity.to_string(),
            timing_distribution: [0.0; TIMING_BUCKETS],
            network_origin_hash: None,
            avg_record_size: 0.0,
            avg_metadata_keys: 0.0,
            hardware_fingerprint: None,
            observation_count: 0,
            abandoned: false,
        }
    }

    /// Record an observation (hour of day, record size, metadata key count).
    pub fn observe(&mut self, hour: usize, record_size: usize, metadata_keys: usize) {
        let hour = hour % TIMING_BUCKETS;
        let n = self.observation_count as f64;

        // Incremental average for timing distribution
        self.timing_distribution[hour] += 1.0;

        // Incremental average for record size
        self.avg_record_size = (self.avg_record_size * n + record_size as f64) / (n + 1.0);

        // Incremental average for metadata keys
        self.avg_metadata_keys = (self.avg_metadata_keys * n + metadata_keys as f64) / (n + 1.0);

        self.observation_count += 1;
    }

    /// Normalize the timing distribution (sum to 1.0).
    pub fn normalized_timing(&self) -> [f64; TIMING_BUCKETS] {
        let total: f64 = self.timing_distribution.iter().sum();
        if total == 0.0 {
            return [0.0; TIMING_BUCKETS];
        }
        let mut normalized = [0.0; TIMING_BUCKETS];
        for (i, v) in self.timing_distribution.iter().enumerate() {
            normalized[i] = v / total;
        }
        normalized
    }

    /// Whether this fingerprint has enough data to be meaningful.
    pub fn is_mature(&self) -> bool {
        self.observation_count >= MIN_OBSERVATIONS
    }

    /// Cosine similarity of timing distributions.
    fn timing_similarity(&self, other: &Self) -> f64 {
        let a = self.normalized_timing();
        let b = other.normalized_timing();
        cosine_similarity(&a, &b)
    }

    /// Compare two fingerprints and return overall similarity (0.0-1.0).
    pub fn similarity(&self, other: &Self) -> f64 {
        if !self.is_mature() || !other.is_mature() {
            return 0.0;
        }

        let mut score = 0.0;
        let mut weight = 0.0;

        // Timing pattern similarity (weight: 0.3)
        let timing_sim = self.timing_similarity(other);
        score += timing_sim * 0.3;
        weight += 0.3;

        // Network origin match (weight: 0.25)
        if let (Some(a), Some(b)) = (&self.network_origin_hash, &other.network_origin_hash) {
            score += if a == b { 0.25 } else { 0.0 };
            weight += 0.25;
        }

        // Record size similarity (weight: 0.15)
        let max_size = self.avg_record_size.max(other.avg_record_size);
        if max_size > 0.0 {
            let size_sim =
                1.0 - (self.avg_record_size - other.avg_record_size).abs() / max_size;
            score += size_sim * 0.15;
            weight += 0.15;
        }

        // Metadata key count similarity (weight: 0.1)
        let max_keys = self.avg_metadata_keys.max(other.avg_metadata_keys);
        if max_keys > 0.0 {
            let keys_sim =
                1.0 - (self.avg_metadata_keys - other.avg_metadata_keys).abs() / max_keys;
            score += keys_sim * 0.1;
            weight += 0.1;
        }

        // Hardware fingerprint match (weight: 0.2)
        if let (Some(a), Some(b)) = (&self.hardware_fingerprint, &other.hardware_fingerprint) {
            score += if a == b { 0.2 } else { 0.0 };
            weight += 0.2;
        }

        if weight > 0.0 {
            score / weight
        } else {
            0.0
        }
    }
}

/// A detected reincarnation candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReincarnationCandidate {
    /// New identity suspected of being a reincarnation.
    pub new_identity: String,
    /// Abandoned identity it matches.
    pub old_identity: String,
    /// Similarity score (0.0-1.0).
    pub similarity: f64,
    /// Signals that contributed to the match.
    pub signals: Vec<String>,
    /// Detection timestamp.
    pub detected_at: f64,
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Cosine similarity between two vectors.
fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let mag_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let mag_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();

    if mag_a == 0.0 || mag_b == 0.0 {
        return 0.0;
    }
    dot / (mag_a * mag_b)
}

// ─── State ─────────────────────────────────────────────────────────────────

/// Tracks behavioral fingerprints for reincarnation detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReincarnationState {
    /// Fingerprints by identity.
    fingerprints: HashMap<String, BehavioralFingerprint>,
    /// Detected reincarnation candidates.
    candidates: Vec<ReincarnationCandidate>,
}

impl ReincarnationState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a fingerprint for an identity.
    pub fn fingerprint_mut(&mut self, identity: &str) -> &mut BehavioralFingerprint {
        self.fingerprints
            .entry(identity.to_string())
            .or_insert_with(|| BehavioralFingerprint::new(identity))
    }

    /// Record an observation for an identity.
    pub fn observe(
        &mut self,
        identity: &str,
        hour: usize,
        record_size: usize,
        metadata_keys: usize,
    ) {
        self.fingerprint_mut(identity)
            .observe(hour, record_size, metadata_keys);
    }

    /// Set network origin for an identity.
    pub fn set_network_origin(&mut self, identity: &str, origin_hash: &str) {
        self.fingerprint_mut(identity).network_origin_hash = Some(origin_hash.to_string());
    }

    /// Set hardware fingerprint for an identity.
    pub fn set_hardware_fingerprint(&mut self, identity: &str, hw_fingerprint: &str) {
        self.fingerprint_mut(identity).hardware_fingerprint = Some(hw_fingerprint.to_string());
    }

    /// Mark an identity as abandoned (slashed, reputation destroyed).
    pub fn mark_abandoned(&mut self, identity: &str) {
        self.fingerprint_mut(identity).abandoned = true;
    }

    /// Check a new identity against all abandoned fingerprints.
    pub fn check_reincarnation(
        &mut self,
        new_identity: &str,
        now: f64,
    ) -> Vec<ReincarnationCandidate> {
        let new_fp = match self.fingerprints.get(new_identity) {
            Some(fp) if fp.is_mature() => fp.clone(),
            _ => return Vec::new(),
        };

        let mut candidates = Vec::new();

        for (old_id, old_fp) in &self.fingerprints {
            if !old_fp.abandoned || old_id == new_identity || !old_fp.is_mature() {
                continue;
            }

            let similarity = new_fp.similarity(old_fp);
            if similarity >= REINCARNATION_THRESHOLD {
                let mut signals = Vec::new();

                if new_fp.timing_similarity(old_fp) > 0.7 {
                    signals.push("timing_pattern".into());
                }
                if new_fp.network_origin_hash == old_fp.network_origin_hash
                    && new_fp.network_origin_hash.is_some()
                {
                    signals.push("network_origin".into());
                }
                if new_fp.hardware_fingerprint == old_fp.hardware_fingerprint
                    && new_fp.hardware_fingerprint.is_some()
                {
                    signals.push("hardware_match".into());
                }

                candidates.push(ReincarnationCandidate {
                    new_identity: new_identity.to_string(),
                    old_identity: old_id.clone(),
                    similarity,
                    signals,
                    detected_at: now,
                });
            }
        }

        self.candidates.extend(candidates.clone());
        candidates
    }

    /// Trust penalty multiplier for an identity.
    /// Returns 1.0 (no penalty) or REINCARNATION_TRUST_PENALTY if suspected.
    pub fn trust_multiplier(&self, identity: &str) -> f64 {
        if self
            .candidates
            .iter()
            .any(|c| c.new_identity == identity)
        {
            REINCARNATION_TRUST_PENALTY
        } else {
            1.0
        }
    }

    /// Get all detected candidates.
    pub fn all_candidates(&self) -> &[ReincarnationCandidate] {
        &self.candidates
    }

    /// Number of tracked fingerprints.
    pub fn fingerprint_count(&self) -> usize {
        self.fingerprints.len()
    }

    /// Read-only access to fingerprints map (for periodic reincarnation checks in ingest).
    pub fn fingerprints(&self) -> &HashMap<String, BehavioralFingerprint> {
        &self.fingerprints
    }

    /// Number of abandoned identities being tracked.
    pub fn abandoned_count(&self) -> usize {
        self.fingerprints.values().filter(|f| f.abandoned).count()
    }

    /// Number of detected reincarnation candidates.
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_fingerprint(
        identity: &str,
        primary_hour: usize,
        avg_size: usize,
        avg_keys: usize,
    ) -> BehavioralFingerprint {
        let mut fp = BehavioralFingerprint::new(identity);
        for _ in 0..20 {
            fp.observe(primary_hour, avg_size, avg_keys);
        }
        fp
    }

    #[test]
    fn test_fingerprint_observe() {
        let mut fp = BehavioralFingerprint::new("alice");
        fp.observe(14, 500, 5);
        fp.observe(14, 600, 6);

        assert_eq!(fp.observation_count, 2);
        assert!((fp.avg_record_size - 550.0).abs() < 0.1);
        assert!((fp.avg_metadata_keys - 5.5).abs() < 0.1);
    }

    #[test]
    fn test_fingerprint_maturity() {
        let mut fp = BehavioralFingerprint::new("alice");
        assert!(!fp.is_mature());

        for i in 0..10 {
            fp.observe(i % 24, 100, 3);
        }
        assert!(fp.is_mature());
    }

    #[test]
    fn test_identical_fingerprints_high_similarity() {
        let fp1 = build_fingerprint("alice", 14, 500, 5);
        let fp2 = build_fingerprint("clone", 14, 500, 5);

        let sim = fp1.similarity(&fp2);
        assert!(sim > 0.9, "sim={sim}");
    }

    #[test]
    fn test_different_fingerprints_low_similarity() {
        let fp1 = build_fingerprint("alice", 2, 100, 2);
        let fp2 = build_fingerprint("bob", 14, 5000, 20);

        let sim = fp1.similarity(&fp2);
        assert!(sim < 0.5, "sim={sim}");
    }

    #[test]
    fn test_immature_fingerprint_zero_similarity() {
        let fp1 = BehavioralFingerprint::new("alice");
        let fp2 = build_fingerprint("bob", 14, 500, 5);

        assert_eq!(fp1.similarity(&fp2), 0.0);
    }

    #[test]
    fn test_cosine_similarity_identical() {
        let a = [1.0, 2.0, 3.0];
        let b = [1.0, 2.0, 3.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let a = [1.0, 0.0, 0.0];
        let b = [0.0, 1.0, 0.0];
        assert!((cosine_similarity(&a, &b)).abs() < 0.001);
    }

    #[test]
    fn test_reincarnation_detection() {
        let mut state = ReincarnationState::new();

        // Old identity: active at hour 14, small records
        for _ in 0..20 {
            state.observe("old-alice", 14, 500, 5);
        }
        state.set_network_origin("old-alice", "net-hash-001");
        state.mark_abandoned("old-alice");

        // New identity: same pattern
        for _ in 0..20 {
            state.observe("new-alice", 14, 500, 5);
        }
        state.set_network_origin("new-alice", "net-hash-001");

        let candidates = state.check_reincarnation("new-alice", 1000.0);
        assert!(!candidates.is_empty());
        assert_eq!(candidates[0].old_identity, "old-alice");
        assert!(candidates[0].similarity >= REINCARNATION_THRESHOLD);
    }

    #[test]
    fn test_no_false_positive() {
        let mut state = ReincarnationState::new();

        // Old identity: night owl, large records
        for _ in 0..20 {
            state.observe("old-alice", 2, 10000, 20);
        }
        state.set_network_origin("old-alice", "net-A");
        state.set_hardware_fingerprint("old-alice", "hw-A");
        state.mark_abandoned("old-alice");

        // New identity: totally different pattern
        for _ in 0..20 {
            state.observe("bob", 14, 200, 3);
        }
        state.set_network_origin("bob", "net-B");
        state.set_hardware_fingerprint("bob", "hw-B");

        let candidates = state.check_reincarnation("bob", 1000.0);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_trust_penalty() {
        let mut state = ReincarnationState::new();

        for _ in 0..20 {
            state.observe("old", 14, 500, 5);
        }
        state.mark_abandoned("old");

        for _ in 0..20 {
            state.observe("new", 14, 500, 5);
        }

        // Before detection
        assert_eq!(state.trust_multiplier("new"), 1.0);

        // After detection
        state.check_reincarnation("new", 1000.0);
        assert!(state.trust_multiplier("new") < 1.0);
    }

    #[test]
    fn test_non_abandoned_not_checked() {
        let mut state = ReincarnationState::new();

        // Active identity (not abandoned)
        for _ in 0..20 {
            state.observe("alice", 14, 500, 5);
        }

        // Similar new identity
        for _ in 0..20 {
            state.observe("clone", 14, 500, 5);
        }

        let candidates = state.check_reincarnation("clone", 1000.0);
        assert!(candidates.is_empty()); // Alice not abandoned, no match
    }

    #[test]
    fn test_hardware_fingerprint_signal() {
        let mut state = ReincarnationState::new();

        for _ in 0..20 {
            state.observe("old", 14, 500, 5);
        }
        state.set_hardware_fingerprint("old", "hw-unique-001");
        state.mark_abandoned("old");

        for _ in 0..20 {
            state.observe("new", 14, 500, 5);
        }
        state.set_hardware_fingerprint("new", "hw-unique-001");

        let candidates = state.check_reincarnation("new", 1000.0);
        assert!(!candidates.is_empty());
        assert!(candidates[0].signals.contains(&"hardware_match".to_string()));
    }

    // ─── fixture-free, pure helpers ──────────────────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_reincarnation_constants_strict_pin_and_threshold_penalty_relations() {
        // 4 module constants. All four are load-bearing for the reincarnation
        // detection policy: changing any silently shifts how aggressively
        // identities are flagged or penalized.
        assert_eq!(TIMING_BUCKETS, 24, "must match hours in a day");
        assert!((REINCARNATION_THRESHOLD - 0.75).abs() < f64::EPSILON);
        assert!((REINCARNATION_TRUST_PENALTY - 0.3).abs() < f64::EPSILON);
        assert_eq!(MIN_OBSERVATIONS, 10);

        // Cross-relations:
        // (a) Threshold must be in (0, 1) — values outside this range break
        //     the similarity-comparison semantics.
        assert!(REINCARNATION_THRESHOLD > 0.0);
        assert!(REINCARNATION_THRESHOLD < 1.0);
        // (b) Penalty must be in (0, 1) — must REDUCE trust (< 1) but not
        //     zero it out (> 0).
        assert!(REINCARNATION_TRUST_PENALTY > 0.0);
        assert!(REINCARNATION_TRUST_PENALTY < 1.0);
        // (c) The detection threshold should be higher than the trust
        //     penalty factor — high similarity required to trigger,
        //     but the penalty itself is a heavier reduction than that.
        //     (Both are independent dials, but THRESHOLD>PENALTY is the
        //     current policy.)
        assert!(REINCARNATION_THRESHOLD > REINCARNATION_TRUST_PENALTY);
        // (d) Need enough observations for the fingerprint to be
        //     meaningful before similarity is checked.
        assert!(MIN_OBSERVATIONS > 0);
        // (e) TIMING_BUCKETS fits comfortably in any reasonable usize and
        //     matches the hour-of-day cardinality used by observe().
        assert!(TIMING_BUCKETS > 0);
        assert!(TIMING_BUCKETS <= 24, "24 hour buckets is the natural ceiling");
    }

    #[test]
    fn batch_b_behavioral_fingerprint_new_initial_state_and_maturity_boundary() {
        // 8-field initial state pin. If a future PR adds a field without
        // a Default, this constructor stops compiling — the test forces
        // a conscious decision about the new field's default.
        let fp = BehavioralFingerprint::new("alice");
        assert_eq!(fp.identity, "alice");
        assert_eq!(fp.timing_distribution, [0.0; TIMING_BUCKETS]);
        assert!(fp.network_origin_hash.is_none());
        assert!((fp.avg_record_size - 0.0).abs() < f64::EPSILON);
        assert!((fp.avg_metadata_keys - 0.0).abs() < f64::EPSILON);
        assert!(fp.hardware_fingerprint.is_none());
        assert_eq!(fp.observation_count, 0);
        assert!(!fp.abandoned);

        // Maturity boundary: exactly MIN_OBSERVATIONS observations is the
        // crossing point. 9 obs → immature, 10 obs → mature. is_mature
        // uses >= comparison.
        let mut fp = BehavioralFingerprint::new("boundary");
        for _ in 0..(MIN_OBSERVATIONS - 1) {
            fp.observe(0, 100, 1);
        }
        assert!(!fp.is_mature(), "{} obs must be immature", MIN_OBSERVATIONS - 1);
        fp.observe(0, 100, 1);
        assert!(fp.is_mature(), "{} obs must be mature", MIN_OBSERVATIONS);

        // Empty identity is permitted at construction (callers can pass
        // arbitrary strings — the constructor doesn't validate).
        let fp = BehavioralFingerprint::new("");
        assert_eq!(fp.identity, "");
        assert_eq!(fp.observation_count, 0);
    }

    #[test]
    fn batch_b_observe_hour_modulo_wrap_and_incremental_average_correctness() {
        // Hour modulo: hour values outside [0, 24) wrap to bucket = hour % 24.
        let mut fp = BehavioralFingerprint::new("modulo");
        fp.observe(25, 100, 1);  // wraps to bucket 1
        fp.observe(48, 100, 1);  // wraps to bucket 0
        fp.observe(0, 100, 1);   // bucket 0
        fp.observe(23, 100, 1);  // bucket 23 (edge)
        fp.observe(24, 100, 1);  // wraps to bucket 0
        assert_eq!(fp.timing_distribution[0], 3.0, "buckets 0+24+48 all map to bucket 0");
        assert_eq!(fp.timing_distribution[1], 1.0);
        assert_eq!(fp.timing_distribution[23], 1.0);
        assert_eq!(fp.observation_count, 5);

        // usize::MAX wraps consistently (usize::MAX % 24 — but the
        // expected bucket depends on platform; we just verify it's in
        // [0, 24)).
        let mut fp = BehavioralFingerprint::new("max");
        fp.observe(usize::MAX, 0, 0);
        let bucket = usize::MAX % TIMING_BUCKETS;
        assert!(bucket < TIMING_BUCKETS);
        assert_eq!(fp.timing_distribution[bucket], 1.0);
        // All other buckets should be zero.
        for (i, v) in fp.timing_distribution.iter().enumerate() {
            if i != bucket {
                assert_eq!(*v, 0.0, "bucket {i} should be 0");
            }
        }

        // Incremental average correctness: observe(_, 100, 1), (_, 200, 2),
        // (_, 300, 3) — expected averages: size 200, keys 2.
        let mut fp = BehavioralFingerprint::new("avg");
        fp.observe(0, 100, 1);
        assert!((fp.avg_record_size - 100.0).abs() < 0.001);
        assert!((fp.avg_metadata_keys - 1.0).abs() < 0.001);
        fp.observe(0, 200, 2);
        assert!((fp.avg_record_size - 150.0).abs() < 0.001);
        assert!((fp.avg_metadata_keys - 1.5).abs() < 0.001);
        fp.observe(0, 300, 3);
        assert!((fp.avg_record_size - 200.0).abs() < 0.001);
        assert!((fp.avg_metadata_keys - 2.0).abs() < 0.001);
        assert_eq!(fp.observation_count, 3);

        // Uneven sequence: 0, 1000, 0 → avg 333.33...
        let mut fp = BehavioralFingerprint::new("uneven");
        fp.observe(0, 0, 0);
        fp.observe(0, 1000, 10);
        fp.observe(0, 0, 0);
        assert!((fp.avg_record_size - (1000.0 / 3.0)).abs() < 0.001);
        assert!((fp.avg_metadata_keys - (10.0 / 3.0)).abs() < 0.001);
    }

    #[test]
    fn batch_b_normalized_timing_zero_safe_sums_to_one_and_single_bucket_concentration() {
        // All-zero distribution → all-zero normalized (no NaN / no panic).
        let fp = BehavioralFingerprint::new("empty");
        let norm = fp.normalized_timing();
        assert_eq!(norm, [0.0; TIMING_BUCKETS]);
        let sum: f64 = norm.iter().sum();
        assert_eq!(sum, 0.0, "all-zero must normalize to all-zero (not NaN)");
        // None of the values should be NaN.
        for v in &norm {
            assert!(!v.is_nan());
        }

        // Single-bucket concentration: after N observations all at hour 14,
        // normalized[14]==1.0 and every other bucket is 0.0.
        let mut fp = BehavioralFingerprint::new("focused");
        for _ in 0..20 {
            fp.observe(14, 100, 1);
        }
        let norm = fp.normalized_timing();
        assert!((norm[14] - 1.0).abs() < 0.001, "bucket 14 should be 1.0");
        for (i, v) in norm.iter().enumerate() {
            if i != 14 {
                assert_eq!(*v, 0.0, "bucket {i} should be 0.0");
            }
        }

        // Uniform distribution across all 24 hours → each bucket = 1/24.
        let mut fp = BehavioralFingerprint::new("uniform");
        for h in 0..24 {
            fp.observe(h, 100, 1);
        }
        let norm = fp.normalized_timing();
        for (i, v) in norm.iter().enumerate() {
            assert!((v - (1.0 / 24.0)).abs() < 0.001, "uniform bucket {i} = 1/24");
        }
        let sum: f64 = norm.iter().sum();
        assert!((sum - 1.0).abs() < 0.001, "uniform must sum to 1.0");

        // Mixed concentration: 12 observations at hour 14, 4 at hour 18
        // → normalized[14] = 12/16 = 0.75, normalized[18] = 4/16 = 0.25.
        let mut fp = BehavioralFingerprint::new("mixed");
        for _ in 0..12 { fp.observe(14, 100, 1); }
        for _ in 0..4 { fp.observe(18, 100, 1); }
        let norm = fp.normalized_timing();
        assert!((norm[14] - 0.75).abs() < 0.001);
        assert!((norm[18] - 0.25).abs() < 0.001);
        let sum: f64 = norm.iter().sum();
        assert!((sum - 1.0).abs() < 0.001);
    }

    #[test]
    fn batch_b_cosine_similarity_edge_cases_and_reincarnation_candidate_shape() {
        // Both-zero → 0.0 (no NaN from 0/0).
        let zeros = [0.0f64; 3];
        let result = cosine_similarity(&zeros, &zeros);
        assert_eq!(result, 0.0);
        assert!(!result.is_nan());

        // One-zero → 0.0.
        let nonzero = [1.0, 2.0, 3.0];
        assert_eq!(cosine_similarity(&zeros, &nonzero), 0.0);
        assert_eq!(cosine_similarity(&nonzero, &zeros), 0.0);

        // Scale-invariant: cosine_similarity is direction-only.
        let a = [1.0, 2.0, 3.0];
        let b = [2.0, 4.0, 6.0]; // 2*a
        let sim = cosine_similarity(&a, &b);
        assert!((sim - 1.0).abs() < 0.001, "scaled vectors must yield cosine 1.0, got {sim}");
        let c = [100.0, 200.0, 300.0]; // 100*a
        let sim2 = cosine_similarity(&a, &c);
        assert!((sim2 - 1.0).abs() < 0.001);

        // Opposite direction: -1.0.
        let neg = [-1.0, -2.0, -3.0];
        let sim_neg = cosine_similarity(&a, &neg);
        assert!((sim_neg - (-1.0)).abs() < 0.001);

        // Orthogonal: 0.0 (already tested above but pinning more axes).
        let x = [1.0, 0.0, 0.0];
        let y = [0.0, 1.0, 0.0];
        let z = [0.0, 0.0, 1.0];
        assert!(cosine_similarity(&x, &y).abs() < 0.001);
        assert!(cosine_similarity(&y, &z).abs() < 0.001);
        assert!(cosine_similarity(&x, &z).abs() < 0.001);

        // ReincarnationCandidate 5-field shape pin + Clone + serde round-trip.
        let candidate = ReincarnationCandidate {
            new_identity: "new-id".into(),
            old_identity: "old-id".into(),
            similarity: 0.85,
            signals: vec!["timing_pattern".into(), "hardware_match".into()],
            detected_at: 1234.5,
        };
        assert_eq!(candidate.new_identity, "new-id");
        assert_eq!(candidate.old_identity, "old-id");
        assert!((candidate.similarity - 0.85).abs() < f64::EPSILON);
        assert_eq!(candidate.signals.len(), 2);
        assert!((candidate.detected_at - 1234.5).abs() < f64::EPSILON);

        // Clone produces independent copy.
        let cloned = candidate.clone();
        assert_eq!(cloned.new_identity, candidate.new_identity);
        assert_eq!(cloned.signals, candidate.signals);

        // Serde round-trip preserves all 5 fields.
        let json = serde_json::to_string(&candidate).unwrap();
        // All 5 field names must appear in the JSON.
        for key in ["new_identity", "old_identity", "similarity", "signals", "detected_at"] {
            assert!(json.contains(key), "missing field {key} in serialized JSON: {json}");
        }
        let parsed: ReincarnationCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.new_identity, candidate.new_identity);
        assert_eq!(parsed.old_identity, candidate.old_identity);
        assert!((parsed.similarity - candidate.similarity).abs() < f64::EPSILON);
        assert_eq!(parsed.signals, candidate.signals);
        assert!((parsed.detected_at - candidate.detected_at).abs() < f64::EPSILON);
    }
}
