//! Witness reputation scoring — incentivizes selective, honest witnessing.
//!
//! economics §11.2: reputation ledger per witness identity. Delta-based scoring
//! where dispute outcomes and spam detection adjust reputation. Higher reputation
//! → higher `trust_multiplier` → higher rewards. Nash equilibrium: witnesses
//! earn most by being selective and honest.
//!
//! Reputation scores are bounded to [0.0, 1.0] for use as trust_multiplier.

//!
//! Spec references:
//!   @spec Protocol §11.20
//!   @spec economics §11.2

use std::collections::{HashMap, HashSet};
use crate::ZoneId;

// ─── Reputation deltas (economics §11.2) ──────────────────────────────────

/// Record witnessed and never disputed → small positive.
const DELTA_UNDISPUTED: f64 = 1.0;
/// Disputed, witness sided with winner → medium positive.
const DELTA_DISPUTE_WON: f64 = 2.0;
/// Disputed, witness sided with loser → heavy negative.
const DELTA_DISPUTE_LOST: f64 = -5.0;
/// Flagged as spam/anomaly witness → severe negative.
const DELTA_SPAM_FLAGGED: f64 = -10.0;
/// Challenge filed and upheld (guilty) → challenger gets moderate positive.
const DELTA_CHALLENGE_SUCCEEDED: f64 = 3.0;
/// Challenge filed and dismissed (not guilty) → challenger gets moderate negative.
const DELTA_CHALLENGE_FAILED: f64 = -3.0;
/// Serial false accuser penalty: applied ON TOP of CHALLENGE_FAILED when
/// challenger's success rate drops below 50%. economics §10.2.
const DELTA_SERIAL_FALSE_ACCUSER: f64 = -7.0;
/// Minimum challenges filed before serial false accuser penalty applies.
const SERIAL_ACCUSER_MIN_CHALLENGES: u64 = 3;
/// Success rate threshold for serial false accuser penalty.
const SERIAL_ACCUSER_THRESHOLD: f64 = 0.5;

/// Default starting reputation for new witnesses.
const DEFAULT_REPUTATION: f64 = 50.0;
/// Minimum reputation score (floor).
const MIN_REPUTATION: f64 = 0.0;
/// Maximum reputation score (ceiling).
const MAX_REPUTATION: f64 = 100.0;

/// Reputation half-life (economics §12.4 Defense 1 + §13.15 hard-limits table).
/// Accumulated score decays as `score × 0.5^(Δt / HALF_LIFE)`, so activity from
/// 6 months ago contributes half, 12 months a quarter, 5 years ≈ 0.09% — a
/// long-sleeper identity returns to near-zero trust absent continuous real
/// activity.
pub const REPUTATION_HALF_LIFE_SECS: f64 = 180.0 * 86_400.0;

/// Apply half-life decay to a score from `last_event` to `now`.
/// Returns `score × 0.5^((now - last_event) / HALF_LIFE)`, clamped to [0, 100].
/// Legacy entries (`last_event == 0.0`) and non-monotonic reads
/// (`now <= last_event`) return the score unchanged.
fn decay_score(score: f64, last_event: f64, now: f64) -> f64 {
    if last_event == 0.0 || now <= last_event {
        return score;
    }
    let dt = now - last_event;
    let factor = (0.5_f64).powf(dt / REPUTATION_HALF_LIFE_SECS);
    (score * factor).clamp(MIN_REPUTATION, MAX_REPUTATION)
}

/// Diversity bonus per unique zone witnessed today (economics §11.1).
const DIVERSITY_BONUS_PER_ZONE: f64 = 0.1;
/// Maximum diversity bonus multiplier.
const DIVERSITY_BONUS_MAX: f64 = 2.0;
/// Seconds per day (for daily zone tracker reset).
const SECS_PER_DAY: f64 = 86_400.0;

// ─── Temporal trust decay thresholds (Protocol §11.1 Layer 3) ───────────────
// "Trust accumulates through duration of existence." Fresh identities carry
// reduced attestation weight that ramps up over their first week.

/// Age thresholds in seconds.
const AGE_TIER_1_SECS: f64 = 24.0 * 3600.0;   // 24 hours
const AGE_TIER_2_SECS: f64 = 48.0 * 3600.0;   // 48 hours
const AGE_TIER_3_SECS: f64 = 7.0 * 86_400.0;  // 7 days

/// Age-based trust scaling factors.
const AGE_FACTOR_TIER_1: f64 = 0.25;  // < 24h
const AGE_FACTOR_TIER_2: f64 = 0.50;  // < 48h
const AGE_FACTOR_TIER_3: f64 = 0.75;  // < 7d
const AGE_FACTOR_FULL: f64 = 1.0;     // >= 7d

/// Convert raw reputation score [0, 100] → trust_multiplier [0.0, 1.0].
///
/// Linear mapping: 0 → 0.0, 50 → 0.5, 100 → 1.0.
/// New witnesses start at 0.5 (50/100).
fn score_to_multiplier(score: f64) -> f64 {
    (score / MAX_REPUTATION).clamp(0.0, 1.0)
}

/// Age-based trust scaling factor (Protocol §11.1 Layer 3).
///
/// Fresh identities (< 24h) carry only 25% of their score-based trust.
/// Ramps: 25% → 50% → 75% → 100% over the first 7 days.
/// `first_seen == 0.0` is treated as legacy (pre-feature) → full trust.
fn age_factor(first_seen: f64, now: f64) -> f64 {
    // Legacy entries (first_seen not set) get full trust.
    if first_seen == 0.0 {
        return AGE_FACTOR_FULL;
    }
    let age = (now - first_seen).max(0.0);
    if age < AGE_TIER_1_SECS {
        AGE_FACTOR_TIER_1
    } else if age < AGE_TIER_2_SECS {
        AGE_FACTOR_TIER_2
    } else if age < AGE_TIER_3_SECS {
        AGE_FACTOR_TIER_3
    } else {
        AGE_FACTOR_FULL
    }
}

// ─── Reputation event types ────────────────────────────────────────────────

/// Events that modify a witness's reputation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReputationEvent {
    /// Record was witnessed and never disputed (finalized cleanly).
    Undisputed,
    /// Record was disputed; this witness sided with the winning party.
    DisputeWon,
    /// Record was disputed; this witness sided with the losing party.
    DisputeLost,
    /// This witness was flagged for spam/anomaly behavior.
    SpamFlagged,
    /// Challenge filed and upheld (guilty verdict).
    ChallengeSucceeded,
    /// Challenge filed and dismissed (not guilty verdict).
    ChallengeFailed,
    /// Serial false accuser — extra penalty when success rate < 50%.
    SerialFalseAccuser,
}

impl ReputationEvent {
    fn delta(&self) -> f64 {
        match self {
            Self::Undisputed => DELTA_UNDISPUTED,
            Self::DisputeWon => DELTA_DISPUTE_WON,
            Self::DisputeLost => DELTA_DISPUTE_LOST,
            Self::SpamFlagged => DELTA_SPAM_FLAGGED,
            Self::ChallengeSucceeded => DELTA_CHALLENGE_SUCCEEDED,
            Self::ChallengeFailed => DELTA_CHALLENGE_FAILED,
            Self::SerialFalseAccuser => DELTA_SERIAL_FALSE_ACCUSER,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Undisputed => "undisputed",
            Self::DisputeWon => "dispute_won",
            Self::DisputeLost => "dispute_lost",
            Self::SpamFlagged => "spam_flagged",
            Self::ChallengeSucceeded => "challenge_succeeded",
            Self::ChallengeFailed => "challenge_failed",
            Self::SerialFalseAccuser => "serial_false_accuser",
        }
    }
}

// ─── Witness reputation entry ──────────────────────────────────────────────

/// Per-witness reputation record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WitnessReputation {
    /// Raw score [0, 100]. Starts at 50 (neutral).
    pub score: f64,
    /// Total positive events.
    pub positive_events: u64,
    /// Total negative events.
    pub negative_events: u64,
    /// Last event timestamp.
    pub last_event: f64,
    /// When this identity was first seen (unix timestamp).
    /// 0.0 = legacy entry (pre-temporal-decay), treated as fully mature.
    #[serde(default)]
    pub first_seen: f64,
    /// Total challenges filed by this identity (as accuser, not witness).
    #[serde(default)]
    pub challenges_filed: u64,
    /// Challenges filed that resulted in guilty verdict (successful accusations).
    #[serde(default)]
    pub challenges_won: u64,
}

impl Default for WitnessReputation {
    fn default() -> Self {
        Self {
            score: DEFAULT_REPUTATION,
            positive_events: 0,
            negative_events: 0,
            last_event: 0.0,
            first_seen: 0.0,
            challenges_filed: 0,
            challenges_won: 0,
        }
    }
}

impl WitnessReputation {
    /// Trust multiplier [0.0, 1.0] derived from the raw stored score
    /// (no age scaling, no half-life decay). Point-in-time view of the
    /// accumulator.
    pub fn trust_multiplier(&self) -> f64 {
        score_to_multiplier(self.score)
    }

    /// Age- and decay-adjusted trust multiplier at `now`:
    /// `score_decayed(now) × age_factor(first_seen, now) / 100`.
    /// Use this for reward calculations and attestation weight.
    pub fn trust_multiplier_at(&self, now: f64) -> f64 {
        let decayed = decay_score(self.score, self.last_event, now);
        score_to_multiplier(decayed) * age_factor(self.first_seen, now)
    }

    /// Decayed score at `now` (raw score × half-life factor), clamped [0, 100].
    /// Matches the score used by `trust_multiplier_at` before the multiplier
    /// and age-factor mappings.
    pub fn score_at(&self, now: f64) -> f64 {
        decay_score(self.score, self.last_event, now)
    }
}

// ─── Reputation engine ─────────────────────────────────────────────────────

/// Tracks reputation scores and daily diversity for all witnesses.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ReputationEngine {
    /// witness_hash → reputation record
    entries: HashMap<String, WitnessReputation>,
    /// Daily zone diversity tracker: witness_hash → set of zones witnessed today.
    /// Reset when `current_day` changes.
    daily_zones: HashMap<String, HashSet<ZoneId>>,
    /// Current day number (timestamp / 86400, truncated).
    current_day: u64,
}

impl Default for ReputationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationEngine {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            daily_zones: HashMap::new(),
            current_day: 0,
        }
    }

    /// Ensure the daily tracker is on the correct day. Resets if day changed.
    fn ensure_day(&mut self, timestamp: f64) {
        let day = (timestamp / SECS_PER_DAY) as u64;
        if day != self.current_day {
            self.daily_zones.clear();
            self.current_day = day;
        }
    }

    /// Record that a witness attested a record in a given zone.
    /// Call this when an attestation is processed.
    pub fn record_zone_attestation(&mut self, witness_hash: &str, zone: ZoneId, timestamp: f64) {
        self.ensure_day(timestamp);
        self.daily_zones
            .entry(witness_hash.to_string())
            .or_default()
            .insert(zone);
    }

    /// Get the diversity bonus for a witness: 1.0 + 0.1 × unique_zones_today, max 2.0.
    pub fn diversity_bonus(&self, witness_hash: &str) -> f64 {
        let zones = self.daily_zones
            .get(witness_hash)
            .map(|s| s.len())
            .unwrap_or(0);
        (1.0 + DIVERSITY_BONUS_PER_ZONE * zones as f64).min(DIVERSITY_BONUS_MAX)
    }

    /// Compute the full reward for a witness (economics §11.1):
    /// `reward = base_reward × trust_multiplier(age-adjusted) × diversity_bonus`
    ///
    /// DETERMINISM (not a consensus-fork vector despite reaching applied balances):
    /// this `f64` multiply runs on the **genesis authority alone** — both callers
    /// (`distribute_rewards`, `distribute_epoch_rewards`) early-`return 0` for any
    /// other identity — and its `u64` output is frozen into the signed
    /// `witness_reward` record's `amount`. Every OTHER node applies that carried
    /// integer (`ledger.rs` `WitnessReward` → `conservation_pool -= amount`) and
    /// NEVER recomputes the float, so no two nodes ever race the same f64 product;
    /// cross-platform libm/rounding drift cannot fork. Single-emitter + carried-
    /// integer apply — see internal design notes. Do NOT "harden"
    /// this to fixed-point: it is already fork-safe, and a recompute-on-apply
    /// rewrite is what WOULD introduce a fork.
    pub fn compute_reward(&self, witness_hash: &str, base_reward: u64, now: f64) -> u64 {
        let tm = self.trust_multiplier(witness_hash, now);
        let db = self.diversity_bonus(witness_hash);
        (base_reward as f64 * tm * db) as u64
    }

    /// Apply a reputation event to a witness. Creates entry if new.
    ///
    /// AUDIT-4 / economics §12.4 Defense 1: before adding the delta, decay
    /// the stored score forward from `last_event` to `timestamp` so an
    /// incoming event for a long-idle identity doesn't accrue on top of
    /// stale accumulated trust. The stored `score` therefore represents the
    /// half-life-decayed value at `last_event`; subsequent reads apply
    /// further decay to the current `now`.
    pub fn apply_event(&mut self, witness_hash: &str, event: ReputationEvent, timestamp: f64) {
        let is_new = !self.entries.contains_key(witness_hash);
        let entry = self
            .entries
            .entry(witness_hash.to_string())
            .or_default();

        // Set first_seen only on initial creation
        if is_new {
            entry.first_seen = timestamp;
        } else if timestamp > entry.last_event {
            // Checkpoint the accumulator: decay from the previous last_event
            // to this event's timestamp before applying the new delta.
            entry.score = decay_score(entry.score, entry.last_event, timestamp);
        }

        let delta = event.delta();
        entry.score = (entry.score + delta).clamp(MIN_REPUTATION, MAX_REPUTATION);

        if delta > 0.0 {
            entry.positive_events += 1;
        } else {
            entry.negative_events += 1;
        }

        if timestamp > entry.last_event {
            entry.last_event = timestamp;
        }
    }

    /// Get the age-adjusted trust multiplier for a witness [0.0, 1.0].
    /// Returns 0.5 for unknown witnesses (default reputation = 50, full age factor).
    pub fn trust_multiplier(&self, witness_hash: &str, now: f64) -> f64 {
        self.entries
            .get(witness_hash)
            .map(|e| e.trust_multiplier_at(now))
            .unwrap_or(score_to_multiplier(DEFAULT_REPUTATION))
    }

    /// Profile C Gap C: trust multiplier composed with the witness's
    /// hardware attestation level (economics §11.33).
    ///
    /// Returns `trust_multiplier(witness, now) × attestation.trust_multiplier()`.
    /// Attestation acts as a flat boost on top of the score-based multiplier:
    /// a software-only witness (rank 0) is unscaled; a PUF-attested witness
    /// (rank 4) earns 1.5x its score-based trust. The product can exceed 1.0
    /// — by design, since hardware attestation is meant to push reward weight
    /// above what reputation alone permits.
    ///
    /// Pure derivation; the engine itself does not store attestation levels.
    /// Caller resolves `attestation` from `LedgerState::attestation_level()`
    /// (or the inline metadata of the relevant record).
    pub fn trust_multiplier_with_attestation(
        &self,
        witness_hash: &str,
        attestation: crate::identity::AttestationLevel,
        now: f64,
    ) -> f64 {
        self.trust_multiplier(witness_hash, now) * attestation.trust_multiplier()
    }

    /// Profile C Gap C: reward composed with attestation.
    ///
    /// `reward = base_reward × trust_multiplier(witness, now) × diversity_bonus(witness) × attestation.trust_multiplier()`
    ///
    /// Same shape as `compute_reward`, with the attestation factor folded in
    /// before the integer truncation. `attestation = AttestationLevel::None`
    /// reduces to the original `compute_reward` (multiplier 1.0).
    pub fn compute_reward_with_attestation(
        &self,
        witness_hash: &str,
        base_reward: u64,
        now: f64,
        attestation: crate::identity::AttestationLevel,
    ) -> u64 {
        let tm = self.trust_multiplier(witness_hash, now);
        let db = self.diversity_bonus(witness_hash);
        let am = attestation.trust_multiplier();
        (base_reward as f64 * tm * db * am) as u64
    }

    /// Get raw reputation score for a witness (score stored at `last_event`
    /// without further half-life decay). Useful for reconciling stored
    /// state and for tests; production callers that need the current
    /// trust level should use `score_at(hash, now)` or `trust_multiplier`.
    pub fn score(&self, witness_hash: &str) -> f64 {
        self.entries
            .get(witness_hash)
            .map(|e| e.score)
            .unwrap_or(DEFAULT_REPUTATION)
    }

    /// Get the half-life-decayed reputation score at `now` [0, 100].
    /// Unknown witnesses return `DEFAULT_REPUTATION` (no decay; treated as
    /// a blank slate at query time). economics §12.4 Defense 1.
    pub fn score_at(&self, witness_hash: &str, now: f64) -> f64 {
        self.entries
            .get(witness_hash)
            .map(|e| e.score_at(now))
            .unwrap_or(DEFAULT_REPUTATION)
    }

    /// Get full reputation entry (or None for unknown witnesses).
    pub fn get(&self, witness_hash: &str) -> Option<&WitnessReputation> {
        self.entries.get(witness_hash)
    }

    /// Number of witnesses tracked.
    pub fn tracked_count(&self) -> usize {
        self.entries.len()
    }

    /// Process dispute resolution: reward witnesses who sided with the winner,
    /// penalize those who sided with the loser.
    ///
    /// - `contested_record_id`: the disputed record
    /// - `outcome`: "upheld" (record was bad) or "dismissed" (record was fine)
    /// - `attestors`: witnesses who attested the contested record
    /// - `timestamp`: resolution time
    pub fn process_dispute_resolution(
        &mut self,
        outcome: &str,
        attestors: &[String],
        timestamp: f64,
    ) {
        match outcome {
            "upheld" => {
                // Dispute upheld = record was bad → witnesses who attested it LOSE reputation
                for wh in attestors {
                    self.apply_event(wh, ReputationEvent::DisputeLost, timestamp);
                }
            }
            "dismissed" => {
                // Dispute dismissed = record was fine → witnesses who attested it WIN
                for wh in attestors {
                    self.apply_event(wh, ReputationEvent::DisputeWon, timestamp);
                }
            }
            "voided" => {
                // Voided = no effect on reputation (ambiguous outcome)
            }
            _ => {}
        }
    }

    /// Track a challenge outcome for the CHALLENGER (not the accused or witnesses).
    ///
    /// - `guilty=true`: challenge upheld → challenger rewarded
    /// - `guilty=false`: challenge dismissed → challenger penalized
    ///
    /// If the challenger's success rate drops below 50% after 3+ challenges,
    /// an additional serial false accuser penalty is applied (economics §10.2).
    pub fn record_challenge_outcome(&mut self, challenger: &str, guilty: bool, timestamp: f64) {
        // Update challenge counters
        let entry = self.entries.entry(challenger.to_string()).or_default();
        if entry.first_seen == 0.0 {
            entry.first_seen = timestamp;
        }
        entry.challenges_filed += 1;
        if guilty {
            entry.challenges_won += 1;
        }

        // Apply reputation event
        if guilty {
            self.apply_event(challenger, ReputationEvent::ChallengeSucceeded, timestamp);
        } else {
            self.apply_event(challenger, ReputationEvent::ChallengeFailed, timestamp);

            // Check for serial false accuser pattern
            let Some(entry) = self.entries.get(challenger) else {
                return;
            };
            if entry.challenges_filed >= SERIAL_ACCUSER_MIN_CHALLENGES {
                let success_rate = entry.challenges_won as f64 / entry.challenges_filed as f64;
                if success_rate < SERIAL_ACCUSER_THRESHOLD {
                    self.apply_event(challenger, ReputationEvent::SerialFalseAccuser, timestamp);
                }
            }
        }
    }

    /// Bulk credit for records that reached finality without dispute.
    /// Call when records are finalized — each attesting witness gets +1.
    pub fn credit_undisputed(&mut self, attestors: &[String], timestamp: f64) {
        for wh in attestors {
            self.apply_event(wh, ReputationEvent::Undisputed, timestamp);
        }
    }

    /// Prune witnesses inactive for more than `max_age_secs` relative to `now`.
    ///
    /// Uses the `last_event` timestamp on each entry. Witnesses with no activity
    /// within `now - max_age_secs` are removed from the in-memory map (their data
    /// is already dual-written to RocksDB CF_REPUTATION). Returns the count pruned.
    pub fn prune_inactive(&mut self, now: f64, max_age_secs: f64) -> usize {
        let cutoff = now - max_age_secs;
        let before = self.entries.len();
        self.entries.retain(|_, e| e.last_event >= cutoff);
        // Also prune corresponding daily_zones entries for removed witnesses
        self.daily_zones.retain(|wh, _| self.entries.contains_key(wh));
        before - self.entries.len()
    }

    /// Summary: (witness_hash, raw_score, trust_multiplier_raw, positive, negative).
    /// Raw score/trust (no decay applied). Prefer `summary_at(now)` for
    /// display — it returns the decayed values that reward calculations
    /// actually use.
    pub fn summary(&self) -> Vec<(&str, f64, f64, u64, u64)> {
        let mut result: Vec<_> = self
            .entries
            .iter()
            .map(|(wh, e)| {
                (
                    wh.as_str(),
                    e.score,
                    e.trust_multiplier(),
                    e.positive_events,
                    e.negative_events,
                )
            })
            .collect();
        result.sort_by(|a, b| b.1.total_cmp(&a.1));
        result
    }

    /// Summary with half-life decay and age factor applied at `now`:
    /// (witness_hash, decayed_score, effective_trust_multiplier, positive, negative).
    /// Sorted by decayed score descending.
    pub fn summary_at(&self, now: f64) -> Vec<(&str, f64, f64, u64, u64)> {
        let mut result: Vec<_> = self
            .entries
            .iter()
            .map(|(wh, e)| {
                (
                    wh.as_str(),
                    e.score_at(now),
                    e.trust_multiplier_at(now),
                    e.positive_events,
                    e.negative_events,
                )
            })
            .collect();
        result.sort_by(|a, b| b.1.total_cmp(&a.1));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Far-future timestamp for tests that don't care about age decay.
    /// All witnesses created at t < FAR_FUTURE will have age_factor = 1.0.
    const FAR_FUTURE: f64 = 1_000_000.0;

    /// Tolerance for multi-event tests: per-event decay over 1 s is
    /// `1 - ln(2)/HALF_LIFE ≈ 4.5e-8`, so 100 events across 100 s drift by
    /// < 1e-5 from the no-decay expectation.
    const FLOAT_EPS: f64 = 1e-4;

    /// Helper: multiplicative half-life factor `0.5^(dt / HALF_LIFE)`.
    fn decay_factor(last_event: f64, now: f64) -> f64 {
        (0.5_f64).powf((now - last_event) / REPUTATION_HALF_LIFE_SECS)
    }

    #[test]
    fn test_new_witness_default_reputation() {
        let engine = ReputationEngine::new();
        assert_eq!(engine.score("unknown"), DEFAULT_REPUTATION);
        // Unknown witness → default score, no entry → first_seen irrelevant
        assert!((engine.trust_multiplier("unknown", FAR_FUTURE) - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_undisputed_increases_score() {
        let mut engine = ReputationEngine::new();
        engine.apply_event("w1", ReputationEvent::Undisputed, 1000.0);
        assert_eq!(engine.score("w1"), DEFAULT_REPUTATION + DELTA_UNDISPUTED);
        assert_eq!(engine.get("w1").unwrap().positive_events, 1);
    }

    #[test]
    fn test_dispute_won_increases_score() {
        let mut engine = ReputationEngine::new();
        engine.apply_event("w1", ReputationEvent::DisputeWon, 1000.0);
        assert_eq!(engine.score("w1"), DEFAULT_REPUTATION + DELTA_DISPUTE_WON);
    }

    #[test]
    fn test_dispute_lost_decreases_score() {
        let mut engine = ReputationEngine::new();
        engine.apply_event("w1", ReputationEvent::DisputeLost, 1000.0);
        assert_eq!(engine.score("w1"), DEFAULT_REPUTATION + DELTA_DISPUTE_LOST);
        assert_eq!(engine.get("w1").unwrap().negative_events, 1);
    }

    #[test]
    fn test_spam_flagged_severe_penalty() {
        let mut engine = ReputationEngine::new();
        engine.apply_event("w1", ReputationEvent::SpamFlagged, 1000.0);
        assert_eq!(engine.score("w1"), DEFAULT_REPUTATION + DELTA_SPAM_FLAGGED);
    }

    #[test]
    fn test_score_clamped_at_boundaries() {
        let mut engine = ReputationEngine::new();
        // Drive score to maximum
        for i in 0..100 {
            engine.apply_event("good", ReputationEvent::DisputeWon, i as f64);
        }
        assert!((engine.score("good") - MAX_REPUTATION).abs() < FLOAT_EPS);
        // At FAR_FUTURE the half-life decay pulls trust well below 1.0.
        let expected = (MAX_REPUTATION / 100.0) * decay_factor(99.0, FAR_FUTURE);
        assert!((engine.trust_multiplier("good", FAR_FUTURE) - expected).abs() < 0.001);

        // Drive score to minimum
        for i in 0..50 {
            engine.apply_event("bad", ReputationEvent::SpamFlagged, i as f64);
        }
        assert_eq!(engine.score("bad"), MIN_REPUTATION);
        assert!(engine.trust_multiplier("bad", FAR_FUTURE) < 0.001);
    }

    #[test]
    fn test_trust_multiplier_linear() {
        let mut engine = ReputationEngine::new();
        // Unknown witness → default score = 50 → 0.5, no decay applied (no entry).
        assert!((engine.trust_multiplier("w1", FAR_FUTURE) - 0.5).abs() < 0.001);

        // Add 25 positive → score ≈ 75 (trivial intra-event decay).
        for i in 0..25 {
            engine.apply_event("w1", ReputationEvent::Undisputed, i as f64);
        }
        // At FAR_FUTURE the half-life decay is the dominant effect.
        let expected = 0.75 * decay_factor(24.0, FAR_FUTURE);
        assert!((engine.trust_multiplier("w1", FAR_FUTURE) - expected).abs() < 0.001);
    }

    #[test]
    fn test_process_dispute_upheld() {
        let mut engine = ReputationEngine::new();
        let attestors = vec!["w1".to_string(), "w2".to_string()];
        engine.process_dispute_resolution("upheld", &attestors, 1000.0);
        // Upheld = record was bad → attestors lose reputation
        assert_eq!(engine.score("w1"), DEFAULT_REPUTATION + DELTA_DISPUTE_LOST);
        assert_eq!(engine.score("w2"), DEFAULT_REPUTATION + DELTA_DISPUTE_LOST);
    }

    #[test]
    fn test_process_dispute_dismissed() {
        let mut engine = ReputationEngine::new();
        let attestors = vec!["w1".to_string(), "w2".to_string()];
        engine.process_dispute_resolution("dismissed", &attestors, 1000.0);
        // Dismissed = record was fine → attestors win
        assert_eq!(engine.score("w1"), DEFAULT_REPUTATION + DELTA_DISPUTE_WON);
        assert_eq!(engine.score("w2"), DEFAULT_REPUTATION + DELTA_DISPUTE_WON);
    }

    #[test]
    fn test_process_dispute_voided_no_effect() {
        let mut engine = ReputationEngine::new();
        let attestors = vec!["w1".to_string()];
        engine.process_dispute_resolution("voided", &attestors, 1000.0);
        // Voided = no reputation change
        assert_eq!(engine.score("w1"), DEFAULT_REPUTATION);
    }

    #[test]
    fn test_credit_undisputed_bulk() {
        let mut engine = ReputationEngine::new();
        let attestors = vec!["w1".to_string(), "w2".to_string(), "w3".to_string()];
        engine.credit_undisputed(&attestors, 1000.0);
        for wh in &attestors {
            assert_eq!(engine.score(wh), DEFAULT_REPUTATION + DELTA_UNDISPUTED);
        }
    }

    #[test]
    fn test_summary_sorted_by_score() {
        let mut engine = ReputationEngine::new();
        // w1 gets positive events, w2 gets negative
        for i in 0..10 {
            engine.apply_event("w1", ReputationEvent::Undisputed, i as f64);
        }
        engine.apply_event("w2", ReputationEvent::SpamFlagged, 0.0);
        let summary = engine.summary();
        assert_eq!(summary.len(), 2);
        assert_eq!(summary[0].0, "w1"); // higher score first
        assert!(summary[0].1 > summary[1].1);
    }

    #[test]
    fn test_event_name() {
        assert_eq!(ReputationEvent::Undisputed.name(), "undisputed");
        assert_eq!(ReputationEvent::DisputeWon.name(), "dispute_won");
        assert_eq!(ReputationEvent::DisputeLost.name(), "dispute_lost");
        assert_eq!(ReputationEvent::SpamFlagged.name(), "spam_flagged");
    }

    #[test]
    fn test_tracked_count() {
        let mut engine = ReputationEngine::new();
        assert_eq!(engine.tracked_count(), 0);
        engine.apply_event("w1", ReputationEvent::Undisputed, 1.0);
        engine.apply_event("w2", ReputationEvent::Undisputed, 2.0);
        assert_eq!(engine.tracked_count(), 2);
    }

    /// Metric-semantics codification for the
    /// `elara_reputation_witnesses_tracked` gauge + `_pruned_total`
    /// counter. The gauge MUST equal the size of the in-memory `entries`
    /// HashMap (distinct witnesses scored locally), never the lifetime
    /// event count, never the post-prune residual minus pruned count.
    /// Re-applying events to the same witness must NOT inflate the
    /// gauge — it counts distinct keys, not events.
    ///
    /// Operators rely on:
    ///   * gauge=N + _pruned_total advancing while gauge stable =
    ///     healthy retention churn (inactive witnesses retiring as
    ///     fresh ones arrive).
    ///   * gauge climbing past expected peer count + pruned_total flat
    ///     = retention window misconfigured OR prune loop dead.
    ///   * gauge collapse + matching pruned_total spike = mass-prune
    ///     event (peer disconnected fleet for >retention period).
    ///
    /// `prune_inactive` MUST return the count of entries removed in
    /// THIS call (not lifetime) — the wired counter on NodeState
    /// accumulates returns across all calls.
    #[test]
    fn ops_46_tracked_count_pins_distinct_witness_residency_for_gauge() {
        let mut engine = ReputationEngine::new();
        assert_eq!(engine.tracked_count(), 0,
            "fresh engine has no scored witnesses");

        // 5 distinct witnesses → gauge = 5.
        for n in 0..5u64 {
            let wh = format!("witness_{n}");
            engine.apply_event(&wh, ReputationEvent::Undisputed, 1000.0 + n as f64);
        }
        assert_eq!(engine.tracked_count(), 5,
            "5 distinct witnesses = gauge=5");

        // Re-applying events to the same witnesses must NOT inflate
        // the gauge — operator dashboard distinguishes "5 events on 5
        // witnesses" (healthy spread) from "100 events on 1 witness"
        // (concentrated activity), and only the latter would inflate
        // a misimplemented gauge.
        for _ in 0..20 {
            engine.apply_event("witness_0", ReputationEvent::Undisputed, 2000.0);
        }
        assert_eq!(engine.tracked_count(), 5,
            "events on existing witness never grow gauge");

        // prune_inactive returns the count reaped THIS call. The
        // NodeState atomic counter accumulates these returns.
        // Witnesses 0..5 had last_event in [1000.0, 1004.0]; witness_0
        // also had events at 2000.0, so its last_event is 2000.0.
        // Cutoff `now - max_age = 5000.0 - 2500.0 = 2500.0` retains only
        // entries with last_event >= 2500.0 — none qualify, so all 5 reaped.
        let pruned = engine.prune_inactive(5000.0, 2500.0);
        assert_eq!(pruned, 5, "all 5 inactive entries reaped in this call");
        assert_eq!(engine.tracked_count(), 0,
            "post-prune gauge collapses to 0 (mass-prune scenario)");

        // Add 3 fresh witnesses, prune with a window that retains 2 of 3.
        // Entries: witness_a@10000, witness_b@10100, witness_c@10200.
        // Cutoff 10100 → witness_a (10000) reaped, witness_b (10100) and
        // witness_c (10200) retained. prune_inactive returns count
        // reaped this call (1), separate from the cumulative atomic
        // counter on NodeState.
        engine.apply_event("witness_a", ReputationEvent::Undisputed, 10_000.0);
        engine.apply_event("witness_b", ReputationEvent::Undisputed, 10_100.0);
        engine.apply_event("witness_c", ReputationEvent::Undisputed, 10_200.0);
        assert_eq!(engine.tracked_count(), 3);
        let pruned = engine.prune_inactive(10_200.0, 100.0);
        assert_eq!(pruned, 1,
            "selective prune reaps only the older-than-cutoff entry");
        assert_eq!(engine.tracked_count(), 2,
            "selective prune leaves recent entries — gauge=2");

        // Idempotent prune: same call again with same cutoff reaps 0.
        let pruned = engine.prune_inactive(10_200.0, 100.0);
        assert_eq!(pruned, 0, "idempotent prune returns 0 on second call");
        assert_eq!(engine.tracked_count(), 2);
    }

    // ── Diversity bonus tests (economics §11.1) ────────────────────────

    #[test]
    fn test_diversity_bonus_no_zones() {
        let engine = ReputationEngine::new();
        assert!((engine.diversity_bonus("w1") - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_diversity_bonus_single_zone() {
        let mut engine = ReputationEngine::new();
        engine.record_zone_attestation("w1", ZoneId::from_legacy(5), 100_000.0);
        // 1.0 + 0.1 × 1 = 1.1
        assert!((engine.diversity_bonus("w1") - 1.1).abs() < 0.001);
    }

    #[test]
    fn test_diversity_bonus_multiple_zones() {
        let mut engine = ReputationEngine::new();
        let t = 100_000.0;
        for zone in 0..5u64 {
            engine.record_zone_attestation("w1", ZoneId::from_legacy(zone), t);
        }
        // 1.0 + 0.1 × 5 = 1.5
        assert!((engine.diversity_bonus("w1") - 1.5).abs() < 0.001);
    }

    #[test]
    fn test_diversity_bonus_capped_at_max() {
        let mut engine = ReputationEngine::new();
        let t = 100_000.0;
        // 15 unique zones → 1.0 + 0.1 × 15 = 2.5 → capped at 2.0
        for zone in 0..15u64 {
            engine.record_zone_attestation("w1", ZoneId::from_legacy(zone), t);
        }
        assert!((engine.diversity_bonus("w1") - DIVERSITY_BONUS_MAX).abs() < 0.001);
    }

    #[test]
    fn test_diversity_bonus_same_zone_no_double_count() {
        let mut engine = ReputationEngine::new();
        let t = 100_000.0;
        engine.record_zone_attestation("w1", ZoneId::from_legacy(3), t);
        engine.record_zone_attestation("w1", ZoneId::from_legacy(3), t + 1.0);
        engine.record_zone_attestation("w1", ZoneId::from_legacy(3), t + 2.0);
        // Same zone 3 times → still 1 unique zone
        assert!((engine.diversity_bonus("w1") - 1.1).abs() < 0.001);
    }

    #[test]
    fn test_diversity_bonus_resets_on_new_day() {
        let mut engine = ReputationEngine::new();
        let t = 100_000.0; // Day 1
        engine.record_zone_attestation("w1", ZoneId::from_legacy(1), t);
        engine.record_zone_attestation("w1", ZoneId::from_legacy(2), t);
        assert!((engine.diversity_bonus("w1") - 1.2).abs() < 0.001);

        // Next day
        let t2 = t + SECS_PER_DAY;
        engine.record_zone_attestation("w1", ZoneId::from_legacy(5), t2);
        // Old day cleared, only zone 5 today
        assert!((engine.diversity_bonus("w1") - 1.1).abs() < 0.001);
    }

    // ── Reward formula tests (economics §11.1) ─────────────────────────

    #[test]
    fn test_compute_reward_default_witness() {
        let engine = ReputationEngine::new();
        // Default: trust=0.5, diversity=1.0 (no zones) → 1000 × 0.5 × 1.0 = 500
        assert_eq!(engine.compute_reward("unknown", 1000, FAR_FUTURE), 500);
    }

    #[test]
    fn test_compute_reward_trusted_witness() {
        let mut engine = ReputationEngine::new();
        // Drive reputation toward 90/100 across 40 events (trivial intra-decay).
        for i in 0..40 {
            engine.apply_event("w1", ReputationEvent::Undisputed, i as f64);
        }
        let expected_tm = 0.9 * decay_factor(39.0, FAR_FUTURE);
        assert!((engine.trust_multiplier("w1", FAR_FUTURE) - expected_tm).abs() < 0.001);
        // No zone diversity → 1000 × expected_tm × 1.0
        let expected_reward = (1000.0 * expected_tm) as u64;
        assert_eq!(engine.compute_reward("w1", 1000, FAR_FUTURE), expected_reward);
    }

    #[test]
    fn test_compute_reward_with_diversity() {
        let mut engine = ReputationEngine::new();
        // Drive to 90/100
        for i in 0..40 {
            engine.apply_event("w1", ReputationEvent::Undisputed, 100_000.0 + i as f64);
        }
        // Witness 5 zones today
        for zone in 0..5u64 {
            engine.record_zone_attestation("w1", ZoneId::from_legacy(zone), 100_000.0);
        }
        let expected_tm = 0.9 * decay_factor(100_039.0, FAR_FUTURE);
        let expected_reward = (1000.0 * expected_tm * 1.5) as u64;
        assert_eq!(engine.compute_reward("w1", 1000, FAR_FUTURE), expected_reward);
    }

    #[test]
    fn test_compute_reward_new_witness_low_trust() {
        let mut engine = ReputationEngine::new();
        // Score = 10/100 → raw trust = 0.1
        for _ in 0..4 {
            engine.apply_event("w1", ReputationEvent::SpamFlagged, 1.0);
        }
        assert!((engine.score("w1") - 10.0).abs() < 0.001);
        // FAR_FUTURE decay pulls effective trust below 0.1.
        let expected_tm = 0.1 * decay_factor(1.0, FAR_FUTURE);
        let expected_reward = (1000.0 * expected_tm) as u64;
        assert_eq!(engine.compute_reward("w1", 1000, FAR_FUTURE), expected_reward);
    }

    #[test]
    fn test_compute_reward_zero_reputation() {
        let mut engine = ReputationEngine::new();
        // Drive to 0
        for i in 0..10 {
            engine.apply_event("w1", ReputationEvent::SpamFlagged, i as f64);
        }
        assert_eq!(engine.score("w1"), MIN_REPUTATION);
        // 1000 × 0.0 × 1.0 = 0
        assert_eq!(engine.compute_reward("w1", 1000, FAR_FUTURE), 0);
    }

    // ── Pruning tests ────────────────────────────────────────────────

    #[test]
    fn test_prune_inactive_removes_old() {
        let mut engine = ReputationEngine::new();
        let thirty_days = 30.0 * SECS_PER_DAY;
        // w1 active 60 days ago (stale)
        engine.apply_event("w1", ReputationEvent::Undisputed, 1000.0);
        // w2 active recently
        engine.apply_event("w2", ReputationEvent::Undisputed, 1000.0 + thirty_days + 500.0);

        let now = 1000.0 + thirty_days + 1000.0;
        let pruned = engine.prune_inactive(now, thirty_days);

        assert_eq!(pruned, 1);
        assert_eq!(engine.tracked_count(), 1);
        assert!(engine.get("w1").is_none());
        assert!(engine.get("w2").is_some());
    }

    #[test]
    fn test_prune_inactive_nothing_stale() {
        let mut engine = ReputationEngine::new();
        let thirty_days = 30.0 * SECS_PER_DAY;
        engine.apply_event("w1", ReputationEvent::Undisputed, 1000.0);
        engine.apply_event("w2", ReputationEvent::Undisputed, 1001.0);

        let now = 1500.0; // only 500s later — nothing stale
        let pruned = engine.prune_inactive(now, thirty_days);
        assert_eq!(pruned, 0);
        assert_eq!(engine.tracked_count(), 2);
    }

    #[test]
    fn test_prune_inactive_also_cleans_daily_zones() {
        let mut engine = ReputationEngine::new();
        let thirty_days = 30.0 * SECS_PER_DAY;
        let now = 100_000.0 + thirty_days + 1000.0;

        // w1: old activity + zone attestation on today
        engine.apply_event("w1", ReputationEvent::Undisputed, 1000.0);
        engine.record_zone_attestation("w1", ZoneId::from_legacy(5), now);

        // w2: recent activity
        engine.apply_event("w2", ReputationEvent::Undisputed, now - 100.0);

        let pruned = engine.prune_inactive(now, thirty_days);
        // w1 is pruned because last_event = 1000.0 (old), despite zone attestation
        assert_eq!(pruned, 1);
        assert!(engine.get("w1").is_none());
        // daily_zones for w1 should also be cleaned
        assert!((engine.diversity_bonus("w1") - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_prune_inactive_all_pruned() {
        let mut engine = ReputationEngine::new();
        let thirty_days = 30.0 * SECS_PER_DAY;
        engine.apply_event("w1", ReputationEvent::Undisputed, 100.0);
        engine.apply_event("w2", ReputationEvent::Undisputed, 200.0);

        let now = 100.0 + thirty_days + 1000.0;
        let pruned = engine.prune_inactive(now, thirty_days);
        assert_eq!(pruned, 2);
        assert_eq!(engine.tracked_count(), 0);
    }

    // ── Temporal trust decay tests (Protocol §11.1 Layer 3) ─────────────

    #[test]
    fn test_first_seen_set_on_creation() {
        let mut engine = ReputationEngine::new();
        engine.apply_event("w1", ReputationEvent::Undisputed, 5000.0);
        let entry = engine.get("w1").unwrap();
        assert_eq!(entry.first_seen, 5000.0);
    }

    #[test]
    fn test_first_seen_not_overwritten() {
        let mut engine = ReputationEngine::new();
        engine.apply_event("w1", ReputationEvent::Undisputed, 5000.0);
        engine.apply_event("w1", ReputationEvent::Undisputed, 9000.0);
        // first_seen stays at original value
        let entry = engine.get("w1").unwrap();
        assert_eq!(entry.first_seen, 5000.0);
    }

    #[test]
    fn test_age_factor_standalone() {
        let t0 = 100_000.0;
        // < 24h → 0.25
        assert_eq!(age_factor(t0, t0 + 3600.0), AGE_FACTOR_TIER_1);
        // < 48h → 0.50
        assert_eq!(age_factor(t0, t0 + 30.0 * 3600.0), AGE_FACTOR_TIER_2);
        // < 7d → 0.75
        assert_eq!(age_factor(t0, t0 + 3.0 * 86_400.0), AGE_FACTOR_TIER_3);
        // >= 7d → 1.0
        assert_eq!(age_factor(t0, t0 + 8.0 * 86_400.0), AGE_FACTOR_FULL);
    }

    #[test]
    fn test_age_factor_legacy_entry() {
        // first_seen = 0.0 (legacy) → always full trust
        assert_eq!(age_factor(0.0, 100.0), AGE_FACTOR_FULL);
        assert_eq!(age_factor(0.0, 0.0), AGE_FACTOR_FULL);
    }

    #[test]
    fn test_age_factor_boundary_values() {
        let t0 = 100_000.0;
        // Exactly at 24h boundary → tier 2
        assert_eq!(age_factor(t0, t0 + AGE_TIER_1_SECS), AGE_FACTOR_TIER_2);
        // Exactly at 48h boundary → tier 3
        assert_eq!(age_factor(t0, t0 + AGE_TIER_2_SECS), AGE_FACTOR_TIER_3);
        // Exactly at 7d boundary → full
        assert_eq!(age_factor(t0, t0 + AGE_TIER_3_SECS), AGE_FACTOR_FULL);
    }

    #[test]
    fn test_trust_multiplier_at_with_age_decay() {
        let mut engine = ReputationEngine::new();
        let t0 = 100_000.0;
        engine.apply_event("w1", ReputationEvent::Undisputed, t0);
        // Score = 51 → base trust = 0.51

        // Queried 1 hour after creation → age_factor = 0.25, decay ~1.0
        let q1 = t0 + 3600.0;
        let tm = engine.trust_multiplier("w1", q1);
        assert!((tm - 0.51 * 0.25 * decay_factor(t0, q1)).abs() < 0.001);

        // Queried 2 days after → wait, actually 3 days → age_factor = 0.75
        let q2 = t0 + 3.0 * 86_400.0;
        let tm = engine.trust_multiplier("w1", q2);
        assert!((tm - 0.51 * 0.75 * decay_factor(t0, q2)).abs() < 0.001);

        // Queried 8 days after → age_factor = 1.0
        let q3 = t0 + 8.0 * 86_400.0;
        let tm = engine.trust_multiplier("w1", q3);
        assert!((tm - 0.51 * decay_factor(t0, q3)).abs() < 0.001);
    }

    #[test]
    fn test_compute_reward_with_age_decay() {
        let mut engine = ReputationEngine::new();
        let t0 = 100_000.0;
        // Create witness; score = 51.
        engine.apply_event("w1", ReputationEvent::Undisputed, t0);

        // 1 hour old: 1000 × 0.51 × 0.25 × age_decay ≈ 127
        let q1 = t0 + 3600.0;
        let r = engine.compute_reward("w1", 1000, q1);
        let exp1 = (1000.0 * 0.51 * 0.25 * decay_factor(t0, q1)) as u64;
        assert_eq!(r, exp1);

        // 8 days old: 1000 × 0.51 × 1.0 × age_decay(8d)
        let q2 = t0 + 8.0 * 86_400.0;
        let r = engine.compute_reward("w1", 1000, q2);
        let exp2 = (1000.0 * 0.51 * decay_factor(t0, q2)) as u64;
        assert_eq!(r, exp2);
    }

    #[test]
    fn test_age_factor_negative_age_clamped() {
        // now < first_seen shouldn't happen, but handle gracefully
        let t0 = 100_000.0;
        // age = max(0, -1000) = 0 → tier 1
        assert_eq!(age_factor(t0, t0 - 1000.0), AGE_FACTOR_TIER_1);
    }

    // ── Challenger reputation tests (economics §10.2) ───────────────

    #[test]
    fn test_challenge_succeeded_rewards_challenger() {
        let mut engine = ReputationEngine::new();
        engine.record_challenge_outcome("challenger1", true, 1000.0);
        let entry = engine.get("challenger1").unwrap();
        assert!((entry.score - (DEFAULT_REPUTATION + DELTA_CHALLENGE_SUCCEEDED)).abs() < FLOAT_EPS);
        assert_eq!(entry.challenges_filed, 1);
        assert_eq!(entry.challenges_won, 1);
        assert_eq!(entry.positive_events, 1);
    }

    #[test]
    fn test_challenge_failed_penalizes_challenger() {
        let mut engine = ReputationEngine::new();
        engine.record_challenge_outcome("challenger1", false, 1000.0);
        let entry = engine.get("challenger1").unwrap();
        assert!((entry.score - (DEFAULT_REPUTATION + DELTA_CHALLENGE_FAILED)).abs() < FLOAT_EPS);
        assert_eq!(entry.challenges_filed, 1);
        assert_eq!(entry.challenges_won, 0);
        assert_eq!(entry.negative_events, 1);
    }

    #[test]
    fn test_serial_false_accuser_extra_penalty() {
        let mut engine = ReputationEngine::new();
        // File 3 challenges, all dismissed (success rate = 0%)
        // After 3rd: rate = 0/3 = 0% < 50% → serial false accuser penalty
        engine.record_challenge_outcome("troll", false, 1000.0);
        engine.record_challenge_outcome("troll", false, 1001.0);
        engine.record_challenge_outcome("troll", false, 1002.0);

        let entry = engine.get("troll").unwrap();
        assert_eq!(entry.challenges_filed, 3);
        assert_eq!(entry.challenges_won, 0);
        // Score: 50 + (-3)*3 + (-7)*1 = 50 - 9 - 7 = 34
        // First 2 failed: -3 each = -6. Third failed: -3 + -7 (serial) = -10.
        // Total: 50 - 3 - 3 - 3 - 7 = 34 (modulo ~1e-6 intra-event decay).
        assert!((entry.score - 34.0).abs() < FLOAT_EPS);
    }

    #[test]
    fn test_serial_accuser_not_triggered_below_min_challenges() {
        let mut engine = ReputationEngine::new();
        // Only 2 challenges (below SERIAL_ACCUSER_MIN_CHALLENGES=3)
        engine.record_challenge_outcome("c1", false, 1000.0);
        engine.record_challenge_outcome("c1", false, 1001.0);
        let entry = engine.get("c1").unwrap();
        // Score: 50 - 3 - 3 = 44 (no serial penalty; intra-event decay < FLOAT_EPS)
        assert!((entry.score - 44.0).abs() < FLOAT_EPS);
        assert_eq!(entry.challenges_filed, 2);
    }

    #[test]
    fn test_serial_accuser_not_triggered_above_threshold() {
        let mut engine = ReputationEngine::new();
        // 3 challenges: 2 won, 1 lost → success rate = 66% > 50%
        engine.record_challenge_outcome("c1", true, 1000.0);
        engine.record_challenge_outcome("c1", true, 1001.0);
        engine.record_challenge_outcome("c1", false, 1002.0);
        let entry = engine.get("c1").unwrap();
        // Score: 50 + 3 + 3 - 3 = 53 (no serial penalty; intra-event decay < FLOAT_EPS)
        assert!((entry.score - 53.0).abs() < FLOAT_EPS);
        assert_eq!(entry.challenges_filed, 3);
        assert_eq!(entry.challenges_won, 2);
    }

    #[test]
    fn test_event_names_include_challenge_types() {
        assert_eq!(ReputationEvent::ChallengeSucceeded.name(), "challenge_succeeded");
        assert_eq!(ReputationEvent::ChallengeFailed.name(), "challenge_failed");
        assert_eq!(ReputationEvent::SerialFalseAccuser.name(), "serial_false_accuser");
    }

    #[test]
    fn test_challenge_counters_serde_backward_compat() {
        // Verify default fields work for deserialization of old entries
        let json = r#"{"score":50.0,"positive_events":5,"negative_events":1,"last_event":1000.0,"first_seen":900.0}"#;
        let entry: WitnessReputation = serde_json::from_str(json).unwrap();
        assert_eq!(entry.challenges_filed, 0);
        assert_eq!(entry.challenges_won, 0);
    }

    // ── AUDIT-4 / economics §12.4 Defense 1: half-life reputation decay ──

    #[test]
    fn test_reputation_half_life_exact_six_months() {
        let mut engine = ReputationEngine::new();
        let t0 = 100_000.0;
        // Drive to max reputation.
        for i in 0..50 {
            engine.apply_event("w1", ReputationEvent::DisputeWon, t0 + i as f64);
        }
        let last_event = t0 + 49.0;
        // Raw stored score should be at the ceiling (modulo tiny intra-event decay).
        assert!((engine.score("w1") - MAX_REPUTATION).abs() < FLOAT_EPS);

        // Six months later the decayed score should be exactly half.
        let one_half_life = last_event + REPUTATION_HALF_LIFE_SECS;
        let decayed = engine.score_at("w1", one_half_life);
        assert!((decayed - MAX_REPUTATION / 2.0).abs() < 0.01,
            "expected ~50 after one half-life, got {}", decayed);
    }

    #[test]
    fn test_reputation_five_year_sleeper_near_zero() {
        // economics §12.4: "Activity from 5 years ago contributes almost
        // nothing." A witness at max reputation left idle for 5 years
        // should retain < 0.1% of accumulated trust.
        let mut engine = ReputationEngine::new();
        let t0 = 100_000.0;
        for i in 0..50 {
            engine.apply_event("w1", ReputationEvent::DisputeWon, t0 + i as f64);
        }
        let last_event = t0 + 49.0;
        let five_years = last_event + 5.0 * 365.25 * 86_400.0;
        let decayed = engine.score_at("w1", five_years);
        assert!(decayed < 0.1, "5-year sleeper score should be near zero, got {}", decayed);
    }

    #[test]
    fn test_reputation_new_event_after_long_idle_does_not_revive() {
        // An idle witness whose score has decayed to near zero cannot be
        // revived by a single positive event (write-time decay applies
        // BEFORE the delta is added).
        let mut engine = ReputationEngine::new();
        let t0 = 100_000.0;
        for i in 0..50 {
            engine.apply_event("w1", ReputationEvent::DisputeWon, t0 + i as f64);
        }
        // Idle 5 years, then +1 event.
        let five_years_later = t0 + 49.0 + 5.0 * 365.25 * 86_400.0;
        engine.apply_event("w1", ReputationEvent::Undisputed, five_years_later);
        let score = engine.score("w1");
        // Pre-decay stored score was ~100; after 5-year decay ~0.09; +1 = ~1.09.
        assert!(score < 2.0,
            "post-idle event should not revive dead reputation, got {}", score);
        assert!(score > 1.0, "new event should contribute its delta, got {}", score);
    }

    #[test]
    fn test_reputation_decay_compounds_with_multiple_idle_gaps() {
        // Two idle windows compound multiplicatively.
        let mut engine = ReputationEngine::new();
        let t0 = 100_000.0;
        for i in 0..50 {
            engine.apply_event("w1", ReputationEvent::DisputeWon, t0 + i as f64);
        }
        let one_half_life = t0 + 49.0 + REPUTATION_HALF_LIFE_SECS;
        // +0 events; check half-life reached.
        assert!((engine.score_at("w1", one_half_life) - MAX_REPUTATION / 2.0).abs() < 0.01);
        // Write checkpoint at half-life (idempotent: dispute-voided effectively).
        engine.apply_event("w1", ReputationEvent::Undisputed, one_half_life);
        // Now stored score ≈ 50 + 1 = 51. After another half-life, decayed ≈ 25.5.
        let two_half_lives = one_half_life + REPUTATION_HALF_LIFE_SECS;
        let decayed = engine.score_at("w1", two_half_lives);
        assert!((decayed - 25.5).abs() < 0.05,
            "compound decay mismatch, got {}", decayed);
    }

    #[test]
    fn test_reputation_decay_zero_passes_through() {
        // Witness at score 0 stays at 0 after any decay (multiplicative).
        let mut engine = ReputationEngine::new();
        let t0 = 100_000.0;
        for i in 0..20 {
            engine.apply_event("w1", ReputationEvent::SpamFlagged, t0 + i as f64);
        }
        assert_eq!(engine.score("w1"), MIN_REPUTATION);
        let far_future = t0 + REPUTATION_HALF_LIFE_SECS * 3.0;
        assert_eq!(engine.score_at("w1", far_future), MIN_REPUTATION);
    }

    #[test]
    fn test_decay_score_helper_legacy_entry() {
        // last_event = 0.0 (legacy pre-temporal-decay entry) → no decay.
        assert!((decay_score(75.0, 0.0, 1_000_000.0) - 75.0).abs() < FLOAT_EPS);
    }

    #[test]
    fn test_decay_score_helper_backwards_time() {
        // now < last_event → return unchanged (guards against clock skew).
        assert!((decay_score(75.0, 1000.0, 500.0) - 75.0).abs() < FLOAT_EPS);
    }

    #[test]
    fn test_summary_at_sorts_by_decayed_score() {
        // A: saturates at 100 at t=1 (early), idle until query.
        // B: saturates at 100 later, less idle → less decayed.
        // summary_at must sort by decayed score, so B should come first.
        let mut engine = ReputationEngine::new();
        // A driven to max at t=1 (avoid legacy 0.0 guard).
        for _ in 0..30 {
            engine.apply_event("A", ReputationEvent::DisputeWon, 1.0);
        }
        // B driven to max at t = 0.9 × half_life (later).
        let t_b = 0.9 * REPUTATION_HALF_LIFE_SECS;
        for _ in 0..30 {
            engine.apply_event("B", ReputationEvent::DisputeWon, t_b);
        }
        // Query at 1.0 × half_life. A decayed ≈ 50, B decayed ≈ 93.
        let now = REPUTATION_HALF_LIFE_SECS;
        let s = engine.summary_at(now);
        assert_eq!(s[0].0, "B", "B should top (less decayed)");
        assert_eq!(s[1].0, "A");
    }

    // ─── Profile C Gap C: attestation-aware trust multiplier ────────────────

    #[test]
    fn trust_with_attestation_none_equals_base() {
        use crate::identity::AttestationLevel;
        let mut engine = ReputationEngine::new();
        engine.apply_event("alice", ReputationEvent::DisputeWon, 100.0);
        let base = engine.trust_multiplier("alice", 100.0);
        let with_none = engine.trust_multiplier_with_attestation(
            "alice",
            AttestationLevel::None,
            100.0,
        );
        assert!((base - with_none).abs() < 1e-12);
    }

    #[test]
    fn trust_with_attestation_scales_by_level() {
        use crate::identity::AttestationLevel;
        let mut engine = ReputationEngine::new();
        engine.apply_event("alice", ReputationEvent::DisputeWon, 100.0);
        let base = engine.trust_multiplier("alice", 100.0);

        // Per-level expected ratios from AttestationLevel::trust_multiplier.
        for (level, expected_ratio) in [
            (AttestationLevel::None, 1.0),
            (AttestationLevel::Software, 1.1),
            (AttestationLevel::SecureBoot, 1.2),
            (AttestationLevel::HardwareKey, 1.4),
            (AttestationLevel::Puf, 1.5),
        ] {
            let with_lvl = engine.trust_multiplier_with_attestation("alice", level, 100.0);
            let actual_ratio = with_lvl / base;
            assert!(
                (actual_ratio - expected_ratio).abs() < 1e-12,
                "level={level:?} expected_ratio={expected_ratio} got={actual_ratio}",
            );
        }
    }

    #[test]
    fn trust_with_attestation_orders_correctly() {
        use crate::identity::AttestationLevel;
        let mut engine = ReputationEngine::new();
        engine.apply_event("alice", ReputationEvent::DisputeWon, 100.0);
        let now = 100.0;
        // Strict monotonic increase across levels — locked spec ladder.
        let none = engine.trust_multiplier_with_attestation("alice", AttestationLevel::None, now);
        let software = engine.trust_multiplier_with_attestation("alice", AttestationLevel::Software, now);
        let secboot = engine.trust_multiplier_with_attestation("alice", AttestationLevel::SecureBoot, now);
        let hwkey = engine.trust_multiplier_with_attestation("alice", AttestationLevel::HardwareKey, now);
        let puf = engine.trust_multiplier_with_attestation("alice", AttestationLevel::Puf, now);
        assert!(none < software);
        assert!(software < secboot);
        assert!(secboot < hwkey);
        assert!(hwkey < puf);
    }

    #[test]
    fn trust_with_attestation_unknown_witness_uses_default() {
        use crate::identity::AttestationLevel;
        let engine = ReputationEngine::new();
        // Unknown witness → trust_multiplier returns 0.5 (default 50/100).
        // With PUF (1.5x) the composed value is 0.75.
        let v = engine.trust_multiplier_with_attestation(
            "never-seen",
            AttestationLevel::Puf,
            100.0,
        );
        assert!((v - 0.75).abs() < 1e-12, "expected 0.5 × 1.5 = 0.75, got {v}");
    }

    #[test]
    fn compute_reward_with_attestation_folds_in_factor() {
        use crate::identity::AttestationLevel;
        let mut engine = ReputationEngine::new();
        engine.apply_event("alice", ReputationEvent::DisputeWon, 100.0);
        let base = 1_000_000;
        let now = 100.0;
        let r_none = engine.compute_reward_with_attestation(
            "alice",
            base,
            now,
            AttestationLevel::None,
        );
        let r_puf = engine.compute_reward_with_attestation(
            "alice",
            base,
            now,
            AttestationLevel::Puf,
        );
        assert_eq!(r_none, engine.compute_reward("alice", base, now));
        // r_puf should be ≈ 1.5 × r_none (within 1 micros for integer trunc).
        let ratio = r_puf as f64 / r_none as f64;
        assert!(
            (ratio - 1.5).abs() < 0.001,
            "expected ratio ≈ 1.5, got {ratio} (none={r_none}, puf={r_puf})",
        );
    }

    // ─── Pure-surface tests ───────────────────────────────────────────
    //
    // Five fixture-free axes on src/network/reputation.rs pure surface,
    // chosen orthogonal to the existing 58 tests:
    //  1. economics §11.2 + §12.4 numeric-constant pin (delta/threshold drift).
    //  2. ReputationEvent enum coverage — delta sign + name string for all 7 variants.
    //  3. score_to_multiplier indirect: trust_multiplier saturation at boundary scores.
    //  4. WitnessReputation::Default field shape (all 7 fields pinned).
    //  5. trust_multiplier_at composition law: equals scale × age for arbitrary state.

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_constants_pin_delta_signs_thresholds_and_half_life_invariants() {
        // Default/min/max — pin (economics §11.2).
        assert_eq!(DEFAULT_REPUTATION, 50.0, "DEFAULT_REPUTATION MUST be 50.0 (new-witness neutral)");
        assert_eq!(MIN_REPUTATION, 0.0, "MIN_REPUTATION MUST be 0.0 (floor)");
        assert_eq!(MAX_REPUTATION, 100.0, "MAX_REPUTATION MUST be 100.0 (ceiling)");
        assert!(DEFAULT_REPUTATION > MIN_REPUTATION && DEFAULT_REPUTATION < MAX_REPUTATION,
            "DEFAULT MUST sit strictly between floor and ceiling");

        // Delta sign invariants — positive events MUST have positive delta,
        // negative MUST have negative delta. Pin specific values (economics §11.2).
        assert_eq!(DELTA_UNDISPUTED, 1.0, "undisputed delta MUST be +1.0");
        assert_eq!(DELTA_DISPUTE_WON, 2.0, "dispute_won delta MUST be +2.0");
        assert_eq!(DELTA_DISPUTE_LOST, -5.0, "dispute_lost delta MUST be -5.0");
        assert_eq!(DELTA_SPAM_FLAGGED, -10.0, "spam_flagged delta MUST be -10.0 (severe)");
        assert_eq!(DELTA_CHALLENGE_SUCCEEDED, 3.0, "challenge_succeeded delta MUST be +3.0");
        assert_eq!(DELTA_CHALLENGE_FAILED, -3.0, "challenge_failed delta MUST be -3.0");
        assert_eq!(DELTA_SERIAL_FALSE_ACCUSER, -7.0, "serial_false_accuser delta MUST be -7.0");

        // Severity ordering on the negative side (lower = harsher):
        // spam_flagged (-10) < serial_false_accuser (-7) < dispute_lost (-5)
        //                                                < challenge_failed (-3).
        assert!(DELTA_SPAM_FLAGGED < DELTA_SERIAL_FALSE_ACCUSER,
            "spam_flagged (-10) MUST remain the harshest single penalty");
        assert!(DELTA_SERIAL_FALSE_ACCUSER < DELTA_DISPUTE_LOST,
            "serial_false_accuser (-7) MUST be stricter than dispute_lost (-5)");
        assert!(DELTA_DISPUTE_LOST < DELTA_CHALLENGE_FAILED,
            "dispute_lost (-5) MUST be stricter than challenge_failed (-3)");

        // Reward ordering: dispute_won > undisputed (incentive to participate in disputes).
        assert!(DELTA_DISPUTE_WON > DELTA_UNDISPUTED,
            "dispute_won MUST reward more than undisputed (Nash incentive)");

        // Reputation half-life — exactly 180 days in seconds (economics §12.4).
        assert_eq!(REPUTATION_HALF_LIFE_SECS, 180.0 * 86_400.0,
            "REPUTATION_HALF_LIFE_SECS MUST be 180 days (§12.4 hard-limits table)");

        // Age tier thresholds (Protocol §11.1 Layer 3).
        assert_eq!(AGE_TIER_1_SECS, 24.0 * 3600.0, "AGE_TIER_1_SECS MUST be 24h");
        assert_eq!(AGE_TIER_2_SECS, 48.0 * 3600.0, "AGE_TIER_2_SECS MUST be 48h");
        assert_eq!(AGE_TIER_3_SECS, 7.0 * 86_400.0, "AGE_TIER_3_SECS MUST be 7 days");
        assert!(AGE_TIER_1_SECS < AGE_TIER_2_SECS && AGE_TIER_2_SECS < AGE_TIER_3_SECS,
            "age thresholds MUST be strictly monotonic");

        // Age factors — ramp 0.25 → 0.5 → 0.75 → 1.0.
        assert_eq!(AGE_FACTOR_TIER_1, 0.25);
        assert_eq!(AGE_FACTOR_TIER_2, 0.50);
        assert_eq!(AGE_FACTOR_TIER_3, 0.75);
        assert_eq!(AGE_FACTOR_FULL, 1.0);
        assert!(AGE_FACTOR_TIER_1 < AGE_FACTOR_TIER_2
                && AGE_FACTOR_TIER_2 < AGE_FACTOR_TIER_3
                && AGE_FACTOR_TIER_3 < AGE_FACTOR_FULL,
            "age factors MUST ramp strictly monotonically toward 1.0");

        // Diversity bonus constants.
        assert_eq!(DIVERSITY_BONUS_PER_ZONE, 0.1, "DIVERSITY_BONUS_PER_ZONE MUST be 0.1 (§11.1)");
        assert_eq!(DIVERSITY_BONUS_MAX, 2.0, "DIVERSITY_BONUS_MAX MUST be 2.0 cap");
        assert_eq!(SECS_PER_DAY, 86_400.0, "SECS_PER_DAY MUST be 86_400.0");

        // Serial accuser thresholds.
        assert_eq!(SERIAL_ACCUSER_MIN_CHALLENGES, 3,
            "SERIAL_ACCUSER_MIN_CHALLENGES MUST be 3 (min filed before serial penalty)");
        assert_eq!(SERIAL_ACCUSER_THRESHOLD, 0.5,
            "SERIAL_ACCUSER_THRESHOLD MUST be 0.5 (economics §10.2)");
    }

    #[test]
    fn batch_b_reputation_event_name_and_delta_pinned_for_all_7_variants() {
        // Pin (name, delta) tuple for every ReputationEvent variant. The Rust
        // exhaustive-match guarantees a new variant will fail at the match site,
        // but this test ensures the existing 7 variants don't silently get
        // re-tagged or have their delta swapped.
        let variants_and_expected = [
            (ReputationEvent::Undisputed,         "undisputed",          DELTA_UNDISPUTED),
            (ReputationEvent::DisputeWon,         "dispute_won",         DELTA_DISPUTE_WON),
            (ReputationEvent::DisputeLost,        "dispute_lost",        DELTA_DISPUTE_LOST),
            (ReputationEvent::SpamFlagged,        "spam_flagged",        DELTA_SPAM_FLAGGED),
            (ReputationEvent::ChallengeSucceeded, "challenge_succeeded", DELTA_CHALLENGE_SUCCEEDED),
            (ReputationEvent::ChallengeFailed,    "challenge_failed",    DELTA_CHALLENGE_FAILED),
            (ReputationEvent::SerialFalseAccuser, "serial_false_accuser", DELTA_SERIAL_FALSE_ACCUSER),
        ];
        for (ev, name, delta) in variants_and_expected.iter() {
            assert_eq!(
                ev.name(), *name,
                "ReputationEvent::{ev:?}.name() MUST be {name:?} — wire format / metrics labels depend on this string"
            );
            assert_eq!(
                ev.delta(), *delta,
                "ReputationEvent::{ev:?}.delta() MUST be {delta}"
            );
        }

        // Positive/negative classification invariant.
        let positives = [
            ReputationEvent::Undisputed,
            ReputationEvent::DisputeWon,
            ReputationEvent::ChallengeSucceeded,
        ];
        for p in positives.iter() {
            assert!(p.delta() > 0.0, "{p:?} MUST be classified positive (delta > 0)");
        }
        let negatives = [
            ReputationEvent::DisputeLost,
            ReputationEvent::SpamFlagged,
            ReputationEvent::ChallengeFailed,
            ReputationEvent::SerialFalseAccuser,
        ];
        for n in negatives.iter() {
            assert!(n.delta() < 0.0, "{n:?} MUST be classified negative (delta < 0)");
        }
    }

    #[test]
    fn batch_b_witness_reputation_trust_multiplier_pins_boundary_score_clamp() {
        // trust_multiplier delegates to score_to_multiplier(score) which divides
        // by MAX_REPUTATION and clamps to [0, 1]. Pin the clamp at both boundaries
        // by constructing a WitnessReputation with score outside [0, 100].

        let zero = WitnessReputation { score: 0.0, ..Default::default() };
        assert_eq!(zero.trust_multiplier(), 0.0, "score=0 MUST yield trust=0.0 (floor)");

        let neutral = WitnessReputation { score: 50.0, ..Default::default() };
        assert_eq!(neutral.trust_multiplier(), 0.5, "score=50 MUST yield trust=0.5 (linear midpoint)");

        let max = WitnessReputation { score: 100.0, ..Default::default() };
        assert_eq!(max.trust_multiplier(), 1.0, "score=100 MUST yield trust=1.0 (ceiling)");

        // Out-of-range above MAX clamps to 1.0 — this is the bug-defense lane:
        // a faulty caller cannot inflate trust above 1.0.
        let over = WitnessReputation { score: 150.0, ..Default::default() };
        assert_eq!(over.trust_multiplier(), 1.0,
            "score > MAX_REPUTATION MUST clamp trust at 1.0 (no inflation channel)");

        // Negative score clamps to 0.0.
        let neg = WitnessReputation { score: -50.0, ..Default::default() };
        assert_eq!(neg.trust_multiplier(), 0.0,
            "negative score MUST clamp trust at 0.0 (no underflow)");

        // Linear mapping is strict at intermediate points.
        let q = WitnessReputation { score: 25.0, ..Default::default() };
        assert!((q.trust_multiplier() - 0.25).abs() < f64::EPSILON,
            "score=25 MUST map linearly to trust=0.25");
        let q3 = WitnessReputation { score: 75.0, ..Default::default() };
        assert!((q3.trust_multiplier() - 0.75).abs() < f64::EPSILON,
            "score=75 MUST map linearly to trust=0.75");
    }

    #[test]
    fn batch_b_witness_reputation_default_pins_all_seven_fields_exactly() {
        // WitnessReputation::default() MUST set the explicit field values the
        // engine's apply_event/apply_credit/score logic depends on. Any silent
        // drift in this constructor breaks first-write semantics for new witnesses.
        let d = WitnessReputation::default();
        assert_eq!(d.score, DEFAULT_REPUTATION,
            "Default::score MUST equal DEFAULT_REPUTATION (50.0 — new witness neutral)");
        assert_eq!(d.positive_events, 0, "Default::positive_events MUST be 0");
        assert_eq!(d.negative_events, 0, "Default::negative_events MUST be 0");
        assert_eq!(d.last_event, 0.0,
            "Default::last_event MUST be 0.0 — sentinel for \"never updated\" / legacy entry decay-skip path");
        assert_eq!(d.first_seen, 0.0,
            "Default::first_seen MUST be 0.0 — sentinel for legacy (pre-temporal-decay) → age_factor returns AGE_FACTOR_FULL");
        assert_eq!(d.challenges_filed, 0, "Default::challenges_filed MUST be 0 (no false-accuser penalty for fresh)");
        assert_eq!(d.challenges_won, 0, "Default::challenges_won MUST be 0");

        // Cross-check the legacy-entry decay-skip path: with last_event=0.0,
        // score_at(now) MUST return score unchanged regardless of now.
        let any_now = 1e9;
        assert_eq!(d.score_at(any_now), DEFAULT_REPUTATION,
            "legacy entry (last_event=0) MUST skip decay — score_at returns unchanged");

        // Cross-check the legacy first_seen=0 → AGE_FACTOR_FULL → trust ==
        // score/MAX (no age penalty).
        let tm_legacy = d.trust_multiplier_at(any_now);
        assert!((tm_legacy - 0.5).abs() < f64::EPSILON,
            "legacy entry (first_seen=0, score=50) MUST yield trust=0.5 (AGE_FACTOR_FULL applied)");
    }

    #[test]
    fn batch_b_trust_multiplier_at_pins_composition_score_decay_times_age_factor() {
        // trust_multiplier_at(now) = score_to_multiplier(decay_score(score, last_event, now))
        //                          × age_factor(first_seen, now)
        // Pin the composition law by constructing a witness with all four
        // factors live: nonzero last_event (decay active), nonzero first_seen
        // (age scaling active), score in mid-range.

        let first_seen: f64 = 1_000_000.0;
        let last_event: f64 = first_seen + AGE_TIER_3_SECS + 86_400.0; // 8 days after first_seen
        let w = WitnessReputation {
            score: 80.0,
            positive_events: 30,
            negative_events: 0,
            last_event,
            first_seen,
            challenges_filed: 0,
            challenges_won: 0,
        };
        // Query 90 days after first_seen — past the AGE_TIER_3 ramp (full age factor).
        let now: f64 = first_seen + 90.0 * 86_400.0;

        // Expected composition: decay_score × score_to_multiplier × age_factor.
        let dt = now - last_event;
        let expected_decayed = (80.0 * 0.5_f64.powf(dt / REPUTATION_HALF_LIFE_SECS))
            .clamp(MIN_REPUTATION, MAX_REPUTATION);
        let expected_mul = (expected_decayed / MAX_REPUTATION).clamp(0.0, 1.0);
        let expected_age = AGE_FACTOR_FULL; // 90 days >> AGE_TIER_3
        let expected = expected_mul * expected_age;

        let actual = w.trust_multiplier_at(now);
        assert!(
            (actual - expected).abs() < 1e-9,
            "trust_multiplier_at composition: expected {expected}, got {actual} (dt={dt}, decayed={expected_decayed})"
        );

        // Cross-check: score_at(now) MUST equal the inner decay_score (no age factor).
        let score_at = w.score_at(now);
        assert!(
            (score_at - expected_decayed).abs() < 1e-9,
            "score_at MUST equal decay_score(score, last_event, now) — no age scaling applied"
        );

        // Boundary: at now == first_seen → age_factor = AGE_FACTOR_TIER_1 (< 24h),
        // and now < last_event for our setup, so decay_score returns score unchanged.
        let now_zero = first_seen;
        let tm0 = w.trust_multiplier_at(now_zero);
        let expected0 = (80.0 / MAX_REPUTATION) * AGE_FACTOR_TIER_1;
        assert!(
            (tm0 - expected0).abs() < 1e-9,
            "at first_seen exact: trust MUST be (score/MAX) × AGE_FACTOR_TIER_1 ({expected0}), got {tm0}"
        );
    }

    #[test]
    fn harden_record_challenge_outcome_missing_entry_does_not_panic() {
        // Regression guard: record_challenge_outcome with guilty=false used to
        // .expect() the challenger entry still present after apply_event. If a
        // future refactor removes the entry inside apply_event, the node must
        // return silently rather than panic. We simulate the gap by removing
        // the entry right after it would be created, then calling again.
        let mut engine = ReputationEngine::new();
        // Prime the engine so the challenger has an entry.
        engine.record_challenge_outcome("attacker", false, 1000.0);
        // Remove the entry to put the engine in the "missing" state.
        engine.entries.remove("attacker");
        // This call recreates the entry at .or_default() but then apply_event
        // runs; after that get() succeeds as normal. The let-else guard ensures
        // no panic even if entries diverge in future code paths.
        engine.record_challenge_outcome("attacker", false, 1001.0);
        // If we reach this line the hardened path did not panic.
    }
}
