//! Exchange Identity Classification — economics v0.4.1 Section 13.12.2.
//!
//! Behavioral detection identifies likely exchange/custodial entities.
//! Score is a weighted sum of behavioral signals:
//! - unique_inbound_30d > 100
//! - unique_outbound_30d > 100
//! - zero_publications
//! - zero_witness_activity
//! - balance_volatility > threshold
//! - transfer_volume/stake_ratio > 10
//!
//! Restrictions applied to classified exchanges:
//! - Transfer velocity: 50% of normal
//! - Governance weight: ZERO
//! - Witness eligibility: INELIGIBLE
//! - Circuit breaker weight: 2x
//! - Stake rewards: ZERO

//!
//! Spec references:
//!   @spec economics §13.13.3

use std::collections::{HashMap, HashSet};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Exchange score threshold: above this → classified as exchange.
pub const EXCHANGE_CLASSIFICATION_THRESHOLD: f64 = 0.60;

/// Weight for each behavioral signal.
pub const WEIGHT_UNIQUE_INBOUND: f64 = 0.20;
pub const WEIGHT_UNIQUE_OUTBOUND: f64 = 0.20;
pub const WEIGHT_ZERO_PUBLICATIONS: f64 = 0.15;
pub const WEIGHT_ZERO_WITNESS: f64 = 0.15;
pub const WEIGHT_BALANCE_VOLATILITY: f64 = 0.15;
pub const WEIGHT_VOLUME_STAKE_RATIO: f64 = 0.15;

/// Thresholds for individual signals.
pub const UNIQUE_COUNTERPARTY_THRESHOLD: u64 = 100;
pub const BALANCE_VOLATILITY_THRESHOLD: f64 = 0.50; // >50% balance swing in 30d
pub const VOLUME_STAKE_RATIO_THRESHOLD: f64 = 10.0;

// ── Fixed-point classification gate (consensus determinism) ──────────────────
// `reclassify` runs inside `apply_op` on EVERY node, so the classification
// decision mutates replicated state (`confirmed_exchanges`, which gates transfer
// accept/reject). The f64 score-sum-vs-0.60 and the `volume as f64 / staked as
// f64` ratio are non-portable, so the consensus gate uses integer "points" and
// an integer volume/stake predicate instead. See internal design notes.

/// Volume/stake ratio threshold as an integer (volume > 10·staked).
pub const VOLUME_STAKE_RATIO_THRESHOLD_INT: u128 = 10;
/// Per-signal weights as integer points (f64 weights × 100).
pub const PTS_UNIQUE_INBOUND: u32 = 20;
pub const PTS_UNIQUE_OUTBOUND: u32 = 20;
pub const PTS_ZERO_PUBLICATIONS: u32 = 15;
pub const PTS_ZERO_WITNESS: u32 = 15;
pub const PTS_BALANCE_VOLATILITY: u32 = 15;
pub const PTS_VOLUME_STAKE_RATIO: u32 = 15;
/// Classification threshold in points (0.60 × 100).
pub const EXCHANGE_CLASSIFICATION_THRESHOLD_PTS: u32 = 60;

/// Transfer velocity multiplier for classified exchanges.
pub const EXCHANGE_VELOCITY_MULTIPLIER: f64 = 0.50;
/// Circuit breaker weight multiplier for exchanges (2x sensitivity).
pub const EXCHANGE_CIRCUIT_BREAKER_WEIGHT: f64 = 2.0;

// ─── Behavioral Signals ────────────────────────────────────────────────────

/// Raw behavioral signals for an identity over a 30-day window.
#[derive(Debug, Clone, Default)]
pub struct ExchangeSignals {
    /// Number of unique inbound transfer sources in 30 days.
    pub unique_inbound_30d: u64,
    /// Number of unique outbound transfer destinations in 30 days.
    pub unique_outbound_30d: u64,
    /// Whether this identity has published any non-ledger records.
    pub has_publications: bool,
    /// Whether this identity has performed any witness attestations.
    pub has_witness_activity: bool,
    /// Balance volatility: max_balance / min_balance ratio in 30 days.
    /// Expressed as `(max - min) / max`. 0 = stable, 1 = extreme.
    pub balance_volatility: f64,
    /// Transfer volume / stake ratio (0 if no stake).
    pub volume_stake_ratio: f64,
}

/// Compute the exchange classification score from behavioral signals.
///
/// Returns a score in [0.0, 1.0]. Score >= EXCHANGE_CLASSIFICATION_THRESHOLD
/// means the identity behaves like an exchange.
pub fn compute_exchange_score(signals: &ExchangeSignals) -> f64 {
    let mut score = 0.0;

    if signals.unique_inbound_30d > UNIQUE_COUNTERPARTY_THRESHOLD {
        score += WEIGHT_UNIQUE_INBOUND;
    }
    if signals.unique_outbound_30d > UNIQUE_COUNTERPARTY_THRESHOLD {
        score += WEIGHT_UNIQUE_OUTBOUND;
    }
    if !signals.has_publications {
        score += WEIGHT_ZERO_PUBLICATIONS;
    }
    if !signals.has_witness_activity {
        score += WEIGHT_ZERO_WITNESS;
    }
    if signals.balance_volatility > BALANCE_VOLATILITY_THRESHOLD {
        score += WEIGHT_BALANCE_VOLATILITY;
    }
    if signals.volume_stake_ratio > VOLUME_STAKE_RATIO_THRESHOLD {
        score += WEIGHT_VOLUME_STAKE_RATIO;
    }

    score
}

/// Integer "points" twin of [`compute_exchange_score`] (each f64 weight × 100),
/// used by the consensus classification gate so the accept/reject decision is
/// bit-identical across architectures. The volume/stake signal is compared via
/// an exact integer predicate upstream in `build_signals`, so on the replicated
/// apply path every input to this function is integer- or bool-valued.
pub fn compute_exchange_score_pts(signals: &ExchangeSignals) -> u32 {
    let mut pts = 0u32;
    if signals.unique_inbound_30d > UNIQUE_COUNTERPARTY_THRESHOLD {
        pts += PTS_UNIQUE_INBOUND;
    }
    if signals.unique_outbound_30d > UNIQUE_COUNTERPARTY_THRESHOLD {
        pts += PTS_UNIQUE_OUTBOUND;
    }
    if !signals.has_publications {
        pts += PTS_ZERO_PUBLICATIONS;
    }
    if !signals.has_witness_activity {
        pts += PTS_ZERO_WITNESS;
    }
    if signals.balance_volatility > BALANCE_VOLATILITY_THRESHOLD {
        pts += PTS_BALANCE_VOLATILITY;
    }
    if signals.volume_stake_ratio > VOLUME_STAKE_RATIO_THRESHOLD {
        pts += PTS_VOLUME_STAKE_RATIO;
    }
    pts
}

/// Whether an identity is classified as an exchange (integer consensus gate).
pub fn is_exchange(signals: &ExchangeSignals) -> bool {
    compute_exchange_score_pts(signals) >= EXCHANGE_CLASSIFICATION_THRESHOLD_PTS
}

// ─── Restrictions ──────────────────────────────────────────────────────────

/// Restrictions applied to exchange-classified identities.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExchangeRestrictions {
    /// Transfer velocity multiplier (0.5 = 50% of normal).
    pub velocity_multiplier: f64,
    /// Governance voting weight (0 = no voting power).
    pub governance_weight: f64,
    /// Whether this identity can witness records.
    pub witness_eligible: bool,
    /// Circuit breaker contribution weight (2x = more sensitive).
    pub circuit_breaker_weight: f64,
    /// Stake reward multiplier (0 = no rewards).
    pub stake_reward_multiplier: f64,
}

impl ExchangeRestrictions {
    /// Normal restrictions (not an exchange).
    pub fn normal() -> Self {
        Self {
            velocity_multiplier: 1.0,
            governance_weight: 1.0,
            witness_eligible: true,
            circuit_breaker_weight: 1.0,
            stake_reward_multiplier: 1.0,
        }
    }

    /// Exchange restrictions.
    pub fn exchange() -> Self {
        Self {
            velocity_multiplier: EXCHANGE_VELOCITY_MULTIPLIER,
            governance_weight: 0.0,
            witness_eligible: false,
            circuit_breaker_weight: EXCHANGE_CIRCUIT_BREAKER_WEIGHT,
            stake_reward_multiplier: 0.0,
        }
    }

    /// Get restrictions based on exchange classification.
    pub fn for_identity(signals: &ExchangeSignals) -> Self {
        if is_exchange(signals) {
            Self::exchange()
        } else {
            Self::normal()
        }
    }
}

// ─── State ─────────────────────────────────────────────────────────────────

/// Per-identity behavioral signal accumulators (persisted, bounded, monotone).
///
/// The classification signals are **all-time** (not a 30-day window — the
/// `*_30d` signal names are historical), so the state only ever grows. To keep
/// it bounded (SCALE rule) and deterministic across a snapshot bootstrap (the
/// determinism fix — internal design notes, Track C), each
/// unique-counterparty set is capped at `THRESHOLD + 1` entries, then **dropped
/// and latched**: the only consumer is the `count > THRESHOLD` gate, so the
/// exact count above the threshold is irrelevant. Per-identity state is
/// therefore O(THRESHOLD) before the latch and O(1) after, and the persisted
/// snapshot size is independent of transfer history. The whole entry is removed
/// once the identity is confirmed (a confirmed classification is itself latched).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct IdentitySignals {
    /// Unique inbound counterparties, capped at `THRESHOLD + 1`. Emptied when
    /// `inbound_over` latches.
    #[serde(default)]
    counterparties_in: HashSet<String>,
    /// Unique outbound counterparties, capped at `THRESHOLD + 1`.
    #[serde(default)]
    counterparties_out: HashSet<String>,
    /// Latch: inbound unique counterparties crossed `THRESHOLD` (set dropped).
    #[serde(default)]
    inbound_over: bool,
    /// Latch: outbound unique counterparties crossed `THRESHOLD` (set dropped).
    #[serde(default)]
    outbound_over: bool,
    /// All-time transfer volume (credited to both sender and recipient).
    #[serde(default)]
    volume: u64,
    /// Has published a non-ledger record.
    #[serde(default)]
    has_published: bool,
    /// Has performed witness activity.
    #[serde(default)]
    has_witnessed: bool,
}

impl IdentitySignals {
    /// Add an inbound counterparty, bounding the set at `THRESHOLD + 1` then
    /// dropping it and latching `inbound_over` (idempotent once latched).
    fn add_inbound(&mut self, from: &str) {
        if self.inbound_over {
            return;
        }
        self.counterparties_in.insert(from.to_string());
        if self.counterparties_in.len() > UNIQUE_COUNTERPARTY_THRESHOLD as usize {
            self.inbound_over = true;
            self.counterparties_in = HashSet::new();
        }
    }

    /// Add an outbound counterparty (symmetric to [`add_inbound`]).
    fn add_outbound(&mut self, to: &str) {
        if self.outbound_over {
            return;
        }
        self.counterparties_out.insert(to.to_string());
        if self.counterparties_out.len() > UNIQUE_COUNTERPARTY_THRESHOLD as usize {
            self.outbound_over = true;
            self.counterparties_out = HashSet::new();
        }
    }

    /// Inbound unique-counterparty count as seen by the classification gate
    /// (`THRESHOLD + 1` once latched — any value `> THRESHOLD` is equivalent).
    fn inbound_count(&self) -> u64 {
        if self.inbound_over {
            UNIQUE_COUNTERPARTY_THRESHOLD + 1
        } else {
            self.counterparties_in.len() as u64
        }
    }

    /// Outbound unique-counterparty count as seen by the classification gate.
    fn outbound_count(&self) -> u64 {
        if self.outbound_over {
            UNIQUE_COUNTERPARTY_THRESHOLD + 1
        } else {
            self.counterparties_out.len() as u64
        }
    }
}

/// Tracks exchange classification state for identities.
///
/// **Persisted + monotone (Track C, internal design notes).**
/// `classifications` / `confirmed_exchanges` / `tracked` all survive a state
/// snapshot (the `LedgerState.exchange_classifier` field is `#[serde(default)]`,
/// was `#[serde(skip)]`), and classification is **one-way**: once an identity is
/// confirmed an exchange it stays confirmed — there is no implicit
/// de-classification on `reclassify`. That guarantees a since-genesis node and a
/// snapshot-bootstrapped node always agree on `is_classified`, the only
/// classifier output read on the consensus apply path (prediction-reward
/// multiplier, idle_decay gating, governance/witness rejects).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ExchangeClassifier {
    /// Classified identities with their latest score (display / RPC).
    pub classifications: HashMap<String, f64>,
    /// Identities confirmed as exchanges (consensus gate; monotone).
    pub confirmed_exchanges: HashSet<String>,
    /// Per-identity bounded behavioral accumulators. An entry is dropped once
    /// the identity is confirmed (latched). Absent ⇒ no activity tracked yet.
    #[serde(default)]
    tracked: HashMap<String, IdentitySignals>,
}

impl ExchangeClassifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a transfer between two identities. Updates counterparty tracking
    /// and volume for both sender and recipient. A side already confirmed an
    /// exchange is skipped — its classification is latched, so its accumulators
    /// are inert (and were dropped at confirmation).
    pub fn record_transfer(&mut self, from: &str, to: &str, amount: u64) {
        if !self.confirmed_exchanges.contains(from) {
            let s = self.tracked.entry(from.to_string()).or_default();
            s.add_outbound(to);
            s.volume = s.volume.saturating_add(amount);
        }
        if !self.confirmed_exchanges.contains(to) {
            let s = self.tracked.entry(to.to_string()).or_default();
            s.add_inbound(from);
            s.volume = s.volume.saturating_add(amount);
        }
    }

    /// Mark an identity as having published a non-ledger record.
    pub fn record_publication(&mut self, identity: &str) {
        if self.confirmed_exchanges.contains(identity) {
            return;
        }
        self.tracked.entry(identity.to_string()).or_default().has_published = true;
    }

    /// Mark an identity as having performed witness activity.
    pub fn record_witness_activity(&mut self, identity: &str) {
        if self.confirmed_exchanges.contains(identity) {
            return;
        }
        self.tracked.entry(identity.to_string()).or_default().has_witnessed = true;
    }

    /// Build signals for an identity from tracked state.
    /// `staked_amount` should be the identity's total active stake.
    pub fn build_signals(&self, identity: &str, staked_amount: u64) -> ExchangeSignals {
        let s = self.tracked.get(identity);
        let inbound = s.map_or(0, |s| s.inbound_count());
        let outbound = s.map_or(0, |s| s.outbound_count());
        let volume = s.map_or(0, |s| s.volume);
        // Deterministic volume/stake signal: the only consumer is the
        // `> VOLUME_STAKE_RATIO_THRESHOLD` gate, so reproduce that predicate
        // exactly in integer (`volume > 10·staked`) and store an exact f64
        // sentinel — never the non-portable `volume as f64 / staked as f64`.
        let vol_stake = if staked_amount > 0 {
            if (volume as u128)
                > VOLUME_STAKE_RATIO_THRESHOLD_INT.saturating_mul(staked_amount as u128)
            {
                VOLUME_STAKE_RATIO_THRESHOLD + 1.0
            } else {
                0.0
            }
        } else if volume > 0 {
            // No stake but has volume — effectively infinite ratio, over threshold.
            VOLUME_STAKE_RATIO_THRESHOLD + 1.0
        } else {
            0.0
        };

        ExchangeSignals {
            unique_inbound_30d: inbound,
            unique_outbound_30d: outbound,
            has_publications: s.is_some_and(|s| s.has_published),
            has_witness_activity: s.is_some_and(|s| s.has_witnessed),
            // Balance volatility requires time-series data we don't track here.
            // Defaults to 0 (not volatile) — conservative (harder to classify).
            balance_volatility: 0.0,
            volume_stake_ratio: vol_stake,
        }
    }

    /// Reclassify an identity based on current tracked signals. **One-way:** a
    /// confirmed exchange stays confirmed (returns its latched score) — never
    /// recomputes off (possibly empty, post-bootstrap) signals.
    pub fn reclassify(&mut self, identity: &str, staked_amount: u64) -> f64 {
        if self.confirmed_exchanges.contains(identity) {
            return self.classifications.get(identity).copied().unwrap_or(1.0);
        }
        let signals = self.build_signals(identity, staked_amount);
        self.classify(identity, &signals)
    }

    /// Update classification for an identity from explicit signals.
    ///
    /// **Monotone latch (Track C):** crossing the threshold confirms the
    /// identity and drops its now-inert per-identity tracking; a sub-threshold
    /// score NEVER removes an existing confirmation. Implicit de-classification
    /// was the snapshot-fork vector (a bootstrapped node with empty signals
    /// re-ran this on full history and un-classified everyone) and is
    /// deliberately gone — explicit de-classification, if ever needed, must be a
    /// sealed record.
    pub fn classify(&mut self, identity: &str, signals: &ExchangeSignals) -> f64 {
        // Store the f64 score for display/RPC, but gate replicated state on the
        // integer points so `confirmed_exchanges` is identical on every node.
        let score = compute_exchange_score(signals);
        self.classifications.insert(identity.to_string(), score);
        if compute_exchange_score_pts(signals) >= EXCHANGE_CLASSIFICATION_THRESHOLD_PTS {
            self.confirmed_exchanges.insert(identity.to_string());
            // Confirmed → drop the per-identity accumulators (inert once latched).
            self.tracked.remove(identity);
        }
        score
    }

    /// Check if an identity is classified as an exchange.
    pub fn is_classified(&self, identity: &str) -> bool {
        self.confirmed_exchanges.contains(identity)
    }

    /// Return all currently classified exchange identity hashes.
    pub fn classified_identities(&self) -> Vec<String> {
        self.confirmed_exchanges.iter().cloned().collect()
    }

    /// Get the exchange score for an identity (None if never classified).
    pub fn score(&self, identity: &str) -> Option<f64> {
        self.classifications.get(identity).copied()
    }

    /// Get restrictions for an identity.
    pub fn restrictions(&self, identity: &str) -> ExchangeRestrictions {
        if self.is_classified(identity) {
            ExchangeRestrictions::exchange()
        } else {
            ExchangeRestrictions::normal()
        }
    }

    /// Number of classified exchanges.
    pub fn exchange_count(&self) -> usize {
        self.confirmed_exchanges.len()
    }

    /// All classified exchange identities.
    pub fn exchanges(&self) -> &HashSet<String> {
        &self.confirmed_exchanges
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange_signals() -> ExchangeSignals {
        ExchangeSignals {
            unique_inbound_30d: 500,
            unique_outbound_30d: 500,
            has_publications: false,
            has_witness_activity: false,
            balance_volatility: 0.80,
            volume_stake_ratio: 25.0,
        }
    }

    fn normal_signals() -> ExchangeSignals {
        ExchangeSignals {
            unique_inbound_30d: 5,
            unique_outbound_30d: 3,
            has_publications: true,
            has_witness_activity: true,
            balance_volatility: 0.10,
            volume_stake_ratio: 0.5,
        }
    }

    #[test]
    fn test_exchange_score_full() {
        let signals = exchange_signals();
        let score = compute_exchange_score(&signals);
        assert_eq!(score, 1.0); // All 6 signals fire
    }

    #[test]
    fn test_normal_score() {
        let signals = normal_signals();
        let score = compute_exchange_score(&signals);
        assert_eq!(score, 0.0); // No signals fire
    }

    #[test]
    fn test_partial_score() {
        let signals = ExchangeSignals {
            unique_inbound_30d: 200,
            unique_outbound_30d: 200,
            has_publications: true,
            has_witness_activity: true,
            balance_volatility: 0.10,
            volume_stake_ratio: 0.5,
        };
        let score = compute_exchange_score(&signals);
        // Only inbound + outbound fire = 0.20 + 0.20 = 0.40
        assert!((score - 0.40).abs() < 0.001);
        assert!(!is_exchange(&signals)); // Below threshold
    }

    #[test]
    fn test_threshold_boundary() {
        // 4 of 6 signals = 0.65 or 0.70 depending on which
        let signals = ExchangeSignals {
            unique_inbound_30d: 200,
            unique_outbound_30d: 200,
            has_publications: false,
            has_witness_activity: false,
            balance_volatility: 0.10,
            volume_stake_ratio: 0.5,
        };
        let score = compute_exchange_score(&signals);
        // inbound (0.20) + outbound (0.20) + no_pub (0.15) + no_witness (0.15) = 0.70
        assert!((score - 0.70).abs() < 0.001);
        assert!(is_exchange(&signals)); // Above 0.60 threshold
    }

    #[test]
    fn test_restrictions_exchange() {
        let r = ExchangeRestrictions::exchange();
        assert_eq!(r.velocity_multiplier, 0.50);
        assert_eq!(r.governance_weight, 0.0);
        assert!(!r.witness_eligible);
        assert_eq!(r.circuit_breaker_weight, 2.0);
        assert_eq!(r.stake_reward_multiplier, 0.0);
    }

    #[test]
    fn test_restrictions_normal() {
        let r = ExchangeRestrictions::normal();
        assert_eq!(r.velocity_multiplier, 1.0);
        assert_eq!(r.governance_weight, 1.0);
        assert!(r.witness_eligible);
    }

    #[test]
    fn test_classifier_classify() {
        let mut classifier = ExchangeClassifier::new();
        let score = classifier.classify("exchange_1", &exchange_signals());
        assert_eq!(score, 1.0);
        assert!(classifier.is_classified("exchange_1"));
        assert_eq!(classifier.exchange_count(), 1);
    }

    #[test]
    fn test_classifier_reclassify_is_monotone() {
        let mut classifier = ExchangeClassifier::new();
        classifier.classify("node_1", &exchange_signals());
        assert!(classifier.is_classified("node_1"));

        // Monotone latch (Track C, internal design notes): a later
        // sub-threshold score does NOT de-classify. Implicit de-classification was
        // the snapshot-fork vector (a bootstrapped node with empty signals re-ran
        // classify on full history and un-classified everyone) and is deliberately
        // gone — once an exchange, always an exchange.
        classifier.classify("node_1", &normal_signals());
        assert!(classifier.is_classified("node_1"), "classification must be one-way");
        assert_eq!(classifier.exchange_count(), 1);
    }

    #[test]
    fn test_classifier_restrictions() {
        let mut classifier = ExchangeClassifier::new();
        classifier.classify("exchange", &exchange_signals());
        classifier.classify("normal", &normal_signals());

        let r1 = classifier.restrictions("exchange");
        assert_eq!(r1.governance_weight, 0.0);

        let r2 = classifier.restrictions("normal");
        assert_eq!(r2.governance_weight, 1.0);
    }

    #[test]
    fn test_weights_sum_to_one() {
        let total = WEIGHT_UNIQUE_INBOUND + WEIGHT_UNIQUE_OUTBOUND
            + WEIGHT_ZERO_PUBLICATIONS + WEIGHT_ZERO_WITNESS
            + WEIGHT_BALANCE_VOLATILITY + WEIGHT_VOLUME_STAKE_RATIO;
        assert!((total - 1.0).abs() < 0.001, "weights must sum to 1.0, got {total}");
    }

    #[test]
    fn test_record_transfer_tracks_counterparties() {
        let mut c = ExchangeClassifier::new();
        c.record_transfer("alice", "bob", 1000);
        c.record_transfer("alice", "charlie", 2000);
        c.record_transfer("dave", "bob", 500);

        let alice_signals = c.build_signals("alice", 0);
        assert_eq!(alice_signals.unique_outbound_30d, 2); // bob, charlie
        assert_eq!(alice_signals.unique_inbound_30d, 0);

        let bob_signals = c.build_signals("bob", 0);
        assert_eq!(bob_signals.unique_inbound_30d, 2); // alice, dave
        assert_eq!(bob_signals.unique_outbound_30d, 0);
    }

    #[test]
    fn test_record_transfer_deduplicates() {
        let mut c = ExchangeClassifier::new();
        // Same pair 10 times = still 1 unique counterparty
        for _ in 0..10 {
            c.record_transfer("alice", "bob", 100);
        }
        let signals = c.build_signals("alice", 0);
        assert_eq!(signals.unique_outbound_30d, 1);
    }

    #[test]
    fn test_volume_stake_ratio_no_stake() {
        let mut c = ExchangeClassifier::new();
        c.record_transfer("alice", "bob", 1000);
        let signals = c.build_signals("alice", 0); // no stake
        // Should be > threshold (infinite ratio capped)
        assert!(signals.volume_stake_ratio > VOLUME_STAKE_RATIO_THRESHOLD);
    }

    #[test]
    fn test_volume_stake_ratio_with_stake() {
        // build_signals now stores a deterministic below/above-threshold sentinel
        // (integer predicate `volume > 10·staked`), not the non-portable precise
        // f64 ratio — the only consumer is the `> THRESHOLD` classification gate.
        let mut c = ExchangeClassifier::new();
        c.record_transfer("alice", "bob", 500);
        let below = c.build_signals("alice", 1000); // 500 !> 10·1000 → below
        assert!(below.volume_stake_ratio <= VOLUME_STAKE_RATIO_THRESHOLD);
        // A volume exceeding 10× stake is flagged above threshold.
        let mut c2 = ExchangeClassifier::new();
        c2.record_transfer("ex", "bob", 20_000); // 20000 > 10·1000
        let above = c2.build_signals("ex", 1000);
        assert!(above.volume_stake_ratio > VOLUME_STAKE_RATIO_THRESHOLD);
    }

    #[test]
    fn exchange_volume_stake_gate_is_exact_above_2pow53() {
        // 10·staked = 1e16 > 2^53, where `volume as f64 / staked as f64` could
        // round either side of 10.0. The integer predicate lands on the exact
        // boundary: volume == 10·staked is NOT over threshold; +1 is.
        let staked = 1_000_000_000_000_000u64; // 1e15
        let at_boundary = staked.saturating_mul(10); // 1e16 > 2^53
        let mut c = ExchangeClassifier::new();
        c.record_transfer("ex", "dst", at_boundary);
        assert!(c.build_signals("ex", staked).volume_stake_ratio <= VOLUME_STAKE_RATIO_THRESHOLD);
        let mut c2 = ExchangeClassifier::new();
        c2.record_transfer("ex", "dst", at_boundary.saturating_add(1));
        assert!(c2.build_signals("ex", staked).volume_stake_ratio > VOLUME_STAKE_RATIO_THRESHOLD);
    }

    #[test]
    fn test_publication_and_witness_flags() {
        let mut c = ExchangeClassifier::new();
        assert!(!c.build_signals("alice", 0).has_publications);
        assert!(!c.build_signals("alice", 0).has_witness_activity);

        c.record_publication("alice");
        assert!(c.build_signals("alice", 0).has_publications);

        c.record_witness_activity("alice");
        assert!(c.build_signals("alice", 0).has_witness_activity);
    }

    #[test]
    fn test_reclassify_from_tracked_signals() {
        let mut c = ExchangeClassifier::new();
        // Build up exchange-like behavior: >100 unique counterparties, no pub, no witness
        for i in 0..150 {
            c.record_transfer("suspect", &format!("user_{i}"), 100);
            c.record_transfer(&format!("depositor_{i}"), "suspect", 100);
        }
        let score = c.reclassify("suspect", 0);
        // 4 signals fire: inbound>100, outbound>100, no_pub, no_witness = 0.70
        // Plus volume_stake_ratio (no stake, has volume) = +0.15 = 0.85
        assert!(score >= EXCHANGE_CLASSIFICATION_THRESHOLD, "score={score}");
        assert!(c.is_classified("suspect"));
    }

    #[test]
    fn test_reclassify_normal_user() {
        let mut c = ExchangeClassifier::new();
        // Normal user: few counterparties, publishes, witnesses
        for i in 0..5 {
            c.record_transfer("user", &format!("peer_{i}"), 100);
        }
        c.record_publication("user");
        c.record_witness_activity("user");
        let score = c.reclassify("user", 10000);
        assert!(score < EXCHANGE_CLASSIFICATION_THRESHOLD, "score={score}");
        assert!(!c.is_classified("user"));
    }

    // ── exchange classification tests (economics §13.7) ────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_classification_threshold_constants_strict_pin_with_valid_ranges() {
        assert_eq!(EXCHANGE_CLASSIFICATION_THRESHOLD, 0.60);
        assert_eq!(UNIQUE_COUNTERPARTY_THRESHOLD, 100);
        assert_eq!(BALANCE_VOLATILITY_THRESHOLD, 0.50);
        assert_eq!(VOLUME_STAKE_RATIO_THRESHOLD, 10.0);
        // Each in valid range:
        assert!(EXCHANGE_CLASSIFICATION_THRESHOLD > 0.0 && EXCHANGE_CLASSIFICATION_THRESHOLD < 1.0);
        assert!(BALANCE_VOLATILITY_THRESHOLD > 0.0 && BALANCE_VOLATILITY_THRESHOLD < 1.0);
        assert!(UNIQUE_COUNTERPARTY_THRESHOLD > 0);
        assert!(VOLUME_STAKE_RATIO_THRESHOLD > 1.0, "exchange volume should be >1x stake");
        // CLASSIFICATION_THRESHOLD > BALANCE_VOLATILITY (a single signal alone
        // shouldn't tip classification — needs at least 3 signals @ 0.20 or
        // 4 signals @ 0.15 to cross 0.60).
        assert!(EXCHANGE_CLASSIFICATION_THRESHOLD > BALANCE_VOLATILITY_THRESHOLD);
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_signal_weight_constants_individual_pin_with_0_20_0_15_split_structure() {
        // Two weights at 0.20 (highest signal: unique counterparties).
        assert_eq!(WEIGHT_UNIQUE_INBOUND, 0.20);
        assert_eq!(WEIGHT_UNIQUE_OUTBOUND, 0.20);
        // Four weights at 0.15.
        assert_eq!(WEIGHT_ZERO_PUBLICATIONS, 0.15);
        assert_eq!(WEIGHT_ZERO_WITNESS, 0.15);
        assert_eq!(WEIGHT_BALANCE_VOLATILITY, 0.15);
        assert_eq!(WEIGHT_VOLUME_STAKE_RATIO, 0.15);
        // Structural pins:
        // 2 × 0.20 = 0.40 (heavy signals)
        let heavy = WEIGHT_UNIQUE_INBOUND + WEIGHT_UNIQUE_OUTBOUND;
        assert!((heavy - 0.40).abs() < 1e-9);
        // 4 × 0.15 = 0.60 (light signals)
        let light = WEIGHT_ZERO_PUBLICATIONS + WEIGHT_ZERO_WITNESS
            + WEIGHT_BALANCE_VOLATILITY + WEIGHT_VOLUME_STAKE_RATIO;
        assert!((light - 0.60).abs() < 1e-9);
        // heavy + light == 1.0 (already pinned by test_weights_sum_to_one,
        // but pin per-class here so refactors can't shift weights between
        // classes without failing).
        assert!((heavy + light - 1.0).abs() < 1e-9);
        // Heavy weights > light weights (asymmetry pinned).
        assert!(WEIGHT_UNIQUE_INBOUND > WEIGHT_BALANCE_VOLATILITY);
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_velocity_circuit_breaker_constants_inverse_multiplier_invariant() {
        assert_eq!(EXCHANGE_VELOCITY_MULTIPLIER, 0.50);
        assert_eq!(EXCHANGE_CIRCUIT_BREAKER_WEIGHT, 2.0);
        // VELOCITY * CB_WEIGHT == 1.0 — structural invariant: throttling
        // exchange transfers by half AND doubling their circuit-breaker
        // weight is symmetric (slower flow + higher sensitivity = same total
        // "pressure" on the breaker as a normal-velocity normal-weight identity).
        assert!((EXCHANGE_VELOCITY_MULTIPLIER * EXCHANGE_CIRCUIT_BREAKER_WEIGHT - 1.0).abs() < 1e-12);
        // VELOCITY < 1.0 (throttled), CB_WEIGHT > 1.0 (amplified).
        assert!(EXCHANGE_VELOCITY_MULTIPLIER < 1.0);
        assert!(EXCHANGE_CIRCUIT_BREAKER_WEIGHT > 1.0);
        // VELOCITY is exactly half (50% reduction).
        assert!((EXCHANGE_VELOCITY_MULTIPLIER - 0.5).abs() < 1e-12);
        // CB_WEIGHT is exactly double.
        assert!((EXCHANGE_CIRCUIT_BREAKER_WEIGHT - 2.0).abs() < 1e-12);
    }

    #[test]
    fn batch_b_exchange_restrictions_normal_5_field_completeness_with_direction_delta() {
        let n = ExchangeRestrictions::normal();
        let e = ExchangeRestrictions::exchange();
        // Normal: all 5 fields pinned (test_restrictions_normal only checks 3 — pin 2 more).
        assert_eq!(n.velocity_multiplier, 1.0);
        assert_eq!(n.governance_weight, 1.0);
        assert!(n.witness_eligible);
        assert_eq!(n.circuit_breaker_weight, 1.0);
        assert_eq!(n.stake_reward_multiplier, 1.0);
        // Direction delta: every field changes in correct direction normal → exchange.
        // 4 fields DECREASE (velocity, governance, witness_eligibility, stake_reward).
        assert!(e.velocity_multiplier < n.velocity_multiplier);
        assert!(e.governance_weight < n.governance_weight);
        assert!(!e.witness_eligible && n.witness_eligible);
        assert!(e.stake_reward_multiplier < n.stake_reward_multiplier);
        // 1 field INCREASES (circuit_breaker_weight = more sensitivity).
        assert!(e.circuit_breaker_weight > n.circuit_breaker_weight);
        // 3 fields are absolute zeros in exchange (no governance, no witness, no stake rewards).
        assert_eq!(e.governance_weight, 0.0);
        assert!(!e.witness_eligible);
        assert_eq!(e.stake_reward_multiplier, 0.0);
    }

    #[test]
    fn batch_b_exchange_classifier_new_equals_default_with_bidirectional_volume_tracking() {
        let c_new = ExchangeClassifier::new();
        let c_def = ExchangeClassifier::default();
        // Initial empty maps on both constructors.
        assert!(c_new.classifications.is_empty());
        assert!(c_def.classifications.is_empty());
        assert!(c_new.confirmed_exchanges.is_empty());
        assert!(c_def.confirmed_exchanges.is_empty());
        assert_eq!(c_new.exchange_count(), 0);
        // record_transfer credits BOTH sides of the transfer (sender + recipient
        // each see the volume in their tracked total) — pin this invariant.
        let mut c = ExchangeClassifier::new();
        c.record_transfer("alice", "bob", 1_000);
        let alice_sig = c.build_signals("alice", 0);
        let bob_sig = c.build_signals("bob", 0);
        // Alice sent to bob → outbound counterparty for alice, inbound for bob.
        assert_eq!(alice_sig.unique_outbound_30d, 1);
        assert_eq!(alice_sig.unique_inbound_30d, 0);
        assert_eq!(bob_sig.unique_inbound_30d, 1);
        assert_eq!(bob_sig.unique_outbound_30d, 0);
        // serde JSON round-trip: Track C persists the per-identity `tracked`
        // accumulators (was #[serde(skip)]) so the classifier survives a snapshot
        // bootstrap — the determinism fix. The state now SURVIVES the round-trip.
        let json = serde_json::to_string(&c).unwrap();
        let back: ExchangeClassifier = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tracked.len(), c.tracked.len());
        assert_eq!(
            back.build_signals("alice", 0).unique_outbound_30d,
            c.build_signals("alice", 0).unique_outbound_30d,
        );
        assert_eq!(back.build_signals("bob", 0).unique_inbound_30d, 1);
    }
}
