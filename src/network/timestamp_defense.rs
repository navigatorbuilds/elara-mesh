//! Timestamp Gaming Defense — reject records with manipulated timestamps.
//!
//! Validates that record timestamps are consistent with:
//! 1. Network arrival time (cannot be too far in the future).
//! 2. ITC (Interval Tree Clock) causal ordering.
//! 3. Per-zone consensus on acceptable time skew.
//!
//! Records with timestamps significantly ahead of the node's wall clock
//! are rejected outright. Records with timestamps that violate ITC ordering
//! (claiming to be "before" their causal predecessors) are flagged.

//!
//! Spec references:
//!   @spec Protocol §11.6

use std::collections::HashMap;
use crate::ZoneId;
use serde::{Serialize, Deserialize};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Maximum allowed future skew: records cannot claim a timestamp more than
/// this many seconds ahead of the receiving node's wall clock.
pub const MAX_FUTURE_SKEW_SECS: f64 = 300.0; // 5 minutes

/// Maximum allowed past skew: records claiming a timestamp far in the past
/// relative to their parents are suspicious (possible replay).
pub const MAX_PAST_SKEW_SECS: f64 = 86_400.0 * 30.0; // 30 days

/// Minimum timestamp (Unix epoch). Records before this are clearly invalid.
pub const MIN_VALID_TIMESTAMP: f64 = 1_700_000_000.0; // ~2023-11-14

/// Rate limit: max timestamp violations per identity before blocking.
/// Set higher to avoid cascading blocks from minor clock skew during sync bursts.
pub const MAX_VIOLATIONS_PER_IDENTITY: u64 = 20;

/// Violation decay window (seconds). Violations older than this are forgotten.
/// 10 minutes — enough to absorb sync bursts without hour-long blocks.
pub const VIOLATION_DECAY_SECS: f64 = 600.0; // 10 minutes

/// Maximum record age (seconds) for drift estimation. Records older than this
/// (e.g., arriving via gossip/sync backfill) are legitimate but must NOT update
/// the zone drift estimator — their large negative (record_ts - arrival_ts)
/// would poison the EMA, causing fresh transfers to be rejected as FutureTooFar.
pub const MAX_DRIFT_UPDATE_AGE_SECS: f64 = 60.0; // 1 minute — tighter to prevent gossip-delayed records from poisoning drift EMA

// ─── Types ─────────────────────────────────────────────────────────────────

/// Result of timestamp validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampVerdict {
    /// Timestamp is within acceptable bounds.
    Valid,
    /// Timestamp is too far in the future.
    FutureTooFar,
    /// Timestamp is before minimum valid epoch.
    BeforeEpoch,
    /// Timestamp is suspiciously far in the past relative to parent.
    PastTooFar,
    /// Record's timestamp violates ITC causal ordering (claims to be
    /// before a record it causally depends on).
    CausalViolation,
    /// Identity has exceeded violation rate limit.
    RateLimited,
}

impl TimestampVerdict {
    pub fn is_valid(&self) -> bool {
        *self == Self::Valid
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::FutureTooFar => "future_too_far",
            Self::BeforeEpoch => "before_epoch",
            Self::PastTooFar => "past_too_far",
            Self::CausalViolation => "causal_violation",
            Self::RateLimited => "rate_limited",
        }
    }
}

/// Per-zone time consensus tracking.
#[derive(Debug, Clone, Default)]
pub struct ZoneTimeConsensus {
    /// Latest accepted timestamp per zone.
    latest_timestamps: HashMap<ZoneId, f64>,
    /// Average timestamp drift per zone (rolling).
    zone_drift: HashMap<ZoneId, f64>,
}

impl ZoneTimeConsensus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an accepted timestamp for a zone.
    pub fn record(&mut self, zone: &ZoneId, timestamp: f64) {
        let entry = self.latest_timestamps.entry(zone.clone()).or_insert(0.0);
        if timestamp > *entry {
            *entry = timestamp;
        }
    }

    /// Get the latest accepted timestamp for a zone.
    pub fn latest(&self, zone: &ZoneId) -> Option<f64> {
        self.latest_timestamps.get(zone).copied()
    }

    /// Update zone drift estimate.
    ///
    /// Only updates from records whose timestamp is within [`MAX_DRIFT_UPDATE_AGE_SECS`]
    /// of arrival time. Old records arriving via gossip backfill have a large negative
    /// `(record_ts - arrival_ts)` that would poison the EMA and cause fresh transfers
    /// to be rejected as `FutureTooFar`.
    pub fn update_drift(&mut self, zone: &ZoneId, record_ts: f64, arrival_ts: f64) {
        let age = arrival_ts - record_ts;
        if age > MAX_DRIFT_UPDATE_AGE_SECS {
            // Old record — skip drift update to avoid poisoning the estimator.
            return;
        }
        let drift = record_ts - arrival_ts;
        let current = self.zone_drift.entry(zone.clone()).or_insert(0.0);
        // Exponential moving average with alpha=0.1
        *current = *current * 0.9 + drift * 0.1;
    }

    /// Get estimated drift for a zone.
    pub fn drift(&self, zone: &ZoneId) -> f64 {
        self.zone_drift.get(zone).copied().unwrap_or(0.0)
    }
}

// ─── State ─────────────────────────────────────────────────────────────────

/// Serializable snapshot of timestamp violations for RocksDB persistence.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimestampViolationSnapshot {
    pub violations: HashMap<String, Vec<f64>>,
}

/// Tracks timestamp violations per identity for rate limiting.
///
/// Violations are persisted to RocksDB via periodic snapshots in the
/// memory_prune_loop. On startup, violations from the current decay window
/// are loaded so that rate limits survive restarts.
#[derive(Debug, Clone, Default)]
pub struct TimestampDefense {
    /// Per-identity violation records: (identity_hash → violation timestamps).
    violations: HashMap<String, Vec<f64>>,
    /// Per-zone time consensus.
    zone_consensus: ZoneTimeConsensus,
    /// Total records validated.
    total_validated: u64,
    /// Total records rejected.
    total_rejected: u64,
}

impl TimestampDefense {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate a record's timestamp.
    ///
    /// - `record_ts`: the record's claimed timestamp.
    /// - `arrival_ts`: when the node received this record (wall clock).
    /// - `parent_ts`: timestamp of the record's latest parent (if any).
    /// - `creator`: identity hash of the creator.
    /// - `zone`: the zone this record belongs to.
    pub fn validate(
        &mut self,
        record_ts: f64,
        arrival_ts: f64,
        parent_ts: Option<f64>,
        creator: &str,
        zone: ZoneId,
    ) -> TimestampVerdict {
        self.total_validated += 1;

        // 1. Below minimum epoch
        if record_ts < MIN_VALID_TIMESTAMP {
            self.record_violation(creator, arrival_ts);
            self.total_rejected += 1;
            return TimestampVerdict::BeforeEpoch;
        }

        // 2. Too far in the future
        let zone_drift = self.zone_consensus.drift(&zone);
        let adjusted_skew = record_ts - arrival_ts - zone_drift;
        if adjusted_skew > MAX_FUTURE_SKEW_SECS {
            tracing::warn!(
                "timestamp_defense: FutureTooFar for {} — record_ts={:.3} arrival_ts={:.3} raw_skew={:.3} zone_drift={:.6} adjusted_skew={:.3} max={}",
                &creator[..creator.len().min(16)], record_ts, arrival_ts, record_ts - arrival_ts, zone_drift, adjusted_skew, MAX_FUTURE_SKEW_SECS,
            );
            self.record_violation(creator, arrival_ts);
            self.total_rejected += 1;
            return TimestampVerdict::FutureTooFar;
        }

        // 3. Causal violation: record claims to be before its parent
        if let Some(pts) = parent_ts {
            if record_ts < pts {
                self.record_violation(creator, arrival_ts);
                self.total_rejected += 1;
                return TimestampVerdict::CausalViolation;
            }

            // 4. Suspiciously far in the past relative to parent
            if pts - record_ts > MAX_PAST_SKEW_SECS {
                self.record_violation(creator, arrival_ts);
                self.total_rejected += 1;
                return TimestampVerdict::PastTooFar;
            }
        }

        // 5. Rate limit check
        if self.is_rate_limited(creator, arrival_ts) {
            self.total_rejected += 1;
            return TimestampVerdict::RateLimited;
        }

        // Valid — update zone consensus
        self.zone_consensus.record(&zone, record_ts);
        self.zone_consensus.update_drift(&zone, record_ts, arrival_ts);

        TimestampVerdict::Valid
    }

    /// Record a violation for an identity.
    fn record_violation(&mut self, creator: &str, now: f64) {
        self.violations
            .entry(creator.to_string())
            .or_default()
            .push(now);
    }

    /// Check if an identity has exceeded the violation rate limit.
    fn is_rate_limited(&self, creator: &str, now: f64) -> bool {
        let cutoff = now - VIOLATION_DECAY_SECS;
        self.violations
            .get(creator)
            .map(|violations| {
                violations.iter().filter(|&&t| t >= cutoff).count() as u64
                    >= MAX_VIOLATIONS_PER_IDENTITY
            })
            .unwrap_or(false)
    }

    /// Prune old violations. Returns number of identities removed.
    pub fn prune(&mut self, now: f64) -> usize {
        let before = self.violations.len();
        let cutoff = now - VIOLATION_DECAY_SECS;
        self.violations.retain(|_, violations| {
            violations.retain(|t| *t >= cutoff);
            !violations.is_empty()
        });
        before - self.violations.len()
    }

    /// Export violations for persistence. Only includes entries within the decay window.
    pub fn export_violations(&self) -> TimestampViolationSnapshot {
        TimestampViolationSnapshot {
            violations: self.violations.clone(),
        }
    }

    /// Import violations from a persisted snapshot. Prunes expired entries on load.
    pub fn import_violations(&mut self, snapshot: TimestampViolationSnapshot, now: f64) {
        let cutoff = now - VIOLATION_DECAY_SECS;
        for (identity, timestamps) in snapshot.violations {
            let valid: Vec<f64> = timestamps.into_iter().filter(|&t| t >= cutoff).collect();
            if !valid.is_empty() {
                self.violations.insert(identity, valid);
            }
        }
    }

    /// Number of identities with active violations.
    pub fn violator_count(&self) -> usize {
        self.violations.len()
    }

    pub fn total_validated(&self) -> u64 {
        self.total_validated
    }

    pub fn total_rejected(&self) -> u64 {
        self.total_rejected
    }

    /// Zone time consensus state.
    pub fn zone_consensus(&self) -> &ZoneTimeConsensus {
        &self.zone_consensus
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ZoneId;

    const NOW: f64 = 1_800_000_000.0;

    #[test]
    fn test_valid_timestamp() {
        let mut defense = TimestampDefense::new();
        let v = defense.validate(NOW, NOW, None, "alice", ZoneId::from_legacy(0));
        assert_eq!(v, TimestampVerdict::Valid);
    }

    #[test]
    fn test_future_too_far() {
        let mut defense = TimestampDefense::new();
        let future_ts = NOW + MAX_FUTURE_SKEW_SECS + 10.0;
        let v = defense.validate(future_ts, NOW, None, "alice", ZoneId::from_legacy(0));
        assert_eq!(v, TimestampVerdict::FutureTooFar);
    }

    #[test]
    fn test_before_epoch() {
        let mut defense = TimestampDefense::new();
        let v = defense.validate(1_000_000.0, NOW, None, "alice", ZoneId::from_legacy(0));
        assert_eq!(v, TimestampVerdict::BeforeEpoch);
    }

    #[test]
    fn test_causal_violation() {
        let mut defense = TimestampDefense::new();
        // Record claims timestamp before its parent
        let v = defense.validate(NOW - 100.0, NOW, Some(NOW), "alice", ZoneId::from_legacy(0));
        assert_eq!(v, TimestampVerdict::CausalViolation);
    }

    #[test]
    fn test_valid_with_parent() {
        let mut defense = TimestampDefense::new();
        // Record 10s after parent — valid
        let v = defense.validate(NOW, NOW, Some(NOW - 10.0), "alice", ZoneId::from_legacy(0));
        assert_eq!(v, TimestampVerdict::Valid);
    }

    #[test]
    fn test_rate_limiting() {
        let mut defense = TimestampDefense::new();
        // Generate violations — use large offset so all iterations exceed MAX_FUTURE_SKEW
        for i in 0..MAX_VIOLATIONS_PER_IDENTITY {
            let future_ts = NOW + MAX_FUTURE_SKEW_SECS + 1000.0;
            defense.validate(future_ts, NOW + i as f64, None, "mallory", ZoneId::from_legacy(0));
        }

        // Next valid record should be rate limited
        let v = defense.validate(NOW, NOW + 10.0, None, "mallory", ZoneId::from_legacy(0));
        assert_eq!(v, TimestampVerdict::RateLimited);
    }

    #[test]
    fn test_rate_limit_decay() {
        let mut defense = TimestampDefense::new();
        // Generate old violations — use large offset so all exceed threshold
        for i in 0..MAX_VIOLATIONS_PER_IDENTITY {
            let old = NOW - VIOLATION_DECAY_SECS - 100.0;
            let future_ts = old + MAX_FUTURE_SKEW_SECS + 1000.0;
            defense.validate(future_ts, old + i as f64, None, "mallory", ZoneId::from_legacy(0));
        }

        // After decay, should not be rate limited
        let v = defense.validate(NOW, NOW, None, "mallory", ZoneId::from_legacy(0));
        assert_eq!(v, TimestampVerdict::Valid);
    }

    #[test]
    fn test_zone_consensus_tracking() {
        let mut defense = TimestampDefense::new();
        defense.validate(NOW, NOW, None, "alice", ZoneId::from_legacy(5));
        defense.validate(NOW + 10.0, NOW + 10.0, None, "bob", ZoneId::from_legacy(5));

        assert_eq!(defense.zone_consensus().latest(&ZoneId::from_legacy(5)), Some(NOW + 10.0));
    }

    #[test]
    fn test_prune() {
        let mut defense = TimestampDefense::new();
        let future_ts = NOW + MAX_FUTURE_SKEW_SECS + 10.0;
        defense.validate(future_ts, NOW, None, "mallory", ZoneId::from_legacy(0));
        assert_eq!(defense.violator_count(), 1);

        defense.prune(NOW + VIOLATION_DECAY_SECS + 1.0);
        assert_eq!(defense.violator_count(), 0);
    }

    #[test]
    fn test_counters() {
        let mut defense = TimestampDefense::new();
        defense.validate(NOW, NOW, None, "alice", ZoneId::from_legacy(0)); // valid
        defense.validate(1_000.0, NOW, None, "bob", ZoneId::from_legacy(0)); // rejected

        assert_eq!(defense.total_validated(), 2);
        assert_eq!(defense.total_rejected(), 1);
    }

    /// Metric-semantics codification for the new
    /// `elara_timestamp_defense_*` gauge + counter set. Pins the
    /// operator-dashboard invariants:
    ///   * `violators_active` counts DISTINCT identities, not events —
    ///     5 rejections from one identity ≠ 5 violators.
    ///   * Multiple verdict gates (FutureTooFar / BeforeEpoch /
    ///     CausalViolation / PastTooFar) all funnel into the same
    ///     violator pool; rate-limit verdict bumps `_rejected_total`
    ///     without growing the violator pool (no recursive feedback —
    ///     a rate-limited identity can't inflate its own violator entry).
    ///   * `_validated_total` counts every record that ran the gate
    ///     including ones that returned `Valid`.
    ///   * `prune()` clears violators_active down without rolling back
    ///     either lifetime counter — operators MUST treat _total counters
    ///     as monotonic, gauge as instantaneous.
    #[test]
    fn ops_43_violator_count_pins_distinct_identity_residency_for_gauge() {
        let mut defense = TimestampDefense::new();
        let zone = || ZoneId::from_legacy(0);

        assert_eq!(defense.violator_count(), 0);
        assert_eq!(defense.total_validated(), 0);
        assert_eq!(defense.total_rejected(), 0);

        // (1) Five FutureTooFar rejects from ONE identity:
        //     violators_active = 1 (distinct), rejected_total = 5 (events).
        let future = NOW + MAX_FUTURE_SKEW_SECS + 100.0;
        for i in 0..5 {
            let v = defense.validate(future, NOW + i as f64, None, "mallory", zone());
            assert_eq!(v, TimestampVerdict::FutureTooFar);
        }
        assert_eq!(defense.violator_count(), 1,
            "5 events on 1 identity = 1 violator (gauge counts distinct keys, not events)");
        assert_eq!(defense.total_validated(), 5);
        assert_eq!(defense.total_rejected(), 5);

        // (2) Different identity, different verdict gate (BeforeEpoch).
        //     Every gate funnels into the same violator pool.
        let v = defense.validate(1_000.0, NOW, None, "alice", zone());
        assert_eq!(v, TimestampVerdict::BeforeEpoch);
        assert_eq!(defense.violator_count(), 2,
            "BeforeEpoch + FutureTooFar share the violator pool");

        // (3) Third identity, CausalViolation (parent newer than record).
        let v = defense.validate(NOW - 100.0, NOW, Some(NOW), "carol", zone());
        assert_eq!(v, TimestampVerdict::CausalViolation);
        assert_eq!(defense.violator_count(), 3);

        // (4) Push mallory past MAX_VIOLATIONS_PER_IDENTITY → next attempt
        //     returns RateLimited. RateLimited bumps `_rejected_total`
        //     but MUST NOT add a fresh violation entry — otherwise
        //     a rate-limited identity could inflate its own pool count.
        for i in 5..MAX_VIOLATIONS_PER_IDENTITY {
            defense.validate(future, NOW + i as f64, None, "mallory", zone());
        }
        let pre_rate_violators = defense.violator_count();
        let pre_rate_rejected = defense.total_rejected();
        let v = defense.validate(NOW, NOW, None, "mallory", zone());
        assert_eq!(v, TimestampVerdict::RateLimited,
            "after MAX_VIOLATIONS_PER_IDENTITY=20 violations, gate is closed");
        assert_eq!(defense.violator_count(), pre_rate_violators,
            "RateLimited verdict does not grow the violator pool (no self-inflation)");
        assert_eq!(defense.total_rejected(), pre_rate_rejected + 1,
            "RateLimited still bumps the lifetime rejected counter");

        // (5) prune() past the decay window clears violators but
        //     preserves the _total counters (monotonic semantics).
        //     Mallory's latest violation was at NOW + (MAX-1) so the
        //     prune cutoff must clear that timestamp too.
        let validated_before_prune = defense.total_validated();
        let rejected_before_prune = defense.total_rejected();
        let prune_now = NOW + MAX_VIOLATIONS_PER_IDENTITY as f64 + VIOLATION_DECAY_SECS + 1.0;
        let removed = defense.prune(prune_now);
        assert_eq!(removed, 3, "prune returns count of identities cleared");
        assert_eq!(defense.violator_count(), 0,
            "prune past decay window drains the gauge");
        assert_eq!(defense.total_validated(), validated_before_prune,
            "prune MUST NOT roll back the validated counter");
        assert_eq!(defense.total_rejected(), rejected_before_prune,
            "prune MUST NOT roll back the rejected counter");
    }

    #[test]
    fn test_verdict_strings() {
        assert_eq!(TimestampVerdict::Valid.as_str(), "valid");
        assert_eq!(TimestampVerdict::FutureTooFar.as_str(), "future_too_far");
        assert_eq!(TimestampVerdict::CausalViolation.as_str(), "causal_violation");
        assert!(TimestampVerdict::Valid.is_valid());
        assert!(!TimestampVerdict::FutureTooFar.is_valid());
    }

    #[test]
    fn test_slight_future_ok() {
        let mut defense = TimestampDefense::new();
        // 4 minutes ahead — within 5-minute window
        let v = defense.validate(NOW + 240.0, NOW, None, "alice", ZoneId::from_legacy(0));
        assert_eq!(v, TimestampVerdict::Valid);
    }

    #[test]
    fn test_old_gossip_records_do_not_poison_drift() {
        // Reproduces the drift poisoning bug: old records arriving via gossip
        // had large negative (record_ts - arrival_ts) that corrupted the EMA,
        // causing fresh transfers to be rejected as FutureTooFar.
        let mut defense = TimestampDefense::new();
        let zone = ZoneId::from_legacy(1);

        // Simulate 10 old records arriving via gossip — timestamps 2-4 hours old
        for i in 0..10 {
            let old_record_ts = NOW - 7200.0 - (i as f64 * 600.0); // 2-4 hours old
            defense.validate(old_record_ts, NOW, None, &format!("peer{i}"), zone.clone());
        }

        // Zone drift should still be near zero (old records clamped out)
        let drift = defense.zone_consensus().drift(&zone).abs();
        assert!(
            drift < 10.0,
            "drift should be near zero after old gossip records, got {drift}"
        );

        // Fresh transfer should NOT be rejected
        let v = defense.validate(NOW + 1.0, NOW + 1.0, None, "alice", zone.clone());
        assert_eq!(
            v,
            TimestampVerdict::Valid,
            "fresh transfer rejected after old gossip records poisoned drift"
        );
    }

    #[test]
    fn test_recent_records_still_update_drift() {
        // Records within the 60s window should still update drift normally.
        let mut defense = TimestampDefense::new();
        let zone = ZoneId::from_legacy(2);

        // Record from 30 seconds ago — within the 60s window
        let recent_ts = NOW - 30.0;
        defense.validate(recent_ts, NOW, None, "bob", zone.clone());

        // Drift should be updated (negative, since record is in the past)
        let drift = defense.zone_consensus().drift(&zone);
        assert!(
            drift < 0.0,
            "drift should be negative for a 30s-old record, got {drift}"
        );
    }

    #[test]
    fn test_export_import_violations() {
        let mut defense = TimestampDefense::new();
        let future_ts = NOW + MAX_FUTURE_SKEW_SECS + 10.0;

        // Generate some violations
        for i in 0..5 {
            defense.validate(future_ts, NOW + i as f64, None, "mallory", ZoneId::from_legacy(0));
        }
        defense.validate(future_ts, NOW, None, "eve", ZoneId::from_legacy(0));
        assert_eq!(defense.violator_count(), 2);

        // Export and import into fresh instance
        let snapshot = defense.export_violations();
        let mut defense2 = TimestampDefense::new();
        defense2.import_violations(snapshot, NOW + 1.0);
        assert_eq!(defense2.violator_count(), 2);

        // Verify rate limiting still works after import
        assert!(!defense2.is_rate_limited("mallory", NOW + 1.0));

        // Import with time past decay window — should discard all
        let snapshot2 = defense.export_violations();
        let mut defense3 = TimestampDefense::new();
        defense3.import_violations(snapshot2, NOW + VIOLATION_DECAY_SECS + 100.0);
        assert_eq!(defense3.violator_count(), 0);
    }

    #[test]
    fn test_export_import_serde_roundtrip() {
        let mut defense = TimestampDefense::new();
        let future_ts = NOW + MAX_FUTURE_SKEW_SECS + 10.0;
        defense.validate(future_ts, NOW, None, "mallory", ZoneId::from_legacy(0));

        let snapshot = defense.export_violations();
        let json = serde_json::to_vec(&snapshot).unwrap();
        let loaded: TimestampViolationSnapshot = serde_json::from_slice(&json).unwrap();
        assert_eq!(loaded.violations.len(), 1);
        assert!(loaded.violations.contains_key("mallory"));
    }

    #[test]
    fn test_prune_returns_count() {
        let mut defense = TimestampDefense::new();
        let future_ts = NOW + MAX_FUTURE_SKEW_SECS + 10.0;
        defense.validate(future_ts, NOW, None, "mallory", ZoneId::from_legacy(0));
        defense.validate(future_ts, NOW, None, "eve", ZoneId::from_legacy(0));
        assert_eq!(defense.violator_count(), 2);

        // Prune within window — nothing removed
        let pruned = defense.prune(NOW + 1.0);
        assert_eq!(pruned, 0);

        // Prune past window — both removed
        let pruned = defense.prune(NOW + VIOLATION_DECAY_SECS + 1.0);
        assert_eq!(pruned, 2);
    }

    #[test]
    fn test_drift_clamp_boundary() {
        // Record exactly at the 60s boundary: should still update drift.
        let mut defense = TimestampDefense::new();
        let zone = ZoneId::from_legacy(3);

        // Exactly 60s old — at the boundary, age == MAX_DRIFT_UPDATE_AGE_SECS
        // The check is `age > MAX_DRIFT_UPDATE_AGE_SECS` so exactly-at-boundary updates.
        let boundary_ts = NOW - MAX_DRIFT_UPDATE_AGE_SECS;
        defense.validate(boundary_ts, NOW, None, "carol", zone.clone());
        let drift = defense.zone_consensus().drift(&zone);
        assert!(
            drift != 0.0,
            "record at exactly 60s boundary should still update drift"
        );

        // 1 second past the boundary — should NOT update
        let mut defense2 = TimestampDefense::new();
        let past_boundary_ts = NOW - MAX_DRIFT_UPDATE_AGE_SECS - 1.0;
        defense2.validate(past_boundary_ts, NOW, None, "dave", zone.clone());
        let drift2 = defense2.zone_consensus().drift(&zone);
        assert!(
            drift2.abs() < f64::EPSILON,
            "record 1s past the 60s boundary should NOT update drift, got {drift2}"
        );
    }

    // ─── fixture-free axes ────────────────────────
    // Pins surface invariants not covered by the legacy tests above:
    //  (1) all 6 module constants strict-pin + cross-relations
    //  (2) TimestampVerdict 6-variant exhaustive shape (Copy/Eq/Debug/as_str/is_valid)
    //  (3) validate() dispatch order (BeforeEpoch -> FutureTooFar -> CausalViolation -> PastTooFar -> RateLimited -> Valid)
    //  (4) ZoneTimeConsensus latest() monotonic + drift EMA formula + boundary + zone independence
    //  (5) TimestampViolationSnapshot serde + export/import cutoff + prune cleanup matrix

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_timestamp_constants_strict_pin_and_cross_relations() {
        // Six module constants. Any drift here is chain-breaking — fresh
        // transfers acceptance window, replay-defense window, and
        // restart-safety persistence window all key off these numbers.
        // Strict equality so a refactor cannot silently relax acceptance.
        assert_eq!(MAX_FUTURE_SKEW_SECS, 300.0,
            "MAX_FUTURE_SKEW_SECS=300.0 (5 min) — wall-clock acceptance window");
        assert_eq!(MAX_PAST_SKEW_SECS, 86_400.0 * 30.0,
            "MAX_PAST_SKEW_SECS=30 days expressed as 86_400.0*30.0 (arithmetic form pin)");
        assert_eq!(MAX_PAST_SKEW_SECS, 2_592_000.0,
            "MAX_PAST_SKEW_SECS numerical form = 2_592_000.0 seconds");
        assert_eq!(MIN_VALID_TIMESTAMP, 1_700_000_000.0,
            "MIN_VALID_TIMESTAMP=1.7e9 (~2023-11-14) — pre-protocol records rejected");
        assert_eq!(MAX_VIOLATIONS_PER_IDENTITY, 20u64,
            "MAX_VIOLATIONS_PER_IDENTITY=20 u64 — rate-limit threshold");
        assert_eq!(VIOLATION_DECAY_SECS, 600.0,
            "VIOLATION_DECAY_SECS=600.0 (10 min) — sync-burst absorption window");
        assert_eq!(MAX_DRIFT_UPDATE_AGE_SECS, 60.0,
            "MAX_DRIFT_UPDATE_AGE_SECS=60.0 (1 min) — gossip-backfill drift-poison defense");

        // Type-pin: violation counter is u64 (not usize / not i64). Load-bearing
        // for >=-comparison against violations.len() cast to u64 in is_rate_limited.
        let _u64_check: u64 = MAX_VIOLATIONS_PER_IDENTITY;

        // Cross-relations between the timing windows.
        assert!(MAX_PAST_SKEW_SECS > MAX_FUTURE_SKEW_SECS,
            "past skew (30d) >> future skew (5m) — replay tolerance is asymmetric");
        let past_to_future_ratio = MAX_PAST_SKEW_SECS / MAX_FUTURE_SKEW_SECS;
        assert!((past_to_future_ratio - 8640.0).abs() < 1e-9,
            "past/future ratio = 30 days / 5 min = 8640 exact");

        // VIOLATION_DECAY_SECS > MAX_FUTURE_SKEW_SECS — load-bearing: a single
        // burst of future-skewed records gets a full decay-window of grace
        // before the next attempt counts toward a new rate-limit window.
        assert!(VIOLATION_DECAY_SECS > MAX_FUTURE_SKEW_SECS,
            "decay window (10m) > future-skew window (5m) — rate-limit gives 2x acceptance window of grace");
        assert_eq!(VIOLATION_DECAY_SECS / MAX_FUTURE_SKEW_SECS, 2.0,
            "decay/future ratio = 2.0 exact");

        // MAX_DRIFT_UPDATE_AGE_SECS < MAX_FUTURE_SKEW_SECS — tighter than acceptance
        // because drift-poisoning is a one-way-ratchet failure: once the EMA is
        // contaminated, fresh transfers fall outside the FutureTooFar gate.
        assert!(MAX_DRIFT_UPDATE_AGE_SECS < MAX_FUTURE_SKEW_SECS,
            "drift-update age (60s) < future-skew window (300s) — defense-in-depth");
        assert_eq!(MAX_FUTURE_SKEW_SECS / MAX_DRIFT_UPDATE_AGE_SECS, 5.0,
            "future/drift-update ratio = 5.0 exact");

        // All positive (sanity guard — a negative constant would invert semantics).
        assert!(MAX_FUTURE_SKEW_SECS > 0.0);
        assert!(MAX_PAST_SKEW_SECS > 0.0);
        assert!(MIN_VALID_TIMESTAMP > 0.0);
        assert!(MAX_VIOLATIONS_PER_IDENTITY > 0,
            "0-threshold would block legitimate retries");
        assert!(VIOLATION_DECAY_SECS > 0.0);
        assert!(MAX_DRIFT_UPDATE_AGE_SECS > 0.0);

        // MIN_VALID_TIMESTAMP < contemporary NOW — anti-bootstrap-trap guard.
        // The constant marks the floor; a value > the current epoch would
        // brick the chain at startup.
        const NOW_REFERENCE: f64 = 1_800_000_000.0; // 2027-01-15, well in the future at write time
        assert!(MIN_VALID_TIMESTAMP < NOW_REFERENCE,
            "MIN_VALID_TIMESTAMP must remain in the past relative to wall clock");
    }

    #[test]
    fn batch_b_verdict_6_variant_exhaustive_copy_eq_debug_as_str_is_valid() {
        // The 6 variants are the entire output surface of validate(). Any
        // refactor that adds, removes, or renames a verdict touches the
        // operator dashboard, rate-limit gate, and persistence layer.
        let variants = [
            TimestampVerdict::Valid,
            TimestampVerdict::FutureTooFar,
            TimestampVerdict::BeforeEpoch,
            TimestampVerdict::PastTooFar,
            TimestampVerdict::CausalViolation,
            TimestampVerdict::RateLimited,
        ];
        assert_eq!(variants.len(), 6,
            "TimestampVerdict has EXACTLY 6 variants");

        // Copy semantics. Compile-error test: if Copy is dropped, the
        // multi-use pattern below stops compiling.
        let v = TimestampVerdict::FutureTooFar;
        let _a = v;
        let _b = v;
        let _c = v;
        assert_eq!(v, TimestampVerdict::FutureTooFar,
            "Copy preserves original after multiple let-bindings");

        // PartialEq + Eq pairwise distinctness (6x6 matrix, 30 distinct pairs).
        for (i, vi) in variants.iter().enumerate() {
            for (j, vj) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(vi, vj, "diagonal: {vi:?} == self");
                } else {
                    assert_ne!(vi, vj, "off-diagonal: {vi:?} != {vj:?}");
                }
            }
        }

        // as_str() exhaustive — pins the operator-dashboard label set.
        // The existing test_verdict_strings covers only 3 of 6.
        assert_eq!(TimestampVerdict::Valid.as_str(), "valid");
        assert_eq!(TimestampVerdict::FutureTooFar.as_str(), "future_too_far");
        assert_eq!(TimestampVerdict::BeforeEpoch.as_str(), "before_epoch");
        assert_eq!(TimestampVerdict::PastTooFar.as_str(), "past_too_far");
        assert_eq!(TimestampVerdict::CausalViolation.as_str(), "causal_violation");
        assert_eq!(TimestampVerdict::RateLimited.as_str(), "rate_limited");

        // as_str() labels are pairwise distinct (cross-check w/ variant enum).
        let labels: Vec<&str> = variants.iter().map(|v| v.as_str()).collect();
        for (i, li) in labels.iter().enumerate() {
            for (j, lj) in labels.iter().enumerate() {
                if i != j {
                    assert_ne!(li, lj,
                        "two verdicts must not share the same as_str() label (i={i}, j={j})");
                }
            }
        }

        // as_str() is snake_case ASCII (no spaces, no caps, no Unicode).
        for v in &variants {
            let s = v.as_str();
            assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "as_str() must be ASCII lowercase + underscore: got {s:?}");
            assert!(!s.is_empty(), "as_str() must be non-empty");
            assert!(!s.starts_with('_'), "as_str() must not lead with underscore: {s:?}");
            assert!(!s.ends_with('_'), "as_str() must not trail underscore: {s:?}");
        }

        // is_valid() truth-matrix: Valid -> true, all 5 others -> false.
        assert!(TimestampVerdict::Valid.is_valid(), "Valid.is_valid() == true");
        assert!(!TimestampVerdict::FutureTooFar.is_valid());
        assert!(!TimestampVerdict::BeforeEpoch.is_valid());
        assert!(!TimestampVerdict::PastTooFar.is_valid());
        assert!(!TimestampVerdict::CausalViolation.is_valid());
        assert!(!TimestampVerdict::RateLimited.is_valid());

        // Debug renders variant name (operator log greppability).
        assert!(format!("{:?}", TimestampVerdict::FutureTooFar).contains("FutureTooFar"));
        assert!(format!("{:?}", TimestampVerdict::PastTooFar).contains("PastTooFar"));
        assert!(format!("{:?}", TimestampVerdict::CausalViolation).contains("CausalViolation"));
        assert!(format!("{:?}", TimestampVerdict::RateLimited).contains("RateLimited"));

        // Clone behaves like Copy (derive Clone is implied by Copy).
        let original = TimestampVerdict::BeforeEpoch;
        #[allow(clippy::clone_on_copy)] // intentional — pin Clone-derive presence on Copy type
        let cloned = original.clone();
        assert_eq!(cloned, original);
    }

    #[test]
    fn batch_b_validate_dispatch_order_exhaustive_gate_precedence_matrix() {
        // validate() runs 5 gates in fixed order:
        //   (1) BeforeEpoch (record_ts < MIN_VALID_TIMESTAMP)
        //   (2) FutureTooFar (record_ts - arrival - zone_drift > MAX_FUTURE_SKEW)
        //   (3) CausalViolation (parent_ts.is_some() && record_ts < parent_ts)
        //   (4) PastTooFar (parent_ts - record_ts > MAX_PAST_SKEW)
        //   (5) RateLimited (creator has >= MAX_VIOLATIONS_PER_IDENTITY in window)
        //   else Valid
        //
        // First gate to fire wins. This test pins precedence pair-by-pair
        // by constructing inputs that simultaneously fail multiple gates
        // and asserting the EARLIER gate's verdict is returned.
        const NOW: f64 = 1_800_000_000.0;
        let zone = || ZoneId::from_legacy(0);

        // Pair: BeforeEpoch trumps CausalViolation.
        //   record_ts=1.0 (below MIN), parent_ts=2.0 (record < parent triggers Causal)
        //   Expected: BeforeEpoch (gate 1 wins).
        let mut d = TimestampDefense::new();
        let v = d.validate(1.0, NOW, Some(2.0), "alice", zone());
        assert_eq!(v, TimestampVerdict::BeforeEpoch,
            "BeforeEpoch must fire BEFORE the parent_ts CausalViolation gate");

        // Pair: BeforeEpoch trumps FutureTooFar.
        // record_ts=1_000_000 is < MIN_VALID. With arrival_ts at NOW, the
        // (record_ts - arrival_ts) skew is hugely NEGATIVE so FutureTooFar
        // would not fire anyway — but we pin that the BeforeEpoch return
        // happens at gate 1 even if a future arrival could change the math.
        let mut d = TimestampDefense::new();
        let v = d.validate(1_000_000.0, NOW, None, "alice", zone());
        assert_eq!(v, TimestampVerdict::BeforeEpoch);

        // Pair: FutureTooFar trumps CausalViolation.
        //   record_ts = NOW + MAX_FUTURE_SKEW + 100 (FutureTooFar)
        //   parent_ts = NOW + MAX_FUTURE_SKEW + 200 (record_ts < parent_ts → Causal would fire too)
        //   Expected: FutureTooFar (gate 2 wins).
        let mut d = TimestampDefense::new();
        let bad = NOW + MAX_FUTURE_SKEW_SECS + 100.0;
        let bad_parent = bad + 50.0;
        let v = d.validate(bad, NOW, Some(bad_parent), "alice", zone());
        assert_eq!(v, TimestampVerdict::FutureTooFar,
            "FutureTooFar must fire BEFORE CausalViolation");

        // Pair: CausalViolation (record_ts < parent_ts, both within future-skew window).
        //   Pure causal flip — pins gate 3 fires when gates 1,2 pass.
        let mut d = TimestampDefense::new();
        let v = d.validate(NOW, NOW, Some(NOW + 10.0), "alice", zone());
        assert_eq!(v, TimestampVerdict::CausalViolation);

        // PastTooFar UNREACHABLE under current control flow (regression guard).
        //   PastTooFar requires pts - record_ts > MAX_PAST_SKEW which requires
        //   pts > record_ts which triggers CausalViolation first. If a future
        //   refactor swaps the comparison or reorders, PastTooFar may suddenly
        //   become reachable — this test pins that under all "obvious"
        //   triggering inputs, the current code returns CausalViolation.
        let mut d = TimestampDefense::new();
        let very_old_record = MIN_VALID_TIMESTAMP + 1.0; // above MIN, way before parent
        let very_new_parent = NOW; // parent_ts - record_ts > MAX_PAST_SKEW
        assert!(very_new_parent - very_old_record > MAX_PAST_SKEW_SECS,
            "test premise: parent-record gap exceeds MAX_PAST_SKEW");
        let v = d.validate(very_old_record, NOW, Some(very_new_parent), "alice", zone());
        assert_eq!(v, TimestampVerdict::CausalViolation,
            "current control flow: PastTooFar unreachable — CausalViolation fires first");

        // Gate 5: RateLimited fires AFTER all 4 structural gates pass.
        // First flood the violation pool past MAX_VIOLATIONS_PER_IDENTITY using
        // FutureTooFar (which calls record_violation), then send a structurally
        // VALID record. Gates 1-4 all pass, gate 5 fires.
        let mut d = TimestampDefense::new();
        let bad = NOW + MAX_FUTURE_SKEW_SECS + 100.0;
        for i in 0..MAX_VIOLATIONS_PER_IDENTITY {
            d.validate(bad, NOW + i as f64, None, "mallory", zone());
        }
        let v = d.validate(NOW, NOW, None, "mallory", zone());
        assert_eq!(v, TimestampVerdict::RateLimited);

        // RateLimited does NOT call record_violation (no self-inflation).
        let pre = d.violator_count();
        d.validate(NOW, NOW, None, "mallory", zone());
        assert_eq!(d.violator_count(), pre,
            "RateLimited verdict path skips record_violation — pool size unchanged");

        // Valid: all 5 gates pass. validate() returns Valid AND updates
        // zone consensus + drift (existing tests cover separately).
        let mut d = TimestampDefense::new();
        let v = d.validate(NOW, NOW, None, "alice", zone());
        assert_eq!(v, TimestampVerdict::Valid);

        // total_validated counts EVERY call regardless of verdict.
        // total_rejected counts every non-Valid verdict including RateLimited.
        let mut d = TimestampDefense::new();
        d.validate(NOW, NOW, None, "alice", zone()); // Valid
        d.validate(1.0, NOW, None, "bob", zone());   // BeforeEpoch
        d.validate(NOW + MAX_FUTURE_SKEW_SECS + 100.0, NOW, None, "carol", zone()); // FutureTooFar
        d.validate(NOW, NOW, Some(NOW + 10.0), "dave", zone()); // CausalViolation
        assert_eq!(d.total_validated(), 4,
            "_validated counts every call: 4 calls -> 4");
        assert_eq!(d.total_rejected(), 3,
            "_rejected counts non-Valid only: 3 rejects out of 4");
    }

    #[test]
    fn batch_b_zone_consensus_latest_monotonic_drift_ema_boundary_and_isolation() {
        // ZoneTimeConsensus is the per-zone timekeeping state.
        // Pins: new()==default; latest() monotonic-max; drift() EMA formula;
        // drift-update boundary strict > MAX_DRIFT_UPDATE_AGE_SECS; per-zone isolation.
        let zone_a = ZoneId::from_legacy(100);
        let zone_b = ZoneId::from_legacy(200);

        let mut c = ZoneTimeConsensus::new();
        // Initial state: no zones recorded → latest=None, drift=0.0 for any zone.
        assert_eq!(c.latest(&zone_a), None,
            "new() ZoneTimeConsensus has no recorded zones");
        assert_eq!(c.latest(&zone_b), None);
        assert_eq!(c.drift(&zone_a), 0.0,
            "new() drift defaults to 0.0 for any zone");
        assert_eq!(c.drift(&zone_b), 0.0);

        // latest() monotonic-max: record(zone, t1) then record(zone, t2 < t1) MUST keep t1.
        c.record(&zone_a, 1000.0);
        assert_eq!(c.latest(&zone_a), Some(1000.0));
        c.record(&zone_a, 500.0); // older — must NOT overwrite
        assert_eq!(c.latest(&zone_a), Some(1000.0),
            "record(t<latest) MUST NOT decrement latest — monotonic invariant");
        c.record(&zone_a, 2000.0);
        assert_eq!(c.latest(&zone_a), Some(2000.0));
        c.record(&zone_a, 2000.0); // equal — no-op
        assert_eq!(c.latest(&zone_a), Some(2000.0));

        // Per-zone isolation: recording zone_a does NOT affect zone_b.
        assert_eq!(c.latest(&zone_b), None,
            "zone_b unchanged after zone_a records");

        // Default::default() == new().
        let default = ZoneTimeConsensus::default();
        assert_eq!(default.latest(&zone_a), None);
        assert_eq!(default.drift(&zone_a), 0.0);

        // ── update_drift EMA formula pin ────────────────────────────
        // Per source line 126: *current = *current * 0.9 + drift * 0.1
        // with drift = record_ts - arrival_ts, alpha = 0.1.
        // Start: current = 0.0. Record arrives 10s late (record_ts - arrival_ts = -10).
        // Expected: 0.0 * 0.9 + (-10.0) * 0.1 = -1.0
        let mut c = ZoneTimeConsensus::new();
        c.update_drift(&zone_a, 1000.0, 1010.0);
        let d1 = c.drift(&zone_a);
        assert!((d1 - (-1.0)).abs() < 1e-9,
            "EMA(0, -10) = -1.0; got {d1}");

        // Second update: current = -1.0, new drift = -10.
        // Expected: -1.0 * 0.9 + -10.0 * 0.1 = -0.9 + -1.0 = -1.9
        c.update_drift(&zone_a, 1000.0, 1010.0);
        let d2 = c.drift(&zone_a);
        assert!((d2 - (-1.9)).abs() < 1e-9,
            "EMA second tick: 0.9*(-1) + 0.1*(-10) = -1.9; got {d2}");

        // ── Drift-update age boundary: strict > MAX_DRIFT_UPDATE_AGE_SECS ──
        // At exact boundary (age == 60.0), the gate is `if age > MAX` so
        // boundary-exact value PASSES the gate and updates.
        let mut c = ZoneTimeConsensus::new();
        c.update_drift(&zone_a, 1000.0, 1000.0 + MAX_DRIFT_UPDATE_AGE_SECS);
        assert!(c.drift(&zone_a) != 0.0,
            "drift-update at exact boundary (age==60) MUST update — strict > check");

        // One-tick past boundary (age = 60.0 + 0.001 → > 60.0): DOES NOT update.
        let mut c = ZoneTimeConsensus::new();
        c.update_drift(&zone_a, 1000.0, 1000.0 + MAX_DRIFT_UPDATE_AGE_SECS + 0.001);
        assert_eq!(c.drift(&zone_a), 0.0,
            "drift-update past boundary (age==60.001) MUST NOT update");

        // Per-zone drift isolation: update_drift on zone_a does not affect zone_b.
        let mut c = ZoneTimeConsensus::new();
        c.update_drift(&zone_a, 1000.0, 1010.0);
        assert!(c.drift(&zone_a) != 0.0);
        assert_eq!(c.drift(&zone_b), 0.0,
            "zone_b drift unaffected by zone_a EMA update");

        // Clone independence: cloning the consensus does not alias internal HashMaps.
        let mut c = ZoneTimeConsensus::new();
        c.record(&zone_a, 1000.0);
        c.update_drift(&zone_a, 1000.0, 1010.0);
        let cloned = c.clone();
        c.record(&zone_a, 9999.0);
        c.update_drift(&zone_a, 9999.0, 9999.0);
        assert_eq!(cloned.latest(&zone_a), Some(1000.0),
            "Clone snapshot — base mutation does NOT alias clone state");
    }

    #[test]
    fn batch_b_snapshot_serde_export_import_cutoff_and_prune_cleanup_matrix() {
        // TimestampViolationSnapshot is the persistence wire format and
        // restart-safety boundary. Pins:
        //   * 1-field shape (violations: HashMap<String, Vec<f64>>)
        //   * default == empty
        //   * JSON serde round-trip (empty + populated)
        //   * export clones (mutating the export does not affect the source)
        //   * import filters timestamps < (now - VIOLATION_DECAY_SECS)
        //   * import preserves entries with at-least-one fresh timestamp
        //   * prune cleanup matrix: empty / fully-stale / mixed / unchanged

        // Default is empty.
        let snap = TimestampViolationSnapshot::default();
        assert!(snap.violations.is_empty(),
            "Default snapshot has empty violations map");

        // 1-field exhaustive destructure pin — guards against silent field addition.
        let TimestampViolationSnapshot { violations } = snap;
        assert_eq!(violations.len(), 0);

        // Empty snapshot JSON round-trip.
        let empty = TimestampViolationSnapshot::default();
        let json = serde_json::to_vec(&empty).expect("serialize empty snapshot");
        let loaded: TimestampViolationSnapshot = serde_json::from_slice(&json)
            .expect("deserialize empty snapshot");
        assert_eq!(loaded.violations.len(), 0);

        // Populated snapshot JSON round-trip preserves keys + values + count.
        let mut populated = TimestampViolationSnapshot::default();
        populated.violations.insert("alice".into(), vec![100.0, 200.0, 300.0]);
        populated.violations.insert("bob".into(), vec![400.0]);
        let json = serde_json::to_vec(&populated).expect("serialize");
        let loaded: TimestampViolationSnapshot = serde_json::from_slice(&json)
            .expect("deserialize");
        assert_eq!(loaded.violations.len(), 2);
        assert_eq!(loaded.violations.get("alice").unwrap(), &vec![100.0, 200.0, 300.0]);
        assert_eq!(loaded.violations.get("bob").unwrap(), &vec![400.0]);

        // export_violations clones — mutating the export does NOT alias the source.
        const NOW: f64 = 1_800_000_000.0;
        let mut defense = TimestampDefense::new();
        let bad = NOW + MAX_FUTURE_SKEW_SECS + 100.0;
        defense.validate(bad, NOW, None, "mallory", ZoneId::from_legacy(0));
        let mut exported = defense.export_violations();
        exported.violations.insert("phantom".into(), vec![NOW]);
        assert!(!defense.export_violations().violations.contains_key("phantom"),
            "Mutating the export must not propagate to the source defense");

        // import_violations cutoff = now - VIOLATION_DECAY_SECS.
        // Construct snapshot with mixed-age timestamps; only fresh survive.
        let mut snap = TimestampViolationSnapshot::default();
        snap.violations.insert("mixed".into(), vec![
            NOW - VIOLATION_DECAY_SECS - 100.0, // stale (past cutoff)
            NOW - VIOLATION_DECAY_SECS - 1.0,   // stale (just past cutoff)
            NOW - VIOLATION_DECAY_SECS + 1.0,   // fresh (just inside cutoff)
            NOW - 1.0,                          // fresh (very recent)
        ]);
        snap.violations.insert("all_stale".into(), vec![
            NOW - VIOLATION_DECAY_SECS - 1.0,
            NOW - VIOLATION_DECAY_SECS - 500.0,
        ]);
        snap.violations.insert("all_fresh".into(), vec![NOW - 1.0, NOW - 2.0]);
        let mut d = TimestampDefense::new();
        d.import_violations(snap, NOW);
        // "mixed" keeps 2 of 4 timestamps; entry preserved.
        // "all_stale" filters to empty; entry DROPPED (per source line 274:
        //   `if !valid.is_empty() { self.violations.insert(...); }`).
        // "all_fresh" keeps all 2 timestamps.
        assert_eq!(d.violator_count(), 2,
            "import drops identities with zero fresh timestamps; mixed+all_fresh remain");

        // import cutoff is strict >= (per source line 273: `filter(|&t| t >= cutoff)`).
        let mut snap = TimestampViolationSnapshot::default();
        let cutoff = NOW - VIOLATION_DECAY_SECS;
        snap.violations.insert("boundary".into(), vec![cutoff]); // exactly at cutoff
        let mut d = TimestampDefense::new();
        d.import_violations(snap, NOW);
        assert_eq!(d.violator_count(), 1,
            "timestamp at exact cutoff (t == now - DECAY) is KEPT (>=  check)");

        // import cutoff strictly drops t < cutoff.
        let mut snap = TimestampViolationSnapshot::default();
        snap.violations.insert("just_below".into(), vec![cutoff - 0.001]);
        let mut d = TimestampDefense::new();
        d.import_violations(snap, NOW);
        assert_eq!(d.violator_count(), 0,
            "timestamp just below cutoff (cutoff - 0.001) is DROPPED");

        // prune() cleanup matrix.
        // (a) empty defense → 0 removed.
        let mut d = TimestampDefense::new();
        assert_eq!(d.prune(NOW), 0,
            "prune on empty defense returns 0");

        // (b) all-stale entries → all removed; return count = N.
        let mut d = TimestampDefense::new();
        d.validate(bad, NOW, None, "x", ZoneId::from_legacy(0));
        d.validate(bad, NOW, None, "y", ZoneId::from_legacy(0));
        d.validate(bad, NOW, None, "z", ZoneId::from_legacy(0));
        assert_eq!(d.violator_count(), 3);
        let removed = d.prune(NOW + VIOLATION_DECAY_SECS + 1.0);
        assert_eq!(removed, 3,
            "prune past decay window returns count of cleared identities");
        assert_eq!(d.violator_count(), 0);

        // (c) prune within window → 0 removed (all entries still fresh).
        let mut d = TimestampDefense::new();
        d.validate(bad, NOW, None, "x", ZoneId::from_legacy(0));
        let removed = d.prune(NOW + 1.0);
        assert_eq!(removed, 0,
            "prune within decay window does not remove fresh entries");
        assert_eq!(d.violator_count(), 1);

        // (d) Mixed: identity with some fresh + some stale timestamps after partial-window prune.
        // Pool seeded via import_violations to get a true mixed-age vec (the
        // double-validate path can't construct one because record_violation
        // stores arrival_ts and the second arrival_ts kills FutureTooFar).
        // Prune at (cutoff = past + 2*DECAY): drops the stale timestamp,
        // keeps the fresh one, identity remains in pool, removed count = 0.
        let mut snap = TimestampViolationSnapshot::default();
        snap.violations.insert("mixed".into(), vec![
            NOW,                       // stale once cutoff > NOW
            NOW + VIOLATION_DECAY_SECS + 100.0, // fresh well past cutoff
        ]);
        let mut d = TimestampDefense::new();
        // Import at NOW + DECAY + 200: cutoff = NOW + 200 → first ts (NOW) is
        // older than cutoff and is dropped at import time. So import alone
        // cannot leave a mixed-age vec. We need to seed via direct field
        // access. TimestampDefense is pub(crate)-tested in-module; reach into
        // the field directly.
        d.violations.insert("mixed".into(), snap.violations.remove("mixed").unwrap());
        assert_eq!(d.violator_count(), 1);
        // Prune at NOW + DECAY + 50: cutoff = NOW + 50. First ts (NOW) is
        // stale; second ts (NOW + DECAY + 100) is fresh. Vec retains 1 entry,
        // identity remains in pool, removed count = 0.
        let removed = d.prune(NOW + VIOLATION_DECAY_SECS + 50.0);
        assert_eq!(removed, 0,
            "identity keeps fresh timestamp, NOT removed from pool");
        assert_eq!(d.violator_count(), 1,
            "mixed-age identity remains in pool after partial prune");
    }
}
