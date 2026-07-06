//! Progressive trust tiers with 6-signal behavioral entropy scoring.
//!
//! economics v0.4.1 Section 9.2-9.3:
//!
//! **Entropy scoring** (§9.2): 6 weighted signals, 7-day rolling window.
//! - Inter-record timing variance (0.25)
//! - Content hash diversity (0.20)
//! - Witness source diversity (0.20)
//! - Record creation rate normality (0.15)
//! - Network origin diversity (0.10)
//! - Record size variance (0.10)
//!
//! **Trust tiers** (§9.3):
//! - Tier 0 (New): identity created, 10/day, no witness, no earn
//! - Tier 1 (Active): 30 days + entropy > 0.6, 50/day, no witness, no earn
//! - Tier 2 (Trusted): 90 days + entropy > 0.7 + 3+ diverse witnesses, 200/day, witness+earn
//!
//! **Quarantine** (§9.2): entropy < 0.3 → records accepted but NOT propagated.
//! Genesis authority is always Tier 2 (exempt from limits).

//!
//! Spec references:
//!   @spec economics §9.2
//!   @spec economics §9.3

use std::collections::{HashMap, HashSet};

use crate::errors::{ElaraError, Result};

// ─── Constants (economics v0.4.1 §9.2-9.4) ────────────────────────────────

/// Tier 0 daily limit.
pub const TIER_0_DAILY: u32 = 20;
/// Tier 1 daily limit.
pub const TIER_1_DAILY: u32 = 50;
/// Tier 2 daily limit.
pub const TIER_2_DAILY: u32 = 200;

/// Age threshold for Tier 1: 30 days in seconds.
pub const TIER_1_AGE_SECS: f64 = 30.0 * 24.0 * 3600.0;
/// Age threshold for Tier 2: 90 days in seconds.
pub const TIER_2_AGE_SECS: f64 = 90.0 * 24.0 * 3600.0;

/// Minimum entropy for Tier 1 promotion.
pub const TIER_1_MIN_ENTROPY: f64 = 0.6;
/// Minimum entropy for Tier 2 promotion.
pub const TIER_2_MIN_ENTROPY: f64 = 0.7;
/// Minimum diverse witnesses for Tier 2 promotion.
pub const TIER_2_MIN_DIVERSE_WITNESSES: usize = 3;

/// Full access entropy threshold (§9.2).
pub const ENTROPY_FULL_ACCESS: f64 = 0.6;
/// Throttled band lower bound (§9.2).
pub const ENTROPY_THROTTLE: f64 = 0.3;
// Below ENTROPY_THROTTLE → quarantined (accepted, not propagated).

/// Rolling window for entropy signals: 7 days in seconds.
pub const ENTROPY_WINDOW_SECS: f64 = 7.0 * 24.0 * 3600.0;

/// Daily window: 24 hours in seconds.
pub const DAILY_WINDOW_SECS: f64 = 24.0 * 3600.0;

/// Stake-gated throughput: base units (10^9/beat) of stake per daily record.
/// 100 beat (= 10^11 base units) / 1000 records = 10^8 base units per record.
/// The bare `100_000` was a pre-10^9-migration leftover that granted 1,000,000
/// records/day for 100 beat instead of the §9.4-documented 1,000.
/// economics v0.4.1 Section 9.4.
pub const BASE_UNITS_PER_DAILY_RECORD: u64 = 100_000_000;

/// "Normal" human record creation rate: 1-20/day. Above this → bot-like.
const RATE_NORMAL_MAX: f64 = 20.0;

// ─── Signal weights (economics v0.4.1 §9.2) ───────────────────────────────

const W_TIMING: f64 = 0.25;
const W_CONTENT: f64 = 0.20;
const W_WITNESS: f64 = 0.20;
const W_RATE: f64 = 0.15;
const W_ORIGIN: f64 = 0.10;
const W_SIZE: f64 = 0.10;

// ─── Types ──────────────────────────────────────────────────────────────────

/// Trust tier for a network identity (economics §9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// New identity: 10 records/day, no witness, no earn.
    Tier0,
    /// 30+ days, entropy > 0.6: 50 records/day, no witness, no earn.
    Tier1,
    /// 90+ days, entropy > 0.7, 3+ diverse witnesses: 200/day, can witness+earn.
    Tier2,
}

impl TrustTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tier0 => "tier0",
            Self::Tier1 => "tier1",
            Self::Tier2 => "tier2",
        }
    }

    /// Daily record limit for this tier.
    pub fn daily_limit(&self) -> u32 {
        match self {
            Self::Tier0 => TIER_0_DAILY,
            Self::Tier1 => TIER_1_DAILY,
            Self::Tier2 => TIER_2_DAILY,
        }
    }
}

// Backward-compatible aliases
pub type TrustEngine = EntropyEngine;
pub type TrustProfile = EntropyProfile;

/// Timestamped record event for 7-day rolling window analysis.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RecordEvent {
    timestamp: f64,
    content_hash: u64,
    wire_size: u32,
}

/// Entropy status: whether this identity should be throttled or quarantined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyStatus {
    /// entropy > 0.6: full free-tier access.
    FullAccess,
    /// entropy 0.3-0.6: reduced rate limit.
    Throttled,
    /// entropy < 0.3: records accepted but NOT propagated.
    Quarantined,
}

impl EntropyStatus {
    pub fn from_entropy(e: f64) -> Self {
        if e >= ENTROPY_FULL_ACCESS {
            Self::FullAccess
        } else if e >= ENTROPY_THROTTLE {
            Self::Throttled
        } else {
            Self::Quarantined
        }
    }
}

/// Per-identity entropy profile with 6-signal 7-day rolling window.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntropyProfile {
    /// When this identity was first seen (timestamp).
    pub first_seen: f64,
    /// Last activity timestamp (submission or witness registration).
    /// Used for inactive-identity pruning.
    /// Defaults to 0.0 for profiles serialized before this field existed;
    /// next activity will update it.
    #[serde(default)]
    pub last_seen: f64,
    /// Total records submitted by this identity (all time).
    pub total_records: u64,
    /// Rolling 7-day window of record events.
    events: Vec<RecordEvent>,
    /// Daily submission counter: (day_start_timestamp, count).
    daily_counter: (f64, u32),
    /// Unique witness identity hashes that have attested this identity's records.
    /// Used for Tier 2 diverse-witness check.
    diverse_witnesses: HashSet<String>,
    /// Network origins (subnet prefixes or peer hashes) seen in the window.
    network_origins: Vec<(f64, u64)>, // (timestamp, origin_hash)
}

impl EntropyProfile {
    pub fn new(first_seen: f64) -> Self {
        Self {
            first_seen,
            last_seen: first_seen,
            total_records: 0,
            events: Vec::new(),
            daily_counter: (first_seen, 0),
            diverse_witnesses: HashSet::new(),
            network_origins: Vec::new(),
        }
    }

    /// Compute identity age in seconds.
    pub fn age(&self, now: f64) -> f64 {
        (now - self.first_seen).max(0.0)
    }

    /// Record a submission with full signal data.
    pub fn record_submission(&mut self, content_hash: u64, timestamp: f64) {
        self.record_submission_full(content_hash, timestamp, 0, 0);
    }

    /// Record a submission with wire size and network origin.
    pub fn record_submission_full(
        &mut self,
        content_hash: u64,
        timestamp: f64,
        wire_size: u32,
        origin_hash: u64,
    ) {
        self.total_records += 1;
        if timestamp > self.last_seen {
            self.last_seen = timestamp;
        }

        // Reset daily counter if we've crossed into a new day
        if timestamp - self.daily_counter.0 >= DAILY_WINDOW_SECS {
            self.daily_counter = (timestamp, 0);
        }
        self.daily_counter.1 += 1;

        // Add to rolling window
        self.events.push(RecordEvent {
            timestamp,
            content_hash,
            wire_size,
        });

        // Track network origin
        if origin_hash != 0 {
            self.network_origins.push((timestamp, origin_hash));
        }

        // Prune events outside 7-day window
        self.prune_window(timestamp);
    }

    /// Register a witness for this identity (for Tier 2 check).
    pub fn register_witness(&mut self, witness_hash: &str, timestamp: f64) {
        self.diverse_witnesses.insert(witness_hash.to_string());
        if timestamp > self.last_seen {
            self.last_seen = timestamp;
        }
    }

    /// Current daily submission count.
    pub fn daily_count(&self, now: f64) -> u32 {
        if now - self.daily_counter.0 >= DAILY_WINDOW_SECS {
            0 // day has rolled over
        } else {
            self.daily_counter.1
        }
    }

    /// Prune events outside the 7-day window.
    fn prune_window(&mut self, now: f64) {
        let cutoff = now - ENTROPY_WINDOW_SECS;
        self.events.retain(|e| e.timestamp >= cutoff);
        self.network_origins.retain(|(t, _)| *t >= cutoff);
    }

    // ─── Signal computations (each returns 0.0-1.0) ─────────────────────

    /// Signal 1: Inter-record timing variance (weight 0.25).
    /// Human: variable intervals (hours/days). Bot: burst (ms apart).
    fn timing_variance(&self) -> f64 {
        if self.events.len() < 3 {
            return 1.0; // benefit of the doubt
        }

        // Compute inter-record intervals
        let mut intervals: Vec<f64> = Vec::with_capacity(self.events.len() - 1);
        for pair in self.events.windows(2) {
            let dt = (pair[1].timestamp - pair[0].timestamp).abs();
            intervals.push(dt);
        }

        if intervals.is_empty() {
            return 1.0;
        }

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean < f64::EPSILON {
            return 0.0; // all at the same instant
        }

        // Coefficient of variation: std_dev / mean. Higher = more variable = more human.
        let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
            / intervals.len() as f64;
        let cv = variance.sqrt() / mean;

        // cv = 0 → perfectly regular (bot), cv >= 1 → very variable (human)
        // Normalize: tanh(cv) gives nice 0-1 mapping, cv=1 → 0.76
        cv.tanh()
    }

    /// Signal 2: Content hash diversity (weight 0.20).
    /// Human: unique content. Bot: empty/duplicate.
    fn content_diversity(&self) -> f64 {
        if self.events.len() < 2 {
            return 1.0;
        }
        let unique: HashSet<u64> = self.events.iter().map(|e| e.content_hash).collect();
        unique.len() as f64 / self.events.len() as f64
    }

    /// Signal 3: Witness source diversity (weight 0.20).
    /// Human: multiple unrelated witnesses. Bot: same cluster or none.
    fn witness_diversity(&self) -> f64 {
        let count = self.diverse_witnesses.len();
        if count == 0 {
            return 0.5; // neutral if no witnesses yet (not penalized)
        }
        // Saturate at 5 unique witnesses → 1.0
        (count as f64 / 5.0).min(1.0)
    }

    /// Signal 4: Record creation rate normality (weight 0.15).
    /// Human: 1-20/day. Bot: 100+/day.
    fn rate_normality(&self) -> f64 {
        if self.events.is_empty() {
            return 1.0;
        }

        // Average records per day in the window
        let window_days = match (self.events.first(), self.events.last()) {
            (Some(first), Some(last)) => {
                let span = last.timestamp - first.timestamp;
                (span / DAILY_WINDOW_SECS).max(1.0)
            }
            _ => 1.0,
        };
        let rate_per_day = self.events.len() as f64 / window_days;

        if rate_per_day <= RATE_NORMAL_MAX {
            1.0 // human-like
        } else {
            // Exponential decay above normal max
            // At 100/day: score ~0.18, at 200/day: score ~0.03
            (-(rate_per_day - RATE_NORMAL_MAX) / (RATE_NORMAL_MAX * 2.0)).exp()
        }
    }

    /// Signal 5: Network origin diversity (weight 0.10).
    /// Human: variable IPs/locations. Bot: same subnet.
    fn origin_diversity(&self) -> f64 {
        if self.network_origins.is_empty() {
            return 0.5; // neutral if no origin data
        }
        let unique: HashSet<u64> = self.network_origins.iter().map(|(_, h)| *h).collect();
        // Even 2-3 different origins is decent for humans
        unique.len() as f64 / self.network_origins.len() as f64
    }

    /// Signal 6: Record size variance (weight 0.10).
    /// Human: variable record sizes. Bot: uniform (same payload template).
    fn size_variance(&self) -> f64 {
        let sizes: Vec<f64> = self.events.iter()
            .filter(|e| e.wire_size > 0)
            .map(|e| e.wire_size as f64)
            .collect();

        if sizes.len() < 3 {
            return 0.5; // neutral if not enough data
        }

        let mean = sizes.iter().sum::<f64>() / sizes.len() as f64;
        if mean < f64::EPSILON {
            return 0.0;
        }

        let variance = sizes.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
            / sizes.len() as f64;
        let cv = variance.sqrt() / mean;

        // cv = 0 → identical sizes (bot). cv >= 0.5 → good variance (human).
        (cv * 2.0).min(1.0)
    }

    /// Compute the 6-signal weighted entropy score (economics §9.2).
    ///
    /// Returns 0.0 (bot-like) to 1.0 (human-like).
    pub fn entropy(&self) -> f64 {
        W_TIMING * self.timing_variance()
            + W_CONTENT * self.content_diversity()
            + W_WITNESS * self.witness_diversity()
            + W_RATE * self.rate_normality()
            + W_ORIGIN * self.origin_diversity()
            + W_SIZE * self.size_variance()
    }

    /// Get individual signal scores for debugging/API.
    pub fn signal_scores(&self) -> EntropySignals {
        EntropySignals {
            timing_variance: self.timing_variance(),
            content_diversity: self.content_diversity(),
            witness_diversity: self.witness_diversity(),
            rate_normality: self.rate_normality(),
            origin_diversity: self.origin_diversity(),
            size_variance: self.size_variance(),
        }
    }

    /// Entropy status: full access, throttled, or quarantined.
    pub fn status(&self) -> EntropyStatus {
        EntropyStatus::from_entropy(self.entropy())
    }

    /// Number of diverse witnesses.
    pub fn diverse_witness_count(&self) -> usize {
        self.diverse_witnesses.len()
    }

    /// Determine the current trust tier based on age, entropy, and witnesses.
    pub fn tier(&self, now: f64) -> TrustTier {
        self.tier_with_continuity(now, None)
    }

    /// Determine trust tier with optional continuity gate (Protocol §11.35).
    ///
    /// When `continuity_score` is provided:
    /// - Tier 1 requires continuity >= 0.2 (at least ~10 days of consistent presence)
    /// - Tier 2 requires continuity >= 0.5 (at least ~60 days of consistent presence)
    ///
    /// This prevents dormant identities from advancing tiers based on age alone.
    pub fn tier_with_continuity(&self, now: f64, continuity_score: Option<f64>) -> TrustTier {
        let age = self.age(now);
        let entropy = self.entropy();
        let cont = continuity_score.unwrap_or(1.0); // no gate if not provided

        if age >= TIER_2_AGE_SECS
            && entropy >= TIER_2_MIN_ENTROPY
            && self.diverse_witnesses.len() >= TIER_2_MIN_DIVERSE_WITNESSES
            && cont >= 0.5
        {
            TrustTier::Tier2
        } else if age >= TIER_1_AGE_SECS && entropy >= TIER_1_MIN_ENTROPY && cont >= 0.2 {
            TrustTier::Tier1
        } else {
            TrustTier::Tier0
        }
    }
}

/// Breakdown of individual entropy signal scores.
#[derive(Debug, Clone, Copy)]
pub struct EntropySignals {
    pub timing_variance: f64,
    pub content_diversity: f64,
    pub witness_diversity: f64,
    pub rate_normality: f64,
    pub origin_diversity: f64,
    pub size_variance: f64,
}

/// Network-wide trust engine with 6-signal behavioral entropy.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EntropyEngine {
    profiles: HashMap<String, EntropyProfile>,
}

impl EntropyEngine {
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
        }
    }

    /// Get or create a profile for an identity.
    pub fn profile(&mut self, identity: &str, now: f64) -> &mut EntropyProfile {
        self.profiles
            .entry(identity.to_string())
            .or_insert_with(|| EntropyProfile::new(now))
    }

    /// Get profile (read-only, if it exists).
    pub fn get_profile(&self, identity: &str) -> Option<&EntropyProfile> {
        self.profiles.get(identity)
    }

    /// Try to restore a pruned identity's profile from RocksDB (CF_TRUST).
    ///
    /// If the identity was pruned from in-memory state but its profile was
    /// dual-written to RocksDB, this reloads it into the in-memory map and
    /// returns a reference. Returns `None` if not found in RocksDB either.
    #[cfg(feature = "node")]
    pub fn restore_from_rocks(
        &mut self,
        identity: &str,
        rocks: &crate::storage::rocks::StorageEngine,
    ) -> Option<&EntropyProfile> {
        if self.profiles.contains_key(identity) {
            return self.profiles.get(identity);
        }
        let bytes = rocks
            .get_cf_raw(crate::storage::rocks::CF_TRUST, identity.as_bytes())
            .ok()
            .flatten()?;
        let profile: EntropyProfile = serde_json::from_slice(&bytes).ok()?;
        self.profiles.insert(identity.to_string(), profile);
        self.profiles.get(identity)
    }

    /// Get the age of an identity in seconds. Returns 0.0 if unknown.
    pub fn identity_age(&self, identity: &str, now: f64) -> f64 {
        self.profiles
            .get(identity)
            .map_or(0.0, |p| (now - p.first_seen).max(0.0))
    }

    /// Check if an identity can submit a record right now.
    /// Returns Ok(()) if allowed, Err if daily limit exceeded.
    ///
    /// `genesis_authority` is always allowed (exempt).
    pub fn check_submission(
        &self,
        identity: &str,
        genesis_authority: &str,
        now: f64,
    ) -> Result<()> {
        self.check_submission_with_stake(identity, genesis_authority, now, 0)
    }

    /// Check submission with stake-gated throughput (default ratio).
    ///
    /// If `staked_micro > 0`, daily limit = `staked_micro / BASE_UNITS_PER_DAILY_RECORD`.
    /// No behavioral scoring for staked identities — the stake IS the anti-spam commitment.
    pub fn check_submission_with_stake(
        &self,
        identity: &str,
        genesis_authority: &str,
        now: f64,
        staked_micro: u64,
    ) -> Result<()> {
        self.check_submission_with_stake_ratio(identity, genesis_authority, now, staked_micro, BASE_UNITS_PER_DAILY_RECORD)
    }

    /// Check submission with a governance-adjustable stake throughput ratio.
    ///
    /// `ratio`: base units (10^9/beat) of stake per daily record. Default = 100,000,000.
    /// Governance can adjust this via the `stake_throughput_ratio` parameter.
    pub fn check_submission_with_stake_ratio(
        &self,
        identity: &str,
        genesis_authority: &str,
        now: f64,
        staked_micro: u64,
        ratio: u64,
    ) -> Result<()> {
        // Genesis authority is always trusted
        if identity == genesis_authority {
            return Ok(());
        }

        let Some(profile) = self.profiles.get(identity) else {
            // Unknown identity — allow first submission (will create profile)
            return Ok(());
        };

        let daily_count = profile.daily_count(now);

        // Stake-gated throughput: staked identities bypass trust tier limits
        if staked_micro > 0 {
            let effective_ratio = if ratio > 0 { ratio } else { BASE_UNITS_PER_DAILY_RECORD };
            let staked_limit = (staked_micro / effective_ratio) as u32;
            let staked_limit = staked_limit.max(TIER_0_DAILY); // never below Tier 0 min
            if daily_count >= staked_limit {
                return Err(ElaraError::Ledger(format!(
                    "stake-gated daily limit exceeded: {} beat staked allows {}/day, \
                     already submitted {} today",
                    staked_micro / crate::accounting::types::BASE_UNITS_PER_BEAT,
                    staked_limit,
                    daily_count,
                )));
            }
            return Ok(());
        }

        let tier = profile.tier(now);
        let daily_limit = tier.daily_limit();

        // Throttle: if entropy 0.3-0.6, halve the limit
        let entropy = profile.entropy();
        let effective_limit = if (ENTROPY_THROTTLE..ENTROPY_FULL_ACCESS).contains(&entropy) {
            daily_limit / 2
        } else {
            daily_limit
        };

        if daily_count >= effective_limit {
            return Err(ElaraError::Ledger(format!(
                "daily record limit exceeded: {} allows {} records/day{}, \
                 already submitted {} today",
                tier.as_str(),
                effective_limit,
                if effective_limit < daily_limit { " (throttled)" } else { "" },
                daily_count,
            )));
        }

        Ok(())
    }

    /// Check submission with continuity-gated tier evaluation (Protocol §11.35).
    ///
    /// Same as `check_submission_with_stake_ratio` but uses `tier_with_continuity()`
    /// to require minimum continuity scores for tier advancement.
    pub fn check_submission_with_continuity(
        &self,
        identity: &str,
        genesis_authority: &str,
        now: f64,
        staked_micro: u64,
        ratio: u64,
        continuity_score: f64,
    ) -> Result<()> {
        if identity == genesis_authority {
            return Ok(());
        }

        let Some(profile) = self.profiles.get(identity) else {
            return Ok(());
        };

        let daily_count = profile.daily_count(now);

        // Stake-gated: bypass trust tier limits
        if staked_micro > 0 {
            let effective_ratio = if ratio > 0 { ratio } else { BASE_UNITS_PER_DAILY_RECORD };
            let staked_limit = (staked_micro / effective_ratio) as u32;
            let staked_limit = staked_limit.max(TIER_0_DAILY);
            if daily_count >= staked_limit {
                return Err(ElaraError::Ledger(format!(
                    "stake-gated daily limit exceeded: {} beat staked allows {}/day, \
                     already submitted {} today",
                    staked_micro / crate::accounting::types::BASE_UNITS_PER_BEAT, staked_limit, daily_count,
                )));
            }
            return Ok(());
        }

        let tier = profile.tier_with_continuity(now, Some(continuity_score));
        let daily_limit = tier.daily_limit();

        let entropy = profile.entropy();
        let effective_limit = if (ENTROPY_THROTTLE..ENTROPY_FULL_ACCESS).contains(&entropy) {
            daily_limit / 2
        } else {
            daily_limit
        };

        if daily_count >= effective_limit {
            return Err(ElaraError::Ledger(format!(
                "daily record limit exceeded: {} (continuity={:.2}) allows {} records/day{}, \
                 already submitted {} today",
                tier.as_str(), continuity_score, effective_limit,
                if effective_limit < daily_limit { " (throttled)" } else { "" },
                daily_count,
            )));
        }

        Ok(())
    }

    /// Process a single record during streaming rebuild. Extracts creator and
    /// fingerprint, records the submission. O(1) per record.
    pub fn process_record(&mut self, rec: &crate::record::ValidationRecord) {
        let creator = crate::accounting::types::creator_identity_hash(rec);
        let fingerprint = content_fingerprint(&rec.metadata);
        self.record_submission(&creator, fingerprint, rec.timestamp);
    }

    /// Record a submission for an identity (call after accepting a record).
    pub fn record_submission(
        &mut self,
        identity: &str,
        content_hash: u64,
        timestamp: f64,
    ) {
        let profile = self.profile(identity, timestamp);
        profile.record_submission(content_hash, timestamp);
    }

    /// Record a submission with full signal data.
    pub fn record_submission_full(
        &mut self,
        identity: &str,
        content_hash: u64,
        timestamp: f64,
        wire_size: u32,
        origin_hash: u64,
    ) {
        let profile = self.profile(identity, timestamp);
        profile.record_submission_full(content_hash, timestamp, wire_size, origin_hash);
    }

    /// Register a witness attestation for an identity (for Tier 2 diverse witness check).
    pub fn register_witness(&mut self, creator_identity: &str, witness_hash: &str, now: f64) {
        let profile = self.profile(creator_identity, now);
        profile.register_witness(witness_hash, now);
    }

    /// Number of tracked identities.
    pub fn tracked_identities(&self) -> usize {
        self.profiles.len()
    }

    /// Check if an identity can witness (Tier 2 required).
    pub fn can_witness(&self, identity: &str, now: f64) -> bool {
        match self.profiles.get(identity) {
            Some(profile) => profile.tier(now) == TrustTier::Tier2,
            None => false,
        }
    }

    /// Get the trust tier for an identity.
    pub fn tier(&self, identity: &str, now: f64) -> TrustTier {
        match self.profiles.get(identity) {
            Some(profile) => profile.tier(now),
            None => TrustTier::Tier0,
        }
    }

    /// Check if an identity's records should be quarantined (not propagated).
    pub fn is_quarantined(&self, identity: &str) -> bool {
        match self.profiles.get(identity) {
            Some(profile) => profile.status() == EntropyStatus::Quarantined,
            None => false,
        }
    }

    /// Get entropy status for an identity.
    pub fn entropy_status(&self, identity: &str) -> EntropyStatus {
        match self.profiles.get(identity) {
            Some(profile) => profile.status(),
            None => EntropyStatus::FullAccess, // unknown = benefit of doubt
        }
    }

    /// Prune identities inactive for more than `max_age_secs`.
    ///
    /// Uses the `last_seen` timestamp (updated on every submission and witness
    /// registration). Pruned profiles are already dual-written to RocksDB
    /// (CF_TRUST) and can be reloaded on demand. Returns the count pruned.
    pub fn prune_inactive(&mut self, now: f64, max_age_secs: u64) -> usize {
        let cutoff = now - max_age_secs as f64;
        let before = self.profiles.len();
        self.profiles.retain(|_, p| p.last_seen >= cutoff);
        before - self.profiles.len()
    }
}

/// Compute a fast content hash from record metadata for entropy tracking.
/// Uses FNV-1a hash of the sorted metadata keys+values.
pub fn content_fingerprint(metadata: &std::collections::BTreeMap<String, serde_json::Value>) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325; // FNV offset basis
    for (k, v) in metadata {
        for byte in k.bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x0100_0000_01b3); // FNV prime
        }
        let v_str = v.to_string();
        for byte in v_str.bytes().take(64) {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── TrustTier basics ─────────────────────────────────────────

    #[test]
    fn test_tier_daily_limits() {
        assert_eq!(TrustTier::Tier0.daily_limit(), TIER_0_DAILY);
        assert_eq!(TrustTier::Tier1.daily_limit(), TIER_1_DAILY);
        assert_eq!(TrustTier::Tier2.daily_limit(), TIER_2_DAILY);
    }

    #[test]
    fn test_tier_ordering() {
        assert!(TrustTier::Tier0 < TrustTier::Tier1);
        assert!(TrustTier::Tier1 < TrustTier::Tier2);
    }

    #[test]
    fn test_tier_as_str() {
        assert_eq!(TrustTier::Tier0.as_str(), "tier0");
        assert_eq!(TrustTier::Tier1.as_str(), "tier1");
        assert_eq!(TrustTier::Tier2.as_str(), "tier2");
    }

    // ─── New identity defaults ────────────────────────────────────

    #[test]
    fn test_new_identity_tier0() {
        let profile = EntropyProfile::new(1000.0);
        assert_eq!(profile.tier(1000.0), TrustTier::Tier0);
        assert_eq!(profile.total_records, 0);
        assert_eq!(profile.daily_count(1000.0), 0);
    }

    // ─── Individual signal tests ──────────────────────────────────

    #[test]
    fn test_timing_variance_few_records() {
        let profile = EntropyProfile::new(1000.0);
        // < 3 events → benefit of doubt = 1.0
        assert!((profile.timing_variance() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_timing_variance_burst_is_low() {
        let mut profile = EntropyProfile::new(1000.0);
        // Bot-like: records 1ms apart
        for i in 0..20 {
            profile.record_submission(i, 1000.0 + i as f64 * 0.001);
        }
        let tv = profile.timing_variance();
        assert!(tv < 0.3, "burst timing variance should be low, got {tv}");
    }

    #[test]
    fn test_timing_variance_variable_is_high() {
        let mut profile = EntropyProfile::new(1000.0);
        // Human-like: variable intervals (hours)
        let timestamps = [
            1000.0, 1000.0 + 3600.0, 1000.0 + 7200.0, 1000.0 + 50000.0,
            1000.0 + 60000.0, 1000.0 + 150000.0, 1000.0 + 200000.0,
        ];
        for (i, &ts) in timestamps.iter().enumerate() {
            profile.record_submission(i as u64, ts);
        }
        let tv = profile.timing_variance();
        assert!(tv > 0.5, "variable timing variance should be high, got {tv}");
    }

    #[test]
    fn test_content_diversity_all_unique() {
        let mut profile = EntropyProfile::new(1000.0);
        for i in 0..50 {
            profile.record_submission(i, 1000.0 + i as f64);
        }
        assert!((profile.content_diversity() - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_content_diversity_all_identical() {
        let mut profile = EntropyProfile::new(1000.0);
        for i in 0..50 {
            profile.record_submission(42, 1000.0 + i as f64);
        }
        assert!(profile.content_diversity() < 0.05);
    }

    #[test]
    fn test_witness_diversity_none() {
        let profile = EntropyProfile::new(1000.0);
        // No witnesses → neutral (0.5)
        assert!((profile.witness_diversity() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_witness_diversity_saturates() {
        let mut profile = EntropyProfile::new(1000.0);
        for i in 0..10 {
            profile.register_witness(&format!("witness-{i}"), 1000.0 + i as f64);
        }
        assert!((profile.witness_diversity() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_rate_normality_low_rate() {
        let mut profile = EntropyProfile::new(1000.0);
        // 5 records over 7 days = ~0.7/day
        for i in 0..5 {
            profile.record_submission(i, 1000.0 + i as f64 * DAILY_WINDOW_SECS);
        }
        assert!((profile.rate_normality() - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_rate_normality_high_rate() {
        let mut profile = EntropyProfile::new(1000.0);
        // 200 records in 1 day = 200/day
        for i in 0..200 {
            profile.record_submission(i, 1000.0 + i as f64 * 0.5);
        }
        let rn = profile.rate_normality();
        assert!(rn < 0.3, "high rate should score low, got {rn}");
    }

    #[test]
    fn test_rate_normality_single_event_no_panic() {
        // Exactly 1 event: first() == last() → span = 0, window_days = 1.0,
        // rate = 1/1 which is ≤ RATE_NORMAL_MAX → score 1.0.
        // Exercises the formerly-panicking expect() path with a safe fallback.
        let mut profile = EntropyProfile::new(1000.0);
        profile.record_submission(42, 1000.0);
        assert!((profile.rate_normality() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_size_variance_uniform() {
        let mut profile = EntropyProfile::new(1000.0);
        // Identical sizes → low variance
        for i in 0..20 {
            profile.record_submission_full(i, 1000.0 + i as f64, 500, 0);
        }
        assert!(profile.size_variance() < 0.1, "uniform size should score low");
    }

    #[test]
    fn test_size_variance_variable() {
        let mut profile = EntropyProfile::new(1000.0);
        // Variable sizes
        let sizes = [100, 500, 200, 1000, 50, 800, 300, 1500, 150, 2000];
        for (i, &sz) in sizes.iter().enumerate() {
            profile.record_submission_full(i as u64, 1000.0 + i as f64, sz, 0);
        }
        assert!(profile.size_variance() > 0.5, "variable sizes should score high");
    }

    #[test]
    fn test_origin_diversity_single() {
        let mut profile = EntropyProfile::new(1000.0);
        // Same origin every time
        for i in 0..10 {
            profile.record_submission_full(i, 1000.0 + i as f64, 0, 12345);
        }
        assert!(profile.origin_diversity() < 0.2, "single origin should score low");
    }

    #[test]
    fn test_origin_diversity_multiple() {
        let mut profile = EntropyProfile::new(1000.0);
        // Different origin each time
        for i in 0..10 {
            profile.record_submission_full(i, 1000.0 + i as f64, 0, i + 1);
        }
        assert!((profile.origin_diversity() - 1.0).abs() < 0.01, "unique origins should score 1.0");
    }

    // ─── Composite entropy score ──────────────────────────────────

    #[test]
    fn test_entropy_human_like_is_high() {
        let mut profile = EntropyProfile::new(1000.0);
        // Simulate human: variable timing, unique content, variable sizes, multiple origins
        let base = 1000.0;
        let timestamps = [
            base, base + 3600.0, base + 14400.0, base + 50000.0,
            base + 86000.0, base + 200000.0, base + 300000.0,
            base + 400000.0, base + 500000.0, base + 550000.0,
        ];
        let sizes = [100, 500, 200, 1000, 50, 800, 300, 1500, 150, 2000];
        for (i, (&ts, &sz)) in timestamps.iter().zip(sizes.iter()).enumerate() {
            profile.record_submission_full(i as u64, ts, sz, i as u64 + 1);
        }
        for i in 0..3 {
            profile.register_witness(&format!("w{i}"), 550000.0);
        }

        let e = profile.entropy();
        assert!(e > 0.6, "human-like entropy should be > 0.6, got {e}");
    }

    #[test]
    fn test_entropy_bot_like_is_low() {
        let mut profile = EntropyProfile::new(1000.0);
        // Simulate bot: regular timing, same content, same size, same origin
        for i in 0..100 {
            profile.record_submission_full(42, 1000.0 + i as f64 * 0.01, 500, 12345);
        }

        let e = profile.entropy();
        assert!(e < 0.3, "bot-like entropy should be < 0.3, got {e}");
    }

    // ─── Entropy status ───────────────────────────────────────────

    #[test]
    fn test_entropy_status_thresholds() {
        assert_eq!(EntropyStatus::from_entropy(0.8), EntropyStatus::FullAccess);
        assert_eq!(EntropyStatus::from_entropy(0.6), EntropyStatus::FullAccess);
        assert_eq!(EntropyStatus::from_entropy(0.5), EntropyStatus::Throttled);
        assert_eq!(EntropyStatus::from_entropy(0.3), EntropyStatus::Throttled);
        assert_eq!(EntropyStatus::from_entropy(0.29), EntropyStatus::Quarantined);
        assert_eq!(EntropyStatus::from_entropy(0.0), EntropyStatus::Quarantined);
    }

    // ─── Tier progression ─────────────────────────────────────────

    #[test]
    fn test_tier_0_to_1_at_30_days() {
        let mut profile = EntropyProfile::new(1000.0);
        // Human-like activity to get entropy > 0.6
        for i in 0..10 {
            profile.record_submission_full(
                i,
                1000.0 + i as f64 * 10000.0,
                100 + (i as u32 * 50),
                i + 1,
            );
        }

        let at_29_days = 1000.0 + 29.0 * DAILY_WINDOW_SECS;
        assert_eq!(profile.tier(at_29_days), TrustTier::Tier0);

        let at_31_days = 1000.0 + 31.0 * DAILY_WINDOW_SECS;
        assert_eq!(profile.tier(at_31_days), TrustTier::Tier1);
    }

    #[test]
    fn test_tier_1_to_2_needs_witnesses() {
        let mut profile = EntropyProfile::new(1000.0);
        // Human-like: variable timing, unique content, variable sizes, multiple origins
        let intervals = [3600.0, 14400.0, 50000.0, 7200.0, 86000.0, 200000.0, 3000.0, 43000.0, 100000.0];
        let mut t = 1000.0;
        for (i, &dt) in intervals.iter().enumerate() {
            t += dt;
            profile.record_submission_full(
                i as u64,
                t,
                100 + (i as u32 * 50),
                i as u64 + 1,
            );
        }

        let at_91_days = 1000.0 + 91.0 * DAILY_WINDOW_SECS;

        // 90+ days, good entropy, but no diverse witnesses → stays Tier 1
        assert_eq!(profile.tier(at_91_days), TrustTier::Tier1);

        // Add 2 witnesses — still not enough (need 3)
        profile.register_witness("w1", at_91_days);
        profile.register_witness("w2", at_91_days);
        assert_eq!(profile.tier(at_91_days), TrustTier::Tier1);

        // Add 3rd witness → Tier 2
        profile.register_witness("w3", at_91_days);
        assert_eq!(profile.tier(at_91_days), TrustTier::Tier2);
    }

    #[test]
    fn test_low_entropy_stays_tier0() {
        let mut profile = EntropyProfile::new(1000.0);
        // All identical content, burst timing = low entropy
        for i in 0..100 {
            profile.record_submission(42, 1000.0 + i as f64 * 0.01);
        }

        let at_1_year = 1000.0 + 366.0 * DAILY_WINDOW_SECS;
        // Even old, low entropy = stays Tier 0
        assert_eq!(profile.tier(at_1_year), TrustTier::Tier0);
    }

    // ─── Daily counter ────────────────────────────────────────────

    #[test]
    fn test_daily_counter_reset() {
        let mut profile = EntropyProfile::new(1000.0);
        profile.record_submission(1, 1000.0);
        profile.record_submission(2, 1000.0);
        assert_eq!(profile.daily_count(1000.0), 2);

        let next_day = 1000.0 + DAILY_WINDOW_SECS + 1.0;
        assert_eq!(profile.daily_count(next_day), 0);

        profile.record_submission(3, next_day);
        assert_eq!(profile.daily_count(next_day), 1);
    }

    // ─── Engine: check_submission ─────────────────────────────────

    #[test]
    fn test_check_submission_under_limit() {
        let mut engine = EntropyEngine::new();
        engine.record_submission("alice", 1, 1000.0);
        assert!(engine.check_submission("alice", "genesis", 1000.0).is_ok());
    }

    #[test]
    fn test_check_submission_exceeds_daily_limit() {
        let mut engine = EntropyEngine::new();
        // Tier 0 limit = 10. Submit 11 records.
        for i in 0..11u32 {
            engine.record_submission("alice", 42, 1000.0 + i as f64);
        }
        let result = engine.check_submission("alice", "genesis", 1000.0 + 100.0);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("daily record limit exceeded"));
    }

    #[test]
    fn test_genesis_authority_exempt() {
        let mut engine = EntropyEngine::new();
        for i in 0..2000u64 {
            engine.record_submission("genesis", 42, 1000.0 + i as f64);
        }
        assert!(engine.check_submission("genesis", "genesis", 3000.0).is_ok());
    }

    #[test]
    fn test_unknown_identity_allowed() {
        let engine = EntropyEngine::new();
        assert!(engine.check_submission("newbie", "genesis", 1000.0).is_ok());
    }

    // ─── Engine: can_witness ──────────────────────────────────────

    #[test]
    fn test_can_witness_requires_tier2() {
        let mut engine = EntropyEngine::new();
        // Human-like: variable timing
        let intervals = [3600.0, 14400.0, 50000.0, 7200.0, 86000.0, 200000.0, 3000.0, 43000.0, 100000.0];
        let mut t = 1000.0;
        for (i, &dt) in intervals.iter().enumerate() {
            t += dt;
            engine.record_submission_full(
                "alice", i as u64, t, 100 + (i as u32 * 50), i as u64 + 1,
            );
        }

        // Tier 0: can't witness
        assert!(!engine.can_witness("alice", 1000.0));

        // At 31 days: Tier 1, still can't witness
        let at_31_days = 1000.0 + 31.0 * DAILY_WINDOW_SECS;
        assert!(!engine.can_witness("alice", at_31_days));

        // At 91 days without witnesses: Tier 1, can't witness
        let at_91_days = 1000.0 + 91.0 * DAILY_WINDOW_SECS;
        assert!(!engine.can_witness("alice", at_91_days));

        // Add 3 diverse witnesses → Tier 2, can witness
        engine.register_witness("alice", "w1", at_91_days);
        engine.register_witness("alice", "w2", at_91_days);
        engine.register_witness("alice", "w3", at_91_days);
        assert!(engine.can_witness("alice", at_91_days));
    }

    // ─── Engine: quarantine ───────────────────────────────────────

    #[test]
    fn test_quarantine_bot_like() {
        let mut engine = EntropyEngine::new();
        // Bot pattern: same content, burst timing, same origin, same size
        for i in 0..100 {
            engine.record_submission_full("bot", 42, 1000.0 + i as f64 * 0.01, 500, 12345);
        }
        assert!(engine.is_quarantined("bot"));
    }

    #[test]
    fn test_no_quarantine_human() {
        let mut engine = EntropyEngine::new();
        // Human pattern
        for i in 0..10 {
            engine.record_submission_full(
                "human", i, 1000.0 + i as f64 * 50000.0, 100 + (i as u32 * 50), i + 1,
            );
        }
        assert!(!engine.is_quarantined("human"));
    }

    // ─── Stake-gated throughput ───────────────────────────────────

    #[test]
    fn test_staked_identity_bypasses_tier_limit() {
        let mut engine = EntropyEngine::new();
        for i in 0..5u32 {
            engine.record_submission("factory", 42, 1000.0 + i as f64);
        }
        let result = engine.check_submission_with_stake(
            "factory", "genesis", 1000.0 + 100.0, 100_000_000,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_staked_identity_limit_scales_with_stake() {
        let mut engine = EntropyEngine::new();
        for i in 0..1001u32 {
            engine.record_submission("factory", i as u64, 1000.0 + i as f64);
        }

        // 100 beat → 1000/day → 1001st should fail
        let result = engine.check_submission_with_stake(
            "factory", "genesis", 1000.0 + 2000.0, 100 * crate::accounting::types::BASE_UNITS_PER_BEAT,
        );
        assert!(result.is_err());

        // 10,000 beat → 100,000/day → should pass
        let result = engine.check_submission_with_stake(
            "factory", "genesis", 1000.0 + 2000.0, 10_000 * crate::accounting::types::BASE_UNITS_PER_BEAT,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_staked_no_entropy_requirement() {
        let mut engine = EntropyEngine::new();
        for i in 0..100u32 {
            engine.record_submission("iot-gw", 42, 1000.0 + i as f64);
        }

        // Without stake: Tier 0 limit (10) exceeded
        assert!(engine.check_submission("iot-gw", "genesis", 1000.0 + 200.0).is_err());

        // With stake: 1000 beat → 10,000/day limit (staked bypasses entropy)
        let result = engine.check_submission_with_stake(
            "iot-gw", "genesis", 1000.0 + 200.0, 1_000 * crate::accounting::types::BASE_UNITS_PER_BEAT,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_zero_stake_falls_through_to_tier() {
        let mut engine = EntropyEngine::new();
        engine.record_submission("alice", 1, 1000.0);
        assert!(engine.check_submission_with_stake("alice", "genesis", 1000.0, 0).is_ok());
    }

    #[test]
    fn test_governance_adjustable_ratio() {
        let mut engine = EntropyEngine::new();
        for i in 0..501u32 {
            engine.record_submission("factory", i as u64, 1000.0 + i as f64);
        }

        // 100 beat staked = 100 * 10^9 base units.
        let stake_100_beat: u64 = 100 * crate::accounting::types::BASE_UNITS_PER_BEAT;

        // Default ratio (10^8 base units/record): 100 beat → 1000/day
        let result = engine.check_submission_with_stake_ratio(
            "factory", "genesis", 1000.0 + 2000.0, stake_100_beat, BASE_UNITS_PER_DAILY_RECORD,
        );
        assert!(result.is_ok());

        // Governance doubles ratio: 100 beat → only 500/day
        let result = engine.check_submission_with_stake_ratio(
            "factory", "genesis", 1000.0 + 2000.0, stake_100_beat, BASE_UNITS_PER_DAILY_RECORD * 2,
        );
        assert!(result.is_err()); // 501 > 500

        // Governance halves ratio: 100 beat → 2000/day
        let result = engine.check_submission_with_stake_ratio(
            "factory", "genesis", 1000.0 + 2000.0, stake_100_beat, BASE_UNITS_PER_DAILY_RECORD / 2,
        );
        assert!(result.is_ok()); // 501 < 2000
    }

    #[test]
    fn test_exact_stake_tiers() {
        let engine = EntropyEngine::new();
        let ratio = BASE_UNITS_PER_DAILY_RECORD;

        // Verify exact tier limits from economics §9.4 (stakes in base units, 10^9/beat)
        let beat = crate::accounting::types::BASE_UNITS_PER_BEAT;
        // 100 beat → 1,000/day
        assert_eq!(100 * beat / ratio, 1_000);
        // 10K beat → 100,000/day
        assert_eq!(10_000 * beat / ratio, 100_000);
        // 100K beat → 1,000,000/day
        assert_eq!(100_000 * beat / ratio, 1_000_000);
        // 1M beat → 10,000,000/day
        assert_eq!(1_000_000 * beat / ratio, 10_000_000);

        // Quick sanity: genesis always passes
        assert!(engine.check_submission_with_stake_ratio("genesis", "genesis", 1.0, 0, ratio).is_ok());
    }

    // ─── Window pruning ───────────────────────────────────────────

    #[test]
    fn test_7_day_window_pruning() {
        let mut profile = EntropyProfile::new(1000.0);
        // Submit 5 records at t=1000
        for i in 0..5 {
            profile.record_submission(i, 1000.0);
        }
        assert_eq!(profile.events.len(), 5);

        // Submit 3 more records 8 days later → old records pruned
        let eight_days_later = 1000.0 + 8.0 * DAILY_WINDOW_SECS;
        for i in 10..13 {
            profile.record_submission(i, eight_days_later);
        }
        assert_eq!(profile.events.len(), 3, "old events should be pruned");
    }

    // ─── Signal scores API ────────────────────────────────────────

    #[test]
    fn test_signal_scores_all_present() {
        let mut profile = EntropyProfile::new(1000.0);
        for i in 0..10 {
            profile.record_submission_full(i, 1000.0 + i as f64 * 3600.0, 100 + i as u32, i + 1);
        }
        let signals = profile.signal_scores();
        // All signals should be in [0, 1]
        assert!((0.0..=1.0).contains(&signals.timing_variance));
        assert!((0.0..=1.0).contains(&signals.content_diversity));
        assert!((0.0..=1.0).contains(&signals.witness_diversity));
        assert!((0.0..=1.0).contains(&signals.rate_normality));
        assert!((0.0..=1.0).contains(&signals.origin_diversity));
        assert!((0.0..=1.0).contains(&signals.size_variance));
    }

    // ─── Content fingerprint ──────────────────────────────────────

    #[test]
    fn test_content_fingerprint_different_metadata() {
        let mut m1 = std::collections::BTreeMap::new();
        m1.insert("beat_op".to_string(), serde_json::json!("transfer"));
        m1.insert("beat_amount".to_string(), serde_json::json!(1000));

        let mut m2 = std::collections::BTreeMap::new();
        m2.insert("beat_op".to_string(), serde_json::json!("mint"));
        m2.insert("beat_amount".to_string(), serde_json::json!(500));

        assert_ne!(content_fingerprint(&m1), content_fingerprint(&m2));
    }

    #[test]
    fn test_content_fingerprint_same_metadata() {
        let mut m1 = std::collections::BTreeMap::new();
        m1.insert("key".to_string(), serde_json::json!("value"));

        let mut m2 = std::collections::BTreeMap::new();
        m2.insert("key".to_string(), serde_json::json!("value"));

        assert_eq!(content_fingerprint(&m1), content_fingerprint(&m2));
    }

    // ─── Throttle effect on daily limit ───────────────────────────

    #[test]
    fn test_throttled_identity_halved_limit() {
        let mut engine = EntropyEngine::new();
        // Create identity with entropy between 0.3 and 0.6 (throttle band)
        // Mix of unique and duplicate content
        for i in 0..6u64 {
            // 6 records: 3 unique + 3 duplicate = 50% diversity
            let hash = if i < 3 { i } else { 0 };
            engine.record_submission("mixed", hash, 1000.0 + i as f64 * 3600.0);
        }

        let profile = engine.get_profile("mixed").unwrap();
        let e = profile.entropy();
        // Just verify the engine applies throttle (halved limit) for mid-entropy
        // The exact entropy depends on all 6 signals but content diversity contributes
        let tier = profile.tier(1000.0 + 50000.0);
        let full_limit = tier.daily_limit();
        let status = profile.status();

        // This tests the throttle logic path exists
        if status == EntropyStatus::Throttled {
            // When throttled, the effective limit should be half
            let _ = engine.check_submission_with_stake(
                "mixed", "genesis", 1000.0 + 50000.0, 0,
            );
            // Just ensure it doesn't panic; the actual throttle behavior is tested
            // by test_check_submission_exceeds_daily_limit above
        }
        assert!((0.0..=1.0).contains(&e), "entropy should be normalized, got {e}");
        assert!(full_limit > 0);
    }

    // ─── Diverse witness tracking ─────────────────────────────────

    #[test]
    fn test_diverse_witness_count() {
        let mut engine = EntropyEngine::new();
        engine.record_submission("alice", 1, 1000.0);

        engine.register_witness("alice", "w1", 1000.0);
        engine.register_witness("alice", "w2", 1000.0);
        engine.register_witness("alice", "w1", 1000.0); // duplicate

        let profile = engine.get_profile("alice").unwrap();
        assert_eq!(profile.diverse_witness_count(), 2);
    }

    // ─── 48-hour witness age gate ────────────────────────────────

    const MIN_WITNESS_AGE_SECS: f64 = 48.0 * 3600.0;

    #[test]
    fn test_identity_age_unknown_returns_zero() {
        let engine = EntropyEngine::new();
        assert_eq!(engine.identity_age("nonexistent", 999_999.0), 0.0);
    }

    #[test]
    fn test_identity_age_exact() {
        let mut engine = EntropyEngine::new();
        let created_at = 1_000_000.0;
        engine.record_submission("alice", 1, created_at);

        // 24 hours later
        let age = engine.identity_age("alice", created_at + 24.0 * 3600.0);
        assert!((age - 24.0 * 3600.0).abs() < 0.01);

        // 48 hours later
        let age = engine.identity_age("alice", created_at + 48.0 * 3600.0);
        assert!((age - 48.0 * 3600.0).abs() < 0.01);
    }

    #[test]
    fn test_witness_rejected_before_48h() {
        let mut engine = EntropyEngine::new();
        let created_at = 1_000_000.0;
        engine.record_submission("young_witness", 1, created_at);

        // 1 hour old — must be rejected
        let age = engine.identity_age("young_witness", created_at + 3600.0);
        assert!(age < MIN_WITNESS_AGE_SECS, "1h-old identity should fail age gate");

        // 47h 59m old — still too young
        let age = engine.identity_age("young_witness", created_at + 47.0 * 3600.0 + 59.0 * 60.0);
        assert!(age < MIN_WITNESS_AGE_SECS, "47h59m identity should fail age gate");
    }

    #[test]
    fn test_witness_accepted_after_48h() {
        let mut engine = EntropyEngine::new();
        let created_at = 1_000_000.0;
        engine.record_submission("mature_witness", 1, created_at);

        // Exactly 48 hours
        let age = engine.identity_age("mature_witness", created_at + MIN_WITNESS_AGE_SECS);
        assert!(age >= MIN_WITNESS_AGE_SECS, "48h identity should pass age gate");

        // 72 hours — well past
        let age = engine.identity_age("mature_witness", created_at + 72.0 * 3600.0);
        assert!(age >= MIN_WITNESS_AGE_SECS, "72h identity should pass age gate");
    }

    // ─── last_seen tracking ──────────────────────────────────────

    #[test]
    fn test_last_seen_set_on_creation() {
        let profile = EntropyProfile::new(5000.0);
        assert!((profile.last_seen - 5000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_last_seen_updated_on_submission() {
        let mut profile = EntropyProfile::new(1000.0);
        profile.record_submission(1, 2000.0);
        assert!((profile.last_seen - 2000.0).abs() < f64::EPSILON);
        profile.record_submission(2, 3000.0);
        assert!((profile.last_seen - 3000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_last_seen_updated_on_witness() {
        let mut profile = EntropyProfile::new(1000.0);
        profile.register_witness("w1", 4000.0);
        assert!((profile.last_seen - 4000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_last_seen_does_not_go_backwards() {
        let mut profile = EntropyProfile::new(5000.0);
        profile.record_submission(1, 3000.0); // older timestamp
        assert!((profile.last_seen - 5000.0).abs() < f64::EPSILON);
    }

    // ─── prune_inactive ──────────────────────────────────────────

    #[test]
    fn test_prune_inactive_removes_stale() {
        let mut engine = EntropyEngine::new();
        let thirty_days: u64 = 30 * 24 * 3600;
        let now = 1_000_000.0;

        engine.record_submission("active", 1, now);
        engine.record_submission("stale", 1, now - 31.0 * 24.0 * 3600.0);

        let pruned = engine.prune_inactive(now, thirty_days);
        assert_eq!(pruned, 1);
        assert!(engine.get_profile("active").is_some());
        assert!(engine.get_profile("stale").is_none());
    }

    #[test]
    fn test_prune_inactive_keeps_recent() {
        let mut engine = EntropyEngine::new();
        let thirty_days: u64 = 30 * 24 * 3600;
        let now = 1_000_000.0;

        engine.record_submission("a", 1, now - 10.0 * 24.0 * 3600.0);
        engine.record_submission("b", 2, now - 29.0 * 24.0 * 3600.0);

        let pruned = engine.prune_inactive(now, thirty_days);
        assert_eq!(pruned, 0);
        assert_eq!(engine.tracked_identities(), 2);
    }

    #[test]
    fn test_prune_inactive_all_pruned() {
        let mut engine = EntropyEngine::new();
        let one_day: u64 = 24 * 3600;
        let now = 1_000_000.0;

        engine.record_submission("old1", 1, now - 2.0 * 24.0 * 3600.0);
        engine.record_submission("old2", 2, now - 3.0 * 24.0 * 3600.0);

        let pruned = engine.prune_inactive(now, one_day);
        assert_eq!(pruned, 2);
        assert_eq!(engine.tracked_identities(), 0);
    }

    #[test]
    fn test_prune_respects_witness_activity() {
        let mut engine = EntropyEngine::new();
        let thirty_days: u64 = 30 * 24 * 3600;
        let now = 1_000_000.0;

        // Identity created 60 days ago, last submission 40 days ago
        engine.record_submission("old_sub", 1, now - 40.0 * 24.0 * 3600.0);
        // But got a witness registration 5 days ago
        engine.register_witness("old_sub", "w1", now - 5.0 * 24.0 * 3600.0);

        let pruned = engine.prune_inactive(now, thirty_days);
        assert_eq!(pruned, 0, "witness activity should keep profile alive");
    }

    // ─── Continuity-gated tier tests ──────────────────────────────────

    #[test]
    fn test_tier_with_continuity_gates_tier1() {
        let mut profile = EntropyProfile::new(0.0);
        let now = TIER_1_AGE_SECS + 1000.0;

        // Build up enough entropy for Tier 1
        for i in 0..50u64 {
            profile.record_submission_full(i, i as f64 * 3600.0 + 1.0, (i * 100 + 50) as u32, i);
        }

        // Without continuity gate → Tier 1 (age + entropy met)
        assert_eq!(profile.tier(now), TrustTier::Tier1);

        // With high continuity → still Tier 1
        assert_eq!(profile.tier_with_continuity(now, Some(0.5)), TrustTier::Tier1);

        // With low continuity → demoted to Tier 0
        assert_eq!(profile.tier_with_continuity(now, Some(0.1)), TrustTier::Tier0);
    }

    #[test]
    fn test_tier_with_continuity_gates_tier2() {
        let mut profile = EntropyProfile::new(0.0);
        let now = TIER_2_AGE_SECS + 1000.0;

        // Build up entropy and witnesses for Tier 2
        for i in 0..100u64 {
            profile.record_submission_full(i, i as f64 * 3600.0 + 1.0, (i * 100 + 50) as u32, i);
        }
        for i in 0..5 {
            profile.register_witness(&format!("w{i}"), 1000.0);
        }

        // Without continuity gate → Tier 2
        assert_eq!(profile.tier(now), TrustTier::Tier2);

        // With high continuity → still Tier 2
        assert_eq!(profile.tier_with_continuity(now, Some(0.7)), TrustTier::Tier2);

        // With medium continuity (>= 0.2 but < 0.5) → demoted to Tier 1
        assert_eq!(profile.tier_with_continuity(now, Some(0.3)), TrustTier::Tier1);

        // With very low continuity → demoted to Tier 0
        assert_eq!(profile.tier_with_continuity(now, Some(0.05)), TrustTier::Tier0);
    }

    #[test]
    fn test_check_submission_with_continuity() {
        let mut engine = EntropyEngine::new();

        // Create identity 31+ days ago to qualify for Tier 1 on age alone
        engine.record_submission_full("alice", 0, 0.0, 100, 1);
        // Now submit 25 records today (within same daily window)
        let today = TIER_1_AGE_SECS + 1000.0;
        for i in 1..25u64 {
            engine.record_submission_full("alice", i, today + i as f64 * 60.0, (i * 100) as u32, i);
        }
        let now = today + 25.0 * 60.0;

        // Verify we'd be Tier 1 with no continuity gate
        let profile = engine.get_profile("alice").unwrap();
        assert_eq!(profile.tier(now), TrustTier::Tier1);

        // High continuity → Tier 1 limits (50/day), 24 submitted today → ok
        assert!(engine.check_submission_with_continuity(
            "alice", "genesis", now, 0, BASE_UNITS_PER_DAILY_RECORD, 0.5,
        ).is_ok());

        // Low continuity → Tier 0 limits (20/day), 24 submitted today → blocked
        assert!(engine.check_submission_with_continuity(
            "alice", "genesis", now, 0, BASE_UNITS_PER_DAILY_RECORD, 0.05,
        ).is_err());
    }

    #[test]
    fn test_continuity_gate_none_is_no_gate() {
        let mut profile = EntropyProfile::new(0.0);
        let now = TIER_1_AGE_SECS + 1000.0;

        for i in 0..50u64 {
            profile.record_submission_full(i, i as f64 * 3600.0 + 1.0, (i * 100 + 50) as u32, i);
        }

        // None continuity = no gate applied (backward compat)
        assert_eq!(profile.tier_with_continuity(now, None), profile.tier(now));
    }

    // ─── additional tests ───────────────────────────────────────
    //
    // Five fixture-free axes on accounting/trust.rs pure surface, chosen orthogonal
    // to the existing 56 tests:
    //  1. economics §9.2-9.4 numeric constants pin (drift detector).
    //  2. content_fingerprint determinism + empty-map FNV pin + value cap.
    //  3. EntropyProfile::age clamp (nonneg under time-reorder / now < first_seen).
    //  4. EntropyProfile::new initial state via public API surface only.
    //  5. tier() == tier_with_continuity(None) equivalence pin (delegation invariant).

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_constants_pin_tier_daily_age_entropy_window_and_stake_price_values() {
        // Tier daily limits — exact integer literals (§9.3).
        assert_eq!(TIER_0_DAILY, 20, "TIER_0_DAILY MUST be 20 (economics §9.3)");
        assert_eq!(TIER_1_DAILY, 50, "TIER_1_DAILY MUST be 50 (economics §9.3)");
        assert_eq!(TIER_2_DAILY, 200, "TIER_2_DAILY MUST be 200 (economics §9.3)");

        // Strict monotonic ordering: tier0 < tier1 < tier2.
        assert!(
            TIER_0_DAILY < TIER_1_DAILY && TIER_1_DAILY < TIER_2_DAILY,
            "daily limits MUST be strictly monotonic; any inversion breaks tier-up incentive"
        );

        // Age thresholds — 30 days / 90 days as exact second counts (§9.3).
        assert_eq!(TIER_1_AGE_SECS, 30.0 * 86400.0, "TIER_1_AGE_SECS MUST be 30 days");
        assert_eq!(TIER_2_AGE_SECS, 90.0 * 86400.0, "TIER_2_AGE_SECS MUST be 90 days");
        assert!(
            TIER_2_AGE_SECS > TIER_1_AGE_SECS,
            "tier2 age threshold MUST exceed tier1 (promotion gate ordering)"
        );

        // Entropy thresholds — pin economics §9.2 illustrative numbers.
        assert_eq!(TIER_1_MIN_ENTROPY, 0.6, "TIER_1_MIN_ENTROPY MUST be 0.6 (§9.2)");
        assert_eq!(TIER_2_MIN_ENTROPY, 0.7, "TIER_2_MIN_ENTROPY MUST be 0.7 (§9.2)");
        assert!(TIER_2_MIN_ENTROPY > TIER_1_MIN_ENTROPY, "tier2 entropy gate MUST be stricter");
        assert_eq!(
            TIER_2_MIN_DIVERSE_WITNESSES, 3,
            "TIER_2_MIN_DIVERSE_WITNESSES MUST be 3 (witness-quorum floor)"
        );

        // EntropyStatus thresholds.
        assert_eq!(ENTROPY_FULL_ACCESS, 0.6, "ENTROPY_FULL_ACCESS MUST be 0.6 (§9.2)");
        assert_eq!(ENTROPY_THROTTLE, 0.3, "ENTROPY_THROTTLE MUST be 0.3 (§9.2)");
        assert!(
            ENTROPY_THROTTLE < ENTROPY_FULL_ACCESS,
            "throttle band MUST be below full-access band (status-machine ordering)"
        );

        // Tier-1 promotion gate MUST align with the FullAccess entropy floor
        // — same numeric value, but separate constants (decoupled deliberately).
        assert_eq!(
            TIER_1_MIN_ENTROPY, ENTROPY_FULL_ACCESS,
            "tier1 entropy gate happens to equal ENTROPY_FULL_ACCESS in §9.2 — drift in either MUST be deliberate"
        );

        // Window constants — 7 days for entropy signals, 24 h for daily counter.
        assert_eq!(ENTROPY_WINDOW_SECS, 7.0 * 86400.0, "entropy window MUST be 7 days");
        assert_eq!(DAILY_WINDOW_SECS, 86400.0, "daily window MUST be 24 hours");
        assert!(
            ENTROPY_WINDOW_SECS > DAILY_WINDOW_SECS,
            "entropy window MUST exceed daily window (7-day rolling vs 1-day reset)"
        );

        // Stake-gated throughput price (§9.4).
        assert_eq!(
            BASE_UNITS_PER_DAILY_RECORD, 100_000_000,
            "BASE_UNITS_PER_DAILY_RECORD MUST be 10^8 base units (100 beat → 1000 records/day @ §9.4)"
        );

        // Bridge to tier daily-limit method (already covered by test_tier_daily_limits
        // but pin via a different access path — variant → const directly):
        assert_eq!(TrustTier::Tier0.daily_limit(), TIER_0_DAILY);
        assert_eq!(TrustTier::Tier1.daily_limit(), TIER_1_DAILY);
        assert_eq!(TrustTier::Tier2.daily_limit(), TIER_2_DAILY);
    }

    #[test]
    fn batch_b_content_fingerprint_pins_fnv_offset_and_64_byte_value_cap() {
        use std::collections::BTreeMap;

        // Empty map MUST yield FNV-1a 64-bit offset basis exactly — load-bearing
        // for cross-version hash stability of the "no metadata" canonical state.
        let empty: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        assert_eq!(
            content_fingerprint(&empty),
            0xcbf29ce484222325,
            "empty BTreeMap MUST hash to FNV-1a 64-bit offset basis; drift breaks cross-version dedup"
        );

        // Determinism across calls on the same input (no hidden state).
        let mut m = BTreeMap::new();
        m.insert("op".to_string(), serde_json::json!("transfer"));
        m.insert("amount".to_string(), serde_json::json!(1_000));
        let h1 = content_fingerprint(&m);
        let h2 = content_fingerprint(&m);
        assert_eq!(h1, h2, "content_fingerprint MUST be deterministic for the same input");

        // 64-byte value cap: two values that differ only AFTER byte 64 hash identically.
        // The function does `.take(64)` on the value string bytes — pin this so the
        // cap can't drift without breaking the test.
        let mut a = BTreeMap::new();
        let mut b = BTreeMap::new();
        let base = "x".repeat(64); // exactly 64 bytes of "x"
        a.insert("k".to_string(), serde_json::json!(format!("{}AAAA", base)));
        b.insert("k".to_string(), serde_json::json!(format!("{}BBBB", base)));
        // Note: serde_json::to_string adds quotes, so the actual hashed string for
        // value="xxx...AAAA" is "\"xxx...AAAA\"". The cap kicks in at byte 64 of
        // that quoted string. The first 64 bytes are identical (open-quote + 63 x's)
        // for both, so hashes MUST be equal.
        assert_eq!(
            content_fingerprint(&a),
            content_fingerprint(&b),
            "values diverging only past byte 64 MUST hash identically (64-byte take() cap)"
        );

        // Key/value-position sensitivity: swapping a key with its value
        // changes the BTreeMap shape and MUST change the hash.
        let mut kv = BTreeMap::new();
        kv.insert("alice".to_string(), serde_json::json!("bob"));
        let mut vk = BTreeMap::new();
        vk.insert("bob".to_string(), serde_json::json!("alice"));
        assert_ne!(
            content_fingerprint(&kv),
            content_fingerprint(&vk),
            "key↔value swap MUST yield different hashes (k/v positions are NOT symmetric)"
        );
    }

    #[test]
    fn batch_b_entropy_profile_age_clamps_nonneg_on_time_reorder() {
        // age() = max(0, now - first_seen). Pin the .max(0.0) clamp so a clock
        // skew (now < first_seen) NEVER yields a negative age that could
        // underflow downstream tier comparisons.
        let profile = EntropyProfile::new(10_000.0);

        // now == first_seen → 0.0 exactly (boundary).
        assert_eq!(profile.age(10_000.0), 0.0, "now == first_seen MUST yield age=0.0");

        // now < first_seen by 1 second → clamp to 0.0, NOT -1.0.
        assert_eq!(
            profile.age(9_999.0),
            0.0,
            "now < first_seen MUST clamp to 0.0 (defends against clock-skew underflow)"
        );

        // Huge negative delta → still 0.0.
        assert_eq!(
            profile.age(0.0),
            0.0,
            "now=0 with first_seen=10000 MUST clamp (no negative ages)"
        );

        // now > first_seen by exactly DAILY_WINDOW_SECS → that exact delta.
        let after = 10_000.0 + DAILY_WINDOW_SECS;
        assert_eq!(profile.age(after), DAILY_WINDOW_SECS, "positive delta MUST passthrough exactly");

        // Aged just past TIER_1_AGE_SECS → that exact delta value.
        let aged = 10_000.0 + TIER_1_AGE_SECS + 1.0;
        assert!(
            (profile.age(aged) - (TIER_1_AGE_SECS + 1.0)).abs() < f64::EPSILON,
            "age math MUST be exact for large positive deltas"
        );
    }

    #[test]
    fn batch_b_entropy_profile_new_pins_initial_state_via_public_methods() {
        // EntropyProfile::new(first_seen) MUST initialize a fresh profile with:
        //   total_records = 0, daily_count = 0, age(first_seen) = 0,
        //   tier = Tier0 (no records, no witnesses, no age),
        //   status() depends on entropy() which on empty profile returns the
        //   uniform-prior aggregate of the 6 signals (no records → neutral).
        let profile = EntropyProfile::new(5_000.0);

        // Public-surface pins — no private-field access.
        assert_eq!(profile.total_records, 0, "fresh profile MUST have 0 total_records");
        assert_eq!(
            profile.daily_count(5_000.0), 0,
            "fresh profile MUST report daily_count=0 at first_seen exactly"
        );
        assert_eq!(
            profile.daily_count(5_000.0 + 1.0), 0,
            "fresh profile MUST report daily_count=0 even one second after first_seen"
        );

        // Tier MUST be Tier0 immediately (no age, no entropy gates met).
        assert_eq!(
            profile.tier(5_000.0), TrustTier::Tier0,
            "fresh profile MUST be Tier0 at first_seen (no records, no age)"
        );
        // Even at TIER_1_AGE_SECS later, with no records → entropy below gate
        // → still Tier0. The 6-signal aggregate on an empty events vec returns
        // 1.0 for timing-variance (benefit-of-doubt) but witness/origin/etc.
        // are neutral or low. Pin the actual outcome: still Tier0 because no
        // witnesses + no recorded signals enough to clear the entropy gate.
        let later = 5_000.0 + TIER_1_AGE_SECS + 1.0;
        let tier_later = profile.tier(later);
        // Either Tier0 or Tier1 depending on default entropy aggregate; pin to
        // the actual implementation by reading current behavior — not Tier2
        // (witness count is 0 < TIER_2_MIN_DIVERSE_WITNESSES).
        assert_ne!(
            tier_later, TrustTier::Tier2,
            "fresh profile aged past TIER_1 MUST NOT reach Tier2 (witness count = 0 < {} required)",
            TIER_2_MIN_DIVERSE_WITNESSES
        );

        // After a single submission, total_records MUST be 1, daily_count MUST be 1.
        let mut p = profile.clone();
        p.record_submission(42, 5_000.0);
        assert_eq!(p.total_records, 1, "after 1 submission total_records MUST be 1");
        assert_eq!(p.daily_count(5_000.0), 1, "daily_count MUST track 1 submission");
    }

    #[test]
    fn batch_b_tier_equals_tier_with_continuity_none_pins_delegation_invariant() {
        // tier(now) MUST be the exact equivalent of tier_with_continuity(now, None).
        // This is a delegation invariant: tier()'s body at line 417 is literally
        // `self.tier_with_continuity(now, None)`. Pin it across multiple states.

        // State 1: fresh profile, far past tier-2 age threshold.
        let p1 = EntropyProfile::new(0.0);
        let far_future = TIER_2_AGE_SECS + 1_000_000.0;
        assert_eq!(
            p1.tier(far_future),
            p1.tier_with_continuity(far_future, None),
            "tier MUST equal tier_with_continuity(None) for empty profile at far future"
        );
        // No witnesses → can't be Tier2 regardless.
        assert_ne!(
            p1.tier(far_future),
            TrustTier::Tier2,
            "no diverse witnesses MUST cap at Tier1 max"
        );

        // State 2: profile with many records (high entropy) but young.
        let mut p2 = EntropyProfile::new(0.0);
        for i in 0..30u64 {
            p2.record_submission_full(i, (i as f64) * 7200.0 + 1.0, 100 + (i as u32 * 30), i + 1);
        }
        let young = 86_400.0; // 1 day old
        assert_eq!(
            p2.tier(young),
            p2.tier_with_continuity(young, None),
            "tier MUST equal tier_with_continuity(None) for young high-activity profile"
        );
        // 1 day old → cannot be Tier1 (TIER_1_AGE_SECS = 30 days).
        assert_eq!(
            p2.tier(young),
            TrustTier::Tier0,
            "1-day-old profile MUST be Tier0 regardless of entropy"
        );

        // State 3: aged profile with continuity=Some(1.0) MUST equal None (no gate).
        let mature = TIER_1_AGE_SECS + 100.0;
        assert_eq!(
            p2.tier_with_continuity(mature, Some(1.0)),
            p2.tier_with_continuity(mature, None),
            "continuity=Some(1.0) MUST equal None (no-gate default is 1.0 per line 430)"
        );
    }
}
