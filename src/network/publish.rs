//! NETWORK_PUBLISH — Private-to-public DAG transition (Protocol §10.6, economics §18).
//!
//! Enables private DAG records to be published to the public DAG.
//! Publication is a metadata-tagged record referencing the source records.
//!
//! Publication modes:
//! - Snapshot: one-time bulk publication of historical records
//! - Streaming: continuous forwarding of new records as they're created
//! - Gradual: time-boxed incremental publication
//!
//! Scopes:
//! - Full: all records from source network are published
//! - Selective: only records matching criteria are published
//! - Federated: cross-network publication with trust delegation

//!
//! Spec references:
//!   @spec Protocol §10.6.3

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use crate::ZoneId;

// ─── Constants ─────────────────────────────────────────────────────────────

/// Metadata key identifying a NETWORK_PUBLISH record.
pub const PUBLISH_OP_KEY: &str = "network_publish";

/// Maximum records per single publication batch.
pub const MAX_RECORDS_PER_PUBLICATION: usize = 10_000;

/// Minimum publication depth (at least 1 record).
pub const MIN_HISTORICAL_DEPTH: u64 = 1;

/// Maximum historical depth (10 years of records at ~1/sec ≈ 315M).
pub const MAX_HISTORICAL_DEPTH: u64 = 315_000_000;

/// NETWORK_PUBLISH master switch — **disabled** pending the multi-root merge theorem.
///
/// The per-record publication model in [`PublicationState::process_publication`]
/// (imported records ENTER public consensus, `retroactive_witnessing: true`) is the
/// coin-era trust-conferral design dropped by the 2026-06-09 pivot. The 2026-06-14
/// disjoint-DAG merge audit found it unsound: `ValidationRecord::signable_bytes` carries
/// no realm/network binding, so an imported record is consensus-indistinguishable from a
/// native one, and MESH-BFT's single-network safety theorem does not cover adopting a
/// foreign realm's records as native settlement parents. The agreed reframe is
/// *inert-import*: public consensus attests the publication BUNDLE existed at an anchored
/// time, never the individual records. The reframe, the M1-M5 disjoint-DAG merge rules, the
/// finality-preservation argument, and the G1-G4 re-enable gates are specified in
/// `docs/MESH-BFT-MERGE-SEMANTICS.md`.
/// Until those gates are green this entry point is hard-disabled so the dead model cannot be
/// silently flipped on.
pub const NETWORK_PUBLISH_ENABLED: bool = false;

/// Error returned by [`PublicationState::process_publication`] while NETWORK_PUBLISH is off.
pub const NETWORK_PUBLISH_DISABLED_MSG: &str =
    "NETWORK_PUBLISH is disabled pending the multi-root merge theorem: the per-record \
     publication model is unsound (no realm binding; not covered by MESH-BFT single-network \
     safety) and is being reframed to inert bundle-attestation. See \
     docs/MESH-BFT-MERGE-SEMANTICS.md (gates G1-G4) + an internal audit.";

// ─── Types ─────────────────────────────────────────────────────────────────

/// How records transition from private to public DAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionMode {
    /// One-time bulk publication of historical records.
    Snapshot,
    /// Continuous forwarding of new records as created.
    Streaming,
    /// Time-boxed incremental publication.
    Gradual,
}

impl TransitionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Streaming => "streaming",
            Self::Gradual => "gradual",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "snapshot" => Some(Self::Snapshot),
            "streaming" => Some(Self::Streaming),
            "gradual" => Some(Self::Gradual),
            _ => None,
        }
    }
}

/// Scope of publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationScope {
    /// All records from source network are published.
    Full,
    /// Only records matching criteria are published.
    Selective,
    /// Cross-network publication with trust delegation.
    Federated,
}

impl PublicationScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Selective => "selective",
            Self::Federated => "federated",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "full" => Some(Self::Full),
            "selective" => Some(Self::Selective),
            "federated" => Some(Self::Federated),
            _ => None,
        }
    }
}

/// What metadata/content to omit during publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionPolicy {
    /// No redaction — publish everything as-is.
    None,
    /// Redact metadata values (keep keys, replace values with hashes).
    MetadataValues,
    /// Redact content (publish only content hashes, not raw content).
    Content,
    /// Redact both metadata values and content.
    Full,
}

impl RedactionPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MetadataValues => "metadata_values",
            Self::Content => "content",
            Self::Full => "full",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Self::None),
            "metadata_values" => Some(Self::MetadataValues),
            "content" => Some(Self::Content),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
}

/// A publication request parsed from record metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicationRequest {
    /// Unique identifier for this publication batch.
    pub publication_id: String,
    /// Source network identifier (private DAG).
    pub source_network_id: String,
    /// Record IDs/hashes being published.
    pub published_records: Vec<String>,
    /// Publication scope.
    pub scope: PublicationScope,
    /// Target zone on the public DAG.
    pub target_zone: ZoneId,
    /// How far back in history to publish.
    pub historical_depth: u64,
    /// What to redact.
    pub redaction_policy: RedactionPolicy,
    /// How the transition occurs.
    pub transition_mode: TransitionMode,
    /// Publisher identity hash.
    pub publisher: String,
    /// Timestamp of publication.
    pub published_at: f64,
}

/// A publication that has been processed and accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedPublication {
    pub request: PublicationRequest,
    /// Record IDs that were successfully published.
    pub accepted_records: Vec<String>,
    /// Record IDs that were rejected (e.g., already published, invalid).
    pub rejected_records: Vec<String>,
    /// Whether retroactive witnessing is enabled for these records.
    pub retroactive_witnessing: bool,
}

// ─── State ─────────────────────────────────────────────────────────────────

/// Tracks publication state across the network.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PublicationState {
    /// All processed publications by publication_id.
    pub publications: HashMap<String, ProcessedPublication>,
    /// Records that have been published (record_id → publication_id).
    pub published_records: HashMap<String, String>,
    /// Active streaming publications (source_network_id → publication_id).
    pub active_streams: HashMap<String, String>,
    /// Records eligible for retroactive witnessing (record_id → deadline timestamp).
    pub retroactive_eligible: HashMap<String, f64>,
}

/// Duration for retroactive witnessing eligibility: 30 days.
const RETROACTIVE_WITNESS_WINDOW_SECS: f64 = 30.0 * 24.0 * 3600.0;

impl PublicationState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a publication request.
    ///
    /// Hard-gated by [`NETWORK_PUBLISH_ENABLED`] (disabled). The per-record model below is
    /// dead, unsound coin-era code (see the const docs + 2026-06-14 DAG-merge audit); the
    /// gate returns [`NETWORK_PUBLISH_DISABLED_MSG`] before any mutation so it cannot be
    /// flipped on by accident. Real logic lives in `process_publication_inner`.
    pub fn process_publication(
        &mut self,
        request: PublicationRequest,
    ) -> Result<&ProcessedPublication, String> {
        if !NETWORK_PUBLISH_ENABLED {
            return Err(NETWORK_PUBLISH_DISABLED_MSG.to_string());
        }
        self.process_publication_inner(request)
    }

    /// Internal publication logic, gated by [`Self::process_publication`]. Separated so the
    /// disabled-by-default killswitch can short-circuit without losing test coverage of the
    /// underlying accept/reject + insert/get path.
    fn process_publication_inner(
        &mut self,
        request: PublicationRequest,
    ) -> Result<&ProcessedPublication, String> {
        // Validate
        if request.published_records.len() > MAX_RECORDS_PER_PUBLICATION {
            return Err(format!(
                "too many records in publication: {}, max {}",
                request.published_records.len(),
                MAX_RECORDS_PER_PUBLICATION
            ));
        }
        if request.historical_depth < MIN_HISTORICAL_DEPTH {
            return Err("historical depth must be >= 1".into());
        }
        if request.historical_depth > MAX_HISTORICAL_DEPTH {
            return Err(format!(
                "historical depth {} exceeds maximum {}",
                request.historical_depth, MAX_HISTORICAL_DEPTH
            ));
        }
        if self.publications.contains_key(&request.publication_id) {
            return Err(format!(
                "publication {} already exists",
                request.publication_id
            ));
        }

        // Classify records as accepted or rejected
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        for record_id in &request.published_records {
            if self.published_records.contains_key(record_id) {
                rejected.push(record_id.clone()); // Already published
            } else {
                accepted.push(record_id.clone());
            }
        }

        let pub_id = request.publication_id.clone();
        let now = request.published_at;

        // Register accepted records
        for record_id in &accepted {
            self.published_records
                .insert(record_id.clone(), pub_id.clone());
            // Enable retroactive witnessing for published records
            self.retroactive_eligible
                .insert(record_id.clone(), now + RETROACTIVE_WITNESS_WINDOW_SECS);
        }

        // Track streaming publications
        if request.transition_mode == TransitionMode::Streaming {
            self.active_streams
                .insert(request.source_network_id.clone(), pub_id.clone());
        }

        let processed = ProcessedPublication {
            request,
            accepted_records: accepted,
            rejected_records: rejected,
            retroactive_witnessing: true,
        };

        self.publications.insert(pub_id.clone(), processed);
        self.publications
            .get(&pub_id)
            .ok_or_else(|| format!("insert/get race in process_publication for {pub_id}"))
    }

    /// Check if a record has been published.
    pub fn is_published(&self, record_id: &str) -> bool {
        self.published_records.contains_key(record_id)
    }

    /// Check if a record is eligible for retroactive witnessing.
    pub fn is_retroactive_eligible(&self, record_id: &str, now: f64) -> bool {
        match self.retroactive_eligible.get(record_id) {
            Some(deadline) => now <= *deadline,
            None => false,
        }
    }

    /// Get the publication that includes a given record.
    pub fn publication_for_record(&self, record_id: &str) -> Option<&ProcessedPublication> {
        let pub_id = self.published_records.get(record_id)?;
        self.publications.get(pub_id)
    }

    /// Check if a source network has an active streaming publication.
    pub fn has_active_stream(&self, source_network_id: &str) -> bool {
        self.active_streams.contains_key(source_network_id)
    }

    /// Stop a streaming publication.
    pub fn stop_stream(&mut self, source_network_id: &str) -> bool {
        self.active_streams.remove(source_network_id).is_some()
    }

    /// Expire retroactive witnessing eligibility for old records.
    pub fn expire_retroactive(&mut self, now: f64) {
        self.retroactive_eligible
            .retain(|_, deadline| now <= *deadline);
    }

    /// Total number of publications.
    pub fn publication_count(&self) -> usize {
        self.publications.len()
    }

    /// Total number of published records.
    pub fn published_record_count(&self) -> usize {
        self.published_records.len()
    }

    /// Number of active streaming publications.
    pub fn active_stream_count(&self) -> usize {
        self.active_streams.len()
    }

    /// Number of records eligible for retroactive witnessing.
    pub fn retroactive_eligible_count(&self) -> usize {
        self.retroactive_eligible.len()
    }

    /// Summary for API endpoints.
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "publications": self.publication_count(),
            "published_records": self.published_record_count(),
            "active_streams": self.active_stream_count(),
            "retroactive_eligible": self.retroactive_eligible_count(),
        })
    }
}

// ─── Metadata Builders ────────────────────────────────────────────────────

/// Build metadata for a NETWORK_PUBLISH record.
#[allow(clippy::too_many_arguments)]
pub fn publish_metadata(
    publication_id: &str,
    source_network_id: &str,
    published_records: &[String],
    scope: PublicationScope,
    target_zone: ZoneId,
    historical_depth: u64,
    redaction_policy: RedactionPolicy,
    transition_mode: TransitionMode,
) -> BTreeMap<String, String> {
    let mut meta = BTreeMap::new();
    meta.insert(PUBLISH_OP_KEY.into(), "publish".into());
    meta.insert("publication_id".into(), publication_id.into());
    meta.insert("source_network_id".into(), source_network_id.into());
    meta.insert(
        "published_records".into(),
        serde_json::to_string(published_records).unwrap_or_default(),
    );
    meta.insert("scope".into(), scope.as_str().into());
    meta.insert("target_zone".into(), target_zone.to_string());
    meta.insert("historical_depth".into(), historical_depth.to_string());
    meta.insert("redaction_policy".into(), redaction_policy.as_str().into());
    meta.insert("transition_mode".into(), transition_mode.as_str().into());
    meta
}

/// Extract a publication request from record metadata.
pub fn extract_publication(
    metadata: &BTreeMap<String, String>,
    publisher: &str,
    timestamp: f64,
) -> Option<PublicationRequest> {
    if metadata.get(PUBLISH_OP_KEY)? != "publish" {
        return None;
    }

    let publication_id = metadata.get("publication_id")?.clone();
    let source_network_id = metadata.get("source_network_id")?.clone();
    let records_json = metadata.get("published_records")?;
    let published_records: Vec<String> = serde_json::from_str(records_json).ok()?;
    let scope = PublicationScope::parse(metadata.get("scope")?)?;
    let target_zone: ZoneId = ZoneId::new(metadata.get("target_zone")?);
    let historical_depth: u64 = metadata.get("historical_depth")?.parse().ok()?;
    let redaction_policy = RedactionPolicy::parse(metadata.get("redaction_policy")?)?;
    let transition_mode = TransitionMode::parse(metadata.get("transition_mode")?)?;

    Some(PublicationRequest {
        publication_id,
        source_network_id,
        published_records,
        scope,
        target_zone,
        historical_depth,
        redaction_policy,
        transition_mode,
        publisher: publisher.to_string(),
        published_at: timestamp,
    })
}

// ─── Redaction ─────────────────────────────────────────────────────────────

/// Apply a redaction policy to record metadata.
/// Returns the redacted metadata (original is not modified).
pub fn apply_redaction(
    metadata: &BTreeMap<String, serde_json::Value>,
    policy: RedactionPolicy,
) -> BTreeMap<String, serde_json::Value> {
    match policy {
        RedactionPolicy::None => metadata.clone(),
        RedactionPolicy::MetadataValues => {
            // Keep keys, replace values with "[REDACTED]"
            metadata
                .keys()
                .map(|k| (k.clone(), serde_json::Value::String("[REDACTED]".into())))
                .collect()
        }
        RedactionPolicy::Content => {
            // Content redaction happens at a different layer (content_hash only)
            // Metadata stays intact
            metadata.clone()
        }
        RedactionPolicy::Full => {
            // Replace all values and mark as fully redacted
            let mut redacted: BTreeMap<String, serde_json::Value> = metadata
                .keys()
                .map(|k| (k.clone(), serde_json::Value::String("[REDACTED]".into())))
                .collect();
            redacted.insert(
                "_redaction".into(),
                serde_json::Value::String("full".into()),
            );
            redacted
        }
    }
}

// ─── Cross-Network Verification ───────────────────────────────────────────

/// Verify that a set of record hashes match their claimed source.
/// In production, this would verify cryptographic proofs of private DAG origin.
/// For now, structural validation only.
pub fn verify_publication_integrity(
    published_records: &[String],
    source_network_id: &str,
) -> Result<(), String> {
    if published_records.is_empty() {
        return Err("publication must include at least one record".into());
    }
    if source_network_id.is_empty() {
        return Err("source network ID is required".into());
    }
    if published_records.len() > MAX_RECORDS_PER_PUBLICATION {
        return Err(format!(
            "too many records: {}, max {}",
            published_records.len(),
            MAX_RECORDS_PER_PUBLICATION
        ));
    }

    // Check for duplicates within the publication
    let unique: HashSet<&String> = published_records.iter().collect();
    if unique.len() != published_records.len() {
        return Err("duplicate record IDs in publication".into());
    }

    Ok(())
}

// ─── Mega-Publication Rate Limits (economics §18.9) ─────────────────────

/// Publication rate scaling factor: 1% baseline.
const PUBLICATION_RATE_FACTOR: f64 = 0.01;

/// Maximum token acquisition rate: 0.5% of circulating supply per 30 days.
const MAX_ACQUISITION_RATE_PER_30D: f64 = 0.005;

/// Vesting multiplier: publication_duration × 0.5.
const VESTING_DURATION_MULTIPLIER: f64 = 0.5;

/// Conservation contribution threshold: publications > 5% of public DAG.
const CONSERVATION_THRESHOLD_FRACTION: f64 = 0.05;

/// Conservation contribution rate: 10% of storage delegation beats.
const CONSERVATION_CONTRIBUTION_RATE: f64 = 0.10;

/// Scaled publication rate limit (economics §18.9 Formula 1).
///
/// `max_records_per_day = public_dag_size × 0.01 / (1 + publisher_dag_size / public_dag_size)`
///
/// This creates a natural throttle: small publishers can publish quickly,
/// but mega-publishers (10×+ the public DAG) take months or years.
pub fn max_records_per_day(public_dag_size: u64, publisher_dag_size: u64) -> f64 {
    if public_dag_size == 0 {
        return 0.0;
    }
    let public = public_dag_size as f64;
    let publisher = publisher_dag_size as f64;
    public * PUBLICATION_RATE_FACTOR / (1.0 + publisher / public)
}

/// Token acquisition velocity constraint (economics §18.9 Formula 2).
///
/// Returns the maximum beat that can be acquired in a 30-day period.
/// `max_acquisition = circulating_supply × 0.005`
pub fn max_token_acquisition_30d(circulating_supply: u64) -> u64 {
    (circulating_supply as f64 * MAX_ACQUISITION_RATE_PER_30D) as u64
}

/// Vesting period for acquired beats during publication (economics §18.9 Formula 2).
///
/// `vesting_period_secs = publication_duration_secs × 0.5`
///
/// Whichever constraint (acquisition rate or vesting) is tighter applies.
pub fn publication_vesting_period_secs(publication_duration_secs: f64) -> f64 {
    publication_duration_secs * VESTING_DURATION_MULTIPLIER
}

/// Conservation contribution rate (economics §18.9 Formula 3).
///
/// `contribution_rate = (publication_size / public_dag_size) × 0.10`
///
/// Only applies when publication exceeds 5% of the public DAG.
/// Returns the fraction of storage delegation beats that must be
/// redirected to the Conservation Pool.
pub fn conservation_contribution(publication_size: u64, public_dag_size: u64) -> f64 {
    if public_dag_size == 0 {
        return 0.0;
    }
    let fraction = publication_size as f64 / public_dag_size as f64;
    if fraction <= CONSERVATION_THRESHOLD_FRACTION {
        return 0.0;
    }
    fraction * CONSERVATION_CONTRIBUTION_RATE
}

/// Attention economy dampening factor (economics §18.9 Formula 4).
///
/// `attention_dampening = 1 / (1 + log₂(entity_size / median_size))`
///
/// A publisher 1,000× the median size earns ~9% of the baseline attention
/// rate per record. Returns 1.0 (no dampening) if entity <= median.
pub fn attention_dampening(entity_publication_size: u64, median_participant_size: u64) -> f64 {
    if median_participant_size == 0 || entity_publication_size <= median_participant_size {
        return 1.0;
    }
    let ratio = entity_publication_size as f64 / median_participant_size as f64;
    1.0 / (1.0 + ratio.log2())
}

/// Full mega-publication assessment: evaluates all four defense mechanisms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MegaPublicationAssessment {
    /// Maximum records this publisher can publish per day.
    pub max_records_per_day: f64,
    /// Days needed to publish the entire private DAG.
    pub estimated_days_to_publish: f64,
    /// Maximum beat acquirable in 30 days.
    pub max_acquisition_30d: u64,
    /// Required vesting period (seconds) for acquired beats.
    pub vesting_period_secs: f64,
    /// Fraction of storage delegation beats redirected to Conservation Pool.
    /// 0.0 if publication is below 5% threshold.
    pub conservation_contribution: f64,
    /// Attention dampening factor (0.0-1.0). Lower = more dampened.
    pub attention_factor: f64,
    /// Whether this publication triggers mega-publication constraints.
    pub is_mega: bool,
}

/// Assess all mega-publication constraints for a publisher.
pub fn assess_mega_publication(
    publisher_dag_size: u64,
    public_dag_size: u64,
    circulating_supply: u64,
    median_participant_size: u64,
) -> MegaPublicationAssessment {
    let rate = max_records_per_day(public_dag_size, publisher_dag_size);
    let days = if rate > 0.0 {
        publisher_dag_size as f64 / rate
    } else {
        f64::INFINITY
    };

    // Publication duration in seconds (days × 86400)
    let pub_duration_secs = days * 86400.0;
    let vesting = publication_vesting_period_secs(pub_duration_secs);
    let acq = max_token_acquisition_30d(circulating_supply);
    let cons = conservation_contribution(publisher_dag_size, public_dag_size);
    let attention = attention_dampening(publisher_dag_size, median_participant_size);

    // A publication is "mega" if it exceeds the conservation threshold (5% of public DAG)
    let is_mega = public_dag_size > 0
        && (publisher_dag_size as f64 / public_dag_size as f64) > CONSERVATION_THRESHOLD_FRACTION;

    MegaPublicationAssessment {
        max_records_per_day: rate,
        estimated_days_to_publish: days,
        max_acquisition_30d: acq,
        vesting_period_secs: vesting,
        conservation_contribution: cons,
        attention_factor: attention,
        is_mega,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request(n_records: usize) -> PublicationRequest {
        let records: Vec<String> = (0..n_records).map(|i| format!("rec-{i}")).collect();
        PublicationRequest {
            publication_id: "pub-001".into(),
            source_network_id: "private-net-alpha".into(),
            published_records: records,
            scope: PublicationScope::Full,
            target_zone: ZoneId::from_legacy(42),
            historical_depth: 1000,
            redaction_policy: RedactionPolicy::None,
            transition_mode: TransitionMode::Snapshot,
            publisher: "alice".into(),
            published_at: 1000.0,
        }
    }

    #[test]
    fn test_process_publication() {
        let mut state = PublicationState::new();
        let req = sample_request(5);
        let result = state.process_publication_inner(req);
        assert!(result.is_ok());
        let pub_result = result.unwrap();
        assert_eq!(pub_result.accepted_records.len(), 5);
        assert_eq!(pub_result.rejected_records.len(), 0);
        assert_eq!(state.published_record_count(), 5);
    }

    #[test]
    fn test_duplicate_records_rejected() {
        let mut state = PublicationState::new();
        let req1 = sample_request(3);
        state.process_publication_inner(req1).unwrap();

        // Second publication with overlapping records
        let req2 = PublicationRequest {
            publication_id: "pub-002".into(),
            published_records: vec!["rec-0".into(), "rec-1".into(), "rec-new".into()],
            ..sample_request(0)
        };
        let result = state.process_publication_inner(req2).unwrap();
        assert_eq!(result.accepted_records.len(), 1); // only rec-new
        assert_eq!(result.rejected_records.len(), 2); // rec-0, rec-1 already published
    }

    #[test]
    fn test_duplicate_publication_id_rejected() {
        let mut state = PublicationState::new();
        let req = sample_request(2);
        state.process_publication_inner(req).unwrap();

        let req2 = sample_request(2);
        let result = state.process_publication_inner(req2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[test]
    fn test_too_many_records() {
        let mut state = PublicationState::new();
        let req = sample_request(MAX_RECORDS_PER_PUBLICATION + 1);
        let result = state.process_publication_inner(req);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too many records"));
    }

    #[test]
    fn test_is_published() {
        let mut state = PublicationState::new();
        let req = sample_request(3);
        state.process_publication_inner(req).unwrap();

        assert!(state.is_published("rec-0"));
        assert!(state.is_published("rec-2"));
        assert!(!state.is_published("rec-99"));
    }

    #[test]
    fn test_retroactive_witnessing_eligibility() {
        let mut state = PublicationState::new();
        let req = sample_request(2);
        state.process_publication_inner(req).unwrap();

        // Within 30-day window
        assert!(state.is_retroactive_eligible("rec-0", 1000.0 + 86400.0));
        // After 30-day window
        assert!(!state.is_retroactive_eligible(
            "rec-0",
            1000.0 + RETROACTIVE_WITNESS_WINDOW_SECS + 1.0
        ));
    }

    #[test]
    fn test_expire_retroactive() {
        let mut state = PublicationState::new();
        let req = sample_request(5);
        state.process_publication_inner(req).unwrap();
        assert_eq!(state.retroactive_eligible_count(), 5);

        // Expire after 30 days
        state.expire_retroactive(1000.0 + RETROACTIVE_WITNESS_WINDOW_SECS + 1.0);
        assert_eq!(state.retroactive_eligible_count(), 0);
    }

    #[test]
    fn test_streaming_publication() {
        let mut state = PublicationState::new();
        let mut req = sample_request(2);
        req.transition_mode = TransitionMode::Streaming;
        state.process_publication_inner(req).unwrap();

        assert!(state.has_active_stream("private-net-alpha"));
        assert_eq!(state.active_stream_count(), 1);

        // Stop stream
        assert!(state.stop_stream("private-net-alpha"));
        assert!(!state.has_active_stream("private-net-alpha"));
    }

    #[test]
    fn test_metadata_roundtrip() {
        let records = vec!["rec-1".into(), "rec-2".into()];
        let meta = publish_metadata(
            "pub-001",
            "private-net",
            &records,
            PublicationScope::Selective,
            ZoneId::from_legacy(42),
            500,
            RedactionPolicy::MetadataValues,
            TransitionMode::Gradual,
        );

        let parsed = extract_publication(&meta, "alice", 1000.0).unwrap();
        assert_eq!(parsed.publication_id, "pub-001");
        assert_eq!(parsed.source_network_id, "private-net");
        assert_eq!(parsed.published_records.len(), 2);
        assert_eq!(parsed.scope, PublicationScope::Selective);
        assert_eq!(parsed.target_zone, 42);
        assert_eq!(parsed.historical_depth, 500);
        assert_eq!(parsed.redaction_policy, RedactionPolicy::MetadataValues);
        assert_eq!(parsed.transition_mode, TransitionMode::Gradual);
    }

    #[test]
    fn test_redaction_none() {
        let mut meta = BTreeMap::new();
        meta.insert("key1".into(), serde_json::Value::String("value1".into()));
        meta.insert("key2".into(), serde_json::Value::Number(42.into()));

        let redacted = apply_redaction(&meta, RedactionPolicy::None);
        assert_eq!(redacted, meta);
    }

    #[test]
    fn test_redaction_metadata_values() {
        let mut meta = BTreeMap::new();
        meta.insert("key1".into(), serde_json::Value::String("secret".into()));
        meta.insert("key2".into(), serde_json::Value::Number(42.into()));

        let redacted = apply_redaction(&meta, RedactionPolicy::MetadataValues);
        assert_eq!(
            redacted.get("key1"),
            Some(&serde_json::Value::String("[REDACTED]".into()))
        );
        assert_eq!(
            redacted.get("key2"),
            Some(&serde_json::Value::String("[REDACTED]".into()))
        );
    }

    #[test]
    fn test_redaction_full() {
        let mut meta = BTreeMap::new();
        meta.insert("key1".into(), serde_json::Value::String("secret".into()));

        let redacted = apply_redaction(&meta, RedactionPolicy::Full);
        assert!(redacted.contains_key("_redaction"));
    }

    #[test]
    fn test_verify_integrity_valid() {
        let records = vec!["rec-1".into(), "rec-2".into()];
        assert!(verify_publication_integrity(&records, "net-1").is_ok());
    }

    #[test]
    fn test_verify_integrity_empty_records() {
        let result = verify_publication_integrity(&[], "net-1");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_integrity_empty_source() {
        let records = vec!["rec-1".into()];
        let result = verify_publication_integrity(&records, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_integrity_duplicate_records() {
        let records = vec!["rec-1".into(), "rec-1".into()];
        let result = verify_publication_integrity(&records, "net-1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate"));
    }

    #[test]
    fn test_publication_for_record() {
        let mut state = PublicationState::new();
        let req = sample_request(3);
        state.process_publication_inner(req).unwrap();

        let pub_info = state.publication_for_record("rec-1").unwrap();
        assert_eq!(pub_info.request.publication_id, "pub-001");
        assert!(state.publication_for_record("rec-99").is_none());
    }

    #[test]
    fn test_summary() {
        let mut state = PublicationState::new();
        let req = sample_request(5);
        state.process_publication_inner(req).unwrap();

        let s = state.summary();
        assert_eq!(s["publications"], 1);
        assert_eq!(s["published_records"], 5);
    }

    // ─── Mega-Publication Rate Limit Tests (economics §18.9) ────────────

    #[test]
    fn test_rate_limit_small_publisher() {
        // Small publisher: 1% of network → ~1 day
        // public=1_000_000, publisher=10_000 (1%)
        // max = 1M × 0.01 / (1 + 10K/1M) = 10_000 / 1.01 ≈ 9,901
        let rate = max_records_per_day(1_000_000, 10_000);
        assert!(rate > 9_900.0 && rate < 10_000.0);
        // Days to publish: 10_000 / 9_901 ≈ 1.01
        let days = 10_000.0 / rate;
        assert!(days > 0.9 && days < 1.2);
    }

    #[test]
    fn test_rate_limit_equal_publisher() {
        // Equal-sized publisher: 100% → slower
        // public=1_000_000, publisher=1_000_000
        // max = 1M × 0.01 / (1 + 1) = 10_000 / 2 = 5,000
        let rate = max_records_per_day(1_000_000, 1_000_000);
        assert!((rate - 5_000.0).abs() < 1.0);
        // Days: 1M / 5K = 200 days ≈ 7 months
        let days = 1_000_000.0 / rate;
        assert!(days > 199.0 && days < 201.0);
    }

    #[test]
    fn test_rate_limit_mega_publisher() {
        // 10× publisher: much slower
        // public=1_000_000, publisher=10_000_000
        // max = 1M × 0.01 / (1 + 10) = 10_000 / 11 ≈ 909
        let rate = max_records_per_day(1_000_000, 10_000_000);
        assert!(rate > 900.0 && rate < 920.0);
        // Days: 10M / 909 ≈ 11,001 days ≈ 30 years
        let days = 10_000_000.0 / rate;
        assert!(days > 10_000.0 && days < 12_000.0);
    }

    #[test]
    fn test_rate_limit_zero_public_dag() {
        assert_eq!(max_records_per_day(0, 100), 0.0);
    }

    #[test]
    fn test_rate_limit_zero_publisher() {
        // Empty publisher: rate = public × 0.01 / (1 + 0) = public × 0.01
        let rate = max_records_per_day(1_000_000, 0);
        assert!((rate - 10_000.0).abs() < 0.01);
    }

    #[test]
    fn test_token_acquisition_velocity() {
        // 1 billion beat circulating → max 5M per 30 days (0.5%)
        let max = max_token_acquisition_30d(1_000_000_000);
        assert_eq!(max, 5_000_000);
    }

    #[test]
    fn test_vesting_period() {
        // 30-year publication → 15-year vesting
        let thirty_years_secs = 30.0 * 365.25 * 86400.0;
        let vesting = publication_vesting_period_secs(thirty_years_secs);
        let fifteen_years_secs = 15.0 * 365.25 * 86400.0;
        assert!((vesting - fifteen_years_secs).abs() < 1.0);
    }

    #[test]
    fn test_conservation_below_threshold() {
        // 4% of DAG → no conservation contribution
        assert_eq!(conservation_contribution(40_000, 1_000_000), 0.0);
    }

    #[test]
    fn test_conservation_at_threshold() {
        // 5% exactly → still no contribution (must exceed)
        assert_eq!(conservation_contribution(50_000, 1_000_000), 0.0);
    }

    #[test]
    fn test_conservation_above_threshold() {
        // 30% of DAG → contribution = 0.30 × 0.10 = 0.03 (3%)
        let contrib = conservation_contribution(300_000, 1_000_000);
        assert!((contrib - 0.03).abs() < 0.001);
    }

    #[test]
    fn test_conservation_zero_dag() {
        assert_eq!(conservation_contribution(100, 0), 0.0);
    }

    #[test]
    fn test_attention_dampening_equal() {
        // Entity = median → no dampening
        assert_eq!(attention_dampening(100, 100), 1.0);
    }

    #[test]
    fn test_attention_dampening_smaller() {
        // Entity < median → no dampening
        assert_eq!(attention_dampening(50, 100), 1.0);
    }

    #[test]
    fn test_attention_dampening_1000x() {
        // 1,000× median → 1 / (1 + log₂(1000)) ≈ 1 / (1 + 9.97) ≈ 0.091
        let factor = attention_dampening(100_000, 100);
        assert!(factor > 0.08 && factor < 0.10);
    }

    #[test]
    fn test_attention_dampening_zero_median() {
        assert_eq!(attention_dampening(100, 0), 1.0);
    }

    #[test]
    fn test_mega_assessment_small_publisher() {
        let a = assess_mega_publication(10_000, 1_000_000, 1_000_000_000, 1_000);
        assert!(!a.is_mega); // 1% < 5% threshold
        assert!(a.max_records_per_day > 9_000.0);
        assert_eq!(a.conservation_contribution, 0.0);
    }

    #[test]
    fn test_mega_assessment_mega_publisher() {
        let a = assess_mega_publication(10_000_000, 1_000_000, 1_000_000_000, 1_000);
        assert!(a.is_mega); // 1,000% > 5% threshold
        assert!(a.conservation_contribution > 0.0);
        assert!(a.attention_factor < 1.0);
        assert!(a.estimated_days_to_publish > 10_000.0);
        assert_eq!(a.max_acquisition_30d, 5_000_000);
    }

    // ─── economics §18.9 invariants ──────────────────────────────────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_publish_constants_strict_pin_economics_18_9_factors() {
        // Whitepaper §18.9 fixes the four scaling factors. A silent drift in
        // any constant changes the mainnet economics — pin exact values plus
        // cross-invariants (acquisition stricter than publication, etc.).
        assert_eq!(PUBLICATION_RATE_FACTOR, 0.01);
        assert_eq!(MAX_ACQUISITION_RATE_PER_30D, 0.005);
        assert_eq!(VESTING_DURATION_MULTIPLIER, 0.5);
        assert_eq!(CONSERVATION_THRESHOLD_FRACTION, 0.05);
        assert_eq!(CONSERVATION_CONTRIBUTION_RATE, 0.10);
        assert_eq!(RETROACTIVE_WITNESS_WINDOW_SECS, 30.0 * 24.0 * 3600.0);

        // Cross-invariants
        assert!(
            PUBLICATION_RATE_FACTOR > MAX_ACQUISITION_RATE_PER_30D,
            "publication rate (1%) must exceed acquisition rate (0.5%)"
        );
        assert!(
            CONSERVATION_CONTRIBUTION_RATE > CONSERVATION_THRESHOLD_FRACTION,
            "contribution rate (10%) must exceed threshold (5%) so triggering contributes meaningfully"
        );
        assert!(
            VESTING_DURATION_MULTIPLIER > 0.0 && VESTING_DURATION_MULTIPLIER <= 1.0,
            "vesting multiplier must be in (0, 1] — half-duration vesting"
        );
    }

    #[test]
    fn batch_b_max_records_per_day_strictly_monotonic_decreasing_in_publisher_size() {
        // Formula 1: rate = public × 0.01 / (1 + publisher/public)
        // As publisher_dag_size grows, denominator grows, rate strictly
        // decreases. Pin monotonicity across 6 orders of magnitude so a
        // future formula refactor that, e.g., flips the ratio direction
        // surfaces here, not in production economics.
        let public = 1_000_000u64;
        let mut prev = max_records_per_day(public, 0);
        for publisher in [1_000u64, 10_000, 100_000, 1_000_000, 10_000_000] {
            let cur = max_records_per_day(public, publisher);
            assert!(
                cur < prev,
                "rate must strictly decrease as publisher grows: prev={prev} cur={cur} at publisher={publisher}",
            );
            assert!(cur > 0.0, "rate must remain strictly positive: {cur} at publisher={publisher}");
            prev = cur;
        }
    }

    #[test]
    fn batch_b_attention_dampening_strictly_monotonic_decreasing_above_median() {
        // Formula 4: factor = 1 / (1 + log₂(entity / median)) when entity > median.
        // Strictly decreasing in entity. Pin across 5 orders of magnitude.
        let median = 100u64;
        let mut prev = attention_dampening(median + 1, median);
        assert!(prev < 1.0 && prev > 0.0, "just-above factor must be in (0, 1): {prev}");

        for entity in [200u64, 1_000, 10_000, 100_000, 1_000_000, 10_000_000] {
            let cur = attention_dampening(entity, median);
            assert!(
                cur < prev,
                "factor must strictly decrease as entity grows: prev={prev} cur={cur} at entity={entity}",
            );
            assert!(cur > 0.0, "factor must remain strictly positive: {cur}");
            prev = cur;
        }
    }

    #[test]
    fn batch_b_conservation_contribution_strict_less_than_or_equal_threshold_returns_zero() {
        // The branch is `if fraction <= CONSERVATION_THRESHOLD_FRACTION { return 0.0; }`.
        // Existing tests pin at-threshold (50_000 / 1_000_000 = 0.05) → 0.0 and
        // above-threshold (300_000 / 1M = 0.30) → 0.03. This axis pins the
        // STRICTLY-just-above edge — a fraction one publisher-record above 5%
        // must yield strictly positive contribution. Catches a future flip
        // from `<=` to `<` (which would silently exempt at-threshold callers).
        let at = conservation_contribution(50_000, 1_000_000);
        let just_above = conservation_contribution(50_001, 1_000_000);
        assert_eq!(at, 0.0, "exactly at 5% threshold must yield 0.0");
        assert!(
            just_above > 0.0,
            "just-above 5% (50001/1M = 0.050001) must yield strictly positive: got {just_above}",
        );
        // Expected ≈ 0.050001 × 0.10 = 0.0050001
        assert!(
            just_above < 0.0051 && just_above > 0.005,
            "just-above value ≈ 0.005 ± rounding: got {just_above}",
        );
    }

    #[test]
    fn batch_b_max_token_acquisition_30d_proportional_scaling_to_supply() {
        // Formula 2: acquisition = supply × 0.005, truncated to u64. Existing
        // test pins one value (1B → 5M). Pin LINEAR PROPORTIONALITY: doubling
        // supply doubles acquisition, across the spectrum from 1K → 10B. A
        // future refactor that changes the formula to logarithmic or adds a
        // cap silently breaks this.
        assert_eq!(max_token_acquisition_30d(0), 0);
        assert_eq!(max_token_acquisition_30d(1_000), 5);
        assert_eq!(max_token_acquisition_30d(1_000_000), 5_000);
        assert_eq!(max_token_acquisition_30d(1_000_000_000), 5_000_000);
        assert_eq!(max_token_acquisition_30d(10_000_000_000), 50_000_000);

        // Doubling supply doubles acquisition (within u64 precision)
        for base in [1_000_000u64, 100_000_000, 1_000_000_000] {
            let a = max_token_acquisition_30d(base);
            let b = max_token_acquisition_30d(base * 2);
            assert_eq!(
                b,
                a * 2,
                "doubling supply must double acquisition: base={base} a={a} b={b}",
            );
        }
    }

    #[test]
    fn process_publication_returns_reference_to_inserted_entry() {
        // Regression: the insert/get path previously panicked via expect() on the
        // HashMap get after insert. Now returns Err instead of crashing. Calls the
        // inner fn directly because the public entry point is hard-disabled by the
        // NETWORK_PUBLISH killswitch (tested separately below) — this preserves
        // coverage of the underlying logic.
        let mut state = PublicationState::new();
        let req = sample_request(3);
        let pub_id = req.publication_id.clone();
        let entry = state.process_publication_inner(req).expect("must succeed");
        assert_eq!(entry.request.publication_id, pub_id);
        assert_eq!(entry.accepted_records.len(), 3);
    }

    #[test]
    fn network_publish_is_hard_disabled_by_default() {
        // NETWORK_PUBLISH implements the dropped coin-era per-record trust-conferral
        // model (2026-06-14 disjoint-DAG-merge audit: unsound, no realm binding in
        // record signing). It must stay hard-disabled until the inert bundle-attestation
        // reframe lands, so the dead model cannot be flipped on by accident.
        // Compile-time guard: flipping NETWORK_PUBLISH_ENABLED on without removing
        // this assertion fails the build — the dropped per-record model cannot be
        // re-enabled by accident until the multi-root merge theorem lands.
        const _: () = assert!(
            !NETWORK_PUBLISH_ENABLED,
            "NETWORK_PUBLISH must remain disabled until the multi-root merge theorem lands"
        );
        let mut state = PublicationState::new();
        let err = state
            .process_publication(sample_request(3))
            .expect_err("must be rejected while disabled");
        assert!(err.contains("disabled"), "error must explain the killswitch: {err}");
        // The gate must reject BEFORE any mutation.
        assert!(state.publications.is_empty(), "no publication may be recorded while disabled");
        assert!(
            state.published_records.is_empty(),
            "no record may be marked published while disabled"
        );
        assert!(state.active_streams.is_empty());
        assert!(state.retroactive_eligible.is_empty());
    }
}
