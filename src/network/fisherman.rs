//! Fisherman slashing — staked challengers report protocol violations.
//!
//! economics §10.2: any staked identity can file a CHALLENGE record with evidence.
//! A VRF-seeded random jury evaluates the evidence. >75% supermajority required.
//! Appeal mechanism: challenged verdict triggers new, larger jury.
//!
//! Challenge types (§10.2):
//! - Spam: indiscriminate witnessing, 10% slash
//! - False witnessing: attesting invalid records, 25% slash
//! - Double signing: equivocation (already auto-detected), 50% slash
//! - Cartel formation: coordinated Sybil, 25% per member

//!
//! Spec references:
//!   @spec Protocol §11.1
//!   @spec economics §10

use std::collections::HashMap;

use crate::crypto::hash::sha3_256;
use crate::errors::{ElaraError, Result};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Metadata key for fisherman challenge operations.
pub const CHALLENGE_OP_KEY: &str = "challenge_op";

/// Default jury size for initial challenges.
/// Increased from 5 to 13 (higher barrier for sybil manipulation).
pub const DEFAULT_JURY_SIZE: usize = 13;
/// Jury size for appeals (doubled).
pub const APPEAL_JURY_SIZE: usize = 26;
/// Supermajority threshold (75%).
pub const SUPERMAJORITY_THRESHOLD: f64 = 0.75;
/// Minimum stake required to file a challenge (10 beat, in base units / 10^9).
/// The bare `10_000_000` was a stale pre-10^9-migration literal resolving to
/// 0.01 beat, which made frivolous fraud-challenge filings ~1000x too cheap.
pub const MIN_CHALLENGE_STAKE: u64 = 10 * crate::accounting::types::BASE_UNITS_PER_BEAT;
/// Challenge evidence window (seconds).
pub const CHALLENGE_EVIDENCE_WINDOW_SECS: f64 = 7.0 * 86_400.0; // 7 days
/// Jury voting window (seconds).
pub const JURY_VOTING_WINDOW_SECS: f64 = 3.0 * 86_400.0; // 3 days
/// Appeal window after verdict (seconds).
pub const APPEAL_WINDOW_SECS: f64 = 2.0 * 86_400.0; // 2 days

/// Slash percentages by challenge type.
pub fn slash_percent(challenge_type: &ChallengeType) -> f64 {
    match challenge_type {
        ChallengeType::Spam => 0.10,
        ChallengeType::FalseWitnessing => 0.25,
        ChallengeType::DoubleSigning => 0.50,
        ChallengeType::CartelFormation => 0.25,
    }
}

// ─── Types ───────────────────────────────────────────────────────────────────

/// Types of protocol violations that can be challenged.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    /// Indiscriminate witnessing (low-quality attestations).
    Spam,
    /// Attesting invalid or fraudulent records.
    FalseWitnessing,
    /// Equivocation: attesting conflicting records.
    DoubleSigning,
    /// Coordinated Sybil attack among colluding witnesses.
    CartelFormation,
}

impl ChallengeType {
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "spam" => Some(Self::Spam),
            "false_witnessing" => Some(Self::FalseWitnessing),
            "double_signing" => Some(Self::DoubleSigning),
            "cartel_formation" => Some(Self::CartelFormation),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Spam => "spam",
            Self::FalseWitnessing => "false_witnessing",
            Self::DoubleSigning => "double_signing",
            Self::CartelFormation => "cartel_formation",
        }
    }
}

/// Challenge lifecycle status.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    /// Filed, awaiting jury selection.
    Filed,
    /// Jury selected, voting in progress.
    JuryVoting,
    /// Verdict reached, in appeal window.
    Verdict,
    /// Appeal filed, new jury voting.
    Appeal,
    /// Final verdict (no more appeals).
    Final,
    /// Challenge dismissed (insufficient evidence or lost vote).
    Dismissed,
}

impl ChallengeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::JuryVoting => "jury_voting",
            Self::Verdict => "verdict",
            Self::Appeal => "appeal",
            Self::Final => "final",
            Self::Dismissed => "dismissed",
        }
    }
}

/// A jury member's vote.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JuryVote {
    /// Juror identity hash.
    pub juror: String,
    /// true = guilty, false = not guilty.
    pub guilty: bool,
    /// When the vote was cast.
    pub timestamp: f64,
}

/// A fisherman challenge.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Challenge {
    /// Challenge ID (= record ID of the challenge filing).
    pub id: String,
    /// Who filed the challenge.
    pub challenger: String,
    /// Who is accused.
    pub accused: String,
    /// Type of violation.
    pub challenge_type: ChallengeType,
    /// Evidence (legacy: record IDs or descriptions).
    pub evidence: Vec<String>,
    /// Structured evidence with Merkle proofs (new format).
    /// When present, jury can verify evidence cryptographically.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub structured_evidence: Vec<ChallengeEvidence>,
    /// When filed.
    pub filed_at: f64,
    /// Current status.
    pub status: ChallengeStatus,
    /// Selected jury members.
    pub jury: Vec<String>,
    /// Votes cast by jury members.
    pub votes: Vec<JuryVote>,
    /// Whether this is an appeal round.
    pub is_appeal: bool,
    /// Verdict: true = guilty, false = not guilty, None = pending.
    pub verdict: Option<bool>,
    /// When verdict was reached.
    pub verdict_at: Option<f64>,
    /// Slash amount if guilty (base units).
    pub slash_amount: Option<u64>,
}

impl Challenge {
    /// Count guilty / not-guilty votes.
    pub fn vote_tally(&self) -> (usize, usize) {
        let guilty = self.votes.iter().filter(|v| v.guilty).count();
        let not_guilty = self.votes.len() - guilty;
        (guilty, not_guilty)
    }

    /// Check if supermajority has been reached.
    pub fn has_supermajority(&self) -> Option<bool> {
        if self.votes.len() < self.jury.len() {
            return None; // Not all votes in
        }
        let (guilty, _) = self.vote_tally();
        // Integer supermajority on the consensus verdict path: with
        // SUPERMAJORITY_THRESHOLD = 3/4, `guilty/jury_len >= 3/4` is exactly
        // `guilty*4 >= jury_len*3`. Avoids an f64 ratio entirely (defense-in-depth,
        // matches the settlement fixed-point determinism pattern) and removes any
        // boundary-rounding ambiguity. jury_len <= 13 so no overflow.
        Some(guilty.saturating_mul(4) >= self.jury.len().saturating_mul(3))
    }

    /// Whether the appeal window is still open.
    pub fn in_appeal_window(&self, now: f64) -> bool {
        if self.is_appeal {
            return false; // Can't appeal an appeal
        }
        match self.verdict_at {
            Some(t) => now - t < APPEAL_WINDOW_SECS,
            None => false,
        }
    }
}

/// A single piece of evidence in a fisherman challenge.
///
/// Evidence items are cryptographically verifiable: each references a record
/// by ID and includes a Merkle inclusion proof against the zone's tree root
/// at the time the evidence was collected.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChallengeEvidence {
    /// Record ID being cited as evidence.
    pub record_id: String,
    /// Zone the record belongs to (for Merkle tree lookup).
    pub zone: crate::ZoneId,
    /// Content hash of the record (the leaf in the Merkle tree).
    pub content_hash: [u8; 32],
    /// Merkle inclusion proof: proves the record exists in the zone's tree
    /// under the given root. Jury verifies this offline without fetching
    /// the record from the network.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_proof: Option<super::merkle::SparseMerkleProof>,
    /// Optional textual description of why this record is evidence.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

impl ChallengeEvidence {
    /// Verify this evidence item's Merkle proof (if present).
    pub fn verify(&self) -> bool {
        match &self.merkle_proof {
            Some(proof) => {
                // Proof leaf must match the claimed content hash
                proof.leaf == self.content_hash
                    && super::merkle::verify_proof(proof)
            }
            None => false, // No proof = unverifiable evidence
        }
    }
}

/// Parsed challenge operation from record metadata.
#[derive(Debug, Clone)]
pub enum ParsedChallengeOp {
    /// File a new challenge.
    File {
        accused: String,
        challenge_type: String,
        evidence: Vec<String>,
    },
    /// Cast a jury vote.
    Vote {
        challenge_id: String,
        guilty: bool,
    },
    /// File an appeal against a verdict.
    Appeal {
        challenge_id: String,
        reason: String,
    },
}

// ─── Challenge State ─────────────────────────────────────────────────────────

/// All challenge state.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ChallengeState {
    /// Active and historical challenges.
    pub challenges: HashMap<String, Challenge>,
}

impl ChallengeState {
    pub fn new() -> Self {
        Self {
            challenges: HashMap::new(),
        }
    }

    /// File a new challenge. Returns the jury selection.
    ///
    /// `epoch_vrf_output`: VRF output from the latest sealed epoch for this zone.
    /// If provided, seeds jury selection with verifiable randomness (Dilithium3-VRF, alg 0x11).
    /// If None (no VRF-sealed epochs yet), falls back to challenge-only seeding.
    #[allow(clippy::too_many_arguments)]
    pub fn file_challenge(
        &mut self,
        challenge_id: String,
        challenger: String,
        accused: String,
        challenge_type: ChallengeType,
        evidence: Vec<String>,
        timestamp: f64,
        eligible_jurors: &[String],
        epoch_vrf_output: Option<&[u8; 32]>,
    ) -> Result<Vec<String>> {
        if self.challenges.contains_key(&challenge_id) {
            return Err(ElaraError::Dispute(format!("challenge already exists: {challenge_id}")));
        }

        // Check for existing open challenge against the same accused
        let existing = self.challenges.values().any(|c| {
            c.accused == accused
                && !matches!(c.status, ChallengeStatus::Final | ChallengeStatus::Dismissed)
        });
        if existing {
            return Err(ElaraError::Dispute(format!(
                "open challenge already exists against {}", accused.chars().take(16).collect::<String>()
            )));
        }

        // Select jury using VRF-seeded random selection.
        // epoch_vrf_output provides unpredictability — attacker can't pre-generate
        // sybil identities targeting specific jury positions.
        let epoch_seed = epoch_vrf_output.map_or(&[][..], |o| &o[..]);
        let jury = select_jury_with_epoch(
            &challenge_id, &challenger, &accused, eligible_jurors,
            DEFAULT_JURY_SIZE, epoch_seed,
        );

        if jury.is_empty() {
            return Err(ElaraError::Dispute("no eligible jurors available".into()));
        }

        let challenge = Challenge {
            id: challenge_id.clone(),
            challenger,
            accused,
            challenge_type,
            evidence,
            structured_evidence: Vec::new(),
            filed_at: timestamp,
            status: ChallengeStatus::JuryVoting,
            jury: jury.clone(),
            votes: Vec::new(),
            is_appeal: false,
            verdict: None,
            verdict_at: None,
            slash_amount: None,
        };

        self.challenges.insert(challenge_id, challenge);
        Ok(jury)
    }

    /// Attach structured evidence to an existing challenge.
    /// Called when the challenger provides Merkle proofs for cited records.
    pub fn attach_evidence(
        &mut self,
        challenge_id: &str,
        evidence: Vec<ChallengeEvidence>,
    ) -> Result<usize> {
        let challenge = self.challenges.get_mut(challenge_id)
            .ok_or_else(|| ElaraError::Dispute(format!("challenge not found: {challenge_id}")))?;

        if matches!(challenge.status, ChallengeStatus::Final | ChallengeStatus::Dismissed) {
            return Err(ElaraError::Dispute("challenge is closed".into()));
        }

        let valid_count = evidence.iter().filter(|e| e.verify()).count();
        challenge.structured_evidence.extend(evidence);
        Ok(valid_count)
    }

    /// Cast a jury vote on a challenge.
    pub fn cast_vote(
        &mut self,
        challenge_id: &str,
        juror: &str,
        guilty: bool,
        timestamp: f64,
    ) -> Result<Option<bool>> {
        let challenge = self.challenges.get_mut(challenge_id)
            .ok_or_else(|| ElaraError::Dispute(format!("challenge not found: {challenge_id}")))?;

        if !matches!(challenge.status, ChallengeStatus::JuryVoting | ChallengeStatus::Appeal) {
            return Err(ElaraError::Dispute("challenge is not in voting phase".into()));
        }

        if !challenge.jury.contains(&juror.to_string()) {
            return Err(ElaraError::Dispute(format!("not a juror for this challenge: {}", juror.chars().take(16).collect::<String>())));
        }

        // Check for duplicate vote
        if challenge.votes.iter().any(|v| v.juror == juror) {
            return Err(ElaraError::Dispute("juror has already voted".into()));
        }

        // Check voting window
        if timestamp - challenge.filed_at > JURY_VOTING_WINDOW_SECS {
            return Err(ElaraError::Dispute("voting window has expired".into()));
        }

        challenge.votes.push(JuryVote {
            juror: juror.to_string(),
            guilty,
            timestamp,
        });

        // Check if all votes are in
        if challenge.votes.len() == challenge.jury.len() {
            let verdict = challenge.has_supermajority();
            if let Some(is_guilty) = verdict {
                challenge.verdict = Some(is_guilty);
                challenge.verdict_at = Some(timestamp);

                if is_guilty {
                    // Calculate slash amount
                    let sp = slash_percent(&challenge.challenge_type);
                    challenge.slash_amount = Some((sp * 1_000_000_000.0) as u64); // placeholder, actual calculation done at execution time
                    if challenge.is_appeal {
                        challenge.status = ChallengeStatus::Final;
                    } else {
                        challenge.status = ChallengeStatus::Verdict;
                    }
                } else {
                    challenge.status = ChallengeStatus::Dismissed;
                }
                return Ok(Some(is_guilty));
            }
        }

        Ok(None) // Vote recorded, no verdict yet
    }

    /// File an appeal against a verdict.
    pub fn file_appeal(
        &mut self,
        challenge_id: &str,
        appellant: &str,
        reason: String,
        timestamp: f64,
        eligible_jurors: &[String],
        epoch_vrf_output: Option<&[u8; 32]>,
    ) -> Result<Vec<String>> {
        let challenge = self.challenges.get_mut(challenge_id)
            .ok_or_else(|| ElaraError::Dispute(format!("challenge not found: {challenge_id}")))?;

        if challenge.status != ChallengeStatus::Verdict {
            return Err(ElaraError::Dispute("can only appeal a verdict (not final/dismissed)".into()));
        }

        if !challenge.in_appeal_window(timestamp) {
            return Err(ElaraError::Dispute("appeal window has expired".into()));
        }

        // Only the accused or challenger can appeal
        if appellant != challenge.accused && appellant != challenge.challenger {
            return Err(ElaraError::Dispute("only the accused or challenger can appeal".into()));
        }

        // Select new, larger jury (excluding original jury, challenger, and accused)
        let mut excluded: Vec<&str> = challenge.jury.iter().map(|s| s.as_str()).collect();
        excluded.push(&challenge.challenger);
        excluded.push(&challenge.accused);

        let new_eligible: Vec<String> = eligible_jurors.iter()
            .filter(|j| !excluded.contains(&j.as_str()))
            .cloned()
            .collect();

        let epoch_seed = epoch_vrf_output.map_or(&[][..], |o| &o[..]);
        let appeal_id = format!("{challenge_id}:appeal");
        let new_jury = select_jury_with_epoch(
            &appeal_id, &challenge.challenger, &challenge.accused,
            &new_eligible, APPEAL_JURY_SIZE, epoch_seed,
        );

        if new_jury.is_empty() {
            return Err(ElaraError::Dispute("no eligible jurors for appeal".into()));
        }

        challenge.status = ChallengeStatus::Appeal;
        challenge.jury = new_jury.clone();
        challenge.votes.clear();
        challenge.verdict = None;
        challenge.verdict_at = None;
        challenge.is_appeal = true;
        challenge.evidence.push(format!("appeal:{reason}"));

        Ok(new_jury)
    }

    /// Finalize a verdict challenge that's past the appeal window.
    pub fn finalize_if_expired(&mut self, challenge_id: &str, now: f64) -> bool {
        let Some(challenge) = self.challenges.get_mut(challenge_id) else {
            return false;
        };
        if challenge.status == ChallengeStatus::Verdict && !challenge.in_appeal_window(now) {
            challenge.status = ChallengeStatus::Final;
            return true;
        }
        false
    }

    /// Get a challenge by ID.
    pub fn get(&self, id: &str) -> Option<&Challenge> {
        self.challenges.get(id)
    }

    /// Iterate over all challenges.
    pub fn all(&self) -> impl Iterator<Item = &Challenge> {
        self.challenges.values()
    }

    /// List all open (non-final) challenges.
    pub fn open_challenges(&self) -> Vec<&Challenge> {
        self.challenges.values()
            .filter(|c| !matches!(c.status, ChallengeStatus::Final | ChallengeStatus::Dismissed))
            .collect()
    }

    /// Bounded count of open (non-`Final`/`Dismissed`)
    /// challenges. Same predicate as [`open_challenges`] but skips the per-call
    /// `Vec<&Challenge>` allocation — operators only want the count for
    /// `/metrics`. Pair with `elara_challenges_filed_total` (filed counter):
    /// flat `open_count` while `filed_total` climbs = challenges are resolving;
    /// both climbing together = challenges accumulating (jury voting stalled
    /// OR appeal window not closing). O(challenges) per scrape, no allocation.
    pub fn open_count(&self) -> usize {
        self.challenges.values()
            .filter(|c| !matches!(c.status, ChallengeStatus::Final | ChallengeStatus::Dismissed))
            .count()
    }

    /// List all challenges.
    pub fn all_challenges(&self) -> Vec<&Challenge> {
        self.challenges.values().collect()
    }

    /// Challenges awaiting a specific juror's vote.
    pub fn pending_votes_for(&self, juror: &str) -> Vec<&Challenge> {
        self.challenges.values()
            .filter(|c| {
                matches!(c.status, ChallengeStatus::JuryVoting | ChallengeStatus::Appeal)
                    && c.jury.contains(&juror.to_string())
                    && !c.votes.iter().any(|v| v.juror == juror)
            })
            .collect()
    }
}

// ─── VRF-seeded jury selection ───────────────────────────────────────────────

/// Select jury members using deterministic random selection seeded by challenge data
/// and epoch randomness.
///
/// Build a `ChallengeEvidence` item from a record in local storage.
///
/// Looks up the record, determines its zone, generates a Merkle inclusion proof
/// from the zone's sparse Merkle tree, and packages it into a verifiable evidence item.
/// Returns None if the record doesn't exist or can't be proven.
pub fn build_evidence(
    rocks: &crate::storage::rocks::StorageEngine,
    record_id: &str,
    description: &str,
) -> Option<ChallengeEvidence> {
    

    let record = rocks.get_record(record_id).ok()??;
    let zone = record.zone.clone().unwrap_or_else(|| crate::ZoneId::from_legacy(0));

    // The leaf in the Merkle tree is the content hash of the record.
    let leaf: [u8; 32] = if record.content_hash.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&record.content_hash);
        arr
    } else {
        return None;
    };

    // Generate inclusion proof
    let tree = super::merkle::SparseMerkleTree::new(rocks, zone.clone());
    let proof = tree.proof(&leaf).ok().flatten()?;

    Some(ChallengeEvidence {
        record_id: record_id.to_string(),
        zone,
        content_hash: leaf,
        merkle_proof: Some(proof),
        description: description.to_string(),
    })
}

/// VRF seed = SHA3-256(challenge_id || challenger || accused || epoch_seed).
/// The epoch_seed comes from the latest sealed epoch's Merkle root, making jury
/// selection unpredictable before the challenge is filed (attacker doesn't know
/// which epoch their challenge will land in). Prevents sybil
/// pre-generation of identities targeting specific jury positions.
///
/// Selection: sort eligible by SHA3(seed || juror_hash), take first `count`.
/// Excludes challenger and accused.
#[cfg(test)]
fn select_jury(
    challenge_id: &str,
    challenger: &str,
    accused: &str,
    eligible: &[String],
    count: usize,
) -> Vec<String> {
    select_jury_with_epoch(challenge_id, challenger, accused, eligible, count, &[])
}

/// Jury selection with explicit epoch seed (for production use with epoch Merkle root).
pub fn select_jury_with_epoch(
    challenge_id: &str,
    challenger: &str,
    accused: &str,
    eligible: &[String],
    count: usize,
    epoch_seed: &[u8],
) -> Vec<String> {
    if eligible.is_empty() {
        return Vec::new();
    }

    let mut seed_input = format!("{challenge_id}:{challenger}:{accused}:");
    seed_input.push_str(&hex::encode(epoch_seed));
    let seed = sha3_256(seed_input.as_bytes());

    // Score each eligible juror by SHA3(seed || juror)
    let mut scored: Vec<([u8; 32], &String)> = eligible.iter()
        .filter(|j| j.as_str() != challenger && j.as_str() != accused)
        .map(|juror| {
            let mut input = seed.to_vec();
            input.extend_from_slice(juror.as_bytes());
            let score = sha3_256(&input);
            (score, juror)
        })
        .collect();

    // Sort by score (deterministic ordering)
    scored.sort_by_key(|a| a.0);

    // Take first `count`
    scored.into_iter()
        .take(count)
        .map(|(_, j)| j.clone())
        .collect()
}

// ─── Metadata extraction ─────────────────────────────────────────────────────

/// Extract challenge operation from record metadata.
pub fn extract_challenge_op(
    metadata: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<Option<ParsedChallengeOp>> {
    let op_val = match metadata.get(CHALLENGE_OP_KEY) {
        Some(v) => v,
        None => return Ok(None),
    };

    let op_str = op_val.as_str()
        .ok_or_else(|| ElaraError::Dispute("challenge_op must be a string".into()))?;

    match op_str {
        "file" => {
            let accused = get_str(metadata, "challenge_accused")?;
            let ctype = get_str(metadata, "challenge_type")?;
            let evidence: Vec<String> = metadata.get("challenge_evidence")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            Ok(Some(ParsedChallengeOp::File { accused, challenge_type: ctype, evidence }))
        }
        "vote" => {
            let challenge_id = get_str(metadata, "challenge_id")?;
            let guilty = metadata.get("challenge_guilty")
                .and_then(|v| v.as_bool())
                .ok_or_else(|| ElaraError::Dispute("challenge_guilty must be a boolean".into()))?;
            Ok(Some(ParsedChallengeOp::Vote { challenge_id, guilty }))
        }
        "appeal" => {
            let challenge_id = get_str(metadata, "challenge_id")?;
            let reason = get_str(metadata, "challenge_appeal_reason")?;
            Ok(Some(ParsedChallengeOp::Appeal { challenge_id, reason }))
        }
        other => Err(ElaraError::Dispute(format!("unknown challenge op: {other}"))),
    }
}

fn get_str(
    meta: &std::collections::BTreeMap<String, serde_json::Value>,
    key: &str,
) -> Result<String> {
    meta.get(key)
        .ok_or_else(|| ElaraError::Dispute(format!("missing field: {key}")))?
        .as_str()
        .ok_or_else(|| ElaraError::Dispute(format!("{key} must be a string")))
        .map(|s| s.to_string())
}

/// Verify a challenge operation (basic validation).
pub fn verify_challenge(op: &ParsedChallengeOp) -> Result<()> {
    match op {
        ParsedChallengeOp::File { accused, challenge_type, evidence } => {
            if accused.is_empty() {
                return Err(ElaraError::Dispute("accused is empty".into()));
            }
            if ChallengeType::parse_str(challenge_type).is_none() {
                return Err(ElaraError::Dispute(format!(
                    "invalid challenge_type: {challenge_type} (must be spam, false_witnessing, double_signing, or cartel_formation)"
                )));
            }
            if evidence.is_empty() {
                return Err(ElaraError::Dispute("evidence is empty".into()));
            }
        }
        ParsedChallengeOp::Vote { challenge_id, .. } => {
            if challenge_id.is_empty() {
                return Err(ElaraError::Dispute("challenge_id is empty".into()));
            }
        }
        ParsedChallengeOp::Appeal { challenge_id, reason } => {
            if challenge_id.is_empty() {
                return Err(ElaraError::Dispute("challenge_id is empty".into()));
            }
            if reason.is_empty() {
                return Err(ElaraError::Dispute("appeal reason is empty".into()));
            }
        }
    }
    Ok(())
}

/// Build metadata for filing a challenge.
pub fn file_challenge_metadata(
    accused: &str,
    challenge_type: &str,
    evidence: &[&str],
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(CHALLENGE_OP_KEY.into(), serde_json::json!("file"));
    m.insert("challenge_accused".into(), serde_json::json!(accused));
    m.insert("challenge_type".into(), serde_json::json!(challenge_type));
    m.insert("challenge_evidence".into(), serde_json::json!(evidence));
    m
}

/// Build metadata for a jury vote.
pub fn vote_metadata(
    challenge_id: &str,
    guilty: bool,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(CHALLENGE_OP_KEY.into(), serde_json::json!("vote"));
    m.insert("challenge_id".into(), serde_json::json!(challenge_id));
    m.insert("challenge_guilty".into(), serde_json::json!(guilty));
    m
}

/// Build metadata for an appeal.
pub fn appeal_metadata(
    challenge_id: &str,
    reason: &str,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(CHALLENGE_OP_KEY.into(), serde_json::json!("appeal"));
    m.insert("challenge_id".into(), serde_json::json!(challenge_id));
    m.insert("challenge_appeal_reason".into(), serde_json::json!(reason));
    m
}

/// Rebuild challenge state from all records in storage.
/// WARNING: Loads ALL records — O(all_records) memory. Production startup uses
/// rebuild_challenges_from_records with streaming data.
#[cfg(test)]
pub fn rebuild_challenges(storage: &dyn crate::storage::Storage) -> ChallengeState {
    let records = storage.query(None, None, None, None, usize::MAX).unwrap_or_default();
    rebuild_challenges_from_records(&records, None)
}

/// Rebuild challenge state from a pre-loaded record slice (single-pass startup).
///
/// AUDIT-6: `epoch_state` supplies the time-indexed VRF output used as the jury
/// seed. Pass `Some(&state)` with the rebuilt epoch state so juries match the live
/// path; pass `None` only for tests or legacy paths where VRF history is absent
/// (falls back to empty seed — non-consensus determinism with live).
///
/// **F2 tombstone guard (R4):** storage-less (no CF_METADATA access) so it cannot
/// skip tombstoned records inline, and it has ZERO production callers today (its
/// `#[cfg(test)]` wrapper is test-only). If ever wired into a production boot/sync
/// path, the CALLER must pre-filter tombstoned records (as ledger's
/// `rebuild_ledger_from_records` must) — else a tombstone-first op-carrying record is
/// revived here, re-introducing the F2 divergence for this subsystem. See
/// internal design notes (R4).
pub fn rebuild_challenges_from_records(
    all_records: &[crate::record::ValidationRecord],
    epoch_state: Option<&super::epoch::EpochState>,
) -> ChallengeState {
    use crate::accounting::types::creator_identity_hash;

    let mut state = ChallengeState::new();
    let mut sorted: Vec<&crate::record::ValidationRecord> = all_records.iter().collect();
    // Total-order replay: timestamp + record-ID tiebreak (mirrors ledger.rs/epoch.rs).
    // Equal-timestamp challenge/vote/appeal ops must replay identically across nodes.
    sorted.sort_by(|a, b| {
        a.timestamp.total_cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id))
    });

    // Collect all staked identities for jury eligibility
    let all_identities: Vec<String> = sorted.iter()
        .map(|r| creator_identity_hash(r))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    for rec in &sorted {
        if let Ok(Some(op)) = extract_challenge_op(&rec.metadata) {
            let creator = creator_identity_hash(rec);
            let rec_zone = rec.zone.clone()
                .unwrap_or_else(|| crate::ZoneId::from_legacy(0));
            let vrf = epoch_state
                .and_then(|es| es.vrf_output_at_or_before(&rec_zone, rec.timestamp));
            match op {
                ParsedChallengeOp::File { accused, challenge_type, evidence } => {
                    if let Some(ct) = ChallengeType::parse_str(&challenge_type) {
                        let _ = state.file_challenge(
                            rec.id.clone(), creator, accused, ct, evidence,
                            rec.timestamp, &all_identities, vrf.as_ref(),
                        );
                    }
                }
                ParsedChallengeOp::Vote { challenge_id, guilty } => {
                    let _ = state.cast_vote(&challenge_id, &creator, guilty, rec.timestamp);
                }
                ParsedChallengeOp::Appeal { challenge_id, reason } => {
                    let _ = state.file_appeal(
                        &challenge_id, &creator, reason, rec.timestamp, &all_identities, vrf.as_ref(),
                    );
                }
            }
        }
    }
    state
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn jurors() -> Vec<String> {
        (0..20).map(|i| format!("juror_{i}")).collect()
    }

    #[test]
    fn test_file_challenge() {
        let mut state = ChallengeState::new();
        let jury = state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::Spam, vec!["evidence_1".into()],
            1000.0, &jurors(), None,
        ).unwrap();
        assert_eq!(jury.len(), DEFAULT_JURY_SIZE);
        assert_eq!(state.challenges.len(), 1);
        assert_eq!(state.challenges["c1"].status, ChallengeStatus::JuryVoting);
    }

    #[test]
    fn test_file_challenge_duplicate_accused() {
        let mut state = ChallengeState::new();
        state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1000.0, &jurors(), None,
        ).unwrap();
        let result = state.file_challenge(
            "c2".into(), "carol".into(), "bob".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1001.0, &jurors(), None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn ops_40_open_count_matches_open_challenges_predicate() {
        // open_count() must agree with open_challenges().len()
        // across empty / all-open / partial-final / partial-dismissed
        // / fully-resolved transitions. Mirrors the fast-path the
        // /metrics emitter uses (no Vec allocation).
        let mut state = ChallengeState::new();
        assert_eq!(state.open_count(), 0, "empty store");
        assert_eq!(state.open_count(), state.open_challenges().len());

        state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1000.0, &jurors(), None,
        ).unwrap();
        state.file_challenge(
            "c2".into(), "alice".into(), "carol".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1001.0, &jurors(), None,
        ).unwrap();
        state.file_challenge(
            "c3".into(), "alice".into(), "dave".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1002.0, &jurors(), None,
        ).unwrap();
        assert_eq!(state.open_count(), 3, "all three filed");
        assert_eq!(state.open_count(), state.open_challenges().len());

        // c1 reaches Final via finalize_if_expired path; here we simulate
        // by mutating the status directly (the predicate is what matters).
        state.challenges.get_mut("c1").unwrap().status = ChallengeStatus::Final;
        assert_eq!(state.open_count(), 2, "c1 finalized → 2 open");
        assert_eq!(state.open_count(), state.open_challenges().len());

        // c2 dismissed.
        state.challenges.get_mut("c2").unwrap().status = ChallengeStatus::Dismissed;
        assert_eq!(state.open_count(), 1, "c2 dismissed → 1 open");
        assert_eq!(state.open_count(), state.open_challenges().len());

        // c3 finalized — store fully drained (operator-relevant case:
        // every filed challenge has resolved, gauge returns to 0).
        state.challenges.get_mut("c3").unwrap().status = ChallengeStatus::Final;
        assert_eq!(state.open_count(), 0, "all resolved");
        assert_eq!(state.open_count(), state.open_challenges().len());
    }

    #[test]
    fn test_jury_excludes_challenger_and_accused() {
        let eligible = vec!["alice".into(), "bob".into(), "juror_1".into(), "juror_2".into(), "juror_3".into()];
        let jury = select_jury("c1", "alice", "bob", &eligible, 3);
        assert!(!jury.contains(&"alice".to_string()));
        assert!(!jury.contains(&"bob".to_string()));
        assert_eq!(jury.len(), 3);
    }

    #[test]
    fn test_jury_deterministic() {
        let eligible = jurors();
        let jury1 = select_jury("c1", "alice", "bob", &eligible, 5);
        let jury2 = select_jury("c1", "alice", "bob", &eligible, 5);
        assert_eq!(jury1, jury2);
    }

    #[test]
    fn test_jury_different_for_different_challenges() {
        let eligible = jurors();
        let jury1 = select_jury("c1", "alice", "bob", &eligible, 5);
        let jury2 = select_jury("c2", "alice", "bob", &eligible, 5);
        assert_ne!(jury1, jury2);
    }

    #[test]
    fn test_cast_vote_guilty() {
        let mut state = ChallengeState::new();
        let jury = state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::FalseWitnessing, vec!["ev".into()],
            1000.0, &jurors(), None,
        ).unwrap();

        // All jurors vote guilty
        for (i, juror) in jury.iter().enumerate() {
            let result = state.cast_vote("c1", juror, true, 1001.0 + i as f64).unwrap();
            if i < jury.len() - 1 {
                assert_eq!(result, None);
            } else {
                assert_eq!(result, Some(true)); // Guilty verdict
            }
        }
        assert_eq!(state.challenges["c1"].verdict, Some(true));
        assert_eq!(state.challenges["c1"].status, ChallengeStatus::Verdict);
    }

    #[test]
    fn test_cast_vote_not_guilty() {
        let mut state = ChallengeState::new();
        let jury = state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1000.0, &jurors(), None,
        ).unwrap();

        // All jurors vote not guilty
        for (i, juror) in jury.iter().enumerate() {
            let _ = state.cast_vote("c1", juror, false, 1001.0 + i as f64);
        }
        assert_eq!(state.challenges["c1"].verdict, Some(false));
        assert_eq!(state.challenges["c1"].status, ChallengeStatus::Dismissed);
    }

    #[test]
    fn test_supermajority_threshold() {
        let mut state = ChallengeState::new();
        let jury = state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1000.0, &jurors(), None,
        ).unwrap();

        // 3/5 = 60% < 75% → not guilty
        let mut result = None;
        for (i, juror) in jury.iter().enumerate() {
            let guilty = i < 3; // 3 guilty, 2 not
            result = state.cast_vote("c1", juror, guilty, 1001.0 + i as f64).unwrap();
        }
        assert_eq!(result, Some(false));
        assert_eq!(state.challenges["c1"].status, ChallengeStatus::Dismissed);
    }

    #[test]
    fn test_supermajority_guilty() {
        let mut state = ChallengeState::new();
        let jury = state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1000.0, &jurors(), None,
        ).unwrap();

        // 10/13 = 76.9% >= 75% → guilty
        let guilty_count = (jury.len() as f64 * SUPERMAJORITY_THRESHOLD).ceil() as usize;
        for (i, juror) in jury.iter().enumerate() {
            let guilty = i < guilty_count;
            let _ = state.cast_vote("c1", juror, guilty, 1001.0 + i as f64);
        }
        assert_eq!(state.challenges["c1"].verdict, Some(true));
    }

    #[test]
    fn test_duplicate_vote_rejected() {
        let mut state = ChallengeState::new();
        let jury = state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1000.0, &jurors(), None,
        ).unwrap();

        state.cast_vote("c1", &jury[0], true, 1001.0).unwrap();
        assert!(state.cast_vote("c1", &jury[0], false, 1002.0).is_err());
    }

    #[test]
    fn test_non_juror_vote_rejected() {
        let mut state = ChallengeState::new();
        state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1000.0, &jurors(), None,
        ).unwrap();

        assert!(state.cast_vote("c1", "not_a_juror", true, 1001.0).is_err());
    }

    #[test]
    fn test_file_appeal() {
        let mut state = ChallengeState::new();
        let jury = state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::DoubleSigning, vec!["ev".into()],
            1000.0, &jurors(), None,
        ).unwrap();

        // All vote guilty → verdict
        for (i, juror) in jury.iter().enumerate() {
            state.cast_vote("c1", juror, true, 1001.0 + i as f64).unwrap();
        }
        assert_eq!(state.challenges["c1"].status, ChallengeStatus::Verdict);

        // Bob appeals
        let new_jury = state.file_appeal(
            "c1", "bob", "I was framed".into(),
            1002.0 + jury.len() as f64, &jurors(), None,
        ).unwrap();
        assert_eq!(new_jury.len().min(APPEAL_JURY_SIZE), new_jury.len());
        assert_eq!(state.challenges["c1"].status, ChallengeStatus::Appeal);
        assert!(state.challenges["c1"].is_appeal);
    }

    #[test]
    fn test_appeal_after_appeal_rejected() {
        let mut state = ChallengeState::new();
        let jury = state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::DoubleSigning, vec!["ev".into()],
            1000.0, &jurors(), None,
        ).unwrap();

        for (i, juror) in jury.iter().enumerate() {
            state.cast_vote("c1", juror, true, 1001.0 + i as f64).unwrap();
        }

        let new_jury = state.file_appeal("c1", "bob", "framed".into(), 1010.0, &jurors(), None).unwrap();

        // Vote guilty again in appeal → Final
        for (i, juror) in new_jury.iter().enumerate() {
            state.cast_vote("c1", juror, true, 1020.0 + i as f64).unwrap();
        }
        assert_eq!(state.challenges["c1"].status, ChallengeStatus::Final);
    }

    #[test]
    fn test_appeal_expired_window() {
        let mut state = ChallengeState::new();
        let jury = state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1000.0, &jurors(), None,
        ).unwrap();

        for (i, juror) in jury.iter().enumerate() {
            state.cast_vote("c1", juror, true, 1001.0 + i as f64).unwrap();
        }

        // Try to appeal after window
        let result = state.file_appeal(
            "c1", "bob", "late".into(),
            1001.0 + APPEAL_WINDOW_SECS + 100.0, &jurors(), None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_finalize_if_expired() {
        let mut state = ChallengeState::new();
        let jury = state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1000.0, &jurors(), None,
        ).unwrap();

        for (i, juror) in jury.iter().enumerate() {
            state.cast_vote("c1", juror, true, 1001.0 + i as f64).unwrap();
        }
        assert_eq!(state.challenges["c1"].status, ChallengeStatus::Verdict);

        // Before appeal window expires
        assert!(!state.finalize_if_expired("c1", 1002.0));

        // After appeal window
        assert!(state.finalize_if_expired("c1", 1001.0 + APPEAL_WINDOW_SECS + 100.0));
        assert_eq!(state.challenges["c1"].status, ChallengeStatus::Final);
    }

    #[test]
    fn test_slash_percentages() {
        assert!((slash_percent(&ChallengeType::Spam) - 0.10).abs() < 0.001);
        assert!((slash_percent(&ChallengeType::FalseWitnessing) - 0.25).abs() < 0.001);
        assert!((slash_percent(&ChallengeType::DoubleSigning) - 0.50).abs() < 0.001);
        assert!((slash_percent(&ChallengeType::CartelFormation) - 0.25).abs() < 0.001);
    }

    #[test]
    fn test_challenge_type_roundtrip() {
        for ct in &[ChallengeType::Spam, ChallengeType::FalseWitnessing, ChallengeType::DoubleSigning, ChallengeType::CartelFormation] {
            let s = ct.as_str();
            assert_eq!(ChallengeType::parse_str(s).as_ref(), Some(ct));
        }
    }

    #[test]
    fn test_extract_file_metadata() {
        let meta = file_challenge_metadata("bob", "spam", &["ev1", "ev2"]);
        let op = extract_challenge_op(&meta).unwrap().unwrap();
        match op {
            ParsedChallengeOp::File { accused, challenge_type, evidence } => {
                assert_eq!(accused, "bob");
                assert_eq!(challenge_type, "spam");
                assert_eq!(evidence, vec!["ev1", "ev2"]);
            }
            _ => panic!("expected File"),
        }
    }

    #[test]
    fn test_extract_vote_metadata() {
        let meta = vote_metadata("c1", true);
        let op = extract_challenge_op(&meta).unwrap().unwrap();
        match op {
            ParsedChallengeOp::Vote { challenge_id, guilty } => {
                assert_eq!(challenge_id, "c1");
                assert!(guilty);
            }
            _ => panic!("expected Vote"),
        }
    }

    #[test]
    fn test_extract_appeal_metadata() {
        let meta = appeal_metadata("c1", "I was framed");
        let op = extract_challenge_op(&meta).unwrap().unwrap();
        match op {
            ParsedChallengeOp::Appeal { challenge_id, reason } => {
                assert_eq!(challenge_id, "c1");
                assert_eq!(reason, "I was framed");
            }
            _ => panic!("expected Appeal"),
        }
    }

    #[test]
    fn test_verify_challenge_valid() {
        let op = ParsedChallengeOp::File {
            accused: "bob".into(),
            challenge_type: "spam".into(),
            evidence: vec!["ev1".into()],
        };
        assert!(verify_challenge(&op).is_ok());
    }

    #[test]
    fn test_verify_challenge_invalid_type() {
        let op = ParsedChallengeOp::File {
            accused: "bob".into(),
            challenge_type: "invalid".into(),
            evidence: vec!["ev1".into()],
        };
        assert!(verify_challenge(&op).is_err());
    }

    #[test]
    fn test_verify_challenge_empty_evidence() {
        let op = ParsedChallengeOp::File {
            accused: "bob".into(),
            challenge_type: "spam".into(),
            evidence: vec![],
        };
        assert!(verify_challenge(&op).is_err());
    }

    #[test]
    fn test_pending_votes_for() {
        let mut state = ChallengeState::new();
        let jury = state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1000.0, &jurors(), None,
        ).unwrap();

        // Before any votes, all jurors have pending votes
        for juror in &jury {
            assert_eq!(state.pending_votes_for(juror).len(), 1);
        }

        // After voting, that juror has no pending
        state.cast_vote("c1", &jury[0], true, 1001.0).unwrap();
        assert_eq!(state.pending_votes_for(&jury[0]).len(), 0);
        assert_eq!(state.pending_votes_for(&jury[1]).len(), 1);
    }

    #[test]
    fn test_open_challenges() {
        let mut state = ChallengeState::new();
        state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1000.0, &jurors(), None,
        ).unwrap();

        assert_eq!(state.open_challenges().len(), 1);

        // File and dismiss another
        let jury = state.file_challenge(
            "c2".into(), "carol".into(), "dave".into(),
            ChallengeType::Spam, vec!["ev".into()],
            2000.0, &jurors(), None,
        ).unwrap();
        for (i, juror) in jury.iter().enumerate() {
            state.cast_vote("c2", juror, false, 2001.0 + i as f64).unwrap();
        }
        assert_eq!(state.challenges["c2"].status, ChallengeStatus::Dismissed);
        assert_eq!(state.open_challenges().len(), 1); // Only c1 still open
    }

    // ── VRF-seeded jury selection tests ──────────────────────────

    #[test]
    fn test_jury_with_vrf_seed_differs_from_without() {
        let eligible = jurors();
        let vrf_output = [0xABu8; 32];

        let jury_no_vrf = select_jury_with_epoch(
            "c1", "alice", "bob", &eligible, 5, &[],
        );
        let jury_with_vrf = select_jury_with_epoch(
            "c1", "alice", "bob", &eligible, 5, &vrf_output,
        );

        // Different seeds must produce different juries
        assert_ne!(jury_no_vrf, jury_with_vrf,
            "VRF-seeded jury must differ from unseeded jury");
    }

    #[test]
    fn test_jury_with_different_vrf_seeds_differ() {
        let eligible = jurors();
        let vrf_output_1 = [0x01u8; 32];
        let vrf_output_2 = [0x02u8; 32];

        let jury1 = select_jury_with_epoch(
            "c1", "alice", "bob", &eligible, 5, &vrf_output_1,
        );
        let jury2 = select_jury_with_epoch(
            "c1", "alice", "bob", &eligible, 5, &vrf_output_2,
        );

        assert_ne!(jury1, jury2,
            "Different VRF outputs must produce different juries");
    }

    #[test]
    fn test_jury_with_vrf_is_deterministic() {
        let eligible = jurors();
        let vrf_output = [0xCDu8; 32];

        let jury1 = select_jury_with_epoch(
            "c1", "alice", "bob", &eligible, 5, &vrf_output,
        );
        let jury2 = select_jury_with_epoch(
            "c1", "alice", "bob", &eligible, 5, &vrf_output,
        );

        assert_eq!(jury1, jury2,
            "Same VRF output must produce same jury");
    }

    #[test]
    fn test_file_challenge_with_vrf_output() {
        let mut state = ChallengeState::new();
        let vrf_output = [0xEFu8; 32];

        let jury = state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1000.0, &jurors(), Some(&vrf_output),
        ).unwrap();

        assert_eq!(jury.len(), DEFAULT_JURY_SIZE);

        // The jury should be different from one filed without VRF
        let mut state2 = ChallengeState::new();
        let jury_no_vrf = state2.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::Spam, vec!["ev".into()],
            1000.0, &jurors(), None,
        ).unwrap();

        assert_ne!(jury, jury_no_vrf,
            "VRF-seeded challenge must produce different jury than unseeded");
    }

    // ── AUDIT-6: VRF history ring + rebuild determinism ──────────

    #[test]
    fn test_audit6_epoch_vrf_lookup_at_or_before_timestamp() {
        // EpochState populated via register_seal — verify time-indexed lookup picks
        // the right VRF for any query timestamp.
        let mut epoch_state = super::super::epoch::EpochState::new();
        let zone0 = crate::ZoneId::from_legacy(0);
        let mk_seal = |num, end, vrf_byte| super::super::epoch::ParsedEpochSeal {
            zone: zone0.clone(),
            epoch_number: num,
            start: 0.0,
            end,
            record_count: 1,
            merkle_root: [0u8; 32],
            previous_seal_hash: [0u8; 32],
            vrf_output: Some([vrf_byte; 32]),
            vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };
        epoch_state.register_seal(&mk_seal(1, 500.0, 0x11), "seal_a", [0u8; 32]);
        epoch_state.register_seal(&mk_seal(2, 1500.0, 0x22), "seal_b", [0u8; 32]);
        epoch_state.register_seal(&mk_seal(3, 2500.0, 0x33), "seal_c", [0u8; 32]);

        // Before any seal → None
        assert_eq!(epoch_state.vrf_output_at_or_before(&zone0, 100.0), None);
        // Exactly at seal_a's end → seal_a's VRF
        assert_eq!(epoch_state.vrf_output_at_or_before(&zone0, 500.0), Some([0x11u8; 32]));
        // Between seal_a and seal_b → seal_a's VRF
        assert_eq!(epoch_state.vrf_output_at_or_before(&zone0, 1000.0), Some([0x11u8; 32]));
        // Between seal_b and seal_c → seal_b's VRF
        assert_eq!(epoch_state.vrf_output_at_or_before(&zone0, 2000.0), Some([0x22u8; 32]));
        // After seal_c → seal_c's VRF
        assert_eq!(epoch_state.vrf_output_at_or_before(&zone0, 10_000.0), Some([0x33u8; 32]));
        // Different zone → None
        let zone1 = crate::ZoneId::from_legacy(1);
        assert_eq!(epoch_state.vrf_output_at_or_before(&zone1, 5000.0), None);
    }

    #[test]
    fn test_audit6_vrf_history_ring_is_bounded() {
        // Push more than VRF_HISTORY_PER_ZONE seals; ring must retain only the last N.
        let mut epoch_state = super::super::epoch::EpochState::new();
        let zone0 = crate::ZoneId::from_legacy(0);
        let cap = super::super::epoch::VRF_HISTORY_PER_ZONE;
        let push_n = cap + 10;
        for i in 0..push_n {
            let seal = super::super::epoch::ParsedEpochSeal {
                zone: zone0.clone(),
                epoch_number: (i + 1) as u64,
                start: (i as f64) * 100.0,
                end: ((i + 1) as f64) * 100.0,
                record_count: 1,
                merkle_root: [0u8; 32],
                previous_seal_hash: [0u8; 32],
                vrf_output: Some([((i % 255) as u8); 32]),
                vrf_proof: None,
                record_hashes: vec![],
                zone_balance_total: None,
                zone_registry_root: None,
                zone_registry_delta: None,
                seal_zone_count: None,
                aggregator_rank: 0,
                account_smt_root: None,
                drand_pulse: None,
                xzone_dest_finality_committees: None,
            };
            epoch_state.register_seal(&seal, &format!("seal_{i}"), [0u8; 32]);
        }
        let ring = epoch_state.vrf_history.get(&zone0).expect("ring populated");
        assert_eq!(ring.len(), cap, "ring is bounded at VRF_HISTORY_PER_ZONE");
        // Oldest `push_n - cap` seals evicted. Querying just before the first retained
        // end_ts must return None (entry fell out of history).
        let first_retained_end = ring.front().map(|(t, _, _, _)| *t).unwrap();
        assert!(first_retained_end > 100.0, "early seals were evicted");
        assert_eq!(
            epoch_state.vrf_output_at_or_before(&zone0, first_retained_end - 0.001),
            None,
            "queries before the oldest retained entry return None (legacy fallback)"
        );
    }

    #[test]
    fn test_audit6_rebuild_challenges_is_deterministic_with_epoch_state() {
        // Build an EpochState with one sealed epoch, build a slate of challenge
        // records with enough distinct creators to populate the eligible set, then
        // assert two rebuilds over the same inputs produce identical juries (AUDIT-6
        // core invariant: rebuild is a pure function of (records, epoch_state)).
        use crate::record::{Classification, ValidationRecord};

        let mut epoch_state = super::super::epoch::EpochState::new();
        let zone0 = crate::ZoneId::from_legacy(0);
        let seal = super::super::epoch::ParsedEpochSeal {
            zone: zone0.clone(),
            epoch_number: 1,
            start: 0.0,
            end: 500.0,
            record_count: 1,
            merkle_root: [0u8; 32],
            previous_seal_hash: [0u8; 32],
            vrf_output: Some([0x55u8; 32]),
            vrf_proof: None,
            record_hashes: vec![],
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };
        epoch_state.register_seal(&seal, "seal_a", [0u8; 32]);

        // 20 "filler" records establishing a broad eligible-set (one record per PK).
        let mk_rec = |id: &str, pk: Vec<u8>, ts: f64, meta: std::collections::BTreeMap<String, serde_json::Value>| {
            ValidationRecord {
                id: id.into(),
                version: 5,
                content_hash: vec![0u8; 32],
                creator_public_key: pk,
                timestamp: ts,
                parents: vec![],
                classification: Classification::Public,
                metadata: meta,
                signature: None,
                sphincs_signature: None,
                zk_proof: None,
                itc_stamp: None,
                zone_refs: vec![],
                creator_sphincs_pk: None,
                sig_algorithm: 0x01,
                sphincs_algorithm: None,
                zone: Some(zone0.clone()),
                identity_hash_wire: None,
                nonce: 0,
            }
        };
        let mut records = Vec::new();
        for i in 0..20 {
            records.push(mk_rec(
                &format!("r_{i}"),
                format!("pk_{i}").into_bytes(),
                200.0 + i as f64,
                std::collections::BTreeMap::new(),
            ));
        }
        // Accused must be the identity_hash of one of the above PKs — use pk_0.
        let accused_hash = crate::accounting::types::creator_identity_hash(&records[0]);
        // Challenger uses pk_999 (not in eligible set — it's the challenge record's creator).
        let chal_meta = file_challenge_metadata(&accused_hash, "spam", &["ev1"]);
        records.push(mk_rec(
            "c_audit6",
            b"pk_chal".to_vec(),
            1000.0,
            chal_meta,
        ));

        let rebuilt_a = rebuild_challenges_from_records(&records, Some(&epoch_state));
        let rebuilt_b = rebuild_challenges_from_records(&records, Some(&epoch_state));

        let jury_a = &rebuilt_a.challenges["c_audit6"].jury;
        let jury_b = &rebuilt_b.challenges["c_audit6"].jury;
        assert!(!jury_a.is_empty(), "jury populated from eligible set");
        assert_eq!(jury_a, jury_b,
            "AUDIT-6: rebuild is a pure function of (records, epoch_state)");

        // Now rebuild WITHOUT epoch_state (legacy path, empty VRF seed). Jury must
        // differ because the seed differs.
        let rebuilt_no_vrf = rebuild_challenges_from_records(&records, None);
        let jury_no_vrf = &rebuilt_no_vrf.challenges["c_audit6"].jury;
        assert_ne!(jury_a, jury_no_vrf,
            "AUDIT-6: VRF-seeded rebuild produces a different jury than unseeded");
    }

    // ── Structured evidence tests ────────────────────────────────

    #[test]
    fn test_evidence_verify_valid_proof() {
        use crate::crypto::hash::sha3_256;
        use crate::network::merkle::{SparseMerkleProof, SparseMerkleProofNode};

        let leaf = [0xAAu8; 32];
        // Build a trivial 1-level proof: leaf + sibling → root
        let sibling = [0xBBu8; 32];
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&leaf);
        combined[32..].copy_from_slice(&sibling);
        let root = sha3_256(&combined);

        let proof = SparseMerkleProof {
            leaf,
            root,
            siblings: vec![SparseMerkleProofNode {
                hash: sibling,
                is_right: true,
            }],
            zone: crate::ZoneId::from_legacy(0),
        };

        let evidence = ChallengeEvidence {
            record_id: "test-record".to_string(),
            zone: crate::ZoneId::from_legacy(0),
            content_hash: leaf,
            merkle_proof: Some(proof),
            description: "test evidence".to_string(),
        };

        assert!(evidence.verify(), "valid Merkle proof should verify");
    }

    #[test]
    fn test_evidence_verify_tampered_proof() {
        use crate::crypto::hash::sha3_256;
        use crate::network::merkle::{SparseMerkleProof, SparseMerkleProofNode};

        let leaf = [0xAAu8; 32];
        let sibling = [0xBBu8; 32];
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&leaf);
        combined[32..].copy_from_slice(&sibling);
        let root = sha3_256(&combined);

        // Tamper: wrong leaf in proof
        let mut tampered_leaf = leaf;
        tampered_leaf[0] = 0xFF;

        let proof = SparseMerkleProof {
            leaf: tampered_leaf,
            root,
            siblings: vec![SparseMerkleProofNode {
                hash: sibling,
                is_right: true,
            }],
            zone: crate::ZoneId::from_legacy(0),
        };

        let evidence = ChallengeEvidence {
            record_id: "test-record".to_string(),
            zone: crate::ZoneId::from_legacy(0),
            content_hash: leaf, // original leaf
            merkle_proof: Some(proof),
            description: String::new(),
        };

        // Fails because proof.leaf != content_hash
        assert!(!evidence.verify(), "tampered proof should not verify");
    }

    #[test]
    fn test_evidence_no_proof_fails() {
        let evidence = ChallengeEvidence {
            record_id: "test-record".to_string(),
            zone: crate::ZoneId::from_legacy(0),
            content_hash: [0xAAu8; 32],
            merkle_proof: None,
            description: "no proof".to_string(),
        };
        assert!(!evidence.verify(), "evidence without proof should not verify");
    }

    #[test]
    fn test_attach_evidence() {
        use crate::crypto::hash::sha3_256;
        use crate::network::merkle::{SparseMerkleProof, SparseMerkleProofNode};

        let mut state = ChallengeState::new();
        state.file_challenge(
            "c1".into(), "alice".into(), "bob".into(),
            ChallengeType::FalseWitnessing, vec!["rec-1".into()],
            1000.0, &jurors(), None,
        ).unwrap();

        let leaf = [0xCCu8; 32];
        let sibling = [0xDDu8; 32];
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&leaf);
        combined[32..].copy_from_slice(&sibling);
        let root = sha3_256(&combined);

        let evidence = vec![ChallengeEvidence {
            record_id: "rec-1".to_string(),
            zone: crate::ZoneId::from_legacy(0),
            content_hash: leaf,
            merkle_proof: Some(SparseMerkleProof {
                leaf,
                root,
                siblings: vec![SparseMerkleProofNode { hash: sibling, is_right: true }],
                zone: crate::ZoneId::from_legacy(0),
            }),
            description: "bad attestation".to_string(),
        }];

        let valid = state.attach_evidence("c1", evidence).unwrap();
        assert_eq!(valid, 1);
        assert_eq!(state.challenges["c1"].structured_evidence.len(), 1);
    }

    #[test]
    fn test_evidence_serialization_roundtrip() {
        let evidence = ChallengeEvidence {
            record_id: "test".to_string(),
            zone: crate::ZoneId::from_legacy(0),
            content_hash: [0xEEu8; 32],
            merkle_proof: None,
            description: "test desc".to_string(),
        };

        let json = serde_json::to_string(&evidence).unwrap();
        let deserialized: ChallengeEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.record_id, "test");
        assert_eq!(deserialized.content_hash, [0xEEu8; 32]);
        assert!(deserialized.merkle_proof.is_none());
    }

    // ─── Challenge pure-helper tests ─────────────────────────────────────────
    //
    // Fixture-free pure-helper tests on direct Challenge methods +
    // governance constants. No ChallengeState/Storage — just struct
    // construction and method calls.

    fn make_challenge(
        id: &str,
        jury: Vec<String>,
        votes: Vec<JuryVote>,
        verdict_at: Option<f64>,
        is_appeal: bool,
    ) -> Challenge {
        Challenge {
            id: id.into(),
            challenger: "alice".into(),
            accused: "bob".into(),
            challenge_type: ChallengeType::Spam,
            evidence: vec!["ev".into()],
            structured_evidence: Vec::new(),
            filed_at: 1000.0,
            status: ChallengeStatus::JuryVoting,
            jury,
            votes,
            is_appeal,
            verdict: None,
            verdict_at,
            slash_amount: None,
        }
    }

    /// pin all 7 governance constants AND the
    /// `APPEAL_JURY_SIZE = 2 · DEFAULT_JURY_SIZE` doubling relation.
    /// These values define the dispute economy — silent drift would
    /// break governance audits and slashing economics.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_governance_constants_pinned_with_appeal_doubling_invariant() {
        assert_eq!(DEFAULT_JURY_SIZE, 13, "session-143 raised from 5 to 13");
        assert_eq!(APPEAL_JURY_SIZE, 26, "appeal jury doubles initial");
        assert_eq!(
            APPEAL_JURY_SIZE,
            2 * DEFAULT_JURY_SIZE,
            "APPEAL_JURY_SIZE must remain exactly 2·DEFAULT_JURY_SIZE"
        );
        assert!(
            (SUPERMAJORITY_THRESHOLD - 0.75).abs() < 1e-12,
            "75% supermajority threshold"
        );
        assert_eq!(
            MIN_CHALLENGE_STAKE,
            10 * crate::accounting::types::BASE_UNITS_PER_BEAT,
            "10 beat in base units / 10^9 (anti-frivolous filings)"
        );
        assert!(
            (CHALLENGE_EVIDENCE_WINDOW_SECS - 7.0 * 86_400.0).abs() < 1e-9,
            "7-day evidence window"
        );
        assert!(
            (JURY_VOTING_WINDOW_SECS - 3.0 * 86_400.0).abs() < 1e-9,
            "3-day voting window"
        );
        assert!(
            (APPEAL_WINDOW_SECS - 2.0 * 86_400.0).abs() < 1e-9,
            "2-day appeal window"
        );
        // Lifecycle invariant: voting must finish strictly before evidence
        // window expires (else operators can't gather + present in time).
        assert!(
            JURY_VOTING_WINDOW_SECS < CHALLENGE_EVIDENCE_WINDOW_SECS,
            "voting window must be shorter than evidence window"
        );
    }

    /// `ChallengeStatus::as_str()` pins all 6 variants to their
    /// serialized strings. Wire-stable: a rename of any variant string
    /// breaks all consumers (explorer UI, audit pipelines, RPC clients).
    #[test]
    fn batch_b_challenge_status_as_str_pins_all_six_variants() {
        assert_eq!(ChallengeStatus::Filed.as_str(), "filed");
        assert_eq!(ChallengeStatus::JuryVoting.as_str(), "jury_voting");
        assert_eq!(ChallengeStatus::Verdict.as_str(), "verdict");
        assert_eq!(ChallengeStatus::Appeal.as_str(), "appeal");
        assert_eq!(ChallengeStatus::Final.as_str(), "final");
        assert_eq!(ChallengeStatus::Dismissed.as_str(), "dismissed");
    }

    #[allow(clippy::doc_lazy_continuation)]
    /// `Challenge::vote_tally()` + `has_supermajority()` direct
    /// invocation. The existing supermajority tests go through file_challenge
    /// + cast_vote (end-to-end); these pin the pure methods on hand-built
    /// Challenges, isolating the math from ChallengeState side effects.
    #[test]
    fn batch_b_vote_tally_and_supermajority_direct_method_invariants() {
        let jury: Vec<String> = (0..13).map(|i| format!("juror_{i}")).collect();

        // No votes: tally is (0, 0); has_supermajority returns None (incomplete).
        let empty = make_challenge("c-empty", jury.clone(), vec![], None, false);
        assert_eq!(empty.vote_tally(), (0, 0));
        assert_eq!(
            empty.has_supermajority(),
            None,
            "incomplete votes must return None (not Some(false))"
        );

        // 10 guilty / 3 not guilty out of 13 = 76.9% >= 75% → Some(true).
        let votes_guilty: Vec<JuryVote> = jury
            .iter()
            .enumerate()
            .map(|(i, j)| JuryVote {
                juror: j.clone(),
                guilty: i < 10,
                timestamp: 1001.0 + i as f64,
            })
            .collect();
        let guilty = make_challenge("c-g", jury.clone(), votes_guilty, None, false);
        assert_eq!(guilty.vote_tally(), (10, 3));
        assert_eq!(guilty.has_supermajority(), Some(true));

        // 9 guilty / 4 not = 69.2% < 75% → Some(false) (dismissal).
        let votes_below: Vec<JuryVote> = jury
            .iter()
            .enumerate()
            .map(|(i, j)| JuryVote {
                juror: j.clone(),
                guilty: i < 9,
                timestamp: 1001.0 + i as f64,
            })
            .collect();
        let below = make_challenge("c-b", jury, votes_below, None, false);
        assert_eq!(below.vote_tally(), (9, 4));
        assert_eq!(below.has_supermajority(), Some(false));
    }

    /// `Challenge::in_appeal_window()` 4-branch truth table:
    /// (1) is_appeal=true → false unconditionally (no appeals of appeals),
    /// (2) verdict_at=None → false (no verdict to appeal),
    /// (3) verdict reached, now within APPEAL_WINDOW_SECS → true,
    /// (4) verdict reached, now past APPEAL_WINDOW_SECS → false.
    #[test]
    fn batch_b_in_appeal_window_four_branch_truth_table() {
        let jury = vec!["j1".to_string()];

        // (1) is_appeal=true with verdict in-window → still false.
        let appeal_round = make_challenge(
            "c1",
            jury.clone(),
            vec![],
            Some(1000.0),
            true,
        );
        assert!(
            !appeal_round.in_appeal_window(1100.0),
            "cannot appeal an appeal (is_appeal=true → false)"
        );

        // (2) verdict_at=None → false (no verdict to appeal yet).
        let no_verdict = make_challenge("c2", jury.clone(), vec![], None, false);
        assert!(
            !no_verdict.in_appeal_window(1100.0),
            "no verdict_at → false"
        );

        // (3) verdict reached at t=1000, query at t=1100 → in-window.
        let in_window = make_challenge("c3", jury.clone(), vec![], Some(1000.0), false);
        assert!(
            in_window.in_appeal_window(1100.0),
            "100s after verdict (< 2d) → in-window"
        );
        // Boundary: now - verdict_at = APPEAL_WINDOW_SECS - 1 → still in-window.
        assert!(
            in_window.in_appeal_window(1000.0 + APPEAL_WINDOW_SECS - 1.0),
            "just under APPEAL_WINDOW_SECS → in-window"
        );

        // (4) verdict reached at t=1000, query past APPEAL_WINDOW_SECS → expired.
        let expired = make_challenge("c4", jury, vec![], Some(1000.0), false);
        assert!(
            !expired.in_appeal_window(1000.0 + APPEAL_WINDOW_SECS),
            "exactly at APPEAL_WINDOW_SECS → expired (strict <)"
        );
        assert!(
            !expired.in_appeal_window(1000.0 + APPEAL_WINDOW_SECS + 1.0),
            "past APPEAL_WINDOW_SECS → expired"
        );
    }

    /// `verify_challenge()` non-File error paths + `parse_str`
    /// unknown returns None. Existing tests cover the File path (valid,
    /// invalid_type, empty_evidence); these pin the Vote and Appeal
    /// branches that rely on non-empty challenge_id and reason.
    #[test]
    fn batch_b_verify_challenge_vote_appeal_error_paths_and_parse_str_unknown() {
        // Vote: empty challenge_id → Err
        let bad_vote = ParsedChallengeOp::Vote {
            challenge_id: String::new(),
            guilty: true,
        };
        assert!(
            verify_challenge(&bad_vote).is_err(),
            "Vote with empty challenge_id must error"
        );
        // Vote: non-empty challenge_id → Ok
        let good_vote = ParsedChallengeOp::Vote {
            challenge_id: "c1".into(),
            guilty: false,
        };
        assert!(
            verify_challenge(&good_vote).is_ok(),
            "Vote with valid challenge_id must pass"
        );

        // Appeal: empty challenge_id → Err
        let appeal_no_id = ParsedChallengeOp::Appeal {
            challenge_id: String::new(),
            reason: "I was framed".into(),
        };
        assert!(
            verify_challenge(&appeal_no_id).is_err(),
            "Appeal with empty challenge_id must error"
        );

        // Appeal: empty reason → Err
        let appeal_no_reason = ParsedChallengeOp::Appeal {
            challenge_id: "c1".into(),
            reason: String::new(),
        };
        assert!(
            verify_challenge(&appeal_no_reason).is_err(),
            "Appeal with empty reason must error"
        );

        // Appeal: both fields populated → Ok
        let good_appeal = ParsedChallengeOp::Appeal {
            challenge_id: "c1".into(),
            reason: "evidence was insufficient".into(),
        };
        assert!(
            verify_challenge(&good_appeal).is_ok(),
            "Appeal with both fields → ok"
        );

        // ChallengeType::parse_str: unknown variant returns None.
        assert!(
            ChallengeType::parse_str("nonsense").is_none(),
            "unknown challenge_type string must return None"
        );
        assert!(
            ChallengeType::parse_str("").is_none(),
            "empty challenge_type string must return None"
        );
    }
}

// ─── Epoch Challenges (Layered Consensus Layer 3) ───────────────────────────

use crate::ZoneId;

/// Evidence types for epoch challenges.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochChallengeEvidence {
    /// Record has invalid Dilithium3 signature.
    InvalidSignature,
    /// Record spends more than available balance (double spend).
    DoubleSpend,
    /// Record has malformed wire format.
    FormatViolation,
    /// Record fails entropy check (anti-spam).
    EntropyViolation,
    /// Duplicate record in epoch.
    Duplicate,
}

/// A challenge against a specific record within a sealed epoch.
///
/// Layered consensus Layer 3 (internal design notes):
/// Fisherman can challenge individual records within sealed epochs.
/// The challenge must include a Merkle proof showing the record IS
/// in the challenged epoch.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EpochChallenge {
    /// Challenge ID.
    pub id: String,
    /// Epoch number containing the challenged record.
    pub epoch_number: u64,
    /// Zone of the epoch.
    pub zone: ZoneId,
    /// Hash of the challenged record.
    pub challenged_record_hash: [u8; 32],
    /// Evidence type.
    pub evidence: EpochChallengeEvidence,
    /// Merkle proof that the record is in the epoch's Merkle tree.
    /// Path from leaf to root (siblings along the path).
    pub merkle_proof: Vec<[u8; 32]>,
    /// Who filed the challenge.
    pub challenger: String,
    /// When filed.
    pub filed_at: f64,
    /// Jury for this challenge.
    pub jury: Vec<String>,
    /// Votes.
    pub votes: Vec<JuryVote>,
    /// Verdict.
    pub verdict: Option<bool>,
}

/// Differentiated penalty structure for epoch challenges.
///
/// internal design notes:
/// - Anchor (epoch proposer): FULL slash — they built the Merkle tree including the bad record.
/// - Attesting witnesses: 10-20% slash — they attested to batch, incentivized to spot-check.
/// - Non-attesting witnesses: 0% penalty — choosing not to attest is safe.
///
/// Nash equilibrium: anchors validate carefully (full slash risk),
/// witnesses spot-check (reduced slash + reputation damage),
/// fishermen monitor (challenger reward).
#[derive(Debug, Clone)]
pub struct DifferentiatedPenalty {
    /// Anchor's slash percentage (of their largest active stake).
    pub anchor_slash_pct: f64,
    /// Attesting witnesses' slash percentage.
    pub witness_slash_pct: f64,
}

impl DifferentiatedPenalty {
    /// Default penalties per internal design notes.
    pub fn default_penalties() -> Self {
        Self {
            anchor_slash_pct: 1.0,    // 100% — full slash
            witness_slash_pct: 0.15,  // 15% — middle of 10-20% range
        }
    }

    /// Compute slash amount for the anchor.
    pub fn anchor_slash(&self, anchor_stake: u64) -> u64 {
        (anchor_stake as f64 * self.anchor_slash_pct) as u64
    }

    /// Compute slash amount for an attesting witness.
    pub fn witness_slash(&self, witness_stake: u64) -> u64 {
        (witness_stake as f64 * self.witness_slash_pct) as u64
    }
}

/// State tracker for epoch challenges.
#[derive(Debug, Clone, Default)]
pub struct EpochChallengeState {
    /// Active epoch challenges: challenge_id → EpochChallenge.
    pub challenges: HashMap<String, EpochChallenge>,
}

/// Parameters bundle for [`EpochChallengeState::file_epoch_challenge`].
pub struct EpochChallengeFiling<'a> {
    pub id: String,
    pub epoch_number: u64,
    pub zone: ZoneId,
    pub challenged_record_hash: [u8; 32],
    pub evidence: EpochChallengeEvidence,
    pub merkle_proof: Vec<[u8; 32]>,
    pub challenger: String,
    pub timestamp: f64,
    pub eligible_jurors: &'a [String],
    pub epoch_vrf_output: Option<&'a [u8; 32]>,
}

impl EpochChallengeState {
    pub fn new() -> Self {
        Self {
            challenges: HashMap::new(),
        }
    }

    /// File an epoch challenge.
    ///
    /// The challenger must provide a Merkle proof that the challenged record
    /// is actually in the epoch seal's Merkle tree.
    pub fn file_epoch_challenge(
        &mut self,
        filing: EpochChallengeFiling<'_>,
    ) -> Result<Vec<String>> {
        let EpochChallengeFiling {
            id,
            epoch_number,
            zone,
            challenged_record_hash,
            evidence,
            merkle_proof,
            challenger,
            timestamp,
            eligible_jurors,
            epoch_vrf_output,
        } = filing;

        if self.challenges.contains_key(&id) {
            return Err(ElaraError::Ledger(format!("epoch challenge {} already exists", id)));
        }

        // Select jury using VRF
        let epoch_seed = epoch_vrf_output
            .map(|o| o.to_vec())
            .unwrap_or_else(|| sha3_256(id.as_bytes()).to_vec());
        let jury = select_jury_with_epoch(
            &id, &challenger, "",
            eligible_jurors, DEFAULT_JURY_SIZE, &epoch_seed,
        );

        let challenge = EpochChallenge {
            id: id.clone(),
            epoch_number,
            zone,
            challenged_record_hash,
            evidence,
            merkle_proof,
            challenger,
            filed_at: timestamp,
            jury: jury.clone(),
            votes: Vec::new(),
            verdict: None,
        };

        self.challenges.insert(id, challenge);
        Ok(jury)
    }

    /// Cast a jury vote on an epoch challenge.
    pub fn cast_vote(
        &mut self,
        challenge_id: &str,
        juror: &str,
        guilty: bool,
        timestamp: f64,
    ) -> Result<Option<bool>> {
        let challenge = self.challenges.get_mut(challenge_id)
            .ok_or_else(|| ElaraError::Ledger(format!("epoch challenge {} not found", challenge_id)))?;

        // Check juror is on the jury
        if !challenge.jury.contains(&juror.to_string()) {
            return Err(ElaraError::Ledger(format!("{} is not on the jury", juror)));
        }

        // Check not already voted
        if challenge.votes.iter().any(|v| v.juror == juror) {
            return Err(ElaraError::Ledger(format!("{} already voted", juror)));
        }

        challenge.votes.push(JuryVote {
            juror: juror.to_string(),
            guilty,
            timestamp,
        });

        // Check if supermajority reached
        if challenge.votes.len() >= challenge.jury.len() {
            let guilty_count = challenge.votes.iter().filter(|v| v.guilty).count();
            let ratio = guilty_count as f64 / challenge.jury.len() as f64;
            let verdict = ratio >= SUPERMAJORITY_THRESHOLD;
            challenge.verdict = Some(verdict);
            return Ok(Some(verdict));
        }

        Ok(None)
    }

    /// Count of open (unresolved) epoch challenges.
    pub fn open_count(&self) -> usize {
        self.challenges.values().filter(|c| c.verdict.is_none()).count()
    }

    /// Check if a specific epoch has any open challenges.
    pub fn has_open_challenges(&self, zone: &ZoneId, epoch_number: u64) -> bool {
        self.challenges.values().any(|c| {
            c.zone == *zone && c.epoch_number == epoch_number && c.verdict.is_none()
        })
    }

    /// Prune resolved challenges older than cutoff.
    pub fn prune_resolved(&mut self, cutoff: f64) -> usize {
        let before = self.challenges.len();
        self.challenges.retain(|_, c| {
            c.verdict.is_none() || c.filed_at > cutoff
        });
        before - self.challenges.len()
    }
}

// ─── Epoch Challenge Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod epoch_challenge_tests {
    use super::*;

    fn jurors() -> Vec<String> {
        (0..20).map(|i| format!("juror-{i}")).collect()
    }

    #[test]
    fn test_file_epoch_challenge() {
        let mut state = EpochChallengeState::new();
        let zone = ZoneId::from_legacy(0);
        let hash = [42u8; 32];

        let jury = state.file_epoch_challenge(EpochChallengeFiling {
            id: "ec-1".into(),
            epoch_number: 5,
            zone,
            challenged_record_hash: hash,
            evidence: EpochChallengeEvidence::InvalidSignature,
            merkle_proof: vec![[1u8; 32], [2u8; 32]], // mock merkle proof
            challenger: "challenger-1".into(),
            timestamp: 1000.0,
            eligible_jurors: &jurors(),
            epoch_vrf_output: None,
        }).unwrap();

        assert_eq!(jury.len(), DEFAULT_JURY_SIZE);
        assert_eq!(state.open_count(), 1);
    }

    #[test]
    fn test_epoch_challenge_verdict() {
        let mut state = EpochChallengeState::new();
        let zone = ZoneId::from_legacy(0);

        let jury = state.file_epoch_challenge(EpochChallengeFiling {
            id: "ec-2".into(),
            epoch_number: 0,
            zone: zone.clone(),
            challenged_record_hash: [0u8; 32],
            evidence: EpochChallengeEvidence::DoubleSpend,
            merkle_proof: vec![],
            challenger: "alice".into(),
            timestamp: 100.0,
            eligible_jurors: &jurors(),
            epoch_vrf_output: None,
        }).unwrap();

        // All jurors vote guilty
        for juror in &jury {
            let result = state.cast_vote("ec-2", juror, true, 200.0).unwrap();
            if juror == jury.last().unwrap() {
                assert_eq!(result, Some(true)); // verdict on last vote
            }
        }

        assert_eq!(state.open_count(), 0);
    }

    #[test]
    fn test_differentiated_penalty() {
        let penalties = DifferentiatedPenalty::default_penalties();

        // Anchor with 1000 stake → full slash
        assert_eq!(penalties.anchor_slash(1000), 1000);

        // Witness with 1000 stake → 15% slash
        assert_eq!(penalties.witness_slash(1000), 150);
    }

    #[test]
    fn test_has_open_challenges() {
        let mut state = EpochChallengeState::new();
        let zone = ZoneId::from_legacy(0);

        assert!(!state.has_open_challenges(&zone, 5));

        state.file_epoch_challenge(EpochChallengeFiling {
            id: "ec-3".into(),
            epoch_number: 5,
            zone: zone.clone(),
            challenged_record_hash: [0u8; 32],
            evidence: EpochChallengeEvidence::FormatViolation,
            merkle_proof: vec![],
            challenger: "bob".into(),
            timestamp: 100.0,
            eligible_jurors: &jurors(),
            epoch_vrf_output: None,
        }).unwrap();

        assert!(state.has_open_challenges(&zone, 5));
        assert!(!state.has_open_challenges(&zone, 6)); // different epoch
    }

    #[test]
    fn test_prune_resolved_challenges() {
        let mut state = EpochChallengeState::new();
        let zone = ZoneId::from_legacy(0);

        let jury = state.file_epoch_challenge(EpochChallengeFiling {
            id: "ec-4".into(),
            epoch_number: 0,
            zone,
            challenged_record_hash: [0u8; 32],
            evidence: EpochChallengeEvidence::Duplicate,
            merkle_proof: vec![],
            challenger: "alice".into(),
            timestamp: 50.0,
            eligible_jurors: &jurors(),
            epoch_vrf_output: None,
        }).unwrap();

        // Vote to resolve
        for juror in &jury {
            let _ = state.cast_vote("ec-4", juror, true, 60.0);
        }

        assert_eq!(state.challenges.len(), 1);
        let pruned = state.prune_resolved(100.0); // cutoff after filed_at
        assert_eq!(pruned, 1);
        assert!(state.challenges.is_empty());
    }
}
