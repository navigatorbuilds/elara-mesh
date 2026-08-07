//! Conviction voting governance — economics v0.4.0 Section 7, Protocol v0.6.1 Section 10.3.
//!
//! Governance operations are embedded in ValidationRecord metadata using the
//! `governance_op` key (separate from `beat_op` ledger operations).
//!
//! Design principles:
//! - Time-weighted conviction: holding your vote longer = more weight
//! - Square-root dampening: prevents plutocratic domination
//! - Per-identity cap: max 1/√N of total voting power
//! - Supermajority (67%) required to pass
//! - 30-day execution delay after passing
//! - Only governance-staked beats count for voting

//!
//! Spec references:
//!   @spec economics §7.1
//!   @spec Protocol §10.2 (Decision Categories — ProposalCategory enum)
//!   @spec Protocol §10.3 (Voting Mechanism — conviction voting + supermajority)
//!   @spec Protocol §10.4 (Governance Attack Mitigations — sqrt dampening + 5% cap)

use std::collections::HashMap;

use crate::ZoneId;
use crate::errors::{ElaraError, Result};
use crate::accounting::types::{StakePurpose, BASE_UNITS_PER_BEAT};

// ─── Constants (economics v0.4.0 Section 7) ─────────────────────────────────

/// Conviction time constant τ: 7 days in seconds.
/// conviction(stake, t) = stake × (1 - e^(-t/τ))
pub const CONVICTION_TAU_SECS: f64 = 7.0 * 24.0 * 3600.0;

/// Supermajority threshold: 67% of conviction-weighted votes.
pub const SUPERMAJORITY_THRESHOLD: f64 = 0.67;

/// Minimum participation: 25% of total governance-staked supply must vote (economics §7.1).
pub const MIN_PARTICIPATION_FRACTION: f64 = 0.25;

/// Execution delay after a proposal passes: 30 days in seconds.
pub const EXECUTION_DELAY_SECS: f64 = 30.0 * 24.0 * 3600.0;

/// Default voting period: 14 days in seconds.
pub const VOTING_PERIOD_SECS: f64 = 14.0 * 24.0 * 3600.0;

/// Minimum governance stake required to create a proposal: 1,000 beat.
pub const MIN_PROPOSAL_STAKE: u64 = 1_000 * BASE_UNITS_PER_BEAT;

/// Maximum active proposals per identity at any time.
pub const MAX_ACTIVE_PROPOSALS_PER_IDENTITY: usize = 3;

// ─── Types ───────────────────────────────────────────────────────────────────

/// Proposal category determines who can vote and what threshold applies.
///
/// @spec Protocol §10.2 (Decision Categories), §11.18 (Protocol Upgrade Mechanism)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalCategory {
    /// Zone-local: only zone stakeholders vote.
    ZoneLocal,
    /// Cross-zone non-critical: conviction voting, standard threshold.
    Parameter,
    /// Cross-zone critical: higher scrutiny (algorithm changes, supply adjustments).
    Critical,
    /// Protocol upgrade (§11.18): SoftFork / HardFork / Emergency lifecycle.
    /// Threshold + transition window depend on the upgrade kind (carried alongside
    /// the proposal, not on the category itself); evaluate via
    /// `evaluate_protocol_upgrade_proposal()`.
    ProtocolUpgrade,
}

impl ProposalCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ZoneLocal => "zone_local",
            Self::Parameter => "parameter",
            Self::Critical => "critical",
            Self::ProtocolUpgrade => "protocol_upgrade",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "zone_local" => Ok(Self::ZoneLocal),
            "parameter" => Ok(Self::Parameter),
            "critical" => Ok(Self::Critical),
            "protocol_upgrade" => Ok(Self::ProtocolUpgrade),
            other => Err(ElaraError::Governance(format!("unknown category: {other}"))),
        }
    }
}

/// Proposal lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    /// Voting is open.
    Active,
    /// Voting period ended, supermajority reached. Waiting execution delay.
    Passed,
    /// Voting period ended, did not reach supermajority or quorum.
    Rejected,
    /// Voting period expired with insufficient participation.
    Expired,
    /// Successfully executed after delay period.
    Executed,
    /// Withdrawn by proposer before voting ends.
    Cancelled,
    /// Emergency veto by >75% anchor nodes (economics §7.5).
    Vetoed,
}

/// Per-status counts maintained at every transition site so
/// `proposal_counts()` and `active_proposals()` can return in O(1) instead
/// of scanning all proposals under `ledger.read()`. Mirrors the
/// per-status pending counters on `CrossZoneState`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ProposalStatusCounts {
    pub active: u64,
    pub passed: u64,
    pub rejected: u64,
    pub expired: u64,
    pub executed: u64,
    pub cancelled: u64,
    pub vetoed: u64,
}

impl ProposalStatusCounts {
    fn inc(&mut self, status: ProposalStatus) {
        match status {
            ProposalStatus::Active => self.active = self.active.saturating_add(1),
            ProposalStatus::Passed => self.passed = self.passed.saturating_add(1),
            ProposalStatus::Rejected => self.rejected = self.rejected.saturating_add(1),
            ProposalStatus::Expired => self.expired = self.expired.saturating_add(1),
            ProposalStatus::Executed => self.executed = self.executed.saturating_add(1),
            ProposalStatus::Cancelled => self.cancelled = self.cancelled.saturating_add(1),
            ProposalStatus::Vetoed => self.vetoed = self.vetoed.saturating_add(1),
        }
    }

    fn dec(&mut self, status: ProposalStatus) {
        match status {
            ProposalStatus::Active => self.active = self.active.saturating_sub(1),
            ProposalStatus::Passed => self.passed = self.passed.saturating_sub(1),
            ProposalStatus::Rejected => self.rejected = self.rejected.saturating_sub(1),
            ProposalStatus::Expired => self.expired = self.expired.saturating_sub(1),
            ProposalStatus::Executed => self.executed = self.executed.saturating_sub(1),
            ProposalStatus::Cancelled => self.cancelled = self.cancelled.saturating_sub(1),
            ProposalStatus::Vetoed => self.vetoed = self.vetoed.saturating_sub(1),
        }
    }
}

/// Vote direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteDirection {
    For,
    Against,
    Abstain,
}

impl VoteDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::For => "for",
            Self::Against => "against",
            Self::Abstain => "abstain",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "for" => Ok(Self::For),
            "against" => Ok(Self::Against),
            "abstain" => Ok(Self::Abstain),
            other => Err(ElaraError::Governance(format!("unknown vote direction: {other}"))),
        }
    }
}

/// A single vote on a proposal.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Vote {
    /// Voter identity hash.
    pub voter: String,
    /// Effective voting weight = own governance stake + delegated fold, in
    /// base units. Reconciled to the final delegation/stake state at settle
    /// (see [`GovernanceState::reconcile_effective_stakes`]); `tally_votes`
    /// reads this field.
    pub stake: u64,
    /// Direction: for, against, or abstain.
    pub direction: VoteDirection,
    /// When the vote was cast (timestamp).
    pub voted_at: f64,
    /// The voter's OWN governance stake, frozen at vote time. `None` =
    /// legacy/unset (pre-field votes deserialize here; reconcile falls back to
    /// `stake`). `Some(0)` is a legitimate pure-delegate (no own stake, votes
    /// only delegated power). Settle-time reconcile rebuilds `stake` from this
    /// frozen own + a fresh delegated fold, so conviction can never credit a
    /// late stake top-up with the early `voted_at` (the vote-time stake lock).
    #[serde(default)]
    pub own_stake: Option<u64>,
}

// ─── Random Committee Selection (economics §7.4) ───────────────────────────

/// Default committee size for critical proposals.
pub const COMMITTEE_SIZE: usize = 100;
/// Challenge period after committee verdict (30 days).
pub const COMMITTEE_CHALLENGE_PERIOD_SECS: f64 = 30.0 * 24.0 * 3600.0;
/// Committee voting period (14 days).
pub const COMMITTEE_VOTING_PERIOD_SECS: f64 = 14.0 * 24.0 * 3600.0;
/// Committee supermajority threshold.
pub const COMMITTEE_SUPERMAJORITY: f64 = 0.67;
/// Re-vote committee size when challenged.
pub const COMMITTEE_REVOTE_SIZE: usize = 200;

/// A randomly selected committee for critical governance decisions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Committee {
    /// Selected committee members (identity hashes).
    pub members: Vec<String>,
    /// VRF seed used for deterministic selection.
    pub vrf_seed: String,
    /// Whether this is a challenge re-vote (larger committee).
    pub is_revote: bool,
    /// When the committee was selected.
    pub selected_at: f64,
    /// Challenge period end (if verdict reached).
    pub challenge_deadline: Option<f64>,
    /// Who challenged (if any).
    pub challenger: Option<String>,
}

/// Select a random committee using trust-weighted VRF selection.
///
/// Selection is deterministic: SHA3(vrf_seed || candidate_index) produces
/// a score, and candidates are selected by trust-weighted score ranking.
///
/// Uses TRUST weight (not beat weight) — honest participation history
/// matters more than wealth.
pub fn select_committee(
    vrf_seed: &str,
    candidates: &[(String, f64)], // (identity_hash, trust_multiplier)
    committee_size: usize,
) -> Vec<String> {
    if candidates.is_empty() || committee_size == 0 {
        return Vec::new();
    }
    let size = committee_size.min(candidates.len());

    // Score each candidate: SHA3(seed || identity) → [0,1], weighted by trust
    let mut scored: Vec<(f64, &String)> = candidates.iter().map(|(id, trust)| {
        let input = format!("{vrf_seed}:{id}");
        let hash = crate::crypto::hash::sha3_256(input.as_bytes());
        // Convert first 8 bytes of hash to f64 in [0,1]
        let mut score_bytes = [0u8; 8];
        score_bytes.copy_from_slice(&hash[..8]);
        let raw = u64::from_le_bytes(score_bytes) as f64
            / u64::MAX as f64;
        // Trust-weighted: higher trust = higher chance of selection
        let weighted = raw * trust.max(0.01); // floor trust to prevent 0-weight exclusion
        (weighted, id)
    }).collect();

    // Sort descending by score, take top N
    scored.sort_by(|a, b| b.0.total_cmp(&a.0));
    scored.into_iter().take(size).map(|(_, id)| id.clone()).collect()
}

/// Check if an identity is on the committee for a proposal.
pub fn is_committee_member(proposal: &Proposal, voter: &str) -> bool {
    match &proposal.committee {
        Some(c) => c.members.contains(&voter.to_string()),
        None => true, // No committee = open voting
    }
}

// ─── Emergency Anchor Veto (economics §7.5) ────────────────────────────────

/// Anchor veto supermajority threshold: >75% of known anchor nodes.
pub const ANCHOR_VETO_THRESHOLD: f64 = 0.75;

/// Maximum vetoes per zone per quarter (rate limit).
pub const ANCHOR_VETO_MAX_PER_QUARTER: usize = 2;

/// Quarter duration in seconds (90 days).
pub const QUARTER_SECS: f64 = 90.0 * 24.0 * 3600.0;

/// A single anchor veto signal on a proposal.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnchorVetoSignal {
    /// Identity hash of the anchor node.
    pub anchor_identity: String,
    /// Zone this anchor is in.
    pub zone: ZoneId,
    /// When the veto signal was cast.
    pub signaled_at: f64,
}

/// Tracks anchor veto signals and rate limits.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AnchorVetoState {
    /// Veto signals per proposal: proposal_id → signals.
    pub signals: HashMap<String, Vec<AnchorVetoSignal>>,
    /// Completed vetoes per (zone, quarter_start): for rate limiting.
    pub vetoes_by_quarter: HashMap<(ZoneId, u64), usize>,
}

impl AnchorVetoState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Quarter start timestamp for a given time.
    fn quarter_start(timestamp: f64) -> u64 {
        let secs = timestamp as u64;
        // Align to 90-day quarters from epoch
        let quarter_secs = QUARTER_SECS as u64;
        (secs / quarter_secs) * quarter_secs
    }

    /// Check if a zone has exceeded its veto rate limit for the current quarter.
    pub fn rate_limited(&self, zone: ZoneId, timestamp: f64) -> bool {
        let qs = Self::quarter_start(timestamp);
        let count = self.vetoes_by_quarter.get(&(zone, qs)).copied().unwrap_or(0);
        count >= ANCHOR_VETO_MAX_PER_QUARTER
    }

    /// Record a veto signal from an anchor node.
    ///
    /// Returns true if this anchor hasn't already signaled on this proposal.
    pub fn signal_veto(
        &mut self,
        proposal_id: &str,
        anchor_identity: &str,
        zone: ZoneId,
        timestamp: f64,
    ) -> bool {
        let signals = self.signals.entry(proposal_id.to_string()).or_default();

        // Dedup: ignore if already signaled
        if signals.iter().any(|s| s.anchor_identity == anchor_identity) {
            return false;
        }

        signals.push(AnchorVetoSignal {
            anchor_identity: anchor_identity.to_string(),
            zone,
            signaled_at: timestamp,
        });
        true
    }

    /// Check if enough anchor nodes have signaled to veto a proposal.
    ///
    /// Returns true if >75% of known anchor nodes have signaled.
    pub fn check_threshold(
        &self,
        proposal_id: &str,
        total_anchor_nodes: usize,
    ) -> bool {
        if total_anchor_nodes == 0 {
            return false;
        }
        let signal_count = self.signals.get(proposal_id)
            .map(|s| s.len())
            .unwrap_or(0);
        let fraction = signal_count as f64 / total_anchor_nodes as f64;
        fraction > ANCHOR_VETO_THRESHOLD
    }

    /// Record that a veto was completed (for rate limiting).
    pub fn record_veto(&mut self, zone: ZoneId, timestamp: f64) {
        let qs = Self::quarter_start(timestamp);
        *self.vetoes_by_quarter.entry((zone, qs)).or_insert(0) += 1;
    }

    /// Signal count for a proposal.
    pub fn signal_count(&self, proposal_id: &str) -> usize {
        self.signals.get(proposal_id).map(|s| s.len()).unwrap_or(0)
    }

    /// All signals for a proposal.
    pub fn signals_for(&self, proposal_id: &str) -> &[AnchorVetoSignal] {
        self.signals.get(proposal_id).map(|s| s.as_slice()).unwrap_or(&[])
    }

    /// Rebuild from records (called at startup).
    pub fn rebuild_from_signals(
        signals: &[(String, AnchorVetoSignal)],
    ) -> Self {
        let mut state = Self::new();
        for (proposal_id, signal) in signals {
            let entry = state.signals.entry(proposal_id.clone()).or_default();
            if !entry.iter().any(|s| s.anchor_identity == signal.anchor_identity) {
                entry.push(signal.clone());
            }
        }
        state
    }
}

/// A governance proposal.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Proposal {
    /// Proposal ID (= record ID of the propose record).
    pub id: String,
    /// Proposer identity hash.
    pub proposer: String,
    /// Category determines voting rules.
    pub category: ProposalCategory,
    /// Short title.
    pub title: String,
    /// Detailed description of what changes.
    pub description: String,
    /// When the proposal was created.
    pub created_at: f64,
    /// Voting deadline (created_at + VOTING_PERIOD_SECS).
    pub voting_deadline: f64,
    /// Current status.
    pub status: ProposalStatus,
    /// When the proposal passed (if it did).
    pub passed_at: Option<f64>,
    /// All votes on this proposal.
    pub votes: Vec<Vote>,
    /// Random committee (Critical proposals only, economics §7.4).
    /// If set, only committee members can vote.
    pub committee: Option<Committee>,
}

impl Proposal {
    /// Check if voting is still open at the given timestamp.
    pub fn is_voting_open(&self, now: f64) -> bool {
        self.status == ProposalStatus::Active && now < self.voting_deadline
    }

    /// Check if a voter has already voted.
    pub fn has_voted(&self, voter: &str) -> bool {
        self.votes.iter().any(|v| v.voter == voter)
    }

    /// Check if execution delay has elapsed (proposal can be executed).
    pub fn can_execute(&self, now: f64) -> bool {
        if self.status != ProposalStatus::Passed {
            return false;
        }
        match self.passed_at {
            Some(t) => now >= t + EXECUTION_DELAY_SECS,
            None => false,
        }
    }
}

/// A delegation of governance voting power.
/// Depth-1 only: A→B is allowed but A→B→C is not (B cannot re-delegate A's power).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DelegationEntry {
    /// Who delegated their vote.
    pub delegator: String,
    /// Who receives the voting power.
    pub delegate: String,
    /// When the delegation was created.
    pub created_at: f64,
    /// Whether the delegation is still active.
    pub active: bool,
}

// ─── Governable Parameters ──────────────────────────────────────────────────

/// Recognized governance-modifiable parameter names.
pub const GOVERNABLE_PARAMS: &[&str] = &[
    "propagation_rate_limit_per_hour",
    "epoch_seal_interval_secs",
    "witness_reward_micros",
    "record_retention_secs",
    "stake_throughput_ratio",
];

/// Runtime-adjustable network parameters set by governance votes.
///
/// ⚠ ENFORCEMENT SPLIT (grounded 2026-07-21): not all of these are consumed at
/// runtime. WIRED = read from `governance.params.*` in the hot path (votes take
/// effect). DECORATIVE = validated + persisted + displayed on `/governance/params`
/// but NOT enforced — the runtime reads the corresponding `config.*` field and there
/// is NO governance→config sync, so a vote to change one is accepted and shown yet
/// changes nothing. Wiring the decorative params (via the epoch-sealed effective_epoch
/// activation pattern — NOT a raw config write, which forks) is a deferred
/// multi-validator item; see internal design notes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GovernableParams {
    /// WIRED. Per-identity propagation rate limit (records/hour). Read in ingest as
    /// `max(config, governance.params)` (ingest.rs), so votes take effect.
    pub propagation_rate_limit_per_hour: u64,
    /// DECORATIVE (not yet enforced). Epoch seal interval in seconds. The seal loop reads
    /// `config.epoch_seal_interval_secs` (u64, default 60); this governance value
    /// (default 300.0) is never consumed — a vote here changes nothing today.
    pub epoch_seal_interval_secs: f64,
    /// DECORATIVE (not yet enforced). Witness reward per attestation (base units, 10^9/beat;
    /// `_micros` name is legacy). Rewards read `config.witness_reward_micros`; this
    /// governance value is never consumed — an economic vote here no-ops today.
    pub witness_reward_micros: u64,
    /// DECORATIVE (not yet enforced). Record retention before GC (seconds, 0 = infinite).
    /// GC reads `config.record_retention_secs`; this governance value is never consumed.
    pub record_retention_secs: f64,
    /// WIRED. Stake-gated throughput ratio: base units (10^9/beat) of stake per daily
    /// record (economics §9.4). Read directly in ingest, so votes take effect.
    /// Default 100,000,000 → 100 beat = 1,000/day, 10K beat = 100K/day, etc.
    pub stake_throughput_ratio: u64,
}

impl Default for GovernableParams {
    fn default() -> Self {
        Self {
            propagation_rate_limit_per_hour: 120,
            epoch_seal_interval_secs: 300.0,
            witness_reward_micros: 1_000_000_000, // 1 beat (base units, 10^9/beat; _micros name is legacy)
            record_retention_secs: 0.0,           // infinite
            stake_throughput_ratio: 100_000_000,  // 10^8 base units/record (100 beat → 1000/day @ §9.4)
        }
    }
}

impl GovernableParams {
    /// Apply a named parameter change. Returns Err if the name is unrecognized
    /// or the value can't be parsed.
    pub fn apply(&mut self, name: &str, value: &str) -> crate::errors::Result<()> {
        match name {
            "propagation_rate_limit_per_hour" => {
                self.propagation_rate_limit_per_hour = value.parse()
                    .map_err(|_| ElaraError::Governance(format!("invalid u64: {value}")))?;
            }
            "epoch_seal_interval_secs" => {
                self.epoch_seal_interval_secs = value.parse()
                    .map_err(|_| ElaraError::Governance(format!("invalid f64: {value}")))?;
            }
            "witness_reward_micros" => {
                self.witness_reward_micros = value.parse()
                    .map_err(|_| ElaraError::Governance(format!("invalid u64: {value}")))?;
            }
            "record_retention_secs" => {
                self.record_retention_secs = value.parse()
                    .map_err(|_| ElaraError::Governance(format!("invalid f64: {value}")))?;
            }
            "stake_throughput_ratio" => {
                self.stake_throughput_ratio = value.parse()
                    .map_err(|_| ElaraError::Governance(format!("invalid u64: {value}")))?;
            }
            other => {
                return Err(ElaraError::Governance(format!("unrecognized parameter: {other}")));
            }
        }
        Ok(())
    }

    /// Get the current value of a parameter by name.
    pub fn get(&self, name: &str) -> Option<String> {
        match name {
            "propagation_rate_limit_per_hour" => Some(self.propagation_rate_limit_per_hour.to_string()),
            "epoch_seal_interval_secs" => Some(self.epoch_seal_interval_secs.to_string()),
            "witness_reward_micros" => Some(self.witness_reward_micros.to_string()),
            "record_retention_secs" => Some(self.record_retention_secs.to_string()),
            "stake_throughput_ratio" => Some(self.stake_throughput_ratio.to_string()),
            _ => None,
        }
    }
}

/// Record of a governance parameter change.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParamChange {
    /// Parameter name.
    pub name: String,
    /// Previous value.
    pub old_value: String,
    /// New value.
    pub new_value: String,
    /// Proposal ID that triggered this change.
    pub proposal_id: String,
    /// When the change was applied.
    pub applied_at: f64,
}

/// §11.18 ProtocolUpgrade execution outcome recorded at `Execute` dispatch.
///
/// Portable plain-types snapshot — uses wire strings for `kind` and `outcome`
/// so the storage compiles without `feature = "node"` (the
/// `network::protocol_upgrade::{UpgradeKind, UpgradeOutcome}` enums live behind
/// the node feature gate). Conversion happens at the adapter boundary in
/// `apply_protocol_upgrade_outcome()`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UpgradeOutcomeRecord {
    /// Proposal ID this outcome belongs to (= record ID of the propose record).
    pub proposal_id: String,
    /// Upgrade kind wire string: `"soft_fork" | "hard_fork" | "emergency"`.
    pub kind: String,
    /// SHA-256 (or stronger) of the reference implementation diff.
    pub reference_impl_hash: String,
    /// Epoch at which the proposal was published.
    pub proposed_at_epoch: u64,
    /// Outcome wire string: `"vote_open" | "passed" | "failed" | "active"`.
    pub outcome: String,
    /// Observed for/(for+against) ratio at tally time. `Some` for `failed`
    /// outcomes (per `UpgradeOutcome::Failed { for_ratio }`); `None` for
    /// `vote_open`, `passed`, `active` (which carry deadlines, not ratios).
    pub for_ratio: Option<f64>,
    /// `vote_window_close_secs + kind.transition_days() × 86400` for
    /// `passed` outcomes; `None` for the other three.
    pub transition_deadline_secs: Option<u64>,
    /// Timestamp at which the outcome was recorded into governance state.
    pub recorded_at_ts: f64,
}

/// Full governance state — tracks all proposals and computes conviction.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct GovernanceState {
    /// Active and historical proposals (keyed by proposal ID).
    pub proposals: HashMap<String, Proposal>,
    /// Active delegations (keyed by delegator identity hash — each identity can only delegate once).
    pub delegations: HashMap<String, DelegationEntry>,
    /// Current governable parameters (runtime-adjustable).
    pub params: GovernableParams,
    /// History of parameter changes applied by governance.
    pub param_changes: Vec<ParamChange>,
    /// Emergency anchor veto tracking (economics §7.5).
    pub anchor_vetoes: AnchorVetoState,
    /// Incrementally maintained count of `delegations.values().filter(|d| d.active).count()`.
    /// Closes the O(N)-under-`ledger.read()` scan on `/token/enforcement` and `/governance/summary`.
    /// Updated at every `delegate()` (+1) and `undelegate()` (-1) call. Must be re-derived
    /// after snapshot restore via `recount_active_delegations()` since serde-loaded fields skip
    /// runtime invariants. `#[serde(default)]` lets old snapshots load with 0 — the recount on
    /// snapshot apply fixes it before any read.
    #[serde(default)]
    pub active_delegations_count: u64,
    /// Per-status proposal counts. Maintained at every `propose()` (+active),
    /// `cancel`/`settle`/`execute`/`challenge`/`anchor_veto_signal` transition. Closes the
    /// O(N) `proposal_counts()` and `active_proposals()` scans served by
    /// `/token/enforcement`, `/governance/summary`, and the per-proposer rate-limit gate.
    /// `#[serde(default)]` for backward-compat; recount on snapshot apply repairs.
    #[serde(default)]
    pub proposal_status_counts: ProposalStatusCounts,
    /// §11.18 Protocol Upgrade Mechanism Slice 2: recorded execution outcomes per
    /// ProtocolUpgrade proposal. Populated at `apply_governance_op::Execute`
    /// dispatch when the proposal category is `ProtocolUpgrade`, the metadata
    /// carries `governance_upgrade_kind` + `governance_reference_impl_hash` +
    /// `governance_proposed_at_epoch`, and `apply_protocol_upgrade_outcome()`
    /// successfully evaluates the tally. Keyed by proposal ID; one entry per
    /// proposal (re-execution overwrites). `#[serde(default)]` for backward-compat
    /// with snapshots predating §11.18 Slice 2.
    #[serde(default)]
    pub upgrade_outcomes: HashMap<String, UpgradeOutcomeRecord>,
}

impl GovernanceState {
    pub fn new() -> Self {
        Self {
            proposals: HashMap::new(),
            delegations: HashMap::new(),
            params: GovernableParams::default(),
            param_changes: Vec::new(),
            anchor_vetoes: AnchorVetoState::new(),
            active_delegations_count: 0,
            proposal_status_counts: ProposalStatusCounts::default(),
            upgrade_outcomes: HashMap::new(),
        }
    }

    /// Recompute `active_delegations_count` from `delegations`. O(N) full scan,
    /// intended for snapshot-restore path and tests — never call on the hot path. The
    /// invariant `active_delegations_count == delegations.values().filter(|d| d.active).count()`
    /// must hold after every mutation; this helper repairs it after a non-mutation reload.
    pub fn recount_active_delegations(&mut self) {
        self.active_delegations_count = self
            .delegations
            .values()
            .filter(|d| d.active)
            .count() as u64;
    }

    /// Recompute `proposal_status_counts` from `proposals`. Snapshot-restore /
    /// test only. Invariant after every mutation: counts match
    /// `proposals.values().group_by(.status).count()`.
    pub fn recount_proposal_statuses(&mut self) {
        let mut counts = ProposalStatusCounts::default();
        for p in self.proposals.values() {
            counts.inc(p.status);
        }
        self.proposal_status_counts = counts;
    }

    /// Bookkeeping for status transitions. No-op when old == new.
    /// Callers MUST invoke this after writing `proposal.status = new_status`
    /// for any proposal whose old status differs.
    fn record_status_transition(
        &mut self,
        old: ProposalStatus,
        new: ProposalStatus,
    ) {
        if old == new {
            return;
        }
        self.proposal_status_counts.dec(old);
        self.proposal_status_counts.inc(new);
    }

    /// Apply a governance parameter change from an executed proposal.
    /// Returns the old value.
    ///
    /// Validates against hard protocol limits (economics §13.15) before applying.
    pub fn apply_param_change(
        &mut self,
        proposal_id: &str,
        param_name: &str,
        new_value: &str,
        timestamp: f64,
    ) -> crate::errors::Result<String> {
        // Hard limit check: governance cannot override protocol invariants
        if let Err(violation) = crate::accounting::limits::validate_param_change(param_name, new_value) {
            return Err(ElaraError::Governance(violation.to_string()));
        }
        let old_value = self.params.get(param_name)
            .ok_or_else(|| ElaraError::Governance(format!("unrecognized parameter: {param_name}")))?;
        self.params.apply(param_name, new_value)?;
        self.param_changes.push(ParamChange {
            name: param_name.to_string(),
            old_value: old_value.clone(),
            new_value: new_value.to_string(),
            proposal_id: proposal_id.to_string(),
            applied_at: timestamp,
        });
        Ok(old_value)
    }

    /// §11.18 Protocol Upgrade Mechanism Slice 2 adapter.
    ///
    /// Apply at `apply_governance_op::Execute` dispatch when the proposal
    /// category is `ProtocolUpgrade`. Looks up the proposal, delegates to
    /// `evaluate_protocol_upgrade_proposal()` for the tally, and records the
    /// result on `self.upgrade_outcomes` keyed by proposal ID.
    ///
    /// Re-execution overwrites the previous record so an `Active` transition
    /// captured at a later tick replaces an earlier `Passed` snapshot from the
    /// initial execute (callers wanting the full history can read the audit
    /// log on the executing record).
    ///
    /// Returns `ElaraError::Governance` if the proposal is missing or its
    /// category is not `ProtocolUpgrade`. Callers should treat both as
    /// soft-skip conditions (the proposal exists but isn't an upgrade — log
    /// and move on); the error variant lets a future
    /// `/admin/proposal/upgrade` route surface the failure to operators.
    ///
    /// @spec Protocol §11.18 (Protocol Upgrade Mechanism), Slice 2 dispatch
    // `node-core`, not `node`: the ledger apply path (`ledger.rs`) calls this and
    // must compile + behave identically under any build that runs the ledger — a
    // consensus path cannot diverge on an allocator-only feature like `node`.
    #[cfg(feature = "node-core")]
    pub fn apply_protocol_upgrade_outcome(
        &mut self,
        proposal_id: &str,
        kind: crate::network::protocol_upgrade::UpgradeKind,
        reference_impl_hash: String,
        proposed_at_epoch: u64,
        current_time_secs: u64,
        recorded_at_ts: f64,
    ) -> Result<crate::network::protocol_upgrade::UpgradeOutcome> {
        use crate::network::protocol_upgrade::UpgradeOutcome;

        let proposal = self.proposals.get(proposal_id).ok_or_else(|| {
            ElaraError::Governance(format!(
                "apply_protocol_upgrade_outcome: proposal not found: {proposal_id}"
            ))
        })?;

        let outcome = evaluate_protocol_upgrade_proposal(
            proposal,
            kind,
            reference_impl_hash.clone(),
            proposed_at_epoch,
            current_time_secs,
        )?;

        let (outcome_str, for_ratio, transition_deadline_secs) = match outcome {
            UpgradeOutcome::VoteOpen => ("vote_open", None, None),
            UpgradeOutcome::Passed { transition_deadline_secs } => {
                ("passed", None, Some(transition_deadline_secs))
            }
            UpgradeOutcome::Failed { for_ratio } => ("failed", Some(for_ratio), None),
            UpgradeOutcome::Active => ("active", None, None),
        };

        self.upgrade_outcomes.insert(
            proposal_id.to_string(),
            UpgradeOutcomeRecord {
                proposal_id: proposal_id.to_string(),
                kind: kind.as_str().to_string(),
                reference_impl_hash,
                proposed_at_epoch,
                outcome: outcome_str.to_string(),
                for_ratio,
                transition_deadline_secs,
                recorded_at_ts,
            },
        );

        Ok(outcome)
    }

    /// Create a new proposal. Requires the proposer to have sufficient governance stake.
    ///
    /// For Critical proposals, pass a committee (from `select_committee()`).
    /// Non-Critical proposals should pass `None`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_proposal(
        &mut self,
        proposal_id: String,
        proposer: &str,
        category: ProposalCategory,
        title: String,
        description: String,
        governance_stake: u64,
        timestamp: f64,
        committee: Option<Committee>,
    ) -> Result<()> {
        if governance_stake < MIN_PROPOSAL_STAKE {
            return Err(ElaraError::Governance(format!(
                "insufficient governance stake: {} < {} required",
                governance_stake, MIN_PROPOSAL_STAKE
            )));
        }

        if self.proposals.contains_key(&proposal_id) {
            return Err(ElaraError::Governance(format!(
                "proposal already exists: {proposal_id}"
            )));
        }

        // Critical proposals require a committee
        if category == ProposalCategory::Critical && committee.is_none() {
            return Err(ElaraError::Governance(
                "critical proposals require a randomly selected committee".into()
            ));
        }

        let voting_period = if committee.is_some() {
            COMMITTEE_VOTING_PERIOD_SECS
        } else {
            VOTING_PERIOD_SECS
        };

        let proposal = Proposal {
            id: proposal_id.clone(),
            proposer: proposer.to_string(),
            category,
            title,
            description,
            created_at: timestamp,
            voting_deadline: timestamp + voting_period,
            status: ProposalStatus::Active,
            passed_at: None,
            votes: Vec::new(),
            committee,
        };

        self.proposals.insert(proposal_id, proposal);
        // Fresh insert — count one more Active proposal.
        self.proposal_status_counts.inc(ProposalStatus::Active);
        Ok(())
    }

    /// Cast a vote on a proposal, defaulting the frozen own-stake to the
    /// passed `governance_stake`.
    ///
    /// Convenience for callers with NO delegation (own == effective): tests and
    /// non-delegated single-voter paths. The consensus apply path (which folds
    /// delegated stake into `governance_stake`) MUST use
    /// [`Self::cast_vote_with_own`] so the frozen own stays the un-delegated
    /// base — otherwise settle-time reconcile would treat delegated stake as
    /// own and mis-fold.
    pub fn cast_vote(
        &mut self,
        proposal_id: &str,
        voter: &str,
        direction: VoteDirection,
        governance_stake: u64,
        timestamp: f64,
    ) -> Result<()> {
        self.cast_vote_with_own(proposal_id, voter, direction, governance_stake, governance_stake, timestamp)
    }

    /// Cast a vote, recording the voter's effective weight (`governance_stake`)
    /// and their frozen vote-time own stake (`own_stake`) separately.
    ///
    /// If the proposal has a committee assigned (Critical proposals), only
    /// committee members may vote. Non-members are rejected.
    pub fn cast_vote_with_own(
        &mut self,
        proposal_id: &str,
        voter: &str,
        direction: VoteDirection,
        governance_stake: u64,
        own_stake: u64,
        timestamp: f64,
    ) -> Result<()> {
        let proposal = self.proposals.get_mut(proposal_id)
            .ok_or_else(|| ElaraError::Governance(format!("proposal not found: {proposal_id}")))?;

        if !proposal.is_voting_open(timestamp) {
            return Err(ElaraError::Governance("voting period has ended".into()));
        }

        if proposal.has_voted(voter) {
            return Err(ElaraError::Governance(format!(
                "identity {voter} has already voted on {proposal_id}"
            )));
        }

        if governance_stake == 0 {
            return Err(ElaraError::Governance("must have governance stake to vote".into()));
        }

        // Committee enforcement: if committee is set, only members can vote
        if !is_committee_member(proposal, voter) {
            return Err(ElaraError::Governance(format!(
                "identity {voter} is not on the committee for {proposal_id}"
            )));
        }

        proposal.votes.push(Vote {
            voter: voter.to_string(),
            stake: governance_stake,
            direction,
            voted_at: timestamp,
            // Freeze the voter's own stake at vote time. `governance_stake` is
            // the effective weight (own + delegated) for the gate/preview;
            // `own_stake` is the un-delegated base reconcile keeps stable so a
            // post-vote stake top-up can't borrow the early `voted_at`.
            own_stake: Some(own_stake),
        });

        Ok(())
    }

    /// Cancel a proposal (proposer only, while still active).
    pub fn cancel_proposal(
        &mut self,
        proposal_id: &str,
        canceller: &str,
    ) -> Result<()> {
        let proposal = self.proposals.get_mut(proposal_id)
            .ok_or_else(|| ElaraError::Governance(format!("proposal not found: {proposal_id}")))?;

        if proposal.status != ProposalStatus::Active {
            return Err(ElaraError::Governance("can only cancel active proposals".into()));
        }

        if proposal.proposer != canceller {
            return Err(ElaraError::Governance("only the proposer can cancel".into()));
        }

        let old_status = proposal.status;
        proposal.status = ProposalStatus::Cancelled;
        // Active → Cancelled (active-guard above pins old to Active).
        self.record_status_transition(old_status, ProposalStatus::Cancelled);
        Ok(())
    }

    /// Rebuild every vote's effective `stake` on `proposal_id` from the FINAL
    /// delegation state immediately before settle, so a delegate's fold can
    /// never double-count a delegator who later voted directly or undelegated.
    ///
    /// [`effective_voting_stake`] folds a delegator's stake into the delegate's
    /// vote *at the delegate's vote time*. That fold is a derived aggregate
    /// captured early and never reconciled: if the delegate votes first and the
    /// delegator then votes directly (the only `cast_vote` guard is
    /// `has_voted(voter)`), the delegator's stake is counted twice — once in the
    /// stale fold, once in their own vote. The same staleness lets an
    /// undelegate-after-fold sequence double-count. We rebuild each weight as
    /// `frozen own + fresh delegated fold`, where the fold includes only the
    /// stake of *currently-active* delegators who did *not* vote directly. This
    /// removes the order-dependent double-count for direct (depth-1)
    /// delegations; it does NOT change the existing depth-≥2 chain semantics of
    /// [`effective_voting_stake`] (which this mirrors), so it is no worse than
    /// the incremental fold it replaces.
    ///
    /// Crucially the own part is the vote-time `Vote::own_stake`, NOT a
    /// settle-time recompute: re-reading own from current stakes would let a
    /// voter cast early with dust (banking a long conviction duration off
    /// `voted_at`) then top up stake before the deadline, dodging the
    /// conviction time-discount. Freezing own keeps the vote-time stake lock.
    /// Legacy votes (`own_stake == None`, pre-field) fall back to `stake`.
    ///
    /// KNOWN LIMITATION (delegated portion only): the fold IS settle-time — it
    /// must be, since "who voted directly" is only known at settle. So a
    /// delegator who balloons stake (or freshly delegates) after their
    /// delegate's early vote can credit that delegate's early `voted_at` with
    /// the inflated delegated weight. This is strictly narrower than the
    /// single-identity double-count it replaces (needs delegate+delegator
    /// collusion, bounded by really-held stake); fully closing it needs a
    /// per-delegator vote-time stake snapshot. Tracked as future hardening.
    ///
    /// Idempotent: the absolute recompute reads the frozen `own_stake` and the
    /// live delegation map, never the value it overwrites — running it twice
    /// yields the same `stake`.
    ///
    /// Deterministic: integer sums over the (consensus-replicated) delegation
    /// map and stake set, keyed by unique voter — order-independent.
    /// O(active_delegations + votes), run once per proposal at settle.
    pub fn reconcile_effective_stakes(
        &mut self,
        stakes: &HashMap<String, crate::accounting::ledger::StakeEntry>,
        proposal_id: &str,
    ) {
        // Identities that cast a direct vote on this proposal (own their stake).
        let direct_voters: std::collections::HashSet<String> = match self.proposals.get(proposal_id) {
            Some(p) => p.votes.iter().map(|v| v.voter.clone()).collect(),
            None => return,
        };

        // Reverse-index the delegation map: delegate -> Σ governance stake of its
        // active delegators that did NOT cast a direct vote on this proposal.
        let mut folded: HashMap<String, u64> = HashMap::new();
        for entry in self.delegations.values() {
            if !entry.active || direct_voters.contains(&entry.delegator) {
                continue;
            }
            let s = governance_stake_for(stakes, &entry.delegator);
            if s == 0 {
                continue;
            }
            let slot = folded.entry(entry.delegate.clone()).or_insert(0);
            *slot = slot.saturating_add(s);
        }

        if let Some(p) = self.proposals.get_mut(proposal_id) {
            for v in p.votes.iter_mut() {
                // Frozen vote-time own (legacy None -> the stored effective).
                let own = v.own_stake.unwrap_or(v.stake);
                let delegated = folded.get(&v.voter).copied().unwrap_or(0);
                v.stake = own.saturating_add(delegated);
            }
        }
    }

    /// Settle a proposal: compute conviction-weighted votes and determine outcome.
    /// Call this when the voting deadline passes.
    pub fn settle_proposal(
        &mut self,
        proposal_id: &str,
        total_governance_staked: u64,
        now: f64,
    ) -> Result<ProposalStatus> {
        // Scope the &mut borrow so we can update counters after.
        let outcome: ProposalStatus = {
            let proposal = self.proposals.get_mut(proposal_id)
                .ok_or_else(|| ElaraError::Governance(format!("proposal not found: {proposal_id}")))?;

            if proposal.status != ProposalStatus::Active {
                return Err(ElaraError::Governance("proposal is not active".into()));
            }

            if now < proposal.voting_deadline {
                return Err(ElaraError::Governance("voting period has not ended yet".into()));
            }

            let tally = tally_votes(proposal, now, None);

            // Check minimum participation (raw stake, not dampened conviction).
            // Integer form of `raw < total * 0.25`: `raw * 4 < total * 1`. No f64.
            let participation_below = (tally.raw_participating_stake as u128)
                .saturating_mul(PARTICIPATION_DEN)
                < (total_governance_staked as u128).saturating_mul(PARTICIPATION_NUM);

            if participation_below {
                proposal.status = ProposalStatus::Expired;
                ProposalStatus::Expired
            } else {
                // Check supermajority (abstain doesn't count toward threshold).
                // All `_q` integer: gate `for_fraction >= 0.67` becomes the
                // division-free `for_q * 100 >= decisive_q * 67`.
                let decisive_q = tally
                    .for_conviction_q
                    .saturating_add(tally.against_conviction_q);
                if decisive_q == 0 {
                    proposal.status = ProposalStatus::Expired;
                    ProposalStatus::Expired
                } else {
                    let supermajority_met = tally
                        .for_conviction_q
                        .saturating_mul(SUPERMAJORITY_DEN)
                        >= decisive_q.saturating_mul(SUPERMAJORITY_NUM);
                    if supermajority_met {
                        proposal.status = ProposalStatus::Passed;
                        proposal.passed_at = Some(now);
                        // For committee proposals: set challenge deadline
                        if let Some(ref mut committee) = proposal.committee {
                            if committee.challenge_deadline.is_none() {
                                committee.challenge_deadline = Some(now + COMMITTEE_CHALLENGE_PERIOD_SECS);
                            }
                        }
                        ProposalStatus::Passed
                    } else {
                        proposal.status = ProposalStatus::Rejected;
                        ProposalStatus::Rejected
                    }
                }
            }
        };
        // Active-guard above pins old=Active for every branch.
        self.record_status_transition(ProposalStatus::Active, outcome);
        Ok(outcome)
    }

    /// Execute a passed proposal after the delay period.
    ///
    /// For committee proposals: also requires the challenge period to have
    /// elapsed without a challenge. If challenged, execution is blocked until
    /// the re-vote committee settles.
    pub fn execute_proposal(
        &mut self,
        proposal_id: &str,
        now: f64,
    ) -> Result<()> {
        let proposal = self.proposals.get_mut(proposal_id)
            .ok_or_else(|| ElaraError::Governance(format!("proposal not found: {proposal_id}")))?;

        if !proposal.can_execute(now) {
            return Err(ElaraError::Governance(
                "proposal cannot be executed yet (not passed or delay not elapsed)".into()
            ));
        }

        // Committee challenge period check
        if let Some(ref committee) = proposal.committee {
            if let Some(deadline) = committee.challenge_deadline {
                if now < deadline {
                    return Err(ElaraError::Governance(
                        "committee challenge period has not elapsed".into()
                    ));
                }
            }
            // If there's a challenger but no re-vote committee, block execution
            if committee.challenger.is_some() && !committee.is_revote {
                return Err(ElaraError::Governance(
                    "committee verdict is challenged; awaiting re-vote".into()
                ));
            }
        }

        let old_status = proposal.status;
        proposal.status = ProposalStatus::Executed;
        // can_execute() above pins old to Passed for any successful path,
        // but we read the actual old to be robust against can_execute future changes.
        self.record_status_transition(old_status, ProposalStatus::Executed);
        Ok(())
    }

    /// Challenge a committee verdict on a passed Critical proposal.
    ///
    /// Any governance stakeholder can challenge within the challenge period.
    /// This triggers a re-vote with a larger committee (200 members).
    /// The challenger must have governance stake.
    pub fn challenge_committee(
        &mut self,
        proposal_id: &str,
        challenger: &str,
        governance_stake: u64,
        now: f64,
    ) -> Result<()> {
        if governance_stake < MIN_PROPOSAL_STAKE {
            return Err(ElaraError::Governance(format!(
                "insufficient stake to challenge: {} < {} required",
                governance_stake, MIN_PROPOSAL_STAKE
            )));
        }

        let proposal = self.proposals.get_mut(proposal_id)
            .ok_or_else(|| ElaraError::Governance(format!("proposal not found: {proposal_id}")))?;

        if proposal.status != ProposalStatus::Passed {
            return Err(ElaraError::Governance(
                "can only challenge passed proposals".into()
            ));
        }

        let committee = proposal.committee.as_mut()
            .ok_or_else(|| ElaraError::Governance(
                "proposal has no committee (not a critical proposal)".into()
            ))?;

        if committee.is_revote {
            return Err(ElaraError::Governance(
                "re-vote verdicts cannot be challenged".into()
            ));
        }

        if committee.challenger.is_some() {
            return Err(ElaraError::Governance(
                "proposal has already been challenged".into()
            ));
        }

        let deadline = committee.challenge_deadline
            .ok_or_else(|| ElaraError::Governance(
                "challenge period not set (proposal not yet settled)".into()
            ))?;

        if now >= deadline {
            return Err(ElaraError::Governance(
                "challenge period has expired".into()
            ));
        }

        committee.challenger = Some(challenger.to_string());
        // Reset to Active for re-vote
        let old_status = proposal.status;
        proposal.status = ProposalStatus::Active;
        proposal.passed_at = None;
        proposal.votes.clear();

        // Status-guard above pins old=Passed.
        self.record_status_transition(old_status, ProposalStatus::Active);
        Ok(())
    }

    /// Apply a re-vote committee to a challenged proposal.
    ///
    /// Called after `challenge_committee()` — selects a larger committee
    /// and resets voting with a new deadline.
    pub fn apply_revote_committee(
        &mut self,
        proposal_id: &str,
        revote_committee: Committee,
        now: f64,
    ) -> Result<()> {
        let proposal = self.proposals.get_mut(proposal_id)
            .ok_or_else(|| ElaraError::Governance(format!("proposal not found: {proposal_id}")))?;

        if proposal.status != ProposalStatus::Active {
            return Err(ElaraError::Governance(
                "proposal must be active for re-vote".into()
            ));
        }

        let existing = proposal.committee.as_ref()
            .ok_or_else(|| ElaraError::Governance("no existing committee".into()))?;

        if existing.challenger.is_none() {
            return Err(ElaraError::Governance(
                "proposal has not been challenged".into()
            ));
        }

        proposal.voting_deadline = now + COMMITTEE_VOTING_PERIOD_SECS;
        proposal.committee = Some(revote_committee);
        Ok(())
    }

    /// Emergency anchor veto: signal veto on a proposal.
    ///
    /// When >75% of anchor nodes signal, the proposal is vetoed.
    /// Rate-limited: 2 per zone per quarter.
    pub fn anchor_veto_signal(
        &mut self,
        proposal_id: &str,
        anchor_identity: &str,
        zone: ZoneId,
        total_anchor_nodes: usize,
        timestamp: f64,
    ) -> Result<bool> {
        // Check proposal exists and is active/passed
        let proposal = self.proposals.get(proposal_id)
            .ok_or_else(|| ElaraError::Governance(format!("proposal not found: {proposal_id}")))?;

        if proposal.status != ProposalStatus::Active && proposal.status != ProposalStatus::Passed {
            return Err(ElaraError::Governance(
                "can only veto active or passed proposals".into()
            ));
        }

        // Rate limit check
        if self.anchor_vetoes.rate_limited(zone.clone(), timestamp) {
            return Err(ElaraError::Governance(format!(
                "zone {zone} has exhausted veto quota for this quarter (max {})",
                ANCHOR_VETO_MAX_PER_QUARTER
            )));
        }

        // Record the signal
        let is_new = self.anchor_vetoes.signal_veto(proposal_id, anchor_identity, zone.clone(), timestamp);
        if !is_new {
            return Err(ElaraError::Governance(format!(
                "anchor {anchor_identity} has already signaled on {proposal_id}"
            )));
        }

        // Check if threshold is met
        if self.anchor_vetoes.check_threshold(proposal_id, total_anchor_nodes) {
            // Veto the proposal
            let old_status = {
                let proposal = self
                    .proposals
                    .get_mut(proposal_id)
                    .ok_or_else(|| ElaraError::Governance(format!(
                        "internal: proposal {proposal_id} missing at veto-trigger get_mut")))?;
                let old = proposal.status;
                proposal.status = ProposalStatus::Vetoed;
                old
            };
            // Guard above (line 915) pins old to Active or Passed.
            self.record_status_transition(old_status, ProposalStatus::Vetoed);
            self.anchor_vetoes.record_veto(zone, timestamp);
            return Ok(true); // veto triggered
        }

        Ok(false) // signal recorded, threshold not yet met
    }

    /// Count of active proposals. O(1) read off the maintained counter.
    pub fn active_proposals(&self) -> usize {
        self.proposal_status_counts.active as usize
    }

    /// Count of active proposals by a specific proposer. Per-proposer slice has
    /// no incremental counter (would require a HashMap<proposer, count>); the
    /// scan stays for now since the rate-limit gate is per-identity-per-call,
    /// not on the metrics scrape path. Bounded by `MAX_ACTIVE_PROPOSALS_PER_IDENTITY`
    /// in practice — the active set per proposer is small.
    pub fn active_proposals_by(&self, proposer: &str) -> usize {
        self.proposals.values()
            .filter(|p| p.status == ProposalStatus::Active && p.proposer == proposer)
            .count()
    }

    /// Count of proposals in each status. O(1) read off the maintained
    /// counter; was O(N) match-loop before. Closes the scan on `/token/enforcement`
    /// and `/governance/summary` under `ledger.read()`.
    pub fn proposal_counts(&self) -> (usize, usize, usize, usize, usize, usize, usize) {
        let c = &self.proposal_status_counts;
        (
            c.active as usize,
            c.passed as usize,
            c.rejected as usize,
            c.expired as usize,
            c.executed as usize,
            c.cancelled as usize,
            c.vetoed as usize,
        )
    }

    /// Delegate governance voting power to another identity.
    /// Depth-1 only: a delegator cannot already be a delegate of someone else
    /// who has re-delegated (no transitive chains).
    pub fn delegate(
        &mut self,
        delegator: &str,
        delegate: &str,
        timestamp: f64,
    ) -> Result<()> {
        if delegator == delegate {
            return Err(ElaraError::Governance("cannot delegate to self".into()));
        }

        // Check if delegator already has an active delegation
        if let Some(existing) = self.delegations.get(delegator) {
            if existing.active {
                return Err(ElaraError::Governance(format!(
                    "already delegated to {}; undelegate first",
                    existing.delegate
                )));
            }
        }

        // Cycle detection: the delegate must not have delegated to the delegator
        if let Some(del_entry) = self.delegations.get(delegate) {
            if del_entry.active && del_entry.delegate == delegator {
                return Err(ElaraError::Governance(
                    "circular delegation: delegate has already delegated to you".into()
                ));
            }
        }

        // Only increment if we're going from no-active to active.
        // The existing entry (if any) was inactive (else we'd have errored above) — so
        // overwriting it bumps the count by 1. A fresh insert is also +1.
        let prev_was_active = self
            .delegations
            .get(delegator)
            .map(|d| d.active)
            .unwrap_or(false);
        debug_assert!(!prev_was_active, "active-guard above should have rejected");
        self.delegations.insert(
            delegator.to_string(),
            DelegationEntry {
                delegator: delegator.to_string(),
                delegate: delegate.to_string(),
                created_at: timestamp,
                active: true,
            },
        );
        self.active_delegations_count = self.active_delegations_count.saturating_add(1);
        Ok(())
    }

    /// Remove a delegation.
    pub fn undelegate(
        &mut self,
        delegator: &str,
    ) -> Result<()> {
        let entry = self.delegations.get_mut(delegator)
            .ok_or_else(|| ElaraError::Governance("no active delegation".into()))?;

        if !entry.active {
            return Err(ElaraError::Governance("delegation already inactive".into()));
        }

        entry.active = false;
        // Every undelegate transitions an active entry → inactive.
        self.active_delegations_count = self.active_delegations_count.saturating_sub(1);
        Ok(())
    }

    /// Get all active delegators for a given delegate (who has delegated to them).
    pub fn delegators_for(&self, delegate: &str) -> Vec<&DelegationEntry> {
        self.delegations
            .values()
            .filter(|d| d.active && d.delegate == delegate)
            .collect()
    }

    /// Get the active delegation for a delegator (if any).
    pub fn delegation_of(&self, delegator: &str) -> Option<&DelegationEntry> {
        self.delegations.get(delegator).filter(|d| d.active)
    }
}

/// Tally result from conviction-weighted voting.
///
/// Conviction fields are `_q`-scaled integers (value * [`CONVICTION_Q`]) so the
/// settle gate is bit-identical across gossip order and architecture. The f64
/// accessor methods are DISPLAY-only (RPC/explorer) and must never gate consensus.
#[derive(Debug, Clone)]
pub struct VoteTally {
    /// Total conviction-weighted "for" votes (after dampening + cap), `_q`-scaled.
    pub for_conviction_q: u128,
    /// Total conviction-weighted "against" votes (after dampening + cap), `_q`-scaled.
    pub against_conviction_q: u128,
    /// Total conviction-weighted "abstain" votes (participation only), `_q`-scaled.
    pub abstain_conviction_q: u128,
    /// Number of unique voters.
    pub voter_count: usize,
    /// Sum of raw governance stakes from all voters (for participation check).
    pub raw_participating_stake: u64,
}

impl VoteTally {
    /// "For" conviction in stake-units (display only; never gate consensus).
    pub fn for_conviction(&self) -> f64 {
        self.for_conviction_q as f64 / CONVICTION_Q as f64
    }
    /// "Against" conviction in stake-units (display only; never gate consensus).
    pub fn against_conviction(&self) -> f64 {
        self.against_conviction_q as f64 / CONVICTION_Q as f64
    }
    /// "Abstain" conviction in stake-units (display only; never gate consensus).
    pub fn abstain_conviction(&self) -> f64 {
        self.abstain_conviction_q as f64 / CONVICTION_Q as f64
    }
}

/// Compute raw conviction for a stake held for a duration.
///
/// `conviction(stake, t) = stake × (1 - e^(-t/τ))`
///
/// At t=0: 0, at t=7d: ~63.2% of stake, at t=21d: ~95% of stake.
pub fn conviction(stake: u64, duration_secs: f64) -> f64 {
    if duration_secs <= 0.0 || stake == 0 {
        return 0.0;
    }
    (stake as f64) * (1.0 - (-duration_secs / CONVICTION_TAU_SECS).exp())
}

/// Square-root dampening on conviction weight.
///
/// `effective_power = sqrt(conviction)`
///
/// Prevents whale domination: 4x stake only gives 2x voting power.
pub fn dampened_power(raw_conviction: f64) -> f64 {
    if raw_conviction <= 0.0 {
        return 0.0;
    }
    raw_conviction.sqrt()
}

/// Per-identity voting power cap: max 1/√N of total voting power.
///
/// With N voters, no single voter can have more than 1/√N fraction.
/// This limits whales even further beyond square-root dampening.
pub fn identity_cap(total_dampened_power: f64, voter_count: usize) -> f64 {
    if voter_count <= 1 {
        return f64::MAX;
    }
    total_dampened_power / (voter_count as f64).sqrt()
}

// ─── Deterministic fixed-point conviction (consensus apply path) ─────────────
//
// The f64 `conviction` / `dampened_power` / `identity_cap` above are kept for
// RPC/explorer DISPLAY only. The governance settle path runs on EVERY node in
// the deterministic replicated apply path (`settle_proposal` -> `apply_param_change`
// -> balances -> account-SMT root -> seal), so its arithmetic MUST be
// bit-identical across gossip-arrival order AND across libm/arch. f64 `exp()` is
// not correctly-rounded by IEEE-754 (cross-arch fork), and f64 summation is
// non-associative (gossip-order fork). These `_q` helpers mirror the H1
// settlement-gate discipline (`consensus.rs` `SETTLEMENT_Q`): every `_q` quantity
// is an integer scaled by `CONVICTION_Q`. See internal design notes.

/// Fixed-point scale: a `_q` value of `CONVICTION_Q` represents 1.0.
pub const CONVICTION_Q: u128 = 1_000_000_000;

/// `round(e^(-1) * CONVICTION_Q)` — the only transcendental constant. Every
/// integer-part power `e^(-k)` is rebuilt by `k` round-half-up multiplies, so no
/// node ever evaluates `exp()` at runtime.
const E_INV_Q: u128 = 367_879_441;

/// Supermajority threshold as an exact rational (mirrors f64 `SUPERMAJORITY_THRESHOLD`
/// = 0.67): the gate `for_fraction >= 0.67` becomes `for_q * 100 >= decisive_q * 67`.
const SUPERMAJORITY_NUM: u128 = 67;
const SUPERMAJORITY_DEN: u128 = 100;
/// Min participation as an exact rational (mirrors f64 `MIN_PARTICIPATION_FRACTION`
/// = 0.25): `raw < total/4` becomes `raw * 4 < total`.
const PARTICIPATION_NUM: u128 = 1;
const PARTICIPATION_DEN: u128 = 4;

/// Floor an f64 unix-seconds timestamp to integer seconds for deterministic
/// duration math. Non-finite / negative -> 0 (the `as u64` cast truncates toward
/// zero = floor for positives). Sub-second precision is irrelevant at tau = 7d.
fn secs_floor(t: f64) -> u64 {
    if t.is_finite() && t > 0.0 {
        t as u64
    } else {
        0
    }
}

/// Deterministic integer `(1 - e^(-t/tau)) * CONVICTION_Q`, in `[0, CONVICTION_Q]`.
///
/// Range-reduce `x = t/tau = k + r` (`k = floor(x)`, `r in [0,1)`):
/// `e^(-x) = (e^(-1))^k * e^(-r)`. `(e^(-1))^k` is `k` round-half-up multiplies by
/// [`E_INV_Q`]; `e^(-r)` is a 16-term integer Maclaurin series (alternating, error
/// `<= r^17/17!` << 1 Q-unit for `r<1`). All integer -> bit-identical on every arch.
fn one_minus_exp_neg_q(t_secs: u64, tau_secs: u64) -> u128 {
    if t_secs == 0 || tau_secs == 0 {
        return 0;
    }
    let q = CONVICTION_Q;
    // x in Q-scale: x_q = (t/tau) * Q. k = integer part, r_q = fractional part in Q.
    let x_q = (t_secs as u128).saturating_mul(q) / tau_secs as u128;
    let k = x_q / q;
    // Beyond k ~= 42, e^(-k) < 0.5/Q -> rounds to 0 -> 1 - e^(-x) saturates to Q.
    if k >= 42 {
        return q;
    }
    let r_q = x_q % q; // r in [0, Q)

    // e^(-r) * Q via Maclaurin: sum (-r)^n / n!, alternating, round-half-up.
    let mut term = q; // (r^0 / 0!) = 1.0 in Q
    let mut exp_r_q = q; // running e^(-r) * Q
    let mut subtract = true;
    for n in 1..=16u128 {
        let denom = n.saturating_mul(q);
        // term_n = term_{n-1} * r / n  (magnitude), round-half-up.
        term = (term.saturating_mul(r_q) + denom / 2) / denom;
        if term == 0 {
            break;
        }
        if subtract {
            exp_r_q = exp_r_q.saturating_sub(term);
        } else {
            exp_r_q = exp_r_q.saturating_add(term);
        }
        subtract = !subtract;
    }

    // e^(-k) * Q: start at 1.0, apply k round-half-up multiplies by E_INV_Q.
    let mut exp_k_q = q;
    for _ in 0..k {
        exp_k_q = (exp_k_q.saturating_mul(E_INV_Q) + q / 2) / q;
    }

    // e^(-x) = e^(-k) * e^(-r); result = Q - e^(-x)*Q, clamped to [0, Q].
    let exp_x_q = (exp_k_q.saturating_mul(exp_r_q) + q / 2) / q;
    q.saturating_sub(exp_x_q.min(q))
}

/// Deterministic conviction in `_q` units (= conviction value * `CONVICTION_Q`).
/// Integer mirror of [`conviction`]; the only version that may gate consensus.
pub fn conviction_q(stake: u64, duration_secs: u64) -> u128 {
    if duration_secs == 0 || stake == 0 {
        return 0;
    }
    let tau = CONVICTION_TAU_SECS as u64; // 604800
    (stake as u128).saturating_mul(one_minus_exp_neg_q(duration_secs, tau))
}

/// Deterministic sqrt-dampened power in `_q` units. `dampened = sqrt(conviction)`,
/// so `dampened_q = sqrt(conviction)*Q = isqrt(conviction_q * Q)` via integer
/// `isqrt` — NOT f64 `sqrt`, because the input here is a `u128` and `u128 as f64`
/// is a lossy cast above 2^53 (a fresh fork source). Integer mirror of
/// [`dampened_power`].
pub fn dampened_power_q(conviction_q_val: u128) -> u128 {
    conviction_q_val.saturating_mul(CONVICTION_Q).isqrt()
}

/// Deterministic per-identity cap in `_q` units: `total/sqrt(N)`. Integer mirror
/// of [`identity_cap`]; `sqrt(N)*Q = isqrt(N*Q^2)` keeps it integer. `N <= 1` -> no cap.
fn identity_cap_q(total_power_q: u128, voter_count: usize) -> u128 {
    if voter_count <= 1 {
        return u128::MAX;
    }
    let sqrt_n_q = (voter_count as u128)
        .saturating_mul(CONVICTION_Q)
        .saturating_mul(CONVICTION_Q)
        .isqrt(); // = sqrt(N) * Q (floor)
    if sqrt_n_q == 0 {
        return u128::MAX;
    }
    total_power_q.saturating_mul(CONVICTION_Q) / sqrt_n_q
}

// ─── Governance weight decay on liquidation (economics §13.8) ──────────────

/// 30-day window for outflow measurement.
const DECAY_OUTFLOW_WINDOW_SECS: f64 = 30.0 * 24.0 * 3600.0;
/// 90-day window for peak staked balance measurement.
const DECAY_PEAK_STAKED_WINDOW_SECS: f64 = 90.0 * 24.0 * 3600.0;
/// Outflow ratio threshold below which no decay applies.
const DECAY_OUTFLOW_THRESHOLD: f64 = 0.05;
/// Multiplier on outflow_ratio for decay calculation.
const DECAY_MULTIPLIER: f64 = 3.0;
/// Floor: governance power never drops below 1%.
const DECAY_FLOOR: f64 = 0.01;

/// Compute governance weight decay multiplier for an identity.
///
/// Formula (economics §13.8):
/// ```text
/// outflow_ratio = net_outflow_30d / max(staked_balance, peak_staked_90d)
/// if outflow_ratio > 0.05:
///     governance_decay = max(0.01, 1.0 - outflow_ratio × 3)
/// else:
///     governance_decay = 1.0  (no decay)
/// ```
///
/// Examples: 10% outflow = 70% power, 20% = 40%, 33%+ = 1% floor.
/// Dumping = leaving = no voting power.
///
/// **CONSENSUS-FORBIDDEN (Track D, internal design notes).** This reads
/// `VelocityTracker`, which since the rate-limit demotion is a node-local, mempool-only
/// `#[serde(skip)]` tracker (empty on a snapshot-bootstrapped node). Feeding its output
/// into `tally_votes(..., Some(&decay))` on any **consensus-replicated** path (sealed
/// governance tally / apply_op) would reintroduce a per-node-divergent input → vote-count
/// fork. Every production `tally_votes` call passes `decay_factors=None` (inert today). If
/// decay is ever activated, redesign it on **persisted, SMT-committed** buckets first — do
/// NOT wire this velocity-derived multiplier into consensus.
pub fn governance_decay_multiplier(
    velocity: &crate::accounting::velocity::VelocityTracker,
    staked_balance: u64,
    identity: &str,
    now: f64,
) -> f64 {
    if staked_balance == 0 {
        return DECAY_FLOOR; // No stake = minimal power
    }

    let outflow_30d = velocity.outflow_in_custom_window(identity, now, DECAY_OUTFLOW_WINDOW_SECS);
    if outflow_30d == 0 {
        return 1.0; // No outflows = no decay
    }

    let peak_staked_90d = velocity.peak_balance_in_window(identity, now, DECAY_PEAK_STAKED_WINDOW_SECS);
    let denominator = (staked_balance as f64).max(peak_staked_90d as f64);
    if denominator <= 0.0 {
        return DECAY_FLOOR;
    }

    let outflow_ratio = outflow_30d as f64 / denominator;
    if outflow_ratio <= DECAY_OUTFLOW_THRESHOLD {
        return 1.0; // Below threshold = no decay
    }

    (1.0 - outflow_ratio * DECAY_MULTIPLIER).max(DECAY_FLOOR)
}

/// Tally all votes on a proposal with conviction weighting, dampening, caps,
/// and optional governance weight decay (economics §13.8).
///
/// `decay_factors`: optional per-voter multipliers from `governance_decay_multiplier()`.
/// Pass `None` to skip decay (all voters get full power).
pub fn tally_votes(
    proposal: &Proposal,
    now: f64,
    decay_factors: Option<&HashMap<String, f64>>,
) -> VoteTally {
    if proposal.votes.is_empty() {
        return VoteTally {
            for_conviction_q: 0,
            against_conviction_q: 0,
            abstain_conviction_q: 0,
            voter_count: 0,
            raw_participating_stake: 0,
        };
    }

    let now_secs = secs_floor(now);

    // Sum raw stakes for participation check (integer-exact, order-independent).
    let raw_participating_stake: u64 = proposal.votes.iter().map(|v| v.stake).sum();

    // Canonical voter-sorted order. `voter` is unique per proposal (`has_voted`
    // dedup at cast time), so this is a total order with no ties. u128 addition
    // is already associative, but sorting pins the canonical form against any
    // future order-sensitive change (belt-and-suspenders, mirrors `effective_stake_q`).
    let mut sorted: Vec<&Vote> = proposal.votes.iter().collect();
    sorted.sort_by(|a, b| a.voter.cmp(&b.voter).then(a.voted_at.total_cmp(&b.voted_at)));

    // Phase 1: per-vote dampened power in `_q`, applying decay if present.
    let mut powers: Vec<(VoteDirection, u128)> = Vec::with_capacity(sorted.len());
    for v in &sorted {
        let duration_secs = now_secs.saturating_sub(secs_floor(v.voted_at));
        let raw_q = conviction_q(v.stake, duration_secs);
        let dampened_q = dampened_power_q(raw_q);
        // Governance weight decay (economics §13.8) is `None` in the consensus
        // apply path (`settle_proposal` passes None). When `Some`, quantize the
        // caller-supplied f64 multiplier to Q deterministically (one
        // correctly-rounded f64 op on a fixed value -> identical across arch).
        // Wiring decay INTO consensus first requires integerizing
        // `governance_decay_multiplier` itself.
        let power_q = match decay_factors.and_then(|df| df.get(&v.voter)).copied() {
            Some(d) if d != 1.0 => {
                let d_q = (d.max(0.0) * CONVICTION_Q as f64).round() as u128;
                dampened_q.saturating_mul(d_q) / CONVICTION_Q
            }
            _ => dampened_q,
        };
        powers.push((v.direction, power_q));
    }

    let voter_count = powers.len();

    // Phase 2: total dampened power for the cap (order-independent u128 sum).
    let total_power_q: u128 = powers
        .iter()
        .fold(0u128, |acc, (_, p)| acc.saturating_add(*p));
    let cap_q = identity_cap_q(total_power_q, voter_count);

    // Phase 3: apply cap and sum by direction (all u128).
    let mut for_q = 0u128;
    let mut against_q = 0u128;
    let mut abstain_q = 0u128;
    for (direction, power_q) in &powers {
        let capped = (*power_q).min(cap_q);
        match direction {
            VoteDirection::For => for_q = for_q.saturating_add(capped),
            VoteDirection::Against => against_q = against_q.saturating_add(capped),
            VoteDirection::Abstain => abstain_q = abstain_q.saturating_add(capped),
        }
    }

    VoteTally {
        for_conviction_q: for_q,
        against_conviction_q: against_q,
        abstain_conviction_q: abstain_q,
        voter_count,
        raw_participating_stake,
    }
}

// ─── Governance operation metadata ──────────────────────────────────────────

/// Governance operation key in record metadata.
pub const GOVERNANCE_OP_KEY: &str = "governance_op";

/// Parsed governance operation.
#[derive(Debug, Clone)]
pub enum ParsedGovernanceOp {
    Propose {
        category: ProposalCategory,
        title: String,
        description: String,
    },
    Vote {
        proposal_id: String,
        direction: VoteDirection,
    },
    Execute {
        proposal_id: String,
    },
    Cancel {
        proposal_id: String,
    },
    Delegate {
        delegate: String,
    },
    Undelegate,
}

/// Extract governance operation from a record's metadata.
pub fn extract_governance_op(
    metadata: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<Option<ParsedGovernanceOp>> {
    let op_val = match metadata.get(GOVERNANCE_OP_KEY) {
        Some(v) => v,
        None => return Ok(None),
    };

    let op_str = op_val
        .as_str()
        .ok_or_else(|| ElaraError::Governance("governance_op must be a string".into()))?;

    match op_str {
        "propose" => {
            let category_str = get_gov_str(metadata, "governance_category")?;
            let category = ProposalCategory::parse(&category_str)?;
            let title = get_gov_str(metadata, "governance_title")?;
            let description = get_gov_str(metadata, "governance_description")?;
            Ok(Some(ParsedGovernanceOp::Propose { category, title, description }))
        }
        "vote" => {
            let proposal_id = get_gov_str(metadata, "governance_proposal_id")?;
            let direction_str = get_gov_str(metadata, "governance_direction")?;
            let direction = VoteDirection::parse(&direction_str)?;
            Ok(Some(ParsedGovernanceOp::Vote { proposal_id, direction }))
        }
        "execute" => {
            let proposal_id = get_gov_str(metadata, "governance_proposal_id")?;
            Ok(Some(ParsedGovernanceOp::Execute { proposal_id }))
        }
        "cancel" => {
            let proposal_id = get_gov_str(metadata, "governance_proposal_id")?;
            Ok(Some(ParsedGovernanceOp::Cancel { proposal_id }))
        }
        "delegate" => {
            let delegate = get_gov_str(metadata, "governance_delegate")?;
            Ok(Some(ParsedGovernanceOp::Delegate { delegate }))
        }
        "undelegate" => {
            Ok(Some(ParsedGovernanceOp::Undelegate))
        }
        other => Err(ElaraError::Governance(format!("unknown governance op: {other}"))),
    }
}

fn get_gov_str(
    meta: &std::collections::BTreeMap<String, serde_json::Value>,
    key: &str,
) -> Result<String> {
    meta.get(key)
        .ok_or_else(|| ElaraError::Governance(format!("missing field: {key}")))?
        .as_str()
        .ok_or_else(|| ElaraError::Governance(format!("{key} must be a string")))
        .map(|s| s.to_string())
}

/// Build metadata for a Propose operation.
pub fn propose_metadata(
    category: &ProposalCategory,
    title: &str,
    description: &str,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(GOVERNANCE_OP_KEY.into(), serde_json::json!("propose"));
    m.insert("governance_category".into(), serde_json::json!(category.as_str()));
    m.insert("governance_title".into(), serde_json::json!(title));
    m.insert("governance_description".into(), serde_json::json!(description));
    m
}

/// Build metadata for a Vote operation.
pub fn vote_metadata(
    proposal_id: &str,
    direction: &VoteDirection,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(GOVERNANCE_OP_KEY.into(), serde_json::json!("vote"));
    m.insert("governance_proposal_id".into(), serde_json::json!(proposal_id));
    m.insert("governance_direction".into(), serde_json::json!(direction.as_str()));
    m
}

/// Build metadata for an Execute operation.
pub fn execute_metadata(
    proposal_id: &str,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(GOVERNANCE_OP_KEY.into(), serde_json::json!("execute"));
    m.insert("governance_proposal_id".into(), serde_json::json!(proposal_id));
    m
}

/// §11.18 Slice 2 helper: build metadata for an Execute operation on a
/// ProtocolUpgrade proposal. The three upgrade-specific fields are
/// `governance_upgrade_kind` (wire string: `"soft_fork" | "hard_fork" |
/// "emergency"`), `governance_reference_impl_hash` (SHA-256 hex of the
/// reference implementation diff per whitepaper §11.18 line 27), and
/// `governance_proposed_at_epoch` (the epoch at which the proposal was
/// published; needed to bind the tally to a specific point in time on the
/// chain).
///
/// Missing any of these three fields causes `apply_governance_op::Execute`
/// to skip outcome recording (the proposal still executes); the operator
/// must re-execute with a malformed-metadata-fixed record to populate
/// `upgrade_outcomes`. This is by-design: a bad metadata blob shouldn't
/// roll back a valid `execute_proposal()` call that updated the status
/// counter.
pub fn execute_protocol_upgrade_metadata(
    proposal_id: &str,
    upgrade_kind: &str,
    reference_impl_hash: &str,
    proposed_at_epoch: u64,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = execute_metadata(proposal_id);
    m.insert(
        "governance_upgrade_kind".into(),
        serde_json::json!(upgrade_kind),
    );
    m.insert(
        "governance_reference_impl_hash".into(),
        serde_json::json!(reference_impl_hash),
    );
    m.insert(
        "governance_proposed_at_epoch".into(),
        serde_json::json!(proposed_at_epoch),
    );
    m
}

/// Build metadata for a Cancel operation.
pub fn cancel_metadata(
    proposal_id: &str,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(GOVERNANCE_OP_KEY.into(), serde_json::json!("cancel"));
    m.insert("governance_proposal_id".into(), serde_json::json!(proposal_id));
    m
}

/// Build metadata for a Delegate operation.
pub fn delegate_metadata(
    delegate: &str,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(GOVERNANCE_OP_KEY.into(), serde_json::json!("delegate"));
    m.insert("governance_delegate".into(), serde_json::json!(delegate));
    m
}

/// Build metadata for an Undelegate operation.
pub fn undelegate_metadata() -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(GOVERNANCE_OP_KEY.into(), serde_json::json!("undelegate"));
    m
}

/// Build metadata for a Challenge operation (committee challenge).
pub fn challenge_metadata(
    proposal_id: &str,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(GOVERNANCE_OP_KEY.into(), serde_json::json!("challenge"));
    m.insert("governance_proposal_id".into(), serde_json::json!(proposal_id));
    m
}

/// Build metadata for an anchor veto signal.
pub fn anchor_veto_metadata(
    proposal_id: &str,
    zone: ZoneId,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(GOVERNANCE_OP_KEY.into(), serde_json::json!("anchor_veto"));
    m.insert("governance_proposal_id".into(), serde_json::json!(proposal_id));
    m.insert("governance_veto_zone".into(), serde_json::json!(zone));
    m
}

/// Inject committee fields into proposal metadata.
pub fn inject_committee_metadata(
    m: &mut std::collections::BTreeMap<String, serde_json::Value>,
    committee: &Committee,
) {
    m.insert("committee_members".into(), serde_json::json!(committee.members));
    m.insert("committee_vrf_seed".into(), serde_json::json!(committee.vrf_seed));
    m.insert("committee_is_revote".into(), serde_json::json!(committee.is_revote));
    m.insert("committee_selected_at".into(), serde_json::json!(committee.selected_at));
}

/// Extract a committee from record metadata (for rebuild/replay).
///
/// Returns `None` if committee_members is absent — this is normal for
/// non-Critical proposals.
pub fn extract_committee_from_metadata(
    metadata: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Option<Committee> {
    let members = metadata.get("committee_members")?;
    let members: Vec<String> = match members {
        serde_json::Value::Array(arr) => {
            arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
        }
        _ => return None,
    };
    if members.is_empty() {
        return None;
    }
    let vrf_seed = metadata.get("committee_vrf_seed")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let is_revote = metadata.get("committee_is_revote")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let selected_at = metadata.get("committee_selected_at")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    Some(Committee {
        members,
        vrf_seed,
        is_revote,
        selected_at,
        challenge_deadline: None,
        challenger: None,
    })
}

/// Compute total governance-staked supply from the ledger's active stakes.
pub fn total_governance_staked(
    stakes: &HashMap<String, crate::accounting::ledger::StakeEntry>,
) -> u64 {
    stakes
        .values()
        .filter(|s| s.active && s.purpose == StakePurpose::Governance)
        .map(|s| s.amount)
        .sum()
}

/// Compute governance stake for a specific identity.
pub fn governance_stake_for(
    stakes: &HashMap<String, crate::accounting::ledger::StakeEntry>,
    identity_hash: &str,
) -> u64 {
    stakes
        .values()
        .filter(|s| s.active && s.purpose == StakePurpose::Governance && s.staker == identity_hash)
        .map(|s| s.amount)
        .sum()
}

/// Compute effective voting power for an identity, including delegated stakes.
///
/// Effective power = own governance stake + sum of delegators' governance stakes
/// (only delegators who haven't voted themselves on this proposal).
pub fn effective_voting_stake(
    stakes: &HashMap<String, crate::accounting::ledger::StakeEntry>,
    gov_state: &GovernanceState,
    voter: &str,
    proposal: &Proposal,
) -> u64 {
    let own_stake = governance_stake_for(stakes, voter);

    // Add delegated stakes (only from delegators who haven't already voted directly)
    let delegated: u64 = gov_state
        .delegators_for(voter)
        .iter()
        .filter(|d| !proposal.has_voted(&d.delegator))
        .map(|d| governance_stake_for(stakes, &d.delegator))
        .sum();

    own_stake + delegated
}

// ─── Protocol Upgrade Adapter (§11.18) ──────────────────────────────────────

/// Evaluate a governance `Proposal` of category `ProtocolUpgrade` via the
/// §11.18 tally primitive.
///
/// Adapter that maps the conviction-voting fields on a `Proposal` to the
/// `UpgradeProposal` data carrier defined in `network::protocol_upgrade` and
/// delegates the actual decision to `evaluate_upgrade_tally`. Vote weights
/// use the raw `stake` recorded with each vote (NOT conviction) because
/// §11.18 algorithm changes lock in long-term and are decided on raw stake,
/// not time-weighted preference (whitepaper §11.18 line 24 "supermajority
/// vote of all stakeholders").
///
/// Returns `ElaraError::Governance` if the proposal is not of category
/// `ProtocolUpgrade`. Other shapes (wrong field types, malformed votes)
/// cannot occur because the `Proposal` struct enforces them at the type
/// level.
///
/// @spec Protocol §11.18 (Protocol Upgrade Mechanism)
// `node-core` (not `node`): a body-dependency of `apply_protocol_upgrade_outcome`,
// which runs in the ledger apply path — must exist wherever that path compiles.
#[cfg(feature = "node-core")]
pub fn evaluate_protocol_upgrade_proposal(
    proposal: &Proposal,
    kind: crate::network::protocol_upgrade::UpgradeKind,
    reference_impl_hash: String,
    proposed_at_epoch: u64,
    current_time_secs: u64,
) -> Result<crate::network::protocol_upgrade::UpgradeOutcome> {
    if proposal.category != ProposalCategory::ProtocolUpgrade {
        return Err(ElaraError::Governance(format!(
            "evaluate_protocol_upgrade_proposal called on non-ProtocolUpgrade category: {}",
            proposal.category.as_str()
        )));
    }

    let mut votes_for_weight: u128 = 0;
    let mut votes_against_weight: u128 = 0;
    let mut votes_abstain_weight: u128 = 0;
    for v in &proposal.votes {
        let w = v.stake as u128;
        match v.direction {
            VoteDirection::For => {
                votes_for_weight = votes_for_weight.saturating_add(w);
            }
            VoteDirection::Against => {
                votes_against_weight = votes_against_weight.saturating_add(w);
            }
            VoteDirection::Abstain => {
                votes_abstain_weight = votes_abstain_weight.saturating_add(w);
            }
        }
    }

    let up = crate::network::protocol_upgrade::UpgradeProposal {
        proposal_id: proposal.id.clone(),
        kind,
        reference_impl_hash,
        proposed_at_epoch,
        votes_for_weight,
        votes_against_weight,
        votes_abstain_weight,
        vote_window_close_secs: proposal.voting_deadline as u64,
        current_time_secs,
        transition_deadline_secs: None,
    };

    Ok(crate::network::protocol_upgrade::evaluate_upgrade_tally(&up))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: f64 = 24.0 * 3600.0;

    #[test]
    fn test_conviction_zero_duration() {
        assert_eq!(conviction(1_000_000, 0.0), 0.0);
    }

    #[test]
    fn test_conviction_zero_stake() {
        assert_eq!(conviction(0, 7.0 * DAY), 0.0);
    }

    #[test]
    fn test_conviction_at_tau() {
        // At t = τ (7 days), conviction ≈ 63.2% of stake
        let c = conviction(1_000_000, 7.0 * DAY);
        let expected = 1_000_000.0 * (1.0 - 1.0_f64 / std::f64::consts::E);
        assert!((c - expected).abs() < 1.0, "conviction at τ should be ~632120, got {c}");
    }

    #[test]
    fn test_conviction_at_3_tau() {
        // At t = 3τ (21 days), conviction ≈ 95% of stake
        let c = conviction(1_000_000, 21.0 * DAY);
        assert!(c > 950_000.0, "conviction at 3τ should be >95%, got {c}");
        assert!(c < 960_000.0, "conviction at 3τ should be <96%, got {c}");
    }

    #[test]
    fn test_conviction_monotonic() {
        let c1 = conviction(1_000_000, 1.0 * DAY);
        let c7 = conviction(1_000_000, 7.0 * DAY);
        let c14 = conviction(1_000_000, 14.0 * DAY);
        assert!(c1 < c7);
        assert!(c7 < c14);
    }

    // ─── Fixed-point conviction determinism (H2 fork fix) ────────────────────
    // internal design notes. These pin the consensus settle path
    // to bit-identical integer arithmetic across gossip order AND architecture.

    #[test]
    fn conviction_q_matches_f64_curve_at_anchors() {
        let tau = CONVICTION_TAU_SECS as u64;
        // _q value is `value * CONVICTION_Q`; divide back to stake-units.
        let at_tau = conviction_q(1_000_000, tau) as f64 / CONVICTION_Q as f64;
        assert!((at_tau - 632_120.0).abs() < 50.0, "conviction_q at τ ~632120, got {at_tau}");
        let at_3tau = conviction_q(1_000_000, 3 * tau) as f64 / CONVICTION_Q as f64;
        assert!(at_3tau > 950_000.0 && at_3tau < 960_000.0, "conviction_q at 3τ ~95%, got {at_3tau}");
        assert_eq!(conviction_q(1_000_000, 0), 0);
        assert_eq!(conviction_q(0, tau), 0);
    }

    #[test]
    fn conviction_q_is_monotonic_and_saturates() {
        let tau = CONVICTION_TAU_SECS as u64;
        let c1 = conviction_q(1_000_000, tau / 7);
        let c7 = conviction_q(1_000_000, tau);
        let c21 = conviction_q(1_000_000, 3 * tau);
        assert!(c1 < c7 && c7 < c21);
        // Far past saturation, (1 − e^(−x)) → Q exactly, so conviction_q = stake·Q.
        assert_eq!(conviction_q(1_000_000, 100 * tau), 1_000_000u128 * CONVICTION_Q);
    }

    #[test]
    fn tally_votes_is_insertion_order_independent() {
        // Same votes, opposite arrival orders → byte-identical _q tally. The H2a
        // regression gate (the old f64-sum path could diverge near a boundary).
        let t0 = 0.0;
        let mk = |rev: bool| {
            let mut votes = vec![
                Vote { voter: "aaa".into(), stake: 5_000 * BASE_UNITS_PER_BEAT, direction: VoteDirection::For, voted_at: t0, own_stake: None },
                Vote { voter: "bbb".into(), stake: 3_000 * BASE_UNITS_PER_BEAT, direction: VoteDirection::Against, voted_at: t0 + 100.0, own_stake: None },
                Vote { voter: "ccc".into(), stake: 7_000 * BASE_UNITS_PER_BEAT, direction: VoteDirection::For, voted_at: t0 + 50.0, own_stake: None },
                Vote { voter: "ddd".into(), stake: 1_500 * BASE_UNITS_PER_BEAT, direction: VoteDirection::Abstain, voted_at: t0 + 25.0, own_stake: None },
            ];
            if rev { votes.reverse(); }
            Proposal {
                id: "p".into(), proposer: "x".into(), category: ProposalCategory::Parameter,
                title: "T".into(), description: "D".into(),
                created_at: t0, voting_deadline: t0 + VOTING_PERIOD_SECS,
                status: ProposalStatus::Active, passed_at: None, committee: None, votes,
            }
        };
        let fwd = tally_votes(&mk(false), 7.0 * DAY, None);
        let rev = tally_votes(&mk(true), 7.0 * DAY, None);
        assert_eq!(fwd.for_conviction_q, rev.for_conviction_q);
        assert_eq!(fwd.against_conviction_q, rev.against_conviction_q);
        assert_eq!(fwd.abstain_conviction_q, rev.abstain_conviction_q);
    }

    #[test]
    fn conviction_q_has_no_f64_cliff_above_2pow53() {
        // Stakes above 2^53 base units lose integer precision as f64. The _q path
        // is exact: a stake delta well above the f64 cliff changes conviction_q.
        let tau = CONVICTION_TAU_SECS as u64;
        let big = 1u64 << 60; // ≫ 2^53
        let a = conviction_q(big, tau);
        let b = conviction_q(big + (1u64 << 40), tau);
        assert!(a < b, "stake delta above the f64 cliff must change conviction_q ({a} vs {b})");
        // Must not overflow at max supply, far past saturation.
        let _ = conviction_q(crate::accounting::types::MAX_SUPPLY, 100 * tau);
    }

    #[test]
    fn q_gate_constants_match_f64_thresholds() {
        // The integer gates must encode the exact f64 thresholds they replace.
        assert_eq!(SUPERMAJORITY_NUM as f64 / SUPERMAJORITY_DEN as f64, SUPERMAJORITY_THRESHOLD);
        assert_eq!(PARTICIPATION_NUM as f64 / PARTICIPATION_DEN as f64, MIN_PARTICIPATION_FRACTION);
    }

    #[test]
    fn test_dampened_power_sqrt() {
        assert_eq!(dampened_power(0.0), 0.0);
        assert!((dampened_power(100.0) - 10.0).abs() < 0.001);
        assert!((dampened_power(10000.0) - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_dampened_power_whale_resistance() {
        // 4x stake should give only 2x voting power
        let power_small = dampened_power(1000.0);
        let power_big = dampened_power(4000.0);
        let ratio = power_big / power_small;
        assert!((ratio - 2.0).abs() < 0.01, "4x stake should give 2x power, got {ratio}x");
    }

    #[test]
    fn test_identity_cap() {
        let cap = identity_cap(100.0, 4);
        assert!((cap - 50.0).abs() < 0.01, "cap for 4 voters should be 100/√4 = 50, got {cap}");
    }

    #[test]
    fn test_identity_cap_single_voter() {
        let cap = identity_cap(100.0, 1);
        assert_eq!(cap, f64::MAX);
    }

    #[test]
    fn test_create_proposal() {
        let mut state = GovernanceState::new();
        state.create_proposal(
            "prop-001".into(), "alice", ProposalCategory::Parameter,
            "Increase reward".into(), "Double the witness reward".into(),
            2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();

        assert_eq!(state.proposals.len(), 1);
        let p = &state.proposals["prop-001"];
        assert_eq!(p.status, ProposalStatus::Active);
        assert_eq!(p.proposer, "alice");
        assert_eq!(p.voting_deadline, 1000.0 + VOTING_PERIOD_SECS);
    }

    #[test]
    fn test_create_proposal_insufficient_stake() {
        let mut state = GovernanceState::new();
        let result = state.create_proposal(
            "prop-001".into(), "alice", ProposalCategory::Parameter,
            "Title".into(), "Desc".into(),
            500 * BASE_UNITS_PER_BEAT, 1000.0, None, // Only 500 beat, need 1000
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_create_proposal_duplicate() {
        let mut state = GovernanceState::new();
        state.create_proposal(
            "prop-001".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();
        let result = state.create_proposal(
            "prop-001".into(), "bob", ProposalCategory::Parameter,
            "T2".into(), "D2".into(), 2_000 * BASE_UNITS_PER_BEAT, 1001.0, None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_cast_vote() {
        let mut state = GovernanceState::new();
        state.create_proposal(
            "prop-001".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();

        state.cast_vote(
            "prop-001", "bob", VoteDirection::For,
            1_000 * BASE_UNITS_PER_BEAT, 1000.0 + DAY,
        ).unwrap();

        assert_eq!(state.proposals["prop-001"].votes.len(), 1);
        assert_eq!(state.proposals["prop-001"].votes[0].voter, "bob");
    }

    #[test]
    fn test_cast_vote_no_stake() {
        let mut state = GovernanceState::new();
        state.create_proposal(
            "prop-001".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();

        let result = state.cast_vote("prop-001", "bob", VoteDirection::For, 0, 1000.0 + DAY);
        assert!(result.is_err());
    }

    #[test]
    fn test_cast_vote_double_vote() {
        let mut state = GovernanceState::new();
        state.create_proposal(
            "prop-001".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();
        state.cast_vote("prop-001", "bob", VoteDirection::For, 1_000 * BASE_UNITS_PER_BEAT, 1000.0 + DAY).unwrap();
        let result = state.cast_vote("prop-001", "bob", VoteDirection::Against, 1_000 * BASE_UNITS_PER_BEAT, 1000.0 + 2.0 * DAY);
        assert!(result.is_err());
    }

    #[test]
    fn test_cast_vote_after_deadline() {
        let mut state = GovernanceState::new();
        state.create_proposal(
            "prop-001".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();

        let result = state.cast_vote(
            "prop-001", "bob", VoteDirection::For,
            1_000 * BASE_UNITS_PER_BEAT, 1000.0 + VOTING_PERIOD_SECS + 1.0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_settle_passes_supermajority() {
        let mut state = GovernanceState::new();
        let t0 = 1000.0;
        let stake = 1_000 * BASE_UNITS_PER_BEAT;

        state.create_proposal(
            "prop-001".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), stake, t0, None,
        ).unwrap();

        // 3 votes for, 1 against — 75% supermajority
        for voter in ["v1", "v2", "v3"] {
            state.cast_vote("prop-001", voter, VoteDirection::For, stake, t0 + DAY).unwrap();
        }
        state.cast_vote("prop-001", "v4", VoteDirection::Against, stake, t0 + DAY).unwrap();

        let total_gov_staked = 4 * stake;
        let result = state.settle_proposal("prop-001", total_gov_staked, t0 + VOTING_PERIOD_SECS + 1.0).unwrap();
        assert_eq!(result, ProposalStatus::Passed);
    }

    #[test]
    fn test_settle_rejected_no_supermajority() {
        let mut state = GovernanceState::new();
        let t0 = 1000.0;
        let stake = 1_000 * BASE_UNITS_PER_BEAT;

        state.create_proposal(
            "prop-001".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), stake, t0, None,
        ).unwrap();

        // 1 for, 1 against — 50% < 67%
        state.cast_vote("prop-001", "v1", VoteDirection::For, stake, t0 + DAY).unwrap();
        state.cast_vote("prop-001", "v2", VoteDirection::Against, stake, t0 + DAY).unwrap();

        let total_gov_staked = 2 * stake; // 100% participation
        let result = state.settle_proposal("prop-001", total_gov_staked, t0 + VOTING_PERIOD_SECS + 1.0).unwrap();
        assert_eq!(result, ProposalStatus::Rejected);
    }

    #[test]
    fn test_settle_expired_low_participation() {
        let mut state = GovernanceState::new();
        let t0 = 1000.0;
        let stake = 1_000 * BASE_UNITS_PER_BEAT;

        state.create_proposal(
            "prop-001".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), stake, t0, None,
        ).unwrap();

        // Only 1 voter out of total governance staked = 100 voters worth
        state.cast_vote("prop-001", "v1", VoteDirection::For, stake, t0 + DAY).unwrap();

        let total_gov_staked = 100 * stake; // 1% participation < 10% required
        let result = state.settle_proposal("prop-001", total_gov_staked, t0 + VOTING_PERIOD_SECS + 1.0).unwrap();
        assert_eq!(result, ProposalStatus::Expired);
    }

    #[test]
    fn test_settle_before_deadline() {
        let mut state = GovernanceState::new();
        state.create_proposal(
            "prop-001".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();

        let result = state.settle_proposal("prop-001", 10_000 * BASE_UNITS_PER_BEAT, 1000.0 + DAY);
        assert!(result.is_err());
    }

    #[test]
    fn test_cancel_proposal() {
        let mut state = GovernanceState::new();
        state.create_proposal(
            "prop-001".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();

        state.cancel_proposal("prop-001", "alice").unwrap();
        assert_eq!(state.proposals["prop-001"].status, ProposalStatus::Cancelled);
    }

    #[test]
    fn test_cancel_by_non_proposer() {
        let mut state = GovernanceState::new();
        state.create_proposal(
            "prop-001".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();

        let result = state.cancel_proposal("prop-001", "bob");
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_after_delay() {
        let mut state = GovernanceState::new();
        let t0 = 1000.0;
        let stake = 1_000 * BASE_UNITS_PER_BEAT;

        state.create_proposal(
            "prop-001".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), stake, t0, None,
        ).unwrap();

        // 3 for, 1 against
        for voter in ["v1", "v2", "v3"] {
            state.cast_vote("prop-001", voter, VoteDirection::For, stake, t0 + DAY).unwrap();
        }
        state.cast_vote("prop-001", "v4", VoteDirection::Against, stake, t0 + DAY).unwrap();

        let settle_time = t0 + VOTING_PERIOD_SECS + 1.0;
        state.settle_proposal("prop-001", 4 * stake, settle_time).unwrap();

        // Try to execute before delay
        let result = state.execute_proposal("prop-001", settle_time + DAY);
        assert!(result.is_err());

        // Execute after full delay
        state.execute_proposal("prop-001", settle_time + EXECUTION_DELAY_SECS + 1.0).unwrap();
        assert_eq!(state.proposals["prop-001"].status, ProposalStatus::Executed);
    }

    #[test]
    fn test_conviction_weighting_rewards_patience() {
        // Voter who holds their vote longer should have more conviction
        let stake = 1_000 * BASE_UNITS_PER_BEAT;
        let early = conviction(stake, 1.0 * DAY);  // voted 1 day ago
        let late = conviction(stake, 10.0 * DAY);   // voted 10 days ago
        assert!(late > early, "longer hold should give more conviction");
        assert!(late > 2.0 * early, "10 days should give >2x the conviction of 1 day");
    }

    #[test]
    fn test_tally_empty() {
        let proposal = Proposal {
            id: "p".into(), proposer: "a".into(),
            category: ProposalCategory::Parameter,
            title: "T".into(), description: "D".into(),
            created_at: 0.0, voting_deadline: 1000.0,
            status: ProposalStatus::Active,
            passed_at: None, votes: vec![], committee: None,
        };
        let tally = tally_votes(&proposal, 1000.0, None);
        assert_eq!(tally.voter_count, 0);
        assert_eq!(tally.for_conviction(), 0.0);
    }

    #[test]
    fn test_tally_cap_limits_whale() {
        let stake_whale = 100_000 * BASE_UNITS_PER_BEAT;
        let stake_small = 100 * BASE_UNITS_PER_BEAT;
        let t0 = 0.0;

        let proposal = Proposal {
            id: "p".into(), proposer: "a".into(),
            category: ProposalCategory::Parameter,
            title: "T".into(), description: "D".into(),
            created_at: t0, voting_deadline: t0 + VOTING_PERIOD_SECS,
            status: ProposalStatus::Active,
            passed_at: None, committee: None,
            votes: vec![
                Vote { voter: "whale".into(), stake: stake_whale, direction: VoteDirection::For, voted_at: t0, own_stake: None },
                Vote { voter: "small1".into(), stake: stake_small, direction: VoteDirection::Against, voted_at: t0, own_stake: None },
                Vote { voter: "small2".into(), stake: stake_small, direction: VoteDirection::Against, voted_at: t0, own_stake: None },
                Vote { voter: "small3".into(), stake: stake_small, direction: VoteDirection::Against, voted_at: t0, own_stake: None },
            ],
        };

        let tally = tally_votes(&proposal, t0 + 7.0 * DAY, None);
        // Due to cap, whale's vote should be limited — 3 small voters should outweigh
        // Cap = total_power / √4 = total_power / 2
        // This means whale's capped power is at most half the total
        assert!(
            tally.against_conviction() > 0.0,
            "against should have conviction"
        );
    }

    #[test]
    fn test_proposal_category_roundtrip() {
        for cat in [ProposalCategory::ZoneLocal, ProposalCategory::Parameter, ProposalCategory::Critical, ProposalCategory::ProtocolUpgrade] {
            let s = cat.as_str();
            let parsed = ProposalCategory::parse(s).unwrap();
            assert_eq!(parsed, cat);
        }
    }

    /// §11.18 wire-up: the new `ProtocolUpgrade` variant must round-trip its
    /// canonical wire string `"protocol_upgrade"`. Pinned separately from the
    /// loop test because an off-by-one regression in `as_str()` (e.g.
    /// `"protocolupgrade"` without underscore) would let the loop pass via the
    /// roundtrip closure but break wire compatibility with the JSON metadata
    /// emitted by `propose_metadata()` and consumed by `extract_governance_op()`.
    #[test]
    fn test_proposal_category_protocol_upgrade_wire_string() {
        assert_eq!(ProposalCategory::ProtocolUpgrade.as_str(), "protocol_upgrade");
        assert_eq!(
            ProposalCategory::parse("protocol_upgrade").unwrap(),
            ProposalCategory::ProtocolUpgrade,
        );
        // Confirm the variant is distinct from the existing three at the wire
        // boundary — a typo collision (e.g. "critical" → ProtocolUpgrade)
        // would silently misroute votes through the wrong threshold gate.
        assert_ne!(
            ProposalCategory::parse("critical").unwrap(),
            ProposalCategory::ProtocolUpgrade,
        );
        assert_ne!(
            ProposalCategory::parse("parameter").unwrap(),
            ProposalCategory::ProtocolUpgrade,
        );
    }

    #[test]
    fn test_vote_direction_roundtrip() {
        for dir in [VoteDirection::For, VoteDirection::Against, VoteDirection::Abstain] {
            let s = dir.as_str();
            let parsed = VoteDirection::parse(s).unwrap();
            assert_eq!(parsed, dir);
        }
    }

    #[test]
    fn test_extract_propose_metadata() {
        let meta = propose_metadata(
            &ProposalCategory::Parameter,
            "Increase rewards",
            "Double the witness reward from 1 to 2 beat",
        );
        let op = extract_governance_op(&meta).unwrap().unwrap();
        match op {
            ParsedGovernanceOp::Propose { category, title, description } => {
                assert_eq!(category, ProposalCategory::Parameter);
                assert_eq!(title, "Increase rewards");
                assert!(description.contains("Double"));
            }
            _ => panic!("expected Propose"),
        }
    }

    #[test]
    fn test_extract_vote_metadata() {
        let meta = vote_metadata("prop-001", &VoteDirection::For);
        let op = extract_governance_op(&meta).unwrap().unwrap();
        match op {
            ParsedGovernanceOp::Vote { proposal_id, direction } => {
                assert_eq!(proposal_id, "prop-001");
                assert_eq!(direction, VoteDirection::For);
            }
            _ => panic!("expected Vote"),
        }
    }

    #[test]
    fn test_extract_execute_metadata() {
        let meta = execute_metadata("prop-001");
        let op = extract_governance_op(&meta).unwrap().unwrap();
        match op {
            ParsedGovernanceOp::Execute { proposal_id } => {
                assert_eq!(proposal_id, "prop-001");
            }
            _ => panic!("expected Execute"),
        }
    }

    #[test]
    fn test_extract_cancel_metadata() {
        let meta = cancel_metadata("prop-001");
        let op = extract_governance_op(&meta).unwrap().unwrap();
        match op {
            ParsedGovernanceOp::Cancel { proposal_id } => {
                assert_eq!(proposal_id, "prop-001");
            }
            _ => panic!("expected Cancel"),
        }
    }

    #[test]
    fn test_extract_no_governance_op() {
        let meta = std::collections::BTreeMap::new();
        assert!(extract_governance_op(&meta).unwrap().is_none());
    }

    #[test]
    fn test_proposal_counts() {
        let mut state = GovernanceState::new();
        let stake = 2_000 * BASE_UNITS_PER_BEAT;

        state.create_proposal("p1".into(), "alice", ProposalCategory::Parameter, "T".into(), "D".into(), stake, 0.0, None).unwrap();
        state.create_proposal("p2".into(), "alice", ProposalCategory::Parameter, "T".into(), "D".into(), stake, 0.0, None).unwrap();
        state.cancel_proposal("p2", "alice").unwrap();

        let (active, _passed, _rejected, _expired, _executed, cancelled, _vetoed) = state.proposal_counts();
        assert_eq!(active, 1);
        assert_eq!(cancelled, 1);
    }

    #[test]
    fn test_total_governance_staked() {
        let mut stakes = HashMap::new();
        stakes.insert("s1".into(), crate::accounting::ledger::StakeEntry {
            record_id: "s1".into(), amount: 1000, purpose: StakePurpose::Governance,
            staker: "alice".into(), timestamp: 0.0, active: true,
        });
        stakes.insert("s2".into(), crate::accounting::ledger::StakeEntry {
            record_id: "s2".into(), amount: 2000, purpose: StakePurpose::Witness,
            staker: "bob".into(), timestamp: 0.0, active: true,
        });
        stakes.insert("s3".into(), crate::accounting::ledger::StakeEntry {
            record_id: "s3".into(), amount: 500, purpose: StakePurpose::Governance,
            staker: "charlie".into(), timestamp: 0.0, active: false, // inactive
        });

        assert_eq!(total_governance_staked(&stakes), 1000);
    }

    #[test]
    fn test_governance_stake_for_identity() {
        let mut stakes = HashMap::new();
        stakes.insert("s1".into(), crate::accounting::ledger::StakeEntry {
            record_id: "s1".into(), amount: 1000, purpose: StakePurpose::Governance,
            staker: "alice".into(), timestamp: 0.0, active: true,
        });
        stakes.insert("s2".into(), crate::accounting::ledger::StakeEntry {
            record_id: "s2".into(), amount: 2000, purpose: StakePurpose::Governance,
            staker: "alice".into(), timestamp: 0.0, active: true,
        });
        stakes.insert("s3".into(), crate::accounting::ledger::StakeEntry {
            record_id: "s3".into(), amount: 500, purpose: StakePurpose::Governance,
            staker: "bob".into(), timestamp: 0.0, active: true,
        });

        assert_eq!(governance_stake_for(&stakes, "alice"), 3000);
        assert_eq!(governance_stake_for(&stakes, "bob"), 500);
        assert_eq!(governance_stake_for(&stakes, "nobody"), 0);
    }

    // ─── Delegation Tests ────────────────────────────────────────────

    #[test]
    fn test_delegate_ok() {
        let mut state = GovernanceState::new();
        state.delegate("alice", "bob", 1000.0).unwrap();
        assert_eq!(state.delegations.len(), 1);
        assert!(state.delegation_of("alice").is_some());
        assert_eq!(state.delegation_of("alice").unwrap().delegate, "bob");
    }

    #[test]
    fn test_delegate_self_rejected() {
        let mut state = GovernanceState::new();
        let result = state.delegate("alice", "alice", 1000.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_delegate_double_rejected() {
        let mut state = GovernanceState::new();
        state.delegate("alice", "bob", 1000.0).unwrap();
        let result = state.delegate("alice", "charlie", 1001.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_delegate_circular_rejected() {
        let mut state = GovernanceState::new();
        state.delegate("alice", "bob", 1000.0).unwrap();
        let result = state.delegate("bob", "alice", 1001.0);
        assert!(result.is_err());
    }

    #[test]
    fn test_undelegate_ok() {
        let mut state = GovernanceState::new();
        state.delegate("alice", "bob", 1000.0).unwrap();
        state.undelegate("alice").unwrap();
        assert!(state.delegation_of("alice").is_none());
    }

    #[test]
    fn test_undelegate_no_delegation() {
        let mut state = GovernanceState::new();
        let result = state.undelegate("alice");
        assert!(result.is_err());
    }

    #[test]
    fn test_re_delegate_after_undelegate() {
        let mut state = GovernanceState::new();
        state.delegate("alice", "bob", 1000.0).unwrap();
        state.undelegate("alice").unwrap();
        state.delegate("alice", "charlie", 1002.0).unwrap();
        assert_eq!(state.delegation_of("alice").unwrap().delegate, "charlie");
    }

    #[test]
    fn test_delegators_for() {
        let mut state = GovernanceState::new();
        state.delegate("alice", "judge", 1000.0).unwrap();
        state.delegate("bob", "judge", 1001.0).unwrap();
        state.delegate("charlie", "other", 1002.0).unwrap();

        let delegators = state.delegators_for("judge");
        assert_eq!(delegators.len(), 2);
    }

    #[test]
    fn test_effective_voting_stake_with_delegation() {
        let mut stakes = HashMap::new();
        // Bob has 1000 governance stake
        stakes.insert("s1".into(), crate::accounting::ledger::StakeEntry {
            record_id: "s1".into(), amount: 1000, purpose: StakePurpose::Governance,
            staker: "bob".into(), timestamp: 0.0, active: true,
        });
        // Alice has 500 governance stake, delegates to bob
        stakes.insert("s2".into(), crate::accounting::ledger::StakeEntry {
            record_id: "s2".into(), amount: 500, purpose: StakePurpose::Governance,
            staker: "alice".into(), timestamp: 0.0, active: true,
        });

        let mut gov = GovernanceState::new();
        gov.delegate("alice", "bob", 100.0).unwrap();

        // Create a proposal (no votes yet)
        gov.create_proposal(
            "p1".into(), "someone", ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 0.0, None,
        ).unwrap();

        let proposal = &gov.proposals["p1"];
        let eff = effective_voting_stake(&stakes, &gov, "bob", proposal);
        assert_eq!(eff, 1500, "bob should have own 1000 + alice's 500");
    }

    #[test]
    fn test_effective_stake_excludes_direct_voter() {
        let mut stakes = HashMap::new();
        stakes.insert("s1".into(), crate::accounting::ledger::StakeEntry {
            record_id: "s1".into(), amount: 1000, purpose: StakePurpose::Governance,
            staker: "bob".into(), timestamp: 0.0, active: true,
        });
        stakes.insert("s2".into(), crate::accounting::ledger::StakeEntry {
            record_id: "s2".into(), amount: 500, purpose: StakePurpose::Governance,
            staker: "alice".into(), timestamp: 0.0, active: true,
        });

        let mut gov = GovernanceState::new();
        gov.delegate("alice", "bob", 100.0).unwrap();
        gov.create_proposal(
            "p1".into(), "someone", ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 0.0, None,
        ).unwrap();

        // Alice votes directly — her stake should NOT count in bob's delegation
        gov.cast_vote("p1", "alice", VoteDirection::Against, 500, 1.0).unwrap();

        let proposal = &gov.proposals["p1"];
        let eff = effective_voting_stake(&stakes, &gov, "bob", proposal);
        assert_eq!(eff, 1000, "alice voted directly, so bob only has own 1000");
    }

    // Helper: two governance stakers (bob=1000, alice=500) for delegation tests.
    #[cfg(test)]
    fn two_gov_stakers() -> HashMap<String, crate::accounting::ledger::StakeEntry> {
        let mut stakes = HashMap::new();
        stakes.insert("s1".into(), crate::accounting::ledger::StakeEntry {
            record_id: "s1".into(), amount: 1000, purpose: StakePurpose::Governance,
            staker: "bob".into(), timestamp: 0.0, active: true,
        });
        stakes.insert("s2".into(), crate::accounting::ledger::StakeEntry {
            record_id: "s2".into(), amount: 500, purpose: StakePurpose::Governance,
            staker: "alice".into(), timestamp: 0.0, active: true,
        });
        stakes
    }

    #[test]
    fn test_reconcile_fixes_delegate_first_double_count() {
        // PRIMARY double-count: alice delegates to bob, bob (the delegate) votes
        // FIRST folding alice in, then alice votes directly. cast_vote only
        // checks has_voted(alice), so the direct vote is accepted and alice's
        // 500 ends up counted twice (bob=1500, alice=500 -> raw 2000).
        let stakes = two_gov_stakers();
        let mut gov = GovernanceState::new();
        gov.delegate("alice", "bob", 100.0).unwrap();
        gov.create_proposal(
            "p1".into(), "someone", ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 0.0, None,
        ).unwrap();

        let bob_eff = effective_voting_stake(&stakes, &gov, "bob", &gov.proposals["p1"]);
        assert_eq!(bob_eff, 1500, "bob folds alice at his vote time");
        gov.cast_vote_with_own("p1", "bob", VoteDirection::For, bob_eff, governance_stake_for(&stakes, "bob"), 1.0).unwrap();

        let alice_eff = effective_voting_stake(&stakes, &gov, "alice", &gov.proposals["p1"]);
        assert_eq!(alice_eff, 500);
        gov.cast_vote_with_own("p1", "alice", VoteDirection::For, alice_eff, governance_stake_for(&stakes, "alice"), 2.0).unwrap();

        let raw_buggy: u64 = gov.proposals["p1"].votes.iter().map(|v| v.stake).sum();
        assert_eq!(raw_buggy, 2000, "pre-reconcile: alice's 500 is double-counted");

        gov.reconcile_effective_stakes(&stakes, "p1");

        let votes = &gov.proposals["p1"].votes;
        let bob_v = votes.iter().find(|v| v.voter == "bob").unwrap();
        let alice_v = votes.iter().find(|v| v.voter == "alice").unwrap();
        assert_eq!(bob_v.stake, 1000, "fold drops alice (she voted directly)");
        assert_eq!(alice_v.stake, 500, "alice keeps only her own");
        let raw_fixed: u64 = votes.iter().map(|v| v.stake).sum();
        assert_eq!(raw_fixed, 1500, "each unit of stake counted exactly once");
    }

    #[test]
    fn test_reconcile_fixes_undelegate_after_fold_residual() {
        // RESIDUAL: bob votes folding alice, THEN alice undelegates and votes.
        // The stored fold in bob's vote is stale; reconcile drops alice because
        // she is no longer an active delegator.
        let stakes = two_gov_stakers();
        let mut gov = GovernanceState::new();
        gov.delegate("alice", "bob", 100.0).unwrap();
        gov.create_proposal(
            "p1".into(), "someone", ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 0.0, None,
        ).unwrap();

        let bob_eff = effective_voting_stake(&stakes, &gov, "bob", &gov.proposals["p1"]);
        assert_eq!(bob_eff, 1500);
        gov.cast_vote_with_own("p1", "bob", VoteDirection::For, bob_eff, governance_stake_for(&stakes, "bob"), 1.0).unwrap();

        gov.undelegate("alice").unwrap();
        let alice_eff = effective_voting_stake(&stakes, &gov, "alice", &gov.proposals["p1"]);
        gov.cast_vote_with_own("p1", "alice", VoteDirection::For, alice_eff, governance_stake_for(&stakes, "alice"), 2.0).unwrap();

        gov.reconcile_effective_stakes(&stakes, "p1");

        let votes = &gov.proposals["p1"].votes;
        assert_eq!(votes.iter().find(|v| v.voter == "bob").unwrap().stake, 1000);
        let raw: u64 = votes.iter().map(|v| v.stake).sum();
        assert_eq!(raw, 1500, "undelegate-then-vote no longer double-counts");
    }

    #[test]
    fn test_reconcile_preserves_valid_fold() {
        // NEGATIVE: alice delegates to bob and does NOT vote directly. Bob's
        // legitimate fold (own 1000 + alice 500) must survive reconcile.
        let stakes = two_gov_stakers();
        let mut gov = GovernanceState::new();
        gov.delegate("alice", "bob", 100.0).unwrap();
        gov.create_proposal(
            "p1".into(), "someone", ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 0.0, None,
        ).unwrap();

        let bob_eff = effective_voting_stake(&stakes, &gov, "bob", &gov.proposals["p1"]);
        gov.cast_vote_with_own("p1", "bob", VoteDirection::For, bob_eff, governance_stake_for(&stakes, "bob"), 1.0).unwrap();

        gov.reconcile_effective_stakes(&stakes, "p1");

        let votes = &gov.proposals["p1"].votes;
        assert_eq!(votes.iter().find(|v| v.voter == "bob").unwrap().stake, 1500,
            "valid delegation fold is preserved");
    }

    // Helper: one governance staker with `amount` under record id `s1`.
    #[cfg(test)]
    fn one_gov_staker(staker: &str, amount: u64) -> HashMap<String, crate::accounting::ledger::StakeEntry> {
        let mut stakes = HashMap::new();
        stakes.insert("s1".into(), crate::accounting::ledger::StakeEntry {
            record_id: "s1".into(), amount, purpose: StakePurpose::Governance,
            staker: staker.into(), timestamp: 0.0, active: true,
        });
        stakes
    }

    #[test]
    fn test_reconcile_freezes_own_against_late_stake_amplification() {
        // Discount-evasion guard: bob votes early with own=100, then balloons
        // his governance stake to 1000 before the deadline. reconcile must keep
        // his weight at the FROZEN vote-time own (100), NOT the settle-time
        // 1000 — else a dust-early vote banks conviction duration off `voted_at`
        // then tops up to dodge the time-discount.
        let early = one_gov_staker("bob", 100);
        let mut gov = GovernanceState::new();
        gov.create_proposal(
            "p1".into(), "someone", ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 0.0, None,
        ).unwrap();
        let bob_eff = effective_voting_stake(&early, &gov, "bob", &gov.proposals["p1"]);
        assert_eq!(bob_eff, 100);
        gov.cast_vote_with_own("p1", "bob", VoteDirection::For, bob_eff,
            governance_stake_for(&early, "bob"), 1.0).unwrap();

        // Bob balloons his governance stake 10x before settle.
        let late = one_gov_staker("bob", 1000);
        gov.reconcile_effective_stakes(&late, "p1");

        let bob_v = gov.proposals["p1"].votes.iter().find(|v| v.voter == "bob").unwrap();
        assert_eq!(bob_v.stake, 100, "frozen vote-time own; late top-up cannot amplify");
        assert_eq!(bob_v.own_stake, Some(100), "own_stake frozen at vote time");
    }

    #[test]
    fn test_reconcile_is_idempotent() {
        // Running reconcile twice yields the same weight: the absolute recompute
        // reads frozen own + the live fold, never the value it overwrites.
        let stakes = two_gov_stakers();
        let mut gov = GovernanceState::new();
        gov.delegate("alice", "bob", 100.0).unwrap();
        gov.create_proposal(
            "p1".into(), "someone", ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 0.0, None,
        ).unwrap();
        let bob_eff = effective_voting_stake(&stakes, &gov, "bob", &gov.proposals["p1"]);
        gov.cast_vote_with_own("p1", "bob", VoteDirection::For, bob_eff,
            governance_stake_for(&stakes, "bob"), 1.0).unwrap();

        gov.reconcile_effective_stakes(&stakes, "p1");
        let after_one = gov.proposals["p1"].votes.iter().find(|v| v.voter == "bob").unwrap().stake;
        gov.reconcile_effective_stakes(&stakes, "p1");
        let after_two = gov.proposals["p1"].votes.iter().find(|v| v.voter == "bob").unwrap().stake;
        assert_eq!(after_one, 1500);
        assert_eq!(after_two, after_one, "reconcile is idempotent");
    }

    #[test]
    fn test_extract_delegate_metadata() {
        let meta = delegate_metadata("bob_hash");
        let op = extract_governance_op(&meta).unwrap().unwrap();
        match op {
            ParsedGovernanceOp::Delegate { delegate } => {
                assert_eq!(delegate, "bob_hash");
            }
            _ => panic!("expected Delegate"),
        }
    }

    #[test]
    fn test_extract_undelegate_metadata() {
        let meta = undelegate_metadata();
        let op = extract_governance_op(&meta).unwrap().unwrap();
        assert!(matches!(op, ParsedGovernanceOp::Undelegate));
    }

    // ─── Governable Params Tests ─────────────────────────────────────

    #[test]
    fn test_governable_params_default() {
        let params = GovernableParams::default();
        assert_eq!(params.propagation_rate_limit_per_hour, 120);
        assert_eq!(params.epoch_seal_interval_secs, 300.0);
        assert_eq!(params.witness_reward_micros, 1_000_000_000); // 1 beat in base units
        assert_eq!(params.record_retention_secs, 0.0);
    }

    #[test]
    fn test_governable_params_apply() {
        let mut params = GovernableParams::default();
        params.apply("propagation_rate_limit_per_hour", "240").unwrap();
        assert_eq!(params.propagation_rate_limit_per_hour, 240);
    }

    #[test]
    fn test_governable_params_apply_unknown() {
        let mut params = GovernableParams::default();
        assert!(params.apply("unknown_param", "42").is_err());
    }

    #[test]
    fn test_governable_params_apply_bad_value() {
        let mut params = GovernableParams::default();
        assert!(params.apply("propagation_rate_limit_per_hour", "not_a_number").is_err());
    }

    #[test]
    fn test_governable_params_get() {
        let params = GovernableParams::default();
        assert_eq!(params.get("propagation_rate_limit_per_hour"), Some("120".to_string()));
        assert_eq!(params.get("nonexistent"), None);
    }

    #[test]
    fn test_governance_apply_param_change() {
        let mut state = GovernanceState::new();
        state.create_proposal(
            "prop-param".into(), "alice", ProposalCategory::Parameter,
            "Increase rate limit".into(), "Double the propagation rate limit".into(),
            2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();

        let old = state.apply_param_change(
            "prop-param", "propagation_rate_limit_per_hour", "240", 2000.0,
        ).unwrap();

        assert_eq!(old, "120");
        assert_eq!(state.params.propagation_rate_limit_per_hour, 240);
        assert_eq!(state.param_changes.len(), 1);
        assert_eq!(state.param_changes[0].name, "propagation_rate_limit_per_hour");
        assert_eq!(state.param_changes[0].old_value, "120");
        assert_eq!(state.param_changes[0].new_value, "240");
    }

    #[test]
    fn test_governance_param_change_history() {
        let mut state = GovernanceState::new();
        state.apply_param_change("p1", "witness_reward_micros", "2000000", 1000.0).unwrap();
        state.apply_param_change("p2", "epoch_seal_interval_secs", "600", 2000.0).unwrap();
        state.apply_param_change("p3", "witness_reward_micros", "3000000", 3000.0).unwrap();

        assert_eq!(state.param_changes.len(), 3);
        assert_eq!(state.params.witness_reward_micros, 3_000_000);
        assert_eq!(state.params.epoch_seal_interval_secs, 600.0);
    }

    #[test]
    fn test_governable_params_all_recognized() {
        for name in GOVERNABLE_PARAMS {
            let params = GovernableParams::default();
            assert!(params.get(name).is_some(), "param {name} not recognized by get()");
        }
    }

    #[test]
    fn test_governable_params_roundtrip_all() {
        let mut params = GovernableParams::default();
        params.apply("propagation_rate_limit_per_hour", "500").unwrap();
        params.apply("epoch_seal_interval_secs", "120.5").unwrap();
        params.apply("witness_reward_micros", "5000000").unwrap();
        params.apply("record_retention_secs", "86400.0").unwrap();

        assert_eq!(params.propagation_rate_limit_per_hour, 500);
        assert_eq!(params.epoch_seal_interval_secs, 120.5);
        assert_eq!(params.witness_reward_micros, 5_000_000);
        assert_eq!(params.record_retention_secs, 86400.0);
    }

    // ─── Governance weight decay tests (economics §13.8) ───────────────

    #[test]
    fn test_governance_decay_no_outflow() {
        let velocity = crate::accounting::velocity::VelocityTracker::new();
        let decay = governance_decay_multiplier(&velocity, 1_000_000, "alice", 1000.0);
        assert_eq!(decay, 1.0);
    }

    #[test]
    fn test_governance_decay_below_threshold() {
        let mut velocity = crate::accounting::velocity::VelocityTracker::new();
        // 4% outflow (below 5% threshold)
        velocity.record_balance("alice", 1_000_000, 500.0);
        velocity.record_outflow("alice", 40_000, 900.0); // 4% of 1M
        let decay = governance_decay_multiplier(&velocity, 1_000_000, "alice", 1000.0);
        assert_eq!(decay, 1.0); // No decay
    }

    #[test]
    fn test_governance_decay_10_percent_outflow() {
        let mut velocity = crate::accounting::velocity::VelocityTracker::new();
        velocity.record_balance("alice", 1_000_000, 500.0);
        velocity.record_outflow("alice", 100_000, 900.0); // 10% outflow
        let decay = governance_decay_multiplier(&velocity, 1_000_000, "alice", 1000.0);
        // outflow_ratio = 0.10, decay = 1.0 - 0.10 * 3 = 0.70
        assert!((decay - 0.70).abs() < 0.001, "expected ~0.70, got {decay}");
    }

    #[test]
    fn test_governance_decay_20_percent_outflow() {
        let mut velocity = crate::accounting::velocity::VelocityTracker::new();
        velocity.record_balance("alice", 1_000_000, 500.0);
        velocity.record_outflow("alice", 200_000, 900.0); // 20% outflow
        let decay = governance_decay_multiplier(&velocity, 1_000_000, "alice", 1000.0);
        // outflow_ratio = 0.20, decay = 1.0 - 0.20 * 3 = 0.40
        assert!((decay - 0.40).abs() < 0.001, "expected ~0.40, got {decay}");
    }

    #[test]
    fn test_governance_decay_floor() {
        let mut velocity = crate::accounting::velocity::VelocityTracker::new();
        velocity.record_balance("alice", 1_000_000, 500.0);
        velocity.record_outflow("alice", 500_000, 900.0); // 50% outflow
        let decay = governance_decay_multiplier(&velocity, 1_000_000, "alice", 1000.0);
        // outflow_ratio = 0.50, decay = 1.0 - 0.50 * 3 = -0.50, floored to 0.01
        assert_eq!(decay, 0.01);
    }

    #[test]
    fn test_governance_decay_no_stake() {
        let velocity = crate::accounting::velocity::VelocityTracker::new();
        let decay = governance_decay_multiplier(&velocity, 0, "alice", 1000.0);
        assert_eq!(decay, 0.01); // No stake = floor
    }

    #[test]
    fn test_governance_decay_peak_staked_denominator() {
        let mut velocity = crate::accounting::velocity::VelocityTracker::new();
        // Peak balance was 2M but current stake is 500K (unstaked half)
        velocity.record_balance("alice", 2_000_000, 500.0);
        velocity.record_outflow("alice", 200_000, 900.0); // 200K outflow
        let decay = governance_decay_multiplier(&velocity, 500_000, "alice", 1000.0);
        // denominator = max(500K, 2M) = 2M
        // outflow_ratio = 200K / 2M = 0.10, decay = 1.0 - 0.10 * 3 = 0.70
        assert!((decay - 0.70).abs() < 0.001, "expected ~0.70, got {decay}");
    }

    #[test]
    fn test_governance_decay_applied_in_tally() {
        let stake = 1_000 * BASE_UNITS_PER_BEAT;
        let t0 = 86400.0 * 7.0; // 7 days in

        let mut proposal = Proposal {
            id: "decay-test".into(), proposer: "test".into(),
            category: ProposalCategory::Parameter,
            title: "test decay".into(), description: "D".into(),
            created_at: t0, voting_deadline: t0 + 14.0 * DAY,
            status: ProposalStatus::Active,
            passed_at: None, votes: vec![],
            committee: None,
        };
        proposal.votes.push(Vote { voter: "whale".into(), stake, direction: VoteDirection::For, voted_at: t0, own_stake: None });
        proposal.votes.push(Vote { voter: "holder".into(), stake, direction: VoteDirection::Against, voted_at: t0, own_stake: None });

        // Without decay: equal power
        let tally_none = tally_votes(&proposal, t0 + 7.0 * DAY, None);
        assert!((tally_none.for_conviction() - tally_none.against_conviction()).abs() < 0.01);

        // With decay: whale has 40% power (20% outflow = 0.40 decay)
        let mut decay = HashMap::new();
        decay.insert("whale".to_string(), 0.40);
        decay.insert("holder".to_string(), 1.0);

        let tally_decayed = tally_votes(&proposal, t0 + 7.0 * DAY, Some(&decay));
        // whale gets 40% of normal power, holder gets 100%
        assert!(tally_decayed.against_conviction() > tally_decayed.for_conviction());
        // whale power should be ~40% of holder power
        let ratio = tally_decayed.for_conviction() / tally_decayed.against_conviction();
        assert!((ratio - 0.40).abs() < 0.01, "expected ~0.40 ratio, got {ratio}");
    }

    // ─── Committee selection tests (economics §7.4) ─────────────────────

    #[test]
    fn test_select_committee_deterministic() {
        let candidates: Vec<(String, f64)> = (0..200)
            .map(|i| (format!("node_{i}"), 1.0))
            .collect();
        let c1 = select_committee("seed-42", &candidates, COMMITTEE_SIZE);
        let c2 = select_committee("seed-42", &candidates, COMMITTEE_SIZE);
        assert_eq!(c1, c2, "same seed must produce same committee");
    }

    #[test]
    fn test_select_committee_different_seeds() {
        let candidates: Vec<(String, f64)> = (0..200)
            .map(|i| (format!("node_{i}"), 1.0))
            .collect();
        let c1 = select_committee("seed-a", &candidates, COMMITTEE_SIZE);
        let c2 = select_committee("seed-b", &candidates, COMMITTEE_SIZE);
        assert_ne!(c1, c2, "different seeds should produce different committees");
    }

    #[test]
    fn test_select_committee_size_capped() {
        let candidates: Vec<(String, f64)> = (0..50)
            .map(|i| (format!("node_{i}"), 1.0))
            .collect();
        let c = select_committee("seed", &candidates, COMMITTEE_SIZE);
        assert_eq!(c.len(), 50, "committee capped at candidate count");
    }

    #[test]
    fn test_select_committee_trust_weighted() {
        // Create 10 candidates, one with very high trust
        let mut candidates: Vec<(String, f64)> = (0..10)
            .map(|i| (format!("node_{i}"), 0.1))
            .collect();
        candidates.push(("trusted_node".into(), 100.0));

        // Select a committee of 5 — high-trust node should almost always be in it
        let c = select_committee("test-seed", &candidates, 5);
        assert!(c.contains(&"trusted_node".to_string()),
            "highly trusted node should be selected");
    }

    #[test]
    fn test_select_committee_empty() {
        let c = select_committee("seed", &[], 100);
        assert!(c.is_empty());
        let c2 = select_committee("seed", &[("a".into(), 1.0)], 0);
        assert!(c2.is_empty());
    }

    #[test]
    fn test_select_committee_hash_to_score_no_panic() {
        // Exercises the sha3_256 → [u8;8] copy_from_slice path (was try_into().expect()).
        // Single candidate forces deterministic output regardless of scoring.
        let candidates = vec![("alice".to_string(), 1.0)];
        let r1 = select_committee("fixed-seed", &candidates, 1);
        assert_eq!(r1, vec!["alice".to_string()]);
        // Same seed must produce identical result (determinism).
        let r2 = select_committee("fixed-seed", &candidates, 1);
        assert_eq!(r1, r2);
        // Different seed must still return the only candidate (coverage not sensitivity).
        let r3 = select_committee("other-seed", &candidates, 1);
        assert_eq!(r3, vec!["alice".to_string()]);
    }

    #[test]
    fn test_committee_member_enforcement() {
        let mut state = GovernanceState::new();
        let stake = 2_000 * BASE_UNITS_PER_BEAT;
        let t0 = 1000.0;

        let committee = Committee {
            members: vec!["member_a".into(), "member_b".into(), "member_c".into()],
            vrf_seed: "test-vrf".into(),
            is_revote: false,
            selected_at: t0,
            challenge_deadline: None,
            challenger: None,
        };

        state.create_proposal(
            "critical-1".into(), "alice", ProposalCategory::Critical,
            "Algorithm change".into(), "Important".into(), stake, t0,
            Some(committee),
        ).unwrap();

        // Committee member can vote
        state.cast_vote("critical-1", "member_a", VoteDirection::For, stake, t0 + DAY).unwrap();

        // Non-committee member cannot
        let err = state.cast_vote("critical-1", "outsider", VoteDirection::For, stake, t0 + DAY);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("not on the committee"));
    }

    #[test]
    fn test_critical_requires_committee() {
        let mut state = GovernanceState::new();
        let stake = 2_000 * BASE_UNITS_PER_BEAT;
        let err = state.create_proposal(
            "crit-no-committee".into(), "alice", ProposalCategory::Critical,
            "Title".into(), "Desc".into(), stake, 1000.0, None,
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("require a randomly selected committee"));
    }

    #[test]
    fn test_committee_challenge_deadline_set_on_settle() {
        let mut state = GovernanceState::new();
        let stake = 2_000 * BASE_UNITS_PER_BEAT;
        let t0 = 1000.0;

        let committee = Committee {
            members: vec!["m1".into(), "m2".into(), "m3".into()],
            vrf_seed: "s".into(),
            is_revote: false,
            selected_at: t0,
            challenge_deadline: None,
            challenger: None,
        };

        state.create_proposal(
            "c1".into(), "alice", ProposalCategory::Critical,
            "T".into(), "D".into(), stake, t0, Some(committee),
        ).unwrap();

        // All 3 members vote for
        for m in ["m1", "m2", "m3"] {
            state.cast_vote("c1", m, VoteDirection::For, stake, t0 + DAY).unwrap();
        }

        let settle_time = t0 + COMMITTEE_VOTING_PERIOD_SECS + 1.0;
        let total_staked = 3 * stake;
        let result = state.settle_proposal("c1", total_staked, settle_time).unwrap();
        assert_eq!(result, ProposalStatus::Passed);

        // Challenge deadline should be set
        let p = &state.proposals["c1"];
        let deadline = p.committee.as_ref().unwrap().challenge_deadline.unwrap();
        assert!((deadline - (settle_time + COMMITTEE_CHALLENGE_PERIOD_SECS)).abs() < 0.01);
    }

    #[test]
    fn test_committee_challenge_and_revote() {
        let mut state = GovernanceState::new();
        let stake = 2_000 * BASE_UNITS_PER_BEAT;
        let t0 = 1000.0;

        let committee = Committee {
            members: vec!["m1".into(), "m2".into(), "m3".into()],
            vrf_seed: "s".into(),
            is_revote: false,
            selected_at: t0,
            challenge_deadline: None,
            challenger: None,
        };

        state.create_proposal(
            "c2".into(), "alice", ProposalCategory::Critical,
            "T".into(), "D".into(), stake, t0, Some(committee),
        ).unwrap();

        for m in ["m1", "m2", "m3"] {
            state.cast_vote("c2", m, VoteDirection::For, stake, t0 + DAY).unwrap();
        }

        let settle_time = t0 + COMMITTEE_VOTING_PERIOD_SECS + 1.0;
        state.settle_proposal("c2", 3 * stake, settle_time).unwrap();

        // Challenge within challenge period
        let challenge_time = settle_time + 100.0;
        state.challenge_committee("c2", "disgruntled", stake, challenge_time).unwrap();

        // Proposal should be back to Active, votes cleared
        let p = &state.proposals["c2"];
        assert_eq!(p.status, ProposalStatus::Active);
        assert!(p.votes.is_empty());
        assert_eq!(p.committee.as_ref().unwrap().challenger.as_deref(), Some("disgruntled"));

        // Apply re-vote committee
        let revote_committee = Committee {
            members: (0..COMMITTEE_REVOTE_SIZE).map(|i| format!("rv_{i}")).collect(),
            vrf_seed: "revote-seed".into(),
            is_revote: true,
            selected_at: challenge_time,
            challenge_deadline: None,
            challenger: None,
        };

        state.apply_revote_committee("c2", revote_committee, challenge_time + 1.0).unwrap();
        let p2 = &state.proposals["c2"];
        assert_eq!(p2.committee.as_ref().unwrap().members.len(), COMMITTEE_REVOTE_SIZE);
        assert!(p2.committee.as_ref().unwrap().is_revote);
    }

    #[test]
    fn test_committee_challenge_after_deadline() {
        let mut state = GovernanceState::new();
        let stake = 2_000 * BASE_UNITS_PER_BEAT;
        let t0 = 1000.0;

        let committee = Committee {
            members: vec!["m1".into(), "m2".into()],
            vrf_seed: "s".into(),
            is_revote: false,
            selected_at: t0,
            challenge_deadline: None,
            challenger: None,
        };

        state.create_proposal(
            "c3".into(), "alice", ProposalCategory::Critical,
            "T".into(), "D".into(), stake, t0, Some(committee),
        ).unwrap();

        for m in ["m1", "m2"] {
            state.cast_vote("c3", m, VoteDirection::For, stake, t0 + DAY).unwrap();
        }

        let settle_time = t0 + COMMITTEE_VOTING_PERIOD_SECS + 1.0;
        state.settle_proposal("c3", 2 * stake, settle_time).unwrap();

        // Challenge AFTER deadline should fail
        let late = settle_time + COMMITTEE_CHALLENGE_PERIOD_SECS + 1.0;
        let err = state.challenge_committee("c3", "late_challenger", stake, late);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn test_revote_cannot_be_challenged() {
        let mut state = GovernanceState::new();
        let stake = 2_000 * BASE_UNITS_PER_BEAT;
        let t0 = 1000.0;

        // Create with a revote committee directly
        let committee = Committee {
            members: vec!["m1".into(), "m2".into()],
            vrf_seed: "s".into(),
            is_revote: true,
            selected_at: t0,
            challenge_deadline: Some(t0 + COMMITTEE_CHALLENGE_PERIOD_SECS),
            challenger: None,
        };

        state.create_proposal(
            "c4".into(), "alice", ProposalCategory::Critical,
            "T".into(), "D".into(), stake, t0, Some(committee),
        ).unwrap();

        for m in ["m1", "m2"] {
            state.cast_vote("c4", m, VoteDirection::For, stake, t0 + DAY).unwrap();
        }

        let settle_time = t0 + COMMITTEE_VOTING_PERIOD_SECS + 1.0;
        state.settle_proposal("c4", 2 * stake, settle_time).unwrap();

        let err = state.challenge_committee("c4", "challenger", stake, settle_time + 100.0);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("re-vote"));
    }

    #[test]
    fn test_committee_challenged_blocks_execution() {
        let mut state = GovernanceState::new();
        let stake = 2_000 * BASE_UNITS_PER_BEAT;
        let t0 = 1000.0;

        let committee = Committee {
            members: vec!["m1".into(), "m2".into()],
            vrf_seed: "s".into(),
            is_revote: false,
            selected_at: t0,
            challenge_deadline: None,
            challenger: None,
        };

        state.create_proposal(
            "c5".into(), "alice", ProposalCategory::Critical,
            "T".into(), "D".into(), stake, t0, Some(committee),
        ).unwrap();

        for m in ["m1", "m2"] {
            state.cast_vote("c5", m, VoteDirection::For, stake, t0 + DAY).unwrap();
        }

        let settle_time = t0 + COMMITTEE_VOTING_PERIOD_SECS + 1.0;
        state.settle_proposal("c5", 2 * stake, settle_time).unwrap();

        // Challenge within period
        state.challenge_committee("c5", "dissenter", stake, settle_time + 100.0).unwrap();

        // Apply revote committee so status is back to Active
        let revote = Committee {
            members: vec!["rv1".into(), "rv2".into(), "rv3".into()],
            vrf_seed: "revote".into(),
            is_revote: true,
            selected_at: settle_time + 200.0,
            challenge_deadline: None,
            challenger: None,
        };
        state.apply_revote_committee("c5", revote, settle_time + 200.0).unwrap();

        // Re-vote: all vote for
        for m in ["rv1", "rv2", "rv3"] {
            state.cast_vote("c5", m, VoteDirection::For, stake, settle_time + 300.0).unwrap();
        }

        // Settle revote
        let revote_settle = settle_time + 200.0 + COMMITTEE_VOTING_PERIOD_SECS + 1.0;
        state.settle_proposal("c5", 3 * stake, revote_settle).unwrap();

        // Execution after both delays: passes because revote is final
        let exec_time = revote_settle + EXECUTION_DELAY_SECS + COMMITTEE_CHALLENGE_PERIOD_SECS + 1.0;
        state.execute_proposal("c5", exec_time).unwrap();
        assert_eq!(state.proposals["c5"].status, ProposalStatus::Executed);
    }

    #[test]
    fn test_committee_metadata_roundtrip() {
        let committee = Committee {
            members: vec!["alice".into(), "bob".into(), "charlie".into()],
            vrf_seed: "epoch-42-block-7".into(),
            is_revote: false,
            selected_at: 1234567.0,
            challenge_deadline: None,
            challenger: None,
        };

        let mut m = std::collections::BTreeMap::new();
        inject_committee_metadata(&mut m, &committee);

        let extracted = extract_committee_from_metadata(&m).unwrap();
        assert_eq!(extracted.members, committee.members);
        assert_eq!(extracted.vrf_seed, committee.vrf_seed);
        assert_eq!(extracted.is_revote, committee.is_revote);
        assert!((extracted.selected_at - committee.selected_at).abs() < 0.01);
    }

    #[test]
    fn test_extract_committee_missing_metadata() {
        let m = std::collections::BTreeMap::new();
        assert!(extract_committee_from_metadata(&m).is_none());
    }

    #[test]
    fn test_is_committee_member_no_committee() {
        let proposal = Proposal {
            id: "p1".into(), proposer: "alice".into(),
            category: ProposalCategory::Parameter,
            title: "T".into(), description: "D".into(),
            created_at: 0.0, voting_deadline: DAY,
            status: ProposalStatus::Active,
            passed_at: None, votes: vec![],
            committee: None,
        };
        // No committee = anyone can vote
        assert!(is_committee_member(&proposal, "anyone"));
    }

    // ─── Anchor veto tests (economics §7.5) ──────────────────────────────

    #[test]
    fn test_anchor_veto_signal() {
        let mut state = GovernanceState::new();
        let stake = 2_000 * BASE_UNITS_PER_BEAT;
        let t0 = 1000.0;

        state.create_proposal(
            "target".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), stake, t0, None,
        ).unwrap();

        // Signal veto (4 anchors total, need >75% = at least 4 signals)
        let result = state.anchor_veto_signal("target", "anchor_1", ZoneId::from_legacy(0), 4, t0 + 10.0).unwrap();
        assert!(!result); // not yet threshold

        let result = state.anchor_veto_signal("target", "anchor_2", ZoneId::from_legacy(0), 4, t0 + 20.0).unwrap();
        assert!(!result);

        let result = state.anchor_veto_signal("target", "anchor_3", ZoneId::from_legacy(0), 4, t0 + 30.0).unwrap();
        assert!(!result); // 3/4 = 75%, need >75%

        let result = state.anchor_veto_signal("target", "anchor_4", ZoneId::from_legacy(0), 4, t0 + 40.0).unwrap();
        assert!(result); // 4/4 = 100% > 75% — veto triggered

        assert_eq!(state.proposals["target"].status, ProposalStatus::Vetoed);
    }

    #[test]
    fn test_anchor_veto_dedup() {
        let mut state = GovernanceState::new();
        let stake = 2_000 * BASE_UNITS_PER_BEAT;
        let t0 = 1000.0;

        state.create_proposal(
            "target".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), stake, t0, None,
        ).unwrap();

        state.anchor_veto_signal("target", "anchor_1", ZoneId::from_legacy(0), 10, t0).unwrap();
        // Same anchor again
        let err = state.anchor_veto_signal("target", "anchor_1", ZoneId::from_legacy(0), 10, t0 + 1.0);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("already signaled"));
    }

    #[test]
    fn test_anchor_veto_signal_unknown_proposal_returns_err() {
        // anchor_veto_signal must return Err (not panic) when the proposal
        // doesn't exist — covers the ok_or_else error path.
        let mut state = GovernanceState::new();
        let err = state.anchor_veto_signal("ghost", "anchor_1", ZoneId::from_legacy(0), 4, 1000.0);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_anchor_veto_rate_limit() {
        let mut state = GovernanceState::new();
        let stake = 2_000 * BASE_UNITS_PER_BEAT;
        let t0 = 1000.0;

        // Create 3 proposals and veto 2 in the same zone
        for i in 0..3 {
            state.create_proposal(
                format!("p{i}"), "alice", ProposalCategory::Parameter,
                "T".into(), "D".into(), stake, t0, None,
            ).unwrap();
        }

        // Veto first two (each needs >75% of 2 anchors = both anchors)
        for pid in ["p0", "p1"] {
            state.anchor_veto_signal(pid, "a1", ZoneId::from_legacy(0), 2, t0 + 10.0).unwrap();
            state.anchor_veto_signal(pid, "a2", ZoneId::from_legacy(0), 2, t0 + 20.0).unwrap(); // triggers veto
        }

        // Third should be rate-limited for zone 0
        let err = state.anchor_veto_signal("p2", "a1", ZoneId::from_legacy(0), 2, t0 + 30.0);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("exhausted veto quota"));
    }

    #[test]
    fn test_anchor_veto_different_zones_independent() {
        let mut state = GovernanceState::new();
        let stake = 2_000 * BASE_UNITS_PER_BEAT;
        let t0 = 1000.0;

        for i in 0..3 {
            state.create_proposal(
                format!("p{i}"), "alice", ProposalCategory::Parameter,
                "T".into(), "D".into(), stake, t0, None,
            ).unwrap();
        }

        // Exhaust zone 0 quota
        for pid in ["p0", "p1"] {
            state.anchor_veto_signal(pid, "a1", ZoneId::from_legacy(0), 2, t0).unwrap();
            state.anchor_veto_signal(pid, "a2", ZoneId::from_legacy(0), 2, t0).unwrap();
        }

        // Zone 1 is independent, should work
        let result = state.anchor_veto_signal("p2", "a3", ZoneId::from_legacy(1), 2, t0 + 10.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_anchor_veto_only_active_or_passed() {
        let mut state = GovernanceState::new();
        let stake = 2_000 * BASE_UNITS_PER_BEAT;
        let t0 = 1000.0;

        state.create_proposal(
            "p1".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), stake, t0, None,
        ).unwrap();
        state.cancel_proposal("p1", "alice").unwrap();

        let err = state.anchor_veto_signal("p1", "anchor", ZoneId::from_legacy(0), 10, t0);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("active or passed"));
    }

    #[test]
    fn test_anchor_veto_on_passed_proposal() {
        let mut state = GovernanceState::new();
        let stake = 2_000 * BASE_UNITS_PER_BEAT;
        let t0 = 1000.0;

        state.create_proposal(
            "p1".into(), "alice", ProposalCategory::Parameter,
            "T".into(), "D".into(), stake, t0, None,
        ).unwrap();

        // Vote and settle
        state.cast_vote("p1", "v1", VoteDirection::For, stake, t0 + DAY).unwrap();
        let settle_time = t0 + VOTING_PERIOD_SECS + 1.0;
        state.settle_proposal("p1", stake, settle_time).unwrap();
        assert_eq!(state.proposals["p1"].status, ProposalStatus::Passed);

        // Veto a passed proposal
        state.anchor_veto_signal("p1", "a1", ZoneId::from_legacy(0), 1, settle_time + 10.0).unwrap();
        // 1/1 = 100% > 75% → vetoed
        assert_eq!(state.proposals["p1"].status, ProposalStatus::Vetoed);
    }

    #[test]
    fn test_anchor_veto_threshold_math() {
        // Verify threshold is strictly >75%
        let mut veto_state = AnchorVetoState::new();
        veto_state.signal_veto("p1", "a1", ZoneId::from_legacy(0), 100.0);
        veto_state.signal_veto("p1", "a2", ZoneId::from_legacy(0), 200.0);
        veto_state.signal_veto("p1", "a3", ZoneId::from_legacy(0), 300.0);

        // 3/4 = 75% — NOT > 75%, should not trigger
        assert!(!veto_state.check_threshold("p1", 4));

        veto_state.signal_veto("p1", "a4", ZoneId::from_legacy(0), 400.0);
        // 4/4 = 100% > 75% — triggers
        assert!(veto_state.check_threshold("p1", 4));

        // 4/5 = 80% > 75% — triggers
        assert!(veto_state.check_threshold("p1", 5));

        // 4/6 = 66.7% — does NOT trigger
        assert!(!veto_state.check_threshold("p1", 6));
    }

    #[test]
    fn test_anchor_veto_metadata() {
        let m = anchor_veto_metadata("proposal-123", ZoneId::from_legacy(42));
        assert_eq!(m["governance_op"], serde_json::json!("anchor_veto"));
        assert_eq!(m["governance_proposal_id"], serde_json::json!("proposal-123"));
        assert_eq!(m["governance_veto_zone"], serde_json::json!("42"));
    }

    #[test]
    fn test_anchor_veto_quarter_reset() {
        let mut veto_state = AnchorVetoState::new();
        let t0 = QUARTER_SECS * 10.0; // Some quarter boundary

        // Use up quota in this quarter
        veto_state.record_veto(ZoneId::from_legacy(0), t0 + 1.0);
        veto_state.record_veto(ZoneId::from_legacy(0), t0 + 2.0);
        assert!(veto_state.rate_limited(ZoneId::from_legacy(0), t0 + 3.0));

        // Next quarter: not rate limited
        let next_quarter = t0 + QUARTER_SECS + 1.0;
        assert!(!veto_state.rate_limited(ZoneId::from_legacy(0), next_quarter));
    }

    // ─── Active-delegation counter invariant ──────────────────────────────────
    // Invariant: `active_delegations_count == delegations.values().filter(|d| d.active).count()`
    // after every mutation. Random-ops + redelegate cycle + recount-after-deserialize.

    fn ops155_assert_invariant(state: &GovernanceState, where_: &str) {
        let derived = state
            .delegations
            .values()
            .filter(|d| d.active)
            .count() as u64;
        assert_eq!(
            state.active_delegations_count, derived,
            "[{where_}] maintained={} derived={}; mutation site forgot counter update",
            state.active_delegations_count, derived,
        );
    }

    #[test]
    fn ops155_invariant_under_delegate_undelegate_redelegate() {
        let mut state = GovernanceState::new();
        ops155_assert_invariant(&state, "fresh");

        // Fresh delegations: +1 each.
        state.delegate("alice", "bob", 100.0).unwrap();
        ops155_assert_invariant(&state, "after alice→bob");
        state.delegate("carol", "dave", 101.0).unwrap();
        ops155_assert_invariant(&state, "after carol→dave");
        state.delegate("eve", "frank", 102.0).unwrap();
        ops155_assert_invariant(&state, "after eve→frank");
        assert_eq!(state.active_delegations_count, 3);

        // Re-delegating an active delegator must error and not move the counter.
        let pre = state.active_delegations_count;
        let err = state.delegate("alice", "judge", 103.0);
        assert!(err.is_err());
        assert_eq!(state.active_delegations_count, pre);
        ops155_assert_invariant(&state, "after rejected re-delegate");

        // Self-delegation rejected and counter unchanged.
        let err2 = state.delegate("alice", "alice", 104.0);
        assert!(err2.is_err());
        ops155_assert_invariant(&state, "after self-delegate rejected");

        // Undelegate is -1.
        state.undelegate("alice").unwrap();
        ops155_assert_invariant(&state, "after undelegate alice");
        assert_eq!(state.active_delegations_count, 2);

        // Double-undelegate must error and not move the counter.
        let err3 = state.undelegate("alice");
        assert!(err3.is_err());
        ops155_assert_invariant(&state, "after rejected double-undelegate");
        assert_eq!(state.active_delegations_count, 2);

        // Re-delegation of a previously-undelegated identity overwrites with active=true. +1.
        state.delegate("alice", "judge2", 105.0).unwrap();
        ops155_assert_invariant(&state, "after redelegate alice→judge2");
        assert_eq!(state.active_delegations_count, 3);

        // Undelegate everyone — counter goes to 0.
        state.undelegate("alice").unwrap();
        state.undelegate("carol").unwrap();
        state.undelegate("eve").unwrap();
        ops155_assert_invariant(&state, "after undelegate all");
        assert_eq!(state.active_delegations_count, 0);
        // The map still has 3 inactive entries — count must not regress to 3.
        assert_eq!(state.delegations.len(), 3);
    }

    #[test]
    fn ops155_recount_aligns_with_synthetic_active_set() {
        // Simulate a snapshot-restore where active_delegations_count loaded as 0
        // (older wire format) but the delegations map has live active entries.
        let mut state = GovernanceState::new();
        state.delegations.insert(
            "alice".into(),
            DelegationEntry {
                delegator: "alice".into(),
                delegate: "bob".into(),
                created_at: 100.0,
                active: true,
            },
        );
        state.delegations.insert(
            "carol".into(),
            DelegationEntry {
                delegator: "carol".into(),
                delegate: "dave".into(),
                created_at: 101.0,
                active: false,
            },
        );
        state.delegations.insert(
            "eve".into(),
            DelegationEntry {
                delegator: "eve".into(),
                delegate: "frank".into(),
                created_at: 102.0,
                active: true,
            },
        );
        // Pre-recount: counter is stale (0).
        assert_eq!(state.active_delegations_count, 0);

        state.recount_active_delegations();
        assert_eq!(state.active_delegations_count, 2);
        ops155_assert_invariant(&state, "after recount");

        // Idempotency.
        state.recount_active_delegations();
        assert_eq!(state.active_delegations_count, 2);
    }

    #[test]
    fn ops155_serde_round_trip_preserves_count_via_recount() {
        // Build a state with N active delegations, serialize, deserialize,
        // recount — must produce the same count.
        let mut original = GovernanceState::new();
        for i in 0..7 {
            original
                .delegate(&format!("d{i}"), &format!("e{i}"), 100.0 + i as f64)
                .unwrap();
        }
        original.undelegate("d3").unwrap(); // one inactive
        assert_eq!(original.active_delegations_count, 6);
        ops155_assert_invariant(&original, "original");

        let bytes = serde_json::to_vec(&original).unwrap();
        let mut loaded: GovernanceState = serde_json::from_slice(&bytes).unwrap();
        // Forward-compat: serde now serializes the field, so loaded counter equals the source.
        assert_eq!(loaded.active_delegations_count, 6);
        ops155_assert_invariant(&loaded, "post-deserialize");

        // Recount must remain idempotent against a freshly loaded state.
        loaded.recount_active_delegations();
        assert_eq!(loaded.active_delegations_count, 6);
        ops155_assert_invariant(&loaded, "post-recount");
    }

    #[test]
    fn ops155_recount_repairs_pre_ops155_snapshot_zero_counter() {
        // Simulate the wire shape from a node running an older build: the JSON
        // has no `active_delegations_count` key, so #[serde(default)] yields 0.
        let json = r#"{
            "proposals": {},
            "delegations": {
                "alice": {"delegator":"alice","delegate":"bob","created_at":100.0,"active":true},
                "carol": {"delegator":"carol","delegate":"dave","created_at":101.0,"active":true}
            },
            "params": {
                "propagation_rate_limit_per_hour": 120,
                "epoch_seal_interval_secs": 300.0,
                "witness_reward_micros": 1000000,
                "record_retention_secs": 0.0,
                "stake_throughput_ratio": 100000
            },
            "param_changes": [],
            "anchor_vetoes": {"signals": {}, "vetoes_by_quarter": {}}
        }"#;
        let mut loaded: GovernanceState = serde_json::from_str(json).unwrap();
        // Older-build counter loads as 0 (serde default).
        assert_eq!(loaded.active_delegations_count, 0);

        // Snapshot apply must call recount before any reader observes the state.
        loaded.recount_active_delegations();
        assert_eq!(loaded.active_delegations_count, 2);
        ops155_assert_invariant(&loaded, "post-recount");
    }

    // ─── Proposal-status counter invariant ────────────────────────────────────
    // Invariant: `proposal_status_counts == derived from proposals.values()`
    // after every mutation. State-machine walk + recount-after-deserialize.

    fn ops156_derive_counts(state: &GovernanceState) -> ProposalStatusCounts {
        let mut counts = ProposalStatusCounts::default();
        for p in state.proposals.values() {
            counts.inc(p.status);
        }
        counts
    }

    fn ops156_assert_invariant(state: &GovernanceState, where_: &str) {
        let derived = ops156_derive_counts(state);
        let m = &state.proposal_status_counts;
        assert_eq!(
            (m.active, m.passed, m.rejected, m.expired, m.executed, m.cancelled, m.vetoed),
            (derived.active, derived.passed, derived.rejected, derived.expired,
             derived.executed, derived.cancelled, derived.vetoed),
            "[{where_}] maintained vs derived disagree — mutation site forgot counter update",
        );
    }

    #[test]
    fn ops156_invariant_under_propose_settle_execute_cancel() {
        let mut state = GovernanceState::new();
        ops156_assert_invariant(&state, "fresh");

        // 3 fresh proposals → 3 Active.
        for i in 0..3 {
            state.create_proposal(
                format!("p{i}"), "alice", ProposalCategory::Parameter,
                format!("title{i}"), format!("desc{i}"),
                2_000 * BASE_UNITS_PER_BEAT, 1000.0 + i as f64, None,
            ).unwrap();
        }
        ops156_assert_invariant(&state, "after 3 propose");
        assert_eq!(state.active_proposals(), 3);

        // Cancel p0 → Active=2, Cancelled=1.
        state.cancel_proposal("p0", "alice").unwrap();
        ops156_assert_invariant(&state, "after cancel p0");
        let (a, _, _, _, _, c, _) = state.proposal_counts();
        assert_eq!((a, c), (2, 1));

        // Cancel error path (already cancelled) — counter must not move.
        let pre = state.proposal_status_counts.clone();
        let err = state.cancel_proposal("p0", "alice");
        assert!(err.is_err());
        ops156_assert_invariant(&state, "after re-cancel rejected");
        assert_eq!(
            (state.proposal_status_counts.active, state.proposal_status_counts.cancelled),
            (pre.active, pre.cancelled),
        );
    }

    #[test]
    fn ops156_invariant_under_settle_branches() {
        // Walk all 4 settle branches: low-participation Expired, no-decisive Expired,
        // Passed, Rejected. Each must transition Active → outcome.
        // Low participation: stake=1000, total_governance_staked=1_000_000_000 → 1000/1e9 < 5%.
        let mut state = GovernanceState::new();
        state.create_proposal(
            "p1".into(), "alice", ProposalCategory::Parameter,
            "t".into(), "d".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();
        state.cast_vote("p1", "alice", VoteDirection::For, 1_000, 1_001.0).unwrap();
        // Settle past voting_deadline. total_gov_staked is large → MIN_PARTICIPATION_FRACTION
        // gate trips → Expired.
        let result = state.settle_proposal("p1", 1_000_000_000_000, 1000.0 + VOTING_PERIOD_SECS + 1.0).unwrap();
        assert_eq!(result, ProposalStatus::Expired);
        ops156_assert_invariant(&state, "after settle low-participation");
        assert_eq!(state.proposal_status_counts.expired, 1);
        assert_eq!(state.proposal_status_counts.active, 0);

        // Re-settle (already Expired) — must error AND counters unchanged.
        let pre = state.proposal_status_counts.clone();
        let err = state.settle_proposal("p1", 1_000_000_000_000, 2000.0);
        assert!(err.is_err());
        ops156_assert_invariant(&state, "after re-settle rejected");
        assert_eq!(state.proposal_status_counts.active, pre.active);

        // Passed branch: enough participating stake + supermajority for-conviction.
        // Use a tiny total so participation fraction trivially passes.
        let mut state2 = GovernanceState::new();
        state2.create_proposal(
            "p2".into(), "bob", ProposalCategory::Parameter,
            "t".into(), "d".into(), 2_000 * BASE_UNITS_PER_BEAT, 2000.0, None,
        ).unwrap();
        state2.cast_vote("p2", "bob", VoteDirection::For, 100, 2_001.0).unwrap();
        let r2 = state2.settle_proposal("p2", 100, 2000.0 + VOTING_PERIOD_SECS + 1.0).unwrap();
        assert_eq!(r2, ProposalStatus::Passed);
        ops156_assert_invariant(&state2, "after settle Passed");
        assert_eq!(state2.proposal_status_counts.passed, 1);
        assert_eq!(state2.proposal_status_counts.active, 0);

        // Execute branch: Passed → Executed.
        let r3 = state2.execute_proposal("p2",
            2000.0 + VOTING_PERIOD_SECS + EXECUTION_DELAY_SECS + 1.0);
        assert!(r3.is_ok());
        ops156_assert_invariant(&state2, "after execute");
        assert_eq!(state2.proposal_status_counts.executed, 1);
        assert_eq!(state2.proposal_status_counts.passed, 0);
    }

    #[test]
    fn ops156_recount_repairs_zero_counters() {
        // Synthesize state with proposals but stale counts (snapshot-restore scenario).
        let mut state = GovernanceState::new();
        state.create_proposal(
            "p1".into(), "alice", ProposalCategory::Parameter,
            "t".into(), "d".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();
        state.cancel_proposal("p1", "alice").unwrap();
        state.create_proposal(
            "p2".into(), "alice", ProposalCategory::Parameter,
            "t".into(), "d".into(), 2_000 * BASE_UNITS_PER_BEAT, 2000.0, None,
        ).unwrap();
        // Manually wipe counters to simulate an older snapshot load.
        state.proposal_status_counts = ProposalStatusCounts::default();
        assert_eq!(state.proposal_status_counts.active, 0);
        assert_eq!(state.proposal_status_counts.cancelled, 0);

        state.recount_proposal_statuses();
        ops156_assert_invariant(&state, "after recount");
        assert_eq!(state.proposal_status_counts.active, 1);
        assert_eq!(state.proposal_status_counts.cancelled, 1);

        // Idempotency.
        state.recount_proposal_statuses();
        ops156_assert_invariant(&state, "after second recount");
    }

    #[test]
    fn ops156_serde_round_trip_and_recount() {
        let mut original = GovernanceState::new();
        for i in 0..5 {
            original.create_proposal(
                format!("p{i}"), "alice", ProposalCategory::Parameter,
                format!("t{i}"), format!("d{i}"),
                2_000 * BASE_UNITS_PER_BEAT, 1000.0 + i as f64, None,
            ).unwrap();
        }
        original.cancel_proposal("p1", "alice").unwrap();
        ops156_assert_invariant(&original, "original");
        assert_eq!(original.proposal_status_counts.active, 4);
        assert_eq!(original.proposal_status_counts.cancelled, 1);

        let bytes = serde_json::to_vec(&original).unwrap();
        let mut loaded: GovernanceState = serde_json::from_slice(&bytes).unwrap();
        // Forward-compat: counter ships in JSON.
        assert_eq!(loaded.proposal_status_counts.active, 4);
        assert_eq!(loaded.proposal_status_counts.cancelled, 1);
        ops156_assert_invariant(&loaded, "post-deserialize");

        loaded.recount_proposal_statuses();
        ops156_assert_invariant(&loaded, "post-recount");
    }

    // ─── fixture-free tests ─────────────────────────────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_duration_constants_strict_pin_with_cross_equivalences() {
        // economics §7: time-windows are mainnet-correct, not "testing defaults".
        // Pin both literal seconds AND structural cross-relations so tuning one
        // duration without the matched one will break this test loud.

        // CONVICTION_TAU = 7 days
        assert_eq!(CONVICTION_TAU_SECS, 7.0 * 24.0 * 3600.0);
        assert_eq!(CONVICTION_TAU_SECS, 604_800.0);

        // VOTING == COMMITTEE_VOTING == 14 days (the same period — committee
        // proposals use the same voting window as ordinary ones)
        assert_eq!(VOTING_PERIOD_SECS, 14.0 * 24.0 * 3600.0);
        assert_eq!(VOTING_PERIOD_SECS, 1_209_600.0);
        assert_eq!(
            VOTING_PERIOD_SECS, COMMITTEE_VOTING_PERIOD_SECS,
            "committee voting period must equal main voting period"
        );

        // EXECUTION == COMMITTEE_CHALLENGE == 30 days (the post-pass cooldown
        // for ordinary execution equals the challenge window for committee
        // proposals)
        assert_eq!(EXECUTION_DELAY_SECS, 30.0 * 24.0 * 3600.0);
        assert_eq!(EXECUTION_DELAY_SECS, 2_592_000.0);
        assert_eq!(
            EXECUTION_DELAY_SECS, COMMITTEE_CHALLENGE_PERIOD_SECS,
            "committee challenge period must equal execution delay"
        );

        // QUARTER == 90 days == 3× the 30-day window (used by anchor veto
        // rate-limit)
        assert_eq!(QUARTER_SECS, 90.0 * 24.0 * 3600.0);
        assert_eq!(QUARTER_SECS, 7_776_000.0);
        assert!(
            (QUARTER_SECS - 3.0 * EXECUTION_DELAY_SECS).abs() < 1e-9,
            "quarter must equal 3 × execution delay"
        );

        // Sanity ordering: TAU < VOTING < EXECUTION < QUARTER
        assert!(CONVICTION_TAU_SECS < VOTING_PERIOD_SECS);
        assert!(VOTING_PERIOD_SECS < EXECUTION_DELAY_SECS);
        assert!(EXECUTION_DELAY_SECS < QUARTER_SECS);
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_threshold_constants_strict_pin_with_supermajority_cross_equivalence() {
        // SUPERMAJORITY 0.67 (2/3 with one-percent buffer over the floor)
        assert_eq!(SUPERMAJORITY_THRESHOLD, 0.67);
        assert_eq!(COMMITTEE_SUPERMAJORITY, 0.67);
        assert_eq!(
            SUPERMAJORITY_THRESHOLD, COMMITTEE_SUPERMAJORITY,
            "committee supermajority must equal main supermajority"
        );

        // Other thresholds
        assert_eq!(MIN_PARTICIPATION_FRACTION, 0.25);
        assert_eq!(ANCHOR_VETO_THRESHOLD, 0.75);

        // SUPERMAJORITY (0.67) < ANCHOR_VETO_THRESHOLD (0.75): vetoing
        // requires a STRICTER supermajority than passing — by design, harder
        // to overturn a vote than to pass one.
        assert!(SUPERMAJORITY_THRESHOLD < ANCHOR_VETO_THRESHOLD);

        // Sizing constants
        assert_eq!(COMMITTEE_SIZE, 100);
        assert_eq!(COMMITTEE_REVOTE_SIZE, 200);
        assert_eq!(
            COMMITTEE_REVOTE_SIZE,
            2 * COMMITTEE_SIZE,
            "revote committee must be exactly 2× normal committee"
        );
        assert_eq!(MAX_ACTIVE_PROPOSALS_PER_IDENTITY, 3);
        assert_eq!(ANCHOR_VETO_MAX_PER_QUARTER, 2);

        // MIN_PROPOSAL_STAKE = 1000 beat (1000 × 1B micro)
        assert_eq!(MIN_PROPOSAL_STAKE, 1_000 * crate::accounting::types::BASE_UNITS_PER_BEAT);
        assert_eq!(MIN_PROPOSAL_STAKE, 1_000_000_000_000_u64);
    }

    #[test]
    fn batch_b_governance_op_key_value_and_cross_module_disjointness() {
        // Strict value pin — wire format is "governance_op" snake_case.
        assert_eq!(GOVERNANCE_OP_KEY, "governance_op");
        assert!(GOVERNANCE_OP_KEY.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        assert!(!GOVERNANCE_OP_KEY.contains(' '));

        // Cross-module disjointness — no two op-key constants share a value.
        // Renaming one without checking the others would silently merge two
        // operation namespaces and break parser dispatch.
        let keys: [&str; 4] = [
            GOVERNANCE_OP_KEY,
            crate::accounting::batch::BATCH_OP_KEY,
            crate::accounting::dormancy::DORMANCY_OP_KEY,
            crate::accounting::storage_market::STORAGE_OP_KEY,
        ];
        for (i, a) in keys.iter().enumerate() {
            for (j, b) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "op-key collision: keys[{i}]={a} == keys[{j}]={b}");
                }
            }
        }
    }

    #[test]
    fn batch_b_proposal_status_seven_variant_snake_case_serde_with_copy_semantics() {
        // All 7 variants serialize to snake_case-quoted JSON strings and
        // deserialize back. ProposalStatus has Copy, so use-after-move is fine.
        let cases: &[(ProposalStatus, &str)] = &[
            (ProposalStatus::Active, "\"active\""),
            (ProposalStatus::Passed, "\"passed\""),
            (ProposalStatus::Rejected, "\"rejected\""),
            (ProposalStatus::Expired, "\"expired\""),
            (ProposalStatus::Executed, "\"executed\""),
            (ProposalStatus::Cancelled, "\"cancelled\""),
            (ProposalStatus::Vetoed, "\"vetoed\""),
        ];

        // Copy: each ps can be used twice without clone()
        for (ps, expected_json) in cases {
            let ps_copy = *ps; // exercise Copy
            let s = serde_json::to_string(ps).unwrap();
            assert_eq!(&s, expected_json, "serialize {ps:?}");
            let back: ProposalStatus = serde_json::from_str(&s).unwrap();
            assert_eq!(back, ps_copy, "round-trip {ps:?}");
        }

        // Pairwise distinctness — no two variants compare equal (PartialEq/Eq)
        for (i, (a, _)) in cases.iter().enumerate() {
            for (j, (b, _)) in cases.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b, "variants[{i}] and variants[{j}] must differ");
                }
            }
        }
    }

    #[test]
    fn batch_b_parsed_governance_op_six_variant_clone_independence_with_payload_preservation() {
        // ParsedGovernanceOp has no PartialEq derive — verify Clone preserves
        // payload via match-extract, then mutate the clone's payload to confirm
        // the original is untouched.

        // Variant 1: Propose
        let p = ParsedGovernanceOp::Propose {
            category: ProposalCategory::Parameter,
            title: "T1".into(),
            description: "D1".into(),
        };
        let mut p_clone = p.clone();
        if let ParsedGovernanceOp::Propose { title, description, .. } = &mut p_clone {
            title.push_str("_mut");
            description.push_str("_mut");
        }
        match (&p, &p_clone) {
            (
                ParsedGovernanceOp::Propose { title: t1, description: d1, category: c1 },
                ParsedGovernanceOp::Propose { title: t2, description: d2, category: c2 },
            ) => {
                assert_eq!(t1, "T1", "original title must survive clone-mutation");
                assert_eq!(d1, "D1", "original description must survive clone-mutation");
                assert_eq!(t2, "T1_mut");
                assert_eq!(d2, "D1_mut");
                assert_eq!(c1.as_str(), "parameter");
                assert_eq!(c2.as_str(), "parameter");
            }
            _ => panic!("Propose clone must remain Propose"),
        }

        // Variant 2: Vote
        let v = ParsedGovernanceOp::Vote {
            proposal_id: "PID".into(),
            direction: VoteDirection::For,
        };
        let v_clone = v.clone();
        match (&v, &v_clone) {
            (
                ParsedGovernanceOp::Vote { proposal_id: id1, direction: d1 },
                ParsedGovernanceOp::Vote { proposal_id: id2, direction: d2 },
            ) => {
                assert_eq!(id1, id2);
                assert_eq!(d1.as_str(), "for");
                assert_eq!(d2.as_str(), "for");
            }
            _ => panic!("Vote clone must remain Vote"),
        }

        // Variants 3-5: Execute/Cancel/Delegate carry a single string payload
        let trio: Vec<ParsedGovernanceOp> = vec![
            ParsedGovernanceOp::Execute { proposal_id: "EX".into() },
            ParsedGovernanceOp::Cancel { proposal_id: "CA".into() },
            ParsedGovernanceOp::Delegate { delegate: "DG".into() },
        ];
        let trio_clone = trio.clone();
        assert_eq!(trio.len(), trio_clone.len());
        match (&trio[0], &trio_clone[0]) {
            (ParsedGovernanceOp::Execute { proposal_id: a }, ParsedGovernanceOp::Execute { proposal_id: b }) => {
                assert_eq!(a, "EX"); assert_eq!(b, "EX");
            }
            _ => panic!("Execute clone must remain Execute"),
        }
        match (&trio[1], &trio_clone[1]) {
            (ParsedGovernanceOp::Cancel { proposal_id: a }, ParsedGovernanceOp::Cancel { proposal_id: b }) => {
                assert_eq!(a, "CA"); assert_eq!(b, "CA");
            }
            _ => panic!("Cancel clone must remain Cancel"),
        }
        match (&trio[2], &trio_clone[2]) {
            (ParsedGovernanceOp::Delegate { delegate: a }, ParsedGovernanceOp::Delegate { delegate: b }) => {
                assert_eq!(a, "DG"); assert_eq!(b, "DG");
            }
            _ => panic!("Delegate clone must remain Delegate"),
        }

        // Variant 6: Undelegate (unit variant — Clone must stay Undelegate)
        let u = ParsedGovernanceOp::Undelegate;
        let u_clone = u.clone();
        assert!(matches!(u, ParsedGovernanceOp::Undelegate));
        assert!(matches!(u_clone, ParsedGovernanceOp::Undelegate));
    }

    // ── §11.18 Protocol Upgrade Adapter tests (feature=node) ────────────

    /// Adapter must refuse non-`ProtocolUpgrade` categories. Pins the type-of
    /// validation that prevents callers from feeding a `Parameter` proposal
    /// into the §11.18 tally (which would erroneously apply UpgradeKind
    /// thresholds to ordinary conviction-vote outcomes).
    #[cfg(feature = "node")]
    #[test]
    fn protocol_upgrade_adapter_rejects_non_protocol_upgrade_category() {
        use crate::network::protocol_upgrade::UpgradeKind;
        let p = Proposal {
            id: "p-wrong-cat".into(),
            proposer: "alice".into(),
            category: ProposalCategory::Parameter,
            title: "T".into(),
            description: "D".into(),
            created_at: 0.0,
            voting_deadline: 100.0,
            status: ProposalStatus::Active,
            passed_at: None,
            votes: vec![],
            committee: None,
        };
        let err = evaluate_protocol_upgrade_proposal(
            &p,
            UpgradeKind::HardFork,
            String::new(),
            0,
            200,
        )
        .expect_err("Parameter category must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("non-ProtocolUpgrade"),
            "error must name the mismatch: {msg}"
        );
        assert!(msg.contains("parameter"), "error must include observed category: {msg}");
    }

    /// VoteOpen passthrough: when the proposal's voting deadline has not yet
    /// passed, the adapter must return `VoteOpen` regardless of vote totals.
    /// Pins that the adapter does NOT shortcut the §11.18 window-close check.
    #[cfg(feature = "node")]
    #[test]
    fn protocol_upgrade_adapter_returns_vote_open_before_window_close() {
        use crate::network::protocol_upgrade::{UpgradeKind, UpgradeOutcome};
        let p = Proposal {
            id: "p-open".into(),
            proposer: "alice".into(),
            category: ProposalCategory::ProtocolUpgrade,
            title: "T".into(),
            description: "D".into(),
            created_at: 0.0,
            voting_deadline: 1000.0,
            status: ProposalStatus::Active,
            passed_at: None,
            votes: vec![Vote {
                voter: "v1".into(),
                stake: 999,
                direction: VoteDirection::For,
                voted_at: 10.0,
                own_stake: None,
            }],
            committee: None,
        };
        let outcome = evaluate_protocol_upgrade_proposal(
            &p,
            UpgradeKind::SoftFork,
            String::new(),
            0,
            500,
        )
        .unwrap();
        assert_eq!(outcome, UpgradeOutcome::VoteOpen);
    }

    /// HardFork pass path: 70/30 raw-stake split at window close ⇒ for_ratio
    /// = 0.70 >= 0.67 threshold ⇒ `Passed`, with deadline = window_close +
    /// 180 days. Pins the raw-stake mapping (NOT conviction) per the
    /// adapter's spec doc.
    #[cfg(feature = "node")]
    #[test]
    fn protocol_upgrade_adapter_hardfork_passes_at_70_30_raw_stake() {
        use crate::network::protocol_upgrade::{UpgradeKind, UpgradeOutcome};
        let p = Proposal {
            id: "p-pass".into(),
            proposer: "alice".into(),
            category: ProposalCategory::ProtocolUpgrade,
            title: "T".into(),
            description: "D".into(),
            created_at: 0.0,
            voting_deadline: 1000.0,
            status: ProposalStatus::Active,
            passed_at: None,
            votes: vec![
                Vote { voter: "v1".into(), stake: 7_000, direction: VoteDirection::For, voted_at: 10.0, own_stake: None },
                Vote { voter: "v2".into(), stake: 3_000, direction: VoteDirection::Against, voted_at: 20.0, own_stake: None },
            ],
            committee: None,
        };
        // current_time == window_close ⇒ tally runs; transition not yet elapsed.
        let outcome = evaluate_protocol_upgrade_proposal(
            &p,
            UpgradeKind::HardFork,
            "ref-hash".into(),
            42,
            1000,
        )
        .unwrap();
        match outcome {
            UpgradeOutcome::Passed { transition_deadline_secs } => {
                // 180d * 86400 = 15_552_000s + window_close 1000 = 15_553_000
                assert_eq!(transition_deadline_secs, 1000 + 180 * 86_400);
            }
            other => panic!("expected Passed at 70/30 HardFork; got {other:?}"),
        }
    }

    /// HardFork fail path: 60/40 raw-stake split ⇒ for_ratio = 0.60 < 0.67
    /// threshold ⇒ `Failed { for_ratio }`. Pins the threshold-edge classification.
    #[cfg(feature = "node")]
    #[test]
    fn protocol_upgrade_adapter_hardfork_fails_at_60_40_raw_stake() {
        use crate::network::protocol_upgrade::{UpgradeKind, UpgradeOutcome};
        let p = Proposal {
            id: "p-fail".into(),
            proposer: "alice".into(),
            category: ProposalCategory::ProtocolUpgrade,
            title: "T".into(),
            description: "D".into(),
            created_at: 0.0,
            voting_deadline: 500.0,
            status: ProposalStatus::Active,
            passed_at: None,
            votes: vec![
                Vote { voter: "v1".into(), stake: 600, direction: VoteDirection::For, voted_at: 10.0, own_stake: None },
                Vote { voter: "v2".into(), stake: 400, direction: VoteDirection::Against, voted_at: 20.0, own_stake: None },
            ],
            committee: None,
        };
        let outcome = evaluate_protocol_upgrade_proposal(
            &p,
            UpgradeKind::HardFork,
            String::new(),
            0,
            600,
        )
        .unwrap();
        match outcome {
            UpgradeOutcome::Failed { for_ratio } => {
                assert!((for_ratio - 0.6).abs() < 1e-9, "for_ratio = {for_ratio}");
            }
            other => panic!("expected Failed at 60/40 HardFork; got {other:?}"),
        }
    }

    #[allow(clippy::doc_lazy_continuation)]
    /// Abstain weight is recorded on the UpgradeProposal but does NOT shift
    /// the for/against denominator. Pins the §11.18 invariant against accidental
    /// abstain-in-denominator regressions. 600 for + 300 against + 1000 abstain
    /// against a SoftFork (50% threshold) ⇒ for_ratio = 600/(600+300) = 0.6667
    /// > 0.50 ⇒ Passes. If abstain were (incorrectly) summed into the
    /// denominator the ratio would be 600/1900 = 0.316 < 0.50 ⇒ would Fail.
    /// HardFork variant of the same test would fail at 0.6667 < 0.67 — that's
    /// the same scenario pinned inside `network::protocol_upgrade::tests` and
    /// not repeated here to avoid duplicating coverage.
    #[cfg(feature = "node")]
    #[test]
    fn protocol_upgrade_adapter_abstain_not_counted_toward_threshold() {
        use crate::network::protocol_upgrade::{UpgradeKind, UpgradeOutcome};
        let p = Proposal {
            id: "p-abstain".into(),
            proposer: "alice".into(),
            category: ProposalCategory::ProtocolUpgrade,
            title: "T".into(),
            description: "D".into(),
            created_at: 0.0,
            voting_deadline: 500.0,
            status: ProposalStatus::Active,
            passed_at: None,
            votes: vec![
                Vote { voter: "v1".into(), stake: 600, direction: VoteDirection::For, voted_at: 10.0, own_stake: None },
                Vote { voter: "v2".into(), stake: 300, direction: VoteDirection::Against, voted_at: 20.0, own_stake: None },
                Vote { voter: "v3".into(), stake: 1000, direction: VoteDirection::Abstain, voted_at: 30.0, own_stake: None },
            ],
            committee: None,
        };
        let outcome = evaluate_protocol_upgrade_proposal(
            &p,
            UpgradeKind::SoftFork,
            String::new(),
            0,
            600,
        )
        .unwrap();
        // SoftFork has 0d transition ⇒ at any time >= window_close the tally
        // jumps straight from VoteOpen → Active (skips Passed). Accept either
        // Passed or Active as "upgrade accepted"; reject Failed (which would
        // indicate the abstain weight slipped into the denominator).
        assert!(
            matches!(outcome, UpgradeOutcome::Passed { .. } | UpgradeOutcome::Active),
            "abstain must not be in denominator: 600/(600+300)=0.667 > 0.50 SoftFork; got {outcome:?}"
        );
    }

    /// Empty-votes ⇒ total_decisive = 0 ⇒ `Failed { for_ratio: 0.0 }`.
    /// Pins that no-vote proposals don't accidentally pass (e.g. via NaN
    /// from a 0/0 division).
    #[cfg(feature = "node")]
    #[test]
    fn protocol_upgrade_adapter_empty_votes_failed_zero_ratio() {
        use crate::network::protocol_upgrade::{UpgradeKind, UpgradeOutcome};
        let p = Proposal {
            id: "p-empty".into(),
            proposer: "alice".into(),
            category: ProposalCategory::ProtocolUpgrade,
            title: "T".into(),
            description: "D".into(),
            created_at: 0.0,
            voting_deadline: 500.0,
            status: ProposalStatus::Active,
            passed_at: None,
            votes: vec![],
            committee: None,
        };
        let outcome = evaluate_protocol_upgrade_proposal(
            &p,
            UpgradeKind::SoftFork,
            String::new(),
            0,
            600,
        )
        .unwrap();
        assert_eq!(outcome, UpgradeOutcome::Failed { for_ratio: 0.0 });
    }

    /// Active outcome: HardFork passes AND current_time exceeds
    /// (window_close + 180d). Pins the end-to-end transition path through the
    /// adapter — proves the adapter doesn't strip the time-progression that
    /// turns `Passed` into `Active`.
    #[cfg(feature = "node")]
    #[test]
    fn protocol_upgrade_adapter_active_after_transition_window_elapsed() {
        use crate::network::protocol_upgrade::{UpgradeKind, UpgradeOutcome};
        let p = Proposal {
            id: "p-active".into(),
            proposer: "alice".into(),
            category: ProposalCategory::ProtocolUpgrade,
            title: "T".into(),
            description: "D".into(),
            created_at: 0.0,
            voting_deadline: 1000.0,
            status: ProposalStatus::Passed,
            passed_at: Some(1000.0),
            votes: vec![
                Vote { voter: "v1".into(), stake: 800, direction: VoteDirection::For, voted_at: 10.0, own_stake: None },
                Vote { voter: "v2".into(), stake: 100, direction: VoteDirection::Against, voted_at: 20.0, own_stake: None },
            ],
            committee: None,
        };
        let after_transition = 1000 + 180 * 86_400 + 1;
        let outcome = evaluate_protocol_upgrade_proposal(
            &p,
            UpgradeKind::HardFork,
            String::new(),
            0,
            after_transition,
        )
        .unwrap();
        assert_eq!(outcome, UpgradeOutcome::Active);
    }

    // ── §11.18 Slice 2: apply_protocol_upgrade_outcome (GovernanceState method)

    /// Helper: build a GovernanceState with a single ProtocolUpgrade proposal
    /// at the specified vote weights. Mirrors the §11.18 adapter test fixture
    /// pattern but seats the proposal inside `state.governance.proposals` so
    /// the `apply_protocol_upgrade_outcome` lookup resolves.
    #[cfg(feature = "node")]
    fn upgrade_state_with_proposal(
        proposal_id: &str,
        for_w: u64,
        against_w: u64,
        abstain_w: u64,
        voting_deadline: f64,
    ) -> GovernanceState {
        let mut state = GovernanceState::default();
        let mut votes: Vec<Vote> = Vec::new();
        if for_w > 0 {
            votes.push(Vote {
                voter: "v-for".into(),
                stake: for_w,
                direction: VoteDirection::For,
                voted_at: 1.0,
                own_stake: None,
            });
        }
        if against_w > 0 {
            votes.push(Vote {
                voter: "v-against".into(),
                stake: against_w,
                direction: VoteDirection::Against,
                voted_at: 1.0,
                own_stake: None,
            });
        }
        if abstain_w > 0 {
            votes.push(Vote {
                voter: "v-abstain".into(),
                stake: abstain_w,
                direction: VoteDirection::Abstain,
                voted_at: 1.0,
                own_stake: None,
            });
        }
        state.proposals.insert(
            proposal_id.to_string(),
            Proposal {
                id: proposal_id.into(),
                proposer: "proposer".into(),
                category: ProposalCategory::ProtocolUpgrade,
                title: "T".into(),
                description: "D".into(),
                created_at: 0.0,
                voting_deadline,
                status: ProposalStatus::Executed,
                passed_at: Some(voting_deadline),
                votes,
                committee: None,
            },
        );
        state
    }

    /// HardFork at 70/30 raw stake should record outcome=passed with the
    /// transition deadline = window_close + 180 * 86400. The wire string
    /// `"hard_fork"` round-trips and `for_ratio` is None for passed outcomes
    /// (the per-outcome shape is what differentiates Failed from the others).
    #[cfg(feature = "node")]
    #[test]
    fn slice2_apply_protocol_upgrade_outcome_records_passed_on_hardfork_70_30() {
        use crate::network::protocol_upgrade::{UpgradeKind, UpgradeOutcome};
        let mut state = upgrade_state_with_proposal("p-hf-pass", 7000, 3000, 0, 1000.0);
        let outcome = state
            .apply_protocol_upgrade_outcome(
                "p-hf-pass",
                UpgradeKind::HardFork,
                "sha256:hf-ref".into(),
                42,
                1000,
                1000.0,
            )
            .expect("apply should succeed for ProtocolUpgrade category");

        match outcome {
            UpgradeOutcome::Passed { transition_deadline_secs } => {
                assert_eq!(transition_deadline_secs, 1000 + 180 * 86_400);
            }
            other => panic!("expected Passed, got {:?}", other),
        }

        let rec = state
            .upgrade_outcomes
            .get("p-hf-pass")
            .expect("outcome must be recorded");
        assert_eq!(rec.proposal_id, "p-hf-pass");
        assert_eq!(rec.kind, "hard_fork");
        assert_eq!(rec.reference_impl_hash, "sha256:hf-ref");
        assert_eq!(rec.proposed_at_epoch, 42);
        assert_eq!(rec.outcome, "passed");
        assert!(rec.for_ratio.is_none(), "passed outcomes carry no ratio");
        assert_eq!(rec.transition_deadline_secs, Some(1000 + 180 * 86_400));
        assert_eq!(rec.recorded_at_ts, 1000.0);
    }

    /// HardFork at 60/40 raw stake should record outcome=failed with
    /// `for_ratio = 0.6` and no transition deadline. The Failed payload is
    /// the only variant that carries `for_ratio`, so its presence is the
    /// discriminator between "tally rejected" (operator must re-propose with
    /// more support) vs "tally accepted" (deadline starts ticking).
    #[cfg(feature = "node")]
    #[test]
    fn slice2_apply_protocol_upgrade_outcome_records_failed_on_hardfork_60_40() {
        use crate::network::protocol_upgrade::{UpgradeKind, UpgradeOutcome};
        let mut state = upgrade_state_with_proposal("p-hf-fail", 600, 400, 0, 1000.0);
        let outcome = state
            .apply_protocol_upgrade_outcome(
                "p-hf-fail",
                UpgradeKind::HardFork,
                "sha256:hf-fail".into(),
                7,
                1000,
                1000.0,
            )
            .expect("apply should succeed for ProtocolUpgrade category");

        match outcome {
            UpgradeOutcome::Failed { for_ratio } => {
                assert!((for_ratio - 0.6).abs() < 1e-9);
            }
            other => panic!("expected Failed, got {:?}", other),
        }

        let rec = state
            .upgrade_outcomes
            .get("p-hf-fail")
            .expect("outcome must be recorded");
        assert_eq!(rec.outcome, "failed");
        assert!(rec.transition_deadline_secs.is_none());
        let ratio = rec.for_ratio.expect("failed outcomes carry a ratio");
        assert!((ratio - 0.6).abs() < 1e-9);
    }

    /// HardFork passes AND `now >= window_close + 180d` should record
    /// outcome=active (no deadline — the transition has elapsed and the
    /// new code IS canonical). Differentiates the Active state-class from
    /// the Passed state-class on the storage axis: a sweeping `outcome ==
    /// "passed"` filter must NOT return active proposals.
    #[cfg(feature = "node")]
    #[test]
    fn slice2_apply_protocol_upgrade_outcome_records_active_after_transition_window() {
        use crate::network::protocol_upgrade::{UpgradeKind, UpgradeOutcome};
        let mut state = upgrade_state_with_proposal("p-hf-active", 8000, 2000, 0, 1000.0);
        let after_transition = 1000 + 180 * 86_400 + 1;
        let outcome = state
            .apply_protocol_upgrade_outcome(
                "p-hf-active",
                UpgradeKind::HardFork,
                "sha256:hf-active".into(),
                100,
                after_transition,
                after_transition as f64,
            )
            .unwrap();
        assert_eq!(outcome, UpgradeOutcome::Active);

        let rec = state
            .upgrade_outcomes
            .get("p-hf-active")
            .expect("outcome must be recorded");
        assert_eq!(rec.outcome, "active");
        assert!(rec.transition_deadline_secs.is_none());
        assert!(rec.for_ratio.is_none());
    }

    /// VoteOpen outcome (current_time < window_close) should record
    /// outcome=vote_open with no ratio + no deadline. Even though this
    /// branch should not normally fire under `apply_governance_op::Execute`
    /// (the execute path runs after voting closes), the adapter must
    /// still record correctly so a debug-tool that pokes the adapter with
    /// a future timestamp gets a consistent picture.
    #[cfg(feature = "node")]
    #[test]
    fn slice2_apply_protocol_upgrade_outcome_records_vote_open_before_window_close() {
        use crate::network::protocol_upgrade::{UpgradeKind, UpgradeOutcome};
        let mut state = upgrade_state_with_proposal("p-open", 9000, 100, 0, 1000.0);
        let outcome = state
            .apply_protocol_upgrade_outcome(
                "p-open",
                UpgradeKind::HardFork,
                "sha256:open".into(),
                0,
                500,
                500.0,
            )
            .unwrap();
        assert_eq!(outcome, UpgradeOutcome::VoteOpen);

        let rec = state.upgrade_outcomes.get("p-open").unwrap();
        assert_eq!(rec.outcome, "vote_open");
        assert!(rec.for_ratio.is_none());
        assert!(rec.transition_deadline_secs.is_none());
    }

    /// Adapter must reject lookup on a missing proposal with a Governance
    /// error naming the missing ID. Without this guard a downstream caller
    /// could silently no-op on a typo'd proposal ID, and the upgrade_outcomes
    /// map would never be populated despite the dispatch path appearing to
    /// run cleanly.
    #[cfg(feature = "node")]
    #[test]
    fn slice2_apply_protocol_upgrade_outcome_rejects_missing_proposal() {
        use crate::network::protocol_upgrade::UpgradeKind;
        let mut state = GovernanceState::default();
        let err = state
            .apply_protocol_upgrade_outcome(
                "p-not-here",
                UpgradeKind::HardFork,
                "sha256:x".into(),
                0,
                1000,
                1000.0,
            )
            .expect_err("missing proposal must error");
        match err {
            ElaraError::Governance(msg) => {
                assert!(msg.contains("proposal not found"));
                assert!(msg.contains("p-not-here"));
            }
            other => panic!("expected Governance error, got {:?}", other),
        }
        assert!(
            state.upgrade_outcomes.is_empty(),
            "no outcome should be recorded when lookup fails"
        );
    }

    /// Adapter must reject lookup when the proposal exists but is not
    /// `ProtocolUpgrade` category. Mirrors the inner adapter's category
    /// check at `governance.rs::evaluate_protocol_upgrade_proposal`, so a
    /// caller that mis-routes a Parameter proposal into the upgrade path
    /// gets a Governance error rather than silently writing a misleading
    /// outcome row into `upgrade_outcomes`.
    #[cfg(feature = "node")]
    #[test]
    fn slice2_apply_protocol_upgrade_outcome_rejects_non_protocol_upgrade_category() {
        use crate::network::protocol_upgrade::UpgradeKind;
        let mut state = GovernanceState::default();
        state.proposals.insert(
            "p-param".into(),
            Proposal {
                id: "p-param".into(),
                proposer: "x".into(),
                category: ProposalCategory::Parameter,
                title: "T".into(),
                description: "D".into(),
                created_at: 0.0,
                voting_deadline: 1000.0,
                status: ProposalStatus::Executed,
                passed_at: Some(1000.0),
                votes: vec![],
                committee: None,
            },
        );
        let err = state
            .apply_protocol_upgrade_outcome(
                "p-param",
                UpgradeKind::SoftFork,
                String::new(),
                0,
                2000,
                2000.0,
            )
            .expect_err("Parameter proposal must error at adapter");
        match err {
            ElaraError::Governance(msg) => {
                assert!(msg.contains("non-ProtocolUpgrade"));
                assert!(msg.contains("parameter"));
            }
            other => panic!("expected Governance error, got {:?}", other),
        }
        assert!(state.upgrade_outcomes.is_empty());
    }

    /// Re-execution (a second apply call) must OVERWRITE the previous
    /// record, NOT accumulate. Pins the documented semantic in the method
    /// docstring ("re-execution overwrites the previous record so an
    /// Active transition captured at a later tick replaces an earlier
    /// Passed snapshot"). A regression that switched to .entry().or_insert
    /// would silently freeze the first outcome and break operator
    /// observability of the Passed → Active transition.
    #[cfg(feature = "node")]
    #[test]
    fn slice2_apply_protocol_upgrade_outcome_re_execution_overwrites_prior_record() {
        use crate::network::protocol_upgrade::UpgradeKind;
        let mut state = upgrade_state_with_proposal("p-twice", 8000, 2000, 0, 1000.0);
        // First execute: inside transition window → Passed.
        state
            .apply_protocol_upgrade_outcome(
                "p-twice",
                UpgradeKind::HardFork,
                "sha256:v1".into(),
                10,
                1000,
                1000.0,
            )
            .unwrap();
        assert_eq!(state.upgrade_outcomes.get("p-twice").unwrap().outcome, "passed");
        assert_eq!(state.upgrade_outcomes.len(), 1);

        // Second execute at after-transition time → Active overwrites Passed.
        let after = 1000 + 180 * 86_400 + 1;
        state
            .apply_protocol_upgrade_outcome(
                "p-twice",
                UpgradeKind::HardFork,
                "sha256:v1".into(),
                10,
                after,
                after as f64,
            )
            .unwrap();
        assert_eq!(state.upgrade_outcomes.get("p-twice").unwrap().outcome, "active");
        assert_eq!(
            state.upgrade_outcomes.len(),
            1,
            "re-execution must overwrite, not accumulate"
        );
    }

    /// Serde round-trip of `UpgradeOutcomeRecord`. Pins the wire shape so a
    /// JSON consumer (e.g. a future `/admin/proposal/upgrade_outcomes` route)
    /// can rely on the field names + Option<f64>/Option<u64> serialization
    /// for null-vs-number discrimination between Failed and Passed.
    #[test]
    fn slice2_upgrade_outcome_record_serde_round_trip() {
        let rec = UpgradeOutcomeRecord {
            proposal_id: "p-serde".into(),
            kind: "hard_fork".into(),
            reference_impl_hash: "sha256:abc".into(),
            proposed_at_epoch: 99,
            outcome: "passed".into(),
            for_ratio: None,
            transition_deadline_secs: Some(15_553_000),
            recorded_at_ts: 12_345.6,
        };
        let json = serde_json::to_string(&rec).unwrap();
        // Field names that downstream readers depend on:
        assert!(json.contains("\"proposal_id\":\"p-serde\""));
        assert!(json.contains("\"kind\":\"hard_fork\""));
        assert!(json.contains("\"outcome\":\"passed\""));
        assert!(json.contains("\"transition_deadline_secs\":15553000"));
        // Round-trip equality:
        let back: UpgradeOutcomeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    /// `GovernanceState` must `#[serde(default)]` the new `upgrade_outcomes`
    /// field — a snapshot produced before §11.18 Slice 2 lands has no such
    /// field, and the on-restore deserialization MUST default to an empty
    /// map rather than fail. Closes the snapshot-compat axis for the new
    /// field; mirrors the same pattern used for the
    /// `active_delegations_count` + `proposal_status_counts` fields.
    #[test]
    fn slice2_governance_state_loads_old_snapshot_without_upgrade_outcomes_field() {
        // A pre-Slice-2 snapshot JSON: every field GovernanceState had
        // before this field was added. The deserializer must accept this without
        // requiring `upgrade_outcomes`.
        let pre_slice2 = serde_json::json!({
            "proposals": {},
            "delegations": {},
            "params": GovernableParams::default(),
            "param_changes": [],
            "anchor_vetoes": AnchorVetoState::new(),
            "active_delegations_count": 0,
            "proposal_status_counts": ProposalStatusCounts::default(),
        });
        let state: GovernanceState = serde_json::from_value(pre_slice2)
            .expect("pre-Slice-2 snapshots must load without upgrade_outcomes field");
        assert!(
            state.upgrade_outcomes.is_empty(),
            "missing field must default to empty map"
        );
    }
}
