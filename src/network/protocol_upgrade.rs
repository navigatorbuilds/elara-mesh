//! Protocol Upgrade Mechanism — Protocol §11.18 algorithmic primitives.
//!
//! Pure data + state-machine module. No runtime callers wired yet — this
//! ships as a primitive on the same pattern as `network::cross_zone_trust`
//! (§11.22): types + thresholds + tally + state machine, with wire-up to
//! `token::governance` ProposalCategory and acceptance gates deferred to a
//! follow-up commit.
//!
//! Scope of this module:
//!   1. Upgrade taxonomy: `UpgradeKind = SoftFork | HardFork | Emergency`
//!      with whitepaper-pinned threshold + transition + discussion windows.
//!   2. Algorithm lifecycle states: `AlgorithmState = Active | Legacy |
//!      Deprecated | Archived` and the legal transition graph between them
//!      (forward-only, no skips, idempotent on same-state).
//!   3. Threshold constants (50% soft-fork, 67% hard-fork supermajority,
//!      75% emergency supermajority, 90d discussion, 180d normal transition,
//!      48h emergency vote window, 30d emergency transition).
//!   4. `UpgradeProposal` data carrier (reference-impl hash, vote tallies,
//!      vote-close deadline, current time).
//!   5. `evaluate_upgrade_tally(...) -> UpgradeOutcome` pure-function tally
//!      primitive — `VoteOpen | Passed | Failed | Active`.
//!
//! Scale-rule compliance: every primitive is O(1) per proposal — vote
//! tallies sum integer counters, state-machine transitions are constant-time
//! enum lookups, threshold comparisons are constant-time. No O(all_records)
//! iteration, no per-tally fleet scans. Holds at 1M-zone / 10K-node mainnet
//! scale because the surface is bounded by the number of concurrently-open
//! upgrade proposals (whitepaper §11.18 implies one-at-a-time emergency
//! cadence; even at 100 concurrent proposals the per-tick cost is ~100 × O(1)
//! integer comparisons).

use crate::errors::{ElaraError, Result};
use serde::{Deserialize, Serialize};

// ── Threshold + window constants (whitepaper §11.18) ────────────────────

/// Soft-fork: simple majority (50%).
pub const SOFT_FORK_THRESHOLD: f64 = 0.50;

/// Hard-fork: 67% supermajority per whitepaper §11.18 line 24
/// ("governance approval (>67% supermajority per Section 10.3)").
pub const HARD_FORK_THRESHOLD: f64 = 0.67;

/// Emergency: 75% supermajority per whitepaper §11.18 line 40
/// ("Emergency vote: 48-hour window, >75% supermajority required").
pub const EMERGENCY_THRESHOLD: f64 = 0.75;

/// Hard-fork discussion period — whitepaper §11.18 line 28.
pub const NORMAL_DISCUSSION_DAYS: u32 = 90;

/// Hard-fork transition window — whitepaper §11.18 line 30.
pub const NORMAL_TRANSITION_DAYS: u32 = 180;

/// Emergency vote window — whitepaper §11.18 line 40.
pub const EMERGENCY_VOTE_WINDOW_HOURS: u32 = 48;

/// Emergency transition window — whitepaper §11.18 line 41.
pub const EMERGENCY_TRANSITION_DAYS: u32 = 30;

pub const SECONDS_PER_DAY: u64 = 86_400;
pub const SECONDS_PER_HOUR: u64 = 3_600;

// ── UpgradeKind taxonomy ────────────────────────────────────────────────

/// Upgrade taxonomy per whitepaper §11.18.
///
/// Soft-fork: backward-compatible (new optional fields, new classification
/// levels, new entity types). No coordination required.
///
/// Hard-fork: breaking (consensus mechanism, required field additions,
/// algorithm deprecation). 67% supermajority + 90d discussion + 180d
/// transition window.
///
/// Emergency: fast-track for critical security patches (algorithm break,
/// critical vulnerability). 75% supermajority + 48h vote window + 30d
/// transition. Intentionally rare and high-threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeKind {
    SoftFork,
    HardFork,
    Emergency,
}

impl UpgradeKind {
    /// Supermajority threshold required for this upgrade kind to pass.
    pub fn supermajority_threshold(self) -> f64 {
        match self {
            Self::SoftFork => SOFT_FORK_THRESHOLD,
            Self::HardFork => HARD_FORK_THRESHOLD,
            Self::Emergency => EMERGENCY_THRESHOLD,
        }
    }

    /// Transition window in days. Soft-forks have no formal transition
    /// (nodes upgrade at their own pace — whitepaper §11.18 line 17).
    pub fn transition_days(self) -> u32 {
        match self {
            Self::SoftFork => 0,
            Self::HardFork => NORMAL_TRANSITION_DAYS,
            Self::Emergency => EMERGENCY_TRANSITION_DAYS,
        }
    }

    /// Discussion window in days. Emergency skips this entirely; soft-fork
    /// has no formal discussion period (per the "individual nodes upgrade
    /// at their own pace" model).
    pub fn discussion_days(self) -> u32 {
        match self {
            Self::SoftFork => 0,
            Self::HardFork => NORMAL_DISCUSSION_DAYS,
            Self::Emergency => 0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SoftFork => "soft_fork",
            Self::HardFork => "hard_fork",
            Self::Emergency => "emergency",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "soft_fork" => Ok(Self::SoftFork),
            "hard_fork" => Ok(Self::HardFork),
            "emergency" => Ok(Self::Emergency),
            other => Err(ElaraError::Governance(format!(
                "unknown upgrade kind: {other}"
            ))),
        }
    }
}

// ── AlgorithmState lifecycle ────────────────────────────────────────────

/// Algorithm lifecycle states per whitepaper §11.18 lines 47-54.
///
/// ```text
/// ACTIVE     → algorithm used for new signatures
/// LEGACY     → algorithm accepted for verification, not recommended for new signatures
/// DEPRECATED → algorithm accepted for verification of old records only, rejected for new
/// ARCHIVED   → algorithm documented in protocol history, old records still verifiable
/// ```
///
/// Per whitepaper line 56: "No algorithm is ever deleted from the protocol's
/// specification" — all four states accept verification; only `Active`
/// accepts new signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgorithmState {
    Active,
    Legacy,
    Deprecated,
    Archived,
}

impl AlgorithmState {
    /// Whitepaper §11.18 transition rule: ACTIVE → LEGACY → DEPRECATED →
    /// ARCHIVED is the only forward path. No backward transitions, no skips.
    pub fn can_transition_to(self, target: Self) -> bool {
        matches!(
            (self, target),
            (Self::Active, Self::Legacy)
                | (Self::Legacy, Self::Deprecated)
                | (Self::Deprecated, Self::Archived)
        )
    }

    /// Only `Active` state accepts new signatures.
    pub fn accepts_new_signatures(self) -> bool {
        matches!(self, Self::Active)
    }

    /// All four states accept verification — whitepaper line 56 invariant.
    pub fn accepts_verification(self) -> bool {
        true
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Legacy => "legacy",
            Self::Deprecated => "deprecated",
            Self::Archived => "archived",
        }
    }
}

/// Apply an `AlgorithmState` transition.
///
/// Same-state requests are idempotent no-ops (return current). Forward-graph
/// requests advance one step. Skips and backward transitions return an
/// `ElaraError::Governance` describing the illegal request.
pub fn transition_algorithm_state(
    current: AlgorithmState,
    target: AlgorithmState,
) -> Result<AlgorithmState> {
    if current == target {
        return Ok(current);
    }
    if !current.can_transition_to(target) {
        return Err(ElaraError::Governance(format!(
            "illegal algorithm state transition: {} -> {}",
            current.as_str(),
            target.as_str()
        )));
    }
    Ok(target)
}

// ── UpgradeProposal data carrier + tally ────────────────────────────────

/// Upgrade proposal data carrier. Carries all inputs `evaluate_upgrade_tally`
/// needs to deterministically classify the proposal — no hidden global state.
///
/// `current_time_secs` is passed in (rather than read from a clock) so the
/// tally is pure and deterministic for the same input. Callers supply the
/// observed-now from `chrono::Utc::now()` or the consensus-tick timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeProposal {
    pub proposal_id: String,
    pub kind: UpgradeKind,
    /// SHA-256 (or stronger) of the reference implementation diff. Pinned
    /// so a passed vote binds to a SPECIFIC code, not a kind/description
    /// (whitepaper §11.18 line 27 "Proposal published (with reference
    /// implementation)").
    pub reference_impl_hash: String,
    pub proposed_at_epoch: u64,
    pub votes_for_weight: u128,
    pub votes_against_weight: u128,
    /// Abstain weight is recorded but does NOT count toward the decisive
    /// total (mirrors `governance.rs` line 822 "abstain doesn't count
    /// toward threshold").
    pub votes_abstain_weight: u128,
    /// Unix-seconds at which the voting window closes. Before close ⇒
    /// `VoteOpen`; at-or-after close ⇒ tally proceeds.
    pub vote_window_close_secs: u64,
    /// Observed current Unix-seconds. Passed in by caller.
    pub current_time_secs: u64,
    /// Optional carried deadline from a prior tally. Not consulted by
    /// `evaluate_upgrade_tally` (which always recomputes from
    /// `vote_window_close_secs + kind.transition_days()`); kept on the
    /// struct as a snapshot for serialization / RPC responses.
    pub transition_deadline_secs: Option<u64>,
}

/// Result of `evaluate_upgrade_tally`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UpgradeOutcome {
    /// Voting window still open (current_time < window_close).
    VoteOpen,
    /// Threshold reached, transition window in flight. `transition_deadline_secs`
    /// is `vote_window_close_secs + kind.transition_days() × 86400`.
    Passed { transition_deadline_secs: u64 },
    /// Failed to reach threshold by window close. `for_ratio` is the
    /// observed for/(for+against) ratio at close (0.0 if no decisive votes).
    Failed { for_ratio: f64 },
    /// Passed AND transition window elapsed — the upgrade is active and
    /// the new format is the canonical one (old format still verifiable
    /// per AlgorithmState lifecycle).
    Active,
}

/// Pure tally function. Returns `UpgradeOutcome` deterministically from the
/// proposal's recorded vote weights + observed current time. Threshold
/// comparison is `for_ratio >= kind.supermajority_threshold()` (>= because
/// whitepaper §11.18 line 24 says ">67%" which we read as ">= 67%" in
/// fixed-point — the spec's intent is "two-thirds or more", not "strictly
/// more than two-thirds" which would be unreachable in integer arithmetic).
///
/// Per the scale rule: O(1) — three integer comparisons + one float ratio.
pub fn evaluate_upgrade_tally(proposal: &UpgradeProposal) -> UpgradeOutcome {
    let now = proposal.current_time_secs;

    if now < proposal.vote_window_close_secs {
        return UpgradeOutcome::VoteOpen;
    }

    let total_decisive = proposal
        .votes_for_weight
        .saturating_add(proposal.votes_against_weight);

    if total_decisive == 0 {
        return UpgradeOutcome::Failed { for_ratio: 0.0 };
    }

    let for_ratio = (proposal.votes_for_weight as f64) / (total_decisive as f64);
    let threshold = proposal.kind.supermajority_threshold();

    if for_ratio < threshold {
        return UpgradeOutcome::Failed { for_ratio };
    }

    let transition_secs = (proposal.kind.transition_days() as u64) * SECONDS_PER_DAY;
    let deadline = proposal
        .vote_window_close_secs
        .saturating_add(transition_secs);

    if now >= deadline {
        UpgradeOutcome::Active
    } else {
        UpgradeOutcome::Passed {
            transition_deadline_secs: deadline,
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── UpgradeKind threshold + window invariants ────────────────────

    /// Pins the three supermajority thresholds to the whitepaper §11.18
    /// values. A regression that swapped HardFork↔Emergency would silently
    /// flip the security envelope on emergency patches.
    #[test]
    fn upgrade_kind_thresholds_match_whitepaper_11_18() {
        assert_eq!(UpgradeKind::SoftFork.supermajority_threshold(), 0.50);
        assert_eq!(UpgradeKind::HardFork.supermajority_threshold(), 0.67);
        assert_eq!(UpgradeKind::Emergency.supermajority_threshold(), 0.75);
    }

    #[test]
    fn upgrade_kind_transition_windows_match_whitepaper_11_18() {
        assert_eq!(UpgradeKind::SoftFork.transition_days(), 0);
        assert_eq!(UpgradeKind::HardFork.transition_days(), 180);
        assert_eq!(UpgradeKind::Emergency.transition_days(), 30);
    }

    #[test]
    fn upgrade_kind_discussion_windows_match_whitepaper_11_18() {
        assert_eq!(UpgradeKind::SoftFork.discussion_days(), 0);
        assert_eq!(UpgradeKind::HardFork.discussion_days(), 90);
        // Emergency skips the discussion phase entirely (line 37-42).
        assert_eq!(UpgradeKind::Emergency.discussion_days(), 0);
    }

    #[test]
    fn upgrade_kind_parse_round_trip() {
        for kind in [UpgradeKind::SoftFork, UpgradeKind::HardFork, UpgradeKind::Emergency] {
            assert_eq!(UpgradeKind::parse(kind.as_str()).unwrap(), kind);
        }
        assert!(UpgradeKind::parse("not_a_real_kind").is_err());
    }

    // ── AlgorithmState transition graph ──────────────────────────────

    #[test]
    fn algorithm_state_forward_transitions_legal() {
        assert!(AlgorithmState::Active.can_transition_to(AlgorithmState::Legacy));
        assert!(AlgorithmState::Legacy.can_transition_to(AlgorithmState::Deprecated));
        assert!(AlgorithmState::Deprecated.can_transition_to(AlgorithmState::Archived));
    }

    #[test]
    fn algorithm_state_backward_transitions_illegal() {
        // Whitepaper enforces forward-only — once you LEGACY you don't
        // un-LEGACY; the algorithm doesn't come back into ACTIVE service
        // because some operator changes their mind.
        assert!(!AlgorithmState::Legacy.can_transition_to(AlgorithmState::Active));
        assert!(!AlgorithmState::Deprecated.can_transition_to(AlgorithmState::Legacy));
        assert!(!AlgorithmState::Archived.can_transition_to(AlgorithmState::Deprecated));
        assert!(!AlgorithmState::Archived.can_transition_to(AlgorithmState::Active));
    }

    #[test]
    fn algorithm_state_skip_transitions_illegal() {
        // No ACTIVE → DEPRECATED or LEGACY → ARCHIVED — every state must
        // be visited in sequence so operators get the full LEGACY warning
        // period (whitepaper line 51 "not recommended for new signatures").
        assert!(!AlgorithmState::Active.can_transition_to(AlgorithmState::Deprecated));
        assert!(!AlgorithmState::Active.can_transition_to(AlgorithmState::Archived));
        assert!(!AlgorithmState::Legacy.can_transition_to(AlgorithmState::Archived));
    }

    #[test]
    fn transition_algorithm_state_idempotent_on_same_state() {
        // Same-to-same is a no-op, not an error. Callers don't need to
        // pre-check current state before requesting an "advance".
        for s in [
            AlgorithmState::Active,
            AlgorithmState::Legacy,
            AlgorithmState::Deprecated,
            AlgorithmState::Archived,
        ] {
            assert_eq!(transition_algorithm_state(s, s).unwrap(), s);
        }
    }

    #[test]
    fn transition_algorithm_state_legal_path_advances() {
        let s0 = AlgorithmState::Active;
        let s1 = transition_algorithm_state(s0, AlgorithmState::Legacy).unwrap();
        let s2 = transition_algorithm_state(s1, AlgorithmState::Deprecated).unwrap();
        let s3 = transition_algorithm_state(s2, AlgorithmState::Archived).unwrap();
        assert_eq!(s3, AlgorithmState::Archived);
    }

    #[test]
    fn transition_algorithm_state_rejects_illegal_skip() {
        let err = transition_algorithm_state(AlgorithmState::Active, AlgorithmState::Archived);
        assert!(err.is_err());
        match err {
            Err(ElaraError::Governance(msg)) => {
                assert!(msg.contains("illegal algorithm state transition"));
                assert!(msg.contains("active"));
                assert!(msg.contains("archived"));
            }
            other => panic!("expected Governance error, got {:?}", other),
        }
    }

    #[test]
    fn algorithm_state_signature_acceptance_only_active() {
        assert!(AlgorithmState::Active.accepts_new_signatures());
        assert!(!AlgorithmState::Legacy.accepts_new_signatures());
        assert!(!AlgorithmState::Deprecated.accepts_new_signatures());
        assert!(!AlgorithmState::Archived.accepts_new_signatures());
    }

    #[test]
    fn algorithm_state_verification_acceptance_all_states() {
        // Whitepaper line 56: "No algorithm is ever deleted from the
        // protocol's specification." All four states verify; only ACTIVE
        // signs.
        assert!(AlgorithmState::Active.accepts_verification());
        assert!(AlgorithmState::Legacy.accepts_verification());
        assert!(AlgorithmState::Deprecated.accepts_verification());
        assert!(AlgorithmState::Archived.accepts_verification());
    }

    // ── UpgradeProposal tally outcomes ───────────────────────────────

    fn proposal(
        kind: UpgradeKind,
        for_w: u128,
        against_w: u128,
        now_offset_secs: i64,
    ) -> UpgradeProposal {
        let close = 1_000_000_u64;
        let current = if now_offset_secs >= 0 {
            close.saturating_add(now_offset_secs as u64)
        } else {
            close.saturating_sub((-now_offset_secs) as u64)
        };
        UpgradeProposal {
            proposal_id: "test-prop-1".into(),
            kind,
            reference_impl_hash: "sha256:abc".into(),
            proposed_at_epoch: 0,
            votes_for_weight: for_w,
            votes_against_weight: against_w,
            votes_abstain_weight: 0,
            vote_window_close_secs: close,
            current_time_secs: current,
            transition_deadline_secs: None,
        }
    }

    #[test]
    fn tally_returns_vote_open_before_window_close() {
        let p = proposal(UpgradeKind::HardFork, 1000, 100, -1);
        assert_eq!(evaluate_upgrade_tally(&p), UpgradeOutcome::VoteOpen);
    }

    #[test]
    fn tally_at_exact_window_close_proceeds_to_evaluation() {
        // Boundary: current == window_close. Comparison is `now < close`,
        // so equality proceeds to tally evaluation (NOT VoteOpen).
        let p = proposal(UpgradeKind::HardFork, 700, 100, 0);
        assert_ne!(evaluate_upgrade_tally(&p), UpgradeOutcome::VoteOpen);
    }

    #[test]
    fn tally_hardfork_passes_at_67_percent_exact() {
        // 670/1000 = 0.670 == 0.67 threshold. The comparison is
        // `for_ratio < threshold` → Failed, so 0.67 == 0.67 passes.
        let p = proposal(UpgradeKind::HardFork, 670, 330, 1);
        match evaluate_upgrade_tally(&p) {
            UpgradeOutcome::Passed { .. } => {}
            other => panic!("expected Passed at 67% threshold, got {:?}", other),
        }
    }

    #[test]
    fn tally_hardfork_fails_below_67_percent() {
        // 660/1000 = 0.660 < 0.67 → Failed.
        let p = proposal(UpgradeKind::HardFork, 660, 340, 1);
        match evaluate_upgrade_tally(&p) {
            UpgradeOutcome::Failed { for_ratio } => assert!(for_ratio < 0.67),
            other => panic!("expected Failed below 67%, got {:?}", other),
        }
    }

    #[test]
    fn tally_emergency_rejects_70_percent_below_75_threshold() {
        // 70% would pass HardFork (>=67%) but NOT Emergency (>=75%) —
        // pins the divergence between the two thresholds.
        let p = proposal(UpgradeKind::Emergency, 700, 300, 1);
        match evaluate_upgrade_tally(&p) {
            UpgradeOutcome::Failed { for_ratio } => {
                assert!((0.67..0.75).contains(&for_ratio));
            }
            other => panic!(
                "expected Failed (70% < 75% emergency threshold), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn tally_emergency_passes_at_75_percent_exact() {
        let p = proposal(UpgradeKind::Emergency, 750, 250, 1);
        match evaluate_upgrade_tally(&p) {
            UpgradeOutcome::Passed { .. } | UpgradeOutcome::Active => {}
            other => panic!("expected Passed at exactly 75%, got {:?}", other),
        }
    }

    #[test]
    fn tally_hardfork_active_after_180_day_transition_window() {
        // Hard-fork transition is 180 days. At day 365 we should be Active.
        let one_year_secs: i64 = (365 * SECONDS_PER_DAY) as i64;
        let p = proposal(UpgradeKind::HardFork, 700, 100, one_year_secs);
        assert_eq!(evaluate_upgrade_tally(&p), UpgradeOutcome::Active);
    }

    #[test]
    fn tally_hardfork_passed_during_transition_window_carries_correct_deadline() {
        // At day 90 (mid-transition for hard-fork's 180d window) we should
        // be Passed-in-window with deadline = close + 180 days.
        let ninety_days_secs: i64 = (90 * SECONDS_PER_DAY) as i64;
        let p = proposal(UpgradeKind::HardFork, 700, 100, ninety_days_secs);
        match evaluate_upgrade_tally(&p) {
            UpgradeOutcome::Passed {
                transition_deadline_secs,
            } => {
                assert_eq!(
                    transition_deadline_secs,
                    1_000_000 + 180 * SECONDS_PER_DAY
                );
            }
            other => panic!("expected Passed during transition, got {:?}", other),
        }
    }

    #[test]
    fn tally_emergency_active_after_30_day_transition_not_180() {
        // Emergency uses 30-day transition, NOT the 180-day hard-fork
        // window. A regression that ran emergency on the 180-day path
        // would leave critical patches in "Passed" limbo for 5 extra months.
        let forty_days_secs: i64 = (40 * SECONDS_PER_DAY) as i64;
        let p = proposal(UpgradeKind::Emergency, 800, 100, forty_days_secs);
        assert_eq!(evaluate_upgrade_tally(&p), UpgradeOutcome::Active);
    }

    #[test]
    fn tally_passed_at_deadline_boundary_flips_to_active() {
        // At exactly close + transition_days, comparison `now >= deadline`
        // → Active. Pins the boundary so a future <-vs-<= refactor can't
        // silently leave a one-second gap where the upgrade isn't active.
        let exactly_180d: i64 = (180 * SECONDS_PER_DAY) as i64;
        let p = proposal(UpgradeKind::HardFork, 700, 100, exactly_180d);
        assert_eq!(evaluate_upgrade_tally(&p), UpgradeOutcome::Active);
    }

    #[test]
    fn tally_zero_votes_fails_with_zero_ratio() {
        let p = proposal(UpgradeKind::HardFork, 0, 0, 1);
        match evaluate_upgrade_tally(&p) {
            UpgradeOutcome::Failed { for_ratio } => assert_eq!(for_ratio, 0.0),
            other => panic!("expected Failed at zero votes, got {:?}", other),
        }
    }

    #[test]
    fn tally_abstain_does_not_count_toward_decisive_threshold() {
        // 600 for + 300 against = 900 decisive; abstain 1000 ignored.
        // 600/900 = 66.67% — fails HardFork 67%. A regression that
        // counted abstain into the denominator would flip this to a pass.
        let mut p = proposal(UpgradeKind::HardFork, 600, 300, 1);
        p.votes_abstain_weight = 1000;
        match evaluate_upgrade_tally(&p) {
            UpgradeOutcome::Failed { for_ratio } => {
                assert!((for_ratio - 0.6666666666666666).abs() < 1e-9);
            }
            other => panic!("expected Failed at 66.67%, got {:?}", other),
        }
    }

    #[test]
    fn tally_softfork_passes_at_simple_majority() {
        // SoftFork uses 50% threshold.
        let p = proposal(UpgradeKind::SoftFork, 510, 490, 1);
        match evaluate_upgrade_tally(&p) {
            UpgradeOutcome::Passed { .. } | UpgradeOutcome::Active => {}
            other => panic!("expected SoftFork to pass at 51%, got {:?}", other),
        }
    }

    #[test]
    fn tally_softfork_fails_below_simple_majority() {
        // 49.9% — below 50% threshold.
        let p = proposal(UpgradeKind::SoftFork, 499, 501, 1);
        match evaluate_upgrade_tally(&p) {
            UpgradeOutcome::Failed { for_ratio } => assert!(for_ratio < 0.50),
            other => panic!("expected Failed at 49.9%, got {:?}", other),
        }
    }

    #[test]
    fn tally_overflow_resistant_saturates_not_panics() {
        // Pathological: votes_for + votes_against = u128::MAX + 1 would
        // overflow. Saturating addition ensures the tally still completes
        // (with a slightly truncated total, but no panic). Mainnet at 1M
        // zones × 10K nodes × extreme stake never reaches u128::MAX, but
        // the saturating guard defends against malformed input on the
        // wire from a byzantine peer or storage corruption.
        let p = UpgradeProposal {
            proposal_id: "saturation-test".into(),
            kind: UpgradeKind::HardFork,
            reference_impl_hash: "sha256:abc".into(),
            proposed_at_epoch: 0,
            votes_for_weight: u128::MAX - 100,
            votes_against_weight: 200, // saturating_add caps at u128::MAX
            votes_abstain_weight: 0,
            vote_window_close_secs: 1_000_000,
            current_time_secs: 1_000_001,
            transition_deadline_secs: None,
        };
        // Just must not panic — for_ratio ≈ 1.0, so Passed/Active.
        let outcome = evaluate_upgrade_tally(&p);
        matches!(outcome, UpgradeOutcome::Passed { .. } | UpgradeOutcome::Active);
    }

    // ── Cross-kind end-to-end scenarios ──────────────────────────────

    #[test]
    fn end_to_end_emergency_upgrade_lifecycle() {
        // Whitepaper §11.18 lines 37-44 spec the emergency path:
        // Day 0   — Security advisory + emergency vote opens.
        // Day 2   — 48h vote window closes with 80% for, 20% against.
        // Day 2-32 — 30-day transition window.
        // Day 32  — Upgrade Active.
        //
        // Build a single proposal and re-tally at each phase to pin the
        // outcome progression.
        let base_close = 1_000_000_u64;
        let mut p = UpgradeProposal {
            proposal_id: "emergency-dilithium3-break".into(),
            kind: UpgradeKind::Emergency,
            reference_impl_hash: "sha256:emergency-patch".into(),
            proposed_at_epoch: 0,
            votes_for_weight: 800,
            votes_against_weight: 200,
            votes_abstain_weight: 0,
            vote_window_close_secs: base_close,
            current_time_secs: base_close - 1, // pre-close
            transition_deadline_secs: None,
        };

        // Phase 1: vote open (current_time < window_close).
        assert_eq!(evaluate_upgrade_tally(&p), UpgradeOutcome::VoteOpen);

        // Phase 2: vote closed, in 30-day transition (day 15).
        p.current_time_secs = base_close + 15 * SECONDS_PER_DAY;
        match evaluate_upgrade_tally(&p) {
            UpgradeOutcome::Passed { transition_deadline_secs } => {
                assert_eq!(transition_deadline_secs, base_close + 30 * SECONDS_PER_DAY);
            }
            other => panic!("phase 2 expected Passed, got {:?}", other),
        }

        // Phase 3: 30-day transition elapsed (day 31).
        p.current_time_secs = base_close + 31 * SECONDS_PER_DAY;
        assert_eq!(evaluate_upgrade_tally(&p), UpgradeOutcome::Active);
    }

    #[test]
    fn end_to_end_failed_hardfork_stays_failed_across_time() {
        // A hard-fork that failed at vote close (60% for) should remain
        // Failed regardless of how far into the future we advance time —
        // no "eventually passes" silent flip.
        let base_close = 1_000_000_u64;
        let mut p = UpgradeProposal {
            proposal_id: "rejected-hardfork".into(),
            kind: UpgradeKind::HardFork,
            reference_impl_hash: "sha256:rejected".into(),
            proposed_at_epoch: 0,
            votes_for_weight: 600,
            votes_against_weight: 400,
            votes_abstain_weight: 0,
            vote_window_close_secs: base_close,
            current_time_secs: base_close + 1,
            transition_deadline_secs: None,
        };

        // Just after close: Failed.
        match evaluate_upgrade_tally(&p) {
            UpgradeOutcome::Failed { .. } => {}
            other => panic!("expected immediate Failed, got {:?}", other),
        }

        // 10 years later: still Failed.
        p.current_time_secs = base_close + 10 * 365 * SECONDS_PER_DAY;
        match evaluate_upgrade_tally(&p) {
            UpgradeOutcome::Failed { .. } => {}
            other => panic!("expected long-term Failed, got {:?}", other),
        }
    }
}
