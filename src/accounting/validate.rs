//! beat ledger validation — pre-flight checks before submitting ledger records.
//!
//! These functions validate a proposed ledger operation against the current
//! ledger state WITHOUT modifying it. Use before creating and signing a
//! ledger record to get early feedback on whether it will be accepted.

//!
//! Spec references:
//!   @spec Protocol §3.5
//!   @spec economics §9.3

use crate::errors::{ElaraError, Result};
use crate::accounting::authority::is_privileged_emitter;
use crate::accounting::ledger::LedgerState;
use crate::accounting::types::*;

/// Validation result with human-readable error message.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub error: Option<String>,
}

impl ValidationResult {
    fn ok() -> Self {
        Self {
            valid: true,
            error: None,
        }
    }

    fn fail(msg: impl Into<String>) -> Self {
        Self {
            valid: false,
            error: Some(msg.into()),
        }
    }
}

/// Validate a mint operation.
pub fn validate_mint(
    state: &LedgerState,
    actor_identity_hash: &str,
    genesis_authority: &str,
    amount: u64,
    _to: &str,
) -> ValidationResult {
    if !is_privileged_emitter(actor_identity_hash, genesis_authority) {
        return ValidationResult::fail("only genesis authority can mint");
    }
    if amount == 0 {
        return ValidationResult::fail("mint amount must be > 0");
    }
    match state.total_supply.checked_add(amount) {
        Some(new_supply) if new_supply > MAX_SUPPLY => {
            return ValidationResult::fail(format!(
                "would exceed max supply: {} + {} > {}",
                state.total_supply, amount, MAX_SUPPLY
            ));
        }
        None => {
            return ValidationResult::fail(format!(
                "mint would overflow: {} + {}",
                state.total_supply, amount
            ));
        }
        _ => {}
    }
    ValidationResult::ok()
}

/// Validate a transfer operation.
pub fn validate_transfer(
    state: &LedgerState,
    sender_identity_hash: &str,
    amount: u64,
    to: &str,
    current_timestamp: f64,
    genesis_authority: &str,
    enforce_rate_limits: bool,
) -> ValidationResult {
    if amount == 0 {
        return ValidationResult::fail("transfer amount must be > 0");
    }
    if sender_identity_hash == to {
        return ValidationResult::fail("cannot transfer to self");
    }
    let balance = state.balance(sender_identity_hash);
    if balance < amount {
        return ValidationResult::fail(format!(
            "insufficient balance: have {}, need {}",
            balance, amount
        ));
    }
    // Profile B (single-sig) transfer cap: max 1,000 beat per transaction
    if !is_privileged_emitter(sender_identity_hash, genesis_authority)
        && state.is_single_sig(sender_identity_hash)
        && amount > PROFILE_B_TRANSFER_CAP
    {
        return ValidationResult::fail(format!(
            "Profile B transfer cap exceeded: {} beat > {} beat. \
             Upgrade to Profile A (dual-sig) for higher limits.",
            format_beat_precise(amount), format_beat_precise(PROFILE_B_TRANSFER_CAP)
        ));
    }

    // Vesting + rate-limit checks (genesis authority exempt).
    if !is_privileged_emitter(sender_identity_hash, genesis_authority) {
        // Vesting check: sender must have enough unlocked balance. DETERMINISM:
        // `vesting` is `#[serde(default)]` (persisted, Track C) — a consensus-validity
        // rule, so it is enforced on EVERY record including synced/sealed ones and is
        // NOT gated by `enforce_rate_limits`.
        let transferable = state.vesting.transferable_balance(sender_identity_hash, balance, current_timestamp);
        if transferable < amount {
            return ValidationResult::fail(format!(
                "insufficient unlocked balance: {} available, {} locked by vesting, need {}",
                balance,
                state.vesting.locked_balance(sender_identity_hash, current_timestamp),
                amount
            ));
        }

        // Circuit breaker / velocity / acquisition are pure mempool-admission
        // (standardness) rate-limiters reading the `#[serde(skip)]` per-node trackers
        // (circuit_breaker / velocity / acquisition). They MUST NOT gate accept/reject
        // on the synced/sealed-record replay path: a snapshot-bootstrapped follower has
        // empty trackers (breaker Normal) while a since-genesis node may be saturated,
        // so a consensus read forks the two → divergent balances → account-SMT-root
        // fork (replay-determinism audit finding 3; completes Track D — apply_op already
        // dropped these, but validate_op still ran on synced records). `apply_op`
        // independently enforces the deterministic validity rules (balance,
        // conservation, vesting, authorization), so skipping standardness on replay is
        // safe. internal design notes.
        if enforce_rate_limits {
            // Exchange restrictions: classified exchanges get tighter limits.
            let exchange_restrictions = state.exchange_classifier.restrictions(sender_identity_hash);

            // Circuit breaker: may block large transfers entirely (exchanges at 2x
            // sensitivity). Integer-weighted exactly as in apply_op (ledger.rs) so the
            // validate-side reject decision is bit-identical.
            let circulating = state.circulating_supply();
            let weight_q = (exchange_restrictions.circuit_breaker_weight * 1_000_000_000.0) as u128;
            let weighted_amount =
                ((amount as u128).saturating_mul(weight_q) / 1_000_000_000).min(u64::MAX as u128) as u64;
            if let Err(e) = state
                .circuit_breaker
                .check_transfer(weighted_amount, circulating)
            {
                return ValidationResult::fail(e.to_string());
            }

            // Velocity check (halved by circuit breaker at L1/L2, exchange multiplier stacks)
            let account = state.account(sender_identity_hash);
            let multiplier = state.circuit_breaker.velocity_multiplier()
                * exchange_restrictions.velocity_multiplier;
            if let Err(e) = state.velocity.check_velocity(
                sender_identity_hash,
                amount,
                account.total(),
                current_timestamp,
                multiplier,
            ) {
                return ValidationResult::fail(e.to_string());
            }

            // Acquisition velocity: recipient must not exceed 0.5% of circulating per 30 days
            if let Err(e) = state.acquisition.check_acquisition(
                to, amount, circulating, current_timestamp, genesis_authority,
            ) {
                return ValidationResult::fail(e.to_string());
            }
        }
    }
    ValidationResult::ok()
}

/// Validate a stake operation.
pub fn validate_stake(
    state: &LedgerState,
    staker_identity_hash: &str,
    amount: u64,
    _purpose: &StakePurpose,
) -> ValidationResult {
    if amount < MIN_STAKE {
        return ValidationResult::fail(format!(
            "stake amount {} below minimum {}",
            amount, MIN_STAKE
        ));
    }
    let balance = state.balance(staker_identity_hash);
    if balance < amount {
        return ValidationResult::fail(format!(
            "insufficient balance for stake: have {}, need {}",
            balance, amount
        ));
    }
    ValidationResult::ok()
}

/// Validate an unstake operation.
pub fn validate_unstake(
    state: &LedgerState,
    actor_identity_hash: &str,
    stake_record_id: &str,
    current_timestamp: f64,
) -> ValidationResult {
    let stake = match state.stakes.get(stake_record_id) {
        Some(s) => s,
        None => return ValidationResult::fail(format!("stake not found: {stake_record_id}")),
    };

    if !stake.active {
        return ValidationResult::fail(format!(
            "stake already unstaked: {stake_record_id}"
        ));
    }

    if stake.staker != actor_identity_hash {
        return ValidationResult::fail("you do not own this stake");
    }

    let elapsed = current_timestamp - stake.timestamp;
    if elapsed < UNSTAKE_COOLDOWN {
        let remaining = UNSTAKE_COOLDOWN - elapsed;
        let days = remaining / 86400.0;
        return ValidationResult::fail(format!(
            "cooldown not elapsed: {days:.1} days remaining"
        ));
    }

    ValidationResult::ok()
}

/// Validate a witness reward operation.
///
/// Two modes:
/// - Genesis authority signs: funds drawn from conservation pool (auto-reward)
/// - Witness signs: funds drawn from payer account (manual claim)
pub fn validate_witness_reward(
    state: &LedgerState,
    actor_identity_hash: &str,
    genesis_authority: &str,
    amount: u64,
    from: &str,
    to: &str,
) -> ValidationResult {
    if amount == 0 {
        return ValidationResult::fail("witness reward must be > 0");
    }
    if amount > MAX_WITNESS_REWARD {
        return ValidationResult::fail(format!(
            "witness reward {} exceeds max {}",
            amount, MAX_WITNESS_REWARD
        ));
    }
    if from == to {
        return ValidationResult::fail("witness cannot reward self");
    }

    // SECURITY: Only genesis authority can create witness rewards.
    // Manual witness rewards removed — allowed theft via arbitrary beat_from.
    if !is_privileged_emitter(actor_identity_hash, genesis_authority) {
        return ValidationResult::fail("only genesis authority can create witness reward records");
    }

    if state.conservation_pool < amount {
        return ValidationResult::fail(format!(
            "conservation pool insufficient: have {}, need {}",
            state.conservation_pool, amount
        ));
    }
    ValidationResult::ok()
}

/// Validate any ledger operation from its parsed form.
/// `enforce_rate_limits`: true on fresh local/RPC submission (mempool admission),
/// false on the synced/sealed-record replay path. The circuit-breaker / velocity /
/// acquisition gates read `#[serde(skip)]` per-node trackers that a snapshot-
/// bootstrapped follower does not have, so running them as an accept/reject gate on
/// a sealed record forks the bootstrapped node from a since-genesis node. They are
/// pure mempool standardness (Bitcoin standardness-vs-validity): a sealed record is
/// applied identically by every node. See internal design notes
/// (Track D) + internal design notes (finding 3).
pub fn validate_op(
    state: &LedgerState,
    actor_identity_hash: &str,
    genesis_authority: &str,
    op: &ParsedLedgerOp,
    current_timestamp: f64,
    enforce_rate_limits: bool,
) -> ValidationResult {
    match op {
        ParsedLedgerOp::Mint { amount, to, .. } => {
            validate_mint(state, actor_identity_hash, genesis_authority, *amount, to)
        }
        ParsedLedgerOp::Transfer { amount, to, .. } => {
            validate_transfer(state, actor_identity_hash, *amount, to, current_timestamp, genesis_authority, enforce_rate_limits)
        }
        ParsedLedgerOp::Stake { amount, purpose } => {
            validate_stake(state, actor_identity_hash, *amount, purpose)
        }
        ParsedLedgerOp::Unstake { stake_record_id } => {
            validate_unstake(state, actor_identity_hash, stake_record_id, current_timestamp)
        }
        ParsedLedgerOp::WitnessReward { amount, from, to, .. } => {
            validate_witness_reward(state, actor_identity_hash, genesis_authority, *amount, from, to)
        }
        ParsedLedgerOp::Slash { amount, offender, stake_record_id, .. } => {
            validate_slash(state, actor_identity_hash, genesis_authority, *amount, offender, stake_record_id)
        }
        ParsedLedgerOp::DormancyReclaim { amount, dormant_identity, last_activity } => {
            validate_dormancy_reclaim(state, actor_identity_hash, genesis_authority, *amount, dormant_identity, *last_activity, current_timestamp)
        }
        ParsedLedgerOp::Burn { amount, .. } => {
            validate_burn(state, actor_identity_hash, genesis_authority, *amount)
        }
        ParsedLedgerOp::IdleDecay { batch } => {
            // Only the genesis authority may impose custodial idle_decay (same
            // model as Slash / Burn / WitnessReward / DormancyReclaim). Cheap
            // pre-flight: authorization + non-empty + conservation; the per-debit
            // balance checks run in apply_idle_decay_batch at apply time.
            if !is_privileged_emitter(actor_identity_hash, genesis_authority) {
                return ValidationResult::fail("only genesis authority can impose idle_decay");
            }
            if batch.is_empty() {
                return ValidationResult::fail("idle_decay batch is empty");
            }
            if !batch.is_conserved() {
                return ValidationResult::fail(
                    "idle_decay batch not conserved (Σ debits != pool + Σ stakers)",
                );
            }
            ValidationResult::ok()
        }
        ParsedLedgerOp::XZoneTimeoutRefund { batch }
        | ParsedLedgerOp::XZoneStaleReap { batch } => {
            // Only the genesis authority may un-lock a third party's expired
            // cross-zone transfer (same model as IdleDecay). Cheap pre-flight:
            // authorization + non-empty. There is no batch conservation predicate
            // — a refund/reap is a 1:1 un-lock, not a redistribution; per-entry
            // eligibility is re-checked at apply time against replicated `pending`
            // (skip-missing). internal design notes.
            if !is_privileged_emitter(actor_identity_hash, genesis_authority) {
                return ValidationResult::fail(
                    "only genesis authority can emit xzone timeout refund / stale reap",
                );
            }
            if batch.is_empty() {
                return ValidationResult::fail("xzone timeout refund / reap batch is empty");
            }
            ValidationResult::ok()
        }
        ParsedLedgerOp::PoolFund { amount } => {
            if !is_privileged_emitter(actor_identity_hash, genesis_authority) {
                return ValidationResult::fail("only genesis authority can fund pool");
            }
            if *amount == 0 {
                return ValidationResult::fail("pool_fund amount must be > 0");
            }
            let account = state.accounts.get(actor_identity_hash);
            let available = account.map(|a| a.available).unwrap_or(0);
            if available < *amount {
                return ValidationResult::fail("insufficient balance for pool_fund");
            }
            ValidationResult::ok()
        }
        ParsedLedgerOp::Predict { amount, zone, target_epoch: _, claim: _, predicted_value: _ } => {
            let is_sandbox = zone.starts_with("sandbox/") || zone == "sandbox";
            if !is_sandbox && *amount < crate::accounting::types::MIN_PREDICTION_STAKE {
                return ValidationResult::fail("prediction stake below minimum (use sandbox/ zone for free)");
            }
            if *amount > 0 {
                let account = state.accounts.get(actor_identity_hash);
                let available = account.map(|a| a.available).unwrap_or(0);
                if available < *amount {
                    return ValidationResult::fail("insufficient balance for prediction");
                }
            }
            ValidationResult::ok()
        }
        ParsedLedgerOp::XZoneLock { amount, source_zone, dest_zone, .. } => {
            if source_zone == dest_zone {
                return ValidationResult::fail("cross-zone lock: source and dest zones must differ");
            }
            if *amount == 0 {
                return ValidationResult::fail("cross-zone lock: amount must be > 0");
            }
            let account = state.accounts.get(actor_identity_hash);
            let available = account.map(|a| a.available).unwrap_or(0);
            if available < *amount {
                return ValidationResult::fail("insufficient balance for cross-zone lock");
            }
            // Cross-zone velocity (mempool standardness). Mirrors the rate-limit reject
            // demoted out of apply_op (Track D, internal design notes):
            // classified exchanges are velocity-limited on cross-zone transfers too. Lives
            // here (not apply_op) because velocity is a per-node #[serde(skip)] tracker — a
            // consensus read of it forks bootstrapped vs since-genesis nodes. Gated by
            // `enforce_rate_limits` so it is skipped on the synced/sealed replay path
            // (replay-audit finding 3, same reason as the in-zone rate-limiters).
            if enforce_rate_limits
                && !is_privileged_emitter(actor_identity_hash, genesis_authority)
                && state.exchange_classifier.is_classified(actor_identity_hash)
            {
                let restrictions = state.exchange_classifier.restrictions(actor_identity_hash);
                let sender_total = account.map(|a| a.total()).unwrap_or(0);
                let multiplier = state.circuit_breaker.velocity_multiplier()
                    * restrictions.velocity_multiplier;
                if let Err(e) = state.velocity.check_velocity(
                    actor_identity_hash,
                    *amount,
                    sender_total,
                    current_timestamp,
                    multiplier,
                ) {
                    return ValidationResult::fail(e.to_string());
                }
            }
            ValidationResult::ok()
        }
        ParsedLedgerOp::XZoneClaim { transfer_id, amount, .. } => {
            if *amount == 0 {
                return ValidationResult::fail("cross-zone claim: amount must be > 0");
            }
            // SECURITY (conservation, defense-in-depth): if the locked transfer is
            // already known locally, the claim's wire amount MUST equal the locked
            // amount. apply_op credits the authoritative locked amount regardless
            // (the load-bearing guard), but rejecting a mismatched claim here stops
            // an inflated record from ever being written or gossiped. When the lock
            // is not yet known locally (sync ordering), defer to apply-time
            // claim_transfer rather than fail-closed, to avoid starving a legitimate
            // claim that races ahead of its lock — mirrors XZoneCancel/Reject.
            if let Some(t) = state.cross_zone.pending.get(transfer_id.as_str()) {
                if *amount != t.amount {
                    return ValidationResult::fail(
                        "cross-zone claim: amount does not match the locked transfer",
                    );
                }
            }
            // Remaining claim validation is handled in apply_op — the lock must
            // exist and the claimer must be the authorized recipient.
            ValidationResult::ok()
        }
        ParsedLedgerOp::XZoneCancel { transfer_id } => {
            // Gap 2 atomic-rollback. Authorization (creator == sender) and
            // unsealed-state checks are enforced in `cross_zone::cancel_transfer`
            // at apply time; here we only sanity-check the transfer exists at
            // validate time. Pre-empting unknown-id submissions saves a
            // pointless ledger write.
            if transfer_id.is_empty() {
                return ValidationResult::fail("cross-zone cancel: transfer_id required");
            }
            if !state.cross_zone.pending.contains_key(transfer_id) {
                return ValidationResult::fail("cross-zone cancel: transfer not found");
            }
            ValidationResult::ok()
        }
        ParsedLedgerOp::XZoneReject { transfer_id } => {
            // Mirror of XZoneCancel — recipient-initiated. Authorization
            // (creator == recipient) and unsealed-state checks enforced in
            // `cross_zone::reject_transfer` at apply time.
            if transfer_id.is_empty() {
                return ValidationResult::fail("cross-zone reject: transfer_id required");
            }
            if !state.cross_zone.pending.contains_key(transfer_id) {
                return ValidationResult::fail("cross-zone reject: transfer not found");
            }
            ValidationResult::ok()
        }
        ParsedLedgerOp::XZoneAbort {
            transfer_id,
            dest_committee_hash,
            dest_committee_size,
            signers,
        } => {
            // Gap 2 sealed-abort: cheap pre-flight. The full
            // proof + sealed-state gate runs in apply_op; here we reject
            // submissions that obviously can't apply, to save the ledger
            // write for an immediately-doomed record.
            if transfer_id.is_empty() {
                return ValidationResult::fail("cross-zone abort: transfer_id required");
            }
            if *dest_committee_size == 0 {
                return ValidationResult::fail("cross-zone abort: dest_committee_size must be > 0");
            }
            if signers.is_empty() {
                return ValidationResult::fail("cross-zone abort: signers required");
            }
            let pending = match state.cross_zone.pending.get(transfer_id) {
                Some(p) => p,
                None => return ValidationResult::fail("cross-zone abort: transfer not found"),
            };
            if pending.status != crate::accounting::cross_zone::TransferStatus::Locked {
                return ValidationResult::fail("cross-zone abort: transfer not in Locked state");
            }
            if pending.merkle_proof.is_empty() || pending.source_seal_epoch == 0 {
                return ValidationResult::fail("cross-zone abort: transfer not sealed yet (use cancel/reject)");
            }
            // Run the full cryptographic verification at validate-time too —
            // it's pure and the apply path will run it again, but rejecting
            // bad-proof records before sealing them into a record is the
            // whole point of validate.
            if let Err(e) = crate::accounting::cross_zone::verify_abort_quorum(
                transfer_id,
                &pending.dest_zone,
                pending.source_seal_epoch,
                dest_committee_hash,
                *dest_committee_size,
                signers,
                // B2 fix: gate against the canonical dest-committee anchor frozen
                // from the source seal (fail-closed when absent).
                pending.dest_finality_committee,
            ) {
                return ValidationResult::fail(format!(
                    "cross-zone abort: proof rejected: {e}"
                ));
            }
            ValidationResult::ok()
        }
        ParsedLedgerOp::DormancyDeclare { target_identity, last_known_active } => {
            validate_dormancy_declare(state, target_identity, *last_known_active, current_timestamp)
        }
        ParsedLedgerOp::DormancyHeartbeat => {
            // Creator must currently be in Dormant phase; enforced in apply_op via
            // state.dormancy.wake_up. No balance or authority requirement here.
            match state.dormancy.phase(actor_identity_hash) {
                crate::accounting::dormancy::DormancyPhase::Dormant => ValidationResult::ok(),
                crate::accounting::dormancy::DormancyPhase::Active => {
                    ValidationResult::fail("heartbeat rejected: identity is already Active")
                }
                crate::accounting::dormancy::DormancyPhase::Reclaimed => {
                    ValidationResult::fail("heartbeat rejected: identity already Reclaimed")
                }
            }
        }
        ParsedLedgerOp::DormancyProofOfLife { target_identity, .. } => {
            match state.dormancy.phase(target_identity) {
                crate::accounting::dormancy::DormancyPhase::Dormant => ValidationResult::ok(),
                crate::accounting::dormancy::DormancyPhase::Active => {
                    ValidationResult::fail("proof_of_life rejected: target is already Active")
                }
                crate::accounting::dormancy::DormancyPhase::Reclaimed => {
                    ValidationResult::fail("proof_of_life rejected: target already Reclaimed")
                }
            }
        }
        ParsedLedgerOp::WitnessRegister { zone_path, bond } => {
            // Bond floor is enforced at parse time; re-check anyway in case the
            // op was constructed by hand. Validate available-balance coverage
            // here so the ingest pipeline rejects underfunded registrations
            // before they hit the consensus layer.
            if *bond < crate::accounting::types::WITNESS_BOND_MIN {
                return ValidationResult::fail("witness_register: bond below minimum");
            }
            if zone_path.is_empty() {
                return ValidationResult::fail("witness_register: zone_path empty");
            }
            let account = state.accounts.get(actor_identity_hash);
            let available = account.map(|a| a.available).unwrap_or(0);
            if available < *bond {
                return ValidationResult::fail("witness_register: insufficient balance");
            }
            ValidationResult::ok()
        }
    }
}

/// Pre-flight validation for a slash operation.
pub fn validate_slash(
    state: &LedgerState,
    actor: &str,
    genesis_authority: &str,
    amount: u64,
    offender: &str,
    stake_record_id: &str,
) -> ValidationResult {
    if !is_privileged_emitter(actor, genesis_authority) {
        return ValidationResult::fail("only genesis authority can slash");
    }
    if amount == 0 {
        return ValidationResult::fail("slash amount must be > 0");
    }
    let stake = match state.stakes.get(stake_record_id) {
        Some(s) => s,
        None => return ValidationResult::fail("stake not found"),
    };
    if !stake.active {
        return ValidationResult::fail("stake is not active");
    }
    if stake.staker != offender {
        return ValidationResult::fail("offender does not own stake");
    }
    // Amount will be capped at MAX_SLASH_PERCENTAGE during execution
    ValidationResult::ok()
}

/// Pre-flight validation for a dormancy reclaim operation.
pub fn validate_dormancy_reclaim(
    state: &LedgerState,
    actor: &str,
    genesis_authority: &str,
    amount: u64,
    dormant_identity: &str,
    last_activity: f64,
    current_timestamp: f64,
) -> ValidationResult {
    if !is_privileged_emitter(actor, genesis_authority) {
        return ValidationResult::fail("only genesis authority can reclaim dormant beats");
    }
    if amount == 0 {
        return ValidationResult::fail("reclaim amount must be > 0");
    }
    let account = match state.accounts.get(dormant_identity) {
        Some(a) => a,
        None => return ValidationResult::fail("dormant identity not found"),
    };
    if account.available == 0 {
        return ValidationResult::fail("dormant identity has no available balance");
    }
    let time_since_active = current_timestamp - account.last_active;
    if time_since_active < DORMANCY_THRESHOLD {
        return ValidationResult::fail(format!(
            "identity not dormant: last active {:.0}s ago, threshold {:.0}s",
            time_since_active, DORMANCY_THRESHOLD
        ));
    }
    if (last_activity - account.last_active).abs() > 1.0 {
        return ValidationResult::fail("last_activity timestamp mismatch");
    }
    // AUDIT-3: require Phase 2 declaration exists + Phase 3 wake-up window expired
    match state.dormancy.phase(dormant_identity) {
        crate::accounting::dormancy::DormancyPhase::Active => {
            return ValidationResult::fail(
                "reclaim rejected: no DormancyDeclare for this identity (Phase 2 required)",
            );
        }
        crate::accounting::dormancy::DormancyPhase::Reclaimed => {
            return ValidationResult::fail("reclaim rejected: already reclaimed");
        }
        crate::accounting::dormancy::DormancyPhase::Dormant => {}
    }
    if !state.dormancy.eligible_for_reclamation(dormant_identity, current_timestamp) {
        return ValidationResult::fail(
            "reclaim rejected: wake-up window has not yet expired",
        );
    }
    // Amount will be capped at available balance during execution
    ValidationResult::ok()
}

/// Pre-flight validation for a dormancy declare operation (Phase 2).
pub fn validate_dormancy_declare(
    state: &LedgerState,
    target_identity: &str,
    last_known_active: f64,
    current_timestamp: f64,
) -> ValidationResult {
    let account = match state.accounts.get(target_identity) {
        Some(a) => a,
        None => return ValidationResult::fail("declare target not found"),
    };
    match state.dormancy.phase(target_identity) {
        crate::accounting::dormancy::DormancyPhase::Active => {}
        crate::accounting::dormancy::DormancyPhase::Dormant => {
            return ValidationResult::fail("declare rejected: identity already declared dormant");
        }
        crate::accounting::dormancy::DormancyPhase::Reclaimed => {
            return ValidationResult::fail("declare rejected: identity already reclaimed");
        }
    }
    let time_since_active = current_timestamp - account.last_active;
    if time_since_active < DORMANCY_THRESHOLD {
        return ValidationResult::fail(format!(
            "declare rejected: target not dormant yet (last active {:.0}s ago, need {:.0}s)",
            time_since_active, DORMANCY_THRESHOLD
        ));
    }
    if (last_known_active - account.last_active).abs() > 1.0 {
        return ValidationResult::fail("last_known_active mismatch");
    }
    ValidationResult::ok()
}

/// Pre-flight validation for a burn operation.
///
/// Burn redirects beats to the Conservation Pool (preserving conservation invariant).
/// Restricted to genesis authority only — prevents arbitrary supply manipulation.
pub fn validate_burn(
    state: &LedgerState,
    burner_identity_hash: &str,
    genesis_authority: &str,
    amount: u64,
) -> ValidationResult {
    if !is_privileged_emitter(burner_identity_hash, genesis_authority) {
        return ValidationResult::fail("only genesis authority can execute burn (beats redirect to Conservation Pool)");
    }
    if amount == 0 {
        return ValidationResult::fail("burn amount must be > 0");
    }
    let balance = state.balance(burner_identity_hash);
    if balance < amount {
        return ValidationResult::fail(format!(
            "insufficient balance for burn: have {}, need {}",
            balance, amount
        ));
    }
    ValidationResult::ok()
}

/// Check if an identity has sufficient balance for a transfer or stake.
pub fn check_balance(
    state: &LedgerState,
    identity_hash: &str,
    amount: u64,
) -> Result<()> {
    let balance = state.balance(identity_hash);
    if balance < amount {
        return Err(ElaraError::Ledger(format!(
            "insufficient balance: have {} base units (10^9 = 1 beat), need {}",
            balance, amount
        )));
    }
    Ok(())
}

/// Validate a governance parameter name (recognized by GovernableParams).
pub fn validate_governance_param_name(name: &str) -> ValidationResult {
    if crate::accounting::governance::GOVERNABLE_PARAMS.contains(&name) {
        ValidationResult::ok()
    } else {
        ValidationResult::fail(format!("unrecognized governance parameter: {name}"))
    }
}

/// Validate a governance operation against current ledger + governance state.
pub fn validate_governance_op(
    state: &LedgerState,
    actor_identity_hash: &str,
    op: &crate::accounting::governance::ParsedGovernanceOp,
    current_timestamp: f64,
) -> ValidationResult {
    use crate::accounting::governance::{self, ParsedGovernanceOp, ProposalStatus, MIN_PROPOSAL_STAKE, MAX_ACTIVE_PROPOSALS_PER_IDENTITY};

    match op {
        ParsedGovernanceOp::Propose { .. } => {
            let gov_stake = governance::governance_stake_for(&state.stakes, actor_identity_hash);
            if gov_stake < MIN_PROPOSAL_STAKE {
                return ValidationResult::fail(format!(
                    "insufficient governance stake to propose: have {}, need {}",
                    gov_stake, MIN_PROPOSAL_STAKE
                ));
            }
            let active_count = state.governance.active_proposals_by(actor_identity_hash);
            if active_count >= MAX_ACTIVE_PROPOSALS_PER_IDENTITY {
                return ValidationResult::fail(format!(
                    "too many active proposals: {} (max {})",
                    active_count, MAX_ACTIVE_PROPOSALS_PER_IDENTITY
                ));
            }
            ValidationResult::ok()
        }
        ParsedGovernanceOp::Vote { proposal_id, .. } => {
            let proposal = match state.governance.proposals.get(proposal_id.as_str()) {
                Some(p) => p,
                None => return ValidationResult::fail(format!("proposal not found: {proposal_id}")),
            };
            if !proposal.is_voting_open(current_timestamp) {
                return ValidationResult::fail("voting period has ended or proposal is not active");
            }
            if proposal.has_voted(actor_identity_hash) {
                return ValidationResult::fail(format!(
                    "identity {actor_identity_hash} has already voted on {proposal_id}"
                ));
            }
            let gov_stake = governance::governance_stake_for(&state.stakes, actor_identity_hash);
            if gov_stake == 0 {
                return ValidationResult::fail("must have governance stake to vote");
            }
            ValidationResult::ok()
        }
        ParsedGovernanceOp::Execute { proposal_id } => {
            let proposal = match state.governance.proposals.get(proposal_id.as_str()) {
                Some(p) => p,
                None => return ValidationResult::fail(format!("proposal not found: {proposal_id}")),
            };
            if proposal.status != ProposalStatus::Passed {
                return ValidationResult::fail("proposal has not passed");
            }
            if !proposal.can_execute(current_timestamp) {
                return ValidationResult::fail("execution delay has not elapsed");
            }
            ValidationResult::ok()
        }
        ParsedGovernanceOp::Cancel { proposal_id } => {
            let proposal = match state.governance.proposals.get(proposal_id.as_str()) {
                Some(p) => p,
                None => return ValidationResult::fail(format!("proposal not found: {proposal_id}")),
            };
            if proposal.status != ProposalStatus::Active {
                return ValidationResult::fail("can only cancel active proposals");
            }
            if proposal.proposer != actor_identity_hash {
                return ValidationResult::fail("only the proposer can cancel");
            }
            ValidationResult::ok()
        }
        ParsedGovernanceOp::Delegate { delegate } => {
            if actor_identity_hash == delegate {
                return ValidationResult::fail("cannot delegate to self");
            }
            let gov_stake = governance::governance_stake_for(&state.stakes, actor_identity_hash);
            if gov_stake == 0 {
                return ValidationResult::fail("must have governance stake to delegate");
            }
            // Check for existing active delegation
            if let Some(existing) = state.governance.delegation_of(actor_identity_hash) {
                return ValidationResult::fail(format!(
                    "already delegated to {}; undelegate first",
                    existing.delegate
                ));
            }
            // Cycle check
            if let Some(del_entry) = state.governance.delegation_of(delegate) {
                if del_entry.delegate == actor_identity_hash {
                    return ValidationResult::fail(
                        "circular delegation: delegate has already delegated to you"
                    );
                }
            }
            ValidationResult::ok()
        }
        ParsedGovernanceOp::Undelegate => {
            if state.governance.delegation_of(actor_identity_hash).is_none() {
                return ValidationResult::fail("no active delegation to remove");
            }
            ValidationResult::ok()
        }
    }
}

/// Summary of ledger state for display.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LedgerSummary {
    pub total_supply_micros: u64,
    pub total_supply_beat: f64,
    pub total_staked_micros: u64,
    pub total_staked_beat: f64,
    pub circulating_micros: u64,
    pub circulating_beat: f64,
    pub conservation_pool_micros: u64,
    pub conservation_pool_beat: f64,
    pub pool_cap_micros: u64,
    pub num_accounts: usize,
    pub num_active_stakes: usize,
    pub records_processed: u64,
}

/// Format base units as a precise decimal string (no f64 precision loss).
/// e.g. 10_000_000_000_000_000_000 → "10000000000.000000000"
pub fn format_beat_precise(micros: u64) -> String {
    let whole = micros / BASE_UNITS_PER_BEAT;
    let frac = micros % BASE_UNITS_PER_BEAT;
    if frac == 0 {
        format!("{whole}.0")
    } else {
        // Trim trailing zeros for cleaner output
        let frac_str = format!("{:09}", frac);
        let trimmed = frac_str.trim_end_matches('0');
        format!("{whole}.{trimmed}")
    }
}

/// Generate a summary of the current ledger state.
pub fn summarize(state: &LedgerState) -> LedgerSummary {
    let circulating = state.total_supply - state.total_staked - state.conservation_pool;
    // B10: O(1) maintained counter instead of an O(all_stakes) scan under the
    // ledger read lock (`summarize` is hit on every `/network` request).
    let active_stakes = state.active_stakes_count as usize;

    LedgerSummary {
        total_supply_micros: state.total_supply,
        total_supply_beat: state.total_supply as f64 / BASE_UNITS_PER_BEAT as f64,
        total_staked_micros: state.total_staked,
        total_staked_beat: state.total_staked as f64 / BASE_UNITS_PER_BEAT as f64,
        circulating_micros: circulating,
        circulating_beat: circulating as f64 / BASE_UNITS_PER_BEAT as f64,
        conservation_pool_micros: state.conservation_pool,
        conservation_pool_beat: state.conservation_pool as f64 / BASE_UNITS_PER_BEAT as f64,
        pool_cap_micros: state.pool_cap(),
        num_accounts: state.accounts.len(),
        num_active_stakes: active_stakes,
        records_processed: state.records_processed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::ledger::LedgerState;

    fn genesis_hash() -> String {
        "genesis_authority_hash".to_string()
    }

    fn alice_hash() -> String {
        "alice_hash".to_string()
    }

    fn bob_hash() -> String {
        "bob_hash".to_string()
    }

    fn state_with_balance(identity: &str, amount: u64) -> LedgerState {
        let mut state = LedgerState::new();
        let account = state.accounts.entry(identity.to_string()).or_default();
        account.available = amount;
        state.total_supply = amount;
        state
    }

    #[test]
    fn test_validate_mint_ok() {
        let state = LedgerState::new();
        let r = validate_mint(&state, &genesis_hash(), &genesis_hash(), 1_000, &alice_hash());
        assert!(r.valid);
    }

    #[test]
    fn test_validate_mint_unauthorized() {
        let state = LedgerState::new();
        let r = validate_mint(&state, &alice_hash(), &genesis_hash(), 1_000, &alice_hash());
        assert!(!r.valid);
    }

    #[test]
    fn test_validate_mint_zero() {
        let state = LedgerState::new();
        let r = validate_mint(&state, &genesis_hash(), &genesis_hash(), 0, &alice_hash());
        assert!(!r.valid);
    }

    #[test]
    fn test_validate_transfer_ok() {
        let state = state_with_balance(&alice_hash(), 1_000);
        let r = validate_transfer(&state, &alice_hash(), 500, &bob_hash(), 1000.0, &genesis_hash(), true);
        assert!(r.valid);
    }

    #[test]
    fn test_validate_transfer_overdraft() {
        let state = state_with_balance(&alice_hash(), 100);
        let r = validate_transfer(&state, &alice_hash(), 500, &bob_hash(), 1000.0, &genesis_hash(), true);
        assert!(!r.valid);
    }

    #[test]
    fn test_validate_transfer_zero() {
        let state = state_with_balance(&alice_hash(), 1_000);
        let r = validate_transfer(&state, &alice_hash(), 0, &bob_hash(), 1000.0, &genesis_hash(), true);
        assert!(!r.valid);
    }

    #[test]
    fn test_validate_transfer_self() {
        let state = state_with_balance(&alice_hash(), 1_000);
        let r = validate_transfer(&state, &alice_hash(), 100, &alice_hash(), 1000.0, &genesis_hash(), true);
        assert!(!r.valid);
    }

    #[test]
    fn test_validate_stake_ok() {
        let state = state_with_balance(&alice_hash(), 500 * BASE_UNITS_PER_BEAT);
        let r = validate_stake(&state, &alice_hash(), 200 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        assert!(r.valid);
    }

    #[test]
    fn test_validate_stake_below_min() {
        let state = state_with_balance(&alice_hash(), 500 * BASE_UNITS_PER_BEAT);
        let r = validate_stake(&state, &alice_hash(), 50 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        assert!(!r.valid);
    }

    #[test]
    fn test_validate_unstake_ok() {
        let mut state = state_with_balance(&alice_hash(), 0);
        let account = state.accounts.get_mut(&alice_hash()).unwrap();
        account.staked = 200 * BASE_UNITS_PER_BEAT;

        state.stakes.insert(
            "stake-1".into(),
            crate::accounting::ledger::StakeEntry {
                record_id: "stake-1".into(),
                amount: 200 * BASE_UNITS_PER_BEAT,
                purpose: StakePurpose::Witness,
                staker: alice_hash(),
                timestamp: 1000.0,
                active: true,
            },
        );

        // After cooldown
        let r = validate_unstake(&state, &alice_hash(), "stake-1", 1000.0 + UNSTAKE_COOLDOWN + 1.0);
        assert!(r.valid);
    }

    #[test]
    fn test_validate_unstake_too_early() {
        let mut state = LedgerState::new();
        state.stakes.insert(
            "stake-1".into(),
            crate::accounting::ledger::StakeEntry {
                record_id: "stake-1".into(),
                amount: 200 * BASE_UNITS_PER_BEAT,
                purpose: StakePurpose::Witness,
                staker: alice_hash(),
                timestamp: 1000.0,
                active: true,
            },
        );

        let r = validate_unstake(&state, &alice_hash(), "stake-1", 1001.0);
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("cooldown"));
    }

    #[test]
    fn test_validate_unstake_wrong_owner() {
        let mut state = LedgerState::new();
        state.stakes.insert(
            "stake-1".into(),
            crate::accounting::ledger::StakeEntry {
                record_id: "stake-1".into(),
                amount: 200 * BASE_UNITS_PER_BEAT,
                purpose: StakePurpose::Witness,
                staker: alice_hash(),
                timestamp: 1000.0,
                active: true,
            },
        );

        let r = validate_unstake(&state, &bob_hash(), "stake-1", 1000.0 + UNSTAKE_COOLDOWN + 1.0);
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("own"));
    }

    #[test]
    fn test_validate_witness_reward_ok() {
        let mut state = state_with_balance(&alice_hash(), 100 * BASE_UNITS_PER_BEAT);
        state.conservation_pool = 10 * BASE_UNITS_PER_BEAT;
        // Only genesis can create witness rewards
        let r = validate_witness_reward(&state, &genesis_hash(), &genesis_hash(), BASE_UNITS_PER_BEAT, &genesis_hash(), &bob_hash());
        assert!(r.valid);
    }

    #[test]
    fn test_validate_witness_reward_exceeds_max() {
        let mut state = state_with_balance(&alice_hash(), 100 * BASE_UNITS_PER_BEAT);
        state.conservation_pool = 100 * BASE_UNITS_PER_BEAT;
        let r = validate_witness_reward(&state, &genesis_hash(), &genesis_hash(), 11 * BASE_UNITS_PER_BEAT, &genesis_hash(), &bob_hash());
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("exceeds max"));
    }

    #[test]
    fn test_validate_witness_reward_self() {
        let mut state = state_with_balance(&alice_hash(), 100 * BASE_UNITS_PER_BEAT);
        state.conservation_pool = 10 * BASE_UNITS_PER_BEAT;
        let r = validate_witness_reward(&state, &genesis_hash(), &genesis_hash(), BASE_UNITS_PER_BEAT, &genesis_hash(), &genesis_hash());
        assert!(!r.valid);
    }

    #[test]
    fn test_validate_witness_reward_non_genesis_rejected() {
        let state = state_with_balance(&alice_hash(), 100 * BASE_UNITS_PER_BEAT);
        // Non-genesis signer should be rejected
        let r = validate_witness_reward(&state, &bob_hash(), &genesis_hash(), BASE_UNITS_PER_BEAT, &alice_hash(), &bob_hash());
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("genesis authority"));
    }

    #[test]
    fn test_validate_witness_reward_genesis_from_pool() {
        let mut state = state_with_balance(&alice_hash(), 100 * BASE_UNITS_PER_BEAT);
        state.conservation_pool = 5 * BASE_UNITS_PER_BEAT;
        // Genesis authority signs reward from pool to bob
        let r = validate_witness_reward(&state, &genesis_hash(), &genesis_hash(), BASE_UNITS_PER_BEAT, &alice_hash(), &bob_hash());
        assert!(r.valid);
    }

    #[test]
    fn test_validate_witness_reward_genesis_pool_insufficient() {
        let mut state = state_with_balance(&alice_hash(), 100 * BASE_UNITS_PER_BEAT);
        state.conservation_pool = 0;
        let r = validate_witness_reward(&state, &genesis_hash(), &genesis_hash(), BASE_UNITS_PER_BEAT, &alice_hash(), &bob_hash());
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("conservation pool"));
    }

    #[test]
    fn test_summarize() {
        let mut state = state_with_balance(&alice_hash(), 800 * BASE_UNITS_PER_BEAT);
        let account = state.accounts.get_mut(&alice_hash()).unwrap();
        account.staked = 200 * BASE_UNITS_PER_BEAT;
        state.total_supply = 1_000 * BASE_UNITS_PER_BEAT;
        state.total_staked = 200 * BASE_UNITS_PER_BEAT;
        state.records_processed = 5;

        let summary = summarize(&state);
        assert_eq!(summary.total_supply_beat, 1_000.0);
        assert_eq!(summary.total_staked_beat, 200.0);
        assert_eq!(summary.circulating_beat, 800.0);
        assert_eq!(summary.num_accounts, 1);
    }

    // ─── Burn Validation Tests ────────────────────────────────────────

    #[test]
    fn test_validate_burn_ok() {
        let state = state_with_balance(&genesis_hash(), 1_000 * BASE_UNITS_PER_BEAT);
        let r = validate_burn(&state, &genesis_hash(), &genesis_hash(), 500 * BASE_UNITS_PER_BEAT);
        assert!(r.valid);
    }

    #[test]
    fn test_validate_burn_non_genesis_rejected() {
        let state = state_with_balance(&alice_hash(), 1_000 * BASE_UNITS_PER_BEAT);
        let r = validate_burn(&state, &alice_hash(), &genesis_hash(), 500 * BASE_UNITS_PER_BEAT);
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("genesis authority"));
    }

    #[test]
    fn test_validate_burn_zero() {
        let state = state_with_balance(&genesis_hash(), 1_000 * BASE_UNITS_PER_BEAT);
        let r = validate_burn(&state, &genesis_hash(), &genesis_hash(), 0);
        assert!(!r.valid);
    }

    #[test]
    fn test_validate_burn_insufficient() {
        let state = state_with_balance(&genesis_hash(), 100 * BASE_UNITS_PER_BEAT);
        let r = validate_burn(&state, &genesis_hash(), &genesis_hash(), 500 * BASE_UNITS_PER_BEAT);
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("insufficient"));
    }

    // ─── Governance Validation Tests ─────────────────────────────────

    fn state_with_governance_stake(identity: &str, amount: u64) -> LedgerState {
        let mut state = LedgerState::new();
        let account = state.accounts.entry(identity.to_string()).or_default();
        account.staked = amount;
        state.total_supply = amount;
        state.total_staked = amount;
        state.stakes.insert(
            "gov-stake-1".into(),
            crate::accounting::ledger::StakeEntry {
                record_id: "gov-stake-1".into(),
                amount,
                purpose: StakePurpose::Governance,
                staker: identity.to_string(),
                timestamp: 0.0,
                active: true,
            },
        );
        state
    }

    #[test]
    fn test_validate_governance_propose_ok() {
        use crate::accounting::governance::{ParsedGovernanceOp, ProposalCategory};
        let state = state_with_governance_stake(&alice_hash(), 2_000 * BASE_UNITS_PER_BEAT);
        let op = ParsedGovernanceOp::Propose {
            category: ProposalCategory::Parameter,
            title: "Test".into(),
            description: "Test desc".into(),
        };
        let r = validate_governance_op(&state, &alice_hash(), &op, 1000.0);
        assert!(r.valid);
    }

    #[test]
    fn test_validate_governance_propose_insufficient_stake() {
        use crate::accounting::governance::{ParsedGovernanceOp, ProposalCategory};
        let state = state_with_governance_stake(&alice_hash(), 500 * BASE_UNITS_PER_BEAT);
        let op = ParsedGovernanceOp::Propose {
            category: ProposalCategory::Parameter,
            title: "Test".into(),
            description: "Test desc".into(),
        };
        let r = validate_governance_op(&state, &alice_hash(), &op, 1000.0);
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("insufficient"));
    }

    #[test]
    fn test_validate_governance_vote_ok() {
        use crate::accounting::governance::{ParsedGovernanceOp, VoteDirection, ProposalCategory};
        let mut state = state_with_governance_stake(&bob_hash(), 1_000 * BASE_UNITS_PER_BEAT);
        // Add a proposal
        state.governance.create_proposal(
            "prop-001".into(), &alice_hash(), ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();
        let op = ParsedGovernanceOp::Vote {
            proposal_id: "prop-001".into(),
            direction: VoteDirection::For,
        };
        let r = validate_governance_op(&state, &bob_hash(), &op, 1000.0 + 86400.0);
        assert!(r.valid);
    }

    #[test]
    fn test_validate_governance_vote_no_stake() {
        use crate::accounting::governance::{ParsedGovernanceOp, VoteDirection, ProposalCategory};
        let mut state = LedgerState::new();
        state.governance.create_proposal(
            "prop-001".into(), &alice_hash(), ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();
        let op = ParsedGovernanceOp::Vote {
            proposal_id: "prop-001".into(),
            direction: VoteDirection::For,
        };
        let r = validate_governance_op(&state, &bob_hash(), &op, 1000.0 + 86400.0);
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("governance stake"));
    }

    #[test]
    fn test_validate_governance_vote_after_deadline() {
        use crate::accounting::governance::{ParsedGovernanceOp, VoteDirection, ProposalCategory, VOTING_PERIOD_SECS};
        let mut state = state_with_governance_stake(&bob_hash(), 1_000 * BASE_UNITS_PER_BEAT);
        state.governance.create_proposal(
            "prop-001".into(), &alice_hash(), ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();
        let op = ParsedGovernanceOp::Vote {
            proposal_id: "prop-001".into(),
            direction: VoteDirection::For,
        };
        let r = validate_governance_op(&state, &bob_hash(), &op, 1000.0 + VOTING_PERIOD_SECS + 1.0);
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("ended"));
    }

    #[test]
    fn test_validate_governance_vote_double() {
        use crate::accounting::governance::{ParsedGovernanceOp, VoteDirection, ProposalCategory};
        let mut state = state_with_governance_stake(&bob_hash(), 1_000 * BASE_UNITS_PER_BEAT);
        state.governance.create_proposal(
            "prop-001".into(), &alice_hash(), ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();
        // First vote succeeds
        state.governance.cast_vote("prop-001", &bob_hash(), VoteDirection::For, 1_000 * BASE_UNITS_PER_BEAT, 1001.0).unwrap();
        // Second vote fails validation
        let op = ParsedGovernanceOp::Vote {
            proposal_id: "prop-001".into(),
            direction: VoteDirection::Against,
        };
        let r = validate_governance_op(&state, &bob_hash(), &op, 1002.0);
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("already voted"));
    }

    #[test]
    fn test_validate_governance_cancel_ok() {
        use crate::accounting::governance::{ParsedGovernanceOp, ProposalCategory};
        let mut state = LedgerState::new();
        state.governance.create_proposal(
            "prop-001".into(), &alice_hash(), ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();
        let op = ParsedGovernanceOp::Cancel { proposal_id: "prop-001".into() };
        let r = validate_governance_op(&state, &alice_hash(), &op, 1001.0);
        assert!(r.valid);
    }

    #[test]
    fn test_validate_governance_cancel_wrong_proposer() {
        use crate::accounting::governance::{ParsedGovernanceOp, ProposalCategory};
        let mut state = LedgerState::new();
        state.governance.create_proposal(
            "prop-001".into(), &alice_hash(), ProposalCategory::Parameter,
            "T".into(), "D".into(), 2_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
        ).unwrap();
        let op = ParsedGovernanceOp::Cancel { proposal_id: "prop-001".into() };
        let r = validate_governance_op(&state, &bob_hash(), &op, 1001.0);
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("proposer"));
    }

    #[test]
    fn test_validate_governance_vote_nonexistent_proposal() {
        use crate::accounting::governance::{ParsedGovernanceOp, VoteDirection};
        let state = state_with_governance_stake(&bob_hash(), 1_000 * BASE_UNITS_PER_BEAT);
        let op = ParsedGovernanceOp::Vote {
            proposal_id: "nonexistent".into(),
            direction: VoteDirection::For,
        };
        let r = validate_governance_op(&state, &bob_hash(), &op, 1000.0);
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("not found"));
    }

    // ─── Delegation Validation Tests ─────────────────────────────────

    #[test]
    fn test_validate_delegate_ok() {
        use crate::accounting::governance::ParsedGovernanceOp;
        let state = state_with_governance_stake(&alice_hash(), 1_000 * BASE_UNITS_PER_BEAT);
        let op = ParsedGovernanceOp::Delegate { delegate: bob_hash() };
        let r = validate_governance_op(&state, &alice_hash(), &op, 1000.0);
        assert!(r.valid);
    }

    #[test]
    fn test_validate_delegate_no_stake() {
        use crate::accounting::governance::ParsedGovernanceOp;
        let state = LedgerState::new();
        let op = ParsedGovernanceOp::Delegate { delegate: bob_hash() };
        let r = validate_governance_op(&state, &alice_hash(), &op, 1000.0);
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("governance stake"));
    }

    #[test]
    fn test_validate_delegate_self() {
        use crate::accounting::governance::ParsedGovernanceOp;
        let state = state_with_governance_stake(&alice_hash(), 1_000 * BASE_UNITS_PER_BEAT);
        let op = ParsedGovernanceOp::Delegate { delegate: alice_hash() };
        let r = validate_governance_op(&state, &alice_hash(), &op, 1000.0);
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("self"));
    }

    #[test]
    fn test_validate_delegate_circular() {
        use crate::accounting::governance::ParsedGovernanceOp;
        let mut state = state_with_governance_stake(&alice_hash(), 1_000 * BASE_UNITS_PER_BEAT);
        state.governance.delegate(&bob_hash(), &alice_hash(), 999.0).unwrap();
        let op = ParsedGovernanceOp::Delegate { delegate: bob_hash() };
        let r = validate_governance_op(&state, &alice_hash(), &op, 1000.0);
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("circular"));
    }

    #[test]
    fn test_validate_undelegate_ok() {
        use crate::accounting::governance::ParsedGovernanceOp;
        let mut state = LedgerState::new();
        state.governance.delegate(&alice_hash(), &bob_hash(), 999.0).unwrap();
        let op = ParsedGovernanceOp::Undelegate;
        let r = validate_governance_op(&state, &alice_hash(), &op, 1000.0);
        assert!(r.valid);
    }

    #[test]
    fn test_validate_undelegate_no_delegation() {
        use crate::accounting::governance::ParsedGovernanceOp;
        let state = LedgerState::new();
        let op = ParsedGovernanceOp::Undelegate;
        let r = validate_governance_op(&state, &alice_hash(), &op, 1000.0);
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("no active"));
    }

    // ─── Profile B Transfer Cap Tests ───────────────────────────────

    #[test]
    fn test_profile_b_transfer_within_cap() {
        let mut state = state_with_balance(&alice_hash(), 5_000 * BASE_UNITS_PER_BEAT);
        // Register alice as Profile B (single-sig)
        state.register_identity_profile(&alice_hash(), crate::identity::CryptoProfile::ProfileB);
        let r = validate_transfer(
            &state, &alice_hash(), 1_000 * BASE_UNITS_PER_BEAT,
            &bob_hash(), 1000.0, &genesis_hash(), true,
        );
        assert!(r.valid, "Profile B transfer at exactly 1,000 beat should succeed");
    }

    #[test]
    fn test_profile_b_transfer_exceeds_cap() {
        let mut state = state_with_balance(&alice_hash(), 5_000 * BASE_UNITS_PER_BEAT);
        state.register_identity_profile(&alice_hash(), crate::identity::CryptoProfile::ProfileB);
        let r = validate_transfer(
            &state, &alice_hash(), 1_001 * BASE_UNITS_PER_BEAT,
            &bob_hash(), 1000.0, &genesis_hash(), true,
        );
        assert!(!r.valid, "Profile B transfer above 1,000 beat should fail");
        assert!(r.error.unwrap().contains("Profile B transfer cap"));
    }

    #[test]
    fn test_profile_a_transfer_above_cap_ok() {
        let mut state = state_with_balance(&alice_hash(), 5_000 * BASE_UNITS_PER_BEAT);
        // Register alice as Profile A (dual-sig) — no per-tx cap
        state.register_identity_profile(&alice_hash(), crate::identity::CryptoProfile::ProfileA);
        let r = validate_transfer(
            &state, &alice_hash(), 3_000 * BASE_UNITS_PER_BEAT,
            &bob_hash(), 1000.0, &genesis_hash(), true,
        );
        assert!(r.valid, "Profile A identity should not be capped at 1,000 beat");
    }

    #[test]
    fn test_unknown_profile_treated_as_profile_b() {
        // Identity with no registered profile should be treated as Profile B (conservative)
        let state = state_with_balance(&alice_hash(), 5_000 * BASE_UNITS_PER_BEAT);
        let r = validate_transfer(
            &state, &alice_hash(), 1_500 * BASE_UNITS_PER_BEAT,
            &bob_hash(), 1000.0, &genesis_hash(), true,
        );
        assert!(!r.valid, "Unknown profile should be treated as Profile B");
        assert!(r.error.unwrap().contains("Profile B transfer cap"));
    }

    #[test]
    fn test_genesis_exempt_from_profile_b_cap() {
        let mut state = state_with_balance(&genesis_hash(), 100_000 * BASE_UNITS_PER_BEAT);
        state.register_identity_profile(&genesis_hash(), crate::identity::CryptoProfile::ProfileB);
        let r = validate_transfer(
            &state, &genesis_hash(), 50_000 * BASE_UNITS_PER_BEAT,
            &alice_hash(), 1000.0, &genesis_hash(), true,
        );
        assert!(r.valid, "Genesis authority should be exempt from Profile B cap");
    }

    // ── replay-determinism audit, finding 3 / Track D ─────────────────
    // The circuit-breaker / velocity / acquisition rate-limiters in validate_op read
    // the three `#[serde(skip)]` per-node trackers. validate_op runs on synced/sealed
    // records (ingest.rs, outside the skip_timestamp_defense block), so before this fix
    // a snapshot-bootstrapped follower (empty trackers) and a since-genesis node
    // (saturated trackers) computed DIFFERENT accept/reject verdicts on the SAME sealed
    // record → divergent balances → account-SMT-root fork. These tests pin the
    // VALIDATE-layer leg (the apply-layer leg is pinned by ledger.rs
    // bootstrap_equivalence_*_rate_limit_fork). Invariant: with enforce_rate_limits=false
    // (the sync/gossip replay path) both nodes converge; with enforce_rate_limits=true
    // (fresh local/RPC submit) the flag must still gate (so the rate-limit is real for
    // mempool admission, just not for sealed-record replay).

    /// Round-trip a ledger through the snapshot serde format — drops the three
    /// `#[serde(skip)]` rate-limit trackers, i.e. produces a snapshot-bootstrapped node.
    fn snapshot_roundtrip(node: &LedgerState) -> LedgerState {
        let wire = serde_json::to_string(node).expect("serialize snapshot");
        serde_json::from_str(&wire).expect("deserialize snapshot")
    }

    #[test]
    fn validate_transfer_velocity_skipped_on_sync_converges() {
        let alice = alice_hash();
        let bob = bob_hash();
        let bal = 200_000 * BASE_UNITS_PER_BEAT; // velocity Tier LOW → 100K/day cap
        let amount = 50_000 * BASE_UNITS_PER_BEAT;
        let ts = 1001.0;

        let mut node_genesis = LedgerState::new();
        // 100M supply so the acquisition cap (0.5% = 500K) exceeds the test transfer and
        // only the velocity gate under test can reject; alice's velocity tier is set by her
        // 200K balance (LOW → 100K/day), independent of supply.
        node_genesis.total_supply = 100_000_000 * BASE_UNITS_PER_BEAT;
        node_genesis.accounts.entry(alice.clone()).or_default().available = bal;
        // Profile A (dual-sig) so the deterministic Profile-B per-tx cap (validate-only,
        // #[serde(default)] identity_profiles → survives the snapshot identically on both
        // nodes) does not reject before the rate-limiters under test are reached.
        node_genesis.register_identity_profile(&alice, crate::identity::CryptoProfile::ProfileA);
        node_genesis.velocity.record_balance(&alice, bal, 1000.0);
        node_genesis
            .velocity
            .record_outflow(&alice, 100_000 * BASE_UNITS_PER_BEAT, 1000.0);
        let node_bootstrapped = snapshot_roundtrip(&node_genesis);

        // Preconditions: the trackers genuinely diverge (else the test is vacuous).
        assert!(node_genesis.velocity.outflow_in_window(&alice, ts) > 0);
        assert_eq!(node_bootstrapped.velocity.outflow_in_window(&alice, ts), 0);

        // SYNC path (enforce_rate_limits=false): both nodes converge — no fork.
        let g = validate_transfer(&node_genesis, &alice, amount, &bob, ts, &genesis_hash(), false);
        let b = validate_transfer(&node_bootstrapped, &alice, amount, &bob, ts, &genesis_hash(), false);
        assert!(g.valid, "sync path: saturated since-genesis node must NOT reject ({:?})", g.error);
        assert!(b.valid, "sync path: bootstrapped node accepts");

        // FRESH path (enforce_rate_limits=true): the flag still gates. This divergence
        // is exactly what running the gate on a sealed record would have forked.
        let g_fresh = validate_transfer(&node_genesis, &alice, amount, &bob, ts, &genesis_hash(), true);
        let b_fresh = validate_transfer(&node_bootstrapped, &alice, amount, &bob, ts, &genesis_hash(), true);
        assert!(!g_fresh.valid, "fresh path: saturated velocity must reject");
        assert!(b_fresh.valid, "fresh path: empty velocity accepts");
    }

    #[test]
    fn validate_transfer_circuit_breaker_skipped_on_sync_converges() {
        use crate::accounting::circuit_breaker::BreakerLevel;
        let alice = alice_hash();
        let bob = bob_hash();
        let circ = 100_000_000 * BASE_UNITS_PER_BEAT;
        let bal = 80_000 * BASE_UNITS_PER_BEAT; // < 100K → velocity Tier FREE (no confound)
        // > breaker pause threshold (circ/10_000 = 10K), < acquisition cap (0.5% = 500K).
        let amount = 50_000 * BASE_UNITS_PER_BEAT;
        let ts = 1001.0;

        let mut node_genesis = LedgerState::new();
        node_genesis.total_supply = circ;
        node_genesis.accounts.entry(alice.clone()).or_default().available = bal;
        // Profile A (dual-sig) so the deterministic Profile-B per-tx cap (validate-only,
        // #[serde(default)] identity_profiles → survives the snapshot identically on both
        // nodes) does not reject before the rate-limiters under test are reached.
        node_genesis.register_identity_profile(&alice, crate::identity::CryptoProfile::ProfileA);
        // Drive the network-wide breaker to Level 2 (≥5% of circulating in 24h).
        node_genesis
            .circuit_breaker
            .record_volume(6_000_000 * BASE_UNITS_PER_BEAT, 1000.0);
        node_genesis.circuit_breaker.update_level(circ, 1000.0);
        let node_bootstrapped = snapshot_roundtrip(&node_genesis);

        // Precondition: breaker level diverges across bootstrap (whole field is serde-skip).
        assert_eq!(node_genesis.circuit_breaker.level, BreakerLevel::Level2);
        assert_eq!(node_bootstrapped.circuit_breaker.level, BreakerLevel::Normal);

        // SYNC path: converge.
        let g = validate_transfer(&node_genesis, &alice, amount, &bob, ts, &genesis_hash(), false);
        let b = validate_transfer(&node_bootstrapped, &alice, amount, &bob, ts, &genesis_hash(), false);
        assert!(g.valid && b.valid, "sync path forked on the circuit breaker (g={:?} b={:?})", g.error, b.error);

        // FRESH path: flag gates — L2 node pauses the large transfer, Normal node accepts.
        let g_fresh = validate_transfer(&node_genesis, &alice, amount, &bob, ts, &genesis_hash(), true);
        let b_fresh = validate_transfer(&node_bootstrapped, &alice, amount, &bob, ts, &genesis_hash(), true);
        assert!(!g_fresh.valid, "fresh path: Level 2 breaker must pause the large transfer");
        assert!(b_fresh.valid, "fresh path: Normal-breaker bootstrapped node accepts");
    }

    #[test]
    fn validate_transfer_acquisition_skipped_on_sync_converges() {
        let alice = alice_hash();
        let bob = bob_hash();
        let circ = 100_000_000 * BASE_UNITS_PER_BEAT; // > 1M floor; acquisition cap 0.5% = 500K
        let bal = 80_000 * BASE_UNITS_PER_BEAT; // Tier FREE
        let amount = 50_000 * BASE_UNITS_PER_BEAT;
        let ts = 1001.0;

        let mut node_genesis = LedgerState::new();
        node_genesis.total_supply = circ;
        node_genesis.accounts.entry(alice.clone()).or_default().available = bal;
        // Profile A (dual-sig) so the deterministic Profile-B per-tx cap (validate-only,
        // #[serde(default)] identity_profiles → survives the snapshot identically on both
        // nodes) does not reject before the rate-limiters under test are reached.
        node_genesis.register_identity_profile(&alice, crate::identity::CryptoProfile::ProfileA);
        // Saturate bob's (recipient) 30-day acquisition window to the limit.
        node_genesis
            .acquisition
            .record_inflow(&bob, 500_000 * BASE_UNITS_PER_BEAT, 1000.0);
        let node_bootstrapped = snapshot_roundtrip(&node_genesis);

        assert!(node_genesis.acquisition.inflow_in_window(&bob, ts) > 0);
        assert_eq!(node_bootstrapped.acquisition.inflow_in_window(&bob, ts), 0);

        // SYNC path: converge.
        let g = validate_transfer(&node_genesis, &alice, amount, &bob, ts, &genesis_hash(), false);
        let b = validate_transfer(&node_bootstrapped, &alice, amount, &bob, ts, &genesis_hash(), false);
        assert!(g.valid && b.valid, "sync path forked on acquisition (g={:?} b={:?})", g.error, b.error);

        // FRESH path: flag gates — saturated recipient window rejects, empty accepts.
        let g_fresh = validate_transfer(&node_genesis, &alice, amount, &bob, ts, &genesis_hash(), true);
        let b_fresh = validate_transfer(&node_bootstrapped, &alice, amount, &bob, ts, &genesis_hash(), true);
        assert!(!g_fresh.valid, "fresh path: saturated acquisition window must reject");
        assert!(b_fresh.valid, "fresh path: empty acquisition window accepts");
    }

    /// The flag must thread through the validate_op dispatcher (not only
    /// validate_transfer directly) — pins the ingest.rs call boundary.
    #[test]
    fn validate_op_threads_enforce_rate_limits_to_transfer() {
        let alice = alice_hash();
        let bob = bob_hash();
        let bal = 200_000 * BASE_UNITS_PER_BEAT;
        let amount = 50_000 * BASE_UNITS_PER_BEAT;
        let ts = 1001.0;

        let mut node_genesis = LedgerState::new();
        // 100M supply so the acquisition cap (0.5% = 500K) exceeds the test transfer and
        // only the velocity gate under test can reject; alice's velocity tier is set by her
        // 200K balance (LOW → 100K/day), independent of supply.
        node_genesis.total_supply = 100_000_000 * BASE_UNITS_PER_BEAT;
        node_genesis.accounts.entry(alice.clone()).or_default().available = bal;
        // Profile A (dual-sig) so the deterministic Profile-B per-tx cap (validate-only,
        // #[serde(default)] identity_profiles → survives the snapshot identically on both
        // nodes) does not reject before the rate-limiters under test are reached.
        node_genesis.register_identity_profile(&alice, crate::identity::CryptoProfile::ProfileA);
        node_genesis.velocity.record_balance(&alice, bal, 1000.0);
        node_genesis
            .velocity
            .record_outflow(&alice, 100_000 * BASE_UNITS_PER_BEAT, 1000.0);
        let node_bootstrapped = snapshot_roundtrip(&node_genesis);

        let op = ParsedLedgerOp::Transfer { amount, to: bob.clone(), memo: None };

        // Sync path through the real dispatcher: converge.
        assert!(validate_op(&node_genesis, &alice, &genesis_hash(), &op, ts, false).valid);
        assert!(validate_op(&node_bootstrapped, &alice, &genesis_hash(), &op, ts, false).valid);
        // Fresh path: flag gates at the dispatcher boundary too.
        assert!(!validate_op(&node_genesis, &alice, &genesis_hash(), &op, ts, true).valid);
        assert!(validate_op(&node_bootstrapped, &alice, &genesis_hash(), &op, ts, true).valid);
    }

    #[test]
    fn test_validate_governance_param_name_valid() {
        let r = validate_governance_param_name("propagation_rate_limit_per_hour");
        assert!(r.valid);
        let r = validate_governance_param_name("witness_reward_micros");
        assert!(r.valid);
    }

    #[test]
    fn test_validate_governance_param_name_invalid() {
        let r = validate_governance_param_name("nonexistent_param");
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("unrecognized"));
    }

    #[test]
    fn test_validate_governance_propose_rate_limit() {
        use crate::accounting::governance::{ParsedGovernanceOp, ProposalCategory, MAX_ACTIVE_PROPOSALS_PER_IDENTITY};
        let mut state = state_with_governance_stake(&alice_hash(), 5_000 * BASE_UNITS_PER_BEAT);

        // Create MAX active proposals
        for i in 0..MAX_ACTIVE_PROPOSALS_PER_IDENTITY {
            state.governance.create_proposal(
                format!("prop-{i}"), &alice_hash(), ProposalCategory::Parameter,
                "T".into(), "D".into(), 5_000 * BASE_UNITS_PER_BEAT, 1000.0, None,
            ).unwrap();
        }

        // Next proposal should be rejected by validation
        let op = ParsedGovernanceOp::Propose {
            category: ProposalCategory::Parameter,
            title: "One too many".into(),
            description: "Should fail".into(),
        };
        let r = validate_governance_op(&state, &alice_hash(), &op, 1000.0);
        assert!(!r.valid);
        assert!(r.error.unwrap().contains("too many"));
    }

    // ───────────────────────────────────────────────────────────────────────
    // Fixture-free tests, pure helpers on accounting/validate.rs.
    // Axes chosen to be orthogonal to the existing test set: ValidationResult
    // constructor field shape, format_beat_precise edge cases, check_balance
    // exact boundary, GOVERNABLE_PARAMS literal pinning, summarize invariants.
    // ───────────────────────────────────────────────────────────────────────

    #[test]
    fn batch_b_validation_result_ok_and_fail_pin_field_shape_and_error_message() {
        // ok() MUST yield valid=true with error=None — no message body, no Some(empty).
        let ok = ValidationResult::ok();
        assert!(ok.valid, "ValidationResult::ok must set valid=true");
        assert!(ok.error.is_none(), "ValidationResult::ok must set error=None (not Some(empty))");

        // fail(&str) MUST yield valid=false with error=Some(exact message).
        let f1 = ValidationResult::fail("reason A");
        assert!(!f1.valid, "ValidationResult::fail must set valid=false");
        assert_eq!(
            f1.error.as_deref(),
            Some("reason A"),
            "fail(&str) MUST preserve the exact message body (no prefix/suffix mangling)"
        );

        // fail(String) MUST accept owned String via impl Into<String>.
        let f2 = ValidationResult::fail(String::from("owned reason"));
        assert!(!f2.valid);
        assert_eq!(f2.error.as_deref(), Some("owned reason"));

        // fail(format!) is the production pattern; verify it threads through.
        let f3 = ValidationResult::fail(format!("amount {} exceeds cap {}", 42u64, 10u64));
        assert!(!f3.valid);
        assert_eq!(f3.error.as_deref(), Some("amount 42 exceeds cap 10"));
    }

    #[test]
    fn batch_b_format_beat_precise_pins_whole_frac_trim_and_unit_boundaries() {
        // Zero MUST format as "0.0" (whole=0, frac=0 → frac==0 branch).
        assert_eq!(format_beat_precise(0), "0.0", "0 micros MUST render as \"0.0\"");

        // Exactly 1 beat (1 unit = 1_000_000_000 micros) → "1.0" (whole=1, frac=0).
        assert_eq!(
            format_beat_precise(BASE_UNITS_PER_BEAT),
            "1.0",
            "BASE_UNITS_PER_BEAT MUST render as \"1.0\" — whole-unit boundary"
        );

        // 10 beat (10 * 1e9 micros) → "10.0" (multi-digit whole, zero frac).
        assert_eq!(format_beat_precise(10 * BASE_UNITS_PER_BEAT), "10.0");

        // 1.5 beat → "1.5" (trim trailing zeros from "500000000").
        let one_point_five = BASE_UNITS_PER_BEAT + BASE_UNITS_PER_BEAT / 2; // 1_500_000_000
        assert_eq!(
            format_beat_precise(one_point_five),
            "1.5",
            "1_500_000_000 MUST trim to \"1.5\" — trailing-zero trim load-bearing for UX"
        );

        // 1.123456789 → "1.123456789" (no trailing zeros, full 9-digit fraction).
        assert_eq!(format_beat_precise(1_123_456_789), "1.123456789");

        // Sub-unit only: 1 micro = "0.000000001" (whole=0, frac=1, trim to 9 sig digits).
        // "{:09}" pads to "000000001"; trim_end_matches('0') strips nothing → "000000001".
        assert_eq!(
            format_beat_precise(1),
            "0.000000001",
            "1 base unit MUST render with 9 zero-padded frac digits (no trailing-zero trim removes leading zeros)"
        );

        // u64::MAX MUST NOT panic; verify it produces a non-empty deterministic string.
        let huge = format_beat_precise(u64::MAX);
        assert!(!huge.is_empty(), "u64::MAX MUST format without panic");
        assert!(huge.contains('.'), "result MUST contain a decimal point");
    }

    #[test]
    fn batch_b_check_balance_pins_exact_boundary_and_one_below_error_format() {
        // balance == amount → Ok (boundary: balance exactly covers amount).
        let state = state_with_balance(&alice_hash(), 1_000);
        assert!(
            check_balance(&state, &alice_hash(), 1_000).is_ok(),
            "balance == amount MUST be Ok (exact-boundary spend allowed)"
        );

        // balance == amount - 1 → Err with both numerics in the message body.
        let state_short = state_with_balance(&alice_hash(), 999);
        let err = check_balance(&state_short, &alice_hash(), 1_000)
            .expect_err("balance < amount MUST be Err");
        let msg = err.to_string();
        assert!(
            msg.contains("999") && msg.contains("1000"),
            "insufficient-balance error MUST include both have={{balance}} and need={{amount}} numerics; got: {msg}"
        );
        assert!(
            msg.contains("insufficient"),
            "error message MUST contain the literal token \"insufficient\" so operators can grep — got: {msg}"
        );

        // amount == 0 against balance == 0 → Ok (no overdraw, no shortfall).
        let empty = LedgerState::new();
        assert!(
            check_balance(&empty, &alice_hash(), 0).is_ok(),
            "zero-amount check against missing-account (balance=0) MUST be Ok — no shortfall"
        );

        // Unknown identity (no account) → balance defaults to 0 → Err on positive amount.
        assert!(
            check_balance(&empty, "no_such_identity", 1).is_err(),
            "unknown identity MUST yield balance=0 → Err on positive amount (no panic on missing key)"
        );
    }

    #[test]
    fn batch_b_validate_governance_param_name_pins_all_five_known_params_and_rejects_unknown() {
        // All 5 GOVERNABLE_PARAMS literal members MUST be accepted by the validator.
        // This pins the source-of-truth list so dropping/renaming any of them
        // breaks this test before it breaks the governance flow.
        let known = [
            "propagation_rate_limit_per_hour",
            "epoch_seal_interval_secs",
            "witness_reward_micros",
            "record_retention_secs",
            "stake_throughput_ratio",
        ];
        for name in known.iter() {
            let r = validate_governance_param_name(name);
            assert!(
                r.valid,
                "GOVERNABLE_PARAMS member {name:?} MUST validate as ok — list drift will break governance proposals"
            );
            assert!(r.error.is_none());
        }

        // Empty string MUST be rejected (not silently accepted as a sentinel).
        let r_empty = validate_governance_param_name("");
        assert!(!r_empty.valid, "empty param name MUST be rejected");

        // Unknown param MUST be rejected with the param name echoed for ops debugging.
        let r_unk = validate_governance_param_name("nonexistent_param_xyz");
        assert!(!r_unk.valid);
        let err = r_unk.error.unwrap();
        assert!(
            err.contains("nonexistent_param_xyz"),
            "rejection MUST echo the offending param name for ops grep; got: {err}"
        );
        assert!(
            err.contains("unrecognized"),
            "rejection MUST contain the literal \"unrecognized\" token; got: {err}"
        );

        // Case sensitivity: GOVERNABLE_PARAMS membership is exact, NOT case-insensitive.
        // Uppercase variant MUST be rejected.
        let r_upper = validate_governance_param_name("EPOCH_SEAL_INTERVAL_SECS");
        assert!(
            !r_upper.valid,
            "param-name matching is case-sensitive; uppercase variant MUST be rejected"
        );
    }

    #[test]
    fn batch_b_summarize_pins_circulating_invariant_and_active_stake_filter() {
        use crate::accounting::ledger::{StakeEntry, AccountState};
        use crate::accounting::types::StakePurpose;

        // Build a state where supply = staked + conservation_pool + circulating
        // and verify summarize() preserves that arithmetic invariant.
        let mut state = LedgerState::new();
        state.total_supply = 10_000;
        state.total_staked = 3_000;
        state.conservation_pool = 2_000;
        // Insert 2 accounts so num_accounts pins to 2 (NOT len()-stake-tied).
        let a = AccountState { available: 4_000, ..AccountState::default() };
        state.accounts.insert("a".to_string(), a);
        let b = AccountState { available: 1_000, ..AccountState::default() };
        state.accounts.insert("b".to_string(), b);
        // Insert 3 stake records: 2 active + 1 inactive. Post-B10 the active count
        // is the maintained `LedgerState.active_stakes_count`, reconciled from the
        // `stakes` map by `rebuild_staker_index` (called on every load path);
        // summarize() reads it and MUST report only the active ones.
        let mk_stake = |id: &str, active: bool| StakeEntry {
            record_id: id.to_string(),
            amount: 1_000,
            purpose: StakePurpose::Witness,
            staker: "x".to_string(),
            timestamp: 0.0,
            active,
        };
        state.stakes.insert("s1".to_string(), mk_stake("s1", true));
        state.stakes.insert("s2".to_string(), mk_stake("s2", true));
        state.stakes.insert("s3".to_string(), mk_stake("s3", false));
        state.records_processed = 42;
        // Reconcile the maintained active-stake counter from the directly-built
        // `stakes` map — exactly what every real load path does (B10).
        state.rebuild_staker_index();

        let s = summarize(&state);

        // INVARIANT: circulating = total_supply - total_staked - conservation_pool.
        assert_eq!(
            s.circulating_micros, 10_000 - 3_000 - 2_000,
            "circulating_micros MUST equal supply - staked - pool (load-bearing accounting identity)"
        );
        assert_eq!(s.total_supply_micros, 10_000);
        assert_eq!(s.total_staked_micros, 3_000);
        assert_eq!(s.conservation_pool_micros, 2_000);

        // beat denomination: micros/BASE_UNITS_PER_BEAT (f64 cast, exact since amounts are tiny).
        assert_eq!(s.total_supply_beat, 10_000.0 / BASE_UNITS_PER_BEAT as f64);
        assert_eq!(s.conservation_pool_beat, 2_000.0 / BASE_UNITS_PER_BEAT as f64);

        // num_accounts MUST equal accounts.len(), independent of stakes.len().
        assert_eq!(s.num_accounts, 2, "num_accounts MUST come from accounts map, not stakes");

        // num_active_stakes MUST equal count of active==true, NOT total stakes.len().
        assert_eq!(
            s.num_active_stakes, 2,
            "num_active_stakes MUST filter on active==true (2 active out of 3 total)"
        );

        // records_processed MUST passthrough verbatim.
        assert_eq!(s.records_processed, 42);

        // pool_cap_micros MUST passthrough state.pool_cap() — verify nonzero presence.
        // (exact value depends on state.pool_cap() impl; pin only the passthrough channel)
        assert_eq!(s.pool_cap_micros, state.pool_cap());
    }
}
