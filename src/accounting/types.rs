//! beat ledger operation types — embedded in ValidationRecord metadata.
//!
//! Every ledger operation is a regular ValidationRecord where the `metadata`
//! field contains `beat_op` plus operation-specific fields. The record's
//! `creator_public_key` identifies the actor (sender for transfers, minter
//! for mints, staker for stakes).
//!
//! Amounts are in the base atomic unit (u64). 1 beat = 1_000_000_000 base
//! units (9 decimals) — see `BASE_UNITS_PER_BEAT` below. (Legacy JSON wire
//! fields keep the `_micros` suffix for compatibility; the value is 10^9.)

//!
//! Spec references:
//!   @spec economics §3.1

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::hash::{sha3_256, sha3_256_hex};
use crate::errors::{ElaraError, Result};
use crate::record::{Classification, ValidationRecord};

/// Base atomic units per whole beat: 1 beat = 1_000_000_000 (10^9, 9 decimals).
/// Amounts stored as strings in metadata (u64 > 2^53 can't be JSON numbers).
/// 10B beat × 10^9 = 10^19 atomic units — fits u64 (max 1.8×10^19).
///
/// Naming note: serialized field names carry a historical `_micros` suffix
/// (e.g. `total_supply_micros`) — those are wire-stable and kept, but the
/// unit they hold is THIS base unit (10^-9 beat), not 10^-6.
pub const BASE_UNITS_PER_BEAT: u64 = 1_000_000_000;

/// Maximum total supply: 10 billion beat.
/// Headroom for billions of devices staking, governance, and storage delegation.
pub const MAX_SUPPLY: u64 = 10_000_000_000 * BASE_UNITS_PER_BEAT;

/// Minimum stake amount: 100 beat.
pub const MIN_STAKE: u64 = 100 * BASE_UNITS_PER_BEAT;

/// Anti-sybil witness floor: minimum total stake (in BASE UNITS) for a
/// non-genesis identity to have its push-path attestations accepted
/// (Protocol §7.5.1). 100 beat — same number as `MIN_STAKE` but a distinct
/// gate: this bounds *who may witness*, `MIN_STAKE` bounds *the smallest stake
/// op*. MUST be base units (10^9/beat): it is compared against
/// `LedgerState::staked()`, which returns base units. The bare `100_000_000`
/// literal that used to live at each gate was a pre-10^9-migration leftover
/// (correct as "100 beat" only at the old 10^6 scale) and silently weakened the
/// gate 1000× to 0.1 beat. Centralized here so the ingest gates and the
/// low-stake replay re-check can never diverge again.
pub const MIN_WITNESS_STAKE_BASE_UNITS: u64 = 100 * BASE_UNITS_PER_BEAT;

/// GENESIS VALIDATOR BOOTSTRAP (internal design notes): one
/// entry in the genesis validator set. A clean-slate chain cannot finalize
/// its first stake op (a creator cannot self-finalize and there is no other
/// staker), so the initial validators are marked staked directly in the
/// genesis ledger baseline. GENESIS PARAMETER: the list must be
/// byte-identical on every node, like `genesis_authority` — divergence here
/// forks the ledger baseline.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GenesisValidator {
    /// 64-char hex identity hash of the validator node.
    pub identity: String,
    /// Initial stake in base units (10^9/beat), carved from the genesis
    /// authority's minted allocation at baseline (supply-conserving). The
    /// `_micros` field name is legacy wire-compat (see module header); the
    /// value is base units — a 100-beat genesis validator is `100_000_000_000`,
    /// not `100_000_000` (the latter is 0.1 beat, below `MIN_STAKE`).
    pub stake_micros: u64,
}

/// Unstake cooldown: 7 days in seconds.
pub const UNSTAKE_COOLDOWN: f64 = 7.0 * 24.0 * 3600.0;

/// Default witness reward: 1 beat per attestation.
pub const DEFAULT_WITNESS_REWARD: u64 = BASE_UNITS_PER_BEAT;

/// Minimum bond for a `WitnessRegister` op (Gap 2.1 Phase 2b.3 Slice 3).
/// Set deliberately at the minimum stake floor — the bond is the
/// economic gate against witness-registry spam at 1M zones × N
/// witnesses scale; pricing it below `MIN_STAKE` would let an
/// attacker flood `CF_WITNESS_REGISTRY` more cheaply than they could
/// stake. Same number, different lock: stake unlocks after cooldown,
/// witness bond stays locked until the witness is unregistered.
pub const WITNESS_BOND_MIN: u64 = MIN_STAKE;

/// Maximum witness reward: 10 beat per attestation.
pub const MAX_WITNESS_REWARD: u64 = 10 * BASE_UNITS_PER_BEAT;

/// Profile B (single-sig) transfer cap: 1,000 beat per transaction.
/// Dual-sig (Profile A) identities have no per-transaction cap beyond velocity limits.
pub const PROFILE_B_TRANSFER_CAP: u64 = 1_000 * BASE_UNITS_PER_BEAT;

/// Metadata key prefix for all beat fields.
pub const BEAT_OP_KEY: &str = "beat_op";

// ─── Conservation Pool Constants ──────────────────────────────────────────

/// Well-known identity hash for the Conservation Pool.
/// This is a virtual identity — no private key exists. It can only receive
/// beats through protocol-defined operations (slash, dormancy reclaim).
/// Value: SHA3-256("ELARA_CONSERVATION_POOL") truncated to hex string.
pub const CONSERVATION_POOL_IDENTITY: &str =
    "conservation_pool_0000000000000000000000000000000000000000";

/// Conservation Pool hard cap: 10% of total minted supply.
/// If pool exceeds this, overflow is distributed proportionally to all stakers.
pub const CONSERVATION_POOL_MAX_FRACTION: f64 = 0.10;

/// Slash distribution: 50% to pool, 30% to challenger, 20% to jury.
pub const SLASH_POOL_FRACTION: f64 = 0.50;
pub const SLASH_CHALLENGER_FRACTION: f64 = 0.30;
pub const SLASH_JURY_FRACTION: f64 = 0.20;

/// Maximum slash percentage: 50% of stake (hard protocol limit).
pub const MAX_SLASH_PERCENTAGE: f64 = 0.50;

// ── Integer twins for consensus apply-path arithmetic ────────────────────────
// These fractions multiply `stake.amount` / `total_supply` (which can exceed
// 2^53) inside `apply_op` on EVERY node, so they must be applied as exact
// rationals, not f64. See internal design notes.
/// 10% conservation-pool cap as 1/10.
pub const CONSERVATION_POOL_MAX_FRACTION_NUM: u128 = 1;
pub const CONSERVATION_POOL_MAX_FRACTION_DEN: u128 = 10;
/// Max single-event slash, 50% of stake, as 1/2.
pub const MAX_SLASH_PERCENTAGE_NUM: u128 = 1;
pub const MAX_SLASH_PERCENTAGE_DEN: u128 = 2;
/// Slash split: pool 50% (1/2), challenger 30% (3/10); jury = remainder (dust-safe).
pub const SLASH_POOL_FRACTION_NUM: u128 = 1;
pub const SLASH_POOL_FRACTION_DEN: u128 = 2;
pub const SLASH_CHALLENGER_FRACTION_NUM: u128 = 3;
pub const SLASH_CHALLENGER_FRACTION_DEN: u128 = 10;

/// Dormancy threshold: 5 years in seconds.
pub const DORMANCY_THRESHOLD: f64 = 5.0 * 365.25 * 24.0 * 3600.0;

/// Dormancy wake-up window: 2 years in seconds.
pub const DORMANCY_WAKEUP_WINDOW: f64 = 2.0 * 365.25 * 24.0 * 3600.0;

/// Ledger operation types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerOp {
    /// Create new beat (genesis authority only).
    Mint,
    /// Transfer beat from sender to recipient.
    Transfer,
    /// Lock beat for witness duties or governance.
    Stake,
    /// Unlock previously staked beat (after cooldown).
    Unstake,
    /// Witness attestation reward (deducted from record creator, credited to witness).
    WitnessReward,
    /// Slash a staker's stake (protocol-level, genesis authority only).
    /// Distribution: 50% to Conservation Pool, 30% to challenger, 20% to jury.
    Slash,
    /// Reclaim beats from a dormant identity (protocol-level, genesis authority only).
    /// 100% goes to Conservation Pool.
    DormancyReclaim,
    /// Recycle beat to the Conservation Pool (genesis authority only).
    /// Supply is unchanged — beats are recycled, not destroyed (the apply
    /// path credits the pool and leaves `total_supply` constant).
    Burn,
    /// Seed the conservation pool from the sender's balance (genesis authority only).
    PoolFund,
    /// Stake beat on a prediction about a future epoch's outcome.
    /// Evaluated at epoch seal: correct → stake returned + reward, wrong → stake to pool.
    Predict,
    /// Lock beat for a cross-zone transfer (Phase 1 of two-phase commit).
    XZoneLock,
    /// Claim locked beat in the destination zone (Phase 2 of two-phase commit).
    XZoneClaim,
    /// Cancel an unsealed XZoneLock — sender-initiated early refund.
    /// Only valid before the lock record has been committed to an epoch seal
    /// (`source_merkle_root == 0` / `merkle_proof.is_empty()`). Once sealed,
    /// the recipient could be in flight; sender-cancel is unsafe and must be
    /// replaced by a recipient-zone abort proof or the 24h passive timeout.
    XZoneCancel,
    /// Reject an unsealed XZoneLock — recipient-initiated early refund.
    /// Mirror of XZoneCancel for the case where the recipient does not want
    /// the transfer (wrong amount, suspicious sender, etc.) and signals A
    /// before the lock has been committed to an epoch seal. Once sealed the
    /// recipient could already have submitted a claim in zone B; reject
    /// becomes a double-spend window and must wait for committee abort proof
    /// or 24h timeout.
    XZoneReject,
    /// Abort a *sealed* XZoneLock via a destination-zone committee
    /// non-inclusion attestation (Gap 2 sealed-abort). Once the lock has been
    /// committed to a source-zone epoch seal, the recipient could already be
    /// in flight in zone B, so neither sender-cancel nor recipient-reject is
    /// safe. The abort instead carries a 2/3 quorum of zone-B committee
    /// signatures attesting "no claim was admitted before the abort window."
    /// Apply path verifies the proof, refunds the original sender, and
    /// transitions the transfer to `Aborted` (terminal). Anyone may submit
    /// the abort record — the proof itself is the authorization.
    XZoneAbort,
    /// Phase 2 of dormancy lifecycle — declare an identity dormant.
    /// Requires 2+ independent witnesses (enforced via network record settlement).
    /// Starts the 2-year wake-up window.
    DormancyDeclare,
    /// Phase 3 of dormancy lifecycle — heartbeat from the dormant identity itself
    /// proving liveness. Resets phase to Active.
    DormancyHeartbeat,
    /// Phase 3 of dormancy lifecycle — third-party relay of a signed proof-of-life
    /// message from the dormant identity. Resets target's phase to Active.
    DormancyProofOfLife,
    /// Register the creator as a bonded finality witness for one zone
    /// (Gap 2.1 Phase 2b.3 Slice 3). Locks `WITNESS_BOND_MIN` beat and
    /// pins the creator's Dilithium PK in `CF_WITNESS_REGISTRY` keyed by
    /// `(zone_path, creator_identity_hash)`. Once finalized, every node
    /// in the network agrees on the witness's eligibility, so the
    /// finality-committee snapshot computes identically across nodes —
    /// the fix for the Slice 1 snapshot-mismatch divergence.
    WitnessRegister,
    /// Protocol-imposed custodial idle_decay (economics §13.13.1). A frozen
    /// per-epoch batch emitted by the genesis authority that debits
    /// exchange-classified identities and credits the Conservation Pool +
    /// active stakers. Deterministic propagation (Option A) of the holding fee;
    /// see internal design notes.
    IdleDecay,
    /// A frozen per-epoch batch of cross-zone timeout refunds (economics §16.1)
    /// emitted by the genesis authority. Un-locks expired UNSEALED cross-zone
    /// transfers back to their senders. Replaces the old ungated in-loop
    /// `process_expired_xzone` mutation (which forked on per-node wall-clock);
    /// applied verbatim on every node so balances + account-SMT root converge.
    /// Option A; see internal design notes.
    XZoneTimeoutRefund,
    /// A frozen per-epoch batch of far-horizon SEALED-stuck reaps (co-fix (b),
    /// economics §16.1) emitted by the genesis authority. Hard-refunds SEALED
    /// cross-zone locks stuck ~30d past expiry under a dead/partitioned dest
    /// committee (no XZoneAbort quorum ever formed) — bounding the otherwise
    /// never-pruned Locked set. Distinct from XZoneTimeoutRefund so the
    /// sealed-reap and unsealed-timeout predicates can never be confused.
    /// internal design notes.
    XZoneStaleReap,
}

#[allow(clippy::should_implement_trait)]
impl LedgerOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Transfer => "transfer",
            Self::Stake => "stake",
            Self::Unstake => "unstake",
            Self::WitnessReward => "witness_reward",
            Self::Slash => "slash",
            Self::DormancyReclaim => "dormancy_reclaim",
            Self::Burn => "burn",
            Self::PoolFund => "pool_fund",
            Self::Predict => "predict",
            Self::XZoneLock => "xzone_lock",
            Self::XZoneClaim => "xzone_claim",
            Self::XZoneCancel => "xzone_cancel",
            Self::XZoneReject => "xzone_reject",
            Self::XZoneAbort => "xzone_abort",
            Self::DormancyDeclare => "dormancy_declare",
            Self::DormancyHeartbeat => "dormancy_heartbeat",
            Self::DormancyProofOfLife => "dormancy_proof_of_life",
            Self::WitnessRegister => "witness_register",
            Self::IdleDecay => "idle_decay",
            Self::XZoneTimeoutRefund => "xzone_timeout_refund",
            Self::XZoneStaleReap => "xzone_stale_reap",
        }
    }

    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "mint" => Ok(Self::Mint),
            "transfer" => Ok(Self::Transfer),
            "stake" => Ok(Self::Stake),
            "unstake" => Ok(Self::Unstake),
            "witness_reward" => Ok(Self::WitnessReward),
            "slash" => Ok(Self::Slash),
            "dormancy_reclaim" => Ok(Self::DormancyReclaim),
            "burn" => Ok(Self::Burn),
            "pool_fund" => Ok(Self::PoolFund),
            "predict" => Ok(Self::Predict),
            "xzone_lock" => Ok(Self::XZoneLock),
            "xzone_claim" => Ok(Self::XZoneClaim),
            "xzone_cancel" => Ok(Self::XZoneCancel),
            "xzone_reject" => Ok(Self::XZoneReject),
            "xzone_abort" => Ok(Self::XZoneAbort),
            "dormancy_declare" => Ok(Self::DormancyDeclare),
            "dormancy_heartbeat" => Ok(Self::DormancyHeartbeat),
            "dormancy_proof_of_life" => Ok(Self::DormancyProofOfLife),
            "witness_register" => Ok(Self::WitnessRegister),
            "idle_decay" => Ok(Self::IdleDecay),
            "xzone_timeout_refund" => Ok(Self::XZoneTimeoutRefund),
            "xzone_stale_reap" => Ok(Self::XZoneStaleReap),
            other => Err(ElaraError::Ledger(format!("unknown ledger op: {other}"))),
        }
    }
}

/// Parsed ledger operation extracted from a ValidationRecord.
#[derive(Debug, Clone)]
pub enum ParsedLedgerOp {
    Mint {
        amount: u64,
        to: String,
        reason: String,
    },
    Transfer {
        amount: u64,
        to: String,
        memo: Option<String>,
    },
    Stake {
        amount: u64,
        purpose: StakePurpose,
    },
    Unstake {
        stake_record_id: String,
    },
    WitnessReward {
        amount: u64,
        from: String,       // record creator (pays the fee)
        to: String,         // witness (receives the fee)
        record_id: String,  // the witnessed record
    },
    Slash {
        amount: u64,            // base units to slash from stake
        offender: String,       // identity being slashed
        challenger: String,     // gets 30%
        jury: Vec<String>,      // gets 20% (split equally among members)
        stake_record_id: String,// which stake to slash
        reason: String,
    },
    DormancyReclaim {
        amount: u64,            // base units to reclaim
        dormant_identity: String,
        last_activity: f64,     // timestamp of last activity (for verification)
    },
    Burn {
        amount: u64,
        memo: Option<String>,
    },
    PoolFund {
        amount: u64,
    },
    /// Stake beat on a prediction about a future epoch's zone activity.
    Predict {
        /// beat staked on this prediction (locked until evaluation).
        amount: u64,
        /// Target zone the prediction is about.
        zone: String,
        /// Target epoch number (must be in the future when created).
        target_epoch: u64,
        /// What is being predicted.
        claim: PredictionClaim,
        /// The predicted value (interpretation depends on claim type).
        predicted_value: u64,
    },
    /// Lock beat for cross-zone transfer (sender side).
    XZoneLock {
        amount: u64,
        recipient: String,
        source_zone: String,
        dest_zone: String,
    },
    /// Claim locked beat in destination zone (recipient side).
    XZoneClaim {
        transfer_id: String,
        amount: u64,
        recipient: String,
    },
    /// Cancel an unsealed XZoneLock and refund the sender.
    /// Record creator must be the original lock's sender; the lock must not
    /// yet have a Merkle proof attached (i.e. has not appeared in an epoch
    /// seal). Apply path returns the locked amount to creator.available.
    XZoneCancel {
        transfer_id: String,
    },
    /// Reject an unsealed XZoneLock and refund the sender (recipient-initiated).
    /// Record creator must be the original lock's recipient; same unsealed-only
    /// safety constraint as XZoneCancel. Apply path credits transfer.sender's
    /// available balance — note creator (recipient) ≠ refund destination
    /// (sender), unlike XZoneCancel where creator = refund destination.
    XZoneReject {
        transfer_id: String,
    },
    /// Abort a *sealed* XZoneLock via a B-committee non-inclusion attestation
    /// (Gap 2 sealed-abort). The signers carry destination-zone committee
    /// membership proofs against `dest_committee_hash` plus Dilithium3
    /// signatures over the canonical abort message
    /// (`xzone_abort_signable_bytes(transfer_id, dest_zone, source_seal_epoch,
    /// dest_committee_hash)`). Apply path calls `verify_abort_quorum` and,
    /// on success, `cross_zone::abort_transfer` to refund the original sender.
    /// Anyone can submit the record — the proof is the authorization, so
    /// creator ≠ refund destination in general.
    XZoneAbort {
        transfer_id: String,
        dest_committee_hash: [u8; 32],
        dest_committee_size: u32,
        signers: Vec<crate::accounting::cross_zone::SealFinalityWitness>,
    },
    /// Declare a dormant identity (Phase 2 of dormancy lifecycle).
    /// Creator is the declarer. Network-layer attestation enforces witness count.
    DormancyDeclare {
        target_identity: String,
        last_known_active: f64,
    },
    /// Heartbeat from the dormant identity (Phase 3 wake-up).
    /// Creator must be the dormant identity itself.
    DormancyHeartbeat,
    /// Third-party proof-of-life relay (Phase 3 wake-up).
    /// The relayer submits a signed message from the target proving liveness.
    DormancyProofOfLife {
        target_identity: String,
        signature: String,
    },
    /// Register the creator as a bonded finality witness for one zone
    /// (Gap 2.1 Phase 2b.3 Slice 3). The bond is locked from the creator's
    /// available balance; the Dilithium PK is taken from the record's
    /// `creator_public_key` and pinned in `CF_WITNESS_REGISTRY` so every
    /// node converges on the same finality-committee candidate set.
    WitnessRegister {
        zone_path: String,
        bond: u64,
    },
    /// A frozen per-epoch custodial-idle_decay batch (economics §13.13.1),
    /// emitted by the genesis authority. Debits exchange-classified identities
    /// and credits the Conservation Pool + active stakers. Applied verbatim on
    /// every node via the standard record path so balances + account-SMT root
    /// converge fleet-wide (Option A; internal design notes). Apply gates
    /// on `creator == genesis_authority` and the batch's conservation invariant.
    IdleDecay {
        batch: crate::accounting::idle_decay::IdleDecayBatch,
    },
    /// A frozen per-epoch batch of cross-zone timeout refunds (economics §16.1),
    /// emitted by the genesis authority. Un-locks expired UNSEALED cross-zone
    /// transfers back to their senders, applied verbatim on every node via the
    /// standard record path so balances + `pending_xzone_locked` + account-SMT
    /// root converge fleet-wide (Option A; docs/CROSS-ZONE-TIMEOUT-REFUND-
    /// internal design notes). Apply gates on `creator == genesis_authority`; per-entry
    /// eligibility is re-checked against the node's own `pending` (skip-missing).
    XZoneTimeoutRefund {
        batch: crate::accounting::cross_zone::XZoneRefundBatch,
    },
    /// A frozen per-epoch batch of far-horizon SEALED-stuck reaps (co-fix (b),
    /// economics §16.1), emitted by the genesis authority. Hard-refunds SEALED
    /// cross-zone locks stuck ~30d past expiry under a dead dest committee,
    /// applied verbatim fleet-wide (Option A). Reuses the `XZoneRefundBatch`
    /// payload; the distinct op keeps the sealed-reap predicate separate from
    /// the unsealed-timeout one. Apply gates on `creator == genesis_authority`.
    XZoneStaleReap {
        batch: crate::accounting::cross_zone::XZoneRefundBatch,
    },
}

/// What the stake is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StakePurpose {
    /// Witness duties (counter-sign records).
    Witness,
    /// Governance participation (conviction voting).
    Governance,
    /// Storage delegation (host records for others).
    Storage,
}

#[allow(clippy::should_implement_trait)]
impl StakePurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Witness => "witness",
            Self::Governance => "governance",
            Self::Storage => "storage",
        }
    }

    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "witness" => Ok(Self::Witness),
            "governance" => Ok(Self::Governance),
            "storage" => Ok(Self::Storage),
            other => Err(ElaraError::Ledger(format!("unknown stake purpose: {other}"))),
        }
    }
}

/// What a prediction claims about a future epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredictionClaim {
    /// Will the zone have any non-seal records? predicted_value: 1 = yes, 0 = no.
    Active,
    /// How many records will the zone have? predicted_value = count.
    Volume,
    /// How many unique identities will participate? predicted_value = count.
    IdentityCount,
}

#[allow(clippy::should_implement_trait)]
impl PredictionClaim {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Volume => "volume",
            Self::IdentityCount => "identity_count",
        }
    }

    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "active" => Ok(Self::Active),
            "volume" => Ok(Self::Volume),
            "identity_count" => Ok(Self::IdentityCount),
            other => Err(ElaraError::Ledger(format!("unknown prediction claim: {other}"))),
        }
    }
}

/// Minimum prediction stake: 10 beat.
pub const MIN_PREDICTION_STAKE: u64 = 10 * BASE_UNITS_PER_BEAT;

/// Prediction reward rate: 10% of staked amount (paid from conservation pool).
pub const PREDICTION_REWARD_RATE: f64 = 0.10;
/// Integer twin (exact rational 1/10) for the consensus reward path — the f64
/// rate above forks across arch once `pred.amount` exceeds 2^53.
pub const PREDICTION_REWARD_RATE_NUM: u128 = 1;
pub const PREDICTION_REWARD_RATE_DEN: u128 = 10;

/// Maximum margin for numeric predictions (volume, identity_count): 20%.
/// A prediction is correct if |actual - predicted| / max(actual, 1) <= margin.
pub const PREDICTION_MARGIN: f64 = 0.20;
/// Integer twin (exact rational 1/5 = 0.20) for the correct/wrong consensus gate.
pub const PREDICTION_MARGIN_NUM: u128 = 1;
pub const PREDICTION_MARGIN_DEN: u128 = 5;

/// Extract ledger operation from a ValidationRecord's metadata, if present.
/// Returns None if the record has no `beat_op` field.
pub fn extract_ledger_op(record: &ValidationRecord) -> Result<Option<ParsedLedgerOp>> {
    let op_val = match record.metadata.get(BEAT_OP_KEY) {
        Some(v) => v,
        None => return Ok(None),
    };

    let op_str = op_val
        .as_str()
        .ok_or_else(|| ElaraError::Ledger("beat_op must be a string".into()))?;
    let op = LedgerOp::from_str(op_str)?;

    match op {
        LedgerOp::Mint => {
            let amount = get_u64(&record.metadata, "beat_amount")?;
            let to = get_string(&record.metadata, "beat_to")?;
            let reason = get_string_or(&record.metadata, "beat_reason", "genesis");
            Ok(Some(ParsedLedgerOp::Mint { amount, to, reason }))
        }
        LedgerOp::Transfer => {
            let amount = get_u64(&record.metadata, "beat_amount")?;
            let to = get_string(&record.metadata, "beat_to")?;
            let memo = record
                .metadata
                .get("beat_memo")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            Ok(Some(ParsedLedgerOp::Transfer { amount, to, memo }))
        }
        LedgerOp::Stake => {
            let amount = get_u64(&record.metadata, "beat_amount")?;
            let purpose_str = get_string_or(&record.metadata, "beat_purpose", "witness");
            let purpose = StakePurpose::from_str(&purpose_str)?;
            Ok(Some(ParsedLedgerOp::Stake { amount, purpose }))
        }
        LedgerOp::Unstake => {
            let stake_record_id = get_string(&record.metadata, "beat_stake_id")?;
            Ok(Some(ParsedLedgerOp::Unstake { stake_record_id }))
        }
        LedgerOp::WitnessReward => {
            let amount = get_u64(&record.metadata, "beat_amount")?;
            let from = get_string(&record.metadata, "beat_from")?;
            let to = get_string(&record.metadata, "beat_to")?;
            let record_id = get_string(&record.metadata, "beat_record_id")?;
            Ok(Some(ParsedLedgerOp::WitnessReward { amount, from, to, record_id }))
        }
        LedgerOp::Slash => {
            let amount = get_u64(&record.metadata, "beat_amount")?;
            let offender = get_string(&record.metadata, "beat_offender")?;
            let challenger = get_string(&record.metadata, "beat_challenger")?;
            // Jury: support both array (new) and string (legacy) format
            let jury = match record.metadata.get("beat_jury") {
                Some(serde_json::Value::Array(arr)) => {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                }
                Some(serde_json::Value::String(s)) => vec![s.clone()],
                _ => return Err(ElaraError::Ledger("missing or invalid beat_jury".into())),
            };
            let stake_record_id = get_string(&record.metadata, "beat_stake_id")?;
            let reason = get_string_or(&record.metadata, "beat_reason", "protocol violation");
            Ok(Some(ParsedLedgerOp::Slash {
                amount, offender, challenger, jury, stake_record_id, reason,
            }))
        }
        LedgerOp::DormancyReclaim => {
            let amount = get_u64(&record.metadata, "beat_amount")?;
            let dormant_identity = get_string(&record.metadata, "beat_dormant_identity")?;
            let last_activity = get_f64(&record.metadata, "beat_last_activity")?;
            Ok(Some(ParsedLedgerOp::DormancyReclaim {
                amount, dormant_identity, last_activity,
            }))
        }
        LedgerOp::Burn => {
            let amount = get_u64(&record.metadata, "beat_amount")?;
            let memo = record
                .metadata
                .get("beat_memo")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            Ok(Some(ParsedLedgerOp::Burn { amount, memo }))
        }
        LedgerOp::PoolFund => {
            let amount = get_u64(&record.metadata, "beat_amount")?;
            Ok(Some(ParsedLedgerOp::PoolFund { amount }))
        }
        LedgerOp::Predict => {
            let amount = get_u64(&record.metadata, "beat_amount")?;
            let zone = get_string(&record.metadata, "beat_predict_zone")?;
            let target_epoch = get_u64(&record.metadata, "beat_predict_epoch")?;
            let claim_str = get_string(&record.metadata, "beat_predict_claim")?;
            let claim = PredictionClaim::from_str(&claim_str)?;
            let predicted_value = get_u64(&record.metadata, "beat_predict_value")?;
            Ok(Some(ParsedLedgerOp::Predict {
                amount, zone, target_epoch, claim, predicted_value,
            }))
        }
        LedgerOp::XZoneLock => {
            let amount = get_u64(&record.metadata, "beat_amount")?;
            let recipient = get_string(&record.metadata, "beat_to")?;
            let source_zone = get_string(&record.metadata, "beat_source_zone")?;
            let dest_zone = get_string(&record.metadata, "beat_dest_zone")?;
            Ok(Some(ParsedLedgerOp::XZoneLock { amount, recipient, source_zone, dest_zone }))
        }
        LedgerOp::XZoneClaim => {
            let transfer_id = get_string(&record.metadata, "beat_transfer_id")?;
            let amount = get_u64(&record.metadata, "beat_amount")?;
            let recipient = get_string(&record.metadata, "beat_to")?;
            Ok(Some(ParsedLedgerOp::XZoneClaim { transfer_id, amount, recipient }))
        }
        LedgerOp::XZoneCancel => {
            let transfer_id = get_string(&record.metadata, "beat_transfer_id")?;
            Ok(Some(ParsedLedgerOp::XZoneCancel { transfer_id }))
        }
        LedgerOp::XZoneReject => {
            let transfer_id = get_string(&record.metadata, "beat_transfer_id")?;
            Ok(Some(ParsedLedgerOp::XZoneReject { transfer_id }))
        }
        LedgerOp::XZoneAbort => {
            let transfer_id = get_string(&record.metadata, "beat_transfer_id")?;
            let hash_str = get_string(&record.metadata, "xzone_dest_committee_hash")?;
            let hash_vec = hex::decode(&hash_str).map_err(|e| {
                ElaraError::Ledger(format!("xzone_abort: invalid dest_committee_hash hex: {e}"))
            })?;
            if hash_vec.len() != 32 {
                return Err(ElaraError::Ledger(format!(
                    "xzone_abort: dest_committee_hash must be 32 bytes, got {}",
                    hash_vec.len()
                )));
            }
            let mut dest_committee_hash = [0u8; 32];
            dest_committee_hash.copy_from_slice(&hash_vec);
            let dest_committee_size = u32::try_from(get_u64(&record.metadata, "xzone_dest_committee_size")?)
                .map_err(|_| ElaraError::Ledger("xzone_abort: dest_committee_size overflows u32".into()))?;
            let signers_val = record.metadata.get("xzone_abort_signers").ok_or_else(|| {
                ElaraError::Ledger("xzone_abort: missing xzone_abort_signers".into())
            })?;
            let signers: Vec<crate::accounting::cross_zone::SealFinalityWitness> =
                serde_json::from_value(signers_val.clone()).map_err(|e| {
                    ElaraError::Ledger(format!("xzone_abort: invalid signers: {e}"))
                })?;
            Ok(Some(ParsedLedgerOp::XZoneAbort {
                transfer_id,
                dest_committee_hash,
                dest_committee_size,
                signers,
            }))
        }
        LedgerOp::DormancyDeclare => {
            let target_identity = get_string(&record.metadata, "beat_target_identity")?;
            let last_known_active = get_f64(&record.metadata, "beat_last_known_active")?;
            Ok(Some(ParsedLedgerOp::DormancyDeclare { target_identity, last_known_active }))
        }
        LedgerOp::DormancyHeartbeat => {
            Ok(Some(ParsedLedgerOp::DormancyHeartbeat))
        }
        LedgerOp::DormancyProofOfLife => {
            let target_identity = get_string(&record.metadata, "beat_target_identity")?;
            let signature = get_string(&record.metadata, "beat_proof_signature")?;
            Ok(Some(ParsedLedgerOp::DormancyProofOfLife { target_identity, signature }))
        }
        LedgerOp::WitnessRegister => {
            let zone_path = get_string(&record.metadata, "beat_zone")?;
            let bond = get_u64(&record.metadata, "beat_bond")?;
            if bond < WITNESS_BOND_MIN {
                return Err(ElaraError::Ledger(format!(
                    "witness_register bond {bond} below minimum {WITNESS_BOND_MIN}"
                )));
            }
            if zone_path.is_empty() {
                return Err(ElaraError::Ledger("witness_register beat_zone empty".into()));
            }
            Ok(Some(ParsedLedgerOp::WitnessRegister { zone_path, bond }))
        }
        LedgerOp::IdleDecay => {
            let batch_val = record.metadata.get("idle_decay_batch").ok_or_else(|| {
                ElaraError::Ledger("idle_decay: missing idle_decay_batch".into())
            })?;
            let batch: crate::accounting::idle_decay::IdleDecayBatch =
                serde_json::from_value(batch_val.clone()).map_err(|e| {
                    ElaraError::Ledger(format!("idle_decay: invalid batch: {e}"))
                })?;
            Ok(Some(ParsedLedgerOp::IdleDecay { batch }))
        }
        LedgerOp::XZoneTimeoutRefund => {
            let batch_val = record.metadata.get("xzone_refund_batch").ok_or_else(|| {
                ElaraError::Ledger("xzone_timeout_refund: missing xzone_refund_batch".into())
            })?;
            let batch: crate::accounting::cross_zone::XZoneRefundBatch =
                serde_json::from_value(batch_val.clone()).map_err(|e| {
                    ElaraError::Ledger(format!("xzone_timeout_refund: invalid batch: {e}"))
                })?;
            Ok(Some(ParsedLedgerOp::XZoneTimeoutRefund { batch }))
        }
        LedgerOp::XZoneStaleReap => {
            let batch_val = record.metadata.get("xzone_reap_batch").ok_or_else(|| {
                ElaraError::Ledger("xzone_stale_reap: missing xzone_reap_batch".into())
            })?;
            let batch: crate::accounting::cross_zone::XZoneRefundBatch =
                serde_json::from_value(batch_val.clone()).map_err(|e| {
                    ElaraError::Ledger(format!("xzone_stale_reap: invalid batch: {e}"))
                })?;
            Ok(Some(ParsedLedgerOp::XZoneStaleReap { batch }))
        }
    }
}

/// Build metadata for a IdleDecay batch record (Option A propagation,
/// internal design notes). The frozen batch is serialized whole under
/// `idle_decay_batch` (serde round-trip), mirroring the `xzone_abort_signers`
/// encoding; `beat_amount` carries the total debit for explorer display + record
/// content-hash diversity (it is NOT read on the apply path — the batch is).
pub fn idle_decay_batch_metadata(
    batch: &crate::accounting::idle_decay::IdleDecayBatch,
) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("idle_decay"));
    m.insert(
        "beat_amount".into(),
        serde_json::json!((batch.total_debit() as u64).to_string()),
    );
    m.insert(
        "idle_decay_batch".into(),
        serde_json::to_value(batch).unwrap_or(serde_json::Value::Null),
    );
    m
}

/// Build metadata for an `XZoneTimeoutRefund` batch record (Option A propagation,
/// internal design notes). The frozen batch is serialized
/// whole under `xzone_refund_batch` (serde round-trip), mirroring the
/// `idle_decay_batch` encoding; `beat_amount` carries the total refund for
/// explorer display + record content-hash diversity (it is NOT read on the apply
/// path — the per-entry live `pending` amount is).
pub fn xzone_refund_batch_metadata(
    batch: &crate::accounting::cross_zone::XZoneRefundBatch,
) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("xzone_timeout_refund"));
    m.insert(
        "beat_amount".into(),
        serde_json::json!((batch.total_refund() as u64).to_string()),
    );
    m.insert(
        "xzone_refund_batch".into(),
        serde_json::to_value(batch).unwrap_or(serde_json::Value::Null),
    );
    m
}

/// Build metadata for an `XZoneStaleReap` batch record (co-fix (b), Option A
/// propagation, internal design notes). The frozen batch
/// is serialized whole under `xzone_reap_batch` (distinct key from the timeout
/// refund's `xzone_refund_batch`); `beat_amount` carries the total reaped value
/// for explorer display + content-hash diversity (NOT read on the apply path —
/// the per-entry live `pending` amount is).
pub fn xzone_reap_batch_metadata(
    batch: &crate::accounting::cross_zone::XZoneRefundBatch,
) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("xzone_stale_reap"));
    m.insert(
        "beat_amount".into(),
        serde_json::json!((batch.total_refund() as u64).to_string()),
    );
    m.insert(
        "xzone_reap_batch".into(),
        serde_json::to_value(batch).unwrap_or(serde_json::Value::Null),
    );
    m
}

/// Build metadata for a Mint operation.
pub fn mint_metadata(amount: u64, to: &str, reason: &str) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("mint"));
    m.insert("beat_amount".into(), serde_json::json!(amount.to_string()));
    m.insert("beat_to".into(), serde_json::json!(to));
    m.insert("beat_reason".into(), serde_json::json!(reason));
    m
}

/// Build metadata for a Transfer operation.
pub fn transfer_metadata(
    amount: u64,
    to: &str,
    memo: Option<&str>,
) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("transfer"));
    m.insert("beat_amount".into(), serde_json::json!(amount.to_string()));
    m.insert("beat_to".into(), serde_json::json!(to));
    if let Some(memo) = memo {
        m.insert("beat_memo".into(), serde_json::json!(memo));
    }
    m
}

/// Build metadata for a Stake operation.
pub fn stake_metadata(amount: u64, purpose: &StakePurpose) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("stake"));
    m.insert("beat_amount".into(), serde_json::json!(amount.to_string()));
    m.insert("beat_purpose".into(), serde_json::json!(purpose.as_str()));
    m
}

/// Build metadata for an Unstake operation.
pub fn unstake_metadata(stake_record_id: &str) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("unstake"));
    m.insert(
        "beat_stake_id".into(),
        serde_json::json!(stake_record_id),
    );
    m
}

/// Build metadata for a `witness_register` operation (Gap 2.1 Phase 2b.3
/// Slice 3). The bond is encoded as a string per the project-wide
/// convention for u64 amounts (JSON numbers can't represent values
/// above 2^53).
pub fn witness_register_metadata(zone_path: &str, bond: u64) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("witness_register"));
    m.insert("beat_zone".into(), serde_json::json!(zone_path));
    m.insert("beat_bond".into(), serde_json::json!(bond.to_string()));
    m
}

/// Build metadata for a witness reward operation.
pub fn witness_reward_metadata(amount: u64, from: &str, to: &str, record_id: &str) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("witness_reward"));
    m.insert("beat_amount".into(), serde_json::json!(amount.to_string()));
    m.insert("beat_from".into(), serde_json::json!(from));
    m.insert("beat_to".into(), serde_json::json!(to));
    m.insert("beat_record_id".into(), serde_json::json!(record_id));
    m
}

/// Build metadata for a Slash operation.
pub fn slash_metadata(
    amount: u64,
    offender: &str,
    challenger: &str,
    jury: &[String],
    stake_record_id: &str,
    reason: &str,
) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("slash"));
    m.insert("beat_amount".into(), serde_json::json!(amount.to_string()));
    m.insert("beat_offender".into(), serde_json::json!(offender));
    m.insert("beat_challenger".into(), serde_json::json!(challenger));
    m.insert("beat_jury".into(), serde_json::json!(jury));
    m.insert("beat_stake_id".into(), serde_json::json!(stake_record_id));
    m.insert("beat_reason".into(), serde_json::json!(reason));
    m
}

/// Build metadata for a Burn operation.
pub fn burn_metadata(amount: u64, memo: Option<&str>) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("burn"));
    m.insert("beat_amount".into(), serde_json::json!(amount.to_string()));
    if let Some(memo) = memo {
        m.insert("beat_memo".into(), serde_json::json!(memo));
    }
    m
}

/// Build metadata for a Pool Fund operation (genesis authority seeds conservation pool).
pub fn pool_fund_metadata(amount: u64) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("pool_fund"));
    m.insert("beat_amount".into(), serde_json::json!(amount.to_string()));
    m
}

/// Build metadata for a Predict operation.
pub fn predict_metadata(
    amount: u64,
    zone: &str,
    target_epoch: u64,
    claim: &PredictionClaim,
    predicted_value: u64,
) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("predict"));
    m.insert("beat_amount".into(), serde_json::json!(amount.to_string()));
    m.insert("beat_predict_zone".into(), serde_json::json!(zone));
    m.insert("beat_predict_epoch".into(), serde_json::json!(target_epoch.to_string()));
    m.insert("beat_predict_claim".into(), serde_json::json!(claim.as_str()));
    m.insert("beat_predict_value".into(), serde_json::json!(predicted_value.to_string()));
    m
}

/// Build metadata for a Dormancy Reclaim operation.
pub fn dormancy_reclaim_metadata(
    amount: u64,
    dormant_identity: &str,
    last_activity: f64,
) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("dormancy_reclaim"));
    m.insert("beat_amount".into(), serde_json::json!(amount.to_string()));
    m.insert(
        "beat_dormant_identity".into(),
        serde_json::json!(dormant_identity),
    );
    m.insert("beat_last_activity".into(), serde_json::json!(last_activity));
    m
}

/// Build metadata for a Dormancy Declare operation (Phase 2).
pub fn dormancy_declare_metadata(
    target_identity: &str,
    last_known_active: f64,
) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("dormancy_declare"));
    m.insert("beat_target_identity".into(), serde_json::json!(target_identity));
    m.insert("beat_last_known_active".into(), serde_json::json!(last_known_active));
    m
}

/// Build metadata for a Dormancy Heartbeat operation (Phase 3 self-wake).
pub fn dormancy_heartbeat_metadata() -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("dormancy_heartbeat"));
    m
}

/// Build metadata for a Dormancy Proof-of-Life relay operation (Phase 3 third-party wake).
pub fn dormancy_proof_of_life_metadata(
    target_identity: &str,
    signature: &str,
) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("dormancy_proof_of_life"));
    m.insert("beat_target_identity".into(), serde_json::json!(target_identity));
    m.insert("beat_proof_signature".into(), serde_json::json!(signature));
    m
}

/// Build metadata for an XZoneLock operation (cross-zone transfer, sender side).
pub fn xzone_lock_metadata(
    amount: u64,
    recipient: &str,
    source_zone: &str,
    dest_zone: &str,
) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("xzone_lock"));
    m.insert("beat_amount".into(), serde_json::json!(amount.to_string()));
    m.insert("beat_to".into(), serde_json::json!(recipient));
    m.insert("beat_source_zone".into(), serde_json::json!(source_zone));
    m.insert("beat_dest_zone".into(), serde_json::json!(dest_zone));
    m
}

/// Build metadata for an XZoneClaim operation (cross-zone transfer, recipient side).
pub fn xzone_claim_metadata(
    transfer_id: &str,
    amount: u64,
    recipient: &str,
) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("xzone_claim"));
    m.insert("beat_transfer_id".into(), serde_json::json!(transfer_id));
    m.insert("beat_amount".into(), serde_json::json!(amount.to_string()));
    m.insert("beat_to".into(), serde_json::json!(recipient));
    m
}

/// Build metadata for an XZoneCancel operation (Gap 2 atomic-rollback).
/// Sender-initiated cancel of a still-unsealed XZoneLock; the apply path
/// refunds the locked amount back to the creator's available balance.
pub fn xzone_cancel_metadata(
    transfer_id: &str,
) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("xzone_cancel"));
    m.insert("beat_transfer_id".into(), serde_json::json!(transfer_id));
    m
}

/// Build metadata for an XZoneReject operation (Gap 2 atomic-rollback).
/// Recipient-initiated reject of a still-unsealed XZoneLock; the apply path
/// credits the original sender's available balance (NOT the creator).
pub fn xzone_reject_metadata(
    transfer_id: &str,
) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("xzone_reject"));
    m.insert("beat_transfer_id".into(), serde_json::json!(transfer_id));
    m
}

/// Build metadata for an XZoneAbort operation (Gap 2 sealed-abort).
///
/// Carries the destination-zone committee snapshot identifier
/// (`dest_committee_hash` + `dest_committee_size`) plus the witness
/// signatures, so the source-zone apply path can run the full proof check
/// without round-tripping to zone B at apply time. The transfer's
/// `dest_zone` and `source_seal_epoch` come from the on-source pending
/// entry — they are NOT carried in metadata to avoid a forge surface.
pub fn xzone_abort_metadata(
    transfer_id: &str,
    dest_committee_hash: &[u8; 32],
    dest_committee_size: u32,
    signers: &[crate::accounting::cross_zone::SealFinalityWitness],
) -> BTreeMap<String, serde_json::Value> {
    let mut m = BTreeMap::new();
    m.insert(BEAT_OP_KEY.into(), serde_json::json!("xzone_abort"));
    m.insert("beat_transfer_id".into(), serde_json::json!(transfer_id));
    m.insert(
        "xzone_dest_committee_hash".into(),
        serde_json::json!(hex::encode(dest_committee_hash)),
    );
    m.insert(
        "xzone_dest_committee_size".into(),
        serde_json::json!(dest_committee_size.to_string()),
    );
    m.insert(
        "xzone_abort_signers".into(),
        serde_json::to_value(signers).unwrap_or(serde_json::Value::Array(vec![])),
    );
    m
}

/// Domain tag for the canonical v2 ledger content-hash preimage.
pub const LEDGER_PREIMAGE_V2_TAG: &str = "ELARA_LEDGER_V2";

/// Canonicalize one metadata value for the v2 ledger preimage.
///
/// Number-vs-string encoding of the same integer MUST hash identically
/// (`get_u64` accepts both at apply time, so they are the same logical
/// value — the 9-decimal amount range is string-encoded on the wire).
/// f64 values canonicalize via to_bits (bit-exact, no float formatting);
/// arrays/objects via compact serde_json (deterministic for BTreeMap-backed
/// values).
///
/// NUMBER HANDLING MUST MIRROR THE BINARY WIRE CODEC
/// (`wire::encode_json_value`), which preserves a JSON integer only when
/// `n.as_i64()` is `Some` and collapses everything else — u64 values above
/// `i64::MAX`, and every float — into an f64. The builder computes a
/// record's `content_hash` from PRE-encode metadata; a verifier recomputes
/// it from POST-decode metadata. If the two disagreed on a value's type,
/// the `enforce_ledger_content_hash_v2` gate would reject an honest record
/// and wedge a syncing chain (audit 2026-07-06 follow-up). Branching on
/// `as_i64()` first — the codec's exact integer-preservation predicate —
/// makes the two sides agree for every value:
///   * `as_i64` Some → decimal (survives the codec as a `META_INT`);
///   * otherwise → the f64 bit pattern the codec transports (bit-exact
///     across `to_be_bytes`/`from_be_bytes`).
///
/// Honest ledger amounts ride the STRING branch (string-encoded by every
/// builder, lossless via `META_STRING`), so the f64 fallback is reached only
/// by a future raw-number field. Such a field is degraded to
/// consistent-but-lossy above `i64::MAX` — never to a wedge — but a new
/// large-value numeric field SHOULD be string-encoded (like `beat_amount`)
/// to stay lossless end-to-end.
fn canonical_preimage_value(v: &serde_json::Value) -> String {
    if let Some(i) = v.as_i64() {
        return i.to_string();
    }
    if let Some(s) = v.as_str() {
        // Numeric strings collapse to their decimal form (amount-encoding parity).
        if let Ok(u) = s.parse::<u64>() {
            return u.to_string();
        }
        return s.to_string();
    }
    if let Some(b) = v.as_bool() {
        return b.to_string();
    }
    if let Some(f) = v.as_f64() {
        // u64 values above i64::MAX AND genuine floats land here — the codec
        // stores both as f64, so hash the f64 bit pattern the wire carries.
        return format!("f{}", f.to_bits());
    }
    serde_json::to_string(v).unwrap_or_default()
}

/// Canonical v2 content-hash preimage for ledger records — THE single source
/// of truth shared by every ledger-record builder (`create_ledger_record_with_nonce`,
/// reward, slash, witness_register) and the ingest enforcement gate.
///
/// Returns `None` when the metadata carries no `beat_op` (not a ledger record).
///
/// Binds, netstring-framed (`len:bytes,` — unambiguous against free-text
/// injection via memo/reason fields):
///   - the domain tag,
///   - the creator's identity hash + the slot nonce (so the hash is a
///     self-contained slot-and-operation commitment),
///   - EVERY metadata entry, in BTreeMap (sorted) order — not a per-op field
///     table, so a new op or a new consensus-read key can never silently
///     fall out of the binding (audit 2026-07-06: the old
///     `"beat:<op>:<amount>"` form was blind to recipient/source/nonce AND
///     hashed every amount as 0 because builders string-encode
///     `beat_amount` while the preimage read it with `.as_u64()`).
pub fn canonical_ledger_preimage_v2(
    metadata: &BTreeMap<String, serde_json::Value>,
    creator_public_key: &[u8],
    nonce: u64,
) -> Option<String> {
    metadata.get(BEAT_OP_KEY)?;
    let mut out = String::with_capacity(256);
    let mut push = |s: &str| {
        out.push_str(&s.len().to_string());
        out.push(':');
        out.push_str(s);
        out.push(',');
    };
    push(LEDGER_PREIMAGE_V2_TAG);
    push("creator");
    push(&sha3_256_hex(creator_public_key));
    push("nonce");
    push(&nonce.to_string());
    for (k, v) in metadata {
        push(k);
        push(&canonical_preimage_value(v));
    }
    Some(out)
}

/// Recompute the canonical v2 preimage from a record's SIGNED fields and
/// compare against its embedded `content_hash`. `Ok(())` for non-ledger
/// records (no `beat_op`) and for matching ledger records; `Err` on mismatch.
///
/// This is the ingest enforcement gate's check (config
/// `enforce_ledger_content_hash_v2`, DEFAULT OFF until the re-genesis —
/// pre-v2 history re-ingested by catching-up followers would wedge
/// otherwise). Without enforcement the builder fix alone is cosmetic
/// against an adversary who hand-sets `content_hash`.
pub fn verify_ledger_content_hash_v2(record: &ValidationRecord) -> Result<()> {
    let Some(preimage) = canonical_ledger_preimage_v2(
        &record.metadata,
        &record.creator_public_key,
        record.nonce,
    ) else {
        return Ok(());
    };
    let expected = sha3_256(preimage.as_bytes());
    if record.content_hash.as_slice() != expected.as_slice() {
        return Err(ElaraError::Ledger(
            "ledger content_hash does not commit to the record's signed \
             metadata (canonical v2 preimage mismatch)"
                .into(),
        ));
    }
    Ok(())
}

/// Create a signed ledger record with an explicit slot nonce.
///
/// The record's content_hash is SHA3-256 of the canonical v2 ledger
/// preimage (`canonical_ledger_preimage_v2`) — it commits to the creator,
/// the slot nonce, and every signed metadata field (op, amount, recipient,
/// per-op identifiers), so two same-slot operations that differ in ANY
/// consensus-read field hash differently and equivocation between them is
/// provable via ConflictProof.
///
/// The `nonce` is stamped *before* signing so it is bound into the record's
/// wire bytes — this is the slot_key component that MESH-BFT Phase 3 Stage 1C
/// uses to enforce mutual exclusion. Callers MUST pass a monotonically
/// increasing value per-identity; reusing a nonce is equivocation: any pair
/// of distinct records claiming the same slot produces a ConflictProof at
/// every honest node (the pair is duplicate-not-conflict only when the two
/// records are byte-identical).
///
/// For in-node writers, prefer `NodeState::create_self_ledger_record` which
/// allocates the nonce from the per-node counter automatically.
pub fn create_ledger_record_with_nonce(
    identity: &crate::identity::Identity,
    parents: Vec<String>,
    metadata: BTreeMap<String, serde_json::Value>,
    nonce: u64,
) -> Result<ValidationRecord> {
    let content_str = canonical_ledger_preimage_v2(&metadata, &identity.public_key, nonce)
        .unwrap_or_else(|| format!("{LEDGER_PREIMAGE_V2_TAG},no_op"));

    let mut record = ValidationRecord::create(
        content_str.as_bytes(),
        identity.public_key.clone(),
        parents,
        Classification::Public,
        Some(metadata),
    );

    // Stamp the slot nonce BEFORE signing — otherwise the v5 signable bytes
    // reflect nonce=0 and the network rejects the record as equivocation.
    record.nonce = nonce;

    // Sign (dual-sig for Profile A)
    identity.sign_record(&mut record)?;

    Ok(record)
}

/// Legacy entry point — always emits nonce=0.
///
/// Retained for CLI / mobile / test call sites that don't yet have access to
/// a nonce counter (the CLI runs as a separate process and has no in-memory
/// state to bump). These paths either submit to a single-shot context where
/// slot_key=<account>:0 is unused, or need to be migrated to query
/// `/next_nonce` from the node RPC as part of a follow-up.
///
/// **Do not call this from inside the node** — use
/// `NodeState::create_self_ledger_record` instead. Every in-node site that
/// once called this has been migrated; new in-node writers must do the same
/// or they will collide with their own prior record on slot_key and gossip
/// a self-ConflictProof.
pub fn create_ledger_record(
    identity: &crate::identity::Identity,
    parents: Vec<String>,
    metadata: BTreeMap<String, serde_json::Value>,
) -> Result<ValidationRecord> {
    create_ledger_record_with_nonce(identity, parents, metadata, 0)
}

/// Get the identity hash (hex SHA3-256 of public key) from a record's creator.
/// Parse beat_amount from metadata — handles both number and string encoding.
/// Use this instead of `.as_u64()` for forward/backward compatibility.
pub fn parse_beat_amount(val: &serde_json::Value) -> Option<u64> {
    val.as_u64()
        .or_else(|| val.as_str().and_then(|s| s.parse::<u64>().ok()))
        .or_else(|| val.as_f64().map(|f| f as u64))
}

pub fn creator_identity_hash(record: &ValidationRecord) -> String {
    sha3_256_hex(&record.creator_public_key)
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Parse a u64 from metadata — accepts both JSON number and string encoding.
/// String encoding required for values > 2^53 (9-decimal beat amounts).
fn get_u64(meta: &BTreeMap<String, serde_json::Value>, key: &str) -> Result<u64> {
    let val = meta.get(key)
        .ok_or_else(|| ElaraError::Ledger(format!("missing field: {key}")))?;
    // Try number first (backward compat with 6-decimal records)
    if let Some(n) = val.as_u64() {
        return Ok(n);
    }
    // Try string (9-decimal amounts > 2^53)
    if let Some(s) = val.as_str() {
        return s.parse::<u64>()
            .map_err(|_| ElaraError::Ledger(format!("{key} must be a positive integer, got: {s}")));
    }
    // Try f64 → u64 (JSON numbers that lost precision)
    if let Some(f) = val.as_f64() {
        if f >= 0.0 && f <= u64::MAX as f64 {
            return Ok(f as u64);
        }
    }
    Err(ElaraError::Ledger(format!("{key} must be a positive integer")))
}

fn get_f64(meta: &BTreeMap<String, serde_json::Value>, key: &str) -> Result<f64> {
    meta.get(key)
        .ok_or_else(|| ElaraError::Ledger(format!("missing field: {key}")))?
        .as_f64()
        .ok_or_else(|| ElaraError::Ledger(format!("{key} must be a number")))
}

fn get_string(meta: &BTreeMap<String, serde_json::Value>, key: &str) -> Result<String> {
    meta.get(key)
        .ok_or_else(|| ElaraError::Ledger(format!("missing field: {key}")))?
        .as_str()
        .ok_or_else(|| ElaraError::Ledger(format!("{key} must be a string")))
        .map(|s| s.to_string())
}

fn get_string_or(
    meta: &BTreeMap<String, serde_json::Value>,
    key: &str,
    default: &str,
) -> String {
    meta.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or(default)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::sha3_256;

    fn dummy_pk() -> Vec<u8> {
        vec![0xAA; 1952]
    }

    fn make_ledger_record(
        metadata: BTreeMap<String, serde_json::Value>,
    ) -> ValidationRecord {
        ValidationRecord {
            id: "test-001".into(),
            version: crate::wire::WIRE_VERSION,
            content_hash: sha3_256(b"test").to_vec(),
            creator_public_key: dummy_pk(),
            timestamp: 1700000000.0,
            parents: vec![],
            classification: Classification::Public,
            metadata,
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
            itc_stamp: None,
            zone_refs: Vec::new(),
            creator_sphincs_pk: None,
            sig_algorithm: 0x01,
            sphincs_algorithm: None,
            zone: None,
            identity_hash_wire: None,
            nonce: 0,
        }
    }

    fn v2_test_identity() -> crate::identity::Identity {
        crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        )
        .unwrap()
    }

    /// Audit 2026-07-06 pin: the canonical v2 preimage binds amount (at
    /// genesis scale — the old form hashed every string-encoded amount as
    /// 0), recipient, and nonce; number-vs-string amount encodings hash
    /// identically.
    #[test]
    fn canonical_v2_preimage_binds_amount_recipient_nonce() {
        let pk = dummy_pk();
        // Genesis-scale mint (1e19 > 2^53, string-encoded by the builder).
        let mint = mint_metadata(10_000_000_000_000_000_000u64, "abc123", "genesis");
        let p = canonical_ledger_preimage_v2(&mint, &pk, 0).unwrap();
        assert!(
            p.contains("10000000000000000000"),
            "amount must be bound at full value, got: {p}"
        );

        // Same amount, different recipients → different preimages.
        let t_x = transfer_metadata(100, "recipient_x", None);
        let t_y = transfer_metadata(100, "recipient_y", None);
        let p_x = canonical_ledger_preimage_v2(&t_x, &pk, 7).unwrap();
        let p_y = canonical_ledger_preimage_v2(&t_y, &pk, 7).unwrap();
        assert_ne!(p_x, p_y, "recipient must be bound");

        // Same everything, different nonce → different preimages.
        let p_n8 = canonical_ledger_preimage_v2(&t_x, &pk, 8).unwrap();
        assert_ne!(p_x, p_n8, "nonce must be bound");

        // Number vs string encoding of the same amount → identical preimage
        // (get_u64 accepts both at apply; they are the same logical value).
        let mut t_num = transfer_metadata(100, "recipient_x", None);
        t_num.insert("beat_amount".into(), serde_json::json!(100u64));
        let p_num = canonical_ledger_preimage_v2(&t_num, &pk, 7).unwrap();
        assert_eq!(p_x, p_num, "number/string amount encodings must collapse");

        // No beat_op → not a ledger record → None.
        assert!(canonical_ledger_preimage_v2(&BTreeMap::new(), &pk, 0).is_none());
    }

    /// Audit 2026-07-06 pin: the enforcement gate accepts records from the
    /// standard builder and the witness_register shape, and rejects a
    /// record whose content_hash no longer commits to its metadata.
    #[test]
    fn verify_ledger_content_hash_v2_accepts_builders_rejects_tamper() {
        let id = v2_test_identity();

        // Standard builder (transfer).
        let rec = create_ledger_record_with_nonce(
            &id,
            vec![],
            transfer_metadata(42, "recipient_x", Some("memo")),
            3,
        )
        .unwrap();
        assert!(verify_ledger_content_hash_v2(&rec).is_ok());

        // witness_register shape (the admin handler builds it exactly so).
        let meta = witness_register_metadata("0", WITNESS_BOND_MIN);
        let content = canonical_ledger_preimage_v2(&meta, &id.public_key, 9).unwrap();
        let mut wr = ValidationRecord::create(
            content.as_bytes(),
            id.public_key.clone(),
            vec![],
            Classification::Public,
            Some(meta),
        );
        wr.nonce = 9;
        assert!(verify_ledger_content_hash_v2(&wr).is_ok());

        // Tamper: swap the recipient after building → gate rejects.
        let mut tampered = rec.clone();
        tampered
            .metadata
            .insert("beat_to".into(), serde_json::json!("attacker"));
        assert!(verify_ledger_content_hash_v2(&tampered).is_err());

        // Tamper: hand-set content_hash → gate rejects.
        let mut hand_set = rec.clone();
        hand_set.content_hash = sha3_256(b"beat:transfer:42").to_vec();
        assert!(verify_ledger_content_hash_v2(&hand_set).is_err());

        // Non-ledger record (no beat_op) → gate is a no-op.
        let plain = make_ledger_record(BTreeMap::new());
        assert!(verify_ledger_content_hash_v2(&plain).is_ok());
    }

    /// Audit 2026-07-06 FOLLOW-UP pin: the v2 preimage MUST be stable across
    /// the binary metadata wire codec. The builder hashes PRE-encode
    /// metadata; an ingesting verifier recomputes from POST-decode metadata.
    /// The codec preserves a JSON integer only within the i64 range and
    /// collapses u64 > i64::MAX (and floats) to f64 — so a raw-number field
    /// above i64::MAX is exactly the type-drift case that would make an
    /// honest record fail its own `enforce_ledger_content_hash_v2` gate and
    /// wedge a syncing chain. `canonical_preimage_value` branches on
    /// `as_i64()` to mirror the codec; this test locks that the two sides
    /// agree even for a > i64::MAX raw integer.
    #[test]
    fn v2_preimage_is_stable_across_the_binary_wire_codec() {
        let pk = dummy_pk();

        // A beat_op record carrying: the honest string-encoded amount, a
        // sub-i64::MAX raw number (timestamp shape — the only raw-number
        // metadata any current builder emits), AND a hypothetical future
        // raw u64 field above i64::MAX (1e19 > i64::MAX ≈ 9.22e18) — the
        // precise type-drift trigger.
        let mut meta = transfer_metadata(500, "recipient_x", Some("memo"));
        meta.insert("beat_last_activity".into(), serde_json::json!(1_700_000_000_u64));
        meta.insert(
            "future_raw_big".into(),
            serde_json::json!(10_000_000_000_000_000_000_u64),
        );

        let pre = canonical_ledger_preimage_v2(&meta, &pk, 42).unwrap();

        // Round-trip the metadata through the ACTUAL wire codec.
        let mut buf = Vec::new();
        crate::wire::encode_metadata_binary(&mut buf, &meta).unwrap();
        let mut reader = crate::wire::WireReader::new(&buf);
        let decoded = crate::wire::decode_metadata_binary(&mut reader).unwrap();

        let post = canonical_ledger_preimage_v2(&decoded, &pk, 42).unwrap();

        assert_eq!(
            pre, post,
            "v2 preimage drifted across the wire codec — enforce_ledger_content_hash_v2 \
             would reject an honest record and wedge the chain"
        );

        // End-to-end: a built record whose metadata has been round-tripped
        // through the codec (what an ingesting verifier actually sees) still
        // passes its own content-hash gate.
        let id = v2_test_identity();
        // 9.5e18 > i64::MAX — string-encoded by transfer_metadata, so it
        // rides the lossless META_STRING path end-to-end.
        let mut built = create_ledger_record_with_nonce(
            &id,
            vec![],
            transfer_metadata(9_500_000_000_000_000_000u64, "recipient_y", None),
            11,
        )
        .unwrap();
        let mut b2 = Vec::new();
        crate::wire::encode_metadata_binary(&mut b2, &built.metadata).unwrap();
        let mut r2 = crate::wire::WireReader::new(&b2);
        built.metadata = crate::wire::decode_metadata_binary(&mut r2).unwrap();
        assert!(
            verify_ledger_content_hash_v2(&built).is_ok(),
            "record must survive its own gate after a metadata wire round-trip"
        );
    }

    #[test]
    fn test_extract_mint() {
        let meta = mint_metadata(1_000_000, "abc123", "genesis");
        let rec = make_ledger_record(meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        match op {
            ParsedLedgerOp::Mint { amount, to, reason } => {
                assert_eq!(amount, 1_000_000);
                assert_eq!(to, "abc123");
                assert_eq!(reason, "genesis");
            }
            _ => panic!("expected Mint"),
        }
    }

    #[test]
    fn test_extract_transfer() {
        let meta = transfer_metadata(500_000, "recipient_hash", Some("payment"));
        let rec = make_ledger_record(meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        match op {
            ParsedLedgerOp::Transfer { amount, to, memo } => {
                assert_eq!(amount, 500_000);
                assert_eq!(to, "recipient_hash");
                assert_eq!(memo.as_deref(), Some("payment"));
            }
            _ => panic!("expected Transfer"),
        }
    }

    #[test]
    fn test_extract_stake() {
        let meta = stake_metadata(100 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let rec = make_ledger_record(meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        match op {
            ParsedLedgerOp::Stake { amount, purpose } => {
                assert_eq!(amount, 100 * BASE_UNITS_PER_BEAT);
                assert_eq!(purpose, StakePurpose::Witness);
            }
            _ => panic!("expected Stake"),
        }
    }

    #[test]
    fn test_extract_unstake() {
        let meta = unstake_metadata("stake-record-001");
        let rec = make_ledger_record(meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        match op {
            ParsedLedgerOp::Unstake { stake_record_id } => {
                assert_eq!(stake_record_id, "stake-record-001");
            }
            _ => panic!("expected Unstake"),
        }
    }

    #[test]
    fn test_extract_non_ledger_record() {
        let rec = make_ledger_record(BTreeMap::new());
        assert!(extract_ledger_op(&rec).unwrap().is_none());
    }

    #[test]
    fn test_extract_unknown_op() {
        let mut meta = BTreeMap::new();
        meta.insert(BEAT_OP_KEY.into(), serde_json::json!("freeze"));
        let rec = make_ledger_record(meta);
        assert!(extract_ledger_op(&rec).is_err());
    }

    #[test]
    fn test_transfer_missing_amount() {
        let mut meta = BTreeMap::new();
        meta.insert(BEAT_OP_KEY.into(), serde_json::json!("transfer"));
        meta.insert("beat_to".into(), serde_json::json!("abc"));
        let rec = make_ledger_record(meta);
        assert!(extract_ledger_op(&rec).is_err());
    }

    #[test]
    fn test_ledger_op_roundtrip() {
        for op in [LedgerOp::Mint, LedgerOp::Transfer, LedgerOp::Stake, LedgerOp::Unstake, LedgerOp::WitnessReward, LedgerOp::Slash, LedgerOp::DormancyReclaim, LedgerOp::Burn, LedgerOp::PoolFund, LedgerOp::Predict, LedgerOp::XZoneLock, LedgerOp::XZoneClaim, LedgerOp::XZoneCancel, LedgerOp::XZoneReject, LedgerOp::XZoneAbort, LedgerOp::DormancyDeclare, LedgerOp::DormancyHeartbeat, LedgerOp::DormancyProofOfLife] {
            let s = op.as_str();
            let parsed = LedgerOp::from_str(s).unwrap();
            assert_eq!(parsed, op);
        }
    }

    #[test]
    fn test_stake_purpose_roundtrip() {
        for p in [StakePurpose::Witness, StakePurpose::Governance, StakePurpose::Storage] {
            let s = p.as_str();
            let parsed = StakePurpose::from_str(s).unwrap();
            assert_eq!(parsed, p);
        }
    }

    #[test]
    fn test_extract_slash() {
        let jury = vec!["juror_a".to_string(), "juror_b".to_string()];
        let meta = slash_metadata(
            500_000, "offender_hash", "challenger_hash", &jury,
            "stake-001", "double signing",
        );
        let rec = make_ledger_record(meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        match op {
            ParsedLedgerOp::Slash { amount, offender, challenger, jury, stake_record_id, reason } => {
                assert_eq!(amount, 500_000);
                assert_eq!(offender, "offender_hash");
                assert_eq!(challenger, "challenger_hash");
                assert_eq!(jury, vec!["juror_a", "juror_b"]);
                assert_eq!(stake_record_id, "stake-001");
                assert_eq!(reason, "double signing");
            }
            _ => panic!("expected Slash"),
        }
    }

    #[test]
    fn test_extract_slash_legacy_string_jury() {
        // Legacy format: jury as single string (backward compat)
        let mut meta = std::collections::BTreeMap::new();
        meta.insert("beat_op".into(), serde_json::json!("slash"));
        meta.insert("beat_amount".into(), serde_json::json!(500_000u64.to_string()));
        meta.insert("beat_offender".into(), serde_json::json!("offender_hash"));
        meta.insert("beat_challenger".into(), serde_json::json!("challenger_hash"));
        meta.insert("beat_jury".into(), serde_json::json!("legacy_jury"));
        meta.insert("beat_stake_id".into(), serde_json::json!("stake-001"));
        meta.insert("beat_reason".into(), serde_json::json!("test"));
        let rec = make_ledger_record(meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        match op {
            ParsedLedgerOp::Slash { jury, .. } => {
                assert_eq!(jury, vec!["legacy_jury".to_string()]);
            }
            _ => panic!("expected Slash"),
        }
    }

    #[test]
    fn test_extract_dormancy_reclaim() {
        let meta = dormancy_reclaim_metadata(1_000_000, "dormant_hash", 1000000.0);
        let rec = make_ledger_record(meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        match op {
            ParsedLedgerOp::DormancyReclaim { amount, dormant_identity, last_activity } => {
                assert_eq!(amount, 1_000_000);
                assert_eq!(dormant_identity, "dormant_hash");
                assert_eq!(last_activity, 1000000.0);
            }
            _ => panic!("expected DormancyReclaim"),
        }
    }

    #[test]
    fn test_extract_burn() {
        let meta = burn_metadata(500_000, Some("deflationary"));
        let rec = make_ledger_record(meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        match op {
            ParsedLedgerOp::Burn { amount, memo } => {
                assert_eq!(amount, 500_000);
                assert_eq!(memo.as_deref(), Some("deflationary"));
            }
            _ => panic!("expected Burn"),
        }
    }

    #[test]
    fn test_extract_burn_no_memo() {
        let meta = burn_metadata(1_000_000, None);
        let rec = make_ledger_record(meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        match op {
            ParsedLedgerOp::Burn { amount, memo } => {
                assert_eq!(amount, 1_000_000);
                assert!(memo.is_none());
            }
            _ => panic!("expected Burn"),
        }
    }

    #[test]
    fn test_extract_idle_decay_batch_roundtrip() {
        use crate::accounting::idle_decay::IdleDecayBatch;
        // 1.5M debit == 750k pool + 750k stakers → conserved.
        let batch = IdleDecayBatch {
            epoch: 42,
            zone: "medical/eu".into(),
            debits: vec![("exch_a".into(), 1_000_000), ("exch_b".into(), 500_000)],
            pool_credit: 750_000,
            staker_credits: vec![("staker_x".into(), 500_000), ("staker_y".into(), 250_000)],
        };
        assert!(batch.is_conserved());
        let meta = idle_decay_batch_metadata(&batch);
        let rec = make_ledger_record(meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        match op {
            ParsedLedgerOp::IdleDecay { batch: parsed } => {
                assert_eq!(parsed, batch, "batch must survive the metadata round-trip");
            }
            _ => panic!("expected IdleDecay"),
        }
    }

    #[test]
    fn test_idle_decay_ledger_op_string_roundtrip() {
        assert_eq!(LedgerOp::IdleDecay.as_str(), "idle_decay");
        assert_eq!(LedgerOp::from_str("idle_decay").unwrap(), LedgerOp::IdleDecay);
    }

    #[test]
    fn test_extract_predict_active() {
        let meta = predict_metadata(
            10 * BASE_UNITS_PER_BEAT,
            "medical/eu",
            42,
            &PredictionClaim::Active,
            1,
        );
        let rec = make_ledger_record(meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        match op {
            ParsedLedgerOp::Predict { amount, zone, target_epoch, claim, predicted_value } => {
                assert_eq!(amount, 10 * BASE_UNITS_PER_BEAT);
                assert_eq!(zone, "medical/eu");
                assert_eq!(target_epoch, 42);
                assert_eq!(claim, PredictionClaim::Active);
                assert_eq!(predicted_value, 1);
            }
            _ => panic!("expected Predict"),
        }
    }

    #[test]
    fn test_extract_predict_volume() {
        let meta = predict_metadata(
            50 * BASE_UNITS_PER_BEAT,
            "iot/sensors",
            100,
            &PredictionClaim::Volume,
            500,
        );
        let rec = make_ledger_record(meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        match op {
            ParsedLedgerOp::Predict { amount, zone, target_epoch, claim, predicted_value } => {
                assert_eq!(amount, 50 * BASE_UNITS_PER_BEAT);
                assert_eq!(zone, "iot/sensors");
                assert_eq!(target_epoch, 100);
                assert_eq!(claim, PredictionClaim::Volume);
                assert_eq!(predicted_value, 500);
            }
            _ => panic!("expected Predict"),
        }
    }

    #[test]
    fn test_prediction_claim_roundtrip() {
        for c in [PredictionClaim::Active, PredictionClaim::Volume, PredictionClaim::IdentityCount] {
            let s = c.as_str();
            let parsed = PredictionClaim::from_str(s).unwrap();
            assert_eq!(parsed, c);
        }
    }

    #[test]
    fn test_creator_identity_hash() {
        let rec = make_ledger_record(BTreeMap::new());
        let hash = creator_identity_hash(&rec);
        assert_eq!(hash.len(), 64); // hex SHA3-256
    }

    #[test]
    fn test_extract_witness_register() {
        let meta = witness_register_metadata("zone:hel", WITNESS_BOND_MIN);
        let rec = make_ledger_record(meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        match op {
            ParsedLedgerOp::WitnessRegister { zone_path, bond } => {
                assert_eq!(zone_path, "zone:hel");
                assert_eq!(bond, WITNESS_BOND_MIN);
            }
            _ => panic!("expected WitnessRegister"),
        }
    }

    #[test]
    fn test_witness_register_below_min_rejected() {
        let meta = witness_register_metadata("zone:hel", WITNESS_BOND_MIN - 1);
        let rec = make_ledger_record(meta);
        let err = extract_ledger_op(&rec).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("below minimum"), "expected bond-floor rejection, got: {msg}");
    }

    #[test]
    fn test_witness_register_empty_zone_rejected() {
        let meta = witness_register_metadata("", WITNESS_BOND_MIN);
        let rec = make_ledger_record(meta);
        let err = extract_ledger_op(&rec).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("beat_zone empty"), "expected empty-zone rejection, got: {msg}");
    }

    #[test]
    fn batch_b_ledger_op_roundtrip_all_19_variants_and_rejects_unknown() {
        // Pin every LedgerOp variant's wire string — exhaustively covers all 19
        // variants (including WitnessRegister) AND verifies rejection of
        // malformed inputs.
        let cases: &[(LedgerOp, &str)] = &[
            (LedgerOp::Mint, "mint"),
            (LedgerOp::Transfer, "transfer"),
            (LedgerOp::Stake, "stake"),
            (LedgerOp::Unstake, "unstake"),
            (LedgerOp::WitnessReward, "witness_reward"),
            (LedgerOp::Slash, "slash"),
            (LedgerOp::DormancyReclaim, "dormancy_reclaim"),
            (LedgerOp::Burn, "burn"),
            (LedgerOp::PoolFund, "pool_fund"),
            (LedgerOp::Predict, "predict"),
            (LedgerOp::XZoneLock, "xzone_lock"),
            (LedgerOp::XZoneClaim, "xzone_claim"),
            (LedgerOp::XZoneCancel, "xzone_cancel"),
            (LedgerOp::XZoneReject, "xzone_reject"),
            (LedgerOp::XZoneAbort, "xzone_abort"),
            (LedgerOp::DormancyDeclare, "dormancy_declare"),
            (LedgerOp::DormancyHeartbeat, "dormancy_heartbeat"),
            (LedgerOp::DormancyProofOfLife, "dormancy_proof_of_life"),
            (LedgerOp::WitnessRegister, "witness_register"),
        ];
        assert_eq!(cases.len(), 19, "must cover all 19 LedgerOp variants");
        for (op, s) in cases {
            assert_eq!(&op.as_str(), s, "as_str for {:?}", op);
            let parsed = LedgerOp::from_str(s).expect("from_str must succeed");
            assert_eq!(&parsed, op, "round-trip for {:?}", op);
        }
        // Reject malformed inputs.
        assert!(LedgerOp::from_str("FOO").is_err());
        assert!(LedgerOp::from_str("").is_err());
        assert!(LedgerOp::from_str("MINT").is_err(), "uppercase must be rejected (snake_case only)");
        assert!(LedgerOp::from_str("Mint").is_err(), "mixed case must be rejected");
        assert!(LedgerOp::from_str("beat_mint").is_err(), "prefixed must be rejected");
    }

    #[test]
    fn batch_b_stake_purpose_and_prediction_claim_roundtrip_all_variants_and_reject_unknown() {
        // StakePurpose: 3 variants + rejection.
        for (p, s) in [
            (StakePurpose::Witness, "witness"),
            (StakePurpose::Governance, "governance"),
            (StakePurpose::Storage, "storage"),
        ] {
            assert_eq!(p.as_str(), s);
            let parsed = StakePurpose::from_str(s).expect("from_str must succeed");
            assert_eq!(parsed, p);
        }
        assert!(StakePurpose::from_str("delegate").is_err());
        assert!(StakePurpose::from_str("").is_err());
        assert!(StakePurpose::from_str("WITNESS").is_err(), "uppercase must be rejected");

        // PredictionClaim: 3 variants + rejection.
        for (c, s) in [
            (PredictionClaim::Active, "active"),
            (PredictionClaim::Volume, "volume"),
            (PredictionClaim::IdentityCount, "identity_count"),
        ] {
            assert_eq!(c.as_str(), s);
            let parsed = PredictionClaim::from_str(s).expect("from_str must succeed");
            assert_eq!(parsed, c);
        }
        assert!(PredictionClaim::from_str("identityCount").is_err(), "camelCase must be rejected");
        assert!(PredictionClaim::from_str("").is_err());
        assert!(PredictionClaim::from_str("ACTIVE").is_err());
    }

    #[test]
    fn batch_b_economic_constants_pin_micros_supply_and_slash_split_invariant() {
        // Pin the load-bearing economic constants. These are protocol-level numbers;
        // a silent drift in any of them changes monetary policy or stake economics.
        assert_eq!(BASE_UNITS_PER_BEAT, 1_000_000_000, "1 beat = 1e9 micros");
        assert_eq!(MAX_SUPPLY, 10_000_000_000 * BASE_UNITS_PER_BEAT, "10B beat total supply cap");
        assert_eq!(MIN_STAKE, 100 * BASE_UNITS_PER_BEAT, "min stake = 100 beat");
        assert_eq!(WITNESS_BOND_MIN, MIN_STAKE, "witness bond floor == MIN_STAKE");
        assert_eq!(DEFAULT_WITNESS_REWARD, BASE_UNITS_PER_BEAT, "default witness reward = 1 beat");
        assert_eq!(MAX_WITNESS_REWARD, 10 * BASE_UNITS_PER_BEAT, "max witness reward = 10 beat");
        assert_eq!(PROFILE_B_TRANSFER_CAP, 1_000 * BASE_UNITS_PER_BEAT, "Profile B cap = 1000 beat");

        // Unstake cooldown is exactly 7 days.
        assert_eq!(UNSTAKE_COOLDOWN, 7.0 * 24.0 * 3600.0);

        // Slash split MUST sum to exactly 1.0 — pool/challenger/jury partition the slashed stake.
        let sum = SLASH_POOL_FRACTION + SLASH_CHALLENGER_FRACTION + SLASH_JURY_FRACTION;
        assert!((sum - 1.0).abs() < 1e-12, "slash fractions must sum to 1.0: got {}", sum);
        // Pin the split itself.
        assert_eq!(SLASH_POOL_FRACTION, 0.50);
        assert_eq!(SLASH_CHALLENGER_FRACTION, 0.30);
        assert_eq!(SLASH_JURY_FRACTION, 0.20);
        assert_eq!(MAX_SLASH_PERCENTAGE, 0.50, "max single-event slash = 50% of stake");

        // Pool / dormancy guardrails.
        assert_eq!(CONSERVATION_POOL_MAX_FRACTION, 0.10);
        assert_eq!(DORMANCY_THRESHOLD, 5.0 * 365.25 * 24.0 * 3600.0, "5 years (Julian)");
        assert_eq!(DORMANCY_WAKEUP_WINDOW, 2.0 * 365.25 * 24.0 * 3600.0, "2-year wake-up");

        // Prediction constants.
        assert_eq!(MIN_PREDICTION_STAKE, 10 * BASE_UNITS_PER_BEAT, "min prediction stake = 10 beat");
        assert!((PREDICTION_REWARD_RATE - 0.10).abs() < 1e-12);
        assert!((PREDICTION_MARGIN - 0.20).abs() < 1e-12);

        // beat_op metadata key — wire-format invariant.
        assert_eq!(BEAT_OP_KEY, "beat_op");

        // Conservation pool identity — pin the exact wire-string. Virtual identity
        // (no private key); changes here would orphan accumulated pool balance.
        assert_eq!(
            CONSERVATION_POOL_IDENTITY,
            "conservation_pool_0000000000000000000000000000000000000000",
        );
        assert!(
            CONSERVATION_POOL_IDENTITY.starts_with("conservation_pool_"),
            "must keep human-readable prefix",
        );
    }

    #[test]
    fn batch_b_extract_ledger_op_beat_op_type_mismatch_returns_err_and_missing_is_none() {
        // beat_op absent → Ok(None) — record is simply not a ledger operation.
        let rec = make_ledger_record(BTreeMap::new());
        assert!(extract_ledger_op(&rec).expect("ok").is_none(), "missing beat_op → Ok(None)");

        // beat_op present but wrong JSON type → Err("must be a string").
        for bad_val in [
            serde_json::json!(42),
            serde_json::json!(4.2),
            serde_json::json!(true),
            serde_json::json!(null),
            serde_json::json!({"nested": "object"}),
            serde_json::json!(["array", "of", "strings"]),
        ] {
            let mut meta = BTreeMap::new();
            meta.insert(BEAT_OP_KEY.into(), bad_val.clone());
            let rec = make_ledger_record(meta);
            let err = extract_ledger_op(&rec).unwrap_err();
            let msg = format!("{}", err);
            assert!(
                msg.contains("must be a string") || msg.contains("unknown ledger op"),
                "for value {:?}, expected type/unknown-op error, got: {}",
                bad_val, msg,
            );
        }

        // beat_op = "" (empty string) → "unknown ledger op: " err (from LedgerOp::from_str).
        let mut meta = BTreeMap::new();
        meta.insert(BEAT_OP_KEY.into(), serde_json::json!(""));
        let rec = make_ledger_record(meta);
        assert!(extract_ledger_op(&rec).is_err(), "empty string must Err");
    }

    #[test]
    fn batch_b_metadata_builders_pin_op_strings_and_optional_field_handling() {
        // Mint emits 4 keys: beat_op + amount + to + reason.
        let mint = mint_metadata(100, "alice", "genesis");
        assert_eq!(mint.get(BEAT_OP_KEY).and_then(|v| v.as_str()), Some("mint"));
        assert_eq!(mint.get("beat_amount").and_then(|v| v.as_str()), Some("100"), "u64 encoded as string");
        assert_eq!(mint.get("beat_to").and_then(|v| v.as_str()), Some("alice"));
        assert_eq!(mint.get("beat_reason").and_then(|v| v.as_str()), Some("genesis"));

        // Transfer WITH memo → beat_memo present.
        let xfer_with_memo = transfer_metadata(50, "bob", Some("hello"));
        assert_eq!(xfer_with_memo.get(BEAT_OP_KEY).and_then(|v| v.as_str()), Some("transfer"));
        assert_eq!(xfer_with_memo.get("beat_memo").and_then(|v| v.as_str()), Some("hello"));

        // Transfer WITHOUT memo → no beat_memo key in the map at all.
        let xfer_no_memo = transfer_metadata(50, "bob", None);
        assert!(!xfer_no_memo.contains_key("beat_memo"), "no memo → key omitted, not null");

        // Burn WITH and WITHOUT memo — same optional behaviour.
        let burn_with = burn_metadata(1, Some("oops"));
        assert_eq!(burn_with.get("beat_memo").and_then(|v| v.as_str()), Some("oops"));
        let burn_no = burn_metadata(1, None);
        assert!(!burn_no.contains_key("beat_memo"));

        // Stake — pins the purpose wire string for all 3 variants.
        for (purpose, expected) in [
            (StakePurpose::Witness, "witness"),
            (StakePurpose::Governance, "governance"),
            (StakePurpose::Storage, "storage"),
        ] {
            let meta = stake_metadata(100, &purpose);
            assert_eq!(meta.get(BEAT_OP_KEY).and_then(|v| v.as_str()), Some("stake"));
            assert_eq!(meta.get("beat_purpose").and_then(|v| v.as_str()), Some(expected));
        }

        // DormancyHeartbeat — only the op key, no payload.
        let hb = dormancy_heartbeat_metadata();
        assert_eq!(hb.len(), 1, "heartbeat has only beat_op");
        assert_eq!(hb.get(BEAT_OP_KEY).and_then(|v| v.as_str()), Some("dormancy_heartbeat"));

        // WitnessRegister — bond serialized as string (JSON-number-safe u64).
        let wr = witness_register_metadata("/zones/test", WITNESS_BOND_MIN);
        assert_eq!(wr.get(BEAT_OP_KEY).and_then(|v| v.as_str()), Some("witness_register"));
        assert_eq!(wr.get("beat_zone").and_then(|v| v.as_str()), Some("/zones/test"));
        assert_eq!(
            wr.get("beat_bond").and_then(|v| v.as_str()),
            Some(WITNESS_BOND_MIN.to_string().as_str()),
        );
    }
}
