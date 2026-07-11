//! beat Ledger — balance derivation by replaying ledger records from the DAG.
//!
//! There is no separate balance database. Balances are computed by scanning
//! all records with `beat_op` metadata, ordered by timestamp, and applying
//! each operation to a running balance map.
//!
//! This is the canonical state derivation — the DAG IS the ledger.

//!
//! Spec references:
//!   @spec economics §16.1
//!   @spec economics §2.1

use std::collections::HashMap;

use crate::errors::{ElaraError, Result};
use crate::identity::CryptoProfile;
use crate::record::ValidationRecord;
use crate::accounting::acquisition::{AcquisitionTracker, VestingManager};
use crate::accounting::authority::is_privileged_emitter;
use crate::accounting::circuit_breaker::CircuitBreaker;
use crate::accounting::governance::GovernanceState;
use crate::accounting::types::*;
use crate::accounting::cross_zone::CrossZoneState;
use crate::accounting::idle_decay::IdleDecayState;
use crate::accounting::custodial::ExchangeClassifier;
use crate::accounting::velocity::VelocityTracker;

/// Active prediction entry — locked stake awaiting epoch evaluation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PredictionEntry {
    pub record_id: String,
    pub predictor: String,
    pub amount: u64,
    pub zone: String,
    pub target_epoch: u64,
    pub claim: PredictionClaim,
    pub predicted_value: u64,
    pub timestamp: f64,
    /// None = pending, Some(true) = correct, Some(false) = wrong.
    pub outcome: Option<bool>,
}

/// Active stake entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StakeEntry {
    pub record_id: String,
    pub amount: u64,
    pub purpose: StakePurpose,
    pub staker: String,
    pub timestamp: f64,
    pub active: bool,
}

/// Account state for a single identity.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AccountState {
    /// Available (liquid) balance in base units.
    pub available: u64,
    /// Total staked amount in base units.
    pub staked: u64,
    /// Total ever received (including mints).
    pub total_received: u64,
    /// Total ever sent (transfers + stakes).
    pub total_sent: u64,
    /// Number of ledger operations by this identity.
    pub tx_count: u64,
    /// Timestamp of last activity (any ledger operation involving this account).
    /// Used for dormancy detection.
    pub last_active: f64,
    /// Locked vesting balance in base units (vests by accumulated uptime).
    /// Not spendable until uptime-vesting milestones unlock it.
    /// Unlocked portions move to `available`. See `uptime_vesting.rs`.
    #[serde(default)]
    pub vested_locked: u64,
    /// Accumulated online uptime in seconds (persisted across restarts).
    /// Used for uptime-vesting milestones.
    #[serde(default)]
    pub uptime_secs: u64,
    /// Consecutive days inactive (for inactivity drain).
    /// Reset to 0 when node is active (online ≥1h within 7 days).
    #[serde(default)]
    pub inactive_days: u32,
    /// beat bonded as a finality witness across all zones (Gap 2.1
    /// Phase 2b.3 Slice 3). Deducted from `available` at the time of
    /// `WitnessRegister` apply and held until an explicit unregister
    /// (out of scope for Slice 3). Excluded from `total()` and
    /// `total_with_locked()` so the SMT and downstream balance views
    /// reflect liquid + staked only — same accounting shape as
    /// `pending_xzone_locked` at the global level.
    #[serde(default)]
    pub witness_bonded: u64,
}

impl AccountState {
    /// Total balance = available + staked (excludes vested_locked).
    pub fn total(&self) -> u64 {
        self.available + self.staked
    }

    /// Full balance including locked vesting credits.
    pub fn total_with_locked(&self) -> u64 {
        self.available + self.staked + self.vested_locked
    }
}

/// Complete ledger state derived from DAG replay.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LedgerState {
    /// Per-identity account states.
    pub accounts: HashMap<String, AccountState>,
    /// Active stakes (keyed by stake record ID).
    pub stakes: HashMap<String, StakeEntry>,
    /// Total supply minted.
    pub total_supply: u64,
    /// Total currently staked across all accounts.
    pub total_staked: u64,
    /// Conservation Pool balance (base units).
    /// Hard cap: CONSERVATION_POOL_MAX_FRACTION * total_supply.
    pub conservation_pool: u64,
    /// Pool disbursement tracking: (month_start_timestamp, amount_disbursed_this_month).
    /// Hard limit: max 1% of pool balance per 30-day window (economics §2.4).
    ///
    /// LATENT DETERMINISM HAZARD (C11): the `.0` window-start is an f64 wall-clock
    /// timestamp and `record_pool_disbursement`/`pool_monthly_remaining` have NO
    /// production caller today (test-only). DO NOT wire pool disbursement into the
    /// apply path without passing a consensus-replicated `now` (a sealed record's
    /// timestamp) — a per-node wall-clock window boundary forks the conservation
    /// pool across nodes. See internal design notes.
    #[serde(default)]
    pub pool_disbursed_window: (f64, u64),
    /// Number of ledger records processed.
    pub records_processed: u64,
    /// Transfer velocity tracker (transient — rebuilt from DAG replay).
    #[serde(skip)]
    pub velocity: VelocityTracker,
    /// Circuit breaker state (transient — rebuilt from DAG replay).
    #[serde(skip)]
    pub circuit_breaker: CircuitBreaker,
    /// Acquisition velocity tracker (transient — rebuilt from DAG replay).
    #[serde(skip)]
    pub acquisition: AcquisitionTracker,
    /// Vesting schedules for large mints. Persisted in snapshots (was
    /// `#[serde(skip)]`) so a snapshot-bootstrapped node inherits the 365-day
    /// large-mint lock instead of starting empty. The lock gates
    /// `transferable_balance` on the consensus apply path, so dropping it forked a
    /// bootstrapped node from a since-genesis node (balance → account-SMT-root
    /// divergence, no self-heal). `#[serde(default)]` keeps pre-fix snapshots (no
    /// field) loadable — they land empty, exactly the prior behavior. See
    /// internal design notes (Track C).
    #[serde(default)]
    pub vesting: VestingManager,
    /// Governance state — proposals, votes, conviction.
    /// Persisted in snapshots for fast restart. Falls back to empty if missing (backward compat).
    #[serde(default)]
    pub governance: GovernanceState,
    /// Cryptographic profile per identity (Profile A = dual-sig, Profile B = single-sig).
    /// Used to enforce per-transaction transfer caps for Profile B identities.
    #[serde(default)]
    pub identity_profiles: HashMap<String, CryptoProfile>,
    /// Hardware attestation level per identity (Profile C Gap C / economics §11.33).
    /// Auto-registered from `record.metadata["attestation_level"]` on every applied
    /// record, monotonically (only upgrades, never downgrades — once an identity
    /// has demonstrated it can attest at level N, dropping to N-1 must not bypass
    /// the gate). Unknown identities default to `AttestationLevel::None` (rank 0).
    /// Read at delegation_op authorize time to gate Gateway eligibility.
    #[serde(default)]
    pub attestation_levels: HashMap<String, crate::identity::AttestationLevel>,
    /// Applied record IDs — prevents double-counting during rebuild_ledger.
    /// Runtime dedup is now handled by RocksDB CF_APPLIED (avoids cloning 135K+ entries).
    ///
    /// Gap 7 (2026-04-21): this set IS serialized on the wire for snapshot
    /// transfers. A bootstrapping peer populates its own CF_APPLIED from this
    /// set so delta-sync records skip re-apply (CF_APPLIED dedup at
    /// state_core). Without this, every new node does O(all_records) ledger
    /// replay → hours at 10M records.
    ///
    /// Clone() still skips this field (runtime clones are hot and don't need
    /// it — local dedup reads CF_APPLIED directly). The snapshot-build path
    /// explicitly populates it via `Rocks::collect_applied_ids()` before
    /// serialization; see `routes/sync.rs::serve_snapshot`.
    #[serde(default)]
    pub applied_record_ids: std::collections::HashSet<String>,
    /// Index: staker identity hash → active stake record IDs.
    /// Transient — rebuilt from `stakes` on deserialization or startup.
    /// Eliminates O(all_stakes) scan in stakes_for() and all_stakers().
    #[serde(skip)]
    pub staker_index: HashMap<String, Vec<String>>,
    /// O(1) count of active stakes — the number of `stakes` entries with
    /// `active == true` (equivalently, the total id count across `staker_index`).
    /// Transient (`#[serde(skip)]`) and reconciled in [`LedgerState::rebuild_staker_index`]
    /// on every load path (startup / snapshot bootstrap / crash-recovery /
    /// divergence repair), then maintained incrementally at the four stake
    /// activate/deactivate sites. Lets `summarize()` (hit on `/network`) read the
    /// active-stake count without an O(all_stakes) scan under the ledger read
    /// lock (B10). Display-only (`LedgerSummary.num_active_stakes`) — never feeds
    /// consensus, so any drift cannot fork the chain and the rebuild reconcile is
    /// the backstop.
    #[serde(skip)]
    pub active_stakes_count: u64,
    /// Active predictions (keyed by prediction record ID).
    /// Pending until the target epoch is sealed, then evaluated.
    #[serde(default)]
    pub predictions: HashMap<String, PredictionEntry>,
    /// Total beat currently locked in pending cross-zone transfers.
    /// Conservation: sum(available) + total_staked + pending_xzone_locked + conservation_pool = total_supply
    #[serde(default)]
    pub pending_xzone_locked: u64,
    /// Per-transfer tracking for cross-zone transfers (lock/claim/abort/refund).
    /// Persisted (was `#[serde(skip)]`, internal design notes):
    /// `apply_op` reads `pending` as an accept/reject gate for
    /// XZoneClaim/Cancel/Abort/Reject, so it MUST survive a snapshot bootstrap or
    /// a bootstrapped node forks (empty `pending` rejects a claim a since-genesis
    /// node accepts). The snapshot-bootstrap path does NOT replay history, so the
    /// old "rebuilt from DAG replay" assumption was false on that path.
    /// `#[serde(default)]` — pre-fix snapshots deserialize to empty (= prior behavior).
    #[serde(default)]
    pub cross_zone: CrossZoneState,
    /// Exchange identity classifier — behavioral detection of exchange/custodial entities.
    /// Persisted (Track C, internal design notes): `confirmed_exchanges`
    /// gates consensus accept/reject + the fleet-wide prediction-reward multiplier, so it
    /// MUST survive a snapshot bootstrap or a bootstrapped node forks. `#[serde(default)]`
    /// (was `#[serde(skip)]`) — pre-fix snapshots deserialize to empty (= prior behavior).
    /// Classification is monotone, so the persisted state is deterministic across nodes.
    #[serde(default)]
    pub exchange_classifier: ExchangeClassifier,
    /// Custodial idle_decay state — flow tracking and assessment for exchange identities.
    /// Transient — rebuilt from transfer patterns during DAG replay.
    #[serde(skip)]
    pub idle_decay: IdleDecayState,
    /// Dormancy 3-phase lifecycle (economics §2.5).
    /// Persistent: declarations + phases are authoritative state. Populated by
    /// DormancyDeclare/Heartbeat/ProofOfLife ops in apply_op; gates DormancyReclaim.
    #[serde(default)]
    pub dormancy: crate::accounting::dormancy::DormancyState,
    /// Timestamp of the most recently applied ledger/governance record.
    /// Used by incremental_ledger_replay to seek directly to new records,
    /// avoiding O(all_records) scans. Updated on every apply_op.
    #[serde(default)]
    pub last_applied_ts: f64,
    /// Monotonic counter bumped on every mutation that can change the
    /// staked-anchor set — i.e. every site that mutates `total_staked`
    /// (Stake `+=`, Unstake `-=`, Slash `-=`, genesis stake). Keys the
    /// `NodeState` staked-anchor view cache. A strictly-increasing token is
    /// required (not just a `total_staked` fingerprint): a net-zero reshuffle
    /// — A unstakes X, B stakes X between two reads — leaves `total_staked`
    /// unchanged while the membership set moved, which only a monotonic
    /// counter catches. Transient runtime-local coherence token, so
    /// `#[serde(skip)]`; restored nodes rebuild the view from authoritative
    /// CF + ledger on first read (see `NodeState::invalidate_anchor_view`).
    #[serde(skip)]
    pub stake_mutation_seq: u64,
    /// Account-state SMT dirty set — identity hashes (hex) whose balance
    /// changed since the last `flush_smt`. Populated by `apply_op`, drained
    /// by `crate::network::account_merkle::flush_dirty`. Transient: the SMT
    /// itself is authoritative on disk; this set just batches incremental
    /// updates so we don't rehash unchanged accounts.
    #[serde(skip)]
    pub smt_dirty: std::collections::HashSet<String>,
    /// Witness-registry writes pending durable persistence (Gap 2.1
    /// Phase 2b.3 Slice 3). Populated by `apply_op` for each
    /// `WitnessRegister` op; drained by `Rocks::flush_pending_witness_*`
    /// (added in Slice 3c) so `CF_WITNESS_REGISTRY` reflects every
    /// applied registration. Transient — never serialized; on restart
    /// the registry is rehydrated by replaying records from the DAG
    /// just like any other ledger state.
    ///
    /// Each entry: (zone_path, identity_hash, dilithium_pk, bond, registered_epoch).
    #[serde(skip)]
    pub pending_witness_registrations: Vec<(String, String, Vec<u8>, u64, u64)>,
}

impl Clone for LedgerState {
    fn clone(&self) -> Self {
        Self {
            accounts: self.accounts.clone(),
            stakes: self.stakes.clone(),
            total_supply: self.total_supply,
            total_staked: self.total_staked,
            conservation_pool: self.conservation_pool,
            pool_disbursed_window: self.pool_disbursed_window,
            records_processed: self.records_processed,
            velocity: self.velocity.clone(),
            circuit_breaker: self.circuit_breaker.clone(),
            acquisition: self.acquisition.clone(),
            vesting: self.vesting.clone(),
            governance: self.governance.clone(),
            identity_profiles: self.identity_profiles.clone(),
            attestation_levels: self.attestation_levels.clone(),
            // Skip cloning applied_record_ids (135K+ entries).
            // Runtime dedup is in RocksDB CF_APPLIED. This set is only used
            // during rebuild_ledger (where it's rebuilt from scratch).
            applied_record_ids: std::collections::HashSet::new(),
            staker_index: self.staker_index.clone(),
            active_stakes_count: self.active_stakes_count,
            predictions: self.predictions.clone(),
            pending_xzone_locked: self.pending_xzone_locked,
            cross_zone: self.cross_zone.clone(),
            exchange_classifier: self.exchange_classifier.clone(),
            idle_decay: self.idle_decay.clone(),
            dormancy: self.dormancy.clone(),
            last_applied_ts: self.last_applied_ts,
            stake_mutation_seq: self.stake_mutation_seq,
            smt_dirty: self.smt_dirty.clone(),
            pending_witness_registrations: self.pending_witness_registrations.clone(),
        }
    }
}

impl Default for LedgerState {
    fn default() -> Self {
        Self::new()
    }
}

impl LedgerState {
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            stakes: HashMap::new(),
            total_supply: 0,
            total_staked: 0,
            conservation_pool: 0,
            records_processed: 0,
            velocity: VelocityTracker::new(),
            circuit_breaker: CircuitBreaker::new(),
            acquisition: AcquisitionTracker::new(),
            vesting: VestingManager::new(),
            governance: GovernanceState::new(),
            identity_profiles: HashMap::new(),
            attestation_levels: HashMap::new(),
            staker_index: HashMap::new(),
            active_stakes_count: 0,
            predictions: HashMap::new(),
            pool_disbursed_window: (0.0, 0),
            applied_record_ids: std::collections::HashSet::new(),
            pending_xzone_locked: 0,
            cross_zone: CrossZoneState::new(),
            exchange_classifier: ExchangeClassifier::new(),
            idle_decay: IdleDecayState::new(),
            dormancy: crate::accounting::dormancy::DormancyState::new(),
            last_applied_ts: 0.0,
            stake_mutation_seq: 0,
            smt_dirty: std::collections::HashSet::new(),
            pending_witness_registrations: Vec::new(),
        }
    }

    /// Rebuild the staker index from the stakes HashMap.
    /// Called after deserialization or snapshot load since staker_index is transient.
    pub fn rebuild_staker_index(&mut self) {
        self.staker_index.clear();
        let mut active = 0u64;
        for (record_id, entry) in &self.stakes {
            if entry.active {
                self.staker_index
                    .entry(entry.staker.clone())
                    .or_default()
                    .push(record_id.clone());
                active += 1;
            }
        }
        // B10: reconcile the O(1) active-stake counter from the authoritative
        // `stakes` map on every load path. The incremental maintenance at the
        // four activate/deactivate sites is the steady-state source; this
        // rebuild is the backstop that re-derives truth after any load/restore.
        self.active_stakes_count = active;
    }

    /// Process expired cross-zone transfers and refund senders.
    /// Returns the number of refunds processed.
    /// SUPERSEDED (co-fix (c), internal design notes): no
    /// longer wired into the production seal loop — it mutated `account.available`
    /// / `last_active` / `pending_xzone_locked` out-of-band from a per-node
    /// wall-clock, which forked seal-eligible nodes against each other and against
    /// followers (who never ran it). The timeout refund now flows through the
    /// signed `XZoneTimeoutRefund` record (`compute_expired_refund_batch` →
    /// `apply_refund_batch`), applied identically on every node. Retained only for
    /// the unit tests that pin `cross_zone.process_expired` semantics — DO NOT
    /// re-wire it into any consensus path.
    pub fn process_expired_xzone(&mut self, now: f64) -> usize {
        let refunds = self.cross_zone.process_expired(now);
        let count = refunds.len();
        for (transfer_id, sender, amount) in refunds {
            // Credit back to sender
            let account = self.accounts.entry(sender.clone()).or_default();
            account.available += amount;
            account.last_active = now;
            self.pending_xzone_locked = self.pending_xzone_locked.saturating_sub(amount);
            tracing::info!(
                "xzone_refund: {} refunded {} (expired transfer_id={})",
                &sender[..sender.len().min(16)], amount, &transfer_id[..transfer_id.len().min(16)]
            );
        }
        count
    }

    /// Conservation Pool hard cap based on current total supply.
    /// Integer 10% (1/10): `pool_headroom` gates confiscation/slash/reclaim/burn
    /// amounts in `apply_op` on every node, so the cap must be node-identical
    /// (the old `total_supply as f64 * 0.10` forked once supply > 2^53).
    pub fn pool_cap(&self) -> u64 {
        ((self.total_supply as u128) * CONSERVATION_POOL_MAX_FRACTION_NUM
            / CONSERVATION_POOL_MAX_FRACTION_DEN) as u64
    }

    /// How much room remains in the Conservation Pool before hitting the cap.
    pub fn pool_headroom(&self) -> u64 {
        self.pool_cap().saturating_sub(self.conservation_pool)
    }

    /// Maximum pool disbursement allowed in the current 30-day window.
    /// Hard limit: 1% of pool balance per month (economics §2.4).
    ///
    /// DETERMINISM: the 1% cap is integer division (`/ 100`), not the old
    /// `pool as f64 * 0.01` — float arithmetic forks once the pool exceeds 2^53
    /// (the same class fixed for `pool_cap`). No production caller wires this yet;
    /// any future caller MUST pass a consensus-replicated `now` (a sealed record's
    /// timestamp), never per-node wall-clock, or the window boundary forks.
    pub fn pool_monthly_remaining(&self, now: f64) -> u64 {
        const MONTH_SECS: f64 = 30.0 * 24.0 * 3600.0;

        let (window_start, disbursed) = self.pool_disbursed_window;
        // 1% of pool balance — integer, bit-identical on every node.
        let monthly_cap = self.conservation_pool / 100;
        if now - window_start >= MONTH_SECS {
            // New window — full 1% available
            monthly_cap
        } else {
            // Same window — subtract what's already been disbursed
            monthly_cap.saturating_sub(disbursed)
        }
    }

    /// Record a pool disbursement (call after withdrawing from pool).
    /// DETERMINISM: `now` must be a consensus-replicated timestamp (sealed
    /// record), never per-node wall-clock — see `pool_monthly_remaining`.
    pub fn record_pool_disbursement(&mut self, amount: u64, now: f64) {
        const MONTH_SECS: f64 = 30.0 * 24.0 * 3600.0;
        let (window_start, disbursed) = self.pool_disbursed_window;
        if now - window_start >= MONTH_SECS {
            self.pool_disbursed_window = (now, amount);
        } else {
            self.pool_disbursed_window = (window_start, disbursed + amount);
        }
    }

    /// Get account state for an identity (returns default if unknown).
    pub fn account(&self, identity_hash: &str) -> AccountState {
        self.accounts
            .get(identity_hash)
            .cloned()
            .unwrap_or_default()
    }

    /// Get available balance for an identity.
    pub fn balance(&self, identity_hash: &str) -> u64 {
        self.accounts
            .get(identity_hash)
            .map(|a| a.available)
            .unwrap_or(0)
    }

    /// Circulating supply = total_supply - total_staked - conservation_pool.
    pub fn circulating_supply(&self) -> u64 {
        self.total_supply
            .saturating_sub(self.total_staked)
            .saturating_sub(self.conservation_pool)
    }

    /// Get staked balance for an identity.
    pub fn staked(&self, identity_hash: &str) -> u64 {
        self.accounts
            .get(identity_hash)
            .map(|a| a.staked)
            .unwrap_or(0)
    }

    /// Apply a single record to the ledger if it's a ledger or governance operation.
    /// Returns Ok(true) if an operation was applied, Ok(false) if non-ledger/governance record.
    pub fn apply_single_record(&mut self, record: &ValidationRecord, genesis_authority: &str) -> Result<bool> {
        // Check for ledger operation first
        if let Some(op) = extract_ledger_op(record)? {
            apply_op(self, record, &op, genesis_authority)?;
            return Ok(true);
        }

        // Check for governance operation
        use crate::accounting::governance::extract_governance_op;
        if let Some(gov_op) = extract_governance_op(&record.metadata)? {
            let creator = creator_identity_hash(record);
            apply_governance_op(self, record, &gov_op, &creator)?;
            return Ok(true);
        }

        // Non-ledger, non-governance record = a "publication" for exchange classification
        let creator = creator_identity_hash(record);
        self.exchange_classifier.record_publication(&creator);
        Ok(false)
    }

    /// Get active stakes for an identity. O(1) lookup via staker_index.
    pub fn stakes_for(&self, identity_hash: &str) -> Vec<&StakeEntry> {
        match self.staker_index.get(identity_hash) {
            Some(record_ids) => record_ids
                .iter()
                .filter_map(|rid| self.stakes.get(rid))
                .filter(|s| s.active)
                .collect(),
            None => Vec::new(),
        }
    }

    /// Register the cryptographic profile for an identity.
    /// Profile A (dual-sig) identities get higher transfer limits.
    pub fn register_identity_profile(&mut self, identity_hash: &str, profile: CryptoProfile) {
        self.identity_profiles
            .insert(identity_hash.to_string(), profile);
    }

    /// Check if an identity is single-sig (Profile B or unknown).
    /// Unknown identities are treated as Profile B (conservative default).
    pub fn is_single_sig(&self, identity_hash: &str) -> bool {
        match self.identity_profiles.get(identity_hash) {
            Some(CryptoProfile::ProfileA) => false,
            _ => true, // Profile B, C, or unknown → single-sig cap applies
        }
    }

    /// Register or upgrade the hardware attestation level for an identity.
    ///
    /// Profile C Gap C (economics §11.33). Monotonic by `rank()`: a record
    /// advertising a level lower than the recorded one is a no-op. This
    /// prevents a compromised gateway from advertising `attestation_level: NONE`
    /// to slip past the Gateway eligibility floor with the same key — the
    /// rollback would have to be paired with a new identity.
    ///
    /// Note: this is observational, not cryptographic. The level the parent
    /// claims is taken at face value on testnet. Mainnet must add evidence
    /// verification (TPM quote / Android Key Attestation) — deferred to a
    /// follow-up doc per internal design notes §3 Gap C.
    pub fn register_identity_attestation(
        &mut self,
        identity_hash: &str,
        level: crate::identity::AttestationLevel,
    ) {
        match self.attestation_levels.get(identity_hash) {
            Some(existing) if existing.rank() >= level.rank() => {
                // Recorded level is at or above the candidate — never downgrade.
            }
            _ => {
                self.attestation_levels
                    .insert(identity_hash.to_string(), level);
            }
        }
    }

    /// Get the recorded attestation level for an identity. Unknown identities
    /// return `AttestationLevel::None` (rank 0).
    pub fn attestation_level(
        &self,
        identity_hash: &str,
    ) -> crate::identity::AttestationLevel {
        self.attestation_levels
            .get(identity_hash)
            .copied()
            .unwrap_or(crate::identity::AttestationLevel::None)
    }

    /// Get all identities that have active stakes (for jury selection). O(1) via staker_index.
    pub fn all_stakers(&self) -> Vec<String> {
        self.staker_index.keys().cloned().collect()
    }

    /// Get pending predictions targeting a specific zone and epoch.
    pub fn pending_predictions(&self, zone: &str, epoch: u64) -> Vec<&PredictionEntry> {
        self.predictions.values()
            .filter(|p| p.outcome.is_none() && p.zone == zone && p.target_epoch == epoch)
            .collect()
    }

    /// Compute the per-epoch custodial-idle_decay batch — **pure** (`&self`, no
    /// mutation). The producer calls this at the epoch-seal boundary and freezes
    /// the result into a signed `IdleDecay` system record (Option A propagation,
    /// internal design notes); every node then applies that record via
    /// [`apply_idle_decay_batch`](Self::apply_idle_decay_batch), so all nodes
    /// converge on identical balances + account-SMT root (closes the
    /// producer-only-mutation divergence H1).
    ///
    /// The math is byte-identical to the previous in-place path: each exchange's
    /// deduction is computed from its PRE-batch balance (so a staker-exchange's
    /// own payout can't perturb its assessment), the staker split is a pure floor
    /// share of each staker's weight, and ALL rounding dust (the odd-unit pool
    /// half plus per-staker floor remainders) lands in the Conservation Pool —
    /// order-independent, conservation-exact. Returns `None` if no exchange owes
    /// anything (no record is emitted).
    pub fn compute_idle_decay_batch(
        &self,
        zone: &str,
        epoch: u64,
        now: f64,
        epoch_duration_secs: f64,
    ) -> Option<crate::accounting::idle_decay::IdleDecayBatch> {
        use crate::accounting::idle_decay::{IdleDecayBatch, MIN_IDLE_DECAY_BALANCE};

        // Floor to integer seconds — sub-second precision is irrelevant at a daily
        // rate, and the value path downstream is integer u128 (determinism).
        let duration_secs = epoch_duration_secs.max(0.0) as u64;
        if duration_secs == 0 {
            return None;
        }

        // Snapshot staker weights ONCE: idle_decay credits `available`, never
        // `staked`, so weights are constant across the whole batch and independent
        // of iteration order. (u128 sums — a multi-stake staker cannot overflow.)
        let stakers: Vec<(String, u128)> = self
            .staker_index
            .iter()
            .map(|(id, stake_ids)| {
                let staked: u128 = stake_ids
                    .iter()
                    .filter_map(|sid| self.stakes.get(sid))
                    .map(|s| s.amount as u128)
                    .sum();
                (id.clone(), staked)
            })
            .filter(|(_, s)| *s > 0)
            .collect();
        let total_weight: u128 = stakers.iter().map(|(_, s)| *s).sum();

        // Phase 1 — per-exchange deduction from the PRE-batch balance (pure).
        let exchange_ids: Vec<String> = self
            .exchange_classifier
            .classified_identities()
            .into_iter()
            .filter(|id| self.idle_decay.tracker_count(id) > 0)
            .collect();

        let mut deductions: Vec<(String, u64, u64)> = Vec::new(); // (identity, deduct, pool_share)
        for identity in &exchange_ids {
            let balance = self.accounts.get(identity).map(|a| a.available).unwrap_or(0);
            if balance < MIN_IDLE_DECAY_BALANCE {
                continue;
            }
            if let Some(assessment) = self.idle_decay.assess_amount(identity, balance, duration_secs, now) {
                let deduct = assessment.idle_decay_micros.min(balance);
                if deduct == 0 {
                    continue;
                }
                let pool_share = assessment.pool_micros.min(deduct);
                deductions.push((identity.clone(), deduct, pool_share));
            }
        }
        if deductions.is_empty() {
            return None;
        }

        // Phase 2 — accumulate the frozen batch (no account mutation). Staker
        // credits accumulate into a BTreeMap (sorted, order-independent); dust
        // → pool. Same arithmetic as the old in-place loop, just into a payload.
        let mut pool_credit = 0u64;
        let mut staker_map: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
        for (_identity, deduct, pool_share) in &deductions {
            let deduct = *deduct;
            let pool_share = *pool_share;
            pool_credit += pool_share;
            let staker_share = deduct - pool_share;
            if staker_share > 0 && total_weight > 0 {
                let mut distributed = 0u64;
                for (staker_id, staked) in &stakers {
                    let share = (staker_share as u128 * *staked / total_weight) as u64;
                    if share > 0 {
                        *staker_map.entry(staker_id.clone()).or_insert(0) += share;
                        distributed += share;
                    }
                }
                // Dust (staker_share − Σ floor shares) → Conservation Pool.
                pool_credit += staker_share - distributed;
            } else if staker_share > 0 {
                // No active stakers — entire staker portion to the Conservation Pool.
                pool_credit += staker_share;
            }
        }

        let mut debits: Vec<(String, u64)> =
            deductions.into_iter().map(|(id, deduct, _)| (id, deduct)).collect();
        debits.sort_by(|a, b| a.0.cmp(&b.0)); // canonical order
        let staker_credits: Vec<(String, u64)> = staker_map.into_iter().collect(); // BTreeMap → sorted

        let batch = IdleDecayBatch { epoch, zone: zone.to_string(), debits, pool_credit, staker_credits };
        debug_assert!(batch.is_conserved(), "compute_idle_decay_batch must be conservation-exact");
        Some(batch)
    }

    /// Apply a frozen [`IdleDecayBatch`] to the ledger — runs on **every** node
    /// (producer and witnesses) via the `IdleDecay` record's standard apply path.
    ///
    /// The amounts are frozen at the producer; this only verifies + mutates:
    ///   * conservation (`Σ debits == pool_credit + Σ staker_credits`),
    ///   * each debit ≤ the exchange's live `available` (all-or-nothing — a
    ///     deterministic batch always passes; a shortfall means upstream
    ///     divergence, so reject the whole record rather than underflow),
    ///
    /// then debits each exchange, credits the Conservation Pool and stakers
    /// (`available` only — matching the prior in-place semantics), advances the
    /// observability counters, and prunes stale flow data. Idempotency across
    /// re-delivery is the caller's record-ID dedup (`applied_record_ids`).
    pub fn apply_idle_decay_batch(
        &mut self,
        batch: &crate::accounting::idle_decay::IdleDecayBatch,
        now: f64,
    ) -> Result<()> {
        if !batch.is_conserved() {
            return Err(ElaraError::Ledger(format!(
                "idle_decay batch not conserved: debits {} != credits {}",
                batch.total_debit(),
                batch.total_credit()
            )));
        }
        // Phase 1 — validate every debit before mutating anything.
        for (id, amt) in &batch.debits {
            let available = self.accounts.get(id).map(|a| a.available).unwrap_or(0);
            if available < *amt {
                return Err(ElaraError::Ledger(format!(
                    "idle_decay debit {} exceeds available {} for {}",
                    amt,
                    available,
                    &id[..id.len().min(16)]
                )));
            }
        }
        // Phase 2 — apply (additions commute; sorted lists keep it canonical).
        let mut collected = 0u64;
        for (id, amt) in &batch.debits {
            if let Some(account) = self.accounts.get_mut(id) {
                account.available -= *amt;
            }
            collected += *amt;
        }
        self.conservation_pool += batch.pool_credit;
        let mut distributed = 0u64;
        for (staker, amt) in &batch.staker_credits {
            self.accounts.entry(staker.clone()).or_default().available += *amt;
            distributed += *amt;
        }
        self.idle_decay.note_applied_batch(collected, batch.pool_credit, distributed);
        // Prune stale flow data on every node (in lockstep with the record),
        // keeping non-producer trackers bounded too.
        self.idle_decay.prune_all(now);
        Ok(())
    }

    /// Evaluate all predictions targeting the given zone and epoch.
    ///
    /// Called at epoch seal time. `actual_record_count` is the number of non-seal
    /// records in the sealed epoch. `actual_identity_count` is the number of
    /// unique creator identities in those records.
    ///
    /// Returns (correct_count, wrong_count, total_rewarded, total_confiscated).
    pub fn evaluate_predictions(
        &mut self,
        zone: &str,
        epoch: u64,
        actual_record_count: u64,
        actual_identity_count: u64,
    ) -> (u64, u64, u64, u64) {
        // Collect prediction IDs targeting this zone+epoch.
        // DETERMINISM (fleet-wide seal path): `self.predictions` is a HashMap, so
        // `.values()` yields a per-node-random order. The loop below mutates
        // `conservation_pool` under a `.min()`/`pool_headroom()` cap, so when the
        // pool is near a bound the *order* decides who gets the full reward/refund
        // vs. the capped remainder — two honest nodes replaying the same seal would
        // diverge on `conservation_pool` + predictor balances → account-SMT fork one
        // seal later. `record_id` is the unique map key, so sort is a total order.
        let mut pred_ids: Vec<String> = self.predictions.values()
            .filter(|p| p.outcome.is_none() && p.zone == zone && p.target_epoch == epoch)
            .map(|p| p.record_id.clone())
            .collect();
        pred_ids.sort();

        let mut correct = 0u64;
        let mut wrong = 0u64;
        let mut total_rewarded = 0u64;
        let mut total_confiscated = 0u64;

        for pred_id in pred_ids {
            let pred = match self.predictions.get(&pred_id) {
                Some(p) => p.clone(),
                None => continue,
            };

            let is_correct = evaluate_claim(
                &pred.claim, pred.predicted_value,
                actual_record_count, actual_identity_count,
            );

            if is_correct {
                correct += 1;
                // Return stake + reward from conservation pool
                // Exchange-classified identities get reduced rewards (stake_reward_multiplier)
                let restrictions = self.exchange_classifier.restrictions(&pred.predictor);
                // Integer reward (runs fleet-wide at seal): 10% of stake = amount/10,
                // then × stake_reward_multiplier ∈ {0.0, 1.0} (exact, scaled by 1e9).
                // `pred.amount` can exceed 2^53, so the old f64 multiply forked.
                let base_reward = ((pred.amount as u128) * PREDICTION_REWARD_RATE_NUM
                    / PREDICTION_REWARD_RATE_DEN) as u64;
                let mult_q = (restrictions.stake_reward_multiplier * 1_000_000_000.0) as u128;
                let reward =
                    ((base_reward as u128).saturating_mul(mult_q) / 1_000_000_000) as u64;
                let actual_reward = reward.min(self.conservation_pool);
                self.conservation_pool -= actual_reward;

                let account = self.accounts.entry(pred.predictor.clone()).or_default();
                account.available += pred.amount + actual_reward;
                account.total_received = account.total_received.saturating_add(pred.amount).saturating_add(actual_reward);
                // F-2: predictor payout mutates `accounts` OUTSIDE apply_op, so
                // mark dirty or the leaf never reaches the persistent SMT.
                // CAVEAT: evaluate_predictions runs AFTER snapshot_dirty in the
                // seal loop (epoch.rs), so this mark flushes at the NEXT seal —
                // a one-epoch lag, and it does not advance last_applied_ts, so
                // the §6a overhang gate will NOT absorb it. The full fix for a
                // prediction-ACTIVE chain is to reorder evaluation before the
                // seal's SMT snapshot. Latent today (no Predict records on-chain).
                self.smt_dirty.insert(pred.predictor.clone());
                total_rewarded += actual_reward;
            } else {
                wrong += 1;
                // Confiscate stake to conservation pool — capped by headroom
                let pool_actual = pred.amount.min(self.pool_headroom());
                self.conservation_pool += pool_actual;

                // If pool is at cap, refund overflow to predictor (conservation invariant)
                let overflow = pred.amount - pool_actual;
                if overflow > 0 {
                    let account = self.accounts.entry(pred.predictor.clone()).or_default();
                    account.available += overflow;
                    // saturating: the matching debit's `total_sent +=` may be
                    // absent on an account materialized here via `or_default`
                    // (predictor pruned mid-flight) — a bare `-=` would wrap in
                    // release / panic in debug. Mirrors the `saturating_add`
                    // used at every other `total_sent` write (e.g. PoolFund).
                    account.total_sent = account.total_sent.saturating_sub(overflow);
                    // F-2: see the correct-branch note — off-apply_op mutation,
                    // mark dirty so the overflow refund reaches the persistent SMT.
                    self.smt_dirty.insert(pred.predictor.clone());
                }
                total_confiscated += pool_actual; // only count what actually entered pool
            }

            // Mark prediction as evaluated
            if let Some(p) = self.predictions.get_mut(&pred_id) {
                p.outcome = Some(is_correct);
            }
        }

        (correct, wrong, total_rewarded, total_confiscated)
    }
}

/// Evaluate whether a prediction claim is correct given actual epoch data.
fn evaluate_claim(
    claim: &PredictionClaim,
    predicted: u64,
    actual_record_count: u64,
    actual_identity_count: u64,
) -> bool {
    match claim {
        PredictionClaim::Active => {
            let zone_was_active = actual_record_count > 0;
            let predicted_active = predicted > 0;
            zone_was_active == predicted_active
        }
        PredictionClaim::Volume => within_margin(
            predicted,
            actual_record_count,
            PREDICTION_MARGIN_NUM,
            PREDICTION_MARGIN_DEN,
        ),
        PredictionClaim::IdentityCount => within_margin(
            predicted,
            actual_identity_count,
            PREDICTION_MARGIN_NUM,
            PREDICTION_MARGIN_DEN,
        ),
    }
}

/// Check if predicted value is within margin of actual value.
/// `|predicted - actual| / max(actual, 1) <= num/den`, evaluated as the integer
/// cross-multiplication `diff·den <= num·max(actual,1)` so the correct/wrong
/// consensus decision is identical on every node (no f64 in the gate).
fn within_margin(predicted: u64, actual: u64, margin_num: u128, margin_den: u128) -> bool {
    let diff = predicted.abs_diff(actual) as u128;
    let denom = actual.max(1) as u128;
    diff.saturating_mul(margin_den) <= margin_num.saturating_mul(denom)
}

/// Derive complete ledger state from a set of ledger records.
///
/// Records MUST be sorted by timestamp (ascending). The caller is responsible
/// for extracting ledger records from the DAG and sorting them.
pub fn derive_ledger(
    ledger_records: &[(ValidationRecord, ParsedLedgerOp)],
    genesis_authority: &str,
) -> Result<LedgerState> {
    let mut state = LedgerState::new();

    for (record, op) in ledger_records {
        apply_op(&mut state, record, op, genesis_authority)?;
    }

    Ok(state)
}

/// Tolerant ledger derivation — skips invalid operations instead of failing.
///
/// Use this when deriving from DAG storage that may contain records arrived
/// via gossip out of causal order, or economically invalid ops (overspend,
/// unauthorized mint). Valid ops are applied; invalid ones are silently skipped.
///
/// Returns the number of skipped records alongside the derived state.
/// Synthetic record-id prefix for genesis validator stakes. The prefix keys
/// the idempotence guard: re-running the baseline (rebuild, snapshot +
/// incremental replay, boot retry) never double-applies.
pub const GENESIS_STAKE_RECORD_PREFIX: &str = "genesis-stake:";

/// GENESIS VALIDATOR BOOTSTRAP — apply the genesis validator set to a ledger
/// baseline (internal design notes). For each validator the
/// stake is CARVED from the genesis authority's minted allocation
/// (`available -= stake`, validator `staked += stake`) so total supply is
/// conserved. Runs AFTER record replay so the genesis mint is present.
///
/// Deterministic and idempotent: synthetic record id
/// `genesis-stake:<identity>` guards re-application; timestamps are the
/// constant 0.0 (never local clock). An underfunded carve (validator stake
/// exceeding the authority's remaining balance) is skipped with an error log
/// — deterministic across nodes replaying the same records, and surfaced at
/// config time by `NodeConfig::validate`.
///
/// Returns the number of validators newly applied.
pub fn apply_genesis_validators(
    state: &mut LedgerState,
    validators: &[crate::accounting::types::GenesisValidator],
    genesis_authority: &str,
) -> usize {
    let mut applied = 0usize;
    for v in validators {
        if v.stake_micros == 0 {
            continue;
        }
        let rid = format!("{GENESIS_STAKE_RECORD_PREFIX}{}", v.identity);
        if state.stakes.contains_key(&rid) {
            continue; // already applied (snapshot or earlier rebuild)
        }
        let authority_available = state
            .accounts
            .get(genesis_authority)
            .map(|a| a.available)
            .unwrap_or(0);
        if authority_available < v.stake_micros {
            // Pre-mint pass: on a fresh boot the first ledger build runs
            // BEFORE auto_genesis_mint funds the authority (supply==0), so
            // every validator is skipped here and applied by the post-mint
            // rebuild moments later. That ordering is expected on every
            // genesis-authority first boot and every peer's pre-sync build —
            // log it quietly. ERROR is reserved for a funded chain whose
            // config genuinely over-allocates (real misconfiguration).
            if state.total_supply == 0 {
                tracing::info!(
                    validator = %v.identity,
                    "genesis validator stake deferred — ledger pre-mint \
                     (applied automatically by the post-mint rebuild)"
                );
            } else {
                tracing::error!(
                    validator = %v.identity,
                    stake = v.stake_micros,
                    authority_available,
                    "genesis validator stake exceeds genesis authority balance — \
                     skipped (fix genesis_validators config; all nodes skip \
                     identically so this cannot fork, but the validator is NOT staked)"
                );
            }
            continue;
        }
        if let Some(auth) = state.accounts.get_mut(genesis_authority) {
            auth.available -= v.stake_micros;
        }
        let account = state.accounts.entry(v.identity.clone()).or_default();
        account.staked += v.stake_micros;
        // F-2: genesis stake mutates the authority's `available` and the
        // validator's `staked` OUTSIDE apply_op, so without these marks the
        // leaves never reach the persistent account SMT (smt_dirty is
        // `#[serde(skip)]` and does not survive restart). That made every
        // seal's `account_smt_root` omit any genesis validator that never
        // transacted, while `root_over_accounts` (boot replay) includes it →
        // a guaranteed false §6a boot mismatch. These marks fix fresh-genesis
        // nodes; the idempotency guard above makes this a no-op on a warm
        // restart, so already-genesised nodes are healed by the boot reconcile
        // (`reconcile_genesis_accounts_into_smt`, called from elara_node.rs).
        state.smt_dirty.insert(genesis_authority.to_string());
        state.smt_dirty.insert(v.identity.clone());
        state.stakes.insert(
            rid.clone(),
            StakeEntry {
                record_id: rid.clone(),
                amount: v.stake_micros,
                purpose: crate::accounting::types::StakePurpose::Witness,
                staker: v.identity.clone(),
                timestamp: 0.0,
                active: true,
            },
        );
        state
            .staker_index
            .entry(v.identity.clone())
            .or_default()
            .push(rid);
        state.active_stakes_count = state.active_stakes_count.saturating_add(1); // B10
        state.total_staked += v.stake_micros;
        state.stake_mutation_seq = state.stake_mutation_seq.wrapping_add(1);
        applied += 1;
    }
    applied
}

pub fn derive_ledger_tolerant(
    ledger_records: &[(ValidationRecord, ParsedLedgerOp)],
    genesis_authority: &str,
) -> (LedgerState, usize) {
    let mut state = LedgerState::new();
    let mut failed: Vec<usize> = Vec::new();

    // First pass: apply all records in order
    for (i, (record, op)) in ledger_records.iter().enumerate() {
        if apply_op(&mut state, record, op, genesis_authority).is_err() {
            failed.push(i);
        }
    }

    // Retry pass: some records may have failed due to ordering (e.g., transfer
    // arrived before the sender's balance was credited by a later record).
    // Now that earlier records have been applied, retry the failed ones.
    if !failed.is_empty() {
        let retry_count = failed.len();
        let mut still_failed = 0usize;
        for &i in &failed {
            let (record, op) = &ledger_records[i];
            if apply_op(&mut state, record, op, genesis_authority).is_err() {
                still_failed += 1;
            }
        }
        if still_failed < retry_count {
            tracing::info!(
                "ledger replay: {} records recovered on retry ({} still skipped)",
                retry_count - still_failed, still_failed
            );
        }
        (state, still_failed)
    } else {
        (state, 0)
    }
}

/// Tolerant derivation from storage — the primary way to get ledger state from a DAG.
///
/// Unlike `derive_from_storage`, this never fails due to invalid ledger records
/// in the DAG. Invalid ops are skipped. Also replays governance operations.
/// WARNING: Loads ALL public records — O(all_records) memory. Production uses
/// rebuild_ledger_streaming on StorageEngine.
#[cfg(test)]
pub fn derive_from_storage_tolerant(
    storage: &dyn crate::storage::Storage,
    genesis_authority: &str,
    genesis_validators: &[crate::accounting::types::GenesisValidator],
) -> Result<(LedgerState, usize)> {
    // Single-pass: query all public records (timestamp-sorted via index),
    // classify each as ledger op or governance op, and apply in order.
    // Previously did TWO full scans (extract_ledger_records + extract_governance_records).
    let all_public = storage.query(
        Some(crate::record::Classification::Public),
        None, None, None, usize::MAX,
    )?;

    let mut ledger_records = Vec::new();
    let mut gov_records = Vec::new();
    let mut seen_ids = std::collections::HashSet::new();

    for record in all_public {
        // Dedup at source: skip records with duplicate IDs from storage query
        if !seen_ids.insert(record.id.clone()) {
            #[cfg(feature = "node")]
            tracing::warn!("derive_from_storage: DUPLICATE record ID in storage query: {}", &record.id[..record.id.len().min(24)]);
            continue;
        }
        if let Ok(Some(op)) = extract_ledger_op(&record) {
            ledger_records.push((record, op));
        } else if record.metadata.contains_key(crate::accounting::governance::GOVERNANCE_OP_KEY) {
            gov_records.push(record);
        }
    }

    // Ensure deterministic replay: sort by timestamp, then record ID as tiebreaker.
    // Storage index SHOULD return timestamp order, but RocksDB sync timing can
    // cause different index ordering across nodes — explicit sort guarantees
    // all nodes derive identical ledger state from the same record set.
    ledger_records.sort_by(|a, b| {
        a.0.timestamp.total_cmp(&b.0.timestamp)
            .then_with(|| a.0.id.cmp(&b.0.id))
    });
    let (mut state, skipped) = derive_ledger_tolerant(&ledger_records, genesis_authority);
    // Genesis validator baseline — post-replay so the genesis mint is present.
    apply_genesis_validators(&mut state, genesis_validators, genesis_authority);

    // Apply governance ops — sort for determinism
    gov_records.sort_by(|a, b| {
        a.timestamp.total_cmp(&b.timestamp)
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut gov_applied = 0usize;
    let mut gov_skipped = 0usize;
    for record in &gov_records {
        let creator = creator_identity_hash(record);
        if let Ok(Some(gov_op)) = crate::accounting::governance::extract_governance_op(&record.metadata) {
            match apply_governance_op(&mut state, record, &gov_op, &creator) {
                Ok(()) => gov_applied += 1,
                Err(_) => gov_skipped += 1,
            }
        }
    }
    if gov_skipped > 0 {
        tracing::debug!("governance replay: {gov_applied} applied, {gov_skipped} skipped");
    }

    Ok((state, skipped))
}

/// Tolerant derivation from a pre-loaded record slice (single-pass startup).
///
/// Same as `derive_from_storage_tolerant` but avoids querying storage — uses records
/// already loaded into memory.
pub fn derive_from_records_tolerant(
    all_records: &[ValidationRecord],
    genesis_authority: &str,
    genesis_validators: &[crate::accounting::types::GenesisValidator],
) -> Result<(LedgerState, usize)> {
    let mut ledger_records = extract_ledger_records_from_slice(all_records);
    // Ensure deterministic replay order across all nodes
    ledger_records.sort_by(|a, b| {
        a.0.timestamp.total_cmp(&b.0.timestamp)
            .then_with(|| a.0.id.cmp(&b.0.id))
    });
    let (mut state, skipped) = derive_ledger_tolerant(&ledger_records, genesis_authority);
    // Genesis validator baseline — post-replay so the genesis mint is present.
    apply_genesis_validators(&mut state, genesis_validators, genesis_authority);

    // Replay governance operations from all public records
    let mut gov_records = extract_governance_records_from_slice(all_records);
    gov_records.sort_by(|a, b| {
        a.timestamp.total_cmp(&b.timestamp)
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut gov_applied = 0usize;
    let mut gov_skipped = 0usize;
    for record in &gov_records {
        let creator = creator_identity_hash(record);
        if let Ok(Some(gov_op)) = crate::accounting::governance::extract_governance_op(&record.metadata) {
            match apply_governance_op(&mut state, record, &gov_op, &creator) {
                Ok(()) => gov_applied += 1,
                Err(_) => gov_skipped += 1,
            }
        }
    }
    if gov_skipped > 0 {
        tracing::debug!("governance replay: {gov_applied} applied, {gov_skipped} skipped");
    }

    Ok((state, skipped))
}

/// Apply a single ledger operation to the ledger state.
///
/// This is the core state transition function. Each operation is validated
/// against the current state before being applied.
pub fn apply_op(
    state: &mut LedgerState,
    record: &ValidationRecord,
    op: &ParsedLedgerOp,
    genesis_authority: &str,
) -> Result<()> {
    // Dedup: skip records already successfully applied to prevent double-counting.
    if state.applied_record_ids.contains(&record.id) {
        return Ok(()); // Already applied — skip silently
    }

    let creator = creator_identity_hash(record);

    // Auto-detect cryptographic profile from record signatures.
    // Profile A has both Dilithium3 + SPHINCS+ (dual-sig).
    // Profile B has Dilithium3 only (single-sig).
    if record.sphincs_signature.is_some() && record.creator_sphincs_pk.is_some() {
        state.register_identity_profile(&creator, CryptoProfile::ProfileA);
    } else if !state.identity_profiles.contains_key(&creator) {
        state.register_identity_profile(&creator, CryptoProfile::ProfileB);
    }

    // Profile C Gap C: auto-register the creator's advertised attestation
    // level. Registry is monotonic — only upgrades. Mainnet evidence
    // verification (TPM quote / Android Key Attestation chain) is deferred;
    // for now the level is taken at face value, gating Gateway eligibility
    // at delegation_op authorize time.
    if let Some(level) = crate::accounting::delegation::extract_attestation_level(record) {
        state.register_identity_attestation(&creator, level);
    }

    match op {
        ParsedLedgerOp::Mint { amount, to, reason } => {
            // Only genesis authority can mint
            if !is_privileged_emitter(&creator, genesis_authority) {
                return Err(ElaraError::Ledger(format!(
                    "unauthorized mint: {} is not genesis authority",
                    &creator[..creator.len().min(16)]
                )));
            }

            // Duplicate genesis mint prevention: if this is a genesis allocation
            // mint and the supply is already at MAX_SUPPLY, reject immediately.
            // This catches the case where a second genesis mint record (different
            // UUID) enters via gossip after a storage wipe + reboot.
            if reason.starts_with("genesis:") && state.total_supply >= MAX_SUPPLY {
                return Err(ElaraError::Ledger(format!(
                    "duplicate genesis mint rejected: supply already at MAX_SUPPLY ({})",
                    state.total_supply
                )));
            }

            // Check max supply (use checked_add to prevent u64 overflow wrapping)
            match state.total_supply.checked_add(*amount) {
                Some(new_supply) if new_supply <= MAX_SUPPLY => {},
                _ => {
                    return Err(ElaraError::Ledger(format!(
                        "mint would exceed max supply: {} + {} > {}",
                        state.total_supply, amount, MAX_SUPPLY
                    )));
                }
            }

            let account = state.accounts.entry(to.clone()).or_default();
            account.available += amount;
            account.total_received = account.total_received.saturating_add(*amount);
            account.tx_count = account.tx_count.saturating_add(1);
            account.last_active = record.timestamp;

            // Track peak balance for velocity tiers
            state.velocity.record_balance(to, account.total(), record.timestamp);

            // Save supply before mint for vesting threshold
            let supply_before = state.total_supply;
            state.total_supply += amount;

            // Record inflow for acquisition tracking
            state.acquisition.record_inflow(to, *amount, record.timestamp);

            // Large mint vesting: > 0.1% of supply BEFORE this mint → 365-day vesting.
            // Also checks cumulative mints in 30-day window to prevent split-mint bypass (§13.4).
            let single_triggers = VestingManager::requires_vesting(*amount, supply_before);
            let cumulative_triggers = state.vesting.cumulative_exceeds_threshold(
                to, *amount, supply_before, record.timestamp,
            );
            state.vesting.record_mint(to, *amount, record.timestamp);
            if single_triggers || cumulative_triggers {
                state.vesting.add_vesting(to, record.id.clone(), *amount, record.timestamp);
            }
        }

        ParsedLedgerOp::Transfer { amount, to, .. } => {
            if *amount == 0 {
                return Err(ElaraError::Ledger("transfer amount must be > 0".into()));
            }

            // Cannot send to yourself
            if creator == *to {
                return Err(ElaraError::Ledger("cannot transfer to self".into()));
            }

            // Read sender state without holding mutable ref (avoids borrow conflict)
            let sender_available = state.account(&creator).available;

            if sender_available < *amount {
                return Err(ElaraError::Ledger(format!(
                    "insufficient balance: have {}, need {}",
                    sender_available, amount
                )));
            }

            // Vesting check: sender must have enough unlocked balance
            if !is_privileged_emitter(&creator, genesis_authority) {
                let transferable = state.vesting.transferable_balance(&creator, sender_available, record.timestamp);
                if transferable < *amount {
                    return Err(ElaraError::Ledger(format!(
                        "insufficient unlocked balance: {} available, {} locked by vesting, need {}",
                        sender_available,
                        state.vesting.locked_balance(&creator, record.timestamp),
                        amount
                    )));
                }
            }
            // Genesis authority: per-transfer cap after full genesis prevents draining supply.
            // During genesis (supply < MAX_SUPPLY), larger transfers are allowed for setup.
            // After genesis: cap at 1% of total supply per transfer record.
            // Pool distributions use dedicated endpoints with proper allocation checks.
            if is_privileged_emitter(&creator, genesis_authority) && state.total_supply >= MAX_SUPPLY {
                let max_genesis_transfer = MAX_SUPPLY / 100; // 1% = 100M beat
                if *amount > max_genesis_transfer {
                    return Err(ElaraError::Ledger(format!(
                        "genesis transfer exceeds 1% cap: {} > {} (use pool distribution endpoints)",
                        amount, max_genesis_transfer
                    )));
                }
            }

            // CONSENSUS-FORBIDDEN: circuit-breaker / velocity / acquisition rate-limit
            // *rejects* are deliberately NOT applied on the consensus path (Track D,
            // internal design notes). They are pure anti-abuse heuristics
            // whose inputs are per-node observed history (the #[serde(skip)]
            // circuit_breaker / velocity / acquisition trackers). Reading them in apply_op
            // forks a snapshot-bootstrapped node (empty trackers → different accept/reject)
            // from a since-genesis node → divergent balances → permanent chain fork.
            // Enforcement is demoted to node-local mempool admission: validate_op
            // (validate.rs) runs all three pre-ingest (ingest.rs:1174) and on RPC submit
            // (routes/core.rs:999). A *sealed* record is applied identically by every node
            // (Bitcoin standardness-vs-validity). The record_* tracker mutations below STAY
            // — they feed the node-local proposal/validate path, not consensus accept/reject.

            // Debit sender
            let sender = state.accounts.entry(creator.clone()).or_default();
            sender.available -= amount;
            sender.total_sent = sender.total_sent.saturating_add(*amount);
            sender.tx_count = sender.tx_count.saturating_add(1);
            sender.last_active = record.timestamp;
            let sender_new_total = sender.total();

            // Record outflow and updated balance for velocity tracking
            state.velocity.record_outflow(&creator, *amount, record.timestamp);
            state.velocity.record_balance(&creator, sender_new_total, record.timestamp);

            // Credit recipient
            let recipient = state.accounts.entry(to.clone()).or_default();
            recipient.available += amount;
            recipient.total_received = recipient.total_received.saturating_add(*amount);
            recipient.tx_count = recipient.tx_count.saturating_add(1);
            recipient.last_active = record.timestamp;
            let recipient_new_total = recipient.total();

            // Record recipient's new balance for peak tracking
            state.velocity.record_balance(to, recipient_new_total, record.timestamp);

            // Record inflow for acquisition tracking
            state.acquisition.record_inflow(to, *amount, record.timestamp);

            // Record volume for circuit breaker and update level
            let circulating = state.circulating_supply();
            state.circuit_breaker.record_volume(*amount, record.timestamp);
            state.circuit_breaker.update_level(circulating, record.timestamp);

            // Exchange classification: record transfer counterparties and reclassify
            state.exchange_classifier.record_transfer(&creator, to, *amount);
            let sender_stake = state.staked(&creator);
            state.exchange_classifier.reclassify(&creator, sender_stake);
            let recipient_stake = state.staked(to);
            state.exchange_classifier.reclassify(to, recipient_stake);

            // IdleDecay flow tracking: record flows for classified exchange identities
            let ts = record.timestamp;
            if state.exchange_classifier.is_classified(&creator) {
                state.idle_decay.record_outflow(&creator, *amount, ts);
                let bal = state.accounts.get(&creator).map(|a| a.total()).unwrap_or(0);
                state.idle_decay.record_balance(&creator, bal, ts);
            }
            if state.exchange_classifier.is_classified(to) {
                state.idle_decay.record_inflow(to, *amount, ts);
                let bal = state.accounts.get(to).map(|a| a.total()).unwrap_or(0);
                state.idle_decay.record_balance(to, bal, ts);
            }
        }

        ParsedLedgerOp::Stake { amount, purpose } => {
            if *amount < MIN_STAKE {
                return Err(ElaraError::Ledger(format!(
                    "stake amount {} below minimum {}",
                    amount, MIN_STAKE
                )));
            }

            // Exchanges cannot stake for governance (zero governance weight)
            if *purpose == StakePurpose::Governance && state.exchange_classifier.is_classified(&creator) {
                return Err(ElaraError::Ledger(
                    "classified exchanges cannot stake for governance".into()
                ));
            }

            let account = state.accounts.entry(creator.clone()).or_default();
            if account.available < *amount {
                return Err(ElaraError::Ledger(format!(
                    "insufficient balance for stake: have {}, need {}",
                    account.available, amount
                )));
            }

            // Move from available to staked
            account.available -= amount;
            account.staked += amount;
            account.total_sent = account.total_sent.saturating_add(*amount); // counts as "sent" for accounting
            account.tx_count = account.tx_count.saturating_add(1);
            account.last_active = record.timestamp;

            // Track balance change (available decreased, staked increased — total unchanged)
            state.velocity.record_balance(&creator, account.total(), record.timestamp);

            state.stakes.insert(
                record.id.clone(),
                StakeEntry {
                    record_id: record.id.clone(),
                    amount: *amount,
                    purpose: purpose.clone(),
                    staker: creator.clone(),
                    timestamp: record.timestamp,
                    active: true,
                },
            );
            state.staker_index.entry(creator.clone()).or_default().push(record.id.clone());
            state.active_stakes_count = state.active_stakes_count.saturating_add(1); // B10
            state.total_staked += amount;
            state.stake_mutation_seq = state.stake_mutation_seq.wrapping_add(1);
        }

        ParsedLedgerOp::Unstake { stake_record_id } => {
            let stake = state
                .stakes
                .get(stake_record_id)
                .ok_or_else(|| {
                    ElaraError::Ledger(format!("stake not found: {stake_record_id}"))
                })?
                .clone();

            if !stake.active {
                return Err(ElaraError::Ledger(format!(
                    "stake already unstaked: {stake_record_id}"
                )));
            }

            // Verify ownership
            if stake.staker != creator {
                return Err(ElaraError::Ledger(format!(
                    "unstake denied: {} does not own stake {}",
                    &creator[..creator.len().min(16)],
                    stake_record_id
                )));
            }

            // Check cooldown
            let elapsed = record.timestamp - stake.timestamp;
            if elapsed < UNSTAKE_COOLDOWN {
                return Err(ElaraError::Ledger(format!(
                    "unstake cooldown: {:.0}s remaining (need {:.0}s)",
                    UNSTAKE_COOLDOWN - elapsed,
                    UNSTAKE_COOLDOWN,
                )));
            }

            // Move from staked back to available
            let account = state.accounts.entry(creator.clone()).or_default();
            account.staked -= stake.amount;
            account.available += stake.amount;
            account.total_received = account.total_received.saturating_add(stake.amount); // counts as "received" back
            account.tx_count = account.tx_count.saturating_add(1);
            account.last_active = record.timestamp;

            // Track balance change (total unchanged but available increased)
            state.velocity.record_balance(&creator, account.total(), record.timestamp);

            state
                .stakes
                .get_mut(stake_record_id)
                .ok_or_else(|| {
                    ElaraError::Ledger(format!("unstake: stake {stake_record_id} vanished mid-apply"))
                })?
                .active = false;
            if let Some(ids) = state.staker_index.get_mut(&creator) {
                ids.retain(|id| id != stake_record_id);
                if ids.is_empty() {
                    state.staker_index.remove(&creator);
                }
            }
            state.active_stakes_count = state.active_stakes_count.saturating_sub(1); // B10 (stake verified active above)
            state.total_staked -= stake.amount;
            state.stake_mutation_seq = state.stake_mutation_seq.wrapping_add(1);
        }

        ParsedLedgerOp::WitnessReward { amount, from, to, record_id: _ } => {
            if *amount == 0 {
                return Err(ElaraError::Ledger("witness reward must be > 0".into()));
            }
            if *amount > MAX_WITNESS_REWARD {
                return Err(ElaraError::Ledger(format!(
                    "witness reward {} exceeds max {}",
                    amount, MAX_WITNESS_REWARD
                )));
            }

            // Cannot reward yourself
            if from == to {
                return Err(ElaraError::Ledger("witness cannot reward self".into()));
            }

            // SECURITY: Only genesis authority can create witness rewards.
            // Manual witness rewards (non-genesis signs, draws from payer account)
            // were removed — they allowed theft by setting beat_from to any identity.
            if !is_privileged_emitter(&creator, genesis_authority) {
                return Err(ElaraError::Ledger(
                    "only genesis authority can create witness reward records".into()
                ));
            }

            // Classified exchanges are ineligible for witness rewards
            if state.exchange_classifier.is_classified(to) {
                return Err(ElaraError::Ledger(
                    "classified exchanges are ineligible for witness rewards".into()
                ));
            }

            // Draw from conservation pool
            if state.conservation_pool < *amount {
                return Err(ElaraError::Ledger(format!(
                    "conservation pool insufficient for reward: have {}, need {}",
                    state.conservation_pool, amount
                )));
            }
            state.conservation_pool -= amount;

            let witness = state.accounts.entry(to.clone()).or_default();
            witness.available += amount;
            witness.total_received = witness.total_received.saturating_add(*amount);
            witness.tx_count = witness.tx_count.saturating_add(1);
            witness.last_active = record.timestamp;

            // Exchange classification: mark recipient as having witness activity
            state.exchange_classifier.record_witness_activity(to);

            // Track witness balance for velocity tiers
            state.velocity.record_balance(to, witness.total(), record.timestamp);
        }

        ParsedLedgerOp::Slash {
            amount, offender, challenger, jury, stake_record_id, ..
        } => {
            // Only genesis authority can execute slashes
            if !is_privileged_emitter(&creator, genesis_authority) {
                return Err(ElaraError::Ledger(format!(
                    "unauthorized slash: {} is not genesis authority",
                    &creator[..creator.len().min(16)]
                )));
            }

            // Look up the stake
            let stake = state
                .stakes
                .get(stake_record_id)
                .ok_or_else(|| {
                    ElaraError::Ledger(format!("stake not found: {stake_record_id}"))
                })?
                .clone();

            if !stake.active {
                return Err(ElaraError::Ledger(format!(
                    "stake already inactive: {stake_record_id}"
                )));
            }

            // Verify offender owns the stake
            if stake.staker != *offender {
                return Err(ElaraError::Ledger(format!(
                    "slash target mismatch: stake {} owned by {}, not {}",
                    stake_record_id,
                    &stake.staker[..stake.staker.len().min(16)],
                    &offender[..offender.len().min(16)]
                )));
            }

            // Cap slash at MAX_SLASH_PERCENTAGE of stake and at actual staked amount.
            // Integer rationals (no f64): `stake.amount` can exceed 2^53 and this
            // split is recomputed on every node, so it must be node-identical.
            let max_slash = ((stake.amount as u128) * MAX_SLASH_PERCENTAGE_NUM
                / MAX_SLASH_PERCENTAGE_DEN) as u64;
            let actual_slash = (*amount).min(max_slash).min(stake.amount);

            if actual_slash == 0 {
                return Err(ElaraError::Ledger("slash amount is zero".into()));
            }

            // Distribution: 50% pool, 30% challenger, 20% jury (jury = remainder
            // so the split is conservation-exact with no rounding dust lost).
            let pool_share =
                ((actual_slash as u128) * SLASH_POOL_FRACTION_NUM / SLASH_POOL_FRACTION_DEN) as u64;
            let challenger_share = ((actual_slash as u128) * SLASH_CHALLENGER_FRACTION_NUM
                / SLASH_CHALLENGER_FRACTION_DEN) as u64;
            let jury_share = actual_slash - pool_share - challenger_share;

            // Debit offender's stake
            let offender_account = state.accounts.entry(offender.clone()).or_default();
            offender_account.staked -= actual_slash;
            offender_account.total_sent = offender_account.total_sent.saturating_add(actual_slash);
            offender_account.tx_count = offender_account.tx_count.saturating_add(1);
            offender_account.last_active = record.timestamp;

            // Update stake entry
            let stake_entry = state.stakes.get_mut(stake_record_id).ok_or_else(|| {
                ElaraError::Ledger(format!("slash: stake {stake_record_id} vanished mid-apply"))
            })?;
            if stake_entry.amount <= actual_slash {
                stake_entry.active = false;
                stake_entry.amount = 0;
                // Remove fully-slashed stake from staker index
                if let Some(ids) = state.staker_index.get_mut(offender.as_str()) {
                    ids.retain(|id| id != stake_record_id);
                    if ids.is_empty() {
                        state.staker_index.remove(offender.as_str());
                    }
                }
                state.active_stakes_count = state.active_stakes_count.saturating_sub(1); // B10 (full slash; verified active above)
            } else {
                stake_entry.amount -= actual_slash;
            }
            state.total_staked -= actual_slash;
            state.stake_mutation_seq = state.stake_mutation_seq.wrapping_add(1);

            // Credit challenger (30%)
            let challenger_account = state.accounts.entry(challenger.clone()).or_default();
            challenger_account.available += challenger_share;
            challenger_account.total_received = challenger_account.total_received.saturating_add(challenger_share);
            challenger_account.tx_count = challenger_account.tx_count.saturating_add(1);
            challenger_account.last_active = record.timestamp;

            // Credit jury (20%) — split equally among jury members. If the jury
            // is empty, `jury_share` has already been debited from the offender
            // (via `actual_slash`) but has no recipient; fold it into the
            // conservation-pool credit below so the slash stays conservation-exact
            // (offender debit == sum of all credits). Empty-jury is
            // authority-gated/unreachable on an honest emitter today, but becomes
            // reachable once ConflictProofs are gossiped pre-S3 (B12(f)) — this
            // closes the silent supply-shrink path. test_slash_empty_jury_conserves.
            let mut pool_credit = pool_share;
            if jury.is_empty() {
                pool_credit += jury_share;
            } else {
                let per_juror = jury_share / jury.len() as u64;
                let mut remainder = jury_share - per_juror * jury.len() as u64;
                for juror in jury.iter() {
                    // First juror(s) absorb integer-division dust
                    let dust = if remainder > 0 { remainder -= 1; 1 } else { 0 };
                    let juror_amount = per_juror + dust;
                    let juror_account = state.accounts.entry(juror.clone()).or_default();
                    juror_account.available += juror_amount;
                    juror_account.total_received = juror_account.total_received.saturating_add(juror_amount);
                    juror_account.tx_count = juror_account.tx_count.saturating_add(1);
                    juror_account.last_active = record.timestamp;
                }
            }

            // Credit Conservation Pool (50%, plus any empty-jury share) — capped
            let pool_actual = pool_credit.min(state.pool_headroom());
            state.conservation_pool += pool_actual;

            // If pool is at cap, overflow goes to challenger
            let overflow = pool_credit - pool_actual;
            if overflow > 0 {
                let c_acct = state.accounts.entry(challenger.clone()).or_default();
                c_acct.available += overflow;
                c_acct.total_received = c_acct.total_received.saturating_add(overflow);
            }
        }

        ParsedLedgerOp::IdleDecay { batch } => {
            // Protocol-imposed custodial idle_decay (economics §13.13.1), emitted
            // by the genesis authority once per epoch as a frozen batch (Option A,
            // internal design notes). Same authorization model as
            // Slash / Burn / WitnessReward / DormancyReclaim — only the genesis
            // authority may impose this third-party debit. Conservation, per-debit
            // balance checks, mutation, counter advance, and tracker pruning all
            // live in apply_idle_decay_batch (directly unit-tested).
            if !is_privileged_emitter(&creator, genesis_authority) {
                return Err(ElaraError::Ledger(format!(
                    "unauthorized idle_decay: {} is not genesis authority",
                    &creator[..creator.len().min(16)]
                )));
            }
            state.apply_idle_decay_batch(batch, record.timestamp)?;
        }

        ParsedLedgerOp::XZoneTimeoutRefund { batch } => {
            // Frozen per-epoch batch of expired-UNSEALED cross-zone refunds
            // (economics §16.1), emitted by the genesis authority once per epoch
            // (Option A, internal design notes). Same
            // authorization model as IdleDecay — only the genesis authority may
            // un-lock a third party's in-flight transfer. Replaces the old ungated
            // in-loop `process_expired_xzone` mutation, which forked because each
            // seal-eligible node ran it at a different wall-clock `now` and
            // followers never ran it at all.
            if !is_privileged_emitter(&creator, genesis_authority) {
                return Err(ElaraError::Ledger(format!(
                    "unauthorized xzone timeout refund: {} is not genesis authority",
                    &creator[..creator.len().min(16)]
                )));
            }
            // apply_refund_batch flips each eligible Locked→Refunded against THIS
            // node's replicated `pending` (skip-missing: a CLAIM/Cancel/Abort that
            // landed first is skipped, never double-refunded) and returns the
            // (sender, amount) subset actually un-locked — read from the live
            // entry, so a forged batch amount is inert. The per-entry account
            // mutation is byte-identical to XZoneCancel's unsealed refund.
            let applied = state.cross_zone.apply_refund_batch(batch);
            for (sender, amount) in applied {
                let account = state.accounts.entry(sender.clone()).or_default();
                account.available += amount;
                // total_sent was incremented at lock — decrement on un-lock so the
                // velocity-window net-outflow stays accurate (mirrors XZoneCancel).
                account.total_sent = account.total_sent.saturating_sub(amount);
                account.tx_count = account.tx_count.saturating_add(1);
                account.last_active = record.timestamp;
                state.velocity.record_balance(&sender, account.total(), record.timestamp);
                state.pending_xzone_locked = state.pending_xzone_locked.saturating_sub(amount);
            }
        }

        ParsedLedgerOp::XZoneStaleReap { batch } => {
            // Far-horizon hard-reap of SEALED cross-zone locks stuck ~30d past
            // expiry under a dead/partitioned dest committee (co-fix (b),
            // economics §16.1, internal design notes).
            // Same genesis-authority gate + skip-missing apply + per-entry account
            // mutation as XZoneTimeoutRefund; only the cross_zone eligibility
            // predicate differs (Locked AND SEALED, vs Locked AND unsealed). Safe
            // to refund at 30d because the 24h CLAIM window closed 29d ago, so no
            // claim can race the refund.
            if !is_privileged_emitter(&creator, genesis_authority) {
                return Err(ElaraError::Ledger(format!(
                    "unauthorized xzone stale reap: {} is not genesis authority",
                    &creator[..creator.len().min(16)]
                )));
            }
            let applied = state.cross_zone.apply_reap_batch(batch);
            for (sender, amount) in applied {
                let account = state.accounts.entry(sender.clone()).or_default();
                account.available += amount;
                account.total_sent = account.total_sent.saturating_sub(amount);
                account.tx_count = account.tx_count.saturating_add(1);
                account.last_active = record.timestamp;
                state.velocity.record_balance(&sender, account.total(), record.timestamp);
                state.pending_xzone_locked = state.pending_xzone_locked.saturating_sub(amount);
            }
        }

        ParsedLedgerOp::Burn { amount, .. } => {
            if !is_privileged_emitter(&creator, genesis_authority) {
                return Err(ElaraError::Ledger("only genesis authority can execute burn".into()));
            }
            if *amount == 0 {
                return Err(ElaraError::Ledger("burn amount must be > 0".into()));
            }

            let account = state.accounts.entry(creator.clone()).or_default();
            if account.available < *amount {
                return Err(ElaraError::Ledger(format!(
                    "insufficient balance for burn: have {}, need {}",
                    account.available, amount
                )));
            }

            account.available -= amount;
            account.total_sent = account.total_sent.saturating_add(*amount);
            account.tx_count = account.tx_count.saturating_add(1);
            account.last_active = record.timestamp;

            // Redirect to Conservation Pool — preserves conservation invariant.
            // total_supply unchanged. Beats recycled, not destroyed.
            state.conservation_pool += amount;
        }

        ParsedLedgerOp::DormancyReclaim {
            amount, dormant_identity, last_activity,
        } => {
            // Only genesis authority can execute dormancy reclaims
            if !is_privileged_emitter(&creator, genesis_authority) {
                return Err(ElaraError::Ledger(format!(
                    "unauthorized dormancy reclaim: {} is not genesis authority",
                    &creator[..creator.len().min(16)]
                )));
            }

            // Verify the dormant identity exists
            let dormant_account = state.accounts.get(dormant_identity)
                .ok_or_else(|| {
                    ElaraError::Ledger(format!("dormant identity not found: {}", &dormant_identity[..dormant_identity.len().min(16)]))
                })?;

            // Verify dormancy — last_activity must be before threshold
            let time_since_active = record.timestamp - dormant_account.last_active;
            if time_since_active < DORMANCY_THRESHOLD {
                return Err(ElaraError::Ledger(format!(
                    "identity not dormant: last active {:.0}s ago, threshold is {:.0}s",
                    time_since_active, DORMANCY_THRESHOLD
                )));
            }

            // Verify the claimed last_activity matches our records
            if (*last_activity - dormant_account.last_active).abs() > 1.0 {
                return Err(ElaraError::Ledger(format!(
                    "last_activity mismatch: claimed {}, actual {}",
                    last_activity, dormant_account.last_active
                )));
            }

            // AUDIT-3: Enforce 3-phase lifecycle — reclaim requires Phase 2 declaration
            // exists AND Phase 3 wake-up window has expired (economics §2.5).
            // Without this gate, genesis-authority compromise = instant drain of all
            // dormant accounts with no public notice, no recourse.
            match state.dormancy.phase(dormant_identity) {
                crate::accounting::dormancy::DormancyPhase::Active => {
                    return Err(ElaraError::Ledger(format!(
                        "dormancy reclaim requires Phase 2 declaration: {} has no DormancyDeclare record",
                        &dormant_identity[..dormant_identity.len().min(16)]
                    )));
                }
                crate::accounting::dormancy::DormancyPhase::Reclaimed => {
                    return Err(ElaraError::Ledger(format!(
                        "dormancy reclaim already executed for {}",
                        &dormant_identity[..dormant_identity.len().min(16)]
                    )));
                }
                crate::accounting::dormancy::DormancyPhase::Dormant => {}
            }
            if !state.dormancy.eligible_for_reclamation(dormant_identity, record.timestamp) {
                let deadline = state.dormancy.declaration(dormant_identity)
                    .map(|d| d.wakeup_deadline).unwrap_or(0.0);
                return Err(ElaraError::Ledger(format!(
                    "wake-up window not yet expired: deadline {:.0}, now {:.0}",
                    deadline, record.timestamp
                )));
            }

            // Cap at available balance
            let actual_reclaim = (*amount).min(dormant_account.available);
            if actual_reclaim == 0 {
                return Err(ElaraError::Ledger("dormancy reclaim amount is zero".into()));
            }

            // Debit dormant account
            let dormant = state.accounts.get_mut(dormant_identity).ok_or_else(|| {
                ElaraError::Ledger(format!(
                    "dormancy reclaim: account {} vanished mid-apply",
                    &dormant_identity[..dormant_identity.len().min(16)]
                ))
            })?;
            dormant.available -= actual_reclaim;
            dormant.total_sent = dormant.total_sent.saturating_add(actual_reclaim);
            dormant.tx_count = dormant.tx_count.saturating_add(1);
            // NOTE: Do NOT update last_active — reclaim is not "activity" by the owner

            // Credit Conservation Pool — capped
            let pool_actual = actual_reclaim.min(state.pool_headroom());
            state.conservation_pool += pool_actual;

            // If pool is at cap, overflow stays in dormant account (no forced redistribution)
            if pool_actual < actual_reclaim {
                let dormant = state.accounts.get_mut(dormant_identity).ok_or_else(|| {
                    ElaraError::Ledger(format!(
                        "dormancy reclaim overflow-refund: account {} vanished mid-apply",
                        &dormant_identity[..dormant_identity.len().min(16)]
                    ))
                })?;
                dormant.available += actual_reclaim - pool_actual;
                // saturating: see the prediction-overflow refund — a bare `-=`
                // would wrap in release / panic in debug if `total_sent` was
                // never incremented for this reclaimed dormant balance.
                dormant.total_sent =
                    dormant.total_sent.saturating_sub(actual_reclaim - pool_actual);
            }

            // Transition Phase 2 → Phase 4 (Reclaimed).
            state.dormancy.record_reclamation(dormant_identity, actual_reclaim);
        }

        ParsedLedgerOp::PoolFund { amount } => {
            // Only genesis authority can fund the conservation pool
            if !is_privileged_emitter(&creator, genesis_authority) {
                return Err(ElaraError::Ledger(format!(
                    "unauthorized pool_fund: {} is not genesis authority",
                    &creator[..creator.len().min(16)]
                )));
            }
            if *amount == 0 {
                return Err(ElaraError::Ledger("pool_fund amount must be > 0".into()));
            }

            let account = state.accounts.entry(creator.clone()).or_default();
            if account.available < *amount {
                return Err(ElaraError::Ledger(format!(
                    "insufficient balance for pool_fund: have {}, need {}",
                    account.available, amount
                )));
            }

            account.available -= amount;
            account.total_sent = account.total_sent.saturating_add(*amount);
            account.tx_count = account.tx_count.saturating_add(1);
            account.last_active = record.timestamp;

            // Credit conservation pool — capped
            let pool_actual = (*amount).min(state.pool_headroom());
            state.conservation_pool += pool_actual;

            // If pool is at cap, refund overflow to sender
            let overflow = *amount - pool_actual;
            if overflow > 0 {
                let account = state.accounts.entry(creator.clone()).or_default();
                account.available += overflow;
                // saturating: consistent with the `saturating_add` at the debit
                // above — never wrap/panic on the refund leg.
                account.total_sent = account.total_sent.saturating_sub(overflow);
            }
        }

        ParsedLedgerOp::Predict { amount, zone, target_epoch, claim, predicted_value } => {
            // Sandbox zones allow zero-cost predictions (EMERGENT-MIND §5)
            let is_sandbox = zone.starts_with("sandbox/") || zone == "sandbox";
            if !is_sandbox && *amount < MIN_PREDICTION_STAKE {
                return Err(ElaraError::Ledger(format!(
                    "prediction stake {} below minimum {} (use sandbox/ zone for free predictions)",
                    amount, MIN_PREDICTION_STAKE
                )));
            }

            if *amount > 0 {
                let account = state.accounts.entry(creator.clone()).or_default();
                if account.available < *amount {
                    return Err(ElaraError::Ledger(format!(
                        "insufficient balance for prediction: have {}, need {}",
                        account.available, amount
                    )));
                }

                // Lock stake from available balance
                account.available -= amount;
                account.total_sent = account.total_sent.saturating_add(*amount);
                account.tx_count = account.tx_count.saturating_add(1);
                account.last_active = record.timestamp;

                // Track balance change
                state.velocity.record_balance(&creator, account.total(), record.timestamp);
            } else {
                // Zero-cost sandbox prediction — just track activity
                let account = state.accounts.entry(creator.clone()).or_default();
                account.tx_count = account.tx_count.saturating_add(1);
                account.last_active = record.timestamp;
            }

            // Register prediction for future evaluation
            state.predictions.insert(
                record.id.clone(),
                PredictionEntry {
                    record_id: record.id.clone(),
                    predictor: creator.clone(),
                    amount: *amount,
                    zone: zone.clone(),
                    target_epoch: *target_epoch,
                    claim: claim.clone(),
                    predicted_value: *predicted_value,
                    timestamp: record.timestamp,
                    outcome: None,
                },
            );
        }

        ParsedLedgerOp::XZoneLock { amount, recipient, source_zone, dest_zone } => {
            if source_zone == dest_zone {
                return Err(ElaraError::Ledger("cross-zone lock: source and dest zones must differ".into()));
            }

            // CONSENSUS-FORBIDDEN: cross-zone velocity rate-limit reject demoted to mempool
            // admission (Track D, internal design notes) — velocity is a
            // #[serde(skip)] per-node tracker, same fork class as the in-zone transfer path.
            // The equivalent check now lives in validate_op's XZoneLock arm (validate.rs).

            // Balance check. entry().or_default() (not get()) preserves the
            // historical behavior of materializing an empty account for an unknown
            // creator even when the lock is rejected here — keeping the account map
            // and its SMT root replay-identical. Scoped so the &mut borrow is
            // released before lock_transfer re-borrows `state`.
            {
                let account = state.accounts.entry(creator.clone()).or_default();
                if account.available < *amount {
                    return Err(ElaraError::Ledger(format!(
                        "insufficient balance for cross-zone lock: have {}, need {}",
                        account.available, amount
                    )));
                }
            }

            // Register the pending transfer FIRST — fail-closed. lock_transfer
            // validates (dup transfer_id / zero amount / same zone) and rejects
            // atomically, BEFORE mutating cross_zone. The `?` MUST precede the
            // debit + pending bump below: if it errored AFTER them, `amount` would
            // be stranded — available↓ and pending_xzone_locked↑ cancel in the
            // conservation SUM (no supply break), but no cross_zone.pending entry
            // exists for claim/abort/refund to ever release it. transfer_id ==
            // record.id, so a dup needs the same record applied twice, which the
            // apply_op head-guard (applied_record_ids) already blocks; this
            // ordering is defense-in-depth that holds even if that guard is ever
            // bypassed. Lock record hash stored for Merkle proof verification (M7).
            state.cross_zone.lock_transfer(
                record.id.clone(),
                creator.clone(),
                recipient.clone(),
                *amount,
                crate::ZoneId::new(source_zone),
                crate::ZoneId::new(dest_zone),
                record.timestamp,
                record.record_hash(),
            )?;

            // Debit sender — beats are now "in flight". Infallible from here, so
            // the lock entry registered above can never be orphaned.
            let account = state.accounts.entry(creator.clone()).or_default();
            account.available -= amount;
            account.total_sent = account.total_sent.saturating_add(*amount);
            account.tx_count = account.tx_count.saturating_add(1);
            account.last_active = record.timestamp;
            state.velocity.record_balance(&creator, account.total(), record.timestamp);

            // Track pending cross-zone amount for conservation invariant.
            // saturating_add mirrors the saturating_sub release paths.
            state.pending_xzone_locked = state.pending_xzone_locked.saturating_add(*amount);

            #[cfg(feature = "node-core")]
            tracing::info!(
                "xzone_lock: {} locked {} for {} (zone {} → {}), transfer_id={}",
                &creator[..16], amount, &recipient[..recipient.len().min(16)],
                source_zone, dest_zone, &record.id[..16]
            );
        }

        ParsedLedgerOp::XZoneClaim { transfer_id, amount: _wire_amount, recipient } => {
            // Verify and mark transfer as claimed BEFORE crediting beats.
            // claim_transfer checks: exists, status=Locked, correct recipient,
            // not expired, and merkle proof is valid (M7). It returns the
            // authoritative PendingTransfer.
            let claimed = state.cross_zone.claim_transfer(
                transfer_id,
                recipient,
                &record.id,
                record.timestamp,
            )?;

            // SECURITY (conservation): credit the AUTHORITATIVE locked amount
            // (`claimed.amount`), NOT the wire `amount` field. The wire field is
            // unvalidated attacker input — validate_op only checks it is non-zero,
            // and nothing binds it to the locked transfer. Crediting it let a
            // legitimate recipient claim a real 1-beat transfer for an arbitrary
            // amount → beats created ex nihilo (no matching debit), breaking the
            // conservation invariant. The locked amount was debited from the
            // sender at XZoneLock time and is the only sound value to release.
            let amount = claimed.amount;

            // Credit recipient in destination zone
            let account = state.accounts.entry(recipient.clone()).or_default();
            account.available += amount;
            account.total_received = account.total_received.saturating_add(amount);
            account.tx_count = account.tx_count.saturating_add(1);
            account.last_active = record.timestamp;
            state.velocity.record_balance(recipient, account.total(), record.timestamp);

            // Release from pending cross-zone tracking
            state.pending_xzone_locked = state.pending_xzone_locked.saturating_sub(amount);

            #[cfg(feature = "node-core")]
            tracing::info!(
                "xzone_claim: {} claimed {} (transfer_id={})",
                &recipient[..recipient.len().min(16)], amount, &transfer_id[..transfer_id.len().min(16)]
            );
        }

        ParsedLedgerOp::XZoneCancel { transfer_id } => {
            // Gap 2 atomic-rollback: sender-initiated cancel of an unsealed
            // XZoneLock. cancel_transfer enforces:
            //   - transfer exists and is in Locked status,
            //   - record creator is the original sender,
            //   - lock has NOT yet been committed to an epoch seal
            //     (`merkle_proof` is empty).
            // Returns the (transfer_id, sender, amount) tuple — we credit
            // amount back to creator.available and decrement the global
            // pending_xzone_locked tracker.
            let (_tid, _sender, amount) = state
                .cross_zone
                .cancel_transfer(transfer_id, &creator)?;

            let account = state.accounts.entry(creator.clone()).or_default();
            account.available += amount;
            // total_sent was incremented at lock — decrement on rollback so
            // the velocity-window total accurately reflects net outflow.
            account.total_sent = account.total_sent.saturating_sub(amount);
            account.tx_count = account.tx_count.saturating_add(1);
            account.last_active = record.timestamp;
            state.velocity.record_balance(&creator, account.total(), record.timestamp);

            state.pending_xzone_locked = state.pending_xzone_locked.saturating_sub(amount);

            #[cfg(feature = "node-core")]
            tracing::info!(
                "xzone_cancel: {} cancelled {} (transfer_id={}, refund={})",
                &creator[..creator.len().min(16)],
                &transfer_id[..transfer_id.len().min(16)],
                &transfer_id[..transfer_id.len().min(16)],
                amount,
            );
        }

        ParsedLedgerOp::XZoneAbort {
            transfer_id,
            dest_committee_hash,
            dest_committee_size,
            signers,
        } => {
            // Gap 2 sealed-abort: destination-zone committee non-inclusion
            // attestation refunds the sender of an already-sealed transfer.
            // Authorization is the proof itself, not the record creator —
            // anyone with a valid 2/3 B-committee quorum can submit.
            //
            // Apply path is the canonical proof-verification site: we resolve
            // (dest_zone, source_seal_epoch) from the source-side pending
            // entry rather than trusting the metadata, then run
            // verify_abort_quorum. abort_transfer's gates ensure the transfer
            // is sealed and Locked — see its docstring for the split between
            // proof verification (here) and state-transition (there).
            // B2 fix: resolve (dest_zone, source_seal_epoch) AND the canonical
            // dest-committee anchor frozen from the source seal — all from the
            // local pending entry, never the wire record. verify_abort_quorum
            // gates the wire committee against this anchor (fail-closed if None).
            let (dest_zone, source_seal_epoch, anchored_committee) = {
                let pending = state
                    .cross_zone
                    .pending
                    .get(transfer_id)
                    .ok_or_else(|| {
                        ElaraError::Ledger(format!(
                            "xzone_abort: transfer {} not found",
                            transfer_id
                        ))
                    })?;
                (
                    pending.dest_zone.clone(),
                    pending.source_seal_epoch,
                    pending.dest_finality_committee,
                )
            };

            crate::accounting::cross_zone::verify_abort_quorum(
                transfer_id,
                &dest_zone,
                source_seal_epoch,
                dest_committee_hash,
                *dest_committee_size,
                signers,
                anchored_committee,
            )
            .map_err(|e| {
                ElaraError::Ledger(format!(
                    "xzone_abort: B-committee proof rejected for {}: {}",
                    transfer_id, e
                ))
            })?;

            let (_tid, sender, amount) = state.cross_zone.abort_transfer(transfer_id)?;

            let sender_acct = state.accounts.entry(sender.clone()).or_default();
            sender_acct.available += amount;
            // total_sent was incremented at lock — undo the outflow on refund.
            sender_acct.total_sent = sender_acct.total_sent.saturating_sub(amount);
            sender_acct.last_active = record.timestamp;
            state
                .velocity
                .record_balance(&sender, sender_acct.total(), record.timestamp);

            // Submitter (creator) gets a tx_count bump even though they are
            // typically not the refund destination — this is their record,
            // it cost them a fee, and it should reflect on their account.
            let creator_acct = state.accounts.entry(creator.clone()).or_default();
            creator_acct.tx_count = creator_acct.tx_count.saturating_add(1);
            creator_acct.last_active = record.timestamp;

            state.pending_xzone_locked = state.pending_xzone_locked.saturating_sub(amount);

            #[cfg(feature = "node-core")]
            tracing::info!(
                "xzone_abort: {} aborted transfer {} via B-committee quorum (refund {} → {})",
                &creator[..creator.len().min(16)],
                &transfer_id[..transfer_id.len().min(16)],
                amount,
                &sender[..sender.len().min(16)],
            );
        }

        ParsedLedgerOp::XZoneReject { transfer_id } => {
            // Gap 2 atomic-rollback: recipient-initiated reject of an unsealed
            // XZoneLock. reject_transfer enforces:
            //   - transfer exists and is in Locked status,
            //   - record creator is the original recipient,
            //   - lock has NOT yet been committed to an epoch seal
            //     (`merkle_proof` is empty).
            // Returns the (transfer_id, sender, amount) tuple — we credit
            // amount back to the SENDER's available (NOT the creator who is
            // the recipient) and decrement pending_xzone_locked.
            let (_tid, sender, amount) = state
                .cross_zone
                .reject_transfer(transfer_id, &creator)?;

            let sender_acct = state.accounts.entry(sender.clone()).or_default();
            sender_acct.available += amount;
            sender_acct.total_sent = sender_acct.total_sent.saturating_sub(amount);
            sender_acct.last_active = record.timestamp;
            state.velocity.record_balance(&sender, sender_acct.total(), record.timestamp);

            // Recipient's tx_count bumps for the reject record itself, even
            // though no balance change happens for them.
            let rcpt_acct = state.accounts.entry(creator.clone()).or_default();
            rcpt_acct.tx_count = rcpt_acct.tx_count.saturating_add(1);
            rcpt_acct.last_active = record.timestamp;

            state.pending_xzone_locked = state.pending_xzone_locked.saturating_sub(amount);

            #[cfg(feature = "node-core")]
            tracing::info!(
                "xzone_reject: {} rejected transfer {} (refund {} → {})",
                &creator[..creator.len().min(16)],
                &transfer_id[..transfer_id.len().min(16)],
                amount,
                &sender[..sender.len().min(16)],
            );
        }

        ParsedLedgerOp::DormancyDeclare { target_identity, last_known_active } => {
            // Phase 2 of dormancy lifecycle (economics §2.5).
            // Record's network-layer settlement already enforces quorum attestation
            // (≥ 2 distinct witnesses). We pass 2 as the minimum; real attestor set
            // is validated at the consensus layer before this record reaches apply_op.
            let target_account = state.accounts.get(target_identity)
                .ok_or_else(|| ElaraError::Ledger(format!(
                    "declare target not found: {}",
                    &target_identity[..target_identity.len().min(16)]
                )))?;

            // last_known_active must match ledger's last_active (defense against
            // a declarer forging an earlier timestamp to bypass the 5-year threshold).
            if (*last_known_active - target_account.last_active).abs() > 1.0 {
                return Err(ElaraError::Ledger(format!(
                    "last_known_active mismatch: claimed {}, ledger {}",
                    last_known_active, target_account.last_active
                )));
            }

            // Delegate phase/threshold/already-declared checks to DormancyState.
            // witness_count=2 corresponds to the 2+ network-layer quorum that the
            // record already passed to reach a settled state.
            state.dormancy.declare(
                target_identity,
                &creator,
                *last_known_active,
                record.timestamp,
                crate::accounting::dormancy::DORMANCY_MIN_WITNESSES,
            ).map_err(ElaraError::Ledger)?;

            #[cfg(feature = "node-core")]
            tracing::info!(
                "dormancy_declare: {} declared {} dormant (wake-up deadline in ~2yr)",
                &creator[..creator.len().min(16)],
                &target_identity[..target_identity.len().min(16)]
            );
        }

        ParsedLedgerOp::DormancyHeartbeat => {
            // Phase 3 self-wake (economics §2.5).
            // Creator IS the dormant identity proving liveness by signing this record.
            // Record is rejected by default pipeline unless creator's signature is valid,
            // so creator == dormant identity here by construction.
            state.dormancy.wake_up(&creator, record.timestamp)
                .map_err(ElaraError::Ledger)?;

            // Reset last_active so future threshold checks start from now.
            if let Some(account) = state.accounts.get_mut(&creator) {
                account.last_active = record.timestamp;
            }

            #[cfg(feature = "node-core")]
            tracing::info!(
                "dormancy_heartbeat: {} woke up from dormancy",
                &creator[..creator.len().min(16)]
            );
        }

        ParsedLedgerOp::WitnessRegister { zone_path, bond } => {
            // Bond is gated at parse time to be ≥ WITNESS_BOND_MIN, so just
            // verify the creator's available balance covers it.
            let account = state.accounts.entry(creator.clone()).or_default();
            if account.available < *bond {
                return Err(ElaraError::Ledger(format!(
                    "witness_register: insufficient balance ({} < {})",
                    account.available, bond
                )));
            }
            account.available -= *bond;
            account.witness_bonded = account.witness_bonded.saturating_add(*bond);
            account.last_active = record.timestamp;
            account.tx_count = account.tx_count.saturating_add(1);

            // Derive epoch from record timestamp (1 epoch ≈ 60s @ adaptive
            // floor). The exact epoch number is informational — what matters
            // for committee selection is presence in the registry, not the
            // registration time. Cheap monotonic counter.
            let registered_epoch = (record.timestamp as u64) / 60;

            // Queue durable write to CF_WITNESS_REGISTRY — drained in Slice 3c
            // by the storage layer after apply commits.
            state.pending_witness_registrations.push((
                zone_path.clone(),
                creator.clone(),
                record.creator_public_key.clone(),
                *bond,
                registered_epoch,
            ));

            #[cfg(feature = "node-core")]
            tracing::info!(
                "witness_register: {} bonded {} beat in zone {}",
                &creator[..creator.len().min(16)],
                *bond / crate::accounting::types::BASE_UNITS_PER_BEAT,
                zone_path
            );
        }

        ParsedLedgerOp::DormancyProofOfLife { target_identity, signature } => {
            // Phase 3 third-party wake (economics §2.5).
            // The relayer submits a signed proof-of-life message from the target.
            // MVP: signature is opaque — stored in record metadata for later crypto
            // verification (Phase B). The wake-up itself requires that the target
            // was previously declared dormant, which gates non-owner abuse: a random
            // relayer cannot wake an Active identity.
            let _ = signature; // reserved for Phase B signature verification
            state.dormancy.wake_up(target_identity, record.timestamp)
                .map_err(ElaraError::Ledger)?;

            // Reset last_active for the target.
            if let Some(account) = state.accounts.get_mut(target_identity) {
                account.last_active = record.timestamp;
            }

            #[cfg(feature = "node-core")]
            tracing::info!(
                "dormancy_proof_of_life: {} relayed wake for {}",
                &creator[..creator.len().min(16)],
                &target_identity[..target_identity.len().min(16)]
            );
        }
    }

    state.records_processed += 1;
    state.applied_record_ids.insert(record.id.clone());
    if record.timestamp > state.last_applied_ts {
        state.last_applied_ts = record.timestamp;
    }

    // Phase 3 Stage 2B: track which accounts need their SMT leaf refreshed.
    // The actual hashing + tree update is batched in flush_dirty (called at
    // epoch boundaries or snapshot time). The creator always moves (tx_count
    // at minimum); any counterparty account touched by the op is added too.
    state.smt_dirty.insert(creator.clone());
    match op {
        ParsedLedgerOp::Mint { to, .. }
        | ParsedLedgerOp::Transfer { to, .. } => {
            state.smt_dirty.insert(to.clone());
        }
        ParsedLedgerOp::WitnessReward { to, from, .. } => {
            state.smt_dirty.insert(to.clone());
            state.smt_dirty.insert(from.clone());
        }
        ParsedLedgerOp::XZoneLock { recipient, .. }
        | ParsedLedgerOp::XZoneClaim { recipient, .. } => {
            state.smt_dirty.insert(recipient.clone());
        }
        ParsedLedgerOp::XZoneReject { transfer_id } => {
            // Sender's available balance changed (refund). Recipient (creator)
            // already in smt_dirty above. Look up sender from the (now-Refunded)
            // pending entry — still present in cross_zone.pending.
            if let Some(t) = state.cross_zone.pending.get(transfer_id) {
                state.smt_dirty.insert(t.sender.clone());
            }
        }
        ParsedLedgerOp::XZoneAbort { transfer_id, .. } => {
            // Sender's available balance is credited back on abort. Submitter
            // (creator) is already in smt_dirty above. Pending entry is still
            // present (now in Aborted state) so we can read the sender out.
            if let Some(t) = state.cross_zone.pending.get(transfer_id) {
                state.smt_dirty.insert(t.sender.clone());
            }
        }
        ParsedLedgerOp::DormancyReclaim { dormant_identity, .. } => {
            state.smt_dirty.insert(dormant_identity.clone());
        }
        ParsedLedgerOp::DormancyDeclare { target_identity, .. }
        | ParsedLedgerOp::DormancyProofOfLife { target_identity, .. } => {
            // Target identity's phase changes but balance does not on declare;
            // still mark dirty so downstream proofs reflect the phase transition
            // if account-SMT ever includes dormancy phase. Cheap either way.
            state.smt_dirty.insert(target_identity.clone());
        }
        ParsedLedgerOp::Slash { offender, challenger, jury, .. } => {
            state.smt_dirty.insert(offender.clone());
            state.smt_dirty.insert(challenger.clone());
            for j in jury {
                state.smt_dirty.insert(j.clone());
            }
        }
        ParsedLedgerOp::IdleDecay { batch } => {
            // Every debited exchange + every credited staker moves its `available`.
            // The Conservation Pool is a scalar (no SMT leaf). This set MUST equal
            // the accounts mutated in apply_idle_decay_batch, or the producer's and
            // witnesses' account-SMT roots diverge for this seal.
            for (id, _) in &batch.debits {
                state.smt_dirty.insert(id.clone());
            }
            for (id, _) in &batch.staker_credits {
                state.smt_dirty.insert(id.clone());
            }
        }
        ParsedLedgerOp::XZoneTimeoutRefund { batch } => {
            // Every refunded sender moves its `available` (+ total_sent/tx_count/
            // last_active, all SMT-leaf fields). `pending_xzone_locked` is a scalar
            // (no leaf). Mark every listed sender dirty — a deterministic superset
            // of the actually-applied subset (apply_refund_batch may skip entries a
            // CLAIM resolved first); re-hashing an unmutated leaf is a no-op, and a
            // SUBSET would risk a stale leaf → SMT-root divergence at this seal.
            for (_tid, sender, _amt) in &batch.refunds {
                state.smt_dirty.insert(sender.clone());
            }
        }
        ParsedLedgerOp::XZoneStaleReap { batch } => {
            // Same SMT-leaf rationale as XZoneTimeoutRefund — mark every listed
            // sender dirty (deterministic superset of the reaped subset).
            for (_tid, sender, _amt) in &batch.refunds {
                state.smt_dirty.insert(sender.clone());
            }
        }
        ParsedLedgerOp::Stake { .. }
        | ParsedLedgerOp::Unstake { .. }
        | ParsedLedgerOp::Burn { .. }
        | ParsedLedgerOp::PoolFund { .. }
        | ParsedLedgerOp::Predict { .. }
        | ParsedLedgerOp::DormancyHeartbeat
        | ParsedLedgerOp::XZoneCancel { .. }
        | ParsedLedgerOp::WitnessRegister { .. } => {
            // Creator-only — already inserted above. WitnessRegister moves bond
            // from `available` → `witness_bonded` on the creator's own account,
            // so creator-only is correct.
        }
    }

    Ok(())
}

/// Extract and sort all ledger records from a storage backend.
///
/// Returns (record, parsed_op) pairs sorted by timestamp ascending.
/// WARNING: Loads ALL records — O(all_records) memory.
#[cfg(test)]
pub fn extract_ledger_records(
    storage: &dyn crate::storage::Storage,
) -> Result<Vec<(ValidationRecord, ParsedLedgerOp)>> {
    // Query all public records (ledger ops are always public)
    let all_records = storage.query(
        Some(crate::record::Classification::Public),
        None,
        None,
        None,
        usize::MAX,
    )?;

    let mut ledger_records = Vec::new();

    for record in all_records {
        if let Some(op) = extract_ledger_op(&record)? {
            ledger_records.push((record, op));
        }
    }

    // Sort by timestamp ascending (oldest first — replay order)
    ledger_records.sort_by(|a, b| a.0.timestamp.total_cmp(&b.0.timestamp));

    Ok(ledger_records)
}

/// Extract governance records from storage, sorted by timestamp.
/// WARNING: Loads ALL records — O(all_records) memory.
#[cfg(test)]
pub fn extract_governance_records(
    storage: &dyn crate::storage::Storage,
) -> Result<Vec<ValidationRecord>> {
    let all_records = storage.query(
        Some(crate::record::Classification::Public),
        None, None, None, usize::MAX,
    )?;

    let mut gov_records: Vec<ValidationRecord> = all_records
        .into_iter()
        .filter(|r| r.metadata.contains_key(crate::accounting::governance::GOVERNANCE_OP_KEY))
        .collect();

    gov_records.sort_by(|a, b| {
        a.timestamp.total_cmp(&b.timestamp)
    });

    Ok(gov_records)
}

/// Extract and sort ledger records from a pre-loaded slice (single-pass startup).
///
/// Same logic as `extract_ledger_records` but operates on records already in memory.
pub fn extract_ledger_records_from_slice(
    all_records: &[ValidationRecord],
) -> Vec<(ValidationRecord, ParsedLedgerOp)> {
    let mut ledger_records = Vec::new();

    for record in all_records {
        // Ledger ops are always public
        if record.classification != crate::record::Classification::Public {
            continue;
        }
        if let Ok(Some(op)) = extract_ledger_op(record) {
            ledger_records.push((record.clone(), op));
        }
    }

    // Sort by timestamp ascending (oldest first — replay order)
    ledger_records.sort_by(|a, b| a.0.timestamp.total_cmp(&b.0.timestamp));

    ledger_records
}

/// Extract governance records from a pre-loaded slice (single-pass startup).
pub fn extract_governance_records_from_slice(
    all_records: &[ValidationRecord],
) -> Vec<ValidationRecord> {
    let mut gov_records: Vec<ValidationRecord> = all_records
        .iter()
        .filter(|r| {
            r.classification == crate::record::Classification::Public
                && r.metadata.contains_key(crate::accounting::governance::GOVERNANCE_OP_KEY)
        })
        .cloned()
        .collect();

    gov_records.sort_by(|a, b| {
        a.timestamp.total_cmp(&b.timestamp)
    });

    gov_records
}

/// Apply a governance operation to the ledger state.
pub(crate) fn apply_governance_op(
    state: &mut LedgerState,
    record: &ValidationRecord,
    op: &crate::accounting::governance::ParsedGovernanceOp,
    creator: &str,
) -> Result<()> {
    use crate::accounting::governance::{ParsedGovernanceOp, governance_stake_for, effective_voting_stake, total_governance_staked};

    // Idempotency head-guard (B1). Governance ops are NOT idempotent — a
    // re-applied vote/settle/delegate double-counts. apply_op (ledger) has this
    // guard at its head (insert at the tail); apply_governance_op historically
    // relied on the replay's on-disk `is_applied()` check for dedup, which B1
    // removed (it silently dropped post-checkpoint records). Mirror apply_op:
    // skip a record already folded into THIS ledger's in-memory set, and record
    // the id at the tail so a re-presented governance record in the same replay
    // pass is a clean no-op.
    if state.applied_record_ids.contains(&record.id) {
        return Ok(());
    }

    // Classified exchanges have zero governance weight — block all governance ops
    if state.exchange_classifier.is_classified(creator) {
        return Err(ElaraError::Governance(
            "classified exchanges cannot participate in governance".into()
        ));
    }

    match op {
        ParsedGovernanceOp::Propose { category, title, description } => {
            let gov_stake = governance_stake_for(&state.stakes, creator);
            // Committee is set to None here — committee selection happens
            // at the network layer before record insertion, and is stored
            // in the proposal via rebuild. Critical proposals that lack a
            // committee will be rejected by create_proposal().
            // For rebuild from existing records, committees are reconstructed
            // from committee_* metadata fields.
            let committee = crate::accounting::governance::extract_committee_from_metadata(
                &record.metadata,
            );
            state.governance.create_proposal(
                record.id.clone(),
                creator,
                category.clone(),
                title.clone(),
                description.clone(),
                gov_stake,
                record.timestamp,
                committee,
            )?;
        }
        ParsedGovernanceOp::Vote { proposal_id, direction } => {
            // Effective stake includes own governance stake + delegated governance stakes
            let proposal = state.governance.proposals.get(proposal_id.as_str())
                .ok_or_else(|| ElaraError::Governance(format!("proposal not found: {proposal_id}")))?;
            let eff_stake = effective_voting_stake(&state.stakes, &state.governance, creator, proposal);
            // Freeze the voter's OWN governance stake (vote-time) alongside the
            // effective weight, so settle-time reconcile preserves the
            // conviction stake-lock (see reconcile_effective_stakes).
            let own_stake = governance_stake_for(&state.stakes, creator);
            state.governance.cast_vote_with_own(
                proposal_id, creator, *direction, eff_stake, own_stake, record.timestamp,
            )?;
        }
        ParsedGovernanceOp::Execute { proposal_id } => {
            // Check if this is a Parameter proposal with param_name/param_value
            let is_param = state.governance.proposals.get(proposal_id.as_str())
                .is_some_and(|p| p.category == crate::accounting::governance::ProposalCategory::Parameter);
            // §11.18 Slice 2: check for ProtocolUpgrade category before executing
            // (after `execute_proposal` the status flips to Executed, so the
            // category check itself stays the same — we record the flag now and
            // act after the execute call succeeds).
            #[cfg(feature = "node-core")]
            let is_protocol_upgrade = state.governance.proposals.get(proposal_id.as_str())
                .is_some_and(|p| p.category == crate::accounting::governance::ProposalCategory::ProtocolUpgrade);

            state.governance.execute_proposal(proposal_id, record.timestamp)?;

            // If Parameter category, apply the param change from metadata
            if is_param {
                if let (Some(name), Some(value)) = (
                    record.metadata.get("governance_param_name").and_then(|v| v.as_str()),
                    record.metadata.get("governance_param_value").and_then(|v| v.as_str()),
                ) {
                    let _ = state.governance.apply_param_change(
                        proposal_id, name, value, record.timestamp,
                    );
                }
            }

            // §11.18 Slice 2 dispatch: if ProtocolUpgrade category, read the
            // upgrade kind + reference-impl hash + proposed-at-epoch from the
            // executing record's metadata and record the tally outcome on
            // `state.governance.upgrade_outcomes`. Missing or malformed
            // metadata silently skips outcome recording — the execute itself
            // already succeeded; operators inspect `upgrade_outcomes` to see
            // whether the upgrade resolved to Passed / Failed / Active. A
            // failed-to-record case is operationally distinct from a Failed
            // outcome (the proposal exists but no outcome row means the
            // executing record was malformed; an outcome=failed row means the
            // vote did not reach the threshold).
            #[cfg(feature = "node-core")]
            if is_protocol_upgrade {
                let kind_str = record
                    .metadata
                    .get("governance_upgrade_kind")
                    .and_then(|v| v.as_str());
                let hash = record
                    .metadata
                    .get("governance_reference_impl_hash")
                    .and_then(|v| v.as_str());
                let epoch_meta = record
                    .metadata
                    .get("governance_proposed_at_epoch")
                    .and_then(|v| v.as_u64());

                if let (Some(kind_s), Some(hash_s), Some(epoch_v)) =
                    (kind_str, hash, epoch_meta)
                {
                    if let Ok(kind) =
                        crate::network::protocol_upgrade::UpgradeKind::parse(kind_s)
                    {
                        // record.timestamp is f64 unix-seconds; cast to u64
                        // for the §11.18 tally clock. Negative or NaN
                        // timestamps reduce to 0 via the as-cast, which makes
                        // the tally treat the record as "earlier than any
                        // vote-window close" → VoteOpen (the safe default;
                        // the proposal can be re-executed later when the
                        // clock advances).
                        let now_secs = if record.timestamp.is_finite()
                            && record.timestamp >= 0.0
                        {
                            record.timestamp as u64
                        } else {
                            0
                        };
                        let _ = state.governance.apply_protocol_upgrade_outcome(
                            proposal_id,
                            kind,
                            hash_s.to_string(),
                            epoch_v,
                            now_secs,
                            record.timestamp,
                        );
                    }
                }
            }
        }
        ParsedGovernanceOp::Cancel { proposal_id } => {
            state.governance.cancel_proposal(proposal_id, creator)?;
        }
        ParsedGovernanceOp::Delegate { delegate } => {
            state.governance.delegate(creator, delegate, record.timestamp)?;
        }
        ParsedGovernanceOp::Undelegate => {
            state.governance.undelegate(creator)?;
        }
    }

    // Auto-settle any proposals past their voting deadline
    let total_gov = total_governance_staked(&state.stakes);
    let mut expired_proposals: Vec<String> = state.governance.proposals
        .iter()
        .filter(|(_, p)| {
            p.status == crate::accounting::governance::ProposalStatus::Active
                && record.timestamp >= p.voting_deadline
        })
        .map(|(id, _)| id.clone())
        .collect();
    // Canonical order: `proposals` is a HashMap, so iteration order is
    // nondeterministic. Settle is currently per-proposal independent, but
    // pinning a total order here removes a latent fork the moment any
    // cross-proposal coupling is introduced.
    expired_proposals.sort();

    for proposal_id in &expired_proposals {
        // Rebuild vote weights from the final delegation/stake state before
        // settle so a delegate's stale fold can never double-count a delegator
        // who voted directly or undelegated (see reconcile_effective_stakes).
        state.governance.reconcile_effective_stakes(&state.stakes, proposal_id);
        if let Err(e) = state.governance.settle_proposal(proposal_id, total_gov, record.timestamp) {
            tracing::debug!("governance settle skip for {}: {e}", &proposal_id[..proposal_id.len().min(16)]);
        }
    }

    state.records_processed += 1;
    // B1: record this governance id as folded into the in-memory set (mirrors
    // apply_op at the ledger tail) so the replay head-guard dedups a re-presented
    // record within the same pass.
    state.applied_record_ids.insert(record.id.clone());
    if record.timestamp > state.last_applied_ts {
        state.last_applied_ts = record.timestamp;
    }
    Ok(())
}


/// Convenience: derive full ledger state directly from storage.
/// WARNING: Loads ALL records — O(all_records) memory.
#[cfg(test)]
pub fn derive_from_storage(
    storage: &dyn crate::storage::Storage,
    genesis_authority: &str,
) -> Result<LedgerState> {
    let ledger_records = extract_ledger_records(storage)?;
    derive_ledger(&ledger_records, genesis_authority)
}

/// Get transaction history for an identity (most recent first).
/// WARNING: Loads ALL records — O(all_records) memory.
#[cfg(test)]
pub fn get_history(
    storage: &dyn crate::storage::Storage,
    identity_hash: &str,
) -> Result<Vec<(ValidationRecord, ParsedLedgerOp)>> {
    let mut ledger_records = extract_ledger_records(storage)?;

    // Filter: records where this identity is sender OR recipient
    ledger_records.retain(|(record, op)| {
        let creator = creator_identity_hash(record);
        if creator == identity_hash {
            return true;
        }
        match op {
            ParsedLedgerOp::Mint { to, .. } | ParsedLedgerOp::Transfer { to, .. } => {
                to == identity_hash
            }
            ParsedLedgerOp::WitnessReward { from, to, .. } => {
                from == identity_hash || to == identity_hash
            }
            ParsedLedgerOp::Slash { offender, challenger, jury, .. } => {
                offender == identity_hash || challenger == identity_hash || jury.iter().any(|j| j == identity_hash)
            }
            ParsedLedgerOp::DormancyReclaim { dormant_identity, .. } => {
                dormant_identity == identity_hash
            }
            ParsedLedgerOp::IdleDecay { batch } => {
                batch.debits.iter().any(|(id, _)| id == identity_hash)
                    || batch.staker_credits.iter().any(|(id, _)| id == identity_hash)
            }
            ParsedLedgerOp::XZoneTimeoutRefund { batch }
            | ParsedLedgerOp::XZoneStaleReap { batch } => {
                batch.refunds.iter().any(|(_tid, sender, _amt)| sender == identity_hash)
            }
            _ => false,
        }
    });

    // Most recent first
    ledger_records.reverse();
    Ok(ledger_records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::sha3_256;
    use crate::accounting::types;
    use std::collections::BTreeMap;

    fn make_record_with_pk(
        id: &str,
        pk: &[u8],
        ts: f64,
        meta: BTreeMap<String, serde_json::Value>,
    ) -> ValidationRecord {
        ValidationRecord {
            id: id.into(),
            version: crate::wire::WIRE_VERSION,
            content_hash: sha3_256(id.as_bytes()).to_vec(),
            creator_public_key: pk.to_vec(),
            timestamp: ts,
            parents: vec![],
            classification: crate::record::Classification::Public,
            metadata: meta,
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

    fn genesis_pk() -> Vec<u8> {
        vec![0x01; 1952]
    }

    fn alice_pk() -> Vec<u8> {
        vec![0x02; 1952]
    }

    fn bob_pk() -> Vec<u8> {
        vec![0x03; 1952]
    }

    fn identity_hash(pk: &[u8]) -> String {
        crate::crypto::hash::sha3_256_hex(pk)
    }

    /// CONSTRUCTION-LEVEL DETERMINISM GUARD (the internal roadmap C10b;
    /// internal design notes).
    ///
    /// The snapshot-bootstrap path (`network/sync.rs::apply_bootstrap_snapshot_full`)
    /// does NOT replay DAG history — it deserializes `LedgerState` directly. So every
    /// `#[serde(skip)]` field lands as `Default` on a bootstrapped node. If such a
    /// field is READ on the consensus apply path (`apply_op`) to gate accept/reject or
    /// to mutate a balance / stake / the account-SMT root, the bootstrapped node
    /// diverges from a since-genesis node → permanent fork. This class has bitten the
    /// project THREE times (`vesting` / `cross_zone` / `exchange_classifier`, each
    /// `#[serde(skip)]` → `#[serde(default)]`).
    ///
    /// The destructure below has NO `..` rest pattern, so ADDING A FIELD to
    /// `LedgerState` breaks compilation HERE and forces the author to classify it:
    ///   PERSISTED — serde-serialized (plain or `#[serde(default)]`); round-trips.
    ///   SKIP (i)  — rebuilt deterministically on EVERY restore path before any reader.
    ///   SKIP (ii) — write-only / never read on `apply_op` as accept-reject or balance input.
    /// A SKIP field that is neither (i) nor (ii) is an unproven fork — fix it, don't list it.
    ///
    /// Verdict basis: fusion AUDIT-FIRST 2026-06-21 (3 Sonnet + 1 Opus panel → Opus
    /// synthesis → 1 Opus final-verify) re-checked all 9 skip fields against source and
    /// found none in the fork class. Mirrors `hash_account_state_is_sensitive_to_every_field`
    /// (network/account_merkle.rs) — a compile-style pin on a consensus seam.
    #[test]
    fn ledger_state_serde_skip_fields_have_documented_bootstrap_rebuild_path() {
        let LedgerState {
            // ── PERSISTED (round-trips on the wire) ──────────────────────────
            accounts: _,
            stakes: _,
            total_supply: _,
            total_staked: _,
            conservation_pool: _,
            pool_disbursed_window: _,
            records_processed: _,
            vesting: _,             // was skip→default: gates transferable_balance in apply_op
            governance: _,
            identity_profiles: _,
            attestation_levels: _,
            applied_record_ids: _,
            predictions: _,
            pending_xzone_locked: _,
            cross_zone: _,          // was skip→default: apply gate for XZoneClaim/Cancel/Abort/Reject
            exchange_classifier: _, // was skip→default: gates is_classified() on the apply path
            dormancy: _,
            last_applied_ts: _,
            // ── SKIP — each MUST be (i) rebuilt-on-bootstrap or (ii) write-only ──
            velocity: _,            // (ii) write-only in apply_op; read only in validate_op behind enforce_rate_limits (off the commit path) — CONSENSUS-FORBIDDEN block in apply_op
            circuit_breaker: _,     // (ii) ditto; level never read in apply_op
            acquisition: _,         // (ii) ditto
            staker_index: _,        // (i)  rebuild_staker_index() @ network/sync.rs (from serialized `stakes`)
            active_stakes_count: _, // (i)  reconciled by rebuild_staker_index(); display-only otherwise
            idle_decay: _,           // (ii) apply_idle_decay_batch is tracker-independent; compute_idle_decay_batch is genesis-authority-only (network/epoch.rs)
            stake_mutation_seq: _,  // (ii) cache key; cache dropped via invalidate_anchor_view() @ network/sync.rs
            smt_dirty: _,           // (ii) write-only flush buffer; on-disk account SMT is authoritative
            pending_witness_registrations: _, // (ii) write-only queue; drained to CF_WITNESS_REGISTRY
        } = LedgerState::new();

        // Behavioural half: prove the annotations match real serde behaviour, so a
        // future edit that flips `#[serde(skip)]`↔persisted is caught even though the
        // destructure above still compiles. Populate one representative SKIP field and
        // one representative PERSISTED field, round-trip through the snapshot format,
        // and assert SKIP drops to Default while PERSISTED survives.
        let mut node = LedgerState::new();
        let who = identity_hash(&alice_pk());
        node.velocity.record_outflow(&who, 123, 1000.0); // SKIP field — must drop
        node.total_supply = 777; // PERSISTED field — must survive
        let wire = serde_json::to_string(&node).expect("serialize snapshot");
        let restored: LedgerState = serde_json::from_str(&wire).expect("deserialize snapshot");
        assert_eq!(
            restored.velocity.outflow_in_window(&who, 1000.0),
            0,
            "velocity is #[serde(skip)] — it MUST land empty after a snapshot round-trip"
        );
        assert_eq!(
            restored.total_supply, 777,
            "total_supply is persisted — it MUST survive a snapshot round-trip"
        );
    }

    /// Regression pin for the audit's key safety property: `apply_idle_decay_batch`
    /// MUST be independent of the `#[serde(skip)]` `idle_decay` flow tracker — every
    /// committed mutation (account debits, conservation-pool credit, staker credits)
    /// comes from the SIGNED batch payload + persisted `accounts`, never from
    /// `self.idle_decay`. That is exactly what makes `idle_decay` safe to skip: a
    /// snapshot-bootstrapped node (empty tracker) applies an authority-signed batch
    /// byte-identically to a since-genesis node. If a future edit makes the apply path
    /// read the tracker for a committed value, this test forks and fails.
    /// (Producer-side `compute_idle_decay_batch` is genesis-authority-only — see the
    /// authority-restore caveat in internal design notes.)
    #[test]
    fn apply_idle_decay_batch_is_independent_of_skipped_tracker() {
        use crate::accounting::idle_decay::IdleDecayBatch;
        let exch = identity_hash(&alice_pk());
        let staker = identity_hash(&bob_pk());

        // A since-genesis node with a populated idle_decay tracker, and the same node
        // after a snapshot round-trip (drops the #[serde(skip)] tracker → empty).
        let mut genesis = LedgerState::new();
        genesis.accounts.entry(exch.clone()).or_default().available = 10_000;
        genesis.idle_decay.record_inflow(&exch, 5_000, 1000.0);
        genesis.idle_decay.record_balance(&exch, 10_000, 1000.0);
        let mut bootstrapped: LedgerState =
            serde_json::from_str(&serde_json::to_string(&genesis).unwrap()).unwrap();

        // Precondition: the trackers genuinely diverge (else the test is vacuous).
        assert!(genesis.idle_decay.tracker_count(&exch) > 0);
        assert_eq!(bootstrapped.idle_decay.tracker_count(&exch), 0);

        // The same authority-signed batch (debit exch 1000 → pool 600 + staker 400).
        let batch = IdleDecayBatch {
            epoch: 1,
            zone: "0".to_string(),
            debits: vec![(exch.clone(), 1000)],
            pool_credit: 600,
            staker_credits: vec![(staker.clone(), 400)],
        };
        assert!(batch.is_conserved());

        genesis
            .apply_idle_decay_batch(&batch, 2000.0)
            .expect("apply on genesis");
        bootstrapped
            .apply_idle_decay_batch(&batch, 2000.0)
            .expect("apply on bootstrapped");

        // Committed state must be identical despite the divergent skipped trackers.
        assert_eq!(
            genesis.accounts.get(&exch).map(|a| a.available),
            bootstrapped.accounts.get(&exch).map(|a| a.available),
            "idle_decay debit diverged across bootstrap — apply path read the skipped tracker"
        );
        assert_eq!(
            genesis.accounts.get(&staker).map(|a| a.available),
            bootstrapped.accounts.get(&staker).map(|a| a.available),
            "staker credit diverged across bootstrap"
        );
        assert_eq!(
            genesis.conservation_pool, bootstrapped.conservation_pool,
            "conservation pool diverged across bootstrap"
        );
    }

    /// Bootstrap-equivalence regression gate for the `#[serde(skip)]`
    /// consensus-tracker fork (see internal design notes).
    ///
    /// A large mint to a non-genesis identity installs a 365-day vesting lock in
    /// the `VestingManager`. That manager is `#[serde(skip)]`, so a node that
    /// snapshot-bootstraps (serialize → deserialize, no genesis replay) loses the
    /// lock and computes `transferable_balance` from empty vesting — wrongly
    /// admitting a transfer a since-genesis node rejects. The two nodes then hold
    /// different balances for the same sealed record set → different account-SMT
    /// root → permanent fork with no self-heal. This test reproduces that
    /// divergence; the Track-C fix (persist + bound the vesting state) turns it
    /// green.
    #[test]
    fn bootstrap_equivalence_large_mint_vesting_fork() {
        let genesis = identity_hash(&genesis_pk());
        let alice = identity_hash(&alice_pk());
        let bob = identity_hash(&bob_pk());

        let mk = |id: &str, pk: &[u8], ts: f64, meta: BTreeMap<String, serde_json::Value>| {
            let r = make_record_with_pk(id, pk, ts, meta);
            let op = extract_ledger_op(&r).unwrap().unwrap();
            (r, op)
        };

        // r1 establishes supply; r2 is a large mint to alice (1M beat > 0.1% of the
        // 10M supply → 365-day vesting); r3 is alice spending inside the lock window.
        let r1 = mk("mint-base", &genesis_pk(), 1.0,
            types::mint_metadata(10_000_000 * BASE_UNITS_PER_BEAT, &genesis, "genesis"));
        let r2 = mk("mint-alice", &genesis_pk(), 2.0,
            types::mint_metadata(1_000_000 * BASE_UNITS_PER_BEAT, &alice, "grant"));
        let r3 = mk("xfer-alice", &alice_pk(), 3.0,
            types::transfer_metadata(10_000 * BASE_UNITS_PER_BEAT, &bob, None));

        // Path A — since genesis: the vesting lock is live, so r3 is rejected
        // (tolerated → skipped, alice keeps her full balance).
        let (ledger_a, _) =
            derive_ledger_tolerant(&[r1.clone(), r2.clone(), r3.clone()], &genesis);

        // Path B — snapshot-bootstrap: build to the mid-point, round-trip through the
        // snapshot serde format (drops the `#[serde(skip)]` VestingManager to
        // Default), then apply r3 on the "bootstrapped" ledger.
        let (pre, _) = derive_ledger_tolerant(&[r1.clone(), r2.clone()], &genesis);
        let wire = serde_json::to_string(&pre).expect("serialize ledger snapshot");
        let mut booted: LedgerState =
            serde_json::from_str(&wire).expect("deserialize ledger snapshot");
        let _ = apply_op(&mut booted, &r3.0, &r3.1, &genesis); // rejected (correct) or applied (fork)

        // Equivalence: a snapshot-bootstrapped node MUST reach the same balances as
        // a since-genesis node over the identical sealed record set.
        assert_eq!(
            ledger_a.balance(&alice), booted.balance(&alice),
            "alice balance diverged across bootstrap: since-genesis={} bootstrapped={} \
             — the large-mint vesting lock did not survive the snapshot",
            ledger_a.balance(&alice), booted.balance(&alice)
        );
        assert_eq!(
            ledger_a.balance(&bob), booted.balance(&bob),
            "bob balance diverged across bootstrap"
        );

        // The sealed value is the account-SMT root; assert it directly where the
        // node-core merkle code is compiled in (the lib test gate runs --features node).
        #[cfg(feature = "node-core")]
        {
            let root_a = crate::network::account_merkle::root_over_accounts(&ledger_a.accounts)
                .expect("root A");
            let root_b = crate::network::account_merkle::root_over_accounts(&booted.accounts)
                .expect("root B");
            assert_eq!(root_a, root_b, "sealed account-SMT root diverged across bootstrap");
        }
    }

    /// Bootstrap-equivalence regression gate — **Track D** (rate-limit demotion),
    /// velocity leg. Companion to `bootstrap_equivalence_large_mint_vesting_fork`.
    ///
    /// The velocity / circuit-breaker / acquisition trackers are `#[serde(skip)]` and
    /// per-node-observed. Before Track D, `apply_op` read them as a transfer
    /// *accept/reject* gate, so a snapshot-bootstrapped node (empty trackers) would
    /// APPLY a transfer a since-genesis node (saturated 24h window) REJECTED →
    /// divergent balances → divergent account-SMT root → permanent fork. The fix
    /// demotes the three rejects to node-local mempool admission (`validate_op`);
    /// `apply_op` no longer reads the trackers, so the two nodes converge. Pre-fix this
    /// test fails at the `r_genesis.is_ok()` assert (the saturated node rejected).
    #[test]
    fn bootstrap_equivalence_velocity_rate_limit_fork() {
        let genesis = identity_hash(&genesis_pk());
        let alice = identity_hash(&alice_pk());
        let bob = identity_hash(&bob_pk());

        // Alice holds 200K beat → velocity Tier LOW (100K-1M): 50%/day = 100K/day cap.
        let bal = 200_000 * BASE_UNITS_PER_BEAT;
        let amount = 50_000 * BASE_UNITS_PER_BEAT;
        let ts = 1001.0;

        // Path A — since-genesis: alice's 24h velocity window is already saturated to
        // the daily cap, so the pre-fix apply_op velocity gate would reject the transfer.
        let mut node_genesis = LedgerState::new();
        node_genesis.total_supply = 1_000_000 * BASE_UNITS_PER_BEAT;
        node_genesis
            .accounts
            .insert(alice.clone(), AccountState { available: bal, ..Default::default() });
        node_genesis.velocity.record_balance(&alice, bal, 1000.0);
        node_genesis
            .velocity
            .record_outflow(&alice, 100_000 * BASE_UNITS_PER_BEAT, 1000.0);

        // Path B — snapshot-bootstrap: round-trip through the serde snapshot format,
        // which drops the `#[serde(skip)]` velocity tracker to Default (empty).
        let wire = serde_json::to_string(&node_genesis).expect("serialize snapshot");
        let mut node_bootstrapped: LedgerState =
            serde_json::from_str(&wire).expect("deserialize snapshot");

        // Preconditions: the divergence is real (else the test would be vacuous).
        assert!(
            node_genesis.velocity.outflow_in_window(&alice, ts) > 0,
            "fixture: since-genesis node must have a saturated velocity window"
        );
        assert_eq!(
            node_bootstrapped.velocity.outflow_in_window(&alice, ts),
            0,
            "precondition: snapshot must drop the #[serde(skip)] velocity tracker"
        );

        let meta = types::transfer_metadata(amount, &bob, None);
        let rec = make_record_with_pk("xfer-velocity", &alice_pk(), ts, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();

        let r_genesis = apply_op(&mut node_genesis, &rec, &op, &genesis);
        let r_bootstrapped = apply_op(&mut node_bootstrapped, &rec, &op, &genesis);

        assert!(
            r_genesis.is_ok(),
            "Track D: apply_op must not reject on a saturated velocity tracker (got {:?})",
            r_genesis
        );
        assert!(r_bootstrapped.is_ok(), "apply_op rejected on empty tracker: {:?}", r_bootstrapped);
        assert_eq!(
            node_genesis.balance(&alice),
            node_bootstrapped.balance(&alice),
            "alice balance forked across bootstrap — velocity gate still consensus-read the \
             dropped tracker (since-genesis={}, bootstrapped={})",
            node_genesis.balance(&alice),
            node_bootstrapped.balance(&alice)
        );
        assert_eq!(
            node_genesis.balance(&bob),
            node_bootstrapped.balance(&bob),
            "bob balance forked across bootstrap"
        );

        #[cfg(feature = "node-core")]
        {
            let root_a = crate::network::account_merkle::root_over_accounts(&node_genesis.accounts)
                .expect("root A");
            let root_b =
                crate::network::account_merkle::root_over_accounts(&node_bootstrapped.accounts)
                    .expect("root B");
            assert_eq!(root_a, root_b, "sealed account-SMT root forked across bootstrap");
        }
    }

    /// Bootstrap-equivalence regression gate — **Track D**, acquisition leg (the
    /// recipient-side rate limit). Same fork class as the velocity leg: a
    /// snapshot-bootstrapped node loses the `#[serde(skip)]` acquisition tracker and
    /// would accept an inbound transfer a since-genesis node rejected. Demoted to
    /// `validate_op`; `apply_op` must apply identically on both nodes.
    #[test]
    fn bootstrap_equivalence_acquisition_rate_limit_fork() {
        let genesis = identity_hash(&genesis_pk());
        let alice = identity_hash(&alice_pk());
        let bob = identity_hash(&bob_pk());

        // circulating = 100M beat (> 1M activation floor) → acquisition limit = 0.5% = 500K.
        // Alice holds 80K (< 100K → velocity Tier FREE, so velocity never confounds).
        let ts = 1001.0;
        let amount = 50_000 * BASE_UNITS_PER_BEAT;

        let mut node_genesis = LedgerState::new();
        node_genesis.total_supply = 100_000_000 * BASE_UNITS_PER_BEAT;
        node_genesis
            .accounts
            .insert(alice.clone(), AccountState { available: 80_000 * BASE_UNITS_PER_BEAT, ..Default::default() });
        // Saturate bob's 30-day acquisition window to the limit.
        node_genesis
            .acquisition
            .record_inflow(&bob, 500_000 * BASE_UNITS_PER_BEAT, 1000.0);

        let wire = serde_json::to_string(&node_genesis).expect("serialize snapshot");
        let mut node_bootstrapped: LedgerState =
            serde_json::from_str(&wire).expect("deserialize snapshot");

        assert!(
            node_genesis.acquisition.inflow_in_window(&bob, ts) > 0,
            "fixture: since-genesis node must have a saturated acquisition window"
        );
        assert_eq!(
            node_bootstrapped.acquisition.inflow_in_window(&bob, ts),
            0,
            "precondition: snapshot must drop the #[serde(skip)] acquisition tracker"
        );

        let meta = types::transfer_metadata(amount, &bob, None);
        let rec = make_record_with_pk("xfer-acquisition", &alice_pk(), ts, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();

        let r_genesis = apply_op(&mut node_genesis, &rec, &op, &genesis);
        let r_bootstrapped = apply_op(&mut node_bootstrapped, &rec, &op, &genesis);

        assert!(
            r_genesis.is_ok(),
            "Track D: apply_op must not reject on a saturated acquisition tracker (got {:?})",
            r_genesis
        );
        assert!(r_bootstrapped.is_ok());
        assert_eq!(
            node_genesis.balance(&bob),
            node_bootstrapped.balance(&bob),
            "bob balance forked across bootstrap on the acquisition gate"
        );
        assert_eq!(node_genesis.balance(&alice), node_bootstrapped.balance(&alice));
    }

    /// Bootstrap-equivalence regression gate — **Track C**, classifier
    /// prediction-reward leg (the audit's "single biggest risk").
    ///
    /// A classified exchange earns NO prediction reward
    /// (`stake_reward_multiplier = 0`). Pre-Track-C the classifier was
    /// `#[serde(skip)]`, so a snapshot-bootstrapped node lost the classification →
    /// PAID a reward (multiplier 1) a since-genesis node withheld → divergent
    /// `conservation_pool` and predictor balance on the fleet-wide
    /// `evaluate_predictions` seal path → permanent fork with nothing logged (the
    /// bootstrap SMT-root verify matches AT bootstrap; divergence is born one seal
    /// later). Track C persists `confirmed_exchanges` (monotone), so both nodes
    /// withhold identically. Pre-fix this fails at the `is_classified`
    /// precondition AND the `conservation_pool` assert.
    #[test]
    fn bootstrap_equivalence_classifier_prediction_reward_fork() {
        let predictor = identity_hash(&alice_pk());
        let zone = "z1";
        let epoch = 42u64;
        let stake = 100_000 * BASE_UNITS_PER_BEAT;

        // Path A — since genesis: predictor is a confirmed exchange (consensus
        // classifier state) with a pending CORRECT prediction it staked.
        let mut node_genesis = LedgerState::new();
        node_genesis.conservation_pool = 1_000_000 * BASE_UNITS_PER_BEAT;
        node_genesis
            .exchange_classifier
            .confirmed_exchanges
            .insert(predictor.clone());
        node_genesis.predictions.insert(
            "pred-1".into(),
            PredictionEntry {
                record_id: "pred-1".into(),
                predictor: predictor.clone(),
                amount: stake,
                zone: zone.into(),
                target_epoch: epoch,
                claim: PredictionClaim::Active,
                predicted_value: 1, // "will be active" — correct since record_count > 0
                timestamp: 1.0,
                outcome: None,
            },
        );

        // Path B — snapshot-bootstrap: round-trip through the serde snapshot format.
        // Pre-Track-C this dropped exchange_classifier to empty.
        let wire = serde_json::to_string(&node_genesis).expect("serialize snapshot");
        let mut node_bootstrapped: LedgerState =
            serde_json::from_str(&wire).expect("deserialize snapshot");

        // The fix in one assert: the classification survives the snapshot.
        assert!(node_genesis.exchange_classifier.is_classified(&predictor));
        assert!(
            node_bootstrapped.exchange_classifier.is_classified(&predictor),
            "Track C: confirmed_exchanges must survive the snapshot bootstrap"
        );

        // Settle the prediction (CORRECT: actual_record_count=10 > 0) on both nodes.
        let (correct_a, _, reward_a, _) = node_genesis.evaluate_predictions(zone, epoch, 10, 3);
        let (correct_b, _, reward_b, _) =
            node_bootstrapped.evaluate_predictions(zone, epoch, 10, 3);

        assert_eq!(correct_a, 1);
        assert_eq!(correct_b, 1);
        // Classified predictor → stake_reward_multiplier = 0 → zero reward on BOTH.
        assert_eq!(reward_a, 0, "classified predictor must earn no reward");
        assert_eq!(
            reward_b, 0,
            "bootstrapped node paid a reward the genesis node withheld → conservation_pool fork"
        );
        assert_eq!(
            node_genesis.conservation_pool, node_bootstrapped.conservation_pool,
            "conservation_pool forked across bootstrap on the prediction-reward path"
        );
        assert_eq!(
            node_genesis.balance(&predictor),
            node_bootstrapped.balance(&predictor),
            "predictor balance forked across bootstrap"
        );
    }

    /// Determinism regression — the `evaluate_predictions` HASHMAP-ORDER fork
    /// (replay-determinism audit, 2026-06-18). Pre-fix the reward/confiscation loop
    /// iterated `self.predictions` (a HashMap) directly; when the conservation
    /// pool can fund only SOME of the correct predictions, the `.min(pool)` cap
    /// means *which* predictor gets the full reward vs. the capped remainder
    /// depends on per-node HashMap iteration order → divergent `conservation_pool`
    /// and predictor balances → account-SMT fork one seal later. This builds the
    /// bounded-pool scenario in 32 fresh ledgers (each HashMap re-seeds, so
    /// iteration order varies run to run) and asserts byte-identical output.
    /// Pre-fix it fails on the runs whose order differs; post-fix (sorted by the
    /// unique `record_id`) it is invariant.
    #[test]
    fn evaluate_predictions_pool_bounded_order_is_deterministic() {
        let zone = "z1";
        let epoch = 7u64;
        let stake = 100_000 * BASE_UNITS_PER_BEAT;
        let reward = stake / 10; // PREDICTION_REWARD_RATE = 1/10
        let pool = reward + reward / 2; // funds exactly 1.5 rewards

        let mk = |rid: &str, predictor: &str| PredictionEntry {
            record_id: rid.into(),
            predictor: predictor.into(),
            amount: stake,
            zone: zone.into(),
            target_epoch: epoch,
            claim: PredictionClaim::Active,
            predicted_value: 1, // "active" — correct when actual_record_count > 0
            timestamp: 1.0,
            outcome: None,
        };

        let mut prev: Option<(u64, u64, u64, u64)> = None;
        for run in 0..32 {
            let mut ledger = LedgerState::new();
            ledger.conservation_pool = pool;
            // pred_a's record_id "aaa" sorts before pred_b's "bbb".
            ledger.predictions.insert("aaa".into(), mk("aaa", "pred_a"));
            ledger.predictions.insert("bbb".into(), mk("bbb", "pred_b"));

            let (correct, _, total_rewarded, _) =
                ledger.evaluate_predictions(zone, epoch, 10, 3);
            assert_eq!(correct, 2, "both predictions are correct");

            let snap = (
                ledger.conservation_pool,
                total_rewarded,
                ledger.account("pred_a").available,
                ledger.account("pred_b").available,
            );
            if let Some(p) = prev {
                assert_eq!(
                    snap, p,
                    "run {run}: evaluate_predictions output diverged across HashMap re-seeds — \
                     pool-bounded reward order is non-deterministic (consensus fork)"
                );
            }
            prev = Some(snap);
        }

        // Pin the sorted-order semantics: "aaa" (pred_a) processed first gets the
        // full reward; "bbb" (pred_b) second gets the capped remainder; pool drains.
        let mut ledger = LedgerState::new();
        ledger.conservation_pool = pool;
        ledger.predictions.insert("aaa".into(), mk("aaa", "pred_a"));
        ledger.predictions.insert("bbb".into(), mk("bbb", "pred_b"));
        let (_, _, total_rewarded, _) = ledger.evaluate_predictions(zone, epoch, 10, 3);
        assert_eq!(ledger.conservation_pool, 0, "pool fully drained");
        assert_eq!(total_rewarded, pool);
        assert_eq!(
            ledger.account("pred_a").available,
            stake + reward,
            "pred_a (record_id 'aaa', sorted first) gets stake + full reward"
        );
        assert_eq!(
            ledger.account("pred_b").available,
            stake + (pool - reward),
            "pred_b (sorted second) gets stake + capped remainder"
        );
    }

    #[test]
    fn test_mint_and_balance() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let rec = make_record_with_pk("mint-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();

        let records = vec![(rec, op)];
        let ledger = derive_ledger(&records, &genesis_hash).unwrap();

        assert_eq!(ledger.balance(&alice_hash), 1_000 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.total_supply, 1_000 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.records_processed, 1);
    }

    #[test]
    fn test_mint_unauthorized() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        // Alice tries to mint (not genesis authority)
        let meta = types::mint_metadata(1_000, &alice_hash, "hack");
        let rec = make_record_with_pk("bad-mint", &alice_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();

        let result = derive_ledger(&[(rec, op)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        // Mint 1000 to Alice
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Alice transfers 300 to Bob
        let m2 = types::transfer_metadata(300 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let r2 = make_record_with_pk("xfer-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let ledger = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash).unwrap();

        assert_eq!(ledger.balance(&alice_hash), 700 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.balance(&bob_hash), 300 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.total_supply, 1_000 * BASE_UNITS_PER_BEAT);
    }

    /// The lifetime accumulators total_received / total_sent / tx_count are unbounded
    /// monotonic counters folded into hash_account_state() (the consensus account-state
    /// SMT leaf). At mainnet scale a hub account's total_received crosses u64::MAX in
    /// days (10T records/day), so a silent wrap would diverge that leaf across nodes —
    /// a fork. The apply path must SATURATE (cap at u64::MAX identically on every node),
    /// not wrap. This pins that wiring; a revert to raw `+=` fails this test (it wraps,
    /// or panics under the dev profile's overflow-checks).
    #[test]
    fn lifetime_accumulators_saturate_instead_of_wrapping() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        // Mint to Alice so she can transfer.
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();
        let mut ledger = derive_ledger(&[(r1, o1)], &genesis_hash).unwrap();

        // Drive Bob's lifetime accumulators to the very edge of u64.
        {
            let bob = ledger.accounts.entry(bob_hash.clone()).or_default();
            bob.total_received = u64::MAX - 5;
            bob.tx_count = u64::MAX;
        }

        // Alice sends 100 to Bob — the credit would overflow total_received and tx_count.
        let m2 = types::transfer_metadata(100 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let r2 = make_record_with_pk("xfer-1", &alice_pk(), 2.0, m2);
        ledger.apply_single_record(&r2, &genesis_hash).unwrap();

        let bob = ledger.accounts.get(&bob_hash).unwrap();
        assert_eq!(bob.total_received, u64::MAX, "total_received must saturate, not wrap");
        assert_eq!(bob.tx_count, u64::MAX, "tx_count must saturate, not wrap");
        // The conserved, transferable balance is a separate field and is exact.
        assert_eq!(bob.available, 100 * BASE_UNITS_PER_BEAT);
    }

    #[test]
    fn test_transfer_insufficient_balance() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        // Mint 100 to Alice
        let m1 = types::mint_metadata(100 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Alice tries to send 200 to Bob (overdraft)
        let m2 = types::transfer_metadata(200 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let r2 = make_record_with_pk("xfer-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_stake_and_unstake() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        // Mint 1000 to Alice
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Alice stakes 200
        let m2 = types::stake_metadata(200 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r2 = make_record_with_pk("stake-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Alice unstakes after cooldown
        let m3 = types::unstake_metadata("stake-1");
        let r3 = make_record_with_pk("unstake-1", &alice_pk(), 2.0 + UNSTAKE_COOLDOWN + 1.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        let ledger = derive_ledger(&[(r1, o1), (r2, o2), (r3, o3)], &genesis_hash).unwrap();

        // All back to available after unstake
        assert_eq!(ledger.balance(&alice_hash), 1_000 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.staked(&alice_hash), 0);
        assert_eq!(ledger.total_staked, 0);
    }

    /// Audit 2026-06-15 item (f): pins the staked-anchor cache-coherence
    /// counter. Every stake mutation applied through the real `apply_op` path
    /// MUST bump `stake_mutation_seq` (the monotonic token that keys the
    /// `NodeState` staked-anchor view), while a non-stake op (mint) MUST NOT.
    /// A monotonic counter — not just the `total_staked` fingerprint — is
    /// required: a net-zero reshuffle (one account unstakes X as another
    /// stakes X) leaves `total_staked` unchanged but moves the membership set.
    #[test]
    fn stake_mutation_seq_bumps_on_real_apply_op_path() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let mut ledger = LedgerState::new();
        assert_eq!(ledger.stake_mutation_seq, 0);

        // Mint to alice — NOT a stake mutation, must NOT bump.
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();
        apply_op(&mut ledger, &r1, &o1, &genesis_hash).unwrap();
        assert_eq!(ledger.stake_mutation_seq, 0, "mint must not bump the stake seq");

        // Stake — must bump.
        let m2 = types::stake_metadata(200 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r2 = make_record_with_pk("stake-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();
        apply_op(&mut ledger, &r2, &o2, &alice_hash).unwrap();
        assert_eq!(ledger.stake_mutation_seq, 1, "stake must bump the seq");

        // Unstake after cooldown — must bump again (monotonic).
        let m3 = types::unstake_metadata("stake-1");
        let r3 = make_record_with_pk("unstake-1", &alice_pk(), 2.0 + UNSTAKE_COOLDOWN + 1.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();
        apply_op(&mut ledger, &r3, &o3, &alice_hash).unwrap();
        assert_eq!(ledger.stake_mutation_seq, 2, "unstake must bump the seq");
    }

    /// B10: `active_stakes_count` is an O(1) maintained mirror of
    /// `stakes.values().filter(active).count()` — the value `summarize()` (hit on
    /// `/network`) now reads instead of scanning all stakes under the read lock.
    /// It must track the real `apply_op` stake/unstake path, survive a clone, and
    /// be reconciled from the authoritative `stakes` map by `rebuild_staker_index`.
    #[test]
    fn active_stakes_count_tracks_apply_op_and_reconciles_on_rebuild() {
        fn scan(l: &LedgerState) -> u64 {
            l.stakes.values().filter(|s| s.active).count() as u64
        }
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let mut ledger = LedgerState::new();
        assert_eq!(ledger.active_stakes_count, 0);
        assert_eq!(ledger.active_stakes_count, scan(&ledger));

        // Mint — not a stake op, count unchanged.
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();
        apply_op(&mut ledger, &r1, &o1, &genesis_hash).unwrap();
        assert_eq!(ledger.active_stakes_count, 0, "mint must not change the active-stake count");

        // Stake — increment (site 2).
        let m2 = types::stake_metadata(200 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r2 = make_record_with_pk("stake-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();
        apply_op(&mut ledger, &r2, &o2, &alice_hash).unwrap();
        assert_eq!(ledger.active_stakes_count, 1, "stake must increment");
        assert_eq!(ledger.active_stakes_count, scan(&ledger));
        // Manual Clone impl must carry the counter.
        assert_eq!(ledger.clone().active_stakes_count, 1);

        // Unstake after cooldown — decrement (site 3).
        let m3 = types::unstake_metadata("stake-1");
        let r3 = make_record_with_pk("unstake-1", &alice_pk(), 2.0 + UNSTAKE_COOLDOWN + 1.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();
        apply_op(&mut ledger, &r3, &o3, &alice_hash).unwrap();
        assert_eq!(ledger.active_stakes_count, 0, "unstake must decrement");
        assert_eq!(ledger.active_stakes_count, scan(&ledger));

        // Re-stake so the reconcile has a non-trivial ground truth.
        let m4 = types::stake_metadata(150 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r4 = make_record_with_pk("stake-2", &alice_pk(), 10.0 + 2.0 * UNSTAKE_COOLDOWN, m4);
        let o4 = extract_ledger_op(&r4).unwrap().unwrap();
        apply_op(&mut ledger, &r4, &o4, &alice_hash).unwrap();
        assert_eq!(ledger.active_stakes_count, 1);

        // Backstop: simulate drift from an unforeseen path, then rebuild must
        // re-derive the count from `stakes`.
        ledger.active_stakes_count = 999;
        ledger.rebuild_staker_index();
        assert_eq!(ledger.active_stakes_count, scan(&ledger), "rebuild must reconcile the counter");
        assert_eq!(ledger.active_stakes_count, 1);
    }

    /// Invariant guard. The runtime hot paths (consensus
    /// register_stakes, ingest global_seal stakers_by_zone, auto_witness
    /// committee build) read `total_staked` and iterate `staker_index.keys()`
    /// instead of scanning all accounts. Both must stay in lock-step with
    /// the per-account `staked` field across stake / unstake / slash.
    #[test]
    fn test_staker_index_matches_filtered_accounts() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        // Mint to two stakers
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-a", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();
        let m2 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &bob_hash, "genesis");
        let r2 = make_record_with_pk("mint-b", &genesis_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Both stake. After this both should appear in staker_index.
        let m3 = types::stake_metadata(200 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r3 = make_record_with_pk("stake-a", &alice_pk(), 3.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();
        let m4 = types::stake_metadata(300 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r4 = make_record_with_pk("stake-b", &bob_pk(), 4.0, m4);
        let o4 = extract_ledger_op(&r4).unwrap().unwrap();

        let ledger = derive_ledger(
            &[(r1, o1), (r2, o2), (r3, o3), (r4, o4)],
            &genesis_hash,
        )
        .unwrap();

        let from_accounts: std::collections::HashSet<&String> = ledger
            .accounts
            .iter()
            .filter(|(_, a)| a.staked > 0)
            .map(|(h, _)| h)
            .collect();
        let from_index: std::collections::HashSet<&String> =
            ledger.staker_index.keys().collect();
        assert_eq!(
            from_accounts, from_index,
            "staker_index must match the staked>0 account set after stake ops"
        );
        assert_eq!(ledger.total_staked, 500 * BASE_UNITS_PER_BEAT);

        // Alice unstakes after cooldown — drops out of staker_index.
        let m5 = types::unstake_metadata("stake-a");
        let r5 = make_record_with_pk(
            "unstake-a",
            &alice_pk(),
            3.0 + UNSTAKE_COOLDOWN + 1.0,
            m5,
        );
        let o5 = extract_ledger_op(&r5).unwrap().unwrap();

        let mint_a = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let mr_a = make_record_with_pk("mint-a", &genesis_pk(), 1.0, mint_a);
        let mo_a = extract_ledger_op(&mr_a).unwrap().unwrap();
        let mint_b = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &bob_hash, "genesis");
        let mr_b = make_record_with_pk("mint-b", &genesis_pk(), 2.0, mint_b);
        let mo_b = extract_ledger_op(&mr_b).unwrap().unwrap();
        let stake_a = types::stake_metadata(200 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let sr_a = make_record_with_pk("stake-a", &alice_pk(), 3.0, stake_a);
        let so_a = extract_ledger_op(&sr_a).unwrap().unwrap();
        let stake_b = types::stake_metadata(300 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let sr_b = make_record_with_pk("stake-b", &bob_pk(), 4.0, stake_b);
        let so_b = extract_ledger_op(&sr_b).unwrap().unwrap();

        let ledger2 = derive_ledger(
            &[(mr_a, mo_a), (mr_b, mo_b), (sr_a, so_a), (sr_b, so_b), (r5, o5)],
            &genesis_hash,
        )
        .unwrap();

        let from_accounts2: std::collections::HashSet<&String> = ledger2
            .accounts
            .iter()
            .filter(|(_, a)| a.staked > 0)
            .map(|(h, _)| h)
            .collect();
        let from_index2: std::collections::HashSet<&String> =
            ledger2.staker_index.keys().collect();
        assert_eq!(
            from_accounts2, from_index2,
            "staker_index must match the staked>0 account set after unstake"
        );
        assert!(!from_index2.contains(&alice_hash));
        assert!(from_index2.contains(&bob_hash));
        assert_eq!(ledger2.total_staked, 300 * BASE_UNITS_PER_BEAT);
    }

    #[test]
    fn test_unstake_too_early() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::stake_metadata(200 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r2 = make_record_with_pk("stake-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Try to unstake 1 second later (way before cooldown)
        let m3 = types::unstake_metadata("stake-1");
        let r3 = make_record_with_pk("unstake-1", &alice_pk(), 3.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2), (r3, o3)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_stake_below_minimum() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Stake 50 beat (below 100 minimum)
        let m2 = types::stake_metadata(50 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r2 = make_record_with_pk("stake-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_unstake_wrong_owner() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::stake_metadata(200 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r2 = make_record_with_pk("stake-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Bob tries to unstake Alice's stake
        let m3 = types::unstake_metadata("stake-1");
        let r3 = make_record_with_pk("unstake-1", &bob_pk(), 2.0 + UNSTAKE_COOLDOWN + 1.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2), (r3, o3)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_conservation() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        // Mint 1000 to Alice
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Alice sends 400 to Bob
        let m2 = types::transfer_metadata(400 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let r2 = make_record_with_pk("xfer-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Alice stakes 200
        let m3 = types::stake_metadata(200 * BASE_UNITS_PER_BEAT, &StakePurpose::Governance);
        let r3 = make_record_with_pk("stake-1", &alice_pk(), 3.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        let ledger = derive_ledger(
            &[(r1, o1), (r2, o2), (r3, o3)],
            &genesis_hash,
        )
        .unwrap();

        // Conservation: all balances + stakes + pool = total supply
        let total_balances: u64 = ledger.accounts.values().map(|a| a.available).sum();
        let total_staked: u64 = ledger.accounts.values().map(|a| a.staked).sum();
        assert_eq!(total_balances + total_staked + ledger.conservation_pool, ledger.total_supply);

        // Verify individual balances
        assert_eq!(ledger.balance(&alice_hash), 400 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.staked(&alice_hash), 200 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.balance(&bob_hash), 400 * BASE_UNITS_PER_BEAT);
    }

    #[test]
    fn test_max_supply_enforcement() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        // Try to mint more than MAX_SUPPLY
        let meta = types::mint_metadata(MAX_SUPPLY + 1, &alice_hash, "too much");
        let rec = make_record_with_pk("mint-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();

        let result = derive_ledger(&[(rec, op)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_genesis_mint_rejected() {
        let genesis_hash = identity_hash(&genesis_pk());

        // First genesis mint: 10B beat — should succeed
        let m1 = types::mint_metadata(MAX_SUPPLY, &genesis_hash, "genesis:total_allocation");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Second genesis mint (different record ID, same content) — should be rejected
        let m2 = types::mint_metadata(MAX_SUPPLY, &genesis_hash, "genesis:total_allocation");
        let r2 = make_record_with_pk("mint-2", &genesis_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Tolerant derivation: first mint succeeds, second is skipped
        let (ledger, skipped) = derive_ledger_tolerant(
            &[(r1, o1), (r2, o2)],
            &genesis_hash,
        );
        assert_eq!(ledger.total_supply, MAX_SUPPLY, "supply should be MAX_SUPPLY, not double");
        assert_eq!(skipped, 1, "second genesis mint should be skipped");
        assert_eq!(ledger.balance(&genesis_hash), MAX_SUPPLY);
    }

    #[test]
    fn test_zero_transfer_rejected() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::transfer_metadata(0, &bob_hash, None);
        let r2 = make_record_with_pk("xfer-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_self_transfer_rejected() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Alice sends to herself
        let m2 = types::transfer_metadata(100 * BASE_UNITS_PER_BEAT, &alice_hash, None);
        let r2 = make_record_with_pk("xfer-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_ledger() {
        let genesis_hash = identity_hash(&genesis_pk());
        let ledger = derive_ledger(&[], &genesis_hash).unwrap();
        assert_eq!(ledger.total_supply, 0);
        assert_eq!(ledger.records_processed, 0);
        assert!(ledger.accounts.is_empty());
    }

    // ─── Witness Reward Tests ─────────────────────────────────────────

    fn witness_pk() -> Vec<u8> {
        vec![0x04; 1952]
    }

    #[test]
    fn test_witness_reward() {
        let genesis_hash = identity_hash(&genesis_pk());
        let witness_hash = identity_hash(&witness_pk());

        // Seed conservation pool via pool_fund
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &genesis_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m1b = types::pool_fund_metadata(100 * BASE_UNITS_PER_BEAT);
        let r1b = make_record_with_pk("pool-1", &genesis_pk(), 1.5, m1b);
        let o1b = extract_ledger_op(&r1b).unwrap().unwrap();

        // Genesis creates witness reward: pool → witness (1 beat)
        let m2 = types::witness_reward_metadata(
            DEFAULT_WITNESS_REWARD,
            &genesis_hash,
            &witness_hash,
            "some-record",
        );
        let r2 = make_record_with_pk("reward-1", &genesis_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let ledger = derive_ledger(&[(r1, o1), (r1b, o1b), (r2, o2)], &genesis_hash).unwrap();

        assert_eq!(ledger.balance(&witness_hash), BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.conservation_pool, 99 * BASE_UNITS_PER_BEAT); // 100 pool - 1 reward
    }

    #[test]
    fn test_witness_reward_non_genesis_rejected() {
        let genesis_hash = identity_hash(&genesis_pk());
        let witness_hash = identity_hash(&witness_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Non-genesis tries to create witness reward — should fail
        let m2 = types::witness_reward_metadata(
            DEFAULT_WITNESS_REWARD,
            &alice_hash,
            &witness_hash,
            "some-record",
        );
        let r2 = make_record_with_pk("reward-1", &witness_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_witness_reward_exceeds_max() {
        let genesis_hash = identity_hash(&genesis_pk());
        let witness_hash = identity_hash(&witness_pk());

        // Seed pool
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &genesis_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();
        let m1b = types::pool_fund_metadata(100 * BASE_UNITS_PER_BEAT);
        let r1b = make_record_with_pk("pool-1", &genesis_pk(), 1.5, m1b);
        let o1b = extract_ledger_op(&r1b).unwrap().unwrap();

        // Try 11 beat reward (max is 10) — signed by genesis
        let m2 = types::witness_reward_metadata(
            11 * BASE_UNITS_PER_BEAT,
            &genesis_hash,
            &witness_hash,
            "some-record",
        );
        let r2 = make_record_with_pk("reward-1", &genesis_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r1b, o1b), (r2, o2)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_witness_reward_pool_insufficient() {
        let genesis_hash = identity_hash(&genesis_pk());
        let witness_hash = identity_hash(&witness_pk());

        // No pool funded — reward should fail
        let m1 = types::witness_reward_metadata(
            DEFAULT_WITNESS_REWARD,
            &genesis_hash,
            &witness_hash,
            "some-record",
        );
        let r1 = make_record_with_pk("reward-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_witness_reward_self_reward_rejected() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Alice tries to reward herself
        let m2 = types::witness_reward_metadata(
            DEFAULT_WITNESS_REWARD,
            &alice_hash,
            &alice_hash,
            "some-record",
        );
        let r2 = make_record_with_pk("reward-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_witness_reward_conservation() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());
        let witness_hash = identity_hash(&witness_pk());

        // Mint 1100 to genesis, pool_fund 100, transfer 1000 to Alice, Alice sends 300 to Bob, genesis rewards witness
        let m0 = types::mint_metadata(1_100 * BASE_UNITS_PER_BEAT, &genesis_hash, "genesis");
        let r0 = make_record_with_pk("mint-0", &genesis_pk(), 0.5, m0);
        let o0 = extract_ledger_op(&r0).unwrap().unwrap();

        let m1b = types::pool_fund_metadata(100 * BASE_UNITS_PER_BEAT);
        let r1b = make_record_with_pk("pool-1", &genesis_pk(), 1.0, m1b);
        let o1b = extract_ledger_op(&r1b).unwrap().unwrap();

        let m1 = types::transfer_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, None);
        let r1 = make_record_with_pk("xfer-g-a", &genesis_pk(), 1.5, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::transfer_metadata(300 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let r2 = make_record_with_pk("xfer-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Genesis auto-reward: pool → witness (5 beat)
        let m3 = types::witness_reward_metadata(
            5 * BASE_UNITS_PER_BEAT,
            &genesis_hash,
            &witness_hash,
            "some-record",
        );
        let r3 = make_record_with_pk("reward-1", &genesis_pk(), 3.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        let ledger = derive_ledger(&[(r0, o0), (r1b, o1b), (r1, o1), (r2, o2), (r3, o3)], &genesis_hash).unwrap();

        // Conservation check
        let total_balances: u64 = ledger.accounts.values().map(|a| a.available).sum();
        let total_staked: u64 = ledger.accounts.values().map(|a| a.staked).sum();
        assert_eq!(total_balances + total_staked + ledger.conservation_pool, ledger.total_supply);

        assert_eq!(ledger.balance(&alice_hash), 700 * BASE_UNITS_PER_BEAT); // 1000 - 300
        assert_eq!(ledger.balance(&bob_hash), 300 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.balance(&witness_hash), 5 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.conservation_pool, 95 * BASE_UNITS_PER_BEAT); // 100 pool - 5 reward
    }

    // ─── Tolerant Derivation Tests ──────────────────────────────────────

    #[test]
    fn test_tolerant_skips_unauthorized_mint() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        // Alice tries to mint (not genesis)
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "hack");
        let r1 = make_record_with_pk("bad-mint", &alice_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let (state, skipped) = derive_ledger_tolerant(&[(r1, o1)], &genesis_hash);
        assert_eq!(skipped, 1);
        assert_eq!(state.total_supply, 0);
        assert!(state.accounts.is_empty());
    }

    #[test]
    fn test_tolerant_skips_overspend() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        // Valid mint: 100 beat to Alice
        let m1 = types::mint_metadata(100 * BASE_UNITS_PER_BEAT, &alice_hash, "seed");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Invalid transfer: Alice sends 9999 beat (more than she has)
        let m2 = types::transfer_metadata(9_999 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let r2 = make_record_with_pk("bad-xfer", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let (state, skipped) = derive_ledger_tolerant(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert_eq!(skipped, 1);
        // Alice still has her 100 beat, Bob has nothing
        assert_eq!(state.account(&alice_hash).available, 100 * BASE_UNITS_PER_BEAT);
        assert_eq!(state.account(&bob_hash).available, 0);
        assert_eq!(state.total_supply, 100 * BASE_UNITS_PER_BEAT);
    }

    #[test]
    fn test_tolerant_skips_self_transfer() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "seed");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Self-transfer
        let m2 = types::transfer_metadata(100 * BASE_UNITS_PER_BEAT, &alice_hash, None);
        let r2 = make_record_with_pk("self-xfer", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let (state, skipped) = derive_ledger_tolerant(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert_eq!(skipped, 1);
        assert_eq!(state.account(&alice_hash).available, 1_000 * BASE_UNITS_PER_BEAT);
    }

    #[test]
    fn test_tolerant_mixed_valid_and_invalid() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        // Valid mint
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "seed");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Invalid: unauthorized mint from Alice
        let m2 = types::mint_metadata(999_999 * BASE_UNITS_PER_BEAT, &alice_hash, "hack");
        let r2 = make_record_with_pk("bad-mint", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Valid transfer: Alice → Bob 200 beat
        let m3 = types::transfer_metadata(200 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let r3 = make_record_with_pk("xfer-1", &alice_pk(), 3.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        // Invalid: overspend Alice → Bob 900 beat (she only has 800 after the first transfer)
        let m4 = types::transfer_metadata(900 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let r4 = make_record_with_pk("bad-xfer", &alice_pk(), 4.0, m4);
        let o4 = extract_ledger_op(&r4).unwrap().unwrap();

        let (state, skipped) = derive_ledger_tolerant(
            &[(r1, o1), (r2, o2), (r3, o3), (r4, o4)],
            &genesis_hash,
        );
        assert_eq!(skipped, 2); // unauthorized mint + overspend
        assert_eq!(state.total_supply, 1_000 * BASE_UNITS_PER_BEAT);
        assert_eq!(state.account(&alice_hash).available, 800 * BASE_UNITS_PER_BEAT);
        assert_eq!(state.account(&bob_hash).available, 200 * BASE_UNITS_PER_BEAT);
    }

    #[test]
    fn test_tolerant_empty() {
        let genesis_hash = identity_hash(&genesis_pk());
        let (state, skipped) = derive_ledger_tolerant(&[], &genesis_hash);
        assert_eq!(skipped, 0);
        assert_eq!(state.total_supply, 0);
    }

    // ─── Slash Tests ─────────────────────────────────────────────────────

    fn challenger_pk() -> Vec<u8> {
        vec![0x05; 1952]
    }

    fn jury_pk() -> Vec<u8> {
        vec![0x06; 1952]
    }

    #[test]
    fn test_slash_basic() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let challenger_hash = identity_hash(&challenger_pk());
        let jury_hash = identity_hash(&jury_pk());

        // Mint 1000 to Alice, she stakes 200
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::stake_metadata(200 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r2 = make_record_with_pk("stake-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Slash 100 beat (50% of her 200 stake)
        let m3 = types::slash_metadata(
            100 * BASE_UNITS_PER_BEAT,
            &alice_hash,
            &challenger_hash,
            std::slice::from_ref(&jury_hash),
            "stake-1",
            "double signing",
        );
        let r3 = make_record_with_pk("slash-1", &genesis_pk(), 3.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        let ledger = derive_ledger(&[(r1, o1), (r2, o2), (r3, o3)], &genesis_hash).unwrap();

        // Alice: 800 available + 100 staked = 900
        assert_eq!(ledger.balance(&alice_hash), 800 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.staked(&alice_hash), 100 * BASE_UNITS_PER_BEAT);

        // Challenger gets 30% = 30 beat
        assert_eq!(ledger.balance(&challenger_hash), 30 * BASE_UNITS_PER_BEAT);

        // Jury gets 20% = 20 beat
        assert_eq!(ledger.balance(&jury_hash), 20 * BASE_UNITS_PER_BEAT);

        // Pool gets 50% = 50 beat
        assert_eq!(ledger.conservation_pool, 50 * BASE_UNITS_PER_BEAT);

        // Conservation: all balances + all stakes + pool = total supply
        let total_balances: u64 = ledger.accounts.values().map(|a| a.available).sum();
        let total_staked: u64 = ledger.accounts.values().map(|a| a.staked).sum();
        assert_eq!(total_balances + total_staked + ledger.conservation_pool, ledger.total_supply);
    }

    #[test]
    fn test_slash_empty_jury_conserves() {
        // B12(a): a slash with an empty jury must not silently shrink supply.
        // `jury_share` (20%) is debited from the offender via `actual_slash`;
        // with no juror to receive it, it is folded into the conservation pool
        // so the slash stays conservation-exact. Empty-jury is authority-gated
        // on an honest emitter today, but reachable once ConflictProofs are
        // gossiped pre-S3 (B12(f)).
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let challenger_hash = identity_hash(&challenger_pk());

        // Mint 1000 to Alice, she stakes 200.
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::stake_metadata(200 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r2 = make_record_with_pk("stake-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Slash 100 beat (50% of her 200 stake) with NO jury.
        let m3 = types::slash_metadata(
            100 * BASE_UNITS_PER_BEAT,
            &alice_hash,
            &challenger_hash,
            &[],
            "stake-1",
            "double signing",
        );
        let r3 = make_record_with_pk("slash-1", &genesis_pk(), 3.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        let ledger = derive_ledger(&[(r1, o1), (r2, o2), (r3, o3)], &genesis_hash).unwrap();

        // Alice: 800 available + 100 staked.
        assert_eq!(ledger.balance(&alice_hash), 800 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.staked(&alice_hash), 100 * BASE_UNITS_PER_BEAT);

        // Challenger still gets 30% = 30 beat.
        assert_eq!(ledger.balance(&challenger_hash), 30 * BASE_UNITS_PER_BEAT);

        // Pool gets 50% + the orphaned 20% jury share = 70 beat (< the 10% cap
        // of 100 beat on a 1000-beat supply, so no overflow to challenger).
        assert_eq!(ledger.conservation_pool, 70 * BASE_UNITS_PER_BEAT);

        // The invariant that matters: nothing was burned.
        // sum(available) + sum(staked) + pool == total_supply.
        let total_balances: u64 = ledger.accounts.values().map(|a| a.available).sum();
        let total_staked: u64 = ledger.accounts.values().map(|a| a.staked).sum();
        assert_eq!(
            total_balances + total_staked + ledger.conservation_pool,
            ledger.total_supply
        );
        assert_eq!(ledger.total_supply, 1_000 * BASE_UNITS_PER_BEAT);
    }

    #[test]
    fn test_slash_multi_jury_distribution() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let challenger_hash = identity_hash(&challenger_pk());
        // Three jurors
        let juror_a = "juror_a_hash".to_string();
        let juror_b = "juror_b_hash".to_string();
        let juror_c = "juror_c_hash".to_string();

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::stake_metadata(300 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r2 = make_record_with_pk("stake-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Slash 150 beat (50% of 300), 3 jurors
        let jury = vec![juror_a.clone(), juror_b.clone(), juror_c.clone()];
        let m3 = types::slash_metadata(
            150 * BASE_UNITS_PER_BEAT,
            &alice_hash,
            &challenger_hash,
            &jury,
            "stake-1",
            "false witnessing",
        );
        let r3 = make_record_with_pk("slash-1", &genesis_pk(), 3.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        let ledger = derive_ledger(&[(r1, o1), (r2, o2), (r3, o3)], &genesis_hash).unwrap();

        // 150 beat slashed total
        assert_eq!(ledger.staked(&alice_hash), 150 * BASE_UNITS_PER_BEAT);

        // Challenger: 30% of 150 = 45 beat
        assert_eq!(ledger.balance(&challenger_hash), 45 * BASE_UNITS_PER_BEAT);

        // Jury total: 20% of 150 = 30 beat, split among 3 = 10 beat each
        assert_eq!(ledger.balance(&juror_a), 10 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.balance(&juror_b), 10 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.balance(&juror_c), 10 * BASE_UNITS_PER_BEAT);

        // Pool: 50% of 150 = 75 beat
        assert_eq!(ledger.conservation_pool, 75 * BASE_UNITS_PER_BEAT);

        // Conservation invariant
        let total_balances: u64 = ledger.accounts.values().map(|a| a.available).sum();
        let total_staked: u64 = ledger.accounts.values().map(|a| a.staked).sum();
        assert_eq!(total_balances + total_staked + ledger.conservation_pool, ledger.total_supply);
    }

    #[test]
    fn test_slash_capped_at_max_percentage() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let challenger_hash = identity_hash(&challenger_pk());
        let jury_hash = identity_hash(&jury_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::stake_metadata(200 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r2 = make_record_with_pk("stake-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Try to slash 200 beat (100% of stake) — should be capped at 50% = 100 beat
        let m3 = types::slash_metadata(
            200 * BASE_UNITS_PER_BEAT,
            &alice_hash,
            &challenger_hash,
            std::slice::from_ref(&jury_hash),
            "stake-1",
            "attack",
        );
        let r3 = make_record_with_pk("slash-1", &genesis_pk(), 3.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        let ledger = derive_ledger(&[(r1, o1), (r2, o2), (r3, o3)], &genesis_hash).unwrap();

        // Only 100 beat slashed (50% cap), Alice keeps 100 staked
        assert_eq!(ledger.staked(&alice_hash), 100 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.conservation_pool, 50 * BASE_UNITS_PER_BEAT);
    }

    #[test]
    fn test_slash_unauthorized() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let challenger_hash = identity_hash(&challenger_pk());
        let jury_hash = identity_hash(&jury_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::stake_metadata(200 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r2 = make_record_with_pk("stake-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Bob (not genesis) tries to slash — should fail
        let m3 = types::slash_metadata(
            100 * BASE_UNITS_PER_BEAT,
            &alice_hash,
            &challenger_hash,
            std::slice::from_ref(&jury_hash),
            "stake-1",
            "malicious",
        );
        let r3 = make_record_with_pk("slash-1", &bob_pk(), 3.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2), (r3, o3)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_slash_inactive_stake_rejected() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let challenger_hash = identity_hash(&challenger_pk());
        let jury_hash = identity_hash(&jury_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::stake_metadata(200 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r2 = make_record_with_pk("stake-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Unstake first
        let m3 = types::unstake_metadata("stake-1");
        let r3 = make_record_with_pk("unstake-1", &alice_pk(), 2.0 + UNSTAKE_COOLDOWN + 1.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        // Try to slash the now-inactive stake
        let m4 = types::slash_metadata(
            100 * BASE_UNITS_PER_BEAT,
            &alice_hash,
            &challenger_hash,
            std::slice::from_ref(&jury_hash),
            "stake-1",
            "too late",
        );
        let r4 = make_record_with_pk("slash-1", &genesis_pk(), 2.0 + UNSTAKE_COOLDOWN + 2.0, m4);
        let o4 = extract_ledger_op(&r4).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2), (r3, o3), (r4, o4)], &genesis_hash);
        assert!(result.is_err());
    }

    // ─── Dormancy Reclaim Tests ──────────────────────────────────────────

    #[test]
    fn test_dormancy_reclaim_basic() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        // Mint 1000 to Alice at t=1.0
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // AUDIT-3: Phase 2 DECLARE required before reclaim. Declared at
        // t=1.0 + DORMANCY_THRESHOLD (5yr of inactivity passed).
        let declare_time = 1.0 + DORMANCY_THRESHOLD + 1.0;
        let m_decl = types::dormancy_declare_metadata(&alice_hash, 1.0);
        let r_decl = make_record_with_pk("decl-1", &bob_pk(), declare_time, m_decl);
        let o_decl = extract_ledger_op(&r_decl).unwrap().unwrap();

        // Phase 3 wake-up window expires at declare_time + 2yr. Reclaim AFTER that.
        let reclaim_time = declare_time + DORMANCY_WAKEUP_WINDOW + 1.0;
        let m2 = types::dormancy_reclaim_metadata(
            500 * BASE_UNITS_PER_BEAT,
            &alice_hash,
            1.0, // Alice's last activity was at t=1.0
        );
        let r2 = make_record_with_pk("reclaim-1", &genesis_pk(), reclaim_time, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let ledger = derive_ledger(
            &[(r1, o1), (r_decl, o_decl), (r2, o2)],
            &genesis_hash,
        ).unwrap();

        // Pool cap = 10% of 1000 beat = 100 beat. Reclaim 500 but pool can only hold 100.
        // Overflow stays with Alice.
        assert_eq!(ledger.conservation_pool, 100 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.balance(&alice_hash), 900 * BASE_UNITS_PER_BEAT);

        // Alice's dormancy phase must now be Reclaimed.
        assert_eq!(
            ledger.dormancy.phase(&alice_hash),
            crate::accounting::dormancy::DormancyPhase::Reclaimed
        );

        // Conservation: balances + staked + pool = supply
        let total_balances: u64 = ledger.accounts.values().map(|a| a.available).sum();
        let total_staked: u64 = ledger.accounts.values().map(|a| a.staked).sum();
        assert_eq!(total_balances + total_staked + ledger.conservation_pool, ledger.total_supply);
    }

    #[test]
    fn test_dormancy_reclaim_not_dormant() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        // Mint to Alice at t=1.0
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Alice transfers at t=2.0 (recent activity)
        let m2 = types::transfer_metadata(100 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let r2 = make_record_with_pk("xfer-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Try to reclaim 3 years later (threshold is 5) — should fail
        let reclaim_time = 2.0 + 3.0 * 365.25 * 24.0 * 3600.0;
        let m3 = types::dormancy_reclaim_metadata(
            500 * BASE_UNITS_PER_BEAT,
            &alice_hash,
            2.0,
        );
        let r3 = make_record_with_pk("reclaim-1", &genesis_pk(), reclaim_time, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2), (r3, o3)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_dormancy_reclaim_requires_declare_phase() {
        // AUDIT-3: genesis authority cannot reclaim without a prior DormancyDeclare.
        // This is the exploit path — genesis-key compromise must NOT equal instant drain.
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Genesis tries to reclaim without any DECLARE record — must fail.
        let reclaim_time = 1.0 + DORMANCY_THRESHOLD + DORMANCY_WAKEUP_WINDOW + 1.0;
        let m2 = types::dormancy_reclaim_metadata(500 * BASE_UNITS_PER_BEAT, &alice_hash, 1.0);
        let r2 = make_record_with_pk("reclaim-1", &genesis_pk(), reclaim_time, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert!(result.is_err());
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("Phase 2 declaration") || msg.contains("DormancyDeclare"),
            "expected Phase 2 declaration error, got: {msg}"
        );
    }

    #[test]
    fn test_dormancy_reclaim_before_wake_window_expires() {
        // AUDIT-3: reclaim must wait for Phase 3 wake-up window to fully expire.
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Declare at 5yr of inactivity.
        let declare_time = 1.0 + DORMANCY_THRESHOLD + 1.0;
        let m_decl = types::dormancy_declare_metadata(&alice_hash, 1.0);
        let r_decl = make_record_with_pk("decl-1", &bob_pk(), declare_time, m_decl);
        let o_decl = extract_ledger_op(&r_decl).unwrap().unwrap();

        // Reclaim only 1 year into the 2-year wake-up window — must fail.
        let reclaim_time = declare_time + 365.25 * 24.0 * 3600.0;
        let m2 = types::dormancy_reclaim_metadata(500 * BASE_UNITS_PER_BEAT, &alice_hash, 1.0);
        let r2 = make_record_with_pk("reclaim-1", &genesis_pk(), reclaim_time, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(
            &[(r1, o1), (r_decl, o_decl), (r2, o2)],
            &genesis_hash,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_dormancy_heartbeat_resets_phase() {
        // AUDIT-3: dormant identity wakes itself via heartbeat before wake-up expires,
        // then a later reclaim attempt fails because phase is Active again.
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Declare dormant.
        let declare_time = 1.0 + DORMANCY_THRESHOLD + 1.0;
        let m_decl = types::dormancy_declare_metadata(&alice_hash, 1.0);
        let r_decl = make_record_with_pk("decl-1", &bob_pk(), declare_time, m_decl);
        let o_decl = extract_ledger_op(&r_decl).unwrap().unwrap();

        // Alice heartbeats back during wake-up window.
        let heartbeat_time = declare_time + 365.25 * 24.0 * 3600.0;
        let m_hb = types::dormancy_heartbeat_metadata();
        let r_hb = make_record_with_pk("hb-1", &alice_pk(), heartbeat_time, m_hb);
        let o_hb = extract_ledger_op(&r_hb).unwrap().unwrap();

        let ledger = derive_ledger(
            &[(r1, o1), (r_decl, o_decl), (r_hb, o_hb)],
            &genesis_hash,
        ).unwrap();

        assert_eq!(
            ledger.dormancy.phase(&alice_hash),
            crate::accounting::dormancy::DormancyPhase::Active
        );
        // Alice's balance untouched.
        assert_eq!(ledger.balance(&alice_hash), 1_000 * BASE_UNITS_PER_BEAT);
    }

    #[test]
    fn test_dormancy_reclaim_unauthorized() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let reclaim_time = 1.0 + DORMANCY_THRESHOLD + 1.0;
        let m2 = types::dormancy_reclaim_metadata(
            500 * BASE_UNITS_PER_BEAT,
            &alice_hash,
            1.0,
        );
        // Bob (not genesis) tries to reclaim
        let r2 = make_record_with_pk("reclaim-1", &bob_pk(), reclaim_time, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_pool_cap_enforcement_on_slash() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let challenger_hash = identity_hash(&challenger_pk());
        let jury_hash = identity_hash(&jury_pk());

        // Mint 100 beat to Alice. Pool cap = 10% = 10 beat.
        let m1 = types::mint_metadata(100 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Alice stakes all 100 beat
        let m2 = types::stake_metadata(100 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r2 = make_record_with_pk("stake-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Slash 50 beat (50% of 100 stake). Pool share = 25 beat but cap is 10.
        let m3 = types::slash_metadata(
            50 * BASE_UNITS_PER_BEAT,
            &alice_hash,
            &challenger_hash,
            std::slice::from_ref(&jury_hash),
            "stake-1",
            "test cap",
        );
        let r3 = make_record_with_pk("slash-1", &genesis_pk(), 3.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        let ledger = derive_ledger(&[(r1, o1), (r2, o2), (r3, o3)], &genesis_hash).unwrap();

        // Pool capped at 10 beat
        assert_eq!(ledger.conservation_pool, 10 * BASE_UNITS_PER_BEAT);

        // Overflow (15 beat) goes to challenger: 15 + 15 = 30 beat
        assert_eq!(ledger.balance(&challenger_hash), 30 * BASE_UNITS_PER_BEAT);

        // Jury gets normal 20% = 10 beat
        assert_eq!(ledger.balance(&jury_hash), 10 * BASE_UNITS_PER_BEAT);

        // Conservation check
        let total_balances: u64 = ledger.accounts.values().map(|a| a.available).sum();
        let total_staked: u64 = ledger.accounts.values().map(|a| a.staked).sum();
        assert_eq!(total_balances + total_staked + ledger.conservation_pool, ledger.total_supply);
    }

    #[test]
    fn test_last_active_tracking() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 100.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::transfer_metadata(100 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let r2 = make_record_with_pk("xfer-1", &alice_pk(), 200.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let ledger = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash).unwrap();

        // Alice: last active at t=200 (the transfer)
        assert_eq!(ledger.account(&alice_hash).last_active, 200.0);
        // Bob: last active at t=200 (received transfer)
        assert_eq!(ledger.account(&bob_hash).last_active, 200.0);
    }

    #[test]
    fn test_slash_and_dormancy_conservation() {
        // Full scenario: mint → stake → slash → dormancy reclaim.
        // Verify conservation invariant holds throughout.
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());
        let challenger_hash = identity_hash(&challenger_pk());
        let jury_hash = identity_hash(&jury_pk());

        // Mint 10_000 to Alice, 5_000 to Bob
        let m1 = types::mint_metadata(10_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::mint_metadata(5_000 * BASE_UNITS_PER_BEAT, &bob_hash, "genesis");
        let r2 = make_record_with_pk("mint-2", &genesis_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        // Alice stakes 2000
        let m3 = types::stake_metadata(2_000 * BASE_UNITS_PER_BEAT, &StakePurpose::Witness);
        let r3 = make_record_with_pk("stake-1", &alice_pk(), 3.0, m3);
        let o3 = extract_ledger_op(&r3).unwrap().unwrap();

        // Slash Alice: 1000 from stake (50% of 2000)
        let m4 = types::slash_metadata(
            1_000 * BASE_UNITS_PER_BEAT,
            &alice_hash,
            &challenger_hash,
            std::slice::from_ref(&jury_hash),
            "stake-1",
            "test",
        );
        let r4 = make_record_with_pk("slash-1", &genesis_pk(), 4.0, m4);
        let o4 = extract_ledger_op(&r4).unwrap().unwrap();

        // AUDIT-3: Phase 2 Declare Bob dormant (after 5yr of inactivity).
        let declare_time = 2.0 + DORMANCY_THRESHOLD + 1.0;
        let m_decl = types::dormancy_declare_metadata(&bob_hash, 2.0);
        let r_decl = make_record_with_pk("decl-bob", &challenger_pk(), declare_time, m_decl);
        let o_decl = extract_ledger_op(&r_decl).unwrap().unwrap();

        // Dormancy reclaim on Bob AFTER wake-up window (Phase 3) expires.
        let reclaim_time = declare_time + DORMANCY_WAKEUP_WINDOW + 1.0;
        let m5 = types::dormancy_reclaim_metadata(
            1_000 * BASE_UNITS_PER_BEAT,
            &bob_hash,
            2.0,
        );
        let r5 = make_record_with_pk("reclaim-1", &genesis_pk(), reclaim_time, m5);
        let o5 = extract_ledger_op(&r5).unwrap().unwrap();

        let ledger = derive_ledger(
            &[(r1, o1), (r2, o2), (r3, o3), (r4, o4), (r_decl, o_decl), (r5, o5)],
            &genesis_hash,
        )
        .unwrap();

        // Conservation: sum of all + pool = total supply
        let total_balances: u64 = ledger.accounts.values().map(|a| a.available).sum();
        let total_staked: u64 = ledger.accounts.values().map(|a| a.staked).sum();
        assert_eq!(
            total_balances + total_staked + ledger.conservation_pool,
            ledger.total_supply
        );

        // Pool should have: 500 (50% of 1000 slash) + 1000 (dormancy) = 1500 beat
        // Pool cap = 10% of 15000 = 1500 beat — exactly at cap
        assert_eq!(ledger.conservation_pool, 1_500 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.total_supply, 15_000 * BASE_UNITS_PER_BEAT);
    }

    // ─── Burn Tests ──────────────────────────────────────────────────────

    #[test]
    fn test_burn_basic() {
        let genesis_hash = identity_hash(&genesis_pk());

        // Mint 1000 to genesis
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &genesis_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Genesis burns 100 beat → Conservation Pool
        let m2 = types::burn_metadata(100 * BASE_UNITS_PER_BEAT, Some("pool redirect"));
        let r2 = make_record_with_pk("burn-1", &genesis_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let ledger = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash).unwrap();

        assert_eq!(ledger.balance(&genesis_hash), 900 * BASE_UNITS_PER_BEAT);
        // total_supply unchanged — beats redirected to pool, not destroyed
        assert_eq!(ledger.total_supply, 1_000 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.conservation_pool, 100 * BASE_UNITS_PER_BEAT);

        // Conservation: balances + staked + pool = total_supply
        let total_balances: u64 = ledger.accounts.values().map(|a| a.available).sum();
        let total_staked: u64 = ledger.accounts.values().map(|a| a.staked).sum();
        assert_eq!(total_balances + total_staked + ledger.conservation_pool, ledger.total_supply);
    }

    #[test]
    fn test_burn_insufficient_balance() {
        let genesis_hash = identity_hash(&genesis_pk());

        let m1 = types::mint_metadata(100 * BASE_UNITS_PER_BEAT, &genesis_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Genesis tries to burn 200 (only has 100)
        let m2 = types::burn_metadata(200 * BASE_UNITS_PER_BEAT, None);
        let r2 = make_record_with_pk("burn-1", &genesis_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_burn_zero_rejected() {
        let genesis_hash = identity_hash(&genesis_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &genesis_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::burn_metadata(0, None);
        let r2 = make_record_with_pk("burn-1", &genesis_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert!(result.is_err());
    }

    // ─── Sybil witness stake gate ─────────────────────

    #[test]
    fn test_staked_returns_zero_for_unknown() {
        let state = LedgerState::new();
        assert_eq!(state.staked("nonexistent"), 0);
    }

    #[test]
    fn test_witness_stake_threshold() {
        let mut state = LedgerState::new();
        let witness = identity_hash(&alice_pk());
        const MIN_WITNESS_STAKE: u64 = 100 * BASE_UNITS_PER_BEAT; // 100 beat

        // Give witness some balance but no stake
        state.accounts.entry(witness.clone()).or_default().available = 500 * BASE_UNITS_PER_BEAT;
        assert!(state.staked(&witness) < MIN_WITNESS_STAKE, "no stake should fail gate");

        // Stake 50 beat — still below threshold
        state.accounts.entry(witness.clone()).or_default().staked = 50 * BASE_UNITS_PER_BEAT;
        assert!(state.staked(&witness) < MIN_WITNESS_STAKE, "50 beat stake should fail gate");

        // Stake 100 beat — at threshold
        state.accounts.entry(witness.clone()).or_default().staked = 100 * BASE_UNITS_PER_BEAT;
        assert!(state.staked(&witness) >= MIN_WITNESS_STAKE, "100 beat stake should pass gate");
    }

    #[test]
    fn test_identity_profile_registration() {
        let mut state = LedgerState::new();
        let alice = identity_hash(&alice_pk());

        // Unknown identity defaults to single-sig (Profile B)
        assert!(state.is_single_sig(&alice));

        // Register as Profile A (dual-sig)
        state.register_identity_profile(&alice, crate::identity::CryptoProfile::ProfileA);
        assert!(!state.is_single_sig(&alice));

        // Different identity still defaults to Profile B
        let bob = identity_hash(&bob_pk());
        assert!(state.is_single_sig(&bob));
    }

    #[test]
    fn test_burn_non_genesis_rejected() {
        // Non-genesis identities cannot burn — conservation invariant
        let genesis_hash = identity_hash(&genesis_pk());
        let bob_hash = identity_hash(&bob_pk());

        let m1 = types::mint_metadata(500 * BASE_UNITS_PER_BEAT, &bob_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::burn_metadata(50 * BASE_UNITS_PER_BEAT, None);
        let r2 = make_record_with_pk("burn-1", &bob_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert!(result.is_err());
    }

    // ─── Prediction Tests ─────────────────────────────────────────────

    #[test]
    fn test_predict_locks_stake() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        // Mint 1000 beat to Alice
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Alice predicts zone "test/zone" will be active in epoch 5
        let m2 = types::predict_metadata(
            100 * BASE_UNITS_PER_BEAT,
            "test/zone",
            5,
            &types::PredictionClaim::Active,
            1,
        );
        let r2 = make_record_with_pk("pred-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let ledger = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash).unwrap();
        let alice = ledger.accounts.get(&alice_hash).unwrap();

        // 1000 - 100 = 900 available
        assert_eq!(alice.available, 900 * BASE_UNITS_PER_BEAT);
        // Prediction entry registered
        assert_eq!(ledger.predictions.len(), 1);
        let pred = ledger.predictions.get("pred-1").unwrap();
        assert_eq!(pred.predictor, alice_hash);
        assert_eq!(pred.amount, 100 * BASE_UNITS_PER_BEAT);
        assert_eq!(pred.zone, "test/zone");
        assert_eq!(pred.target_epoch, 5);
        assert!(pred.outcome.is_none());
    }

    #[test]
    fn test_predict_below_minimum_rejected() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Try to predict with only 5 beat (below MIN_PREDICTION_STAKE of 10 beat)
        let m2 = types::predict_metadata(
            5 * BASE_UNITS_PER_BEAT,
            "test/zone",
            5,
            &types::PredictionClaim::Active,
            1,
        );
        let r2 = make_record_with_pk("pred-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_predict_insufficient_balance_rejected() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(50 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Try to predict with 100 beat but Alice only has 50
        let m2 = types::predict_metadata(
            100 * BASE_UNITS_PER_BEAT,
            "test/zone",
            5,
            &types::PredictionClaim::Active,
            1,
        );
        let r2 = make_record_with_pk("pred-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_evaluate_predictions_correct_active() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        // Mint to Alice + fund conservation pool
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m_pool = types::pool_fund_metadata(500 * BASE_UNITS_PER_BEAT);
        let r_pool = make_record_with_pk("pool-1", &genesis_pk(), 1.1, m_pool);
        let o_pool = extract_ledger_op(&r_pool).unwrap().unwrap();

        // Mint to genesis so it has balance for pool fund
        let m0 = types::mint_metadata(500 * BASE_UNITS_PER_BEAT, &genesis_hash, "bootstrap");
        let r0 = make_record_with_pk("mint-0", &genesis_pk(), 0.5, m0);
        let o0 = extract_ledger_op(&r0).unwrap().unwrap();

        // Alice predicts zone will be active (predicted_value=1)
        let m2 = types::predict_metadata(
            100 * BASE_UNITS_PER_BEAT,
            "test/zone",
            5,
            &types::PredictionClaim::Active,
            1,
        );
        let r2 = make_record_with_pk("pred-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let mut ledger = derive_ledger(&[(r0, o0), (r1, o1), (r_pool, o_pool), (r2, o2)], &genesis_hash).unwrap();

        let alice_before = ledger.accounts.get(&alice_hash).unwrap().available;
        let pool_before = ledger.conservation_pool;

        // Zone had 10 records → active = true → prediction correct
        let (correct, wrong, rewarded, _confiscated) =
            ledger.evaluate_predictions("test/zone", 5, 10, 3);

        assert_eq!(correct, 1);
        assert_eq!(wrong, 0);

        let alice_after = ledger.accounts.get(&alice_hash).unwrap().available;
        // Alice gets stake back + 10% reward
        let expected_reward = ((100 * BASE_UNITS_PER_BEAT) as f64 * 0.10) as u64;
        assert_eq!(alice_after, alice_before + 100 * BASE_UNITS_PER_BEAT + expected_reward);
        assert_eq!(rewarded, expected_reward);
        // Pool decreased by reward
        assert_eq!(ledger.conservation_pool, pool_before - expected_reward);
        // Prediction marked as correct
        assert_eq!(ledger.predictions.get("pred-1").unwrap().outcome, Some(true));
    }

    #[test]
    fn test_evaluate_predictions_wrong_active() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Alice predicts zone will be active (predicted_value=1)
        let m2 = types::predict_metadata(
            100 * BASE_UNITS_PER_BEAT,
            "test/zone",
            5,
            &types::PredictionClaim::Active,
            1,
        );
        let r2 = make_record_with_pk("pred-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let mut ledger = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash).unwrap();

        let alice_before = ledger.accounts.get(&alice_hash).unwrap().available;
        let pool_before = ledger.conservation_pool;

        // Zone had 0 records → active = false → prediction WRONG
        let (correct, wrong, _rewarded, confiscated) =
            ledger.evaluate_predictions("test/zone", 5, 0, 0);

        assert_eq!(correct, 0);
        assert_eq!(wrong, 1);
        assert_eq!(confiscated, 100 * BASE_UNITS_PER_BEAT);

        // Alice doesn't get stake back
        let alice_after = ledger.accounts.get(&alice_hash).unwrap().available;
        assert_eq!(alice_after, alice_before);
        // Pool increased by confiscated stake
        assert_eq!(ledger.conservation_pool, pool_before + 100 * BASE_UNITS_PER_BEAT);
        // Prediction marked as wrong
        assert_eq!(ledger.predictions.get("pred-1").unwrap().outcome, Some(false));
    }

    #[test]
    fn test_evaluate_predictions_volume_within_margin() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        // Mint + pool
        let m0 = types::mint_metadata(500 * BASE_UNITS_PER_BEAT, &genesis_hash, "bootstrap");
        let r0 = make_record_with_pk("mint-0", &genesis_pk(), 0.5, m0);
        let o0 = extract_ledger_op(&r0).unwrap().unwrap();
        let m_pool = types::pool_fund_metadata(200 * BASE_UNITS_PER_BEAT);
        let r_pool = make_record_with_pk("pool-1", &genesis_pk(), 0.6, m_pool);
        let o_pool = extract_ledger_op(&r_pool).unwrap().unwrap();
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Alice predicts 100 records in the zone
        let m2 = types::predict_metadata(
            50 * BASE_UNITS_PER_BEAT,
            "test/zone",
            10,
            &types::PredictionClaim::Volume,
            100,
        );
        let r2 = make_record_with_pk("pred-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let mut ledger = derive_ledger(&[(r0, o0), (r_pool, o_pool), (r1, o1), (r2, o2)], &genesis_hash).unwrap();

        // Actual: 110 records. |110-100|/110 = 0.09 < 0.20 margin → CORRECT
        let (correct, wrong, _, _) = ledger.evaluate_predictions("test/zone", 10, 110, 5);
        assert_eq!(correct, 1);
        assert_eq!(wrong, 0);
    }

    #[test]
    fn test_evaluate_predictions_volume_outside_margin() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Alice predicts 100 records
        let m2 = types::predict_metadata(
            50 * BASE_UNITS_PER_BEAT,
            "test/zone",
            10,
            &types::PredictionClaim::Volume,
            100,
        );
        let r2 = make_record_with_pk("pred-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let mut ledger = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash).unwrap();

        // Actual: 200 records. |200-100|/200 = 0.50 > 0.20 margin → WRONG
        let (correct, wrong, _, _) = ledger.evaluate_predictions("test/zone", 10, 200, 5);
        assert_eq!(correct, 0);
        assert_eq!(wrong, 1);
    }

    #[test]
    fn test_evaluate_different_zone_not_affected() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Alice predicts about "zone_a"
        let m2 = types::predict_metadata(
            100 * BASE_UNITS_PER_BEAT,
            "zone_a",
            5,
            &types::PredictionClaim::Active,
            1,
        );
        let r2 = make_record_with_pk("pred-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let mut ledger = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash).unwrap();

        // Evaluate "zone_b" epoch 5 — Alice's prediction for zone_a should NOT be affected
        let (correct, wrong, _, _) = ledger.evaluate_predictions("zone_b", 5, 10, 3);
        assert_eq!(correct, 0);
        assert_eq!(wrong, 0);
        assert!(ledger.predictions.get("pred-1").unwrap().outcome.is_none());
    }

    #[test]
    fn test_evaluate_predictions_conservation() {
        // Verify total supply conservation: predict stake that's confiscated
        // goes to pool, and the total beat supply doesn't change.
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::predict_metadata(
            100 * BASE_UNITS_PER_BEAT,
            "test/zone",
            5,
            &types::PredictionClaim::Active,
            1,
        );
        let r2 = make_record_with_pk("pred-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let mut ledger = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash).unwrap();

        // Total supply = 1000 beat (all minted to Alice, 100 locked in prediction, 900 available)
        let total_before = ledger.total_supply;

        // Wrong prediction — stake goes to pool
        ledger.evaluate_predictions("test/zone", 5, 0, 0);

        // Conservation: total_supply unchanged, pool absorbed the stake
        assert_eq!(ledger.total_supply, total_before);
        let alice = ledger.accounts.get(&alice_hash).unwrap();
        // Alice's available + pool should equal total supply
        assert_eq!(alice.available + ledger.conservation_pool, total_before);
    }

    #[test]
    fn test_prediction_confiscation_pool_overflow_conservation() {
        // Regression test: when conservation pool is at cap, confiscated prediction
        // stakes must be refunded to the predictor (not silently lost).
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        let m2 = types::predict_metadata(
            100 * BASE_UNITS_PER_BEAT,
            "test/zone",
            5,
            &types::PredictionClaim::Active,
            1,
        );
        let r2 = make_record_with_pk("pred-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let mut ledger = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash).unwrap();

        // Fill pool to capacity
        ledger.conservation_pool = ledger.pool_cap();
        let total_before = ledger.total_supply;
        let alice_before = ledger.accounts.get(&alice_hash).unwrap().available;

        // Wrong prediction — pool is full, overflow must go back to predictor
        let (correct, wrong, _, confiscated) = ledger.evaluate_predictions("test/zone", 5, 0, 0);
        assert_eq!(correct, 0);
        assert_eq!(wrong, 1);
        assert_eq!(confiscated, 0); // nothing actually entered pool

        // Conservation: total supply unchanged
        assert_eq!(ledger.total_supply, total_before);

        // Alice gets her stake back (pool couldn't absorb it)
        let alice_after = ledger.accounts.get(&alice_hash).unwrap().available;
        assert_eq!(alice_after, alice_before + 100 * BASE_UNITS_PER_BEAT);
    }

    // ─── Sandbox Prediction Tests ─────────────────────────────────

    #[test]
    fn test_sandbox_predict_zero_stake() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(100 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Zero-cost prediction in sandbox zone
        let m2 = types::predict_metadata(
            0,
            "sandbox/experiments",
            5,
            &types::PredictionClaim::Active,
            1,
        );
        let r2 = make_record_with_pk("pred-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let ledger = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash).unwrap();
        let alice = ledger.accounts.get(&alice_hash).unwrap();
        // Balance unchanged — no stake locked
        assert_eq!(alice.available, 100 * BASE_UNITS_PER_BEAT);
        // Prediction registered
        assert_eq!(ledger.predictions.len(), 1);
        assert_eq!(ledger.predictions.get("pred-1").unwrap().amount, 0);
    }

    #[test]
    fn test_sandbox_predict_below_min_ok() {
        // Sandbox zones accept predictions below MIN_PREDICTION_STAKE
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(100 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // 1 beat prediction in sandbox (below MIN_PREDICTION_STAKE of 10)
        let m2 = types::predict_metadata(
            BASE_UNITS_PER_BEAT,
            "sandbox/test",
            5,
            &types::PredictionClaim::Volume,
            50,
        );
        let r2 = make_record_with_pk("pred-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let ledger = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash).unwrap();
        let alice = ledger.accounts.get(&alice_hash).unwrap();
        // 1 beat locked
        assert_eq!(alice.available, 99 * BASE_UNITS_PER_BEAT);
    }

    #[test]
    fn test_real_zone_rejects_below_min() {
        // Non-sandbox zones still reject below MIN_PREDICTION_STAKE
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(100 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // 1 beat prediction in real zone — should fail
        let m2 = types::predict_metadata(
            BASE_UNITS_PER_BEAT,
            "medical/eu",
            5,
            &types::PredictionClaim::Active,
            1,
        );
        let r2 = make_record_with_pk("pred-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_sandbox_evaluate_no_economic_effect() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let m1 = types::mint_metadata(100 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m1);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Zero-cost sandbox prediction
        let m2 = types::predict_metadata(
            0,
            "sandbox/test",
            5,
            &types::PredictionClaim::Active,
            1,
        );
        let r2 = make_record_with_pk("pred-1", &alice_pk(), 2.0, m2);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let mut ledger = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash).unwrap();
        let pool_before = ledger.conservation_pool;
        let alice_before = ledger.accounts.get(&alice_hash).unwrap().available;

        // Correct prediction — but no economic effect (zero stake)
        let (correct, wrong, rewarded, confiscated) =
            ledger.evaluate_predictions("sandbox/test", 5, 10, 3);
        assert_eq!(correct, 1);
        assert_eq!(wrong, 0);
        assert_eq!(rewarded, 0);
        assert_eq!(confiscated, 0);

        // Balance and pool unchanged
        assert_eq!(ledger.accounts.get(&alice_hash).unwrap().available, alice_before);
        assert_eq!(ledger.conservation_pool, pool_before);
        // But prediction is marked as correct
        assert_eq!(ledger.predictions.get("pred-1").unwrap().outcome, Some(true));
    }

    #[test]
    fn test_xzone_lock_tracks_in_cross_zone_state() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        let mut ledger = LedgerState::new();

        // Mint to alice
        let meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let rec = make_record_with_pk("mint-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut ledger, &rec, &op, &genesis_hash).unwrap();

        // XZone lock from alice to bob
        let meta = types::xzone_lock_metadata(100 * BASE_UNITS_PER_BEAT, &bob_hash, "0", "1");
        let rec = make_record_with_pk("lock-1", &alice_pk(), 100.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut ledger, &rec, &op, &alice_hash).unwrap();

        // Verify cross_zone state tracks it
        assert_eq!(ledger.cross_zone.locked_count(), 1);
        assert_eq!(ledger.pending_xzone_locked, 100 * BASE_UNITS_PER_BEAT);
        assert!(ledger.cross_zone.get("lock-1").is_some());
    }

    /// Defense-in-depth: an XZoneLock whose transfer_id already exists in
    /// cross_zone.pending must fail CLOSED — reject with no debit and no
    /// pending_xzone_locked bump. The prior code debited + bumped the tracker
    /// THEN swallowed lock_transfer's dup Err, stranding `amount` in
    /// pending_xzone_locked with no releasable transfer (claim/abort/refund only
    /// act on pending entries). transfer_id == record.id, so the apply_op
    /// head-guard normally makes this unreachable; we pre-seed cross_zone to
    /// simulate that guard being bypassed and pin the fail-closed ordering.
    #[test]
    fn xzone_lock_duplicate_transfer_id_fails_closed_no_strand() {
        use crate::ZoneId;
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        let mut ledger = LedgerState::new();

        // Mint to alice so the balance check passes and we actually reach
        // lock_transfer (not short-circuit on insufficient balance).
        let meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let rec = make_record_with_pk("mint-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut ledger, &rec, &op, &genesis_hash).unwrap();

        // Pre-seed cross_zone with an entry keyed by the lock record's id, so
        // lock_transfer will see a duplicate transfer_id. Different zone pair —
        // the dup check is purely on transfer_id, independent of zones.
        ledger
            .cross_zone
            .lock_transfer(
                "lock-dup".into(),
                "someone".into(),
                "else".into(),
                7,
                ZoneId::from_legacy(2),
                ZoneId::from_legacy(3),
                50.0,
                [0u8; 32],
            )
            .unwrap();
        // Snapshot alice's account + the tracker AFTER the mint, BEFORE the dup —
        // compare-after proves the rejected op left them byte-identical without
        // depending on what mint set (mint bumps the recipient's tx_count too).
        let pending_before = ledger.pending_xzone_locked; // 0 — the seed bumps total_locked, not this tracker
        let (avail_before, tx_before, sent_before) = {
            let a = ledger.accounts.get(&alice_hash).unwrap();
            (a.available, a.tx_count, a.total_sent)
        };

        // Apply the colliding XZoneLock from alice.
        let meta = types::xzone_lock_metadata(100 * BASE_UNITS_PER_BEAT, &bob_hash, "0", "1");
        let dup_rec = make_record_with_pk("lock-dup", &alice_pk(), 100.0, meta);
        let dup_op = extract_ledger_op(&dup_rec).unwrap().unwrap();
        let result = apply_op(&mut ledger, &dup_rec, &dup_op, &alice_hash);

        // Fail-closed: rejected, alice's account untouched, tracker NOT stranded.
        assert!(result.is_err(), "duplicate XZoneLock must be rejected, got {result:?}");
        let a = ledger.accounts.get(&alice_hash).unwrap();
        assert_eq!(a.available, avail_before, "alice was debited on a rejected duplicate XZoneLock");
        assert_eq!(a.tx_count, tx_before, "rejected duplicate XZoneLock bumped alice's tx_count");
        assert_eq!(a.total_sent, sent_before, "rejected duplicate XZoneLock bumped alice's total_sent");
        assert_eq!(
            ledger.pending_xzone_locked, pending_before,
            "duplicate XZoneLock stranded amount in pending_xzone_locked"
        );
    }

    #[test]
    fn test_xzone_expired_refund() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        let mut ledger = LedgerState::new();

        // Mint to alice
        let meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let rec = make_record_with_pk("mint-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut ledger, &rec, &op, &genesis_hash).unwrap();

        let before_lock = ledger.accounts.get(&alice_hash).unwrap().available;

        // XZone lock
        let meta = types::xzone_lock_metadata(50 * BASE_UNITS_PER_BEAT, &bob_hash, "0", "1");
        let rec = make_record_with_pk("lock-1", &alice_pk(), 100.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut ledger, &rec, &op, &alice_hash).unwrap();

        assert_eq!(ledger.accounts.get(&alice_hash).unwrap().available, before_lock - 50 * BASE_UNITS_PER_BEAT);

        // Process expired — not expired yet
        let refunds = ledger.process_expired_xzone(200.0);
        assert_eq!(refunds, 0);

        // Process expired — 25h later (past 24h timeout)
        let refunds = ledger.process_expired_xzone(100.0 + 25.0 * 3600.0);
        assert_eq!(refunds, 1);

        // Alice should get her beats back
        assert_eq!(ledger.accounts.get(&alice_hash).unwrap().available, before_lock);
        assert_eq!(ledger.pending_xzone_locked, 0);
        assert_eq!(ledger.cross_zone.locked_count(), 0);
    }

    #[test]
    fn test_xzone_claim_updates_cross_zone_state() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        let mut ledger = LedgerState::new();

        // Mint to alice
        let meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let rec = make_record_with_pk("mint-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut ledger, &rec, &op, &genesis_hash).unwrap();

        // XZone lock
        let meta = types::xzone_lock_metadata(100 * BASE_UNITS_PER_BEAT, &bob_hash, "0", "1");
        let lock_rec = make_record_with_pk("lock-1", &alice_pk(), 100.0, meta);
        let op = extract_ledger_op(&lock_rec).unwrap().unwrap();
        apply_op(&mut ledger, &lock_rec, &op, &alice_hash).unwrap();

        // Simulate epoch seal by attaching a valid merkle proof (M7) +
        // a 1-of-1 finality witness (Phase 5 makes finality mandatory at claim).
        let merkle_root = {
            use crate::crypto::hash::sha3_256;
            use crate::accounting::cross_zone::ProofSibling;
            let leaf = lock_rec.record_hash();
            let sibling = sha3_256(b"sibling");
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&leaf);
            combined[32..].copy_from_slice(&sibling);
            let root = sha3_256(&combined);
            let proof = vec![ProofSibling { hash: sibling, is_right: true }];
            ledger.cross_zone.set_proof("lock-1", proof, root).unwrap();
            root
        };
        {
            use crate::ZoneId;
            let zone_a = ZoneId::from_legacy(0);
            let w = crate::identity::Identity::generate(
                crate::identity::EntityType::Device,
                crate::identity::CryptoProfile::ProfileB,
            ).unwrap();
            let pks = vec![w.public_key.clone()];
            let (committee_hash, c_proofs) =
                crate::accounting::cross_zone::build_committee_proofs(&pks);
            let msg = crate::accounting::cross_zone::xzone_finality_signable_bytes(
                &zone_a, 1, &merkle_root, &committee_hash,
            );
            let sig = crate::accounting::cross_zone::SealFinalityWitness {
                witness_pk: w.public_key.clone(),
                signature: w.sign(&msg).unwrap(),
                committee_proof: c_proofs.get(&w.public_key).cloned().unwrap(),
            };
            ledger.cross_zone
                .set_finality_witnesses("lock-1", vec![sig], committee_hash, 1, 1)
                .unwrap();
        }

        // XZone claim by bob
        let meta = types::xzone_claim_metadata("lock-1", 100 * BASE_UNITS_PER_BEAT, &bob_hash);
        let rec = make_record_with_pk("claim-1", &bob_pk(), 200.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut ledger, &rec, &op, &bob_hash).unwrap();

        // Cross-zone state should show claimed
        assert_eq!(ledger.cross_zone.locked_count(), 0);
        assert_eq!(ledger.pending_xzone_locked, 0);
        let transfer = ledger.cross_zone.get("lock-1").unwrap();
        assert_eq!(transfer.status, crate::accounting::cross_zone::TransferStatus::Claimed);
    }

    /// Bootstrap-equivalence regression gate for the `CrossZoneState`
    /// `#[serde(skip)]` fork (internal design notes).
    ///
    /// Pre-fix `CrossZoneState` was `#[serde(skip)]`, so a snapshot-bootstrapped
    /// node started with an EMPTY `pending`. An `XZoneClaim` for a transfer
    /// locked + sealed before the snapshot then rejected ("transfer not found")
    /// on the bootstrapped node but APPLIED on a since-genesis node → divergent
    /// recipient balance + `pending_xzone_locked` + account-SMT root → permanent
    /// silent fork. This test serializes the pre-claim ledger (exactly what the
    /// snapshot bootstrap path does), then applies the SAME sealed claim on both
    /// the live and the round-tripped ledger and asserts identical balances +
    /// SMT root. Pre-fix it fails (booted node rejects the claim); with the fix
    /// it passes (`pending` survives the round-trip).
    #[test]
    fn bootstrap_equivalence_xzone_claim_fork() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        // Build a ledger with a sealed, Locked cross-zone transfer (zone 0 → 1):
        // mint → XZoneLock → attach merkle proof (M7) + 1-of-1 finality witness.
        let mut pre = LedgerState::new();

        let meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let rec = make_record_with_pk("mint-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut pre, &rec, &op, &genesis_hash).unwrap();

        let meta = types::xzone_lock_metadata(100 * BASE_UNITS_PER_BEAT, &bob_hash, "0", "1");
        let lock_rec = make_record_with_pk("lock-1", &alice_pk(), 100.0, meta);
        let op = extract_ledger_op(&lock_rec).unwrap().unwrap();
        apply_op(&mut pre, &lock_rec, &op, &alice_hash).unwrap();

        let merkle_root = {
            use crate::crypto::hash::sha3_256;
            use crate::accounting::cross_zone::ProofSibling;
            let leaf = lock_rec.record_hash();
            let sibling = sha3_256(b"sibling");
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&leaf);
            combined[32..].copy_from_slice(&sibling);
            let root = sha3_256(&combined);
            let proof = vec![ProofSibling { hash: sibling, is_right: true }];
            pre.cross_zone.set_proof("lock-1", proof, root).unwrap();
            root
        };
        {
            use crate::ZoneId;
            let zone_a = ZoneId::from_legacy(0);
            let w = crate::identity::Identity::generate(
                crate::identity::EntityType::Device,
                crate::identity::CryptoProfile::ProfileB,
            ).unwrap();
            let pks = vec![w.public_key.clone()];
            let (committee_hash, c_proofs) =
                crate::accounting::cross_zone::build_committee_proofs(&pks);
            let msg = crate::accounting::cross_zone::xzone_finality_signable_bytes(
                &zone_a, 1, &merkle_root, &committee_hash,
            );
            let sig = crate::accounting::cross_zone::SealFinalityWitness {
                witness_pk: w.public_key.clone(),
                signature: w.sign(&msg).unwrap(),
                committee_proof: c_proofs.get(&w.public_key).cloned().unwrap(),
            };
            pre.cross_zone
                .set_finality_witnesses("lock-1", vec![sig], committee_hash, 1, 1)
                .unwrap();
        }

        // The sealed claim by bob — applied identically on both paths.
        let claim_meta =
            types::xzone_claim_metadata("lock-1", 100 * BASE_UNITS_PER_BEAT, &bob_hash);
        let claim_rec = make_record_with_pk("claim-1", &bob_pk(), 200.0, claim_meta);
        let claim_op = extract_ledger_op(&claim_rec).unwrap().unwrap();

        // Path A — since genesis: pending is live, claim applies, bob is credited.
        let mut ledger_a = pre.clone();
        let _ = apply_op(&mut ledger_a, &claim_rec, &claim_op, &bob_hash);

        // Path B — snapshot bootstrap: round-trip the pre-claim ledger through the
        // snapshot serde format (pre-fix this dropped CrossZoneState to empty),
        // then apply the same claim.
        let wire = serde_json::to_string(&pre).expect("serialize ledger snapshot");
        let mut booted: LedgerState =
            serde_json::from_str(&wire).expect("deserialize ledger snapshot");
        booted.cross_zone.recount_status();
        let _ = apply_op(&mut booted, &claim_rec, &claim_op, &bob_hash);

        // Sanity: the claim MUST succeed on the since-genesis path, else the test
        // is vacuous (both paths reject and trivially "agree").
        assert_eq!(
            ledger_a.balance(&bob_hash),
            100 * BASE_UNITS_PER_BEAT,
            "claim did not apply on the since-genesis path — fixture is broken"
        );

        // Equivalence: a bootstrapped node MUST reach the same state.
        assert_eq!(
            ledger_a.balance(&bob_hash),
            booted.balance(&bob_hash),
            "bob balance diverged across bootstrap: since-genesis={} bootstrapped={} \
             — the cross-zone pending transfer did not survive the snapshot",
            ledger_a.balance(&bob_hash),
            booted.balance(&bob_hash)
        );
        assert_eq!(
            ledger_a.balance(&alice_hash),
            booted.balance(&alice_hash),
            "alice balance diverged across bootstrap"
        );
        assert_eq!(
            ledger_a.pending_xzone_locked, booted.pending_xzone_locked,
            "pending_xzone_locked diverged across bootstrap: since-genesis={} bootstrapped={}",
            ledger_a.pending_xzone_locked, booted.pending_xzone_locked
        );

        // The sealed value is the account-SMT root; assert it directly where the
        // node-core merkle code is compiled in.
        #[cfg(feature = "node-core")]
        {
            let root_a = crate::network::account_merkle::root_over_accounts(&ledger_a.accounts)
                .expect("root A");
            let root_b = crate::network::account_merkle::root_over_accounts(&booted.accounts)
                .expect("root B");
            assert_eq!(root_a, root_b, "sealed account-SMT root diverged across bootstrap");
        }
    }

    /// Co-fix (c), internal design notes: the expired
    /// timeout refund now flows through the signed `XZoneTimeoutRefund` record
    /// instead of the old ungated in-loop `process_expired_xzone` mutation (which
    /// forked because each seal-eligible node ran it at a different wall-clock
    /// `now` and followers never ran it at all). Pins that the record applies
    /// IDENTICALLY on a since-genesis node and a snapshot-bootstrapped node — same
    /// sender balance, same `pending_xzone_locked`, same account-SMT root — and
    /// that re-delivery never double-credits.
    #[test]
    fn bootstrap_equivalence_xzone_timeout_refund_fork() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        // Build a ledger with an UNSEALED, Locked cross-zone transfer (0 → 1):
        // mint → XZoneLock with no proof attached. pending_xzone_locked = 100 beat.
        let mut pre = LedgerState::new();

        let meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let rec = make_record_with_pk("mint-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut pre, &rec, &op, &genesis_hash).unwrap();

        let lock_ts = 100.0;
        let meta = types::xzone_lock_metadata(100 * BASE_UNITS_PER_BEAT, &bob_hash, "0", "1");
        let lock_rec = make_record_with_pk("lock-1", &alice_pk(), lock_ts, meta);
        let op = extract_ledger_op(&lock_rec).unwrap().unwrap();
        apply_op(&mut pre, &lock_rec, &op, &alice_hash).unwrap();

        assert_eq!(pre.balance(&alice_hash), 900 * BASE_UNITS_PER_BEAT);
        assert_eq!(pre.pending_xzone_locked, 100 * BASE_UNITS_PER_BEAT);

        // The genesis authority computes the expired-unsealed refund batch at a
        // wall-clock past the 24h claim window and freezes it into a record.
        let now = lock_ts + crate::accounting::cross_zone::CLAIM_TIMEOUT_SECS + 1.0;
        let batch = pre
            .cross_zone
            .compute_expired_refund_batch(now, 5, "0")
            .expect("expired unsealed lock must produce a refund batch");
        assert_eq!(batch.refunds.len(), 1, "exactly one expired transfer");
        let refund_rec = make_record_with_pk(
            "xzone-refund-1",
            &genesis_pk(),
            now,
            types::xzone_refund_batch_metadata(&batch),
        );
        let refund_op = extract_ledger_op(&refund_rec).unwrap().unwrap();

        // Path A — since genesis: pending is live, refund applies, alice credited.
        let mut ledger_a = pre.clone();
        apply_op(&mut ledger_a, &refund_rec, &refund_op, &genesis_hash).unwrap();

        // Path B — snapshot bootstrap: round-trip the pre-refund ledger through the
        // snapshot serde format, then apply the SAME refund record.
        let wire = serde_json::to_string(&pre).expect("serialize ledger snapshot");
        let mut booted: LedgerState =
            serde_json::from_str(&wire).expect("deserialize ledger snapshot");
        booted.cross_zone.recount_status();
        apply_op(&mut booted, &refund_rec, &refund_op, &genesis_hash).unwrap();

        // Sanity: the refund MUST apply on the since-genesis path (else vacuous).
        assert_eq!(
            ledger_a.balance(&alice_hash),
            1_000 * BASE_UNITS_PER_BEAT,
            "refund did not credit alice on the since-genesis path — fixture broken"
        );
        assert_eq!(ledger_a.pending_xzone_locked, 0, "pending not released on refund");

        // Equivalence across bootstrap.
        assert_eq!(
            ledger_a.balance(&alice_hash),
            booted.balance(&alice_hash),
            "alice balance diverged across bootstrap: since-genesis={} bootstrapped={}",
            ledger_a.balance(&alice_hash),
            booted.balance(&alice_hash),
        );
        assert_eq!(
            ledger_a.pending_xzone_locked, booted.pending_xzone_locked,
            "pending_xzone_locked diverged across bootstrap"
        );

        // Inner idempotency: a SECOND batch (distinct record id) that lists the
        // same — now Refunded — transfer is skipped per-entry, no double-credit.
        // Bypasses any record-id dedup and exercises apply_refund_batch's status
        // re-check directly.
        let refund_rec2 = make_record_with_pk(
            "xzone-refund-2",
            &genesis_pk(),
            now + 120.0,
            types::xzone_refund_batch_metadata(&batch),
        );
        let refund_op2 = extract_ledger_op(&refund_rec2).unwrap().unwrap();
        let mut replay = ledger_a.clone();
        apply_op(&mut replay, &refund_rec2, &refund_op2, &genesis_hash).unwrap();
        assert_eq!(
            replay.balance(&alice_hash),
            1_000 * BASE_UNITS_PER_BEAT,
            "a second refund batch double-credited alice"
        );
        assert_eq!(replay.pending_xzone_locked, 0);

        #[cfg(feature = "node-core")]
        {
            let root_a = crate::network::account_merkle::root_over_accounts(&ledger_a.accounts)
                .expect("root A");
            let root_b = crate::network::account_merkle::root_over_accounts(&booted.accounts)
                .expect("root B");
            assert_eq!(root_a, root_b, "account-SMT root diverged across bootstrap");
        }
    }

    /// Co-fix (c): the refund batch EXCLUDES sealed transfers (they refund only
    /// via the XZoneAbort committee path), and the apply path SKIPS any listed
    /// transfer a CLAIM/Abort resolved between emit and apply (skip-missing, not
    /// reject-whole) so a late claim can never be double-refunded.
    #[test]
    fn xzone_timeout_refund_excludes_sealed_and_skips_resolved() {
        use crate::ZoneId;
        use crate::crypto::hash::sha3_256;
        use crate::accounting::cross_zone::{CrossZoneState, ProofSibling, TransferStatus};

        let now_expired = 100.0 + crate::accounting::cross_zone::CLAIM_TIMEOUT_SECS + 1.0;

        // Sealed transfers are excluded from the batch.
        let mut cz = CrossZoneState::new();
        cz.lock_transfer(
            "t-sealed".into(), "alice".into(), "bob".into(), 50,
            ZoneId::from_legacy(0), ZoneId::from_legacy(1), 100.0, [0u8; 32],
        )
        .unwrap();
        cz.set_proof(
            "t-sealed",
            vec![ProofSibling { hash: sha3_256(b"s"), is_right: true }],
            sha3_256(b"root"),
        )
        .unwrap();
        assert!(
            cz.compute_expired_refund_batch(now_expired, 1, "0").is_none(),
            "sealed transfers must NOT enter the timeout-refund batch (abort path only)"
        );

        // An unsealed expired transfer DOES enter the batch.
        let mut cz = CrossZoneState::new();
        cz.lock_transfer(
            "t-unsealed".into(), "alice".into(), "bob".into(), 50,
            ZoneId::from_legacy(0), ZoneId::from_legacy(1), 100.0, [0u8; 32],
        )
        .unwrap();
        let batch = cz
            .compute_expired_refund_batch(now_expired, 1, "0")
            .expect("unsealed expired lock must produce a batch");
        assert_eq!(batch.refunds, vec![("t-unsealed".into(), "alice".into(), 50u64)]);

        // apply skips a transfer resolved (Claimed) since emit.
        cz.pending.get_mut("t-unsealed").unwrap().status = TransferStatus::Claimed;
        assert!(
            cz.apply_refund_batch(&batch).is_empty(),
            "a Claimed transfer must be skipped, not refunded again"
        );

        // apply credits a still-Locked-unsealed transfer exactly once, then no-ops.
        let mut cz = CrossZoneState::new();
        cz.lock_transfer(
            "t2".into(), "alice".into(), "bob".into(), 50,
            ZoneId::from_legacy(0), ZoneId::from_legacy(1), 100.0, [0u8; 32],
        )
        .unwrap();
        let batch = cz.compute_expired_refund_batch(now_expired, 1, "0").unwrap();
        assert_eq!(
            cz.apply_refund_batch(&batch),
            vec![("alice".into(), 50u64)],
            "first apply refunds exactly once"
        );
        assert!(
            cz.apply_refund_batch(&batch).is_empty(),
            "second apply is a no-op (already Refunded)"
        );
        assert_eq!(cz.total_locked, 0, "total_locked released exactly once");
    }

    /// Co-fix (b), internal design notes: a SEALED
    /// cross-zone lock stuck ~30d past expiry under a dead dest committee is
    /// hard-refunded via a signed XZoneStaleReap record, applied IDENTICALLY on a
    /// since-genesis node and a snapshot-bootstrapped node. Also pins the
    /// mutual-exclusion with the timeout-refund batch (sealed → reap, never
    /// refund) and the not-yet-30d guard.
    #[test]
    fn bootstrap_equivalence_xzone_stale_reap_fork() {
        use crate::crypto::hash::sha3_256;
        use crate::accounting::cross_zone::ProofSibling;

        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        // mint → XZoneLock (0 → 1) → attach a Merkle proof (SEALED).
        let mut pre = LedgerState::new();
        let meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let rec = make_record_with_pk("mint-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut pre, &rec, &op, &genesis_hash).unwrap();

        let lock_ts = 100.0;
        let meta = types::xzone_lock_metadata(100 * BASE_UNITS_PER_BEAT, &bob_hash, "0", "1");
        let lock_rec = make_record_with_pk("lock-1", &alice_pk(), lock_ts, meta);
        let op = extract_ledger_op(&lock_rec).unwrap().unwrap();
        apply_op(&mut pre, &lock_rec, &op, &alice_hash).unwrap();
        pre.cross_zone
            .set_proof(
                "lock-1",
                vec![ProofSibling { hash: sha3_256(b"s"), is_right: true }],
                sha3_256(b"root"),
            )
            .unwrap();
        assert_eq!(pre.pending_xzone_locked, 100 * BASE_UNITS_PER_BEAT);

        // A sealed transfer is NOT eligible for the timeout refund (unsealed only)
        // even long past expiry — it can ONLY leave via abort or this reaper.
        let past_24h = lock_ts + crate::accounting::cross_zone::CLAIM_TIMEOUT_SECS + 1.0;
        assert!(
            pre.cross_zone.compute_expired_refund_batch(past_24h, 1, "0").is_none(),
            "sealed transfer must not be in the timeout-refund batch"
        );
        // Not yet 30d past expiry → not reap-eligible.
        assert!(
            pre.cross_zone.compute_stale_reap_batch(past_24h, 1, "0").is_none(),
            "sealed transfer must not reap before the 30d horizon"
        );

        // 30d+ past expiry → the genesis authority freezes the reap batch.
        let now = lock_ts
            + crate::accounting::cross_zone::CLAIM_TIMEOUT_SECS
            + crate::accounting::cross_zone::REAP_HORIZON_SECS
            + 1.0;
        let batch = pre
            .cross_zone
            .compute_stale_reap_batch(now, 7, "0")
            .expect("sealed lock past 30d must produce a reap batch");
        assert_eq!(batch.refunds.len(), 1);
        let reap_rec = make_record_with_pk(
            "xzone-reap-1",
            &genesis_pk(),
            now,
            types::xzone_reap_batch_metadata(&batch),
        );
        let reap_op = extract_ledger_op(&reap_rec).unwrap().unwrap();

        // Path A — since genesis.
        let mut ledger_a = pre.clone();
        apply_op(&mut ledger_a, &reap_rec, &reap_op, &genesis_hash).unwrap();

        // Path B — snapshot bootstrap.
        let wire = serde_json::to_string(&pre).expect("serialize");
        let mut booted: LedgerState = serde_json::from_str(&wire).expect("deserialize");
        booted.cross_zone.recount_status();
        apply_op(&mut booted, &reap_rec, &reap_op, &genesis_hash).unwrap();

        // Sanity + equivalence.
        assert_eq!(
            ledger_a.balance(&alice_hash),
            1_000 * BASE_UNITS_PER_BEAT,
            "reap did not refund alice on the since-genesis path — fixture broken"
        );
        assert_eq!(ledger_a.pending_xzone_locked, 0, "pending not released on reap");
        assert_eq!(
            ledger_a.balance(&alice_hash),
            booted.balance(&alice_hash),
            "alice balance diverged across bootstrap"
        );
        assert_eq!(
            ledger_a.pending_xzone_locked, booted.pending_xzone_locked,
            "pending_xzone_locked diverged across bootstrap"
        );

        #[cfg(feature = "node-core")]
        {
            let root_a = crate::network::account_merkle::root_over_accounts(&ledger_a.accounts)
                .expect("root A");
            let root_b = crate::network::account_merkle::root_over_accounts(&booted.accounts)
                .expect("root B");
            assert_eq!(root_a, root_b, "account-SMT root diverged across bootstrap");
        }
    }

    #[test]
    fn test_xzone_claim_rejected_without_proof() {
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        let mut ledger = LedgerState::new();

        // Mint to alice
        let meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let rec = make_record_with_pk("mint-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut ledger, &rec, &op, &genesis_hash).unwrap();

        // XZone lock (no proof attached — epoch seal hasn't happened)
        let meta = types::xzone_lock_metadata(100 * BASE_UNITS_PER_BEAT, &bob_hash, "0", "1");
        let rec = make_record_with_pk("lock-1", &alice_pk(), 100.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut ledger, &rec, &op, &alice_hash).unwrap();

        // XZone claim should fail — no merkle proof (M7)
        let meta = types::xzone_claim_metadata("lock-1", 100 * BASE_UNITS_PER_BEAT, &bob_hash);
        let rec = make_record_with_pk("claim-1", &bob_pk(), 200.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        let result = apply_op(&mut ledger, &rec, &op, &bob_hash);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not yet committed to epoch seal"));
    }

    /// Gap 2 end-to-end: real XZoneLock `apply_op` → real
    /// `attach_xzone_proofs_from_seal` against a populated `ParsedEpochSeal` →
    /// real XZoneClaim `apply_op`. Asserts invariants at every boundary.
    /// Earlier tests fake the epoch seal via `cross_zone.set_proof` — this
    /// one exercises the actual seal-processing code path that runs in
    /// ingest.rs and epoch.rs.
    #[cfg(feature = "node-core")]
    #[test]
    fn test_xzone_end_to_end_lock_seal_claim() {
        use crate::network::epoch::{attach_xzone_proofs_from_seal, ParsedEpochSeal};
        use crate::network::sync::MerkleTree;
        use crate::accounting::cross_zone::TransferStatus;
        use crate::ZoneId;
        use crate::crypto::hash::sha3_256;

        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        let mut ledger = LedgerState::new();

        // ── Mint 1000 beat to alice
        let meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let rec = make_record_with_pk("mint-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut ledger, &rec, &op, &genesis_hash).unwrap();
        let alice_before = ledger.accounts.get(&alice_hash).unwrap().available;
        assert_eq!(alice_before, 1_000 * BASE_UNITS_PER_BEAT);

        // ── Alice submits XZoneLock (zone 0 → zone 1, 100 beat to bob)
        let lock_amount = 100 * BASE_UNITS_PER_BEAT;
        let meta = types::xzone_lock_metadata(lock_amount, &bob_hash, "0", "1");
        let lock_rec = make_record_with_pk("lock-e2e", &alice_pk(), 100.0, meta);
        let op = extract_ledger_op(&lock_rec).unwrap().unwrap();
        apply_op(&mut ledger, &lock_rec, &op, &alice_hash).unwrap();

        assert_eq!(
            ledger.accounts.get(&alice_hash).unwrap().available,
            alice_before - lock_amount,
            "alice.available debited by lock amount"
        );
        assert_eq!(
            ledger.pending_xzone_locked, lock_amount,
            "pending_xzone_locked tracks in-flight amount"
        );
        let pending = ledger
            .cross_zone
            .get("lock-e2e")
            .expect("lock registered in cross_zone.pending");
        assert_eq!(pending.status, TransferStatus::Locked);
        assert!(
            pending.merkle_proof.is_empty(),
            "proof must be empty before seal processed"
        );

        // ── Claim BEFORE seal must fail (M7 proof-required guard)
        let claim_meta = types::xzone_claim_metadata("lock-e2e", lock_amount, &bob_hash);
        let claim_rec_early =
            make_record_with_pk("claim-early", &bob_pk(), 150.0, claim_meta.clone());
        let op = extract_ledger_op(&claim_rec_early).unwrap().unwrap();
        let err = apply_op(&mut ledger, &claim_rec_early, &op, &bob_hash)
            .expect_err("claim without proof must fail");
        assert!(err.to_string().contains("not yet committed to epoch seal"));

        // ── Build a ParsedEpochSeal for zone 0 containing the lock's record_hash,
        //    then run attach_xzone_proofs_from_seal — the exact call ingest.rs
        //    makes when it observes a peer's seal.
        let lock_hash = lock_rec.record_hash();
        let other_hash = sha3_256(b"unrelated-record");
        let mut hashes = vec![lock_hash, other_hash];
        hashes.sort();
        let merkle_root = MerkleTree::root(&hashes);

        let seal = ParsedEpochSeal {
            zone: ZoneId::from_legacy(0),
            epoch_number: 1,
            start: 0.0,
            end: 200.0,
            record_count: hashes.len() as u64,
            merkle_root,
            previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes: hashes,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };
        let proofed = attach_xzone_proofs_from_seal(&mut ledger, &seal);
        assert_eq!(proofed, 1, "exactly one pending lock must have proof attached");

        let sealed = ledger.cross_zone.get("lock-e2e").unwrap();
        assert!(!sealed.merkle_proof.is_empty(), "proof populated post-seal");
        assert_eq!(
            sealed.source_merkle_root, merkle_root,
            "stored root matches seal root"
        );
        assert_eq!(sealed.status, TransferStatus::Locked);

        // Phase 5 (2026-04-28): claim_transfer requires a finality witness
        // quorum. The legacy `attach_xzone_proofs_from_seal` only attaches
        // an inclusion proof; production also runs the `_with_finality`
        // bundler. This e2e test exercises the bare attach + a manual
        // finality bundling step (1-of-1 committee for cheapness — matches
        // the cross_zone unit-test helper).
        let zone_a = ZoneId::from_legacy(0);
        let w = crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        ).unwrap();
        let pks = vec![w.public_key.clone()];
        let (committee_hash, c_proofs) =
            crate::accounting::cross_zone::build_committee_proofs(&pks);
        let msg = crate::accounting::cross_zone::xzone_finality_signable_bytes(
            &zone_a, 1, &merkle_root, &committee_hash,
        );
        let sig = crate::accounting::cross_zone::SealFinalityWitness {
            witness_pk: w.public_key.clone(),
            signature: w.sign(&msg).unwrap(),
            committee_proof: c_proofs.get(&w.public_key).cloned().unwrap(),
        };
        ledger.cross_zone
            .set_finality_witnesses("lock-e2e", vec![sig], committee_hash, 1, 1)
            .unwrap();

        // ── Bob submits XZoneClaim — must succeed post-seal-and-finality
        let claim_rec = make_record_with_pk("claim-e2e", &bob_pk(), 250.0, claim_meta);
        let op = extract_ledger_op(&claim_rec).unwrap().unwrap();
        apply_op(&mut ledger, &claim_rec, &op, &bob_hash).unwrap();

        assert_eq!(
            ledger.accounts.get(&bob_hash).unwrap().available,
            lock_amount,
            "bob.available credited by claim amount"
        );
        assert_eq!(
            ledger.pending_xzone_locked, 0,
            "pending_xzone_locked zeroed after claim"
        );
        let claimed = ledger.cross_zone.get("lock-e2e").unwrap();
        assert_eq!(claimed.status, TransferStatus::Claimed);
        assert_eq!(
            claimed.claim_record_id.as_deref(),
            Some("claim-e2e"),
            "claim_record_id recorded"
        );

        // ── Conservation: alice's debit == bob's credit
        assert_eq!(
            ledger.accounts.get(&alice_hash).unwrap().available,
            alice_before - lock_amount,
        );
        assert_eq!(
            ledger.accounts.get(&alice_hash).unwrap().available
                + ledger.accounts.get(&bob_hash).unwrap().available,
            alice_before,
            "no beat created or destroyed across the xzone flow"
        );
    }

    /// SECURITY REGRESSION (conservation): an XZoneClaim's wire `amount` is
    /// unvalidated attacker input — validate_op only rejects zero. apply_op MUST
    /// credit the AUTHORITATIVE locked amount returned by `claim_transfer`, never
    /// the wire field. Before the fix a legitimate recipient could claim a real
    /// 100-beat sealed transfer with a wire amount of 1_000_000 beat and have the
    /// full inflated sum credited ex nihilo (no matching debit), breaking the
    /// conservation invariant. Pins: credit == locked amount, supply conserved,
    /// pending_xzone_locked released by the real (not the wire) amount.
    #[cfg(feature = "node-core")]
    #[test]
    fn xzone_claim_inflated_wire_amount_credits_only_locked_amount() {
        use crate::network::epoch::{attach_xzone_proofs_from_seal, ParsedEpochSeal};
        use crate::network::sync::MerkleTree;
        use crate::accounting::cross_zone::TransferStatus;
        use crate::ZoneId;
        use crate::crypto::hash::sha3_256;

        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        let mut ledger = LedgerState::new();

        // Mint 1000 beat to alice.
        let meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let rec = make_record_with_pk("mint-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut ledger, &rec, &op, &genesis_hash).unwrap();
        let alice_before = ledger.accounts.get(&alice_hash).unwrap().available;

        // Alice locks 100 beat to bob (zone 0 → 1).
        let lock_amount = 100 * BASE_UNITS_PER_BEAT;
        let meta = types::xzone_lock_metadata(lock_amount, &bob_hash, "0", "1");
        let lock_rec = make_record_with_pk("lock-infl", &alice_pk(), 100.0, meta);
        let op = extract_ledger_op(&lock_rec).unwrap().unwrap();
        apply_op(&mut ledger, &lock_rec, &op, &alice_hash).unwrap();
        assert_eq!(ledger.pending_xzone_locked, lock_amount);

        // Seal the lock (attach inclusion proof) + 1-of-1 finality witness —
        // mirrors test_xzone_end_to_end_lock_seal_claim.
        let lock_hash = lock_rec.record_hash();
        let mut hashes = vec![lock_hash, sha3_256(b"filler")];
        hashes.sort();
        let merkle_root = MerkleTree::root(&hashes);
        let seal = ParsedEpochSeal {
            zone: ZoneId::from_legacy(0),
            epoch_number: 1,
            start: 0.0,
            end: 200.0,
            record_count: hashes.len() as u64,
            merkle_root,
            previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes: hashes,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };
        assert_eq!(attach_xzone_proofs_from_seal(&mut ledger, &seal), 1);

        let zone_a = ZoneId::from_legacy(0);
        let w = crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        )
        .unwrap();
        let pks = vec![w.public_key.clone()];
        let (committee_hash, c_proofs) = crate::accounting::cross_zone::build_committee_proofs(&pks);
        let msg = crate::accounting::cross_zone::xzone_finality_signable_bytes(
            &zone_a,
            1,
            &merkle_root,
            &committee_hash,
        );
        let sig = crate::accounting::cross_zone::SealFinalityWitness {
            witness_pk: w.public_key.clone(),
            signature: w.sign(&msg).unwrap(),
            committee_proof: c_proofs.get(&w.public_key).cloned().unwrap(),
        };
        ledger
            .cross_zone
            .set_finality_witnesses("lock-infl", vec![sig], committee_hash, 1, 1)
            .unwrap();

        // Bob submits an XZoneClaim whose WIRE amount is 1_000_000 beat — four
        // orders of magnitude over the 100 beat actually locked. The claim is
        // otherwise fully valid (real transfer_id, correct recipient, sealed +
        // finalized), so every cryptographic gate passes.
        let inflated = 1_000_000 * BASE_UNITS_PER_BEAT;
        assert!(inflated > lock_amount);
        let claim_meta = types::xzone_claim_metadata("lock-infl", inflated, &bob_hash);
        let claim_rec = make_record_with_pk("claim-infl", &bob_pk(), 250.0, claim_meta);
        let op = extract_ledger_op(&claim_rec).unwrap().unwrap();
        apply_op(&mut ledger, &claim_rec, &op, &bob_hash).unwrap();

        // Bob is credited the LOCKED amount, not the inflated wire amount.
        assert_eq!(
            ledger.accounts.get(&bob_hash).unwrap().available,
            lock_amount,
            "claim must credit the locked amount, NOT the inflated wire amount",
        );
        // Conservation: no beat created across the whole flow.
        assert_eq!(
            ledger.accounts.get(&alice_hash).unwrap().available
                + ledger.accounts.get(&bob_hash).unwrap().available,
            alice_before,
            "no beat created or destroyed by the inflated claim",
        );
        assert_eq!(
            ledger.pending_xzone_locked, 0,
            "pending_xzone_locked released by the real amount, not saturated by wire",
        );
        assert_eq!(
            ledger.cross_zone.get("lock-infl").unwrap().status,
            TransferStatus::Claimed,
        );
    }

    // ── Gap 2 sealed-abort apply path ─────────────────────────────────────

    /// End-to-end: lock → seal → set finality witnesses (zone A) → submit
    /// XZoneAbort with B-committee proof → verify alice gets refunded and
    /// status moves to Aborted. Exercises the parser, validate stub, and
    /// apply path all together.
    #[cfg(feature = "node-core")]
    #[test]
    fn test_xzone_abort_e2e_refunds_sender() {
        use crate::network::epoch::{attach_xzone_proofs_from_seal, ParsedEpochSeal};
        use crate::network::sync::MerkleTree;
        use crate::accounting::cross_zone::{
            build_committee_proofs, xzone_abort_signable_bytes, SealFinalityWitness,
            TransferStatus,
        };
        use crate::ZoneId;

        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        let mut ledger = LedgerState::new();

        let meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let rec = make_record_with_pk("mint-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut ledger, &rec, &op, &genesis_hash).unwrap();
        let alice_before = ledger.accounts.get(&alice_hash).unwrap().available;

        // Lock 100 beat into a zone-0 → zone-1 transfer.
        let lock_amount = 100 * BASE_UNITS_PER_BEAT;
        let meta = types::xzone_lock_metadata(lock_amount, &bob_hash, "0", "1");
        let lock_rec = make_record_with_pk("lock-abort", &alice_pk(), 100.0, meta);
        let op = extract_ledger_op(&lock_rec).unwrap().unwrap();
        apply_op(&mut ledger, &lock_rec, &op, &alice_hash).unwrap();
        assert_eq!(
            ledger.accounts.get(&alice_hash).unwrap().available,
            alice_before - lock_amount
        );

        // Seal it via the real attach_xzone_proofs_from_seal path. After
        // this the lock has merkle_proof + source_seal_epoch populated;
        // sender-cancel/recipient-reject become unsafe and abort is the
        // only refund path short of the 24h timeout.
        let lock_hash = lock_rec.record_hash();
        let mut hashes = vec![lock_hash, crate::crypto::hash::sha3_256(b"unrelated")];
        hashes.sort();
        let merkle_root = MerkleTree::root(&hashes);
        let seal = ParsedEpochSeal {
            zone: ZoneId::from_legacy(0),
            epoch_number: 4,
            start: 0.0,
            end: 200.0,
            record_count: hashes.len() as u64,
            merkle_root,
            previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes: hashes,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };
        let proofed = attach_xzone_proofs_from_seal(&mut ledger, &seal);
        assert_eq!(proofed, 1);

        // attach_xzone_proofs_from_seal does not populate source_seal_epoch
        // on its own — production wires it via a follow-up
        // set_finality_witnesses call. Mirror that here so abort_transfer's
        // sealed-and-finalized gate is satisfied.
        ledger
            .cross_zone
            .set_finality_witnesses("lock-abort", vec![], [0u8; 32], 4, 0)
            .unwrap();

        // Build a 3-witness destination committee for zone B and produce a
        // 2/3-quorum abort proof. The witnesses don't need to be the same
        // as zone A's seal witnesses — the abort proof is a B-zone artifact.
        let w1 = crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        )
        .unwrap();
        let w2 = crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        )
        .unwrap();
        let w3 = crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        )
        .unwrap();
        let pks = vec![
            w1.public_key.clone(),
            w2.public_key.clone(),
            w3.public_key.clone(),
        ];
        let (committee_hash, proofs) = build_committee_proofs(&pks);
        let dest_zone = ZoneId::from_legacy(1);
        let source_seal_epoch = 4u64;
        let msg = xzone_abort_signable_bytes(
            "lock-abort",
            &dest_zone,
            source_seal_epoch,
            &committee_hash,
        );
        let signers: Vec<SealFinalityWitness> = [&w1, &w2]
            .iter()
            .map(|w| SealFinalityWitness {
                witness_pk: w.public_key.clone(),
                signature: w.sign(&msg).unwrap(),
                committee_proof: proofs.get(&w.public_key).cloned().unwrap(),
            })
            .collect();

        // B2 fix: simulate the seal-ingest freeze of the canonical dest-committee
        // anchor (production: attach_xzone_proofs_from_seal_with_finality reads it
        // from the source seal's xzone_dest_finality_committees map). The abort
        // apply path gates the wire committee against this; without it the abort
        // is fail-closed. Anchor matches the 3-member committee signed above.
        ledger
            .cross_zone
            .pending
            .get_mut("lock-abort")
            .unwrap()
            .dest_finality_committee = Some((committee_hash, 3));

        // Bob (the recipient) submits the abort. Could just as well be a
        // third party — the proof is the authorization.
        let abort_meta = types::xzone_abort_metadata(
            "lock-abort",
            &committee_hash,
            3,
            &signers,
        );
        let abort_rec = make_record_with_pk("abort-1", &bob_pk(), 250.0, abort_meta);
        let op = extract_ledger_op(&abort_rec).unwrap().unwrap();
        apply_op(&mut ledger, &abort_rec, &op, &bob_hash).unwrap();

        // Alice's lock-time debit has been undone; pending counter zeroed;
        // status terminal at Aborted.
        assert_eq!(
            ledger.accounts.get(&alice_hash).unwrap().available,
            alice_before,
            "alice refunded the locked amount"
        );
        assert_eq!(ledger.pending_xzone_locked, 0);
        assert_eq!(
            ledger.cross_zone.get("lock-abort").unwrap().status,
            TransferStatus::Aborted
        );
    }

    /// Same setup but with a forged (under-quorum) signer set — apply must
    /// reject and leave alice's balance debited and the transfer Locked.
    #[cfg(feature = "node-core")]
    #[test]
    fn test_xzone_abort_rejects_under_quorum_proof() {
        use crate::network::epoch::{attach_xzone_proofs_from_seal, ParsedEpochSeal};
        use crate::network::sync::MerkleTree;
        use crate::accounting::cross_zone::{
            build_committee_proofs, xzone_abort_signable_bytes, SealFinalityWitness,
            TransferStatus,
        };
        use crate::ZoneId;

        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        let mut ledger = LedgerState::new();
        let meta = types::mint_metadata(500 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let rec = make_record_with_pk("mint-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();
        apply_op(&mut ledger, &rec, &op, &genesis_hash).unwrap();

        let lock_amount = 50 * BASE_UNITS_PER_BEAT;
        let meta = types::xzone_lock_metadata(lock_amount, &bob_hash, "0", "1");
        let lock_rec = make_record_with_pk("lock-q", &alice_pk(), 100.0, meta);
        let op = extract_ledger_op(&lock_rec).unwrap().unwrap();
        apply_op(&mut ledger, &lock_rec, &op, &alice_hash).unwrap();

        let lock_hash = lock_rec.record_hash();
        let mut hashes = vec![lock_hash, crate::crypto::hash::sha3_256(b"x")];
        hashes.sort();
        let merkle_root = MerkleTree::root(&hashes);
        let seal = ParsedEpochSeal {
            zone: ZoneId::from_legacy(0),
            epoch_number: 9,
            start: 0.0,
            end: 200.0,
            record_count: hashes.len() as u64,
            merkle_root,
            previous_seal_hash: [0u8; 32],
            vrf_output: None,
            vrf_proof: None,
            record_hashes: hashes,
            zone_balance_total: None,
            zone_registry_root: None,
            zone_registry_delta: None,
            seal_zone_count: None,
            aggregator_rank: 0,
            account_smt_root: None,
            drand_pulse: None,
            xzone_dest_finality_committees: None,
        };
        attach_xzone_proofs_from_seal(&mut ledger, &seal);
        ledger
            .cross_zone
            .set_finality_witnesses("lock-q", vec![], [0u8; 32], 9, 0)
            .unwrap();

        // 1-of-3 quorum is below the 2/3 threshold.
        let w1 = crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        )
        .unwrap();
        let w2 = crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        )
        .unwrap();
        let w3 = crate::identity::Identity::generate(
            crate::identity::EntityType::Device,
            crate::identity::CryptoProfile::ProfileB,
        )
        .unwrap();
        let pks = vec![
            w1.public_key.clone(),
            w2.public_key.clone(),
            w3.public_key.clone(),
        ];
        let (committee_hash, proofs) = build_committee_proofs(&pks);
        let dest_zone = ZoneId::from_legacy(1);
        let msg = xzone_abort_signable_bytes("lock-q", &dest_zone, 9, &committee_hash);
        let signers = vec![SealFinalityWitness {
            witness_pk: w1.public_key.clone(),
            signature: w1.sign(&msg).unwrap(),
            committee_proof: proofs.get(&w1.public_key).cloned().unwrap(),
        }];

        let abort_meta = types::xzone_abort_metadata("lock-q", &committee_hash, 3, &signers);
        let abort_rec = make_record_with_pk("abort-bad", &bob_pk(), 250.0, abort_meta);
        let op = extract_ledger_op(&abort_rec).unwrap().unwrap();
        let err = apply_op(&mut ledger, &abort_rec, &op, &bob_hash)
            .expect_err("under-quorum abort must fail");
        assert!(
            err.to_string().contains("B-committee proof rejected"),
            "expected proof rejection, got: {err}"
        );

        // No balance change, no state transition.
        assert_eq!(
            ledger.accounts.get(&alice_hash).unwrap().available,
            500 * BASE_UNITS_PER_BEAT - lock_amount
        );
        assert_eq!(ledger.pending_xzone_locked, lock_amount);
        assert_eq!(
            ledger.cross_zone.get("lock-q").unwrap().status,
            TransferStatus::Locked
        );
    }


    // ── Conservation Fuzz ─────────────────────────────────────────────────

    /// Verify conservation invariant: all_balances + all_staked + conservation_pool + pending_xzone = total_supply.
    fn assert_conservation(ledger: &LedgerState, label: &str) {
        let total_balances: u64 = ledger.accounts.values().map(|a| a.available).sum();
        let total_staked: u64 = ledger.accounts.values().map(|a| a.staked).sum();
        let accounted = total_balances + total_staked + ledger.conservation_pool + ledger.pending_xzone_locked;
        assert_eq!(
            accounted, ledger.total_supply,
            "CONSERVATION VIOLATION at {label}: balances={total_balances} staked={total_staked} \
             pool={} pending_xzone={} sum={accounted} != supply={}",
            ledger.conservation_pool, ledger.pending_xzone_locked, ledger.total_supply
        );
    }

    /// Simple deterministic PRNG (xorshift64) — no external deps needed.
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self { Self(seed) }
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn range(&mut self, max: u64) -> u64 {
            if max == 0 { return 0; }
            self.next() % max
        }
    }

    /// 1000 random ledger operations with conservation check after EVERY op.
    /// Uses 5 identities: genesis + 4 users. Operations: mint, transfer, stake,
    /// unstake, witness_reward, slash, burn, pool_fund. Invalid ops are tolerated
    /// (derive_ledger_tolerant skips them) — conservation must still hold.
    #[test]
    fn test_conservation_fuzz_1000_random_ops() {
        let pks: Vec<Vec<u8>> = (0..5).map(|i| vec![i + 1; 1952]).collect();
        let hashes: Vec<String> = pks.iter().map(|pk| identity_hash(pk)).collect();
        let genesis_hash = &hashes[0];

        let mut rng = Rng::new(0xDEAD_BEEF_CAFE_1234);
        let mut ops: Vec<(ValidationRecord, ParsedLedgerOp)> = Vec::new();
        let mut ts = 1.0;
        let mut op_id = 0usize;

        // Genesis: mint 10,000 beat to each of the 4 users
        for (i, hash) in hashes.iter().enumerate().take(5).skip(1) {
            let meta = types::mint_metadata(10_000 * BASE_UNITS_PER_BEAT, hash, "genesis");
            let rec = make_record_with_pk(&format!("mint-{i}"), &pks[0], ts, meta);
            let parsed = extract_ledger_op(&rec).unwrap().unwrap();
            ops.push((rec, parsed));
            ts += 1.0;
        }

        // Fund conservation pool: 1000 beat from user 1
        {
            let meta = types::pool_fund_metadata(1_000 * BASE_UNITS_PER_BEAT);
            let rec = make_record_with_pk("pool-fund-0", &pks[1], ts, meta);
            let parsed = extract_ledger_op(&rec).unwrap().unwrap();
            ops.push((rec, parsed));
            ts += 1.0;
        }

        // Verify initial conservation
        let (ledger, _) = derive_ledger_tolerant(&ops, genesis_hash);
        assert_conservation(&ledger, "after genesis");

        // Track stake record IDs for unstaking
        let mut stake_ids: Vec<(usize, String)> = Vec::new(); // (owner_idx, record_id)

        // 1000 random operations
        for round in 0..1000 {
            op_id += 1;
            let op_type = rng.range(7); // 0-6: transfer, stake, unstake, reward, slash, burn, pool_fund
            let sender_idx = 1 + rng.range(4) as usize; // users 1-4
            let id = format!("fuzz-{op_id}");

            match op_type {
                0 => {
                    // Transfer: random amount to random user
                    let recipient_idx = 1 + rng.range(4) as usize;
                    if recipient_idx != sender_idx {
                        let amount = (rng.range(500) + 1) * BASE_UNITS_PER_BEAT; // 1-500 beat
                        let meta = types::transfer_metadata(amount, &hashes[recipient_idx], None);
                        let rec = make_record_with_pk(&id, &pks[sender_idx], ts, meta);
                        if let Ok(Some(parsed)) = extract_ledger_op(&rec) {
                            ops.push((rec, parsed));
                        }
                    }
                }
                1 => {
                    // Stake: random amount (100-500 beat)
                    let amount = (100 + rng.range(400)) * BASE_UNITS_PER_BEAT;
                    let purpose = if rng.range(2) == 0 {
                        StakePurpose::Witness
                    } else {
                        StakePurpose::Governance
                    };
                    let meta = types::stake_metadata(amount, &purpose);
                    let rec = make_record_with_pk(&id, &pks[sender_idx], ts, meta);
                    if let Ok(Some(parsed)) = extract_ledger_op(&rec) {
                        ops.push((rec, parsed));
                        stake_ids.push((sender_idx, id.clone()));
                    }
                }
                2 => {
                    // Unstake: pick a random stake (if any exist)
                    if !stake_ids.is_empty() {
                        let idx = rng.range(stake_ids.len() as u64) as usize;
                        let (owner_idx, stake_id) = &stake_ids[idx];
                        let meta = types::unstake_metadata(stake_id);
                        // Use far-future timestamp to pass cooldown
                        let rec = make_record_with_pk(&id, &pks[*owner_idx], ts + 8.0 * 86400.0, meta);
                        if let Ok(Some(parsed)) = extract_ledger_op(&rec) {
                            ops.push((rec, parsed));
                        }
                    }
                }
                3 => {
                    // Witness reward: from genesis to random user (simulates epoch reward)
                    let amount = (rng.range(10) + 1) * BASE_UNITS_PER_BEAT; // 1-10 beat
                    let meta = types::witness_reward_metadata(
                        amount, genesis_hash, &hashes[sender_idx], &format!("rec-{round}")
                    );
                    let rec = make_record_with_pk(&id, &pks[0], ts, meta);
                    if let Ok(Some(parsed)) = extract_ledger_op(&rec) {
                        ops.push((rec, parsed));
                    }
                }
                4 => {
                    // Slash: slash random user (from genesis authority)
                    let slash_amount = (rng.range(50) + 1) * BASE_UNITS_PER_BEAT; // 1-50 beat
                    let challenger_idx = 1 + rng.range(4) as usize;
                    if challenger_idx != sender_idx {
                        let meta = types::slash_metadata(
                            slash_amount, &hashes[sender_idx], &hashes[challenger_idx],
                            &[], &format!("stake-fuzz-{round}"), "fuzz-violation"
                        );
                        let rec = make_record_with_pk(&id, &pks[0], ts, meta);
                        if let Ok(Some(parsed)) = extract_ledger_op(&rec) {
                            ops.push((rec, parsed));
                        }
                    }
                }
                5 => {
                    // Burn
                    let amount = (rng.range(100) + 1) * BASE_UNITS_PER_BEAT;
                    let meta = types::burn_metadata(amount, Some("fuzz-burn"));
                    let rec = make_record_with_pk(&id, &pks[sender_idx], ts, meta);
                    if let Ok(Some(parsed)) = extract_ledger_op(&rec) {
                        ops.push((rec, parsed));
                    }
                }
                6 => {
                    // Pool fund
                    let amount = (rng.range(50) + 1) * BASE_UNITS_PER_BEAT;
                    let meta = types::pool_fund_metadata(amount);
                    let rec = make_record_with_pk(&id, &pks[sender_idx], ts, meta);
                    if let Ok(Some(parsed)) = extract_ledger_op(&rec) {
                        ops.push((rec, parsed));
                    }
                }
                _ => unreachable!(),
            }

            ts += 1.0;
        }

        // Final derivation and conservation check
        let (ledger, skipped) = derive_ledger_tolerant(&ops, genesis_hash);
        assert_conservation(&ledger, &format!("final (1000 ops, {skipped} skipped)"));

        // Also verify by re-deriving — idempotent
        let (ledger2, _) = derive_ledger_tolerant(&ops, genesis_hash);
        assert_conservation(&ledger2, "re-derive");

        // Total supply should never change from genesis
        assert_eq!(ledger.total_supply, 40_000 * BASE_UNITS_PER_BEAT,
            "total supply changed from genesis — this should be impossible");
    }

    #[test]
    fn test_assess_idle_decay_exchange_identity() {
        let mut state = LedgerState::new();
        let exchange = "exchange_hash_001".to_string();
        let staker = "staker_hash_001".to_string();

        // Setup: exchange has 100 beat, staker has 10 beat staked
        state.accounts.entry(exchange.clone()).or_default().available = 100 * BASE_UNITS_PER_BEAT;
        state.accounts.entry(staker.clone()).or_default().available = 50 * BASE_UNITS_PER_BEAT;
        state.total_supply = 150 * BASE_UNITS_PER_BEAT;

        // Classify as exchange
        state.exchange_classifier.confirmed_exchanges.insert(exchange.clone());

        // Record flows to establish churn
        let now = 1_000_000.0;
        state.idle_decay.record_inflow(&exchange, 50 * BASE_UNITS_PER_BEAT, now - 86400.0);
        state.idle_decay.record_outflow(&exchange, 30 * BASE_UNITS_PER_BEAT, now - 43200.0);
        state.idle_decay.record_balance(&exchange, 100 * BASE_UNITS_PER_BEAT, now - 86400.0);

        // Add a staker
        let stake_id = "stake-1".to_string();
        state.stakes.insert(stake_id.clone(), StakeEntry {
            record_id: stake_id.clone(),
            staker: staker.clone(),
            amount: 10 * BASE_UNITS_PER_BEAT,
            purpose: StakePurpose::Witness,
            timestamp: now - 86400.0,
            active: true,
        });
        state.total_staked = 10 * BASE_UNITS_PER_BEAT;
        state.staker_index.entry(staker.clone()).or_default().push(stake_id);

        let before_exchange = state.accounts[&exchange].available;
        let before_pool = state.conservation_pool;
        let before_staker = state.accounts[&staker].available;

        // Compute the frozen batch (pure) then apply it (Option A record path) —
        // proves the propagation path reproduces the old in-place assess_idle_decay.
        let batch = state
            .compute_idle_decay_batch("0", 1, now, 86400.0)
            .expect("exchange owes idle_decay");
        assert!(batch.is_conserved(), "batch must be conservation-exact");
        state.apply_idle_decay_batch(&batch, now).expect("batch applies");
        let total = batch.total_debit() as u64;

        assert!(total > 0, "idle_decay should be non-zero");
        assert!(state.accounts[&exchange].available < before_exchange, "exchange balance should decrease");
        assert!(state.conservation_pool > before_pool, "conservation pool should increase");
        assert!(state.accounts[&staker].available > before_staker, "staker should receive share");

        // Conservation: idle_decay moves beats from exchange → pool + stakers.
        // Total across all accounts + pool should equal total_supply (staked not double-counted
        // because in this test staked amount was NOT deducted from available).
        let sum: u64 = state.accounts.values().map(|a| a.available).sum::<u64>()
            + state.conservation_pool;
        // IdleDecay is a redistribution: exchange lost X, pool gained pool_share, staker gained staker_share
        // So accounts + pool should equal initial accounts + initial pool = total_supply
        assert_eq!(sum, state.total_supply, "conservation invariant violated by idle_decay");
    }

    #[test]
    fn test_assess_idle_decay_multi_staker_deterministic_and_conservative() {
        // Two stakers with unequal weight (3:1). Pins the order-independent
        // distribution: each staker receives the PURE FLOOR share of its weight
        // (never a HashMap-iteration-order "last staker gets the remainder"), all
        // rounding dust lands in the Conservation Pool, and Σ credits == the debit
        // exactly. Regression guard for internal design notes H4.
        let mut state = LedgerState::new();
        let exchange = "exchange_hash_multi".to_string();
        let staker_a = "staker_a".to_string();
        let staker_b = "staker_b".to_string();

        // Balance chosen so the extreme-tier idle_decay is ODD (3_000_001), forcing
        // a 1-unit rounding remainder that must land in the pool, not a staker.
        let balance: u64 = 1_000_000_500;
        state.accounts.entry(exchange.clone()).or_default().available = balance;
        state.total_supply = balance;
        state.exchange_classifier.confirmed_exchanges.insert(exchange.clone());

        let now = 1_000_000.0;
        // churn ≈ (3e9 + 1e9) / 1e9 = 4.0 → Extreme tier (rate 0.30%/day).
        state.idle_decay.record_balance(&exchange, balance, now - 86400.0);
        state.idle_decay.record_inflow(&exchange, 3_000_000_000, now - 43200.0);
        state.idle_decay.record_outflow(&exchange, 1_000_000_000, now - 21600.0);

        for (sid, who, amt) in [
            ("stake-a", &staker_a, 3 * BASE_UNITS_PER_BEAT),
            ("stake-b", &staker_b, BASE_UNITS_PER_BEAT),
        ] {
            state.stakes.insert(sid.to_string(), StakeEntry {
                record_id: sid.to_string(),
                staker: who.clone(),
                amount: amt,
                purpose: StakePurpose::Witness,
                timestamp: now - 86400.0,
                active: true,
            });
            state.total_staked += amt;
            state.staker_index.entry(who.clone()).or_default().push(sid.to_string());
        }

        let batch = state
            .compute_idle_decay_batch("0", 1, now, 86400.0)
            .expect("exchange owes idle_decay at extreme churn");
        assert!(batch.is_conserved(), "batch must be conservation-exact");
        state.apply_idle_decay_batch(&batch, now).expect("batch applies");
        let total = batch.total_debit() as u64;
        assert!(total > 0, "idle_decay should be non-zero at extreme churn");

        // Expected split, derived from the order-independent formula.
        let pool_half = total / 2;
        let staker_share = total - pool_half;
        let total_weight = 4u128 * BASE_UNITS_PER_BEAT as u128;
        let expect_a = (staker_share as u128 * (3 * BASE_UNITS_PER_BEAT) as u128 / total_weight) as u64;
        let expect_b = (staker_share as u128 * BASE_UNITS_PER_BEAT as u128 / total_weight) as u64;
        let dust = staker_share - expect_a - expect_b;
        assert_eq!(dust, 1, "fixture is built to exercise a non-zero pool remainder");

        assert_eq!(state.accounts[&staker_a].available, expect_a, "staker A pure-floor share");
        assert_eq!(state.accounts[&staker_b].available, expect_b, "staker B pure-floor share");
        assert_eq!(state.conservation_pool, pool_half + dust, "pool gets half + all dust");

        // Conservation: nothing created or lost across the whole batch.
        let sum: u64 = state.accounts.values().map(|a| a.available).sum::<u64>()
            + state.conservation_pool;
        assert_eq!(sum, state.total_supply, "conservation invariant violated");
    }

    // ─── Option A propagation: batch determinism + apply-gate tests ─────────
    // internal design notes Commit 2.

    #[test]
    fn compute_idle_decay_batch_is_order_independent_and_canonical() {
        // Two ledgers identical except staker insertion order → byte-identical
        // batches (the BTreeMap accumulation kills the HashMap-order fork H4/H6),
        // with debits + staker_credits sorted by identity for a canonical record.
        fn build(staker_order: &[(&str, u64)]) -> crate::accounting::idle_decay::IdleDecayBatch {
            let mut state = LedgerState::new();
            let exchange = "exch".to_string();
            let balance: u64 = 1_000_000_500;
            state.accounts.entry(exchange.clone()).or_default().available = balance;
            state.total_supply = balance + 10 * BASE_UNITS_PER_BEAT;
            state.exchange_classifier.confirmed_exchanges.insert(exchange.clone());
            let now = 1_000_000.0;
            state.idle_decay.record_balance(&exchange, balance, now - 86400.0);
            state.idle_decay.record_inflow(&exchange, 3_000_000_000, now - 43200.0);
            state.idle_decay.record_outflow(&exchange, 1_000_000_000, now - 21600.0);
            for (i, (who, amt)) in staker_order.iter().enumerate() {
                let sid = format!("stake-{i}");
                state.stakes.insert(sid.clone(), StakeEntry {
                    record_id: sid.clone(), staker: who.to_string(), amount: *amt,
                    purpose: StakePurpose::Witness, timestamp: now - 86400.0, active: true,
                });
                state.total_staked += *amt;
                state.staker_index.entry(who.to_string()).or_default().push(sid);
            }
            state.compute_idle_decay_batch("0", 7, now, 86400.0).expect("owes idle_decay")
        }
        let b1 = build(&[("staker_a", 3 * BASE_UNITS_PER_BEAT), ("staker_b", BASE_UNITS_PER_BEAT)]);
        let b2 = build(&[("staker_b", BASE_UNITS_PER_BEAT), ("staker_a", 3 * BASE_UNITS_PER_BEAT)]);
        assert_eq!(b1, b2, "batch must be independent of staker insertion order");
        assert!(b1.is_conserved());
        assert_eq!(b1.epoch, 7);
        assert_eq!(b1.zone, "0");
        assert!(b1.debits.windows(2).all(|w| w[0].0 <= w[1].0), "debits sorted");
        assert!(b1.staker_credits.windows(2).all(|w| w[0].0 <= w[1].0), "staker_credits sorted");
    }

    #[test]
    fn apply_idle_decay_batch_rejects_non_conserved() {
        use crate::accounting::idle_decay::IdleDecayBatch;
        let mut state = LedgerState::new();
        state.accounts.entry("exch".into()).or_default().available = 1000;
        // debits (1000) != pool (100) + stakers (0) → conservation gate rejects
        // BEFORE any mutation.
        let bad = IdleDecayBatch {
            epoch: 1, zone: "0".into(),
            debits: vec![("exch".into(), 1000)],
            pool_credit: 100, staker_credits: vec![],
        };
        assert!(!bad.is_conserved());
        assert!(state.apply_idle_decay_batch(&bad, 1.0).is_err());
        assert_eq!(state.accounts["exch"].available, 1000, "no mutation on reject");
        assert_eq!(state.conservation_pool, 0);
    }

    #[test]
    fn apply_idle_decay_batch_rejects_debit_exceeding_balance() {
        use crate::accounting::idle_decay::IdleDecayBatch;
        let mut state = LedgerState::new();
        state.accounts.entry("exch".into()).or_default().available = 500;
        // Conserved (debit 1000 == pool 1000) but debit > live balance → fail-loud
        // (upstream divergence), all-or-nothing: no partial debit / underflow.
        let batch = IdleDecayBatch {
            epoch: 1, zone: "0".into(),
            debits: vec![("exch".into(), 1000)],
            pool_credit: 1000, staker_credits: vec![],
        };
        assert!(batch.is_conserved());
        assert!(state.apply_idle_decay_batch(&batch, 1.0).is_err());
        assert_eq!(state.accounts["exch"].available, 500, "no partial debit on reject");
        assert_eq!(state.conservation_pool, 0, "pool untouched on reject");
    }

    #[test]
    fn compute_idle_decay_batch_none_when_idle() {
        // No classified exchanges → nothing owed → None (no record emitted).
        let state = LedgerState::new();
        assert!(state.compute_idle_decay_batch("0", 1, 1_000_000.0, 86400.0).is_none());
        // Zero duration → None even with an exchange present.
        let mut s2 = LedgerState::new();
        s2.exchange_classifier.confirmed_exchanges.insert("e".into());
        s2.idle_decay.record_balance("e", 10 * BASE_UNITS_PER_BEAT, 1_000_000.0);
        assert!(s2.compute_idle_decay_batch("0", 1, 1_000_000.0, 0.0).is_none());
    }

    // ─── ARCH-1: Ledger ↔ consensus desync vulnerability reproducer ─────────
    //
    // Pins down the current (broken) behavior: ledger.apply_single_record()
    // mutates balances unconditionally, with no coupling to
    // AWCConsensus::confirmation_level. A record that never reaches
    // ConfirmationLevel::Finalized still moves beats.
    //
    // On a hostile mainnet this is a conservation-invariant violation: a
    // record with a forged or later-proven-invalid signature commits a
    // balance change that has no rollback path. On the 6-node testnet it
    // does not trip, because everyone signs everything eventually.
    //
    // This test asserts TODAY's behavior so it passes green. The ARCH-1
    // Phase 3 fix (tentative-apply → commit-on-finality → discard-on-reject)
    // will INVERT the final assertion: Alice's balance must NOT change until
    // the transfer record crosses Finalized. At that point, rename the test
    // to `test_arch_1_ledger_commits_only_on_finality` and flip the check.
    //
    // Tracking: ARCH-1 (architectural finding — the committed ledger must
    // mutate only on finality).
    #[cfg(feature = "node-core")]
    #[test]
    fn test_arch_1_ledger_mutates_while_consensus_pending() {
        use crate::network::consensus::{AWCConsensus, ConfirmationLevel};

        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());
        let bob_hash = identity_hash(&bob_pk());

        // Mint 1000 beat to Alice via genesis authority.
        let m1 = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-arch1", &genesis_pk(), 1.0, m1);

        // Alice sends 300 to Bob. Fully valid record — this is the whole
        // point: the vulnerability is structural, not crypto-level.
        let m2 = types::transfer_metadata(300 * BASE_UNITS_PER_BEAT, &bob_hash, None);
        let r2 = make_record_with_pk("xfer-arch1", &alice_pk(), 2.0, m2);
        let r2_id = r2.id.clone();

        // Apply both records through the production ledger path.
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();
        let ledger = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash).unwrap();

        // Ledger is fully mutated. Transfer is applied.
        assert_eq!(
            ledger.balance(&alice_hash),
            700 * BASE_UNITS_PER_BEAT,
            "alice balance moved at apply time"
        );
        assert_eq!(
            ledger.balance(&bob_hash),
            300 * BASE_UNITS_PER_BEAT,
            "bob received at apply time"
        );

        // Now stand up an AWCConsensus instance and feed it ZERO
        // attestations for the transfer record. This models a record that
        // has been ingested but for which witnesses never responded (e.g.
        // because the record was a forgery that real witnesses refuse to
        // sign, or because the creator crashed before propagation).
        let consensus = AWCConsensus::new();
        assert_eq!(
            consensus.confirmation_level(&r2_id),
            ConfirmationLevel::Pending,
            "no attestations fed → Pending"
        );

        // ── THE VULNERABILITY ──
        // The ledger already moved Alice's 300 to Bob even though the
        // transfer record never reached Finalized. The conservation-
        // invariant coupling that the protocol promises (§2.1 economics,
        // §11.12 protocol settle-on-finality) is not enforced.
        //
        // ARCH-1 Phase 3 will make this assertion IMPOSSIBLE to reach:
        // the ledger must stay at 1_000 / 0 until consensus fires
        // a commit callback on the transfer record.
        assert_eq!(
            ledger.balance(&alice_hash),
            700 * BASE_UNITS_PER_BEAT,
            "ARCH-1: alice balance changed without finality — \
             fix must make this branch unreachable"
        );
        assert_eq!(
            ledger.balance(&bob_hash),
            300 * BASE_UNITS_PER_BEAT,
            "ARCH-1: bob credited without finality — \
             fix must make this branch unreachable"
        );
    }

    #[test]
    fn witness_register_locks_bond_and_queues_persistence() {
        use crate::accounting::types::WITNESS_BOND_MIN;

        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        // Mint enough so alice can bond and still have liquid balance.
        let mint_amount = 5 * WITNESS_BOND_MIN;
        let m = types::mint_metadata(mint_amount, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Alice registers as a witness in zone:hel for the minimum bond.
        let wm = types::witness_register_metadata("zone:hel", WITNESS_BOND_MIN);
        let r2 = make_record_with_pk("witreg-1", &alice_pk(), 2.0, wm);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let ledger = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash).unwrap();

        let alice = ledger.accounts.get(&alice_hash).expect("alice account");
        assert_eq!(alice.available, mint_amount - WITNESS_BOND_MIN, "bond debited from available");
        assert_eq!(alice.witness_bonded, WITNESS_BOND_MIN, "bond credited to witness_bonded");
        assert!(alice.tx_count >= 1, "tx_count incremented at least once for the witness_register");

        assert_eq!(ledger.pending_witness_registrations.len(), 1, "one pending durable write queued");
        let (zone, ident, pk, bond, _epoch) = &ledger.pending_witness_registrations[0];
        assert_eq!(zone, "zone:hel");
        assert_eq!(ident, &alice_hash);
        assert_eq!(pk, &alice_pk());
        assert_eq!(*bond, WITNESS_BOND_MIN);
    }

    #[test]
    fn witness_register_rejects_underfunded_bond() {
        use crate::accounting::types::WITNESS_BOND_MIN;

        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        // Mint less than the bond floor.
        let m = types::mint_metadata(WITNESS_BOND_MIN / 2, &alice_hash, "genesis");
        let r1 = make_record_with_pk("mint-1", &genesis_pk(), 1.0, m);
        let o1 = extract_ledger_op(&r1).unwrap().unwrap();

        // Alice tries to bond more than she has.
        let wm = types::witness_register_metadata("zone:hel", WITNESS_BOND_MIN);
        let r2 = make_record_with_pk("witreg-1", &alice_pk(), 2.0, wm);
        let o2 = extract_ledger_op(&r2).unwrap().unwrap();

        let result = derive_ledger(&[(r1, o1), (r2, o2)], &genesis_hash);
        assert!(result.is_err(), "underfunded witness_register must fail");
    }

    // ─── Profile C Gap C: attestation registry tests ────────────────────────

    #[test]
    fn attestation_registry_unknown_returns_none_level() {
        let s = LedgerState::new();
        assert_eq!(
            s.attestation_level("never-seen"),
            crate::identity::AttestationLevel::None,
        );
    }

    #[test]
    fn attestation_registry_set_and_get() {
        let mut s = LedgerState::new();
        s.register_identity_attestation(
            "alice",
            crate::identity::AttestationLevel::SecureBoot,
        );
        assert_eq!(
            s.attestation_level("alice"),
            crate::identity::AttestationLevel::SecureBoot,
        );
    }

    #[test]
    fn attestation_registry_monotonic_only_upgrades() {
        let mut s = LedgerState::new();
        // Start at HardwareKey.
        s.register_identity_attestation(
            "alice",
            crate::identity::AttestationLevel::HardwareKey,
        );
        // Try to downgrade to None — must be a no-op.
        s.register_identity_attestation(
            "alice",
            crate::identity::AttestationLevel::None,
        );
        assert_eq!(
            s.attestation_level("alice"),
            crate::identity::AttestationLevel::HardwareKey,
            "attestation downgrade must be rejected — adversary spoofing lower level",
        );
        // Try to downgrade to SecureBoot (still below HardwareKey) — also no-op.
        s.register_identity_attestation(
            "alice",
            crate::identity::AttestationLevel::SecureBoot,
        );
        assert_eq!(
            s.attestation_level("alice"),
            crate::identity::AttestationLevel::HardwareKey,
        );
        // Upgrade to PUF — accepted.
        s.register_identity_attestation(
            "alice",
            crate::identity::AttestationLevel::Puf,
        );
        assert_eq!(
            s.attestation_level("alice"),
            crate::identity::AttestationLevel::Puf,
        );
    }

    #[test]
    fn attestation_registry_independent_per_identity() {
        let mut s = LedgerState::new();
        s.register_identity_attestation(
            "alice",
            crate::identity::AttestationLevel::Puf,
        );
        s.register_identity_attestation(
            "bob",
            crate::identity::AttestationLevel::None,
        );
        assert_eq!(
            s.attestation_level("alice"),
            crate::identity::AttestationLevel::Puf,
        );
        assert_eq!(
            s.attestation_level("bob"),
            crate::identity::AttestationLevel::None,
        );
        // bob's record never registered? attestation_level returns None default
        assert_eq!(
            s.attestation_level("eve"),
            crate::identity::AttestationLevel::None,
        );
    }

    #[test]
    fn attestation_auto_register_via_apply_op() {
        // Genesis mint with attestation_level metadata — the creator
        // (genesis authority) should have its level recorded post-apply.
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let mut meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        meta.insert(
            crate::accounting::delegation::ATTESTATION_LEVEL_KEY.into(),
            serde_json::json!("HARDWARE_KEY"),
        );
        let rec = make_record_with_pk("mint-attest-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();

        let ledger = derive_ledger(&[(rec, op)], &genesis_hash).unwrap();
        assert_eq!(
            ledger.attestation_level(&genesis_hash),
            crate::identity::AttestationLevel::HardwareKey,
        );
    }

    #[test]
    fn attestation_auto_register_omitted_metadata_is_none() {
        // Plain mint with no attestation_level metadata — creator stays at None.
        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let meta = types::mint_metadata(1_000 * BASE_UNITS_PER_BEAT, &alice_hash, "genesis");
        let rec = make_record_with_pk("mint-noattest-1", &genesis_pk(), 1.0, meta);
        let op = extract_ledger_op(&rec).unwrap().unwrap();

        let ledger = derive_ledger(&[(rec, op)], &genesis_hash).unwrap();
        assert_eq!(
            ledger.attestation_level(&genesis_hash),
            crate::identity::AttestationLevel::None,
        );
    }

    // Conservation Pool helpers.
    // Three top-level pub fn sync helpers on LedgerState (pool_cap / pool_headroom /
    // pool_monthly_remaining + record_pool_disbursement / circulating_supply) had ZERO direct
    // test coverage before this. They encode the economics §2.4 monthly disbursement
    // cap and the conservation-invariant floor; pin them so a future constant tweak must
    // update the test.

    #[test]
    fn batch_r_pool_cap_and_headroom_pin_conservation_pool_max_fraction_formula() {
        // Pins the economics §2.4 hard-cap formula: pool_cap = CONSERVATION_POOL_MAX_FRACTION
        // (0.10) × total_supply, and pool_headroom = pool_cap - conservation_pool with
        // saturating_sub. A regression that switched `as u64` casting or dropped the
        // saturating_sub would either inflate cap or panic on overfill.
        let mut ledger = LedgerState::new();
        ledger.total_supply = 1_000_000 * BASE_UNITS_PER_BEAT;
        let expected_cap = (1_000_000.0 * BASE_UNITS_PER_BEAT as f64 * CONSERVATION_POOL_MAX_FRACTION) as u64;
        assert_eq!(ledger.pool_cap(), expected_cap);
        assert_eq!(ledger.pool_cap(), 100_000 * BASE_UNITS_PER_BEAT);
        assert_eq!(ledger.pool_headroom(), 100_000 * BASE_UNITS_PER_BEAT);

        ledger.conservation_pool = 50_000 * BASE_UNITS_PER_BEAT;
        assert_eq!(ledger.pool_headroom(), 50_000 * BASE_UNITS_PER_BEAT);

        // Pathological overfill — pool > cap must saturate to 0, not panic.
        ledger.conservation_pool = 200_000 * BASE_UNITS_PER_BEAT;
        assert_eq!(ledger.pool_headroom(), 0);
    }

    #[test]
    fn batch_r_pool_monthly_remaining_and_record_disbursement_round_trip_pins_section_2_4_one_percent_window() {
        // Pins both branches of pool_monthly_remaining (same-window subtract vs new-window
        // full-quota reset) and the matching state mutation in record_pool_disbursement.
        // economics §2.4 caps disbursement at 1% of pool balance per 30-day window —
        // a regression in the window-rollover check would let the cap leak (either by
        // never rolling, freezing disbursement at zero, or by always rolling, allowing
        // unbounded drainage).
        const MONTH_SECS: f64 = 30.0 * 24.0 * 3600.0;
        let mut ledger = LedgerState::new();
        ledger.total_supply = 1_000_000 * BASE_UNITS_PER_BEAT;
        ledger.conservation_pool = 100_000 * BASE_UNITS_PER_BEAT;
        let monthly_cap = (100_000.0 * BASE_UNITS_PER_BEAT as f64 * 0.01) as u64;
        assert_eq!(monthly_cap, 1_000 * BASE_UNITS_PER_BEAT);

        // Fresh state — window_start=0.0, disbursed=0. Returns full 1% quota.
        assert_eq!(ledger.pool_monthly_remaining(1000.0), monthly_cap);

        // Disburse half within the window — quota shrinks to remainder.
        ledger.record_pool_disbursement(500 * BASE_UNITS_PER_BEAT, 1000.0);
        assert_eq!(ledger.pool_disbursed_window.0, 0.0); // window_start unchanged
        assert_eq!(ledger.pool_disbursed_window.1, 500 * BASE_UNITS_PER_BEAT);
        assert_eq!(
            ledger.pool_monthly_remaining(1500.0),
            monthly_cap - 500 * BASE_UNITS_PER_BEAT,
        );

        // Advance past 30 days — window rolls over, full quota restored.
        let rollover_now = 1000.0 + MONTH_SECS + 1.0;
        assert_eq!(ledger.pool_monthly_remaining(rollover_now), monthly_cap);

        // Disbursement during the new window MUST reset window_start to now and set
        // disbursed to just the new amount, not accumulate onto the stale tally.
        ledger.record_pool_disbursement(100 * BASE_UNITS_PER_BEAT, rollover_now);
        assert_eq!(ledger.pool_disbursed_window.0, rollover_now);
        assert_eq!(ledger.pool_disbursed_window.1, 100 * BASE_UNITS_PER_BEAT);
    }

    #[test]
    fn batch_r_circulating_supply_saturating_sub_pins_total_minus_staked_minus_pool_floor_zero() {
        // Pins the formula `total_supply - total_staked - conservation_pool` with
        // saturating_sub on BOTH subtractions. A regression that switched to `-`
        // would panic in debug builds on overflow; switching to `wrapping_sub` would
        // silently report enormous bogus circulating supply.
        let mut ledger = LedgerState::new();

        // Empty state — all zero, supply is zero.
        assert_eq!(ledger.circulating_supply(), 0);

        // Normal accounting — circulating = supply - staked - pool.
        ledger.total_supply = 1_000_000 * BASE_UNITS_PER_BEAT;
        ledger.total_staked = 200_000 * BASE_UNITS_PER_BEAT;
        ledger.conservation_pool = 100_000 * BASE_UNITS_PER_BEAT;
        assert_eq!(ledger.circulating_supply(), 700_000 * BASE_UNITS_PER_BEAT);

        // Pathological: staked > supply. First saturating_sub returns 0, second
        // saturating_sub on 0 - pool returns 0. Must NOT panic.
        ledger.total_supply = 100_000 * BASE_UNITS_PER_BEAT;
        ledger.total_staked = 200_000 * BASE_UNITS_PER_BEAT;
        ledger.conservation_pool = 50_000 * BASE_UNITS_PER_BEAT;
        assert_eq!(ledger.circulating_supply(), 0);
    }

    // Covering the
    // deserialization restore-path (rebuild_staker_index + all_stakers) and the
    // Profile A/B gate (register_identity_profile + is_single_sig) and the
    // prediction-pool filter (pending_predictions). These four helpers had ZERO
    // direct test coverage before this and each encodes a distinct contract
    // that a future refactor could silently break.

    #[test]
    fn batch_s_all_stakers_and_rebuild_staker_index_round_trip_pins_active_filter_and_clear() {
        // Pins the deserialization restore-path: rebuild_staker_index must (a) clear
        // any prior index state, (b) skip inactive entries, (c) group record_ids
        // by staker. Then all_stakers reads the keys of the rebuilt index. A
        // regression that dropped the `entry.active` check at ledger.rs:310 would
        // mis-include slashed/closed stakes in jury-selection candidate pools; a
        // regression that dropped the `self.staker_index.clear()` at ledger.rs:308
        // would leak ghost stakers across snapshot restores.
        let mut ledger = LedgerState::new();

        // Fresh state — no stakes, all_stakers returns empty.
        assert!(ledger.all_stakers().is_empty());

        // Pre-seed index with junk to prove rebuild clears it before re-populating.
        ledger.staker_index.insert("ghost".to_string(), vec!["junk-rid".to_string()]);
        assert_eq!(ledger.all_stakers().len(), 1); // ghost is present pre-rebuild

        // Inject three stakes across two distinct stakers, with one inactive entry
        // that MUST be filtered out by the rebuild loop.
        ledger.stakes.insert("rid-1".to_string(), StakeEntry {
            record_id: "rid-1".to_string(),
            amount: 100,
            purpose: StakePurpose::Witness,
            staker: "alice".to_string(),
            timestamp: 1.0,
            active: true,
        });
        ledger.stakes.insert("rid-2".to_string(), StakeEntry {
            record_id: "rid-2".to_string(),
            amount: 200,
            purpose: StakePurpose::Governance,
            staker: "alice".to_string(),
            timestamp: 2.0,
            active: true,
        });
        ledger.stakes.insert("rid-3".to_string(), StakeEntry {
            record_id: "rid-3".to_string(),
            amount: 50,
            purpose: StakePurpose::Storage,
            staker: "bob".to_string(),
            timestamp: 3.0,
            active: false, // inactive — must NOT appear in rebuilt index
        });

        ledger.rebuild_staker_index();

        // Ghost from pre-seed is gone; only the two distinct active stakers remain.
        let stakers: std::collections::HashSet<String> = ledger.all_stakers().into_iter().collect();
        assert_eq!(stakers.len(), 1, "bob's only stake was inactive — must be filtered");
        assert!(stakers.contains("alice"));
        assert!(!stakers.contains("bob"));
        assert!(!stakers.contains("ghost"));

        // Alice's index entry holds both her active record_ids.
        let alice_rids = ledger.staker_index.get("alice").expect("alice indexed");
        assert_eq!(alice_rids.len(), 2);
        let alice_set: std::collections::HashSet<&String> = alice_rids.iter().collect();
        assert!(alice_set.contains(&"rid-1".to_string()));
        assert!(alice_set.contains(&"rid-2".to_string()));

        // Activating bob's stake then rebuilding picks him up — confirms rebuild
        // is fully driven by current self.stakes state, not residual index data.
        ledger.stakes.get_mut("rid-3").unwrap().active = true;
        ledger.rebuild_staker_index();
        let stakers2: std::collections::HashSet<String> = ledger.all_stakers().into_iter().collect();
        assert_eq!(stakers2.len(), 2);
        assert!(stakers2.contains("bob"));
    }

    #[test]
    fn batch_s_register_identity_profile_and_is_single_sig_pin_profile_a_b_c_gate() {
        // Pins the Profile A/B gate: Profile A → dual-sig (single_sig=false), all
        // other states (Profile B, Profile C, unknown) → single_sig=true. A
        // regression that flipped the wildcard arm at ledger.rs:455 to default
        // false would let unregistered identities skip the conservative single-sig
        // transfer cap — Layer-1 economic invariant.
        let mut ledger = LedgerState::new();

        // Unknown identity → conservative default true (Profile B treatment).
        assert!(ledger.is_single_sig("unknown-id"));

        // Profile A → dual-sig → is_single_sig=false.
        ledger.register_identity_profile("alice", CryptoProfile::ProfileA);
        assert!(!ledger.is_single_sig("alice"));

        // Profile B → single-sig=true.
        ledger.register_identity_profile("bob", CryptoProfile::ProfileB);
        assert!(ledger.is_single_sig("bob"));

        // Profile C (gateway-delegated) → single-sig=true (treated as Profile B at
        // the cap layer; gateway delegation is enforced elsewhere).
        ledger.register_identity_profile("carol", CryptoProfile::ProfileC);
        assert!(ledger.is_single_sig("carol"));

        // Overwrite path: alice downgrades from A → B, is_single_sig flips
        // false → true. A regression that made register_identity_profile a
        // monotonic upgrade-only operation would silently freeze stale profiles.
        ledger.register_identity_profile("alice", CryptoProfile::ProfileB);
        assert!(ledger.is_single_sig("alice"));
        assert_eq!(ledger.identity_profiles.get("alice"), Some(&CryptoProfile::ProfileB));
    }

    #[test]
    fn batch_s_pending_predictions_filters_by_zone_epoch_and_pending_outcome() {
        // Pins the three-axis filter on pending_predictions: outcome.is_none() AND
        // zone match AND target_epoch match. A regression that dropped the outcome
        // filter at ledger.rs:507 would return already-resolved predictions and
        // double-count payouts; a regression that dropped the zone or epoch match
        // would return wrong-bucket predictions and trigger spurious payouts.
        let mut ledger = LedgerState::new();

        // Fresh state — no predictions, all queries return empty.
        assert!(ledger.pending_predictions("zone-a", 1).is_empty());

        // Inject 5 predictions covering the cross-product of dimensions:
        //   - pred-1: zone-a, epoch=1, pending → matches ("zone-a", 1)
        //   - pred-2: zone-a, epoch=1, resolved → outcome filter excludes
        //   - pred-3: zone-a, epoch=2, pending → epoch filter excludes
        //   - pred-4: zone-b, epoch=1, pending → zone filter excludes
        //   - pred-5: zone-a, epoch=1, pending → matches; tests multi-match group
        for (rid, zone, epoch, outcome) in [
            ("pred-1", "zone-a", 1u64, None),
            ("pred-2", "zone-a", 1u64, Some(true)),
            ("pred-3", "zone-a", 2u64, None),
            ("pred-4", "zone-b", 1u64, None),
            ("pred-5", "zone-a", 1u64, None),
        ] {
            ledger.predictions.insert(rid.to_string(), PredictionEntry {
                record_id: rid.to_string(),
                predictor: "alice".to_string(),
                amount: 100,
                zone: zone.to_string(),
                target_epoch: epoch,
                claim: PredictionClaim::Active,
                predicted_value: 1,
                timestamp: 1.0,
                outcome,
            });
        }

        // ("zone-a", 1) → only pred-1 and pred-5 match all three filters.
        let matches = ledger.pending_predictions("zone-a", 1);
        let ids: std::collections::HashSet<&String> =
            matches.iter().map(|p| &p.record_id).collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"pred-1".to_string()));
        assert!(ids.contains(&"pred-5".to_string()));

        // Wrong-zone query returns the lone zone-b entry only.
        let zone_b = ledger.pending_predictions("zone-b", 1);
        assert_eq!(zone_b.len(), 1);
        assert_eq!(zone_b[0].record_id, "pred-4");

        // Future-epoch query returns the lone zone-a epoch=2 entry only.
        let epoch_2 = ledger.pending_predictions("zone-a", 2);
        assert_eq!(epoch_2.len(), 1);
        assert_eq!(epoch_2[0].record_id, "pred-3");

        // Empty-match query (zone with no predictions) returns empty vec.
        assert!(ledger.pending_predictions("zone-c", 1).is_empty());
    }

    #[test]
    fn batch_u_account_state_total_and_total_with_locked_exclude_witness_bonded_pin_view_invariants() {
        // Pins the dual-view invariant on AccountState (ledger.rs:97-104):
        //   total()             = available + staked  (NO vested_locked, NO witness_bonded)
        //   total_with_locked() = available + staked + vested_locked  (still NO witness_bonded)
        //
        // The witness_bonded exclusion (commented at ledger.rs:84-92) is the load-bearing
        // contract: WitnessRegister deducts bonded beat from `available` and parks it in
        // `witness_bonded`, and BOTH balance views (SMT-account and snapshot-balance) MUST
        // continue to report the same liquid+staked figure they did before the bond. A
        // regression that added `witness_bonded` to either total would inflate witness
        // accounts' reported balance and break conservation invariants — the SMT root that
        // accounts verify against (`balance_smt.rs::root_for_balances`) would diverge from
        // what `/account/{id}` returns. The vested_locked split (in total_with_locked, out
        // of total) pins the uptime-vesting contract: vested but not yet unlocked credits
        // are visible to "full balance" views but excluded from the spendable+staked total.
        let acct = AccountState {
            available: 100,
            staked: 50,
            vested_locked: 25,
            witness_bonded: 200, // MUST be excluded from BOTH views
            // remaining fields irrelevant to the two methods under test
            total_received: 0,
            total_sent: 0,
            tx_count: 0,
            last_active: 0.0,
            uptime_secs: 0,
            inactive_days: 0,
        };

        // total() = 100 + 50 = 150 — excludes BOTH vested_locked and witness_bonded.
        assert_eq!(acct.total(), 150);
        // total_with_locked() = 100 + 50 + 25 = 175 — excludes ONLY witness_bonded.
        assert_eq!(acct.total_with_locked(), 175);

        // Defaulted AccountState reads as 0 on both views — the new-account contract.
        let zero = AccountState::default();
        assert_eq!(zero.total(), 0);
        assert_eq!(zero.total_with_locked(), 0);

        // Witness_bonded-only account stays at 0 on both views — proves the exclusion
        // even when the bonded amount is the ONLY non-zero balance field.
        let bonded_only = AccountState {
            witness_bonded: 1_000_000,
            ..AccountState::default()
        };
        assert_eq!(bonded_only.total(), 0);
        assert_eq!(bonded_only.total_with_locked(), 0);

        // Vested-only account: total=0, total_with_locked=vested — proves vested_locked
        // is the ONLY field that distinguishes the two views.
        let vested_only = AccountState {
            vested_locked: 500,
            ..AccountState::default()
        };
        assert_eq!(vested_only.total(), 0);
        assert_eq!(vested_only.total_with_locked(), 500);
    }

    #[test]
    fn batch_u_account_and_balance_and_staked_accessors_default_zero_on_unknown_pin_read_passthrough_contract() {
        // Pins the three read-only accessor methods on LedgerState (ledger.rs:378-406):
        //   account(id)   → AccountState, defaulted on unknown id
        //   balance(id)   → u64, 0 on unknown id
        //   staked(id)    → u64, 0 on unknown id
        //
        // These three are the production read-path: /balance, /account, and witness
        // selection in consensus all funnel through them. The Default::unwrap_or_default
        // / unwrap_or(0) contract is load-bearing: a regression that switched to
        // `.expect()` or `.unwrap()` would panic at runtime the first time a account
        // queried a never-active identity (every fresh account on first /balance call).
        // The mid-deposit invariant pins that `account(id)` returns the FULL state by
        // clone (not a partial view) so callers can read `vested_locked`/`witness_bonded`
        // without going through a second accessor.
        let mut ledger = LedgerState::new();

        // Unknown identity: all three accessors return defaults — never panic.
        let acct = ledger.account("never-seen");
        assert_eq!(acct.available, 0);
        assert_eq!(acct.staked, 0);
        assert_eq!(acct.vested_locked, 0);
        assert_eq!(acct.witness_bonded, 0);
        assert_eq!(ledger.balance("never-seen"), 0);
        assert_eq!(ledger.staked("never-seen"), 0);

        // Seed alice with a full account: available + staked + vested_locked.
        ledger.accounts.insert(
            "alice".to_string(),
            AccountState {
                available: 1_000,
                staked: 500,
                vested_locked: 250,
                witness_bonded: 100,
                ..AccountState::default()
            },
        );

        // account(id) returns the FULL clone — all balance fields readable in one call.
        let alice = ledger.account("alice");
        assert_eq!(alice.available, 1_000);
        assert_eq!(alice.staked, 500);
        assert_eq!(alice.vested_locked, 250);
        assert_eq!(alice.witness_bonded, 100);

        // balance(id) is the available-only view: NOT staked, NOT vested_locked.
        assert_eq!(ledger.balance("alice"), 1_000);
        // staked(id) is the staked-only view: NOT available, NOT bonded.
        assert_eq!(ledger.staked("alice"), 500);

        // Confirming once more that an unknown id read alongside the seeded one still
        // returns defaults — pins that the accessor doesn't accidentally fall through
        // to a "last-queried" cache or similar regression.
        assert_eq!(ledger.balance("bob"), 0);
        assert_eq!(ledger.staked("bob"), 0);
        let bob = ledger.account("bob");
        assert_eq!(bob.available, 0);
        assert_eq!(bob.staked, 0);
    }

    #[test]
    fn batch_u_register_identity_attestation_pins_monotonic_no_downgrade_and_attestation_level_default_none() {
        // Pins the Profile C Gap C attestation contract at ledger.rs:471-485 +
        // ledger.rs:489-497:
        //   register_identity_attestation(id, level): insert if no record, OR if new
        //     level.rank() > existing.rank() (strict upgrade). NEVER downgrades.
        //   attestation_level(id): returns AttestationLevel::None (rank 0) for unknown.
        //
        // Why this matters: a compromised gateway should not be able to roll its own
        // attestation back to NONE to slip past a "must be Software or higher" gate
        // using the same identity. The rollback is forced to require a fresh identity.
        // A regression that flipped `>=` to `<=` (or that dropped the match guard
        // entirely) would silently allow downgrade.
        use crate::identity::AttestationLevel;

        let mut ledger = LedgerState::new();

        // Unknown identity → AttestationLevel::None (rank 0). Default-on-unknown is the
        // safe default: every Gateway eligibility check that reads `>=` against a real
        // floor will reject these identities until they register at the required level.
        assert_eq!(ledger.attestation_level("never-seen"), AttestationLevel::None);
        assert_eq!(ledger.attestation_level("never-seen").rank(), 0);

        // Initial registration at Software level lands.
        ledger.register_identity_attestation("alice", AttestationLevel::Software);
        assert_eq!(ledger.attestation_level("alice"), AttestationLevel::Software);

        // Strict upgrade rank=1 → rank=3 lands (HardwareKey > Software).
        ledger.register_identity_attestation("alice", AttestationLevel::HardwareKey);
        assert_eq!(ledger.attestation_level("alice"), AttestationLevel::HardwareKey);

        // Downgrade attempt rank=3 → rank=1: REJECTED, existing level retained.
        ledger.register_identity_attestation("alice", AttestationLevel::Software);
        assert_eq!(
            ledger.attestation_level("alice"),
            AttestationLevel::HardwareKey,
            "downgrade Software<HardwareKey must be a no-op (Profile C Gap C invariant)"
        );

        // Downgrade attempt rank=3 → rank=0 (NONE): REJECTED — the slide-past-floor
        // attack the comment at ledger.rs:462-465 warns about.
        ledger.register_identity_attestation("alice", AttestationLevel::None);
        assert_eq!(
            ledger.attestation_level("alice"),
            AttestationLevel::HardwareKey,
            "downgrade-to-None on existing-Hardware identity must be a no-op"
        );

        // Equal-rank refresh rank=3 → rank=3: no-op (data unchanged either way; the
        // guard at L477 catches rank() >= so equal hits the no-op branch). This pins
        // that a flapping reporter doesn't accidentally re-trigger the insert side.
        let pre = ledger.attestation_level("alice");
        ledger.register_identity_attestation("alice", AttestationLevel::HardwareKey);
        assert_eq!(ledger.attestation_level("alice"), pre);

        // Strict upgrade from HardwareKey → Puf still works after the failed downgrades.
        ledger.register_identity_attestation("alice", AttestationLevel::Puf);
        assert_eq!(ledger.attestation_level("alice"), AttestationLevel::Puf);

        // Independent identity bob starting fresh follows the same insert-on-empty path.
        ledger.register_identity_attestation("bob", AttestationLevel::SecureBoot);
        assert_eq!(ledger.attestation_level("bob"), AttestationLevel::SecureBoot);
        // Alice's level is untouched by bob's registration — pin the keyed isolation.
        assert_eq!(ledger.attestation_level("alice"), AttestationLevel::Puf);
    }

    // Covering
    // ledger-construction zero-state pins, derive-from-empty contract,
    // stakes_for double-filter defense, and the two private prediction helpers
    // (evaluate_claim + within_margin). The sibling tests already cover pool helpers,
    // staker-index rebuild, profile gate, prediction filter, and account
    // accessors — these five axes are the remaining uncovered pure-helper
    // surface that does not require ValidationRecord construction or RocksDB.

    #[test]
    fn batch_b_ledger_state_new_and_default_initialize_with_zero_aggregates_and_empty_collections() {
        // Pins the constructor contract: LedgerState::new() ≡ LedgerState::default()
        // initializes every persistent aggregate to zero and every HashMap/Vec/HashSet
        // to empty. This is load-bearing for the cold-start path — a regression that
        // pre-seeded any field with non-zero state would corrupt conservation
        // invariants on first apply_op, since total_supply / total_staked /
        // conservation_pool / pending_xzone_locked all participate in the
        // (available + staked + pool + pending_xzone_locked == total_supply)
        // invariant verified across all accounts at every seal.
        let fresh = LedgerState::new();
        let defaulted = LedgerState::default();

        // Persistent aggregate counters — every one starts at zero.
        for s in [&fresh, &defaulted] {
            assert_eq!(s.total_supply, 0, "total_supply must start at 0");
            assert_eq!(s.total_staked, 0, "total_staked must start at 0");
            assert_eq!(s.conservation_pool, 0, "conservation_pool must start at 0");
            assert_eq!(s.records_processed, 0, "records_processed must start at 0");
            assert_eq!(s.pending_xzone_locked, 0, "pending_xzone_locked must start at 0");
            assert_eq!(s.pool_disbursed_window, (0.0, 0),
                "pool_disbursed_window must start at (0.0, 0) — first record triggers fresh-window branch");
            assert!((s.last_applied_ts - 0.0).abs() < 1e-12,
                "last_applied_ts must start at 0.0 — incremental_ledger_replay seeks from epoch 0");
        }

        // Every keyed collection starts empty — no ghost entries on cold start.
        for s in [&fresh, &defaulted] {
            assert!(s.accounts.is_empty(), "accounts must start empty");
            assert!(s.stakes.is_empty(), "stakes must start empty");
            assert!(s.identity_profiles.is_empty(), "identity_profiles must start empty");
            assert!(s.attestation_levels.is_empty(), "attestation_levels must start empty");
            assert!(s.staker_index.is_empty(), "staker_index must start empty");
            assert!(s.predictions.is_empty(), "predictions must start empty");
            assert!(s.smt_dirty.is_empty(), "smt_dirty must start empty — no rehash on cold-start flush");
            assert!(s.pending_witness_registrations.is_empty(),
                "pending_witness_registrations must start empty");
            assert!(s.applied_record_ids.is_empty(),
                "applied_record_ids must start empty — first record CF_APPLIED is empty");
        }

        // Default is just a wrapper around new() — pin equivalence on the
        // observable persistent fields. (Transient skip-fields each have their
        // own ::new() with internal state; equivalence on the persistent axes
        // is what callers depend on.)
        assert_eq!(fresh.total_supply, defaulted.total_supply);
        assert_eq!(fresh.total_staked, defaulted.total_staked);
        assert_eq!(fresh.conservation_pool, defaulted.conservation_pool);
        assert_eq!(fresh.accounts.len(), defaulted.accounts.len());
        assert_eq!(fresh.stakes.len(), defaulted.stakes.len());

        // Derived views read zero on a fresh state — confirms aggregates aren't
        // shadowed by transient cache reads.
        assert_eq!(fresh.circulating_supply(), 0,
            "circulating_supply on fresh state must be 0 (no supply, no stake, no pool)");
        assert_eq!(fresh.pool_cap(), 0,
            "pool_cap on fresh state must be 0 (cap = fraction × 0)");
        assert_eq!(fresh.pool_headroom(), 0,
            "pool_headroom on fresh state must be 0 (cap=0, saturating_sub)");
    }

    #[test]
    fn batch_b_derive_ledger_empty_records_returns_fresh_state_with_zero_records_processed() {
        // Pins the boundary case for derive_ledger at ledger.rs:713: an empty
        // record slice must produce a LedgerState observationally equivalent to
        // LedgerState::new() — no spurious genesis allocation, no records_processed
        // tick, no accounts side-effect. This is the cold-start return path before
        // any ledger records exist in the DAG (e.g., a freshly bootstrapped node
        // with only seal records and no ledger ops yet). A regression that mis-set
        // records_processed += 1 in the empty-loop case or that pre-allocated a
        // genesis account would break the (sum(balances) == total_supply)
        // invariant before the first mint lands.
        let result = derive_ledger(&[], "genesis-authority-hash");
        assert!(result.is_ok(), "derive_ledger on empty slice must succeed");
        let state = result.expect("Ok variant");

        // Aggregate counters all zero — empty loop ran zero apply_op iterations.
        assert_eq!(state.total_supply, 0,
            "no records → no mints → total_supply stays 0");
        assert_eq!(state.total_staked, 0,
            "no records → no stakes → total_staked stays 0");
        assert_eq!(state.conservation_pool, 0,
            "no records → no idle_decay/confiscation → pool stays 0");
        assert_eq!(state.records_processed, 0,
            "no records → records_processed stays 0 (no spurious tick)");
        assert_eq!(state.pending_xzone_locked, 0,
            "no records → no xzone locks → pending stays 0");

        // Collections empty — no ghost identity inserted under the genesis_authority arg.
        assert!(state.accounts.is_empty(),
            "no records → genesis_authority arg must NOT auto-seed an account");
        assert!(state.stakes.is_empty(),
            "no records → no stakes");
        assert!(state.predictions.is_empty(),
            "no records → no predictions");
        assert!(state.identity_profiles.is_empty(),
            "no records → no profile registrations");
        assert!(state.attestation_levels.is_empty(),
            "no records → no attestation registrations");

        // Genesis-authority string is ignored for the empty-slice path — even an
        // empty authority string returns the same fresh state without panic.
        let with_empty_auth = derive_ledger(&[], "").expect("empty authority must not panic");
        assert_eq!(with_empty_auth.total_supply, 0);
        assert!(with_empty_auth.accounts.is_empty());

        // Derived views all zero — confirms no skip-field caches leaked state in.
        assert_eq!(state.circulating_supply(), 0);
        assert_eq!(state.pool_cap(), 0);
        assert_eq!(state.balance("any-id"), 0);
        assert_eq!(state.staked("any-id"), 0);
    }

    #[test]
    fn batch_b_stakes_for_unknown_identity_and_inactive_double_filter_pin_defensive_active_check() {
        // Pins the two-layer defense in stakes_for at ledger.rs:432-441:
        //   1. None-branch: unknown staker → empty Vec (no panic, no allocation).
        //   2. Some-branch defensive filter: even if the staker_index points at
        //      a record_id whose StakeEntry has flipped to inactive AFTER the
        //      last rebuild, the `.filter(|s| s.active)` at L437 drops it. This
        //      protects against the race where apply_op marks a stake inactive
        //      but rebuild_staker_index hasn't run yet (e.g., between
        //      WitnessSlash apply and the next snapshot restore).
        // A regression that dropped the L437 active filter would let jury
        // selection sample slashed stakers as live witnesses — Layer-1
        // economic-correctness invariant.
        let mut ledger = LedgerState::new();

        // (1) None-branch: empty index, every query returns empty Vec.
        assert!(ledger.stakes_for("never-staked").is_empty(),
            "unknown staker on empty ledger returns empty Vec via None branch");

        // Seed an active stake; index it; verify Some-branch returns it.
        ledger.stakes.insert("rid-active".to_string(), StakeEntry {
            record_id: "rid-active".to_string(),
            amount: 100,
            purpose: StakePurpose::Witness,
            staker: "alice".to_string(),
            timestamp: 1.0,
            active: true,
        });
        ledger.rebuild_staker_index();
        let active = ledger.stakes_for("alice");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].amount, 100);

        // Unknown staker still returns empty Vec — pin the None-branch persists
        // even after the index has been populated for OTHER identities.
        assert!(ledger.stakes_for("bob").is_empty(),
            "unknown staker on populated ledger returns empty Vec");

        // (2) Defensive-filter axis: flip the stake to inactive WITHOUT
        // rebuilding the index. staker_index still points at "rid-active" but
        // the entry's .active==false. The L437 filter must drop it.
        ledger.stakes.get_mut("rid-active").expect("seeded").active = false;
        assert!(ledger.staker_index.contains_key("alice"),
            "index still maps alice → [rid-active] (no rebuild ran)");
        let post_flip = ledger.stakes_for("alice");
        assert!(post_flip.is_empty(),
            "stakes_for must drop inactive entries even when index still references them — L437 defensive filter");

        // Mixed bag: one active + one inactive under same staker — only active comes through.
        ledger.stakes.insert("rid-fresh".to_string(), StakeEntry {
            record_id: "rid-fresh".to_string(),
            amount: 250,
            purpose: StakePurpose::Governance,
            staker: "alice".to_string(),
            timestamp: 2.0,
            active: true,
        });
        ledger.rebuild_staker_index(); // alice → [rid-fresh] (rid-active filtered at rebuild time)
        // Now flip the rebuild-survivor to inactive without rebuilding.
        // Need a fresh staker that has BOTH entries indexed.
        ledger.stakes.insert("rid-bob-1".to_string(), StakeEntry {
            record_id: "rid-bob-1".to_string(), amount: 10, purpose: StakePurpose::Witness,
            staker: "bob".to_string(), timestamp: 1.0, active: true,
        });
        ledger.stakes.insert("rid-bob-2".to_string(), StakeEntry {
            record_id: "rid-bob-2".to_string(), amount: 20, purpose: StakePurpose::Witness,
            staker: "bob".to_string(), timestamp: 2.0, active: true,
        });
        ledger.rebuild_staker_index();
        // Flip rid-bob-1 inactive — defensive filter drops it; rid-bob-2 survives.
        ledger.stakes.get_mut("rid-bob-1").expect("seeded").active = false;
        let bob_active = ledger.stakes_for("bob");
        assert_eq!(bob_active.len(), 1,
            "post-flip stakes_for returns only the still-active entry");
        assert_eq!(bob_active[0].record_id, "rid-bob-2");
    }

    #[test]
    fn batch_b_evaluate_claim_dispatches_active_boolean_volume_record_count_identity_count_axes() {
        // Pins the private dispatch helper at ledger.rs:680 — `evaluate_claim`
        // routes by PredictionClaim variant and uses the correct actual-value
        // input for each branch. A regression that swapped the actual_record_count
        // and actual_identity_count args in the IdentityCount arm would silently
        // pay out predictions on the wrong axis (Sybil-vs-volume confusion at
        // the prediction-evaluation layer). The Active branch is a pure
        // boolean equivalence; the Volume and IdentityCount branches delegate
        // to within_margin against distinct fields.

        // Active: 4-corner truth table of (predicted > 0) == (actual_record_count > 0).
        // actual_identity_count argument MUST be ignored in this branch — use
        // distinct value to confirm.
        assert!(evaluate_claim(&PredictionClaim::Active, 0, 0, 99),
            "Active: predicted=0 ∧ actual_rec=0 → both 'inactive' → true");
        assert!(!evaluate_claim(&PredictionClaim::Active, 1, 0, 99),
            "Active: predicted=1 ∧ actual_rec=0 → active≠inactive → false");
        assert!(!evaluate_claim(&PredictionClaim::Active, 0, 1, 99),
            "Active: predicted=0 ∧ actual_rec=1 → inactive≠active → false");
        assert!(evaluate_claim(&PredictionClaim::Active, 5, 7, 99),
            "Active: predicted=5 ∧ actual_rec=7 → both 'active' → true");
        // Sanity: changing only identity_count must not flip the Active result.
        assert!(evaluate_claim(&PredictionClaim::Active, 5, 7, 0),
            "Active branch ignores actual_identity_count (was 99, now 0) — result unchanged");

        // Volume: delegates to within_margin(predicted, actual_record_count, 0.20).
        // predicted=100, actual_rec=100, actual_id=DIFFERENT → diff/100 = 0 → within margin → true.
        assert!(evaluate_claim(&PredictionClaim::Volume, 100, 100, 9999),
            "Volume: exact match → within margin regardless of actual_identity_count");
        // predicted=120 vs actual_rec=100 → diff=20, denom=100 → 0.20 = margin → INCLUSIVE true.
        assert!(evaluate_claim(&PredictionClaim::Volume, 120, 100, 9999),
            "Volume: diff/denom == margin must be inclusive (true)");
        // predicted=121 vs actual_rec=100 → diff=21, denom=100 → 0.21 > 0.20 → false.
        assert!(!evaluate_claim(&PredictionClaim::Volume, 121, 100, 9999),
            "Volume: diff/denom > margin → false");
        // Swap-attack test: if implementation accidentally read actual_identity_count
        // instead of actual_record_count, this would FAIL because predicted=100
        // vs actual_id=200 → diff=100, denom=200 → 0.50 > 0.20 → false. Since
        // the correct field is actual_record_count=100 → diff=0 → true.
        assert!(evaluate_claim(&PredictionClaim::Volume, 100, 100, 200),
            "Volume must read actual_record_count (100), NOT actual_identity_count (200) — axis-pin");

        // IdentityCount: delegates to within_margin(predicted, actual_identity_count, 0.20).
        // predicted=50, actual_id=50 → match → true.
        assert!(evaluate_claim(&PredictionClaim::IdentityCount, 50, 9999, 50),
            "IdentityCount: exact match → true regardless of actual_record_count");
        // Swap-attack test for the other direction: predicted=50 vs actual_id=50 → true
        // even when actual_record_count=200 (where 50 vs 200 would be far outside margin).
        assert!(evaluate_claim(&PredictionClaim::IdentityCount, 50, 200, 50),
            "IdentityCount must read actual_identity_count (50), NOT actual_record_count (200) — axis-pin");
        // Outside margin on the id axis: predicted=70 vs actual_id=50 → diff=20, denom=50 → 0.40 > 0.20 → false.
        assert!(!evaluate_claim(&PredictionClaim::IdentityCount, 70, 9999, 50),
            "IdentityCount: outside margin → false");
    }

    #[test]
    fn batch_b_within_margin_zero_actual_floor_and_inclusive_edge_symmetric_abs_diff() {
        // Pins the private margin-math helper at ledger.rs:703 — `within_margin`
        // computes |predicted - actual| / max(actual, 1) ≤ margin. Three load-bearing
        // properties: (a) the max(actual, 1) floor prevents div-by-zero on
        // zero-activity epochs, (b) the comparison is INCLUSIVE (≤ not <) — the
        // exact-margin case must be classified as "correct", (c) abs_diff is
        // symmetric in over/under prediction. A regression that switched ≤ to <
        // would shift exact-edge predictions to "wrong" and confiscate stake
        // unfairly; a regression that dropped the .max(1) would panic at runtime
        // on every zero-activity epoch's first prediction evaluation.
        // Integer margin 0.20 = 1/5 from accounting::types.
        let (mn, md) = (PREDICTION_MARGIN_NUM, PREDICTION_MARGIN_DEN);

        // (a) Zero-actual floor: denominator becomes 1, so predicted=0 → 0/1=0 → true.
        assert!(within_margin(0, 0, mn, md),
            "actual=0, predicted=0 → diff=0 → within margin (zero-activity epoch match)");
        // predicted=1 vs actual=0: diff=1, denom=max(0,1)=1, 1.0 > 0.20 → false (no panic).
        assert!(!within_margin(1, 0, mn, md),
            "actual=0, predicted=1 → diff=1, denom=1 (floor) → 1.0 > 0.20 — no div-by-zero panic");

        // (b) Inclusive-edge: diff/denom == margin must be TRUE.
        // actual=100, predicted=80 → diff=20, denom=100 → 0.20 == 0.20 → INCLUSIVE true.
        assert!(within_margin(80, 100, mn, md),
            "diff/denom == margin (exact 20%) → ≤ inclusive → true");
        // Just over the edge: diff/denom = 0.21 → false.
        assert!(!within_margin(79, 100, mn, md),
            "diff/denom == 21% → > margin → false");

        // (c) abs_diff symmetry: over-prediction and under-prediction
        // by the same amount must produce identical classification.
        assert_eq!(
            within_margin(80, 100, mn, md),
            within_margin(120, 100, mn, md),
            "abs_diff is symmetric — 80 vs 100 must match 120 vs 100",
        );
        assert_eq!(
            within_margin(79, 100, mn, md),
            within_margin(121, 100, mn, md),
            "abs_diff is symmetric on the over-edge case too",
        );
        // Both edge cases at diff=20: above and below must BOTH be true (inclusive).
        assert!(within_margin(120, 100, mn, md),
            "over-prediction at exact 20% margin → inclusive true");

        // Custom-margin pass-through pin: doubling margin to 0.40 = 2/5 lifts the
        // diff=21 case from false to true — confirms the margin args are the
        // actual comparison threshold, not ignored.
        assert!(within_margin(79, 100, 2, 5),
            "doubling margin → 21% diff now within bound → true");
        // Tightening to 0.10 = 1/10 drops the diff=20 inclusive-edge from true to false.
        assert!(!within_margin(80, 100, 1, 10),
            "tightening margin to 10% → 20% diff no longer within bound → false");
    }


    // ── §11.18 Slice 2: apply_governance_op dispatch end-to-end ────────────

    /// Integration test for the §11.18 Slice 2 wire-up at
    /// `apply_governance_op::Execute`. Bypasses the full propose→vote→settle
    /// dance by hand-seating a Passed ProtocolUpgrade proposal in the
    /// governance state, then submitting an Execute record carrying the
    /// upgrade-kind/reference-impl-hash/proposed-at-epoch metadata via
    /// `execute_protocol_upgrade_metadata()`. Verifies the dispatch path
    /// (a) calls `execute_proposal` (status flips Passed → Executed) and
    /// (b) runs `apply_protocol_upgrade_outcome` (upgrade_outcomes populated
    /// with the right wire-string row).
    #[cfg(feature = "node")]
    #[test]
    fn slice2_apply_governance_op_protocol_upgrade_dispatch_records_outcome() {
        use crate::accounting::governance::{
            execute_protocol_upgrade_metadata, EXECUTION_DELAY_SECS, Proposal,
            ProposalCategory, ProposalStatus, Vote, VoteDirection,
        };

        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let mut ledger = LedgerState::new();
        // Hand-seat a Passed ProtocolUpgrade proposal authored by Alice. The
        // 7000/3000 split clears the 0.67 HardFork threshold (for_ratio
        // = 0.70). `passed_at` plus EXECUTION_DELAY_SECS must be ≤ the
        // execute record's timestamp or `execute_proposal()` will reject.
        let voting_deadline = 1_000_000.0_f64;
        let passed_at = voting_deadline + 1.0;
        let proposal_id = "p-upgrade-int-1";
        ledger.governance.proposals.insert(
            proposal_id.to_string(),
            Proposal {
                id: proposal_id.into(),
                proposer: alice_hash.clone(),
                category: ProposalCategory::ProtocolUpgrade,
                title: "T".into(),
                description: "D".into(),
                created_at: 0.0,
                voting_deadline,
                status: ProposalStatus::Passed,
                passed_at: Some(passed_at),
                votes: vec![
                    Vote {
                        voter: "v-for".into(),
                        stake: 7000,
                        direction: VoteDirection::For,
                        voted_at: 1.0,
                        own_stake: None,
                    },
                    Vote {
                        voter: "v-against".into(),
                        stake: 3000,
                        direction: VoteDirection::Against,
                        voted_at: 1.0,
                        own_stake: None,
                    },
                ],
                committee: None,
            },
        );
        // Maintain the proposal-status counter invariant for the inserted Passed proposal.
        // Repair the counters after the manual hand-seat so the
        // execute_proposal record_status_transition has a non-zero Passed
        // count to decrement.
        ledger.governance.recount_proposal_statuses();

        // Apply the Execute record after the EXECUTION_DELAY_SECS gate has
        // elapsed. The metadata carries the upgrade kind + reference impl
        // hash + proposed-at-epoch fields that the §11.18 Slice 2 dispatch
        // path expects.
        let execute_ts = passed_at + EXECUTION_DELAY_SECS + 1.0;
        let meta = execute_protocol_upgrade_metadata(
            proposal_id,
            "hard_fork",
            "sha256:int-ref",
            42,
        );
        let exec_record = make_record_with_pk(
            "exec-rec-1",
            &alice_pk(),
            execute_ts,
            meta,
        );

        ledger
            .apply_single_record(&exec_record, &genesis_hash)
            .expect("apply_single_record must dispatch the Execute op");

        // execute_proposal flipped status from Passed → Executed.
        let p = ledger
            .governance
            .proposals
            .get(proposal_id)
            .expect("proposal must still exist after execute");
        assert_eq!(p.status, ProposalStatus::Executed);

        // §11.18 Slice 2 dispatch recorded the outcome on upgrade_outcomes
        // with the right wire shape.
        let rec = ledger
            .governance
            .upgrade_outcomes
            .get(proposal_id)
            .expect("upgrade_outcomes must hold the dispatch-path entry");
        assert_eq!(rec.proposal_id, proposal_id);
        assert_eq!(rec.kind, "hard_fork");
        assert_eq!(rec.reference_impl_hash, "sha256:int-ref");
        assert_eq!(rec.proposed_at_epoch, 42);
        assert_eq!(rec.outcome, "passed");
        // Deadline = voting_deadline + 180-day transition window per
        // §11.18 HardFork.transition_days() × 86400.
        assert_eq!(
            rec.transition_deadline_secs,
            Some(voting_deadline as u64 + 180 * 86_400)
        );
        assert_eq!(rec.recorded_at_ts, execute_ts);
    }

    /// Missing-metadata branch: Execute on a ProtocolUpgrade proposal whose
    /// record carries no `governance_upgrade_kind` field falls through to
    /// status-flip without populating upgrade_outcomes. The execute itself
    /// MUST succeed (the proposal still transitions Passed → Executed) so
    /// that a misformed metadata blob can't roll back a valid execute call.
    /// Operators inspect `upgrade_outcomes` to detect this case: a Passed →
    /// Executed proposal with NO row in upgrade_outcomes means the
    /// executing record was malformed.
    #[cfg(feature = "node")]
    #[test]
    fn slice2_apply_governance_op_protocol_upgrade_missing_metadata_skips_outcome() {
        use crate::accounting::governance::{
            execute_metadata, EXECUTION_DELAY_SECS, Proposal, ProposalCategory,
            ProposalStatus, Vote, VoteDirection,
        };

        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let mut ledger = LedgerState::new();
        let voting_deadline = 2_000_000.0_f64;
        let passed_at = voting_deadline + 1.0;
        let proposal_id = "p-upgrade-malformed-meta";
        ledger.governance.proposals.insert(
            proposal_id.to_string(),
            Proposal {
                id: proposal_id.into(),
                proposer: alice_hash.clone(),
                category: ProposalCategory::ProtocolUpgrade,
                title: "T".into(),
                description: "D".into(),
                created_at: 0.0,
                voting_deadline,
                status: ProposalStatus::Passed,
                passed_at: Some(passed_at),
                votes: vec![Vote {
                    voter: "v-for".into(),
                    stake: 9000,
                    direction: VoteDirection::For,
                    voted_at: 1.0,
                    own_stake: None,
                }],
                committee: None,
            },
        );
        // Repair the proposal-status counters after the manual hand-seat so the
        // execute_proposal record_status_transition has a non-zero Passed
        // count to decrement.
        ledger.governance.recount_proposal_statuses();

        // execute_metadata() carries ONLY governance_proposal_id — no
        // upgrade_kind / reference_impl_hash / proposed_at_epoch fields.
        let execute_ts = passed_at + EXECUTION_DELAY_SECS + 1.0;
        let meta = execute_metadata(proposal_id);
        let exec_record = make_record_with_pk(
            "exec-rec-malformed",
            &alice_pk(),
            execute_ts,
            meta,
        );

        ledger
            .apply_single_record(&exec_record, &genesis_hash)
            .expect("apply_single_record must succeed even on malformed upgrade metadata");

        // Status flipped despite missing metadata.
        let p = ledger.governance.proposals.get(proposal_id).unwrap();
        assert_eq!(p.status, ProposalStatus::Executed);
        // But upgrade_outcomes is NOT populated.
        assert!(
            !ledger.governance.upgrade_outcomes.contains_key(proposal_id),
            "malformed metadata must skip outcome recording"
        );
    }

    /// Parameter category dispatch must NOT touch upgrade_outcomes — pins
    /// that the new ProtocolUpgrade arm is properly gated on the category
    /// check and a non-protocol-upgrade Execute that happens to carry
    /// upgrade-shaped metadata doesn't accidentally write a row.
    #[cfg(feature = "node")]
    #[test]
    fn slice2_apply_governance_op_parameter_category_does_not_touch_upgrade_outcomes() {
        use crate::accounting::governance::{
            execute_protocol_upgrade_metadata, EXECUTION_DELAY_SECS, Proposal,
            ProposalCategory, ProposalStatus, Vote, VoteDirection,
        };

        let genesis_hash = identity_hash(&genesis_pk());
        let alice_hash = identity_hash(&alice_pk());

        let mut ledger = LedgerState::new();
        let voting_deadline = 3_000_000.0_f64;
        let passed_at = voting_deadline + 1.0;
        let proposal_id = "p-param-not-upgrade";
        ledger.governance.proposals.insert(
            proposal_id.to_string(),
            Proposal {
                id: proposal_id.into(),
                proposer: alice_hash,
                category: ProposalCategory::Parameter, // NOT ProtocolUpgrade
                title: "T".into(),
                description: "D".into(),
                created_at: 0.0,
                voting_deadline,
                status: ProposalStatus::Passed,
                passed_at: Some(passed_at),
                votes: vec![Vote {
                    voter: "v-for".into(),
                    stake: 9000,
                    direction: VoteDirection::For,
                    voted_at: 1.0,
                    own_stake: None,
                }],
                committee: None,
            },
        );
        // Repair the proposal-status counters after the manual hand-seat so the
        // execute_proposal record_status_transition has a non-zero Passed
        // count to decrement.
        ledger.governance.recount_proposal_statuses();

        // Construct an Execute record with the upgrade-shape metadata to
        // stress-test the category gate. Even though the metadata is upgrade-
        // shaped, the category gate must reject and upgrade_outcomes must
        // stay empty.
        let execute_ts = passed_at + EXECUTION_DELAY_SECS + 1.0;
        let meta = execute_protocol_upgrade_metadata(
            proposal_id,
            "hard_fork",
            "sha256:should-not-record",
            42,
        );
        let exec_record = make_record_with_pk(
            "exec-rec-param",
            &alice_pk(),
            execute_ts,
            meta,
        );

        ledger
            .apply_single_record(&exec_record, &genesis_hash)
            .expect("Parameter execute must succeed");

        let p = ledger.governance.proposals.get(proposal_id).unwrap();
        assert_eq!(p.status, ProposalStatus::Executed);
        assert!(
            ledger.governance.upgrade_outcomes.is_empty(),
            "Parameter category must not produce upgrade_outcomes rows"
        );
    }

    // ---- GENESIS VALIDATOR BOOTSTRAP (internal design notes) ----

    fn gv(identity: &str, stake: u64) -> crate::accounting::types::GenesisValidator {
        crate::accounting::types::GenesisValidator { identity: identity.into(), stake_micros: stake }
    }

    /// Ledger with the genesis authority holding `available` (as if the
    /// genesis mint replayed).
    fn ledger_with_authority(authority: &str, available: u64) -> LedgerState {
        let mut s = LedgerState::new();
        s.accounts.entry(authority.to_string()).or_default().available = available;
        s
    }

    #[test]
    fn genesis_validators_carve_stake_supply_conserving() {
        let auth = "aa".repeat(32);
        let v1 = "bb".repeat(32);
        let v2 = "cc".repeat(32);
        let mut s = ledger_with_authority(&auth, 10_000);
        let applied = apply_genesis_validators(
            &mut s,
            &[gv(&v1, 3_000), gv(&v2, 2_000)],
            &auth,
        );
        assert_eq!(applied, 2);
        assert_eq!(s.accounts[&auth].available, 5_000, "carved from authority");
        assert_eq!(s.accounts[&v1].staked, 3_000);
        assert_eq!(s.accounts[&v2].staked, 2_000);
        assert_eq!(s.total_staked, 5_000);
        // Total supply across accounts unchanged: 5000 + 3000 + 2000 = 10000.
        let total: u64 = s.accounts.values().map(|a| a.available + a.staked).sum();
        assert_eq!(total, 10_000, "supply conserved");
        // Stake entries carry the synthetic id + are indexed for liveness.
        assert!(s.stakes.contains_key(&format!("{GENESIS_STAKE_RECORD_PREFIX}{v1}")));
        assert!(s.staker_index.contains_key(&v1));
    }

    #[test]
    fn genesis_validators_mark_smt_dirty_f2() {
        // F-2 regression: genesis stake mutates the authority's `available` and
        // each validator's `staked` OUTSIDE apply_op, so apply_genesis_validators
        // MUST mark them dirty — otherwise the leaves never reach the persistent
        // account SMT and every seal's account_smt_root omits them, producing the
        // §6a false boot-mismatch observed on the live authority node. Pin it so a
        // refactor cannot silently drop the marks.
        let auth = "aa".repeat(32);
        let v1 = "bb".repeat(32);
        let v2 = "cc".repeat(32);
        let mut s = ledger_with_authority(&auth, 10_000);
        assert!(s.smt_dirty.is_empty());
        apply_genesis_validators(&mut s, &[gv(&v1, 3_000), gv(&v2, 2_000)], &auth);
        assert!(s.smt_dirty.contains(&auth), "authority debit must be marked dirty");
        assert!(s.smt_dirty.contains(&v1), "validator stake must be marked dirty");
        assert!(s.smt_dirty.contains(&v2), "validator stake must be marked dirty");
        // A skipped (zero-stake) validator leaves no dirty mark.
        let v3 = "dd".repeat(32);
        let before = s.smt_dirty.len();
        apply_genesis_validators(&mut s, &[gv(&v3, 0)], &auth);
        assert_eq!(s.smt_dirty.len(), before, "zero-stake validator leaves no dirty mark");
        assert!(!s.smt_dirty.contains(&v3));
    }

    #[test]
    fn genesis_validators_idempotent_and_deterministic() {
        let auth = "aa".repeat(32);
        let v1 = "bb".repeat(32);
        let set = [gv(&v1, 3_000)];
        let mut s = ledger_with_authority(&auth, 10_000);
        assert_eq!(apply_genesis_validators(&mut s, &set, &auth), 1);
        // Re-apply (rebuild / snapshot+incremental path): zero new, zero drift.
        assert_eq!(apply_genesis_validators(&mut s, &set, &auth), 0);
        assert_eq!(s.accounts[&auth].available, 7_000, "no double carve");
        assert_eq!(s.accounts[&v1].staked, 3_000, "no double stake");
        assert_eq!(s.total_staked, 3_000);

        // Determinism: independent ledgers with identical inputs converge.
        let mut s2 = ledger_with_authority(&auth, 10_000);
        apply_genesis_validators(&mut s2, &set, &auth);
        assert_eq!(s.accounts[&v1].staked, s2.accounts[&v1].staked);
        assert_eq!(s.accounts[&auth].available, s2.accounts[&auth].available);
        assert_eq!(s.total_staked, s2.total_staked);
    }

    #[test]
    fn genesis_validators_skip_underfunded_and_zero() {
        let auth = "aa".repeat(32);
        let v1 = "bb".repeat(32);
        let v2 = "cc".repeat(32);
        let mut s = ledger_with_authority(&auth, 1_000);
        // v1 exceeds the authority balance → skipped (loud log, deterministic);
        // zero-stake entry → skipped; both leave the ledger untouched.
        let applied = apply_genesis_validators(
            &mut s,
            &[gv(&v1, 5_000), gv(&v2, 0)],
            &auth,
        );
        assert_eq!(applied, 0);
        assert_eq!(s.accounts[&auth].available, 1_000);
        assert_eq!(s.total_staked, 0);
        assert!(!s.accounts.contains_key(&v2), "zero-stake validator never materializes");
    }

    #[test]
    fn genesis_validators_empty_set_is_zero_delta() {
        let auth = "aa".repeat(32);
        let mut s = ledger_with_authority(&auth, 10_000);
        let before_accounts = s.accounts.len();
        assert_eq!(apply_genesis_validators(&mut s, &[], &auth), 0);
        assert_eq!(s.accounts.len(), before_accounts);
        assert_eq!(s.total_staked, 0);
    }

    // Exercises the consensus settlement denominator, so it needs the
    // `node-core`-gated `network::consensus` module — gate it accordingly or a
    // bare default-feature `cargo test --all-targets` fails to compile.
    #[cfg(feature = "node-core")]
    #[test]
    fn genesis_validators_feed_settlement_denominator() {
        // The launch-blocker exit: genesis stakes flow into the consensus
        // settlement denominator via register_stakes_from_ledger, so a
        // record by validator A becomes finalizable once validator B attests.
        let auth = "aa".repeat(32);
        let v1 = "bb".repeat(32);
        let v2 = "cc".repeat(32);
        let mut s = ledger_with_authority(&auth, 10_000);
        apply_genesis_validators(&mut s, &[gv(&v1, 3_000), gv(&v2, 3_000)], &auth);

        let mut consensus = crate::network::consensus::AWCConsensus::new();
        consensus.register_stakes_from_ledger_with_zone_count(&s, 1);
        // Denominator is now the genesis stake — the chain can settle.
        assert!(s.total_staked > 0);
        assert_eq!(s.staked(&v1), 3_000);
        assert_eq!(s.staked(&v2), 3_000);
    }
}
