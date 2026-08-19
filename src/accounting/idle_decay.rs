//! Custodial IdleDecay — economics v0.4.1 Section 13.13.1.
//!
//! Dynamic holding cost for exchange-classified identities. Rate scales with
//! churn ratio: `(total_inflow_7d + total_outflow_7d) / avg_balance_7d`.
//!
//! Five tiers:
//! | Churn (7-day) | Rate/day | Annualized | Profile               |
//! |---------------|----------|------------|-----------------------|
//! | < 0.3         | 0.005%   | 1.83%      | Quiet custodian       |
//! | 0.3 – 0.7    | 0.01%    | 3.65%      | Active trading        |
//! | 0.7 – 1.5    | 0.05%    | 18.25%     | Heavy churn           |
//! | 1.5 – 3.0    | 0.15%    | 54.75%     | Pump-dump pattern     |
//! | > 3.0         | 0.30%    | 109.5%     | Extreme manipulation  |
//!
//! Revenue split: 50% to Conservation Pool, 50% redistributed to active stakers.
//! (Conservation invariant: no tokens are ever burned — §2.1)
//! IdleDecay applies to the exchange account, not end-users.

//!
//! Spec references:
//!   @spec economics §13.13.1

use std::collections::HashMap;

// ─── Constants ─────────────────────────────────────────────────────────────

/// Churn ratio boundaries for idle_decay tiers.
pub const CHURN_TIER_1: f64 = 0.3;
pub const CHURN_TIER_2: f64 = 0.7;
pub const CHURN_TIER_3: f64 = 1.5;
pub const CHURN_TIER_4: f64 = 3.0;

/// Daily idle_decay rates per tier (as fractions, not percentages).
pub const RATE_QUIET: f64 = 0.000_05; // 0.005%/day
pub const RATE_ACTIVE: f64 = 0.000_10; // 0.01%/day
pub const RATE_HEAVY: f64 = 0.000_50; // 0.05%/day
pub const RATE_PUMP_DUMP: f64 = 0.001_50; // 0.15%/day
pub const RATE_EXTREME: f64 = 0.003_00; // 0.30%/day

/// Fraction of idle_decay redirected to Conservation Pool (was "burned" — now recycled
/// to preserve conservation invariant per economics §2.1).
pub const POOL_FRACTION: f64 = 0.50;
/// Fraction of idle_decay redistributed to active stakers.
pub const STAKER_FRACTION: f64 = 0.50;

/// Rolling window for churn calculation (seconds).
pub const CHURN_WINDOW_SECS: f64 = 7.0 * 86_400.0; // 7 days

/// Registered exchanges pay only the base rate regardless of churn.
pub const REGISTERED_RATE: f64 = RATE_QUIET;

/// Minimum balance to bother computing idle_decay (1 beat, in base units / 10^9).
/// The bare `1_000_000` was a pre-10^9-migration leftover resolving to 0.001 beat,
/// which applied idle_decay to balances ~1000x smaller than intended.
pub const MIN_IDLE_DECAY_BALANCE: u64 = crate::accounting::types::BASE_UNITS_PER_BEAT;

// ─── Fixed-point apply path (deterministic) ──────────────────────────────────
//
// The settlement value path is computed in integer u128 — never f64 — so every
// node derives bit-identical idle_decay regardless of CPU arch or libm. Matches
// the `consensus.rs` `SETTLEMENT_Q` / governance `CONVICTION_Q` discipline; see
// internal design notes and internal design notes. The
// f64 `RATE_*` / `CHURN_TIER_*` constants above are retained for explorer/RPC
// display only.

/// Fixed-point scale: a `_q` value of `IDLE_DECAY_Q` represents the ratio 1.0.
pub const IDLE_DECAY_Q: u128 = 1_000_000_000;

/// Seconds per day — the daily-rate denominator on the integer value path.
pub const SECS_PER_DAY: u128 = 86_400;

/// Daily idle_decay rates as integer parts-per-billion (rate · `IDLE_DECAY_Q`).
/// `RATE_QUIET_PPB = 50_000` ⇔ `RATE_QUIET = 0.000_05`. A test pins each against
/// its f64 sibling so the two representations can never silently drift.
pub const RATE_QUIET_PPB: u128 = 50_000;
pub const RATE_ACTIVE_PPB: u128 = 100_000;
pub const RATE_HEAVY_PPB: u128 = 500_000;
pub const RATE_PUMP_DUMP_PPB: u128 = 1_500_000;
pub const RATE_EXTREME_PPB: u128 = 3_000_000;

/// Churn tier boundaries as `_q`-scaled integers (boundary · `IDLE_DECAY_Q`).
pub const CHURN_TIER_1_Q: u128 = 300_000_000; // 0.3
pub const CHURN_TIER_2_Q: u128 = 700_000_000; // 0.7
pub const CHURN_TIER_3_Q: u128 = 1_500_000_000; // 1.5
pub const CHURN_TIER_4_Q: u128 = 3_000_000_000; // 3.0

// ─── Types ─────────────────────────────────────────────────────────────────

/// Churn tier classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ChurnTier {
    /// < 0.3 — normal exchange behavior.
    Quiet,
    /// 0.3 – 0.7 — active trading platform.
    Active,
    /// 0.7 – 1.5 — heavy churn, possible manipulation.
    Heavy,
    /// 1.5 – 3.0 — pump-dump pattern detected.
    PumpDump,
    /// > 3.0 — extreme manipulation.
    Extreme,
}

impl ChurnTier {
    /// Classify a churn ratio into a tier.
    pub fn from_ratio(ratio: f64) -> Self {
        if ratio < CHURN_TIER_1 {
            Self::Quiet
        } else if ratio < CHURN_TIER_2 {
            Self::Active
        } else if ratio < CHURN_TIER_3 {
            Self::Heavy
        } else if ratio < CHURN_TIER_4 {
            Self::PumpDump
        } else {
            Self::Extreme
        }
    }

    /// Classify a `_q`-scaled churn ratio (churn · [`IDLE_DECAY_Q`]) into a tier.
    /// The deterministic integer twin of [`from_ratio`](Self::from_ratio) — this
    /// is the one the apply path uses; `from_ratio` is display-only.
    pub fn from_churn_q(churn_q: u128) -> Self {
        if churn_q < CHURN_TIER_1_Q {
            Self::Quiet
        } else if churn_q < CHURN_TIER_2_Q {
            Self::Active
        } else if churn_q < CHURN_TIER_3_Q {
            Self::Heavy
        } else if churn_q < CHURN_TIER_4_Q {
            Self::PumpDump
        } else {
            Self::Extreme
        }
    }

    /// Daily rate for this tier.
    pub fn daily_rate(&self) -> f64 {
        match self {
            Self::Quiet => RATE_QUIET,
            Self::Active => RATE_ACTIVE,
            Self::Heavy => RATE_HEAVY,
            Self::PumpDump => RATE_PUMP_DUMP,
            Self::Extreme => RATE_EXTREME,
        }
    }

    /// Daily rate for this tier as integer parts-per-billion (rate · [`IDLE_DECAY_Q`]).
    /// The deterministic twin of [`daily_rate`](Self::daily_rate).
    pub fn daily_rate_ppb(&self) -> u128 {
        match self {
            Self::Quiet => RATE_QUIET_PPB,
            Self::Active => RATE_ACTIVE_PPB,
            Self::Heavy => RATE_HEAVY_PPB,
            Self::PumpDump => RATE_PUMP_DUMP_PPB,
            Self::Extreme => RATE_EXTREME_PPB,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Quiet => "quiet",
            Self::Active => "active",
            Self::Heavy => "heavy",
            Self::PumpDump => "pump_dump",
            Self::Extreme => "extreme",
        }
    }
}

/// 7-day flow tracking for a single exchange identity.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FlowTracker {
    /// Timestamped inflow amounts within the window.
    inflows: Vec<(f64, u64)>,
    /// Timestamped outflow amounts within the window.
    outflows: Vec<(f64, u64)>,
    /// Timestamped balance snapshots for averaging.
    balance_snapshots: Vec<(f64, u64)>,
}

impl FlowTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of tracked entries across all vectors.
    pub fn entry_count(&self) -> usize {
        self.inflows.len() + self.outflows.len() + self.balance_snapshots.len()
    }

    /// Record an inflow (beats received by the exchange).
    pub fn record_inflow(&mut self, amount: u64, now: f64) {
        self.inflows.push((now, amount));
    }

    /// Record an outflow (beats sent by the exchange).
    pub fn record_outflow(&mut self, amount: u64, now: f64) {
        self.outflows.push((now, amount));
    }

    /// Record a balance snapshot.
    pub fn record_balance(&mut self, balance: u64, now: f64) {
        self.balance_snapshots.push((now, balance));
    }

    /// Prune entries outside the 7-day window.
    pub fn prune(&mut self, now: f64) {
        let cutoff = now - CHURN_WINDOW_SECS;
        self.inflows.retain(|(t, _)| *t >= cutoff);
        self.outflows.retain(|(t, _)| *t >= cutoff);
        self.balance_snapshots.retain(|(t, _)| *t >= cutoff);
    }

    /// Total inflow in the current window.
    pub fn total_inflow(&self, now: f64) -> u64 {
        let cutoff = now - CHURN_WINDOW_SECS;
        self.inflows
            .iter()
            .filter(|(t, _)| *t >= cutoff)
            .map(|(_, a)| *a)
            .sum()
    }

    /// Total outflow in the current window.
    pub fn total_outflow(&self, now: f64) -> u64 {
        let cutoff = now - CHURN_WINDOW_SECS;
        self.outflows
            .iter()
            .filter(|(t, _)| *t >= cutoff)
            .map(|(_, a)| *a)
            .sum()
    }

    /// Average balance over the 7-day window.
    pub fn avg_balance(&self, now: f64) -> f64 {
        let cutoff = now - CHURN_WINDOW_SECS;
        let relevant: Vec<u64> = self
            .balance_snapshots
            .iter()
            .filter(|(t, _)| *t >= cutoff)
            .map(|(_, b)| *b)
            .collect();
        if relevant.is_empty() {
            return 0.0;
        }
        relevant.iter().sum::<u64>() as f64 / relevant.len() as f64
    }

    /// Compute the 7-day churn ratio (f64, display-only).
    pub fn churn_ratio(&self, now: f64) -> f64 {
        let avg = self.avg_balance(now);
        if avg < 1.0 {
            return 0.0;
        }
        let total_flow = self.total_inflow(now) as f64 + self.total_outflow(now) as f64;
        total_flow / avg
    }

    /// Deterministic 7-day churn ratio scaled by [`IDLE_DECAY_Q`] (churn · `Q`).
    /// The apply-path twin of [`churn_ratio`](Self::churn_ratio): since
    /// `churn = total_flow / avg_balance = total_flow · count / Σ balances`,
    /// `churn_q = total_flow · count · Q / Σ balances`, computed entirely in u128
    /// (flows and balances summed in u128 — never the u64 path — so a multi-turnover
    /// exchange cannot overflow). Returns 0 on an empty/zero balance window.
    pub fn churn_q(&self, now: f64) -> u128 {
        let cutoff = now - CHURN_WINDOW_SECS;
        let mut sum_balances: u128 = 0;
        let mut count: u128 = 0;
        for (t, b) in &self.balance_snapshots {
            if *t >= cutoff {
                sum_balances += *b as u128;
                count += 1;
            }
        }
        if sum_balances == 0 || count == 0 {
            return 0;
        }
        let mut total_flow: u128 = 0;
        for (t, a) in &self.inflows {
            if *t >= cutoff {
                total_flow += *a as u128;
            }
        }
        for (t, a) in &self.outflows {
            if *t >= cutoff {
                total_flow += *a as u128;
            }
        }
        total_flow
            .saturating_mul(count)
            .saturating_mul(IDLE_DECAY_Q)
            / sum_balances
    }
}

/// Result of a idle_decay assessment.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IdleDecayAssessment {
    /// Identity being assessed.
    pub identity: String,
    /// Current churn ratio.
    pub churn_ratio: f64,
    /// Classified churn tier.
    pub tier: ChurnTier,
    /// Daily rate applied.
    pub daily_rate: f64,
    /// Whether identity is a registered exchange (capped rate).
    pub is_registered: bool,
    /// IdleDecay amount in base units (10⁻⁹ beat; field name historical) for this period.
    pub idle_decay_micros: u64,
    /// Amount redirected to Conservation Pool (50%).
    pub pool_micros: u64,
    /// Amount to distribute to stakers (50%).
    pub staker_micros: u64,
}

/// A frozen, per-epoch idle_decay batch — the payload of a `IdleDecay` system
/// record (Option A propagation, see internal design notes).
///
/// The producer computes this once per epoch from its trackers + account
/// balances and emits it as a signed record; every node applies it verbatim
/// through the standard idempotent record path, so all nodes converge on the
/// same balances and account-SMT root (closing the producer-only-mutation
/// divergence H1). Amounts are frozen integers — no node recomputes them.
///
/// **Conservation invariant:** `Σ debits == pool_credit + Σ staker_credits`.
/// Both lists are sorted by identity so the record is byte-canonical.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IdleDecayBatch {
    /// The epoch whose holding period this fee covers.
    pub epoch: u64,
    /// The zone whose seal triggered emission (audit label; not load-bearing —
    /// idle_decay is assessed globally over all classified exchanges).
    pub zone: String,
    /// `(exchange_identity_hash, debit_amount)`, sorted by identity.
    pub debits: Vec<(String, u64)>,
    /// Amount credited to the Conservation Pool (50% + all rounding dust).
    pub pool_credit: u64,
    /// `(staker_identity_hash, credit_amount)`, sorted by identity.
    pub staker_credits: Vec<(String, u64)>,
}

impl IdleDecayBatch {
    /// Σ of all exchange debits (u128 — a whale debit list cannot overflow).
    pub fn total_debit(&self) -> u128 {
        self.debits.iter().map(|(_, a)| *a as u128).sum()
    }

    /// Σ of all credits (pool + stakers).
    pub fn total_credit(&self) -> u128 {
        self.pool_credit as u128
            + self
                .staker_credits
                .iter()
                .map(|(_, a)| *a as u128)
                .sum::<u128>()
    }

    /// Σ of all staker credits.
    pub fn total_staker_credit(&self) -> u128 {
        self.staker_credits.iter().map(|(_, a)| *a as u128).sum()
    }

    /// Conservation invariant: debits exactly fund pool + staker credits.
    pub fn is_conserved(&self) -> bool {
        self.total_debit() == self.total_credit()
    }

    /// No exchange owed anything this epoch.
    pub fn is_empty(&self) -> bool {
        self.debits.is_empty()
    }
}

// ─── State ─────────────────────────────────────────────────────────────────

/// Tracks idle_decay state for all exchange-classified identities.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IdleDecayState {
    /// Per-identity flow trackers.
    trackers: HashMap<String, FlowTracker>,
    /// Registered exchanges (capped at base rate).
    registered: std::collections::HashSet<String>,
    /// Last assessment timestamp per identity.
    last_assessed: HashMap<String, f64>,
    /// Total idle_decay collected (micros).
    total_collected: u64,
    /// Total redirected to Conservation Pool (micros).
    total_pooled: u64,
    /// Total distributed to stakers (micros).
    total_distributed: u64,
}

impl IdleDecayState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a flow tracker for an identity.
    pub fn tracker_mut(&mut self, identity: &str) -> &mut FlowTracker {
        self.trackers
            .entry(identity.to_string())
            .or_default()
    }

    /// Record an inflow to an exchange identity.
    pub fn record_inflow(&mut self, identity: &str, amount: u64, now: f64) {
        self.tracker_mut(identity).record_inflow(amount, now);
    }

    /// Record an outflow from an exchange identity.
    pub fn record_outflow(&mut self, identity: &str, amount: u64, now: f64) {
        self.tracker_mut(identity).record_outflow(amount, now);
    }

    /// Record a balance snapshot for an exchange identity.
    pub fn record_balance(&mut self, identity: &str, balance: u64, now: f64) {
        self.tracker_mut(identity).record_balance(balance, now);
    }

    /// Register an exchange for the reduced-rate program.
    pub fn register_exchange(&mut self, identity: &str) {
        self.registered.insert(identity.to_string());
    }

    /// Revoke exchange registration.
    pub fn revoke_registration(&mut self, identity: &str) {
        self.registered.remove(identity);
    }

    /// Whether an identity is a registered exchange.
    pub fn is_registered(&self, identity: &str) -> bool {
        self.registered.contains(identity)
    }

    /// Assess idle_decay for an exchange identity.
    ///
    /// `balance` is the current balance in base units.
    /// `duration_secs` is the elapsed seconds the fee covers (seal-derived, not
    /// wall-clock — sub-second precision is irrelevant at a daily rate).
    /// Returns None if balance is below minimum threshold or the span is zero.
    ///
    /// The settlement value path is integer u128 — never f64 — so every node
    /// derives bit-identical idle_decay (see internal design notes). The
    /// f64 `churn_ratio` / `daily_rate` on the returned struct are display-only.
    ///
    /// This is the **pure** core (`&self`, no counter / `last_assessed` mutation):
    /// it is the apply-path source of truth that `Ledger::compute_idle_decay_batch`
    /// calls on the producer to freeze per-epoch amounts into a record. The
    /// mutating [`assess`](Self::assess) is a thin wrapper for direct callers.
    pub fn assess_amount(
        &self,
        identity: &str,
        balance: u64,
        duration_secs: u64,
        now: f64,
    ) -> Option<IdleDecayAssessment> {
        if balance < MIN_IDLE_DECAY_BALANCE || duration_secs == 0 {
            return None;
        }

        let tracker = self.trackers.get(identity)?;
        let churn_q = tracker.churn_q(now);
        let tier = ChurnTier::from_churn_q(churn_q);
        let is_registered = self.registered.contains(identity);

        // Registered exchanges always pay the base rate regardless of churn.
        let rate_ppb = if is_registered {
            RATE_QUIET_PPB
        } else {
            tier.daily_rate_ppb()
        };

        // idle_decay = balance · (rate_ppb / Q) · (duration_secs / 86_400), all u128.
        let idle_decay_micros = ((balance as u128)
            .saturating_mul(rate_ppb)
            .saturating_mul(duration_secs as u128)
            / IDLE_DECAY_Q.saturating_mul(SECS_PER_DAY)) as u64;
        // POOL_FRACTION is exactly 0.5 → integer halve; the staker side absorbs the
        // odd-unit remainder (the pool also receives per-staker rounding dust in
        // `Ledger::apply_idle_decay_batch`, so nothing is created or lost).
        let pool_micros = idle_decay_micros / 2;
        let staker_micros = idle_decay_micros - pool_micros;

        Some(IdleDecayAssessment {
            identity: identity.to_string(),
            churn_ratio: churn_q as f64 / IDLE_DECAY_Q as f64, // display-only
            tier,
            daily_rate: if is_registered { REGISTERED_RATE } else { tier.daily_rate() }, // display-only
            is_registered,
            idle_decay_micros,
            pool_micros,
            staker_micros,
        })
    }

    /// Assess idle_decay for an exchange identity, advancing the running counters.
    ///
    /// Thin mutating wrapper over [`assess_amount`](Self::assess_amount): the
    /// arithmetic lives there (single source of truth); this records the totals
    /// and the `last_assessed` timestamp. The consensus apply path does NOT call
    /// this — it goes through `Ledger::{compute,apply}_idle_decay_batch`, and the
    /// counters advance via [`note_applied_batch`](Self::note_applied_batch).
    pub fn assess(
        &mut self,
        identity: &str,
        balance: u64,
        duration_secs: u64,
        now: f64,
    ) -> Option<IdleDecayAssessment> {
        let assessment = self.assess_amount(identity, balance, duration_secs, now)?;
        self.total_collected += assessment.idle_decay_micros;
        self.total_pooled += assessment.pool_micros;
        self.total_distributed += assessment.staker_micros;
        self.last_assessed.insert(identity.to_string(), now);
        Some(assessment)
    }

    /// Advance the running observability counters from an applied
    /// [`IdleDecayBatch`]. Every node calls this on the apply path so the totals
    /// converge fleet-wide instead of tracking only the producer's `assess` calls.
    pub fn note_applied_batch(&mut self, collected: u64, pooled: u64, distributed: u64) {
        self.total_collected += collected;
        self.total_pooled += pooled;
        self.total_distributed += distributed;
    }

    /// Prune all trackers.
    pub fn prune_all(&mut self, now: f64) {
        for tracker in self.trackers.values_mut() {
            tracker.prune(now);
        }
    }

    /// Number of tracked exchange identities.
    pub fn tracked_count(&self) -> usize {
        self.trackers.len()
    }

    /// Number of flow entries for an identity (0 if untracked).
    pub fn tracker_count(&self, identity: &str) -> usize {
        self.trackers.get(identity).map(|t| t.entry_count()).unwrap_or(0)
    }

    /// Number of registered exchanges.
    pub fn registered_count(&self) -> usize {
        self.registered.len()
    }

    /// Total idle_decay collected.
    pub fn total_collected(&self) -> u64 {
        self.total_collected
    }

    /// Total burned.
    pub fn total_pooled(&self) -> u64 {
        self.total_pooled
    }

    /// Total distributed to stakers.
    pub fn total_distributed(&self) -> u64 {
        self.total_distributed
    }
}

/// Build metadata for a idle_decay assessment record.
pub fn idle_decay_metadata(assessment: &IdleDecayAssessment) -> Vec<(String, String)> {
    vec![
        ("idle_decay_op".to_string(), "assess".to_string()),
        ("target_identity".to_string(), assessment.identity.clone()),
        ("churn_ratio".to_string(), format!("{:.4}", assessment.churn_ratio)),
        ("churn_tier".to_string(), assessment.tier.as_str().to_string()),
        ("daily_rate".to_string(), format!("{:.6}", assessment.daily_rate)),
        ("idle_decay_micros".to_string(), assessment.idle_decay_micros.to_string()),
        ("pool_micros".to_string(), assessment.pool_micros.to_string()),
        ("staker_micros".to_string(), assessment.staker_micros.to_string()),
        (
            "registered_exchange".to_string(),
            assessment.is_registered.to_string(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_churn_tier_quiet() {
        assert_eq!(ChurnTier::from_ratio(0.1), ChurnTier::Quiet);
        assert_eq!(ChurnTier::from_ratio(0.0), ChurnTier::Quiet);
        assert_eq!(ChurnTier::from_ratio(0.29), ChurnTier::Quiet);
    }

    #[test]
    fn test_churn_tier_boundaries() {
        assert_eq!(ChurnTier::from_ratio(0.3), ChurnTier::Active);
        assert_eq!(ChurnTier::from_ratio(0.7), ChurnTier::Heavy);
        assert_eq!(ChurnTier::from_ratio(1.5), ChurnTier::PumpDump);
        assert_eq!(ChurnTier::from_ratio(3.0), ChurnTier::Extreme);
    }

    #[test]
    fn test_daily_rates() {
        assert!((ChurnTier::Quiet.daily_rate() - 0.000_05).abs() < f64::EPSILON);
        assert!((ChurnTier::Active.daily_rate() - 0.000_10).abs() < f64::EPSILON);
        assert!((ChurnTier::Heavy.daily_rate() - 0.000_50).abs() < f64::EPSILON);
        assert!((ChurnTier::PumpDump.daily_rate() - 0.001_50).abs() < f64::EPSILON);
        assert!((ChurnTier::Extreme.daily_rate() - 0.003_00).abs() < f64::EPSILON);
    }

    #[test]
    fn test_flow_tracker_churn() {
        let mut tracker = FlowTracker::new();
        let now = 1_000_000.0;

        // Record balance snapshots
        tracker.record_balance(1_000_000, now - 86_400.0);
        tracker.record_balance(1_000_000, now);

        // Record flows
        tracker.record_inflow(500_000, now - 43_200.0);
        tracker.record_outflow(300_000, now - 21_600.0);

        let churn = tracker.churn_ratio(now);
        // (500_000 + 300_000) / 1_000_000 = 0.8
        assert!((churn - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_flow_tracker_empty() {
        let tracker = FlowTracker::new();
        assert_eq!(tracker.churn_ratio(1000.0), 0.0);
    }

    #[test]
    fn test_flow_tracker_prune() {
        let mut tracker = FlowTracker::new();
        tracker.record_inflow(100, 0.0);
        tracker.record_inflow(200, CHURN_WINDOW_SECS + 1.0);

        tracker.prune(CHURN_WINDOW_SECS + 1.0);
        assert_eq!(tracker.total_inflow(CHURN_WINDOW_SECS + 1.0), 200);
    }

    #[test]
    fn test_assess_quiet_exchange() {
        let mut state = IdleDecayState::new();
        let now = 1_000_000.0;

        state.record_balance("exch1", 10_000_000_000, now - 86_400.0);
        state.record_balance("exch1", 10_000_000_000, now);
        state.record_inflow("exch1", 1_000_000_000, now - 43_200.0);
        state.record_outflow("exch1", 500_000_000, now - 21_600.0);

        // Base units (10^9/beat): balance 10 beat, churn = (1 + 0.5) / 10 = 0.15 → Quiet tier
        let assessment = state.assess("exch1", 10_000_000_000, 86_400, now).unwrap();
        assert_eq!(assessment.tier, ChurnTier::Quiet);
        assert!((assessment.daily_rate - RATE_QUIET).abs() < f64::EPSILON);
        // 10_000_000_000 * 0.00005 * 1 day = 500_000 base units
        assert_eq!(assessment.idle_decay_micros, 500_000);
        assert_eq!(assessment.pool_micros, 250_000);
        assert_eq!(assessment.staker_micros, 250_000);
    }

    #[test]
    fn test_assess_extreme_churn() {
        let mut state = IdleDecayState::new();
        let now = 1_000_000.0;

        state.record_balance("exch1", 1_000_000_000, now);
        // Base units: balance 1 beat; massive churn 5 in + 5 out on 1 = churn 10.0
        state.record_inflow("exch1", 5_000_000_000, now - 43_200.0);
        state.record_outflow("exch1", 5_000_000_000, now - 21_600.0);

        let assessment = state.assess("exch1", 1_000_000_000, 86_400, now).unwrap();
        assert_eq!(assessment.tier, ChurnTier::Extreme);
        assert!((assessment.daily_rate - RATE_EXTREME).abs() < f64::EPSILON);
        // 1_000_000_000 * 0.003 * 1 day = 3_000_000 base units
        assert_eq!(assessment.idle_decay_micros, 3_000_000);
    }

    #[test]
    fn test_registered_exchange_capped() {
        let mut state = IdleDecayState::new();
        let now = 1_000_000.0;

        state.register_exchange("exch1");
        state.record_balance("exch1", 10_000_000_000, now);
        // Base units: high churn that would normally be Extreme tier
        state.record_inflow("exch1", 50_000_000_000, now - 43_200.0);
        state.record_outflow("exch1", 50_000_000_000, now - 21_600.0);

        let assessment = state.assess("exch1", 10_000_000_000, 86_400, now).unwrap();
        assert!(assessment.is_registered);
        // Rate capped at REGISTERED_RATE regardless of churn
        assert!((assessment.daily_rate - REGISTERED_RATE).abs() < f64::EPSILON);
    }

    #[test]
    fn test_below_minimum_balance() {
        let mut state = IdleDecayState::new();
        let now = 1_000_000.0;
        state.record_balance("exch1", 100, now);
        state.record_inflow("exch1", 50, now);

        // One base unit below MIN_IDLE_DECAY_BALANCE (1 beat) → skipped.
        let result = state.assess("exch1", MIN_IDLE_DECAY_BALANCE - 1, 86_400, now);
        assert!(result.is_none());
    }

    #[test]
    fn test_totals_accumulate() {
        let mut state = IdleDecayState::new();
        let now = 1_000_000.0;

        state.record_balance("exch1", 10_000_000_000, now);
        state.record_inflow("exch1", 1_000_000_000, now);

        state.assess("exch1", 10_000_000_000, 86_400, now);
        assert!(state.total_collected() > 0);
        assert_eq!(state.total_collected(), state.total_pooled() + state.total_distributed());
    }

    #[test]
    fn test_revoke_registration() {
        let mut state = IdleDecayState::new();
        state.register_exchange("exch1");
        assert!(state.is_registered("exch1"));

        state.revoke_registration("exch1");
        assert!(!state.is_registered("exch1"));
    }

    #[test]
    fn test_metadata() {
        let assessment = IdleDecayAssessment {
            identity: "exch1".to_string(),
            churn_ratio: 0.5,
            tier: ChurnTier::Active,
            daily_rate: RATE_ACTIVE,
            is_registered: false,
            idle_decay_micros: 1000,
            pool_micros: 500,
            staker_micros: 500,
        };
        let meta = idle_decay_metadata(&assessment);
        assert_eq!(meta.len(), 9);
        assert_eq!(meta[0].1, "assess");
        assert_eq!(meta[2].1, "0.5000");
    }

    #[test]
    fn test_burn_staker_split() {
        assert!((POOL_FRACTION + STAKER_FRACTION - 1.0).abs() < f64::EPSILON);
    }

    // ─────────────────────────── additional tests ───────────────────────────
    // Fixture-free idle_decay constant + flow-tracker init pins. The
    // existing tests cover ChurnTier::from_ratio dispatch and the
    // burn-staker split sum; these defend the underlying THRESHOLDS, the
    // RATE constants, and the FlowTracker empty-state invariants.

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_churn_tier_thresholds_pin_strict_values_with_monotonic_ascending() {
        // CHURN_TIER_1..4 are the boundary ratios that ChurnTier::from_ratio
        // dispatches against. Pin each strictly + the monotonic property
        // (no boundary can drift past its neighbor without breaking the
        // five-tier classifier).
        assert_eq!(CHURN_TIER_1, 0.3);
        assert_eq!(CHURN_TIER_2, 0.7);
        assert_eq!(CHURN_TIER_3, 1.5);
        assert_eq!(CHURN_TIER_4, 3.0);
        // Strictly ascending — exhaustive pairwise.
        assert!(CHURN_TIER_1 < CHURN_TIER_2);
        assert!(CHURN_TIER_2 < CHURN_TIER_3);
        assert!(CHURN_TIER_3 < CHURN_TIER_4);
        // All positive, all f64.
        assert!(CHURN_TIER_1 > 0.0);
        let _: f64 = CHURN_TIER_1;
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_idle_decay_rate_constants_strict_values_with_monotonic_ascending() {
        // Daily-rate dial: QUIET (0.005%) → EXTREME (0.30%) — 60× spread
        // across five tiers. Pin each value strictly so a unit drift
        // (% vs basis points, fraction vs percent) fails the test instead
        // of silently mis-scaling idle_decay charges across the fleet.
        assert_eq!(RATE_QUIET, 0.000_05);
        assert_eq!(RATE_ACTIVE, 0.000_10);
        assert_eq!(RATE_HEAVY, 0.000_50);
        assert_eq!(RATE_PUMP_DUMP, 0.001_50);
        assert_eq!(RATE_EXTREME, 0.003_00);
        // Strictly ascending across all five tiers.
        assert!(RATE_QUIET < RATE_ACTIVE);
        assert!(RATE_ACTIVE < RATE_HEAVY);
        assert!(RATE_HEAVY < RATE_PUMP_DUMP);
        assert!(RATE_PUMP_DUMP < RATE_EXTREME);
        // Spread: EXTREME is exactly 60× QUIET (load-bearing dial).
        let spread = RATE_EXTREME / RATE_QUIET;
        assert!((spread - 60.0).abs() < 1e-9, "extreme/quiet ratio must be 60");
        // ACTIVE is exactly 2× QUIET; PUMP_DUMP is 3× HEAVY.
        assert!((RATE_ACTIVE / RATE_QUIET - 2.0).abs() < 1e-9);
        assert!((RATE_PUMP_DUMP / RATE_HEAVY - 3.0).abs() < 1e-9);
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_idle_decay_economic_constants_window_min_balance_pool_staker_individual_pin() {
        // Existing test_burn_staker_split only checks the SUM. Pin each
        // fraction individually (50/50 split, not 60/40 or anything else),
        // plus the rolling window (7d) and the no-bother threshold
        // (MIN_IDLE_DECAY_BALANCE = 1 beat in base units / 10^9).
        assert_eq!(POOL_FRACTION, 0.50);
        assert_eq!(STAKER_FRACTION, 0.50);
        assert_eq!(POOL_FRACTION, STAKER_FRACTION, "must be exact 50/50 split");
        assert_eq!(CHURN_WINDOW_SECS, 7.0 * 86_400.0);
        assert_eq!(MIN_IDLE_DECAY_BALANCE, crate::accounting::types::BASE_UNITS_PER_BEAT);
        let _: u64 = MIN_IDLE_DECAY_BALANCE;
        // Window invariant: > 1 day (otherwise pump-dump signal too noisy).
        assert!(CHURN_WINDOW_SECS > 86_400.0);
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_registered_rate_aliases_rate_quiet_pin_protocol_alias_invariant() {
        // REGISTERED_RATE is defined as `pub const REGISTERED_RATE: f64 =
        // RATE_QUIET;` — registered exchanges always pay base regardless
        // of churn. Pin the alias property so a refactor that splits them
        // (e.g. REGISTERED_RATE = RATE_QUIET / 2) fails this test.
        assert_eq!(REGISTERED_RATE, RATE_QUIET);
        assert!(REGISTERED_RATE < RATE_EXTREME, "registered rate < extreme tier");
        assert!(REGISTERED_RATE <= RATE_ACTIVE, "registered rate ≤ active baseline");
        // Type pin: both f64.
        let _: f64 = REGISTERED_RATE;
    }

    #[test]
    fn batch_b_flow_tracker_new_equals_default_zero_entries_grows_with_records() {
        // FlowTracker derives Default; new() is sugar for Self::default().
        // Pin: both produce zero entries across all three tracked vectors
        // (inflows / outflows / balance_snapshots), AND entry_count grows
        // as records arrive.
        let t_new = FlowTracker::new();
        let t_def = FlowTracker::default();
        assert_eq!(t_new.entry_count(), 0);
        assert_eq!(t_def.entry_count(), 0);

        // record_inflow grows the count.
        let mut t = FlowTracker::new();
        assert_eq!(t.entry_count(), 0);
        t.record_inflow(100, 1.0);
        assert_eq!(t.entry_count(), 1);
        t.record_inflow(200, 2.0);
        assert_eq!(t.entry_count(), 2);
        // serde round-trip on empty is shape-stable.
        let json = serde_json::to_vec(&FlowTracker::new()).unwrap();
        let back: FlowTracker = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.entry_count(), 0);
    }

    // ─────────── fixed-point determinism (internal design notes) ──────────

    #[test]
    fn fixed_point_ppb_and_tier_q_match_f64_siblings() {
        // The integer ppb table + `_q` tier boundaries are the apply-path source
        // of truth; the f64 RATE_* / CHURN_TIER_* are display-only. Pin that they
        // encode the same numbers so the two representations can never drift.
        assert_eq!((RATE_QUIET * IDLE_DECAY_Q as f64).round() as u128, RATE_QUIET_PPB);
        assert_eq!((RATE_ACTIVE * IDLE_DECAY_Q as f64).round() as u128, RATE_ACTIVE_PPB);
        assert_eq!((RATE_HEAVY * IDLE_DECAY_Q as f64).round() as u128, RATE_HEAVY_PPB);
        assert_eq!((RATE_PUMP_DUMP * IDLE_DECAY_Q as f64).round() as u128, RATE_PUMP_DUMP_PPB);
        assert_eq!((RATE_EXTREME * IDLE_DECAY_Q as f64).round() as u128, RATE_EXTREME_PPB);
        assert_eq!((CHURN_TIER_1 * IDLE_DECAY_Q as f64).round() as u128, CHURN_TIER_1_Q);
        assert_eq!((CHURN_TIER_2 * IDLE_DECAY_Q as f64).round() as u128, CHURN_TIER_2_Q);
        assert_eq!((CHURN_TIER_3 * IDLE_DECAY_Q as f64).round() as u128, CHURN_TIER_3_Q);
        assert_eq!((CHURN_TIER_4 * IDLE_DECAY_Q as f64).round() as u128, CHURN_TIER_4_Q);
        // The ppb accessor agrees with the f64 accessor per tier.
        for tier in [ChurnTier::Quiet, ChurnTier::Active, ChurnTier::Heavy,
                     ChurnTier::PumpDump, ChurnTier::Extreme] {
            assert_eq!(
                (tier.daily_rate() * IDLE_DECAY_Q as f64).round() as u128,
                tier.daily_rate_ppb(),
            );
        }
    }

    #[test]
    fn from_churn_q_matches_from_ratio_across_tiers_and_boundaries() {
        // The integer classifier must agree with the f64 one at every tier and
        // exactly on the boundaries (the ULP-flip hazard the fix closes).
        for &ratio in &[0.0_f64, 0.1, 0.29, 0.3, 0.5, 0.7, 1.0, 1.5, 2.9, 3.0, 5.0, 100.0] {
            let churn_q = (ratio * IDLE_DECAY_Q as f64).round() as u128;
            assert_eq!(
                ChurnTier::from_churn_q(churn_q),
                ChurnTier::from_ratio(ratio),
                "tier mismatch at churn={ratio}",
            );
        }
    }

    #[test]
    fn assess_value_path_is_exact_above_2pow53() {
        // A balance above 2^53 (~9e15) where `balance as f64` would lose integer
        // precision and round differently across arches. The u128 path is exact
        // and bit-identical everywhere.
        let mut state = IdleDecayState::new();
        let now = 1_000_000.0;
        let balance: u64 = 9_000_000_000_000_000_000; // 9e18 base units, >> 2^53
        state.record_balance("whale", balance, now - 86_400.0);
        state.record_inflow("whale", 1_000_000_000, now - 43_200.0); // tiny vs balance → Quiet
        let a = state.assess("whale", balance, 86_400, now).unwrap();
        assert_eq!(a.tier, ChurnTier::Quiet);
        // 9e18 * 50_000 / 1e9 = 450_000_000_000_000 (exact integer).
        assert_eq!(a.idle_decay_micros, 450_000_000_000_000);
        assert_eq!(a.pool_micros, 225_000_000_000_000);
        assert_eq!(a.staker_micros, 225_000_000_000_000);
        // Conservation across the split.
        assert_eq!(a.pool_micros + a.staker_micros, a.idle_decay_micros);
    }

    #[test]
    fn assess_odd_idle_decay_gives_remainder_unit_to_staker_side() {
        // POOL_FRACTION is exactly 0.5 → integer halve. An odd idle_decay value
        // sends the single leftover unit to the staker side, never lost.
        let mut state = IdleDecayState::new();
        let now = 1_000_000.0;
        // balance * 3_000_000 / 1e9 = balance * 3 / 1000; balance = 1_000_000_500
        // → 3_000_001.5 → floor 3_000_001 (odd).
        let balance: u64 = 1_000_000_500;
        state.record_balance("e", balance, now - 86_400.0);
        state.record_inflow("e", balance * 5, now - 43_200.0);
        state.record_outflow("e", balance * 5, now - 21_600.0); // churn=10 → Extreme
        let a = state.assess("e", balance, 86_400, now).unwrap();
        assert_eq!(a.tier, ChurnTier::Extreme);
        assert_eq!(a.idle_decay_micros, 3_000_001); // odd
        assert_eq!(a.pool_micros, 1_500_000); // floor(odd/2)
        assert_eq!(a.staker_micros, 1_500_001); // leftover unit to staker side
        assert_eq!(a.pool_micros + a.staker_micros, a.idle_decay_micros);
    }
}
