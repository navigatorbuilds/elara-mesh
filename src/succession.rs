//! Digital Succession (Protocol §6.4, §11.2, §11.27).
//!
//! Identity recovery and succession mechanisms:
//! - Designated heirs: named in identity record, gain read access to private work
//! - Time-locked release: content becomes PUBLIC after specified duration (default 70yr)
//! - Dead man's switch: succession activates on heartbeat timeout
//! - Recovery keys: pre-committed at identity creation, can override device revocations
//!
//! Recovery key hierarchy:
//! 1. Recovery key (highest — overrides any device key action)
//! 2. Any enrolled device key (can revoke other device keys)
//! 3. Successor key (designated in revocation record)

//!
//! Spec references:
//!   @spec Protocol §6.4

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Metadata key for succession operations.
pub const SUCCESSION_OP_KEY: &str = "succession_op";

/// Default time-lock duration: 70 years in seconds.
pub const DEFAULT_TIME_LOCK_SECS: f64 = 70.0 * 365.25 * 86400.0;

/// Default dead man's switch timeout: 365 days in seconds.
pub const DEFAULT_HEARTBEAT_TIMEOUT_SECS: f64 = 365.0 * 86400.0;

// ─── Types ─────────────────────────────────────────────────────────────────

/// Succession path type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuccessionPath {
    /// Named heir gains read access to private/restricted work.
    DesignatedHeir,
    /// Content becomes PUBLIC after time-lock expires.
    TimeLocked,
    /// Automatic activation on heartbeat timeout.
    DeadManSwitch,
}

/// Status of a succession plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuccessionStatus {
    /// Plan is active but not triggered.
    Active,
    /// Succession has been triggered (heir claimed or timeout expired).
    Triggered,
    /// Succession completed (access transferred).
    Completed,
    /// Plan revoked by identity holder.
    Revoked,
}

/// A succession plan for an identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessionPlan {
    /// Identity hash of the plan owner.
    pub owner: String,
    /// Designated heir identity hashes (public keys).
    pub heirs: Vec<String>,
    /// Time-lock duration in seconds (default: 70 years).
    pub time_lock_secs: f64,
    /// Dead man's switch timeout in seconds.
    pub heartbeat_timeout_secs: f64,
    /// Recovery key public half (embedded at identity creation).
    pub recovery_key_hash: Option<String>,
    /// Plan creation timestamp.
    pub created_at: f64,
    /// Current status.
    pub status: SuccessionStatus,
    /// Last heartbeat timestamp (for dead man's switch).
    pub last_heartbeat: f64,
}

impl SuccessionPlan {
    /// Create a new succession plan.
    pub fn new(owner: &str, created_at: f64) -> Self {
        Self {
            owner: owner.to_string(),
            heirs: Vec::new(),
            time_lock_secs: DEFAULT_TIME_LOCK_SECS,
            heartbeat_timeout_secs: DEFAULT_HEARTBEAT_TIMEOUT_SECS,
            recovery_key_hash: None,
            created_at,
            status: SuccessionStatus::Active,
            last_heartbeat: created_at,
        }
    }

    /// Add a designated heir.
    pub fn add_heir(&mut self, heir_identity: &str) {
        if !self.heirs.contains(&heir_identity.to_string()) {
            self.heirs.push(heir_identity.to_string());
        }
    }

    /// Set the recovery key public half.
    pub fn set_recovery_key(&mut self, recovery_key_hash: &str) {
        self.recovery_key_hash = Some(recovery_key_hash.to_string());
    }

    /// Record a heartbeat (proves the owner is still active).
    pub fn heartbeat(&mut self, timestamp: f64) {
        self.last_heartbeat = timestamp;
    }

    /// Check if the dead man's switch has expired.
    pub fn is_heartbeat_expired(&self, now: f64) -> bool {
        now - self.last_heartbeat > self.heartbeat_timeout_secs
    }

    /// Check if the time-lock has expired (content should become public).
    pub fn is_time_lock_expired(&self, now: f64) -> bool {
        now - self.created_at > self.time_lock_secs
    }

    /// Check if a given identity is a designated heir.
    pub fn is_heir(&self, identity: &str) -> bool {
        self.heirs.iter().any(|h| h == identity)
    }

    /// Check if the recovery key matches.
    pub fn verify_recovery_key(&self, key_hash: &str) -> bool {
        self.recovery_key_hash
            .as_ref()
            .is_some_and(|k| k == key_hash)
    }
}

/// A succession claim submitted by an heir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessionClaim {
    /// Identity of the claimant (must be a designated heir).
    pub claimant: String,
    /// Identity of the deceased/unavailable owner.
    pub owner: String,
    /// Which succession path is being invoked.
    pub path: SuccessionPath,
    /// Timestamp of the claim.
    pub claimed_at: f64,
    /// Whether the claim has been verified.
    pub verified: bool,
}

// ─── State ─────────────────────────────────────────────────────────────────

/// Tracks succession plans and claims across the network.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SuccessionState {
    /// Succession plans by owner identity.
    plans: HashMap<String, SuccessionPlan>,
    /// Pending/completed claims by owner identity.
    claims: HashMap<String, Vec<SuccessionClaim>>,
}

impl SuccessionState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a succession plan.
    pub fn register_plan(&mut self, plan: SuccessionPlan) -> Result<(), String> {
        if plan.owner.is_empty() {
            return Err("owner identity is required".into());
        }
        if self.plans.contains_key(&plan.owner) {
            return Err(format!(
                "succession plan for '{}' already exists",
                plan.owner
            ));
        }
        self.plans.insert(plan.owner.clone(), plan);
        Ok(())
    }

    /// Get a succession plan.
    pub fn get_plan(&self, owner: &str) -> Option<&SuccessionPlan> {
        self.plans.get(owner)
    }

    /// Get a mutable plan reference.
    pub fn get_plan_mut(&mut self, owner: &str) -> Option<&mut SuccessionPlan> {
        self.plans.get_mut(owner)
    }

    /// Record a heartbeat for an identity.
    pub fn record_heartbeat(&mut self, owner: &str, timestamp: f64) -> bool {
        match self.plans.get_mut(owner) {
            Some(plan) if plan.status == SuccessionStatus::Active => {
                plan.heartbeat(timestamp);
                true
            }
            _ => false,
        }
    }

    /// Submit a succession claim.
    pub fn submit_claim(&mut self, claim: SuccessionClaim) -> Result<(), String> {
        let plan = self
            .plans
            .get(&claim.owner)
            .ok_or(format!("no succession plan for '{}'", claim.owner))?;

        if plan.status != SuccessionStatus::Active {
            return Err(format!(
                "succession plan for '{}' is not active",
                claim.owner
            ));
        }

        match claim.path {
            SuccessionPath::DesignatedHeir => {
                if !plan.is_heir(&claim.claimant) {
                    return Err(format!(
                        "'{}' is not a designated heir of '{}'",
                        claim.claimant, claim.owner
                    ));
                }
            }
            SuccessionPath::DeadManSwitch => {
                if !plan.is_heartbeat_expired(claim.claimed_at) {
                    return Err("dead man's switch has not expired".into());
                }
            }
            SuccessionPath::TimeLocked => {
                if !plan.is_time_lock_expired(claim.claimed_at) {
                    return Err("time-lock has not expired".into());
                }
            }
        }

        self.claims
            .entry(claim.owner.clone())
            .or_default()
            .push(claim);
        Ok(())
    }

    /// Trigger succession (mark plan as triggered after successful claim).
    pub fn trigger(&mut self, owner: &str) -> bool {
        match self.plans.get_mut(owner) {
            Some(plan) if plan.status == SuccessionStatus::Active => {
                plan.status = SuccessionStatus::Triggered;
                true
            }
            _ => false,
        }
    }

    /// Complete succession.
    pub fn complete(&mut self, owner: &str) -> bool {
        match self.plans.get_mut(owner) {
            Some(plan) if plan.status == SuccessionStatus::Triggered => {
                plan.status = SuccessionStatus::Completed;
                true
            }
            _ => false,
        }
    }

    /// Revoke a succession plan (only by the owner while active).
    pub fn revoke(&mut self, owner: &str) -> bool {
        match self.plans.get_mut(owner) {
            Some(plan) if plan.status == SuccessionStatus::Active => {
                plan.status = SuccessionStatus::Revoked;
                true
            }
            _ => false,
        }
    }

    /// Check for dead man's switch expirations across all active plans.
    pub fn expired_switches(&self, now: f64) -> Vec<&SuccessionPlan> {
        self.plans
            .values()
            .filter(|p| p.status == SuccessionStatus::Active && p.is_heartbeat_expired(now))
            .collect()
    }

    /// Check for time-lock expirations across all active plans.
    pub fn expired_time_locks(&self, now: f64) -> Vec<&SuccessionPlan> {
        self.plans
            .values()
            .filter(|p| p.status == SuccessionStatus::Active && p.is_time_lock_expired(now))
            .collect()
    }

    /// Recovery key override: allows recovery key holder to revoke devices
    /// and designate a successor even without the primary key.
    pub fn recovery_override(
        &mut self,
        owner: &str,
        recovery_key_hash: &str,
        successor: &str,
    ) -> Result<(), String> {
        let plan = self
            .plans
            .get_mut(owner)
            .ok_or(format!("no succession plan for '{}'", owner))?;

        if !plan.verify_recovery_key(recovery_key_hash) {
            return Err("recovery key does not match".into());
        }

        // Recovery key can designate a new heir and trigger succession
        plan.add_heir(successor);
        plan.status = SuccessionStatus::Triggered;
        Ok(())
    }

    /// Number of active plans.
    pub fn active_plan_count(&self) -> usize {
        self.plans
            .values()
            .filter(|p| p.status == SuccessionStatus::Active)
            .count()
    }

    /// Total plans.
    pub fn plan_count(&self) -> usize {
        self.plans.len()
    }

    /// Total claims.
    pub fn claim_count(&self) -> usize {
        self.claims.values().map(|v| v.len()).sum()
    }

    /// Claims for a specific owner.
    pub fn claims_for(&self, owner: &str) -> &[SuccessionClaim] {
        self.claims.get(owner).map_or(&[], |v| v.as_slice())
    }
}

// ─── Metadata Builders ────────────────────────────────────────────────────

/// Build metadata for a succession plan registration.
pub fn succession_plan_metadata(
    heirs: &[String],
    time_lock_secs: f64,
    heartbeat_timeout_secs: f64,
    recovery_key_hash: Option<&str>,
) -> std::collections::BTreeMap<String, String> {
    let mut meta = std::collections::BTreeMap::new();
    meta.insert(SUCCESSION_OP_KEY.into(), "register_plan".into());
    meta.insert(
        "heirs".into(),
        serde_json::to_string(heirs).unwrap_or_default(),
    );
    meta.insert("time_lock_secs".into(), time_lock_secs.to_string());
    meta.insert(
        "heartbeat_timeout_secs".into(),
        heartbeat_timeout_secs.to_string(),
    );
    if let Some(rk) = recovery_key_hash {
        meta.insert("recovery_key_hash".into(), rk.into());
    }
    meta
}

/// Build metadata for a succession claim.
pub fn succession_claim_metadata(
    owner: &str,
    path: &SuccessionPath,
) -> std::collections::BTreeMap<String, String> {
    let mut meta = std::collections::BTreeMap::new();
    meta.insert(SUCCESSION_OP_KEY.into(), "claim".into());
    meta.insert("claim_owner".into(), owner.into());
    let path_str = match path {
        SuccessionPath::DesignatedHeir => "designated_heir",
        SuccessionPath::TimeLocked => "time_locked",
        SuccessionPath::DeadManSwitch => "dead_man_switch",
    };
    meta.insert("claim_path".into(), path_str.into());
    meta
}

/// Build metadata for a heartbeat.
pub fn heartbeat_metadata() -> std::collections::BTreeMap<String, String> {
    let mut meta = std::collections::BTreeMap::new();
    meta.insert(SUCCESSION_OP_KEY.into(), "heartbeat".into());
    meta
}

// ─── Extraction ───────────────────────────────────────────────────────────

/// Parsed succession operation from record metadata.
#[derive(Debug, Clone)]
pub enum ParsedSuccessionOp {
    RegisterPlan {
        heirs: Vec<String>,
        time_lock_secs: f64,
        heartbeat_timeout_secs: f64,
        recovery_key_hash: Option<String>,
    },
    Claim {
        owner: String,
        path: SuccessionPath,
    },
    Heartbeat,
}

/// Extract a succession operation from record metadata.
pub fn extract_succession_op(
    metadata: &std::collections::BTreeMap<String, String>,
) -> Option<ParsedSuccessionOp> {
    let op = metadata.get(SUCCESSION_OP_KEY)?;

    match op.as_str() {
        "register_plan" => {
            let heirs_json = metadata.get("heirs")?;
            let heirs: Vec<String> = serde_json::from_str(heirs_json).ok()?;
            let time_lock_secs: f64 = metadata.get("time_lock_secs")?.parse().ok()?;
            let heartbeat_timeout_secs: f64 =
                metadata.get("heartbeat_timeout_secs")?.parse().ok()?;
            let recovery_key_hash = metadata.get("recovery_key_hash").cloned();

            Some(ParsedSuccessionOp::RegisterPlan {
                heirs,
                time_lock_secs,
                heartbeat_timeout_secs,
                recovery_key_hash,
            })
        }
        "claim" => {
            let owner = metadata.get("claim_owner")?.clone();
            let path_str = metadata.get("claim_path")?;
            let path = match path_str.as_str() {
                "designated_heir" => SuccessionPath::DesignatedHeir,
                "time_locked" => SuccessionPath::TimeLocked,
                "dead_man_switch" => SuccessionPath::DeadManSwitch,
                _ => return None,
            };
            Some(ParsedSuccessionOp::Claim { owner, path })
        }
        "heartbeat" => Some(ParsedSuccessionOp::Heartbeat),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_plan(owner: &str, now: f64) -> SuccessionPlan {
        let mut plan = SuccessionPlan::new(owner, now);
        plan.add_heir("heir-alice");
        plan.add_heir("heir-bob");
        plan.set_recovery_key("recovery-key-hash-001");
        plan
    }

    #[test]
    fn test_register_plan() {
        let mut state = SuccessionState::new();
        let plan = make_plan("owner-1", 1000.0);
        assert!(state.register_plan(plan).is_ok());
        assert_eq!(state.plan_count(), 1);
        assert_eq!(state.active_plan_count(), 1);
    }

    #[test]
    fn test_duplicate_plan_rejected() {
        let mut state = SuccessionState::new();
        state.register_plan(make_plan("owner-1", 1000.0)).unwrap();
        assert!(state.register_plan(make_plan("owner-1", 2000.0)).is_err());
    }

    #[test]
    fn test_heartbeat() {
        let mut state = SuccessionState::new();
        state.register_plan(make_plan("owner-1", 1000.0)).unwrap();

        assert!(state.record_heartbeat("owner-1", 2000.0));
        let plan = state.get_plan("owner-1").unwrap();
        assert_eq!(plan.last_heartbeat, 2000.0);
    }

    #[test]
    fn test_dead_man_switch_not_expired() {
        let mut state = SuccessionState::new();
        state.register_plan(make_plan("owner-1", 1000.0)).unwrap();

        // Not expired yet (< 365 days)
        let expired = state.expired_switches(1000.0 + 86400.0 * 100.0);
        assert!(expired.is_empty());
    }

    #[test]
    fn test_dead_man_switch_expired() {
        let mut state = SuccessionState::new();
        state.register_plan(make_plan("owner-1", 1000.0)).unwrap();

        // Expired (> 365 days)
        let expired = state.expired_switches(1000.0 + DEFAULT_HEARTBEAT_TIMEOUT_SECS + 1.0);
        assert_eq!(expired.len(), 1);
    }

    #[test]
    fn test_heartbeat_resets_switch() {
        let mut state = SuccessionState::new();
        state.register_plan(make_plan("owner-1", 1000.0)).unwrap();

        // Heartbeat at 300 days
        let day300 = 1000.0 + 86400.0 * 300.0;
        state.record_heartbeat("owner-1", day300);

        // Check at 400 days from creation — only 100 days from last heartbeat
        let day400 = 1000.0 + 86400.0 * 400.0;
        let expired = state.expired_switches(day400);
        assert!(expired.is_empty());
    }

    #[test]
    fn test_heir_claim() {
        let mut state = SuccessionState::new();
        state.register_plan(make_plan("owner-1", 1000.0)).unwrap();

        let claim = SuccessionClaim {
            claimant: "heir-alice".into(),
            owner: "owner-1".into(),
            path: SuccessionPath::DesignatedHeir,
            claimed_at: 2000.0,
            verified: false,
        };
        assert!(state.submit_claim(claim).is_ok());
        assert_eq!(state.claim_count(), 1);
    }

    #[test]
    fn test_non_heir_claim_rejected() {
        let mut state = SuccessionState::new();
        state.register_plan(make_plan("owner-1", 1000.0)).unwrap();

        let claim = SuccessionClaim {
            claimant: "mallory".into(),
            owner: "owner-1".into(),
            path: SuccessionPath::DesignatedHeir,
            claimed_at: 2000.0,
            verified: false,
        };
        assert!(state.submit_claim(claim).is_err());
    }

    #[test]
    fn test_dead_man_switch_claim() {
        let mut state = SuccessionState::new();
        state.register_plan(make_plan("owner-1", 1000.0)).unwrap();

        // Claim after switch expired
        let claim = SuccessionClaim {
            claimant: "heir-alice".into(),
            owner: "owner-1".into(),
            path: SuccessionPath::DeadManSwitch,
            claimed_at: 1000.0 + DEFAULT_HEARTBEAT_TIMEOUT_SECS + 1.0,
            verified: false,
        };
        assert!(state.submit_claim(claim).is_ok());
    }

    #[test]
    fn test_dead_man_switch_claim_too_early() {
        let mut state = SuccessionState::new();
        state.register_plan(make_plan("owner-1", 1000.0)).unwrap();

        let claim = SuccessionClaim {
            claimant: "heir-alice".into(),
            owner: "owner-1".into(),
            path: SuccessionPath::DeadManSwitch,
            claimed_at: 2000.0, // Way too early
            verified: false,
        };
        assert!(state.submit_claim(claim).is_err());
    }

    #[test]
    fn test_time_lock_claim() {
        let mut state = SuccessionState::new();
        state.register_plan(make_plan("owner-1", 1000.0)).unwrap();

        // After 70 years
        let claim = SuccessionClaim {
            claimant: "heir-bob".into(),
            owner: "owner-1".into(),
            path: SuccessionPath::TimeLocked,
            claimed_at: 1000.0 + DEFAULT_TIME_LOCK_SECS + 1.0,
            verified: false,
        };
        assert!(state.submit_claim(claim).is_ok());
    }

    #[test]
    fn test_time_lock_claim_too_early() {
        let mut state = SuccessionState::new();
        state.register_plan(make_plan("owner-1", 1000.0)).unwrap();

        let claim = SuccessionClaim {
            claimant: "heir-bob".into(),
            owner: "owner-1".into(),
            path: SuccessionPath::TimeLocked,
            claimed_at: 1000.0 + 86400.0 * 365.0, // Only 1 year
            verified: false,
        };
        assert!(state.submit_claim(claim).is_err());
    }

    #[test]
    fn test_trigger_and_complete() {
        let mut state = SuccessionState::new();
        state.register_plan(make_plan("owner-1", 1000.0)).unwrap();

        assert!(state.trigger("owner-1"));
        let plan = state.get_plan("owner-1").unwrap();
        assert_eq!(plan.status, SuccessionStatus::Triggered);

        assert!(state.complete("owner-1"));
        let plan = state.get_plan("owner-1").unwrap();
        assert_eq!(plan.status, SuccessionStatus::Completed);
    }

    #[test]
    fn test_revoke() {
        let mut state = SuccessionState::new();
        state.register_plan(make_plan("owner-1", 1000.0)).unwrap();

        assert!(state.revoke("owner-1"));
        let plan = state.get_plan("owner-1").unwrap();
        assert_eq!(plan.status, SuccessionStatus::Revoked);

        // Can't claim a revoked plan
        let claim = SuccessionClaim {
            claimant: "heir-alice".into(),
            owner: "owner-1".into(),
            path: SuccessionPath::DesignatedHeir,
            claimed_at: 2000.0,
            verified: false,
        };
        assert!(state.submit_claim(claim).is_err());
    }

    #[test]
    fn test_recovery_override() {
        let mut state = SuccessionState::new();
        state.register_plan(make_plan("owner-1", 1000.0)).unwrap();

        assert!(state
            .recovery_override("owner-1", "recovery-key-hash-001", "new-heir")
            .is_ok());

        let plan = state.get_plan("owner-1").unwrap();
        assert_eq!(plan.status, SuccessionStatus::Triggered);
        assert!(plan.is_heir("new-heir"));
    }

    #[test]
    fn test_recovery_wrong_key() {
        let mut state = SuccessionState::new();
        state.register_plan(make_plan("owner-1", 1000.0)).unwrap();

        let result = state.recovery_override("owner-1", "wrong-key", "attacker");
        assert!(result.is_err());
    }

    #[test]
    fn test_metadata_plan_roundtrip() {
        let heirs = vec!["heir-1".to_string(), "heir-2".to_string()];
        let meta = succession_plan_metadata(
            &heirs,
            DEFAULT_TIME_LOCK_SECS,
            DEFAULT_HEARTBEAT_TIMEOUT_SECS,
            Some("rk-hash"),
        );

        let parsed = extract_succession_op(&meta).unwrap();
        match parsed {
            ParsedSuccessionOp::RegisterPlan {
                heirs: h,
                recovery_key_hash,
                ..
            } => {
                assert_eq!(h.len(), 2);
                assert_eq!(recovery_key_hash, Some("rk-hash".to_string()));
            }
            _ => panic!("expected RegisterPlan"),
        }
    }

    #[test]
    fn test_metadata_claim_roundtrip() {
        let meta = succession_claim_metadata("owner-1", &SuccessionPath::DeadManSwitch);
        let parsed = extract_succession_op(&meta).unwrap();
        match parsed {
            ParsedSuccessionOp::Claim { owner, path } => {
                assert_eq!(owner, "owner-1");
                assert_eq!(path, SuccessionPath::DeadManSwitch);
            }
            _ => panic!("expected Claim"),
        }
    }

    #[test]
    fn test_metadata_heartbeat_roundtrip() {
        let meta = heartbeat_metadata();
        let parsed = extract_succession_op(&meta).unwrap();
        assert!(matches!(parsed, ParsedSuccessionOp::Heartbeat));
    }

    // ─── fixture-free, pure helpers ─────────────────────
    // Five axes pinning load-bearing invariants not covered by the lifecycle
    // tests above:
    //   1. Module constants strict-pin + arithmetic-form cross-checks + cross-
    //      module op-key disjointness.
    //   2. SuccessionPath (3-variant) and SuccessionStatus (4-variant) shape +
    //      serde snake_case JSON tags + pairwise distinctness.
    //   3. SuccessionPlan::new initial-state 8-field shape + helper boundary
    //      semantics (is_heir / is_heartbeat_expired / is_time_lock_expired /
    //      verify_recovery_key) + add_heir idempotency.
    //   4. SuccessionState lifecycle return-contract on trigger/complete/
    //      revoke (true only on Active match; false on non-Active or missing)
    //      + state-machine transitions + expired_switches / expired_time_locks
    //      filter to Active only.
    //   5. Metadata builders 3-shape (register_plan 4 or 5 keys / claim 3 keys
    //      / heartbeat 1 key) + ASCII-sorted BTreeMap iteration + extract
    //      round-trip negative paths (missing op-key / unknown op / malformed
    //      heirs JSON / missing claim fields / unknown claim_path).

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_succession_constants_strict_pin_arithmetic_cross_check_and_cross_module_disjointness() {
        // Axis 1: SUCCESSION_OP_KEY value + length + cross-module disjoint;
        // DEFAULT_TIME_LOCK_SECS and DEFAULT_HEARTBEAT_TIMEOUT_SECS arithmetic
        // forms + cross-relation invariant TIME_LOCK > HEARTBEAT (lifecycle:
        // time-lock release is the LONG path, dead-man's-switch is the SHORT
        // path — TIME_LOCK / HEARTBEAT ratio must stay > 1 by orders of mag).

        // ── SUCCESSION_OP_KEY exact value ──
        assert_eq!(SUCCESSION_OP_KEY, "succession_op");
        assert_eq!(SUCCESSION_OP_KEY.len(), 13);
        // ASCII lowercase snake_case
        assert!(SUCCESSION_OP_KEY.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "op-key must be ASCII lowercase snake_case");
        assert!(SUCCESSION_OP_KEY.contains('_'));
        assert!(!SUCCESSION_OP_KEY.starts_with('_'));
        assert!(!SUCCESSION_OP_KEY.ends_with('_'));

        // ── Cross-module disjointness (avoid collision with other DAM op-keys) ──
        // Other op-keys we've shipped: seed_vault_op, collaboration_op,
        // key_rotation, key_revocation, sphincs_key_rotation, succession_op.
        assert_ne!(SUCCESSION_OP_KEY, crate::seed_vault::SEED_VAULT_OP_KEY);
        assert_ne!(SUCCESSION_OP_KEY, crate::collaboration::COLLABORATION_OP_KEY);
        // succession_op should be the ONLY top-level key in this module's metadata.

        // ── DEFAULT_TIME_LOCK_SECS arithmetic: 70 years × 365.25 days/year × 86400 s/day ──
        let expected_time_lock = 70.0_f64 * 365.25 * 86400.0;
        assert_eq!(DEFAULT_TIME_LOCK_SECS, expected_time_lock);
        // 70 × 365.25 = 25_567.5 days; × 86400 = 2_209_032_000.0 seconds
        assert!((DEFAULT_TIME_LOCK_SECS - 2_209_032_000.0).abs() < 1e-3);
        assert!(DEFAULT_TIME_LOCK_SECS > 0.0);

        // ── DEFAULT_HEARTBEAT_TIMEOUT_SECS: 365 days × 86400 ──
        let expected_heartbeat = 365.0_f64 * 86400.0;
        assert_eq!(DEFAULT_HEARTBEAT_TIMEOUT_SECS, expected_heartbeat);
        assert_eq!(DEFAULT_HEARTBEAT_TIMEOUT_SECS, 31_536_000.0);
        assert!(DEFAULT_HEARTBEAT_TIMEOUT_SECS > 0.0);

        // ── Cross-relation: TIME_LOCK >> HEARTBEAT (70× since one uses 365 days
        //    and the other uses 70 × 365.25 days — ratio ≈ 70.05) ──
        let ratio = DEFAULT_TIME_LOCK_SECS / DEFAULT_HEARTBEAT_TIMEOUT_SECS;
        assert!(ratio > 70.0, "TIME_LOCK / HEARTBEAT ratio {} must exceed 70× (70 years vs 365 days)", ratio);
        assert!(ratio < 71.0, "TIME_LOCK / HEARTBEAT ratio {} must NOT exceed 71× (sanity: 70.05 expected)", ratio);

        // ── f64 type-pin (compile-time witness — both used in time math, not u64) ──
        let _t1: f64 = DEFAULT_TIME_LOCK_SECS;
        let _t2: f64 = DEFAULT_HEARTBEAT_TIMEOUT_SECS;

        // ── Sanity: both fit in f64 with no loss of precision for the
        //    relevant range (1e9 magnitude well below f64's 53-bit mantissa
        //    floor of 9e15) ──
        assert!(DEFAULT_TIME_LOCK_SECS < 1e10);
    }

    #[test]
    fn batch_b_succession_path_and_status_enum_serde_shape_snake_case_and_pairwise_distinct() {
        // Axis 2: SuccessionPath 3-variant + SuccessionStatus 4-variant.
        // Both #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        // with #[serde(rename_all = "snake_case")] — wire format MUST emit
        // snake_case JSON. Pin every variant's JSON + Debug name + pairwise
        // distinctness so a future variant rename can't slip past.

        // ── SuccessionPath: 3 variants ──
        let paths = [
            SuccessionPath::DesignatedHeir,
            SuccessionPath::TimeLocked,
            SuccessionPath::DeadManSwitch,
        ];
        let path_json: Vec<String> = paths.iter().map(|p| serde_json::to_string(p).unwrap()).collect();
        assert_eq!(path_json[0], r#""designated_heir""#);
        assert_eq!(path_json[1], r#""time_locked""#);
        assert_eq!(path_json[2], r#""dead_man_switch""#);

        // Pairwise distinct JSON tags
        for i in 0..paths.len() {
            for j in (i + 1)..paths.len() {
                assert_ne!(path_json[i], path_json[j],
                    "SuccessionPath variants {i} and {j} must have distinct JSON tags");
                assert_ne!(paths[i], paths[j],
                    "SuccessionPath variants {i} and {j} must be PartialEq-distinct");
            }
        }

        // Serde JSON round-trip per variant
        for p in &paths {
            let json = serde_json::to_string(p).unwrap();
            let parsed: SuccessionPath = serde_json::from_str(&json).unwrap();
            assert_eq!(*p, parsed);
        }

        // Debug contains variant name
        assert!(format!("{:?}", SuccessionPath::DesignatedHeir).contains("DesignatedHeir"));
        assert!(format!("{:?}", SuccessionPath::TimeLocked).contains("TimeLocked"));
        assert!(format!("{:?}", SuccessionPath::DeadManSwitch).contains("DeadManSwitch"));

        // Clone independence
        let p_orig = SuccessionPath::TimeLocked;
        let p_clone = p_orig.clone();
        assert_eq!(p_orig, p_clone);

        // ── SuccessionStatus: 4 variants ──
        let statuses = [
            SuccessionStatus::Active,
            SuccessionStatus::Triggered,
            SuccessionStatus::Completed,
            SuccessionStatus::Revoked,
        ];
        let status_json: Vec<String> = statuses.iter().map(|s| serde_json::to_string(s).unwrap()).collect();
        assert_eq!(status_json[0], r#""active""#);
        assert_eq!(status_json[1], r#""triggered""#);
        assert_eq!(status_json[2], r#""completed""#);
        assert_eq!(status_json[3], r#""revoked""#);

        // Pairwise distinct
        for i in 0..statuses.len() {
            for j in (i + 1)..statuses.len() {
                assert_ne!(status_json[i], status_json[j],
                    "SuccessionStatus variants {i} and {j} must have distinct JSON tags");
                assert_ne!(statuses[i], statuses[j]);
            }
        }

        // Round-trip per variant
        for s in &statuses {
            let json = serde_json::to_string(s).unwrap();
            let parsed: SuccessionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, parsed);
        }

        // Debug names
        assert!(format!("{:?}", SuccessionStatus::Active).contains("Active"));
        assert!(format!("{:?}", SuccessionStatus::Triggered).contains("Triggered"));
        assert!(format!("{:?}", SuccessionStatus::Completed).contains("Completed"));
        assert!(format!("{:?}", SuccessionStatus::Revoked).contains("Revoked"));

        // Cross-set distinctness: a status JSON tag must NOT collide with a path JSON tag
        // (the two enums share the wire format but the field positions differ;
        // a tag collision would mask a deserialization bug)
        for ps in &path_json {
            for ss in &status_json {
                assert_ne!(ps, ss, "path/status JSON tag collision: {ps} == {ss}");
            }
        }
    }

    #[test]
    fn batch_b_succession_plan_new_initial_state_8_field_shape_and_helper_boundary_semantics() {
        // Axis 3: SuccessionPlan::new 8-field initial-state + helper boundary
        // semantics that the lifecycle tests gloss over.

        let owner = "test-owner";
        let created_at = 5000.0;
        let plan = SuccessionPlan::new(owner, created_at);

        // ── 8-field initial state ──
        assert_eq!(plan.owner, owner);
        assert!(plan.heirs.is_empty(), "heirs must start empty");
        assert_eq!(plan.time_lock_secs, DEFAULT_TIME_LOCK_SECS, "default time-lock");
        assert_eq!(plan.heartbeat_timeout_secs, DEFAULT_HEARTBEAT_TIMEOUT_SECS, "default heartbeat");
        assert_eq!(plan.recovery_key_hash, None, "recovery_key starts None");
        assert_eq!(plan.created_at, created_at);
        assert_eq!(plan.status, SuccessionStatus::Active, "starts Active");
        assert_eq!(plan.last_heartbeat, created_at,
            "last_heartbeat MUST equal created_at on construction (fresh plan == live owner)");

        // ── add_heir idempotency: adding the SAME identity twice is a no-op
        //    (prevents duplicate-heir spam from inflating heirs Vec) ──
        let mut plan = SuccessionPlan::new(owner, created_at);
        plan.add_heir("alice");
        plan.add_heir("alice"); // duplicate
        plan.add_heir("alice"); // duplicate
        assert_eq!(plan.heirs.len(), 1, "add_heir MUST be idempotent — duplicate identity rejected");
        plan.add_heir("bob");
        assert_eq!(plan.heirs.len(), 2);
        plan.add_heir("bob"); // duplicate
        assert_eq!(plan.heirs.len(), 2);

        // ── is_heir returns true only for added identities (exact match, case-sensitive) ──
        assert!(plan.is_heir("alice"));
        assert!(plan.is_heir("bob"));
        assert!(!plan.is_heir("Alice"), "is_heir must be case-sensitive");
        assert!(!plan.is_heir("carol"));
        assert!(!plan.is_heir(""));

        // ── set_recovery_key + verify_recovery_key ──
        let mut plan = SuccessionPlan::new(owner, created_at);
        assert!(!plan.verify_recovery_key("anything"),
            "verify_recovery_key on None recovery_key_hash must return false");
        assert!(!plan.verify_recovery_key(""),
            "verify_recovery_key('') on None must return false (NOT vacuous true)");
        plan.set_recovery_key("rk-hash-001");
        assert!(plan.verify_recovery_key("rk-hash-001"));
        assert!(!plan.verify_recovery_key("rk-hash-002"));
        assert!(!plan.verify_recovery_key(""), "empty != stored key");
        // set_recovery_key overrides (idempotent on same value, replaces on different)
        plan.set_recovery_key("rk-hash-002");
        assert!(plan.verify_recovery_key("rk-hash-002"));
        assert!(!plan.verify_recovery_key("rk-hash-001"), "old recovery key replaced");

        // ── is_heartbeat_expired boundary: strict > comparison (not >=) ──
        let mut plan = SuccessionPlan::new(owner, 1000.0);
        plan.heartbeat_timeout_secs = 100.0;
        assert!(!plan.is_heartbeat_expired(1099.0), "now-1000=99 < 100, not expired");
        assert!(!plan.is_heartbeat_expired(1100.0), "now-1000=100 NOT > 100 (strict >), not expired AT boundary");
        assert!(plan.is_heartbeat_expired(1101.0), "now-1000=101 > 100, expired");
        // After heartbeat, baseline shifts
        plan.heartbeat(2000.0);
        assert!(!plan.is_heartbeat_expired(2100.0), "AT boundary not expired");
        assert!(plan.is_heartbeat_expired(2101.0));

        // ── is_time_lock_expired boundary (strict >) ──
        let mut plan2 = SuccessionPlan::new(owner, 1000.0);
        plan2.time_lock_secs = 500.0;
        assert!(!plan2.is_time_lock_expired(1499.0));
        assert!(!plan2.is_time_lock_expired(1500.0), "AT boundary not expired (strict >)");
        assert!(plan2.is_time_lock_expired(1501.0));

        // ── At default settings, dead-man timeout at exactly 365 days from
        //    creation is NOT expired (strict >); 1 second later IS expired ──
        let plan_default = SuccessionPlan::new(owner, 1000.0);
        assert!(!plan_default.is_heartbeat_expired(1000.0 + DEFAULT_HEARTBEAT_TIMEOUT_SECS));
        assert!(plan_default.is_heartbeat_expired(1000.0 + DEFAULT_HEARTBEAT_TIMEOUT_SECS + 1.0));
    }

    #[test]
    fn batch_b_succession_state_lifecycle_return_contract_and_state_machine_transitions() {
        // Axis 4: trigger/complete/revoke return-contract:
        //   - true ONLY when plan exists AND is in the legal source state
        //   - false on missing plan OR illegal source state
        // State machine:
        //   Active --trigger--> Triggered --complete--> Completed
        //   Active --revoke--> Revoked (terminal)
        //   Triggered ↛ Active, Completed ↛ Triggered, Revoked ↛ * etc.
        // expired_switches and expired_time_locks filter to Active only —
        // a Triggered/Completed/Revoked plan with an expired switch should
        // NOT show up (otherwise re-claim attacks would be possible).

        let mut state = SuccessionState::new();
        assert_eq!(state.plan_count(), 0);
        assert_eq!(state.active_plan_count(), 0);
        assert_eq!(state.claim_count(), 0);

        // ── trigger / complete / revoke on MISSING plan → all false ──
        assert!(!state.trigger("ghost"));
        assert!(!state.complete("ghost"));
        assert!(!state.revoke("ghost"));

        // ── Register Active plan ──
        let plan = SuccessionPlan::new("alpha", 100.0);
        state.register_plan(plan).unwrap();
        assert_eq!(state.plan_count(), 1);
        assert_eq!(state.active_plan_count(), 1);

        // ── trigger from Active → true ──
        assert!(state.trigger("alpha"));
        assert_eq!(state.get_plan("alpha").unwrap().status, SuccessionStatus::Triggered);
        assert_eq!(state.active_plan_count(), 0, "Triggered plan does NOT count as active");
        assert_eq!(state.plan_count(), 1, "plan still exists, just not active");

        // ── trigger from Triggered → false (idempotency NOT promised — strict state check) ──
        assert!(!state.trigger("alpha"), "trigger from non-Active must return false");

        // ── complete from Triggered → true ──
        assert!(state.complete("alpha"));
        assert_eq!(state.get_plan("alpha").unwrap().status, SuccessionStatus::Completed);

        // ── complete from Completed → false ──
        assert!(!state.complete("alpha"));
        // ── trigger from Completed → false ──
        assert!(!state.trigger("alpha"));
        // ── revoke from Completed → false ──
        assert!(!state.revoke("alpha"));

        // ── Separate plan: Active → Revoked (skip Triggered) ──
        let plan2 = SuccessionPlan::new("beta", 200.0);
        state.register_plan(plan2).unwrap();
        assert!(state.revoke("beta"));
        assert_eq!(state.get_plan("beta").unwrap().status, SuccessionStatus::Revoked);
        // revoke from Revoked → false (terminal)
        assert!(!state.revoke("beta"));
        // trigger from Revoked → false
        assert!(!state.trigger("beta"));
        // complete from Revoked → false (can't complete what was never Triggered)
        assert!(!state.complete("beta"));

        // ── record_heartbeat: Active only ──
        let plan3 = SuccessionPlan::new("gamma", 300.0);
        state.register_plan(plan3).unwrap();
        assert!(state.record_heartbeat("gamma", 400.0));
        assert_eq!(state.get_plan("gamma").unwrap().last_heartbeat, 400.0);
        // After triggering, record_heartbeat → false
        assert!(state.trigger("gamma"));
        assert!(!state.record_heartbeat("gamma", 500.0),
            "record_heartbeat on Triggered plan must return false");
        // last_heartbeat NOT updated (no side-effect on rejection)
        assert_eq!(state.get_plan("gamma").unwrap().last_heartbeat, 400.0);
        // record_heartbeat on missing plan → false
        assert!(!state.record_heartbeat("ghost", 1000.0));

        // ── expired_switches filters to Active only ──
        // Make a plan with a known short timeout, push past it on an Active plan
        let mut active_plan = SuccessionPlan::new("delta", 0.0);
        active_plan.heartbeat_timeout_secs = 10.0;
        state.register_plan(active_plan).unwrap();
        let expired = state.expired_switches(100.0);
        assert_eq!(expired.len(), 1, "Active delta with expired switch shows up");
        // After trigger, Triggered plan with same expired switch must NOT show up
        state.trigger("delta");
        let expired2 = state.expired_switches(100.0);
        assert_eq!(expired2.len(), 0, "Triggered delta must NOT show in expired_switches");

        // ── expired_time_locks filters to Active only ──
        let mut active_tl = SuccessionPlan::new("epsilon", 0.0);
        active_tl.time_lock_secs = 5.0;
        state.register_plan(active_tl).unwrap();
        let expired_tl = state.expired_time_locks(100.0);
        assert_eq!(expired_tl.len(), 1, "Active epsilon with expired time-lock shows up");
        state.revoke("epsilon");
        let expired_tl2 = state.expired_time_locks(100.0);
        assert_eq!(expired_tl2.len(), 0, "Revoked epsilon must NOT show in expired_time_locks");

        // ── claims_for: missing owner → empty slice (NOT None) ──
        assert!(state.claims_for("ghost").is_empty());
        // claims_for: existing owner with no claims → empty slice
        let plan_iota = SuccessionPlan::new("iota", 1000.0);
        state.register_plan(plan_iota).unwrap();
        assert!(state.claims_for("iota").is_empty());

        // ── get_plan/get_plan_mut: missing → None ──
        assert!(state.get_plan("ghost").is_none());
        assert!(state.get_plan_mut("ghost").is_none());
    }

    #[test]
    fn batch_b_succession_metadata_builders_shape_btreemap_sorted_and_extract_negative_paths() {
        // Axis 5: 3 metadata builders shape pins + ASCII-sorted BTreeMap order
        // + extract_succession_op round-trip + 7 negative paths.

        // ── succession_plan_metadata WITHOUT recovery_key_hash: exactly 4 keys ──
        let heirs = vec!["heir-1".to_string(), "heir-2".to_string()];
        let meta_no_rk = succession_plan_metadata(&heirs, 100.0, 200.0, None);
        assert_eq!(meta_no_rk.len(), 4, "without recovery_key_hash: exactly 4 keys");
        let keys_no_rk: Vec<&String> = meta_no_rk.keys().collect();
        // BTreeMap iteration is ASCII-sorted
        assert_eq!(keys_no_rk, vec!["heartbeat_timeout_secs", "heirs", "succession_op", "time_lock_secs"]);

        // ── succession_plan_metadata WITH recovery_key_hash: exactly 5 keys ──
        let meta_with_rk = succession_plan_metadata(&heirs, 100.0, 200.0, Some("rk-hash"));
        assert_eq!(meta_with_rk.len(), 5, "with recovery_key_hash: exactly 5 keys");
        let keys_with_rk: Vec<&String> = meta_with_rk.keys().collect();
        // Sorted: heartbeat_timeout_secs < heirs < recovery_key_hash < succession_op < time_lock_secs
        assert_eq!(keys_with_rk, vec![
            "heartbeat_timeout_secs",
            "heirs",
            "recovery_key_hash",
            "succession_op",
            "time_lock_secs",
        ]);
        assert_eq!(meta_with_rk.get("succession_op").unwrap(), "register_plan");
        assert_eq!(meta_with_rk.get("recovery_key_hash").unwrap(), "rk-hash");
        assert_eq!(meta_with_rk.get("time_lock_secs").unwrap(), "100");
        assert_eq!(meta_with_rk.get("heartbeat_timeout_secs").unwrap(), "200");

        // ── succession_claim_metadata: exactly 3 keys per claim ──
        let meta_claim = succession_claim_metadata("owner-X", &SuccessionPath::DeadManSwitch);
        assert_eq!(meta_claim.len(), 3);
        let claim_keys: Vec<&String> = meta_claim.keys().collect();
        // Sorted: claim_owner < claim_path < succession_op
        assert_eq!(claim_keys, vec!["claim_owner", "claim_path", "succession_op"]);
        assert_eq!(meta_claim.get("succession_op").unwrap(), "claim");
        assert_eq!(meta_claim.get("claim_owner").unwrap(), "owner-X");
        assert_eq!(meta_claim.get("claim_path").unwrap(), "dead_man_switch");

        // Per-path JSON pin for claim_path (matches the SuccessionPath::* match
        // in succession_claim_metadata — wire format MUST stay snake_case)
        for (p, expected) in &[
            (SuccessionPath::DesignatedHeir, "designated_heir"),
            (SuccessionPath::TimeLocked, "time_locked"),
            (SuccessionPath::DeadManSwitch, "dead_man_switch"),
        ] {
            let m = succession_claim_metadata("o", p);
            assert_eq!(m.get("claim_path").unwrap(), expected);
        }

        // ── heartbeat_metadata: exactly 1 key ──
        let meta_hb = heartbeat_metadata();
        assert_eq!(meta_hb.len(), 1);
        assert_eq!(meta_hb.get("succession_op").unwrap(), "heartbeat");

        // ── extract_succession_op positive: register_plan round-trip ──
        let parsed = extract_succession_op(&meta_with_rk).unwrap();
        match parsed {
            ParsedSuccessionOp::RegisterPlan { heirs: h, time_lock_secs, heartbeat_timeout_secs, recovery_key_hash } => {
                assert_eq!(h.len(), 2);
                assert_eq!(time_lock_secs, 100.0);
                assert_eq!(heartbeat_timeout_secs, 200.0);
                assert_eq!(recovery_key_hash, Some("rk-hash".to_string()));
            }
            _ => panic!("expected RegisterPlan"),
        }
        // ── extract_succession_op without recovery_key_hash → recovery_key_hash: None ──
        let parsed_no_rk = extract_succession_op(&meta_no_rk).unwrap();
        match parsed_no_rk {
            ParsedSuccessionOp::RegisterPlan { recovery_key_hash, .. } => {
                assert_eq!(recovery_key_hash, None);
            }
            _ => panic!("expected RegisterPlan"),
        }

        // ── Negative-path 1: missing SUCCESSION_OP_KEY → None ──
        let mut no_op = meta_with_rk.clone();
        no_op.remove("succession_op");
        assert!(extract_succession_op(&no_op).is_none());

        // ── Negative-path 2: unknown op value → None ──
        let mut bad_op = meta_with_rk.clone();
        bad_op.insert("succession_op".into(), "bogus_op".into());
        assert!(extract_succession_op(&bad_op).is_none());

        // ── Negative-path 3: register_plan with missing heirs → None ──
        let mut no_heirs = meta_with_rk.clone();
        no_heirs.remove("heirs");
        assert!(extract_succession_op(&no_heirs).is_none());

        // ── Negative-path 4: register_plan with malformed heirs JSON → None ──
        let mut bad_heirs = meta_with_rk.clone();
        bad_heirs.insert("heirs".into(), "not-json".into());
        assert!(extract_succession_op(&bad_heirs).is_none());

        // ── Negative-path 5: register_plan with non-numeric time_lock_secs → None ──
        let mut bad_tl = meta_with_rk.clone();
        bad_tl.insert("time_lock_secs".into(), "not-a-number".into());
        assert!(extract_succession_op(&bad_tl).is_none());

        // ── Negative-path 6: claim with missing claim_owner → None ──
        let mut bad_claim1 = meta_claim.clone();
        bad_claim1.remove("claim_owner");
        assert!(extract_succession_op(&bad_claim1).is_none());

        // ── Negative-path 7: claim with unknown claim_path → None ──
        let mut bad_claim2 = meta_claim.clone();
        bad_claim2.insert("claim_path".into(), "alien_path".into());
        assert!(extract_succession_op(&bad_claim2).is_none());

        // ── Positive claim round-trip ──
        let parsed_claim = extract_succession_op(&meta_claim).unwrap();
        match parsed_claim {
            ParsedSuccessionOp::Claim { owner, path } => {
                assert_eq!(owner, "owner-X");
                assert_eq!(path, SuccessionPath::DeadManSwitch);
            }
            _ => panic!("expected Claim"),
        }

        // ── Positive heartbeat round-trip ──
        let parsed_hb = extract_succession_op(&meta_hb).unwrap();
        assert!(matches!(parsed_hb, ParsedSuccessionOp::Heartbeat));
    }
}
