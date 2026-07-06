//! Storage Delegation Market — economics v0.4.1 Section 4.
//!
//! Light nodes (sensors, edge devices) can delegate record storage to
//! storage nodes. The market is free-priced: storage nodes set rates,
//! light nodes choose providers based on price, reliability, and location.
//!
//! Record structure:
//! - `storage_op: "delegate"` — create a storage delegation
//! - `storage_op: "terminate"` — end a delegation early
//! - `storage_op: "confirm"` — storage node confirms acceptance
//! - `storage_op: "challenge"` — client challenges data unavailability
//!
//! Key invariant: original node ALWAYS retains signed headers.
//! Only payload data is delegated. This ensures provenance survives
//! even if the storage node disappears.

//!
//! Spec references:
//!   @spec economics §4.4

use std::collections::HashMap;

use crate::errors::{ElaraError, Result};
use crate::record::ValidationRecord;
use crate::accounting::types::BASE_UNITS_PER_BEAT;

// ─── Constants ─────────────────────────────────────────────────────────────

pub const STORAGE_OP_KEY: &str = "storage_op";

/// Minimum witnesses required for a storage delegation.
pub const MIN_DELEGATION_WITNESSES: usize = 2;

/// Maximum delegation duration: 365 days in seconds.
pub const MAX_DELEGATION_DURATION_SECS: f64 = 365.0 * 24.0 * 3600.0;

/// Minimum delegation duration: 1 day in seconds.
pub const MIN_DELEGATION_DURATION_SECS: f64 = 24.0 * 3600.0;

/// Maximum cost per record per day: 1 beat (prevents price gouging).
pub const MAX_COST_PER_RECORD_PER_DAY: u64 = BASE_UNITS_PER_BEAT;

/// Trust decay per failed challenge (storage node lost data).
pub const STORAGE_TRUST_DECAY_PER_FAILURE: f64 = 0.10;

/// Trust recovery per successful verification period (30 days without issues).
pub const STORAGE_TRUST_RECOVERY_PER_PERIOD: f64 = 0.02;

/// Minimum storage trust to accept new delegations.
pub const MIN_STORAGE_TRUST: f64 = 0.30;

// ─── Types ─────────────────────────────────────────────────────────────────

/// Status of a storage delegation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationStatus {
    /// Delegation requested, awaiting storage node confirmation.
    Pending,
    /// Storage node confirmed, delegation active.
    Active,
    /// Delegation ended (expired or terminated).
    Ended,
    /// Delegation challenged (data unavailability).
    Challenged,
}

/// A storage delegation contract.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageDelegation {
    /// Delegation ID (= record ID of the delegate record).
    pub id: String,
    /// Identity hash of the delegator (light node / data owner).
    pub delegator: String,
    /// Identity hash of the storage provider.
    pub provider: String,
    /// Record IDs being delegated for storage.
    pub record_refs: Vec<String>,
    /// Cost in base units for the entire delegation period.
    pub cost: u64,
    /// Duration in seconds.
    pub duration_secs: f64,
    /// When the delegation was created.
    pub created_at: f64,
    /// When the delegation expires (created_at + duration_secs).
    pub expires_at: f64,
    /// Current status.
    pub status: DelegationStatus,
    /// Witnesses who attested this delegation.
    pub witnesses: Vec<String>,
    /// When the storage node confirmed (if confirmed).
    pub confirmed_at: Option<f64>,
}

/// Storage node reliability tracking.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StorageNodeProfile {
    /// Identity hash of the storage node.
    pub identity: String,
    /// Storage reliability trust score (0.0 to 1.0).
    pub trust: f64,
    /// Total delegations served.
    pub total_delegations: u64,
    /// Failed challenges (data lost).
    pub failed_challenges: u64,
    /// Successful delegation completions.
    pub successful_completions: u64,
    /// Total beat earned from storage services.
    pub total_earned: u64,
    /// Currently active delegations.
    pub active_delegations: usize,
}

impl StorageNodeProfile {
    pub fn new(identity: String) -> Self {
        Self {
            identity,
            trust: 1.0,
            total_delegations: 0,
            failed_challenges: 0,
            successful_completions: 0,
            total_earned: 0,
            active_delegations: 0,
        }
    }

    /// Record a failed challenge (data unavailability).
    pub fn record_failure(&mut self) {
        self.failed_challenges += 1;
        self.trust = (self.trust - STORAGE_TRUST_DECAY_PER_FAILURE).max(0.0);
    }

    /// Record a successful delegation completion.
    pub fn record_success(&mut self, earned: u64) {
        self.successful_completions += 1;
        self.total_earned += earned;
        self.trust = (self.trust + STORAGE_TRUST_RECOVERY_PER_PERIOD).min(1.0);
    }

    /// Whether this node can accept new delegations.
    pub fn can_accept_delegations(&self) -> bool {
        self.trust >= MIN_STORAGE_TRUST
    }
}

/// Parsed storage operation from record metadata.
#[derive(Debug, Clone)]
pub enum ParsedStorageOp {
    /// Create a new storage delegation.
    Delegate {
        provider: String,
        record_refs: Vec<String>,
        cost: u64,
        duration_secs: f64,
    },
    /// Storage node confirms acceptance.
    Confirm {
        delegation_id: String,
    },
    /// Client terminates delegation early.
    Terminate {
        delegation_id: String,
    },
    /// Client challenges data unavailability.
    Challenge {
        delegation_id: String,
        missing_records: Vec<String>,
    },
}

/// Extract a storage operation from record metadata.
pub fn extract_storage_op(record: &ValidationRecord) -> Result<ParsedStorageOp> {
    let op = record.metadata.get(STORAGE_OP_KEY)
        .and_then(|v| v.as_str())
        .ok_or_else(|| ElaraError::Ledger("missing storage_op".into()))?;

    match op {
        "delegate" => {
            let provider = record.metadata.get("storage_provider")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ElaraError::Ledger("missing storage_provider".into()))?
                .to_string();
            let record_refs: Vec<String> = record.metadata.get("storage_record_refs")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            if record_refs.is_empty() {
                return Err(ElaraError::Ledger("storage_record_refs cannot be empty".into()));
            }
            let cost = record.metadata.get("storage_cost")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| ElaraError::Ledger("missing or invalid storage_cost".into()))?;
            let duration_secs = record.metadata.get("storage_duration_secs")
                .and_then(|v| v.as_f64())
                .ok_or_else(|| ElaraError::Ledger("missing or invalid storage_duration_secs".into()))?;
            Ok(ParsedStorageOp::Delegate { provider, record_refs, cost, duration_secs })
        }
        "confirm" => {
            let delegation_id = record.metadata.get("storage_delegation_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ElaraError::Ledger("missing storage_delegation_id".into()))?
                .to_string();
            Ok(ParsedStorageOp::Confirm { delegation_id })
        }
        "terminate" => {
            let delegation_id = record.metadata.get("storage_delegation_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ElaraError::Ledger("missing storage_delegation_id".into()))?
                .to_string();
            Ok(ParsedStorageOp::Terminate { delegation_id })
        }
        "challenge" => {
            let delegation_id = record.metadata.get("storage_delegation_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ElaraError::Ledger("missing storage_delegation_id".into()))?
                .to_string();
            let missing_records: Vec<String> = record.metadata.get("storage_missing_records")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            Ok(ParsedStorageOp::Challenge { delegation_id, missing_records })
        }
        other => Err(ElaraError::Ledger(format!("unknown storage_op: {other}"))),
    }
}

// ─── State ─────────────────────────────────────────────────────────────────

/// Storage market state.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct StorageMarket {
    /// Active and historical delegations (keyed by delegation ID).
    pub delegations: HashMap<String, StorageDelegation>,
    /// Storage node profiles (keyed by identity hash).
    pub providers: HashMap<String, StorageNodeProfile>,
}

impl StorageMarket {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new storage delegation.
    #[allow(clippy::too_many_arguments)]
    pub fn create_delegation(
        &mut self,
        delegation_id: String,
        delegator: &str,
        provider: &str,
        record_refs: Vec<String>,
        cost: u64,
        duration_secs: f64,
        witnesses: Vec<String>,
        timestamp: f64,
    ) -> Result<()> {
        if self.delegations.contains_key(&delegation_id) {
            return Err(ElaraError::Ledger(format!("delegation already exists: {delegation_id}")));
        }

        if witnesses.len() < MIN_DELEGATION_WITNESSES {
            return Err(ElaraError::Ledger(format!(
                "insufficient witnesses: {} < {} required",
                witnesses.len(), MIN_DELEGATION_WITNESSES
            )));
        }

        if duration_secs < MIN_DELEGATION_DURATION_SECS {
            return Err(ElaraError::Ledger(format!(
                "duration {duration_secs}s below minimum {MIN_DELEGATION_DURATION_SECS}s"
            )));
        }

        if duration_secs > MAX_DELEGATION_DURATION_SECS {
            return Err(ElaraError::Ledger(format!(
                "duration {duration_secs}s exceeds maximum {MAX_DELEGATION_DURATION_SECS}s"
            )));
        }

        if record_refs.is_empty() {
            return Err(ElaraError::Ledger("must delegate at least one record".into()));
        }

        // Check cost per record per day
        let days = duration_secs / (24.0 * 3600.0);
        let records = record_refs.len() as u64;
        if days > 0.0 && records > 0 {
            let cost_per_record_per_day = cost / (records * days.ceil() as u64).max(1);
            if cost_per_record_per_day > MAX_COST_PER_RECORD_PER_DAY {
                return Err(ElaraError::Ledger(format!(
                    "cost per record per day {} exceeds max {}",
                    cost_per_record_per_day, MAX_COST_PER_RECORD_PER_DAY
                )));
            }
        }

        // Check provider trust
        let profile = self.providers.entry(provider.to_string())
            .or_insert_with(|| StorageNodeProfile::new(provider.to_string()));
        if !profile.can_accept_delegations() {
            return Err(ElaraError::Ledger(format!(
                "provider {provider} trust {:.2} below minimum {MIN_STORAGE_TRUST}",
                profile.trust
            )));
        }

        let delegation = StorageDelegation {
            id: delegation_id.clone(),
            delegator: delegator.to_string(),
            provider: provider.to_string(),
            record_refs,
            cost,
            duration_secs,
            created_at: timestamp,
            expires_at: timestamp + duration_secs,
            status: DelegationStatus::Pending,
            witnesses,
            confirmed_at: None,
        };

        self.delegations.insert(delegation_id, delegation);
        Ok(())
    }

    /// Storage node confirms a pending delegation.
    pub fn confirm_delegation(
        &mut self,
        delegation_id: &str,
        confirmer: &str,
        timestamp: f64,
    ) -> Result<()> {
        let delegation = self.delegations.get_mut(delegation_id)
            .ok_or_else(|| ElaraError::Ledger(format!("delegation not found: {delegation_id}")))?;

        if delegation.status != DelegationStatus::Pending {
            return Err(ElaraError::Ledger("delegation is not pending".into()));
        }

        if delegation.provider != confirmer {
            return Err(ElaraError::Ledger(format!(
                "only the provider ({}) can confirm, not {confirmer}",
                delegation.provider
            )));
        }

        delegation.status = DelegationStatus::Active;
        delegation.confirmed_at = Some(timestamp);

        let profile = self.providers.entry(confirmer.to_string())
            .or_insert_with(|| StorageNodeProfile::new(confirmer.to_string()));
        profile.total_delegations += 1;
        profile.active_delegations += 1;

        Ok(())
    }

    /// Terminate a delegation (by the delegator).
    pub fn terminate_delegation(
        &mut self,
        delegation_id: &str,
        terminator: &str,
    ) -> Result<()> {
        let delegation = self.delegations.get_mut(delegation_id)
            .ok_or_else(|| ElaraError::Ledger(format!("delegation not found: {delegation_id}")))?;

        if delegation.status != DelegationStatus::Active && delegation.status != DelegationStatus::Pending {
            return Err(ElaraError::Ledger("can only terminate active or pending delegations".into()));
        }

        if delegation.delegator != terminator {
            return Err(ElaraError::Ledger(format!(
                "only the delegator ({}) can terminate",
                delegation.delegator
            )));
        }

        let was_active = delegation.status == DelegationStatus::Active;
        delegation.status = DelegationStatus::Ended;

        if was_active {
            if let Some(profile) = self.providers.get_mut(&delegation.provider) {
                profile.active_delegations = profile.active_delegations.saturating_sub(1);
            }
        }

        Ok(())
    }

    /// Challenge a delegation for data unavailability.
    pub fn challenge_delegation(
        &mut self,
        delegation_id: &str,
        challenger: &str,
        missing_records: Vec<String>,
    ) -> Result<()> {
        let delegation = self.delegations.get_mut(delegation_id)
            .ok_or_else(|| ElaraError::Ledger(format!("delegation not found: {delegation_id}")))?;

        if delegation.status != DelegationStatus::Active {
            return Err(ElaraError::Ledger("can only challenge active delegations".into()));
        }

        if delegation.delegator != challenger {
            return Err(ElaraError::Ledger(format!(
                "only the delegator ({}) can challenge",
                delegation.delegator
            )));
        }

        if missing_records.is_empty() {
            return Err(ElaraError::Ledger("must specify at least one missing record".into()));
        }

        delegation.status = DelegationStatus::Challenged;

        // Apply trust decay to the storage provider
        if let Some(profile) = self.providers.get_mut(&delegation.provider) {
            profile.record_failure();
            profile.active_delegations = profile.active_delegations.saturating_sub(1);
        }

        Ok(())
    }

    /// Mark expired delegations and credit providers.
    pub fn expire_delegations(&mut self, now: f64) {
        let mut completed: Vec<(String, u64)> = Vec::new();

        for delegation in self.delegations.values_mut() {
            if delegation.status == DelegationStatus::Active && now >= delegation.expires_at {
                delegation.status = DelegationStatus::Ended;
                completed.push((delegation.provider.clone(), delegation.cost));
            }
        }

        for (provider, cost) in completed {
            if let Some(profile) = self.providers.get_mut(&provider) {
                profile.record_success(cost);
                profile.active_delegations = profile.active_delegations.saturating_sub(1);
            }
        }
    }

    /// Get active delegations for a specific delegator.
    pub fn delegations_for(&self, delegator: &str) -> Vec<&StorageDelegation> {
        self.delegations.values()
            .filter(|d| d.delegator == delegator && d.status == DelegationStatus::Active)
            .collect()
    }

    /// Get active delegations hosted by a specific provider.
    pub fn delegations_by_provider(&self, provider: &str) -> Vec<&StorageDelegation> {
        self.delegations.values()
            .filter(|d| d.provider == provider && d.status == DelegationStatus::Active)
            .collect()
    }

    /// Summary statistics.
    pub fn stats(&self) -> serde_json::Value {
        let active = self.delegations.values().filter(|d| d.status == DelegationStatus::Active).count();
        let pending = self.delegations.values().filter(|d| d.status == DelegationStatus::Pending).count();
        let total = self.delegations.len();

        serde_json::json!({
            "total_delegations": total,
            "active": active,
            "pending": pending,
            "providers": self.providers.len(),
        })
    }

    /// Rebuild from storage delegation records.
    pub fn rebuild(delegations: Vec<StorageDelegation>) -> Self {
        let mut market = Self::new();
        for d in delegations {
            let provider = d.provider.clone();
            let cost = d.cost;
            let is_active = d.status == DelegationStatus::Active;
            market.delegations.insert(d.id.clone(), d);
            let profile = market.providers.entry(provider)
                .or_insert_with(|| StorageNodeProfile::new(String::new()));
            profile.total_delegations += 1;
            if is_active {
                profile.active_delegations += 1;
            } else {
                profile.total_earned += cost;
            }
        }
        market
    }
}

// ─── Metadata Builders ─────────────────────────────────────────────────────

/// Build metadata for a storage delegation request.
pub fn delegate_metadata(
    provider: &str,
    record_refs: &[String],
    cost: u64,
    duration_secs: f64,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(STORAGE_OP_KEY.into(), serde_json::json!("delegate"));
    m.insert("storage_provider".into(), serde_json::json!(provider));
    m.insert("storage_record_refs".into(), serde_json::json!(record_refs));
    m.insert("storage_cost".into(), serde_json::json!(cost));
    m.insert("storage_duration_secs".into(), serde_json::json!(duration_secs));
    m
}

/// Build metadata for a storage confirmation.
pub fn confirm_metadata(delegation_id: &str) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(STORAGE_OP_KEY.into(), serde_json::json!("confirm"));
    m.insert("storage_delegation_id".into(), serde_json::json!(delegation_id));
    m
}

/// Build metadata for a storage termination.
pub fn terminate_metadata(delegation_id: &str) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(STORAGE_OP_KEY.into(), serde_json::json!("terminate"));
    m.insert("storage_delegation_id".into(), serde_json::json!(delegation_id));
    m
}

/// Build metadata for a storage challenge.
pub fn challenge_metadata(
    delegation_id: &str,
    missing_records: &[String],
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(STORAGE_OP_KEY.into(), serde_json::json!("challenge"));
    m.insert("storage_delegation_id".into(), serde_json::json!(delegation_id));
    m.insert("storage_missing_records".into(), serde_json::json!(missing_records));
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: f64 = 24.0 * 3600.0;

    fn make_witnesses() -> Vec<String> {
        vec!["witness_a".into(), "witness_b".into()]
    }

    #[test]
    fn test_create_delegation() {
        let mut market = StorageMarket::new();
        // 30 beat for 2 records over 30 days = 0.5 beat/record/day (within limit)
        market.create_delegation(
            "d1".into(), "light_node", "storage_node",
            vec!["rec_1".into(), "rec_2".into()],
            30 * BASE_UNITS_PER_BEAT, 30.0 * DAY,
            make_witnesses(), 1000.0,
        ).unwrap();

        assert_eq!(market.delegations.len(), 1);
        let d = &market.delegations["d1"];
        assert_eq!(d.status, DelegationStatus::Pending);
        assert_eq!(d.record_refs.len(), 2);
        assert_eq!(d.witnesses.len(), 2);
    }

    #[test]
    fn test_create_delegation_insufficient_witnesses() {
        let mut market = StorageMarket::new();
        let err = market.create_delegation(
            "d1".into(), "light", "storage",
            vec!["r1".into()], 100, 30.0 * DAY,
            vec!["w1".into()], // Only 1 witness
            1000.0,
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("insufficient witnesses"));
    }

    #[test]
    fn test_create_delegation_duration_too_short() {
        let mut market = StorageMarket::new();
        let err = market.create_delegation(
            "d1".into(), "light", "storage",
            vec!["r1".into()], 100, 100.0, // 100 seconds
            make_witnesses(), 1000.0,
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("below minimum"));
    }

    #[test]
    fn test_create_delegation_duration_too_long() {
        let mut market = StorageMarket::new();
        let err = market.create_delegation(
            "d1".into(), "light", "storage",
            vec!["r1".into()], 100, 400.0 * DAY, // > 365 days
            make_witnesses(), 1000.0,
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_confirm_delegation() {
        let mut market = StorageMarket::new();
        market.create_delegation(
            "d1".into(), "light", "storage",
            vec!["r1".into()], 10 * BASE_UNITS_PER_BEAT, 30.0 * DAY,
            make_witnesses(), 1000.0,
        ).unwrap();

        market.confirm_delegation("d1", "storage", 1100.0).unwrap();
        assert_eq!(market.delegations["d1"].status, DelegationStatus::Active);
        assert_eq!(market.providers["storage"].active_delegations, 1);
    }

    #[test]
    fn test_confirm_wrong_provider() {
        let mut market = StorageMarket::new();
        market.create_delegation(
            "d1".into(), "light", "storage_a",
            vec!["r1".into()], 100, 30.0 * DAY,
            make_witnesses(), 1000.0,
        ).unwrap();

        let err = market.confirm_delegation("d1", "storage_b", 1100.0);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("only the provider"));
    }

    #[test]
    fn test_terminate_delegation() {
        let mut market = StorageMarket::new();
        market.create_delegation(
            "d1".into(), "light", "storage",
            vec!["r1".into()], 100, 30.0 * DAY,
            make_witnesses(), 1000.0,
        ).unwrap();
        market.confirm_delegation("d1", "storage", 1100.0).unwrap();

        market.terminate_delegation("d1", "light").unwrap();
        assert_eq!(market.delegations["d1"].status, DelegationStatus::Ended);
        assert_eq!(market.providers["storage"].active_delegations, 0);
    }

    #[test]
    fn test_terminate_wrong_delegator() {
        let mut market = StorageMarket::new();
        market.create_delegation(
            "d1".into(), "light", "storage",
            vec!["r1".into()], 100, 30.0 * DAY,
            make_witnesses(), 1000.0,
        ).unwrap();

        let err = market.terminate_delegation("d1", "stranger");
        assert!(err.is_err());
    }

    #[test]
    fn test_challenge_delegation() {
        let mut market = StorageMarket::new();
        market.create_delegation(
            "d1".into(), "light", "storage",
            vec!["r1".into(), "r2".into()], 100, 30.0 * DAY,
            make_witnesses(), 1000.0,
        ).unwrap();
        market.confirm_delegation("d1", "storage", 1100.0).unwrap();

        market.challenge_delegation("d1", "light", vec!["r2".into()]).unwrap();
        assert_eq!(market.delegations["d1"].status, DelegationStatus::Challenged);
        // Trust should decay
        assert!(market.providers["storage"].trust < 1.0);
        assert_eq!(market.providers["storage"].failed_challenges, 1);
    }

    #[test]
    fn test_expire_delegations() {
        let mut market = StorageMarket::new();
        let cost = 15 * BASE_UNITS_PER_BEAT;
        market.create_delegation(
            "d1".into(), "light", "storage",
            vec!["r1".into()], cost, 30.0 * DAY,
            make_witnesses(), 1000.0,
        ).unwrap();
        market.confirm_delegation("d1", "storage", 1100.0).unwrap();

        // Not expired yet
        market.expire_delegations(1000.0 + 15.0 * DAY);
        assert_eq!(market.delegations["d1"].status, DelegationStatus::Active);

        // Expired
        market.expire_delegations(1000.0 + 31.0 * DAY);
        assert_eq!(market.delegations["d1"].status, DelegationStatus::Ended);
        assert_eq!(market.providers["storage"].successful_completions, 1);
        assert_eq!(market.providers["storage"].total_earned, cost);
    }

    #[test]
    fn test_low_trust_provider_rejected() {
        let mut market = StorageMarket::new();
        // Manually set low trust
        market.providers.insert("bad_node".into(), StorageNodeProfile {
            identity: "bad_node".into(),
            trust: 0.20,
            total_delegations: 5,
            failed_challenges: 4,
            successful_completions: 1,
            total_earned: 0,
            active_delegations: 0,
        });

        let err = market.create_delegation(
            "d1".into(), "light", "bad_node",
            vec!["r1".into()], 100, 30.0 * DAY,
            make_witnesses(), 1000.0,
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("trust"));
    }

    #[test]
    fn test_delegations_for_query() {
        let mut market = StorageMarket::new();
        market.create_delegation(
            "d1".into(), "alice", "storage",
            vec!["r1".into()], 100, 30.0 * DAY,
            make_witnesses(), 1000.0,
        ).unwrap();
        market.confirm_delegation("d1", "storage", 1100.0).unwrap();

        market.create_delegation(
            "d2".into(), "bob", "storage",
            vec!["r2".into()], 100, 30.0 * DAY,
            make_witnesses(), 1000.0,
        ).unwrap();
        market.confirm_delegation("d2", "storage", 1100.0).unwrap();

        assert_eq!(market.delegations_for("alice").len(), 1);
        assert_eq!(market.delegations_by_provider("storage").len(), 2);
    }

    #[test]
    fn test_storage_market_stats() {
        let mut market = StorageMarket::new();
        market.create_delegation(
            "d1".into(), "light", "storage",
            vec!["r1".into()], 100, 30.0 * DAY,
            make_witnesses(), 1000.0,
        ).unwrap();
        market.confirm_delegation("d1", "storage", 1100.0).unwrap();

        let stats = market.stats();
        assert_eq!(stats["total_delegations"], 1);
        assert_eq!(stats["active"], 1);
        assert_eq!(stats["providers"], 1);
    }

    #[test]
    fn test_extract_delegate_op() {
        let m = delegate_metadata("storage_node", &["r1".into(), "r2".into()], 5000, 86400.0);
        let mut record = ValidationRecord {
            id: String::new(), version: crate::wire::WIRE_VERSION, content_hash: vec![], creator_public_key: vec![],
            timestamp: 0.0, parents: vec![], classification: crate::record::Classification::Public,
            metadata: std::collections::BTreeMap::new(), signature: None, sphincs_signature: None,
            zk_proof: None, itc_stamp: None, zone_refs: vec![], creator_sphincs_pk: None, sig_algorithm: 0x01, sphincs_algorithm: None, zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };
        record.metadata = m.into_iter().collect();

        let op = extract_storage_op(&record).unwrap();
        match op {
            ParsedStorageOp::Delegate { provider, record_refs, cost, duration_secs } => {
                assert_eq!(provider, "storage_node");
                assert_eq!(record_refs, vec!["r1", "r2"]);
                assert_eq!(cost, 5000);
                assert_eq!(duration_secs, 86400.0);
            }
            _ => panic!("expected Delegate op"),
        }
    }

    #[test]
    fn test_extract_confirm_op() {
        let m = confirm_metadata("d1");
        let mut record = ValidationRecord {
            id: String::new(), version: crate::wire::WIRE_VERSION, content_hash: vec![], creator_public_key: vec![],
            timestamp: 0.0, parents: vec![], classification: crate::record::Classification::Public,
            metadata: std::collections::BTreeMap::new(), signature: None, sphincs_signature: None,
            zk_proof: None, itc_stamp: None, zone_refs: vec![], creator_sphincs_pk: None, sig_algorithm: 0x01, sphincs_algorithm: None, zone: None,
            identity_hash_wire: None,
            nonce: 0,
        };
        record.metadata = m.into_iter().collect();

        let op = extract_storage_op(&record).unwrap();
        match op {
            ParsedStorageOp::Confirm { delegation_id } => {
                assert_eq!(delegation_id, "d1");
            }
            _ => panic!("expected Confirm op"),
        }
    }

    // ─────────── storage constants + enum-serde tests ──────────────────────
    // Fixture-free constant + dispatch pins. No RocksDB, no record ingest —
    // these defend the protocol-economic constants (delegation bounds, trust
    // floor) and the enum serde shape that on-disk storage delegations are
    // (de)serialized through.

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_storage_op_key_and_delegation_duration_bounds_strict_pins() {
        // STORAGE_OP_KEY is the metadata-field name used at ingest. Drift
        // silently strands every storage delegation record. Duration bounds
        // pin the protocol's 1d-floor / 365d-ceiling on delegation contracts.
        assert_eq!(STORAGE_OP_KEY, "storage_op");
        assert_eq!(MIN_DELEGATION_DURATION_SECS, 24.0 * 3600.0);
        assert_eq!(MAX_DELEGATION_DURATION_SECS, 365.0 * 24.0 * 3600.0);
        // Sanity invariant: min < max, both positive, ratio = 365.
        assert!(MIN_DELEGATION_DURATION_SECS > 0.0);
        assert!(MIN_DELEGATION_DURATION_SECS < MAX_DELEGATION_DURATION_SECS);
        let ratio = MAX_DELEGATION_DURATION_SECS / MIN_DELEGATION_DURATION_SECS;
        assert!((ratio - 365.0).abs() < 1e-9, "duration ratio must be 365 (years/day)");
    }

    #[test]
    fn batch_b_min_delegation_witnesses_and_max_cost_per_record_per_day_pin() {
        // MIN_DELEGATION_WITNESSES = 2 — same rationale as MIN_VETOES_TO_HALT:
        // a single rogue witness cannot manufacture a delegation. MAX_COST
        // pins the price-gouging guard at exactly 1 beat/record/day in base units.
        assert_eq!(MIN_DELEGATION_WITNESSES, 2);
        let _: usize = MIN_DELEGATION_WITNESSES;
        assert_eq!(MAX_COST_PER_RECORD_PER_DAY, BASE_UNITS_PER_BEAT);
        assert_eq!(MAX_COST_PER_RECORD_PER_DAY, 1_000_000_000);
        let _: u64 = MAX_COST_PER_RECORD_PER_DAY;
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_trust_arithmetic_constants_decay_recovery_min_strict_with_invariants() {
        // Storage trust dial: a failure costs 5x what a successful period
        // recovers (0.10 vs 0.02), and the floor for accepting delegations
        // is 0.30 — three consecutive failures from a fresh node (1.0) drops
        // it to exactly MIN_STORAGE_TRUST + epsilon. Pin strict values + the
        // load-bearing inequalities.
        assert_eq!(STORAGE_TRUST_DECAY_PER_FAILURE, 0.10);
        assert_eq!(STORAGE_TRUST_RECOVERY_PER_PERIOD, 0.02);
        assert_eq!(MIN_STORAGE_TRUST, 0.30);
        // Invariants: decay > recovery (failures dominate), min in [0,1].
        assert!(STORAGE_TRUST_DECAY_PER_FAILURE > STORAGE_TRUST_RECOVERY_PER_PERIOD);
        assert!(MIN_STORAGE_TRUST > 0.0 && MIN_STORAGE_TRUST < 1.0);
        // Specific dial: 5x asymmetry between decay and recovery.
        let ratio = STORAGE_TRUST_DECAY_PER_FAILURE / STORAGE_TRUST_RECOVERY_PER_PERIOD;
        assert!((ratio - 5.0).abs() < 1e-9, "decay/recovery ratio must be 5");
    }

    #[test]
    fn batch_b_delegation_status_four_variants_snake_case_serde_round_trip() {
        // Serde shape: `rename_all = "snake_case"` — pin the wire form so
        // CF_DELEGATIONS rows survive serialization-renaming drift, and
        // confirm the 4-variant set (Pending / Active / Ended / Challenged).
        let cases = [
            (DelegationStatus::Pending, "\"pending\""),
            (DelegationStatus::Active, "\"active\""),
            (DelegationStatus::Ended, "\"ended\""),
            (DelegationStatus::Challenged, "\"challenged\""),
        ];
        for (v, expected_json) in &cases {
            let json = serde_json::to_string(v).expect("serialize");
            assert_eq!(&json, expected_json, "snake_case wire form drift for {v:?}");
            let back: DelegationStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&back, v);
        }
        // Distinctness pin — all 4 variants are mutually unequal.
        let all = [
            DelegationStatus::Pending,
            DelegationStatus::Active,
            DelegationStatus::Ended,
            DelegationStatus::Challenged,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
    }

    #[test]
    fn batch_b_storage_node_profile_new_zero_init_and_failure_recovery_clamp() {
        // Fresh profile: trust = 1.0 (max), all counters = 0. Pin both the
        // construction shape and the saturating arithmetic on record_failure
        // (clamp at 0.0) and record_success (clamp at 1.0) — these are the
        // safety properties that prevent trust drift below or above its
        // [0,1] range.
        let mut p = StorageNodeProfile::new("node-x".to_string());
        assert_eq!(p.identity, "node-x");
        assert_eq!(p.trust, 1.0);
        assert_eq!(p.total_delegations, 0);
        assert_eq!(p.failed_challenges, 0);
        assert_eq!(p.successful_completions, 0);
        assert_eq!(p.total_earned, 0);
        assert_eq!(p.active_delegations, 0);
        assert!(p.can_accept_delegations(), "fresh node trust=1.0 ≥ 0.30");

        // record_failure: trust -= 0.10, clamped at 0.
        for _ in 0..20 {
            p.record_failure();
        }
        // 20 failures × 0.10 = 2.0 deduction from initial 1.0 → clamped to 0.
        assert_eq!(p.trust, 0.0, "trust must clamp to 0 under repeated failures");
        assert_eq!(p.failed_challenges, 20);
        assert!(!p.can_accept_delegations(), "trust=0 < MIN_STORAGE_TRUST");

        // record_success: trust += 0.02, clamped at 1.0.
        for _ in 0..100 {
            p.record_success(5);
        }
        // 100 successes × 0.02 = 2.0 addition from 0 → clamped to 1.
        assert_eq!(p.trust, 1.0, "trust must clamp to 1.0 under repeated successes");
        assert_eq!(p.successful_completions, 100);
        assert_eq!(p.total_earned, 500);
    }
}
