//! Dispute Resolution — Protocol §11.13.
//!
//! Three-tier arbitration:
//! 1. Automated consensus (attestation disagreement detection)
//! 2. Community governance proposal (manual escalation)
//! 3. Genesis authority override (emergency resolution)
//!
//! Disputes are embedded in ValidationRecord metadata using the `dispute_op` key.

//!
//! Spec references:
//!   @spec Protocol §11.13
//!   @spec economics §10

use std::collections::HashMap;

use crate::errors::{ElaraError, Result};

/// Metadata key for dispute operations.
pub const DISPUTE_OP_KEY: &str = "dispute_op";

// ─── Types ───────────────────────────────────────────────────────────────────

/// Dispute lifecycle status.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    /// Dispute opened, gathering evidence.
    Open,
    /// Evidence submission phase (within window).
    EvidencePhase,
    /// Escalated to community governance vote.
    CommunityReview,
    /// Dispute resolved (upheld, dismissed, or voided).
    Resolved,
    /// Dispute dismissed (insufficient evidence or invalid).
    Dismissed,
}

/// Resolution details for a closed dispute.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DisputeResolution {
    /// When the dispute was resolved.
    pub resolved_at: f64,
    /// Who/what resolved it: "consensus", "governance", or "genesis".
    pub resolver: String,
    /// Outcome: "upheld", "dismissed", or "voided".
    pub outcome: String,
}

/// A dispute against a record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Dispute {
    /// Dispute ID (= record ID of the open-dispute record).
    pub id: String,
    /// The record being contested.
    pub contested_record_id: String,
    /// Identity hash of the dispute opener.
    pub opener: String,
    /// Reason for the dispute.
    pub reason: String,
    /// When the dispute was opened.
    pub opened_at: f64,
    /// Current status.
    pub status: DisputeStatus,
    /// Record IDs of evidence submissions.
    pub evidence_ids: Vec<String>,
    /// Governance proposal ID (if escalated to community review).
    pub governance_proposal_id: Option<String>,
    /// Resolution details (if resolved).
    pub resolution: Option<DisputeResolution>,
}

/// Parsed dispute operation from record metadata.
#[derive(Debug, Clone)]
pub enum ParsedDisputeOp {
    /// Open a new dispute.
    Open {
        contested_record_id: String,
        reason: String,
    },
    /// Submit evidence for an existing dispute.
    Evidence {
        dispute_id: String,
        evidence_data: String,
    },
    /// Resolve a dispute.
    Resolve {
        dispute_id: String,
        outcome: String,
    },
}

/// Hard cap on in-memory disputes. Resolved disputes auto-pruned when exceeded.
pub const MAX_DISPUTES: usize = 1_000;

/// All dispute state.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DisputeState {
    /// Active and historical disputes (keyed by dispute ID).
    pub disputes: HashMap<String, Dispute>,
}

impl DisputeState {
    pub fn new() -> Self {
        Self {
            disputes: HashMap::new(),
        }
    }

    /// Process a single record during streaming rebuild. Extracts dispute ops
    /// and applies open/evidence/resolve. O(1) per record.
    pub fn process_record(&mut self, rec: &crate::record::ValidationRecord, evidence_window_secs: f64) {
        if let Ok(Some(op)) = extract_dispute_op(&rec.metadata) {
            let creator = crate::accounting::types::creator_identity_hash(rec);
            match op {
                ParsedDisputeOp::Open { contested_record_id, reason } => {
                    let _ = self.open_dispute(
                        rec.id.clone(), contested_record_id, creator, reason, rec.timestamp,
                    );
                }
                ParsedDisputeOp::Evidence { dispute_id, .. } => {
                    let _ = self.add_evidence(
                        &dispute_id, rec.id.clone(), rec.timestamp, evidence_window_secs,
                    );
                }
                ParsedDisputeOp::Resolve { dispute_id, outcome } => {
                    let _ = self.resolve(&dispute_id, &creator, &outcome, rec.timestamp);
                }
            }
        }
    }

    /// Open a new dispute against a record.
    /// Enforces hard memory budget — auto-prunes resolved disputes if at capacity.
    pub fn open_dispute(
        &mut self,
        dispute_id: String,
        contested_record_id: String,
        opener: String,
        reason: String,
        timestamp: f64,
    ) -> Result<()> {
        if self.disputes.contains_key(&dispute_id) {
            return Err(ElaraError::Dispute(format!("dispute already exists: {dispute_id}")));
        }

        // Check no existing open dispute for this record
        if self.dispute_for_record(&contested_record_id).is_some() {
            return Err(ElaraError::Dispute(format!(
                "open dispute already exists for record: {contested_record_id}"
            )));
        }

        // Hard budget: prune resolved disputes if at capacity
        if self.disputes.len() >= MAX_DISPUTES {
            self.prune_resolved();
            // If still over cap after pruning resolved, evict oldest closed disputes
            if self.disputes.len() >= MAX_DISPUTES {
                self.evict_oldest(MAX_DISPUTES / 10);
            }
        }

        self.disputes.insert(dispute_id.clone(), Dispute {
            id: dispute_id,
            contested_record_id,
            opener,
            reason,
            opened_at: timestamp,
            status: DisputeStatus::Open,
            evidence_ids: Vec::new(),
            governance_proposal_id: None,
            resolution: None,
        });
        Ok(())
    }

    /// Add evidence to an existing dispute.
    pub fn add_evidence(
        &mut self,
        dispute_id: &str,
        evidence_record_id: String,
        timestamp: f64,
        evidence_window_secs: f64,
    ) -> Result<()> {
        let dispute = self.disputes.get_mut(dispute_id)
            .ok_or_else(|| ElaraError::Dispute(format!("dispute not found: {dispute_id}")))?;

        if dispute.status == DisputeStatus::Resolved || dispute.status == DisputeStatus::Dismissed {
            return Err(ElaraError::Dispute("dispute is already closed".into()));
        }

        if timestamp - dispute.opened_at > evidence_window_secs {
            return Err(ElaraError::Dispute("evidence window has expired".into()));
        }

        dispute.evidence_ids.push(evidence_record_id);
        dispute.status = DisputeStatus::EvidencePhase;
        Ok(())
    }

    /// Resolve a dispute with an outcome.
    pub fn resolve(
        &mut self,
        dispute_id: &str,
        resolver: &str,
        outcome: &str,
        timestamp: f64,
    ) -> Result<()> {
        let dispute = self.disputes.get_mut(dispute_id)
            .ok_or_else(|| ElaraError::Dispute(format!("dispute not found: {dispute_id}")))?;

        if dispute.status == DisputeStatus::Resolved || dispute.status == DisputeStatus::Dismissed {
            return Err(ElaraError::Dispute("dispute is already closed".into()));
        }

        let status = match outcome {
            "dismissed" => DisputeStatus::Dismissed,
            _ => DisputeStatus::Resolved,
        };

        dispute.status = status;
        dispute.resolution = Some(DisputeResolution {
            resolved_at: timestamp,
            resolver: resolver.to_string(),
            outcome: outcome.to_string(),
        });
        Ok(())
    }

    /// Escalate a dispute to community governance review (Protocol §11.24).
    ///
    /// Transitions EvidencePhase → CommunityReview and links a governance proposal.
    /// The proposal ID should reference an active governance proposal in the ledger layer.
    pub fn escalate_to_governance(
        &mut self,
        dispute_id: &str,
        governance_proposal_id: String,
    ) -> Result<()> {
        let dispute = self.disputes.get_mut(dispute_id)
            .ok_or_else(|| ElaraError::Dispute(format!("dispute not found: {dispute_id}")))?;

        if !matches!(dispute.status, DisputeStatus::Open | DisputeStatus::EvidencePhase) {
            return Err(ElaraError::Dispute(format!(
                "cannot escalate dispute in {:?} state (must be Open or EvidencePhase)",
                dispute.status
            )));
        }

        dispute.status = DisputeStatus::CommunityReview;
        dispute.governance_proposal_id = Some(governance_proposal_id);
        Ok(())
    }

    /// Get open disputes.
    pub fn open_disputes(&self) -> Vec<&Dispute> {
        self.disputes.values()
            .filter(|d| matches!(d.status, DisputeStatus::Open | DisputeStatus::EvidencePhase | DisputeStatus::CommunityReview))
            .collect()
    }

    /// Get all disputes.
    pub fn all_disputes(&self) -> Vec<&Dispute> {
        self.disputes.values().collect()
    }

    /// Get a dispute by ID.
    pub fn get(&self, id: &str) -> Option<&Dispute> {
        self.disputes.get(id)
    }

    /// Find an open dispute for a specific record.
    pub fn dispute_for_record(&self, record_id: &str) -> Option<&Dispute> {
        self.disputes.values().find(|d| {
            d.contested_record_id == record_id
                && matches!(d.status, DisputeStatus::Open | DisputeStatus::EvidencePhase | DisputeStatus::CommunityReview)
        })
    }

    /// Remove resolved/dismissed disputes from in-memory state.
    ///
    /// These are already persisted in RocksDB via record storage, so keeping
    /// them in RAM is pure waste. Returns the number of disputes pruned.
    pub fn prune_resolved(&mut self) -> usize {
        let before = self.disputes.len();
        self.disputes.retain(|_, d| {
            !matches!(d.status, DisputeStatus::Resolved | DisputeStatus::Dismissed)
        });
        before - self.disputes.len()
    }

    /// Evict the oldest N disputes regardless of status (hard budget enforcement).
    /// Prefers evicting resolved/dismissed first, then oldest open disputes.
    fn evict_oldest(&mut self, count: usize) {
        let mut entries: Vec<(String, f64, bool)> = self.disputes.iter()
            .map(|(id, d)| {
                let is_closed = matches!(d.status, DisputeStatus::Resolved | DisputeStatus::Dismissed);
                (id.clone(), d.opened_at, is_closed)
            })
            .collect();
        // Closed disputes first (they're safe to evict), then by age
        entries.sort_by(|a, b| {
            b.2.cmp(&a.2) // closed first
                .then(a.1.total_cmp(&b.1)) // oldest first
        });

        for (id, _, _) in entries.into_iter().take(count) {
            self.disputes.remove(&id);
        }
    }

    /// Total disputes tracked.
    pub fn dispute_count(&self) -> usize {
        self.disputes.len()
    }
}

// ─── Metadata extraction ────────────────────────────────────────────────────

/// Extract dispute operation from record metadata.
pub fn extract_dispute_op(
    metadata: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Result<Option<ParsedDisputeOp>> {
    let op_val = match metadata.get(DISPUTE_OP_KEY) {
        Some(v) => v,
        None => return Ok(None),
    };

    let op_str = op_val.as_str()
        .ok_or_else(|| ElaraError::Dispute("dispute_op must be a string".into()))?;

    match op_str {
        "open" => {
            let contested = get_dispute_str(metadata, "dispute_record_id")?;
            let reason = get_dispute_str(metadata, "dispute_reason")?;
            Ok(Some(ParsedDisputeOp::Open { contested_record_id: contested, reason }))
        }
        "evidence" => {
            let dispute_id = get_dispute_str(metadata, "dispute_id")?;
            let data = get_dispute_str(metadata, "dispute_evidence")?;
            Ok(Some(ParsedDisputeOp::Evidence { dispute_id, evidence_data: data }))
        }
        "resolve" => {
            let dispute_id = get_dispute_str(metadata, "dispute_id")?;
            let outcome = get_dispute_str(metadata, "dispute_outcome")?;
            Ok(Some(ParsedDisputeOp::Resolve { dispute_id, outcome }))
        }
        other => Err(ElaraError::Dispute(format!("unknown dispute op: {other}"))),
    }
}

fn get_dispute_str(
    meta: &std::collections::BTreeMap<String, serde_json::Value>,
    key: &str,
) -> Result<String> {
    meta.get(key)
        .ok_or_else(|| ElaraError::Dispute(format!("missing field: {key}")))?
        .as_str()
        .ok_or_else(|| ElaraError::Dispute(format!("{key} must be a string")))
        .map(|s| s.to_string())
}

/// Verify a dispute operation (basic validation).
pub fn verify_dispute(op: &ParsedDisputeOp) -> Result<()> {
    match op {
        ParsedDisputeOp::Open { contested_record_id, reason } => {
            if contested_record_id.is_empty() {
                return Err(ElaraError::Dispute("contested_record_id is empty".into()));
            }
            if reason.is_empty() {
                return Err(ElaraError::Dispute("dispute reason is empty".into()));
            }
        }
        ParsedDisputeOp::Evidence { dispute_id, evidence_data } => {
            if dispute_id.is_empty() {
                return Err(ElaraError::Dispute("dispute_id is empty".into()));
            }
            if evidence_data.is_empty() {
                return Err(ElaraError::Dispute("evidence_data is empty".into()));
            }
        }
        ParsedDisputeOp::Resolve { dispute_id, outcome } => {
            if dispute_id.is_empty() {
                return Err(ElaraError::Dispute("dispute_id is empty".into()));
            }
            if !["upheld", "dismissed", "voided"].contains(&outcome.as_str()) {
                return Err(ElaraError::Dispute(format!(
                    "invalid outcome: {outcome} (must be upheld, dismissed, or voided)"
                )));
            }
        }
    }
    Ok(())
}

/// Build metadata for opening a dispute.
pub fn open_dispute_metadata(
    contested_record_id: &str,
    reason: &str,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(DISPUTE_OP_KEY.into(), serde_json::json!("open"));
    m.insert("dispute_record_id".into(), serde_json::json!(contested_record_id));
    m.insert("dispute_reason".into(), serde_json::json!(reason));
    m
}

/// Build metadata for submitting evidence.
pub fn evidence_metadata(
    dispute_id: &str,
    evidence_data: &str,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(DISPUTE_OP_KEY.into(), serde_json::json!("evidence"));
    m.insert("dispute_id".into(), serde_json::json!(dispute_id));
    m.insert("dispute_evidence".into(), serde_json::json!(evidence_data));
    m
}

/// Build metadata for resolving a dispute.
pub fn resolve_metadata(
    dispute_id: &str,
    outcome: &str,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(DISPUTE_OP_KEY.into(), serde_json::json!("resolve"));
    m.insert("dispute_id".into(), serde_json::json!(dispute_id));
    m.insert("dispute_outcome".into(), serde_json::json!(outcome));
    m
}

/// Rebuild dispute state from all records in storage.
///
/// This helper is `cfg(test)`-gated. The unbounded `query(usize::MAX)` materializes
/// every record on the chain (~80 GB at 10M records) and would OOM any node.
/// Production boot uses `rebuild_disputes_from_records` driven by the
/// streaming `for_each_record_ordered_bounded` callback in `bin/elara_node.rs`.
/// Keep this helper only for unit tests that build a small in-memory fixture.
#[cfg(test)]
pub fn rebuild_disputes(
    storage: &dyn crate::storage::Storage,
    evidence_window_secs: f64,
) -> DisputeState {
    let records = storage.query(None, None, None, None, usize::MAX).unwrap_or_default();
    rebuild_disputes_from_records(&records, evidence_window_secs)
}

/// Rebuild dispute state from a pre-loaded record slice (single-pass startup).
///
/// **F2 tombstone guard (R4):** storage-less (no CF_METADATA access) so it cannot
/// skip tombstoned records inline, and it has ZERO production callers today (its
/// `#[cfg(test)]` wrapper is test-only). If ever wired into a production boot/sync
/// path, the CALLER must pre-filter tombstoned records (as ledger's
/// `rebuild_ledger_from_records` must) — else a tombstone-first op-carrying record is
/// revived here, re-introducing the F2 divergence for this subsystem. See
/// internal design notes (R4).
pub fn rebuild_disputes_from_records(
    all_records: &[crate::record::ValidationRecord],
    evidence_window_secs: f64,
) -> DisputeState {
    use crate::accounting::types::creator_identity_hash;

    let mut state = DisputeState::new();
    let mut sorted: Vec<&crate::record::ValidationRecord> = all_records.iter().collect();
    // Total-order replay: timestamp + record-ID tiebreak (mirrors ledger.rs/epoch.rs).
    // Dispute resolutions feed the reputation engine (witness eligibility).
    sorted.sort_by(|a, b| {
        a.timestamp.total_cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id))
    });

    for rec in &sorted {
        if let Ok(Some(op)) = extract_dispute_op(&rec.metadata) {
            let creator = creator_identity_hash(rec);
            match op {
                ParsedDisputeOp::Open { contested_record_id, reason } => {
                    let _ = state.open_dispute(
                        rec.id.clone(), contested_record_id, creator, reason, rec.timestamp,
                    );
                }
                ParsedDisputeOp::Evidence { dispute_id, .. } => {
                    let _ = state.add_evidence(
                        &dispute_id, rec.id.clone(), rec.timestamp, evidence_window_secs,
                    );
                }
                ParsedDisputeOp::Resolve { dispute_id, outcome } => {
                    let _ = state.resolve(&dispute_id, &creator, &outcome, rec.timestamp);
                }
            }
        }
    }
    state
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const WEEK: f64 = 7.0 * 24.0 * 3600.0;

    #[test]
    fn test_open_dispute() {
        let mut state = DisputeState::new();
        state.open_dispute("d1".into(), "record-a".into(), "alice".into(), "invalid data".into(), 1000.0).unwrap();
        assert_eq!(state.disputes.len(), 1);
        assert_eq!(state.disputes["d1"].status, DisputeStatus::Open);
    }

    #[test]
    fn test_open_dispute_duplicate() {
        let mut state = DisputeState::new();
        state.open_dispute("d1".into(), "record-a".into(), "alice".into(), "reason".into(), 1000.0).unwrap();
        assert!(state.open_dispute("d2".into(), "record-a".into(), "bob".into(), "other".into(), 1001.0).is_err());
    }

    #[test]
    fn test_add_evidence() {
        let mut state = DisputeState::new();
        state.open_dispute("d1".into(), "record-a".into(), "alice".into(), "reason".into(), 1000.0).unwrap();
        state.add_evidence("d1", "evidence-1".into(), 1500.0, WEEK).unwrap();
        assert_eq!(state.disputes["d1"].evidence_ids.len(), 1);
        assert_eq!(state.disputes["d1"].status, DisputeStatus::EvidencePhase);
    }

    #[test]
    fn test_add_evidence_expired_window() {
        let mut state = DisputeState::new();
        state.open_dispute("d1".into(), "record-a".into(), "alice".into(), "reason".into(), 1000.0).unwrap();
        assert!(state.add_evidence("d1", "late".into(), 1000.0 + WEEK + 1.0, WEEK).is_err());
    }

    #[test]
    fn test_resolve_dispute() {
        let mut state = DisputeState::new();
        state.open_dispute("d1".into(), "record-a".into(), "alice".into(), "reason".into(), 1000.0).unwrap();
        state.resolve("d1", "consensus", "upheld", 2000.0).unwrap();
        assert_eq!(state.disputes["d1"].status, DisputeStatus::Resolved);
        assert_eq!(state.disputes["d1"].resolution.as_ref().unwrap().outcome, "upheld");
    }

    #[test]
    fn test_resolve_dismissed() {
        let mut state = DisputeState::new();
        state.open_dispute("d1".into(), "record-a".into(), "alice".into(), "reason".into(), 1000.0).unwrap();
        state.resolve("d1", "governance", "dismissed", 2000.0).unwrap();
        assert_eq!(state.disputes["d1"].status, DisputeStatus::Dismissed);
    }

    #[test]
    fn test_resolve_already_closed() {
        let mut state = DisputeState::new();
        state.open_dispute("d1".into(), "record-a".into(), "alice".into(), "reason".into(), 1000.0).unwrap();
        state.resolve("d1", "genesis", "voided", 2000.0).unwrap();
        assert!(state.resolve("d1", "genesis", "upheld", 3000.0).is_err());
    }

    #[test]
    fn test_open_disputes_list() {
        let mut state = DisputeState::new();
        state.open_dispute("d1".into(), "r1".into(), "alice".into(), "reason".into(), 1000.0).unwrap();
        state.open_dispute("d2".into(), "r2".into(), "bob".into(), "reason".into(), 1001.0).unwrap();
        state.resolve("d1", "consensus", "dismissed", 2000.0).unwrap();
        assert_eq!(state.open_disputes().len(), 1);
    }

    #[test]
    fn test_dispute_for_record() {
        let mut state = DisputeState::new();
        state.open_dispute("d1".into(), "record-a".into(), "alice".into(), "reason".into(), 1000.0).unwrap();
        assert!(state.dispute_for_record("record-a").is_some());
        assert!(state.dispute_for_record("record-b").is_none());
    }

    #[test]
    fn test_extract_open_metadata() {
        let meta = open_dispute_metadata("record-x", "data integrity issue");
        let op = extract_dispute_op(&meta).unwrap().unwrap();
        match op {
            ParsedDisputeOp::Open { contested_record_id, reason } => {
                assert_eq!(contested_record_id, "record-x");
                assert_eq!(reason, "data integrity issue");
            }
            _ => panic!("expected Open"),
        }
    }

    #[test]
    fn test_extract_evidence_metadata() {
        let meta = evidence_metadata("d1", "proof of tampering");
        let op = extract_dispute_op(&meta).unwrap().unwrap();
        match op {
            ParsedDisputeOp::Evidence { dispute_id, evidence_data } => {
                assert_eq!(dispute_id, "d1");
                assert_eq!(evidence_data, "proof of tampering");
            }
            _ => panic!("expected Evidence"),
        }
    }

    #[test]
    fn test_extract_resolve_metadata() {
        let meta = resolve_metadata("d1", "upheld");
        let op = extract_dispute_op(&meta).unwrap().unwrap();
        match op {
            ParsedDisputeOp::Resolve { dispute_id, outcome } => {
                assert_eq!(dispute_id, "d1");
                assert_eq!(outcome, "upheld");
            }
            _ => panic!("expected Resolve"),
        }
    }

    #[test]
    fn test_verify_dispute_valid() {
        let op = ParsedDisputeOp::Open {
            contested_record_id: "record-a".into(),
            reason: "invalid".into(),
        };
        assert!(verify_dispute(&op).is_ok());
    }

    #[test]
    fn test_verify_dispute_empty_reason() {
        let op = ParsedDisputeOp::Open {
            contested_record_id: "record-a".into(),
            reason: String::new(),
        };
        assert!(verify_dispute(&op).is_err());
    }

    #[test]
    fn test_verify_dispute_invalid_outcome() {
        let op = ParsedDisputeOp::Resolve {
            dispute_id: "d1".into(),
            outcome: "maybe".into(),
        };
        assert!(verify_dispute(&op).is_err());
    }

    // ── Pruning tests ────────────────────────────────────────────────

    #[test]
    fn test_prune_resolved_removes_closed() {
        let mut state = DisputeState::new();
        state.open_dispute("d1".into(), "r1".into(), "alice".into(), "reason".into(), 1000.0).unwrap();
        state.open_dispute("d2".into(), "r2".into(), "bob".into(), "reason".into(), 1001.0).unwrap();
        state.open_dispute("d3".into(), "r3".into(), "carol".into(), "reason".into(), 1002.0).unwrap();
        // Resolve d1, dismiss d2, leave d3 open
        state.resolve("d1", "consensus", "upheld", 2000.0).unwrap();
        state.resolve("d2", "governance", "dismissed", 2001.0).unwrap();

        assert_eq!(state.disputes.len(), 3);
        let pruned = state.prune_resolved();
        assert_eq!(pruned, 2);
        assert_eq!(state.disputes.len(), 1);
        assert!(state.disputes.contains_key("d3"));
    }

    #[test]
    fn test_prune_resolved_nothing_to_prune() {
        let mut state = DisputeState::new();
        state.open_dispute("d1".into(), "r1".into(), "alice".into(), "reason".into(), 1000.0).unwrap();
        let pruned = state.prune_resolved();
        assert_eq!(pruned, 0);
        assert_eq!(state.disputes.len(), 1);
    }

    #[test]
    fn test_prune_resolved_all_closed() {
        let mut state = DisputeState::new();
        state.open_dispute("d1".into(), "r1".into(), "alice".into(), "reason".into(), 1000.0).unwrap();
        state.resolve("d1", "consensus", "upheld", 2000.0).unwrap();
        let pruned = state.prune_resolved();
        assert_eq!(pruned, 1);
        assert!(state.disputes.is_empty());
    }

    #[test]
    fn test_hard_budget_prunes_resolved_on_insert() {
        let mut state = DisputeState::new();
        // Fill to capacity with resolved disputes
        for i in 0..MAX_DISPUTES {
            state.disputes.insert(format!("d-{i}"), super::Dispute {
                id: format!("d-{i}"),
                contested_record_id: format!("r-{i}"),
                opener: "alice".into(),
                reason: "test".into(),
                opened_at: i as f64,
                status: super::DisputeStatus::Resolved,
                evidence_ids: vec![],
                governance_proposal_id: None,
                resolution: Some(super::DisputeResolution {
                    resolved_at: i as f64 + 100.0,
                    resolver: "consensus".into(),
                    outcome: "upheld".into(),
                }),
            });
        }
        assert_eq!(state.disputes.len(), MAX_DISPUTES);

        // Opening a new dispute should auto-prune resolved ones
        state.open_dispute("d-new".into(), "r-new".into(), "bob".into(), "test".into(), 999_999.0).unwrap();
        // All resolved should be gone, only the new one remains
        assert_eq!(state.disputes.len(), 1);
        assert!(state.disputes.contains_key("d-new"));
    }

    #[test]
    fn test_evict_oldest_prefers_closed() {
        let mut state = DisputeState::new();
        // Mix of open and closed disputes
        for i in 0..5 {
            state.disputes.insert(format!("open-{i}"), super::Dispute {
                id: format!("open-{i}"),
                contested_record_id: format!("r-open-{i}"),
                opener: "alice".into(),
                reason: "test".into(),
                opened_at: (i + 100) as f64, // newer
                status: super::DisputeStatus::Open,
                evidence_ids: vec![],
                governance_proposal_id: None,
                resolution: None,
            });
        }
        for i in 0..5 {
            state.disputes.insert(format!("closed-{i}"), super::Dispute {
                id: format!("closed-{i}"),
                contested_record_id: format!("r-closed-{i}"),
                opener: "alice".into(),
                reason: "test".into(),
                opened_at: i as f64, // older
                status: super::DisputeStatus::Resolved,
                evidence_ids: vec![],
                governance_proposal_id: None,
                resolution: Some(super::DisputeResolution {
                    resolved_at: 50.0,
                    resolver: "consensus".into(),
                    outcome: "upheld".into(),
                }),
            });
        }

        state.evict_oldest(3);
        assert_eq!(state.disputes.len(), 7);
        // Closed ones should be evicted first (they sort before open)
        assert!(!state.disputes.contains_key("closed-0"));
        assert!(!state.disputes.contains_key("closed-1"));
        assert!(!state.disputes.contains_key("closed-2"));
        // Open ones should all still be there
        for i in 0..5 {
            assert!(state.disputes.contains_key(&format!("open-{i}")));
        }
    }

    #[test]
    fn test_dispute_count() {
        let mut state = DisputeState::new();
        assert_eq!(state.dispute_count(), 0);
        state.open_dispute("d1".into(), "r1".into(), "alice".into(), "test".into(), 1.0).unwrap();
        assert_eq!(state.dispute_count(), 1);
    }

    #[test]
    fn test_escalate_to_governance() {
        let mut state = DisputeState::new();
        state.open_dispute("d1".into(), "r1".into(), "alice".into(), "double spend".into(), 1.0).unwrap();

        // Escalate to governance
        state.escalate_to_governance("d1", "gov-prop-123".into()).unwrap();
        let d = state.get("d1").unwrap();
        assert_eq!(d.status, DisputeStatus::CommunityReview);
        assert_eq!(d.governance_proposal_id.as_deref(), Some("gov-prop-123"));

        // Can't escalate a resolved dispute
        state.resolve("d1", "governance", "upheld", 2.0).unwrap();
        assert!(state.escalate_to_governance("d1", "gov-prop-456".into()).is_err());
    }

    #[test]
    fn test_escalate_from_evidence_phase() {
        let mut state = DisputeState::new();
        state.open_dispute("d1".into(), "r1".into(), "alice".into(), "invalid".into(), 1.0).unwrap();
        state.add_evidence("d1", "ev1".into(), 1.5, 3600.0).unwrap();
        assert_eq!(state.get("d1").unwrap().status, DisputeStatus::EvidencePhase);

        // Can escalate from EvidencePhase
        state.escalate_to_governance("d1", "gov-prop-789".into()).unwrap();
        assert_eq!(state.get("d1").unwrap().status, DisputeStatus::CommunityReview);
    }

    // ─── additional axes (fixture-free) ─────────────────────────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_dispute_constants_strict_pin_and_cross_module_disjointness() {
        // Axis 1: DISPUTE_OP_KEY + MAX_DISPUTES strict pins + cross-relations.

        // Numeric/string values + type pins.
        assert_eq!(DISPUTE_OP_KEY, "dispute_op");
        assert_eq!(DISPUTE_OP_KEY.len(), 10);
        assert_eq!(MAX_DISPUTES, 1_000_usize);

        let _k: &str = DISPUTE_OP_KEY;
        let _n: usize = MAX_DISPUTES;

        // DISPUTE_OP_KEY is ASCII lowercase snake_case with single '_'.
        assert!(DISPUTE_OP_KEY.is_ascii());
        assert!(DISPUTE_OP_KEY.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        assert_eq!(DISPUTE_OP_KEY.matches('_').count(), 1);

        // Cross-module disjointness — DISPUTE_OP_KEY must NOT collide with
        // other op-key values (load-bearing: shared metadata namespace; a
        // collision would mis-dispatch records).
        assert_ne!(DISPUTE_OP_KEY, crate::collaboration::COLLABORATION_OP_KEY);
        assert_ne!(DISPUTE_OP_KEY, crate::seed_vault::SEED_VAULT_OP_KEY);
        assert_ne!(DISPUTE_OP_KEY, crate::succession::SUCCESSION_OP_KEY);

        // Neither key is a prefix of the other (substring-misdispatch defense).
        assert!(!DISPUTE_OP_KEY.starts_with(crate::collaboration::COLLABORATION_OP_KEY));
        assert!(!crate::collaboration::COLLABORATION_OP_KEY.starts_with(DISPUTE_OP_KEY));

        // MAX_DISPUTES > 0 (a 0-cap state would reject every open).
        assert!(MAX_DISPUTES > 0);

        // MAX_DISPUTES divides cleanly by 10 (evict_oldest uses MAX/10).
        assert_eq!(MAX_DISPUTES % 10, 0);
        assert_eq!(MAX_DISPUTES / 10, 100);

        // MAX_DISPUTES is bounded — single-digit MB at ~1 KB per dispute,
        // not gigabytes. 1000 entries × ~1 KB = ~1 MB.
        assert!(MAX_DISPUTES <= 100_000,
            "memory budget would exceed sensible RAM at higher caps");

        // Field-key constants used by metadata builders / extractors —
        // these are string literals not exported but the canonical wire
        // names. Tested via the metadata builders below.

        // DISPUTE_OP_KEY is not the literal value "open"/"evidence"/"resolve"
        // (op-values vs op-key namespace separation).
        assert_ne!(DISPUTE_OP_KEY, "open");
        assert_ne!(DISPUTE_OP_KEY, "evidence");
        assert_ne!(DISPUTE_OP_KEY, "resolve");
    }

    #[test]
    fn batch_b_dispute_status_5_variant_serde_snake_case_and_parsed_op_3_variant_shape() {
        // Axis 2: DisputeStatus 5-variant serde snake_case + ParsedDisputeOp
        // 3-variant Debug+Clone shape pin.

        // 5x5 pairwise distinctness via PartialEq.
        let variants = [
            DisputeStatus::Open,
            DisputeStatus::EvidencePhase,
            DisputeStatus::CommunityReview,
            DisputeStatus::Resolved,
            DisputeStatus::Dismissed,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b, "variant {i} should equal itself");
                } else {
                    assert_ne!(a, b, "variants {i} and {j} must differ");
                }
            }
        }

        // serde rename_all="snake_case" wire-format pin. Changing these JSON
        // tags is a chain-breaking record-format break.
        assert_eq!(serde_json::to_string(&DisputeStatus::Open).unwrap(), "\"open\"");
        assert_eq!(serde_json::to_string(&DisputeStatus::EvidencePhase).unwrap(),
            "\"evidence_phase\"");
        assert_eq!(serde_json::to_string(&DisputeStatus::CommunityReview).unwrap(),
            "\"community_review\"");
        assert_eq!(serde_json::to_string(&DisputeStatus::Resolved).unwrap(), "\"resolved\"");
        assert_eq!(serde_json::to_string(&DisputeStatus::Dismissed).unwrap(), "\"dismissed\"");

        // JSON tags pairwise distinct.
        let tags: Vec<String> = variants.iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        for i in 0..tags.len() {
            for j in 0..tags.len() {
                if i != j { assert_ne!(tags[i], tags[j], "tag collision at {i}/{j}"); }
            }
        }

        // Round-trip per variant.
        for v in &variants {
            let s = serde_json::to_string(v).unwrap();
            let back: DisputeStatus = serde_json::from_str(&s).unwrap();
            assert_eq!(&back, v);
        }

        // Debug emits variant names.
        for v in &variants {
            let dbg = format!("{:?}", v);
            assert!(!dbg.is_empty());
        }

        // Clone independence.
        for v in &variants {
            let c = v.clone();
            assert_eq!(&c, v);
        }

        // ParsedDisputeOp 3-variant Debug + Clone (no Eq, no Serde derived).
        let op_open = ParsedDisputeOp::Open {
            contested_record_id: "r-1".into(),
            reason: "bad".into(),
        };
        let op_ev = ParsedDisputeOp::Evidence {
            dispute_id: "d-1".into(),
            evidence_data: "ev".into(),
        };
        let op_re = ParsedDisputeOp::Resolve {
            dispute_id: "d-1".into(),
            outcome: "upheld".into(),
        };

        // Debug contains variant names.
        assert!(format!("{op_open:?}").contains("Open"));
        assert!(format!("{op_ev:?}").contains("Evidence"));
        assert!(format!("{op_re:?}").contains("Resolve"));

        // Clone independence.
        let _o = op_open.clone();
        let _e = op_ev.clone();
        let _r = op_re.clone();

        // Variant fields exhaustive match-destructure (compile-time stability).
        match &op_open {
            ParsedDisputeOp::Open { contested_record_id, reason } => {
                assert_eq!(contested_record_id, "r-1");
                assert_eq!(reason, "bad");
            }
            _ => panic!("expected Open"),
        }
        match &op_ev {
            ParsedDisputeOp::Evidence { dispute_id, evidence_data } => {
                assert_eq!(dispute_id, "d-1");
                assert_eq!(evidence_data, "ev");
            }
            _ => panic!("expected Evidence"),
        }
        match &op_re {
            ParsedDisputeOp::Resolve { dispute_id, outcome } => {
                assert_eq!(dispute_id, "d-1");
                assert_eq!(outcome, "upheld");
            }
            _ => panic!("expected Resolve"),
        }
    }

    #[test]
    fn batch_b_dispute_resolution_and_dispute_struct_field_shape_and_serde_roundtrip() {
        // Axis 3: DisputeResolution 3-field + Dispute 9-field exhaustive
        // destructure + serde round-trip preserves None arms.

        // DisputeResolution 3-field exhaustive destructure (compile-time
        // field-name stability — load-bearing for wire format).
        let res = DisputeResolution {
            resolved_at: 2500.0,
            resolver: "consensus".to_string(),
            outcome: "upheld".to_string(),
        };
        let DisputeResolution {
            resolved_at: _,
            resolver: _,
            outcome: _,
        } = &res;

        let _ra: f64 = res.resolved_at;
        let _rv: String = res.resolver.clone();
        let _oc: String = res.outcome.clone();

        // DisputeResolution serde round-trip preserves all 3 fields.
        let r_json = serde_json::to_string(&res).unwrap();
        let r_back: DisputeResolution = serde_json::from_str(&r_json).unwrap();
        assert_eq!(r_back.resolved_at, res.resolved_at);
        assert_eq!(r_back.resolver, res.resolver);
        assert_eq!(r_back.outcome, res.outcome);

        // Dispute 9-field exhaustive destructure.
        let d = Dispute {
            id: "d-1".to_string(),
            contested_record_id: "r-1".to_string(),
            opener: "alice".to_string(),
            reason: "tampering".to_string(),
            opened_at: 1000.0,
            status: DisputeStatus::EvidencePhase,
            evidence_ids: vec!["e-1".to_string(), "e-2".to_string()],
            governance_proposal_id: Some("gp-1".to_string()),
            resolution: Some(res.clone()),
        };
        let Dispute {
            id: _,
            contested_record_id: _,
            opener: _,
            reason: _,
            opened_at: _,
            status: _,
            evidence_ids: _,
            governance_proposal_id: _,
            resolution: _,
        } = &d;

        // Per-field type pin.
        let _id: String = d.id.clone();
        let _cr: String = d.contested_record_id.clone();
        let _op: String = d.opener.clone();
        let _re: String = d.reason.clone();
        let _oa: f64 = d.opened_at;
        let _st: DisputeStatus = d.status.clone();
        let _ev: Vec<String> = d.evidence_ids.clone();
        let _gp: Option<String> = d.governance_proposal_id.clone();
        let _rs: Option<DisputeResolution> = d.resolution.clone();

        // Dispute serde JSON round-trip preserves all 9 fields (no PartialEq
        // derived on Dispute so compare field-by-field).
        let d_json = serde_json::to_string(&d).unwrap();
        let d_back: Dispute = serde_json::from_str(&d_json).unwrap();
        assert_eq!(d_back.id, d.id);
        assert_eq!(d_back.contested_record_id, d.contested_record_id);
        assert_eq!(d_back.opener, d.opener);
        assert_eq!(d_back.reason, d.reason);
        assert_eq!(d_back.opened_at, d.opened_at);
        assert_eq!(d_back.status, d.status);
        assert_eq!(d_back.evidence_ids, d.evidence_ids);
        assert_eq!(d_back.governance_proposal_id, d.governance_proposal_id);
        assert_eq!(d_back.resolution.as_ref().map(|r| (r.resolved_at, r.resolver.clone(), r.outcome.clone())),
            d.resolution.as_ref().map(|r| (r.resolved_at, r.resolver.clone(), r.outcome.clone())));

        // None-arm Dispute (governance_proposal_id=None + resolution=None)
        // round-trips cleanly.
        let d_none = Dispute {
            id: "d-2".to_string(),
            contested_record_id: "r-2".to_string(),
            opener: "bob".to_string(),
            reason: "x".to_string(),
            opened_at: 0.0,
            status: DisputeStatus::Open,
            evidence_ids: vec![],
            governance_proposal_id: None,
            resolution: None,
        };
        let json_none = serde_json::to_string(&d_none).unwrap();
        let back_none: Dispute = serde_json::from_str(&json_none).unwrap();
        assert!(back_none.governance_proposal_id.is_none());
        assert!(back_none.resolution.is_none());
        assert!(back_none.evidence_ids.is_empty());

        // DisputeState 1-field shape + new()==default initial-state pin.
        let s_new = DisputeState::new();
        let s_def = DisputeState::default();
        assert_eq!(s_new.disputes.len(), 0);
        assert_eq!(s_def.disputes.len(), 0);
        assert_eq!(s_new.dispute_count(), 0);

        // DisputeState empty-state serde round-trip.
        let s_json = serde_json::to_string(&s_new).unwrap();
        let s_back: DisputeState = serde_json::from_str(&s_json).unwrap();
        assert_eq!(s_back.dispute_count(), 0);

        // Clone independence (mutating clone leaves original untouched).
        let s_orig = DisputeState::default();
        let mut s_clone = s_orig.clone();
        s_clone.disputes.insert("x".into(), d.clone());
        assert_eq!(s_orig.dispute_count(), 0,
            "original unchanged after clone mutation");
        assert_eq!(s_clone.dispute_count(), 1);
    }

    #[test]
    fn batch_b_dispute_metadata_builders_exact_3_keys_and_btreemap_sorted_and_extract_exhaustive() {
        // Axis 4: metadata builders exact 3-key shape + BTreeMap ASCII-sorted
        // iteration + extract_dispute_op positive + None paths exhaustive.

        // open_dispute_metadata: exactly 3 keys
        // (dispute_op + dispute_record_id + dispute_reason).
        let m_open = open_dispute_metadata("r-x", "reason-x");
        assert_eq!(m_open.len(), 3);
        assert_eq!(m_open[DISPUTE_OP_KEY], serde_json::json!("open"));
        assert_eq!(m_open["dispute_record_id"], serde_json::json!("r-x"));
        assert_eq!(m_open["dispute_reason"], serde_json::json!("reason-x"));

        // BTreeMap iteration is ASCII-sorted by key — pin it.
        let keys_open: Vec<&String> = m_open.keys().collect();
        let mut sorted_open = keys_open.clone();
        sorted_open.sort();
        assert_eq!(keys_open, sorted_open);
        // Concretely: dispute_op < dispute_reason < dispute_record_id ASCII.
        assert_eq!(keys_open[0], "dispute_op");
        assert_eq!(keys_open[1], "dispute_reason");
        assert_eq!(keys_open[2], "dispute_record_id");

        // evidence_metadata: 3 keys (dispute_op + dispute_id + dispute_evidence).
        let m_ev = evidence_metadata("d-1", "ev-1");
        assert_eq!(m_ev.len(), 3);
        assert_eq!(m_ev[DISPUTE_OP_KEY], serde_json::json!("evidence"));
        assert_eq!(m_ev["dispute_id"], serde_json::json!("d-1"));
        assert_eq!(m_ev["dispute_evidence"], serde_json::json!("ev-1"));
        // ASCII sort: dispute_evidence < dispute_id < dispute_op.
        let keys_ev: Vec<&String> = m_ev.keys().collect();
        assert_eq!(keys_ev[0], "dispute_evidence");
        assert_eq!(keys_ev[1], "dispute_id");
        assert_eq!(keys_ev[2], "dispute_op");

        // resolve_metadata: 3 keys (dispute_op + dispute_id + dispute_outcome).
        let m_re = resolve_metadata("d-1", "upheld");
        assert_eq!(m_re.len(), 3);
        assert_eq!(m_re[DISPUTE_OP_KEY], serde_json::json!("resolve"));
        assert_eq!(m_re["dispute_id"], serde_json::json!("d-1"));
        assert_eq!(m_re["dispute_outcome"], serde_json::json!("upheld"));
        let keys_re: Vec<&String> = m_re.keys().collect();
        assert_eq!(keys_re[0], "dispute_id");
        assert_eq!(keys_re[1], "dispute_op");
        assert_eq!(keys_re[2], "dispute_outcome");

        // extract_dispute_op positive round-trip per op-shape.
        let parsed = extract_dispute_op(&m_open).unwrap().unwrap();
        match parsed {
            ParsedDisputeOp::Open { contested_record_id, reason } => {
                assert_eq!(contested_record_id, "r-x");
                assert_eq!(reason, "reason-x");
            }
            _ => panic!("expected Open"),
        }

        let parsed = extract_dispute_op(&m_ev).unwrap().unwrap();
        match parsed {
            ParsedDisputeOp::Evidence { dispute_id, evidence_data } => {
                assert_eq!(dispute_id, "d-1");
                assert_eq!(evidence_data, "ev-1");
            }
            _ => panic!("expected Evidence"),
        }

        let parsed = extract_dispute_op(&m_re).unwrap().unwrap();
        match parsed {
            ParsedDisputeOp::Resolve { dispute_id, outcome } => {
                assert_eq!(dispute_id, "d-1");
                assert_eq!(outcome, "upheld");
            }
            _ => panic!("expected Resolve"),
        }

        // extract_dispute_op None paths exhaustive.

        // (a) empty BTreeMap → no DISPUTE_OP_KEY → Ok(None).
        let empty = std::collections::BTreeMap::<String, serde_json::Value>::new();
        assert!(extract_dispute_op(&empty).unwrap().is_none());

        // (b) BTreeMap with unrelated keys → still Ok(None).
        let mut other = std::collections::BTreeMap::new();
        other.insert("other_op".to_string(), serde_json::json!("foo"));
        assert!(extract_dispute_op(&other).unwrap().is_none());

        // (c) dispute_op not a string → Err.
        let mut bad_type = std::collections::BTreeMap::new();
        bad_type.insert(DISPUTE_OP_KEY.to_string(), serde_json::json!(42));
        let err = format!("{}", extract_dispute_op(&bad_type).unwrap_err());
        assert!(err.contains("must be a string"), "got: {err}");

        // (d) unknown op value → Err.
        let mut unknown = std::collections::BTreeMap::new();
        unknown.insert(DISPUTE_OP_KEY.to_string(), serde_json::json!("vote"));
        let err = format!("{}", extract_dispute_op(&unknown).unwrap_err());
        assert!(err.contains("unknown dispute op"), "got: {err}");

        // (e) open missing dispute_record_id → Err.
        let mut m = std::collections::BTreeMap::new();
        m.insert(DISPUTE_OP_KEY.to_string(), serde_json::json!("open"));
        m.insert("dispute_reason".to_string(), serde_json::json!("r"));
        let err = format!("{}", extract_dispute_op(&m).unwrap_err());
        assert!(err.contains("dispute_record_id"), "got: {err}");

        // (f) open missing dispute_reason → Err.
        let mut m = std::collections::BTreeMap::new();
        m.insert(DISPUTE_OP_KEY.to_string(), serde_json::json!("open"));
        m.insert("dispute_record_id".to_string(), serde_json::json!("r"));
        let err = format!("{}", extract_dispute_op(&m).unwrap_err());
        assert!(err.contains("dispute_reason"), "got: {err}");

        // (g) evidence missing dispute_id → Err.
        let mut m = std::collections::BTreeMap::new();
        m.insert(DISPUTE_OP_KEY.to_string(), serde_json::json!("evidence"));
        m.insert("dispute_evidence".to_string(), serde_json::json!("ev"));
        let err = format!("{}", extract_dispute_op(&m).unwrap_err());
        assert!(err.contains("dispute_id"), "got: {err}");

        // (h) evidence missing dispute_evidence → Err.
        let mut m = std::collections::BTreeMap::new();
        m.insert(DISPUTE_OP_KEY.to_string(), serde_json::json!("evidence"));
        m.insert("dispute_id".to_string(), serde_json::json!("d-1"));
        let err = format!("{}", extract_dispute_op(&m).unwrap_err());
        assert!(err.contains("dispute_evidence"), "got: {err}");

        // (i) resolve missing dispute_outcome → Err.
        let mut m = std::collections::BTreeMap::new();
        m.insert(DISPUTE_OP_KEY.to_string(), serde_json::json!("resolve"));
        m.insert("dispute_id".to_string(), serde_json::json!("d-1"));
        let err = format!("{}", extract_dispute_op(&m).unwrap_err());
        assert!(err.contains("dispute_outcome"), "got: {err}");

        // (j) field present but wrong type (number instead of string) → Err.
        let mut m = std::collections::BTreeMap::new();
        m.insert(DISPUTE_OP_KEY.to_string(), serde_json::json!("open"));
        m.insert("dispute_record_id".to_string(), serde_json::json!("r"));
        m.insert("dispute_reason".to_string(), serde_json::json!(42));
        let err = format!("{}", extract_dispute_op(&m).unwrap_err());
        assert!(err.contains("must be a string"), "got: {err}");
    }

    #[test]
    fn batch_b_dispute_verify_dispute_matrix_open_resolve_dispatch_and_escalate_state_gate() {
        // Axis 5: verify_dispute negative matrix + open_dispute uniqueness +
        // resolve outcome dispatch + escalate_to_governance state-gate matrix.

        // verify_dispute Open: both fields required non-empty.
        let valid = ParsedDisputeOp::Open {
            contested_record_id: "r-1".into(),
            reason: "tampering".into(),
        };
        verify_dispute(&valid).expect("valid Open accepted");

        let empty_rec = ParsedDisputeOp::Open {
            contested_record_id: String::new(),
            reason: "x".into(),
        };
        let err = format!("{}", verify_dispute(&empty_rec).unwrap_err());
        assert!(err.contains("contested_record_id"), "got: {err}");

        let empty_reason = ParsedDisputeOp::Open {
            contested_record_id: "r-1".into(),
            reason: String::new(),
        };
        let err = format!("{}", verify_dispute(&empty_reason).unwrap_err());
        assert!(err.contains("reason"), "got: {err}");

        // verify_dispute Evidence: both fields required non-empty.
        let valid_ev = ParsedDisputeOp::Evidence {
            dispute_id: "d-1".into(),
            evidence_data: "data".into(),
        };
        verify_dispute(&valid_ev).expect("valid Evidence accepted");

        let empty_id = ParsedDisputeOp::Evidence {
            dispute_id: String::new(),
            evidence_data: "x".into(),
        };
        let err = format!("{}", verify_dispute(&empty_id).unwrap_err());
        assert!(err.contains("dispute_id"), "got: {err}");

        let empty_data = ParsedDisputeOp::Evidence {
            dispute_id: "d-1".into(),
            evidence_data: String::new(),
        };
        let err = format!("{}", verify_dispute(&empty_data).unwrap_err());
        assert!(err.contains("evidence_data"), "got: {err}");

        // verify_dispute Resolve: outcome must be in the canonical set.
        for outcome in &["upheld", "dismissed", "voided"] {
            let op = ParsedDisputeOp::Resolve {
                dispute_id: "d-1".into(),
                outcome: (*outcome).into(),
            };
            verify_dispute(&op).unwrap_or_else(|e|
                panic!("outcome '{outcome}' should be valid: {e}"));
        }

        for bad in &["maybe", "unknown", "", "UPHELD", " upheld"] {
            let op = ParsedDisputeOp::Resolve {
                dispute_id: "d-1".into(),
                outcome: (*bad).into(),
            };
            let err = verify_dispute(&op).unwrap_err();
            // empty outcome triggers the outcome-set check OR is detected by
            // the outcome-not-in-set arm — either way Err is the contract.
            let _ = format!("{err}");
        }

        // verify_dispute Resolve: empty dispute_id rejected.
        let empty_rid = ParsedDisputeOp::Resolve {
            dispute_id: String::new(),
            outcome: "upheld".into(),
        };
        let err = format!("{}", verify_dispute(&empty_rid).unwrap_err());
        assert!(err.contains("dispute_id"), "got: {err}");

        // open_dispute uniqueness invariants.
        let mut s = DisputeState::new();
        s.open_dispute("d-A".into(), "r-1".into(), "alice".into(), "x".into(), 100.0)
            .expect("first open ok");
        let d = s.get("d-A").unwrap();
        // Post-open state: status=Open, evidence_ids empty, governance None,
        // resolution None, opened_at=100.0.
        assert_eq!(d.status, DisputeStatus::Open);
        assert!(d.evidence_ids.is_empty());
        assert!(d.governance_proposal_id.is_none());
        assert!(d.resolution.is_none());
        assert_eq!(d.opened_at, 100.0);

        // Duplicate dispute_id rejected.
        let err = format!("{}",
            s.open_dispute("d-A".into(), "r-2".into(), "bob".into(), "y".into(), 200.0).unwrap_err());
        assert!(err.contains("already exists"), "got: {err}");

        // Duplicate contested_record_id with an ACTIVE dispute rejected.
        let err = format!("{}",
            s.open_dispute("d-B".into(), "r-1".into(), "bob".into(), "y".into(), 200.0).unwrap_err());
        assert!(err.contains("already exists"), "got: {err}");

        // After resolving d-A, r-1 has no active dispute — new dispute on r-1 accepted.
        s.resolve("d-A", "consensus", "upheld", 300.0).unwrap();
        s.open_dispute("d-C".into(), "r-1".into(), "carol".into(), "z".into(), 400.0)
            .expect("post-resolve r-1 reusable");
        assert_eq!(s.dispute_count(), 2);

        // resolve outcome dispatch matrix.
        // outcome=="dismissed" → DisputeStatus::Dismissed
        // outcome=="upheld" / "voided" / anything-else → DisputeStatus::Resolved
        let mut s2 = DisputeState::new();
        s2.open_dispute("d-up".into(), "r-up".into(), "a".into(), "x".into(), 1.0).unwrap();
        s2.resolve("d-up", "consensus", "upheld", 2.0).unwrap();
        assert_eq!(s2.get("d-up").unwrap().status, DisputeStatus::Resolved);
        assert_eq!(s2.get("d-up").unwrap().resolution.as_ref().unwrap().outcome, "upheld");
        assert_eq!(s2.get("d-up").unwrap().resolution.as_ref().unwrap().resolver, "consensus");

        s2.open_dispute("d-dm".into(), "r-dm".into(), "a".into(), "x".into(), 3.0).unwrap();
        s2.resolve("d-dm", "gov", "dismissed", 4.0).unwrap();
        assert_eq!(s2.get("d-dm").unwrap().status, DisputeStatus::Dismissed);

        s2.open_dispute("d-vo".into(), "r-vo".into(), "a".into(), "x".into(), 5.0).unwrap();
        s2.resolve("d-vo", "genesis", "voided", 6.0).unwrap();
        assert_eq!(s2.get("d-vo").unwrap().status, DisputeStatus::Resolved);
        assert_eq!(s2.get("d-vo").unwrap().resolution.as_ref().unwrap().outcome, "voided");

        // Non-canonical outcome string still routes to Resolved (only
        // "dismissed" gates the Dismissed branch — by-design).
        s2.open_dispute("d-other".into(), "r-other".into(), "a".into(), "x".into(), 7.0).unwrap();
        s2.resolve("d-other", "consensus", "anything", 8.0).unwrap();
        assert_eq!(s2.get("d-other").unwrap().status, DisputeStatus::Resolved);
        assert_eq!(s2.get("d-other").unwrap().resolution.as_ref().unwrap().outcome, "anything");

        // Re-resolve a closed dispute is rejected.
        let err = format!("{}",
            s2.resolve("d-up", "x", "voided", 9.0).unwrap_err());
        assert!(err.contains("already closed"), "got: {err}");

        // escalate_to_governance state-gate matrix.
        // Open → OK (transitions to CommunityReview).
        let mut s3 = DisputeState::new();
        s3.open_dispute("e-1".into(), "r".into(), "a".into(), "x".into(), 1.0).unwrap();
        assert_eq!(s3.get("e-1").unwrap().status, DisputeStatus::Open);
        s3.escalate_to_governance("e-1", "gp-1".into()).expect("Open escalation ok");
        assert_eq!(s3.get("e-1").unwrap().status, DisputeStatus::CommunityReview);
        assert_eq!(s3.get("e-1").unwrap().governance_proposal_id.as_deref(),
            Some("gp-1"));

        // CommunityReview → cannot escalate again (must be Open or EvidencePhase).
        let err = format!("{}",
            s3.escalate_to_governance("e-1", "gp-2".into()).unwrap_err());
        assert!(err.contains("cannot escalate"), "got: {err}");

        // EvidencePhase → OK (add_evidence transitions then escalate).
        let mut s4 = DisputeState::new();
        s4.open_dispute("e-2".into(), "r".into(), "a".into(), "x".into(), 1.0).unwrap();
        s4.add_evidence("e-2", "ev-1".into(), 1.5, 3600.0).unwrap();
        assert_eq!(s4.get("e-2").unwrap().status, DisputeStatus::EvidencePhase);
        s4.escalate_to_governance("e-2", "gp-3".into()).expect("EvidencePhase ok");

        // Resolved → cannot escalate.
        let mut s5 = DisputeState::new();
        s5.open_dispute("e-3".into(), "r".into(), "a".into(), "x".into(), 1.0).unwrap();
        s5.resolve("e-3", "consensus", "upheld", 2.0).unwrap();
        let err = format!("{}",
            s5.escalate_to_governance("e-3", "gp-4".into()).unwrap_err());
        assert!(err.contains("cannot escalate"), "got: {err}");

        // Dismissed → cannot escalate.
        let mut s6 = DisputeState::new();
        s6.open_dispute("e-4".into(), "r".into(), "a".into(), "x".into(), 1.0).unwrap();
        s6.resolve("e-4", "consensus", "dismissed", 2.0).unwrap();
        let err = format!("{}",
            s6.escalate_to_governance("e-4", "gp-5".into()).unwrap_err());
        assert!(err.contains("cannot escalate"), "got: {err}");

        // Unknown dispute_id → Err (not found).
        let mut s7 = DisputeState::new();
        let err = format!("{}",
            s7.escalate_to_governance("nope", "gp".into()).unwrap_err());
        assert!(err.contains("not found"), "got: {err}");

        // add_evidence: window-expired rejected.
        let mut s8 = DisputeState::new();
        s8.open_dispute("w-1".into(), "r".into(), "a".into(), "x".into(), 1000.0).unwrap();
        // Just inside window: ts - opened_at <= window.
        s8.add_evidence("w-1", "ev-in".into(), 1000.0 + 3600.0, 3600.0)
            .expect("at exact window boundary accepted (uses > not >=)");
        // Just past window: ts - opened_at > window.
        let err = format!("{}",
            s8.add_evidence("w-1", "ev-out".into(), 1000.0 + 3600.0 + 0.001, 3600.0).unwrap_err());
        assert!(err.contains("evidence window"), "got: {err}");

        // add_evidence on closed dispute rejected.
        let mut s9 = DisputeState::new();
        s9.open_dispute("c-1".into(), "r".into(), "a".into(), "x".into(), 1.0).unwrap();
        s9.resolve("c-1", "consensus", "upheld", 2.0).unwrap();
        let err = format!("{}",
            s9.add_evidence("c-1", "ev".into(), 3.0, 3600.0).unwrap_err());
        assert!(err.contains("closed"), "got: {err}");

        // add_evidence on dismissed dispute rejected.
        let mut sa = DisputeState::new();
        sa.open_dispute("c-2".into(), "r".into(), "a".into(), "x".into(), 1.0).unwrap();
        sa.resolve("c-2", "consensus", "dismissed", 2.0).unwrap();
        let err = format!("{}",
            sa.add_evidence("c-2", "ev".into(), 3.0, 3600.0).unwrap_err());
        assert!(err.contains("closed"), "got: {err}");
    }
}
