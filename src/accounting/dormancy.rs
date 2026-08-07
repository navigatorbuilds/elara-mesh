//! Dormancy 3-Phase Lifecycle — economics v0.4.1 Section 2.5.
//!
//! - Phase 1 (Active): `last_active` updated by any signed transaction.
//! - Phase 2 (Dormant): After 5 years of inactivity (DORMANCY_THRESHOLD), requires
//!   DORMANCY_DECLARE record with 2+ independent witnesses.
//! - Phase 3 (Wake-up Window): 2-year window (DORMANCY_WAKEUP_WINDOW) where identity
//!   can prove liveness via signed transaction, heartbeat, or relay proof-of-life.
//! - Phase 4 (Reclamation): After 7 years total inactivity, DORMANCY_RECLAIM moves
//!   100% of liquid beats to Conservation Pool. Identity survives.

//!
//! Spec references:
//!   @spec economics §2.5

use std::collections::HashMap;

use crate::accounting::types::{DORMANCY_THRESHOLD, DORMANCY_WAKEUP_WINDOW};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Minimum independent witnesses required for a DORMANCY_DECLARE record.
pub const DORMANCY_MIN_WITNESSES: usize = 2;

/// Operation key for dormancy records in metadata.
pub const DORMANCY_OP_KEY: &str = "dormancy_op";

// ─── Types ─────────────────────────────────────────────────────────────────

/// Dormancy lifecycle phase for an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DormancyPhase {
    /// Normal operation. `last_active` updated by any signed transaction.
    Active,
    /// Formally declared dormant (20+ years inactive). 2-year wake-up window starts.
    Dormant,
    /// Beats reclaimed. Identity survives but balance is zero.
    Reclaimed,
}

/// A dormancy declaration record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DormancyDeclaration {
    /// Identity hash of the dormant account.
    pub target_identity: String,
    /// Identity hash of the challenger who filed the declaration.
    pub declared_by: String,
    /// Timestamp of the declaration.
    pub declared_at: f64,
    /// Last known active timestamp from the target's DAG history.
    pub last_known_active: f64,
    /// Deadline for the wake-up window (declared_at + 2 years).
    pub wakeup_deadline: f64,
    /// Number of witnesses at declaration time.
    pub witness_count: usize,
}

/// Parsed dormancy operation from record metadata.
#[derive(Debug, Clone)]
pub enum ParsedDormancyOp {
    /// Declare an identity as dormant.
    Declare {
        target_identity: String,
        last_known_active: f64,
    },
    /// Heartbeat proof-of-life from the dormant identity itself.
    Heartbeat,
    /// Third-party relay of a signed proof-of-life message.
    ProofOfLife {
        target_identity: String,
        /// The proof-of-life signature (hex-encoded).
        signature: String,
    },
}

// ─── State ─────────────────────────────────────────────────────────────────

/// Tracks dormancy lifecycle state for all identities.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DormancyState {
    /// Active declarations (target_identity → declaration).
    pub declarations: HashMap<String, DormancyDeclaration>,
    /// Phase per identity (only non-Active phases stored).
    pub phases: HashMap<String, DormancyPhase>,
    /// Reclaimed identities and the amount reclaimed.
    pub reclaimed: HashMap<String, u64>,
}

impl DormancyState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the current phase for an identity.
    pub fn phase(&self, identity: &str) -> DormancyPhase {
        self.phases.get(identity).copied().unwrap_or(DormancyPhase::Active)
    }

    /// Check if an identity is eligible for dormancy declaration.
    /// Requires 20+ years of inactivity.
    pub fn eligible_for_declaration(
        &self,
        last_active: f64,
        now: f64,
    ) -> bool {
        let inactive = now - last_active;
        inactive >= DORMANCY_THRESHOLD
    }

    /// Declare an identity as dormant. Returns error string if invalid.
    pub fn declare(
        &mut self,
        target_identity: &str,
        declared_by: &str,
        last_known_active: f64,
        now: f64,
        witness_count: usize,
    ) -> Result<(), String> {
        // Must not already be declared or reclaimed
        match self.phase(target_identity) {
            DormancyPhase::Dormant => {
                return Err("identity already declared dormant".into());
            }
            DormancyPhase::Reclaimed => {
                return Err("identity already reclaimed".into());
            }
            DormancyPhase::Active => {}
        }

        // Must have enough witnesses
        if witness_count < DORMANCY_MIN_WITNESSES {
            return Err(format!(
                "dormancy declaration requires {} witnesses, got {}",
                DORMANCY_MIN_WITNESSES, witness_count
            ));
        }

        // Must be inactive for 20+ years
        if !self.eligible_for_declaration(last_known_active, now) {
            return Err(format!(
                "identity not eligible: last active {:.0}s ago, need {:.0}s",
                now - last_known_active,
                DORMANCY_THRESHOLD
            ));
        }

        let declaration = DormancyDeclaration {
            target_identity: target_identity.to_string(),
            declared_by: declared_by.to_string(),
            declared_at: now,
            last_known_active,
            wakeup_deadline: now + DORMANCY_WAKEUP_WINDOW,
            witness_count,
        };

        self.declarations
            .insert(target_identity.to_string(), declaration);
        self.phases
            .insert(target_identity.to_string(), DormancyPhase::Dormant);

        Ok(())
    }

    /// Wake up a dormant identity (proof of liveness received).
    /// Returns error string if identity is not in wake-up window.
    pub fn wake_up(&mut self, identity: &str, now: f64) -> Result<(), String> {
        match self.phase(identity) {
            DormancyPhase::Active => {
                return Err("identity is already active".into());
            }
            DormancyPhase::Reclaimed => {
                return Err("identity already reclaimed — cannot wake up".into());
            }
            DormancyPhase::Dormant => {}
        }

        // Check we're within the wake-up window
        if let Some(decl) = self.declarations.get(identity) {
            if now > decl.wakeup_deadline {
                return Err(format!(
                    "wake-up window expired at {:.0}, current time {:.0}",
                    decl.wakeup_deadline, now
                ));
            }
        }

        // Reset to active
        self.phases.remove(identity);
        self.declarations.remove(identity);

        Ok(())
    }

    /// Check if a dormant identity's wake-up window has expired
    /// and is eligible for reclamation (7 years total: 5yr dormancy + 2yr wake-up).
    pub fn eligible_for_reclamation(&self, identity: &str, now: f64) -> bool {
        if self.phase(identity) != DormancyPhase::Dormant {
            return false;
        }
        if let Some(decl) = self.declarations.get(identity) {
            now > decl.wakeup_deadline
        } else {
            false
        }
    }

    /// Record a reclamation (called after DormancyReclaim ledger op executes).
    pub fn record_reclamation(&mut self, identity: &str, amount: u64) {
        self.phases
            .insert(identity.to_string(), DormancyPhase::Reclaimed);
        self.reclaimed.insert(identity.to_string(), amount);
        self.declarations.remove(identity);
    }

    /// Get the declaration for an identity (if any).
    pub fn declaration(&self, identity: &str) -> Option<&DormancyDeclaration> {
        self.declarations.get(identity)
    }

    /// Number of currently dormant identities.
    pub fn dormant_count(&self) -> usize {
        self.phases
            .values()
            .filter(|p| **p == DormancyPhase::Dormant)
            .count()
    }

    /// Number of reclaimed identities.
    pub fn reclaimed_count(&self) -> usize {
        self.phases
            .values()
            .filter(|p| **p == DormancyPhase::Reclaimed)
            .count()
    }

    /// Total reclaimed amount across all identities.
    pub fn total_reclaimed(&self) -> u64 {
        self.reclaimed.values().sum()
    }

    /// All dormant identities with their declarations.
    pub fn dormant_identities(&self) -> Vec<&DormancyDeclaration> {
        self.declarations.values().collect()
    }

    /// Find identities eligible for reclamation (wake-up window expired).
    pub fn reclaimable(&self, now: f64) -> Vec<String> {
        self.declarations
            .iter()
            .filter(|(_, decl)| now > decl.wakeup_deadline)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

// ─── Metadata Builders ────────────────────────────────────────────────────

/// Build metadata for a DORMANCY_DECLARE record.
pub fn declare_metadata(
    target_identity: &str,
    last_known_active: f64,
) -> std::collections::BTreeMap<String, String> {
    let mut meta = std::collections::BTreeMap::new();
    meta.insert(DORMANCY_OP_KEY.into(), "declare".into());
    meta.insert("target_identity".into(), target_identity.into());
    meta.insert(
        "last_known_active".into(),
        format!("{:.0}", last_known_active),
    );
    meta
}

/// Build metadata for a heartbeat proof-of-life.
pub fn heartbeat_metadata() -> std::collections::BTreeMap<String, String> {
    let mut meta = std::collections::BTreeMap::new();
    meta.insert(DORMANCY_OP_KEY.into(), "heartbeat".into());
    meta
}

/// Build metadata for a third-party proof-of-life relay.
pub fn proof_of_life_metadata(
    target_identity: &str,
    signature: &str,
) -> std::collections::BTreeMap<String, String> {
    let mut meta = std::collections::BTreeMap::new();
    meta.insert(DORMANCY_OP_KEY.into(), "proof_of_life".into());
    meta.insert("target_identity".into(), target_identity.into());
    meta.insert("signature".into(), signature.into());
    meta
}

/// Extract a dormancy operation from record metadata.
pub fn extract_dormancy_op(
    metadata: &std::collections::BTreeMap<String, String>,
) -> Option<ParsedDormancyOp> {
    let op = metadata.get(DORMANCY_OP_KEY)?;
    match op.as_str() {
        "declare" => {
            let target = metadata.get("target_identity")?.clone();
            let last_active: f64 = metadata.get("last_known_active")?.parse().ok()?;
            Some(ParsedDormancyOp::Declare {
                target_identity: target,
                last_known_active: last_active,
            })
        }
        "heartbeat" => Some(ParsedDormancyOp::Heartbeat),
        "proof_of_life" => {
            let target = metadata.get("target_identity")?.clone();
            let sig = metadata.get("signature")?.clone();
            Some(ParsedDormancyOp::ProofOfLife {
                target_identity: target,
                signature: sig,
            })
        }
        _ => None,
    }
}

// ─── Rebuild ──────────────────────────────────────────────────────────────

/// Rebuild dormancy state from a sequence of records (for DAG replay).
/// Each tuple: (op, creator_hash, metadata, timestamp, witness_count).
pub fn rebuild_dormancy_state(
    records: &[(ParsedDormancyOp, String, f64, usize)],
) -> DormancyState {
    let mut state = DormancyState::new();
    for (op, creator, timestamp, witness_count) in records {
        match op {
            ParsedDormancyOp::Declare {
                target_identity,
                last_known_active,
            } => {
                let _ = state.declare(
                    target_identity,
                    creator,
                    *last_known_active,
                    *timestamp,
                    *witness_count,
                );
            }
            ParsedDormancyOp::Heartbeat => {
                // Heartbeat from the creator → wake up the creator
                let _ = state.wake_up(creator, *timestamp);
            }
            ParsedDormancyOp::ProofOfLife {
                target_identity, ..
            } => {
                let _ = state.wake_up(target_identity, *timestamp);
            }
        }
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    const YEAR: f64 = 365.25 * 24.0 * 3600.0;

    #[test]
    fn test_eligibility_threshold() {
        let state = DormancyState::new();
        // 4 years: not eligible (threshold is 5)
        assert!(!state.eligible_for_declaration(0.0, 4.0 * YEAR));
        // 5 years: eligible
        assert!(state.eligible_for_declaration(0.0, 5.0 * YEAR));
        // 10 years: definitely eligible
        assert!(state.eligible_for_declaration(0.0, 10.0 * YEAR));
    }

    #[test]
    fn test_declare_success() {
        let mut state = DormancyState::new();
        let now = 21.0 * YEAR; // 21 years since last active
        let result = state.declare("alice", "bob", 0.0, now, 3);
        assert!(result.is_ok());
        assert_eq!(state.phase("alice"), DormancyPhase::Dormant);
        assert_eq!(state.dormant_count(), 1);
    }

    #[test]
    fn test_declare_insufficient_witnesses() {
        let mut state = DormancyState::new();
        let now = 21.0 * YEAR;
        let result = state.declare("alice", "bob", 0.0, now, 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("witnesses"));
    }

    #[test]
    fn test_declare_not_inactive_enough() {
        let mut state = DormancyState::new();
        let now = 3.0 * YEAR; // Only 3 years (threshold is 5)
        let result = state.declare("alice", "bob", 0.0, now, 3);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not eligible"));
    }

    #[test]
    fn test_declare_already_dormant() {
        let mut state = DormancyState::new();
        let now = 21.0 * YEAR;
        state.declare("alice", "bob", 0.0, now, 3).unwrap();
        let result = state.declare("alice", "carol", 0.0, now + 100.0, 2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already declared"));
    }

    #[test]
    fn test_wake_up_within_window() {
        let mut state = DormancyState::new();
        let declared_at = 21.0 * YEAR;
        state.declare("alice", "bob", 0.0, declared_at, 3).unwrap();

        // Wake up 1 year into the 2-year window
        let wake_time = declared_at + 1.0 * YEAR;
        let result = state.wake_up("alice", wake_time);
        assert!(result.is_ok());
        assert_eq!(state.phase("alice"), DormancyPhase::Active);
        assert_eq!(state.dormant_count(), 0);
    }

    #[test]
    fn test_wake_up_expired_window() {
        let mut state = DormancyState::new();
        let declared_at = 21.0 * YEAR;
        state.declare("alice", "bob", 0.0, declared_at, 3).unwrap();

        // Try to wake up after 2-year window
        let too_late = declared_at + 2.5 * YEAR;
        let result = state.wake_up("alice", too_late);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn test_reclamation_eligibility() {
        let mut state = DormancyState::new();
        let declared_at = 21.0 * YEAR;
        state.declare("alice", "bob", 0.0, declared_at, 3).unwrap();

        // Before window expires: not reclaimable
        assert!(!state.eligible_for_reclamation("alice", declared_at + 1.0 * YEAR));

        // After window expires: reclaimable
        assert!(state.eligible_for_reclamation("alice", declared_at + 2.1 * YEAR));
    }

    #[test]
    fn test_record_reclamation() {
        let mut state = DormancyState::new();
        let declared_at = 21.0 * YEAR;
        state.declare("alice", "bob", 0.0, declared_at, 3).unwrap();

        state.record_reclamation("alice", 1_000_000);
        assert_eq!(state.phase("alice"), DormancyPhase::Reclaimed);
        assert_eq!(state.reclaimed_count(), 1);
        assert_eq!(state.total_reclaimed(), 1_000_000);
        assert!(state.declaration("alice").is_none()); // Declaration cleared
    }

    #[test]
    fn test_reclaimed_cannot_be_declared_again() {
        let mut state = DormancyState::new();
        let declared_at = 21.0 * YEAR;
        state.declare("alice", "bob", 0.0, declared_at, 3).unwrap();
        state.record_reclamation("alice", 1_000_000);

        let result = state.declare("alice", "carol", 0.0, 50.0 * YEAR, 3);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already reclaimed"));
    }

    #[test]
    fn test_reclaimed_cannot_wake_up() {
        let mut state = DormancyState::new();
        let declared_at = 21.0 * YEAR;
        state.declare("alice", "bob", 0.0, declared_at, 3).unwrap();
        state.record_reclamation("alice", 1_000_000);

        let result = state.wake_up("alice", declared_at + 0.5 * YEAR);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already reclaimed"));
    }

    #[test]
    fn test_reclaimable_list() {
        let mut state = DormancyState::new();
        let t1 = 21.0 * YEAR;
        let t2 = 22.0 * YEAR;
        state.declare("alice", "bob", 0.0, t1, 2).unwrap();
        state.declare("carol", "dave", 0.0, t2, 3).unwrap();

        // After alice's window but before carol's
        let now = t1 + 2.1 * YEAR;
        let reclaimable = state.reclaimable(now);
        assert_eq!(reclaimable.len(), 1);
        assert!(reclaimable.contains(&"alice".to_string()));
    }

    #[test]
    fn test_metadata_roundtrip_declare() {
        let meta = declare_metadata("alice_hash", 1000.0);
        let parsed = extract_dormancy_op(&meta).unwrap();
        match parsed {
            ParsedDormancyOp::Declare {
                target_identity,
                last_known_active,
            } => {
                assert_eq!(target_identity, "alice_hash");
                assert_eq!(last_known_active, 1000.0);
            }
            _ => panic!("expected Declare"),
        }
    }

    #[test]
    fn test_metadata_roundtrip_heartbeat() {
        let meta = heartbeat_metadata();
        let parsed = extract_dormancy_op(&meta).unwrap();
        assert!(matches!(parsed, ParsedDormancyOp::Heartbeat));
    }

    #[test]
    fn test_metadata_roundtrip_proof_of_life() {
        let meta = proof_of_life_metadata("alice_hash", "deadbeef");
        let parsed = extract_dormancy_op(&meta).unwrap();
        match parsed {
            ParsedDormancyOp::ProofOfLife {
                target_identity,
                signature,
            } => {
                assert_eq!(target_identity, "alice_hash");
                assert_eq!(signature, "deadbeef");
            }
            _ => panic!("expected ProofOfLife"),
        }
    }

    #[test]
    fn test_rebuild_state() {
        let t = 21.0 * YEAR;
        let records = vec![
            (
                ParsedDormancyOp::Declare {
                    target_identity: "alice".into(),
                    last_known_active: 0.0,
                },
                "bob".into(),
                t,
                3,
            ),
            (
                ParsedDormancyOp::Heartbeat,
                "alice".into(),
                t + 0.5 * YEAR,
                0,
            ),
        ];
        let state = rebuild_dormancy_state(&records);
        // Alice was declared then woke up via heartbeat
        assert_eq!(state.phase("alice"), DormancyPhase::Active);
        assert_eq!(state.dormant_count(), 0);
    }

    #[test]
    fn test_full_lifecycle() {
        let mut state = DormancyState::new();

        // Phase 1: Active (default)
        assert_eq!(state.phase("alice"), DormancyPhase::Active);

        // Phase 2: Declare dormant after 21 years
        let t1 = 21.0 * YEAR;
        state.declare("alice", "bob", 0.0, t1, 2).unwrap();
        assert_eq!(state.phase("alice"), DormancyPhase::Dormant);

        // Phase 3: Wake-up window — alice doesn't respond

        // Phase 4: Reclamation after window expires
        let t2 = t1 + DORMANCY_WAKEUP_WINDOW + 1.0;
        assert!(state.eligible_for_reclamation("alice", t2));
        state.record_reclamation("alice", 5_000_000);
        assert_eq!(state.phase("alice"), DormancyPhase::Reclaimed);
        assert_eq!(state.total_reclaimed(), 5_000_000);
    }

    // ── dormancy lifecycle tests (economics §2.5) ──────────────

    #[test]
    fn batch_b_dormancy_const_pin_with_cross_module_op_key_disjointness() {
        assert_eq!(DORMANCY_MIN_WITNESSES, 2, "MIN_WITNESSES pinned at 2 (independence requirement)");
        assert_eq!(DORMANCY_OP_KEY, "dormancy_op", "op key must be 'dormancy_op'");
        // Cross-module namespace disjointness — dormancy_op must NOT collide with
        // other ledger op keys (storage_op).
        assert_ne!(DORMANCY_OP_KEY, crate::accounting::storage_market::STORAGE_OP_KEY);
        // Sanity: op key is snake_case lowercase (no underscores at edges, no caps).
        assert!(DORMANCY_OP_KEY.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        assert!(!DORMANCY_OP_KEY.starts_with('_') && !DORMANCY_OP_KEY.ends_with('_'));
    }

    #[test]
    fn batch_b_dormancy_phase_3_variant_serde_snake_case_with_copy_distinctness() {
        let variants = [
            DormancyPhase::Active,
            DormancyPhase::Dormant,
            DormancyPhase::Reclaimed,
        ];
        // All 3 variants distinct under PartialEq.
        for i in 0..variants.len() {
            for j in 0..variants.len() {
                if i == j { assert_eq!(variants[i], variants[j]); }
                else { assert_ne!(variants[i], variants[j]); }
            }
        }
        // serde JSON tags must be lowercase snake_case (matches `#[serde(rename_all = "snake_case")]`).
        assert_eq!(serde_json::to_string(&DormancyPhase::Active).unwrap(), "\"active\"");
        assert_eq!(serde_json::to_string(&DormancyPhase::Dormant).unwrap(), "\"dormant\"");
        assert_eq!(serde_json::to_string(&DormancyPhase::Reclaimed).unwrap(), "\"reclaimed\"");
        // Round-trip stability for all 3.
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: DormancyPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
        // Copy semantics — DormancyPhase derives Copy.
        let a = DormancyPhase::Dormant;
        let b = a; // copy, not move
        assert_eq!(a, b);
    }

    #[test]
    fn batch_b_dormancy_state_new_equals_default_with_active_fallback_for_unknown() {
        let s_new = DormancyState::new();
        let s_def = DormancyState::default();
        // Empty initial state — both maps zero-sized at construction.
        assert!(s_new.declarations.is_empty());
        assert!(s_new.phases.is_empty());
        assert!(s_new.reclaimed.is_empty());
        assert!(s_def.declarations.is_empty());
        assert!(s_def.phases.is_empty());
        assert!(s_def.reclaimed.is_empty());
        // Unknown identity → Active fallback (not Dormant, not Reclaimed).
        assert_eq!(s_new.phase("never_seen"), DormancyPhase::Active);
        assert_eq!(s_def.phase("never_seen"), DormancyPhase::Active);
        // serde round-trip on empty state preserves emptiness.
        let json = serde_json::to_string(&s_new).unwrap();
        let back: DormancyState = serde_json::from_str(&json).unwrap();
        assert!(back.declarations.is_empty());
        assert!(back.phases.is_empty());
        assert!(back.reclaimed.is_empty());
    }

    #[test]
    fn batch_b_dormancy_declaration_six_field_serde_round_trip_preserves_payload() {
        let decl = DormancyDeclaration {
            target_identity: "alice_hash_42".to_string(),
            declared_by: "bob_hash_7".to_string(),
            declared_at: 1_700_000_000.0,
            last_known_active: 1_500_000_000.0,
            wakeup_deadline: 1_700_000_000.0 + DORMANCY_WAKEUP_WINDOW,
            witness_count: 3,
        };
        let json = serde_json::to_string(&decl).unwrap();
        let back: DormancyDeclaration = serde_json::from_str(&json).unwrap();
        assert_eq!(back.target_identity, "alice_hash_42");
        assert_eq!(back.declared_by, "bob_hash_7");
        assert_eq!(back.declared_at, 1_700_000_000.0);
        assert_eq!(back.last_known_active, 1_500_000_000.0);
        assert_eq!(back.wakeup_deadline, 1_700_000_000.0 + DORMANCY_WAKEUP_WINDOW);
        assert_eq!(back.witness_count, 3);
        // Clone preserves all 6 fields.
        let cloned = decl.clone();
        assert_eq!(cloned.target_identity, decl.target_identity);
        assert_eq!(cloned.witness_count, decl.witness_count);
    }

    #[test]
    fn batch_b_parsed_dormancy_op_three_variant_clone_preserves_payload_and_distinctness() {
        let declare = ParsedDormancyOp::Declare {
            target_identity: "alice".to_string(),
            last_known_active: 999.5,
        };
        let heartbeat = ParsedDormancyOp::Heartbeat;
        let proof = ParsedDormancyOp::ProofOfLife {
            target_identity: "carol".to_string(),
            signature: "deadbeef00".to_string(),
        };
        // Variant tag distinctness via match (PartialEq not derived on this enum).
        let declare_is_declare = matches!(declare, ParsedDormancyOp::Declare { .. });
        let heartbeat_is_heartbeat = matches!(heartbeat, ParsedDormancyOp::Heartbeat);
        let proof_is_proof = matches!(proof, ParsedDormancyOp::ProofOfLife { .. });
        assert!(declare_is_declare && heartbeat_is_heartbeat && proof_is_proof);
        // No cross-variant matches.
        assert!(!matches!(declare, ParsedDormancyOp::Heartbeat));
        assert!(!matches!(declare, ParsedDormancyOp::ProofOfLife { .. }));
        assert!(!matches!(heartbeat, ParsedDormancyOp::Declare { .. }));
        assert!(!matches!(heartbeat, ParsedDormancyOp::ProofOfLife { .. }));
        assert!(!matches!(proof, ParsedDormancyOp::Declare { .. }));
        assert!(!matches!(proof, ParsedDormancyOp::Heartbeat));
        // Clone preserves payload — re-extract fields via match.
        let declare_cloned = declare.clone();
        if let ParsedDormancyOp::Declare { target_identity, last_known_active } = declare_cloned {
            assert_eq!(target_identity, "alice");
            assert_eq!(last_known_active, 999.5);
        } else {
            panic!("Clone changed variant of Declare");
        }
        let proof_cloned = proof.clone();
        if let ParsedDormancyOp::ProofOfLife { target_identity, signature } = proof_cloned {
            assert_eq!(target_identity, "carol");
            assert_eq!(signature, "deadbeef00");
        } else {
            panic!("Clone changed variant of ProofOfLife");
        }
    }
}
