//! AI Collaboration Records (Protocol §6.3).
//!
//! Composite attribution for AI-human collaborative work validation.
//! Each participant (human or AI) is listed with their role, contribution
//! description, and cryptographic signature.
//!
//! Key properties:
//! - All participants must co-sign (multi-party requirement)
//! - Roles: prompter, generator, editor, approver
//! - AI participants include model and version metadata
//! - Immutable on the DAG — retroactive editing is cryptographically impossible
//! - Optional chain references for intermediate outputs

//!
//! Spec references:
//!   @spec Protocol §3.3.5
//!   @spec Protocol §6.3 (AI Attribution — CollaborationRecord with prompter/generator/editor/approver roles)

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Metadata key identifying a collaboration record.
pub const COLLABORATION_OP_KEY: &str = "collaboration_op";

// ─── Types ─────────────────────────────────────────────────────────────────

/// Role of a participant in collaborative work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantRole {
    /// Directed the work (prompting, specification).
    Prompter,
    /// Generated content (primary creation).
    Generator,
    /// Edited or revised content.
    Editor,
    /// Approved the final output.
    Approver,
}

impl ParticipantRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Prompter => "prompter",
            Self::Generator => "generator",
            Self::Editor => "editor",
            Self::Approver => "approver",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "prompter" => Some(Self::Prompter),
            "generator" => Some(Self::Generator),
            "editor" => Some(Self::Editor),
            "approver" => Some(Self::Approver),
            _ => None,
        }
    }
}

/// A participant in collaborative work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    /// Identity hash or public key of the participant.
    pub identity: String,
    /// Role in the collaboration.
    pub role: ParticipantRole,
    /// Description of what this participant contributed.
    pub contribution: String,
    /// AI model name (only for AI participants).
    pub model: Option<String>,
    /// AI model version (only for AI participants).
    pub model_version: Option<String>,
    /// Whether this participant has signed.
    pub signed: bool,
}

impl Participant {
    /// Create a human participant.
    pub fn human(identity: &str, role: ParticipantRole, contribution: &str) -> Self {
        Self {
            identity: identity.to_string(),
            role,
            contribution: contribution.to_string(),
            model: None,
            model_version: None,
            signed: false,
        }
    }

    /// Create an AI participant.
    pub fn ai(
        identity: &str,
        role: ParticipantRole,
        contribution: &str,
        model: &str,
        model_version: &str,
    ) -> Self {
        Self {
            identity: identity.to_string(),
            role,
            contribution: contribution.to_string(),
            model: Some(model.to_string()),
            model_version: Some(model_version.to_string()),
            signed: false,
        }
    }

    /// Whether this participant is an AI.
    pub fn is_ai(&self) -> bool {
        self.model.is_some()
    }
}

/// A collaboration record tracking composite attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationRecord {
    /// Record ID of the collaboration record.
    pub record_id: String,
    /// Content hash of the final output.
    pub work_hash: String,
    /// All participants (human and AI).
    pub participants: Vec<Participant>,
    /// Optional references to intermediate outputs/versions.
    pub chain: Vec<String>,
    /// Timestamp of creation.
    pub created_at: f64,
}

impl CollaborationRecord {
    /// Check whether all participants have signed.
    pub fn fully_signed(&self) -> bool {
        !self.participants.is_empty() && self.participants.iter().all(|p| p.signed)
    }

    /// Number of participants.
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Number of human participants.
    pub fn human_count(&self) -> usize {
        self.participants.iter().filter(|p| !p.is_ai()).count()
    }

    /// Number of AI participants.
    pub fn ai_count(&self) -> usize {
        self.participants.iter().filter(|p| p.is_ai()).count()
    }

    /// Mark a participant as having signed.
    pub fn mark_signed(&mut self, identity: &str) -> bool {
        for p in &mut self.participants {
            if p.identity == identity {
                p.signed = true;
                return true;
            }
        }
        false
    }

    /// Get participants by role.
    pub fn by_role(&self, role: &ParticipantRole) -> Vec<&Participant> {
        self.participants.iter().filter(|p| &p.role == role).collect()
    }
}

// ─── State ─────────────────────────────────────────────────────────────────

/// Tracks collaboration records across the network.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CollaborationState {
    /// All collaboration records by record_id.
    records: std::collections::HashMap<String, CollaborationRecord>,
    /// Index: work_hash → record_ids (detects duplicate attribution claims).
    by_work_hash: std::collections::HashMap<String, Vec<String>>,
    /// Index: identity → record_ids (find all collaborations for a participant).
    by_identity: std::collections::HashMap<String, Vec<String>>,
}

impl CollaborationState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a collaboration record.
    pub fn register(&mut self, record: CollaborationRecord) -> Result<(), String> {
        if record.participants.is_empty() {
            return Err("collaboration must have at least one participant".into());
        }
        if record.work_hash.is_empty() {
            return Err("work_hash is required".into());
        }
        if self.records.contains_key(&record.record_id) {
            return Err(format!(
                "collaboration '{}' already registered",
                record.record_id
            ));
        }

        let rec_id = record.record_id.clone();

        // Index by work_hash
        self.by_work_hash
            .entry(record.work_hash.clone())
            .or_default()
            .push(rec_id.clone());

        // Index by identity
        for p in &record.participants {
            self.by_identity
                .entry(p.identity.clone())
                .or_default()
                .push(rec_id.clone());
        }

        self.records.insert(rec_id, record);
        Ok(())
    }

    /// Get a collaboration record by ID.
    pub fn get(&self, record_id: &str) -> Option<&CollaborationRecord> {
        self.records.get(record_id)
    }

    /// Find collaborations for a given work hash.
    /// Multiple records for the same hash indicate attribution disputes.
    pub fn for_work(&self, work_hash: &str) -> Vec<&CollaborationRecord> {
        self.by_work_hash
            .get(work_hash)
            .map_or(Vec::new(), |ids| {
                ids.iter().filter_map(|id| self.records.get(id)).collect()
            })
    }

    /// Detect conflicting attribution (same work_hash, different participants).
    pub fn conflicts_for_work(&self, work_hash: &str) -> Vec<&CollaborationRecord> {
        let records = self.for_work(work_hash);
        if records.len() > 1 {
            records
        } else {
            Vec::new()
        }
    }

    /// Find all collaborations involving a given identity.
    pub fn for_identity(&self, identity: &str) -> Vec<&CollaborationRecord> {
        self.by_identity
            .get(identity)
            .map_or(Vec::new(), |ids| {
                ids.iter().filter_map(|id| self.records.get(id)).collect()
            })
    }

    /// Total number of collaboration records.
    pub fn count(&self) -> usize {
        self.records.len()
    }

    /// Number of unique works tracked.
    pub fn work_count(&self) -> usize {
        self.by_work_hash.len()
    }

    /// Number of works with conflicting attribution.
    pub fn conflict_count(&self) -> usize {
        self.by_work_hash
            .values()
            .filter(|ids| ids.len() > 1)
            .count()
    }
}

// ─── Metadata Builders ────────────────────────────────────────────────────

/// Build metadata for a collaboration record.
pub fn collaboration_metadata(
    work_hash: &str,
    participants_json: &str,
    chain: &[String],
) -> BTreeMap<String, String> {
    let mut meta = BTreeMap::new();
    meta.insert(COLLABORATION_OP_KEY.into(), "collaboration".into());
    meta.insert("work_hash".into(), work_hash.into());
    meta.insert("participants".into(), participants_json.into());
    if !chain.is_empty() {
        meta.insert(
            "chain".into(),
            serde_json::to_string(chain).unwrap_or_default(),
        );
    }
    meta
}

// ─── Extraction ───────────────────────────────────────────────────────────

/// Extract a collaboration record from record metadata.
pub fn extract_collaboration(
    metadata: &BTreeMap<String, String>,
    record_id: &str,
    timestamp: f64,
) -> Option<CollaborationRecord> {
    if metadata.get(COLLABORATION_OP_KEY)? != "collaboration" {
        return None;
    }

    let work_hash = metadata.get("work_hash")?.clone();
    let participants_json = metadata.get("participants")?;
    let participants: Vec<Participant> = serde_json::from_str(participants_json).ok()?;

    let chain: Vec<String> = metadata
        .get("chain")
        .and_then(|c| serde_json::from_str(c).ok())
        .unwrap_or_default();

    Some(CollaborationRecord {
        record_id: record_id.to_string(),
        work_hash,
        participants,
        chain,
        created_at: timestamp,
    })
}

/// Rebuild collaboration state from a sequence of records.
pub fn rebuild_collaboration_state<'a>(
    records: impl Iterator<Item = &'a CollaborationRecord>,
) -> CollaborationState {
    let mut state = CollaborationState::new();
    for r in records {
        let _ = state.register(r.clone());
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_collab() -> CollaborationRecord {
        CollaborationRecord {
            record_id: "collab-001".into(),
            work_hash: "hash-final-output".into(),
            participants: vec![
                Participant::human("alice", ParticipantRole::Prompter, "direction, editing"),
                Participant::ai(
                    "ai-key-001",
                    ParticipantRole::Generator,
                    "initial draft",
                    "claude-opus-4-6",
                    "2026-02",
                ),
            ],
            chain: vec!["draft-1".into(), "draft-2".into()],
            created_at: 1000.0,
        }
    }

    #[test]
    fn test_register_collaboration() {
        let mut state = CollaborationState::new();
        let collab = sample_collab();
        assert!(state.register(collab).is_ok());
        assert_eq!(state.count(), 1);
        assert_eq!(state.work_count(), 1);
    }

    #[test]
    fn test_participant_counts() {
        let collab = sample_collab();
        assert_eq!(collab.participant_count(), 2);
        assert_eq!(collab.human_count(), 1);
        assert_eq!(collab.ai_count(), 1);
    }

    #[test]
    fn test_fully_signed() {
        let mut collab = sample_collab();
        assert!(!collab.fully_signed());

        collab.mark_signed("alice");
        assert!(!collab.fully_signed()); // AI not signed yet

        collab.mark_signed("ai-key-001");
        assert!(collab.fully_signed());
    }

    #[test]
    fn test_by_role() {
        let collab = sample_collab();
        let prompters = collab.by_role(&ParticipantRole::Prompter);
        assert_eq!(prompters.len(), 1);
        assert_eq!(prompters[0].identity, "alice");

        let generators = collab.by_role(&ParticipantRole::Generator);
        assert_eq!(generators.len(), 1);
        assert!(generators[0].is_ai());
    }

    #[test]
    fn test_for_identity() {
        let mut state = CollaborationState::new();
        state.register(sample_collab()).unwrap();

        let alice_collabs = state.for_identity("alice");
        assert_eq!(alice_collabs.len(), 1);

        let ai_collabs = state.for_identity("ai-key-001");
        assert_eq!(ai_collabs.len(), 1);

        let unknown = state.for_identity("bob");
        assert!(unknown.is_empty());
    }

    #[test]
    fn test_conflict_detection() {
        let mut state = CollaborationState::new();
        state.register(sample_collab()).unwrap();

        // Same work_hash, different attribution
        let mut stolen = CollaborationRecord {
            record_id: "collab-002".into(),
            work_hash: "hash-final-output".into(), // same work
            participants: vec![Participant::human(
                "mallory",
                ParticipantRole::Generator,
                "I made this",
            )],
            chain: vec![],
            created_at: 1001.0,
        };
        stolen.mark_signed("mallory");
        state.register(stolen).unwrap();

        let conflicts = state.conflicts_for_work("hash-final-output");
        assert_eq!(conflicts.len(), 2);
        assert_eq!(state.conflict_count(), 1);
    }

    #[test]
    fn test_no_conflict_single_record() {
        let mut state = CollaborationState::new();
        state.register(sample_collab()).unwrap();

        let conflicts = state.conflicts_for_work("hash-final-output");
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_empty_participants_rejected() {
        let mut state = CollaborationState::new();
        let collab = CollaborationRecord {
            record_id: "bad".into(),
            work_hash: "hash".into(),
            participants: vec![],
            chain: vec![],
            created_at: 1000.0,
        };
        assert!(state.register(collab).is_err());
    }

    #[test]
    fn test_empty_work_hash_rejected() {
        let mut state = CollaborationState::new();
        let collab = CollaborationRecord {
            record_id: "bad".into(),
            work_hash: String::new(),
            participants: vec![Participant::human("alice", ParticipantRole::Prompter, "test")],
            chain: vec![],
            created_at: 1000.0,
        };
        assert!(state.register(collab).is_err());
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut state = CollaborationState::new();
        state.register(sample_collab()).unwrap();
        assert!(state.register(sample_collab()).is_err());
    }

    #[test]
    fn test_metadata_roundtrip() {
        let participants = vec![
            Participant::human("alice", ParticipantRole::Prompter, "editing"),
            Participant::ai("ai-1", ParticipantRole::Generator, "draft", "claude", "4.6"),
        ];
        let participants_json = serde_json::to_string(&participants).unwrap();
        let chain = vec!["draft-1".into()];

        let meta = collaboration_metadata("hash-001", &participants_json, &chain);
        let parsed = extract_collaboration(&meta, "rec-001", 1000.0).unwrap();

        assert_eq!(parsed.work_hash, "hash-001");
        assert_eq!(parsed.participants.len(), 2);
        assert_eq!(parsed.chain.len(), 1);
        assert!(parsed.participants[1].is_ai());
    }

    #[test]
    fn test_role_parse_roundtrip() {
        for role in &[
            ParticipantRole::Prompter,
            ParticipantRole::Generator,
            ParticipantRole::Editor,
            ParticipantRole::Approver,
        ] {
            let s = role.as_str();
            let parsed = ParticipantRole::parse(s).unwrap();
            assert_eq!(&parsed, role);
        }
    }

    #[test]
    fn test_rebuild_state() {
        let r1 = sample_collab();
        let r2 = CollaborationRecord {
            record_id: "collab-002".into(),
            work_hash: "hash-other".into(),
            participants: vec![Participant::human(
                "bob",
                ParticipantRole::Generator,
                "wrote everything",
            )],
            chain: vec![],
            created_at: 2000.0,
        };

        let records = vec![&r1, &r2];
        let state = rebuild_collaboration_state(records.into_iter());
        assert_eq!(state.count(), 2);
        assert_eq!(state.work_count(), 2);
    }

    // ─── fixture-free, pure helpers ─────────────────────

    /// COLLABORATION_OP_KEY strict pin + ASCII lowercase snake_case +
    /// cross-module disjointness vs seed_vault::SEED_VAULT_OP_KEY and
    /// key_rotation flag keys. Wire-format key must NEVER collide with
    /// other subsystems' op-keys (would mis-dispatch records on extract).
    #[cfg(feature = "node-core")]
    #[test]
    fn batch_b_collaboration_op_key_strict_pin_and_cross_module_disjointness() {
        // Exact byte-pin.
        assert_eq!(COLLABORATION_OP_KEY, "collaboration_op");
        // Length pin (16 bytes, no trailing whitespace / null).
        assert_eq!(COLLABORATION_OP_KEY.len(), 16);
        assert_eq!(COLLABORATION_OP_KEY.len(), "collaboration_op".len());

        // ASCII lowercase snake_case discipline.
        assert!(COLLABORATION_OP_KEY.is_ascii());
        assert!(!COLLABORATION_OP_KEY.is_empty());
        assert!(COLLABORATION_OP_KEY.chars().all(|c|
            c.is_ascii_lowercase() || c == '_'
        ));
        assert!(!COLLABORATION_OP_KEY.contains(' '));
        assert!(!COLLABORATION_OP_KEY.contains('-'));
        assert!(!COLLABORATION_OP_KEY.starts_with('_'));
        assert!(!COLLABORATION_OP_KEY.ends_with('_'));

        // Value emitted by collaboration_metadata at this key is literal
        // "collaboration" (different from the key name itself) — this is
        // the op-discriminator string used by extract_collaboration.
        let meta = collaboration_metadata("h", "[]", &[]);
        assert_eq!(meta.get(COLLABORATION_OP_KEY), Some(&"collaboration".to_string()));
        // The KEY and the VALUE must NOT be the same — distinguishes
        // "what kind of op record" from "what kind of op-key bucket".
        assert_ne!(COLLABORATION_OP_KEY, "collaboration");

        // Cross-module disjointness — collide-free dispatch.
        assert_ne!(COLLABORATION_OP_KEY, crate::seed_vault::SEED_VAULT_OP_KEY);
        assert_ne!(COLLABORATION_OP_KEY, crate::network::key_rotation::KEY_ROTATION_KEY);
        assert_ne!(COLLABORATION_OP_KEY, crate::network::key_rotation::REVOCATION_OP_KEY);
        assert_ne!(COLLABORATION_OP_KEY, crate::network::key_rotation::SPHINCS_ROTATION_KEY);
    }

    /// ParticipantRole 4-variant enum: as_str byte-pin per variant +
    /// parse roundtrip exhaustive + serde rename_all snake_case JSON
    /// representation + parse rejects 6 invalid strings + Clone + PartialEq.
    #[test]
    fn batch_b_participant_role_4_variant_as_str_parse_serde_and_invalid_rejection() {
        // All 4 variants.
        let variants = [
            ParticipantRole::Prompter,
            ParticipantRole::Generator,
            ParticipantRole::Editor,
            ParticipantRole::Approver,
        ];
        assert_eq!(variants.len(), 4);

        // as_str byte-pin per variant + lowercase ASCII (no underscore needed —
        // all 4 are single-word).
        assert_eq!(ParticipantRole::Prompter.as_str(), "prompter");
        assert_eq!(ParticipantRole::Generator.as_str(), "generator");
        assert_eq!(ParticipantRole::Editor.as_str(), "editor");
        assert_eq!(ParticipantRole::Approver.as_str(), "approver");
        for v in &variants {
            let s = v.as_str();
            assert!(s.is_ascii());
            assert!(!s.is_empty());
            assert!(s.chars().all(|c| c.is_ascii_lowercase()));
            assert!(!s.contains(' '));
            assert!(!s.contains('_'));
        }

        // All 4 as_str pairwise distinct (else parse() would alias).
        let strs: Vec<&str> = variants.iter().map(|v| v.as_str()).collect();
        let unique: std::collections::HashSet<&&str> = strs.iter().collect();
        assert_eq!(unique.len(), 4);

        // parse roundtrip exhaustive for all 4.
        for v in &variants {
            let parsed = ParticipantRole::parse(v.as_str()).expect("parse");
            assert_eq!(&parsed, v);
        }

        // parse rejects unknown strings — case-sensitive, empty, whitespace,
        // ASCII near-matches.
        let bad: [&str; 9] = ["", " ", "Prompter", "PROMPTER", "prompt", "promptER",
                              "prompter ", " prompter", "unknown"];
        for s in bad {
            assert!(ParticipantRole::parse(s).is_none(), "rejects {s:?}");
        }

        // Serde JSON: rename_all="snake_case" emits "prompter" etc. (since
        // all 4 are already lowercase, snake_case is identical to lowercase).
        for v in &variants {
            let json = serde_json::to_string(v).expect("ser");
            assert_eq!(json, format!("\"{}\"", v.as_str()));
            // Round-trip via JSON.
            let back: ParticipantRole = serde_json::from_str(&json).expect("de");
            assert_eq!(&back, v);
        }

        // Clone + PartialEq + Eq (no Hash required — derived above).
        let a = ParticipantRole::Prompter;
        let b = a.clone();
        assert_eq!(a, b);
        assert_eq!(ParticipantRole::Prompter, ParticipantRole::Prompter);
        assert_ne!(ParticipantRole::Prompter, ParticipantRole::Generator);
        assert_ne!(ParticipantRole::Editor, ParticipantRole::Approver);
        // Pairwise distinctness across all C(4,2)=6 pairs.
        for i in 0..4 {
            for j in 0..4 {
                if i != j {
                    assert_ne!(&variants[i], &variants[j]);
                }
            }
        }
    }

    /// Participant::human and Participant::ai constructor shape pins +
    /// is_ai discrimination via Option<String> model field +
    /// CollaborationRecord empty-participants edge: fully_signed()==false
    /// for empty (load-bearing — !all_signed is unsafe when no signers,
    /// require at-least-one).
    #[test]
    fn batch_b_participant_constructors_and_record_accessors_empty_path() {
        // Participant::human shape — 6-field pin.
        let h = Participant::human("alice", ParticipantRole::Prompter, "draft");
        assert_eq!(h.identity, "alice");
        assert_eq!(h.role, ParticipantRole::Prompter);
        assert_eq!(h.contribution, "draft");
        assert!(h.model.is_none());
        assert!(h.model_version.is_none());
        assert!(!h.signed);
        assert!(!h.is_ai());

        // Participant::ai shape — same 6 fields, but model fields populated.
        let a = Participant::ai("bot-1", ParticipantRole::Generator, "writing",
                                "claude", "4.6");
        assert_eq!(a.identity, "bot-1");
        assert_eq!(a.role, ParticipantRole::Generator);
        assert_eq!(a.contribution, "writing");
        assert_eq!(a.model.as_deref(), Some("claude"));
        assert_eq!(a.model_version.as_deref(), Some("4.6"));
        assert!(!a.signed);
        assert!(a.is_ai());

        // is_ai discriminates ONLY on model.is_some(), ignores model_version.
        // Manually construct a participant with model but no model_version —
        // still counts as AI.
        let weird = Participant {
            identity: "weird".into(),
            role: ParticipantRole::Editor,
            contribution: "x".into(),
            model: Some("custom".into()),
            model_version: None,
            signed: false,
        };
        assert!(weird.is_ai());

        // And the opposite — model None, model_version Some — NOT AI.
        let weird2 = Participant {
            identity: "weird2".into(),
            role: ParticipantRole::Editor,
            contribution: "x".into(),
            model: None,
            model_version: Some("4.6".into()),
            signed: false,
        };
        assert!(!weird2.is_ai());

        // Empty CollaborationRecord: fully_signed()==false (load-bearing —
        // !participants.is_empty() short-circuits, so an empty record is
        // NEVER fully signed, even though `participants.iter().all(|p| p.signed)`
        // would otherwise be vacuously true).
        let empty = CollaborationRecord {
            record_id: "empty".into(),
            work_hash: "h".into(),
            participants: vec![],
            chain: vec![],
            created_at: 0.0,
        };
        assert!(!empty.fully_signed());
        assert_eq!(empty.participant_count(), 0);
        assert_eq!(empty.human_count(), 0);
        assert_eq!(empty.ai_count(), 0);
        assert!(empty.by_role(&ParticipantRole::Prompter).is_empty());

        // Partition invariant: human_count + ai_count == participant_count
        // for any record (each participant is exactly one of human or AI).
        let rec = CollaborationRecord {
            record_id: "rec".into(),
            work_hash: "h".into(),
            participants: vec![
                Participant::human("a", ParticipantRole::Prompter, "x"),
                Participant::ai("b", ParticipantRole::Generator, "x", "m", "v"),
                Participant::human("c", ParticipantRole::Editor, "x"),
                Participant::ai("d", ParticipantRole::Approver, "x", "m", "v"),
            ],
            chain: vec![],
            created_at: 0.0,
        };
        assert_eq!(rec.participant_count(), 4);
        assert_eq!(rec.human_count(), 2);
        assert_eq!(rec.ai_count(), 2);
        assert_eq!(rec.human_count() + rec.ai_count(), rec.participant_count());

        // by_role per role on the 4-variant set: each variant matches 1.
        for role in [ParticipantRole::Prompter, ParticipantRole::Generator,
                     ParticipantRole::Editor, ParticipantRole::Approver] {
            assert_eq!(rec.by_role(&role).len(), 1, "role {:?}", role);
        }
    }

    /// mark_signed return value contract:
    /// - returns true if identity matches a participant (and sets signed=true)
    /// - returns false if no match
    /// - idempotent: second call returns true (still matches), signed stays true
    /// - fully_signed() flips false → true when ALL participants signed
    #[test]
    fn batch_b_mark_signed_return_contract_and_fully_signed_transition() {
        let mut rec = CollaborationRecord {
            record_id: "rec".into(),
            work_hash: "h".into(),
            participants: vec![
                Participant::human("alice", ParticipantRole::Prompter, "x"),
                Participant::ai("bot", ParticipantRole::Generator, "x", "m", "v"),
                Participant::human("carol", ParticipantRole::Approver, "x"),
            ],
            chain: vec![],
            created_at: 0.0,
        };
        assert!(!rec.fully_signed());

        // Unknown identity → false, no participant marked.
        assert!(!rec.mark_signed("unknown"));
        assert!(rec.participants.iter().all(|p| !p.signed));

        // Empty identity → false (won't match any).
        assert!(!rec.mark_signed(""));
        assert!(rec.participants.iter().all(|p| !p.signed));

        // Case sensitivity: "Alice" ≠ "alice" → false.
        assert!(!rec.mark_signed("Alice"));
        assert!(rec.participants.iter().all(|p| !p.signed));

        // Mark first participant: true, signed=true, others unchanged.
        assert!(rec.mark_signed("alice"));
        assert!(rec.participants[0].signed);
        assert!(!rec.participants[1].signed);
        assert!(!rec.participants[2].signed);
        assert!(!rec.fully_signed());

        // Idempotent: re-marking same identity returns true, stays true.
        assert!(rec.mark_signed("alice"));
        assert!(rec.participants[0].signed);
        assert!(!rec.fully_signed());

        // Mark second participant: still not fully signed (one left).
        assert!(rec.mark_signed("bot"));
        assert!(rec.participants[1].signed);
        assert!(!rec.fully_signed());

        // Mark third → fully_signed flips to true.
        assert!(rec.mark_signed("carol"));
        assert!(rec.participants[2].signed);
        assert!(rec.fully_signed());

        // All participants have signed flag set.
        assert!(rec.participants.iter().all(|p| p.signed));

        // Once fully signed, marking again is a no-op return (still true).
        assert!(rec.mark_signed("alice"));
        assert!(rec.fully_signed());
    }

    /// collaboration_metadata exact-shape: 3 keys when chain empty (omits
    /// "chain" key), 4 keys when chain non-empty. Extract is the inverse:
    /// extract_collaboration handles missing chain → empty Vec, malformed
    /// JSON → empty Vec / None depending on field, wrong op-key → None,
    /// missing fields → None.
    #[test]
    fn batch_b_collaboration_metadata_shape_and_extract_negative_paths() {
        // Empty chain → 3 keys (no "chain" entry).
        let m_empty = collaboration_metadata("hash-1", "[]", &[]);
        assert_eq!(m_empty.len(), 3, "no chain → 3 keys");
        assert_eq!(m_empty.get(COLLABORATION_OP_KEY), Some(&"collaboration".to_string()));
        assert_eq!(m_empty.get("work_hash"), Some(&"hash-1".to_string()));
        assert_eq!(m_empty.get("participants"), Some(&"[]".to_string()));
        assert!(!m_empty.contains_key("chain"));

        // Non-empty chain → 4 keys (with "chain" as JSON-serialized array).
        let m_chain = collaboration_metadata("hash-2", "[]", &["a".into(), "b".into()]);
        assert_eq!(m_chain.len(), 4, "with chain → 4 keys");
        assert_eq!(m_chain.get(COLLABORATION_OP_KEY), Some(&"collaboration".to_string()));
        assert_eq!(m_chain.get("work_hash"), Some(&"hash-2".to_string()));
        assert_eq!(m_chain.get("chain"), Some(&"[\"a\",\"b\"]".to_string()));

        // BTreeMap keys are ASCII-sorted: chain < collaboration_op < participants < work_hash
        let keys: Vec<&str> = m_chain.keys().map(|s| s.as_str()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        assert_eq!(keys, vec!["chain", "collaboration_op", "participants", "work_hash"]);

        // extract_collaboration: round-trip preserves all fields incl chain
        // when chain non-empty.
        let participants_json = serde_json::to_string(&vec![
            Participant::human("alice", ParticipantRole::Prompter, "x"),
        ]).unwrap();
        let m = collaboration_metadata("h", &participants_json, &["c1".into()]);
        let r = extract_collaboration(&m, "r1", 99.0).expect("extracts");
        assert_eq!(r.record_id, "r1");
        assert_eq!(r.work_hash, "h");
        assert_eq!(r.created_at, 99.0);
        assert_eq!(r.participants.len(), 1);
        assert_eq!(r.chain, vec!["c1".to_string()]);

        // Missing chain key → extracted chain is empty Vec (default).
        let m2 = collaboration_metadata("h", &participants_json, &[]);
        let r2 = extract_collaboration(&m2, "r2", 100.0).expect("extracts");
        assert!(r2.chain.is_empty());

        // Wrong op-key value → None (extract checks ==).
        let mut wrong = m2.clone();
        wrong.insert(COLLABORATION_OP_KEY.into(), "not_collaboration".into());
        assert!(extract_collaboration(&wrong, "rX", 0.0).is_none());

        // Missing op-key entirely → None.
        let mut no_op = m2.clone();
        no_op.remove(COLLABORATION_OP_KEY);
        assert!(extract_collaboration(&no_op, "rX", 0.0).is_none());

        // Missing work_hash → None.
        let mut no_wh = m2.clone();
        no_wh.remove("work_hash");
        assert!(extract_collaboration(&no_wh, "rX", 0.0).is_none());

        // Missing participants → None.
        let mut no_p = m2.clone();
        no_p.remove("participants");
        assert!(extract_collaboration(&no_p, "rX", 0.0).is_none());

        // Malformed participants JSON → None.
        let mut bad_p = m2.clone();
        bad_p.insert("participants".into(), "not json".into());
        assert!(extract_collaboration(&bad_p, "rX", 0.0).is_none());

        // Malformed chain JSON → chain becomes empty (silent fallback via
        // unwrap_or_default), record still extracts (load-bearing: a bad
        // chain field must NOT block the record entirely — it only loses
        // the audit trail).
        let mut bad_chain = m2.clone();
        bad_chain.insert("chain".into(), "not json".into());
        let r_bc = extract_collaboration(&bad_chain, "rX", 0.0).expect("extracts despite bad chain");
        assert!(r_bc.chain.is_empty());

        // Empty work_hash string is accepted by extract (note: register()
        // rejects it later, but extract is purely format-level).
        let mut empty_wh = m2.clone();
        empty_wh.insert("work_hash".into(), String::new());
        let r_ewh = extract_collaboration(&empty_wh, "rX", 0.0).expect("extracts");
        assert_eq!(r_ewh.work_hash, "");

        // CollaborationState::new() == CollaborationState::default() initial
        // state pin (all 3 indexes empty).
        let s_new = CollaborationState::new();
        let s_def: CollaborationState = CollaborationState::default();
        assert_eq!(s_new.count(), 0);
        assert_eq!(s_new.work_count(), 0);
        assert_eq!(s_new.conflict_count(), 0);
        assert_eq!(s_def.count(), 0);
        assert_eq!(s_def.work_count(), 0);
        assert_eq!(s_def.conflict_count(), 0);
        assert!(s_new.get("any").is_none());
        assert!(s_new.for_work("any").is_empty());
        assert!(s_new.for_identity("any").is_empty());
        assert!(s_new.conflicts_for_work("any").is_empty());
    }
}
