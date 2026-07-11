//! Content Versioning Protocol (Protocol §6.2, §11.30).
//!
//! Tracks revision history of records via metadata-level version chains.
//! Each version record references its predecessor, creating a traversable
//! chain from latest back to v1. Forks (divergent versions from the same
//! parent) are preserved and tracked.
//!
//! Key properties:
//! - Version chains are linked via `previous_version` record ID
//! - `version_number` is a strict sequential counter (no gaps)
//! - Only the original creator or authorized collaborators can create new versions
//! - Forked chains coexist — protocol does not choose a winner

//!
//! Spec references:
//!   @spec Protocol §11.30

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Metadata key identifying a version record.
pub const VERSION_OP_KEY: &str = "version_op";

/// Metadata key for the previous version's record ID.
pub const PREV_VERSION_KEY: &str = "previous_version";

/// Metadata key for the sequential version number.
pub const VERSION_NUMBER_KEY: &str = "version_number";

/// Metadata key for the optional change summary.
pub const CHANGE_SUMMARY_KEY: &str = "change_summary";

/// Metadata key identifying a diff record.
pub const DIFF_OP_KEY: &str = "diff_op";

/// Metadata key for the source version of a diff.
pub const DIFF_FROM_KEY: &str = "diff_from_version";

/// Metadata key for the target version of a diff.
pub const DIFF_TO_KEY: &str = "diff_to_version";

// ─── Types ─────────────────────────────────────────────────────────────────

/// A parsed version record extracted from record metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRecord {
    /// Record ID of this version.
    pub record_id: String,
    /// Record ID of the previous version (None for v1).
    pub previous_version: Option<String>,
    /// Sequential version counter (1-based).
    pub version_number: u64,
    /// Optional description of changes.
    pub change_summary: Option<String>,
    /// Creator identity hash.
    pub creator: String,
    /// Content hash of this version.
    pub content_hash: String,
}

/// A parsed diff record linking two versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffRecord {
    /// Record ID of the diff record itself.
    pub record_id: String,
    /// Source version record ID.
    pub from_version: String,
    /// Target version record ID.
    pub to_version: String,
    /// Creator who produced the diff.
    pub creator: String,
}

/// A fork point where the version chain diverges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionFork {
    /// Record ID of the common parent.
    pub parent: String,
    /// Record IDs of the diverging children.
    pub branches: Vec<String>,
}

// ─── State ─────────────────────────────────────────────────────────────────

/// Tracks version chains across the network.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionState {
    /// All version records by record_id.
    versions: HashMap<String, VersionRecord>,
    /// Forward index: parent_record_id → list of child version record_ids.
    children: HashMap<String, Vec<String>>,
    /// Root versions (v1 records with no previous_version).
    roots: Vec<String>,
    /// Diff records by record_id.
    diffs: HashMap<String, DiffRecord>,
}

impl VersionState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new version record.
    pub fn register_version(&mut self, version: VersionRecord) -> Result<(), String> {
        // Validate version number
        if version.version_number == 0 {
            return Err("version_number must be >= 1".into());
        }

        // v1 must have no previous version
        if version.version_number == 1 && version.previous_version.is_some() {
            return Err("v1 must not have a previous_version".into());
        }

        // v2+ must have a previous version
        if version.version_number > 1 && version.previous_version.is_none() {
            return Err(format!(
                "v{} must reference a previous_version",
                version.version_number
            ));
        }

        // If previous version exists, validate chain
        if let Some(prev_id) = &version.previous_version {
            match self.versions.get(prev_id) {
                Some(prev) => {
                    // Version number must be sequential
                    if version.version_number != prev.version_number + 1 {
                        return Err(format!(
                            "version gap: previous is v{}, new claims v{}",
                            prev.version_number, version.version_number
                        ));
                    }
                    // Creator must match (or be authorized — for now, same creator)
                    if version.creator != prev.creator {
                        return Err(format!(
                            "creator mismatch: previous by '{}', new by '{}'",
                            prev.creator, version.creator
                        ));
                    }
                }
                None => {
                    return Err(format!("previous version '{}' not found", prev_id));
                }
            }
        }

        // Duplicate check
        if self.versions.contains_key(&version.record_id) {
            return Err(format!("version '{}' already registered", version.record_id));
        }

        let record_id = version.record_id.clone();

        // Track parent→child relationship
        if let Some(prev_id) = &version.previous_version {
            self.children
                .entry(prev_id.clone())
                .or_default()
                .push(record_id.clone());
        } else {
            self.roots.push(record_id.clone());
        }

        self.versions.insert(record_id, version);
        Ok(())
    }

    /// Register a diff record between two versions.
    pub fn register_diff(&mut self, diff: DiffRecord) -> Result<(), String> {
        // Validate both versions exist
        if !self.versions.contains_key(&diff.from_version) {
            return Err(format!("from_version '{}' not found", diff.from_version));
        }
        if !self.versions.contains_key(&diff.to_version) {
            return Err(format!("to_version '{}' not found", diff.to_version));
        }

        if self.diffs.contains_key(&diff.record_id) {
            return Err(format!("diff '{}' already registered", diff.record_id));
        }

        self.diffs.insert(diff.record_id.clone(), diff);
        Ok(())
    }

    /// Get a version record by ID.
    pub fn get_version(&self, record_id: &str) -> Option<&VersionRecord> {
        self.versions.get(record_id)
    }

    /// Get the full chain from a version back to v1.
    pub fn chain_to_root(&self, record_id: &str) -> Vec<&VersionRecord> {
        let mut chain = Vec::new();
        let mut current = record_id;

        while let Some(v) = self.versions.get(current) {
            chain.push(v);
            match &v.previous_version {
                Some(prev) => current = prev,
                None => break, // v1 reached
            }
        }

        chain
    }

    /// Get the latest version(s) in a chain starting from a root.
    /// Returns multiple if the chain has forks.
    pub fn latest_versions(&self, root_id: &str) -> Vec<&VersionRecord> {
        let mut tips = Vec::new();
        let mut stack = vec![root_id];

        while let Some(id) = stack.pop() {
            match self.children.get(id) {
                Some(kids) if !kids.is_empty() => {
                    for kid in kids {
                        stack.push(kid);
                    }
                }
                _ => {
                    // No children = tip (latest version)
                    if let Some(v) = self.versions.get(id) {
                        tips.push(v);
                    }
                }
            }
        }

        tips
    }

    /// Detect forks in the version chain (points where multiple children exist).
    pub fn detect_forks(&self) -> Vec<VersionFork> {
        self.children
            .iter()
            .filter(|(_, kids)| kids.len() > 1)
            .map(|(parent, kids)| VersionFork {
                parent: parent.clone(),
                branches: kids.clone(),
            })
            .collect()
    }

    /// Get child versions of a given version.
    pub fn children_of(&self, record_id: &str) -> &[String] {
        self.children.get(record_id).map_or(&[], |v| v.as_slice())
    }

    /// Get the root (v1) for any version by traversing the chain.
    pub fn root_for(&self, record_id: &str) -> Option<&VersionRecord> {
        let chain = self.chain_to_root(record_id);
        chain.last().copied()
    }

    /// Total number of version records tracked.
    pub fn version_count(&self) -> usize {
        self.versions.len()
    }

    /// Number of root (v1) version chains.
    pub fn chain_count(&self) -> usize {
        self.roots.len()
    }

    /// Number of diff records.
    pub fn diff_count(&self) -> usize {
        self.diffs.len()
    }

    /// Get all diffs between two versions.
    pub fn diffs_between(&self, from: &str, to: &str) -> Vec<&DiffRecord> {
        self.diffs
            .values()
            .filter(|d| d.from_version == from && d.to_version == to)
            .collect()
    }
}

// ─── Metadata Builders ────────────────────────────────────────────────────

/// Build metadata for a version record.
pub fn version_metadata(
    previous_version: Option<&str>,
    version_number: u64,
    change_summary: Option<&str>,
) -> std::collections::BTreeMap<String, String> {
    let mut meta = std::collections::BTreeMap::new();
    meta.insert(VERSION_OP_KEY.into(), "version".into());
    meta.insert(VERSION_NUMBER_KEY.into(), version_number.to_string());

    if let Some(prev) = previous_version {
        meta.insert(PREV_VERSION_KEY.into(), prev.into());
    }
    if let Some(summary) = change_summary {
        meta.insert(CHANGE_SUMMARY_KEY.into(), summary.into());
    }

    meta
}

/// Build metadata for a diff record.
pub fn diff_metadata(from_version: &str, to_version: &str) -> std::collections::BTreeMap<String, String> {
    let mut meta = std::collections::BTreeMap::new();
    meta.insert(DIFF_OP_KEY.into(), "diff".into());
    meta.insert(DIFF_FROM_KEY.into(), from_version.into());
    meta.insert(DIFF_TO_KEY.into(), to_version.into());
    meta
}

// ─── Extraction ───────────────────────────────────────────────────────────

/// Extract a version record from record metadata.
pub fn extract_version(
    metadata: &std::collections::BTreeMap<String, String>,
    record_id: &str,
    creator: &str,
    content_hash: &str,
) -> Option<VersionRecord> {
    if metadata.get(VERSION_OP_KEY)? != "version" {
        return None;
    }

    let version_number: u64 = metadata.get(VERSION_NUMBER_KEY)?.parse().ok()?;
    let previous_version = metadata.get(PREV_VERSION_KEY).cloned();
    let change_summary = metadata.get(CHANGE_SUMMARY_KEY).cloned();

    Some(VersionRecord {
        record_id: record_id.to_string(),
        previous_version,
        version_number,
        change_summary,
        creator: creator.to_string(),
        content_hash: content_hash.to_string(),
    })
}

/// Extract a diff record from record metadata.
pub fn extract_diff(
    metadata: &std::collections::BTreeMap<String, String>,
    record_id: &str,
    creator: &str,
) -> Option<DiffRecord> {
    if metadata.get(DIFF_OP_KEY)? != "diff" {
        return None;
    }

    let from_version = metadata.get(DIFF_FROM_KEY)?.clone();
    let to_version = metadata.get(DIFF_TO_KEY)?.clone();

    Some(DiffRecord {
        record_id: record_id.to_string(),
        from_version,
        to_version,
        creator: creator.to_string(),
    })
}

/// Rebuild version state from a sequence of version and diff records.
pub fn rebuild_version_state<'a>(
    versions: impl Iterator<Item = &'a VersionRecord>,
    diffs: impl Iterator<Item = &'a DiffRecord>,
) -> VersionState {
    let mut state = VersionState::new();

    // Sort versions by version_number so v1 is registered before v2
    let mut sorted: Vec<&VersionRecord> = versions.collect();
    sorted.sort_by_key(|v| v.version_number);

    for v in sorted {
        let _ = state.register_version(v.clone());
    }

    for d in diffs {
        let _ = state.register_diff(d.clone());
    }

    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_version(id: &str, prev: Option<&str>, num: u64, creator: &str) -> VersionRecord {
        VersionRecord {
            record_id: id.to_string(),
            previous_version: prev.map(|s| s.to_string()),
            version_number: num,
            change_summary: None,
            creator: creator.to_string(),
            content_hash: format!("hash-{id}"),
        }
    }

    #[test]
    fn test_register_v1() {
        let mut state = VersionState::new();
        let v1 = make_version("rec-1", None, 1, "alice");
        assert!(state.register_version(v1).is_ok());
        assert_eq!(state.version_count(), 1);
        assert_eq!(state.chain_count(), 1);
    }

    #[test]
    fn test_register_chain() {
        let mut state = VersionState::new();
        state.register_version(make_version("v1", None, 1, "alice")).unwrap();
        state.register_version(make_version("v2", Some("v1"), 2, "alice")).unwrap();
        state.register_version(make_version("v3", Some("v2"), 3, "alice")).unwrap();

        assert_eq!(state.version_count(), 3);
        assert_eq!(state.chain_count(), 1);
    }

    #[test]
    fn test_chain_to_root() {
        let mut state = VersionState::new();
        state.register_version(make_version("v1", None, 1, "alice")).unwrap();
        state.register_version(make_version("v2", Some("v1"), 2, "alice")).unwrap();
        state.register_version(make_version("v3", Some("v2"), 3, "alice")).unwrap();

        let chain = state.chain_to_root("v3");
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].record_id, "v3");
        assert_eq!(chain[1].record_id, "v2");
        assert_eq!(chain[2].record_id, "v1");
    }

    #[test]
    fn test_latest_versions_linear() {
        let mut state = VersionState::new();
        state.register_version(make_version("v1", None, 1, "alice")).unwrap();
        state.register_version(make_version("v2", Some("v1"), 2, "alice")).unwrap();
        state.register_version(make_version("v3", Some("v2"), 3, "alice")).unwrap();

        let tips = state.latest_versions("v1");
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0].record_id, "v3");
    }

    #[test]
    fn test_fork_detection() {
        let mut state = VersionState::new();
        state.register_version(make_version("v1", None, 1, "alice")).unwrap();
        state.register_version(make_version("v2a", Some("v1"), 2, "alice")).unwrap();
        state.register_version(make_version("v2b", Some("v1"), 2, "alice")).unwrap();

        let forks = state.detect_forks();
        assert_eq!(forks.len(), 1);
        assert_eq!(forks[0].parent, "v1");
        assert_eq!(forks[0].branches.len(), 2);

        let tips = state.latest_versions("v1");
        assert_eq!(tips.len(), 2);
    }

    #[test]
    fn test_version_gap_rejected() {
        let mut state = VersionState::new();
        state.register_version(make_version("v1", None, 1, "alice")).unwrap();

        // Skip v2 → v3
        let result = state.register_version(make_version("v3", Some("v1"), 3, "alice"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("version gap"));
    }

    #[test]
    fn test_creator_mismatch_rejected() {
        let mut state = VersionState::new();
        state.register_version(make_version("v1", None, 1, "alice")).unwrap();

        let result = state.register_version(make_version("v2", Some("v1"), 2, "bob"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("creator mismatch"));
    }

    #[test]
    fn test_v1_with_previous_rejected() {
        let mut state = VersionState::new();
        let result = state.register_version(make_version("v1", Some("phantom"), 1, "alice"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must not have"));
    }

    #[test]
    fn test_v2_without_previous_rejected() {
        let mut state = VersionState::new();
        let result = state.register_version(make_version("v2", None, 2, "alice"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must reference"));
    }

    #[test]
    fn test_zero_version_rejected() {
        let mut state = VersionState::new();
        let result = state.register_version(make_version("v0", None, 0, "alice"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be >= 1"));
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut state = VersionState::new();
        state.register_version(make_version("v1", None, 1, "alice")).unwrap();
        let result = state.register_version(make_version("v1", None, 1, "alice"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already registered"));
    }

    #[test]
    fn test_missing_previous_rejected() {
        let mut state = VersionState::new();
        let result = state.register_version(make_version("v2", Some("phantom"), 2, "alice"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_diff_record() {
        let mut state = VersionState::new();
        state.register_version(make_version("v1", None, 1, "alice")).unwrap();
        state.register_version(make_version("v2", Some("v1"), 2, "alice")).unwrap();

        let diff = DiffRecord {
            record_id: "diff-1".into(),
            from_version: "v1".into(),
            to_version: "v2".into(),
            creator: "alice".into(),
        };
        assert!(state.register_diff(diff).is_ok());
        assert_eq!(state.diff_count(), 1);

        let diffs = state.diffs_between("v1", "v2");
        assert_eq!(diffs.len(), 1);
    }

    #[test]
    fn test_diff_missing_version_rejected() {
        let mut state = VersionState::new();
        state.register_version(make_version("v1", None, 1, "alice")).unwrap();

        let diff = DiffRecord {
            record_id: "diff-1".into(),
            from_version: "v1".into(),
            to_version: "phantom".into(),
            creator: "alice".into(),
        };
        assert!(state.register_diff(diff).is_err());
    }

    #[test]
    fn test_root_for() {
        let mut state = VersionState::new();
        state.register_version(make_version("v1", None, 1, "alice")).unwrap();
        state.register_version(make_version("v2", Some("v1"), 2, "alice")).unwrap();
        state.register_version(make_version("v3", Some("v2"), 3, "alice")).unwrap();

        let root = state.root_for("v3").unwrap();
        assert_eq!(root.record_id, "v1");
    }

    #[test]
    fn test_children_of() {
        let mut state = VersionState::new();
        state.register_version(make_version("v1", None, 1, "alice")).unwrap();
        state.register_version(make_version("v2a", Some("v1"), 2, "alice")).unwrap();
        state.register_version(make_version("v2b", Some("v1"), 2, "alice")).unwrap();

        let kids = state.children_of("v1");
        assert_eq!(kids.len(), 2);
        assert!(kids.contains(&"v2a".to_string()));
        assert!(kids.contains(&"v2b".to_string()));
    }

    #[test]
    fn test_metadata_roundtrip() {
        let meta = version_metadata(Some("prev-001"), 3, Some("Fixed typo"));
        let parsed = extract_version(&meta, "rec-003", "alice", "hash-003").unwrap();

        assert_eq!(parsed.record_id, "rec-003");
        assert_eq!(parsed.previous_version, Some("prev-001".to_string()));
        assert_eq!(parsed.version_number, 3);
        assert_eq!(parsed.change_summary, Some("Fixed typo".to_string()));
        assert_eq!(parsed.creator, "alice");
    }

    #[test]
    fn test_diff_metadata_roundtrip() {
        let meta = diff_metadata("v1", "v2");
        let parsed = extract_diff(&meta, "diff-001", "alice").unwrap();

        assert_eq!(parsed.from_version, "v1");
        assert_eq!(parsed.to_version, "v2");
    }

    #[test]
    fn test_rebuild_version_state() {
        let v1 = make_version("v1", None, 1, "alice");
        let v2 = make_version("v2", Some("v1"), 2, "alice");
        let v3 = make_version("v3", Some("v2"), 3, "alice");
        let diff = DiffRecord {
            record_id: "d1".into(),
            from_version: "v1".into(),
            to_version: "v2".into(),
            creator: "alice".into(),
        };

        // Intentionally pass out of order — rebuild should sort
        let versions = vec![&v3, &v1, &v2];
        let diffs = vec![&diff];

        let state = rebuild_version_state(versions.into_iter(), diffs.into_iter());
        assert_eq!(state.version_count(), 3);
        assert_eq!(state.diff_count(), 1);
        assert_eq!(state.chain_count(), 1);
    }

    // ─── fixture-free, pure helpers ─────────────────────

    /// All 7 module constants strict-pin + ASCII lowercase snake_case +
    /// pairwise distinct + version-family vs diff-family disjoint +
    /// cross-module disjointness against seed_vault / collaboration /
    /// key_rotation op-keys. Op-key values strict-equal to module name
    /// (load-bearing: extractors dispatch on `metadata.get(OP_KEY) == "X"`,
    /// where X is the lowercase module name; if the bytes drift, extract
    /// returns None silently).
    #[cfg(feature = "node-core")]
    #[test]
    fn batch_b_versioning_module_constants_strict_pin_and_cross_module_disjointness() {
        // Strict-pin every key (the wire format depends on these exact bytes).
        assert_eq!(VERSION_OP_KEY, "version_op");
        assert_eq!(PREV_VERSION_KEY, "previous_version");
        assert_eq!(VERSION_NUMBER_KEY, "version_number");
        assert_eq!(CHANGE_SUMMARY_KEY, "change_summary");
        assert_eq!(DIFF_OP_KEY, "diff_op");
        assert_eq!(DIFF_FROM_KEY, "diff_from_version");
        assert_eq!(DIFF_TO_KEY, "diff_to_version");

        // Byte-length pins (catches silent renames that pass casing checks
        // but change the on-wire size).
        assert_eq!(VERSION_OP_KEY.len(), 10);
        assert_eq!(PREV_VERSION_KEY.len(), 16);
        assert_eq!(VERSION_NUMBER_KEY.len(), 14);
        assert_eq!(CHANGE_SUMMARY_KEY.len(), 14);
        assert_eq!(DIFF_OP_KEY.len(), 7);
        assert_eq!(DIFF_FROM_KEY.len(), 17);
        assert_eq!(DIFF_TO_KEY.len(), 15);

        // All ASCII lowercase + snake_case (only [a-z_]).
        for (name, k) in [
            ("VERSION_OP_KEY", VERSION_OP_KEY),
            ("PREV_VERSION_KEY", PREV_VERSION_KEY),
            ("VERSION_NUMBER_KEY", VERSION_NUMBER_KEY),
            ("CHANGE_SUMMARY_KEY", CHANGE_SUMMARY_KEY),
            ("DIFF_OP_KEY", DIFF_OP_KEY),
            ("DIFF_FROM_KEY", DIFF_FROM_KEY),
            ("DIFF_TO_KEY", DIFF_TO_KEY),
        ] {
            assert!(!k.is_empty(), "{name} is empty");
            assert!(k.is_ascii(), "{name} not ASCII: {k}");
            assert!(k.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{name} not snake_case: {k}");
            assert!(!k.starts_with('_'), "{name} starts with _: {k}");
            assert!(!k.ends_with('_'), "{name} ends with _: {k}");
        }

        // Pairwise distinct across all 7.
        let keys = [
            VERSION_OP_KEY, PREV_VERSION_KEY, VERSION_NUMBER_KEY,
            CHANGE_SUMMARY_KEY, DIFF_OP_KEY, DIFF_FROM_KEY, DIFF_TO_KEY,
        ];
        let unique: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(unique.len(), keys.len(), "duplicate const value: {:?}", keys);

        // The two op-keys (used as dispatch discriminators) are distinct
        // AND neither key is a prefix of the other (a substring-match
        // misdispatch would silently route all version records into the
        // diff extractor's None branch, looking like a metadata bug).
        assert_ne!(VERSION_OP_KEY, DIFF_OP_KEY);
        assert!(!VERSION_OP_KEY.starts_with(DIFF_OP_KEY));
        assert!(!DIFF_OP_KEY.starts_with(VERSION_OP_KEY));

        // Version family vs diff family disjoint — no key from one bucket
        // can accidentally be read as the other (catches a future refactor
        // that drops the *_OP_KEY suffix dispatch in favor of payload-key
        // sniffing).
        let version_family = [
            VERSION_OP_KEY, PREV_VERSION_KEY, VERSION_NUMBER_KEY, CHANGE_SUMMARY_KEY,
        ];
        let diff_family = [DIFF_OP_KEY, DIFF_FROM_KEY, DIFF_TO_KEY];
        for v in &version_family {
            for d in &diff_family {
                assert_ne!(v, d, "version/diff family overlap: {v} == {d}");
            }
        }

        // Cross-module disjointness (other DAM op-modules in the same
        // metadata namespace; a collision would silently route into the
        // wrong extractor).
        let other_module_op_keys = [
            crate::seed_vault::SEED_VAULT_OP_KEY,
            crate::collaboration::COLLABORATION_OP_KEY,
            crate::network::key_rotation::KEY_ROTATION_KEY,
            crate::network::key_rotation::REVOCATION_OP_KEY,
            crate::network::key_rotation::SPHINCS_ROTATION_KEY,
        ];
        for k in &keys {
            for other in &other_module_op_keys {
                assert_ne!(k, other,
                    "versioning key {k} collides with foreign module key {other}");
            }
        }

        // The op-key VALUES emitted by the builder are different from
        // the KEY names — the value is the lowercase module noun
        // (`"version"` / `"diff"`), the key is the suffix `*_op`.
        // A worker who silently inverts these would have the same len so
        // length checks pass; pin the value here.
        let meta = version_metadata(None, 1, None);
        assert_eq!(meta.get(VERSION_OP_KEY).map(String::as_str), Some("version"));
        assert_ne!(meta.get(VERSION_OP_KEY).map(String::as_str), Some(VERSION_OP_KEY));
        let dmeta = diff_metadata("a", "b");
        assert_eq!(dmeta.get(DIFF_OP_KEY).map(String::as_str), Some("diff"));
        assert_ne!(dmeta.get(DIFF_OP_KEY).map(String::as_str), Some(DIFF_OP_KEY));
    }

    /// VersionRecord 6-field + DiffRecord 4-field + VersionFork 2-field
    /// struct shape pins via exhaustive destructuring (force compile-time
    /// stability of public field names) + Clone independence + serde JSON
    /// round-trip preserves every field + Debug contains every field name.
    #[test]
    fn batch_b_struct_shapes_clone_serde_round_trip_and_debug_names() {
        // VersionRecord — exhaustive destructure forces all 6 field names.
        let v = VersionRecord {
            record_id: "rec-1".into(),
            previous_version: Some("rec-0".into()),
            version_number: 7,
            change_summary: Some("typo fix".into()),
            creator: "alice".into(),
            content_hash: "abcdef".into(),
        };
        let VersionRecord {
            record_id,
            previous_version,
            version_number,
            change_summary,
            creator,
            content_hash,
        } = v.clone();
        assert_eq!(record_id, "rec-1");
        assert_eq!(previous_version.as_deref(), Some("rec-0"));
        assert_eq!(version_number, 7);
        assert_eq!(change_summary.as_deref(), Some("typo fix"));
        assert_eq!(creator, "alice");
        assert_eq!(content_hash, "abcdef");

        // Clone independence — mutating the clone leaves the original alone.
        let mut clone = v.clone();
        clone.version_number = 999;
        clone.creator = "bob".into();
        clone.previous_version = None;
        assert_eq!(v.version_number, 7, "original untouched");
        assert_eq!(v.creator, "alice");
        assert_eq!(v.previous_version.as_deref(), Some("rec-0"));

        // Serde JSON round-trip preserves all 6 fields (PartialEq isn't
        // derived, so compare field-by-field).
        let json = serde_json::to_string(&v).expect("ser");
        let back: VersionRecord = serde_json::from_str(&json).expect("de");
        assert_eq!(back.record_id, v.record_id);
        assert_eq!(back.previous_version, v.previous_version);
        assert_eq!(back.version_number, v.version_number);
        assert_eq!(back.change_summary, v.change_summary);
        assert_eq!(back.creator, v.creator);
        assert_eq!(back.content_hash, v.content_hash);

        // Debug contains every field name (catches a refactor that drops
        // `#[derive(Debug)]` or replaces it with a hand-written impl).
        let dbg = format!("{:?}", v);
        for f in ["record_id", "previous_version", "version_number",
                  "change_summary", "creator", "content_hash"] {
            assert!(dbg.contains(f), "Debug missing {f}");
        }

        // None-arms preserved across round-trip (catches a serde rename
        // that silently drops Option::None — load-bearing because v1
        // records have previous_version == None on the wire).
        let v_none = VersionRecord {
            record_id: "r".into(),
            previous_version: None,
            version_number: 1,
            change_summary: None,
            creator: "c".into(),
            content_hash: "h".into(),
        };
        let json = serde_json::to_string(&v_none).expect("ser");
        let back: VersionRecord = serde_json::from_str(&json).expect("de");
        assert!(back.previous_version.is_none());
        assert!(back.change_summary.is_none());

        // DiffRecord — exhaustive 4-field destructure.
        let d = DiffRecord {
            record_id: "diff-1".into(),
            from_version: "v1".into(),
            to_version: "v2".into(),
            creator: "alice".into(),
        };
        let DiffRecord { record_id, from_version, to_version, creator } = d.clone();
        assert_eq!(record_id, "diff-1");
        assert_eq!(from_version, "v1");
        assert_eq!(to_version, "v2");
        assert_eq!(creator, "alice");

        let json = serde_json::to_string(&d).expect("ser");
        let back: DiffRecord = serde_json::from_str(&json).expect("de");
        assert_eq!(back.record_id, d.record_id);
        assert_eq!(back.from_version, d.from_version);
        assert_eq!(back.to_version, d.to_version);
        assert_eq!(back.creator, d.creator);

        let dbg = format!("{:?}", d);
        for f in ["record_id", "from_version", "to_version", "creator"] {
            assert!(dbg.contains(f), "Debug missing {f}");
        }

        // VersionFork — exhaustive 2-field destructure.
        let f = VersionFork {
            parent: "p".into(),
            branches: vec!["a".into(), "b".into()],
        };
        let VersionFork { parent, branches } = f.clone();
        assert_eq!(parent, "p");
        assert_eq!(branches, vec!["a".to_string(), "b".to_string()]);

        let json = serde_json::to_string(&f).expect("ser");
        let back: VersionFork = serde_json::from_str(&json).expect("de");
        assert_eq!(back.parent, f.parent);
        assert_eq!(back.branches, f.branches);

        let dbg = format!("{:?}", f);
        assert!(dbg.contains("parent"));
        assert!(dbg.contains("branches"));

        // Empty branches is a valid (but degenerate) VersionFork — the
        // detector only emits forks where children.len() > 1, but a hand-
        // constructed empty one must round-trip cleanly.
        let empty = VersionFork { parent: "p".into(), branches: vec![] };
        let json = serde_json::to_string(&empty).expect("ser");
        let back: VersionFork = serde_json::from_str(&json).expect("de");
        assert_eq!(back.parent, "p");
        assert!(back.branches.is_empty());
    }

    /// register_version validation matrix exhaustive — every Err arm of
    /// the function is hit, every Ok arm too. Locks the policy contract
    /// for the version chain: no v0, no skip, no creator-swap, no
    /// duplicate, no orphan prev. Adds boundary cases the existing tests
    /// don't cover: numeric edge values, deeper gap detection, and
    /// asserts state is NOT mutated on error (load-bearing — a partial
    /// write would leave dangling children/roots entries that a later
    /// `latest_versions` traversal would visit).
    #[test]
    fn batch_b_register_version_validation_matrix_and_no_partial_mutation() {
        // Helper: exhaustive Err matcher.
        fn err_contains(state: &mut VersionState, v: VersionRecord, frag: &str) {
            let count_before = state.version_count();
            let chain_before = state.chain_count();
            let result = state.register_version(v);
            assert!(result.is_err(), "expected err containing {frag}, got Ok");
            let msg = result.unwrap_err();
            assert!(msg.contains(frag), "expected {frag}, got {msg}");
            // CRITICAL: state must NOT mutate on error path.
            assert_eq!(state.version_count(), count_before, "version_count drifted on err");
            assert_eq!(state.chain_count(), chain_before, "chain_count drifted on err");
        }

        // Empty state pre-conditions.
        let mut s = VersionState::new();
        assert_eq!(s.version_count(), 0);
        assert_eq!(s.chain_count(), 0);

        // ─── v0 rejection ─────
        err_contains(&mut s, make_version("v0", None, 0, "alice"), "must be >= 1");
        // u64::MIN == 0 also covers the literal-zero check.
        err_contains(&mut s, make_version("v0b", Some("phantom"), 0, "alice"), "must be >= 1");

        // ─── v1 with previous_version rejection ─────
        err_contains(&mut s, make_version("v1bad", Some("phantom"), 1, "alice"), "must not have");

        // ─── v2+ without previous_version rejection ─────
        for n in [2u64, 5, 100, u32::MAX as u64, u64::MAX] {
            err_contains(&mut s, make_version(&format!("vn-{n}"), None, n, "alice"),
                "must reference");
        }

        // ─── Orphan previous rejection ─────
        err_contains(&mut s, make_version("v2bad", Some("phantom"), 2, "alice"), "not found");

        // OK: register a clean v1 to enable downstream chain tests.
        s.register_version(make_version("v1", None, 1, "alice")).expect("v1 ok");
        assert_eq!(s.version_count(), 1);
        assert_eq!(s.chain_count(), 1);

        // ─── Duplicate rejection ─────
        // The duplicate check runs AFTER the v1/no-prev / v2+/has-prev /
        // version-gap / creator-match checks (see register_version's flow);
        // so a duplicate must be otherwise-valid to reach the "already
        // registered" arm. Same identity_hash but different change_summary
        // exercises that path.
        let mut dup = make_version("v1", None, 1, "alice");
        dup.change_summary = Some("re-publish attempt".into());
        err_contains(&mut s, dup, "already registered");

        // ─── Version gap rejection (deeper than +2) ─────
        // prev is v1 (number=1), so claiming v3, v5, v100 should all reject.
        for n in [3u64, 5, 100, 1_000_000] {
            err_contains(&mut s, make_version(&format!("g-{n}"), Some("v1"), n, "alice"),
                "version gap");
        }

        // ─── Creator mismatch rejection ─────
        for c in ["bob", "carol", "", "  ", "ALICE"] {
            err_contains(&mut s, make_version(&format!("c-{c}"), Some("v1"), 2, c),
                "creator mismatch");
        }

        // ─── Number-mismatch (smaller than prev+1) — caught by gap check ─────
        // prev is v1; claiming v1 again is duplicate (handled above), but
        // claiming v0 is rejected by v0 check first. Claim v2 with prev
        // being v1 ✓ ok.
        s.register_version(make_version("v2", Some("v1"), 2, "alice")).expect("v2 ok");
        assert_eq!(s.version_count(), 2);
        // Now claim v2 again with prev=v2 (would be v3) — number=2 prev.number=2 → gap.
        err_contains(&mut s, make_version("v2-dup", Some("v2"), 2, "alice"), "version gap");

        // ─── OK Ok arm: linear chain extension ─────
        s.register_version(make_version("v3", Some("v2"), 3, "alice")).expect("v3 ok");
        assert_eq!(s.version_count(), 3);
        assert_eq!(s.chain_count(), 1, "still single root");

        // ─── OK Ok arm: fork at v1 — branches add chain_count? No — chain_count
        // counts ROOTS (v1 records), not chain TIPS. Fork only adds another tip.
        s.register_version(make_version("v2b", Some("v1"), 2, "alice")).expect("v2b ok");
        assert_eq!(s.version_count(), 4);
        assert_eq!(s.chain_count(), 1, "fork at v1 does NOT add a new root");

        // Add a SEPARATE root via a new v1 with different record_id —
        // chain_count() == roots.len() advances by 1.
        s.register_version(make_version("v1-other", None, 1, "bob")).expect("v1-other ok");
        assert_eq!(s.version_count(), 5);
        assert_eq!(s.chain_count(), 2, "second root added");

        // children/parent index integrity after the various Ok paths.
        let kids = s.children_of("v1");
        assert_eq!(kids.len(), 2, "v1 forks into v2 and v2b");
        assert!(kids.contains(&"v2".to_string()));
        assert!(kids.contains(&"v2b".to_string()));
        let kids = s.children_of("v2");
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0], "v3");
        // children_of on terminal tip → empty slice (no panic).
        assert!(s.children_of("v3").is_empty());
        // children_of on totally-unknown id → empty slice (no panic).
        assert!(s.children_of("nothing").is_empty());

        // detect_forks emits exactly one fork (v1 → [v2, v2b]).
        let forks = s.detect_forks();
        assert_eq!(forks.len(), 1);
        assert_eq!(forks[0].parent, "v1");
        assert_eq!(forks[0].branches.len(), 2);

        // root_for traversal.
        assert_eq!(s.root_for("v3").map(|r| r.record_id.as_str()), Some("v1"));
        assert_eq!(s.root_for("v2b").map(|r| r.record_id.as_str()), Some("v1"));
        assert_eq!(s.root_for("v1").map(|r| r.record_id.as_str()), Some("v1"));
        assert_eq!(s.root_for("v1-other").map(|r| r.record_id.as_str()), Some("v1-other"));
        assert!(s.root_for("phantom").is_none());
    }

    /// VersionState::new == VersionState::default initial-state pin (every
    /// accessor returns its zero / empty value for an unknown id; no panic
    /// across the entire surface) + serde JSON round-trip preserves empty
    /// state + cumulative invariants (version_count == sum of chain
    /// lengths after each registration step). Locks the contract that a
    /// freshly-constructed VersionState is observationally indistinguishable
    /// from any path that produces zero state.
    #[test]
    fn batch_b_version_state_initial_state_pin_serde_round_trip_and_invariants() {
        let n = VersionState::new();
        let d: VersionState = VersionState::default();

        // Accessor zero-state across 9 entry points — every read returns
        // its empty / None for any string id.
        for s in [&n, &d] {
            assert_eq!(s.version_count(), 0);
            assert_eq!(s.chain_count(), 0);
            assert_eq!(s.diff_count(), 0);
            for id in ["", "v1", "phantom", "🦀", "a/b/c"] {
                assert!(s.get_version(id).is_none(), "get_version({id}) not None");
                assert!(s.chain_to_root(id).is_empty(), "chain_to_root({id}) not empty");
                assert!(s.latest_versions(id).is_empty(), "latest_versions({id}) not empty");
                assert!(s.children_of(id).is_empty(), "children_of({id}) not empty");
                assert!(s.root_for(id).is_none(), "root_for({id}) not None");
            }
            assert!(s.detect_forks().is_empty(), "detect_forks not empty on fresh state");
            assert!(s.diffs_between("a", "b").is_empty());
            assert!(s.diffs_between("", "").is_empty());
        }

        // Serde JSON round-trip preserves empty state (field counts
        // remain 0 after a full ser→de cycle).
        let json = serde_json::to_string(&n).expect("ser");
        let back: VersionState = serde_json::from_str(&json).expect("de");
        assert_eq!(back.version_count(), 0);
        assert_eq!(back.chain_count(), 0);
        assert_eq!(back.diff_count(), 0);

        // After a non-trivial chain registration, serde JSON round-trip
        // preserves all 3 counters AND the children index (verified via
        // `children_of`).
        let mut s = VersionState::new();
        s.register_version(make_version("v1", None, 1, "alice")).unwrap();
        s.register_version(make_version("v2", Some("v1"), 2, "alice")).unwrap();
        s.register_version(make_version("v3", Some("v2"), 3, "alice")).unwrap();
        s.register_version(make_version("v2b", Some("v1"), 2, "alice")).unwrap();
        let json = serde_json::to_string(&s).expect("ser");
        let back: VersionState = serde_json::from_str(&json).expect("de");
        assert_eq!(back.version_count(), 4);
        assert_eq!(back.chain_count(), 1);
        // Children index preserved.
        let kids = back.children_of("v1");
        assert_eq!(kids.len(), 2);
        // Chain reconstruction works on the deserialized state.
        let chain = back.chain_to_root("v3");
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].record_id, "v3");
        assert_eq!(chain[2].record_id, "v1");

        // Tip detection on the deserialized state matches pre-ser state.
        let tips = back.latest_versions("v1");
        let tip_ids: std::collections::HashSet<&str> =
            tips.iter().map(|v| v.record_id.as_str()).collect();
        assert_eq!(tip_ids.len(), 2);
        assert!(tip_ids.contains("v3"));
        assert!(tip_ids.contains("v2b"));

        // Cumulative invariant: version_count advances exactly +1 per
        // successful register (no off-by-one when fork branches are added).
        let mut s = VersionState::new();
        let mut expected = 0usize;
        for (i, (id, prev, num)) in [
            ("a", None, 1u64),
            ("a-c1", Some("a"), 2),
            ("a-c2", Some("a"), 2),
            ("a-c1-d", Some("a-c1"), 3),
        ].iter().enumerate() {
            s.register_version(make_version(id, *prev, *num, "alice")).unwrap();
            expected += 1;
            assert_eq!(s.version_count(), expected, "step {i}: id={id}");
        }
        assert_eq!(s.chain_count(), 1, "one root across all branches");
        // detect_forks finds exactly one fork (parent "a", 2 branches).
        let forks = s.detect_forks();
        assert_eq!(forks.len(), 1);
        assert_eq!(forks[0].parent, "a");
        assert_eq!(forks[0].branches.len(), 2);
    }

    /// version_metadata / diff_metadata exact key-shape pins (load-bearing
    /// for the on-wire metadata bag — extra keys leak into the record
    /// hash, missing keys break extractor) + BTreeMap ASCII-sorted iter
    /// order + extract_version / extract_diff mutual exclusivity + invalid
    /// metadata produces None silently + rebuild_version_state on mixed
    /// valid/invalid inputs silently drops the invalid ones (load-bearing
    /// boot-time invariant: a corrupt single record cannot poison the
    /// rebuild for the rest of the chain).
    #[test]
    fn batch_b_metadata_builder_exact_shapes_extractor_mutual_exclusivity_and_rebuild_resilience() {
        // ─── version_metadata exact-shape matrix ─────
        // No prev + no summary → exactly 2 keys.
        let m = version_metadata(None, 1, None);
        assert_eq!(m.len(), 2);
        assert_eq!(m.get(VERSION_OP_KEY).map(String::as_str), Some("version"));
        assert_eq!(m.get(VERSION_NUMBER_KEY).map(String::as_str), Some("1"));
        assert!(!m.contains_key(PREV_VERSION_KEY));
        assert!(!m.contains_key(CHANGE_SUMMARY_KEY));

        // Prev only → 3 keys.
        let m = version_metadata(Some("rec-0"), 2, None);
        assert_eq!(m.len(), 3);
        assert_eq!(m.get(PREV_VERSION_KEY).map(String::as_str), Some("rec-0"));
        assert_eq!(m.get(VERSION_NUMBER_KEY).map(String::as_str), Some("2"));
        assert!(!m.contains_key(CHANGE_SUMMARY_KEY));

        // Summary only → 3 keys (v1 with summary).
        let m = version_metadata(None, 1, Some("initial"));
        assert_eq!(m.len(), 3);
        assert_eq!(m.get(CHANGE_SUMMARY_KEY).map(String::as_str), Some("initial"));
        assert!(!m.contains_key(PREV_VERSION_KEY));

        // Both → 4 keys.
        let m = version_metadata(Some("rec-0"), 2, Some("typo fix"));
        assert_eq!(m.len(), 4);
        for k in [VERSION_OP_KEY, VERSION_NUMBER_KEY, PREV_VERSION_KEY, CHANGE_SUMMARY_KEY] {
            assert!(m.contains_key(k), "missing {k}");
        }

        // BTreeMap iteration is ASCII-sorted by key. Pin the order for the
        // 4-key dense case (load-bearing for any consumer that depends on
        // deterministic iteration — e.g., a content hash that walks the
        // bag in iteration order).
        let keys: Vec<&str> = m.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["change_summary", "previous_version", "version_number", "version_op"]);

        // No leakage from diff family.
        for k in [DIFF_OP_KEY, DIFF_FROM_KEY, DIFF_TO_KEY] {
            assert!(!m.contains_key(k), "version metadata leaked diff key {k}");
        }

        // ─── diff_metadata exact-shape ─────
        let d = diff_metadata("v1", "v2");
        assert_eq!(d.len(), 3);
        assert_eq!(d.get(DIFF_OP_KEY).map(String::as_str), Some("diff"));
        assert_eq!(d.get(DIFF_FROM_KEY).map(String::as_str), Some("v1"));
        assert_eq!(d.get(DIFF_TO_KEY).map(String::as_str), Some("v2"));
        let keys: Vec<&str> = d.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["diff_from_version", "diff_op", "diff_to_version"]);
        // No leakage from version family.
        for k in [VERSION_OP_KEY, VERSION_NUMBER_KEY, PREV_VERSION_KEY, CHANGE_SUMMARY_KEY] {
            assert!(!d.contains_key(k), "diff metadata leaked version key {k}");
        }

        // ─── extract_version / extract_diff mutual exclusivity ─────
        // A version-metadata bag yields Some from extract_version, None
        // from extract_diff (op-key dispatch).
        let vm = version_metadata(Some("rec-0"), 2, Some("typo"));
        assert!(extract_version(&vm, "rec-id", "alice", "hash").is_some());
        assert!(extract_diff(&vm, "rec-id", "alice").is_none());

        // Symmetric: diff bag.
        let dm = diff_metadata("v1", "v2");
        assert!(extract_diff(&dm, "diff-id", "alice").is_some());
        assert!(extract_version(&dm, "diff-id", "alice", "hash").is_none());

        // ─── extract_version None paths ─────
        let mut bad = std::collections::BTreeMap::new();
        // No op-key at all.
        assert!(extract_version(&bad, "r", "c", "h").is_none());

        // Wrong op-key value.
        bad.insert(VERSION_OP_KEY.into(), "not-version".into());
        bad.insert(VERSION_NUMBER_KEY.into(), "1".into());
        assert!(extract_version(&bad, "r", "c", "h").is_none(),
            "wrong op-key value must yield None");

        // Right op-key but missing version_number.
        bad.clear();
        bad.insert(VERSION_OP_KEY.into(), "version".into());
        assert!(extract_version(&bad, "r", "c", "h").is_none(),
            "missing version_number → None");

        // Non-numeric version_number.
        bad.insert(VERSION_NUMBER_KEY.into(), "not-a-number".into());
        assert!(extract_version(&bad, "r", "c", "h").is_none(),
            "non-numeric version_number → None");

        // Negative-looking number → u64 parse fails → None.
        bad.insert(VERSION_NUMBER_KEY.into(), "-1".into());
        assert!(extract_version(&bad, "r", "c", "h").is_none(), "-1 → None");

        // u64::MAX is acceptable (no upper-bound clamp).
        bad.insert(VERSION_NUMBER_KEY.into(), u64::MAX.to_string());
        let extracted = extract_version(&bad, "r", "c", "h").expect("u64::MAX accepted");
        assert_eq!(extracted.version_number, u64::MAX);

        // ─── extract_diff None paths ─────
        let mut bad = std::collections::BTreeMap::new();
        assert!(extract_diff(&bad, "r", "c").is_none()); // no op-key
        bad.insert(DIFF_OP_KEY.into(), "wrong".into());
        bad.insert(DIFF_FROM_KEY.into(), "v1".into());
        bad.insert(DIFF_TO_KEY.into(), "v2".into());
        assert!(extract_diff(&bad, "r", "c").is_none(), "wrong op-key → None");

        bad.insert(DIFF_OP_KEY.into(), "diff".into());
        bad.remove(DIFF_FROM_KEY);
        assert!(extract_diff(&bad, "r", "c").is_none(), "missing from → None");

        bad.insert(DIFF_FROM_KEY.into(), "v1".into());
        bad.remove(DIFF_TO_KEY);
        assert!(extract_diff(&bad, "r", "c").is_none(), "missing to → None");

        // ─── extract_version preserves all fields including None arms ─────
        let m = version_metadata(None, 1, None);
        let extracted = extract_version(&m, "rec-1", "alice", "h-1").expect("ok");
        assert_eq!(extracted.record_id, "rec-1");
        assert!(extracted.previous_version.is_none());
        assert_eq!(extracted.version_number, 1);
        assert!(extracted.change_summary.is_none());
        assert_eq!(extracted.creator, "alice");
        assert_eq!(extracted.content_hash, "h-1");

        // ─── rebuild_version_state resilience: invalid records are silently dropped ─────
        // Mix: valid v1, valid v2, gap-v4 (no v3), creator-mismatched v3
        // (different creator), and a diff that references a non-existent
        // version. Only v1+v2 should land; the orphaned ones are silently
        // dropped because rebuild uses `let _ = state.register_version(...)`.
        let v1 = make_version("v1", None, 1, "alice");
        let v2 = make_version("v2", Some("v1"), 2, "alice");
        let v4_gap = make_version("v4", Some("v2"), 4, "alice"); // gap
        let v3_bad = make_version("v3", Some("v2"), 3, "bob");   // creator mismatch
        let d_ok = DiffRecord {
            record_id: "d-ok".into(),
            from_version: "v1".into(),
            to_version: "v2".into(),
            creator: "alice".into(),
        };
        let d_bad = DiffRecord {
            record_id: "d-bad".into(),
            from_version: "phantom".into(),
            to_version: "v2".into(),
            creator: "alice".into(),
        };

        let versions = vec![&v4_gap, &v1, &v3_bad, &v2]; // out of order on purpose
        let diffs = vec![&d_ok, &d_bad];

        let state = rebuild_version_state(versions.into_iter(), diffs.into_iter());
        assert_eq!(state.version_count(), 2, "v1+v2 only — bad records dropped");
        assert_eq!(state.chain_count(), 1);
        assert_eq!(state.diff_count(), 1, "only d-ok survives");
        assert!(state.get_version("v1").is_some());
        assert!(state.get_version("v2").is_some());
        assert!(state.get_version("v4").is_none(), "gap version dropped");
        assert!(state.get_version("v3").is_none(), "creator-mismatch version dropped");
    }
}
