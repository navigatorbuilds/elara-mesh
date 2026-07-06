//! Content safety hardening — Protocol-level defense against harmful content.
//!
//! Makes the network structurally hostile to content distribution rather than
//! relying on content filtering (an arms race we'd lose).
//!
//! Six defense layers:
//! 1. Metadata key allowlist — reject unknown keys
//! 2. Text field byte limits — cap user-writable strings
//! 3. URL rejection — no URIs in any text field
//! 4. Tombstone mechanism — genesis authority can suppress records
//! 5. Browser-side enforcement — defense in depth
//! 6. Propagation filtering — tombstoned records stored but not gossiped

//!
//! Spec references:
//!   @spec Protocol §11.25

use std::collections::BTreeMap;

use crate::errors::{ElaraError, Result};

// ─── Allowed metadata keys ────────────────────────────────────────────────────
//
// Every key the protocol reads or writes, organized by operation category.
// Records containing keys not in this list are rejected at insertion.

const ALLOWED_KEYS: &[&str] = &[
    // Core beat operations (accounting/types.rs)
    "beat_op",
    "beat_amount",
    "beat_to",
    "beat_from",
    "beat_memo",
    "beat_purpose",
    "beat_reason",
    "beat_record_id",
    "beat_offender",
    "beat_challenger",
    "beat_jury",
    "beat_stake_id",
    "beat_last_activity",
    "beat_dormant_identity",
    "beat_target_identity",
    "beat_last_known_active",
    "beat_proof_signature",
    // Batch operations (accounting/batch.rs)
    "batch_op",
    "batch_count",
    "batch_merkle_root",
    "batch_start",
    "batch_end",
    "batch_device_count",
    // Delegation (accounting/delegation.rs)
    "delegation_op",
    "delegation_child",
    "delegation_scope",
    // Dormancy (accounting/dormancy.rs)
    "dormancy_op",
    "target_identity",
    "signature",
    // Order / HTLC metadata keys (DEX backend removed 2026-06-14; retained for filter compat)
    "amount",
    "expires_at",
    // Governance (accounting/governance.rs)
    "governance_op",
    "governance_category",
    "governance_title",
    "governance_description",
    "governance_proposal_id",
    "governance_direction",
    "governance_delegate",
    "governance_veto_zone",
    "committee_members",
    "committee_vrf_seed",
    "committee_is_revote",
    "committee_selected_at",
    "reason",
    // Agent mandate (mandate.rs / network/mandate_node.rs) — C4 slice 1.
    // `mandate_op` carries a serialized issuance MandateRecord; `revocation_op`
    // a serialized RevocationRecord (distinct from key_rotation's
    // "key_revocation"); `mandate_ref` is the mandate_id an act invokes (rides
    // in SIGNED metadata so the agent commits to which mandate it claims).
    crate::mandate::MANDATE_OP_KEY,
    crate::mandate::MANDATE_REVOCATION_OP_KEY,
    crate::mandate::MANDATE_REF_METADATA_KEY,
    // Emergency circuit-breaker (network/emergency.rs). Authority-signed Halt/Resume
    // ops. MUST be allowlisted or every halt record hard-rejects at ingest.
    crate::emergency::EMERGENCY_HALT_OP_KEY,
    crate::emergency::EMERGENCY_RESUME_OP_KEY,
    // Storage market (accounting/storage_market.rs)
    "storage_op",
    "storage_provider",
    "storage_record_refs",
    "storage_cost",
    "storage_duration_secs",
    "storage_delegation_id",
    "storage_missing_records",
    // Epoch (network/epoch.rs)
    "epoch_op",
    "epoch_zone",
    "epoch_number",
    "epoch_start",
    "epoch_end",
    "epoch_record_count",
    "epoch_merkle_root",
    "epoch_record_hashes",
    "epoch_previous_seal",
    "epoch_sparse_merkle_root",
    "epoch_vrf_output",
    "epoch_vrf_proof",
    "epoch_zone_balance_total",
    "epoch_zone_registry_root",
    "epoch_zone_registry_delta",
    "epoch_zone_count",
    // Stage 3b.5 rank-aware aggregator (network/epoch.rs, network/aggregator.rs)
    "epoch_aggregator_rank",
    // Gap 1 account-state SMT root bound into the seal (network/epoch.rs).
    // Light clients verify `/proof/account/{id}` against this value.
    "epoch_account_smt_root",
    // B2 fix: per-dest-zone canonical finality committee anchors bound into the
    // seal (network/epoch.rs, internal design notes). JSON
    // object { zone_path: hex(committee_hash) }. Read at XZoneAbort apply/replay
    // so a forged abort committee cannot pass verify_abort_quorum.
    "epoch_xzone_dest_finality_committees",
    // REALMS P1.5 drand time-bracket pulse, written into the seal by
    // DrandPulse::write_metadata (network/time_bracket.rs). Allowlisted now
    // (inert: no producer emits these yet — slice a2) so slice a3's populated
    // seals pass validate_metadata_keys without a same-commit allowlist edit —
    // pre-empting the super_seal_committee_hash silent-rejection fork class.
    "drand_round",
    "drand_randomness",
    "drand_genesis_unix",
    "drand_period_secs",
    "drand_chain_hash",
    // REALMS P1.5 slice a3: the round's BLS signature pair (192 hex chars
    // each — under the 256-byte default text cap; deliberately NOT in
    // TEXT_LIMITS so the encoded-data heuristic never applies). Carrying
    // them is what lets `elara-verify` reach a trustless PASS offline.
    "drand_signature",
    "drand_previous_signature",
    // Stage 3c.1 global quorum seal (network/epoch.rs)
    "stuck_zone",
    "emitter_zone",
    "stuck_epoch",
    "previous_seal_hash",
    "observed_base_timeout_ms",
    "observed_elapsed_ms",
    "emitted_at",
    "global_seal_vrf_output",
    "global_seal_vrf_proof",
    "seal_zone_count",
    // Zone transition (network/epoch.rs)
    "zone_transition_epoch",
    "zone_transition_new_count",
    "zone_transition_old_count",
    // Super-seal / Gap 3 archival (network/epoch.rs::build_super_seal_metadata)
    "super_seal_zone",
    "super_seal_start_epoch",
    "super_seal_end_epoch",
    "super_seal_count",
    "super_seal_merkle_root",
    "super_seal_prev_hash",
    "super_seal_committee_hash",
    // Network publish (network/publish.rs)
    "network_publish",
    "publication_id",
    "source_network_id",
    "published_records",
    "scope",
    "target_zone",
    "historical_depth",
    "redaction_policy",
    "transition_mode",
    // Zone subscription (network/zone_subscription.rs::subscription_metadata, Gap 5).
    // Emitted every health-tick by `run_zone_subscription_tick` (network/health.rs).
    // Pre-2026-05-13 these 4 keys were absent and every Gap-5 emit silently failed
    // validate_metadata_keys at insert time (debug!-logged, no metric) — same
    // regression-class as the super_seal_committee_hash bug fixed in 349535a.
    "zone_subscription_identity",
    "zone_subscription_zones",
    "zone_subscription_epoch",
    "zone_subscription_valid_until",
    // Cross-zone transfers (accounting/cross_zone.rs::lock_metadata + claim_metadata, Gap 2).
    // Wiring into the cross-zone settlement loop ships with Gap 2 close; pre-loading
    // the allowlist here avoids surfacing the same regression-class at production time.
    "xzone_op",
    "xzone_sender",
    "xzone_recipient",
    "xzone_amount",
    "xzone_source_zone",
    "xzone_dest_zone",
    "xzone_transfer_id",
    "xzone_merkle_proof",
    // Cross-zone sealed-abort (accounting/types.rs::xzone_abort_metadata, Gap 2 recovery).
    // PRODUCTION-ACTIVE: submitted by the abort aggregator at network/epoch.rs:5171
    // after the dest-zone committee gathers ≥2/3 non-inclusion quorum. Without
    // these keys, every aggregator submit
    // would have been silently rejected by validate_metadata_keys, leaving sealed
    // cross-zone transfers stuck past CLAIM_TIMEOUT_SECS with no recovery (the
    // stuck-transfer gauge alarms but the abort can never land). The meta-test
    // missed this builder because xzone_abort_metadata lives in accounting/types.rs
    // alongside the other beat_* builders, not in accounting/cross_zone.rs where
    // lock_metadata/claim_metadata sit; it is now in the meta-test enumeration.
    "xzone_dest_committee_hash",
    "xzone_dest_committee_size",
    "xzone_abort_signers",
    // Dispute (network/dispute.rs)
    "dispute_op",
    "dispute_record_id",
    "dispute_reason",
    "dispute_id",
    "dispute_evidence",
    "dispute_outcome",
    // Fisherman challenges (network/fisherman.rs)
    "challenge_op",
    "challenge_accused",
    "challenge_type",
    "challenge_evidence",
    "challenge_id",
    "challenge_guilty",
    "challenge_appeal_reason",
    // Sunset (network/sunset.rs)
    "sunset_op",
    "sunset_algorithm",
    "sunset_status",
    "sunset_effective_epoch",
    "sunset_reason",
    // Key management (network/key_rotation.rs)
    "key_rotation",
    "key_revocation",
    "sphincs_key_rotation",
    // VRF registration (network/vrf_registry.rs, Protocol §11.12)
    "vrf_registration",
    "vrf_public_key",
    "vrf_full_public_key",
    "node_type",
    // Witness profile registration (network/consensus.rs, Protocol §7.5)
    "witness_profile_registration",
    "witness_organization",
    "witness_subnet",
    "witness_geo_zone",
    // Witness register / bonded per-zone witness (accounting/types.rs, Gap 2.1 Phase 2b.3)
    "beat_zone",
    "beat_bond",
    "new_public_key",
    "new_sphincs_public_key",
    "rotation_reason",
    "revoked_public_key",
    "revocation_reason",
    // GC (network/gc.rs)
    "expires",
    // Collaboration (collaboration.rs)
    "collaboration_op",
    "work_hash",
    "participants",
    "chain",
    // Succession (succession.rs)
    "succession_op",
    "heirs",
    "heartbeat_timeout_secs",
    "time_lock_secs",
    "recovery_key_hash",
    "claim_owner",
    "claim_path",
    // Seed vault (seed_vault.rs)
    "seed_vault_op",
    "tier",
    "key_hash",
    "threshold",
    "new_key_hash",
    "shares_submitted",
    "claim_record_id",
    // Versioning (versioning.rs)
    "version_op",
    "version_number",
    "previous_version",
    "change_summary",
    "diff_op",
    "diff_from_version",
    "diff_to_version",
    // Tombstone (content_safety.rs)
    "tombstone_op",
    "tombstone_target",
    "tombstone_reason",
    // Document stamping (desktop app / RPC)
    "stamp_filename",
    "stamp_size",
    "stamp_type",
    // ZK proof metadata (Protocol §5.3)
    "zk_proof_type",
    // Prediction (accounting/types.rs, EMERGENT-MIND §4)
    "beat_predict_zone",
    "beat_predict_epoch",
    "beat_predict_claim",
    "beat_predict_value",
    // Cross-zone transfers (accounting/types.rs, economics §16)
    "beat_source_zone",
    "beat_dest_zone",
    "beat_transfer_id",
    // Custodial idle_decay batch (accounting/idle_decay.rs, economics §13.13.1) —
    // the whole frozen per-epoch batch is serialized under this one key.
    "idle_decay_batch",
    // Cross-zone timeout-refund batch (accounting/cross_zone.rs, economics §16.1) —
    // the whole frozen per-epoch XZoneRefundBatch is serialized under this key
    // (internal design notes).
    "xzone_refund_batch",
    // Cross-zone far-horizon SEALED-stuck reap batch (accounting/cross_zone.rs, co-fix
    // (b)) — same XZoneRefundBatch payload under a distinct key.
    "xzone_reap_batch",
    // Tip-merge (network/tip_merge.rs)
    "mesh_op",
    "merge_parent_count",
    // Agent action audit trails (wedge demo for autonomous-systems use case).
    // Records have classification=Public, no ledger op; `kind="agent_audit"`
    // is the discriminator consumers match on. Bounded text limits enforced
    // below (args_hash 128 bytes — forward-compat for SHA3-512 hex).
    "kind",
    "tool",
    "action",
    "args_hash",
    "agent_id",
    "session_id",
    // REALMS P1.5(b) anchor-proof records (anchor_proof.rs) — a matured
    // epoch-anchor artifact + its Bitcoin-upgraded OTS proof as a mesh
    // record (`kind="anchor_proof"`). Allowlisted INERT before any producer
    // emits them (same fork-class discipline as the drand_* keys above).
    // The node does NO OTS/BTC verification — elara-verify --anchor-record
    // recomputes the whole binding chain offline.
    "anchor_kind",
    "anchor_digest",
    "anchor_zone",
    "anchor_epoch",
    "anchor_artifact_b64",
    "anchor_ots_b64",
    // Reserved for the RFC-3161 TSA legs — allowlisted now to piggyback this
    // parity cycle; nothing populates them until a TSA verifier exists.
    "anchor_tsr_b64",
    "anchor_qtsr_b64",
];

/// Blocked keys — anti-rehypothecation operations disabled per economics v0.4.4.
const BLOCKED_KEYS: &[&str] = &[
    "derivative_op",
    "wrap_op",
    "collateral_op",
    "tokenize_op",
    "synthetic_op",
    "lend_op",
];

// ─── Text field limits ────────────────────────────────────────────────────────
//
// User-writable text fields with per-field byte limits.
// Limits chosen to allow legitimate use while preventing content distribution.

struct TextLimit {
    key: &'static str,
    max_bytes: usize,
}

const TEXT_LIMITS: &[TextLimit] = &[
    TextLimit { key: "beat_memo", max_bytes: 256 },
    TextLimit { key: "beat_reason", max_bytes: 256 },
    TextLimit { key: "governance_title", max_bytes: 128 },
    TextLimit { key: "governance_description", max_bytes: 1024 },
    TextLimit { key: "dispute_reason", max_bytes: 512 },
    TextLimit { key: "dispute_evidence", max_bytes: 1024 },
    TextLimit { key: "challenge_appeal_reason", max_bytes: 512 },
    TextLimit { key: "revocation_reason", max_bytes: 128 },
    TextLimit { key: "rotation_reason", max_bytes: 128 },
    TextLimit { key: "change_summary", max_bytes: 512 },
    TextLimit { key: "sunset_reason", max_bytes: 256 },
    // PQ crypto keys: Dilithium3 public keys are 1,952 bytes raw = ~3,904 bytes hex-encoded
    TextLimit { key: "new_public_key", max_bytes: 4096 },
    TextLimit { key: "revoked_public_key", max_bytes: 4096 },
    TextLimit { key: "vrf_full_public_key", max_bytes: 4096 },
    // node_type: "anchor" | "witness" | "leaf" | "light" — a few short tokens.
    TextLimit { key: "node_type", max_bytes: 32 },
    // Epoch seal fields: Dilithium3-VRF proofs are ~6,600 bytes hex-encoded
    TextLimit { key: "epoch_vrf_proof", max_bytes: 8192 },
    TextLimit { key: "epoch_vrf_output", max_bytes: 256 },
    TextLimit { key: "epoch_merkle_root", max_bytes: 256 },
    TextLimit { key: "epoch_account_smt_root", max_bytes: 256 },
    TextLimit { key: "epoch_seal_hash", max_bytes: 256 },
    TextLimit { key: "epoch_zone", max_bytes: 64 },
    // Stage 3c.1 global quorum seal hex fields
    TextLimit { key: "global_seal_vrf_proof", max_bytes: 8192 },
    TextLimit { key: "global_seal_vrf_output", max_bytes: 256 },
    TextLimit { key: "previous_seal_hash", max_bytes: 256 },
    // Agent audit fields (wedge). args_hash sized for SHA3-512 hex + slack.
    TextLimit { key: "kind", max_bytes: 32 },
    TextLimit { key: "tool", max_bytes: 64 },
    TextLimit { key: "action", max_bytes: 32 },
    TextLimit { key: "args_hash", max_bytes: 128 },
    TextLimit { key: "agent_id", max_bytes: 64 },
    TextLimit { key: "session_id", max_bytes: 64 },
    // Dormancy proof-of-life signature: Dilithium3 hex is ~6,605 bytes; allow 8KB slack.
    TextLimit { key: "beat_proof_signature", max_bytes: 8192 },
    // Anchor-proof records (P1.5(b)). The binding ingest bound is the 8192
    // per-metadata-value cap measured on the JSON-QUOTED value, so the
    // builder caps raw payloads at 6000/3000 bytes (base64 8000/4000) —
    // these TEXT_LIMITS are the network-enforced outer bounds.
    TextLimit { key: "anchor_kind", max_bytes: 32 },
    TextLimit { key: "anchor_zone", max_bytes: 64 },
    TextLimit { key: "anchor_digest", max_bytes: 128 },
    TextLimit { key: "anchor_artifact_b64", max_bytes: 4096 },
    TextLimit { key: "anchor_ots_b64", max_bytes: 8192 },
    TextLimit { key: "anchor_tsr_b64", max_bytes: 8192 },
    TextLimit { key: "anchor_qtsr_b64", max_bytes: 8192 },
];

/// Per-entry limit for challenge_evidence array field.
const CHALLENGE_EVIDENCE_ENTRY_MAX: usize = 512;

// ─── URL patterns ─────────────────────────────────────────────────────────────

const URL_PATTERNS: &[&str] = &[
    "http://",
    "https://",
    "ftp://",
    "data:",
    "javascript:",
    "magnet:",
    "ipfs://",
    "ipns://",
    "dweb:",
    "ar://",       // Arweave
    "hyper://",    // Hypercore
    "ssb:",        // Secure Scuttlebutt
    "blob:",       // Blob URLs
    "file://",     // Local file access
];

/// Common TLDs to detect plain domain names without protocol prefix.
const DOMAIN_TLDS: &[&str] = &[
    ".com/", ".org/", ".net/", ".io/", ".xyz/", ".onion/", ".info/",
    ".co/", ".me/", ".dev/", ".app/", ".site/", ".online/", ".link/",
    ".com:", ".org:", ".net:", ".io:", ".onion:",
];

fn contains_url(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    // Check explicit URI schemes
    if URL_PATTERNS.iter().any(|p| lower.contains(p)) {
        return true;
    }
    // Check plain domain patterns (e.g., "evil.com/path" or "evil.onion:8080")
    if DOMAIN_TLDS.iter().any(|tld| lower.contains(tld)) {
        return true;
    }
    // Check IP address patterns (e.g., "192.168.1.1:8080/file")
    // Simple heuristic: digits.digits.digits.digits followed by : or /
    let bytes = lower.as_bytes();
    for i in 0..bytes.len().saturating_sub(10) {
        if bytes[i].is_ascii_digit() {
            // Try to match N.N.N.N: or N.N.N.N/
            let rest = &lower[i..];
            if let Some(end) = rest.find([':', '/']) {
                let candidate = &rest[..end];
                let parts: Vec<&str> = candidate.split('.').collect();
                if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                    return true;
                }
            }
        }
    }
    false
}

/// Detect likely encoded binary data (base64, hex dumps).
/// Rejects text that looks like encoded content rather than natural language.
/// Heuristic: if >80% of chars are alphanumeric with no spaces in a string >64 bytes,
/// it's likely encoded data, not a human-written memo.
fn looks_like_encoded_data(text: &str) -> bool {
    if text.len() < 64 {
        return false; // too short to be meaningful encoded data
    }
    let alnum_count = text.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=').count();
    let space_count = text.chars().filter(|c| *c == ' ').count();
    let ratio = alnum_count as f64 / text.len() as f64;
    // High ratio of base64-like chars + very few spaces = likely encoded
    ratio > 0.85 && space_count < 3
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Maximum byte length for a metadata key name.
///
/// Forward-compat (2026-07-02) removed the ALLOWED_KEYS admission reject, so
/// this is the explicit key-name bound (the binary wire already bounds names
/// at 255 bytes via the u8 length prefix on BOTH transports — there is no
/// JSON ingest path; this narrows 255 → 128). Together with the `[a-z0-9_]`
/// charset rule it is a CONSCIOUS PROTOCOL FREEZE: every frozen release
/// binary carries it, so a future protocol key that exceeds 128 bytes or
/// leaves the charset would wedge old nodes — never author one. All current
/// ALLOWED_KEYS entries are ≤ 42 bytes snake_case, so nothing shipping today
/// is anywhere near the bound.
pub const MAX_METADATA_KEY_LEN: usize = 128;

/// Validate metadata keys — forward-compat admission (2026-07-02).
///
/// Until 2026-07-02 this was a strict ALLOWED_KEYS allowlist: any unknown key
/// failed the whole record. That made every additive metadata key a
/// cross-version sync break — a binary built before a key was allowlisted
/// rejected 100% of newer records carrying it (epoch seals included) and froze
/// at its epoch tip. Live incident: `drand_previous_signature` vs. the ACER
/// external-join node. A frozen public-release binary can never be taught new
/// keys, so admission must tolerate them. Decision + adversarial verification:
/// internal design notes.
///
/// The contract now:
/// - BLOCKED_KEYS (anti-rehypothecation) always reject.
/// - Key names: ≤ MAX_METADATA_KEY_LEN bytes of `[a-z0-9_]` (frozen invariant).
/// - Unknown non-blocked keys are ADMITTED and inert: no execution path
///   dispatches on unrecognized keys (named `get()` lookups only), record
///   identity/signature covers the full metadata map either way, and
///   `sanitize_text_fields` + the entry/value/record ingest caps still bound
///   every unknown value.
/// - ALLOWED_KEYS remains the producer-side schema registry: every in-tree
///   record builder MUST register its keys there (enforced by the builder
///   meta-tests in this file). Consensus-interpreted keys additionally
///   require wire/schema version discipline — forward-compat is for inert
///   additive keys only.
pub fn validate_metadata_keys(metadata: &BTreeMap<String, serde_json::Value>) -> Result<()> {
    for key in metadata.keys() {
        if key.len() > MAX_METADATA_KEY_LEN {
            return Err(ElaraError::Wire(format!(
                "metadata key too long: {} bytes (max {MAX_METADATA_KEY_LEN})",
                key.len()
            )));
        }
        if !key.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_')) {
            return Err(ElaraError::Wire(format!(
                "metadata key has invalid characters (allowed: lowercase ASCII letters, digits, underscore): {key}"
            )));
        }
        if BLOCKED_KEYS.contains(&key.as_str()) {
            return Err(ElaraError::Wire(format!(
                "blocked metadata key: {key}"
            )));
        }
        // Unknown non-blocked key: admitted, inert (forward-compat).
    }
    Ok(())
}

/// True if `key` is registered in the protocol schema registry (ALLOWED_KEYS).
/// Observability helper for the `unknown_metadata_keys_admitted_total`
/// counter — NOT an admission gate (see `validate_metadata_keys`).
pub fn is_known_key(key: &str) -> bool {
    ALLOWED_KEYS.contains(&key)
}

/// Default max bytes for any string metadata value without a specific TEXT_LIMITS entry.
/// Prevents using unchecked fields to smuggle content while staying within the
/// per-value 2KB cap enforced at the record level.
const DEFAULT_TEXT_MAX_BYTES: usize = 256;

/// Enforce byte limits and URL rejection on ALL string-valued metadata fields.
///
/// Fields listed in TEXT_LIMITS get their specific limits; all other string fields
/// get DEFAULT_TEXT_MAX_BYTES. This closes the gap where fields like `beat_purpose`,
/// `reason`, `scope`, `participants` etc. were not scanned for URLs or size.
pub fn sanitize_text_fields(metadata: &BTreeMap<String, serde_json::Value>) -> Result<()> {
    for (key, val) in metadata {
        // Find the specific limit for this key, or use default
        let max_bytes = TEXT_LIMITS
            .iter()
            .find(|l| l.key == key.as_str())
            .map(|l| l.max_bytes)
            .unwrap_or(DEFAULT_TEXT_MAX_BYTES);

        if let Some(text) = val.as_str() {
            if text.len() > max_bytes {
                return Err(ElaraError::Wire(format!(
                    "'{}' exceeds max length: {} bytes (max {})",
                    key,
                    text.len(),
                    max_bytes
                )));
            }
            if contains_url(text) {
                return Err(ElaraError::Wire(format!(
                    "URLs not allowed in '{}'", key
                )));
            }
            // Only check user-writable text fields for encoded data, not protocol fields
            // (identity hashes, op names, etc. are legitimately high-entropy hex strings)
            // Crypto key fields are exempt — PQ public keys are legitimately hex-encoded
            const CRYPTO_KEY_FIELDS: &[&str] = &[
                "new_public_key", "revoked_public_key", "vrf_full_public_key",
                // Epoch seal fields contain hex-encoded VRF proofs, Merkle roots, hashes
                "epoch_vrf_proof", "epoch_vrf_output", "epoch_merkle_root",
                "epoch_seal_hash", "epoch_record_hashes",
                // Global quorum seal hex fields (Stage 3c.1)
                "global_seal_vrf_proof", "global_seal_vrf_output", "previous_seal_hash",
                // Agent audit — args_hash is a hex SHA3 digest by design
                "args_hash",
            ];
            let is_text_field = TEXT_LIMITS.iter().any(|l| l.key == key.as_str());
            let is_crypto_field = CRYPTO_KEY_FIELDS.contains(&key.as_str())
                || key.starts_with("epoch_")  // All epoch_* fields may contain hex data
                // anchor_* carries base64 proof payloads BY DESIGN (P1.5(b)) —
                // without this exemption every anchor_proof record would be
                // silently rejected by the encoded-data heuristic at ingest.
                || key.starts_with("anchor_");
            if is_text_field && !is_crypto_field && looks_like_encoded_data(text) {
                return Err(ElaraError::Wire(format!(
                    "encoded binary data not allowed in '{}' (use plain text)", key
                )));
            }
        } else if let Some(arr) = val.as_array() {
            // Scan all string entries in arrays (challenge_evidence, participants, etc.)
            for (i, entry) in arr.iter().enumerate() {
                if let Some(s) = entry.as_str() {
                    if s.len() > CHALLENGE_EVIDENCE_ENTRY_MAX {
                        return Err(ElaraError::Wire(format!(
                            "'{key}[{i}]' exceeds max length: {} bytes (max {})",
                            s.len(),
                            CHALLENGE_EVIDENCE_ENTRY_MAX
                        )));
                    }
                    if contains_url(s) {
                        return Err(ElaraError::Wire(format!(
                            "URLs not allowed in '{key}[{i}]'"
                        )));
                    }
                    // Epoch hash arrays contain legitimately hex-encoded record hashes
                    // (anchor_* included for symmetry with the string path — no anchor
                    // array fields exist today, and the 512-byte entry cap above would
                    // reject a proof-sized element regardless).
                    let is_epoch_hash_field = key.starts_with("epoch_")
                        || key.starts_with("committee_")
                        || key.starts_with("anchor_");
                    if !is_epoch_hash_field && looks_like_encoded_data(s) {
                        return Err(ElaraError::Wire(format!(
                            "encoded binary data not allowed in '{key}[{i}]'"
                        )));
                    }
                }
            }
        }
    }

    Ok(())
}

/// Check if the creator identity is banned.
pub fn check_banned_identity(
    creator_hash: &str,
    banned_set: &std::collections::HashSet<String>,
) -> Result<()> {
    if banned_set.contains(creator_hash) {
        return Err(ElaraError::Wire(format!(
            "identity {} is banned", &creator_hash[..creator_hash.len().min(16)]
        )));
    }
    Ok(())
}

/// Scan ALL string-valued metadata fields against the content blocklist.
///
/// Performs case-insensitive substring matching against every term in the blocklist.
/// Applied to ALL metadata fields containing strings or string arrays.
/// Records matching any term are REJECTED before storage — they never touch the
/// DAG or get gossiped.
pub fn scan_blocked_content(
    metadata: &BTreeMap<String, serde_json::Value>,
    blocklist: &[String],
) -> Result<()> {
    if blocklist.is_empty() {
        return Ok(());
    }

    for (key, val) in metadata {
        if let Some(text) = val.as_str() {
            check_text_against_blocklist(text, key, blocklist)?;
        } else if let Some(arr) = val.as_array() {
            for (i, entry) in arr.iter().enumerate() {
                if let Some(s) = entry.as_str() {
                    check_text_against_blocklist(s, &format!("{key}[{i}]"), blocklist)?;
                }
            }
        }
    }

    Ok(())
}

fn check_text_against_blocklist(text: &str, field_name: &str, blocklist: &[String]) -> Result<()> {
    let lower = text.to_lowercase();
    for term in blocklist {
        if lower.contains(term.as_str()) {
            return Err(ElaraError::Wire(format!(
                "blocked content in '{}': matches content policy", field_name
            )));
        }
    }
    Ok(())
}

/// Extract tombstone target from record metadata, enforcing genesis authority.
///
/// Returns `Ok(Some(target_id))` if this is a valid tombstone record,
/// `Ok(None)` if not a tombstone, `Err` if invalid (wrong authority, missing fields).
pub fn extract_tombstone_target(
    metadata: &BTreeMap<String, serde_json::Value>,
    creator_identity_hash: &str,
    genesis_authority: &str,
) -> Result<Option<String>> {
    let op = match metadata.get("tombstone_op").and_then(|v| v.as_str()) {
        Some(op) => op,
        None => return Ok(None),
    };

    if op != "remove" {
        return Err(ElaraError::Wire(format!(
            "invalid tombstone_op: '{op}' (expected 'remove')"
        )));
    }

    if creator_identity_hash != genesis_authority {
        return Err(ElaraError::Wire(
            "only genesis authority can create tombstones".into(),
        ));
    }

    let target = metadata
        .get("tombstone_target")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ElaraError::Wire("tombstone_target required for tombstone records".into())
        })?;

    Ok(Some(target.to_string()))
}

// ─── Default blocklist ────────────────────────────────────────────────────────
//
// Minimal set of universally illegal terms that ship with every node.
// These cover content that is illegal in ALL jurisdictions. Node operators
// can extend the list via the admin API. Terms are matched case-insensitively
// as substrings by `scan_blocked_content`.

/// Returns the default content blocklist — terms illegal in all jurisdictions.
/// Covers CSAM, weapons of mass destruction, and explicit terrorism recruitment.
pub fn default_blocklist() -> Vec<String> {
    [
        // CSAM-related
        "child exploitation",
        "child pornography",
        "child abuse material",
        "minor sexual",
        "underage sexual",
        "pedophile content",
        "csam",
        // Weapons of mass destruction
        "build a nuclear weapon",
        "synthesize sarin",
        "weaponize anthrax",
        "dirty bomb instructions",
        // Explicit terrorism recruitment
        "join our jihad",
        "terrorist recruitment",
        "pledge allegiance to isis",
        "martyrdom operation",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "node-core"))]
mod tests {
    use super::*;

    fn meta(pairs: &[(&str, &str)]) -> BTreeMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::json!(v)))
            .collect()
    }

    #[test]
    fn test_allowlist_accepts_valid_keys() {
        let m = meta(&[
            ("beat_op", "transfer"),
            ("beat_amount", "1000000"),
            ("beat_to", "abc123def456"),
        ]);
        assert!(validate_metadata_keys(&m).is_ok());
    }

    /// FORWARD-COMPAT REGRESSION PIN (2026-07-02, internal design notes).
    /// Replaces `test_allowlist_rejects_unknown_key`, which pinned the OLD
    /// strict-allowlist behavior that froze cross-version sync (the
    /// `drand_previous_signature` incident). Any change that re-introduces
    /// "unknown metadata key" rejection for non-blocked keys re-arms the
    /// frozen-binary wedge and must not land.
    #[test]
    fn forward_compat_admission_policy_invariants() {
        // (1) Unknown non-blocked keys are ADMITTED — the incident class.
        let m = meta(&[("beat_op", "transfer"), ("evil_payload", "data")]);
        validate_metadata_keys(&m)
            .expect("unknown non-blocked key must be tolerated (forward-compat)");

        // (1b) Seal-shaped map with SEVEN unknown keys admitted — pins the
        // decision to NOT cap unknown-key cardinality: the drand family alone
        // adds up to 7 keys to one seal (time_bracket.rs::write_metadata), so
        // any unknown-count cap would recreate the wedge on the exact record
        // class that caused the incident.
        let m7 = meta(&[
            ("epoch_op", "seal"),
            ("future_drand_style_key_1", "a"),
            ("future_drand_style_key_2", "b"),
            ("future_drand_style_key_3", "c"),
            ("future_drand_style_key_4", "d"),
            ("future_drand_style_key_5", "e"),
            ("future_drand_style_key_6", "f"),
            ("future_drand_style_key_7", "g"),
        ]);
        validate_metadata_keys(&m7)
            .expect("7 unknown keys on one record must be tolerated — no cardinality cap");

        // (2) BLOCKED_KEYS still reject, with the 'blocked' message.
        let blocked = meta(&[("beat_op", "transfer"), ("synthetic_op", "x")]);
        let err = validate_metadata_keys(&blocked).unwrap_err();
        assert!(err.to_string().contains("blocked metadata key"),
            "BLOCKED_KEYS enforcement is invariant under forward-compat");

        // (3) Key-name length cap: reject at MAX_METADATA_KEY_LEN+1, admit at exactly the cap.
        let long_key = "a".repeat(MAX_METADATA_KEY_LEN + 1);
        let m_long: BTreeMap<String, serde_json::Value> =
            [(long_key, serde_json::json!("v"))].into_iter().collect();
        let err = validate_metadata_keys(&m_long).unwrap_err();
        assert!(err.to_string().contains("metadata key too long"), "got: {err}");
        let max_key = "a".repeat(MAX_METADATA_KEY_LEN);
        let m_max: BTreeMap<String, serde_json::Value> =
            [(max_key, serde_json::json!("v"))].into_iter().collect();
        validate_metadata_keys(&m_max)
            .expect("key name at exactly MAX_METADATA_KEY_LEN must be admitted");

        // (4) Charset freeze: uppercase / hyphen / dot / unicode all reject.
        for bad in ["UPPER_KEY", "hyphen-key", "dot.key", "ünïcode_key"] {
            let m_bad: BTreeMap<String, serde_json::Value> =
                [(bad.to_string(), serde_json::json!("v"))].into_iter().collect();
            let err = validate_metadata_keys(&m_bad).unwrap_err();
            assert!(err.to_string().contains("invalid characters"),
                "{bad} must be rejected by the charset rule, got: {err}");
        }

        // (5) Safety not weakened for admitted unknown keys:
        // sanitize_text_fields still bounds unknown string values at
        // DEFAULT_TEXT_MAX_BYTES and still rejects URLs in them.
        let big = "x".repeat(257);
        let m_oversize = meta(&[("some_future_key", big.as_str())]);
        assert!(sanitize_text_fields(&m_oversize).is_err(),
            "unknown-key value over DEFAULT_TEXT_MAX_BYTES must still be rejected");
        let m_url = meta(&[("some_future_key", "visit https://evil.example now")]);
        assert!(sanitize_text_fields(&m_url).is_err(),
            "unknown-key value carrying a URL must still be rejected");

        // (6) A renamed blocked key is admitted but inert — documents that the
        // blocklist dodge grants no capability (no execution path dispatches
        // on unrecognized keys).
        let m_dodge = meta(&[("derivative_op2", "wrap")]);
        validate_metadata_keys(&m_dodge)
            .expect("renamed blocked key is unknown → admitted (inert by named-dispatch)");
    }

    #[test]
    fn test_witness_register_metadata_passes_allowlist() {
        // Regression: Gap 2.1 Phase 2b.3 Slice 4 — the live POST
        // /admin/witness/register handler returned 500 "unknown metadata
        // key: beat_bond" because witness_register_metadata writes
        // `beat_zone` and `beat_bond`, neither of which were in the
        // allowlist. Ledger-layer unit tests skip content_safety, so the
        // gap only surfaced under the full record ingest path.
        let m = meta(&[
            ("beat_op", "witness_register"),
            ("beat_zone", "zone:hil"),
            ("beat_bond", "100000000"),
        ]);
        validate_metadata_keys(&m)
            .expect("witness_register metadata must pass the allowlist");
        sanitize_text_fields(&m)
            .expect("witness_register fields must pass text-limit check");
    }

    #[test]
    fn test_epoch_seal_with_account_smt_root_passes_allowlist() {
        // Regression: Gap 1 binds the global account-state SMT root into
        // every epoch seal (network/epoch.rs:768). `epoch_account_smt_root`
        // was missing from the allowlist, so every Gap-1 seal was rejected
        // on ingest — silently breaking light-client account proofs fleet-wide.
        let m = meta(&[
            ("epoch_op", "seal"),
            ("epoch_zone", "0"),
            ("epoch_number", "42"),
            ("epoch_merkle_root", "deadbeef"),
            ("epoch_account_smt_root", "cafebabe"),
        ]);
        validate_metadata_keys(&m).expect("Gap-1 seal metadata must pass the allowlist");
        sanitize_text_fields(&m).expect("Gap-1 seal fields must pass text-limit check");
    }

    #[test]
    fn test_super_seal_metadata_passes_allowlist() {
        // Regression: Gap 3 super-seal records (network/epoch.rs::build_super_seal_metadata)
        // write 7 `super_seal_*` keys. Without them in the allowlist, every super-seal
        // mint fails at insert with "unknown metadata key: super_seal_committee_hash"
        // — silently breaking checkpoint consolidation fleet-wide. Surfaced
        // by the split counter (insert_failures_total advanced on a node's first
        // super-seal attempt at epoch 11776 with buffer 64/64; sign_failures_total
        // stayed 0, isolating the failure to the storage step).
        let m = meta(&[
            ("super_seal_zone", "0"),
            ("super_seal_start_epoch", "11713"),
            ("super_seal_end_epoch", "11776"),
            ("super_seal_count", "64"),
            ("super_seal_merkle_root", "deadbeef00000000000000000000000000000000000000000000000000000000"),
            ("super_seal_prev_hash", "cafebabe00000000000000000000000000000000000000000000000000000000"),
            ("super_seal_committee_hash", "ba5eba1100000000000000000000000000000000000000000000000000000000"),
        ]);
        validate_metadata_keys(&m).expect("super-seal metadata must pass the allowlist");
        sanitize_text_fields(&m).expect("super-seal fields must pass text-limit check");
    }

    #[test]
    fn test_zone_subscription_metadata_passes_allowlist() {
        // Regression: Gap 5 zone-subscription records
        // (network/zone_subscription.rs::subscription_metadata) write 4 keys
        // — zone_subscription_{identity, zones, epoch, valid_until}. Before
        // this test, none were in the allowlist. Production emit path is
        // `run_zone_subscription_tick` (network/health.rs:1429) which calls
        // `gossip::insert_record_synced` → `validate_metadata_keys`. The
        // failure was silently `debug!`-logged at health.rs:516 so it never
        // surfaced in any metric — Gap-5 scoped jury selection has been
        // running on a stub registry for as long as the keys have been
        // missing. Surfaced 2026-05-13 by the meta-test below.
        use crate::network::zone_subscription::subscription_metadata;
        let zones: Vec<crate::ZoneId> = vec![
            crate::ZoneId::from_legacy(0),
            crate::ZoneId::from_legacy(1),
        ];
        let m = subscription_metadata("identity_hash_abc", &zones, 100, 150);
        validate_metadata_keys(&m)
            .expect("zone_subscription metadata must pass the allowlist");
        sanitize_text_fields(&m)
            .expect("zone_subscription fields must pass text-limit check");
    }

    #[test]
    fn test_xzone_metadata_passes_allowlist() {
        // Pre-emptive coverage for Gap 2 cross-zone settlement
        // (accounting/cross_zone.rs::{lock_metadata, claim_metadata}). The 8
        // `xzone_*` keys these builders write are added to the allowlist
        // ahead of Gap 2 wiring so the same regression-class as
        // super_seal_committee_hash / zone_subscription_* doesn't surface
        // again the day Gap 2 ships.
        use crate::accounting::cross_zone::{claim_metadata, lock_metadata, ProofSibling};
        let lock = lock_metadata(
            "sender_hash",
            "recipient_hash",
            1_000_000,
            &crate::ZoneId::from_legacy(0),
            &crate::ZoneId::from_legacy(1),
        );
        validate_metadata_keys(&lock)
            .expect("xzone lock metadata must pass the allowlist");
        let claim = claim_metadata(
            "transfer_id_xyz",
            "recipient_hash",
            1_000_000,
            &[ProofSibling { hash: [0u8; 32], is_right: false }],
        );
        validate_metadata_keys(&claim)
            .expect("xzone claim metadata must pass the allowlist");
    }

    #[test]
    fn test_xzone_abort_metadata_passes_allowlist() {
        // Regression test: the abort aggregator
        // at network/epoch.rs:5171 submits XZoneAbort records built by
        // accounting/types.rs::xzone_abort_metadata. Previously, three of its keys
        // (`xzone_dest_committee_hash`, `_size`, `_abort_signers`) were absent
        // from ALLOWED_KEYS, so every aggregator submit would have been
        // silently rejected by validate_metadata_keys. Sealed cross-zone
        // transfers past 24h CLAIM_TIMEOUT_SECS would alarm via the
        // stuck-transfer gauge but the abort could never land — same regression
        // class as Gap 3 super_seal_committee_hash (commit 349535a) and Gap 5
        // zone_subscription_* (commit a6dc743).
        let signers: Vec<crate::accounting::cross_zone::SealFinalityWitness> = vec![];
        let m = crate::accounting::types::xzone_abort_metadata(
            "transfer_id_xyz",
            &[7u8; 32],
            5,
            &signers,
        );
        validate_metadata_keys(&m)
            .expect("xzone_abort metadata must pass the allowlist");
        sanitize_text_fields(&m)
            .expect("xzone_abort fields must pass text-limit check");
    }

    /// P1.5(b) fork-class pin: a MAXIMUM-size anchor-proof payload (6000-byte
    /// OTS proof → ~8000-byte base64, pure encoded data) must clear BOTH
    /// ingest-side content gates. This pins the three-place interplay the
    /// fusion audit flagged as the top silent-rejection risk: ALLOWED_KEYS
    /// membership, the TEXT_LIMITS entry, and the `anchor_` crypto exemption
    /// in `sanitize_text_fields` — drop any one and this test goes red at PR
    /// time instead of the record silently vanishing at ingest.
    #[test]
    fn anchor_proof_full_size_payload_passes_both_gates() {
        let meta = crate::anchor_proof::anchor_proof_metadata(
            crate::anchor_proof::ANCHOR_KIND_ELARA_SEAL,
            "aa11bb22cc33dd44ee55ff660011223344556677889900aabbccddeeff001122",
            "0",
            9980,
            br#"{"v":1,"zone":"0","epoch":9980,"seal_hash":"aa"}"#,
            &vec![0xC3u8; crate::anchor_proof::MAX_ANCHOR_OTS_RAW],
        )
        .expect("max-size payload builds");
        validate_metadata_keys(&meta).expect("all anchor_* keys allowlisted");
        sanitize_text_fields(&meta)
            .expect("base64 proof exempt from the encoded-data heuristic");
    }

    /// Meta-test: enumerate every production-reaching record-metadata
    /// builder and assert every key it writes is in `ALLOWED_KEYS`.
    ///
    /// This closes the regression class that produced 3 silent production
    /// bugs already in 2026: `beat_bond` (witness_register), `node_type`
    /// (VRF registration), `epoch_account_smt_root` (Gap 1 seal),
    /// `super_seal_committee_hash` (Gap 3 super-seal), and
    /// `zone_subscription_*` (Gap 5 emit) — each surfacing only on the
    /// full record-ingest path, often months after the builder shipped.
    ///
    /// Pattern for adding a new builder: invoke it with valid stub args,
    /// take `meta.keys()`, push into `assertions` with a context label.
    #[test]
    fn test_all_record_builders_pass_allowlist() {
        fn check(ctx: &str, keys: impl IntoIterator<Item = String>) {
            for key in keys {
                assert!(
                    ALLOWED_KEYS.contains(&key.as_str()),
                    "{ctx} writes key '{key}' not in ALLOWED_KEYS — \
                     allowlist drift, will cause silent insert failure at runtime",
                );
            }
        }

        // ─── Ledger-layer (accounting/types.rs) ────────────────────────────────
        use crate::accounting::types::*;
        check("mint_metadata",
            mint_metadata(1, "to", "reason").into_keys());
        check("transfer_metadata",
            transfer_metadata(1, "to", Some("memo")).into_keys());
        check("stake_metadata",
            stake_metadata(1, &StakePurpose::Witness).into_keys());
        check("unstake_metadata",
            unstake_metadata("rec_id").into_keys());
        check("witness_register_metadata",
            witness_register_metadata("zone:0", 1).into_keys());
        check("witness_reward_metadata",
            witness_reward_metadata(1, "from", "to", "rec").into_keys());
        check("burn_metadata",
            burn_metadata(1, Some("memo")).into_keys());
        check("pool_fund_metadata",
            pool_fund_metadata(1).into_keys());
        check("xzone_lock_metadata",
            xzone_lock_metadata(1, "to", "0", "1").into_keys());
        check("xzone_claim_metadata",
            xzone_claim_metadata("tid", 1, "to").into_keys());
        check("xzone_cancel_metadata",
            xzone_cancel_metadata("tid").into_keys());
        check("xzone_reject_metadata",
            xzone_reject_metadata("tid").into_keys());
        // Gap 2 sealed-abort: the production-active abort aggregator
        // (network/epoch.rs:5171) submits records built by this exact
        // builder after the dest committee gathers ≥2/3 non-inclusion
        // quorum. This builder is easy to miss because it lives
        // in accounting/types.rs (not accounting/cross_zone.rs).
        check("xzone_abort_metadata",
            xzone_abort_metadata("tid", &[0u8; 32], 3, &[]).into_keys());
        // Custodial idle_decay (economics §13.13.1): the genesis-authority seal
        // loop (network/epoch.rs) emits one frozen batch per epoch via this
        // builder — the whole IdleDecayBatch is serialized under `idle_decay_batch`.
        check("idle_decay_batch_metadata",
            idle_decay_batch_metadata(&crate::accounting::idle_decay::IdleDecayBatch {
                epoch: 1, zone: "0".into(),
                debits: vec![("e".into(), 2)], pool_credit: 1,
                staker_credits: vec![("s".into(), 1)],
            }).into_keys());
        check("xzone_refund_batch_metadata",
            xzone_refund_batch_metadata(&crate::accounting::cross_zone::XZoneRefundBatch {
                epoch: 1, zone: "0".into(),
                refunds: vec![("t".into(), "s".into(), 1)],
            }).into_keys());
        check("xzone_reap_batch_metadata",
            xzone_reap_batch_metadata(&crate::accounting::cross_zone::XZoneRefundBatch {
                epoch: 1, zone: "0".into(),
                refunds: vec![("t".into(), "s".into(), 1)],
            }).into_keys());
        check("dormancy_heartbeat_metadata",
            dormancy_heartbeat_metadata().into_keys());

        // ─── Cross-zone (accounting/cross_zone.rs, Gap 2 producer side) ──────
        use crate::accounting::cross_zone::*;
        check("cross_zone::lock_metadata",
            lock_metadata(
                "s", "r", 1,
                &crate::ZoneId::from_legacy(0),
                &crate::ZoneId::from_legacy(1),
            ).into_keys());
        check("cross_zone::claim_metadata",
            claim_metadata(
                "tid", "r", 1,
                &[ProofSibling { hash: [0u8; 32], is_right: false }],
            ).into_keys());

        // ─── Network layer ───────────────────────────────────────────────
        use crate::network::zone_subscription::subscription_metadata;
        let zones = vec![crate::ZoneId::from_legacy(0)];
        check("subscription_metadata",
            subscription_metadata("id", &zones, 1, 2).into_keys());

        // ─── Anchor-proof records (anchor_proof.rs, P1.5(b)) ─────────────
        // Emitted by the sidecar via `elara-cli anchor-submit` after the
        // daily OTS upgrade confirms a Bitcoin attestation.
        check("anchor_proof_metadata",
            crate::anchor_proof::anchor_proof_metadata(
                crate::anchor_proof::ANCHOR_KIND_ELARA_SEAL,
                "aa11bb22cc33dd44ee55ff660011223344556677889900aabbccddeeff001122",
                "0", 1, b"{}", &[1u8, 2, 3],
            ).expect("valid stub args").into_keys());

        // ─── ledger-layer + storage/delegation builder coverage ───────────
        // Promotes builders previously parked in INTENTIONAL_GAPS to live
        // coverage. Each was source-audited: every key the builder writes
        // is already present in ALLOWED_KEYS, so graduation is risk-free
        // and pins the contract from drifting.
        check("batch_metadata",
            crate::accounting::batch::batch_metadata(
                3600, &[0u8; 32], 0.0, 3600.0, 7,
            ).into_keys());
        check("storage_market::confirm_metadata",
            crate::accounting::storage_market::confirm_metadata("dlg_id").into_keys());
        check("storage_market::terminate_metadata",
            crate::accounting::storage_market::terminate_metadata("dlg_id").into_keys());
        {
            use crate::accounting::delegation::{
                delegation_metadata, extend_metadata, DelegationOp, DelegationScope,
            };
            check("delegation_metadata",
                delegation_metadata(
                    &DelegationOp::Authorize,
                    "child_pk_hex",
                    &DelegationScope::Full,
                ).expect("Authorize is always valid").into_keys());
            check("extend_metadata",
                extend_metadata("child_pk_hex", 1_700_000_000.0).into_keys());
        }
        check("witness_profile_metadata",
            crate::network::consensus::witness_profile_metadata(
                &crate::network::consensus::WitnessProfile {
                    organization: "navigatorbuilds".into(),
                    subnet: "192.168.1".into(),
                    geo_zone: "earth-eu".into(),
                },
            ).into_keys());

        // ─── succession / versioning / collaboration builder coverage ────
        // Promotes 5 more builders from INTENTIONAL_GAPS to live coverage.
        // Each source-audited: all keys already in ALLOWED_KEYS (verified
        // via constants SUCCESSION_OP_KEY, VERSION_OP_KEY + sibling version
        // keys, DIFF_OP_KEY + sibling diff keys, SUNSET_OP_KEY + sibling
        // sunset keys, COLLABORATION_OP_KEY + work_hash/participants/chain).
        // Graduation pins the contract against the silent-drift regression
        // class at PR time rather than at runtime.
        check("succession::heartbeat_metadata",
            crate::succession::heartbeat_metadata().into_keys());
        check("version_metadata",
            crate::versioning::version_metadata(
                Some("prev_hash_hex"), 7, Some("test bump"),
            ).into_keys());
        check("diff_metadata",
            crate::versioning::diff_metadata("from_hash", "to_hash").into_keys());
        check("collaboration_metadata",
            crate::collaboration::collaboration_metadata(
                "work_hash_hex",
                "[\"alice\",\"bob\"]",
                &["sig_a".into(), "sig_b".into()],
            ).into_keys());
        check("sunset_metadata",
            crate::network::sunset::sunset_metadata(
                "dilithium3",
                &crate::network::sunset::AlgorithmStatus::Deprecated,
                10_000,
                "PQC migration: §13.4 sunset window",
            ).into_keys());

        // ─── key-rotation / succession / publish builder coverage ────────
        // Promotes 6 more builders from INTENTIONAL_GAPS to live coverage.
        // Source-audited keys + 4 new ALLOWED_KEYS this same commit:
        //  - sphincs_key_rotation / new_sphincs_public_key (key_rotation.rs)
        //  - heirs / heartbeat_timeout_secs (succession.rs)
        // Closes the silent-drift regression class for
        // the entire key-rotation + succession + cross-network publish
        // surface in one swing.
        check("rotation_metadata",
            crate::network::key_rotation::rotation_metadata(
                &[0u8; 32], "test rotation",
            ).into_keys());
        check("sphincs_rotation_metadata",
            crate::network::key_rotation::sphincs_rotation_metadata(
                &[0u8; 64], "PQC rotation",
            ).into_keys());
        check("revocation_metadata",
            crate::network::key_rotation::revocation_metadata(
                &[0u8; 32], "key compromise",
            ).into_keys());
        check("succession_plan_metadata",
            crate::succession::succession_plan_metadata(
                &["heir1".into(), "heir2".into()],
                86_400.0, 604_800.0, Some("recovery_hash_hex"),
            ).into_keys());
        check("succession_claim_metadata",
            crate::succession::succession_claim_metadata(
                "claimant",
                &crate::succession::SuccessionPath::DesignatedHeir,
            ).into_keys());
        check("publish_metadata",
            crate::network::publish::publish_metadata(
                "pub_id", "src_net",
                &["rec_a".into(), "rec_b".into()],
                crate::network::publish::PublicationScope::Full,
                crate::ZoneId::from_legacy(0),
                100,
                crate::network::publish::RedactionPolicy::None,
                crate::network::publish::TransitionMode::Snapshot,
            ).into_keys());

        // ─── remaining ledger-layer builder coverage ──────────────────────
        // Promotes 8 more builders from INTENTIONAL_GAPS to live coverage,
        // sweeping the remaining ledger-layer builders in one
        // batch. Source-audited: all keys already in ALLOWED_KEYS. (The
        // coin-era exchange/HTLC keys were removed with the DEX surface —
        // no live builder writes them.)
        check("slash_metadata",
            crate::accounting::types::slash_metadata(
                100, "offender_id", "challenger_id",
                &["juror1".into(), "juror2".into()],
                "stake_rec_id", "test slash",
            ).into_keys());
        check("predict_metadata",
            crate::accounting::types::predict_metadata(
                10, "zone:0", 42,
                &crate::accounting::types::PredictionClaim::Active,
                1,
            ).into_keys());
        check("dormancy_reclaim_metadata",
            crate::accounting::types::dormancy_reclaim_metadata(
                50, "dormant_id", 1_700_000_000.0,
            ).into_keys());
        check("dormancy_declare_metadata",
            crate::accounting::types::dormancy_declare_metadata(
                "target_id", 1_700_000_000.0,
            ).into_keys());
        check("dormancy_proof_of_life_metadata",
            crate::accounting::types::dormancy_proof_of_life_metadata(
                "target_id", "sig_hex",
            ).into_keys());

        // ─── epoch-layer seal builder coverage ───────────────────────────
        // Graduates the three internal epoch-layer builders (seal,
        // global_seal, super_seal) from INTENTIONAL_GAPS → live check()
        // coverage. Each was previously deferred to "covered by epoch.rs
        // integration tests" — but that's a soft claim. Nothing pins these
        // builders' keys against ALLOWED_KEYS at PR time: drift between a new
        // `epoch_*` / `super_seal_*` / `global_seal_*` key landing in
        // `seal_metadata` / `global_seal_metadata` / `super_seal_metadata`
        // and a corresponding entry in `ALLOWED_KEYS` would silently
        // reject every seal at insert time (same regression class,
        // exactly the bug 349535a fixed for super_seal_committee_hash).
        // Source-audited: every key these three builders write is already
        // in ALLOWED_KEYS (epoch.rs ↔ ALLOWED_KEYS). Graduation is risk-free
        // and pins the contract. seal_metadata is exercised with a POPULATED
        // drand pulse (REALMS P1.5) so this guard catches drand_* allowlist
        // drift before slice a3's producer ever emits those keys.
        let seal_drand_pulse = crate::network::time_bracket::DrandPulse {
            round: 1,
            randomness: "deadbeef".into(),
            genesis_unix: 1_595_431_050,
            period_secs: 30,
            chain_hash: None,
            // Populated at G2-signature length so this guard also catches
            // drand_signature/drand_previous_signature allowlist drift.
            signature: Some("ab".repeat(96)),
            previous_signature: Some("cd".repeat(96)),
        };
        check("seal_metadata", crate::network::epoch::seal_metadata(
            crate::network::epoch::SealMetadataParams {
                zone: crate::ZoneId::from_legacy(0),
                epoch_number: 1,
                start: 0.0,
                end: 60.0,
                record_count: 1,
                merkle_root: &[0u8; 32],
                previous_seal_hash: &[0u8; 32],
                vrf_output: None,
                vrf_proof: None,
                sparse_merkle_root: None,
                record_hashes: None,
                zone_balance_total: None,
                zone_registry_root: None,
                zone_registry_delta: None,
                aggregator_rank: 0,
                account_smt_root: None,
                drand_pulse: Some(&seal_drand_pulse),
            }).into_keys());
        check("global_seal_metadata", crate::network::epoch::global_seal_metadata(
            &crate::ZoneId::from_legacy(0),
            &crate::ZoneId::from_legacy(1),
            42,
            &[0u8; 32],
            5_000,
            6_000,
            1_700_000_000.0,
            &[0u8; 32],
            &[0u8; 64],
        ).into_keys());
        check("super_seal_metadata", crate::network::epoch::super_seal_metadata(
            crate::ZoneId::from_legacy(0),
            0,
            crate::network::epoch::SUPER_SEAL_INTERVAL - 1,
            crate::network::epoch::SUPER_SEAL_INTERVAL,
            &[0u8; 32],
            &[0u8; 32],
            &[0xau8; 32],  // non-zero so committee_hash key is emitted
        ).into_keys());

    }

    /// Programmatic CI-time
    /// check that every `pub fn *_metadata(...) -> BTreeMap<...>` builder
    /// in `src/` is either enumerated in
    /// `test_all_record_builders_pass_allowlist` or listed in
    /// `INTENTIONAL_GAPS` below with a one-line rationale.
    ///
    /// Why this exists: a hand-curated enumeration once missed
    /// `xzone_abort_metadata` because the builder lived in
    /// `accounting/types.rs` instead of the expected `accounting/cross_zone.rs`
    /// (commit `16f6392`). Earlier the same regression class
    /// produced silent allowlist drift in the Gap-3 super-seal
    /// (`349535a`) and Gap-5 zone_subscription_* (`a6dc743`) builders. Each
    /// drift surfaced only at runtime, often weeks after the builder
    /// shipped, because nothing closed the loop between "new builder added
    /// to `src/`" and "meta-test enumeration extended".
    ///
    /// Action when this test fails: either
    ///  1. **Production-active builder** → add a `check("name",
    ///     name(stub_args).into_keys())` line to
    ///     `test_all_record_builders_pass_allowlist` (in the same commit
    ///     that introduces the builder), OR
    ///  2. **Intentional gap** (governance path, internal-only builder,
    ///     deferred coverage) → add the builder name to
    ///     `INTENTIONAL_GAPS` with a one-line rationale.
    ///
    /// Either path is minimal-friction; both close the regression class
    /// by forcing the discipline at PR time rather than at runtime.
    ///
    /// Limitations: bare-name matching means two builders sharing a name
    /// across modules (e.g. `vote_metadata` exists in both
    /// `network/fisherman.rs` and `accounting/governance.rs`) are deduplicated
    /// to one entry — both are covered if either is covered. This is
    /// acceptable because the validator they're checked against
    /// (`validate_metadata_keys`) is itself name-keyed, not module-keyed.
    #[test]
    fn test_meta_test_covers_all_builders_in_src() {
        /// Builders that exist in `src/` but are deliberately deferred
        /// from `test_all_record_builders_pass_allowlist`. Each entry is
        /// (name, rationale). Graduating a builder to full coverage = add
        /// a `check(...)` line to the meta-test + delete its entry here.
        const INTENTIONAL_GAPS: &[(&str, &str)] = &[
            // Ledger-layer builders (slash, predict, dormancy_reclaim/
            //   declare/proof_of_life) are covered above.
            // Governance: dedicated validator surface (accounting/governance.rs),
            // not validate_metadata_keys.
            ("propose_metadata", "governance — dedicated validator"),
            ("vote_metadata", "governance + fisherman — dedicated validators (name shared)"),
            ("execute_metadata", "governance — dedicated validator"),
            ("execute_protocol_upgrade_metadata", "governance §11.18 Slice 2 — dedicated validator (super-set of execute_metadata)"),
            ("cancel_metadata", "governance — dedicated validator"),
            ("delegate_metadata", "governance — dedicated validator"),
            ("undelegate_metadata", "governance — dedicated validator"),
            ("challenge_metadata", "governance — dedicated validator"),
            ("anchor_veto_metadata", "governance — dedicated validator"),
            ("inject_committee_metadata", "governance — dedicated validator"),
            // Key-rotation / VRF / sunset builders.
            // rotation_metadata is covered above.
            // sphincs_rotation_metadata is covered above
            //   (added sphincs_key_rotation + new_sphincs_public_key keys).
            // revocation_metadata is covered above.
            ("vrf_registration_metadata", "test_vrf_registration_metadata_passes_allowlist pins the live keys"),
            // sunset_metadata is covered above.
            // seal_metadata / global_seal_metadata / super_seal_metadata
            // are all covered above — see check(...) lines.
            ("zone_transition_metadata", "tick-30 Gap-4: zone auto-scaling transition"),
            // Other module builders (succession/versioning/collaboration/
            // dispute/fisherman/publish): covered above or
            // dedicated validators.
            // succession_plan_metadata is covered above
            //   (added heirs + heartbeat_timeout_secs keys).
            // succession_claim_metadata is covered above.
            // succession::heartbeat_metadata is covered above in
            // test_all_record_builders_pass_allowlist.
            // version_metadata is covered above.
            // diff_metadata is covered above.
            // collaboration_metadata is covered above.
            ("open_dispute_metadata", "governance dispute — dedicated validator"),
            ("evidence_metadata", "governance dispute — dedicated validator"),
            ("resolve_metadata", "governance dispute — dedicated validator"),
            ("file_challenge_metadata", "fisherman — dedicated validator"),
            ("appeal_metadata", "fisherman — dedicated validator"),
            // publish_metadata is covered above.
            // Other builders surfaced by the framework test are swept
            // into coverage as bandwidth allows.
            // Covered above: batch_metadata, confirm_metadata,
            // terminate_metadata, delegation_metadata, extend_metadata,
            // witness_profile_metadata — see `check(...)` lines in
            // test_all_record_builders_pass_allowlist.
            ("declare_metadata", "tick-30+: dormancy declare (accounting/dormancy.rs duplicate of dormancy_declare_metadata)"),
            ("proof_of_life_metadata", "tick-30+: dormancy proof-of-life (accounting/dormancy.rs)"),
        ];

        /// Functions matching `pub fn *_metadata(` whose return type is
        /// NOT a record-attached metadata `BTreeMap`. Bare-name filter
        /// avoids the need for a multi-line signature parse.
        const NOT_BUILDERS: &[&str] = &[
            // The validator itself.
            "validate_metadata_keys",
            // Extractors, not builders.
            "extract_committee_from_metadata",
            // Wire serialization (operates on the BTreeMap, doesn't build one).
            "encode_metadata_binary",
            "decode_metadata_binary",
            // ZK / commitment proof functions over metadata properties.
            "prove_metadata_property",
            "verify_metadata_property",
            "verify_metadata_property_full",
            // PoWaS proof ↔ metadata-pair conversions.
            "proof_to_metadata",
            "proof_from_metadata",
            // REALMS P1.5(a) time_bracket.rs DrandPulse helpers — name-match
            // the `*_metadata` scan but neither returns a record metadata
            // BTreeMap: write_metadata writes drand_* keys INTO a caller's
            // map (serializer, returns ()); from_metadata PARSES a pulse out
            // of a map (extractor, returns Option<DrandPulse>). Runtime-inert
            // this slice. WHEN slice (a2) wires drand_* keys onto seal
            // records, allowlist those KEYS in validate_metadata_keys + add
            // test_drand_pulse_metadata_passes_allowlist (the keys, not these
            // two fns, are what flows to the validator).
            "write_metadata",
            "from_metadata",
            // P1.5(b) anchor_proof.rs — PARSES an anchor-proof record's map
            // into AnchorProofFields (extractor, returns Result<struct>).
            // The paired BUILDER anchor_proof_metadata IS covered above.
            "parse_anchor_proof_metadata",
            // Snapshot data accessors (return Option<struct>, not BTreeMap).
            "snapshot_metadata",
            "get_snapshot_metadata",
            "pq_snapshot_metadata",
            "serve_snapshot_metadata",
            // Auxiliary builders returning Vec<(String,String)>, not BTreeMap.
            "configure_metadata",
            "recover_metadata",
            "idle_decay_metadata",
            // Python FFI shims (lib.rs) — wrap underlying ledger-layer builders;
            // the underlying builders themselves are what flows to validate_metadata_keys.
            "py_mint_metadata",
            "py_transfer_metadata",
            "py_stake_metadata",
            "py_unstake_metadata",
            "py_burn_metadata",
            "py_witness_reward_metadata",
            "py_slash_metadata",
            "py_dormancy_reclaim_metadata",
        ];

        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let src_root = manifest_dir.join("src");

        // 1. Walk src/ collecting .rs files.
        fn walk(p: &std::path::Path, sink: &mut Vec<std::path::PathBuf>) {
            let entries = match std::fs::read_dir(p) {
                Ok(e) => e,
                Err(_) => return,
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, sink);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    sink.push(path);
                }
            }
        }
        let mut all_files: Vec<std::path::PathBuf> = Vec::new();
        walk(&src_root, &mut all_files);
        assert!(
            !all_files.is_empty(),
            "src/ walk found no .rs files — CARGO_MANIFEST_DIR={}",
            manifest_dir.display()
        );

        // 2. Extract every `pub fn <name>_metadata(` (sync, non-test, not
        //    in NOT_BUILDERS) — bare-name match, dedup across modules.
        let mut found: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        for file in &all_files {
            let content = match std::fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for line in content.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("pub async fn ") {
                    continue;
                }
                if !trimmed.starts_with("pub fn ") {
                    continue;
                }
                let after = &trimmed["pub fn ".len()..];
                let end = match after.find(|c: char| !c.is_alphanumeric() && c != '_') {
                    Some(i) => i,
                    None => continue,
                };
                let name = &after[..end];
                if !name.ends_with("_metadata") {
                    continue;
                }
                if name.starts_with("test_") {
                    continue;
                }
                if NOT_BUILDERS.contains(&name) {
                    continue;
                }
                found.insert(name.to_string());
            }
        }
        assert!(
            !found.is_empty(),
            "no pub fn *_metadata builders found in src/ — walk or filter regressed"
        );

        // 3. Extract `check("…")` labels from the meta-test body to
        //    determine the covered set. Strip `module::` prefix.
        let self_path = manifest_dir.join("src/content_safety.rs");
        let self_src = std::fs::read_to_string(&self_path)
            .expect("read src/content_safety.rs");
        let body_start = self_src
            .find("fn test_all_record_builders_pass_allowlist")
            .expect("test_all_record_builders_pass_allowlist must exist");
        let body_end_rel = self_src[body_start..]
            .find("\n    }\n")
            .expect("meta-test fn must close with `\\n    }\\n`");
        let body = &self_src[body_start..body_start + body_end_rel];

        let mut covered: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let needle = "check(\"";
        let mut cursor = 0usize;
        while let Some(rel) = body[cursor..].find(needle) {
            let after = &body[cursor + rel + needle.len()..];
            cursor = cursor + rel + needle.len();
            if let Some(end) = after.find('"') {
                let label = &after[..end];
                let bare = label.rsplit("::").next().unwrap_or(label);
                covered.insert(bare.to_string());
                cursor += end;
            } else {
                break;
            }
        }
        assert!(
            !covered.is_empty(),
            "no `check(\"…\")` labels extracted from meta-test — parser regressed"
        );

        // 4. Verify INTENTIONAL_GAPS entries don't drift: every name in
        //    INTENTIONAL_GAPS must still exist as a builder in src/. If a
        //    builder is removed, its gap entry must be removed too.
        let gap_names: std::collections::HashSet<&str> =
            INTENTIONAL_GAPS.iter().map(|(n, _)| *n).collect();
        let stale_gaps: Vec<&str> = gap_names
            .iter()
            .filter(|n| !found.contains(**n))
            .copied()
            .collect();
        assert!(
            stale_gaps.is_empty(),
            "INTENTIONAL_GAPS contains names not found in src/ — these builders \
             were renamed/removed without updating the gap list:\n  - {}",
            stale_gaps.join("\n  - ")
        );

        // 5. Verify gap entries aren't ALSO in covered set (redundant).
        let redundant_gaps: Vec<&str> = gap_names
            .iter()
            .filter(|n| covered.contains(**n))
            .copied()
            .collect();
        assert!(
            redundant_gaps.is_empty(),
            "INTENTIONAL_GAPS contains names that are also covered by the \
             meta-test — graduate them by removing from gap list:\n  - {}",
            redundant_gaps.join("\n  - ")
        );

        // 6. Core assertion: every found builder is either covered or in
        //    INTENTIONAL_GAPS. New builders that match neither cause this
        //    test to fail with an actionable message.
        let missing: Vec<&String> = found
            .iter()
            .filter(|n| !covered.contains(n.as_str()))
            .filter(|n| !gap_names.contains(n.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "Meta-test framework drift detected — these `pub fn *_metadata` \
             builders exist in src/ but are NOT enumerated in \
             test_all_record_builders_pass_allowlist NOR listed in \
             INTENTIONAL_GAPS:\n\n  - {}\n\n\
             Action: pick one of two paths in the SAME commit that \
             introduced the new builder:\n\
             (a) If production-active: add `check(\"name\", \
             name(stub_args).into_keys())` to \
             test_all_record_builders_pass_allowlist.\n\
             (b) If intentionally deferred: add (\"name\", \"rationale\") \
             to INTENTIONAL_GAPS.\n\n\
             This framework test was landed at tick-29 (2026-05-13) to \
             close the OPS-190/192/193 regression class: silent allowlist \
             drift between new builders and the meta-test enumeration.",
            missing.iter().map(|s| s.as_str())
                .collect::<Vec<_>>().join("\n  - ")
        );
    }

    #[test]
    fn test_vrf_registration_metadata_passes_allowlist() {
        // Regression: the live VRF registration metadata (§11.12) must pass
        // validate_metadata_keys. Before this test, `node_type` was missing
        // from the allowlist and every anchor's VRF registration record was
        // rejected at submit time — silently crippling committee selection
        // across the fleet (no peer anchor could ever cross-register).
        let m = meta(&[
            ("vrf_registration", "true"),
            ("vrf_public_key", "30c66ec290866e7d2b2678293d138a47"),
            ("vrf_full_public_key", "deadbeef"),
            ("node_type", "anchor"),
        ]);
        validate_metadata_keys(&m).expect("VRF registration metadata must pass the allowlist");
        sanitize_text_fields(&m).expect("VRF registration fields must pass text-limit check");
    }

    #[test]
    fn test_blocked_keys_rejected() {
        for key in &["derivative_op", "wrap_op", "collateral_op", "tokenize_op", "synthetic_op", "lend_op"] {
            let m = meta(&[(key, "create")]);
            let err = validate_metadata_keys(&m).unwrap_err();
            assert!(
                err.to_string().contains("blocked metadata key"),
                "expected blocked error for {key}"
            );
        }
    }

    #[test]
    fn test_text_field_exceeds_limit() {
        // beat_memo max = 256 bytes
        let long_memo = "x".repeat(300);
        let mut m = BTreeMap::new();
        m.insert("beat_memo".into(), serde_json::json!(long_memo));
        let err = sanitize_text_fields(&m).unwrap_err();
        assert!(err.to_string().contains("exceeds max length"));
        assert!(err.to_string().contains("beat_memo"));

        // Within limit is OK (use realistic text with spaces to avoid encoded-data check)
        let ok_memo = "This is a normal transaction memo. ".repeat(8);
        let ok_memo = &ok_memo[..256];
        let mut m2 = BTreeMap::new();
        m2.insert("beat_memo".into(), serde_json::json!(ok_memo));
        assert!(sanitize_text_fields(&m2).is_ok());
    }

    #[test]
    fn test_agent_audit_keys_allowed() {
        // Wedge demo: kind="agent_audit" + full field set must pass allowlist
        // and text sanitization (no URLs, under per-field byte limits).
        let m = meta(&[
            ("kind", "agent_audit"),
            ("tool", "Bash"),
            ("action", "post"),
            ("args_hash", "6f06dd0e26608013eff30bb1e951cda7de3fdd9e78e907470e0dd5c0ed25e273"),
            ("agent_id", "claude-opus-4-7"),
            ("session_id", "2faa3180-ad38-4b9c-9e5f-53e8cab960a3"),
        ]);
        assert!(validate_metadata_keys(&m).is_ok());
        assert!(sanitize_text_fields(&m).is_ok());
    }

    #[test]
    fn test_agent_audit_args_hash_limit() {
        // args_hash 128-byte limit — SHA3-512 hex (128 chars) fits, larger rejected.
        let long_hash = "a".repeat(200);
        let mut m = BTreeMap::new();
        m.insert("args_hash".into(), serde_json::json!(long_hash));
        let err = sanitize_text_fields(&m).unwrap_err();
        assert!(err.to_string().contains("exceeds max length"));
        assert!(err.to_string().contains("args_hash"));
    }

    #[test]
    fn test_url_rejection_http() {
        let m = meta(&[("beat_memo", "check http://evil.com/bad")]);
        let err = sanitize_text_fields(&m).unwrap_err();
        assert!(err.to_string().contains("URLs not allowed"));
    }

    #[test]
    fn test_url_rejection_https() {
        let m = meta(&[("beat_reason", "see https://example.com/content")]);
        let err = sanitize_text_fields(&m).unwrap_err();
        assert!(err.to_string().contains("URLs not allowed"));
    }

    #[test]
    fn test_url_rejection_data_uri() {
        let m = meta(&[("governance_description", "data:image/png;base64,iVBOR")]);
        let err = sanitize_text_fields(&m).unwrap_err();
        assert!(err.to_string().contains("URLs not allowed"));
    }

    #[test]
    fn test_url_rejection_ftp_javascript_magnet() {
        for (field, url) in [
            ("dispute_reason", "ftp://files.example.com/illegal"),
            ("change_summary", "javascript:alert(1)"),
            ("sunset_reason", "magnet:?xt=urn:btih:abc123"),
        ] {
            let m = meta(&[(field, url)]);
            let err = sanitize_text_fields(&m).unwrap_err();
            assert!(
                err.to_string().contains("URLs not allowed"),
                "expected URL rejection for {field}"
            );
        }
    }

    #[test]
    fn test_tombstone_valid() {
        let m = meta(&[
            ("tombstone_op", "remove"),
            ("tombstone_target", "record-123"),
            ("tombstone_reason", "illegal content"),
        ]);
        let result = extract_tombstone_target(&m, "genesis_hash", "genesis_hash").unwrap();
        assert_eq!(result, Some("record-123".into()));

        // Not a tombstone → None
        let m2 = meta(&[("beat_op", "transfer")]);
        assert_eq!(extract_tombstone_target(&m2, "x", "y").unwrap(), None);
    }

    #[test]
    fn test_tombstone_non_genesis_rejected() {
        let m = meta(&[
            ("tombstone_op", "remove"),
            ("tombstone_target", "record-123"),
            ("tombstone_reason", "reason"),
        ]);
        let err = extract_tombstone_target(&m, "random_user", "genesis_hash").unwrap_err();
        assert!(err.to_string().contains("only genesis authority"));
    }

    #[test]
    fn test_banned_identity_rejected() {
        let mut banned = std::collections::HashSet::new();
        banned.insert("abc123".to_string());

        assert!(check_banned_identity("abc123", &banned).is_err());
        assert!(check_banned_identity("xyz456", &banned).is_ok());
        assert!(check_banned_identity("abc123", &std::collections::HashSet::new()).is_ok());
    }

    #[test]
    fn test_content_blocklist_blocks_matching() {
        let blocklist = vec!["illegal".to_string(), "contraband".to_string()];

        // Match in memo
        let m = meta(&[("beat_memo", "this is illegal stuff")]);
        let err = scan_blocked_content(&m, &blocklist).unwrap_err();
        assert!(err.to_string().contains("blocked content"));
        assert!(err.to_string().contains("beat_memo"));

        // Case-insensitive
        let m2 = meta(&[("beat_memo", "ILLEGAL TRADE")]);
        assert!(scan_blocked_content(&m2, &blocklist).is_err());

        // No match passes
        let m3 = meta(&[("beat_memo", "normal transaction")]);
        assert!(scan_blocked_content(&m3, &blocklist).is_ok());

        // Empty blocklist passes everything
        let m4 = meta(&[("beat_memo", "illegal")]);
        assert!(scan_blocked_content(&m4, &[]).is_ok());
    }

    #[test]
    fn test_content_blocklist_all_fields() {
        let blocklist = vec!["forbidden".to_string()];

        // governance_description
        let m = meta(&[("governance_description", "this is forbidden content")]);
        assert!(scan_blocked_content(&m, &blocklist).is_err());

        // dispute_reason
        let m2 = meta(&[("dispute_reason", "forbidden activity")]);
        assert!(scan_blocked_content(&m2, &blocklist).is_err());

        // Non-text fields don't trigger
        let m3 = meta(&[("beat_op", "transfer")]);
        assert!(scan_blocked_content(&m3, &blocklist).is_ok());
    }

    #[test]
    fn test_content_blocklist_array_field() {
        let blocklist = vec!["exploit".to_string()];

        let mut m = BTreeMap::new();
        m.insert(
            "challenge_evidence".into(),
            serde_json::json!(["clean evidence", "this has exploit details"]),
        );
        let err = scan_blocked_content(&m, &blocklist).unwrap_err();
        assert!(err.to_string().contains("blocked content"));
        assert!(err.to_string().contains("challenge_evidence[1]"));
    }

    #[test]
    fn test_unchecked_field_url_rejection() {
        // Fields like beat_purpose, reason, scope were previously unscanned
        let m = meta(&[("beat_purpose", "see https://evil.com/stuff")]);
        assert!(sanitize_text_fields(&m).is_err());

        let m2 = meta(&[("reason", "check http://drugs.onion/shop")]);
        assert!(sanitize_text_fields(&m2).is_err());

        let m3 = meta(&[("scope", "ipfs://QmHash123")]);
        assert!(sanitize_text_fields(&m3).is_err());
    }

    #[test]
    fn test_unchecked_field_size_limit() {
        // Fields without a TEXT_LIMITS entry get DEFAULT_TEXT_MAX_BYTES (256)
        let long = "x".repeat(300);
        let m = meta(&[("beat_purpose", &long)]);
        assert!(sanitize_text_fields(&m).is_err());

        // 256 bytes should pass (realistic text)
        let ok = "Normal purpose text with spaces. ".repeat(8);
        let ok = &ok[..256];
        let m2 = meta(&[("beat_purpose", ok)]);
        assert!(sanitize_text_fields(&m2).is_ok());
    }

    #[test]
    fn test_blocklist_scans_all_fields() {
        let blocklist = vec!["contraband".to_string()];

        // Previously unscanned fields should now be caught
        let m = meta(&[("beat_purpose", "selling contraband here")]);
        assert!(scan_blocked_content(&m, &blocklist).is_err());

        let m2 = meta(&[("reason", "contraband delivery")]);
        assert!(scan_blocked_content(&m2, &blocklist).is_err());

        let m3 = meta(&[("scope", "normal scope")]);
        assert!(scan_blocked_content(&m3, &blocklist).is_ok());
    }

    #[test]
    fn test_url_rejection_new_schemes() {
        for (field, url) in [
            ("beat_memo", "ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYg"),
            ("beat_memo", "ar://bNbA3TEQVL60xlgCcqdz4ZPHFZ6ZA1"),
            ("beat_memo", "dweb:QmHash"),
            ("beat_memo", "hyper://abc123"),
            ("beat_memo", "ssb:@abc123"),
            ("beat_memo", "blob:http://example"),
            ("beat_memo", "file:///etc/passwd"),
        ] {
            let m = meta(&[(field, url)]);
            let err = sanitize_text_fields(&m).unwrap_err();
            assert!(
                err.to_string().contains("URLs not allowed"),
                "expected URL rejection for '{url}'"
            );
        }
    }

    #[test]
    fn test_url_rejection_plain_domains() {
        let m = meta(&[("beat_memo", "go to evil.com/illegal-stuff")]);
        let err = sanitize_text_fields(&m).unwrap_err();
        assert!(err.to_string().contains("URLs not allowed"));

        let m2 = meta(&[("beat_memo", "visit drugs.onion:8080")]);
        let err2 = sanitize_text_fields(&m2).unwrap_err();
        assert!(err2.to_string().contains("URLs not allowed"));
    }

    #[test]
    fn test_url_rejection_ip_address() {
        let m = meta(&[("beat_memo", "connect to 192.168.1.1:8080/files")]);
        let err = sanitize_text_fields(&m).unwrap_err();
        assert!(err.to_string().contains("URLs not allowed"));

        // But normal numeric text should pass
        let m2 = meta(&[("beat_memo", "sent 1000 beats on 2026-03-13")]);
        assert!(sanitize_text_fields(&m2).is_ok());
    }

    #[test]
    fn test_array_field_sanitization() {
        let long_entry = "y".repeat(600);
        let mut m = BTreeMap::new();
        m.insert(
            "challenge_evidence".into(),
            serde_json::json!([long_entry, "short ok"]),
        );
        let err = sanitize_text_fields(&m).unwrap_err();
        assert!(err.to_string().contains("challenge_evidence[0]"));
        assert!(err.to_string().contains("exceeds max length"));

        // URL in array entry
        let mut m2 = BTreeMap::new();
        m2.insert(
            "challenge_evidence".into(),
            serde_json::json!(["valid evidence", "check https://evil.com"]),
        );
        let err2 = sanitize_text_fields(&m2).unwrap_err();
        assert!(err2.to_string().contains("URLs not allowed"));
        assert!(err2.to_string().contains("challenge_evidence[1]"));
    }

    #[test]
    fn test_default_blocklist_not_empty() {
        let bl = default_blocklist();
        assert!(bl.len() >= 10, "default blocklist should have at least 10 terms");
        // All terms should be lowercase (for case-insensitive matching)
        for term in &bl {
            assert_eq!(term, &term.to_lowercase(), "blocklist term should be lowercase: {term}");
        }
    }

    #[test]
    fn test_default_blocklist_blocks_content() {
        let bl = default_blocklist();
        // CSAM term should be caught
        let m = meta(&[("beat_memo", "this is csam content")]);
        assert!(scan_blocked_content(&m, &bl).is_err());

        // Clean content passes
        let m2 = meta(&[("beat_memo", "normal transaction")]);
        assert!(scan_blocked_content(&m2, &bl).is_ok());
    }

    // ─── precedence / boundary / blocklist pins (fixture-free) ────────────────

    /// Pins BLOCKED_KEYS precedence: any of the 6 anti-rehypothecation keys
    /// must emit "blocked metadata key:" with the offending key included,
    /// and must NOT fall through to the "unknown metadata key:" path
    /// (even though blocked keys are also absent from ALLOWED_KEYS).
    #[test]
    fn batch_b_blocked_keys_emit_blocked_error_message_not_unknown() {
        for k in &[
            "derivative_op",
            "wrap_op",
            "collateral_op",
            "tokenize_op",
            "synthetic_op",
            "lend_op",
        ] {
            let m = meta(&[(*k, "any_value")]);
            let err = validate_metadata_keys(&m).unwrap_err();
            let s = err.to_string();
            assert!(
                s.contains("blocked metadata key"),
                "{k} should give 'blocked' error, got: {s}"
            );
            assert!(s.contains(k), "{k} must appear in error, got: {s}");
            assert!(
                !s.contains("unknown metadata key"),
                "blocked key {k} must NOT fall through to 'unknown' path, got: {s}"
            );
        }

        // Counter-case (inverted 2026-07-02 forward-compat): a key that's
        // neither blocked nor allowed is now ADMITTED — blocked keys are the
        // only name-based rejection left.
        let m_unknown = meta(&[("never_allowed_xyz_12345", "x")]);
        validate_metadata_keys(&m_unknown)
            .expect("non-blocked unknown key must be admitted (forward-compat)");
    }

    /// Pins DEFAULT_TEXT_MAX_BYTES (256) for allowed keys that lack a
    /// TEXT_LIMITS entry. `beat_purpose` is in ALLOWED_KEYS but absent from
    /// TEXT_LIMITS, so it must reject exactly at 257 bytes and accept at 256.
    /// Pre-default-cap this field was completely unchecked — closing it is
    /// the structural defense behind the 2KB per-value record cap.
    #[test]
    fn batch_b_default_text_limit_256_byte_boundary_on_unlisted_allowed_key() {
        let ok_256 = "a".repeat(256);
        let m_ok = meta(&[("beat_purpose", ok_256.as_str())]);
        sanitize_text_fields(&m_ok)
            .expect("256-byte beat_purpose at exact DEFAULT boundary must pass");

        let too_long = "a".repeat(257);
        let m_err = meta(&[("beat_purpose", too_long.as_str())]);
        let err = sanitize_text_fields(&m_err).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("beat_purpose"), "error must name field, got: {s}");
        assert!(s.contains("257"), "error must include actual length, got: {s}");
        assert!(s.contains("256"), "error must include max length, got: {s}");

        // beat_purpose is NOT in TEXT_LIMITS so encoded-data check is skipped
        // (is_text_field=false). Verify the all-alnum 256-byte payload above
        // didn't trip looks_like_encoded_data — the OK assert proves it.
    }

    /// Pins all four `extract_tombstone_target` paths: Ok(None) on missing
    /// tombstone_op, three distinct error messages for bad-op / non-genesis /
    /// missing-target, and Ok(Some) on the valid path.
    #[test]
    fn batch_b_extract_tombstone_target_four_paths_none_invalid_op_non_genesis_missing_target() {
        let genesis = "GENESIS_AUTHORITY_HASH";
        let other = "OTHER_IDENTITY_HASH";

        // (a) no tombstone_op → Ok(None) even from non-genesis
        let m_none = meta(&[("beat_op", "transfer")]);
        assert_eq!(
            extract_tombstone_target(&m_none, other, genesis).unwrap(),
            None
        );

        // (b) tombstone_op != "remove" → error with offending op + 'expected'
        let m_bad_op = meta(&[
            ("tombstone_op", "delete"),
            ("tombstone_target", "rec_id"),
        ]);
        let err = extract_tombstone_target(&m_bad_op, genesis, genesis).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("invalid tombstone_op"), "bad-op msg: {s}");
        assert!(s.contains("delete"), "bad-op must include offending op: {s}");
        assert!(s.contains("expected 'remove'"));

        // (c) valid op but non-genesis creator → authority error
        let m_non_genesis = meta(&[
            ("tombstone_op", "remove"),
            ("tombstone_target", "rec_id"),
        ]);
        let err = extract_tombstone_target(&m_non_genesis, other, genesis).unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("only genesis authority"),
            "non-genesis msg: {s}"
        );

        // (d) valid op + genesis creator + missing target → required-field error
        let m_no_target = meta(&[("tombstone_op", "remove")]);
        let err = extract_tombstone_target(&m_no_target, genesis, genesis).unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("tombstone_target required"),
            "missing-target msg: {s}"
        );

        // (e) all conditions met → Ok(Some(target))
        let m_ok = meta(&[
            ("tombstone_op", "remove"),
            ("tombstone_target", "rec_abc"),
        ]);
        assert_eq!(
            extract_tombstone_target(&m_ok, genesis, genesis).unwrap(),
            Some("rec_abc".to_string())
        );
    }

    /// Pins `check_banned_identity` error-message truncation: long identity
    /// (>16 chars) gets truncated to first 16, short identity (<16) appears
    /// in full without panicking on the `.min(16)` slice. Also covers the
    /// empty-set + not-in-set Ok paths.
    #[test]
    fn batch_b_check_banned_identity_error_message_truncates_long_hash_to_16_chars() {
        use std::collections::HashSet;

        // Long identity (32 'a' chars) → first 16 in error, no panic
        let long = "a".repeat(32);
        let mut set: HashSet<String> = HashSet::new();
        set.insert(long.clone());
        let err = check_banned_identity(&long, &set).unwrap_err();
        let s = err.to_string();
        let head = &long[..16];
        assert!(
            s.contains(head),
            "long identity error should contain first 16 chars '{head}', got: {s}"
        );
        assert!(s.contains(" is banned"), "error suffix missing: {s}");

        // Short identity (8 chars < 16) → full identity, no slice panic
        let short = "abc12345";
        let mut set_short: HashSet<String> = HashSet::new();
        set_short.insert(short.to_string());
        let err = check_banned_identity(short, &set_short).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("abc12345"), "short identity must appear in full: {s}");
        assert!(s.contains(" is banned"));

        // Empty banned set → Ok for any identity
        let empty: HashSet<String> = HashSet::new();
        check_banned_identity("any_hash", &empty)
            .expect("empty banned set must allow all identities");

        // Identity not in non-empty set → Ok
        let mut set_other: HashSet<String> = HashSet::new();
        set_other.insert("SOMEONE_ELSE".to_string());
        check_banned_identity("MINE", &set_other)
            .expect("identity absent from banned set must pass");
    }

    #[allow(clippy::doc_lazy_continuation)]
    /// Pins `default_blocklist()` contents: exact count (15 = 7 CSAM + 4 WMD
    /// + 4 terrorism), one term from each category present, no duplicates,
    /// no whitespace edges, no empty terms. Count-drift catches accidental
    /// additions/removals that would change cluster-wide ingest behavior.
    #[test]
    fn batch_b_default_blocklist_exact_count_and_three_category_representatives() {
        let bl = default_blocklist();

        assert_eq!(
            bl.len(),
            15,
            "default_blocklist count drift: got {} terms, expected 15 (7 CSAM + 4 WMD + 4 terrorism)",
            bl.len()
        );

        // One representative from each of the three categories
        assert!(
            bl.iter().any(|t| t == "csam"),
            "CSAM category representative 'csam' missing"
        );
        assert!(
            bl.iter().any(|t| t == "build a nuclear weapon"),
            "WMD category representative 'build a nuclear weapon' missing"
        );
        assert!(
            bl.iter().any(|t| t == "join our jihad"),
            "terrorism category representative 'join our jihad' missing"
        );

        // No duplicates — set insertion must always succeed
        let mut seen = std::collections::HashSet::new();
        for term in &bl {
            assert!(
                seen.insert(term.clone()),
                "duplicate blocklist term: '{term}'"
            );
        }

        // No leading/trailing whitespace, no empty terms
        for term in &bl {
            assert!(!term.is_empty(), "blocklist term must be non-empty");
            assert_eq!(
                term.trim(),
                term.as_str(),
                "blocklist term has whitespace edges: '{term}'"
            );
        }
    }
}
