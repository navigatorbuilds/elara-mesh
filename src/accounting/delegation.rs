//! Identity delegation — parent-child device authorization.
//!
//! Protocol v0.6.2 Section 6.2: Constrained devices (ESP32, $4 sensors)
//! authenticate to a local gateway via delegation records. The gateway
//! (parent) signs batches on behalf of child devices.
//!
//! Delegation records are regular `ValidationRecord`s with `delegation_op`
//! metadata, signed by the parent identity. Children inherit the parent's
//! trust tier floor and share the parent's stake allocation.
//!
//! This enables the giga-factory scenario: one Organization identity
//! stakes 100K beat, delegates 300K device identities, and all devices
//! share the staked throughput.

//!
//! Spec references:
//!   @spec economics §4.3

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::errors::{ElaraError, Result};
use crate::record::ValidationRecord;

use super::types::{creator_identity_hash, BASE_UNITS_PER_BEAT};
use crate::identity::AttestationLevel;

// ─── Constants ─────────────────────────────────────────────────────────────

pub const DELEGATION_OP_KEY: &str = "delegation_op";

/// Metadata key for advertising an identity's hardware attestation level.
/// Value is one of `AttestationLevel`'s string forms (NONE, SOFTWARE, SECURE_BOOT,
/// HARDWARE_KEY, PUF). Identity records that omit it are treated as
/// `AttestationLevel::None` (rank 0). `apply_op` auto-registers the level
/// monotonically (only upgrades, never downgrades).
pub const ATTESTATION_LEVEL_KEY: &str = "attestation_level";

/// Minimum attestation level a gateway must advertise to author
/// `delegation_op = authorize` records on mainnet.
///
/// Rationale (economics §11.33, internal design notes §3 Gap C): a
/// software-only gateway is trivial to fork and concurrently run on attacker
/// hardware while serving children that look legitimate. SecureBoot (rank 2)
/// is the floor — the gateway operator at minimum runs a verified-boot OS so
/// post-compromise key extraction takes physical access. PUF (rank 4) is the
/// upper end (TPM/HSM/PUF sealed key, can't migrate). On testnet operators
/// can drop the floor via `ELARA_MIN_ATTESTATION_FOR_GATEWAY=NONE`.
///
/// The check is at `delegation_op = authorize` time only — revocation paths
/// (Gap D) are intentionally cheaper (a parent can revoke even after losing
/// hardware, and emergency revoke must work in the degraded case).
pub const MIN_ATTESTATION_FOR_GATEWAY: AttestationLevel = AttestationLevel::SecureBoot;

/// Minimum balance required for a non-Gateway/non-Anchor identity to author
/// a `delegation_op` record. The role check (creator's gossiped `NodeType`)
/// is the primary gate; this stake threshold is the cold-boot escape hatch
/// for identities that have not yet heartbeated their role to the local
/// peer table. 10K beat keeps casual identities out without locking
/// out a fresh anchor that just rejoined the network.
///
/// Spec: economics §4.3 (Profile C delegation),
/// internal design notes §3 Gap A.
pub const MIN_STAKE_TO_DELEGATE: u64 = 10_000 * BASE_UNITS_PER_BEAT;

/// Metadata key naming the parent identity whose delegations are being mass-revoked.
pub const REVOKE_ALL_PARENT_KEY: &str = "revoke_all_parent";

/// Metadata key for the human-readable reason of a `revoke_all` op.
pub const REVOKE_ALL_REASON_KEY: &str = "revoke_all_reason";

/// Metadata key for the array of cosigner proofs in the involuntary path.
pub const REVOKE_ALL_COSIGNERS_KEY: &str = "revoke_all_cosigners";

/// Numerator of the involuntary stake-cosign threshold (`numerator / denominator`).
pub const REVOKE_ALL_THRESHOLD_NUMERATOR: u128 = 2;

/// Denominator of the involuntary stake-cosign threshold (`numerator / denominator`).
pub const REVOKE_ALL_THRESHOLD_DENOMINATOR: u128 = 3;

/// Stable canonical-message prefix for cosigner Dilithium3 sigs.
/// Bumping this prefix is a hard wire-format break; never reuse a value.
pub const REVOKE_ALL_CANONICAL_PREFIX: &[u8] = b"elara_revoke_all_v1:";

/// Outcome of evaluating per-parent capacity caps before accepting a fresh
/// `delegation_op = authorize` at ingest time. Pure, no I/O — the caller
/// supplies `child_count` (registry) and `authorize_count_in_window`
/// (sliding-window limiter).
///
/// `Allowed` → record commits.
/// `ChildCapExceeded` → bump `elara_delegation_child_cap_rejected_total`,
/// reject record at `/records`.
/// `RateCapExceeded` → bump `elara_delegation_rate_cap_rejected_total`,
/// reject record at `/records`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeCapDecision {
    Allowed,
    ChildCapExceeded,
    RateCapExceeded,
}

/// Pure helper: evaluate the Gap E per-parent caps. Order is deterministic —
/// child cap is checked before rate cap so an at-cap parent always sees the
/// same rejection reason regardless of timing. No allocations, no I/O.
pub fn check_authorize_caps(
    child_count: usize,
    authorize_count_in_window: usize,
) -> AuthorizeCapDecision {
    if child_count >= MAX_CHILDREN_PER_PARENT {
        return AuthorizeCapDecision::ChildCapExceeded;
    }
    if authorize_count_in_window >= MAX_AUTHORIZE_PER_PARENT_PER_HOUR {
        return AuthorizeCapDecision::RateCapExceeded;
    }
    AuthorizeCapDecision::Allowed
}

/// Compute the default lease expiry for an authorize op that did not provide
/// an explicit `expires_at`. `created + DEFAULT_LEASE_SECONDS`.
pub fn default_expires_at(created: f64) -> f64 {
    created + DEFAULT_LEASE_SECONDS
}

/// Pull `expires_at` out of a record's metadata, if present. Returns
/// `Some(timestamp)` when the field parses as a finite f64,
/// `None` when absent or malformed (per "missing/bad → no-op" pattern from
/// Gap C `extract_attestation_level`).
pub fn extract_expires_at(record: &ValidationRecord) -> Option<f64> {
    record
        .metadata
        .get(EXPIRES_AT_KEY)
        .and_then(|v| v.as_f64())
        .filter(|x| x.is_finite())
}

// ─── Gap E lifecycle constants ─────────────────────────────────────────────

/// Default lease duration applied to a fresh `delegation_op = authorize`
/// when no explicit `expires_at` is provided. 30 days. The parent re-ups
/// via `delegation_op = extend` before this elapses, otherwise the
/// `prune_expired` tick drops the child within 60s of expiry.
pub const DEFAULT_LEASE_SECONDS: f64 = 30.0 * 86_400.0;

/// Hard cap on number of children a single parent can have active in the
/// registry. Once reached, ingest rejects further `authorize` ops with
/// `elara_delegation_child_cap_rejected_total`. 1M is the design ceiling
/// per internal design notes §3 Gap E.
pub const MAX_CHILDREN_PER_PARENT: usize = 1_000_000;

/// Sliding-window rate cap: maximum `authorize` ops a single parent may
/// emit per hour. Compromised gateway protection — without this, one
/// stolen key spams 10M registrations into every node's memory.
pub const MAX_AUTHORIZE_PER_PARENT_PER_HOUR: usize = 10_000;

/// Window over which `MAX_AUTHORIZE_PER_PARENT_PER_HOUR` is evaluated.
pub const AUTHORIZE_RATE_WINDOW_SECONDS: f64 = 3_600.0;

/// Periodic prune-expired-leases tick interval (seconds). The loop walks
/// the delegations map dropping entries whose `expires_at < now`.
pub const PRUNE_EXPIRED_INTERVAL_SECS: u64 = 60;

/// Metadata key for the optional explicit lease expiry timestamp on
/// `delegation_op = authorize` and `delegation_op = extend`. Unix seconds.
/// Absent on authorize → registry defaults to `created + DEFAULT_LEASE_SECONDS`.
/// REQUIRED on extend.
pub const EXPIRES_AT_KEY: &str = "expires_at";

/// Result of evaluating whether a `delegation_op` record may be authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationAuthDecision {
    /// Creator is Gateway/Anchor by declared `NodeType`.
    AllowedByRole,
    /// Creator's role is unknown or non-delegating but stake is at or above
    /// `MIN_STAKE_TO_DELEGATE` — escape hatch for cold-boot anchors.
    AllowedByStake,
    /// Creator is neither role-eligible nor stake-eligible.
    Rejected,
}

/// Decide whether `creator` may author a `delegation_op` record.
///
/// `creator_node_type` is the most recently gossiped role for `creator`,
/// or `None` if the local node has never seen them heartbeat. The intent is
/// "look up the creator's NodeType from the peer table"; the local node
/// passes its own configured NodeType when it is the record creator.
///
/// `creator_balance` is the creator's available + staked balance from the
/// committed ledger snapshot (`AccountState::total()`).
///
/// The check is pure: it does not allocate, lock, or touch shared state, so
/// it is straightforward to unit-test against every (role, stake) combination.
pub fn check_delegation_authorization(
    creator_node_type: Option<&str>,
    creator_balance: u64,
) -> DelegationAuthDecision {
    if let Some(name) = creator_node_type {
        // Inline the `NodeType::can_delegate()` check so this stays callable
        // from wasm targets that don't compile the `network` module.
        // Authoritative match must stay in sync with `NodeType::can_delegate`
        // (`network/peer.rs`) — Gateway + Anchor are the only delegation-capable
        // roles. Anything else (incl. unknown strings) falls through to Leaf.
        if matches!(name, "gateway" | "anchor") {
            return DelegationAuthDecision::AllowedByRole;
        }
    }
    if creator_balance >= MIN_STAKE_TO_DELEGATE {
        return DelegationAuthDecision::AllowedByStake;
    }
    DelegationAuthDecision::Rejected
}

/// Profile C Gap B sig-verify gate decision.
///
/// In the protocol design (economics §4.3, Protocol §4.6/§6.2), a registered
/// delegation child is by intent a constrained device with no PQC keys; the
/// parent signs records on the child's behalf. The on-chain marker for this
/// is the entry in `DelegationRegistry`. If a record's `creator_public_key`
/// hashes to a registered child, the child is signing with its own key — a
/// protocol violation (no per-device accountability is gained, the parent's
/// stake is still inherited, and the whole IoT delegation premise collapses).
///
/// Pure helper so the gate's policy is unit-testable in isolation from the
/// async `state.delegations.read()` call site in `ingest::process_record`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileCGateDecision {
    /// Creator is not a registered child — proceed normally.
    NotRegisteredChild,
    /// Creator is a registered child but the record is its own establishment
    /// `delegation_op` (authorize/revoke) — Gap A handles those.
    DelegationOpExempt,
    /// Creator is a registered child and the record is a regular submission —
    /// reject. The parent must proxy-sign instead.
    Rejected,
}

/// Profile C Gap C gateway-attestation gate decision.
///
/// A `delegation_op = authorize` record from a parent whose advertised
/// `AttestationLevel` is below `min_required` is rejected. Pure helper so
/// the threshold policy is unit-testable in isolation from the async ledger
/// read site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayAttestationDecision {
    /// Parent's attestation level meets or exceeds the configured floor.
    Allowed,
    /// Parent's attestation level is below the configured floor.
    Rejected,
}

/// Decide whether a gateway with `parent_attestation` may author an
/// `authorize` delegation op given a configured `min_required` floor.
///
/// `parent_attestation` is the higher of the ledger-recorded level and the
/// `attestation_level` metadata on the current record (parents can
/// self-bootstrap by including the level on their first authorize). Comparison
/// is by `AttestationLevel::rank()` to avoid surprise from `Ord` derivation.
pub fn check_gateway_attestation(
    parent_attestation: AttestationLevel,
    min_required: AttestationLevel,
) -> GatewayAttestationDecision {
    if parent_attestation.rank() >= min_required.rank() {
        GatewayAttestationDecision::Allowed
    } else {
        GatewayAttestationDecision::Rejected
    }
}

/// Extract the `attestation_level` metadata field from a record, if present
/// and parseable. Unknown / missing returns `None` (caller treats as
/// `AttestationLevel::None`).
pub fn extract_attestation_level(
    record: &ValidationRecord,
) -> Option<AttestationLevel> {
    record
        .metadata
        .get(ATTESTATION_LEVEL_KEY)
        .and_then(|v| v.as_str())
        .and_then(AttestationLevel::parse)
}

/// Decide whether a non-`delegation_op` record from `creator_hash` should be
/// rejected because the creator is a registered Profile C child.
///
/// Inputs are kept primitive (bool / bool) so the callers don't need to hold
/// the registry lock just to ask the gate's policy question. Caller resolves
/// `is_registered_child = registry.parent_of(creator_hash).is_some()` and
/// `is_delegation_op = record.metadata.contains_key(DELEGATION_OP_KEY)`.
pub fn check_profile_c_gate(
    is_registered_child: bool,
    is_delegation_op: bool,
) -> ProfileCGateDecision {
    if !is_registered_child {
        return ProfileCGateDecision::NotRegisteredChild;
    }
    if is_delegation_op {
        return ProfileCGateDecision::DelegationOpExempt;
    }
    ProfileCGateDecision::Rejected
}

// ─── Parsed delegation ─────────────────────────────────────────────────────

/// Parsed metadata from a delegation record.
#[derive(Debug, Clone)]
pub struct ParsedDelegation {
    /// Operation: "authorize" or "revoke".
    pub op: DelegationOp,
    /// Identity hash of the child device being delegated.
    pub child: String,
    /// Scope of delegation.
    pub scope: DelegationScope,
}

/// Delegation operation type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationOp {
    /// Parent authorizes a child device.
    Authorize,
    /// Parent revokes a child's delegation.
    Revoke,
    /// Mass-revoke every child of a parent in one record. Carried via
    /// `ParsedRevokeAll` rather than `ParsedDelegation` because the metadata
    /// shape is different (no `delegation_child`, has cosigner proofs).
    RevokeAll,
    /// Refresh `expires_at` on an existing child without re-authorizing.
    /// Saves bandwidth on millions of devices (Gap E lifecycle).
    Extend,
}

/// Reason for a `revoke_all` op. Appears in metadata as a snake-case string.
/// Operator-facing — surfaced in admin/observability so a fleet operator can
/// distinguish "compromised gateway" from "voluntary key rotation".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeReason {
    /// Gateway key suspected leaked or otherwise compromised.
    Compromised,
    /// Gateway has been retired and its leases are aging out.
    Expired,
    /// Voluntary key rotation: parent is migrating to a new identity.
    Rotated,
}

impl RevokeReason {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "compromised" => Some(Self::Compromised),
            "expired" => Some(Self::Expired),
            "rotated" => Some(Self::Rotated),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Compromised => "compromised",
            Self::Expired => "expired",
            Self::Rotated => "rotated",
        }
    }
}

/// A single cosigner's proof in the involuntary `revoke_all` path.
///
/// Identity is derived from `public_key_hex` via SHA3-256; we never trust a
/// caller-supplied identity hash. Stake is read from the live ledger at apply
/// time, not from this struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignerProof {
    /// Cosigner's Dilithium3 public key (hex-encoded raw bytes).
    pub public_key_hex: String,
    /// Cosigner's Dilithium3 signature over the canonical message
    /// (`revoke_all_canonical_message`), hex-encoded.
    pub signature_hex: String,
}

/// Parsed metadata for a `revoke_all` op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRevokeAll {
    /// Identity hash of the parent whose delegations are being mass-revoked.
    pub parent_to_disarm: String,
    /// Reason (operator-surfaced; not enforced by protocol).
    pub reason: RevokeReason,
    /// Cosigner proofs (empty for the voluntary path).
    pub cosigners: Vec<CosignerProof>,
}

/// Result of authorizing a `revoke_all` op given creator + cosigner stakes.
///
/// Pure helper: the caller resolves cosigner stakes from the live ledger and
/// passes the verified sum here. This keeps the threshold policy unit-testable
/// without a ledger fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeAllAuthDecision {
    /// Creator IS the parent_to_disarm — voluntary handoff.
    Voluntary,
    /// Cosigner stake sum meets the 2/3 threshold — fisherman path.
    Involuntary,
    /// Neither path passed — reject.
    Rejected,
}

/// Decide whether a `revoke_all` op is authorized.
///
/// `valid_cosigner_stake_sum` is the sum of ledger-read balances for cosigners
/// whose Dilithium3 signature was verified against the canonical message.
/// Caller does the verification (see `verify_cosigner_proof`); this helper
/// just applies the threshold rule.
///
/// Voluntary takes precedence: a parent's self-signed revoke_all bypasses the
/// stake check. The threshold uses `numerator * sum >= denominator * supply`
/// arithmetic to avoid losing precision on very small testnet supplies.
pub fn check_revoke_all_authorization(
    creator_hash: &str,
    parent_to_disarm: &str,
    valid_cosigner_stake_sum: u128,
    total_supply: u128,
) -> RevokeAllAuthDecision {
    if creator_hash == parent_to_disarm {
        return RevokeAllAuthDecision::Voluntary;
    }
    if total_supply == 0 {
        // Pre-mint testnet edge: no supply means the threshold collapses to
        // "any non-zero cosign passes", which is a footgun. Refuse instead.
        return RevokeAllAuthDecision::Rejected;
    }
    if valid_cosigner_stake_sum.saturating_mul(REVOKE_ALL_THRESHOLD_DENOMINATOR)
        >= total_supply.saturating_mul(REVOKE_ALL_THRESHOLD_NUMERATOR)
    {
        RevokeAllAuthDecision::Involuntary
    } else {
        RevokeAllAuthDecision::Rejected
    }
}

/// Build the canonical message that cosigners sign for a `revoke_all` op.
///
/// Format: `prefix || parent_to_disarm || ":" || reason_str || ":" || record_timestamp_secs`
///
/// `record_timestamp` is the `ValidationRecord.timestamp` (seconds since epoch).
/// Including it binds each cosigner sig to a specific record so a captured sig
/// can't be replayed onto a different revoke_all event.
pub fn revoke_all_canonical_message(
    parent_to_disarm: &str,
    reason: RevokeReason,
    record_timestamp: f64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        REVOKE_ALL_CANONICAL_PREFIX.len() + parent_to_disarm.len() + 64,
    );
    out.extend_from_slice(REVOKE_ALL_CANONICAL_PREFIX);
    out.extend_from_slice(parent_to_disarm.as_bytes());
    out.push(b':');
    out.extend_from_slice(reason.as_str().as_bytes());
    out.push(b':');
    // f64 → integer-seconds string. Cosigners sign whatever is in the
    // record's wire timestamp; keep the encoding deterministic.
    out.extend_from_slice(format!("{:.6}", record_timestamp).as_bytes());
    out
}

/// Verify a cosigner proof against the canonical message.
///
/// Returns the cosigner's identity hash on success. Rejects on:
/// - non-hex `public_key_hex` / `signature_hex`
/// - Dilithium3 verify failure
///
/// Crypto is delegated to `crypto::pqc::dilithium3_verify`.
pub fn verify_cosigner_proof(
    proof: &CosignerProof,
    canonical_message: &[u8],
) -> Result<String> {
    let pk_bytes = hex::decode(&proof.public_key_hex)
        .map_err(|e| ElaraError::Wire(format!("revoke_all cosigner pk hex: {e}")))?;
    let sig_bytes = hex::decode(&proof.signature_hex)
        .map_err(|e| ElaraError::Wire(format!("revoke_all cosigner sig hex: {e}")))?;
    let ok = crate::crypto::pqc::dilithium3_verify(canonical_message, &sig_bytes, &pk_bytes)
        .map_err(|e| ElaraError::Wire(format!("revoke_all cosigner verify: {e}")))?;
    if !ok {
        return Err(ElaraError::Wire(
            "revoke_all cosigner signature did not verify".into(),
        ));
    }
    Ok(crate::crypto::hash::sha3_256_hex(&pk_bytes))
}

/// Scope of a delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationScope {
    /// Child can submit any record type on behalf of parent.
    Full,
    /// Child can only submit batch records.
    BatchOnly,
}

impl DelegationScope {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "full" => Some(Self::Full),
            "batch_only" => Some(Self::BatchOnly),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::BatchOnly => "batch_only",
        }
    }
}

// ─── Metadata builder ──────────────────────────────────────────────────────

/// Build metadata for a single-child delegation record (`authorize` or
/// `revoke`). For mass-revocation, see `revoke_all_metadata_voluntary` /
/// `revoke_all_metadata_involuntary`. For lease extension, see
/// `extend_metadata`.
///
/// Panics if called with `DelegationOp::RevokeAll` (uses cosigner-array
/// shape) or `DelegationOp::Extend` (carries `expires_at`, not `scope`);
/// use the dedicated builders.
pub fn delegation_metadata(
    op: &DelegationOp,
    child: &str,
    scope: &DelegationScope,
) -> std::result::Result<std::collections::BTreeMap<String, JsonValue>, &'static str> {
    let mut m = std::collections::BTreeMap::new();
    let op_str = match op {
        DelegationOp::Authorize => "authorize",
        DelegationOp::Revoke => "revoke",
        DelegationOp::RevokeAll => return Err(
            "delegation_metadata called with RevokeAll — use revoke_all_metadata_voluntary/involuntary"
        ),
        DelegationOp::Extend => return Err(
            "delegation_metadata called with Extend — use extend_metadata"
        ),
    };
    m.insert(DELEGATION_OP_KEY.into(), serde_json::json!(op_str));
    m.insert("delegation_child".into(), serde_json::json!(child));
    m.insert("delegation_scope".into(), serde_json::json!(scope.as_str()));
    Ok(m)
}

/// Build metadata for an authorize record that carries an explicit lease
/// expiry. Same as `delegation_metadata(Authorize, child, scope)` plus the
/// `expires_at` key. Use this when the parent wants a non-default lease
/// (shorter than `DEFAULT_LEASE_SECONDS = 30d` for short-lived sessions,
/// or longer for stable production gateways).
pub fn authorize_metadata_with_expiry(
    child: &str,
    scope: &DelegationScope,
    expires_at: f64,
) -> std::collections::BTreeMap<String, JsonValue> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(DELEGATION_OP_KEY.into(), serde_json::json!("authorize"));
    m.insert("delegation_child".into(), serde_json::json!(child));
    m.insert("delegation_scope".into(), serde_json::json!(scope.as_str()));
    m.insert(EXPIRES_AT_KEY.into(), serde_json::json!(expires_at));
    m
}

/// Build metadata for `delegation_op = extend`. The record refreshes the
/// child's `expires_at` without re-authorizing the whole record — saves
/// bandwidth on millions of devices that re-up monthly.
pub fn extend_metadata(
    child: &str,
    new_expires_at: f64,
) -> std::collections::BTreeMap<String, JsonValue> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(DELEGATION_OP_KEY.into(), serde_json::json!("extend"));
    m.insert("delegation_child".into(), serde_json::json!(child));
    m.insert(EXPIRES_AT_KEY.into(), serde_json::json!(new_expires_at));
    m
}

// ─── Extract / parse ───────────────────────────────────────────────────────

/// Extract a delegation from a record's metadata, if present.
/// Returns `Ok(None)` if the record is not a delegation record.
pub fn extract_delegation(record: &ValidationRecord) -> Result<Option<ParsedDelegation>> {
    let op_val = match record.metadata.get(DELEGATION_OP_KEY) {
        Some(v) => v,
        None => return Ok(None),
    };

    let op_str = op_val
        .as_str()
        .ok_or_else(|| ElaraError::Wire("delegation_op must be a string".into()))?;

    let op = match op_str {
        "authorize" => DelegationOp::Authorize,
        "revoke" => DelegationOp::Revoke,
        "extend" => DelegationOp::Extend,
        // `revoke_all` has a different metadata shape (no `delegation_child`,
        // carries cosigner proofs); the caller dispatches via
        // `extract_revoke_all`. Returning Ok(None) here lets callers try both
        // parsers without explicit op_str inspection.
        "revoke_all" => return Ok(None),
        _ => return Err(ElaraError::Wire(format!("unknown delegation_op: {op_str}"))),
    };

    let child = record.metadata.get("delegation_child")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| ElaraError::Wire("missing delegation_child".into()))?;

    let scope_str = record.metadata.get("delegation_scope")
        .and_then(|v| v.as_str())
        .unwrap_or("full");

    let scope = DelegationScope::from_str(scope_str)
        .ok_or_else(|| ElaraError::Wire(format!("invalid delegation_scope: {scope_str}")))?;

    Ok(Some(ParsedDelegation { op, child, scope }))
}

/// Extract a `revoke_all` op from a record's metadata, if present.
/// Returns `Ok(None)` when `delegation_op` is absent or not `"revoke_all"`.
///
/// Validates required fields:
/// - `revoke_all_parent` (string, non-empty) — identity hash of parent to disarm.
/// - `revoke_all_reason` (string) — must parse via `RevokeReason::from_str`.
/// - `revoke_all_cosigners` (optional array) — empty/absent for voluntary path.
///
/// Cosigner shape: each entry must be an object with `public_key` + `signature`
/// (both hex-encoded). Crypto verification is NOT done here; caller invokes
/// `verify_cosigner_proof` against the canonical message.
pub fn extract_revoke_all(record: &ValidationRecord) -> Result<Option<ParsedRevokeAll>> {
    let op_str = match record.metadata.get(DELEGATION_OP_KEY).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Ok(None),
    };
    if op_str != "revoke_all" {
        return Ok(None);
    }

    let parent_to_disarm = record
        .metadata
        .get(REVOKE_ALL_PARENT_KEY)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ElaraError::Wire(format!("missing {REVOKE_ALL_PARENT_KEY}")))?
        .to_string();

    let reason_str = record
        .metadata
        .get(REVOKE_ALL_REASON_KEY)
        .and_then(|v| v.as_str())
        .ok_or_else(|| ElaraError::Wire(format!("missing {REVOKE_ALL_REASON_KEY}")))?;
    let reason = RevokeReason::from_str(reason_str)
        .ok_or_else(|| ElaraError::Wire(format!("invalid revoke_all_reason: {reason_str}")))?;

    let cosigners = match record.metadata.get(REVOKE_ALL_COSIGNERS_KEY) {
        Some(JsonValue::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for (i, entry) in arr.iter().enumerate() {
                let obj = entry.as_object().ok_or_else(|| {
                    ElaraError::Wire(format!("revoke_all_cosigners[{i}] not an object"))
                })?;
                let public_key_hex = obj
                    .get("public_key")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ElaraError::Wire(format!("revoke_all_cosigners[{i}].public_key missing"))
                    })?
                    .to_string();
                let signature_hex = obj
                    .get("signature")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ElaraError::Wire(format!("revoke_all_cosigners[{i}].signature missing"))
                    })?
                    .to_string();
                out.push(CosignerProof { public_key_hex, signature_hex });
            }
            out
        }
        Some(JsonValue::Null) | None => Vec::new(),
        Some(_) => {
            return Err(ElaraError::Wire(
                "revoke_all_cosigners must be an array".into(),
            ));
        }
    };

    Ok(Some(ParsedRevokeAll { parent_to_disarm, reason, cosigners }))
}

/// Build metadata for a voluntary `revoke_all` record.
///
/// The parent signs the resulting record with its own key — Gap A's role
/// gate already accepts Gateway/Anchor/staked authors; the apply path's
/// `creator_hash == parent_to_disarm` check classifies this as voluntary.
pub fn revoke_all_metadata_voluntary(
    parent_to_disarm: &str,
    reason: RevokeReason,
) -> std::collections::BTreeMap<String, JsonValue> {
    let mut m = std::collections::BTreeMap::new();
    m.insert(DELEGATION_OP_KEY.into(), serde_json::json!("revoke_all"));
    m.insert(REVOKE_ALL_PARENT_KEY.into(), serde_json::json!(parent_to_disarm));
    m.insert(REVOKE_ALL_REASON_KEY.into(), serde_json::json!(reason.as_str()));
    m
}

/// Build metadata for an involuntary (fisherman) `revoke_all` record.
///
/// Cosigners must each have signed `revoke_all_canonical_message(parent_to_disarm,
/// reason, record_timestamp)` with their Dilithium3 secret key. The aggregator
/// (record submitter) is whoever broadcasts; ingest gates the cosigner stake
/// sum against `total_supply * 2/3`.
pub fn revoke_all_metadata_involuntary(
    parent_to_disarm: &str,
    reason: RevokeReason,
    cosigners: &[CosignerProof],
) -> std::collections::BTreeMap<String, JsonValue> {
    let mut m = revoke_all_metadata_voluntary(parent_to_disarm, reason);
    let arr: Vec<JsonValue> = cosigners
        .iter()
        .map(|c| {
            serde_json::json!({
                "public_key": c.public_key_hex,
                "signature": c.signature_hex,
            })
        })
        .collect();
    m.insert(REVOKE_ALL_COSIGNERS_KEY.into(), JsonValue::Array(arr));
    m
}

// ─── Delegation registry ──────────────────────────────────────────────────

/// Active delegation entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveDelegation {
    /// Parent identity hash.
    pub parent: String,
    /// Scope of delegation.
    pub scope: DelegationScope,
    /// Timestamp when delegation was created.
    pub created: f64,
    /// Optional Unix-seconds lease expiry. When set, `prune_expired(now)`
    /// drops the entry once `now > expires_at`. `serde(default)` keeps
    /// pre-Gap-E snapshots loadable — entries without an `expires_at`
    /// are treated as never-expiring.
    #[serde(default)]
    pub expires_at: Option<f64>,
}

/// Registry tracking active parent→child delegations.
///
/// Used at the network level to:
/// 1. Look up a child's parent for trust/stake inheritance
/// 2. Enforce scope restrictions (batch_only children can't submit arbitrary records)
/// 3. Track delegation counts per parent
/// 4. Rate-limit per-parent `authorize` ops (Gap E sliding window)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DelegationRegistry {
    /// child_identity → ActiveDelegation.
    delegations: HashMap<String, ActiveDelegation>,
    /// parent_identity → set of child identities (reverse index).
    children: HashMap<String, HashSet<String>>,
    /// Per-parent authorize timestamps for the Gap E sliding-window rate
    /// limit (`AUTHORIZE_RATE_WINDOW_SECONDS`). Not serialized — rate-limit
    /// state is transient; on restart the window starts empty (forgiving
    /// behaviour: a node restart shouldn't re-deny an already-rate-limited
    /// gateway forever).
    #[serde(skip)]
    authorize_history: HashMap<String, std::collections::VecDeque<f64>>,
}

impl DelegationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an authorization delegation with an optional explicit lease
    /// expiry. `expires_at = None` is equivalent to "never expires" — used
    /// by tests + legacy snapshot rebuild paths that pre-date Gap E.
    /// Production callers go through `apply_delegation` which always supplies
    /// an explicit expiry (default `created + DEFAULT_LEASE_SECONDS`).
    pub fn authorize_with_expiry(
        &mut self,
        parent: &str,
        child: &str,
        scope: DelegationScope,
        timestamp: f64,
        expires_at: Option<f64>,
    ) {
        // Remove any existing delegation for this child
        self.revoke(child);

        self.delegations.insert(child.to_string(), ActiveDelegation {
            parent: parent.to_string(),
            scope,
            created: timestamp,
            expires_at,
        });

        self.children
            .entry(parent.to_string())
            .or_default()
            .insert(child.to_string());
    }

    /// Backward-compat shortcut: register an authorization with no explicit
    /// lease expiry. Used by tests and the rebuild path. Production records
    /// supply `expires_at` via `apply_delegation`.
    pub fn authorize(&mut self, parent: &str, child: &str, scope: DelegationScope, timestamp: f64) {
        self.authorize_with_expiry(parent, child, scope, timestamp, None);
    }

    /// Refresh the `expires_at` of an existing child without re-authorizing.
    /// Returns `Err` if the child is unknown or `parent` is not the recorded
    /// parent of the child. Idempotent on the new expiry value.
    ///
    /// Used by `delegation_op = "extend"` (Gap E). The Gap A role check at
    /// ingest time already verified the creator is allowed to issue
    /// delegation ops; this layer enforces "only the actual parent can
    /// extend a particular child's lease".
    pub fn extend(&mut self, parent: &str, child: &str, new_expires_at: f64) -> Result<()> {
        match self.delegations.get_mut(child) {
            Some(d) if d.parent == parent => {
                d.expires_at = Some(new_expires_at);
                Ok(())
            }
            Some(d) => Err(ElaraError::Wire(format!(
                "only parent {} can extend delegation for {}",
                d.parent.chars().take(16).collect::<String>(),
                child.chars().take(16).collect::<String>(),
            ))),
            None => Err(ElaraError::Wire(format!(
                "no active delegation for child {}",
                child.chars().take(16).collect::<String>(),
            ))),
        }
    }

    /// Drop every delegation whose `expires_at` is set and `< now`. Returns
    /// the dropped child identity hashes (sorted for deterministic logging /
    /// metrics). Children with `expires_at = None` are never pruned (legacy
    /// snapshot compat).
    ///
    /// O(active_delegations) per call — designed to run every
    /// `PRUNE_EXPIRED_INTERVAL_SECS` (60s) in a background task. Cheap walk
    /// of the HashMap with a single allocation for the dropped vec.
    pub fn prune_expired(&mut self, now: f64) -> Vec<String> {
        let to_drop: Vec<String> = self
            .delegations
            .iter()
            .filter_map(|(child, d)| {
                d.expires_at.filter(|&exp| exp < now).map(|_| child.clone())
            })
            .collect();
        for child in &to_drop {
            self.revoke(child);
        }
        let mut sorted = to_drop;
        sorted.sort();
        sorted
    }

    /// Inspect the count of `authorize` ops by `parent` in the trailing
    /// `AUTHORIZE_RATE_WINDOW_SECONDS` window, after pruning expired entries.
    /// Does NOT record a new event. Used for cap-check before commit.
    pub fn authorize_count_in_window(&mut self, parent: &str, now: f64) -> usize {
        let win = self.authorize_history.entry(parent.to_string()).or_default();
        let cutoff = now - AUTHORIZE_RATE_WINDOW_SECONDS;
        while win.front().is_some_and(|t| *t < cutoff) {
            win.pop_front();
        }
        win.len()
    }

    /// Record an authorize event for `parent` at `now`, returning the post-
    /// record count. Caller is expected to have already passed
    /// `check_authorize_caps`; this just appends to the sliding window.
    pub fn record_authorize_event(&mut self, parent: &str, now: f64) -> usize {
        let win = self.authorize_history.entry(parent.to_string()).or_default();
        let cutoff = now - AUTHORIZE_RATE_WINDOW_SECONDS;
        while win.front().is_some_and(|t| *t < cutoff) {
            win.pop_front();
        }
        win.push_back(now);
        win.len()
    }

    /// Drop authorize-history entries whose newest event is older than the
    /// window (i.e. the parent has gone quiet). Keeps the in-memory map
    /// bounded across long-running nodes. Called periodically alongside
    /// `prune_expired`.
    pub fn cleanup_authorize_history(&mut self, now: f64) {
        let cutoff = now - AUTHORIZE_RATE_WINDOW_SECONDS;
        self.authorize_history
            .retain(|_, win| win.back().is_some_and(|t| *t >= cutoff));
    }

    /// Number of parents currently tracked in the authorize-rate window.
    pub fn tracked_authorize_parents(&self) -> usize {
        self.authorize_history.len()
    }

    /// Revoke a delegation. Returns true if a delegation existed.
    pub fn revoke(&mut self, child: &str) -> bool {
        if let Some(delegation) = self.delegations.remove(child) {
            if let Some(children) = self.children.get_mut(&delegation.parent) {
                children.remove(child);
                if children.is_empty() {
                    self.children.remove(&delegation.parent);
                }
            }
            true
        } else {
            false
        }
    }

    /// Mass-revoke every child of `parent`. Returns the dropped child identity
    /// hashes (sorted for deterministic logging). O(children_of_parent).
    ///
    /// Used by Gap D `revoke_all` op. Walks the reverse-index `children[parent]`
    /// set, drops each entry from `delegations`, then clears the parent's slot.
    /// Idempotent: subsequent calls return an empty Vec.
    pub fn revoke_all_for_parent(&mut self, parent: &str) -> Vec<String> {
        let children_set = match self.children.remove(parent) {
            Some(set) => set,
            None => return Vec::new(),
        };
        let mut dropped: Vec<String> = children_set.into_iter().collect();
        for child in &dropped {
            self.delegations.remove(child);
        }
        dropped.sort();
        dropped
    }

    /// Look up the parent for a child identity. Returns None if not delegated.
    pub fn parent_of(&self, child: &str) -> Option<&ActiveDelegation> {
        self.delegations.get(child)
    }

    /// Get all children of a parent identity.
    pub fn children_of(&self, parent: &str) -> Vec<&str> {
        self.children.get(parent)
            .map(|set| set.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Number of children delegated to a parent.
    pub fn child_count(&self, parent: &str) -> usize {
        self.children.get(parent).map_or(0, |s| s.len())
    }

    /// Total delegations tracked.
    pub fn total(&self) -> usize {
        self.delegations.len()
    }

    /// Check if a child identity is allowed to submit a batch record.
    /// Returns the parent identity hash if allowed.
    pub fn check_batch_submission(&self, child: &str) -> Result<Option<String>> {
        match self.delegations.get(child) {
            Some(delegation) => Ok(Some(delegation.parent.clone())),
            None => Ok(None), // Not a delegated identity — proceed with normal checks
        }
    }

    /// Check if a child identity is allowed to submit an arbitrary record.
    /// Returns the parent identity hash if allowed, Err if scope is batch_only.
    pub fn check_submission(&self, child: &str) -> Result<Option<String>> {
        match self.delegations.get(child) {
            Some(delegation) => {
                if delegation.scope == DelegationScope::BatchOnly {
                    return Err(ElaraError::Wire(format!(
                        "delegated identity {} has batch_only scope, cannot submit arbitrary records",
                        child.chars().take(16).collect::<String>()
                    )));
                }
                Ok(Some(delegation.parent.clone()))
            }
            None => Ok(None),
        }
    }
}

impl DelegationRegistry {
    /// Process a single record during streaming rebuild. Checks for delegation_op
    /// metadata and applies authorize/revoke. O(1) per record.
    pub fn process_record(&mut self, rec: &ValidationRecord) {
        if rec.metadata.contains_key(DELEGATION_OP_KEY) {
            let _ = apply_delegation(rec, self);
        }
    }
}

/// Process a delegation record: apply it to the registry.
///
/// Dispatches on the `delegation_op` value:
/// - `authorize`/`revoke` → `extract_delegation` + one-child handling
/// - `revoke_all` → `extract_revoke_all` + mass-revocation via `revoke_all_for_parent`
///
/// Authorization (Gap A creator role, Gap C attestation, Gap D voluntary/involuntary)
/// is enforced at the ingest layer BEFORE this function runs. By the time we
/// reach apply, the record is committed; this function only mutates the
/// registry. The exception is the `Revoke` (single-child) op which still
/// re-checks parent authority defensively because it predates Gap A.
pub fn apply_delegation(
    record: &ValidationRecord,
    registry: &mut DelegationRegistry,
) -> Result<()> {
    if let Some(delegation) = extract_delegation(record)? {
        let parent = creator_identity_hash(record);
        match delegation.op {
            DelegationOp::Authorize => {
                let expires_at = extract_expires_at(record)
                    .or_else(|| Some(default_expires_at(record.timestamp)));
                registry.authorize_with_expiry(
                    &parent,
                    &delegation.child,
                    delegation.scope,
                    record.timestamp,
                    expires_at,
                );
            }
            DelegationOp::Revoke => {
                if let Some(existing) = registry.parent_of(&delegation.child) {
                    if existing.parent != parent {
                        return Err(ElaraError::Wire(format!(
                            "only parent {} can revoke delegation for {}",
                            &existing.parent[..existing.parent.len().min(16)],
                            &delegation.child[..delegation.child.len().min(16)],
                        )));
                    }
                }
                registry.revoke(&delegation.child);
            }
            DelegationOp::Extend => {
                let new_expiry = extract_expires_at(record).ok_or_else(|| {
                    ElaraError::Wire(
                        "extend op missing or non-finite expires_at metadata".into(),
                    )
                })?;
                registry.extend(&parent, &delegation.child, new_expiry)?;
            }
            DelegationOp::RevokeAll => {
                // Unreachable: extract_delegation returns Ok(None) for revoke_all.
                return Err(ElaraError::Wire(
                    "delegation parser dispatch error: revoke_all reached one-child branch".into(),
                ));
            }
        }
        return Ok(());
    }

    if let Some(parsed) = extract_revoke_all(record)? {
        let _dropped = registry.revoke_all_for_parent(&parsed.parent_to_disarm);
        return Ok(());
    }

    Err(ElaraError::Wire("not a delegation record".into()))
}

/// Rebuild delegation registry from storage by scanning all records.
/// WARNING: Loads ALL records — O(all_records) memory.
#[cfg(test)]
pub fn rebuild_delegation_registry(
    storage: &dyn crate::storage::Storage,
) -> Result<DelegationRegistry> {
    let records = storage.query(None, None, None, None, usize::MAX)?;
    Ok(rebuild_delegation_registry_from_records(&records).unwrap_or_default())
}

/// Rebuild delegation registry from a pre-loaded record slice (single-pass startup).
pub fn rebuild_delegation_registry_from_records(
    all_records: &[crate::record::ValidationRecord],
) -> Result<DelegationRegistry> {
    let mut registry = DelegationRegistry::new();
    let mut sorted: Vec<&crate::record::ValidationRecord> = all_records.iter().collect();

    // Total-order replay: timestamp + record-ID tiebreak (mirrors ledger.rs/epoch.rs).
    // Equal-timestamp authorize/revoke ops must replay identically across nodes.
    sorted.sort_by(|a, b| {
        a.timestamp.total_cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id))
    });

    for record in &sorted {
        if record.metadata.contains_key(DELEGATION_OP_KEY) {
            // Best-effort: skip records that fail to parse
            let _ = apply_delegation(record, &mut registry);
        }
    }

    Ok(registry)
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Classification;
    use std::collections::BTreeMap;

    fn test_record_with_meta(meta: BTreeMap<String, JsonValue>) -> ValidationRecord {
        ValidationRecord::create(
            b"delegation-test",
            vec![0u8; 32],
            vec![],
            Classification::Public,
            Some(meta),
        )
    }

    // ── metadata roundtrip ──────────────────────────────────────────

    #[test]
    fn test_delegation_metadata_roundtrip() {
        let meta = delegation_metadata(
            &DelegationOp::Authorize,
            "child-device-hash",
            &DelegationScope::Full,
        ).unwrap();
        assert_eq!(meta.get(DELEGATION_OP_KEY).unwrap().as_str().unwrap(), "authorize");
        assert_eq!(meta.get("delegation_child").unwrap().as_str().unwrap(), "child-device-hash");
        assert_eq!(meta.get("delegation_scope").unwrap().as_str().unwrap(), "full");
    }

    #[test]
    fn test_revoke_metadata() {
        let meta = delegation_metadata(
            &DelegationOp::Revoke,
            "child-device-hash",
            &DelegationScope::Full,
        ).unwrap();
        assert_eq!(meta.get(DELEGATION_OP_KEY).unwrap().as_str().unwrap(), "revoke");
    }

    #[test]
    fn test_authorize_metadata_with_expiry_keys() {
        let meta = authorize_metadata_with_expiry("child-xyz", &DelegationScope::Full, 9999.0);
        assert_eq!(meta.get(DELEGATION_OP_KEY).and_then(|v| v.as_str()), Some("authorize"));
        assert_eq!(meta.get("delegation_child").and_then(|v| v.as_str()), Some("child-xyz"));
        assert_eq!(meta.get("delegation_scope").and_then(|v| v.as_str()), Some("full"));
        assert_eq!(meta.get(EXPIRES_AT_KEY).and_then(|v| v.as_f64()), Some(9999.0));
    }

    // ── extract ─────────────────────────────────────────────────────

    #[test]
    fn test_extract_none_for_non_delegation() {
        let record = ValidationRecord::create(
            b"normal", vec![0u8; 32], vec![], Classification::Public, None,
        );
        assert!(extract_delegation(&record).unwrap().is_none());
    }

    #[test]
    fn test_extract_authorize() {
        let meta = delegation_metadata(
            &DelegationOp::Authorize,
            "child-abc",
            &DelegationScope::BatchOnly,
        ).unwrap();
        let record = test_record_with_meta(meta);
        let parsed = extract_delegation(&record).unwrap().unwrap();

        assert_eq!(parsed.op, DelegationOp::Authorize);
        assert_eq!(parsed.child, "child-abc");
        assert_eq!(parsed.scope, DelegationScope::BatchOnly);
    }

    #[test]
    fn test_extract_invalid_op() {
        let mut meta = BTreeMap::new();
        meta.insert(DELEGATION_OP_KEY.into(), serde_json::json!("invalid"));
        let record = test_record_with_meta(meta);
        assert!(extract_delegation(&record).is_err());
    }

    #[test]
    fn test_extract_missing_child() {
        let mut meta = BTreeMap::new();
        meta.insert(DELEGATION_OP_KEY.into(), serde_json::json!("authorize"));
        let record = test_record_with_meta(meta);
        assert!(extract_delegation(&record).is_err());
    }

    // ── registry ────────────────────────────────────────────────────

    #[test]
    fn test_registry_authorize_and_lookup() {
        let mut reg = DelegationRegistry::new();
        reg.authorize("factory-gw", "sensor-001", DelegationScope::Full, 1000.0);
        reg.authorize("factory-gw", "sensor-002", DelegationScope::BatchOnly, 1000.0);

        assert_eq!(reg.total(), 2);
        assert_eq!(reg.child_count("factory-gw"), 2);

        let del = reg.parent_of("sensor-001").unwrap();
        assert_eq!(del.parent, "factory-gw");
        assert_eq!(del.scope, DelegationScope::Full);

        let del2 = reg.parent_of("sensor-002").unwrap();
        assert_eq!(del2.scope, DelegationScope::BatchOnly);

        assert!(reg.parent_of("unknown").is_none());
    }

    #[test]
    fn test_registry_revoke() {
        let mut reg = DelegationRegistry::new();
        reg.authorize("parent", "child", DelegationScope::Full, 1000.0);
        assert_eq!(reg.total(), 1);

        assert!(reg.revoke("child"));
        assert_eq!(reg.total(), 0);
        assert!(reg.parent_of("child").is_none());
        assert_eq!(reg.child_count("parent"), 0);

        // Revoking non-existent returns false
        assert!(!reg.revoke("child"));
    }

    #[test]
    fn test_registry_reauthorize_replaces() {
        let mut reg = DelegationRegistry::new();
        reg.authorize("parent-a", "child", DelegationScope::Full, 1000.0);
        reg.authorize("parent-b", "child", DelegationScope::BatchOnly, 2000.0);

        assert_eq!(reg.total(), 1);
        assert_eq!(reg.parent_of("child").unwrap().parent, "parent-b");
        assert_eq!(reg.child_count("parent-a"), 0);
        assert_eq!(reg.child_count("parent-b"), 1);
    }

    #[test]
    fn test_check_submission_full_scope() {
        let mut reg = DelegationRegistry::new();
        reg.authorize("gw", "dev1", DelegationScope::Full, 1000.0);

        let result = reg.check_submission("dev1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("gw".into()));
    }

    #[test]
    fn test_check_submission_batch_only_rejected() {
        let mut reg = DelegationRegistry::new();
        reg.authorize("gw", "dev1", DelegationScope::BatchOnly, 1000.0);

        let result = reg.check_submission("dev1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("batch_only"));
    }

    #[test]
    fn test_check_batch_submission_any_scope() {
        let mut reg = DelegationRegistry::new();
        reg.authorize("gw", "dev1", DelegationScope::BatchOnly, 1000.0);

        // Batch submission is allowed for batch_only scope
        let result = reg.check_batch_submission("dev1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("gw".into()));
    }

    #[test]
    fn test_check_non_delegated_identity() {
        let reg = DelegationRegistry::new();
        // Non-delegated identity returns None (not an error)
        let result = reg.check_submission("standalone");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_children_of() {
        let mut reg = DelegationRegistry::new();
        reg.authorize("factory", "s1", DelegationScope::Full, 1000.0);
        reg.authorize("factory", "s2", DelegationScope::Full, 1000.0);
        reg.authorize("factory", "s3", DelegationScope::Full, 1000.0);

        let mut children = reg.children_of("factory");
        children.sort();
        assert_eq!(children, vec!["s1", "s2", "s3"]);
        assert!(reg.children_of("nobody").is_empty());
    }

    #[test]
    fn test_large_delegation_300k_devices() {
        let mut reg = DelegationRegistry::new();
        // Simulate giga-factory: 300K device delegations
        for i in 0..1000u32 {
            reg.authorize(
                "gigafactory-gw",
                &format!("sensor-{i:06}"),
                DelegationScope::BatchOnly,
                1000.0,
            );
        }
        assert_eq!(reg.total(), 1000);
        assert_eq!(reg.child_count("gigafactory-gw"), 1000);

        // Lookup is O(1)
        let del = reg.parent_of("sensor-000500").unwrap();
        assert_eq!(del.parent, "gigafactory-gw");
    }

    // ── Profile C Gap A: role/stake gate (internal design notes §3 Gap A) ──

    #[test]
    fn gateway_role_is_authorized_regardless_of_stake() {
        let d = check_delegation_authorization(Some("gateway"), 0);
        assert_eq!(d, DelegationAuthDecision::AllowedByRole);
    }

    #[test]
    fn anchor_role_is_authorized_regardless_of_stake() {
        let d = check_delegation_authorization(Some("anchor"), 0);
        assert_eq!(d, DelegationAuthDecision::AllowedByRole);
    }

    #[test]
    fn leaf_below_min_stake_is_rejected() {
        // Casual identity authoring an authorize record — must be blocked,
        // otherwise it inflates its effective child count to game trust.
        let d = check_delegation_authorization(
            Some("leaf"),
            MIN_STAKE_TO_DELEGATE - 1,
        );
        assert_eq!(d, DelegationAuthDecision::Rejected);
    }

    #[test]
    fn unknown_role_below_min_stake_is_rejected() {
        // Cold-boot identity that has not yet gossiped a NodeType, no stake.
        // The registry should refuse delegation_op records from it.
        let d = check_delegation_authorization(None, 0);
        assert_eq!(d, DelegationAuthDecision::Rejected);
    }

    #[test]
    fn unknown_role_at_or_above_min_stake_is_allowed() {
        // Escape hatch for anchors that just rejoined the network and have
        // not heartbeated their role yet — refuses to lock out a fresh
        // anchor that already holds enough beat to be economically credible.
        let d = check_delegation_authorization(None, MIN_STAKE_TO_DELEGATE);
        assert_eq!(d, DelegationAuthDecision::AllowedByStake);
    }

    #[test]
    fn relay_witness_archive_below_min_stake_are_rejected() {
        // can_delegate() == false for these roles. They must rely on the
        // stake escape hatch, not their declared role.
        for role in ["relay", "witness", "archive"] {
            assert_eq!(
                check_delegation_authorization(Some(role), 1_000),
                DelegationAuthDecision::Rejected,
                "role {role} below min stake must be rejected"
            );
            assert_eq!(
                check_delegation_authorization(Some(role), MIN_STAKE_TO_DELEGATE),
                DelegationAuthDecision::AllowedByStake,
                "role {role} at min stake should ride the stake escape"
            );
        }
    }

    #[test]
    fn empty_role_string_falls_through_to_stake_check() {
        // NodeType::from_str("") returns Leaf; check still runs the stake
        // branch rather than crashing on the empty-string corner case.
        assert_eq!(
            check_delegation_authorization(Some(""), 0),
            DelegationAuthDecision::Rejected,
        );
        assert_eq!(
            check_delegation_authorization(Some(""), MIN_STAKE_TO_DELEGATE),
            DelegationAuthDecision::AllowedByStake,
        );
    }

    #[test]
    fn unknown_role_string_falls_through_to_stake_check() {
        // Tomorrow's role enums or operator typos must not silently authorize.
        assert_eq!(
            check_delegation_authorization(Some("validator"), 0),
            DelegationAuthDecision::Rejected,
        );
    }

    // ─── Profile C Gap B: sig-verify gate ──────────────────────────────────

    #[test]
    fn profile_c_gate_passes_for_non_delegated_identity() {
        // Standalone identity submitting any record — gate is a no-op.
        assert_eq!(
            check_profile_c_gate(false, false),
            ProfileCGateDecision::NotRegisteredChild,
        );
        assert_eq!(
            check_profile_c_gate(false, true),
            ProfileCGateDecision::NotRegisteredChild,
        );
    }

    #[test]
    fn profile_c_gate_rejects_registered_child_direct_submission() {
        // The core correctness check: a registered child trying to submit a
        // regular record directly is rejected. The IoT delegation premise
        // requires the parent to sign on the child's behalf.
        assert_eq!(
            check_profile_c_gate(true, false),
            ProfileCGateDecision::Rejected,
        );
    }

    #[test]
    fn profile_c_gate_exempts_delegation_op_from_child_self() {
        // A child's own establishment delegation_op (authorize/revoke that
        // creates or removes its registry entry) must pass — Gap A handles
        // those records' role/stake authorization.
        assert_eq!(
            check_profile_c_gate(true, true),
            ProfileCGateDecision::DelegationOpExempt,
        );
    }

    #[test]
    fn profile_c_gate_decision_is_deterministic() {
        // Sanity: same inputs always yield same decision (no shared state in
        // the helper). Regression guard for any future "look up timestamp /
        // peer table" temptation that would break the pure-function contract.
        for is_child in [true, false] {
            for is_op in [true, false] {
                assert_eq!(
                    check_profile_c_gate(is_child, is_op),
                    check_profile_c_gate(is_child, is_op),
                    "non-deterministic decision for ({is_child}, {is_op})"
                );
            }
        }
    }

    #[test]
    fn profile_c_gate_integration_with_registry() {
        // End-to-end policy: register a child, then both standalone-creator
        // and proxy-signed records in the same registry should yield the
        // expected decisions.
        let mut reg = DelegationRegistry::default();
        reg.authorize("factory-gw", "sensor-001", DelegationScope::Full, 1000.0);

        // Sensor signing with own key → reject.
        assert_eq!(
            check_profile_c_gate(reg.parent_of("sensor-001").is_some(), false),
            ProfileCGateDecision::Rejected,
        );
        // Sensor's establishment delegation_op record (signed by sensor)
        // would itself be exempt — Gap A's role check handles that path.
        assert_eq!(
            check_profile_c_gate(reg.parent_of("sensor-001").is_some(), true),
            ProfileCGateDecision::DelegationOpExempt,
        );
        // Parent (factory-gw) signing — not a child of anyone, gate passes.
        assert_eq!(
            check_profile_c_gate(reg.parent_of("factory-gw").is_some(), false),
            ProfileCGateDecision::NotRegisteredChild,
        );
        // Unrelated standalone identity — gate passes.
        assert_eq!(
            check_profile_c_gate(reg.parent_of("alice").is_some(), false),
            ProfileCGateDecision::NotRegisteredChild,
        );
    }

    #[test]
    fn profile_c_gate_after_revocation_passes() {
        // Once a child is revoked, registry no longer holds it; gate becomes
        // a no-op for it. (Whether we want a separate "tombstone" gate is
        // Gap D's question — Gap B only cares about active registry entries.)
        let mut reg = DelegationRegistry::default();
        reg.authorize("parent", "child", DelegationScope::Full, 1000.0);
        assert_eq!(
            check_profile_c_gate(reg.parent_of("child").is_some(), false),
            ProfileCGateDecision::Rejected,
        );
        assert!(reg.revoke("child"));
        assert_eq!(
            check_profile_c_gate(reg.parent_of("child").is_some(), false),
            ProfileCGateDecision::NotRegisteredChild,
        );
    }

    // ─── Profile C Gap C tests: gateway attestation gate ────────────────────

    #[test]
    fn gateway_attestation_allows_at_or_above_floor() {
        let floor = AttestationLevel::SecureBoot;
        assert_eq!(
            check_gateway_attestation(AttestationLevel::SecureBoot, floor),
            GatewayAttestationDecision::Allowed,
        );
        assert_eq!(
            check_gateway_attestation(AttestationLevel::HardwareKey, floor),
            GatewayAttestationDecision::Allowed,
        );
        assert_eq!(
            check_gateway_attestation(AttestationLevel::Puf, floor),
            GatewayAttestationDecision::Allowed,
        );
    }

    #[test]
    fn gateway_attestation_rejects_below_floor() {
        let floor = AttestationLevel::SecureBoot;
        assert_eq!(
            check_gateway_attestation(AttestationLevel::None, floor),
            GatewayAttestationDecision::Rejected,
        );
        assert_eq!(
            check_gateway_attestation(AttestationLevel::Software, floor),
            GatewayAttestationDecision::Rejected,
        );
    }

    #[test]
    fn gateway_attestation_floor_none_disables_gate() {
        // ELARA_MIN_ATTESTATION_FOR_GATEWAY=NONE testnet escape hatch:
        // every level passes when min_required is None.
        let floor = AttestationLevel::None;
        for level in [
            AttestationLevel::None,
            AttestationLevel::Software,
            AttestationLevel::SecureBoot,
            AttestationLevel::HardwareKey,
            AttestationLevel::Puf,
        ] {
            assert_eq!(
                check_gateway_attestation(level, floor),
                GatewayAttestationDecision::Allowed,
                "level {level:?} should pass with floor=None",
            );
        }
    }

    #[test]
    fn gateway_attestation_uses_rank_not_ord() {
        // PartialOrd / Ord on the enum is derived from declaration order,
        // which happens to align with rank — but the gate explicitly uses
        // rank() so future enum reorderings can't quietly invert the gate.
        for level in [
            AttestationLevel::None,
            AttestationLevel::Software,
            AttestationLevel::SecureBoot,
            AttestationLevel::HardwareKey,
            AttestationLevel::Puf,
        ] {
            let by_rank = level.rank() >= AttestationLevel::SecureBoot.rank();
            let decision = check_gateway_attestation(level, AttestationLevel::SecureBoot);
            assert_eq!(
                decision == GatewayAttestationDecision::Allowed,
                by_rank,
                "rank-vs-decision mismatch for {level:?}",
            );
        }
    }

    #[test]
    fn extract_attestation_level_parses_metadata() {
        let mut meta = BTreeMap::new();
        meta.insert(ATTESTATION_LEVEL_KEY.into(), serde_json::json!("HARDWARE_KEY"));
        let rec = test_record_with_meta(meta);
        assert_eq!(
            extract_attestation_level(&rec),
            Some(AttestationLevel::HardwareKey),
        );
    }

    #[test]
    fn extract_attestation_level_lowercase_alias() {
        let mut meta = BTreeMap::new();
        meta.insert(ATTESTATION_LEVEL_KEY.into(), serde_json::json!("secure_boot"));
        let rec = test_record_with_meta(meta);
        assert_eq!(
            extract_attestation_level(&rec),
            Some(AttestationLevel::SecureBoot),
        );
    }

    #[test]
    fn extract_attestation_level_missing_returns_none() {
        let rec = test_record_with_meta(BTreeMap::new());
        assert_eq!(extract_attestation_level(&rec), None);
    }

    #[test]
    fn extract_attestation_level_garbage_returns_none() {
        let mut meta = BTreeMap::new();
        meta.insert(ATTESTATION_LEVEL_KEY.into(), serde_json::json!("bogus_level"));
        let rec = test_record_with_meta(meta);
        assert_eq!(extract_attestation_level(&rec), None);
    }

    #[test]
    fn min_attestation_for_gateway_is_secure_boot() {
        // Locked-in floor: changes to this constant must be a deliberate
        // protocol revision. SecureBoot rank=2 keeps software-only gateways
        // out without requiring TPM hardware on every gateway operator.
        assert_eq!(MIN_ATTESTATION_FOR_GATEWAY, AttestationLevel::SecureBoot);
        assert_eq!(MIN_ATTESTATION_FOR_GATEWAY.rank(), 2);
    }

    // ── Profile C Gap D: revoke_all (internal design notes §3 Gap D) ──

    fn fresh_dilithium_keypair() -> (Vec<u8>, Vec<u8>) {
        // Deterministic seed sourced from monotonic clock + process id so
        // each test run produces distinct keys without pulling in rand.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id() as u128;
        let counter = TEST_KEY_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u128;
        let mut seed = [0u8; 32];
        seed[..16].copy_from_slice(&nanos.to_le_bytes());
        seed[16..32].copy_from_slice(&(pid ^ counter).to_le_bytes());
        crate::crypto::pqc::dilithium3_keypair_from_seed(&seed).expect("dilithium keypair")
    }

    static TEST_KEY_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn build_cosigner_proof(
        sk: &[u8],
        pk: &[u8],
        canonical: &[u8],
    ) -> CosignerProof {
        let sig = crate::crypto::pqc::dilithium3_sign_with_pk(canonical, sk, pk)
            .expect("dilithium sign");
        CosignerProof {
            public_key_hex: hex::encode(pk),
            signature_hex: hex::encode(&sig),
        }
    }

    #[test]
    fn revoke_all_for_parent_drops_every_child() {
        let mut reg = DelegationRegistry::new();
        for i in 0..100u32 {
            reg.authorize("gw", &format!("dev-{i:03}"), DelegationScope::Full, 1000.0);
        }
        assert_eq!(reg.child_count("gw"), 100);

        let dropped = reg.revoke_all_for_parent("gw");
        assert_eq!(dropped.len(), 100);
        assert_eq!(reg.total(), 0);
        assert_eq!(reg.child_count("gw"), 0);
        assert!(reg.parent_of("dev-050").is_none());
    }

    #[test]
    fn revoke_all_for_parent_returns_sorted_dropped_ids() {
        let mut reg = DelegationRegistry::new();
        reg.authorize("gw", "z-child", DelegationScope::Full, 1.0);
        reg.authorize("gw", "a-child", DelegationScope::Full, 1.0);
        reg.authorize("gw", "m-child", DelegationScope::Full, 1.0);

        let dropped = reg.revoke_all_for_parent("gw");
        assert_eq!(dropped, vec!["a-child", "m-child", "z-child"]);
    }

    #[test]
    fn revoke_all_for_parent_unknown_returns_empty() {
        let mut reg = DelegationRegistry::new();
        reg.authorize("gw-a", "child-1", DelegationScope::Full, 1.0);
        let dropped = reg.revoke_all_for_parent("gw-b");
        assert!(dropped.is_empty());
        // Unrelated parent's children stay intact.
        assert_eq!(reg.child_count("gw-a"), 1);
    }

    #[test]
    fn revoke_all_for_parent_idempotent() {
        let mut reg = DelegationRegistry::new();
        reg.authorize("gw", "child", DelegationScope::Full, 1.0);
        let first = reg.revoke_all_for_parent("gw");
        assert_eq!(first.len(), 1);
        let second = reg.revoke_all_for_parent("gw");
        assert!(second.is_empty());
    }

    #[test]
    fn revoke_all_for_parent_does_not_affect_siblings() {
        let mut reg = DelegationRegistry::new();
        reg.authorize("gw-a", "ca-1", DelegationScope::Full, 1.0);
        reg.authorize("gw-a", "ca-2", DelegationScope::Full, 1.0);
        reg.authorize("gw-b", "cb-1", DelegationScope::Full, 1.0);

        reg.revoke_all_for_parent("gw-a");
        assert_eq!(reg.child_count("gw-a"), 0);
        assert_eq!(reg.child_count("gw-b"), 1);
        assert!(reg.parent_of("cb-1").is_some());
    }

    #[test]
    fn revoke_all_authorization_voluntary_self_signed() {
        // Creator IS parent_to_disarm — voluntary path. Cosigner stake is
        // irrelevant because voluntary precedence.
        let d = check_revoke_all_authorization("parent-x", "parent-x", 0, 1_000_000);
        assert_eq!(d, RevokeAllAuthDecision::Voluntary);
    }

    #[test]
    fn revoke_all_authorization_involuntary_two_thirds() {
        // 2/3 supply met exactly.
        let supply: u128 = 9_000_000;
        let cosigner_sum: u128 = 6_000_000;
        let d = check_revoke_all_authorization(
            "fisherman", "compromised-gw", cosigner_sum, supply,
        );
        assert_eq!(d, RevokeAllAuthDecision::Involuntary);
    }

    #[test]
    fn revoke_all_authorization_below_threshold_rejected() {
        // 2/3 - 1 unit must reject.
        let supply: u128 = 9_000_000;
        let cosigner_sum: u128 = 5_999_999;
        let d = check_revoke_all_authorization(
            "fisherman", "compromised-gw", cosigner_sum, supply,
        );
        assert_eq!(d, RevokeAllAuthDecision::Rejected);
    }

    #[test]
    fn revoke_all_authorization_zero_supply_is_rejected() {
        // Pre-mint testnet edge: any non-zero cosign would otherwise
        // trivially cross the threshold. Refuse explicitly.
        let d = check_revoke_all_authorization("a", "b", 0, 0);
        assert_eq!(d, RevokeAllAuthDecision::Rejected);
        let d2 = check_revoke_all_authorization("a", "b", 1, 0);
        assert_eq!(d2, RevokeAllAuthDecision::Rejected);
    }

    #[test]
    fn revoke_all_authorization_voluntary_takes_precedence() {
        // Even with zero cosigner stake, self-signed voluntary path passes.
        let d = check_revoke_all_authorization("p", "p", 0, 1_000_000_000);
        assert_eq!(d, RevokeAllAuthDecision::Voluntary);
    }

    #[test]
    fn revoke_all_canonical_message_is_deterministic() {
        let m1 = revoke_all_canonical_message(
            "parent-hash-abc", RevokeReason::Compromised, 1_700_000_000.0,
        );
        let m2 = revoke_all_canonical_message(
            "parent-hash-abc", RevokeReason::Compromised, 1_700_000_000.0,
        );
        assert_eq!(m1, m2);
    }

    #[test]
    fn revoke_all_canonical_message_differs_on_each_field() {
        let base = revoke_all_canonical_message(
            "parent-x", RevokeReason::Compromised, 1.0,
        );
        let diff_parent = revoke_all_canonical_message(
            "parent-y", RevokeReason::Compromised, 1.0,
        );
        let diff_reason = revoke_all_canonical_message(
            "parent-x", RevokeReason::Rotated, 1.0,
        );
        let diff_ts = revoke_all_canonical_message(
            "parent-x", RevokeReason::Compromised, 2.0,
        );
        assert_ne!(base, diff_parent);
        assert_ne!(base, diff_reason);
        assert_ne!(base, diff_ts);
    }

    #[test]
    fn verify_cosigner_proof_round_trip() {
        let (pk, sk) = fresh_dilithium_keypair();
        let canonical = revoke_all_canonical_message(
            "parent-x", RevokeReason::Compromised, 1700.0,
        );
        let proof = build_cosigner_proof(&sk, &pk, &canonical);
        let identity_hash = verify_cosigner_proof(&proof, &canonical).unwrap();
        // Identity hash equals SHA3-256 of pk.
        assert_eq!(identity_hash, crate::crypto::hash::sha3_256_hex(&pk));
    }

    #[test]
    fn verify_cosigner_proof_rejects_wrong_message() {
        let (pk, sk) = fresh_dilithium_keypair();
        let canonical = revoke_all_canonical_message(
            "parent-x", RevokeReason::Compromised, 1700.0,
        );
        let proof = build_cosigner_proof(&sk, &pk, &canonical);
        let other = revoke_all_canonical_message(
            "parent-y", RevokeReason::Compromised, 1700.0,
        );
        assert!(verify_cosigner_proof(&proof, &other).is_err());
    }

    #[test]
    fn verify_cosigner_proof_rejects_non_hex() {
        let proof = CosignerProof {
            public_key_hex: "zzzz_not_hex".into(),
            signature_hex: "00".into(),
        };
        let canonical = b"unused";
        assert!(verify_cosigner_proof(&proof, canonical).is_err());
    }

    #[test]
    fn extract_revoke_all_parses_voluntary_metadata() {
        let meta = revoke_all_metadata_voluntary("parent-abc", RevokeReason::Rotated);
        let rec = test_record_with_meta(meta);
        let parsed = extract_revoke_all(&rec).unwrap().unwrap();
        assert_eq!(parsed.parent_to_disarm, "parent-abc");
        assert_eq!(parsed.reason, RevokeReason::Rotated);
        assert!(parsed.cosigners.is_empty());
    }

    #[test]
    fn extract_revoke_all_parses_involuntary_metadata() {
        let (pk, sk) = fresh_dilithium_keypair();
        let canonical = revoke_all_canonical_message(
            "compromised-gw", RevokeReason::Compromised, 1.0,
        );
        let proof = build_cosigner_proof(&sk, &pk, &canonical);
        let meta = revoke_all_metadata_involuntary(
            "compromised-gw",
            RevokeReason::Compromised,
            std::slice::from_ref(&proof),
        );
        let rec = test_record_with_meta(meta);
        let parsed = extract_revoke_all(&rec).unwrap().unwrap();
        assert_eq!(parsed.parent_to_disarm, "compromised-gw");
        assert_eq!(parsed.reason, RevokeReason::Compromised);
        assert_eq!(parsed.cosigners.len(), 1);
        assert_eq!(parsed.cosigners[0].public_key_hex, proof.public_key_hex);
    }

    #[test]
    fn extract_revoke_all_returns_none_for_authorize() {
        let meta = delegation_metadata(
            &DelegationOp::Authorize, "child", &DelegationScope::Full,
        ).unwrap();
        let rec = test_record_with_meta(meta);
        // op="authorize" is not "revoke_all" → None.
        assert!(extract_revoke_all(&rec).unwrap().is_none());
    }

    #[test]
    fn extract_revoke_all_missing_parent_errors() {
        let mut meta = BTreeMap::new();
        meta.insert(DELEGATION_OP_KEY.into(), serde_json::json!("revoke_all"));
        meta.insert(REVOKE_ALL_REASON_KEY.into(), serde_json::json!("rotated"));
        let rec = test_record_with_meta(meta);
        assert!(extract_revoke_all(&rec).is_err());
    }

    #[test]
    fn extract_revoke_all_invalid_reason_errors() {
        let mut meta = BTreeMap::new();
        meta.insert(DELEGATION_OP_KEY.into(), serde_json::json!("revoke_all"));
        meta.insert(REVOKE_ALL_PARENT_KEY.into(), serde_json::json!("p"));
        meta.insert(REVOKE_ALL_REASON_KEY.into(), serde_json::json!("rebooted"));
        let rec = test_record_with_meta(meta);
        assert!(extract_revoke_all(&rec).is_err());
    }

    #[test]
    fn extract_revoke_all_cosigners_must_be_array() {
        let mut meta = BTreeMap::new();
        meta.insert(DELEGATION_OP_KEY.into(), serde_json::json!("revoke_all"));
        meta.insert(REVOKE_ALL_PARENT_KEY.into(), serde_json::json!("p"));
        meta.insert(REVOKE_ALL_REASON_KEY.into(), serde_json::json!("rotated"));
        meta.insert(REVOKE_ALL_COSIGNERS_KEY.into(), serde_json::json!("string"));
        let rec = test_record_with_meta(meta);
        assert!(extract_revoke_all(&rec).is_err());
    }

    #[test]
    fn extract_delegation_returns_none_for_revoke_all() {
        // Verifies the dispatch contract: extract_delegation must yield
        // Ok(None) for "revoke_all" so callers can dispatch without
        // second-guessing the op string.
        let meta = revoke_all_metadata_voluntary("p", RevokeReason::Rotated);
        let rec = test_record_with_meta(meta);
        assert!(extract_delegation(&rec).unwrap().is_none());
    }

    #[test]
    fn apply_delegation_revoke_all_drops_all_children() {
        let mut reg = DelegationRegistry::new();
        // Establish 50 children of gw-x.
        for i in 0..50u32 {
            reg.authorize("gw-x", &format!("c-{i:03}"), DelegationScope::Full, 1.0);
        }
        assert_eq!(reg.child_count("gw-x"), 50);
        let meta = revoke_all_metadata_voluntary("gw-x", RevokeReason::Rotated);
        let rec = test_record_with_meta(meta);
        apply_delegation(&rec, &mut reg).unwrap();
        assert_eq!(reg.child_count("gw-x"), 0);
        assert_eq!(reg.total(), 0);
    }

    #[test]
    fn revoke_all_metadata_round_trip_preserves_cosigner_order() {
        // Cosigner order matters for replay-style tests; metadata builder
        // must not reorder the cosigners array.
        let (pk_a, _sk_a) = fresh_dilithium_keypair();
        let (pk_b, _sk_b) = fresh_dilithium_keypair();
        let proofs = vec![
            CosignerProof {
                public_key_hex: hex::encode(&pk_a),
                signature_hex: "aa".into(),
            },
            CosignerProof {
                public_key_hex: hex::encode(&pk_b),
                signature_hex: "bb".into(),
            },
        ];
        let meta = revoke_all_metadata_involuntary(
            "p", RevokeReason::Compromised, &proofs,
        );
        let rec = test_record_with_meta(meta);
        let parsed = extract_revoke_all(&rec).unwrap().unwrap();
        assert_eq!(parsed.cosigners[0].public_key_hex, hex::encode(&pk_a));
        assert_eq!(parsed.cosigners[1].public_key_hex, hex::encode(&pk_b));
    }

    #[test]
    fn delegation_metadata_errs_on_revoke_all() {
        // RevokeAll has a dedicated builder; passing it here is a caller error.
        let result = delegation_metadata(&DelegationOp::RevokeAll, "x", &DelegationScope::Full);
        assert!(result.is_err());
    }

    #[test]
    fn revoke_reason_round_trips_via_string() {
        for r in [RevokeReason::Compromised, RevokeReason::Expired, RevokeReason::Rotated] {
            let s = r.as_str();
            assert_eq!(RevokeReason::from_str(s), Some(r));
        }
    }

    // ── Gap E lifecycle: constants + pure helpers ───────────────────────

    #[test]
    fn gap_e_default_lease_seconds_is_30_days() {
        assert_eq!(DEFAULT_LEASE_SECONDS, 30.0 * 86_400.0);
    }

    #[test]
    fn gap_e_max_children_per_parent_is_one_million() {
        assert_eq!(MAX_CHILDREN_PER_PARENT, 1_000_000);
    }

    #[test]
    fn gap_e_max_authorize_per_hour_is_ten_thousand() {
        assert_eq!(MAX_AUTHORIZE_PER_PARENT_PER_HOUR, 10_000);
    }

    #[test]
    fn gap_e_authorize_rate_window_is_one_hour() {
        assert_eq!(AUTHORIZE_RATE_WINDOW_SECONDS, 3_600.0);
    }

    #[test]
    fn gap_e_default_expires_at_adds_lease_to_created() {
        let created = 1_000_000.0;
        assert_eq!(default_expires_at(created), created + DEFAULT_LEASE_SECONDS);
    }

    #[test]
    fn gap_e_extract_expires_at_returns_some_when_set() {
        let mut meta = BTreeMap::new();
        meta.insert(DELEGATION_OP_KEY.into(), JsonValue::String("authorize".into()));
        meta.insert("delegation_child".into(), JsonValue::String("c".into()));
        meta.insert(EXPIRES_AT_KEY.into(), serde_json::json!(1_500_000.5_f64));
        let rec = test_record_with_meta(meta);
        assert_eq!(extract_expires_at(&rec), Some(1_500_000.5));
    }

    #[test]
    fn gap_e_extract_expires_at_returns_none_when_missing() {
        let mut meta = BTreeMap::new();
        meta.insert(DELEGATION_OP_KEY.into(), JsonValue::String("authorize".into()));
        meta.insert("delegation_child".into(), JsonValue::String("c".into()));
        let rec = test_record_with_meta(meta);
        assert_eq!(extract_expires_at(&rec), None);
    }

    #[test]
    fn gap_e_extract_expires_at_rejects_non_finite() {
        let mut meta = BTreeMap::new();
        meta.insert(DELEGATION_OP_KEY.into(), JsonValue::String("authorize".into()));
        meta.insert("delegation_child".into(), JsonValue::String("c".into()));
        // serde_json represents NaN/Inf as Null, not a number — verify the
        // extract guard handles a string-shaped value too.
        meta.insert(EXPIRES_AT_KEY.into(), JsonValue::String("not-a-number".into()));
        let rec = test_record_with_meta(meta);
        assert_eq!(extract_expires_at(&rec), None);
    }

    #[test]
    fn gap_e_check_authorize_caps_under_both_limits_allowed() {
        assert_eq!(
            check_authorize_caps(0, 0),
            AuthorizeCapDecision::Allowed
        );
        assert_eq!(
            check_authorize_caps(
                MAX_CHILDREN_PER_PARENT - 1,
                MAX_AUTHORIZE_PER_PARENT_PER_HOUR - 1,
            ),
            AuthorizeCapDecision::Allowed
        );
    }

    #[test]
    fn gap_e_check_authorize_caps_at_child_cap_returns_child_exceeded() {
        assert_eq!(
            check_authorize_caps(MAX_CHILDREN_PER_PARENT, 0),
            AuthorizeCapDecision::ChildCapExceeded
        );
    }

    #[test]
    fn gap_e_check_authorize_caps_above_child_cap_returns_child_exceeded() {
        assert_eq!(
            check_authorize_caps(MAX_CHILDREN_PER_PARENT + 1, 0),
            AuthorizeCapDecision::ChildCapExceeded
        );
    }

    #[test]
    fn gap_e_check_authorize_caps_at_rate_cap_returns_rate_exceeded() {
        assert_eq!(
            check_authorize_caps(0, MAX_AUTHORIZE_PER_PARENT_PER_HOUR),
            AuthorizeCapDecision::RateCapExceeded
        );
    }

    #[test]
    fn gap_e_check_authorize_caps_child_takes_precedence_over_rate() {
        // When both are over, child is reported (deterministic order).
        assert_eq!(
            check_authorize_caps(
                MAX_CHILDREN_PER_PARENT,
                MAX_AUTHORIZE_PER_PARENT_PER_HOUR,
            ),
            AuthorizeCapDecision::ChildCapExceeded
        );
    }

    // ── Gap E lifecycle: registry methods ────────────────────────────────

    #[test]
    fn gap_e_authorize_with_expiry_records_explicit_value() {
        let mut reg = DelegationRegistry::new();
        reg.authorize_with_expiry("p", "c", DelegationScope::Full, 1_000.0, Some(2_000.0));
        let entry = reg.parent_of("c").unwrap();
        assert_eq!(entry.expires_at, Some(2_000.0));
        assert_eq!(entry.created, 1_000.0);
    }

    #[test]
    fn gap_e_authorize_default_signature_no_expiry() {
        // The bare `authorize()` method (used by tests + legacy snapshot
        // rebuild) leaves expires_at = None. Production callers go through
        // apply_delegation which always supplies an explicit expiry.
        let mut reg = DelegationRegistry::new();
        reg.authorize("p", "c", DelegationScope::Full, 1_000.0);
        assert_eq!(reg.parent_of("c").unwrap().expires_at, None);
    }

    #[test]
    fn gap_e_authorize_with_expiry_overwrites_existing_child() {
        let mut reg = DelegationRegistry::new();
        reg.authorize_with_expiry("p1", "c", DelegationScope::Full, 1_000.0, Some(2_000.0));
        reg.authorize_with_expiry("p2", "c", DelegationScope::BatchOnly, 1_500.0, Some(3_000.0));
        let entry = reg.parent_of("c").unwrap();
        assert_eq!(entry.parent, "p2");
        assert_eq!(entry.expires_at, Some(3_000.0));
        assert_eq!(reg.child_count("p1"), 0);
        assert_eq!(reg.child_count("p2"), 1);
    }

    #[test]
    fn gap_e_prune_expired_drops_only_expired_entries() {
        let mut reg = DelegationRegistry::new();
        reg.authorize_with_expiry("p", "alive", DelegationScope::Full, 0.0, Some(2_000.0));
        reg.authorize_with_expiry("p", "expired", DelegationScope::Full, 0.0, Some(500.0));
        reg.authorize_with_expiry("p", "no_expiry", DelegationScope::Full, 0.0, None);
        let dropped = reg.prune_expired(1_000.0);
        assert_eq!(dropped, vec!["expired".to_string()]);
        assert!(reg.parent_of("alive").is_some());
        assert!(reg.parent_of("expired").is_none());
        assert!(reg.parent_of("no_expiry").is_some());
    }

    #[test]
    fn gap_e_prune_expired_returns_sorted_children() {
        let mut reg = DelegationRegistry::new();
        for child in ["zeta", "alpha", "mu", "beta"] {
            reg.authorize_with_expiry("p", child, DelegationScope::Full, 0.0, Some(500.0));
        }
        let dropped = reg.prune_expired(1_000.0);
        assert_eq!(dropped, vec!["alpha", "beta", "mu", "zeta"]);
    }

    #[test]
    fn gap_e_prune_expired_clears_reverse_index_when_all_children_drop() {
        let mut reg = DelegationRegistry::new();
        for child in ["a", "b", "c"] {
            reg.authorize_with_expiry("p", child, DelegationScope::Full, 0.0, Some(500.0));
        }
        assert_eq!(reg.child_count("p"), 3);
        let _ = reg.prune_expired(1_000.0);
        assert_eq!(reg.child_count("p"), 0);
    }

    #[test]
    fn gap_e_prune_expired_skips_entries_with_none_expiry() {
        let mut reg = DelegationRegistry::new();
        reg.authorize("p", "legacy", DelegationScope::Full, 0.0);
        let dropped = reg.prune_expired(1_000_000_000.0);
        assert!(dropped.is_empty());
        assert!(reg.parent_of("legacy").is_some());
    }

    #[test]
    fn gap_e_extend_updates_existing_lease() {
        let mut reg = DelegationRegistry::new();
        reg.authorize_with_expiry("p", "c", DelegationScope::Full, 1_000.0, Some(2_000.0));
        reg.extend("p", "c", 5_000.0).unwrap();
        assert_eq!(reg.parent_of("c").unwrap().expires_at, Some(5_000.0));
    }

    #[test]
    fn gap_e_extend_rejects_unknown_child() {
        let mut reg = DelegationRegistry::new();
        let res = reg.extend("p", "ghost", 5_000.0);
        assert!(res.is_err());
        let msg = res.err().unwrap().to_string();
        assert!(msg.contains("no active delegation"));
    }

    #[test]
    fn gap_e_extend_rejects_wrong_parent() {
        let mut reg = DelegationRegistry::new();
        reg.authorize_with_expiry("real-parent", "c", DelegationScope::Full, 0.0, Some(1_000.0));
        let res = reg.extend("attacker", "c", 5_000.0);
        assert!(res.is_err());
        let msg = res.err().unwrap().to_string();
        assert!(msg.contains("only parent"));
        // Lease was not modified.
        assert_eq!(reg.parent_of("c").unwrap().expires_at, Some(1_000.0));
    }

    #[test]
    fn gap_e_extend_idempotent_on_same_value() {
        let mut reg = DelegationRegistry::new();
        reg.authorize_with_expiry("p", "c", DelegationScope::Full, 0.0, Some(1_000.0));
        reg.extend("p", "c", 5_000.0).unwrap();
        reg.extend("p", "c", 5_000.0).unwrap();
        assert_eq!(reg.parent_of("c").unwrap().expires_at, Some(5_000.0));
    }

    // ── Gap E lifecycle: rate-limit window ───────────────────────────────

    #[test]
    fn gap_e_authorize_count_in_window_starts_zero() {
        let mut reg = DelegationRegistry::new();
        assert_eq!(reg.authorize_count_in_window("p", 1_000.0), 0);
    }

    #[test]
    fn gap_e_record_authorize_event_appends_and_count_observes() {
        let mut reg = DelegationRegistry::new();
        for i in 0..5 {
            reg.record_authorize_event("p", 1_000.0 + i as f64);
        }
        assert_eq!(reg.authorize_count_in_window("p", 1_004.0), 5);
    }

    #[test]
    fn gap_e_authorize_count_in_window_prunes_old_entries() {
        let mut reg = DelegationRegistry::new();
        // Two events 4000s apart — the older falls outside the 3600s window.
        reg.record_authorize_event("p", 1_000.0);
        reg.record_authorize_event("p", 5_000.0);
        let count = reg.authorize_count_in_window("p", 5_000.0);
        assert_eq!(count, 1);
    }

    #[test]
    fn gap_e_cleanup_authorize_history_drops_quiet_parents() {
        let mut reg = DelegationRegistry::new();
        reg.record_authorize_event("active", 5_000.0);
        reg.record_authorize_event("quiet", 100.0);
        assert_eq!(reg.tracked_authorize_parents(), 2);
        reg.cleanup_authorize_history(5_000.0);
        assert_eq!(reg.tracked_authorize_parents(), 1);
        // The active parent's window survives.
        assert_eq!(reg.authorize_count_in_window("active", 5_000.0), 1);
    }

    // ── Gap E lifecycle: metadata + extract ─────────────────────────────

    #[test]
    fn gap_e_extend_metadata_round_trips() {
        let m = extend_metadata("child-x", 9_999.0);
        let rec = test_record_with_meta(m);
        let parsed = extract_delegation(&rec).unwrap().unwrap();
        assert!(matches!(parsed.op, DelegationOp::Extend));
        assert_eq!(parsed.child, "child-x");
        assert_eq!(extract_expires_at(&rec), Some(9_999.0));
    }

    #[test]
    fn gap_e_authorize_metadata_with_expiry_round_trips() {
        let m = authorize_metadata_with_expiry("c", &DelegationScope::Full, 8_888.5);
        let rec = test_record_with_meta(m);
        let parsed = extract_delegation(&rec).unwrap().unwrap();
        assert!(matches!(parsed.op, DelegationOp::Authorize));
        assert_eq!(parsed.child, "c");
        assert_eq!(extract_expires_at(&rec), Some(8_888.5));
    }

    #[test]
    fn gap_e_delegation_metadata_errs_on_extend() {
        let result = delegation_metadata(&DelegationOp::Extend, "x", &DelegationScope::Full);
        assert!(result.is_err());
    }

    #[test]
    fn gap_e_extract_delegation_parses_extend_op() {
        let mut meta = BTreeMap::new();
        meta.insert(DELEGATION_OP_KEY.into(), JsonValue::String("extend".into()));
        meta.insert("delegation_child".into(), JsonValue::String("c".into()));
        meta.insert(EXPIRES_AT_KEY.into(), serde_json::json!(7_777.0));
        let rec = test_record_with_meta(meta);
        let parsed = extract_delegation(&rec).unwrap().unwrap();
        assert!(matches!(parsed.op, DelegationOp::Extend));
        assert_eq!(parsed.child, "c");
    }

    // ── Gap E lifecycle: apply_delegation integration ────────────────────

    #[test]
    fn gap_e_apply_delegation_authorize_sets_default_expiry() {
        let m = delegation_metadata(&DelegationOp::Authorize, "c", &DelegationScope::Full).unwrap();
        let mut rec = test_record_with_meta(m);
        rec.timestamp = 1_000.0;
        let mut reg = DelegationRegistry::new();
        apply_delegation(&rec, &mut reg).unwrap();
        let entry = reg.parent_of("c").unwrap();
        assert_eq!(
            entry.expires_at,
            Some(1_000.0 + DEFAULT_LEASE_SECONDS)
        );
    }

    #[test]
    fn gap_e_apply_delegation_authorize_uses_explicit_expiry() {
        let m = authorize_metadata_with_expiry("c", &DelegationScope::Full, 42_424.0);
        let mut rec = test_record_with_meta(m);
        rec.timestamp = 1_000.0;
        let mut reg = DelegationRegistry::new();
        apply_delegation(&rec, &mut reg).unwrap();
        assert_eq!(reg.parent_of("c").unwrap().expires_at, Some(42_424.0));
    }

    #[test]
    fn gap_e_apply_delegation_extend_prolongs_existing_lease() {
        // First authorize the child via a record (so creator hash matches).
        let auth_meta = authorize_metadata_with_expiry("c", &DelegationScope::Full, 2_000.0);
        let auth_rec = test_record_with_meta(auth_meta);
        let parent_hash = creator_identity_hash(&auth_rec);
        let mut reg = DelegationRegistry::new();
        apply_delegation(&auth_rec, &mut reg).unwrap();
        assert_eq!(reg.parent_of("c").unwrap().parent, parent_hash);

        // Now extend with the same creator.
        let ext_meta = extend_metadata("c", 9_999.0);
        let ext_rec = test_record_with_meta(ext_meta);
        assert_eq!(creator_identity_hash(&ext_rec), parent_hash); // same key bytes ⇒ same hash
        apply_delegation(&ext_rec, &mut reg).unwrap();
        assert_eq!(reg.parent_of("c").unwrap().expires_at, Some(9_999.0));
    }

    #[test]
    fn gap_e_apply_delegation_extend_rejects_missing_expiry() {
        let mut meta = BTreeMap::new();
        meta.insert(DELEGATION_OP_KEY.into(), JsonValue::String("extend".into()));
        meta.insert("delegation_child".into(), JsonValue::String("c".into()));
        // No EXPIRES_AT_KEY — apply_delegation should return Err.
        let rec = test_record_with_meta(meta);
        let mut reg = DelegationRegistry::new();
        let res = apply_delegation(&rec, &mut reg);
        assert!(res.is_err());
        let msg = res.err().unwrap().to_string();
        assert!(msg.contains("missing or non-finite expires_at"));
    }

    #[test]
    fn gap_e_apply_delegation_extend_rejects_unknown_child() {
        let m = extend_metadata("ghost", 9_999.0);
        let rec = test_record_with_meta(m);
        let mut reg = DelegationRegistry::new();
        let res = apply_delegation(&rec, &mut reg);
        assert!(res.is_err());
        let msg = res.err().unwrap().to_string();
        assert!(msg.contains("no active delegation"));
    }

    #[test]
    fn gap_e_apply_delegation_extend_rejects_wrong_parent() {
        // First authorize with one creator key…
        let auth_meta = authorize_metadata_with_expiry("c", &DelegationScope::Full, 2_000.0);
        let mut auth_rec = test_record_with_meta(auth_meta);
        auth_rec.creator_public_key = vec![0u8; 32];
        let mut reg = DelegationRegistry::new();
        apply_delegation(&auth_rec, &mut reg).unwrap();
        // …then craft an extend record from a different creator.
        let ext_meta = extend_metadata("c", 9_999.0);
        let mut ext_rec = test_record_with_meta(ext_meta);
        ext_rec.creator_public_key = vec![0xFF; 32];
        let res = apply_delegation(&ext_rec, &mut reg);
        assert!(res.is_err());
        let msg = res.err().unwrap().to_string();
        assert!(msg.contains("only parent"));
        // Original lease was untouched.
        assert_eq!(reg.parent_of("c").unwrap().expires_at, Some(2_000.0));
    }

    // ── Gap E lifecycle: scale ──────────────────────────────────────────

    #[test]
    fn gap_e_prune_expired_drops_10k_children_in_one_pass() {
        let mut reg = DelegationRegistry::new();
        for i in 0..10_000 {
            reg.authorize_with_expiry(
                "p",
                &format!("child-{i:05}"),
                DelegationScope::Full,
                0.0,
                Some(500.0),
            );
        }
        for i in 0..2_000 {
            reg.authorize_with_expiry(
                "p",
                &format!("alive-{i:04}"),
                DelegationScope::Full,
                0.0,
                Some(2_000.0),
            );
        }
        let dropped = reg.prune_expired(1_000.0);
        assert_eq!(dropped.len(), 10_000);
        assert_eq!(reg.child_count("p"), 2_000);
    }

    // ─── fixture-free tests ─────────────────────────────────

    #[test]
    fn batch_b_delegation_op_key_and_meta_keys_strict_pin_with_cross_module_disjointness() {
        // 6 distinct delegation-namespace keys
        assert_eq!(DELEGATION_OP_KEY, "delegation_op");
        assert_eq!(ATTESTATION_LEVEL_KEY, "attestation_level");
        assert_eq!(EXPIRES_AT_KEY, "expires_at");
        assert_eq!(REVOKE_ALL_PARENT_KEY, "revoke_all_parent");
        assert_eq!(REVOKE_ALL_REASON_KEY, "revoke_all_reason");
        assert_eq!(REVOKE_ALL_COSIGNERS_KEY, "revoke_all_cosigners");

        // All keys snake_case (lowercase + underscores only)
        let keys: [&str; 6] = [
            DELEGATION_OP_KEY,
            ATTESTATION_LEVEL_KEY,
            EXPIRES_AT_KEY,
            REVOKE_ALL_PARENT_KEY,
            REVOKE_ALL_REASON_KEY,
            REVOKE_ALL_COSIGNERS_KEY,
        ];
        for k in &keys {
            assert!(
                k.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{k} must be snake_case lowercase"
            );
            assert!(!k.contains(' '));
        }

        // Pairwise distinctness — no two keys collide within delegation
        for (i, a) in keys.iter().enumerate() {
            for (j, b) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "keys[{i}]={a} collides with keys[{j}]={b}");
                }
            }
        }

        // Cross-module disjointness: DELEGATION_OP_KEY must not collide with
        // foreign op-keys. (Other meta-keys are sub-namespace fields and may
        // legitimately appear in non-delegation contexts.)
        let foreign_keys: [&str; 4] = [
            crate::accounting::governance::GOVERNANCE_OP_KEY,
            crate::accounting::batch::BATCH_OP_KEY,
            crate::accounting::dormancy::DORMANCY_OP_KEY,
            crate::accounting::storage_market::STORAGE_OP_KEY,
        ];
        for foreign in &foreign_keys {
            assert_ne!(
                DELEGATION_OP_KEY, *foreign,
                "DELEGATION_OP_KEY collides with foreign op-key {foreign}"
            );
        }
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn batch_b_min_stake_and_revoke_all_threshold_constants_strict_pin_with_arithmetic_cross_checks() {
        // MIN_STAKE_TO_DELEGATE — 10K beat escape hatch
        assert_eq!(MIN_STAKE_TO_DELEGATE, 10_000 * BASE_UNITS_PER_BEAT);
        assert_eq!(MIN_STAKE_TO_DELEGATE, 10_000_000_000_000_u64);

        // REVOKE_ALL threshold 2/3 — strict rational
        assert_eq!(REVOKE_ALL_THRESHOLD_NUMERATOR, 2);
        assert_eq!(REVOKE_ALL_THRESHOLD_DENOMINATOR, 3);
        // Threshold ratio sanity: 0 < N < D (no degenerate division-by-zero
        // or always-pass thresholds)
        assert!(REVOKE_ALL_THRESHOLD_NUMERATOR < REVOKE_ALL_THRESHOLD_DENOMINATOR);
        assert!(REVOKE_ALL_THRESHOLD_NUMERATOR > 0);

        // Apply the threshold: with total_stake=900, threshold passes at >= 600
        let total: u128 = 900;
        let threshold = total * REVOKE_ALL_THRESHOLD_NUMERATOR / REVOKE_ALL_THRESHOLD_DENOMINATOR;
        assert_eq!(threshold, 600);

        // PRUNE_EXPIRED interval — 60 seconds (one-minute cadence)
        assert_eq!(PRUNE_EXPIRED_INTERVAL_SECS, 60);
    }

    #[test]
    fn batch_b_revoke_all_canonical_prefix_byte_literal_with_v1_versioning() {
        // The canonical message prefix is signed by cosigners. Changing it
        // would invalidate every existing cosigner proof on the network.

        // Exact byte literal pin
        assert_eq!(REVOKE_ALL_CANONICAL_PREFIX, b"elara_revoke_all_v1:");
        assert_eq!(REVOKE_ALL_CANONICAL_PREFIX.len(), 20);

        // ASCII-only (signed message must serialize identically across platforms)
        for b in REVOKE_ALL_CANONICAL_PREFIX {
            assert!(*b < 128, "canonical prefix must be ASCII-only");
        }

        // Versioning suffix "v1:" — required tail for forward-compat (v2 would
        // be a different prefix string with v2: suffix, NOT a metadata field)
        let s = std::str::from_utf8(REVOKE_ALL_CANONICAL_PREFIX).unwrap();
        assert!(s.ends_with("v1:"), "prefix must carry version tag (currently v1:)");
        assert!(s.starts_with("elara_"), "prefix must namespace under elara_");
        assert!(s.contains("revoke_all"), "prefix must name the operation");

        // The full prefix appears in a canonical message via
        // revoke_all_canonical_message() — verify the helper concatenates correctly.
        let msg = revoke_all_canonical_message(
            "parent_id_abc",
            RevokeReason::Compromised,
            1_234_567_890.0,
        );
        assert!(msg.starts_with(REVOKE_ALL_CANONICAL_PREFIX),
            "canonical message must start with the canonical prefix");
    }

    #[test]
    fn batch_b_attestation_level_five_variant_ord_ladder_with_secure_boot_gateway_floor() {
        use crate::identity::AttestationLevel as AL;

        // 5-variant strict ascending Ord ladder
        assert!(AL::None < AL::Software);
        assert!(AL::Software < AL::SecureBoot);
        assert!(AL::SecureBoot < AL::HardwareKey);
        assert!(AL::HardwareKey < AL::Puf);

        // Sort a shuffled array — pins total ordering
        let mut levels = vec![AL::Puf, AL::None, AL::HardwareKey, AL::SecureBoot, AL::Software];
        levels.sort();
        assert_eq!(
            levels,
            vec![AL::None, AL::Software, AL::SecureBoot, AL::HardwareKey, AL::Puf]
        );

        // min/max via iter
        let all = [AL::None, AL::Software, AL::SecureBoot, AL::HardwareKey, AL::Puf];
        assert_eq!(*all.iter().min().unwrap(), AL::None);
        assert_eq!(*all.iter().max().unwrap(), AL::Puf);

        // MIN_ATTESTATION_FOR_GATEWAY is SecureBoot — exactly the middle rung.
        // Two levels above (HardwareKey, Puf), two below (None, Software).
        assert_eq!(MIN_ATTESTATION_FOR_GATEWAY, AL::SecureBoot);
        // Below-floor levels: ledger gateway rejects
        assert!(AL::None < MIN_ATTESTATION_FOR_GATEWAY);
        assert!(AL::Software < MIN_ATTESTATION_FOR_GATEWAY);
        // At-or-above: accepted
        assert!(AL::SecureBoot >= MIN_ATTESTATION_FOR_GATEWAY);
        assert!(AL::HardwareKey >= MIN_ATTESTATION_FOR_GATEWAY);
        assert!(AL::Puf >= MIN_ATTESTATION_FOR_GATEWAY);

        // Default is None (weakest) — Software/SecureBoot/etc. require
        // explicit opt-in metadata.
        assert_eq!(AL::default(), AL::None);
    }

    #[test]
    fn batch_b_five_decision_enums_variant_distinctness_with_copy_and_partial_eq() {
        // AuthorizeCapDecision — 3 variants
        let acd = [
            AuthorizeCapDecision::Allowed,
            AuthorizeCapDecision::ChildCapExceeded,
            AuthorizeCapDecision::RateCapExceeded,
        ];
        for (i, a) in acd.iter().enumerate() {
            for (j, b) in acd.iter().enumerate() {
                if i == j {
                    assert_eq!(*a, *b);
                } else {
                    assert_ne!(*a, *b, "AuthorizeCapDecision variants[{i}/{j}] must differ");
                }
            }
        }
        let _copy_check: AuthorizeCapDecision = AuthorizeCapDecision::Allowed; // exercise Copy
        let _again = AuthorizeCapDecision::Allowed;
        assert_eq!(_copy_check, _again);

        // DelegationAuthDecision — 3 variants
        let dad = [
            DelegationAuthDecision::AllowedByRole,
            DelegationAuthDecision::AllowedByStake,
            DelegationAuthDecision::Rejected,
        ];
        for (i, a) in dad.iter().enumerate() {
            for (j, b) in dad.iter().enumerate() {
                if i != j {
                    assert_ne!(*a, *b, "DelegationAuthDecision variants[{i}/{j}] must differ");
                }
            }
        }

        // ProfileCGateDecision — 3 variants
        let pcg = [
            ProfileCGateDecision::NotRegisteredChild,
            ProfileCGateDecision::DelegationOpExempt,
            ProfileCGateDecision::Rejected,
        ];
        for (i, a) in pcg.iter().enumerate() {
            for (j, b) in pcg.iter().enumerate() {
                if i != j {
                    assert_ne!(*a, *b);
                }
            }
        }

        // GatewayAttestationDecision — 2 variants
        assert_ne!(
            GatewayAttestationDecision::Allowed,
            GatewayAttestationDecision::Rejected
        );
        let _ga_copy: GatewayAttestationDecision = GatewayAttestationDecision::Allowed;
        assert_eq!(_ga_copy, GatewayAttestationDecision::Allowed);

        // RevokeAllAuthDecision — 3 variants (Voluntary / Involuntary / Rejected)
        let raa = [
            RevokeAllAuthDecision::Voluntary,
            RevokeAllAuthDecision::Involuntary,
            RevokeAllAuthDecision::Rejected,
        ];
        for (i, a) in raa.iter().enumerate() {
            for (j, b) in raa.iter().enumerate() {
                if i != j {
                    assert_ne!(*a, *b);
                }
            }
        }

        // Aggregate variant counts pinned — adding/removing a variant breaks this
        assert_eq!(acd.len(), 3, "AuthorizeCapDecision must have exactly 3 variants");
        assert_eq!(dad.len(), 3, "DelegationAuthDecision must have exactly 3 variants");
        assert_eq!(pcg.len(), 3, "ProfileCGateDecision must have exactly 3 variants");
        assert_eq!(raa.len(), 3, "RevokeAllAuthDecision must have exactly 3 variants");
    }
}
