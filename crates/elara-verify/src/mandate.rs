//! Agent-mandate layer — the accountability primitive behind the project's
//! positioning ("proof of WHO — or WHAT — was *authorized* to do what, when").
//!
//! Design: `docs/AGENT-DELEGATION.md`. A *principal* key issues a signed,
//! scoped, time-bounded, revocable **mandate** to an *agent* key. Records
//! later signed by the agent reference their mandate; a verifier assigns each
//! a [`MandateFlag`] answering "this act, by this agent, for this principal,
//! inside this mandate, valid at this moment." Out-of-mandate acts are
//! RECORDED AND FLAGGED, never silently rejected — a truth ledger preserves
//! the evidence (see `docs/AGENT-DELEGATION.md` "RECORD AND FLAG").
//!
//! This is **v0 — observational**: the flag is computed and served via query;
//! it is NOT yet wired into consensus weight / committee eligibility / activity
//! credit (the "zero weight" enforcement is a later, separately-audited slice).
//! Keeping v0 inert w.r.t. the consensus root is what makes it safe to ship on
//! a live authority chain. Fusion-audited 2026-06-19 (4 Opus panel + 1 checker)
//! before any code — the wire format below is a one-way door and was locked
//! against that verdict.
//!
//! NOT to be confused with the node’s `accounting::delegation`, which is a *different*
//! system: device-fleet stake-sharing (parent signs FOR a child, child shares
//! the parent's stake, unauthorized ops are *rejected* at ingest). This module
//! is scoped *revocable agent authority* with record-and-flag forensics (the
//! agent signs AS ITSELF and references its mandate). Distinct concept,
//! distinct names (`mandate_*`, never `delegation_*`), distinct CFs.
//!
//! The core here is deterministic and dependency-light (sha3 + serde only) so
//! it can extract to a standalone crate (Lane 3) alongside the verifier.

use serde::{Deserialize, Serialize};

use elara_record::hash::sha3_256_hex;

/// Domain-separation tag for the mandate signing/id preimage. Versioned: a
/// future wire-format change mints `..._V2` rather than mutating this layout
/// (mirrors `network::realm::REALM_MEMBERSHIP_DOMAIN_TAG`).
pub const MANDATE_DOMAIN_TAG: &[u8] = b"ELARA_MANDATE_V1";

/// Domain-separation tag for the revocation signing/id preimage.
pub const REVOCATION_DOMAIN_TAG: &[u8] = b"ELARA_REVOCATION_V1";

/// In-payload format version. Distinct from the domain tag: the tag gates a
/// hard layout break, this byte gates additive field evolution. A mandate
/// whose `version` a verifier does not recognize flags [`MandateFlag::Malformed`]
/// (honest "I cannot verify this"), never `Valid`.
pub const MANDATE_FORMAT_VERSION: u8 = 1;

/// Version byte for the node's on-disk index VALUES ([`RevocationEntry`],
/// [`MandateActEntry`]) — distinct from [`MANDATE_FORMAT_VERSION`] (the wire
/// payload) and from the snapshot checksum version. Lets the stored value layout
/// evolve without a column-family migration.
pub const MANDATE_STORE_VERSION: u8 = 1;

/// Absolute upper bound on sub-delegation chain length walked by
/// [`evaluate_mandate`] — independent of the attacker-settable
/// [`MandateRecord::sub_delegation_max_depth`] (a `u8`, so a declared chain can
/// claim up to 255). This is the load-bearing termination guarantee on
/// attacker-controlled `parent_mandate_id` pointers (a snapshot-injected storage
/// cycle would otherwise loop) AND the public-endpoint DoS bound: a chain
/// evaluation does at most this many resolver point-reads. A walk that reaches a
/// genuine root needs fewer hops; one that exceeds the bound is
/// [`MandateFlag::DepthExceeded`]. Locking it is a one-way door once chain flags
/// are consumed (raising it later reclassifies historical `DepthExceeded` to
/// `Valid` on some nodes) — 16 is generous vs any real delegation tree.
pub const MANDATE_MAX_CHAIN_DEPTH: usize = 16;

/// Count of snapshot-carried mandates the node storage layer's bulk-apply rejected
/// for failing the consumer-enforced content-address / well-formedness invariant
/// (key ≠ recomputed `mandate_id`, or `!is_well_formed()`). Non-zero ⇒ a
/// snapshot producer shipped a mandate stored under a non-content-hash key — a
/// producer bug or a tampered snapshot that nonetheless passed signer-trust.
/// Defined in core (always compiled) so the storage layer can increment it
/// without referencing the node-gated metrics module.
pub static MANDATE_SNAPSHOT_REJECTED_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Length (hex chars) of a 256-bit SHA3 identity hash (`sha3(pk)`).
pub const IDENTITY_HASH_HEX_LEN: usize = 64;

/// Reserved metadata key carrying the leaf mandate id an act record invokes.
/// MUST be in the ingest allowlist (`content_safety`) in the same commit that
/// ingests it, or every mandate-bearing record hard-rejects. It rides in the
/// record's *signed* metadata so the agent's signature commits to which
/// mandate it claims (closes the "re-point a victim's record at a broader
/// mandate" forgery).
pub const MANDATE_REF_METADATA_KEY: &str = "mandate_ref";

/// Metadata key carrying a serialized issuance [`MandateRecord`]. A protocol
/// wire constant (lives here, beside the type it carries, so feature-light
/// consumers — SDKs, the offline verifier, `examples/mandate_demo.rs` — can name
/// it without pulling in the node `network` module). Re-exported from
/// `network::mandate_node` for back-compat.
pub const MANDATE_OP_KEY: &str = "mandate_op";
/// Metadata key carrying a serialized [`RevocationRecord`]. Distinct from
/// `key_rotation`'s `"key_revocation"`. See [`MANDATE_OP_KEY`] for why it lives
/// in core.
pub const MANDATE_REVOCATION_OP_KEY: &str = "revocation_op";

/// The authority a mandate grants. Scope is matched *permissively by
/// membership* (order-independent) so the canonical encoding sorts + dedups
/// before hashing — two semantically-identical scopes MUST produce one id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MandateScope {
    /// Opcode strings the agent may create (e.g. `"transfer"`), or `["*"]` for
    /// any op. NOTE: `*` means "all ops, including ops added in future protocol
    /// versions" — security-conscious principals should enumerate.
    pub allowed_ops: Vec<String>,
    /// Zone paths the agent may act in, matched by path-prefix (`"zone/A"`
    /// covers `"zone/A"` and `"zone/A/0"` but NOT `"zone/AB"`), or `["*"]` for
    /// any zone. Prefix-match is deliberate: zone auto-scaling (Gap 4) splits a
    /// zone into children at runtime, and a mandate for the parent must cover
    /// the children.
    pub allowed_zones: Vec<String>,
    /// Optional quantitative ceiling on the act's amount (`None` = no limit).
    pub max_amount: Option<u64>,
}

impl MandateScope {
    /// `["*"]` ops + `["*"]` zones + no amount cap — the broadest mandate.
    pub fn wildcard() -> Self {
        Self {
            allowed_ops: vec!["*".to_string()],
            allowed_zones: vec!["*".to_string()],
            max_amount: None,
        }
    }

    /// `true` iff the scope imposes NO restriction: ops include `*`, zones
    /// include `*`, and there is no amount cap. v0 enforces scope only for such
    /// mandates (see [`evaluate_mandate_v0`]).
    pub fn is_wildcard(&self) -> bool {
        self.max_amount.is_none()
            && self.allowed_ops.iter().any(|o| o == "*")
            && self.allowed_zones.iter().any(|z| z == "*")
    }

    /// Lowercase every op/zone token. The matchers ([`Self::allows_op`] /
    /// [`Self::allows_zone`]) are exact, and the canonical op vocabulary
    /// (`LedgerOp::as_str`) plus the agent `action`/`kind` convention are all
    /// lowercase — so a mixed-case scope entry would silently never match (an
    /// unenforceable mandate with no error signal). Issuers normalize BEFORE
    /// signing (case is part of the signed `mandate_id`); see
    /// internal design notes §3. Idempotent. NOT applied at ingest or
    /// in [`MandateRecord::canonicalized`] — those run on already-signed bytes
    /// and would break content-addressing.
    pub fn normalized(&self) -> MandateScope {
        MandateScope {
            allowed_ops: self.allowed_ops.iter().map(|o| o.to_ascii_lowercase()).collect(),
            allowed_zones: self.allowed_zones.iter().map(|z| z.to_ascii_lowercase()).collect(),
            max_amount: self.max_amount,
        }
    }

    fn allows_op(&self, op: &str) -> bool {
        self.allowed_ops.iter().any(|o| o == "*" || o == op)
    }

    fn allows_zone(&self, zone: &str) -> bool {
        self.allowed_zones.iter().any(|z| {
            z == "*" || zone == z || zone.starts_with(&format!("{z}/"))
        })
    }
}

/// A signed grant of scoped authority from a principal key to an agent key.
///
/// Rides inside a [`elara_record::record::ValidationRecord`] whose `creator_public_key`
/// is the **principal** — so the outer record signature *is* the principal's
/// signature over this payload, and ingest checks
/// `sha3(creator_public_key) == principal_identity_hash`. The payload therefore
/// carries no embedded key or signature of its own (no ~4 KB PK bloat per
/// mandate); its authenticity comes from the carrier record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandateRecord {
    /// In-payload format version ([`MANDATE_FORMAT_VERSION`]).
    pub version: u8,
    /// Network this mandate is bound to (the node's `network_id` / a chain
    /// discriminator). Bound into the signed bytes so a mandate signed on one
    /// network cannot be replayed onto another (records are NOT otherwise
    /// network-bound, and unlike a realm cert a ledger-resident mandate has no
    /// live handshake to check the network out-of-band).
    pub network_id: String,
    /// Hex SHA3-256 of the issuing principal's Dilithium3 public key.
    pub principal_identity_hash: String,
    /// Hex SHA3-256 of the granted agent's Dilithium3 public key. An act
    /// record is judged against this: `sha3(act.creator_pk)` must equal it, or
    /// the act flags [`MandateFlag::AgentMismatch`].
    pub agent_identity_hash: String,
    /// What the agent may do.
    pub scope: MandateScope,
    /// Act-validity window start (unix milliseconds, integer — never f64).
    pub not_before_ms: u64,
    /// Act-validity window end (unix milliseconds). `not_after_ms <=
    /// not_before_ms` is an inverted (born-expired) window → `Malformed`.
    pub not_after_ms: u64,
    /// Max sub-delegation depth permitted (0 = the agent may not sub-delegate).
    /// Enforced by [`walk_chain`] via [`MANDATE_MAX_CHAIN_DEPTH`] and the
    /// per-hop distance check. Frozen wire field.
    pub sub_delegation_max_depth: u8,
    /// `None` = a root mandate signed directly by the principal. `Some(id)` =
    /// a sub-delegation whose parent is `id`; [`walk_chain`] verifies the full
    /// chain leaf→root (genealogy link + scope monotone-narrowing + per-hop
    /// revocation), flagging a missing/broken ancestor as
    /// [`MandateFlag::UnverifiedChain`]. Never silently treated as a root
    /// mandate. Frozen wire field.
    pub parent_mandate_id: Option<String>,
    /// Issuer-chosen uniquifier (hex) so re-issuing an identical scope/window
    /// to the same agent yields a fresh `mandate_id` — the design requires
    /// re-authorization to be a NEW mandate, never an un-revoke.
    pub nonce: String,
}

impl MandateRecord {
    /// Construct a root mandate (no sub-delegation parent). Hex fields are
    /// normalized to lowercase, matching the realm-cert convention.
    #[allow(clippy::too_many_arguments)]
    pub fn new_root(
        network_id: impl Into<String>,
        principal_identity_hash: &str,
        agent_identity_hash: &str,
        scope: MandateScope,
        not_before_ms: u64,
        not_after_ms: u64,
        sub_delegation_max_depth: u8,
        nonce: impl Into<String>,
    ) -> Self {
        Self {
            version: MANDATE_FORMAT_VERSION,
            network_id: network_id.into(),
            principal_identity_hash: principal_identity_hash.to_ascii_lowercase(),
            agent_identity_hash: agent_identity_hash.to_ascii_lowercase(),
            // Lowercase ops/zones at the issuance edge so a mixed-case scope is
            // never silently unenforceable (internal design notes §3).
            scope: scope.normalized(),
            not_before_ms,
            not_after_ms,
            sub_delegation_max_depth,
            parent_mandate_id: None,
            nonce: nonce.into(),
        }
    }

    /// Deterministic, domain-separated signing/id preimage. Every
    /// variable-length field is u32-BE length-prefixed (no concatenation
    /// ambiguity), every integer is fixed-width big-endian, and scope vectors
    /// are sorted + deduped so semantically-identical scopes hash identically.
    /// The principal's signature (the carrier record's signature) is over these
    /// bytes; [`Self::mandate_id`] is `sha3` of them.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(MANDATE_DOMAIN_TAG);
        out.push(self.version);
        push_lp(&mut out, self.network_id.as_bytes());
        push_lp(&mut out, self.principal_identity_hash.as_bytes());
        push_lp(&mut out, self.agent_identity_hash.as_bytes());
        // scope: sorted + deduped vectors, then the amount cap with a tag byte.
        let ops = sorted_deduped(&self.scope.allowed_ops);
        out.extend_from_slice(&(ops.len() as u32).to_be_bytes());
        for op in &ops {
            push_lp(&mut out, op.as_bytes());
        }
        let zones = sorted_deduped(&self.scope.allowed_zones);
        out.extend_from_slice(&(zones.len() as u32).to_be_bytes());
        for z in &zones {
            push_lp(&mut out, z.as_bytes());
        }
        match self.scope.max_amount {
            None => out.push(0),
            Some(v) => {
                out.push(1);
                out.extend_from_slice(&v.to_be_bytes());
            }
        }
        out.extend_from_slice(&self.not_before_ms.to_be_bytes());
        out.extend_from_slice(&self.not_after_ms.to_be_bytes());
        out.push(self.sub_delegation_max_depth);
        match &self.parent_mandate_id {
            None => out.push(0),
            Some(id) => {
                out.push(1);
                push_lp(&mut out, id.as_bytes());
            }
        }
        push_lp(&mut out, self.nonce.as_bytes());
        out
    }

    /// Content-address: `sha3` over the domain-tagged canonical bytes. ONE
    /// canonicalization shared by id-derivation, signing, and `mandate_ref` —
    /// there is no second field-subset hash to drift out of sync.
    pub fn mandate_id(&self) -> String {
        sha3_256_hex(&self.canonical_signing_bytes())
    }

    /// Structural self-consistency, independent of any act. Returns `false`
    /// (→ the act flags `Malformed`) for an unrecognized version, an inverted
    /// window, or malformed identity hashes. Cheap; called before trusting a
    /// stored mandate.
    pub fn is_well_formed(&self) -> bool {
        self.version == MANDATE_FORMAT_VERSION
            && self.not_after_ms > self.not_before_ms
            && is_identity_hash(&self.principal_identity_hash)
            && is_identity_hash(&self.agent_identity_hash)
    }

    /// A clone with scope vectors sorted + deduped — the canonical *struct* form
    /// (the same normalization [`Self::canonical_signing_bytes`] applies before
    /// hashing). Stored blobs are canonicalized so a mandate carried in a snapshot
    /// and the same mandate replayed from its issuance record serialize
    /// byte-identically on every node: `mandate_id` is already order-independent,
    /// and this makes the stored value order-independent too (closing the
    /// snapshot-vs-replay blob-divergence the content-hash checksum would
    /// otherwise trip on). Idempotent.
    pub fn canonicalized(&self) -> MandateRecord {
        let mut c = self.clone();
        c.scope.allowed_ops = sorted_deduped(&self.scope.allowed_ops);
        c.scope.allowed_zones = sorted_deduped(&self.scope.allowed_zones);
        c
    }
}

/// A principal's revocation of a mandate. Rides in a [`elara_record::record::ValidationRecord`]
/// whose creator is the principal; the authoritative "moment authority ended"
/// is the carrier record's signed timestamp (NOT a self-asserted field), stored
/// into the revocation index as `revoked_at_ms`. The index ALSO stores the
/// revoker's identity hash (`sha3` of the carrier's `creator_public_key`) so the
/// verifier can authorize the revocation at *read time*: a revocation takes
/// effect only when its revoker equals the resolved mandate's principal (see
/// [`MandateResolver::revocation`]). Revocation is **monotonic and terminal**:
/// the index keeps the *earliest* revocation and never clears it (no un-revoke —
/// re-authorization is a fresh mandate).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// In-payload format version.
    pub version: u8,
    /// Network binding (must match the revoked mandate's network).
    pub network_id: String,
    /// The mandate being revoked.
    pub mandate_id: String,
    /// Free-text reason (forensic; not load-bearing).
    pub reason: String,
}

impl RevocationRecord {
    pub fn new(
        network_id: impl Into<String>,
        mandate_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            version: MANDATE_FORMAT_VERSION,
            network_id: network_id.into(),
            mandate_id: mandate_id.into(),
            reason: reason.into(),
        }
    }

    /// Domain-separated canonical bytes (for the carrier record signature /
    /// future dedup). Revocations are *indexed* by `mandate_id`, so this is not
    /// an authority key, but it pins the wire format the same way mandates do.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(REVOCATION_DOMAIN_TAG);
        out.push(self.version);
        push_lp(&mut out, self.network_id.as_bytes());
        push_lp(&mut out, self.mandate_id.as_bytes());
        push_lp(&mut out, self.reason.as_bytes());
        out
    }
}

/// Versioned on-disk value for the revocation index (`CF_REVOCATION`, keyed by
/// `mandate_id || revoker_identity_hash`). The revoker lives in the KEY (that is
/// what enforces read-time authorization — see [`MandateResolver::revocation`]),
/// so the value carries only the time + a format version. The earliest time per
/// `(mandate_id, revoker)` wins (monotonic, terminal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub version: u8,
    pub revoked_at_ms: u64,
}

impl RevocationEntry {
    pub fn new(revoked_at_ms: u64) -> Self {
        Self { version: MANDATE_STORE_VERSION, revoked_at_ms }
    }
}

/// Versioned on-disk value for the act index (`CF_MANDATE_ACT`, keyed by the act
/// record_id). Carries the minimal claim needed to RECOMPUTE the flag at query
/// time without re-reading the (possibly large) act record: the referenced
/// mandate, the agent who signed, and the act's signed time. `amount` is carried
/// for when the scope-cap path activates; `op`/`zone` are intentionally absent —
/// v0 defers scope enforcement (their only sound derivation is a later,
/// separately-audited slice), so the recomputed claim uses empty op/zone and the
/// verifier only applies scope for wildcard mandates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandateActEntry {
    pub version: u8,
    pub mandate_ref: String,
    pub signer_identity_hash: String,
    pub act_timestamp_ms: u64,
    pub amount: Option<u64>,
}

impl MandateActEntry {
    pub fn new(
        mandate_ref: impl Into<String>,
        signer_identity_hash: impl Into<String>,
        act_timestamp_ms: u64,
        amount: Option<u64>,
    ) -> Self {
        Self {
            version: MANDATE_STORE_VERSION,
            mandate_ref: mandate_ref.into(),
            signer_identity_hash: signer_identity_hash.into(),
            act_timestamp_ms,
            amount,
        }
    }
}

/// The verdict on an act record that references a mandate.
///
/// Discriminants are **wire-stable** — they label metrics, are stored in the
/// flag side-CF, and may be served over the API; never renumber an existing
/// variant. Variants 9–11 are RESERVED for the deferred sub-delegation slice
/// (the enum is observational-only in v0, so adding the reachable variants
/// early costs nothing and keeps the flag space frozen).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MandateFlag {
    /// Act is by the mandated agent, within window, not revoked, in scope.
    Valid = 0,
    /// No mandate resolves for the referenced id — the claim binds the signer
    /// ONLY; the named principal (if any) is cryptographically uninvolved.
    NoChain = 1,
    /// A mandate existed but expired (act after `not_after_ms`).
    Lapsed = 2,
    /// The mandate was revoked at or before the act's signed time.
    PostRevocation = 3,
    /// Valid, in-window, un-revoked mandate, but the act is outside its scope
    /// (op / zone / amount).
    OverScope = 4,
    /// The act's signer is not the mandate's agent — using someone else's
    /// mandate. Binds the signer; *exonerates* the named principal (who
    /// authorized a different key).
    AgentMismatch = 5,
    /// The referenced mandate is missing/unparseable/structurally invalid
    /// (bad version, inverted window, malformed hashes, cross-network ref).
    Malformed = 6,
    /// A well-formed mandate, but the act precedes `not_before_ms`.
    NotYetValid = 7,
    /// The mandate is a sub-delegation (`parent_mandate_id = Some`); v0 does not
    /// verify chains, so this is an honest "not verified" rather than a false
    /// `Valid` or `NoChain`.
    UnverifiedChain = 8,
    /// RESERVED (v1 sub-delegation): chain exceeded `sub_delegation_max_depth`.
    DepthExceeded = 9,
    /// RESERVED (v1 sub-delegation): a hop's scope broadened its parent's.
    ScopeBroadened = 10,
    /// RESERVED (v1): a revocation signed by a party not authorized to revoke.
    UnauthorizedRevocation = 11,
}

#[allow(clippy::should_implement_trait)]
impl MandateFlag {
    /// All 12 variants in discriminant order (0..12) — the same index space as
    /// the `MANDATE_FLAG_TOTAL` metric array. If you add a variant, extend this
    /// array too (the count is checked by `mandate_flag_all_is_exhaustive`; the
    /// label maps are compiler-forced via `as_str`/`from_str`).
    pub const ALL: [MandateFlag; 12] = [
        Self::Valid,
        Self::NoChain,
        Self::Lapsed,
        Self::PostRevocation,
        Self::OverScope,
        Self::AgentMismatch,
        Self::Malformed,
        Self::NotYetValid,
        Self::UnverifiedChain,
        Self::DepthExceeded,
        Self::ScopeBroadened,
        Self::UnauthorizedRevocation,
    ];

    /// Stable lowercase label (metrics, API, logs). Round-trips with
    /// [`Self::from_str`].
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::NoChain => "no_chain",
            Self::Lapsed => "lapsed",
            Self::PostRevocation => "post_revocation",
            Self::OverScope => "over_scope",
            Self::AgentMismatch => "agent_mismatch",
            Self::Malformed => "malformed",
            Self::NotYetValid => "not_yet_valid",
            Self::UnverifiedChain => "unverified_chain",
            Self::DepthExceeded => "depth_exceeded",
            Self::ScopeBroadened => "scope_broadened",
            Self::UnauthorizedRevocation => "unauthorized_revocation",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "valid" => Self::Valid,
            "no_chain" => Self::NoChain,
            "lapsed" => Self::Lapsed,
            "post_revocation" => Self::PostRevocation,
            "over_scope" => Self::OverScope,
            "agent_mismatch" => Self::AgentMismatch,
            "malformed" => Self::Malformed,
            "not_yet_valid" => Self::NotYetValid,
            "unverified_chain" => Self::UnverifiedChain,
            "depth_exceeded" => Self::DepthExceeded,
            "scope_broadened" => Self::ScopeBroadened,
            "unauthorized_revocation" => Self::UnauthorizedRevocation,
            _ => return None,
        })
    }

    /// Only `Valid` confers authority. Every other flag carries zero authority
    /// (and, once the enforcement slice lands, zero consensus weight).
    pub fn is_authorized(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Whether a public status response may name the resolved mandate's
    /// PRINCIPAL for this flag — the anti-framing / anti-libel guarantee. True
    /// only when the act is genuinely attributable to that principal's mandate
    /// (the act is by the mandate's own agent). FALSE for:
    /// - `NoChain` / `Malformed` — no cryptographically-involved principal;
    /// - `AgentMismatch` — the principal authorized a *different* agent and is
    ///   EXONERATED, not party to this act;
    /// - `UnverifiedChain` and reserved variants — the chain isn't verified, so
    ///   naming the (sub-delegation) principal would over-claim.
    pub fn attributes_to_principal(&self) -> bool {
        matches!(
            self,
            Self::Valid
                | Self::Lapsed
                | Self::NotYetValid
                | Self::PostRevocation
                | Self::OverScope
        )
    }
}

/// Read-only access to mandate + revocation state, supplied by the node's CFs
/// (or an in-memory map in tests). Keeps [`evaluate_mandate`] a pure function
/// with no I/O — the verifier is the crate-extractable core.
pub trait MandateResolver {
    /// The mandate for `mandate_id`, if known to this node.
    fn mandate(&self, mandate_id: &str) -> Option<MandateRecord>;
    /// The earliest revocation (unix ms) of `mandate_id` SIGNED BY
    /// `principal_identity_hash` — i.e. authorization is enforced at READ time by
    /// the lookup key, not by a comparison after the fact. The index stores every
    /// revocation keyed by `(mandate_id, revoker)`, so a revocation by a
    /// non-principal lands under a *different* key and is simply never consulted
    /// here (it persists as forensic evidence; v1's reserved
    /// [`MandateFlag::UnauthorizedRevocation`] can surface it without a CF
    /// migration). This is what makes a spoofed revocation INERT — AND
    /// front-run-proof: an attacker's earlier revocation cannot occupy the
    /// principal's slot and block the principal's real revocation (the
    /// single-slot monotonic-min design would have that denial-of-revocation
    /// hole). Storage is unconditional + monotonic per `(mandate_id, revoker)`,
    /// so acceptance is order-independent and replay-idempotent — no ingest-time
    /// authorization gate that could diverge across nodes mid-sync, and no
    /// unbounded deferral queue.
    fn revocation(&self, mandate_id: &str, principal_identity_hash: &str) -> Option<u64>;
}

/// The act being judged: an agent-signed record that references a mandate.
pub struct MandateClaim<'a> {
    /// `sha3` of the act record's `creator_public_key` (the agent), hex.
    pub signer_identity_hash: &'a str,
    /// The act record's *own signed timestamp*, unix ms. The verdict is judged
    /// against this — NOT wall-clock — so the flag is stable over time: a
    /// record that was `Valid` when signed stays `Valid` when re-queried years
    /// later (the literal "queryable over time" differentiator vs OTS). Derive
    /// it once via [`secs_f64_to_ms_saturating`].
    pub act_timestamp_ms: u64,
    /// The leaf mandate id the act references (its signed `mandate_ref`).
    pub mandate_ref: &'a str,
    /// The act's opcode string (matched against `scope.allowed_ops`).
    pub op: &'a str,
    /// The act's zone path (matched against `scope.allowed_zones`).
    pub zone: &'a str,
    /// The act's amount, if any (matched against `scope.max_amount`).
    pub amount: Option<u64>,
    /// The evaluating node's network id (must match the mandate's binding).
    pub network_id: &'a str,
}

/// Pure, deterministic, integer-only mandate verdict. No I/O, no wall-clock —
/// the same `(claim, resolver-state)` yields the same flag on every node and at
/// every time, which is what keeps the (future) consensus-weight wiring
/// fork-safe and the query answer stable.
///
/// Flag precedence is a fixed total order (most-fundamental first), so two
/// nodes never disagree on a multiply-violating record:
/// `Malformed > NoChain > AgentMismatch > DepthExceeded > ScopeBroadened >
/// UnverifiedChain > PostRevocation > Lapsed > NotYetValid > OverScope > Valid`.
/// The order is the *sequence of checks* below (not the discriminant values —
/// e.g. `AgentMismatch`=5 outranks `PostRevocation`=3), pinned by
/// `flag_precedence_is_total_and_deterministic`. Chain-structural faults
/// (DepthExceeded/ScopeBroadened/UnverifiedChain) outrank lifecycle because a
/// chain that is too deep, broadened, or unverifiable establishes no authority
/// regardless of window/scope; `UnauthorizedRevocation`=11 is a property of a
/// revocation record, not an act, and is never returned here.
///
/// Sub-delegations are verified by walking `parent_mandate_id` to a genuine root
/// (see [`walk_chain`]); a root mandate is the one-hop base case. This is the
/// FULL verdict (scope always enforced) — the v1 semantics. v0 callers use
/// [`evaluate_mandate_v0`], which defers the leaf scope-vs-ACT check for
/// non-wildcard mandates because a sound, node-invariant op/zone derivation needs
/// a signed canonical taxonomy that does not exist yet (see
/// internal design notes Q3). The chain scope-NARROWING
/// (mandate-vs-mandate) is a pure struct comparison and is enforced even in v0.
pub fn evaluate_mandate<R: MandateResolver + ?Sized>(
    claim: &MandateClaim<'_>,
    resolver: &R,
) -> MandateFlag {
    evaluate_mandate_inner(claim, resolver, true)
}

/// v0 verdict: identical to [`evaluate_mandate`] EXCEPT scope (op/zone/amount) is
/// enforced ONLY for wildcard mandates. A non-wildcard mandate's scope is
/// *deferred* — v0 reports agent-binding + window + revocation and NEVER a
/// (possibly-wrong) `OverScope`, since enforcing op/zone against an act would
/// require deriving them from non-deterministic node state. Callers that want to
/// tell the user scope was not checked should additionally test
/// [`MandateScope::is_wildcard`] on the resolved mandate.
pub fn evaluate_mandate_v0<R: MandateResolver + ?Sized>(
    claim: &MandateClaim<'_>,
    resolver: &R,
) -> MandateFlag {
    evaluate_mandate_inner(claim, resolver, false)
}

/// v0 verdict PLUS the verified sub-delegation lineage (leaf→root) that produced
/// it. The lineage is non-empty ONLY when the verdict is [`MandateFlag::Valid`] —
/// the one verdict where every hop is proven authorizing end-to-end; every other
/// verdict returns an empty lineage, so a non-authorizing or unverifiable chain
/// never names an ancestor (anti-libel, enforced by construction in the pure
/// function — not left to the caller). Single resolver pass: the returned chain is
/// exactly the one the flag was derived from (no re-walk), so the flag and the
/// lineage can never disagree. Powers the `/mandate/status` lineage view.
pub fn evaluate_mandate_v0_with_lineage<R: MandateResolver + ?Sized>(
    claim: &MandateClaim<'_>,
    resolver: &R,
) -> (MandateFlag, Vec<(String, MandateRecord)>) {
    evaluate_mandate_inner_with_chain(claim, resolver, false)
}

fn evaluate_mandate_inner<R: MandateResolver + ?Sized>(
    claim: &MandateClaim<'_>,
    resolver: &R,
    enforce_nonwildcard_scope: bool,
) -> MandateFlag {
    // The flag is computed by ONE body ([`evaluate_mandate_inner_with_chain`]); the
    // chain projection is dropped here, so this path is byte-for-byte the prior
    // behaviour and no flag-only caller can observe a change.
    evaluate_mandate_inner_with_chain(claim, resolver, enforce_nonwildcard_scope).0
}

/// Core verdict, additionally returning the verified sub-delegation chain
/// (leaf→root). The chain is non-empty ONLY on the `Valid` path — every non-`Valid`
/// return yields an empty chain, so the anti-libel rule ("a verdict that did not
/// cleanly authorize names no one") is baked into the pure function rather than
/// trusted to callers. [`evaluate_mandate_inner`] is a `.0` projection of this, so
/// the flag is identical on both paths.
fn evaluate_mandate_inner_with_chain<R: MandateResolver + ?Sized>(
    claim: &MandateClaim<'_>,
    resolver: &R,
    enforce_nonwildcard_scope: bool,
) -> (MandateFlag, Vec<(String, MandateRecord)>) {
    // 1. Resolve the leaf. No mandate for this reference → the claim binds the
    //    signer only (NoChain), never the named principal.
    let Some(m) = resolver.mandate(claim.mandate_ref) else {
        return (MandateFlag::NoChain, Vec::new());
    };

    // 2. Structural validity of the leaf. A cross-network mandate reference is
    //    treated as malformed-for-this-network (defense in depth; ingest also
    //    refuses to store a foreign-network mandate). `Malformed` is reserved for
    //    the LEAF the act directly references — a malformed *ancestor* surfaces
    //    as `UnverifiedChain` inside the walk (we cannot anchor a genuine chain
    //    through it), keeping `Malformed`'s anti-attribution semantics crisp.
    if !m.is_well_formed() || !m.network_id.eq_ignore_ascii_case(claim.network_id) {
        return (MandateFlag::Malformed, Vec::new());
    }

    // 3. Leaf agent binding — FIRST, before the walk. This is the cheapest
    //    decisive check (one comparison, zero resolver reads), it makes
    //    `AgentMismatch` correctly outrank every chain-structural verdict, and it
    //    bounds the walk's resolver fan-out: an act by a non-agent is rejected
    //    without walking up to `MANDATE_MAX_CHAIN_DEPTH` ancestors (the public
    //    `/mandate/status` DoS guard). The signer must BE the leaf's agent — you
    //    cannot borrow another key's (broader) mandate.
    if !m.agent_identity_hash.eq_ignore_ascii_case(claim.signer_identity_hash) {
        return (MandateFlag::AgentMismatch, Vec::new());
    }

    // 4. Sub-delegation chain. Walk `parent_mandate_id` to a genuine root,
    //    enforcing genealogy + scope-narrowing + depth + network at every hop. A
    //    ROOT mandate returns a one-element chain immediately, so this is a no-op
    //    for the common case (identical behaviour to the pre-walk verifier).
    //    Structural faults (DepthExceeded > ScopeBroadened > UnverifiedChain)
    //    outrank lifecycle/scope per the documented total order.
    let chain = match walk_chain(claim.mandate_ref, m, resolver, claim.network_id) {
        Ok(c) => c,
        Err(flag) => return (flag, Vec::new()),
    };

    // 5. Per-hop revocation, against the act's *signed* time. ANY hop revoked by
    //    its OWN principal at/before the act kills the whole chain — revoking a
    //    mid-chain mandate cuts the subtree beneath it. Each hop is judged
    //    against the single leaf act timestamp (the chain is intact iff intact at
    //    the moment the act was signed). Authorization is structural: the
    //    resolver is asked only for the revocation signed by THAT hop's
    //    principal, so a spoofed revocation by anyone else is inert and cannot
    //    front-run the principal's slot.
    for (hop_id, hop) in &chain {
        if let Some(rev_ms) = resolver.revocation(hop_id, &hop.principal_identity_hash) {
            if rev_ms <= claim.act_timestamp_ms {
                return (MandateFlag::PostRevocation, Vec::new());
            }
        }
    }

    // 6. Lifecycle + scope against the LEAF only. The walk already proved the
    //    leaf's window ⊆ every ancestor's and the leaf's scope ⊆ every ancestor's
    //    (monotone narrowing), so the leaf bounds are the binding constraint —
    //    no ancestor can be lapsed/not-yet-valid or narrower for an act that
    //    satisfies the leaf.
    let leaf = &chain[0].1;
    if claim.act_timestamp_ms > leaf.not_after_ms {
        return (MandateFlag::Lapsed, Vec::new());
    }
    if claim.act_timestamp_ms < leaf.not_before_ms {
        return (MandateFlag::NotYetValid, Vec::new());
    }
    // Scope. Enforced always in v1; in v0 only for wildcard mandates (a wildcard
    // scope is a no-op anyway, so this never produces a false OverScope on the
    // deferred-scope path). NOTE: this is the leaf-scope-vs-ACT check (deferred
    // for non-wildcard in v0); it is distinct from the chain scope-NARROWING
    // (mandate-vs-mandate) in the walk, which is a pure struct comparison and is
    // therefore enforced even in v0.
    let scope_applies = enforce_nonwildcard_scope || leaf.scope.is_wildcard();
    if scope_applies
        && (!leaf.scope.allows_op(claim.op)
            || !leaf.scope.allows_zone(claim.zone)
            || leaf
                .scope
                .max_amount
                .is_some_and(|max| claim.amount.unwrap_or(0) > max))
    {
        return (MandateFlag::OverScope, Vec::new());
    }

    // Valid: the chain is proven authorizing at every hop — the ONLY verdict that
    // may surface the named lineage. `leaf`'s borrow ends at the scope check above
    // (its last use), so moving `chain` out here is borrow-clean under NLL.
    (MandateFlag::Valid, chain)
}

/// Walk a sub-delegation chain from the leaf (resolved at `leaf_id`) up to a
/// genuine root, returning the full chain `[(leaf_id, leaf), …, (root_id, root)]`
/// (each paired with the id it was resolved by, for per-hop revocation lookup) or
/// the highest-precedence structural fault. Pure: reads only the resolver, no
/// wall-clock, no float, integer/string-deterministic — the same
/// `(leaf, resolver-state)` yields the same result on every node.
///
/// Soundness rests on two invariants of the resolver's `mandate(id)` contract:
/// **(INV-A)** `Some` ⇒ the record was authenticated against its own
/// `principal_identity_hash` (live ingest: `sha3(carrier_pk)==principal`; snapshot
/// bootstrap: content-addressed + well-formed via the storage bulk-apply guard,
/// with authenticity inherited from snapshot-signer trust — see
/// `docs/AGENT-DELEGATION.md`). **(INV-B)** the link compares the child's
/// principal to the parent's AGENT. Never add an on-demand *unauthenticated*
/// parent fetch — it would void INV-A and make the chain forgeable.
fn walk_chain<R: MandateResolver + ?Sized>(
    leaf_id: &str,
    leaf: MandateRecord,
    resolver: &R,
    network_id: &str,
) -> Result<Vec<(String, MandateRecord)>, MandateFlag> {
    let mut chain: Vec<(String, MandateRecord)> = vec![(leaf_id.to_string(), leaf)];
    loop {
        // Clone the current tail (chain depth ≤ MANDATE_MAX_CHAIN_DEPTH, records
        // are small) to release the borrow before the eventual push. The `None`
        // arm is unreachable — the chain starts with the leaf and only grows —
        // but we fail closed (return, never panic) to keep the production
        // panic surface at zero (Lane-2).
        let Some((_, current_rec)) = chain.last() else {
            return Err(MandateFlag::UnverifiedChain);
        };
        let current = current_rec.clone();
        let Some(parent_id) = current.parent_mandate_id.clone() else {
            return Ok(chain); // a present, well-formed record with no parent = genuine root
        };
        // `distance` = hops from the leaf to the parent we are about to resolve
        // (leaf itself = 0). Hard bound FIRST, before any resolver read: the sole
        // termination guarantee on attacker-controlled pointers (incl. a
        // snapshot-injected storage cycle) and the DoS bound on read fan-out.
        let distance = chain.len();
        if distance > MANDATE_MAX_CHAIN_DEPTH {
            return Err(MandateFlag::DepthExceeded);
        }
        // Missing ancestor → unverifiable on THIS node. May be transient sync
        // lag (node-local-state-dependent) OR a `parent_mandate_id` no honest
        // node will ever hold (fabricated lineage). Either way non-authorizing,
        // non-attributing. NEVER treat a resolver miss as a genuine root.
        let Some(parent) = resolver.mandate(&parent_id) else {
            return Err(MandateFlag::UnverifiedChain);
        };
        // A malformed / cross-network ancestor cannot anchor a genuine chain.
        if !parent.is_well_formed() || !parent.network_id.eq_ignore_ascii_case(network_id) {
            return Err(MandateFlag::UnverifiedChain);
        }
        // Genealogy link: the child's principal must BE the parent's agent — the
        // parent delegated to exactly the key that signed the child (INV-A binds
        // child.principal == sha3(child carrier pk)). A broken link is a chain
        // that establishes no authority → unverifiable. Surfacing it as
        // `UnverifiedChain` (not a new flag) also keeps partial-sync and
        // full-sync nodes in agreement (a node missing this hop reports the same
        // flag for a different reason).
        if !current
            .principal_identity_hash
            .eq_ignore_ascii_case(&parent.agent_identity_hash)
        {
            return Err(MandateFlag::UnverifiedChain);
        }
        // Depth: every ancestor INDEPENDENTLY caps the hops below it. The parent
        // at `distance` hops from the leaf must permit ≥ `distance` levels of
        // sub-delegation. A stingy ancestor (e.g. root depth=1) cannot be
        // overridden by an intermediate declaring a larger value — the binding
        // constraint is the minimum down the chain. depth=0 ⇒ the holder may not
        // sub-delegate at all (its first child, distance=1, fails here).
        if (parent.sub_delegation_max_depth as usize) < distance {
            return Err(MandateFlag::DepthExceeded);
        }
        // Scope monotone-narrowing: the child's authority must be a subset of the
        // parent's, every dimension. Any broadening is a forged privilege
        // escalation through an intermediate and must never reach `Valid`.
        if !scope_within(&current.scope, &parent.scope)
            || current.not_before_ms < parent.not_before_ms
            || current.not_after_ms > parent.not_after_ms
        {
            return Err(MandateFlag::ScopeBroadened);
        }
        chain.push((parent_id, parent));
    }
}

/// `true` iff `child` grants no more authority than `parent` on the op/zone/amount
/// dimensions (the act-validity window is checked separately by the caller, using
/// the same inclusive `[not_before, not_after]` semantics as the lifecycle gate).
///
/// Reuses the very matchers the act-vs-scope check uses
/// ([`MandateScope::allows_op`] / [`MandateScope::allows_zone`]) so the subset
/// relation is consistent with enforcement: a child `"*"` requires a parent `"*"`
/// (`allows_op("*")`/`allows_zone("*")` are true only when the parent itself
/// holds `"*"`), and the directional zone-prefix trap is handled correctly —
/// child `"zone/A/0"` under parent `"zone/A"` is narrowing (allowed), but child
/// `"zone/A"` under parent `"zone/A/0"` is BROADENING (rejected). Amount uses an
/// explicit `None`-is-unlimited match: an unlimited child under a capped parent is
/// a broadening (a naive `unwrap_or(...)` would silently treat the child as `0`
/// and miss it).
fn scope_within(child: &MandateScope, parent: &MandateScope) -> bool {
    child.allowed_ops.iter().all(|op| parent.allows_op(op))
        && child.allowed_zones.iter().all(|z| parent.allows_zone(z))
        && match (child.max_amount, parent.max_amount) {
            (_, None) => true,        // parent unlimited covers any child cap
            (None, Some(_)) => false, // unlimited child under a capped parent → broaden
            (Some(c), Some(p)) => c <= p,
        }
}

/// Single, documented, boundary-safe conversion of a record's f64-second
/// timestamp to integer unix milliseconds. ONE call site for the whole mandate
/// layer — divergent ad-hoc conversions are exactly the f64 fork class this
/// codebase has bled from. Non-finite / non-positive → 0; overflow saturates.
pub fn secs_f64_to_ms_saturating(ts_secs: f64) -> u64 {
    // NaN and non-positive → 0. Positive infinity falls through and saturates
    // to u64::MAX via the overflow branch below (that's the "saturating" part).
    if ts_secs.is_nan() || ts_secs <= 0.0 {
        return 0;
    }
    let ms = (ts_secs * 1000.0).floor();
    if ms >= u64::MAX as f64 {
        u64::MAX
    } else {
        ms as u64
    }
}

/// `true` iff `s` is a 64-char lowercase-or-uppercase hex string (a 256-bit
/// identity hash).
fn is_identity_hash(s: &str) -> bool {
    s.len() == IDENTITY_HASH_HEX_LEN && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// u32-BE length prefix + bytes. The universal variable-field encoder — kills
/// concatenation ambiguity (`["a","bc"]` vs `["ab","c"]`).
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Sorted + deduped clone — canonicalizes a scope vector so member-equal scopes
/// share one canonical encoding (and thus one `mandate_id`).
fn sorted_deduped(v: &[String]) -> Vec<String> {
    let mut s: Vec<String> = v.to_vec();
    s.sort();
    s.dedup();
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: &str = "testnet";
    // Two distinct 64-hex identity hashes.
    const PRINCIPAL: &str = "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddee";
    const AGENT: &str = "bb11223344556677889900aabbccddeeff00112233445566778899aabbccddee";
    const OTHER: &str = "cc11223344556677889900aabbccddeeff00112233445566778899aabbccddee";
    // A fourth distinct identity for multi-hop chain tests (P→A→B→G).
    const FOURTH: &str = "dd11223344556677889900aabbccddeeff00112233445566778899aabbccddee";

    /// Minimal in-memory resolver for the pure verifier. Revocations are keyed by
    /// `(mandate_id, revoker)` — read-time authorization by lookup key.
    #[derive(Default)]
    struct MapResolver {
        mandates: std::collections::HashMap<String, MandateRecord>,
        revocations: std::collections::HashMap<(String, String), u64>,
    }
    impl MapResolver {
        fn with(m: MandateRecord) -> Self {
            let mut r = Self::default();
            r.mandates.insert(m.mandate_id(), m);
            r
        }
        /// Record a revocation of `id` by `revoker` at `at_ms` (monotonic per
        /// `(id, revoker)`: earliest wins). Revoker hashes normalize to lowercase.
        fn revoke(&mut self, id: &str, at_ms: u64, revoker: &str) {
            let key = (id.to_string(), revoker.to_ascii_lowercase());
            let e = self.revocations.entry(key).or_insert(at_ms);
            if at_ms < *e {
                *e = at_ms;
            }
        }
        /// Insert a mandate keyed by its content id (the production invariant) and
        /// return that id — for building chains where a child references a parent.
        fn add(&mut self, m: MandateRecord) -> String {
            let id = m.mandate_id();
            self.mandates.insert(id.clone(), m);
            id
        }
    }

    /// Build a (possibly sub-delegated) mandate. `parent = None` is a root.
    #[allow(clippy::too_many_arguments)]
    fn mk(
        principal: &str,
        agent: &str,
        scope: MandateScope,
        nb: u64,
        na: u64,
        max_depth: u8,
        parent: Option<&str>,
        nonce: &str,
    ) -> MandateRecord {
        let mut m =
            MandateRecord::new_root(NET, principal, agent, scope, nb, na, max_depth, nonce);
        m.parent_mandate_id = parent.map(|s| s.to_string());
        m
    }

    /// `MandateScope` with explicit ops/zones/amount (test ergonomics).
    fn scope(ops: &[&str], zones: &[&str], amount: Option<u64>) -> MandateScope {
        MandateScope {
            allowed_ops: ops.iter().map(|s| s.to_string()).collect(),
            allowed_zones: zones.iter().map(|s| s.to_string()).collect(),
            max_amount: amount,
        }
    }
    impl MandateResolver for MapResolver {
        fn mandate(&self, id: &str) -> Option<MandateRecord> {
            self.mandates.get(id).cloned()
        }
        fn revocation(&self, id: &str, principal_identity_hash: &str) -> Option<u64> {
            self.revocations
                .get(&(id.to_string(), principal_identity_hash.to_ascii_lowercase()))
                .copied()
        }
    }

    fn root(scope: MandateScope, nb: u64, na: u64) -> MandateRecord {
        MandateRecord::new_root(NET, PRINCIPAL, AGENT, scope, nb, na, 0, "n0")
    }

    fn claim<'a>(
        signer: &'a str,
        ts: u64,
        mref: &'a str,
        op: &'a str,
        zone: &'a str,
        amount: Option<u64>,
    ) -> MandateClaim<'a> {
        MandateClaim {
            signer_identity_hash: signer,
            act_timestamp_ms: ts,
            mandate_ref: mref,
            op,
            zone,
            amount,
            network_id: NET,
        }
    }

    #[test]
    fn canonical_bytes_are_order_independent_for_scope() {
        let a = root(
            MandateScope {
                allowed_ops: vec!["transfer".into(), "stake".into(), "transfer".into()],
                allowed_zones: vec!["zone/b".into(), "zone/a".into()],
                max_amount: Some(100),
            },
            0,
            10,
        );
        let b = root(
            MandateScope {
                allowed_ops: vec!["stake".into(), "transfer".into()],
                allowed_zones: vec!["zone/a".into(), "zone/b".into(), "zone/a".into()],
                max_amount: Some(100),
            },
            0,
            10,
        );
        // Same membership, different input order/dupes → identical id.
        assert_eq!(a.mandate_id(), b.mandate_id());
    }

    #[test]
    fn canonicalized_sorts_dedups_scope_idempotent_and_byte_stable() {
        let a = root(
            MandateScope {
                allowed_ops: vec!["b".into(), "a".into(), "a".into()],
                allowed_zones: vec!["z2".into(), "z1".into()],
                max_amount: Some(5),
            },
            0,
            10,
        );
        let c = a.canonicalized();
        assert_eq!(c.scope.allowed_ops, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(c.scope.allowed_zones, vec!["z1".to_string(), "z2".to_string()]);
        // id was already order-independent; canonicalizing must not change it.
        assert_eq!(c.mandate_id(), a.mandate_id());
        // idempotent
        assert_eq!(c.canonicalized(), c);
        // a differently-ordered logically-equal mandate canonicalizes to a
        // byte-identical serialization (the stored-blob determinism guarantee).
        let b = root(
            MandateScope {
                allowed_ops: vec!["a".into(), "b".into()],
                allowed_zones: vec!["z1".into(), "z2".into()],
                max_amount: Some(5),
            },
            0,
            10,
        );
        assert_eq!(
            serde_json::to_string(&a.canonicalized()).unwrap(),
            serde_json::to_string(&b.canonicalized()).unwrap()
        );
    }

    #[test]
    fn new_root_lowercases_scope_so_mixed_case_is_never_silently_unenforceable() {
        // A principal who writes "Transfer"/"Zone/A" must not get a mandate that
        // silently never matches: the matcher is exact and the op vocabulary
        // (LedgerOp::as_str + the action/kind convention) is lowercase. new_root
        // normalizes at the issuance edge (internal design notes §3).
        let m = root(
            MandateScope {
                allowed_ops: vec!["Transfer".into(), "STAKE".into()],
                allowed_zones: vec!["Zone/A".into()],
                max_amount: Some(100),
            },
            0,
            10,
        );
        assert_eq!(m.scope.allowed_ops, vec!["transfer".to_string(), "stake".to_string()]);
        assert_eq!(m.scope.allowed_zones, vec!["zone/a".to_string()]);
        assert!(m.scope.allows_op("transfer")); // now matches a lowercase act op
        assert!(!m.scope.allows_op("Transfer")); // matcher stays exact (not broadened)
        assert_eq!(m.scope.normalized(), m.scope); // idempotent
    }

    #[test]
    fn store_entries_roundtrip_and_carry_version() {
        let rev = RevocationEntry::new(123);
        assert_eq!(rev.version, MANDATE_STORE_VERSION);
        let j = serde_json::to_string(&rev).unwrap();
        assert_eq!(serde_json::from_str::<RevocationEntry>(&j).unwrap(), rev);

        let act = MandateActEntry::new("mref", AGENT, 456, Some(7));
        assert_eq!(act.version, MANDATE_STORE_VERSION);
        let j2 = serde_json::to_string(&act).unwrap();
        assert_eq!(serde_json::from_str::<MandateActEntry>(&j2).unwrap(), act);
    }

    #[test]
    fn mandate_id_changes_with_nonce_and_fields() {
        let base = root(MandateScope::wildcard(), 0, 10);
        let mut diff_nonce = base.clone();
        diff_nonce.nonce = "n1".into();
        assert_ne!(base.mandate_id(), diff_nonce.mandate_id());

        let mut diff_amount = base.clone();
        diff_amount.scope.max_amount = Some(1);
        assert_ne!(base.mandate_id(), diff_amount.mandate_id());

        let mut diff_window = base.clone();
        diff_window.not_after_ms = 11;
        assert_ne!(base.mandate_id(), diff_window.mandate_id());
    }

    #[test]
    fn canonical_encoding_is_byte_pinned() {
        // A fully-specified fixture, hand-encoded independently of the encoder.
        // If the wire format changes, this MUST be updated deliberately — that
        // is the point (the encoding is a one-way door).
        let m = MandateRecord::new_root(
            "n",
            "ab", // not a real 64-hex hash; canonical bytes don't validate length
            "cd",
            MandateScope {
                allowed_ops: vec!["x".into()],
                allowed_zones: vec![],
                max_amount: Some(1),
            },
            2,
            3,
            0,
            "z",
        );
        let mut expected = Vec::new();
        expected.extend_from_slice(b"ELARA_MANDATE_V1");
        expected.push(1u8); // version
        expected.extend_from_slice(&1u32.to_be_bytes()); // network_id len
        expected.extend_from_slice(b"n");
        expected.extend_from_slice(&2u32.to_be_bytes()); // principal len
        expected.extend_from_slice(b"ab");
        expected.extend_from_slice(&2u32.to_be_bytes()); // agent len
        expected.extend_from_slice(b"cd");
        expected.extend_from_slice(&1u32.to_be_bytes()); // ops count
        expected.extend_from_slice(&1u32.to_be_bytes()); // op[0] len
        expected.extend_from_slice(b"x");
        expected.extend_from_slice(&0u32.to_be_bytes()); // zones count
        expected.push(1u8); // max_amount = Some
        expected.extend_from_slice(&1u64.to_be_bytes());
        expected.extend_from_slice(&2u64.to_be_bytes()); // not_before
        expected.extend_from_slice(&3u64.to_be_bytes()); // not_after
        expected.push(0u8); // sub_delegation_max_depth
        expected.push(0u8); // parent_mandate_id = None
        expected.extend_from_slice(&1u32.to_be_bytes()); // nonce len
        expected.extend_from_slice(b"z");
        assert_eq!(m.canonical_signing_bytes(), expected);
        assert_eq!(m.mandate_id(), sha3_256_hex(&expected));
    }

    #[test]
    fn happy_path_is_valid() {
        let m = root(
            MandateScope {
                allowed_ops: vec!["transfer".into()],
                allowed_zones: vec!["zone/a".into()],
                max_amount: Some(100),
            },
            0,
            1000,
        );
        let id = m.mandate_id();
        let r = MapResolver::with(m);
        let c = claim(AGENT, 500, &id, "transfer", "zone/a", Some(50));
        assert_eq!(evaluate_mandate(&c, &r), MandateFlag::Valid);
    }

    #[test]
    fn no_chain_when_unresolved() {
        let r = MapResolver::default();
        let c = claim(AGENT, 500, "deadbeef", "transfer", "zone/a", None);
        assert_eq!(evaluate_mandate(&c, &r), MandateFlag::NoChain);
    }

    #[test]
    fn agent_mismatch_blocks_borrowed_mandate() {
        let m = root(MandateScope::wildcard(), 0, 1000);
        let id = m.mandate_id();
        let r = MapResolver::with(m);
        // OTHER key tries to use AGENT's mandate.
        let c = claim(OTHER, 500, &id, "transfer", "zone/a", None);
        assert_eq!(evaluate_mandate(&c, &r), MandateFlag::AgentMismatch);
    }

    #[test]
    fn post_revocation_is_inclusive_and_directional() {
        let m = root(MandateScope::wildcard(), 0, 1000);
        let id = m.mandate_id();
        let mut r = MapResolver::with(m);
        r.revoke(&id, 400, PRINCIPAL);
        // act at revocation instant → post-revocation (authority ended at 400).
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 400, &id, "x", "z", None), &r),
            MandateFlag::PostRevocation
        );
        // act after revocation → post-revocation.
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 401, &id, "x", "z", None), &r),
            MandateFlag::PostRevocation
        );
        // act strictly before revocation → not post-revocation (valid here).
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 399, &id, "x", "z", None), &r),
            MandateFlag::Valid
        );
    }

    #[test]
    fn lapsed_and_not_yet_valid_window_edges() {
        let m = root(MandateScope::wildcard(), 100, 200);
        let id = m.mandate_id();
        let r = MapResolver::with(m);
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 99, &id, "x", "z", None), &r),
            MandateFlag::NotYetValid
        );
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 100, &id, "x", "z", None), &r),
            MandateFlag::Valid
        );
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 200, &id, "x", "z", None), &r),
            MandateFlag::Valid
        );
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 201, &id, "x", "z", None), &r),
            MandateFlag::Lapsed
        );
    }

    #[test]
    fn over_scope_op_zone_and_amount() {
        let m = root(
            MandateScope {
                allowed_ops: vec!["transfer".into()],
                allowed_zones: vec!["zone/a".into()],
                max_amount: Some(100),
            },
            0,
            1000,
        );
        let id = m.mandate_id();
        let r = MapResolver::with(m);
        // wrong op
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 1, &id, "stake", "zone/a", Some(1)), &r),
            MandateFlag::OverScope
        );
        // wrong zone
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 1, &id, "transfer", "zone/b", Some(1)), &r),
            MandateFlag::OverScope
        );
        // amount over cap
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 1, &id, "transfer", "zone/a", Some(101)), &r),
            MandateFlag::OverScope
        );
    }

    #[test]
    fn is_wildcard_detects_unrestricted_scope() {
        assert!(MandateScope::wildcard().is_wildcard());
        assert!(!MandateScope {
            allowed_ops: vec!["transfer".into()],
            allowed_zones: vec!["*".into()],
            max_amount: None,
        }
        .is_wildcard()); // restricted ops
        assert!(!MandateScope {
            allowed_ops: vec!["*".into()],
            allowed_zones: vec!["*".into()],
            max_amount: Some(100),
        }
        .is_wildcard()); // amount cap
    }

    #[test]
    fn v0_defers_scope_for_nonwildcard_but_keeps_lifecycle_and_agent() {
        // A non-wildcard mandate evaluated against the v0 deferred-claim shape
        // (op=""/zone=""/amount=None). evaluate_mandate (v1) would say OverScope;
        // evaluate_mandate_v0 must NOT — scope is deferred — but window/agent/
        // revocation still apply.
        let m = root(
            MandateScope {
                allowed_ops: vec!["transfer".into()],
                allowed_zones: vec!["zone/a".into()],
                max_amount: Some(100),
            },
            100,
            200,
        );
        let id = m.mandate_id();
        let mut r = MapResolver::with(m);

        // The v0 deferred-claim shape uses empty op/zone (scope not derived).
        // v1 full eval: empty op/zone trip the non-wildcard scope → OverScope.
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 150, &id, "", "", None), &r),
            MandateFlag::OverScope
        );
        // v0: scope deferred → Valid (in window, right agent, not revoked).
        assert_eq!(
            evaluate_mandate_v0(&claim(AGENT, 150, &id, "", "", None), &r),
            MandateFlag::Valid
        );
        // v0 still enforces window.
        assert_eq!(
            evaluate_mandate_v0(&claim(AGENT, 99, &id, "", "", None), &r),
            MandateFlag::NotYetValid
        );
        assert_eq!(
            evaluate_mandate_v0(&claim(AGENT, 201, &id, "", "", None), &r),
            MandateFlag::Lapsed
        );
        // v0 still enforces agent binding.
        assert_eq!(
            evaluate_mandate_v0(&claim(OTHER, 150, &id, "", "", None), &r),
            MandateFlag::AgentMismatch
        );
        // v0 still enforces (read-time-authorized) revocation.
        r.revoke(&id, 120, PRINCIPAL);
        assert_eq!(
            evaluate_mandate_v0(&claim(AGENT, 150, &id, "", "", None), &r),
            MandateFlag::PostRevocation
        );
    }

    #[test]
    fn v0_equals_full_eval_for_wildcard() {
        let m = root(MandateScope::wildcard(), 0, 1000);
        let id = m.mandate_id();
        let r = MapResolver::with(m);
        let c = claim(AGENT, 500, &id, "anything", "any/zone", Some(999));
        assert_eq!(evaluate_mandate_v0(&c, &r), evaluate_mandate(&c, &r));
        assert_eq!(evaluate_mandate_v0(&c, &r), MandateFlag::Valid);
    }

    #[test]
    fn zone_prefix_matching() {
        let m = root(
            MandateScope {
                allowed_ops: vec!["*".into()],
                allowed_zones: vec!["zone/a".into()],
                max_amount: None,
            },
            0,
            1000,
        );
        let id = m.mandate_id();
        let r = MapResolver::with(m);
        // exact + child covered
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 1, &id, "x", "zone/a", None), &r),
            MandateFlag::Valid
        );
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 1, &id, "x", "zone/a/0", None), &r),
            MandateFlag::Valid
        );
        // sibling-prefix NOT covered ("zone/ab" must not match "zone/a")
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 1, &id, "x", "zone/ab", None), &r),
            MandateFlag::OverScope
        );
    }

    #[test]
    fn unverified_chain_when_ancestor_missing() {
        // A sub-delegation whose parent this node has not synced is honestly
        // "unverified" (node-local-state-dependent), never a false Valid/NoChain.
        let m = mk(AGENT, OTHER, MandateScope::wildcard(), 0, 1000, 0, Some("parent"), "x");
        let r = MapResolver::with(m.clone());
        let id = m.mandate_id();
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 1, &id, "x", "z", None), &r),
            MandateFlag::UnverifiedChain
        );
    }

    #[test]
    fn subdelegation_two_hop_chain_is_valid() {
        // P→A (root, permits 1 level), A→G (leaf). Act by G verifies to a root.
        let mut r = MapResolver::default();
        let r_id = r.add(mk(PRINCIPAL, AGENT, MandateScope::wildcard(), 0, 1000, 1, None, "r"));
        let l_id = r.add(mk(AGENT, OTHER, MandateScope::wildcard(), 0, 1000, 0, Some(&r_id), "l"));
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 500, &l_id, "x", "z", None), &r),
            MandateFlag::Valid
        );
        // And the production v0 path agrees on a wildcard chain.
        assert_eq!(
            evaluate_mandate_v0(&claim(OTHER, 500, &l_id, "x", "z", None), &r),
            MandateFlag::Valid
        );
    }

    #[test]
    fn lineage_valid_root_is_single_hop_naming_leaf_principal() {
        // A genuine root: the lineage is one hop (the leaf is its own root).
        let m = root(MandateScope::wildcard(), 0, 1000);
        let id = m.mandate_id();
        let r = MapResolver::with(m);
        let (flag, chain) =
            evaluate_mandate_v0_with_lineage(&claim(AGENT, 500, &id, "x", "z", None), &r);
        assert_eq!(flag, MandateFlag::Valid);
        // The flag is the `.0` projection of this — the chain-less path must agree.
        assert_eq!(
            flag,
            evaluate_mandate_v0(&claim(AGENT, 500, &id, "x", "z", None), &r)
        );
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].0, id);
        assert!(chain[0].1.principal_identity_hash.eq_ignore_ascii_case(PRINCIPAL));
        assert!(chain[0].1.agent_identity_hash.eq_ignore_ascii_case(AGENT));
    }

    #[test]
    fn lineage_valid_two_hop_is_ordered_leaf_to_root() {
        // P→A (root) → A→G (leaf); act by G. Lineage = [leaf, root], leaf first.
        let mut r = MapResolver::default();
        let r_id = r.add(mk(PRINCIPAL, AGENT, MandateScope::wildcard(), 0, 1000, 1, None, "r"));
        let l_id = r.add(mk(AGENT, OTHER, MandateScope::wildcard(), 0, 1000, 0, Some(&r_id), "l"));
        let (flag, chain) =
            evaluate_mandate_v0_with_lineage(&claim(OTHER, 500, &l_id, "x", "z", None), &r);
        assert_eq!(flag, MandateFlag::Valid);
        assert_eq!(chain.len(), 2);
        // hop 0 = leaf = the immediate authorizer (A delegated to G).
        assert_eq!(chain[0].0, l_id);
        assert!(chain[0].1.principal_identity_hash.eq_ignore_ascii_case(AGENT));
        assert!(chain[0].1.agent_identity_hash.eq_ignore_ascii_case(OTHER));
        // hop 1 = root (P delegated to A).
        assert_eq!(chain[1].0, r_id);
        assert!(chain[1].1.principal_identity_hash.eq_ignore_ascii_case(PRINCIPAL));
        assert!(chain[1].1.agent_identity_hash.eq_ignore_ascii_case(AGENT));
    }

    #[test]
    fn lineage_is_empty_for_every_non_valid_verdict() {
        // AgentMismatch — a non-agent signer: the verdict names no one.
        let m = root(MandateScope::wildcard(), 0, 1000);
        let id = m.mandate_id();
        let r = MapResolver::with(m);
        let (flag, chain) =
            evaluate_mandate_v0_with_lineage(&claim(OTHER, 500, &id, "x", "z", None), &r);
        assert_eq!(flag, MandateFlag::AgentMismatch);
        assert!(chain.is_empty(), "AgentMismatch must name no one");

        // NoChain — an unresolved reference.
        let empty = MapResolver::default();
        let (flag, chain) = evaluate_mandate_v0_with_lineage(
            &claim(AGENT, 500, "deadbeef", "x", "z", None),
            &empty,
        );
        assert_eq!(flag, MandateFlag::NoChain);
        assert!(chain.is_empty());

        // PostRevocation — a fully-WALKED chain that the leaf's principal revoked
        // before the act. The chain exists, but the verdict is non-authorizing, so
        // the lineage is STILL empty (the anti-libel rule, enforced in the pure fn).
        let mut rr = MapResolver::default();
        let r_id = rr.add(mk(PRINCIPAL, AGENT, MandateScope::wildcard(), 0, 1000, 1, None, "r"));
        let l_id = rr.add(mk(AGENT, OTHER, MandateScope::wildcard(), 0, 1000, 0, Some(&r_id), "l"));
        rr.revoke(&l_id, 100, AGENT); // the leaf's principal (A) revokes it
        let (flag, chain) =
            evaluate_mandate_v0_with_lineage(&claim(OTHER, 500, &l_id, "x", "z", None), &rr);
        assert_eq!(flag, MandateFlag::PostRevocation);
        assert!(chain.is_empty(), "a walked-but-revoked chain names no one");
    }

    #[test]
    fn subdelegation_three_hop_chain_is_valid() {
        // P→A→B→G, root permits depth 2.
        let mut r = MapResolver::default();
        let r_id = r.add(mk(PRINCIPAL, AGENT, MandateScope::wildcard(), 0, 1000, 2, None, "r"));
        let m_id = r.add(mk(AGENT, FOURTH, MandateScope::wildcard(), 0, 1000, 1, Some(&r_id), "m"));
        let l_id = r.add(mk(FOURTH, OTHER, MandateScope::wildcard(), 0, 1000, 0, Some(&m_id), "l"));
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 500, &l_id, "x", "z", None), &r),
            MandateFlag::Valid
        );
    }

    #[test]
    fn broken_genealogy_link_is_unverified() {
        // Leaf.principal (OTHER) is NOT the root's agent (AGENT) — the parent
        // never delegated to this child. Not a genuine chain.
        let mut r = MapResolver::default();
        let r_id = r.add(mk(PRINCIPAL, AGENT, MandateScope::wildcard(), 0, 1000, 1, None, "r"));
        let l_id = r.add(mk(OTHER, FOURTH, MandateScope::wildcard(), 0, 1000, 0, Some(&r_id), "l"));
        assert_eq!(
            evaluate_mandate(&claim(FOURTH, 500, &l_id, "x", "z", None), &r),
            MandateFlag::UnverifiedChain
        );
    }

    #[test]
    fn scope_broadened_ops_zones_window() {
        // ops broadening: leaf adds "stake" the root never granted.
        let mut r = MapResolver::default();
        let r_id = r.add(mk(PRINCIPAL, AGENT, scope(&["transfer"], &["*"], None), 0, 1000, 1, None, "r"));
        let l_id = r.add(mk(AGENT, OTHER, scope(&["transfer", "stake"], &["*"], None), 0, 1000, 0, Some(&r_id), "l"));
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 1, &l_id, "transfer", "z", None), &r),
            MandateFlag::ScopeBroadened
        );
        // zone broadening (prefix direction): child "zone/a" is BROADER than
        // parent "zone/a/0" (covers zone/a/b too).
        let mut r2 = MapResolver::default();
        let r2_id = r2.add(mk(PRINCIPAL, AGENT, scope(&["*"], &["zone/a/0"], None), 0, 1000, 1, None, "r"));
        let l2_id = r2.add(mk(AGENT, OTHER, scope(&["*"], &["zone/a"], None), 0, 1000, 0, Some(&r2_id), "l"));
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 1, &l2_id, "x", "zone/a", None), &r2),
            MandateFlag::ScopeBroadened
        );
        // window broadening: leaf outlives the parent's authority.
        let mut r3 = MapResolver::default();
        let r3_id = r3.add(mk(PRINCIPAL, AGENT, MandateScope::wildcard(), 100, 200, 1, None, "r"));
        let l3_id = r3.add(mk(AGENT, OTHER, MandateScope::wildcard(), 50, 300, 0, Some(&r3_id), "l"));
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 150, &l3_id, "x", "z", None), &r3),
            MandateFlag::ScopeBroadened
        );
    }

    #[test]
    fn child_none_amount_under_capped_parent_is_scope_broadened() {
        // THE silent-wrong spot: an UNLIMITED child under a capped parent is a
        // broadening. A naive `unwrap_or(0)` would treat the child as 0 (narrowest)
        // and wave it through.
        let mut r = MapResolver::default();
        let r_id = r.add(mk(PRINCIPAL, AGENT, scope(&["*"], &["*"], Some(100)), 0, 1000, 1, None, "r"));
        let l_id = r.add(mk(AGENT, OTHER, scope(&["*"], &["*"], None), 0, 1000, 0, Some(&r_id), "l"));
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 1, &l_id, "x", "z", None), &r),
            MandateFlag::ScopeBroadened
        );
        // A capped child WITHIN the parent's cap is fine (narrowing).
        let mut r2 = MapResolver::default();
        let r2_id = r2.add(mk(PRINCIPAL, AGENT, scope(&["*"], &["*"], Some(100)), 0, 1000, 1, None, "r"));
        let l2_id = r2.add(mk(AGENT, OTHER, scope(&["*"], &["*"], Some(50)), 0, 1000, 0, Some(&r2_id), "l"));
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 1, &l2_id, "x", "z", Some(40)), &r2),
            MandateFlag::Valid
        );
    }

    #[test]
    fn depth_exceeded_when_ancestor_forbids_subdelegation() {
        // Root depth=0 → permits no sub-delegation; its first child fails.
        let mut r = MapResolver::default();
        let r_id = r.add(mk(PRINCIPAL, AGENT, MandateScope::wildcard(), 0, 1000, 0, None, "r"));
        let l_id = r.add(mk(AGENT, OTHER, MandateScope::wildcard(), 0, 1000, 0, Some(&r_id), "l"));
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 1, &l_id, "x", "z", None), &r),
            MandateFlag::DepthExceeded
        );
    }

    #[test]
    fn depth_cap_is_not_gameable_by_an_intermediate() {
        // Root permits only depth 1, but the intermediate declares 255. The
        // BINDING constraint is the stingy ancestor: a 3rd hop is DepthExceeded.
        let mut r = MapResolver::default();
        let r_id = r.add(mk(PRINCIPAL, AGENT, MandateScope::wildcard(), 0, 1000, 1, None, "r"));
        let m_id = r.add(mk(AGENT, FOURTH, MandateScope::wildcard(), 0, 1000, 255, Some(&r_id), "m"));
        let l_id = r.add(mk(FOURTH, OTHER, MandateScope::wildcard(), 0, 1000, 0, Some(&m_id), "l"));
        // At distance 2 the root (depth=1) is exceeded.
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 1, &l_id, "x", "z", None), &r),
            MandateFlag::DepthExceeded
        );
    }

    #[test]
    fn hard_walk_cap_terminates_a_storage_cycle() {
        // Simulate a snapshot-injected storage cycle (a mandate stored under a
        // non-content-address key pointing at itself). The hard cap is the SOLE
        // termination guard here — the content-address fixpoint that makes cycles
        // infeasible on the ingest path does not hold for a tampered store.
        let mut m = MandateRecord::new_root(NET, OTHER, OTHER, MandateScope::wildcard(), 0, 1000, 255, "cyc");
        m.parent_mandate_id = Some("self".to_string());
        let mut r = MapResolver::default();
        r.mandates.insert("self".to_string(), m);
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 500, "self", "x", "z", None), &r),
            MandateFlag::DepthExceeded
        );
    }

    #[test]
    fn malformed_ancestor_is_unverified_not_malformed() {
        // A bad-version ANCESTOR cannot anchor a genuine chain → UnverifiedChain.
        // Top-level Malformed stays reserved for the LEAF the act references.
        let mut bad_root = mk(PRINCIPAL, AGENT, MandateScope::wildcard(), 0, 1000, 1, None, "r");
        bad_root.version = 2;
        let mut r = MapResolver::default();
        let r_id = r.add(bad_root);
        let l_id = r.add(mk(AGENT, OTHER, MandateScope::wildcard(), 0, 1000, 0, Some(&r_id), "l"));
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 1, &l_id, "x", "z", None), &r),
            MandateFlag::UnverifiedChain
        );
    }

    #[test]
    fn per_hop_revocation_of_midchain_kills_the_subtree() {
        let mut r = MapResolver::default();
        let r_id = r.add(mk(PRINCIPAL, AGENT, MandateScope::wildcard(), 0, 1000, 1, None, "r"));
        let l_id = r.add(mk(AGENT, OTHER, MandateScope::wildcard(), 0, 1000, 0, Some(&r_id), "l"));
        // Revoke the ROOT (by its own principal P) at t=300.
        r.revoke(&r_id, 300, PRINCIPAL);
        // Act after the revocation → the whole chain is dead.
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 500, &l_id, "x", "z", None), &r),
            MandateFlag::PostRevocation
        );
        // Act BEFORE the revocation → still valid (judged at the act's signed time).
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 200, &l_id, "x", "z", None), &r),
            MandateFlag::Valid
        );
    }

    #[test]
    fn midchain_revocation_by_non_principal_is_inert() {
        // A revocation of the root signed by anyone but the root's principal is
        // inert (read-time authorization by lookup key, per-hop).
        let mut r = MapResolver::default();
        let r_id = r.add(mk(PRINCIPAL, AGENT, MandateScope::wildcard(), 0, 1000, 1, None, "r"));
        let l_id = r.add(mk(AGENT, OTHER, MandateScope::wildcard(), 0, 1000, 0, Some(&r_id), "l"));
        r.revoke(&r_id, 1, OTHER); // spoofed revoker
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 500, &l_id, "x", "z", None), &r),
            MandateFlag::Valid
        );
    }

    #[test]
    fn chain_flag_precedence_is_total() {
        // AgentMismatch (leaf check, before walk) outranks every chain verdict.
        let mut r = MapResolver::default();
        let r_id = r.add(mk(PRINCIPAL, AGENT, MandateScope::wildcard(), 0, 1000, 0, None, "r"));
        let l_id = r.add(mk(AGENT, OTHER, MandateScope::wildcard(), 0, 1000, 0, Some(&r_id), "l"));
        // Wrong signer on a (would-be DepthExceeded) chain → AgentMismatch wins.
        assert_eq!(
            evaluate_mandate(&claim(FOURTH, 1, &l_id, "x", "z", None), &r),
            MandateFlag::AgentMismatch
        );
        // DepthExceeded outranks ScopeBroadened: a hop that both forbids depth
        // AND is broadened reports DepthExceeded (depth checked first).
        let mut r2 = MapResolver::default();
        let r2_id = r2.add(mk(PRINCIPAL, AGENT, scope(&["transfer"], &["*"], None), 0, 1000, 0, None, "r"));
        let l2_id = r2.add(mk(AGENT, OTHER, scope(&["transfer", "stake"], &["*"], None), 0, 1000, 0, Some(&r2_id), "l"));
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 1, &l2_id, "transfer", "z", None), &r2),
            MandateFlag::DepthExceeded
        );
    }

    #[test]
    fn malformed_on_bad_version_window_hash_and_network() {
        // bad version
        let mut m = root(MandateScope::wildcard(), 0, 1000);
        m.version = 2;
        let id = m.mandate_id();
        let r = MapResolver::with(m);
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 1, &id, "x", "z", None), &r),
            MandateFlag::Malformed
        );

        // inverted window
        let m2 = root(MandateScope::wildcard(), 1000, 1000);
        let id2 = m2.mandate_id();
        let r2 = MapResolver::with(m2);
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 1, &id2, "x", "z", None), &r2),
            MandateFlag::Malformed
        );

        // malformed agent hash
        let m3 = MandateRecord::new_root(NET, PRINCIPAL, "tooshort", MandateScope::wildcard(), 0, 10, 0, "n");
        let id3 = m3.mandate_id();
        let r3 = MapResolver::with(m3);
        assert_eq!(
            evaluate_mandate(&claim("tooshort", 1, &id3, "x", "z", None), &r3),
            MandateFlag::Malformed
        );

        // cross-network reference
        let m4 = root(MandateScope::wildcard(), 0, 1000);
        let id4 = m4.mandate_id();
        let r4 = MapResolver::with(m4);
        let mut c = claim(AGENT, 1, &id4, "x", "z", None);
        c.network_id = "mainnet";
        assert_eq!(evaluate_mandate(&c, &r4), MandateFlag::Malformed);
    }

    #[test]
    fn flag_precedence_is_total_and_deterministic() {
        // Construct a record that simultaneously trips multiple conditions and
        // assert the documented precedence holds at each level.
        // AgentMismatch (wrong signer) outranks lifecycle/scope: even an expired,
        // revoked, out-of-scope act by the WRONG agent reports AgentMismatch.
        let m = root(
            MandateScope {
                allowed_ops: vec!["transfer".into()],
                allowed_zones: vec!["zone/a".into()],
                max_amount: Some(10),
            },
            100,
            200,
        );
        let id = m.mandate_id();
        let mut r = MapResolver::with(m);
        r.revoke(&id, 150, PRINCIPAL);
        // wrong agent + after window + revoked + out of scope → AgentMismatch wins
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 999, &id, "stake", "zone/z", Some(99)), &r),
            MandateFlag::AgentMismatch
        );
        // right agent, after window AND revoked → PostRevocation outranks Lapsed
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 999, &id, "transfer", "zone/a", Some(1)), &r),
            MandateFlag::PostRevocation
        );
        // right agent, after window, NOT revoked-before-act (revoke at 150, act at 120)
        // act 120 is in-window-ish? window 100..200, act 120 in window, revoked at 150>120
        // → not post-revocation, in window, in scope → Valid
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 120, &id, "transfer", "zone/a", Some(1)), &r),
            MandateFlag::Valid
        );
    }

    #[test]
    fn malformed_outranks_everything_including_no_chain_semantics() {
        // A resolvable-but-malformed mandate must report Malformed, never fall
        // through to a later check or to a false Valid.
        let mut m = root(MandateScope::wildcard(), 0, 1000);
        m.version = 99;
        let id = m.mandate_id();
        let mut r = MapResolver::with(m);
        r.revoke(&id, 1, PRINCIPAL);
        // even with a revocation and wrong agent present, Malformed dominates
        assert_eq!(
            evaluate_mandate(&claim(OTHER, 5, &id, "x", "z", None), &r),
            MandateFlag::Malformed
        );
    }

    #[test]
    fn flag_str_roundtrip_and_stable_discriminants() {
        let all = [
            MandateFlag::Valid,
            MandateFlag::NoChain,
            MandateFlag::Lapsed,
            MandateFlag::PostRevocation,
            MandateFlag::OverScope,
            MandateFlag::AgentMismatch,
            MandateFlag::Malformed,
            MandateFlag::NotYetValid,
            MandateFlag::UnverifiedChain,
            MandateFlag::DepthExceeded,
            MandateFlag::ScopeBroadened,
            MandateFlag::UnauthorizedRevocation,
        ];
        for f in all {
            assert_eq!(MandateFlag::from_str(f.as_str()), Some(f));
        }
        // Wire-stable discriminants — renumbering breaks stored flags + metrics.
        assert_eq!(MandateFlag::Valid as u8, 0);
        assert_eq!(MandateFlag::NoChain as u8, 1);
        assert_eq!(MandateFlag::Lapsed as u8, 2);
        assert_eq!(MandateFlag::PostRevocation as u8, 3);
        assert_eq!(MandateFlag::OverScope as u8, 4);
        assert_eq!(MandateFlag::AgentMismatch as u8, 5);
        assert_eq!(MandateFlag::Malformed as u8, 6);
        assert_eq!(MandateFlag::NotYetValid as u8, 7);
        assert_eq!(MandateFlag::UnverifiedChain as u8, 8);
        assert_eq!(MandateFlag::DepthExceeded as u8, 9);
        assert_eq!(MandateFlag::ScopeBroadened as u8, 10);
        assert_eq!(MandateFlag::UnauthorizedRevocation as u8, 11);
        assert!(MandateFlag::Valid.is_authorized());
        assert!(!MandateFlag::PostRevocation.is_authorized());
    }

    #[test]
    fn attributes_to_principal_is_the_anti_framing_rule() {
        // Genuine attribution → may name the principal.
        for f in [
            MandateFlag::Valid,
            MandateFlag::Lapsed,
            MandateFlag::NotYetValid,
            MandateFlag::PostRevocation,
            MandateFlag::OverScope,
        ] {
            assert!(f.attributes_to_principal(), "{f:?} should attribute");
        }
        // Must NEVER name the principal (no involvement / exonerated / unverified).
        for f in [
            MandateFlag::NoChain,
            MandateFlag::AgentMismatch,
            MandateFlag::Malformed,
            MandateFlag::UnverifiedChain,
            MandateFlag::DepthExceeded,
            MandateFlag::ScopeBroadened,
            MandateFlag::UnauthorizedRevocation,
        ] {
            assert!(!f.attributes_to_principal(), "{f:?} must NOT attribute");
        }
    }

    #[test]
    fn revocation_is_monotonic_in_resolver() {
        let m = root(MandateScope::wildcard(), 0, 1000);
        let id = m.mandate_id();
        let mut r = MapResolver::with(m);
        r.revoke(&id, 500, PRINCIPAL);
        r.revoke(&id, 300, PRINCIPAL); // earlier
        r.revoke(&id, 800, PRINCIPAL); // later, ignored
        assert_eq!(r.revocation(&id, PRINCIPAL), Some(300));
    }

    #[test]
    fn spoofed_revocation_by_non_principal_is_inert_and_cannot_front_run() {
        // Read-time authorization: a revocation signed by anyone other than the
        // mandate's principal confers NO PostRevocation. Critically, an attacker
        // who revokes EARLIER than the principal must NOT be able to block the
        // principal's real revocation (the front-run / denial-of-revocation hole
        // a single monotonic-min slot would have).
        let m = root(MandateScope::wildcard(), 0, 1000);
        let id = m.mandate_id();
        let mut r = MapResolver::with(m);
        // OTHER front-runs with a revocation at t=1 (earlier than anything).
        r.revoke(&id, 1, OTHER);
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 500, &id, "x", "z", None), &r),
            MandateFlag::Valid // spoof is inert
        );
        // The principal's later (t=400) revocation still takes effect — the
        // front-run did not occupy the principal's slot.
        r.revoke(&id, 400, PRINCIPAL);
        assert_eq!(
            evaluate_mandate(&claim(AGENT, 500, &id, "x", "z", None), &r),
            MandateFlag::PostRevocation
        );
        // And the principal's revocation is read independent of the spoof entry.
        assert_eq!(r.revocation(&id, PRINCIPAL), Some(400));
        assert_eq!(r.revocation(&id, OTHER), Some(1)); // spoof persists as evidence
    }

    #[test]
    fn secs_to_ms_boundaries() {
        assert_eq!(secs_f64_to_ms_saturating(0.0), 0);
        assert_eq!(secs_f64_to_ms_saturating(-5.0), 0);
        assert_eq!(secs_f64_to_ms_saturating(f64::NAN), 0);
        assert_eq!(secs_f64_to_ms_saturating(f64::INFINITY), u64::MAX);
        assert_eq!(secs_f64_to_ms_saturating(1.5), 1500);
        assert_eq!(secs_f64_to_ms_saturating(1_700_000_000.123), 1_700_000_000_123);
    }

    #[test]
    fn revocation_canonical_bytes_domain_separated() {
        let rev = RevocationRecord::new(NET, "someid", "compromised");
        let bytes = rev.canonical_signing_bytes();
        assert!(bytes.starts_with(REVOCATION_DOMAIN_TAG));
        // distinct domain tag from mandates (no cross-protocol preimage reuse)
        assert_ne!(REVOCATION_DOMAIN_TAG, MANDATE_DOMAIN_TAG);
    }

    #[test]
    fn mandate_flag_all_is_exhaustive_and_indexed_by_discriminant() {
        // `MandateFlag::ALL` must list every variant exactly once, in
        // discriminant order, so it indexes the `MANDATE_FLAG_TOTAL[12]` metric
        // array 1:1. `from_str(as_str(x)) == x` over ALL + a unique-label check
        // catches a variant added to the enum but forgotten in ALL.
        assert_eq!(MandateFlag::ALL.len(), 12);
        let mut labels = std::collections::HashSet::new();
        for (i, flag) in MandateFlag::ALL.iter().enumerate() {
            assert_eq!(*flag as usize, i, "ALL[{i}] is out of discriminant order");
            assert_eq!(MandateFlag::from_str(flag.as_str()), Some(*flag));
            assert!(labels.insert(flag.as_str()), "duplicate flag in ALL");
        }
    }

    #[test]
    fn unverified_chain_and_no_chain_share_the_zero_weight_class() {
        // Pins the AGENT-DELEGATION enforcement invariant BEFORE any consensus
        // wiring exists (slice deferred to S3, fusion-audited 2026-06-22): the
        // ONLY authority-conferring verdict is `Valid`; EVERY other flag —
        // crucially `UnverifiedChain` (node-local-sync-dependent) — maps to the
        // same zero-weight class as `NoChain`, never a penalty. A future
        // enforcement slice that gives `UnverifiedChain` any weight other than
        // exactly `NoChain`'s would turn sync-skew into a consensus fork; this
        // test makes that regression a build failure, not a field incident.
        assert!(MandateFlag::Valid.is_authorized());
        assert_eq!(
            MandateFlag::UnverifiedChain.is_authorized(),
            MandateFlag::NoChain.is_authorized(),
            "UnverifiedChain must share NoChain's zero-weight class"
        );
        for flag in MandateFlag::ALL {
            assert_eq!(
                flag.is_authorized(),
                flag == MandateFlag::Valid,
                "only Valid confers authority/weight; {} must not",
                flag.as_str()
            );
        }
    }
}
