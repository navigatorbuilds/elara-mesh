//! elara-cli — PQ-only command-line client for Elara Protocol nodes.
//!
//! Usage:
//!   elara-cli --node http://localhost:9473 status
//!   elara-cli --node http://localhost:9473 balance <identity>
//!   elara-cli --node http://localhost:9473 mint --to <hash> --amount 1000 --identity id.json
//!
//! Per AUDIT-10 directive (2026-04-24, "doesn't work like PQ = doesn't work
//! at all"): every verb is dispatched through the PQ router (ML-KEM-768 +
//! Dilithium3 TOFU). There is NO HTTPS/classical fallback. Verbs without
//! server-side PQ dispatch are not exposed here; re-added as they are
//! migrated in Milestone C batches 2+.
//!
//! Spec references:
//!   @spec Protocol §3.4
//!   @spec internal design notes

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};

use elara_runtime::anchor_proof::{anchor_proof_metadata, ANCHOR_KIND_ELARA_SEAL};
use elara_runtime::errors::{ElaraError, Result};
use elara_runtime::identity::Identity;
use elara_runtime::network::fisherman::{
    appeal_metadata as challenge_appeal_metadata, file_challenge_metadata,
    vote_metadata as challenge_vote_metadata,
};
use elara_runtime::network::pq_client::PqNodeClient;
use elara_runtime::network::pq_transport::PeerIdentityStore;
use elara_runtime::accounting::governance::{
    cancel_metadata as gov_cancel_metadata, delegate_metadata,
    execute_metadata as gov_execute_metadata, propose_metadata, undelegate_metadata,
    vote_metadata, ProposalCategory, VoteDirection,
};
use elara_runtime::accounting::types::{
    burn_metadata, create_ledger_record_with_nonce, dormancy_reclaim_metadata, mint_metadata,
    pool_fund_metadata, slash_metadata, stake_metadata, transfer_metadata, unstake_metadata,
    witness_reward_metadata, xzone_claim_metadata, xzone_lock_metadata, BASE_UNITS_PER_BEAT,
};
use elara_runtime::mandate::{
    MandateRecord, MandateScope, RevocationRecord, MANDATE_OP_KEY, MANDATE_REF_METADATA_KEY,
    MANDATE_REVOCATION_OP_KEY,
};
use elara_runtime::emergency::{
    EmergencyHalt, EmergencyResume, EMERGENCY_FORMAT_VERSION, EMERGENCY_HALT_OP_KEY,
    EMERGENCY_RESUME_OP_KEY,
};

/// Allocate a unique slot nonce for a CLI-emitted record.
///
/// Every record's `slot_key` is `{account_hash}:{nonce:016x}`. Ingest PERMANENTLY
/// conflicts a slot if two different records claim the same `(account, nonce)`
/// (SLOT EQUIVOCATION — both records rejected forever, no clear path). The legacy
/// `create_ledger_record` stamps `nonce=0`, so one identity could land only ONE
/// lifetime record — which is why the non-staking-submitter settlement-FT
/// mitigation could carry exactly one transfer.
///
/// This allocator partitions the 64-bit nonce space PER CLI PROCESS: a CSPRNG
/// salt in the high 32 bits (drawn once) plus a monotonic per-process counter in
/// the low 32 bits. In-process uniqueness comes from the counter; cross-process
/// uniqueness from the salt (a collision needs two *concurrent* same-identity
/// processes to draw the same 32-bit salt — a ~2^-32 birthday event). No sidecar,
/// no node round-trip, no wall clock — so same-ms bursts, restart/crash,
/// concurrent processes, and multi-node seal/gossip lag are all structurally
/// collision-free. The protocol enforces only `(account, nonce)` uniqueness, never
/// monotonicity or density, so sparse salt-prefixed nonces are valid.
/// (Fusion-audited 2026-06-21: 3 Sonnet + 1 Opus panel + Opus final-verify.)
fn session_nonce() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    static NONCE: OnceLock<AtomicU64> = OnceLock::new();
    let counter = NONCE.get_or_init(|| {
        let mut salt = [0u8; 4];
        // OS CSPRNG is the salt source. If it is somehow unavailable (no entropy
        // source — a near-impossible condition on a real host), degrade to
        // wall-clock nanos rather than panic: the salt only needs to keep
        // *concurrent same-identity* processes apart, and in-process uniqueness
        // is carried unconditionally by the monotonic low-word counter regardless.
        let salt_hi = match getrandom::getrandom(&mut salt) {
            Ok(()) => u32::from_be_bytes(salt),
            Err(_) => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(1),
        };
        // salt → high 32 bits, per-process counter → low 32 bits.
        AtomicU64::new((salt_hi as u64) << 32)
    });
    counter.fetch_add(1, Ordering::Relaxed)
}

#[derive(Parser)]
#[command(name = "elara-cli", version, about = "Elara Protocol CLI client (PQ-only)")]
struct Cli {
    /// Node URL (e.g., http://localhost:9473). The PQ port is derived as
    /// port + ELARA_PQ_PORT_OFFSET (default 100).
    #[arg(long, default_value = "http://localhost:9473")]
    node: String,

    /// Persistent TOFU pin store path. Without this flag, every invocation
    /// uses an in-memory store and re-pins on first contact. Supplying a
    /// path makes pins survive across invocations — account-grade behavior.
    /// Mismatches abort the call (peer identity rotation).
    #[arg(long)]
    pins: Option<PathBuf>,

    /// Network id (realm) stamped on record submissions. Required when the
    /// target node runs a non-default `network_id` — otherwise writes are
    /// rejected with `network_mismatch`. Falls back to the `ELARA_NETWORK_ID`
    /// environment variable. Read-only commands ignore it.
    #[arg(long)]
    network: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show node status.
    Status,
    /// Query account balance.
    Balance {
        /// Identity hash (omit for all accounts).
        identity: Option<String>,
    },
    /// List connected peers.
    Peers,
    /// Show ledger summary.
    Summary,
    /// Submit a raw record file (wire bytes).
    Submit {
        /// Path to wire bytes file.
        file: PathBuf,
        /// Machine mode (the spool drain's boundary): ONE JSON line with a
        /// classified outcome — class ∈ accepted/duplicate/quota/embargoed/
        /// unreachable/error/indeterminate. Exit 0 iff the record is on the
        /// chain (accepted, or duplicate = already there); nonzero otherwise.
        #[arg(long)]
        json: bool,
    },
    /// Build, sign, and submit an anchor-proof record (P1.5(b)) from a
    /// matured sidecar artifact + its Bitcoin-UPGRADED .ots proof. The
    /// binding tuple (seal_hash/epoch/zone) is read from the artifact
    /// itself — the caller cannot mistype it. Verify the confirmation
    /// FIRST (elara-verify --anchor grades existed-by): a calendar-pending
    /// proof submitted here becomes a permanently non-trustless record.
    AnchorSubmit {
        /// Path to the epoch-anchor artifact (epoch-N-zone-Z.json).
        #[arg(long)]
        artifact: PathBuf,
        /// Path to the upgraded OpenTimestamps proof (.ots).
        #[arg(long)]
        ots: PathBuf,
        /// Path to signer identity JSON.
        #[arg(long)]
        identity: PathBuf,
        /// Write the signed wire record to this path instead of submitting.
        #[arg(long)]
        dry_run: Option<PathBuf>,
    },
    /// Mint beats (genesis authority only).
    Mint {
        /// Recipient identity hash.
        #[arg(long)]
        to: String,
        /// Amount in beat (e.g., 1000).
        #[arg(long)]
        amount: f64,
        /// Path to signer identity JSON.
        #[arg(long)]
        identity: PathBuf,
        /// Mint reason.
        #[arg(long, default_value = "cli-mint")]
        reason: String,
    },
    /// Transfer beats.
    Transfer {
        /// Recipient identity hash.
        #[arg(long)]
        to: String,
        /// Amount in beat.
        #[arg(long)]
        amount: f64,
        /// Path to signer identity JSON.
        #[arg(long)]
        identity: PathBuf,
        /// Optional memo.
        #[arg(long)]
        memo: Option<String>,
    },
    /// Stake beats.
    Stake {
        /// Amount in beat.
        #[arg(long)]
        amount: f64,
        /// Stake purpose: witness, governance, storage.
        #[arg(long, default_value = "witness")]
        purpose: String,
        /// Path to signer identity JSON.
        #[arg(long)]
        identity: PathBuf,
    },
    /// Unstake beats (after cooldown).
    Unstake {
        /// Stake record ID to unstake.
        #[arg(long)]
        stake_record_id: String,
        /// Path to signer identity JSON.
        #[arg(long)]
        identity: PathBuf,
    },
    /// Burn beats permanently (reduces total supply).
    Burn {
        /// Amount in beat.
        #[arg(long)]
        amount: f64,
        /// Path to signer identity JSON.
        #[arg(long)]
        identity: PathBuf,
        /// Optional memo.
        #[arg(long)]
        memo: Option<String>,
    },
    /// Slash a staker's stake (genesis authority only).
    Slash {
        /// Amount in beat to slash.
        #[arg(long)]
        amount: f64,
        /// Offender identity hash.
        #[arg(long)]
        offender: String,
        /// Challenger identity hash (receives 30%).
        #[arg(long)]
        challenger: String,
        /// Jury identity hashes, comma-separated (split 20%).
        #[arg(long)]
        jury: String,
        /// Stake record ID to slash.
        #[arg(long)]
        stake_record_id: String,
        /// Slash reason.
        #[arg(long, default_value = "protocol violation")]
        reason: String,
        /// Path to signer identity JSON (genesis authority).
        #[arg(long)]
        identity: PathBuf,
    },
    /// Issue a witness reward (signed by witness, paid by record creator).
    WitnessReward {
        /// Reward amount in beat.
        #[arg(long)]
        amount: f64,
        /// Payer identity hash (record creator).
        #[arg(long)]
        from: String,
        /// Witness identity hash (reward recipient).
        #[arg(long)]
        to: String,
        /// Record ID being witnessed.
        #[arg(long)]
        record_id: String,
        /// Path to signer identity JSON (witness).
        #[arg(long)]
        identity: PathBuf,
    },
    /// Reclaim beats from a dormant identity (genesis authority only).
    DormancyReclaim {
        /// Amount in beat to reclaim.
        #[arg(long)]
        amount: f64,
        /// Dormant identity hash.
        #[arg(long)]
        dormant_identity: String,
        /// Last activity timestamp of the dormant identity.
        #[arg(long)]
        last_activity: f64,
        /// Path to signer identity JSON (genesis authority).
        #[arg(long)]
        identity: PathBuf,
    },
    /// Fund the conservation pool (genesis authority only).
    PoolFund {
        /// Amount in beat to move into the conservation pool.
        #[arg(long)]
        amount: f64,
        /// Path to signer identity JSON (genesis authority).
        #[arg(long)]
        identity: PathBuf,
    },
    /// Cross-zone Lock — debit sender on the source zone; pairs with XzoneClaim.
    ///
    /// Sender's beats move from `available` into the in-flight `pending_xzone_locked`
    /// pool. The Lock must reach Finalized + be sealed into an epoch seal before the
    /// matching Claim on the destination zone is admissible. If no Claim arrives
    /// within 24 h (CLAIM_TIMEOUT_SECS) the Lock auto-refunds via the epoch-tick
    /// sweep in `epoch.rs::process_expired_xzone`.
    XzoneLock {
        /// Recipient identity hash on the destination zone (64 hex chars).
        #[arg(long)]
        to: String,
        /// Amount in beat.
        #[arg(long)]
        amount: f64,
        /// Source zone path (must differ from dest).
        #[arg(long)]
        source_zone: String,
        /// Destination zone path.
        #[arg(long)]
        dest_zone: String,
        /// Path to signer identity JSON (sender).
        #[arg(long)]
        identity: PathBuf,
    },
    /// Cross-zone Claim — credit recipient on the destination zone.
    ///
    /// Requires the source-zone Lock to be finalized + proof-attached. `transfer_id`
    /// is the record_id of the Lock. `to` must match the Lock's `recipient` and be
    /// the signer of this Claim.
    XzoneClaim {
        /// Lock record_id (also the transfer_id).
        #[arg(long)]
        transfer_id: String,
        /// Amount in beat (must match the Lock).
        #[arg(long)]
        amount: f64,
        /// Recipient identity hash (64 hex chars, must be signer).
        #[arg(long)]
        to: String,
        /// Path to signer identity JSON (recipient).
        #[arg(long)]
        identity: PathBuf,
    },
    /// Show record detail by ID.
    Record {
        /// Record UUID.
        id: String,
    },
    /// Show node health.
    Health,
    /// Show epoch sealing status.
    Epochs,
    /// Inspect an identity JSON file (no node required).
    IdentityInspect {
        /// Path to identity JSON file.
        file: PathBuf,
    },
    /// Create a governance proposal.
    Propose {
        /// Proposal title.
        #[arg(long)]
        title: String,
        /// Proposal description.
        #[arg(long)]
        description: String,
        /// Category: zone_local, parameter, critical.
        #[arg(long, default_value = "parameter")]
        category: String,
        /// Path to signer identity JSON (must have governance stake).
        #[arg(long)]
        identity: PathBuf,
    },
    /// Vote on a governance proposal.
    Vote {
        /// Proposal ID.
        #[arg(long)]
        proposal_id: String,
        /// Direction: for, against, abstain.
        #[arg(long)]
        direction: String,
        /// Path to signer identity JSON (must have governance stake).
        #[arg(long)]
        identity: PathBuf,
    },
    /// Execute a passed governance proposal (after delay period).
    ExecuteProposal {
        /// Proposal ID.
        #[arg(long)]
        proposal_id: String,
        /// Path to signer identity JSON.
        #[arg(long)]
        identity: PathBuf,
    },
    /// Cancel a governance proposal (proposer only).
    CancelProposal {
        /// Proposal ID.
        #[arg(long)]
        proposal_id: String,
        /// Path to signer identity JSON (must be the proposer).
        #[arg(long)]
        identity: PathBuf,
    },
    /// Delegate governance voting power to another identity.
    Delegate {
        /// Identity hash of the delegate.
        #[arg(long)]
        to: String,
        /// Path to signer identity JSON.
        #[arg(long)]
        identity: PathBuf,
    },
    /// Remove a governance delegation.
    Undelegate {
        /// Path to signer identity JSON.
        #[arg(long)]
        identity: PathBuf,
    },
    /// File a fisherman challenge against a protocol violator.
    Challenge {
        /// Identity hash of the accused.
        #[arg(long)]
        accused: String,
        /// Challenge type: spam, false_witnessing, double_signing, cartel_formation.
        #[arg(long, name = "type")]
        challenge_type: String,
        /// Evidence record IDs, comma-separated.
        #[arg(long)]
        evidence: String,
        /// Path to signer identity JSON (must have >= 10 beat staked).
        #[arg(long)]
        identity: PathBuf,
    },
    /// Cast a jury vote on a fisherman challenge.
    ChallengeVote {
        /// Challenge ID to vote on.
        #[arg(long)]
        challenge_id: String,
        /// Vote guilty (true) or not guilty (false).
        #[arg(long)]
        guilty: bool,
        /// Path to signer identity JSON (must be a selected juror).
        #[arg(long)]
        identity: PathBuf,
    },
    /// File an appeal against a fisherman challenge verdict.
    ChallengeAppeal {
        /// Challenge ID to appeal.
        #[arg(long)]
        challenge_id: String,
        /// Reason for the appeal.
        #[arg(long)]
        reason: String,
        /// Path to signer identity JSON (accused or challenger only).
        #[arg(long)]
        identity: PathBuf,
    },

    /// Stage 4E.4 — generate a fresh Dilithium3 admin keypair (operator key).
    /// Writes a JSON file with hex-encoded pubkey + secret key. Add the
    /// pubkey to the node's `ELARA_ADMIN_PUBKEYS` env var.
    PqAdminKeygen {
        /// Output path for the keypair JSON.
        #[arg(long)]
        out: PathBuf,
    },

    /// Stage 4E.4 — print just the public key (hex) from a keypair file.
    /// Useful for adding to ELARA_ADMIN_PUBKEYS without leaking the secret.
    PqAdminPubkey {
        /// Path to keypair JSON (from `pq-admin-keygen`).
        #[arg(long)]
        key: PathBuf,
    },

    /// PQ-R7 — sign an `X-PQ-Admin` header for the given (method, request-target)
    /// and print it to stdout. Pipe into `curl -H "X-PQ-Admin: $(...)"` to call
    /// admin endpoints after the bearer fallback was removed.
    ///
    /// V2 (2026-07-05): the signature binds the full origin-form request target
    /// — path AND query. Pass the `--path` value INCLUDING any `?query`, exactly
    /// as it will appear on the wire (percent-encode by hand; do not let curl
    /// re-encode it), e.g. `--path '/admin/zone_transition?target_epoch=30&new_count=4'`.
    /// A mismatch between the signed target and the sent URL fails closed (403).
    AdminSign {
        /// Path to keypair JSON (from `pq-admin-keygen`).
        #[arg(long)]
        key: PathBuf,
        /// HTTP method (GET, POST, …). Must match the request exactly.
        #[arg(long, default_value = "GET")]
        method: String,
        /// Request target — path plus any `?query` (e.g. `/admin/memory` or
        /// `/admin/zones/subscribe?zone=medical%2Feu`). Must be byte-identical to
        /// the wire request; the query is now part of the signed bytes.
        #[arg(long)]
        path: String,
    },

    /// Emit an AI-agent audit record (wedge demo for the "agent action audit
    /// trails" use case). Creates a Public ValidationRecord with metadata
    /// `{kind: "agent_audit", tool, action, args_hash, agent_id, timestamp}`,
    /// signs it, and submits to the node via PQ transport. Exits silently on
    /// failure so PostToolUse hooks don't block the agent.
    AgentEmit {
        /// Path to signer identity JSON. Defaults to ~/.elara/identity.json.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Tool name (e.g., "Bash", "Edit", "Read").
        #[arg(long)]
        tool: String,
        /// Action (e.g., "pre", "post"). Free-form.
        #[arg(long, default_value = "post")]
        action: String,
        /// Hex-encoded hash of the tool arguments. Clients should SHA3-256
        /// their input JSON; this command does NOT hash for you because
        /// pipeline tools vary in how they canonicalise.
        #[arg(long)]
        args_hash: String,
        /// Agent identifier (e.g., "claude-opus-4-7", "claude-sonnet-4-6").
        #[arg(long, default_value = "claude-code")]
        agent_id: String,
        /// Session id (UUID or Claude session). Optional.
        #[arg(long)]
        session_id: Option<String>,
        /// G1: spool directory. When set, a signed record whose submit does
        /// NOT land (rate refusal, node down, unreadable response) is written
        /// durably to <dir>/pending/<record_id>.wire instead of being
        /// discarded; scripts/elara-spool-drain.sh resubmits later. Exit code
        /// and output are UNCHANGED — the emission still truthfully failed to
        /// land now.
        #[arg(long = "spool-dir")]
        spool_dir: Option<PathBuf>,
        /// Optional mandate_id this act is performed under. When set, the record
        /// carries `mandate_ref` metadata so `GET /mandate/status/{record_id}`
        /// resolves the act against that mandate (Valid / PostRevocation /
        /// AgentMismatch / …) — the authority-to-act provenance OTS+sig cannot
        /// express. The signer (this identity) MUST be the mandate's agent key.
        #[arg(long)]
        mandate_ref: Option<String>,
        /// Suppress stdout on success (default: print accepted id).
        #[arg(long)]
        quiet: bool,
        /// Machine output: print exactly one JSON line to stdout —
        /// `{"ok":true,"record_id":…}` or `{"ok":false,"error":…}` — and exit
        /// NONZERO on failure. This is the mode programmatic callers (the MCP
        /// server) must use: the default human mode deliberately exits 0 on
        /// submit failure so PostToolUse hooks never cascade, which is exactly
        /// the wrong contract for a caller that needs the truth
        /// (MCP-MANDATE-SERVER-VERDICT-2026-08-19 build-order item 1).
        #[arg(long)]
        json: bool,
    },

    /// Emit the chained mirror-publish act: a Public ValidationRecord with
    /// metadata `kind=mirror_publish_act` binding a public-mirror push to the
    /// chain (G4-PUBLIC-BINDING FINAL RULING §2/§7). This is an EXPLICIT emit
    /// path — the schema is fixed here, never a generic metadata pass-through.
    /// A stranger recomputes every claim: `mirror_commit` against GitHub,
    /// `acts_root` from the published feed diff between `mirror_commit` and
    /// `prev_mirror_commit`, `args_hash` from the disclosed construction.
    /// Unlike `agent-emit`, the plain mode exits NONZERO when the record
    /// neither landed nor spooled — this emission is load-bearing for the
    /// publish flow, not a fire-and-forget hook.
    MirrorPublishEmit {
        /// Path to the MAINTAINER signer identity JSON (T94 outward-act
        /// class). REQUIRED — deliberately no ~/.elara/identity.json default,
        /// so a mis-wired caller can never sign a publish act with the
        /// build-agent identity.
        #[arg(long)]
        identity: PathBuf,
        /// Full 40-hex sha of the JUST-PUSHED public mirror commit. The
        /// ledger's short sha stays human-only — 28 bits is not a binding.
        #[arg(long)]
        mirror_commit: String,
        /// Bare owner/name slug of the public mirror. URL-shaped values are
        /// rejected here AND by the node's content scan.
        #[arg(long, default_value = "navigatorbuilds/elara-mesh")]
        mirror_repo: String,
        /// Full 40-hex sha of the tip the mirror served BEFORE this push
        /// (== the previous act's mirror_commit once every publish emits —
        /// the CHAIN that makes a suppressed publish detectable). Omit ONLY
        /// when the mirror had no pre-push tip (initial publish).
        #[arg(long)]
        prev_mirror_commit: Option<String>,
        /// Full 40-hex sha of the PRIVATE tip this publish staged from. Only
        /// SHA3-256(this ascii string) rides in the record as `args_hash`;
        /// the raw private sha itself never ships.
        #[arg(long)]
        private_tip: String,
        /// Path to the publish-window act list: one commit-receipt record_id
        /// per line (the receipt ids NEW in this publish's feed vs
        /// prev_mirror_commit's feed). Deduplicated; `acts_count` = unique
        /// ids; `acts_root` = elara-smt root over `update(k, k)` where
        /// `k = SHA3-256(record_id ascii)`. An empty file yields the SMT
        /// empty root (SHA3-256 of empty input).
        #[arg(long)]
        acts_file: PathBuf,
        /// G1 spool directory (same durability contract as agent-emit): a
        /// signed record whose submit does not land is written to
        /// <dir>/pending/ and resubmitted by scripts/elara-spool-drain.sh,
        /// which drains this class PRIORITY-first and fires the P1
        /// publish-receipt-spooled alert.
        #[arg(long = "spool-dir")]
        spool_dir: Option<PathBuf>,
        /// Machine output: exactly one JSON line
        /// (`{"ok":…,"record_id":…,"spooled":…}`) and NONZERO exit on any
        /// outcome that is not a node-confirmed accept. publish-mirror.sh
        /// uses this mode and treats ok==true OR spooled==true as
        /// emit-or-spool verified.
        #[arg(long)]
        json: bool,
    },

    /// Issue a scoped, revocable agent-mandate ON-CHAIN: the PRINCIPAL (this
    /// signer identity) grants an AGENT key authority to act, for a bounded
    /// time window. The `MandateRecord` rides inside a Public ValidationRecord
    /// signed by the principal; ingest binds it via
    /// `sha3(creator_pk) == principal_identity_hash`, so this identity becomes
    /// the mandate's principal. Prints the `mandate_id` — pass it as
    /// `--mandate-ref` on the agent's `agent-emit` acts. This expresses
    /// "agent A was authorized by principal P to do X, valid T1..T2, revocable"
    /// — which OpenTimestamps + a bare PQ signature structurally cannot.
    MandateIssue {
        /// Path to the PRINCIPAL signer identity JSON (the issuing key).
        #[arg(long)]
        identity: PathBuf,
        /// Agent identity hash (lowercase hex sha3-256 of the agent's Dilithium
        /// public key — i.e. the agent identity's `identity_hash`, shown by
        /// `elara-cli identity-inspect`). The mandate authorizes this key.
        #[arg(long)]
        agent: String,
        /// Validity window length in hours from now (default ~6 months). An act
        /// whose own signed timestamp falls outside [now, now+hours] flags
        /// Lapsed / NotYetValid.
        #[arg(long, default_value_t = 4380)]
        hours: u64,
        /// Comma-separated allowed ops, or `*` for a wildcard (any-op) scope
        /// (default). NOTE: v0 only ENFORCES wildcard scope; a non-wildcard
        /// scope is RECORDED on-chain but op/zone enforcement is deferred to a
        /// later audited slice (the act's status then carries
        /// `scope_deferred: true`). Use `*` for the clean Valid demo.
        #[arg(long, default_value = "*")]
        ops: String,
        /// Optional issuer-chosen uniquifier so re-issuing an identical
        /// scope/window/agent yields a fresh mandate_id (re-authorization is a
        /// NEW mandate, never an un-revoke). Default: a per-process nonce.
        #[arg(long)]
        nonce: Option<String>,
    },

    /// Revoke a previously-issued mandate ON-CHAIN. Signed by the PRINCIPAL
    /// (the original issuer); only the original principal's revocation takes
    /// effect (verified at read time). Revocation is monotonic + terminal (no
    /// un-revoke). Acts whose signed timestamp is at/after the revocation flag
    /// PostRevocation; acts strictly before it stay Valid forever — the
    /// queryable-over-time accountability property.
    MandateRevoke {
        /// Path to the PRINCIPAL signer identity JSON (the original issuer).
        #[arg(long)]
        identity: PathBuf,
        /// The `mandate_id` to revoke (as printed by `mandate-issue`).
        #[arg(long)]
        mandate_id: String,
        /// Free-text forensic reason (recorded, not load-bearing).
        #[arg(long, default_value = "revoked via cli")]
        reason: String,
    },

    /// Issue a signed EmergencyHalt ON-CHAIN — pause new-write admission across the
    /// network until resumed or auto-expiry. Signed by the GENESIS AUTHORITY (only
    /// the authority's halt is honored). Auditable + gossip-propagating + resumable,
    /// unlike killing the process. Node-local (never folded into consensus/seals): it
    /// refuses NEW non-authority writes; already-sealed history, sync, and the
    /// authority's own records keep flowing.
    EmergencyHalt {
        /// Path to the GENESIS AUTHORITY signer identity JSON.
        #[arg(long)]
        identity: PathBuf,
        /// Free-text cause (audit trail).
        #[arg(long, default_value = "emergency halt via cli")]
        reason: String,
        /// Auto-expiry window in seconds (continuity backstop — self-clears after
        /// this even with no resume). Clamped node-side to 30 days. Default 72h.
        #[arg(long, default_value_t = 72 * 3600)]
        max_duration_secs: u64,
        /// Strictly-increasing halt nonce. Default = current unix seconds (monotonic
        /// across invocations; do NOT issue two halts in the same second).
        #[arg(long)]
        nonce: Option<u64>,
    },

    /// Lift an EmergencyHalt ON-CHAIN. Signed by the GENESIS AUTHORITY. A resume with
    /// `halt_nonce >=` the active halt's nonce un-halts (max-fold). Default
    /// `halt_nonce` = current unix seconds, which clears any halt issued earlier.
    EmergencyResume {
        /// Path to the GENESIS AUTHORITY signer identity JSON.
        #[arg(long)]
        identity: PathBuf,
        /// The halt nonce to clear (>= the target halt's nonce). Default = now (secs).
        #[arg(long)]
        halt_nonce: Option<u64>,
    },

    /// Gap 1 light-client SDK helper — fetch epoch headers from the seed peer
    /// over PQ transport (`headers_from` verb). Returns the same JSON the
    /// HTTPS `/headers/from/{epoch}` endpoint serves: `{total, headers: [...]}`.
    /// Intended to drive a light-client header-only sync loop (poll, advance
    /// `since`, repeat) — accounts and watch-only clients use this to verify
    /// balances without holding the chain.
    LightHeaders {
        /// Epoch floor — server returns headers with `epoch_number >= since`.
        #[arg(long)]
        since: u64,
        /// Optional zone filter (e.g. "0", "1"). Defaults to all zones.
        #[arg(long)]
        zone: Option<String>,
        /// Optional response cap. Server default 500, max 2000.
        #[arg(long)]
        limit: Option<usize>,
    },

    /// Gap 1 light-client SDK helper — fetch the per-account state proof
    /// (`account_proof` verb). Returns `{root, leaf, siblings, ...}` keyed
    /// to the latest sealed epoch's `account_smt_root`. Pair with
    /// `LightHeaders` + `verify_account_proof_against_header` to confirm
    /// balance without trusting the seed peer.
    AccountProof {
        /// Identity hash (32-byte hex).
        identity: String,
    },

    /// AUDIT-10 Milestone C account demo — poll seal progress for a record.
    /// Mirrors the `seal_progress` PQ verb. Returns `{sealed, epoch,
    /// attestations, quorum, ...}` so account UIs can render a confirmation
    /// counter (Protocol §11.18).
    SealProgress {
        /// Record id (hex).
        record_id: String,
    },

    /// AUDIT-10 Milestone C account demo — fetch the activity summary for
    /// an identity. Mirrors the `activity` PQ verb. Wallets render the
    /// returned event list as the transaction history feed (Protocol §11.23).
    Activity {
        /// Identity hash (32-byte hex).
        identity: String,
    },

    /// AUDIT-10 Milestone C operator wrapper — fetch the Prometheus
    /// exposition body over the PQ `metrics` verb. Same content as the
    /// axum `/metrics` route, but routed through the PQ session so it
    /// works fleet-wide once `allow_public_https` is flipped off. Pipe
    /// into `grep` for ad-hoc cutover checks (e.g. WS Slice 3 readiness:
    /// `elara-cli --node http://HOST:9473 metrics | grep elara_ws_`).
    Metrics,

    /// ZSP Phase E Slice 2 — local-node zone subscription management.
    /// Wraps `/admin/zones/{scope,subscribe,unsubscribe}` with PQ admin
    /// auth so operators can adjust storage scope without crafting curl
    /// + X-PQ-Admin headers manually.
    Zones {
        #[command(subcommand)]
        action: ZonesAction,
    },
    /// Realm operations (REALMS P1): federation cert issuance.
    Realm {
        #[command(subcommand)]
        action: RealmAction,
    },
}

/// REALMS P1 slice (d) — realm-management subcommands. `issue-cert` is an
/// OFFLINE operation: it signs with the federation root key from a local
/// identity file and never talks to a node.
#[derive(Subcommand)]
enum RealmAction {
    /// Issue a federation membership cert, signed by the realm root.
    /// Hand the output file to the member's operator; they set
    /// `realm_membership_cert_path` to it in elara-node.toml.
    IssueCert {
        /// Member identity hash (64-char hex).
        #[arg(long)]
        member: String,
        /// Path to the realm ROOT identity JSON (the federation signer).
        #[arg(long)]
        root_identity: PathBuf,
        /// Cert validity in days from now.
        #[arg(long, default_value_t = 365)]
        valid_days: u64,
        /// Output path for the cert JSON.
        #[arg(long)]
        out: PathBuf,
    },
}

/// ZSP Phase E Slice 2 — zone-management subcommands. All require a PQ
/// admin keypair (`pq-admin-keygen` output) since the underlying admin
/// surface is auth-gated.
#[derive(Subcommand)]
enum ZonesAction {
    /// Show the local node's subscription scope: subscribed zones,
    /// `default_behavior` (`accept_all` / `scoped`), per-zone disk
    /// counts, global zone-index totals, and pending-purge state.
    /// Hits `GET /admin/zones/scope`.
    Scope {
        /// Path to PQ admin keypair JSON.
        #[arg(long)]
        key: PathBuf,
    },
    /// Add a zone subscription (auto-pins ancestors, persists across
    /// restart). Hits `POST /admin/zones/subscribe?zone=<path>`.
    Add {
        /// Zone path (e.g. "medical/eu" or "0").
        #[arg(long)]
        zone: String,
        /// Path to PQ admin keypair JSON.
        #[arg(long)]
        key: PathBuf,
    },
    /// Remove a zone subscription and queue its records for bounded
    /// background purge. Hits `POST /admin/zones/unsubscribe?zone=<path>`.
    /// Returns the new pending-purge queue depth.
    Remove {
        /// Zone path.
        #[arg(long)]
        zone: String,
        /// Path to PQ admin keypair JSON.
        #[arg(long)]
        key: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let base = cli.node.trim_end_matches('/');

    // T63 flag day (2026-08-19): the CLI is an EMITTING PROCESS — records it
    // builds (agent acts, transfers) are created in THIS process, so the
    // emission network binding must be armed here exactly like the node's
    // main. Found in anger: the first post-flip act carried network_id=""
    // because only elara_node.rs armed the OnceLock. Value resolution mirrors
    // the node: ELARA_NETWORK_ID env override, else the shared default —
    // CLI and node can only disagree if the operator explicitly overrides one.
    {
        let net = std::env::var("ELARA_NETWORK_ID")
            .unwrap_or_else(|_| elara_runtime::network::config::DEFAULT_NETWORK_ID.to_string());
        elara_record::record::set_emission_network_id(&net)
            .map_err(|e| ElaraError::Config(format!("invalid network_id {net:?}: {e}")))?;
    }

    // PQ-only transport. Spin up an ephemeral Dilithium3 keypair + in-memory
    // TOFU pin store. Derive the peer's PQ address from `--node` using the
    // port offset (default 100). If the URL doesn't parse or PQ handshake
    // fails, the command fails — there is NO HTTPS fallback by design
    // (AUDIT-10 directive, 2026-04-24).
    let pq_offset: u16 = std::env::var("ELARA_PQ_PORT_OFFSET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let pq_addr = http_to_pq_addr(base, pq_offset).ok_or_else(|| {
        ElaraError::Config(format!(
            "--node URL {base:?} did not parse host:port; cannot derive PQ peer addr"
        ))
    })?;
    let pq = {
        let kp = elara_runtime::crypto::pqc::dilithium3_keygen()
            .map_err(|e| ElaraError::Crypto(format!("dilithium3 keygen: {e}")))?;
        let (pk, sk) = kp.into_parts();
        let pins = match cli.pins.as_ref() {
            Some(path) => Arc::new(
                PeerIdentityStore::open(path)
                    .map_err(|e| ElaraError::Config(format!(
                        "open pin store {}: {e}", path.display()
                    )))?,
            ),
            None => Arc::new(PeerIdentityStore::in_memory()),
        };
        let client = PqNodeClient::new(pk, sk, pins);
        // T65 D1 item 4 — the chain ends at the compiled-in default instead of
        // "no header", so a bare CLI keeps working the day
        // `require_network_id_header` flips on. Tracking the DEFAULT here is
        // correct (the CLI should follow whatever network this build targets);
        // it is the missing-header ENFORCEMENT fallback that must stay frozen.
        let network_id = cli
            .network
            .clone()
            .or_else(|| std::env::var("ELARA_NETWORK_ID").ok())
            .unwrap_or_else(|| {
                elara_runtime::network::config::DEFAULT_NETWORK_ID.to_string()
            });
        client.with_network_id(network_id)
    };

    // The mandate/revocation network binding is load-bearing (a mandate signed
    // for one network must not replay onto another), so resolve it ONCE from the
    // same source the PQ client stamps as the `x-elara-network-id` header — the
    // mandate's in-payload `network_id` and the carrier's header must agree.
    let effective_network = cli.network.clone().or_else(|| std::env::var("ELARA_NETWORK_ID").ok());

    match cli.command {
        Commands::Status => {
            let resp = pq.get_status(&pq_addr).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Commands::Balance { identity } => {
            let resp = pq.balances(&pq_addr, identity.as_deref()).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Commands::Peers => {
            let resp = pq.list_peers(&pq_addr).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Commands::Summary => {
            let resp = pq.ledger_summary(&pq_addr).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Commands::Submit { file, json } => {
            let wire_bytes = std::fs::read(&file).map_err(ElaraError::Io)?;
            if json {
                // G1 M3: machine mode for the spool drain — ONE JSON line with a
                // Rust-side `class` computed from the node's reason strings in
                // `submit_class`, so no shell ever substring-matches prose.
                // Exit 0 iff the record is on the chain (accepted now or
                // already there). Transport failures (dial/handshake/read —
                // the node never answered) classify "unreachable" BEFORE any
                // reason parsing: environmental, says nothing about the
                // record; the drain stops its sweep without burning attempts.
                let body = match pq.submit_record(&pq_addr, &wire_bytes).await {
                    Ok(body) => body,
                    Err(e) => {
                        println!("{}", serde_json::json!({
                            "ok": false, "class": "unreachable", "reason": e.to_string(),
                        }));
                        return Err(e);
                    }
                };
                match outcome_from_body(&body) {
                    Ok(SubmitOutcome::Accepted(id)) => {
                        println!("{}", serde_json::json!({
                            "ok": true, "class": "accepted", "record_id": id,
                        }));
                    }
                    Ok(SubmitOutcome::Indeterminate(body)) => {
                        println!("{}", serde_json::json!({
                            "ok": false, "class": "indeterminate", "body": body,
                        }));
                        return Err(ElaraError::Network(
                            "submit --json: indeterminate node response".into(),
                        ));
                    }
                    Err(e) => {
                        let reason = e.to_string();
                        let class = submit_class(&reason);
                        println!("{}", serde_json::json!({
                            "ok": class == "duplicate", "class": class, "reason": reason,
                        }));
                        if class != "duplicate" {
                            return Err(e);
                        }
                    }
                }
            } else {
                submit_record(&pq, &pq_addr, &wire_bytes).await?;
            }
        }

        Commands::AnchorSubmit { artifact, ots, identity, dry_run } => {
            let id = load_identity(&identity)?;
            let artifact_bytes = std::fs::read(&artifact).map_err(ElaraError::Io)?;
            let ots_bytes = std::fs::read(&ots).map_err(ElaraError::Io)?;
            // Binding tuple comes FROM the artifact (the bytes the OTS proof
            // commits to) — metadata and artifact cannot disagree by
            // construction, which is exactly what elara-verify re-checks.
            let obj: serde_json::Value = serde_json::from_slice(&artifact_bytes)
                .map_err(|e| ElaraError::Wire(format!("artifact is not JSON: {e}")))?;
            let epoch = obj
                .get("epoch")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| ElaraError::Wire("artifact missing numeric 'epoch'".into()))?;
            let zone = obj
                .get("zone")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ElaraError::Wire("artifact missing 'zone'".into()))?;
            let seal_hash = obj
                .get("seal_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ElaraError::Wire("artifact missing 'seal_hash'".into()))?;
            let meta = anchor_proof_metadata(
                ANCHOR_KIND_ELARA_SEAL,
                seal_hash,
                zone,
                epoch,
                &artifact_bytes,
                &ots_bytes,
            )?;
            // Content = the verbatim artifact bytes → content_hash (sha3)
            // commits the record to exactly what anchor_artifact_b64 carries.
            let mut record = elara_runtime::record::ValidationRecord::create(
                &artifact_bytes,
                id.public_key.clone(),
                vec![],
                elara_runtime::record::Classification::Public,
                Some(meta),
            );
            // Unique slot nonce BEFORE signing (same allocator as every other
            // CLI-emitted record) — reusing a nonce with different content is
            // slot equivocation and gets both records rejected forever.
            record.nonce = session_nonce();
            id.sign_record(&mut record)?;
            match dry_run {
                Some(out) => {
                    std::fs::write(&out, record.to_bytes()).map_err(ElaraError::Io)?;
                    println!(
                        "anchor-proof record written to {} (NOT submitted): id={} epoch={epoch} zone={zone} content_hash={}",
                        out.display(),
                        record.id,
                        hex::encode(&record.content_hash),
                    );
                }
                None => {
                    submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
                    println!(
                        "anchor-proof record submitted: id={} epoch={epoch} zone={zone} content_hash={}",
                        record.id,
                        hex::encode(&record.content_hash),
                    );
                }
            }
        }

        Commands::Mint { to, amount, identity, reason } => {
            let id = load_identity(&identity)?;
            let micros = (amount * BASE_UNITS_PER_BEAT as f64) as u64;
            let meta = mint_metadata(micros, &to, &reason);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
        }

        Commands::Transfer { to, amount, identity, memo } => {
            let id = load_identity(&identity)?;
            let micros = (amount * BASE_UNITS_PER_BEAT as f64) as u64;
            let meta = transfer_metadata(micros, &to, memo.as_deref());
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
        }

        Commands::Stake { amount, purpose, identity } => {
            let id = load_identity(&identity)?;
            let micros = (amount * BASE_UNITS_PER_BEAT as f64) as u64;
            let purpose_enum = elara_runtime::accounting::types::StakePurpose::from_str(&purpose)?;
            let meta = stake_metadata(micros, &purpose_enum);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
        }

        Commands::Unstake { stake_record_id, identity } => {
            let id = load_identity(&identity)?;
            let meta = unstake_metadata(&stake_record_id);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
        }

        Commands::Burn { amount, identity, memo } => {
            let id = load_identity(&identity)?;
            let micros = (amount * BASE_UNITS_PER_BEAT as f64) as u64;
            let meta = burn_metadata(micros, memo.as_deref());
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
        }

        Commands::Slash { amount, offender, challenger, jury, stake_record_id, reason, identity } => {
            let id = load_identity(&identity)?;
            let micros = (amount * BASE_UNITS_PER_BEAT as f64) as u64;
            let jury_list: Vec<String> = jury.split(',').map(|s| s.trim().to_string()).collect();
            let meta = slash_metadata(micros, &offender, &challenger, &jury_list, &stake_record_id, &reason);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
        }

        Commands::WitnessReward { amount, from, to, record_id, identity } => {
            let id = load_identity(&identity)?;
            let micros = (amount * BASE_UNITS_PER_BEAT as f64) as u64;
            let meta = witness_reward_metadata(micros, &from, &to, &record_id);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
        }

        Commands::DormancyReclaim { amount, dormant_identity, last_activity, identity } => {
            let id = load_identity(&identity)?;
            let micros = (amount * BASE_UNITS_PER_BEAT as f64) as u64;
            let meta = dormancy_reclaim_metadata(micros, &dormant_identity, last_activity);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
        }

        Commands::PoolFund { amount, identity } => {
            let id = load_identity(&identity)?;
            let micros = (amount * BASE_UNITS_PER_BEAT as f64) as u64;
            let meta = pool_fund_metadata(micros);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
        }

        Commands::XzoneLock { to, amount, source_zone, dest_zone, identity } => {
            if to.len() != 64 || !to.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ElaraError::Wire("--to must be a 64-char hex identity hash".into()));
            }
            if source_zone == dest_zone {
                return Err(ElaraError::Wire("--source-zone and --dest-zone must differ".into()));
            }
            let id = load_identity(&identity)?;
            let micros = (amount * BASE_UNITS_PER_BEAT as f64) as u64;
            if micros == 0 {
                return Err(ElaraError::Wire("--amount must be > 0".into()));
            }
            let meta = xzone_lock_metadata(micros, &to, &source_zone, &dest_zone);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            let transfer_id = record.id.clone();
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
            println!(
                "xzone_lock submitted: transfer_id={} amount={} beat source={} dest={}",
                transfer_id, amount, source_zone, dest_zone
            );
        }

        Commands::XzoneClaim { transfer_id, amount, to, identity } => {
            if to.len() != 64 || !to.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ElaraError::Wire("--to must be a 64-char hex identity hash".into()));
            }
            let id = load_identity(&identity)?;
            let micros = (amount * BASE_UNITS_PER_BEAT as f64) as u64;
            if micros == 0 {
                return Err(ElaraError::Wire("--amount must be > 0".into()));
            }
            let meta = xzone_claim_metadata(&transfer_id, micros, &to);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            let claim_record_id = record.id.clone();
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
            println!(
                "xzone_claim submitted: claim_record_id={} transfer_id={} amount={} beat",
                claim_record_id, transfer_id, amount
            );
        }

        Commands::Record { id } => {
            let resp = pq.record_detail(&pq_addr, &id).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Commands::Health => {
            let resp = pq.health(&pq_addr).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Commands::Epochs => {
            let resp = pq.epoch_status(&pq_addr).await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Commands::IdentityInspect { file } => {
            let id = load_identity(&file)?;
            println!("Identity Hash:   {}", id.identity_hash);
            println!("Entity Type:     {:?}", id.entity_type);
            println!("Crypto Profile:  {:?}", id.profile);
            println!("Algorithm:       {}", id.algorithm);
            println!("PoW Difficulty:  {}", id.pow_difficulty);
            println!("PoW Nonce:       {}", id.pow_nonce);
            println!("Public Key:      {} bytes", id.public_key.len());
        }

        Commands::Propose { title, description, category, identity } => {
            let id = load_identity(&identity)?;
            let cat = ProposalCategory::parse(&category)?;
            let meta = propose_metadata(&cat, &title, &description);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
        }

        Commands::Vote { proposal_id, direction, identity } => {
            let id = load_identity(&identity)?;
            let dir = VoteDirection::parse(&direction)?;
            let meta = vote_metadata(&proposal_id, &dir);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
        }

        Commands::ExecuteProposal { proposal_id, identity } => {
            let id = load_identity(&identity)?;
            let meta = gov_execute_metadata(&proposal_id);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
        }

        Commands::CancelProposal { proposal_id, identity } => {
            let id = load_identity(&identity)?;
            let meta = gov_cancel_metadata(&proposal_id);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
        }

        Commands::Delegate { to, identity } => {
            let id = load_identity(&identity)?;
            let meta = delegate_metadata(&to);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
        }

        Commands::Undelegate { identity } => {
            let id = load_identity(&identity)?;
            let meta = undelegate_metadata();
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
        }

        Commands::Challenge { accused, challenge_type, evidence, identity } => {
            let id = load_identity(&identity)?;
            let evidence_list: Vec<&str> = evidence.split(',').map(|s| s.trim()).collect();
            let meta = file_challenge_metadata(&accused, &challenge_type, &evidence_list);
            let record = elara_runtime::accounting::types::create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
            println!("challenge filed: {}", record.id);
        }

        Commands::ChallengeVote { challenge_id, guilty, identity } => {
            let id = load_identity(&identity)?;
            let meta = challenge_vote_metadata(&challenge_id, guilty);
            let record = elara_runtime::accounting::types::create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
            println!("vote cast: {} (guilty={})", record.id, guilty);
        }

        Commands::ChallengeAppeal { challenge_id, reason, identity } => {
            let id = load_identity(&identity)?;
            let meta = challenge_appeal_metadata(&challenge_id, &reason);
            let record = elara_runtime::accounting::types::create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
            println!("appeal filed: {}", record.id);
        }

        Commands::PqAdminKeygen { out } => {
            use elara_runtime::crypto::pqc::dilithium3_keygen;
            let kp = dilithium3_keygen()
                .map_err(|e| ElaraError::Crypto(format!("ML-DSA-65 keygen: {e}")))?;
            let json = serde_json::json!({
                "scheme": "ML-DSA-65 (FIPS 204) / Dilithium3",
                "purpose": "elara-admin-pq-auth-v1",
                "public_key": hex::encode(&kp.public_key),
                "secret_key": hex::encode(&kp.secret_key),
            });
            std::fs::write(&out, serde_json::to_string_pretty(&json)?)
                .map_err(|e| ElaraError::Config(format!("write {}: {e}", out.display())))?;
            // Restrict permissions to owner-only on Unix (best-effort).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600));
            }
            println!("Wrote keypair to {}", out.display());
            println!("Pubkey hex (add to ELARA_ADMIN_PUBKEYS):");
            println!("{}", hex::encode(&kp.public_key));
        }

        Commands::PqAdminPubkey { key } => {
            let (pk, _sk) = load_pq_admin_keypair(&key)?;
            println!("{}", hex::encode(pk));
        }

        Commands::AdminSign { key, method, path } => {
            let (pk, sk) = load_pq_admin_keypair(&key)?;
            let hdr = elara_runtime::network::admin_pq_auth::build_admin_header(
                &sk, &pk, &method, &path,
            ).map_err(|e| ElaraError::Crypto(format!("admin sign: {e}")))?;
            // No newline: consumers pipe into curl -H "X-PQ-Admin: $(...)".
            print!("{}", hdr);
        }

        Commands::AgentEmit {
            identity, tool, action, args_hash, agent_id, session_id, mandate_ref, quiet, json,
            spool_dir,
        } => {
            // Resolve identity path — default to ~/.elara/identity.json.
            let id_path = identity.unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                PathBuf::from(home).join(".elara/identity.json")
            });
            let id = load_identity(&id_path)?;

            // Non-ledger Public ValidationRecord with metadata kind=agent_audit.
            // The slot key is (creator, nonce); a constant nonce would cap each
            // identity at ONE lifetime emit, so use the per-process session_nonce()
            // allocator (CSPRNG-salt-prefixed counter) — stronger than the prior
            // wall-clock-millis nonce, which collided on two emits in the same ms.
            let mut meta: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            meta.insert("kind".into(), serde_json::Value::String("agent_audit".into()));
            meta.insert("tool".into(), serde_json::Value::String(tool.clone()));
            // Lowercase the action: it is the agent-axis op (mandate scope is
            // matched exact-and-lowercase — internal design notes §3).
            meta.insert("action".into(), serde_json::Value::String(action.to_lowercase()));
            meta.insert("args_hash".into(), serde_json::Value::String(args_hash.to_lowercase()));
            meta.insert("agent_id".into(), serde_json::Value::String(agent_id.clone()));
            if let Some(sid) = session_id {
                meta.insert("session_id".into(), serde_json::Value::String(sid));
            }
            // Bind this act to a mandate when one is supplied — the record then
            // carries provable authority-to-act, queryable via /mandate/status.
            if let Some(mref) = mandate_ref.as_ref() {
                meta.insert(
                    MANDATE_REF_METADATA_KEY.into(),
                    serde_json::Value::String(mref.to_lowercase()),
                );
            }

            // G1 M5 INVARIANT: agent_audit records keep ZERO parents (the
            // `vec![]` below). The safety of late/spooled submission rests on
            // it — parentless records structurally skip both the causal check
            // and the 30-day past-skew gate at ingest; chaining them into a
            // DAG lineage would reactivate that gate and break the spool.
            let record = elara_runtime::accounting::types::create_ledger_record_with_nonce(
                &id, vec![], meta, session_nonce(),
            )?;
            let rid = record.id.clone();
            // G1 (a): one spool closure for every non-landed path (M2: Err AND
            // Indeterminate). Best-effort — a spool failure is loud on stderr
            // but never changes the emit's exit contract.
            let wire = record.to_bytes();
            let maybe_spool = |reason: &str| -> bool {
                if let Some(dir) = spool_dir.as_deref() {
                    match spool_record(dir, &rid, &wire, reason) {
                        Ok(()) => {
                            eprintln!("spooled: {rid} reason={reason}");
                            true
                        }
                        Err(e) => {
                            eprintln!("spool FAILED for {rid}: {e}");
                            false
                        }
                    }
                } else {
                    false
                }
            };
            if json {
                // Machine mode (the MCP server's boundary): exactly ONE JSON
                // line on stdout, NONZERO exit on anything that is not a
                // node-confirmed accept. An indeterminate response is reported
                // as not-ok — the record MAY have landed, but a machine caller
                // must never be told "success" on a body we could not read.
                // (The default human mode below deliberately exits 0 on failure
                // so PostToolUse hooks never cascade — the exit-0 inheritance
                // the elara-mcp audit refused to ship into programmatic use.)
                let outcome = submit_record_quiet(&pq, &pq_addr, &wire).await;
                // G1 M2: the spool decision comes from spool_reason (ONE
                // tested place, shared with the plain mode below) — Err AND
                // Indeterminate spool, Accepted never.
                let spooled = spool_reason(&outcome).map(|r| maybe_spool(&r)).unwrap_or(false);
                match outcome {
                    Ok(SubmitOutcome::Accepted(accepted_id)) => {
                        println!("{}", serde_json::json!({
                            "ok": true,
                            "record_id": accepted_id,
                            "tool": tool,
                            "action": action.to_lowercase(),
                            "mandate_ref": mandate_ref,
                        }));
                    }
                    Ok(SubmitOutcome::Indeterminate(body)) => {
                        // record_id rides along so the caller can resolve the
                        // ambiguity later via /mandate/status/{record_id}.
                        println!("{}", serde_json::json!({
                            "ok": false,
                            "error": "indeterminate: unclassifiable node response",
                            "record_id": rid,
                            "body": body,
                            "spooled": spooled,
                        }));
                        return Err(ElaraError::Network(
                            "agent-emit --json: indeterminate node response".into(),
                        ));
                    }
                    Err(e) => {
                        println!("{}", serde_json::json!({
                            "ok": false,
                            "error": format!("submit failed: {e}"),
                            "record_id": rid,
                            "spooled": spooled,
                        }));
                        return Err(ElaraError::Network(format!(
                            "agent-emit --json: submit failed: {e}"
                        )));
                    }
                }
                return Ok(());
            }
            // G1 M2: the plain path adopts the same three-way — the old
            // submit_record None-arm printed the raw body and returned Ok,
            // silently DISCARDING an unlanded record. Output stays
            // compatible (the "accepted: <id>" line the quickstart and the
            // receipt hook grep is preserved); only durability changes. The
            // spool decision is the SAME spool_reason as --json mode.
            let outcome = submit_record_quiet(&pq, &pq_addr, &wire).await;
            if let Some(reason) = spool_reason(&outcome) {
                maybe_spool(&reason);
            }
            match outcome {
                Ok(SubmitOutcome::Accepted(accepted_id)) => {
                    println!("accepted: {accepted_id}");
                }
                Ok(SubmitOutcome::Indeterminate(body)) => {
                    println!("{body}");
                    // Exit 0 so hook failures don't cascade into the agent.
                    return Ok(());
                }
                Err(e) => {
                    // Mirror the old submit_record's own rejection eprintln so
                    // stderr stays shape-compatible with pre-spool releases.
                    eprintln!("{e}");
                    if !quiet {
                        eprintln!("agent-emit failed: {e}");
                    }
                    // Exit 0 so hook failures don't cascade into the agent.
                    return Ok(());
                }
            }
            if !quiet {
                match mandate_ref.as_ref() {
                    Some(mref) => println!("agent-emit: {rid} tool={tool} action={action} mandate_ref={mref}"),
                    None => println!("agent-emit: {rid} tool={tool} action={action}"),
                }
            }
        }

        Commands::MirrorPublishEmit {
            identity, mirror_commit, mirror_repo, prev_mirror_commit, private_tip,
            acts_file, spool_dir, json,
        } => {
            // Fail-closed validation BEFORE anything is signed: a malformed
            // input must never produce a signed-but-wrong binding.
            let mirror_commit = validate_full_sha(&mirror_commit, "--mirror-commit")?;
            let prev_mirror_commit = prev_mirror_commit
                .as_deref()
                .map(|p| validate_full_sha(p, "--prev-mirror-commit"))
                .transpose()?;
            let private_tip = validate_full_sha(&private_tip, "--private-tip")?;
            let repo = mirror_repo.trim();
            if repo.is_empty()
                || repo.contains("://")
                || repo.contains(char::is_whitespace)
                || !repo.contains('/')
            {
                return Err(ElaraError::Config(format!(
                    "--mirror-repo must be a bare owner/name slug, got {repo:?}"
                )));
            }
            let rids = parse_acts_file(&acts_file)?;
            let acts_root = mirror_acts_root(&rids)?;

            let id = load_identity(&identity)?;
            let meta = build_mirror_publish_meta(
                &mirror_commit,
                repo,
                prev_mirror_commit.as_deref(),
                &private_tip,
                &acts_root,
                rids.len(),
            );
            // Zero parents — the same G1 M5 invariant as agent_audit: a
            // parentless record skips the causal + 30-day past-skew gates at
            // ingest, which is what makes late/spooled submission safe.
            let record = elara_runtime::accounting::types::create_ledger_record_with_nonce(
                &id, vec![], meta, session_nonce(),
            )?;
            let rid = record.id.clone();
            let wire = record.to_bytes();
            let maybe_spool = |reason: &str| -> bool {
                if let Some(dir) = spool_dir.as_deref() {
                    match spool_record(dir, &rid, &wire, reason) {
                        Ok(()) => {
                            eprintln!("spooled: {rid} reason={reason}");
                            true
                        }
                        Err(e) => {
                            eprintln!("spool FAILED for {rid}: {e}");
                            false
                        }
                    }
                } else {
                    false
                }
            };
            let outcome = submit_record_quiet(&pq, &pq_addr, &wire).await;
            let spooled = spool_reason(&outcome).map(|r| maybe_spool(&r)).unwrap_or(false);
            if json {
                // Machine mode: publish-mirror.sh reads this ONE line and
                // treats ok==true OR spooled==true as emit-or-spool verified.
                match outcome {
                    Ok(SubmitOutcome::Accepted(accepted_id)) => {
                        println!("{}", serde_json::json!({
                            "ok": true,
                            "record_id": accepted_id,
                            "acts_root": acts_root,
                            "acts_count": rids.len(),
                            "spooled": false,
                        }));
                        return Ok(());
                    }
                    Ok(SubmitOutcome::Indeterminate(body)) => {
                        println!("{}", serde_json::json!({
                            "ok": false,
                            "error": "indeterminate: unclassifiable node response",
                            "record_id": rid,
                            "body": body,
                            "spooled": spooled,
                        }));
                        return Err(ElaraError::Network(
                            "mirror-publish-emit --json: indeterminate node response".into(),
                        ));
                    }
                    Err(e) => {
                        println!("{}", serde_json::json!({
                            "ok": false,
                            "error": format!("submit failed: {e}"),
                            "record_id": rid,
                            "spooled": spooled,
                        }));
                        return Err(ElaraError::Network(format!(
                            "mirror-publish-emit --json: submit failed: {e}"
                        )));
                    }
                }
            }
            // Plain mode. DELIBERATE divergence from agent-emit: this emission
            // is load-bearing (emit-or-spool must be verifiable by the publish
            // flow), so a record that neither landed nor spooled exits NONZERO
            // instead of inheriting the hook-safe exit-0 contract.
            match outcome {
                Ok(SubmitOutcome::Accepted(accepted_id)) => {
                    println!("accepted: {accepted_id}");
                    println!(
                        "mirror-publish-emit: {rid} mirror_commit={mirror_commit} acts_count={} acts_root={acts_root}",
                        rids.len()
                    );
                }
                Ok(SubmitOutcome::Indeterminate(body)) => {
                    eprintln!("indeterminate node response: {body}");
                    if spooled {
                        println!("mirror-publish-emit: {rid} NOT confirmed — spooled for drain");
                    } else {
                        return Err(ElaraError::Network(
                            "mirror-publish-emit: record neither confirmed nor spooled".into(),
                        ));
                    }
                }
                Err(e) => {
                    eprintln!("mirror-publish-emit submit failed: {e}");
                    if spooled {
                        println!("mirror-publish-emit: {rid} NOT landed — spooled for drain");
                    } else {
                        return Err(ElaraError::Network(format!(
                            "mirror-publish-emit: submit failed and spool unavailable: {e}"
                        )));
                    }
                }
            }
        }

        Commands::MandateIssue { identity, agent, hours, ops, nonce } => {
            let id = load_identity(&identity)?;
            let net = effective_network.clone().ok_or_else(|| {
                ElaraError::Config(
                    "mandate network binding is load-bearing — pass --network <id> matching the \
                     target node (e.g. testnet)".into(),
                )
            })?;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .map_err(|_| ElaraError::Config("system clock before unix epoch".into()))?;
            let not_after_ms = now_ms.saturating_add(hours.saturating_mul(3_600_000));
            // v0 only enforces WILDCARD scope; a non-wildcard scope is recorded
            // but op/zone enforcement is deferred (status shows scope_deferred).
            let scope = if ops.trim() == "*" {
                MandateScope::wildcard()
            } else {
                MandateScope {
                    allowed_ops: ops
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                    allowed_zones: vec!["*".to_string()],
                    max_amount: None,
                }
            };
            let mnonce = nonce.unwrap_or_else(|| format!("{:016x}", session_nonce()));
            let mandate = MandateRecord::new_root(
                net.clone(),
                &id.identity_hash, // principal = this signer (ingest binds it)
                &agent,
                scope,
                now_ms,
                not_after_ms,
                0, // no sub-delegation
                mnonce,
            );
            if !mandate.is_well_formed() {
                return Err(ElaraError::Config(
                    "mandate is not well-formed — check --agent is a 64-hex identity hash and \
                     --hours > 0".into(),
                ));
            }
            let mandate_id = mandate.mandate_id();
            let mut meta: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            meta.insert(MANDATE_OP_KEY.into(), serde_json::to_value(&mandate)?);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            let rid = record.id.clone();
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
            println!(
                "mandate-issue: mandate_id={mandate_id} carrier_record={rid} \
                 principal={} agent={agent} network={net} window_hours={hours}",
                id.identity_hash
            );
        }

        Commands::MandateRevoke { identity, mandate_id, reason } => {
            let id = load_identity(&identity)?;
            let net = effective_network.clone().ok_or_else(|| {
                ElaraError::Config(
                    "mandate network binding is load-bearing — pass --network <id> matching the \
                     target node (e.g. testnet)".into(),
                )
            })?;
            let mandate_id = mandate_id.to_lowercase();
            let revocation = RevocationRecord::new(net.clone(), mandate_id.clone(), reason.clone());
            let mut meta: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            meta.insert(MANDATE_REVOCATION_OP_KEY.into(), serde_json::to_value(&revocation)?);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            let rid = record.id.clone();
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
            println!(
                "mandate-revoke: mandate_id={mandate_id} carrier_record={rid} \
                 revoker={} network={net} reason={reason:?}",
                id.identity_hash
            );
        }

        Commands::EmergencyHalt { identity, reason, max_duration_secs, nonce } => {
            let id = load_identity(&identity)?;
            let net = effective_network.clone().ok_or_else(|| {
                ElaraError::Config(
                    "emergency-halt network binding is load-bearing — pass --network <id> \
                     matching the target node (e.g. testnet)".into(),
                )
            })?;
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .map_err(|_| ElaraError::Config("system clock before unix epoch".into()))?;
            let nonce = nonce.unwrap_or(now_secs);
            let halt = EmergencyHalt {
                version: EMERGENCY_FORMAT_VERSION,
                network_id: net.clone(),
                nonce,
                issued_ts: now_secs,
                max_duration_secs,
                reason: reason.clone(),
            };
            if !halt.is_well_formed() {
                return Err(ElaraError::Config(
                    "emergency-halt not well-formed — --max-duration-secs must be > 0 and \
                     --reason <= 1 KiB".into(),
                ));
            }
            let mut meta: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            meta.insert(EMERGENCY_HALT_OP_KEY.into(), serde_json::to_value(&halt)?);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            let rid = record.id.clone();
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
            println!(
                "emergency-halt: nonce={nonce} carrier_record={rid} network={net} \
                 max_duration_secs={max_duration_secs} signer={} reason={reason:?}",
                id.identity_hash
            );
        }

        Commands::EmergencyResume { identity, halt_nonce } => {
            let id = load_identity(&identity)?;
            let net = effective_network.clone().ok_or_else(|| {
                ElaraError::Config(
                    "emergency-resume network binding is load-bearing — pass --network <id>".into(),
                )
            })?;
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .map_err(|_| ElaraError::Config("system clock before unix epoch".into()))?;
            let halt_nonce = halt_nonce.unwrap_or(now_secs);
            let resume = EmergencyResume {
                version: EMERGENCY_FORMAT_VERSION,
                network_id: net.clone(),
                halt_nonce,
                issued_ts: now_secs,
            };
            let mut meta: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            meta.insert(EMERGENCY_RESUME_OP_KEY.into(), serde_json::to_value(&resume)?);
            let record = create_ledger_record_with_nonce(&id, vec![], meta, session_nonce())?;
            let rid = record.id.clone();
            submit_record(&pq, &pq_addr, &record.to_bytes()).await?;
            println!(
                "emergency-resume: halt_nonce={halt_nonce} carrier_record={rid} network={net} \
                 signer={}",
                id.identity_hash
            );
        }

        Commands::LightHeaders { since, zone, limit } => {
            let body = pq
                .headers_from(&pq_addr, since, zone.as_deref(), limit)
                .await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }

        Commands::AccountProof { identity } => {
            let body = pq.account_proof(&pq_addr, &identity).await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }

        Commands::SealProgress { record_id } => {
            let body = pq.seal_progress(&pq_addr, &record_id).await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }

        Commands::Activity { identity } => {
            let body = pq.get_activity(&pq_addr, &identity).await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
        }

        Commands::Metrics => {
            let body = pq.get_metrics(&pq_addr).await?;
            print!("{body}");
        }

        Commands::Zones { action } => {
            // ZSP Phase E Slice 2: thin admin-HTTP wrapper. The /admin/*
            // surface lives behind verify_admin_auth_pq, which is the
            // Dilithium3-signed X-PQ-Admin header — so transport stays
            // plain HTTP but the auth boundary is post-quantum.
            run_zones_action(base, action).await?;
        }
        Commands::Realm { action } => match action {
            RealmAction::IssueCert { member, root_identity, valid_days, out } => {
                realm_issue_cert(&member, &root_identity, valid_days, &out)?;
            }
        },
    }

    Ok(())
}

/// ZSP Phase E Slice 2 — admin HTTP dispatcher for `Zones` subcommands.
/// Builds the X-PQ-Admin header from a PQ admin keypair, then issues a
fn build_admin_request(
    client: &reqwest::Client,
    method: &str,
    url: &str,
) -> Result<reqwest::RequestBuilder> {
    match method {
        "GET" => Ok(client.get(url)),
        "POST" => Ok(client.post(url)),
        m => Err(ElaraError::Wire(format!("unsupported admin HTTP method: {m}"))),
    }
}

/// reqwest GET/POST against the node's admin surface and prints the
/// response body. Errors (network, auth-rejected, JSON-parse) are
/// surfaced verbatim so operators can debug without a separate curl
/// step.
async fn run_zones_action(base: &str, action: ZonesAction) -> Result<()> {
    let (method_str, path, key, query) = match action {
        ZonesAction::Scope { key } => ("GET", "/admin/zones/scope", key, None),
        ZonesAction::Add { zone, key } => (
            "POST",
            "/admin/zones/subscribe",
            key,
            Some(format!("zone={}", urlencode_zone(&zone))),
        ),
        ZonesAction::Remove { zone, key } => (
            "POST",
            "/admin/zones/unsubscribe",
            key,
            Some(format!("zone={}", urlencode_zone(&zone))),
        ),
    };

    let (pk, sk) = load_pq_admin_keypair(&key)?;
    // V2: sign the full origin-form request target (path + `?query`) so the
    // query is bound into the signature — the server verifies against the same
    // bytes via `uri.query()`. Build the target once and reuse it for both the
    // signature and the URL, so the signed bytes are exactly the wire bytes.
    // The query here is already `urlencode_zone`-encoded to a url-safe subset,
    // so reqwest's `Url::parse` transmits it byte-for-byte (no re-encoding).
    let request_target = elara_runtime::network::admin_pq_auth::request_target_from_parts(
        path,
        query.as_deref(),
    );
    let header_value = elara_runtime::network::admin_pq_auth::build_admin_header(
        &sk, &pk, method_str, &request_target,
    )
    .map_err(|e| ElaraError::Crypto(format!("admin sign: {e}")))?;

    let url = format!("{}{}", base, request_target);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| ElaraError::Wire(format!("reqwest build: {e}")))?;

    let req = build_admin_request(&client, method_str, &url)?
        .header("X-PQ-Admin", header_value);

    let resp = req
        .send()
        .await
        .map_err(|e| ElaraError::Wire(format!("admin request to {url}: {e}")))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| ElaraError::Wire(format!("read response: {e}")))?;

    if !status.is_success() {
        return Err(ElaraError::Wire(format!(
            "admin {method_str} {path} returned {status}: {body}"
        )));
    }

    // Pretty-print JSON if we can; fall back to raw body otherwise.
    match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v)?),
        Err(_) => println!("{body}"),
    }
    Ok(())
}

/// Minimal URL-percent-encode for a zone-path query value. Zone paths
/// are normalized lowercase ASCII alphanumeric + `/` per
/// `ZoneId::new`, so the encoding surface is just `/` and any stray
/// reserved chars an operator might paste. Avoids pulling in a full
/// urlencoding crate for one verb.
fn urlencode_zone(zone: &str) -> String {
    let mut out = String::with_capacity(zone.len());
    for b in zone.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Load a Dilithium3 admin keypair from a JSON file produced by
/// `pq-admin-keygen`. Returns `(pubkey_bytes, secret_key_bytes)`.
fn load_pq_admin_keypair(path: &PathBuf) -> Result<(Vec<u8>, Vec<u8>)> {
    let json_str = std::fs::read_to_string(path)
        .map_err(|e| ElaraError::Config(format!("read {}: {e}", path.display())))?;
    let v: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| ElaraError::Config(format!("parse {}: {e}", path.display())))?;
    let pk_hex = v["public_key"].as_str()
        .ok_or_else(|| ElaraError::Config("missing 'public_key' in keypair file".into()))?;
    let sk_hex = v["secret_key"].as_str()
        .ok_or_else(|| ElaraError::Config("missing 'secret_key' in keypair file".into()))?;
    let pk = hex::decode(pk_hex)
        .map_err(|e| ElaraError::Config(format!("public_key not hex: {e}")))?;
    let sk = hex::decode(sk_hex)
        .map_err(|e| ElaraError::Config(format!("secret_key not hex: {e}")))?;
    if pk.len() != 1952 {
        return Err(ElaraError::Config(
            format!("public_key wrong length {} (expected 1952)", pk.len())
        ));
    }
    Ok((pk, sk))
}

/// REALMS P1 slice (d): offline federation cert issuance — sign a member's
/// identity hash with the realm root key and write the cert JSON the member
/// node loads via `realm_membership_cert_path`.
fn realm_issue_cert(
    member: &str,
    root_identity: &PathBuf,
    valid_days: u64,
    out: &PathBuf,
) -> Result<()> {
    use elara_runtime::network::realm::RealmMembershipCert;

    let member = member.to_ascii_lowercase();
    if member.len() != 64 || !member.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ElaraError::Config(
            "member must be a 64-char hex identity hash".into(),
        ));
    }
    let root = load_identity(root_identity)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ElaraError::Config("system clock before unix epoch".into()))?
        .as_secs();
    let expires_at = now.saturating_add(valid_days.saturating_mul(86_400));
    let cert = RealmMembershipCert::issue(
        &member,
        &root.public_key,
        &root.secret_key_bytes(),
        now,
        expires_at,
    )?;
    // Round-trip verify before writing — a cert that fails against its own
    // root is operator error worth failing loudly on, not discovering at
    // the member's first dial.
    cert.verify(&hex::encode(&root.public_key), &member, now)
        .map_err(|e| {
            ElaraError::Crypto(format!("freshly issued cert failed self-verify: {e}"))
        })?;
    let json = serde_json::to_string_pretty(&cert)?;
    std::fs::write(out, &json)
        .map_err(|e| ElaraError::Config(format!("failed to write cert: {e}")))?;
    println!("realm membership cert issued");
    println!("  member:      {member}");
    println!("  realm root:  {}…", &hex::encode(&root.public_key)[..16]);
    println!("  valid:       {valid_days} days (unix {now} → {expires_at})");
    println!("  written to:  {}", out.display());
    println!();
    println!("member node config (elara-node.toml):");
    println!("  realm_membership_cert_path = \"{}\"", out.display());
    Ok(())
}

fn load_identity(path: &PathBuf) -> Result<Identity> {
    use elara_runtime::identity::is_encrypted_identity;

    let json_str = std::fs::read_to_string(path)
        .map_err(|e| ElaraError::Config(format!("failed to read identity: {e}")))?;
    let data: BTreeMap<String, serde_json::Value> = serde_json::from_str(&json_str)?;

    if is_encrypted_identity(&data) {
        let passphrase = std::env::var("ELARA_IDENTITY_PASSPHRASE").map_err(|_| {
            ElaraError::Config(
                "identity is encrypted — set ELARA_IDENTITY_PASSPHRASE env var".into(),
            )
        })?;
        Identity::from_encrypted_json(&data, passphrase.as_bytes())
    } else {
        Identity::from_json(&data)
    }
}

/// Translate `--node` base URL ("https://host:9473") into a PQ peer addr
/// ("host:9573") using `offset`. Mirror of `network::gossip::http_to_pq_addr`
/// (which is `pub(crate)` and not reachable from a binary target).
fn http_to_pq_addr(base_url: &str, offset: u16) -> Option<String> {
    let without_scheme = base_url
        .strip_prefix("https://")
        .or_else(|| base_url.strip_prefix("http://"))
        .unwrap_or(base_url);
    let host_port = without_scheme.split('/').next()?;
    let (host, port_str) = host_port.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    Some(format!("{host}:{}", port.saturating_add(offset)))
}

/// Classify a submit-response body into (accepted_id, error_message, or unknown).
/// Returns Some(Ok(id)) on acceptance, Some(Err(_)) on a known rejection, None
/// for unrecognised shapes (caller falls back to printing the raw body).
fn classify_submit_body(body: &serde_json::Value) -> Option<Result<String>> {
    if let Some(true) = body["accepted"].as_bool() {
        let id = body["id"].as_str().unwrap_or("unknown").to_string();
        Some(Ok(id))
    } else { body.get("reason").or_else(|| body.get("error")).map(|reason| Err(ElaraError::Network(format!("submit failed: {reason}")))) }
}

/// Outcome of a classified, non-printing submit — the machine-caller boundary.
/// `Indeterminate` is a response body `classify_submit_body` cannot read: the
/// record MAY have landed; callers must never report it as success.
#[derive(Debug)]
enum SubmitOutcome {
    Accepted(String),
    Indeterminate(String),
}

/// G1 M3: map a node rejection reason to the drain taxonomy, matching the
/// EXACT ingest reason strings in ONE tested place (never shell substrings):
/// - "quota" — any admission throttle (daily cap ingest.rs "daily record
///   limit exceeded", hourly "exceeds propagation rate limit", global
///   "global rate limit exceeded"); drain STOPS, retries next run.
/// - "embargoed" — the node's gossip_rejected memo ("previously_rejected"):
///   it remembers refusing this id once and short-circuits every resubmit
///   until the memo clears (node restart, or the transient-reject
///   reclassification). Not the record's fault: drain keeps the file, burns
///   NO attempt, continues.
/// - "duplicate" — duplicate-shaped rejection (already on chain via a path
///   that errors instead of the success-shaped storage dedup); drain treats
///   as landed.
/// - "error" — everything else; drain leaves the file, loud, continues.
///
/// ─── mirror-publish-emit helpers (G4-PUBLIC-BINDING FINAL RULING §2/§7) ───
///
/// Validate + normalize a full git object sha: exactly 40 ASCII hex chars,
/// returned lowercase. Fail-closed — a short/abbreviated sha is REFUSED, never
/// padded or accepted (28 bits is not a binding).
fn validate_full_sha(s: &str, what: &str) -> Result<String> {
    let t = s.trim();
    if t.len() == 40 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(t.to_ascii_lowercase())
    } else {
        Err(ElaraError::Config(format!(
            "{what} must be a FULL 40-hex-char sha (got {} chars) — short shas are not a binding",
            t.len()
        )))
    }
}

/// The publicly-documented acts_root construction: an elara-smt tree with one
/// entry per unique commit-receipt record_id — `update(k, k)` where
/// `k = SHA3-256(record_id ascii bytes)` — root hex-encoded. Order-independent
/// and dedup-canonical by construction (keyed tree, set semantics), so a
/// stranger recomputing from the published feed diff needs no ordering rules.
/// The empty window yields the SMT empty root (SHA3-256 of empty input).
fn mirror_acts_root(rids: &std::collections::BTreeSet<String>) -> Result<String> {
    use sha3::{Digest, Sha3_256};
    let mut tree = elara_smt::SparseMerkleTree::new(elara_smt::MemorySmtStore::new());
    for rid in rids {
        let k: [u8; 32] = Sha3_256::digest(rid.as_bytes()).into();
        tree.update(&k, &k)
            .map_err(|e| ElaraError::Config(format!("acts_root smt update: {e:?}")))?;
    }
    tree.commit()
        .map_err(|e| ElaraError::Config(format!("acts_root smt commit: {e:?}")))?;
    let root = tree
        .root()
        .map_err(|e| ElaraError::Config(format!("acts_root smt root: {e:?}")))?;
    Ok(hex::encode(root))
}

/// Parse the acts file: one record_id per line, trimmed, blank lines skipped,
/// deduplicated. Each id is bounded (≤64 bytes) and charset-checked (lowercase
/// hex + hyphens — the receipt-id shape) so a mangled file fails HERE, before
/// anything is signed.
fn parse_acts_file(path: &Path) -> Result<std::collections::BTreeSet<String>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| ElaraError::Config(format!("acts file {}: {e}", path.display())))?;
    let mut rids = std::collections::BTreeSet::new();
    for (n, line) in text.lines().enumerate() {
        let rid = line.trim();
        if rid.is_empty() {
            continue;
        }
        let ok = rid.len() <= 64
            && rid
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c) || c == '-');
        if !ok {
            return Err(ElaraError::Config(format!(
                "acts file line {}: {rid:?} is not a receipt record_id (lowercase hex + hyphens, ≤64 bytes)",
                n + 1
            )));
        }
        rids.insert(rid.to_string());
    }
    Ok(rids)
}

/// Build the mirror_publish_act metadata map — the FIXED schema, all seven
/// keys (+ the `action` verb): kind, action, mirror_commit, mirror_repo,
/// prev_mirror_commit (omitted only on an initial publish), args_hash =
/// SHA3-256(private tip sha ascii), acts_root, acts_count. Inputs are assumed
/// already validated/normalized by the callers above.
fn build_mirror_publish_meta(
    mirror_commit: &str,
    mirror_repo: &str,
    prev_mirror_commit: Option<&str>,
    private_tip: &str,
    acts_root: &str,
    acts_count: usize,
) -> BTreeMap<String, serde_json::Value> {
    use sha3::{Digest, Sha3_256};
    let s = |v: &str| serde_json::Value::String(v.into());
    let mut meta: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    meta.insert("kind".into(), s("mirror_publish_act"));
    meta.insert("action".into(), s("publish-mirror"));
    meta.insert("mirror_commit".into(), s(mirror_commit));
    meta.insert("mirror_repo".into(), s(mirror_repo));
    if let Some(prev) = prev_mirror_commit {
        meta.insert("prev_mirror_commit".into(), s(prev));
    }
    let args_hash: [u8; 32] = Sha3_256::digest(private_tip.as_bytes()).into();
    meta.insert("args_hash".into(), s(&hex::encode(args_hash)));
    meta.insert("acts_root".into(), s(acts_root));
    meta.insert("acts_count".into(), s(&acts_count.to_string()));
    meta
}

fn submit_class(reason: &str) -> &'static str {
    let r = reason.to_ascii_lowercase();
    if r.contains("daily record limit exceeded")
        || r.contains("exceeds propagation rate limit")
        || r.contains("global rate limit exceeded")
    {
        "quota"
    } else if r.contains("previously_rejected") {
        "embargoed"
    } else if r.contains("duplicate") {
        "duplicate"
    } else {
        "error"
    }
}

/// G1 M2: the ONE spool decision, shared by both agent-emit output modes —
/// every non-landed outcome spools. `Accepted` = landed (never spool);
/// `Indeterminate` AND `Err` both spool (the pre-G1 plain path silently
/// discarded unlanded records on exactly these arms).
fn spool_reason(outcome: &Result<SubmitOutcome>) -> Option<String> {
    match outcome {
        Ok(SubmitOutcome::Accepted(_)) => None,
        Ok(SubmitOutcome::Indeterminate(_)) => Some("indeterminate node response".into()),
        Err(e) => Some(format!("submit failed: {e}")),
    }
}

/// G1 (a): durably spool a signed-but-unlanded emission. Layout:
/// `<dir>/pending/<record_id>.wire` (the verbatim canonical bytes `elara-cli
/// submit` takes — M1: the drain NEVER re-signs) + `<record_id>.reason` (one
/// line: why it did not land). Atomic within one filesystem: write to a tmp
/// name INSIDE pending/, then rename. Bounded: at ≥4096 pending entries the
/// spool refuses LOUDLY (stderr) rather than grow unbounded; the count-then-
/// write race is accepted as bounded overshoot (single-digit concurrent
/// writers at worst — the drain holds the real lock).
fn spool_record(dir: &Path, rid: &str, wire: &[u8], reason: &str) -> std::io::Result<()> {
    let pending = dir.join("pending");
    std::fs::create_dir_all(&pending)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o700));
    }
    let count = std::fs::read_dir(&pending)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "wire"))
        .count();
    if count >= 4096 {
        eprintln!(
            "spool FULL ({count} pending) — refusing to spool {rid}; drain the spool (scripts/elara-spool-drain.sh)"
        );
        return Err(std::io::Error::other("spool full"));
    }
    let tmp = pending.join(format!(".tmp-{rid}"));
    std::fs::write(&tmp, wire)?;
    std::fs::rename(&tmp, pending.join(format!("{rid}.wire")))?;
    let ts = chrono::Utc::now().to_rfc3339();
    std::fs::write(
        pending.join(format!("{rid}.reason")),
        format!("{ts} {reason}\n"),
    )?;
    // G4 leg: a `<rid>.class` sidecar = the record's `kind`, so the spool drain
    // can PRIORITIZE the mirror_publish_act class and fire the P1 "publish
    // receipt spooled" alert without decoding the wire in bash. Best-effort —
    // a decode failure or missing `kind` just omits the sidecar (the drain
    // then treats the entry as normal priority), and NEVER fails the spool.
    if let Ok(rec) = elara_runtime::record::ValidationRecord::from_bytes(wire) {
        if let Some(kind) = rec.metadata.get("kind").and_then(|v| v.as_str()) {
            let _ = std::fs::write(pending.join(format!("{rid}.class")), format!("{kind}\n"));
        }
    }
    Ok(())
}

/// Pure mapping from a node response body to the machine-caller outcome —
/// split from the transport so the three arms are unit-testable.
fn outcome_from_body(body: &serde_json::Value) -> Result<SubmitOutcome> {
    match classify_submit_body(body) {
        Some(Ok(id)) => Ok(SubmitOutcome::Accepted(id)),
        Some(Err(e)) => Err(e),
        None => Ok(SubmitOutcome::Indeterminate(body.to_string())),
    }
}

/// PQ-only record submission, no printing. Returns the classified outcome so a
/// machine caller (agent-emit --json → the MCP server) gets the truth on one
/// channel: Err = transport failure or node rejection, Accepted = the node said
/// so, Indeterminate = unknown-shaped body (NOT success).
async fn submit_record_quiet(
    pq: &PqNodeClient, addr: &str, wire_bytes: &[u8],
) -> Result<SubmitOutcome> {
    let body = pq.submit_record(addr, wire_bytes).await?;
    outcome_from_body(&body)
}

/// PQ-only record submission. Returns Err on any failure — no HTTPS fallback.
/// Output shape is load-bearing (the issuer quickstart greps `^accepted: `);
/// kept byte-identical to the pre-`--json` behavior: node rejections eprintln
/// here, transport errors propagate silently to the caller.
async fn submit_record(pq: &PqNodeClient, addr: &str, wire_bytes: &[u8]) -> Result<()> {
    let body = pq.submit_record(addr, wire_bytes).await?;
    match classify_submit_body(&body) {
        Some(Ok(id)) => {
            println!("accepted: {id}");
            Ok(())
        }
        Some(Err(e)) => {
            eprintln!("{e}");
            Err(e)
        }
        None => {
            println!("{body}");
            Ok(())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── session_nonce ─────────────────────────────────────────────────────

    #[test]
    fn session_nonce_is_unique_and_salt_prefixed() {
        // The slot-equivocation gate permanently conflicts a slot if one identity
        // ever claims the same (account, nonce) with two different records, so the
        // per-process allocator MUST never repeat a value. Verify: every nonce in
        // a process is unique (low-word counter), and all share the same high-32-bit
        // CSPRNG session salt (the partition that keeps concurrent processes apart).
        let vals: Vec<u64> = (0..10_000).map(|_| session_nonce()).collect();
        let uniq: std::collections::HashSet<u64> = vals.iter().copied().collect();
        assert_eq!(uniq.len(), vals.len(), "every session nonce must be unique");
        let salt = vals[0] >> 32;
        assert!(
            vals.iter().all(|v| v >> 32 == salt),
            "all nonces in one process share the high-32-bit session salt"
        );
        // Low word is the monotonic per-process counter (gappy only if another
        // caller interleaves, which it can't within this single test body).
        assert!(
            vals.windows(2).all(|w| w[1] > w[0]),
            "the per-process counter is strictly increasing"
        );
    }

    // ─── urlencode_zone ────────────────────────────────────────────────────

    #[test]
    fn urlencode_zone_passes_through_unreserved_alphanumeric() {
        assert_eq!(urlencode_zone("zone1"), "zone1");
        assert_eq!(urlencode_zone("AaBb09"), "AaBb09");
    }

    #[test]
    fn urlencode_zone_passes_through_unreserved_punctuation() {
        // RFC3986 unreserved: A-Z a-z 0-9 - _ . ~
        assert_eq!(urlencode_zone("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn urlencode_zone_percent_encodes_reserved_chars() {
        assert_eq!(urlencode_zone("/"), "%2F");
        assert_eq!(urlencode_zone("?"), "%3F");
        assert_eq!(urlencode_zone("#"), "%23");
        assert_eq!(urlencode_zone(" "), "%20");
    }

    #[test]
    fn urlencode_zone_percent_encodes_uppercase_hex() {
        // Spec: hex MUST be uppercase per RFC3986 §2.1
        assert_eq!(urlencode_zone("\x0F"), "%0F");
        // U+00FF encodes to UTF-8 as 0xC3 0xBF; each byte percent-encoded
        assert_eq!(urlencode_zone("\u{FF}"), "%C3%BF");
    }

    #[test]
    fn urlencode_zone_empty_input() {
        assert_eq!(urlencode_zone(""), "");
    }

    #[test]
    fn urlencode_zone_mixed_safe_and_unsafe() {
        assert_eq!(urlencode_zone("a/b"), "a%2Fb");
        assert_eq!(urlencode_zone("zone with spaces"), "zone%20with%20spaces");
    }

    // ─── http_to_pq_addr ──────────────────────────────────────────────────

    #[test]
    fn http_to_pq_addr_https_scheme() {
        // Account's TLS endpoint at 9473, PQ peer 100 above at 9573
        assert_eq!(
            http_to_pq_addr("https://localhost:9473", 100),
            Some("localhost:9573".to_string())
        );
    }

    #[test]
    fn http_to_pq_addr_http_scheme() {
        assert_eq!(
            http_to_pq_addr("http://example.com:8080", 1),
            Some("example.com:8081".to_string())
        );
    }

    #[test]
    fn http_to_pq_addr_no_scheme() {
        // Accept bare "host:port" too
        assert_eq!(
            http_to_pq_addr("host:1234", 10),
            Some("host:1244".to_string())
        );
    }

    #[test]
    fn http_to_pq_addr_strips_path() {
        // /api/v1/foo must be ignored — only host:port matters
        assert_eq!(
            http_to_pq_addr("https://node.example:9473/api/v1/foo", 100),
            Some("node.example:9573".to_string())
        );
    }

    #[test]
    fn http_to_pq_addr_ipv4() {
        assert_eq!(
            http_to_pq_addr("https://203.0.113.7:9473", 100),
            Some("203.0.113.7:9573".to_string())
        );
    }

    #[test]
    fn http_to_pq_addr_missing_port_returns_none() {
        assert_eq!(http_to_pq_addr("https://hostonly", 100), None);
        assert_eq!(http_to_pq_addr("host", 100), None);
    }

    #[test]
    fn http_to_pq_addr_non_numeric_port_returns_none() {
        assert_eq!(http_to_pq_addr("https://host:abc", 100), None);
    }

    #[test]
    fn http_to_pq_addr_offset_zero_keeps_port() {
        assert_eq!(
            http_to_pq_addr("https://host:9473", 0),
            Some("host:9473".to_string())
        );
    }

    #[test]
    fn http_to_pq_addr_saturates_at_u16_max() {
        // Port + offset overflow → saturating_add caps at u16::MAX
        assert_eq!(
            http_to_pq_addr("https://host:60000", 10000),
            Some("host:65535".to_string()),
            "should saturate at 65535"
        );
    }

    // ─── urlencode byte-sweep invariant tests ─────────────────────────────

    #[test]
    fn batch_b_urlencode_zone_full_byte_sweep_unreserved_or_uppercase_hex() {
        // Sweep every single-byte input 0x00..=0xFF and verify the output
        // is EITHER a single unreserved character OR an exact "%HH" with
        // uppercase hex digits. Catches any future drift in either the
        // unreserved-set membership or the hex casing.
        for b in 0u8..=255 {
            let s = if b.is_ascii() {
                String::from(b as char)
            } else {
                // Single non-ASCII byte → make a one-byte UTF-8 string by
                // going through a Vec<u8> isn't safe; instead, build via
                // unsafe? No — use bytes() directly: build a String from a
                // single Latin-1 codepoint that encodes as 2 UTF-8 bytes.
                // To keep this single-byte we constrain to ASCII range.
                continue;
            };
            let out = urlencode_zone(&s);
            let is_unreserved = matches!(
                b,
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~'
            );
            if is_unreserved {
                assert_eq!(out, s, "byte 0x{b:02X} should pass through unchanged");
            } else {
                assert_eq!(out.len(), 3, "byte 0x{b:02X} should encode to 3 chars, got {out:?}");
                assert!(out.starts_with('%'), "byte 0x{b:02X} encoding must start with %");
                let hex = &out[1..];
                assert_eq!(hex.len(), 2);
                for c in hex.chars() {
                    assert!(
                        c.is_ascii_digit() || ('A'..='F').contains(&c),
                        "hex digit must be uppercase ASCII: {c:?} in {out:?}"
                    );
                }
                let parsed = u8::from_str_radix(hex, 16).unwrap();
                assert_eq!(parsed, b, "hex {hex} must decode back to source byte 0x{b:02X}");
            }
        }
    }

    #[test]
    fn batch_b_urlencode_zone_output_length_bounded_by_3x_input_bytes() {
        // Worst-case expansion: every byte becomes "%XX" — i.e. 3× input
        // bytes. Pin this upper bound so a future refactor that does, say,
        // "%XXXX" (overlong) gets caught. Lower bound: output ≥ input
        // (each byte ≥ 1 char of output).
        for input in [
            "",
            "x",
            "/",
            "?",
            "abcdefghij",
            "\x00\x01\x02\x03",
            "zone with spaces and / and ?",
            "/?#@[]{}",
        ] {
            let out = urlencode_zone(input);
            assert!(
                out.len() <= input.len() * 3,
                "output {} bytes exceeds 3x of {} bytes for input {input:?}",
                out.len(),
                input.len()
            );
            assert!(
                out.len() >= input.len()
                    || input.bytes().all(|b| !b.is_ascii()),
                "output {} bytes shorter than {} input bytes for {input:?}",
                out.len(),
                input.len()
            );
        }
    }

    #[test]
    fn batch_b_urlencode_zone_not_idempotent_because_percent_itself_encodes() {
        // urlencode_zone is NOT idempotent: `%` is not in the unreserved
        // set, so it encodes to `%25`. Applying twice yields a different
        // result from once. Pin this so callers know not to double-encode.
        let once = urlencode_zone("a%b");
        assert_eq!(once, "a%25b");
        let twice = urlencode_zone(&once);
        assert_eq!(twice, "a%2525b");
        assert_ne!(once, twice, "urlencode_zone must NOT be idempotent");
        // Also verify multi-byte UTF-8 codepoint encodes byte-by-byte
        // (NOT codepoint-by-codepoint). U+00FF = [0xC3, 0xBF] → "%C3%BF".
        assert_eq!(urlencode_zone("\u{FF}"), "%C3%BF");
        // U+1F600 (😀) = [0xF0, 0x9F, 0x98, 0x80] → 4 %XX groups.
        let smile = urlencode_zone("\u{1F600}");
        assert_eq!(smile, "%F0%9F%98%80");
        assert_eq!(smile.len(), 12); // 4 bytes × 3 chars each
    }

    #[test]
    fn batch_b_http_to_pq_addr_offset_saturation_corner_cases() {
        // saturating_add behavior at the u16 boundary — pin three corners
        // that a non-saturating impl would mis-handle (silent wrap to 0).
        // Corner 1: port=0 + offset=u16::MAX → 65535
        assert_eq!(
            http_to_pq_addr("http://h:0", u16::MAX),
            Some("h:65535".to_string())
        );
        // Corner 2: port=u16::MAX + offset=0 → 65535
        assert_eq!(
            http_to_pq_addr("http://h:65535", 0),
            Some("h:65535".to_string())
        );
        // Corner 3: port=u16::MAX + offset=u16::MAX → saturates at 65535
        // (a wrapping_add would give u16::MAX-1 = 65534).
        assert_eq!(
            http_to_pq_addr("http://h:65535", u16::MAX),
            Some("h:65535".to_string())
        );
        // Corner 4: port=1 + offset=u16::MAX → saturates (NOT wraps to 0).
        assert_eq!(
            http_to_pq_addr("http://h:1", u16::MAX),
            Some("h:65535".to_string())
        );
    }

    #[test]
    fn batch_b_http_to_pq_addr_empty_and_malformed_inputs_return_none() {
        // Defensive: every shape that can't yield a valid host:port must
        // return None rather than panic or emit malformed output.
        // Empty input.
        assert_eq!(http_to_pq_addr("", 100), None);
        // Just a colon — no host portion.
        // Note: ":80" parses as host="" and port=80, which is valid.
        // The malformed cases are inputs with NO colon (no port).
        assert_eq!(http_to_pq_addr("hostonly", 100), None);
        assert_eq!(http_to_pq_addr("https://hostonly", 100), None);
        // Port out-of-range for u16.
        assert_eq!(http_to_pq_addr("http://h:99999", 0), None);
        // Negative port.
        assert_eq!(http_to_pq_addr("http://h:-1", 0), None);
        // Non-numeric port.
        assert_eq!(http_to_pq_addr("http://host:port", 0), None);
        // Hex port (parser is decimal-only).
        assert_eq!(http_to_pq_addr("http://h:0xFF", 0), None);
    }

    // ─── classify_submit_body ─────────────────────────────────────────────

    #[test]
    fn classify_submit_body_accepted_returns_id() {
        let body = serde_json::json!({"accepted": true, "id": "rec-abc"});
        assert_eq!(
            classify_submit_body(&body).unwrap().unwrap(),
            "rec-abc"
        );
    }

    #[test]
    fn classify_submit_body_accepted_missing_id_falls_back_to_unknown() {
        let body = serde_json::json!({"accepted": true});
        assert_eq!(
            classify_submit_body(&body).unwrap().unwrap(),
            "unknown"
        );
    }

    #[test]
    fn classify_submit_body_reason_field_returns_err() {
        let body = serde_json::json!({"reason": "duplicate record"});
        let err = classify_submit_body(&body).unwrap().unwrap_err();
        assert!(err.to_string().contains("duplicate record"));
    }

    #[test]
    fn classify_submit_body_error_field_returns_err() {
        let body = serde_json::json!({"error": "quota exceeded"});
        let err = classify_submit_body(&body).unwrap().unwrap_err();
        assert!(err.to_string().contains("quota exceeded"));
    }

    #[test]
    fn classify_submit_body_unknown_shape_returns_none() {
        let body = serde_json::json!({"status": "pending"});
        assert!(classify_submit_body(&body).is_none());
    }

    // ─── outcome_from_body (agent-emit --json machine boundary) ────────────

    #[test]
    fn outcome_from_body_pins_all_three_arms() {
        // The --json contract (MCP-MANDATE-SERVER-VERDICT build-order item 1):
        // accept = Accepted(id); rejection = Err; unknown-shaped body =
        // Indeterminate, NEVER success — a machine caller must not be told
        // "ok" on a body we could not classify.
        let ok = outcome_from_body(&serde_json::json!({"accepted": true, "id": "r-1"})).unwrap();
        assert!(matches!(ok, SubmitOutcome::Accepted(ref id) if id == "r-1"));

        let err = outcome_from_body(&serde_json::json!({"reason": "network_mismatch"})).unwrap_err();
        assert!(err.to_string().contains("network_mismatch"));

        let ind = outcome_from_body(&serde_json::json!({"status": "pending"})).unwrap();
        match ind {
            SubmitOutcome::Indeterminate(body) => assert!(body.contains("pending")),
            SubmitOutcome::Accepted(_) => panic!("unknown body must never classify as Accepted"),
        }
    }

    #[test]
    fn build_admin_request_rejects_unknown_method() {
        let client = reqwest::Client::new();
        let err = build_admin_request(&client, "DELETE", "http://localhost:9473/admin/test")
            .unwrap_err();
        assert!(err.to_string().contains("unsupported admin HTTP method: DELETE"));
    }

    #[test]
    fn serde_json_error_converts_to_json_variant() {
        // Verifies that serde_json::Error converts to ElaraError::Json via From,
        // so `?` on to_string_pretty propagates as a typed error instead of panicking.
        use elara_runtime::errors::ElaraError;
        let json_err = serde_json::from_str::<serde_json::Value>("not-json").unwrap_err();
        let wrapped: ElaraError = json_err.into();
        assert!(matches!(wrapped, ElaraError::Json(_)));
    }

    #[test]
    fn realm_issue_cert_writes_loadable_verifying_cert() {
        use elara_runtime::identity::{CryptoProfile, EntityType};
        use elara_runtime::network::realm::RealmMembershipCert;

        let tmp = tempfile::tempdir().unwrap();
        let root =
            Identity::generate(EntityType::Device, CryptoProfile::ProfileB).unwrap();
        let root_path = tmp.path().join("root-identity.json");
        std::fs::write(
            &root_path,
            serde_json::to_string(&root.to_json()).unwrap(),
        )
        .unwrap();

        let member = "ab".repeat(32);
        let out = tmp.path().join("member-cert.json");
        realm_issue_cert(&member, &root_path, 30, &out).unwrap();

        // The written file is exactly what a member node loads at boot.
        let cert = RealmMembershipCert::load(&out).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        cert.verify(&hex::encode(&root.public_key), &member, now).unwrap();
        // A different identity must NOT pass under this cert.
        assert!(cert
            .verify(&hex::encode(&root.public_key), &"cd".repeat(32), now)
            .is_err());
        // Uppercase member input normalizes at issue time.
        let out2 = tmp.path().join("member-cert-upper.json");
        realm_issue_cert(&member.to_ascii_uppercase(), &root_path, 30, &out2).unwrap();
        let cert2 = RealmMembershipCert::load(&out2).unwrap();
        cert2.verify(&hex::encode(&root.public_key), &member, now).unwrap();
    }
}

#[cfg(test)]
mod g1_spool_tests {
    use super::{
        build_mirror_publish_meta, mirror_acts_root, parse_acts_file, spool_reason, spool_record,
        submit_class, validate_full_sha, ElaraError, SubmitOutcome,
    };

    /// M3: the quota class matches the EXACT live ingest reason strings for
    /// all three throttle shapes (the stake-gated daily cap exits through the
    /// same ingest.rs:2288 string as the tier cap — one string, four shapes);
    /// the node's gossip_rejected memo classifies embargoed; duplicates
    /// classify duplicate; anything else is error. (Strings verbatim from
    /// src/network/ingest.rs + routes/core.rs.)
    #[test]
    fn submit_class_covers_all_throttle_shapes_embargo_and_duplicate() {
        assert_eq!(
            submit_class("submit failed: daily record limit exceeded: identity limited to 20/day"),
            "quota"
        );
        assert_eq!(
            submit_class("submit failed: identity abcd exceeds propagation rate limit (100/hr, base=100, stake_bonus=0)"),
            "quota"
        );
        assert_eq!(submit_class("submit failed: global rate limit exceeded (500/min)"), "quota");
        // Live-observed 2026-08-24: resubmitting a cap-refused record returns
        // the rejection-memo reason, not the cap string.
        assert_eq!(submit_class("Network error: submit failed: \"previously_rejected\""), "embargoed");
        assert_eq!(submit_class("submit failed: duplicate record"), "duplicate");
        assert_eq!(submit_class("submit failed: invalid signature"), "error");
    }

    /// M2 pin: the ONE spool decision both agent-emit output modes share —
    /// Indeterminate AND Err spool (the pre-G1 silent-loss arms), Accepted
    /// never does.
    #[test]
    fn spool_reason_covers_indeterminate_and_err_never_accepted() {
        assert!(spool_reason(&Ok(SubmitOutcome::Accepted("rid".into()))).is_none());
        let indeterminate = spool_reason(&Ok(SubmitOutcome::Indeterminate("{}".into())))
            .expect("indeterminate must spool");
        assert!(indeterminate.contains("indeterminate"));
        let err = spool_reason(&Err(ElaraError::Network("connection refused".into())))
            .expect("submit error must spool");
        assert!(err.contains("connection refused"));
    }

    /// M1 pin (the substance): what is spooled is the VERBATIM canonical wire
    /// of the already-signed record — decoding the spool file yields the SAME
    /// record id, so `elara-cli submit <file>` resubmits without re-signing
    /// (no fresh nonce, no new id, no extra cap slots).
    #[test]
    fn spooled_wire_roundtrips_to_the_same_record_id() {
        let id = elara_runtime::identity::Identity::generate(
            elara_runtime::identity::EntityType::Ai,
            elara_runtime::identity::CryptoProfile::ProfileB,
        )
        .expect("identity");
        let mut meta = std::collections::BTreeMap::new();
        meta.insert("kind".into(), serde_json::Value::String("agent_audit".into()));
        meta.insert("tool".into(), serde_json::Value::String("git".into()));
        let record = elara_runtime::accounting::types::create_ledger_record_with_nonce(
            &id, vec![], meta, 42,
        )
        .expect("record");
        let rid = record.id.clone();
        let wire = record.to_bytes();

        let dir = tempfile::tempdir().expect("tmpdir");
        spool_record(dir.path(), &rid, &wire, "test: daily record limit exceeded").expect("spool");

        let spooled = std::fs::read(dir.path().join("pending").join(format!("{rid}.wire")))
            .expect("spool file");
        assert_eq!(spooled, wire, "spool must be byte-verbatim");
        let decoded = elara_runtime::record::ValidationRecord::from_bytes(&spooled)
            .expect("spooled bytes decode");
        assert_eq!(decoded.id, rid, "drained id == spooled id (M1)");
        let reason = std::fs::read_to_string(
            dir.path().join("pending").join(format!("{rid}.reason")),
        )
        .expect("sidecar");
        assert!(reason.contains("daily record limit exceeded"));
    }

    // ─── mirror-publish-emit (G4-PUBLIC-BINDING FINAL RULING §2/§7) ────────

    #[test]
    fn validate_full_sha_is_fail_closed() {
        // 40 hex passes and normalizes to lowercase.
        let up = "F7B1746A0011EEFF2233445566778899AABBCCDD";
        assert_eq!(
            validate_full_sha(up, "t").expect("full sha"),
            up.to_ascii_lowercase()
        );
        // Short (the ledger's human-only 8-char), long, and non-hex all REFUSE —
        // an abbreviated sha must never become a signed binding.
        for bad in ["f7b1746a", &format!("{}0", up), "z7b1746a0011eeff2233445566778899aabbccdd"] {
            assert!(validate_full_sha(bad, "t").is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn mirror_acts_root_matches_documented_construction() {
        use sha3::{Digest, Sha3_256};
        // Empty window = the SMT empty root = SHA3-256 of empty input. This is
        // the documented sentinel a stranger can verify without our code.
        let empty = mirror_acts_root(&std::collections::BTreeSet::new()).expect("empty root");
        assert_eq!(empty, hex::encode(elara_smt::empty_hash()));

        // Non-empty: the helper must equal a direct elara-smt build with the
        // documented construction — update(k, k), k = SHA3-256(rid ascii).
        let rids: std::collections::BTreeSet<String> = [
            "01a0339a-4860-7ea2-8f74-b9f37885e8bb",
            "01a033b9-b267-7540-bb87-bd253aab4a40",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let got = mirror_acts_root(&rids).expect("root");
        let mut tree = elara_smt::SparseMerkleTree::new(elara_smt::MemorySmtStore::new());
        for rid in &rids {
            let k: [u8; 32] = Sha3_256::digest(rid.as_bytes()).into();
            tree.update(&k, &k).unwrap();
        }
        tree.commit().unwrap();
        assert_eq!(got, hex::encode(tree.root().unwrap()));
        assert_ne!(got, empty, "non-empty window has a distinct root");
    }

    #[test]
    fn parse_acts_file_dedups_and_fails_closed() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let p = dir.path().join("acts.txt");
        // Duplicates + blank lines + surrounding whitespace: one unique id.
        std::fs::write(&p, "01a0339a-4860-7ea2-8f74-b9f37885e8bb\n\n  01a0339a-4860-7ea2-8f74-b9f37885e8bb  \n").unwrap();
        let rids = parse_acts_file(&p).expect("parse");
        assert_eq!(rids.len(), 1, "duplicate rids collapse (acts_count = unique ids)");

        // A non-receipt-shaped line refuses the WHOLE file — a mangled window
        // list must never produce a signed root over garbage.
        for bad in ["01A0339A-4860-7EA2-8F74-B9F37885E8BB", "rm -rf /", "abc_def"] {
            std::fs::write(&p, format!("{bad}\n")).unwrap();
            assert!(parse_acts_file(&p).is_err(), "{bad:?} must refuse the file");
        }
    }

    #[test]
    fn mirror_publish_meta_passes_the_nodes_ingest_gates() {
        use sha3::{Digest, Sha3_256};
        let mc = "f7b1746a0011eeff2233445566778899aabbccdd";
        let prev = "97ac53d70011eeff2233445566778899aabbccee";
        let tip = "a4dbb5469bb2be703cb3a51074c1c0fe9c62877c";
        let root = mirror_acts_root(&std::collections::BTreeSet::new()).unwrap();
        let meta = build_mirror_publish_meta(mc, "navigatorbuilds/elara-mesh", Some(prev), tip, &root, 0);

        // The FIXED schema: exactly these keys, nothing generic.
        let keys: Vec<&str> = meta.keys().map(|k| k.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "action", "acts_count", "acts_root", "args_hash", "kind",
                "mirror_commit", "mirror_repo", "prev_mirror_commit",
            ],
            "the fixed mirror_publish_act key set (BTreeMap order)"
        );
        assert_eq!(meta["kind"], "mirror_publish_act");
        assert_eq!(meta["action"], "publish-mirror");
        // args_hash is SHA3-256 of the ASCII private-tip sha — the disclosed
        // construction (the raw private sha itself never ships).
        let expect: [u8; 32] = Sha3_256::digest(tip.as_bytes()).into();
        assert_eq!(meta["args_hash"], hex::encode(expect).as_str());

        // End-to-end producer→gate pin: the meta this CLI builds passes the
        // node's OWN ingest validation (allowlist + text sanitization) — the
        // exact gates a4dbb546 registered the schema into.
        elara_runtime::content_safety::validate_metadata_keys(&meta)
            .expect("mirror_publish_act meta is allowlisted");
        elara_runtime::content_safety::sanitize_text_fields(&meta)
            .expect("mirror_publish_act values pass text sanitization");

        // Initial-publish shape: prev omitted, everything else present.
        let first = build_mirror_publish_meta(mc, "navigatorbuilds/elara-mesh", None, tip, &root, 3);
        assert!(!first.contains_key("prev_mirror_commit"));
        assert_eq!(first["acts_count"], "3");
        elara_runtime::content_safety::validate_metadata_keys(&first).expect("initial shape allowlisted");
    }
}
